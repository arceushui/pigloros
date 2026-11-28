//! TME1, the termination evidence of ADR-069 R9 §4.6, with the R10 §4.8
//! stdin feed `adapter-input` and launch failures 3 to 5, and the R14 §3.4
//! launch failures 6 and 7.

use std::num::NonZeroU64;

use ciborium::value::Value;

use super::observed::{cgroup_identity, cgroup_identity_value, work_mount_parts};
use super::{
    code, code_value, consistent, counters, digest, digest_value, open, optional, optional_value,
    seal, uint_in, KernelObservationEvidence, RequestedConfigurationEvidence, Result,
};
use crate::sandbox_provider_protocol::codec::{
    array, bool_value, byte_string, bytes_value, id16, text_value, uint, uint_value,
};
use crate::sandbox_provider_protocol::{
    AttemptProgressCode, BarrierFailure, CancelSource, CgroupCounters, CgroupIdentity,
    CgroupSnapshot, CleanupResult, Contradiction, EndingCode, LaunchFailure,
    LocalNetworkTerminationCode, MainExitCode, OutputCaptureFacts, SandboxProviderProtocolError,
    ServiceFacts, StartJobResult, TerminalCode, TerminationFacts, UnitIdentity, WorkMountFacts,
    WorkStatfsFacts,
};

const MAGIC: &str = "TME1";
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_SOURCE_BYTES: usize = 4096;
/// ELM1's byte ceiling for one transfer or capture.
const MAX_TRANSFER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_LIVE_ATTEMPTS: u64 = 256;
const MAX_SIGNAL: u8 = 64;
/// The shortest framed EAO1 stream: a 7-byte EAO1 frame and a 6-byte EOE1
/// body prefix, each after its 4-byte length (R10 §4.6).
const MIN_FRAMED_BYTES: u64 = 21;

/// TME1 `cleanup.empty-basis`: how the cgroup was proved empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CgroupEmptyBasis {
    /// 0: `cgroup.events` reported it empty.
    Events = 0,
    /// 1: the cgroup was deleted.
    Deleted = 1,
}

/// TME1 `baseline` or `terminal`: one cgroup snapshot with its four raw
/// sources (R9 §4.6.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupSources {
    /// The cgroup the sources were read from.
    pub cgroup: CgroupIdentity,
    /// The `CLOCK_MONOTONIC` capture time in nanoseconds.
    pub observed_at: u64,
    /// The exact bytes of `memory.events.local`, `memory.swap.events`,
    /// `pids.events.local` and `cpu.stat`, 1 to 4096 bytes each.
    pub sources: [Vec<u8>; 4],
}

impl CgroupSources {
    fn value(&self) -> Value {
        Value::Array(vec![
            cgroup_identity_value(self.cgroup),
            uint_value(self.observed_at),
            Value::Array(
                self.sources
                    .iter()
                    .map(|source| bytes_value(source))
                    .collect(),
            ),
        ])
    }

    /// Decode, and parse the sources by the R9 §4.6.2 rules.
    fn decode(value: &Value) -> Result<(Self, CgroupSnapshot)> {
        let [cgroup, observed_at, sources] = array::<3>(value)?;
        let [memory, swap, pids, cpu] = array::<4>(sources)?;
        let decoded = Self {
            cgroup: cgroup_identity(cgroup)?,
            observed_at: uint(observed_at)?,
            sources: [source(memory)?, source(swap)?, source(pids)?, source(cpu)?],
        };
        counters::parse(&decoded.sources)
            .ok_or(SandboxProviderProtocolError::InvalidEncoding)
            .map(|counters| {
                let snapshot = decoded.snapshot(counters);
                (decoded, snapshot)
            })
    }

    const fn snapshot(&self, counters: CgroupCounters) -> CgroupSnapshot {
        CgroupSnapshot {
            cgroup: self.cgroup,
            observed_at: self.observed_at,
            counters,
        }
    }
}

/// TME1 `input`, `output-transfer` or `adapter-input`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferRecord {
    /// When the transfer started (`CLOCK_MONOTONIC` nanoseconds).
    pub start: u64,
    /// Its deadline.
    pub deadline: u64,
    /// When it finished.
    pub finish: u64,
    /// The bytes expected, at most 128 MiB.
    pub expected_bytes: u64,
    /// The bytes accepted, at most 128 MiB.
    pub accepted_bytes: u64,
    /// Whether every expected byte was accepted by the deadline.
    pub complete: bool,
}

impl TransferRecord {
    fn value(self) -> Value {
        Value::Array(vec![
            uint_value(self.start),
            uint_value(self.deadline),
            uint_value(self.finish),
            uint_value(self.expected_bytes),
            uint_value(self.accepted_bytes),
            Value::Bool(self.complete),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [start, deadline, finish, expected, accepted, complete] = array::<6>(value)?;
        Ok(Self {
            start: uint(start)?,
            deadline: uint(deadline)?,
            finish: uint(finish)?,
            expected_bytes: uint_in(expected, 0..=MAX_TRANSFER_BYTES)?,
            accepted_bytes: uint_in(accepted, 0..=MAX_TRANSFER_BYTES)?,
            complete: bool_value(complete)?,
        })
    }

    /// R9 §6 rule 9: it starts by its deadline and finishes after it
    /// starts, and it is complete exactly when every expected byte was
    /// accepted by the deadline.
    const fn ordered(self) -> bool {
        self.start <= self.deadline
            && self.start <= self.finish
            && self.complete
                == (self.accepted_bytes == self.expected_bytes && self.finish <= self.deadline)
    }
}

/// TME1 `output-capture`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputCaptureRecord {
    /// The output bytes accepted, at most 128 MiB.
    pub accepted_bytes: u64,
    /// The output ceiling (ELM1 ID 8) was reached.
    pub ceiling_reached: bool,
    /// The captured output ended on a complete frame.
    pub complete_frame: bool,
}

impl OutputCaptureRecord {
    fn value(self) -> Value {
        Value::Array(vec![
            uint_value(self.accepted_bytes),
            Value::Bool(self.ceiling_reached),
            Value::Bool(self.complete_frame),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [accepted, ceiling, frame] = array::<3>(value)?;
        Ok(Self {
            accepted_bytes: uint_in(accepted, 0..=MAX_TRANSFER_BYTES)?,
            ceiling_reached: bool_value(ceiling)?,
            complete_frame: bool_value(frame)?,
        })
    }

    /// R10 §7 rule 9: a complete frame is never a ceiling stop, and it
    /// holds at least the shortest framed stream.
    const fn ordered(self) -> bool {
        !self.complete_frame || (!self.ceiling_reached && self.accepted_bytes >= MIN_FRAMED_BYTES)
    }
}

/// TME1 `local-network`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalNetworkRecord {
    /// Why the proxy session ended; `None` for a clean close at a frame
    /// boundary.
    pub termination: Option<LocalNetworkTerminationCode>,
    /// The attempt watchdog closed the session.
    pub watchdog_closed: bool,
}

impl LocalNetworkRecord {
    fn value(self) -> Value {
        Value::Array(vec![
            optional_value(self.termination, code_value),
            Value::Bool(self.watchdog_closed),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [termination, closed] = array::<2>(value)?;
        Ok(Self {
            termination: optional(termination, code)?,
            watchdog_closed: bool_value(closed)?,
        })
    }
}

/// TME1 `admission`: the shared admission ledger at AGR1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLedger {
    /// Live attempts after this attempt's acquire (ELM1 ID 13), `1..=256`.
    pub active_attempts: u64,
    /// Incomplete inputs (ELM1 ID 14), `0..=256`.
    pub incomplete_inputs: u64,
}

impl AdmissionLedger {
    fn value(self) -> Value {
        Value::Array(vec![
            uint_value(self.active_attempts),
            uint_value(self.incomplete_inputs),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [active, incomplete] = array::<2>(value)?;
        Ok(Self {
            active_attempts: uint_in(active, 1..=MAX_LIVE_ATTEMPTS)?,
            incomplete_inputs: uint_in(incomplete, 0..=MAX_LIVE_ATTEMPTS)?,
        })
    }
}

/// TME1 `cleanup`: what the terminal cleanup achieved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupRecord {
    /// The result.
    pub result: CleanupResult,
    /// How the bound cgroup was proved empty; present exactly when the
    /// cleanup was proved and a cgroup was bound.
    pub empty_basis: Option<CgroupEmptyBasis>,
    /// When the cleanup finished (`CLOCK_MONOTONIC` nanoseconds).
    pub finished_at: u64,
}

impl CleanupRecord {
    fn value(self) -> Value {
        Value::Array(vec![
            code_value(self.result),
            optional_value(self.empty_basis, code_value),
            uint_value(self.finished_at),
        ])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [result, basis, finished] = array::<3>(value)?;
        Ok(Self {
            result: code(result)?,
            empty_basis: optional(basis, code)?,
            finished_at: uint(finished)?,
        })
    }
}

/// The unsigned fields of one TME1, in R9 order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminationEvidenceFields {
    /// 2: the attempt.
    pub attempt_id: [u8; 16],
    /// 3: the AGR1 self-digest.
    pub agr1_digest: [u8; 32],
    /// 4: the ELM1 digest.
    pub elm1_digest: [u8; 32],
    /// 5: the KOE1 self-digest, which binds RQE1.
    pub koe1_digest: [u8; 32],
    /// 6: how far the attempt got.
    pub progress: AttemptProgressCode,
    /// 7: why the unit was not started or not pinned.
    pub launch_failure: Option<LaunchFailure>,
    /// 8: the start job's result; present iff the start was requested.
    pub start_job: Option<StartJobResult>,
    /// 9: the unit and its bound cgroup.
    pub unit: Option<UnitIdentity>,
    /// 10: the snapshot before `ReleaseV1`.
    pub baseline: Option<CgroupSources>,
    /// 11: the snapshot after exit, before teardown.
    pub terminal: Option<CgroupSources>,
    /// 12: the first failing D5 check.
    pub contradiction: Option<Contradiction>,
    /// 13: the unit's `Result`, `ExecMainCode` and `ExecMainStatus`.
    pub service: Option<ServiceFacts>,
    /// 14: how the released attempt ended.
    pub ending: Option<EndingCode>,
    /// 15: why the launcher barrier did not release.
    pub barrier_failure: Option<BarrierFailure>,
    /// 16: the input transfer.
    pub input: TransferRecord,
    /// 17: the output capture of a released attempt.
    pub output_capture: Option<OutputCaptureRecord>,
    /// 18: the output transfer, once it started.
    pub output_transfer: Option<TransferRecord>,
    /// 19: the Local proxy session.
    pub local_network: Option<LocalNetworkRecord>,
    /// 20: the admission ledger at AGR1.
    pub admission: AdmissionLedger,
    /// 21: the `/work` `statfs` taken with `terminal`.
    pub work_after: Option<WorkStatfsFacts>,
    /// 22: the watchdog deadline `D` in `CLOCK_MONOTONIC` nanoseconds; zero
    /// when it was unreadable.
    pub watchdog_deadline: u64,
    /// 23: who cancelled the attempt, if anyone did.
    pub cancel_source: Option<CancelSource>,
    /// 24: what the terminal cleanup achieved.
    pub cleanup: CleanupRecord,
    /// 25: the TME1 this one succeeds (R9 §4.7).
    pub previous_tme1_digest: Option<[u8; 32]>,
    /// 26: the terminal code; `None` is `Completed`.
    pub terminal_code: Option<TerminalCode>,
    /// 27: the provider's stdin feed after `ReleaseV1`, under ELM1 ID 16
    /// (R10 §4.5); present only at progress 2.
    pub adapter_input: Option<TransferRecord>,
}

/// The decoded snapshots' parsed counters.
type Snapshots = (Option<CgroupSnapshot>, Option<CgroupSnapshot>);

impl TerminationEvidenceFields {
    fn unsigned(&self) -> Vec<Value> {
        vec![
            text_value(MAGIC),
            uint_value(1),
            bytes_value(&self.attempt_id),
            digest_value(&self.agr1_digest),
            digest_value(&self.elm1_digest),
            digest_value(&self.koe1_digest),
            code_value(self.progress),
            optional_value(self.launch_failure, code_value),
            optional_value(self.start_job, code_value),
            optional_value(self.unit, unit_value),
            optional_value(self.baseline.as_ref(), CgroupSources::value),
            optional_value(self.terminal.as_ref(), CgroupSources::value),
            optional_value(self.contradiction, code_value),
            optional_value(self.service, service_value),
            optional_value(self.ending, code_value),
            optional_value(self.barrier_failure, code_value),
            self.input.value(),
            optional_value(self.output_capture, OutputCaptureRecord::value),
            optional_value(self.output_transfer, TransferRecord::value),
            optional_value(self.local_network, LocalNetworkRecord::value),
            self.admission.value(),
            optional_value(self.work_after, work_statfs_value),
            uint_value(self.watchdog_deadline),
            optional_value(self.cancel_source, code_value),
            self.cleanup.value(),
            optional_value(self.previous_tme1_digest.as_ref(), digest_value),
            optional_value(self.terminal_code, code_value),
            optional_value(self.adapter_input, TransferRecord::value),
        ]
    }

    fn decode(fields: &[Value; 28]) -> Result<(Self, Snapshots)> {
        let (attempt_id, agr1_digest, elm1_digest, koe1_digest) = bindings(fields)?;
        let (progress, launch_failure, start_job, unit) = launch(fields)?;
        let ((baseline, baseline_snapshot), (terminal, terminal_snapshot)) = snapshots(fields)?;
        let (contradiction, service, ending, barrier_failure) = outcome(fields)?;
        let (input, output_capture, output_transfer, local_network) = transfers(fields)?;
        let (admission, work_after, watchdog_deadline, cancel_source) = ledger(fields)?;
        let (cleanup, previous_tme1_digest, terminal_code, adapter_input) = conclusion(fields)?;
        let decoded = Self {
            attempt_id,
            agr1_digest,
            elm1_digest,
            koe1_digest,
            progress,
            launch_failure,
            start_job,
            unit,
            baseline,
            terminal,
            contradiction,
            service,
            ending,
            barrier_failure,
            input,
            output_capture,
            output_transfer,
            local_network,
            admission,
            work_after,
            watchdog_deadline,
            cancel_source,
            cleanup,
            previous_tme1_digest,
            terminal_code,
            adapter_input,
        };
        {
            let (shaped, ordered) = (decoded.shaped(), decoded.ordered());
            if !(shaped && ordered) {
                std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!(
                        "pos-sandboxd diag: TME1 shaped={shaped} ordered={ordered}: {decoded:?}\n"
                    ),
                )
                .ok();
            }
        }
        consistent(decoded.shaped() && decoded.ordered())
            .map(|()| (decoded, (baseline_snapshot, terminal_snapshot)))
    }

    /// R9 §4.6.1 and §4.6.3: what each progress requires and forbids, the
    /// main-exit status rule, and when a cleanup records an empty basis.
    fn shaped(&self) -> bool {
        let progressed = match self.progress {
            AttemptProgressCode::NotStarted => self.not_started_shape(),
            AttemptProgressCode::StartedNotReleased => self.started_shape(),
            AttemptProgressCode::Released => self.released_shape(),
        };
        progressed
            && self.service.is_none_or(exit_status_matches)
            && self.cleanup.empty_basis.is_some()
                == (self.cleanup.result == CleanupResult::Proved && self.unit.is_some())
    }

    /// Progress 0: no unit and nothing after it; only a root activation,
    /// pre-start recheck, output reservation, stdio channel, network setup
    /// or replay failure. Their modes are the verifier's (R14 rule 2).
    const fn not_started_shape(&self) -> bool {
        !matches!(self.launch_failure, Some(LaunchFailure::UnitRefFailed))
            && self.start_job.is_none()
            && self.unit.is_none()
            && self.baseline.is_none()
            && self.terminal.is_none()
            && self.service.is_none()
            && self.ending.is_none()
            && self.barrier_failure.is_none()
            && self.nothing_after_release()
            && self.local_network.is_none()
            && self.work_after.is_none()
    }

    /// Progress 1: snapshots only with a unit, both or neither; no ending,
    /// capture, feed or output transfer; only a pin failure. A null start
    /// job is missing evidence (code 2), not a shape error: the provider
    /// requested the start but observed no result it can name (owner
    /// reading G1, Redmine #443 journal 22723).
    const fn started_shape(&self) -> bool {
        matches!(
            self.launch_failure,
            None | Some(LaunchFailure::UnitRefFailed)
        ) && (self.unit.is_some() || self.baseline.is_none())
            && self.baseline.is_some() == self.terminal.is_some()
            && self.ending.is_none()
            && self.nothing_after_release()
            && (self.unit.is_some() || self.work_after.is_none())
    }

    /// Before `ReleaseV1`: no output capture, output transfer or stdin feed.
    const fn nothing_after_release(&self) -> bool {
        self.output_capture.is_none()
            && self.output_transfer.is_none()
            && self.adapter_input.is_none()
    }

    /// Progress 2: a done start job, the unit, the baseline snapshot, an ending and
    /// a capture; no launch or barrier failure. A null `adapter-input` is
    /// missing evidence, not a shape error (R10 §4.8), and so is a null
    /// start job (owner reading G1, Redmine #443 journal 22723) and a null
    /// `terminal` snapshot: the cgroup of the exited unit may be gone before its counters
    /// can be read (ADR-069 R17-E6), and the classifier selects code 2 for it.
    const fn released_shape(&self) -> bool {
        self.launch_failure.is_none()
            && matches!(self.start_job, None | Some(StartJobResult::Done))
            && self.unit.is_some()
            && self.baseline.is_some()
            && self.ending.is_some()
            && self.barrier_failure.is_none()
            && self.output_capture.is_some()
    }

    /// R9 §6 rule 9 within the record, as R10 §7 extends it: each transfer
    /// is ordered, the capture is consistent, the stdin feed lies within the
    /// released run, and the cleanup finished no earlier than the terminal
    /// snapshot.
    fn ordered(&self) -> bool {
        self.transfers_ordered()
            && self
                .terminal
                .as_ref()
                .is_none_or(|terminal| self.cleanup.finished_at >= terminal.observed_at)
    }

    /// Each transfer is ordered, the capture is consistent and the stdin
    /// feed lies within the released run.
    fn transfers_ordered(&self) -> bool {
        self.input.ordered()
            && self.output_transfer.is_none_or(TransferRecord::ordered)
            && self.output_capture.is_none_or(OutputCaptureRecord::ordered)
            && self
                .adapter_input
                .is_none_or(|feed| self.feed_ordered(feed))
    }

    /// R10 §4.8 and §7 rule 9: the stdin feed is ordered, carries exactly
    /// the verified input, starts after the input transfer finished and
    /// after the baseline, and finishes by the terminal snapshot.
    fn feed_ordered(&self, feed: TransferRecord) -> bool {
        feed.ordered()
            && feed.expected_bytes == self.input.expected_bytes
            && feed.start >= self.input.finish
            && self
                .baseline
                .as_ref()
                .is_some_and(|baseline| feed.start >= baseline.observed_at)
            && self
                .terminal
                .as_ref()
                .is_none_or(|terminal| feed.finish <= terminal.observed_at)
    }
}

/// One TME1: its validated fields, parsed counters, self-digest and
/// canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminationEvidence {
    fields: TerminationEvidenceFields,
    snapshots: Snapshots,
    digest: [u8; 32],
    bytes: Vec<u8>,
}

impl TerminationEvidence {
    /// Encode and seal `fields`.
    ///
    /// # Errors
    /// Any R9 rule the decoded record would fail.
    pub fn new(fields: &TerminationEvidenceFields) -> Result<Self> {
        seal(MAGIC, fields.unsigned()).and_then(|bytes| Self::from_canonical_cbor(&bytes))
    }

    /// Decode and validate exact canonical TME1 bytes.
    ///
    /// # Errors
    /// A closed protocol error for every R9 §6 rule the record alone decides,
    /// including a cgroup source that fails the R9 §4.6.2 parser.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        open(
            bytes,
            MAGIC,
            MAX_RECORD_BYTES,
            TerminationEvidenceFields::decode,
        )
        .map(|((fields, snapshots), digest)| Self {
            fields,
            snapshots,
            digest,
            bytes: bytes.to_vec(),
        })
    }

    /// The fields.
    #[must_use]
    pub const fn fields(&self) -> &TerminationEvidenceFields {
        &self.fields
    }

    /// The self-digest under `PiglorOS.TME1.v1\0`.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The canonical record bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The classification view of this TME1 with the RQE1 and KOE1 it
    /// binds, which the caller has bound: a verifier recomputes the
    /// contradiction and terminal code from it (R9 §6 rule 7).
    #[must_use]
    pub fn facts(
        &self,
        requested: &RequestedConfigurationEvidence,
        observed: &KernelObservationEvidence,
    ) -> TerminationFacts {
        let fields = &self.fields;
        TerminationFacts {
            progress: fields.progress,
            launch_failure: fields.launch_failure,
            start_job: fields.start_job,
            unit: fields.unit,
            baseline: self.snapshots.0,
            terminal: self.snapshots.1,
            service: fields.service,
            ending: fields.ending,
            barrier_failure: fields.barrier_failure,
            input_complete: fields.input.complete,
            adapter_input_complete: fields.adapter_input.map(|feed| feed.complete),
            output_capture: fields.output_capture.map(|capture| OutputCaptureFacts {
                ceiling_reached: capture.ceiling_reached,
                complete_frame: capture.complete_frame,
            }),
            output_transfer_complete: fields.output_transfer.map(|transfer| transfer.complete),
            local_network_termination: fields.local_network.and_then(|network| network.termination),
            work_after: fields.work_after,
            watchdog_deadline: NonZeroU64::new(fields.watchdog_deadline),
            cancel_source: fields.cancel_source,
            cleanup: fields.cleanup.result,
            requested: requested.fields().status,
            observed: observed.fields().status.facts(),
        }
    }

    /// This TME1 is the one successor of `previous`, a verified first TME1
    /// with no output transfer: it copies every field except the `output-transfer`
    /// that is now present and incomplete, the predecessor's digest and the
    /// recomputed terminal code (R9 §4.7).
    pub(super) fn succeeds(&self, previous: &Self) -> bool {
        let successor = &self.fields;
        let mut copied = previous.fields.clone();
        copied.output_transfer = successor.output_transfer;
        copied.previous_tme1_digest = successor.previous_tme1_digest;
        copied.terminal_code = successor.terminal_code;
        // A successor always has an output transfer, so requiring none of
        // `previous` also refuses a successor of a successor.
        previous.fields.output_transfer.is_none()
            && successor
                .output_transfer
                .is_some_and(|transfer| !transfer.complete)
            && copied == *successor
    }
}

/// `attempt-id`, `agr1-digest`, `elm1-digest` and `koe1-digest`.
type Bindings = ([u8; 16], [u8; 32], [u8; 32], [u8; 32]);

fn bindings(fields: &[Value; 28]) -> Result<Bindings> {
    Ok((
        id16(&fields[2])?,
        digest(&fields[3])?,
        digest(&fields[4])?,
        digest(&fields[5])?,
    ))
}

type Launch = (
    AttemptProgressCode,
    Option<LaunchFailure>,
    Option<StartJobResult>,
    Option<UnitIdentity>,
);

fn launch(fields: &[Value; 28]) -> Result<Launch> {
    Ok((
        code(&fields[6])?,
        optional(&fields[7], code)?,
        optional(&fields[8], code)?,
        optional(&fields[9], unit_identity)?,
    ))
}

type Snapshot = (Option<CgroupSources>, Option<CgroupSnapshot>);

fn snapshots(fields: &[Value; 28]) -> Result<(Snapshot, Snapshot)> {
    let snapshot = |value: &Value| {
        optional(value, CgroupSources::decode).map(|decoded| match decoded {
            Some((sources, snapshot)) => (Some(sources), Some(snapshot)),
            None => (None, None),
        })
    };
    Ok((snapshot(&fields[10])?, snapshot(&fields[11])?))
}

type Outcome = (
    Option<Contradiction>,
    Option<ServiceFacts>,
    Option<EndingCode>,
    Option<BarrierFailure>,
);

fn outcome(fields: &[Value; 28]) -> Result<Outcome> {
    Ok((
        optional(&fields[12], code)?,
        optional(&fields[13], service)?,
        optional(&fields[14], code)?,
        optional(&fields[15], code)?,
    ))
}

type Transfers = (
    TransferRecord,
    Option<OutputCaptureRecord>,
    Option<TransferRecord>,
    Option<LocalNetworkRecord>,
);

fn transfers(fields: &[Value; 28]) -> Result<Transfers> {
    Ok((
        TransferRecord::decode(&fields[16])?,
        optional(&fields[17], OutputCaptureRecord::decode)?,
        optional(&fields[18], TransferRecord::decode)?,
        optional(&fields[19], LocalNetworkRecord::decode)?,
    ))
}

type Ledger = (
    AdmissionLedger,
    Option<WorkStatfsFacts>,
    u64,
    Option<CancelSource>,
);

fn ledger(fields: &[Value; 28]) -> Result<Ledger> {
    Ok((
        AdmissionLedger::decode(&fields[20])?,
        optional(&fields[21], work_statfs)?,
        uint(&fields[22])?,
        optional(&fields[23], code)?,
    ))
}

type Conclusion = (
    CleanupRecord,
    Option<[u8; 32]>,
    Option<TerminalCode>,
    Option<TransferRecord>,
);

fn conclusion(fields: &[Value; 28]) -> Result<Conclusion> {
    let (cleanup, previous, terminal) = (
        CleanupRecord::decode(&fields[24])?,
        optional(&fields[25], digest)?,
        optional(&fields[26], code)?,
    );
    optional(&fields[27], TransferRecord::decode)
        .map(|adapter_input| (cleanup, previous, terminal, adapter_input))
}

fn unit_identity(value: &Value) -> Result<UnitIdentity> {
    let [invocation, cgroup] = array::<2>(value)?;
    Ok(UnitIdentity {
        invocation_id: id16(invocation)?,
        cgroup: cgroup_identity(cgroup)?,
    })
}

fn unit_value(unit: UnitIdentity) -> Value {
    Value::Array(vec![
        bytes_value(&unit.invocation_id),
        cgroup_identity_value(unit.cgroup),
    ])
}

fn source(value: &Value) -> Result<Vec<u8>> {
    let source = byte_string(value)?;
    if (1..=MAX_SOURCE_BYTES).contains(&source.len()) {
        Ok(source.to_vec())
    } else {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

fn service(value: &Value) -> Result<ServiceFacts> {
    let [result, exit_code, status] = array::<3>(value)?;
    Ok(ServiceFacts {
        result: code(result)?,
        exec_main_code: code(exit_code)?,
        exec_main_status: uint(status).and_then(|status| {
            u8::try_from(status).map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)
        })?,
    })
}

fn service_value(service: ServiceFacts) -> Value {
    Value::Array(vec![
        code_value(service.result),
        code_value(service.exec_main_code),
        uint_value(u64::from(service.exec_main_status)),
    ])
}

/// `exec-main-status` is 0 before an exit and a signal number `1..=64` for
/// a killed or dumped main process (R9 §4.6.1).
const fn exit_status_matches(service: ServiceFacts) -> bool {
    match service.exec_main_code {
        MainExitCode::NotExited => service.exec_main_status == 0,
        MainExitCode::Exited => true,
        MainExitCode::Killed | MainExitCode::Dumped => {
            service.exec_main_status != 0 && service.exec_main_status <= MAX_SIGNAL
        }
    }
}

fn work_statfs(value: &Value) -> Result<WorkStatfsFacts> {
    let [mount_id, capacity, available] = array::<3>(value)?;
    Ok(WorkStatfsFacts {
        mount: work_mount_parts(mount_id, capacity)?,
        available_bytes: uint(available)?,
    })
}

fn work_statfs_value(work: WorkStatfsFacts) -> Value {
    let WorkStatfsFacts {
        mount: WorkMountFacts {
            mount_id,
            capacity_bytes,
        },
        available_bytes,
    } = work;
    Value::Array(vec![
        uint_value(mount_id),
        uint_value(capacity_bytes),
        uint_value(available_bytes),
    ])
}
