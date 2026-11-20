//! The terminal evidence records of one ended attempt (ADR-069 R9 §4.3,
//! §4.4 and §4.6, R10 §4.8).
//!
//! [`EndedAttempt::records`] assembles, only from what the lifecycle
//! retained of the attempt, its RQE1, KOE1 and TME1:
//!
//! * RQE1 is the verified start's (status 0), the rejected or unobtainable
//!   readback of a start that was not verified (2 or 3), or `NotRequested`
//!   when no start was requested (1);
//! * KOE1 is the observation frozen after `ReadyV1` (0), `ObservationFailed`
//!   when `ReadyV1` was accepted and no observation made (2), or
//!   `NotReached` (1); it binds the RQE1 digest;
//! * TME1 records how far the attempt got, its unit, its cgroup snapshots,
//!   its result, ending and barrier failure, its transfers and capture, the
//!   admission ledger, `/work`, the watchdog deadline, the cancellation and
//!   the cleanup, then the contradiction and terminal code that the shared
//!   [`TerminationFacts::classify`] selects from exactly those records.
//!
//! Nothing here signs anything. A time TME1 requires that the monotonic
//! clock could not report is a provider fault (owner reading G2, Redmine
//! #443 journal 22723): no record is made, and the caller emits no response.
//!
//! [`TerminationFacts::classify`]: pos_reference::sandbox_provider_protocol::TerminationFacts::classify

use pos_reference::sandbox_provider_protocol::{
    attempt_watchdog_deadline, AttemptProgressCode, BarrierFailure, CgroupSources, CleanupRecord,
    CleanupResult, EndingCode, KernelObservationEvidence, KernelObservationEvidenceFields,
    KernelObservationStatus, LaunchFailure, LocalNetworkRecord, RequestedConfigurationEvidence,
    RequestedConfigurationEvidenceFields, RequestedConfigurationStatus, SandboxExecutionMode,
    SandboxProviderProtocolError, ServiceFacts, StartJobResult, TerminalClassification,
    TerminationEvidence, TerminationEvidenceFields, TransferRecord, UnitIdentity, WorkMountFacts,
    WorkStatfsFacts,
};

use crate::{
    AdapterIo, AttemptLimitEventSnapshot, AttemptLimitEventSource, AttemptProgress, DeviceNumber,
    EndedAttempt, ExecuteError, IssuedGrant, NetworkEvidence, RequestedConfiguration,
    ResourceEvidence, UnitState, UnverifiedStart,
};

/// ELM1 limit IDs the records read (ADR-069 §8).
const WATCHDOG_LIMIT: u8 = 4;

const NANOSECONDS_PER_MILLISECOND: u64 = 1_000_000;

/// The four limit-event sources in TME1 order (R9 §4.6.2).
const SOURCES: [AttemptLimitEventSource; 4] = [
    AttemptLimitEventSource::MemoryEventsLocal,
    AttemptLimitEventSource::MemorySwapEvents,
    AttemptLimitEventSource::PidsEventsLocal,
    AttemptLimitEventSource::CpuStat,
];

/// What one attempt was admitted with: its AGR1, the admitted facts AGR1
/// commits to, and its input transfer (TME1 `input`).
#[derive(Clone, Debug)]
pub struct AttemptAdmission {
    grant: IssuedGrant,
    input: Option<TransferRecord>,
}

impl AttemptAdmission {
    pub(crate) const fn new(grant: IssuedGrant, input: Option<TransferRecord>) -> Self {
        Self { grant, input }
    }

    /// The AGR1 the attempt was admitted under, with its admitted facts.
    #[must_use]
    pub const fn grant(&self) -> &IssuedGrant {
        &self.grant
    }

    /// TME1 `input`: the input transfer as far as it got; `None` if the
    /// clock could not report when it finished.
    #[must_use]
    pub const fn input(&self) -> Option<TransferRecord> {
        self.input
    }

    /// One ELM1 limit; `None` if ELM1 does not name it.
    fn limit(&self, limit_id: u8) -> Option<u64> {
        self.grant
            .effective_limits()
            .iter()
            .find(|limit| limit.limit_id == limit_id)
            .map(|limit| limit.value)
    }
}

/// The RQE1, KOE1 and TME1 of one ended attempt and its classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptRecords {
    requested: RequestedConfigurationEvidence,
    observed: KernelObservationEvidence,
    termination: TerminationEvidence,
    classification: TerminalClassification,
}

impl AttemptRecords {
    /// RQE1, SPR1 ordinal 19.
    #[must_use]
    pub const fn requested(&self) -> &RequestedConfigurationEvidence {
        &self.requested
    }

    /// KOE1, SPR1 ordinal 20.
    #[must_use]
    pub const fn observed(&self) -> &KernelObservationEvidence {
        &self.observed
    }

    /// TME1, SPR1 ordinal 22 and the SAU1 terminal event's last digest.
    #[must_use]
    pub const fn termination(&self) -> &TerminationEvidence {
        &self.termination
    }

    /// The classification TME1 records: its contradiction, candidates,
    /// terminal code, outcome and whether the lifecycle is quarantined.
    #[must_use]
    pub const fn classification(&self) -> &TerminalClassification {
        &self.classification
    }

    /// The records with the successor of this first, Completed TME1 after
    /// its output transfer timed out (R9 §4.7): every field is copied except
    /// `output-transfer`, now the incomplete `transfer`, the predecessor's
    /// digest and the recomputed terminal code. `transfer` is `None` when a
    /// time of the output transfer could not be read: a provider fault
    /// ([`EvidenceFault::Clock`], R9 Amendment 1 change F).
    fn successor(&self, transfer: Option<TransferRecord>) -> Result<Self, EvidenceFault> {
        let transfer = self.reissued_transfer(transfer)?;
        let stored = self.termination.fields();
        // The transfer carries the retained output and starts after the
        // teardown the stored TME1 records.
        let bound = stored
            .output_capture
            .is_some_and(|capture| capture.accepted_bytes == transfer.expected_bytes)
            && transfer.start >= stored.cleanup.finished_at;
        if !bound {
            return Err(EvidenceFault::UnboundTransfer);
        }
        let mut fields = stored.clone();
        fields.output_transfer = Some(transfer);
        fields.previous_tme1_digest = Some(self.termination.digest());
        classified(self.requested.clone(), self.observed.clone(), fields)
    }

    /// The output transfer a re-issue records: refused
    /// ([`EvidenceFault::NotReissuable`]) unless the stored TME1 is a first,
    /// Completed one and the transfer did not complete, and a provider fault
    /// ([`EvidenceFault::Clock`]) when its times could not be read.
    fn reissued_transfer(
        &self,
        transfer: Option<TransferRecord>,
    ) -> Result<TransferRecord, EvidenceFault> {
        // The stored TME1 must be a first one (no predecessor): R9 §4.7
        // then gives it no output transfer.
        let reissuable = self.termination.fields().previous_tme1_digest.is_none()
            && self.classification.code().is_none()
            && !transfer.is_some_and(|transfer| transfer.complete);
        if reissuable {
            transfer.ok_or(EvidenceFault::Clock)
        } else {
            Err(EvidenceFault::NotReissuable)
        }
    }
}

/// Classify the TME1 of `fields` from the records themselves, and record
/// its contradiction and terminal code (R9 §6 rule 7).
fn classified(
    requested: RequestedConfigurationEvidence,
    observed: KernelObservationEvidence,
    mut fields: TerminationEvidenceFields,
) -> Result<AttemptRecords, EvidenceFault> {
    TerminationEvidence::new(&fields)
        .map(|draft| draft.facts(&requested, &observed).classify())
        .and_then(|classification| {
            fields.contradiction = classification.contradiction();
            fields.terminal_code = classification.code();
            TerminationEvidence::new(&fields).map(|termination| AttemptRecords {
                requested,
                observed,
                termination,
                classification,
            })
        })
        .map_err(EvidenceFault::from)
}

/// Why no terminal records exist for an ended attempt.
///
/// Each is a provider fault: no response is emitted, the lifecycle is
/// quarantined, and restart reconciliation (SIR1) recovers (owner reading
/// G2, Redmine #443 journal 22723).
#[derive(Debug, thiserror::Error)]
pub enum EvidenceFault {
    /// The monotonic clock could not report a time TME1 requires: `input`,
    /// `cleanup.finished-at`, a snapshot's `observed-at`, an `adapter-input`
    /// time or, for a successor, an `output-transfer` time (R9 Amendment 1
    /// change F).
    #[error("a time the termination evidence requires could not be read")]
    Clock,
    /// A fact R9 requires at the attempt's progress could not be read, so no
    /// valid record exists: a start requested without its failure, or a
    /// cgroup device outside the kernel's bounds.
    #[error("the termination evidence lacks a fact its progress requires")]
    Unrepresentable,
    /// The record encoders refused the facts.
    #[error(transparent)]
    Record(#[from] SandboxProviderProtocolError),
    /// The re-issue was refused: the stored TME1 is already a successor or
    /// not Completed, or the output transfer completed (R9 §4.7).
    #[error("the termination evidence cannot be re-issued")]
    NotReissuable,
    /// The output transfer does not carry the retained output, or started
    /// before the cleanup finished.
    #[error("the output transfer is not the retained output's")]
    UnboundTransfer,
}

/// How a start that was requested is known (RQE1).
enum Start<'a, S> {
    /// No start was requested: RQE1 status 1.
    NotRequested,
    /// The start was verified: RQE1 status 0.
    Verified(&'a S),
    /// The start was requested and not verified: RQE1 status 2 or 3.
    Unverified(Option<&'a UnverifiedStart>),
}

/// What one ended attempt reached, by the TME1 fields its progress decides.
struct Reached<'a, S> {
    progress: AttemptProgressCode,
    launch_failure: Option<LaunchFailure>,
    start: Start<'a, S>,
    evidence: Option<&'a ResourceEvidence>,
    ending: Option<EndingCode>,
    timed_out: bool,
    network: Option<&'a NetworkEvidence>,
    adapter: Option<&'a AdapterIo>,
}

impl<'a, S> Reached<'a, S> {
    const fn unstarted(launch_failure: Option<LaunchFailure>) -> Self {
        Self {
            progress: AttemptProgressCode::NotStarted,
            launch_failure,
            start: Start::NotRequested,
            evidence: None,
            ending: None,
            timed_out: false,
            network: None,
            adapter: None,
        }
    }

    fn of(progress: &'a AttemptProgress<S>) -> Self {
        match progress {
            AttemptProgress::Withdrawn
            | AttemptProgress::InputFailed
            | AttemptProgress::NotPrepared
            | AttemptProgress::CancelledBeforeActivation => Self::unstarted(None),
            AttemptProgress::NotActivated(_) => {
                Self::unstarted(Some(LaunchFailure::RootNotActivated))
            }
            AttemptProgress::Failed {
                error,
                unit,
                started,
                evidence,
            } => Self::failed(error, *unit, started.as_ref(), evidence.as_ref()),
            AttemptProgress::Executed {
                started,
                ending,
                network,
                evidence,
                adapter,
            } => Self {
                progress: AttemptProgressCode::Released,
                launch_failure: None,
                start: Start::Verified(started),
                evidence: Some(evidence),
                ending: Some((*ending).into()),
                timed_out: false,
                network: Some(network),
                adapter: Some(adapter),
            },
        }
    }

    /// A failed execution: released once its `ReleaseV1` was sent, started
    /// once its unit start was requested.
    ///
    /// A failure after `ReleaseV1` records no ending, and possibly no
    /// terminal snapshot. A progress-2 TME1 requires both, so its encoder
    /// refuses the record and no response is emitted: a deliberate provider
    /// fault that fails closed (owner decision 2026-11-19, Q2).
    fn failed(
        error: &'a ExecuteError,
        unit: UnitState,
        started: Option<&'a S>,
        evidence: Option<&'a ResourceEvidence>,
    ) -> Self {
        let progress = failed_progress(unit, started.is_some(), evidence);
        let start = match (progress, started) {
            (AttemptProgressCode::NotStarted, _) => Start::NotRequested,
            (_, Some(started)) => Start::Verified(started),
            (_, None) => Start::Unverified(error.unverified_start()),
        };
        Self {
            progress,
            launch_failure: error.launch_failure(),
            start,
            evidence,
            ending: None,
            timed_out: matches!(error, ExecuteError::ReleaseTimeout),
            network: None,
            adapter: None,
        }
    }

    /// TME1 `start-job-result`: `done` for a verified start, what a failed
    /// start observed, and none without a start (R9 §4.6.3; owner reading
    /// G1, Redmine #443 journal 22723).
    fn start_job(&self) -> Option<StartJobResult> {
        match &self.start {
            Start::NotRequested => None,
            Start::Verified(_) => Some(StartJobResult::Done),
            Start::Unverified(start) => start.and_then(|start| start.observed().job),
        }
    }

    /// TME1 `barrier-failure`, recorded only before a release (R9 §4.6.3):
    /// the barrier's own refusal, or a release that did not arrive before
    /// the deadline, which is `ReadyUnavailable` before any `ReadyV1` was
    /// accepted and `RecheckExpired` after (R9 §11 O15).
    fn barrier_failure(&self) -> Option<BarrierFailure> {
        let release = self
            .evidence
            .filter(|_| self.progress == AttemptProgressCode::StartedNotReleased)
            .map(ResourceEvidence::release)?;
        let expired = release
            .ready1_digest()
            .map_or(BarrierFailure::ReadyUnavailable, |_| {
                BarrierFailure::RecheckExpired
            });
        release
            .barrier_failure()
            .or_else(|| self.timed_out.then_some(expired))
    }
}

impl<S: RequestedConfiguration> Start<'_, S> {
    /// The attempt's RQE1.
    fn evidence(
        &self,
        attempt_id: [u8; 16],
        agr1_digest: [u8; 32],
    ) -> Result<RequestedConfigurationEvidence, EvidenceFault> {
        match self {
            Self::NotRequested => {
                RequestedConfigurationEvidence::new(&RequestedConfigurationEvidenceFields {
                    attempt_id,
                    agr1_digest,
                    status: RequestedConfigurationStatus::NotRequested,
                    requested: None,
                    readback: None,
                })
                .map_err(EvidenceFault::from)
            }
            Self::Verified(started) => started
                .requested_configuration_evidence(attempt_id, agr1_digest)
                .map_err(EvidenceFault::from),
            Self::Unverified(start) => {
                start
                    .ok_or(EvidenceFault::Unrepresentable)
                    .and_then(|start| {
                        crate::unverified_requested_configuration(
                            attempt_id,
                            agr1_digest,
                            start.requested(),
                            start.observed().readback.as_deref(),
                        )
                        .map_err(EvidenceFault::from)
                    })
            }
        }
    }
}

/// The attempt's KOE1: the frozen status-0 record, or a status-1 or
/// status-2 record that binds `requested` (R9 §4.4).
fn observation_evidence(
    evidence: Option<&ResourceEvidence>,
    attempt_id: [u8; 16],
    agr1_digest: [u8; 32],
    requested: [u8; 32],
) -> Result<KernelObservationEvidence, EvidenceFault> {
    let release = evidence.map(ResourceEvidence::release);
    if let Some(frozen) = release.and_then(crate::ReleaseOutcome::kernel_observation_evidence) {
        return Ok(frozen.clone());
    }
    let status = release
        .and_then(crate::ReleaseOutcome::ready1_digest)
        .map_or(KernelObservationStatus::NotReached, |ready1_digest| {
            KernelObservationStatus::ObservationFailed { ready1_digest }
        });
    KernelObservationEvidence::new(&KernelObservationEvidenceFields {
        attempt_id,
        agr1_digest,
        status,
        requested_configuration_evidence: requested,
    })
    .map_err(EvidenceFault::from)
}

/// One snapshot as TME1 records it, with its exact sources.
fn sources(snapshot: &AttemptLimitEventSnapshot) -> Result<CgroupSources, EvidenceFault> {
    let cgroup = DeviceNumber::cgroup_evidence(snapshot.cgroup_identity())
        .ok_or(EvidenceFault::Unrepresentable)?;
    let observed_at = snapshot.observed_at_ns().ok_or(EvidenceFault::Clock)?;
    Ok(CgroupSources {
        cgroup,
        observed_at,
        sources: SOURCES.map(|source| snapshot.raw(source).to_vec()),
    })
}

/// TME1 `input` and `adapter-input`; [`EvidenceFault::Clock`] when the
/// clock could not report a time of either (R9 Amendment 1 change F).
fn transfers(
    admission: &AttemptAdmission,
    adapter: Option<&AdapterIo>,
) -> Result<(TransferRecord, Option<TransferRecord>), EvidenceFault> {
    admission
        .input()
        .zip(adapter.map_or(Some(None), |adapter| adapter.input().map(Some)))
        .ok_or(EvidenceFault::Clock)
}

/// TME1 `baseline` and `terminal`. Before a release they are recorded as a
/// pair or not at all (R9 §4.6.3): either one missing leaves both null,
/// which is missing evidence for a bound unit.
fn snapshots(
    evidence: Option<&ResourceEvidence>,
    released: bool,
) -> Result<(Option<CgroupSources>, Option<CgroupSources>), EvidenceFault> {
    let baseline = evidence
        .and_then(ResourceEvidence::resources)
        .map(|resources| sources(resources.baseline()))
        .transpose()?;
    let terminal = evidence
        .and_then(ResourceEvidence::terminal)
        .and_then(|terminal| terminal.terminal().as_ref().ok())
        .map(sources)
        .transpose()?;
    Ok(if released || (baseline.is_some() && terminal.is_some()) {
        (baseline, terminal)
    } else {
        (None, None)
    })
}

/// TME1 `work-after`: `/work` after exit, read through the handle the
/// frozen KOE1 observation opened (R9 §4.6.3). After a failed KOE1 (status 1
/// or 2) no handle exists and it is null, which is valid; after a status-0
/// KOE1 one that could not be read is null too, which is missing evidence,
/// code 2 (owner decision 2026-11-19, R9 amendment review).
fn work_after(evidence: Option<&ResourceEvidence>) -> Option<WorkStatfsFacts> {
    evidence
        .and_then(ResourceEvidence::terminal)
        .and_then(crate::TerminalResources::work_after)
        .and_then(|work| work.as_ref().ok())
        .map(|usage| WorkStatfsFacts {
            mount: WorkMountFacts {
                mount_id: usage.mount().mount_id(),
                capacity_bytes: usage.mount().capacity_bytes(),
            },
            available_bytes: usage.available_bytes(),
        })
}

impl<S: RequestedConfiguration> EndedAttempt<S> {
    /// Assemble this attempt's RQE1, KOE1 and TME1 and classify it (ADR-069
    /// R9 §4.3 to §4.6).
    ///
    /// The TME1 contradiction and terminal code are the ones the shared
    /// classifier derives from the records themselves, so a verifier
    /// recomputes exactly them (R9 §6 rule 7).
    ///
    /// # Errors
    /// [`EvidenceFault::Clock`] when a time TME1 requires is unreadable,
    /// [`EvidenceFault::Unrepresentable`] when a fact its progress requires
    /// is missing, and [`EvidenceFault::Record`] when an encoder refuses
    /// the facts. Each is a provider fault: no response is emitted.
    pub fn records(&self) -> Result<AttemptRecords, EvidenceFault> {
        let admission = self.admission();
        let grant = admission.grant();
        let (attempt_id, agr1_digest) = (self.attempt_id(), grant.digest());
        let reached = Reached::of(self.progress());
        let requested = reached.start.evidence(attempt_id, agr1_digest)?;
        observation_evidence(
            reached.evidence,
            attempt_id,
            agr1_digest,
            requested.digest(),
        )
        .and_then(|observed| {
            let fields = self.termination_fields(&reached, observed.digest())?;
            classified(requested, observed, fields)
        })
    }

    /// The TME1 fields before classification.
    fn termination_fields(
        &self,
        reached: &Reached<'_, S>,
        koe1_digest: [u8; 32],
    ) -> Result<TerminationEvidenceFields, EvidenceFault> {
        let admission = self.admission();
        let grant = admission.grant();
        let released = reached.progress == AttemptProgressCode::Released;
        let evidence = reached.evidence;
        let unit = evidence
            .and_then(ResourceEvidence::unit)
            .map(|(invocation_id, cgroup)| {
                DeviceNumber::cgroup_evidence(cgroup)
                    .map(|cgroup| UnitIdentity {
                        invocation_id,
                        cgroup,
                    })
                    .ok_or(EvidenceFault::Unrepresentable)
            })
            .transpose()?;
        let (baseline, terminal) = snapshots(evidence, released)?;
        let (input, adapter_input) = transfers(admission, reached.adapter)?;
        let bound = unit.is_some();
        Ok(TerminationEvidenceFields {
            attempt_id: self.attempt_id(),
            agr1_digest: grant.digest(),
            elm1_digest: grant.effective_limits_digest(),
            koe1_digest,
            progress: reached.progress,
            launch_failure: reached.launch_failure,
            start_job: reached.start_job(),
            unit,
            baseline,
            terminal,
            contradiction: None,
            service: evidence
                .and_then(ResourceEvidence::terminal)
                .and_then(|terminal| terminal.service().as_ref().ok())
                .map(ServiceFacts::from),
            ending: reached.ending,
            barrier_failure: reached.barrier_failure(),
            input,
            output_capture: reached.adapter.map(|adapter| adapter.output().capture()),
            output_transfer: None,
            local_network: local_network(reached, grant.execution_mode()),
            admission: grant.admission(),
            work_after: work_after(evidence),
            watchdog_deadline: self.watchdog_deadline(reached),
            cancel_source: self.cancel_source(),
            cleanup: self.cleanup_record(bound)?,
            previous_tme1_digest: None,
            terminal_code: None,
            adapter_input,
        })
    }

    /// TME1 `watchdog-deadline` `D` (R9 §4.6.3 and §4.6.5): the unit's
    /// activation plus ELM1 limit 4 once the unit started, its AGR1-time
    /// value before; zero when it is unreadable.
    fn watchdog_deadline(&self, reached: &Reached<'_, S>) -> u64 {
        let admission = self.admission();
        let watchdog = admission
            .limit(WATCHDOG_LIMIT)
            .and_then(|milliseconds| milliseconds.checked_mul(NANOSECONDS_PER_MILLISECOND));
        let anchor = match reached.progress {
            AttemptProgressCode::NotStarted => admission.grant().issued_at(),
            AttemptProgressCode::StartedNotReleased | AttemptProgressCode::Released => reached
                .evidence
                .and_then(ResourceEvidence::resources)
                .map(crate::ReleaseResources::activated_monotonic_ns),
        };
        anchor
            .zip(watchdog)
            .and_then(|(anchor, watchdog)| attempt_watchdog_deadline(anchor, watchdog))
            .map_or(0, std::num::NonZeroU64::get)
    }

    /// TME1 `cleanup` (R9 §4.6.1). The empty basis is recorded only for a
    /// `bound` unit: a cleanup that proved the cgroup of a unit whose binding
    /// failed has no TME1 `unit` to name.
    fn cleanup_record(&self, bound: bool) -> Result<CleanupRecord, EvidenceFault> {
        let finished_at = self.cleanup_finished_at().ok_or(EvidenceFault::Clock)?;
        let (result, empty_basis) = match self.cleanup() {
            Ok(None) => (CleanupResult::NothingCommitted, None),
            Ok(Some(completed)) => (
                CleanupResult::Proved,
                completed.empty_basis().filter(|_| bound).map(Into::into),
            ),
            Err(_) => (CleanupResult::NotProved, None),
        };
        Ok(CleanupRecord {
            result,
            empty_basis,
            finished_at,
        })
    }
}

/// TME1 `progress` of a failed execution: released once its `ReleaseV1`
/// was sent, started once its unit start was requested.
fn failed_progress(
    unit: UnitState,
    started: bool,
    evidence: Option<&ResourceEvidence>,
) -> AttemptProgressCode {
    if evidence.is_some_and(|evidence| evidence.release().release().is_some()) {
        AttemptProgressCode::Released
    } else if started || unit != UnitState::NotStarted {
        AttemptProgressCode::StartedNotReleased
    } else {
        AttemptProgressCode::NotStarted
    }
}

/// TME1 `local-network` (R9 §4.6.3): a Local attempt's proxy session once
/// released; before the release, a bound proxy that never served, which is a
/// clean close.
fn local_network<S>(
    reached: &Reached<'_, S>,
    mode: SandboxExecutionMode,
) -> Option<LocalNetworkRecord> {
    match reached.network {
        Some(NetworkEvidence::Local(served)) => Some(LocalNetworkRecord {
            termination: served.session.termination().map(Into::into),
            watchdog_closed: served.watchdog_expired,
        }),
        Some(NetworkEvidence::None | NetworkEvidence::Replay(_)) => None,
        None => unserved_proxy(reached, mode),
    }
}

/// A Local attempt stopped before its release whose proxy was bound, once
/// the pre-release evidence was read: a clean close.
fn unserved_proxy<S>(
    reached: &Reached<'_, S>,
    mode: SandboxExecutionMode,
) -> Option<LocalNetworkRecord> {
    let bound = reached
        .evidence
        .and_then(ResourceEvidence::resources)
        .is_some();
    (mode == SandboxExecutionMode::Local
        && reached.progress == AttemptProgressCode::StartedNotReleased
        && bound)
        .then_some(LocalNetworkRecord {
            termination: None,
            watchdog_closed: false,
        })
}

mod response;

pub use response::{ResponseFault, RetainedResponse};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
