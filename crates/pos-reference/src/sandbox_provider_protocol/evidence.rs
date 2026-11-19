//! The ADR-069 R9 V1 attempt evidence records and their verifier, as R10
//! extends them with the provider stdio channels and the stdin feed.
//!
//! Three closed, unsigned, self-digested records carry the evidence that the
//! runtime-signed SPR1, SAU1 and RLS1 bind by digest (R9 §4):
//!
//! * [`RequestedConfigurationEvidence`] (RQE1): the transient unit's
//!   requested properties and the typed readback that verified them;
//! * [`KernelObservationEvidence`] (KOE1): the kernel observation of the
//!   released unit. Its self-digest *is* `observed_state_digest`;
//! * [`TerminationEvidence`] (TME1): everything the terminal code depends on,
//!   with the cgroup counter sources as read.
//!
//! Each record has one encoder and one strict decoder, and the encoder
//! validates by decoding what it encoded, so both directions apply the same
//! rules. A decoded record satisfies every R9 §6 rule that the record alone
//! can decide. [`AttemptEvidence::verify`] applies the rules that need the
//! three records together with their grant, ELM1 limits and `ReadyV1`,
//! [`AttemptEvidence::verify_receipt`] binds them to SPR1, and
//! [`AttemptEvidence::verify_response`] authenticates the complete signed
//! response that binds them: AGR1, the SAU1 chain, SPR1, SPY1 and the
//! `ReleaseV1` sent.
//!
//! The negative-probe digest is not a record: SPR1 ordinal 21 is the admitted
//! HCP1's ordinal 7, which [`super::AdmittedSandboxProvider`] enforces when
//! it authenticates a receipt (R9 §4.5).

mod counters;
mod observed;
mod requested;
mod terminated;

use std::ops::RangeInclusive;

use ciborium::value::Value;

use super::codec::{
    bytes_value, decode_document, digest32, encode, record_digest, self_digested, uint, uint_value,
    verify_digest,
};
use super::termination::{
    AttemptProgressCode, BarrierFailure, CancelSource, CleanupResult, Contradiction, EndingCode,
    LaunchFailure, LocalNetworkTerminationCode, MainExitCode, RequestedConfigurationStatus,
    ServiceResultCode, StartJobResult, TerminalCode,
};
use super::{
    AdmissionGrant, ExecutionRelease, LauncherReady, SandboxArchitecture, SandboxExecutionMode,
    SandboxLimit, SandboxProviderProtocolError, SandboxProviderReceipt, SandboxProviderResult,
};

pub use observed::{
    BlockIdentity, DeviceNumber, KernelObservationEvidence, KernelObservationEvidenceFields,
    KernelObservationStatus, NamespaceIdentity, ObservedKernelState, RootMount,
};
pub use requested::{
    DbusProperty, DbusValue, RequestedConfigurationEvidence, RequestedConfigurationEvidenceFields,
};
pub use terminated::{
    AdmissionLedger, CgroupEmptyBasis, CgroupSources, CleanupRecord, LocalNetworkRecord,
    OutputCaptureRecord, TerminationEvidence, TerminationEvidenceFields, TransferRecord,
};

type Result<T> = std::result::Result<T, SandboxProviderProtocolError>;

/// ELM1 limit IDs the verifier reads (ADR-069 §8).
const OUTPUT_BYTES_LIMIT: u8 = 8;
const WORK_BYTES_LIMIT: u8 = 9;
const LIVE_ATTEMPTS_LIMIT: u8 = 13;
const INCOMPLETE_INPUTS_LIMIT: u8 = 14;

/// The tmpfs block size (`f_bsize`, the page size) of an admitted
/// architecture: `/work` capacity is ELM1 limit 9 rounded up to a multiple
/// of it (R9 §4.4). `x86_64` has one page size. An `aarch64` kernel may use
/// any of three, and no admitted record (HCP1, SCS1 or the policy) pins
/// one, so each of them is a candidate.
const fn work_block_bytes(architecture: SandboxArchitecture) -> &'static [u64] {
    match architecture {
        SandboxArchitecture::X86_64 => &[4096],
        SandboxArchitecture::Aarch64 => &[4096, 16_384, 65_536],
    }
}

/// Each closed code is its R9 number, and every other number is rejected.
macro_rules! closed_codes {
    ($($name:ident: [$($variant:ident),+ $(,)?];)+) => {$(
        impl TryFrom<u8> for $name {
            type Error = SandboxProviderProtocolError;

            fn try_from(code: u8) -> Result<Self> {
                [$(Self::$variant),+]
                    .into_iter()
                    .find(|value| *value as u8 == code)
                    .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)
            }
        }

        impl From<$name> for u8 {
            fn from(value: $name) -> Self {
                value as Self
            }
        }
    )+};
}

closed_codes! {
    AttemptProgressCode: [NotStarted, StartedNotReleased, Released];
    LaunchFailure: [
        RootNotActivated, PreStartRecheckFailed, UnitRefFailed, OutputReservationRefused,
        StdioChannelFailed, AdmissionClosed,
    ];
    StartJobResult: [Done, Canceled, Timeout, Failed, Dependency, Skipped];
    Contradiction: [IdentityChanged, TimeReversed, CounterDecreased];
    ServiceResultCode: [
        Success, Resources, Protocol, Timeout, ExitCode, Signal, CoreDump, Watchdog,
        StartLimitHit, OomKill, ExecCondition,
    ];
    MainExitCode: [NotExited, Exited, Killed, Dumped];
    EndingCode: [
        CgroupEmpty, WatchdogKilled, WatchdogKillFailed, ProtocolFailureKilled,
        ProtocolFailureKillFailed, Cancelled, CancelledWatchdogKilled,
        CancelledWatchdogKillFailed,
    ];
    BarrierFailure: [
        ReadyUnavailable, ReadyFraming, ReadyPidMismatch, ReadyMalformed, ReadyMismatch,
        RecheckAuthority, RecheckObservationUnavailable, RecheckObservationChanged,
        RecheckIdentityUnreadable, RecheckExecutableUnreadable, RecheckExpired,
        RecheckUnitChanged, ReleaseSend,
    ];
    LocalNetworkTerminationCode: [
        RemoteUnavailable, DigestMismatch, ProtocolFailure, CaptureFailure, ChannelFailure,
    ];
    CancelSource: [CancelRequest, Revocation];
    CleanupResult: [Proved, NotProved, NothingCommitted];
    RequestedConfigurationStatus: [Verified, NotRequested, Mismatch, ReadbackUnavailable];
    TerminalCode: [
        Cancelled, CleanupFailed, OomKilled, MemoryLimit, TaskLimit, Watchdog,
        FileOrOutputLimit, ProcessCrash, IpcFailure, ProtocolFailure,
    ];
    CgroupEmptyBasis: [Events, Deleted];
}

/// One closed code field.
fn code<T>(value: &Value) -> Result<T>
where
    T: TryFrom<u8, Error = SandboxProviderProtocolError>,
{
    uint(value).and_then(|code| {
        u8::try_from(code)
            .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)
            .and_then(T::try_from)
    })
}

fn code_value<T: Into<u8>>(code: T) -> Value {
    uint_value(u64::from(code.into()))
}

/// A nullable field: `null`, or a value `decode` accepts.
fn optional<T>(value: &Value, decode: impl FnOnce(&Value) -> Result<T>) -> Result<Option<T>> {
    if value == &Value::Null {
        Ok(None)
    } else {
        decode(value).map(Some)
    }
}

fn optional_value<T>(value: Option<T>, encode: impl FnOnce(T) -> Value) -> Value {
    value.map_or(Value::Null, encode)
}

/// An unsigned integer within `range`.
fn uint_in(value: &Value, range: RangeInclusive<u64>) -> Result<u64> {
    uint(value).and_then(|number| {
        if range.contains(&number) {
            Ok(number)
        } else {
            Err(SandboxProviderProtocolError::FieldOutOfBounds)
        }
    })
}

/// An unsigned integer within `range`, as a `u32`.
fn u32_in(value: &Value, range: RangeInclusive<u32>) -> Result<u32> {
    uint(value).and_then(|number| {
        u32::try_from(number)
            .ok()
            .filter(|number| range.contains(number))
            .ok_or(SandboxProviderProtocolError::FieldOutOfBounds)
    })
}

/// A `digest32`, which is never 32 zero bytes (R9 §4.1).
fn digest(value: &Value) -> Result<[u8; 32]> {
    digest32(value).and_then(|digest| {
        if digest == [0; 32] {
            Err(SandboxProviderProtocolError::FieldOutOfBounds)
        } else {
            Ok(digest)
        }
    })
}

fn digest_value(digest: &[u8; 32]) -> Value {
    bytes_value(digest)
}

/// The canonical bytes of the self-digested wrapper `[unsigned, digest]`.
fn seal(magic: &str, unsigned: Vec<Value>) -> Result<Vec<u8>> {
    let unsigned = Value::Array(unsigned);
    record_digest(magic, &unsigned)
        .and_then(|digest| encode(&Value::Array(vec![unsigned, bytes_value(&digest)])))
}

/// Decode one complete self-digested record of at most `max_bytes`: its
/// fields first, then its self-digest.
fn open<T, const N: usize>(
    bytes: &[u8],
    magic: &str,
    max_bytes: usize,
    decode: impl FnOnce(&[Value; N]) -> Result<T>,
) -> Result<(T, [u8; 32])> {
    if bytes.len() > max_bytes {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    let document = decode_document(bytes)?;
    let (fields, digest) = self_digested::<N>(&document, magic)?;
    let decoded = decode(fields)?;
    verify_digest(magic, fields, digest)?;
    Ok((decoded, digest))
}

const fn consistent(holds: bool) -> Result<()> {
    if holds {
        Ok(())
    } else {
        Err(SandboxProviderProtocolError::InconsistentFields)
    }
}

/// What a verifier holds besides the three records of one attempt.
#[derive(Clone, Copy, Debug)]
pub struct AttemptEvidenceContext<'a> {
    /// AGR1 `attempt-id`.
    pub attempt_id: [u8; 16],
    /// The AGR1 self-digest.
    pub agr1_digest: [u8; 32],
    /// AGR1 `elm1-digest`.
    pub elm1_digest: [u8; 32],
    /// The ELM1 record, which must digest to `elm1_digest`.
    pub limits: EffectiveLimitRecord<'a>,
    /// The admitted execution mode.
    pub mode: SandboxExecutionMode,
    /// The admitted host architecture (HCP1 and SCS1), which fixes the
    /// `/work` block size.
    pub architecture: SandboxArchitecture,
    /// The accepted `ReadyV1`; `None` when none was accepted.
    pub ready: Option<&'a LauncherReady>,
    /// The provider's own namespaces, retained once for the runtime.
    pub provider_namespaces: &'a [NamespaceIdentity; 6],
}

/// The ELM1 a verifier holds: its limits and the other fields its
/// self-digest commits to.
#[derive(Clone, Copy, Debug)]
pub struct EffectiveLimitRecord<'a> {
    /// The effective limits.
    pub limits: &'a [SandboxLimit],
    /// The broker hard-caps digest.
    pub broker_caps_digest: [u8; 32],
    /// The APT1 digest.
    pub apt1_digest: [u8; 32],
    /// The LPS1 digest.
    pub lps1_digest: [u8; 32],
    /// The execution-profile digest.
    pub execution_profile_digest: [u8; 32],
    /// The fixture digest.
    pub fixture_digest: [u8; 32],
    /// The runtime-attestation key ID.
    pub runtime_attestation_key_id: &'a str,
}

/// The RQE1, KOE1 and TME1 of one attempt, verified together (R9 §6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptEvidence {
    requested: RequestedConfigurationEvidence,
    observed: KernelObservationEvidence,
    termination: TerminationEvidence,
}

impl AttemptEvidence {
    /// Verify the three records of one attempt against what the verifier
    /// holds. `previous` is the verified evidence whose TME1 `termination`
    /// succeeds, if it is a successor (R9 §4.7).
    ///
    /// The rules are R9 §6 rules 4, 5 and 9 and the parts of rules 2, 6 and
    /// 7 that the records, the grant and ELM1 decide: the KOE1 bindings to
    /// RQE1, `ReadyV1` and the runtime; every attempt and grant binding; the
    /// nullability that follows the mode and ELM1; the admission ledger and
    /// the output ceiling; the recomputed contradiction and terminal code;
    /// and the successor copy rule.
    ///
    /// # Errors
    /// `InconsistentFields` when any rule fails.
    pub fn verify(
        requested: RequestedConfigurationEvidence,
        observed: KernelObservationEvidence,
        termination: TerminationEvidence,
        previous: Option<&Self>,
        context: &AttemptEvidenceContext<'_>,
    ) -> Result<Self> {
        let evidence = Self {
            requested,
            observed,
            termination,
        };
        let limits = Limits::of(&context.limits, context.elm1_digest)?;
        consistent(
            evidence.bound(context)
                && evidence.observation_bound(context, limits.work)
                && evidence.termination_shaped(context.mode, limits.work)
                && evidence.ledger_within(limits)
                && evidence.classified()
                && evidence.chained(previous),
        )
        .map(|()| evidence)
    }

    /// Verify that SPR1 binds these records (R9 §6 rules 5 and 6): the
    /// attempt, grant and ELM1; ordinals 19, 20 and 22; the `ReadyV1` digest
    /// that KOE1 binds; and a `ReleaseV1` exactly when TME1 progress is 2.
    ///
    /// Ordinal 21 is checked against the admitted HCP1 when the receipt is
    /// authenticated.
    ///
    /// # Errors
    /// `InconsistentFields` when a binding fails.
    pub fn verify_receipt(&self, receipt: &SandboxProviderReceipt) -> Result<()> {
        let termination = self.termination.fields();
        consistent(
            receipt.attempt_id == termination.attempt_id
                && [receipt.authority.agr1_digest, receipt.elm1_digest]
                    == [termination.agr1_digest, termination.elm1_digest]
                && [
                    receipt.requested_configuration_evidence,
                    receipt.kernel_observation_evidence,
                    receipt.termination_evidence,
                ] == [
                    self.requested.digest(),
                    self.observed.digest(),
                    self.termination.digest(),
                ]
                && receipt.ready1_digest == self.observed.fields().status.ready1_digest()
                && receipt.release1_digest.is_some()
                    == (termination.progress == AttemptProgressCode::Released),
        )
    }

    /// Authenticate the complete signed response of this attempt under
    /// `key`, the admitted runtime-attestation key (R9 §6 rules 5, 6, 8 and
    /// 10, with ADR-069 §4).
    ///
    /// Every signed record must verify under `key`. AGR1 must be the grant
    /// SPR1 and SPY1 name, with its request, attempt, ELM1, authority and
    /// epochs. SPR1 must bind these records and copy
    /// `negative_probe_evidence`, the admitted HCP1 ordinal 7. The SAU1 chain
    /// must be complete and bind KOE1 (events 11 to 13) and TME1 (events 0
    /// to 10). SPY1's outcome and its terminal event must be TME1's terminal
    /// code, and a `ReleaseV1` exists exactly when SPR1 names one: it binds
    /// the KOE1 digest, which must then have status 0. A `Completed` SPY1's
    /// output descriptor must be exactly as long as TME1
    /// `output-capture.accepted-bytes` (R10 I6).
    ///
    /// # Errors
    /// The decoders' closed errors, `SignatureInvalid` for a signature that
    /// does not verify under `key`, and `InconsistentFields` when a binding
    /// fails.
    pub fn verify_response(
        &self,
        response: &AttemptResponse<'_>,
        negative_probe_evidence: [u8; 32],
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        let grant = AdmissionGrant::from_canonical_cbor(response.grant)?;
        grant.verify_signature(key)?;
        let receipt = SandboxProviderReceipt::from_canonical_cbor(response.receipt)?;
        receipt.verify_signature(key)?;
        let result = SandboxProviderResult::from_canonical_cbor(response.result)?;
        result.verify_signature(key)?;
        self.verify_receipt(&receipt)?;
        result.validate_receipt_lifecycle(&receipt)?;
        super::audit::authenticate_audit_chain(response.audit, &receipt, &result, key)?;
        consistent(
            granted(&grant, &receipt, &result)
                && receipt.negative_probe_evidence == negative_probe_evidence
                && self.reported(&result),
        )?;
        self.released(response.release, &receipt, key)
    }

    /// Rule 8: SPY1's outcome is the one TME1's code selects, and its last
    /// event is that code; `Completed` has no terminal event, and code 0
    /// never occurs. A `Completed` output descriptor is exactly as long as
    /// the captured output TME1 records (R10 I6).
    fn reported(&self, result: &SandboxProviderResult) -> bool {
        let termination = self.termination.fields();
        let code = termination.terminal_code;
        let outcome = self
            .termination
            .facts(&self.requested, &self.observed)
            .classify()
            .outcome();
        result.outcome == outcome
            && code.is_none_or(|code| result.operational_events.last() == Some(&code.code()))
            && result.output.as_ref().is_none_or(|output| {
                termination
                    .output_capture
                    .is_some_and(|capture| capture.accepted_bytes == output.byte_length)
            })
    }

    /// Rule 6's RLS1 binding: a `ReleaseV1` exactly when SPR1 names one,
    /// signed under `key`, for this attempt and `ReadyV1`, under SPR1's
    /// authority, with the KOE1 digest of a status 0 observation.
    fn released(
        &self,
        release: Option<&[u8]>,
        receipt: &SandboxProviderReceipt,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        match (release, receipt.release1_digest) {
            (None, None) => Ok(()),
            (Some(bytes), Some(digest)) => {
                let release = ExecutionRelease::from_canonical_cbor(bytes)?;
                release.verify_signature(key)?;
                let fields = release.fields();
                consistent(
                    release.digest() == digest
                        && fields.attempt_id == receipt.attempt_id
                        && Some(fields.ready1_digest) == receipt.ready1_digest
                        && [fields.trs1_digest, fields.rvs1_digest, fields.apt1_digest]
                            == [
                                receipt.authority.trs1_digest,
                                receipt.authority.rvs1_digest,
                                receipt.authority.apt1_digest,
                            ]
                        && [
                            fields.trust_epoch,
                            fields.revocation_epoch,
                            fields.policy_epoch,
                        ] == [
                            receipt.trust_epoch,
                            receipt.revocation_epoch,
                            receipt.policy_epoch,
                        ]
                        && fields.runtime_attestation_key_id == receipt.runtime_attestation_key_id
                        && fields.observed_readback_digest == self.observed.digest()
                        && matches!(
                            self.observed.fields().status,
                            KernelObservationStatus::Observed { .. }
                        ),
                )
            }
            _ => consistent(false),
        }
    }

    /// Rule 5, and rule 6's RQE1 binding: one attempt and grant throughout,
    /// TME1 binds KOE1 and ELM1, KOE1 binds RQE1, and RQE1 is
    /// `NotRequested` exactly when TME1 progress is 0.
    fn bound(&self, context: &AttemptEvidenceContext<'_>) -> bool {
        let (requested, observed, termination) = (
            self.requested.fields(),
            self.observed.fields(),
            self.termination.fields(),
        );
        [
            requested.attempt_id,
            observed.attempt_id,
            termination.attempt_id,
        ] == [context.attempt_id; 3]
            && [
                requested.agr1_digest,
                observed.agr1_digest,
                termination.agr1_digest,
                termination.elm1_digest,
                termination.koe1_digest,
                observed.requested_configuration_evidence,
            ] == [
                context.agr1_digest,
                context.agr1_digest,
                context.agr1_digest,
                context.elm1_digest,
                self.observed.digest(),
                self.requested.digest(),
            ]
            && (requested.status == RequestedConfigurationStatus::NotRequested)
                == (termination.progress == AttemptProgressCode::NotStarted)
    }

    /// Rule 4: KOE1 binds exactly the accepted `ReadyV1`, and an observation
    /// agrees with it, with the runtime's namespaces and with ELM1 limit 9.
    fn observation_bound(&self, context: &AttemptEvidenceContext<'_>, work_limit: u64) -> bool {
        match (&self.observed.fields().status, context.ready) {
            (KernelObservationStatus::NotReached, None) => true,
            (KernelObservationStatus::ObservationFailed { ready1_digest }, Some(ready)) => {
                *ready1_digest == ready.digest
            }
            (
                KernelObservationStatus::Observed {
                    ready1_digest,
                    observation,
                },
                Some(ready),
            ) => {
                *ready1_digest == ready.digest
                    && observation.matches_ready(ready, context.provider_namespaces)
                    && work_capacity_matches(
                        observation.work,
                        work_limit,
                        work_block_bytes(context.architecture),
                    )
            }
            _ => false,
        }
    }

    /// Rule 2's nullability that follows the mode and ELM1 limit 9
    /// (R9 §4.6.3): `local-network` and `work-after`.
    fn termination_shaped(&self, mode: SandboxExecutionMode, work_limit: u64) -> bool {
        let termination = self.termination.fields();
        let released = termination.progress == AttemptProgressCode::Released;
        let local = mode == SandboxExecutionMode::Local;
        let network = termination.local_network.is_some();
        self.work_after_shaped(work_limit)
            && if released {
                local == network
            } else {
                local || !network
            }
    }

    /// `work-after` may be present only when ELM1 limit 9 is nonzero and
    /// KOE1 has status 0: `/work` is read only through the handle that
    /// observation opened. It is required then, but a null one is missing
    /// evidence (code 2), not a shape error; after a failed KOE1 (status 1
    /// or 2) it is null and no evidence is missing (owner decision
    /// 2026-11-19, R9 amendment review).
    const fn work_after_shaped(&self, work_limit: u64) -> bool {
        let observed = matches!(
            self.observed.fields().status,
            KernelObservationStatus::Observed { .. }
        );
        self.termination.fields().work_after.is_none() || (work_limit != 0 && observed)
    }

    /// Rule 9: the admission ledger is within ELM1 IDs 13 and 14, and the
    /// output capture accepts at most ELM1 ID 8 bytes and reaches the
    /// ceiling only at exactly that many (R10 §4.6).
    fn ledger_within(&self, limits: Limits) -> bool {
        let termination = self.termination.fields();
        termination.admission.active_attempts <= limits.live_attempts
            && termination.admission.incomplete_inputs <= limits.incomplete_inputs
            && termination.output_capture.is_none_or(|capture| {
                capture.accepted_bytes <= limits.output
                    && (!capture.ceiling_reached || capture.accepted_bytes == limits.output)
            })
    }

    /// Rule 7: the recorded contradiction and terminal code are the ones
    /// R9 §4.6.4 and §4.6.5 select.
    fn classified(&self) -> bool {
        let classification = self
            .termination
            .facts(&self.requested, &self.observed)
            .classify();
        let termination = self.termination.fields();
        classification.contradiction() == termination.contradiction
            && classification.code() == termination.terminal_code
    }

    /// Rule 7's chain: a first TME1 names no predecessor, and a successor
    /// names the one verified first TME1 it copies (R9 §4.7).
    fn chained(&self, previous: Option<&Self>) -> bool {
        match (self.termination.fields().previous_tme1_digest, previous) {
            (None, None) => true,
            (Some(digest), Some(previous)) => {
                digest == previous.termination.digest()
                    && self.termination.succeeds(&previous.termination)
            }
            _ => false,
        }
    }
}

/// One complete post-admission `execute` response, without its output
/// SBC1 records, and the `ReleaseV1` the provider sent (ADR-069 §4).
#[derive(Clone, Copy, Debug)]
pub struct AttemptResponse<'a> {
    /// The AGR1 bytes.
    pub grant: &'a [u8],
    /// The SAU1 chain, from sequence zero.
    pub audit: &'a [Vec<u8>],
    /// The SPR1 bytes.
    pub receipt: &'a [u8],
    /// The SPY1 bytes.
    pub result: &'a [u8],
    /// The `ReleaseV1` bytes; `None` when none was sent.
    pub release: Option<&'a [u8]>,
}

/// AGR1 is the grant that SPR1 and SPY1 name: its request, attempt, ELM1,
/// key, the authority digests both records carry, and the epochs.
fn granted(
    grant: &AdmissionGrant,
    receipt: &SandboxProviderReceipt,
    result: &SandboxProviderResult,
) -> bool {
    let (admitted, received) = (&grant.authority, &receipt.authority);
    let by_grant = (
        [grant.request_id, grant.attempt_id],
        [
            grant.grant_digest(),
            grant.elm1_digest,
            admitted.hcp1_digest,
            admitted.spm1_digest,
            admitted.lps1_digest,
            admitted.sim1_digest,
            admitted.apt1_digest,
            admitted.trs1_digest,
            admitted.rvs1_digest,
        ],
        [
            grant.trust_epoch,
            grant.revocation_epoch,
            grant.policy_epoch,
        ],
        grant.runtime_attestation_key_id.as_str(),
    );
    let by_records = (
        [result.request_id, receipt.attempt_id],
        [
            received.agr1_digest,
            receipt.elm1_digest,
            receipt.hcp1_digest,
            received.spm1_digest,
            received.lps1_digest,
            received.sim1_digest,
            received.apt1_digest,
            received.trs1_digest,
            received.rvs1_digest,
        ],
        [
            receipt.trust_epoch,
            receipt.revocation_epoch,
            receipt.policy_epoch,
        ],
        receipt.runtime_attestation_key_id.as_str(),
    );
    by_grant == by_records
}

/// The ELM1 limits the verifier reads.
#[derive(Clone, Copy)]
struct Limits {
    output: u64,
    work: u64,
    live_attempts: u64,
    incomplete_inputs: u64,
}

impl Limits {
    /// The limits of `record`, once it digests to `elm1_digest`.
    fn of(record: &EffectiveLimitRecord<'_>, elm1_digest: [u8; 32]) -> Result<Self> {
        let digest = super::admission::effective_limits_digest(
            record.limits,
            record.broker_caps_digest,
            record.apt1_digest,
            record.lps1_digest,
            record.execution_profile_digest,
            record.fixture_digest,
            record.runtime_attestation_key_id,
        )?;
        consistent(digest == elm1_digest)?;
        let limit = |id| {
            record
                .limits
                .iter()
                .find(|limit| limit.limit_id == id)
                .map(|limit| limit.value)
                .ok_or(SandboxProviderProtocolError::InconsistentFields)
        };
        Ok(Self {
            output: limit(OUTPUT_BYTES_LIMIT)?,
            work: limit(WORK_BYTES_LIMIT)?,
            live_attempts: limit(LIVE_ATTEMPTS_LIMIT)?,
            incomplete_inputs: limit(INCOMPLETE_INPUTS_LIMIT)?,
        })
    }
}

/// KOE1 `work` is null exactly when ELM1 limit 9 is zero, and otherwise its
/// capacity is exactly the limit rounded up to one of `blocks`.
fn work_capacity_matches(work: Option<super::WorkMountFacts>, limit: u64, blocks: &[u64]) -> bool {
    work.map_or(limit == 0, |work| {
        limit != 0
            && blocks.iter().any(|block| {
                limit.div_ceil(*block).checked_mul(*block) == Some(work.capacity_bytes)
            })
    })
}
