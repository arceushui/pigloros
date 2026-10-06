//! ADR-105 `FAE1` authority import: the purpose-specific port and the
//! adapter-independent validation, recovery, and install plan.
//!
//! The port accepts complete `FAE1` bytes, the locally pinned issuer-policy
//! digest, the already present parent Timeline, and the host's trusted
//! Timeline-integrity anchors. It accepts no caller-selected creator, key,
//! classifier, publication field, origin, or trust root.
//!
//! Both adapters share one orchestration. Before any mutation it decodes the
//! envelope and its closure, looks up the import operation ID, admits the
//! issuer under the current policy, verifies the issuer signature, the parent
//! Timeline, the #202 Event evidence, and the `FSM1` signature. Inside one
//! adapter transaction it repeats the lookup and every occupancy check,
//! stages the child Timeline, checks the staged range (#411 or the
//! empty-segment rule) and the final chain hash, and installs every row. The
//! adapters supply only the storage primitives of [`ImportBackendV1`].
//!
//! The `FAR1` descriptor and composition fields (room revision descriptor
//! hash, plugin composition hash, and the fold and tick coordinates) are
//! source claims that the pinned issuer authenticates. The destination holds
//! no independent value to compare them with, so the import compares them
//! only with the other carried records (`FRM1`, `FPO1`, `FCS1`, `FCT1`, and
//! `FCR1`) and never with destination state.
//!
//! Decisions the ADR leaves open, recorded here:
//!
//! - Parent and identity equalities (the requested parent, an absent parent,
//!   and the `FTI1` owner against the parent owner) are
//!   `InvalidAuthorityClosure`. Range and chain-hash checks (a parent below
//!   the cut, the parent or final chain hash, the #411 range, and the
//!   empty-segment head) are `InvalidRangeEvidence`. Every #202 failure is
//!   `InvalidEventEvidence`.
//! - State under an import operation ID that the admission row does not
//!   cover (key evidence without an admission) is partial or orphan state and
//!   `CorruptAuthority`. A row that names only the child, a publication, or
//!   another semantic key, without anything under the operation ID, is an
//!   occupied key and a `Conflict` (R6.8 step 3).
//! - A Principal already bound to an equal Owner, locally or by an earlier
//!   import, is not an occupancy conflict (erratum E10); the import keeps its
//!   own `POB1` under its import operation ID in an imported store, so the
//!   local Principal table never holds a second binding for it.

use std::collections::HashMap;

use pos_core::{
    is_geographic_event_type,
    store::{EventStore, SeqRange, TimelineExport},
    CoreError, EventId, ForkAppendOperationV1, ForkAttributionAuthorityEnvelopeV1,
    ForkAttributionCodecErrorV1, ForkAttributionImportClosureErrorV1,
    ForkAttributionImportClosureV1, ForkTimelineImportInputV1, Hash,
    ImportedForkAttributionAdmissionV1, ImportedKeyRecordV1, ImportedKeyTombstoneV1, KeyIdentityV1,
    PublicKey, Seq, TimelineEventVerificationV1, TimelineId,
};
use pos_crypto::{
    fork_attribution::verify_local_fork_manifest_signature_only,
    fork_attribution_authority::verify_fork_attribution_authority_envelope_signature_v1,
};

use crate::{
    verify_signed_timeline_range_v1, verify_timeline_import_v1,
    ForkAttributionIssuerAdmissionBasisV1, ForkAttributionIssuerAdmissionQueryV1,
    ForkAttributionIssuerPolicyErrorV1 as PolicyError,
    ForkAttributionIssuerPolicyInstallationPortV1, TimelineSignedRangeClaimV1,
};

/// One `FAE1` import request from the trusted composition boundary.
#[derive(Clone, Copy, Debug)]
pub struct ForkAttributionAuthorityImportRequestV1<'a> {
    /// The complete canonical `FAE1` bytes. The import operation ID is
    /// `FAE1` field 2 and is the only recovery key.
    pub envelope_bytes: &'a [u8],
    /// The locally pinned digest of the issuer policy the operator expects
    /// to admit this import; it must equal `FAE1` field 4.
    pub expected_issuer_policy_digest: Hash,
    /// The already present parent Timeline; it must equal the `FTI1` parent.
    pub parent_timeline_id: TimelineId,
    /// The host's exact Timeline-integrity trust anchors for #202 and #411.
    pub trust_anchors: &'a [(KeyIdentityV1, PublicKey)],
}

/// The immutable receipt of one committed `FAE1` import.
///
/// An exact retry returns the original receipt byte for byte.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionAuthorityImportReceiptV1 {
    /// The committed `IFA1` import admission.
    pub admission: ImportedForkAttributionAdmissionV1,
}

impl ForkAttributionAuthorityImportReceiptV1 {
    /// The canonical bytes of the committed `IFA1` admission.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.admission.to_canonical_cbor()
    }
}

/// The closed public errors of the `FAE1` import (ADR-105 section 6).
///
/// Validation errors expose no imported record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAttributionAuthorityImportErrorV1 {
    /// The envelope or a carried record does not decode strictly.
    #[error("Fork attribution import encoding is invalid")]
    InvalidEncoding,
    /// The envelope declares an unsupported version.
    #[error("Fork attribution import version is unsupported")]
    UnsupportedVersion,
    /// The envelope exceeds an envelope-level byte or count bound.
    #[error("Fork attribution import exceeds a bound")]
    BoundsExceeded,
    /// The issuer is unknown, or no issuer policy admits new imports.
    #[error("Fork attribution issuer is not trusted")]
    UntrustedIssuer,
    /// The issuer is `Retired` and cannot authorize a new import.
    #[error("Fork attribution issuer is retired")]
    IssuerRetired,
    /// The issuer is `Revoked`.
    #[error("Fork attribution issuer is revoked")]
    IssuerRevoked,
    /// The pinned or envelope policy digest is not the current floor.
    #[error("Fork attribution issuer policy changed")]
    PolicyChanged,
    /// The issuer or `FSM1` signature does not verify.
    #[error("Fork attribution import signature is invalid")]
    InvalidSignature,
    /// The #202 Event evidence, trust anchors, or destination registry
    /// reject the child segment.
    #[error("Fork attribution import Event evidence is invalid")]
    InvalidEventEvidence,
    /// The parent cut, #411 range, empty-segment head, or final chain hash
    /// rejects the child segment.
    #[error("Fork attribution import range evidence is invalid")]
    InvalidRangeEvidence,
    /// The carried records do not form one consistent authority closure, or
    /// the parent Timeline or its owner does not match.
    #[error("Fork attribution import authority closure is invalid")]
    InvalidAuthorityClosure,
    /// The import operation was reused unequally, or a semantic key is held.
    #[error("Fork attribution import conflicts with committed state")]
    Conflict,
    /// Committed state is partial, orphaned, inconsistent, or tampered.
    #[error("Fork attribution authority state is corrupt")]
    CorruptAuthority,
    /// A storage failure left the outcome unknown; retry identical bytes.
    #[error("Fork attribution import storage outcome is indeterminate")]
    StorageIndeterminate,
}

type ImportError = ForkAttributionAuthorityImportErrorV1;
type Receipt = ForkAttributionAuthorityImportReceiptV1;
type Request<'a> = ForkAttributionAuthorityImportRequestV1<'a>;

impl From<ForkAttributionCodecErrorV1> for ForkAttributionAuthorityImportErrorV1 {
    /// Map an envelope decode failure (erratum E5 and E9).
    fn from(error: ForkAttributionCodecErrorV1) -> Self {
        match error {
            ForkAttributionCodecErrorV1::UnsupportedVersion => Self::UnsupportedVersion,
            ForkAttributionCodecErrorV1::FieldOutOfBounds => Self::BoundsExceeded,
            ForkAttributionCodecErrorV1::FieldMismatch => Self::InvalidAuthorityClosure,
            ForkAttributionCodecErrorV1::InvalidEncoding
            | ForkAttributionCodecErrorV1::NonCanonical
            | ForkAttributionCodecErrorV1::ImportedAuthorityUnavailable
            | ForkAttributionCodecErrorV1::InterventionOrder => Self::InvalidEncoding,
        }
    }
}

impl From<ForkAttributionImportClosureErrorV1> for ForkAttributionAuthorityImportErrorV1 {
    fn from(error: ForkAttributionImportClosureErrorV1) -> Self {
        match error {
            ForkAttributionImportClosureErrorV1::InvalidEncoding => Self::InvalidEncoding,
            ForkAttributionImportClosureErrorV1::InvalidAuthorityClosure => {
                Self::InvalidAuthorityClosure
            }
        }
    }
}

impl From<CoreError> for ForkAttributionAuthorityImportErrorV1 {
    /// A store read or write failure never proves what was committed.
    fn from(_: CoreError) -> Self {
        Self::StorageIndeterminate
    }
}

/// Map an issuer admission failure for a wholly absent import (step 4).
///
/// A missing policy or an invalid key leaves no trusted issuer. The install
/// variants cannot come from an admission and are corrupt policy state.
const fn absent_policy_failure(error: PolicyError) -> ImportError {
    match error {
        PolicyError::PolicyChanged => ImportError::PolicyChanged,
        PolicyError::IssuerRetired => ImportError::IssuerRetired,
        PolicyError::IssuerRevoked => ImportError::IssuerRevoked,
        PolicyError::StorageIndeterminate => ImportError::StorageIndeterminate,
        PolicyError::UntrustedIssuer
        | PolicyError::PolicyUnavailable
        | PolicyError::InvalidIssuerKey => ImportError::UntrustedIssuer,
        PolicyError::CorruptPolicy
        | PolicyError::InvalidEncoding
        | PolicyError::UnsupportedVersion
        | PolicyError::BoundsExceeded
        | PolicyError::PinMismatch
        | PolicyError::ScopeMismatch
        | PolicyError::Rollback
        | PolicyError::GenerationConflict
        | PolicyError::GenerationSkipped
        | PolicyError::WrongPredecessor
        | PolicyError::HistoryExhausted
        | PolicyError::IllegalTransition
        | PolicyError::NoOpSuccessor
        | PolicyError::NoActiveIssuer => ImportError::CorruptAuthority,
    }
}

/// Map an issuer admission failure for a committed import (step 3).
///
/// A committed import was admitted by its recorded policy, so every policy
/// verdict other than a storage failure is corrupt authority (the #517
/// obligation: `IssuerRetired` and `IssuerRevoked` included).
const fn committed_policy_failure(error: PolicyError) -> ImportError {
    if matches!(error, PolicyError::StorageIndeterminate) {
        ImportError::StorageIndeterminate
    } else {
        ImportError::CorruptAuthority
    }
}

/// The stored admission row of one committed import.
#[derive(Clone)]
pub(crate) struct StoredImportV1 {
    /// The stored canonical `IFA1` bytes.
    pub(crate) admission_bytes: Vec<u8>,
    /// The stored canonical `FAE1` bytes.
    pub(crate) envelope_bytes: Vec<u8>,
    /// The stored full-envelope digest.
    pub(crate) envelope_digest: Hash,
}

/// One decoded and closure-validated `FAE1`.
pub(crate) struct PreparedImportV1 {
    pub(crate) envelope: ForkAttributionAuthorityEnvelopeV1,
    pub(crate) closure: ForkAttributionImportClosureV1,
    pub(crate) export: TimelineExport,
    pub(crate) bytes: Vec<u8>,
}

impl PreparedImportV1 {
    /// Import steps 1 and 2 plus every store-independent closure equality.
    fn decode(bytes: &[u8]) -> Result<Self, ImportError> {
        let envelope = ForkAttributionAuthorityEnvelopeV1::from_canonical_cbor(bytes)?;
        let closure = ForkAttributionImportClosureV1::validate(&envelope)?;
        let export = envelope.unsigned().timeline_export();
        if export
            .events
            .iter()
            .any(|event| is_geographic_event_type(&event.event_type))
        {
            return Err(ImportError::InvalidEventEvidence);
        }
        Ok(Self {
            envelope,
            closure,
            export,
            bytes: bytes.to_vec(),
        })
    }

    pub(crate) const fn import_operation_id(&self) -> Hash {
        self.envelope.unsigned().input().import_operation_id
    }

    /// `FTI1`, the child-segment projection.
    pub(crate) const fn fork(&self) -> &ForkTimelineImportInputV1 {
        self.envelope.unsigned().input().timeline_import.input()
    }

    const fn final_head(&self) -> u64 {
        self.envelope
            .unsigned()
            .input()
            .timeline_import
            .final_logical_head()
    }

    /// The `IFA1` admission that this envelope earns under `generation`, a
    /// `FIP1` generation that `admit_issuer` returned.
    fn admission(&self, generation: u64) -> ImportedForkAttributionAdmissionV1 {
        ImportedForkAttributionAdmissionV1::from_admitted(&self.envelope, generation)
    }

    /// Whether a stored `IFA1` names exactly this envelope, whatever policy
    /// generation admitted it.
    fn is_admitted_by(&self, admission: &ImportedForkAttributionAdmissionV1) -> bool {
        let fields = admission.input();
        let unsigned = self.envelope.unsigned();
        let input = unsigned.input();
        fields.import_operation_id == input.import_operation_id
            && fields.authority_origin_digest == unsigned.authority_origin_digest()
            && fields.full_envelope_digest == self.envelope.full_envelope_digest()
            && fields.issuer == input.issuer
            && fields.issuer_policy_digest == input.issuer_policy_digest
            && fields.child_timeline_id == self.fork().child_timeline_id
            && fields.final_logical_head == self.final_head()
            && fields.closure_root == unsigned.closure_root()
            && fields.fork_admission_digest == self.closure.fork_admission_digest()
    }

    const fn plan(&self, admission: ImportedForkAttributionAdmissionV1) -> InstallPlanV1<'_> {
        InstallPlanV1 {
            prepared: self,
            admission,
        }
    }
}

/// Everything an adapter needs to read or write one import's rows.
pub(crate) struct InstallPlanV1<'a> {
    pub(crate) prepared: &'a PreparedImportV1,
    pub(crate) admission: ImportedForkAttributionAdmissionV1,
}

impl InstallPlanV1<'_> {
    pub(crate) const fn closure(&self) -> &ForkAttributionImportClosureV1 {
        &self.prepared.closure
    }

    pub(crate) const fn import_operation_id(&self) -> Hash {
        self.prepared.import_operation_id()
    }

    pub(crate) const fn child(&self) -> TimelineId {
        self.prepared.fork().child_timeline_id
    }

    pub(crate) const fn final_head(&self) -> u64 {
        self.prepared.final_head()
    }

    pub(crate) const fn key_record(&self) -> ImportedKeyRecordV1 {
        self.prepared.envelope.unsigned().input().key_record
    }

    pub(crate) const fn key_tombstone(&self) -> Option<ImportedKeyTombstoneV1> {
        self.prepared.envelope.unsigned().input().key_tombstone
    }

    /// The child Events in logical-sequence order.
    pub(crate) fn event_ids(&self) -> Vec<EventId> {
        self.closure()
            .event_origins()
            .iter()
            .map(|record| record.input().event_id)
            .collect()
    }

    /// The local sequence of each Event beside its `FOP1`, in order.
    #[cfg(feature = "sqlite")]
    pub(crate) fn local_sequences(&self) -> Vec<u64> {
        self.prepared
            .export
            .events
            .iter()
            .map(|event| event.seq.as_u64())
            .collect()
    }
}

/// The canonical bytes of every row one import installs, or the bytes an
/// adapter finds under the same keys.
///
/// A missing row is `None`; a retry is complete only when the stored rows
/// equal the expected rows exactly, which also rejects an extra `FCT1`,
/// `FCR1`, `FOP1`, `EOR1`, or `FIA1` for the child.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InstalledRowsV1 {
    pub(crate) binding: Option<Vec<u8>>,
    pub(crate) admission: Option<Vec<u8>>,
    pub(crate) origins: Vec<Option<Vec<u8>>>,
    pub(crate) interventions: Vec<Option<Vec<u8>>>,
    pub(crate) source: Option<Vec<u8>>,
    pub(crate) table: Option<Vec<u8>>,
    pub(crate) registration: Option<Vec<u8>>,
    pub(crate) operations: Vec<Vec<u8>>,
    pub(crate) publication_operation: Option<Vec<u8>>,
    pub(crate) publication_binding: Option<Vec<u8>>,
    pub(crate) publication_artifact: Option<Vec<u8>>,
    pub(crate) key_record: Option<Vec<u8>>,
    pub(crate) key_tombstone: Option<Vec<u8>>,
}

impl InstalledRowsV1 {
    /// The rows that the closure of `plan` installs.
    pub(crate) fn expected(plan: &InstallPlanV1<'_>) -> Self {
        let closure = plan.closure();
        let interventions = closure
            .intervention_admissions()
            .iter()
            .map(|record| (record.input().event_id, record.to_canonical_cbor()))
            .collect::<HashMap<_, _>>();
        let graph = closure.classifier();
        Self {
            binding: Some(closure.principal_owner_binding().to_canonical_cbor()),
            admission: Some(closure.fork_admission().to_canonical_cbor()),
            origins: closure
                .event_origins()
                .iter()
                .map(|record| Some(record.to_canonical_cbor()))
                .collect(),
            interventions: plan
                .event_ids()
                .iter()
                .map(|event_id| interventions.get(event_id).cloned())
                .collect(),
            source: graph.map(|graph| graph.source.to_canonical_cbor()),
            table: graph.map(|graph| graph.table.to_canonical_cbor()),
            registration: graph.map(|graph| graph.registration.to_canonical_cbor()),
            operations: closure
                .append_operations()
                .iter()
                .map(ForkAppendOperationV1::to_canonical_cbor)
                .collect(),
            publication_operation: Some(closure.publication_operation().to_canonical_cbor()),
            publication_binding: Some(closure.publication_binding().to_canonical_cbor()),
            publication_artifact: Some(closure.publication_artifact().to_canonical_cbor()),
            key_record: Some(plan.key_record().to_canonical_cbor()),
            key_tombstone: plan
                .key_tombstone()
                .as_ref()
                .map(ImportedKeyTombstoneV1::to_canonical_cbor),
        }
    }
}

/// The storage primitives of one adapter for the `FAE1` import.
///
/// Every read is exact and fails closed. `occupied` and `install_rows` run
/// only inside [`Self::atomically`], which is one adapter transaction: all
/// staged and installed rows become visible together or not at all.
pub(crate) trait ImportBackendV1:
    EventStore + ForkAttributionIssuerPolicyInstallationPortV1
{
    /// The stored admission row for one import operation ID, if any.
    fn read_stored_import(
        &self,
        import_operation_id: Hash,
    ) -> Result<Option<StoredImportV1>, ImportError>;

    /// Whether imported key evidence is stored under the operation ID.
    fn has_key_evidence(&self, import_operation_id: Hash) -> Result<bool, ImportError>;

    /// The rows found under the keys of `plan`, exactly as stored.
    fn read_installed(&self, plan: &InstallPlanV1<'_>) -> Result<InstalledRowsV1, ImportError>;

    /// Whether any new semantic key of `plan` is held, and
    /// `CorruptAuthority` when a referenced imported `FCS1` row differs.
    fn occupied(&self, plan: &InstallPlanV1<'_>) -> Result<bool, ImportError>;

    /// Stage the child Timeline and its Events in the open transaction.
    fn stage_child(&mut self, export: &TimelineExport) -> Result<(), ImportError>;

    /// Insert every row of `plan`, reusing an identical imported `FCS1`.
    fn install_rows(&mut self, plan: &InstallPlanV1<'_>) -> Result<(), ImportError>;

    /// Run `body` as one transaction: commit its success, or leave nothing
    /// visible on failure. An unknown outcome is `StorageIndeterminate`.
    fn atomically<T, F>(&mut self, child: TimelineId, body: F) -> Result<T, ImportError>
    where
        F: FnOnce(&mut Self) -> Result<T, ImportError>;
}

/// The purpose-specific `FAE1` import port (ADR-105 section 5).
///
/// It is the only way to install authority-origin code 2. It never routes
/// through `import_timeline_with_id` and exposes no structural fallback.
/// Imported code-2 rows stay unreadable through the trusted reads until
/// #519.
pub trait ForkAttributionAuthorityImportPortV1:
    ForkAttributionIssuerPolicyInstallationPortV1
{
    /// Validate and atomically install one `FAE1`, or recover its committed
    /// receipt.
    ///
    /// A byte-identical committed import returns its original receipt
    /// without consulting current policy. A different complete envelope or
    /// any occupied key is `Conflict`, partial or inconsistent state is
    /// `CorruptAuthority`, and an uncertain commit is `StorageIndeterminate`;
    /// retry the identical bytes.
    ///
    /// # Errors
    /// Returns a closed import error, and makes nothing visible, when any
    /// check or the atomic store transition fails.
    fn import_verified(
        &mut self,
        request: &ForkAttributionAuthorityImportRequestV1<'_>,
    ) -> Result<ForkAttributionAuthorityImportReceiptV1, ForkAttributionAuthorityImportErrorV1>;
}

/// Run one `FAE1` import against an adapter.
pub(crate) fn run_import<S: ImportBackendV1>(
    store: &mut S,
    request: &Request<'_>,
) -> Result<Receipt, ImportError> {
    let prepared = PreparedImportV1::decode(request.envelope_bytes)?;
    if let Some(receipt) = recover(&*store, &prepared)? {
        return Ok(receipt);
    }
    precheck(&*store, &prepared, request)?;
    let child = prepared.fork().child_timeline_id;
    store.atomically(child, |store| install_absent(store, &prepared, request))
}

/// Import step 3: look up the import operation ID before any current-policy
/// admission.
///
/// A complete committed graph is revalidated from its stored bytes. It is the
/// original receipt for identical request bytes and a `Conflict` for any other
/// envelope; partial or orphan state is `CorruptAuthority`.
fn recover<S: ImportBackendV1>(
    store: &S,
    prepared: &PreparedImportV1,
) -> Result<Option<Receipt>, ImportError> {
    let operation_id = prepared.import_operation_id();
    let Some(stored) = store.read_stored_import(operation_id)? else {
        return if store.has_key_evidence(operation_id)? {
            Err(ImportError::CorruptAuthority)
        } else {
            Ok(None)
        };
    };
    let committed = revalidate(store, operation_id, &stored)?;
    if stored.envelope_bytes == prepared.bytes {
        Ok(Some(committed))
    } else {
        Err(ImportError::Conflict)
    }
}

/// Revalidate one committed import from its stored bytes alone: the stored
/// admission and accepted `FIP1`, every installed row, and the child
/// Timeline. It never reads the current policy.
fn revalidate<S: ImportBackendV1>(
    store: &S,
    operation_id: Hash,
    stored: &StoredImportV1,
) -> Result<Receipt, ImportError> {
    let corrupt = ImportError::CorruptAuthority;
    let prepared = PreparedImportV1::decode(&stored.envelope_bytes)
        .ok()
        .ok_or(corrupt)?;
    let admission =
        ImportedForkAttributionAdmissionV1::from_canonical_cbor(&stored.admission_bytes)
            .ok()
            .ok_or(corrupt)?;
    let generation = admission.input().issuer_policy_generation;
    let consistent = prepared.import_operation_id() == operation_id
        && prepared.envelope.full_envelope_digest() == stored.envelope_digest
        && prepared.is_admitted_by(&admission);
    if !consistent {
        return Err(corrupt);
    }
    let query = ForkAttributionIssuerAdmissionQueryV1 {
        issuer: prepared.envelope.unsigned().input().issuer.clone(),
        policy_digest: admission.input().issuer_policy_digest,
        basis: ForkAttributionIssuerAdmissionBasisV1::CommittedImport {
            policy_generation: generation,
        },
    };
    let verdict = store.admit_issuer(&query);
    verdict.map_err(committed_policy_failure)?;
    let plan = prepared.plan(admission);
    let complete = store.read_installed(&plan)? == InstalledRowsV1::expected(&plan)
        && child_matches(store, &prepared)?;
    if complete {
        Ok(Receipt {
            admission: plan.admission,
        })
    } else {
        Err(corrupt)
    }
}

/// Whether the stored child Timeline and its own Events are exactly the
/// imported segment.
fn child_matches<S: EventStore>(
    store: &S,
    prepared: &PreparedImportV1,
) -> Result<bool, ImportError> {
    let child = prepared.fork().child_timeline_id;
    if store.get_timeline(child)? != Some(prepared.export.timeline.clone()) {
        return Ok(false);
    }
    Ok(store.read_own(child, SeqRange::all())? == prepared.export.events)
}

/// Import steps 4 to 8 before a transaction, repeated inside it: the issuer
/// admission and signature, the parent Timeline and its owner, the #202
/// Event evidence, and the `FSM1` signature. Returns the admitting policy
/// generation.
fn precheck<S: ImportBackendV1>(
    store: &S,
    prepared: &PreparedImportV1,
    request: &Request<'_>,
) -> Result<u64, ImportError> {
    let input = prepared.envelope.unsigned().input();
    if input.issuer_policy_digest != request.expected_issuer_policy_digest {
        return Err(ImportError::PolicyChanged);
    }
    let admitted = store
        .admit_issuer(&ForkAttributionIssuerAdmissionQueryV1 {
            issuer: input.issuer.clone(),
            policy_digest: input.issuer_policy_digest,
            basis: ForkAttributionIssuerAdmissionBasisV1::AbsentImport,
        })
        .map_err(absent_policy_failure)?;
    if verify_fork_attribution_authority_envelope_signature_v1(&prepared.envelope).is_err() {
        return Err(ImportError::InvalidSignature);
    }
    precheck_parent(store, prepared, request)?;
    precheck_events(store, prepared, request)?;
    verify_manifest_signature(prepared)?;
    Ok(admitted.policy_generation)
}

/// The parent Timeline exists, is the requested one, has the `FTI1` owner,
/// reaches the cut, and has the `FTI1` chain hash there.
fn precheck_parent<S: EventStore>(
    store: &S,
    prepared: &PreparedImportV1,
    request: &Request<'_>,
) -> Result<(), ImportError> {
    let fork = prepared.fork();
    if fork.parent_timeline_id != request.parent_timeline_id {
        return Err(ImportError::InvalidAuthorityClosure);
    }
    let Some(parent) = store.get_timeline(fork.parent_timeline_id)? else {
        return Err(ImportError::InvalidAuthorityClosure);
    };
    if parent.meta.owner != fork.owner {
        return Err(ImportError::InvalidAuthorityClosure);
    }
    let cut = Seq::from_u64(fork.parent_cut);
    if store.logical_head(fork.parent_timeline_id)? < cut {
        return Err(ImportError::InvalidRangeEvidence);
    }
    if store.chain_hash_at(fork.parent_timeline_id, cut)? == fork.parent_chain_hash {
        Ok(())
    } else {
        Err(ImportError::InvalidRangeEvidence)
    }
}

/// Import step 7, first half: the #202 verification with the destination
/// registry snapshot. A missing registry is a verification failure; only a
/// storage failure is indeterminate.
fn precheck_events<S: EventStore>(
    store: &S,
    prepared: &PreparedImportV1,
    request: &Request<'_>,
) -> Result<(), ImportError> {
    if !prepared.export.events.is_empty() && store.load_key_registry()?.is_none() {
        return Err(ImportError::InvalidEventEvidence);
    }
    verify_timeline_import_v1(store, &prepared.export, request.trust_anchors)
        .map_err(|error| core_failure(&error, ImportError::InvalidEventEvidence))
}

/// Map a store or verification failure: storage failures never prove a
/// verdict, so they are indeterminate, and any other failure is `rejection`.
const fn core_failure(error: &CoreError, rejection: ImportError) -> ImportError {
    if matches!(
        error,
        CoreError::Storage(_) | CoreError::StorageOutcomeUnknown(_)
    ) {
        ImportError::StorageIndeterminate
    } else {
        rejection
    }
}

/// Import step 8: the ADR-065 role-bound `FSM1` signature over the complete
/// `FRM1` bytes under the imported verification-only public key.
fn verify_manifest_signature(prepared: &PreparedImportV1) -> Result<(), ImportError> {
    let key = prepared
        .envelope
        .unsigned()
        .input()
        .key_record
        .public_verification_key();
    verify_local_fork_manifest_signature_only(prepared.closure.signed_manifest(), key)
        .ok()
        .ok_or(ImportError::InvalidSignature)
}

/// The transaction body for a wholly absent import operation.
fn install_absent<S: ImportBackendV1>(
    store: &mut S,
    prepared: &PreparedImportV1,
    request: &Request<'_>,
) -> Result<Receipt, ImportError> {
    if let Some(receipt) = recover(&*store, prepared)? {
        return Ok(receipt);
    }
    // The pre-transaction checks run again on purpose: the Ed25519 issuer and
    // `FSM1` verifications are repeated here so that the policy floor, the
    // destination registry, and the parent are checked under the write lock.
    let generation = precheck(&*store, prepared, request)?;
    let plan = prepared.plan(prepared.admission(generation));
    if store.occupied(&plan)? {
        return Err(ImportError::Conflict);
    }
    store.stage_child(&prepared.export)?;
    verify_staged(&*store, prepared, request.trust_anchors)?;
    store.install_rows(&plan)?;
    Ok(Receipt {
        admission: plan.admission,
    })
}

/// Check the staged child: #411 for a nonempty segment, the explicit
/// empty-segment head and range check otherwise, then the final chain hash.
fn verify_staged<S: EventStore>(
    store: &S,
    prepared: &PreparedImportV1,
    anchors: &[(KeyIdentityV1, PublicKey)],
) -> Result<(), ImportError> {
    let fork = prepared.fork();
    let child = fork.child_timeline_id;
    let cut = Seq::from_u64(fork.parent_cut);
    let final_head = Seq::from_u64(prepared.final_head());
    if fork.local_head == 0 {
        verify_empty_segment(store, child, cut)?;
    } else {
        verify_signed_segment(store, child, cut, final_head, anchors)?;
    }
    let manifest = prepared.closure.signed_manifest().manifest().input();
    if store.chain_hash_at(child, final_head)? == manifest.final_fork_chain_head_hash {
        Ok(())
    } else {
        Err(ImportError::InvalidRangeEvidence)
    }
}

/// An empty child segment makes no #411 completeness claim: the staged child
/// head equals the parent cut and its own range is empty.
///
/// An honest adapter always stages exactly that, so this is defence in depth
/// that ADR-105 requires; the fault-injecting `Probe` tests reach it. Do not
/// remove it as a tautology.
fn verify_empty_segment<S: EventStore>(
    store: &S,
    child: TimelineId,
    cut: Seq,
) -> Result<(), ImportError> {
    let empty = store.read_own(child, SeqRange::all())?.is_empty();
    if empty && store.logical_head(child)? == cut {
        Ok(())
    } else {
        Err(ImportError::InvalidRangeEvidence)
    }
}

/// Invoke #411 on the staged store view for `(cut, final_head]` and require
/// every per-Event result `Verified` and `CompleteThroughHead`.
fn verify_signed_segment<S: EventStore>(
    store: &S,
    child: TimelineId,
    cut: Seq,
    final_head: Seq,
    anchors: &[(KeyIdentityV1, PublicKey)],
) -> Result<(), ImportError> {
    let range = SeqRange::bounded(Seq::from_u64(cut.as_u64().saturating_add(1)), final_head);
    let events = store.read(child, range)?;
    let report =
        verify_signed_timeline_range_v1(store, child, range, &events, anchors, Some(final_head))
            .map_err(|error| core_failure(&error, ImportError::InvalidRangeEvidence))?;
    let verified = report
        .per_event()
        .iter()
        .all(|result| *result == TimelineEventVerificationV1::Verified);
    if verified && report.range_claim() == TimelineSignedRangeClaimV1::CompleteThroughHead {
        Ok(())
    } else {
        Err(ImportError::InvalidRangeEvidence)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use pos_core::{
        Event, ForkAttributionIssuerPolicyEntryV1, ForkAttributionIssuerPolicyInputV1,
        ForkAttributionIssuerPolicyV1, ForkAttributionIssuerStateV1, ForkAttributionIssuerV1,
        KeyRegistryStateV1, Timeline, TimelineMeta,
    };

    use super::{
        ForkAttributionCodecErrorV1 as Codec, ForkAttributionImportClosureErrorV1 as Closure, *,
    };
    use crate::{
        fae1_fixture::{
            pin_policy, request_for, Built, Fallible, Shape, Spec, World, PARENT_CUT, POLICY_SCOPE,
        },
        memory::MemoryStore,
        AuthenticatedOperatorPolicyPinV1,
    };

    #[test]
    fn decode_failures_map_to_the_closed_import_errors() {
        let cases = [
            (Codec::UnsupportedVersion, ImportError::UnsupportedVersion),
            (Codec::FieldOutOfBounds, ImportError::BoundsExceeded),
            (Codec::FieldMismatch, ImportError::InvalidAuthorityClosure),
            (Codec::InvalidEncoding, ImportError::InvalidEncoding),
            (Codec::NonCanonical, ImportError::InvalidEncoding),
            (
                Codec::ImportedAuthorityUnavailable,
                ImportError::InvalidEncoding,
            ),
            (Codec::InterventionOrder, ImportError::InvalidEncoding),
        ];
        for (codec, expected) in cases {
            assert_eq!(ImportError::from(codec), expected);
        }
        assert_eq!(
            ImportError::from(Closure::InvalidEncoding),
            ImportError::InvalidEncoding
        );
        assert_eq!(
            ImportError::from(Closure::InvalidAuthorityClosure),
            ImportError::InvalidAuthorityClosure
        );
        let storage = CoreError::Storage("failed".to_owned());
        assert_eq!(
            ImportError::from(storage),
            ImportError::StorageIndeterminate
        );
    }

    #[test]
    fn policy_failures_map_per_admission_basis() {
        let absent = [
            (PolicyError::PolicyChanged, ImportError::PolicyChanged),
            (PolicyError::IssuerRetired, ImportError::IssuerRetired),
            (PolicyError::IssuerRevoked, ImportError::IssuerRevoked),
            (
                PolicyError::StorageIndeterminate,
                ImportError::StorageIndeterminate,
            ),
            (PolicyError::UntrustedIssuer, ImportError::UntrustedIssuer),
            (PolicyError::PolicyUnavailable, ImportError::UntrustedIssuer),
            (PolicyError::InvalidIssuerKey, ImportError::UntrustedIssuer),
            (PolicyError::CorruptPolicy, ImportError::CorruptAuthority),
            (PolicyError::InvalidEncoding, ImportError::CorruptAuthority),
            (
                PolicyError::UnsupportedVersion,
                ImportError::CorruptAuthority,
            ),
            (PolicyError::BoundsExceeded, ImportError::CorruptAuthority),
            (PolicyError::PinMismatch, ImportError::CorruptAuthority),
            (PolicyError::ScopeMismatch, ImportError::CorruptAuthority),
            (PolicyError::Rollback, ImportError::CorruptAuthority),
            (
                PolicyError::GenerationConflict,
                ImportError::CorruptAuthority,
            ),
            (
                PolicyError::GenerationSkipped,
                ImportError::CorruptAuthority,
            ),
            (PolicyError::WrongPredecessor, ImportError::CorruptAuthority),
            (PolicyError::HistoryExhausted, ImportError::CorruptAuthority),
            (
                PolicyError::IllegalTransition,
                ImportError::CorruptAuthority,
            ),
            (PolicyError::NoOpSuccessor, ImportError::CorruptAuthority),
            (PolicyError::NoActiveIssuer, ImportError::CorruptAuthority),
        ];
        for (policy, expected) in absent {
            assert_eq!(absent_policy_failure(policy), expected);
            let committed = if policy == PolicyError::StorageIndeterminate {
                ImportError::StorageIndeterminate
            } else {
                ImportError::CorruptAuthority
            };
            assert_eq!(committed_policy_failure(policy), committed);
        }
    }

    /// A step to run on the inner store before the transaction body.
    type Prelude = Box<dyn FnOnce(&mut MemoryStore) + Send>;

    /// One injected storage failure.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        GetTimeline(TimelineId),
        LogicalHead(TimelineId),
        ChainHash(TimelineId),
        ReadOwn(TimelineId),
        Read(TimelineId),
        /// The nth (1-based) registry read.
        Registry(u32),
    }

    /// A `MemoryStore` behind the backend seam that can race, hide state,
    /// misreport a head, or fail one read, to drive the paths no honest store
    /// reaches. The Memory adapter alone hosts it: the `SQLite` adapter reaches
    /// its read failures through dropped tables instead.
    struct Probe {
        inner: MemoryStore,
        before_body: Option<Prelude>,
        child_head: Option<(TimelineId, Seq)>,
        hide_child: bool,
        own_events: Option<Vec<Event>>,
        committed_verdict: Option<PolicyError>,
        fault: Option<Fault>,
        registry_reads: AtomicU32,
    }

    impl Probe {
        const fn new(inner: MemoryStore) -> Self {
            Self {
                inner,
                before_body: None,
                child_head: None,
                hide_child: false,
                own_events: None,
                committed_verdict: None,
                fault: None,
                registry_reads: AtomicU32::new(0),
            }
        }

        fn failing(&self, fault: Fault) -> Result<(), CoreError> {
            if self.fault == Some(fault) {
                Err(CoreError::Storage("injected failure".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    impl EventStore for Probe {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.inner.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: TimelineId,
            drafts: &[pos_core::EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.append(timeline, drafts)
        }

        fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            self.failing(Fault::Read(timeline))?;
            self.inner.read(timeline, range)
        }

        fn fork(
            &mut self,
            parent: TimelineId,
            at_seq: Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.inner.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.inner.list_timelines()
        }

        fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            self.failing(Fault::GetTimeline(id))?;
            if self.hide_child && self.child_head.is_some_and(|(child, _)| child == id) {
                return Ok(None);
            }
            self.inner.get_timeline(id)
        }

        fn read_own(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            self.failing(Fault::ReadOwn(timeline))?;
            self.own_events.as_ref().map_or_else(
                || self.inner.read_own(timeline, range),
                |events| Ok(events.clone()),
            )
        }

        fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
            self.failing(Fault::LogicalHead(id))?;
            match self.child_head {
                Some((child, head)) if child == id => Ok(head),
                _ => self.inner.logical_head(id),
            }
        }

        fn chain_hash_at(&self, timeline: TimelineId, at_seq: Seq) -> Result<Hash, CoreError> {
            self.failing(Fault::ChainHash(timeline))?;
            self.inner.chain_hash_at(timeline, at_seq)
        }

        fn load_key_registry(&self) -> Result<Option<KeyRegistryStateV1>, CoreError> {
            let read = self.registry_reads.fetch_add(1, Ordering::SeqCst) + 1;
            self.failing(Fault::Registry(read))?;
            self.inner.load_key_registry()
        }

        fn create_timeline_with_meta(&mut self, meta: TimelineMeta) -> Result<Timeline, CoreError> {
            self.inner.create_timeline_with_meta(meta)
        }

        fn append_committed(
            &mut self,
            timeline: TimelineId,
            events: &[Event],
        ) -> Result<(), CoreError> {
            self.inner.append_committed(timeline, events)
        }

        fn import_committed(
            &mut self,
            meta: TimelineMeta,
            events: &[Event],
        ) -> Result<Timeline, CoreError> {
            self.inner.import_committed(meta, events)
        }

        fn delete_timeline(&mut self, id: TimelineId) -> Result<(), CoreError> {
            self.inner.delete_timeline(id)
        }
    }

    impl ForkAttributionIssuerPolicyInstallationPortV1 for Probe {
        fn install(
            &mut self,
            pin: &AuthenticatedOperatorPolicyPinV1,
            policy_bytes: &[u8],
        ) -> Result<crate::IssuerPolicyInstallReceiptV1, PolicyError> {
            self.inner.install(pin, policy_bytes)
        }

        fn issuer_policy_floor(&self) -> Result<Option<crate::IssuerPolicyFloorV1>, PolicyError> {
            self.inner.issuer_policy_floor()
        }

        fn admit_issuer(
            &self,
            query: &ForkAttributionIssuerAdmissionQueryV1,
        ) -> Result<crate::ForkAttributionIssuerAdmissionV1, PolicyError> {
            if let (Some(error), ForkAttributionIssuerAdmissionBasisV1::CommittedImport { .. }) =
                (self.committed_verdict, query.basis)
            {
                return Err(error);
            }
            self.inner.admit_issuer(query)
        }
    }

    impl ImportBackendV1 for Probe {
        fn read_stored_import(
            &self,
            import_operation_id: Hash,
        ) -> Result<Option<StoredImportV1>, ImportError> {
            self.inner.read_stored_import(import_operation_id)
        }

        fn has_key_evidence(&self, import_operation_id: Hash) -> Result<bool, ImportError> {
            self.inner.has_key_evidence(import_operation_id)
        }

        fn read_installed(&self, plan: &InstallPlanV1<'_>) -> Result<InstalledRowsV1, ImportError> {
            self.inner.read_installed(plan)
        }

        fn occupied(&self, plan: &InstallPlanV1<'_>) -> Result<bool, ImportError> {
            self.inner.occupied(plan)
        }

        fn stage_child(&mut self, export: &TimelineExport) -> Result<(), ImportError> {
            self.inner.stage_child(export)
        }

        fn install_rows(&mut self, plan: &InstallPlanV1<'_>) -> Result<(), ImportError> {
            self.inner.install_rows(plan)
        }

        fn atomically<T, F>(&mut self, _child: TimelineId, body: F) -> Result<T, ImportError>
        where
            F: FnOnce(&mut Self) -> Result<T, ImportError>,
        {
            if let Some(prelude) = self.before_body.take() {
                prelude(&mut self.inner);
            }
            body(self)
        }
    }

    fn prepared_store(world: &World, built: &Built) -> Fallible<MemoryStore> {
        let mut store = MemoryStore::new();
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        Ok(store)
    }

    /// A prelude that commits `winner` before the transaction body runs.
    fn racer(world: &World, winner: &Built) -> Prelude {
        let bytes = winner.bytes.clone();
        let digest = winner.policy.digest();
        let parent = world.root;
        let anchors = world.anchors.clone();
        Box::new(move |inner| {
            let asked = Request {
                envelope_bytes: &bytes,
                expected_issuer_policy_digest: digest,
                parent_timeline_id: parent,
                trust_anchors: &anchors,
            };
            assert!(inner.import_verified(&asked).is_ok());
        })
    }

    #[test]
    fn a_race_is_resolved_by_the_in_transaction_recheck() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let reused = world.build(&Spec {
            operations_seed: 0xc0,
            ..Spec::default()
        })?;
        let same_child = world.build(&Spec::distinct(0))?;
        let expected = [
            (&built, None),
            (&reused, Some(ImportError::Conflict)),
            (&same_child, Some(ImportError::Conflict)),
        ];
        for (winner, error) in expected {
            let mut probe = Probe::new(prepared_store(&world, &built)?);
            probe.before_body = Some(racer(&world, winner));
            let outcome = run_import(&mut probe, &request_for(&world, &built));
            assert_eq!(outcome.err(), error);
        }
        Ok(())
    }

    #[test]
    fn a_misreported_staged_head_is_range_evidence() -> Fallible<()> {
        for shape in [Shape::Mixed, Shape::EmptyClassified] {
            let world = World::new(shape, false)?;
            let built = world.build(&Spec::default())?;
            let mut probe = Probe::new(prepared_store(&world, &built)?);
            let child = world.child_at(0)?.id;
            probe.child_head = Some((child, Seq::from_u64(99)));
            let outcome = run_import(&mut probe, &request_for(&world, &built));
            assert_eq!(outcome.err(), Some(ImportError::InvalidRangeEvidence));
        }
        Ok(())
    }

    #[test]
    fn a_phantom_own_event_in_an_empty_segment_is_range_evidence() -> Fallible<()> {
        let world = World::new(Shape::EmptyClassified, false)?;
        let built = world.build(&Spec::default())?;
        let inner = prepared_store(&world, &built)?;
        let phantom = inner.read_own(world.root, SeqRange::all())?;
        let mut probe = Probe::new(inner);
        probe.own_events = Some(phantom);
        let outcome = run_import(&mut probe, &request_for(&world, &built));
        assert_eq!(outcome.err(), Some(ImportError::InvalidRangeEvidence));
        Ok(())
    }

    #[test]
    fn a_hidden_child_or_other_events_make_a_committed_import_corrupt() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        for hide_child in [true, false] {
            let mut probe = Probe::new(prepared_store(&world, &built)?);
            assert!(run_import(&mut probe, &request_for(&world, &built)).is_ok());
            let head = Seq::from_u64(PARENT_CUT + 4);
            probe.child_head = Some((world.child_at(0)?.id, head));
            probe.hide_child = hide_child;
            probe.own_events = (!hide_child).then(Vec::new);
            let outcome = run_import(&mut probe, &request_for(&world, &built));
            assert_eq!(outcome.err(), Some(ImportError::CorruptAuthority));
        }
        Ok(())
    }

    #[test]
    fn a_committed_retry_never_consults_the_pinned_policy() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut store = prepared_store(&world, &built)?;
        let receipt = store.import_verified(&request_for(&world, &built))?;
        let stale = Request {
            expected_issuer_policy_digest: Hash::from_bytes([0x77; 32]),
            ..request_for(&world, &built)
        };
        assert_eq!(store.import_verified(&stale), Ok(receipt));
        Ok(())
    }

    #[test]
    fn a_committed_admission_never_survives_an_adverse_policy_verdict() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut probe = Probe::new(prepared_store(&world, &built)?);
        assert!(run_import(&mut probe, &request_for(&world, &built)).is_ok());
        let cases = [
            (PolicyError::IssuerRetired, ImportError::CorruptAuthority),
            (PolicyError::IssuerRevoked, ImportError::CorruptAuthority),
            (PolicyError::UntrustedIssuer, ImportError::CorruptAuthority),
            (
                PolicyError::StorageIndeterminate,
                ImportError::StorageIndeterminate,
            ),
        ];
        for (verdict, expected) in cases {
            probe.committed_verdict = Some(verdict);
            let outcome = run_import(&mut probe, &request_for(&world, &built));
            assert_eq!(outcome.err(), Some(expected));
        }
        Ok(())
    }

    /// Run one default import of `shape` whose store fails at `fault(root, child)`.
    fn faulted_import(
        shape: Shape,
        fault: fn(TimelineId, TimelineId) -> Fault,
    ) -> Fallible<Result<Receipt, ImportError>> {
        let world = World::new(shape, false)?;
        let built = world.build(&Spec::default())?;
        let mut probe = Probe::new(prepared_store(&world, &built)?);
        probe.fault = Some(fault(world.root, world.child_at(0)?.id));
        Ok(run_import(&mut probe, &request_for(&world, &built)))
    }

    #[test]
    fn a_store_failure_at_each_read_is_indeterminate() -> Fallible<()> {
        let mixed: [fn(TimelineId, TimelineId) -> Fault; 7] = [
            |root, _| Fault::GetTimeline(root),
            |root, _| Fault::LogicalHead(root),
            |root, _| Fault::ChainHash(root),
            |_, child| Fault::Read(child),
            |_, child| Fault::ChainHash(child),
            |_, _| Fault::Registry(1),
            // The registry reads of the range check follow four in the checks.
            |_, _| Fault::Registry(5),
        ];
        for fault in mixed {
            let outcome = faulted_import(Shape::Mixed, fault)?;
            assert_eq!(outcome.err(), Some(ImportError::StorageIndeterminate));
        }
        let empty: [fn(TimelineId, TimelineId) -> Fault; 2] = [
            |_, child| Fault::ReadOwn(child),
            |_, child| Fault::LogicalHead(child),
        ];
        for fault in empty {
            let outcome = faulted_import(Shape::EmptyClassified, fault)?;
            assert_eq!(outcome.err(), Some(ImportError::StorageIndeterminate));
        }
        Ok(())
    }

    #[test]
    fn a_store_failure_while_revalidating_the_child_is_indeterminate() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut probe = Probe::new(prepared_store(&world, &built)?);
        assert!(run_import(&mut probe, &request_for(&world, &built)).is_ok());
        probe.fault = Some(Fault::ReadOwn(world.child_at(0)?.id));
        let outcome = run_import(&mut probe, &request_for(&world, &built));
        assert_eq!(outcome.err(), Some(ImportError::StorageIndeterminate));
        Ok(())
    }

    #[test]
    fn a_policy_that_moves_inside_the_transaction_is_refused() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x32; 32]);
        let other = ForkAttributionIssuerV1::new(
            "issuer-b",
            1,
            PublicKey::from_bytes(key.verifying_key().to_bytes()),
        )?;
        let moved = ForkAttributionIssuerPolicyV1::new(ForkAttributionIssuerPolicyInputV1 {
            scope: POLICY_SCOPE.to_owned(),
            generation: 2,
            previous_policy_digest: Some(built.policy.digest()),
            entries: vec![
                ForkAttributionIssuerPolicyEntryV1 {
                    issuer: built.issuer.clone(),
                    state: ForkAttributionIssuerStateV1::Active,
                },
                ForkAttributionIssuerPolicyEntryV1 {
                    issuer: other,
                    state: ForkAttributionIssuerStateV1::Active,
                },
            ],
        })?;
        let mut probe = Probe::new(prepared_store(&world, &built)?);
        probe.before_body = Some(Box::new(move |inner| {
            assert!(pin_policy(inner, &moved).is_ok());
        }));
        let outcome = run_import(&mut probe, &request_for(&world, &built));
        assert_eq!(outcome.err(), Some(ImportError::PolicyChanged));
        Ok(())
    }

    #[test]
    fn storage_failures_are_indeterminate_and_verdicts_are_rejections() {
        let storage = CoreError::Storage("failed".to_owned());
        let unknown = CoreError::StorageOutcomeUnknown("unknown".to_owned());
        let verdict = CoreError::SignatureVerificationFailed;
        for rejection in [
            ImportError::InvalidEventEvidence,
            ImportError::InvalidRangeEvidence,
        ] {
            assert_eq!(
                core_failure(&storage, rejection),
                ImportError::StorageIndeterminate
            );
            assert_eq!(
                core_failure(&unknown, rejection),
                ImportError::StorageIndeterminate
            );
            assert_eq!(core_failure(&verdict, rejection), rejection);
        }
    }

    #[test]
    fn an_admission_names_only_its_own_envelope() -> Fallible<()> {
        let mut world = World::new(Shape::Mixed, false)?;
        world.add_child(Shape::Mixed)?;
        let first = world.build(&Spec::default())?;
        let second = world.build(&Spec::distinct(1))?;
        let mut probe = Probe::new(prepared_store(&world, &first)?);
        let receipt = run_import(&mut probe, &request_for(&world, &first))?;
        let other = run_import(&mut probe, &request_for(&world, &second))?;
        assert_ne!(receipt, other);
        let prepared = PreparedImportV1::decode(&first.bytes)?;
        assert!(prepared.is_admitted_by(&receipt.admission));
        assert!(!prepared.is_admitted_by(&other.admission));
        Ok(())
    }
}
