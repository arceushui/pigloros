//! ADR-114 bounded, read-only Fork attribution validation.
//!
//! Requirements and limits are structural values. Only their binding into an
//! installed runtime verifier's protected-use result selects required evidence;
//! none of these values grants signing, append or protected-release authority.

use crate::CommittedForkManifestV1;
use pos_core::{
    store::{EventReadBounds, SeqRange},
    trusted_clock::{GuardMonotonicSourceV1, MonotonicMarkV1},
    ErasureContainmentErrorV1, Hash, Seq, TimelineId,
};
use std::time::Instant;

#[cfg(feature = "sqlite")]
mod admission;
#[cfg(feature = "sqlite")]
mod append_operation;
#[cfg(feature = "sqlite")]
mod classifier;
#[cfg(feature = "sqlite")]
mod publication;
#[cfg(feature = "sqlite")]
mod retained_key;

/// Core's code-2 FAR1/FPO1 decoder replaces this exact origin tail by [1]
/// in a real local-projection buffer. Borrow only its length, not a new DTO.
#[cfg(feature = "sqlite")]
fn imported_projection_length(bytes: &[u8]) -> Option<usize> {
    const IMPORTED_ORIGIN_HEAD: [u8; 4] = [0x82, 0x02, 0x58, 0x20];
    const IMPORTED_ORIGIN_BYTES: usize = IMPORTED_ORIGIN_HEAD.len() + 32;
    const LOCAL_ORIGIN_BYTES: usize = 2;
    let prefix = bytes.len().checked_sub(IMPORTED_ORIGIN_BYTES)?;
    // Subtraction proves this slice exists; replacing 36 bytes by 2 also
    // cannot overflow the existing input length.
    bytes[prefix..]
        .starts_with(&IMPORTED_ORIGIN_HEAD)
        .then_some(prefix + LOCAL_ORIGIN_BYTES)
}

/// Private validator context. Only the protected bridge borrows a ledger;
/// ordinary publication reads retain their existing, non-protected contract.
/// A failed debit remains latched in the borrowed ledger even when the native
/// validator translates it to its existing closed error vocabulary.
pub(crate) struct NativeReadContextV1<'budget, 'clock> {
    budget: Option<&'budget mut ForkReplayReadBudgetV1<'clock>>,
    read_deadline: Option<(Instant, u64)>,
}

impl<'budget, 'clock> NativeReadContextV1<'budget, 'clock> {
    pub(crate) const fn ordinary() -> Self {
        Self {
            budget: None,
            read_deadline: None,
        }
    }

    pub(crate) const fn protected(budget: &'budget mut ForkReplayReadBudgetV1<'clock>) -> Self {
        Self {
            budget: Some(budget),
            read_deadline: None,
        }
    }

    #[cfg(feature = "sqlite")]
    const fn for_event_read(
        budget: &'budget mut ForkReplayReadBudgetV1<'clock>,
        read_deadline: Option<(Instant, u64)>,
    ) -> Self {
        Self {
            budget: Some(budget),
            read_deadline,
        }
    }

    #[cfg(feature = "sqlite")]
    pub(crate) const fn is_protected(&self) -> bool {
        self.budget.is_some()
    }

    /// Native work can refuse before issuing a debit (for example when its
    /// checked field sum fails). Latch that refusal in the original ledger
    /// without fabricating a charge or sampling the clock again.
    #[cfg(feature = "sqlite")]
    pub(crate) fn refuse(&mut self) {
        if let Some(budget) = self.budget.as_deref_mut() {
            budget.failed = true;
        }
    }

    pub(crate) fn check(&mut self) -> Result<(), crate::ForkManifestPublicationErrorV1> {
        let deadline = self.read_deadline;
        self.budget
            .as_deref_mut()
            .map_or(Ok(()), |budget| {
                budget
                    .check_time()
                    .and_then(|()| budget.accept(within_read_deadline(deadline)))
            })
            .map_err(|_| crate::ForkManifestPublicationErrorV1::PublicationConflict)
    }

    pub(crate) fn bytes(
        &mut self,
        length: usize,
    ) -> Result<(), crate::ForkManifestPublicationErrorV1> {
        self.budget
            .as_deref_mut()
            .map_or(Ok(()), |budget| budget.charge_bytes(length))
            .map_err(|_| crate::ForkManifestPublicationErrorV1::PublicationConflict)
    }

    /// Refuse a known oversized native row before `SQLite` fetches its fields.
    /// This is only a prospective check: each actual owned getter is debited
    /// separately, so a decoder that stops early does not invent later copies.
    #[cfg(feature = "sqlite")]
    pub(crate) fn require_bytes(
        &mut self,
        length: Option<usize>,
    ) -> Result<(), crate::ForkManifestPublicationErrorV1> {
        self.budget
            .as_deref_mut()
            .map_or(Ok(()), |budget| {
                budget.check_time().and_then(|()| {
                    budget.accept(
                        length.is_some_and(|length| length <= budget.remaining_native_bytes()),
                    )
                })
            })
            .map_err(|_| crate::ForkManifestPublicationErrorV1::PublicationConflict)
    }

    pub(crate) fn canonical(
        &mut self,
        length: Result<usize, pos_core::CanonicalLengthErrorV1>,
    ) -> Result<(), crate::ForkManifestPublicationErrorV1> {
        self.budget
            .as_deref_mut()
            .map_or(Ok(()), |budget| budget.charge_canonical(length))
            .map_err(|_| crate::ForkManifestPublicationErrorV1::PublicationConflict)
    }

    pub(crate) fn suffix_row(&mut self) -> Result<(), crate::ForkManifestPublicationErrorV1> {
        self.budget
            .as_deref_mut()
            .map_or(Ok(()), |budget| budget.charge_rows(1))
            .map_err(|_| crate::ForkManifestPublicationErrorV1::PublicationConflict)
    }

    /// Refuse a cursor step before it can inspect a row past the remaining
    /// ceiling. The caller charges only an actually returned row afterward.
    #[cfg(feature = "sqlite")]
    pub(crate) fn row_available(&mut self) -> Result<(), crate::ForkManifestPublicationErrorV1> {
        self.budget
            .as_deref_mut()
            .map_or(Ok(()), |budget| {
                budget.check_time()?;
                if budget.rows == budget.limits.rows {
                    budget.accept(false)
                } else {
                    Ok(())
                }
            })
            .map_err(|_| crate::ForkManifestPublicationErrorV1::PublicationConflict)
    }

    pub(crate) fn node(
        &mut self,
        depth: usize,
    ) -> Result<(), crate::ForkManifestPublicationErrorV1> {
        self.budget
            .as_deref_mut()
            .map_or(Ok(()), |budget| budget.charge_node(depth))
            .map_err(|_| crate::ForkManifestPublicationErrorV1::PublicationConflict)
    }

    /// Locate borrowed allocation carriers, debit, then immediately run the
    /// existing capped decoder. This gate grants no native validity: magic,
    /// preferred widths, semantics and exact canonical equality stay in core.
    pub(crate) fn imported_admission(
        &mut self,
        bytes: &[u8],
    ) -> Result<pos_core::ImportedForkAttributionAdmissionV1, crate::ForkManifestPublicationErrorV1>
    {
        use crate::ForkManifestPublicationErrorV1::PublicationConflict;
        self.check()?;
        if self.budget.is_some() {
            if bytes.len() > pos_core::MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1 {
                return Err(PublicationConflict);
            }
            let issuer = AdmissionCarrierV1::field(bytes, 5, 2).ok_or(PublicationConflict)?;
            // The borrowed carrier fits its enclosing <=512-byte record,
            // which also implies the existing 512-byte FAI1 decoder cap.
            let identifier = AdmissionCarrierV1::field(issuer, 2, 3).ok_or(PublicationConflict)?;
            if identifier.len() > pos_core::MAX_FORK_ATTRIBUTION_ISSUER_ID_BYTES_V1 {
                return Err(PublicationConflict);
            }
            self.bytes(identifier.len())?; // FAI1 decoder's issuer String.
            self.bytes(issuer.len())?; // FAI1 decoder's canonical comparison Vec.
            self.bytes(bytes.len())?; // IFA1 decoder's canonical comparison Vec.
            self.bytes(issuer.len())?; // IFA1 emitter's separate nested FAI1 Vec.
        }
        let decoded = pos_core::ImportedForkAttributionAdmissionV1::from_canonical_cbor(bytes)
            .map_err(|_| PublicationConflict);
        self.check()?;
        decoded
    }
}

/// Borrowed prefix reader for just IFA1 field 5 and FAI1 field 2. It never
/// constructs a record, follows an input-sized collection, or copies a carrier.
struct AdmissionCarrierV1<'bytes>(&'bytes [u8]);

impl<'bytes> AdmissionCarrierV1<'bytes> {
    fn field(bytes: &'bytes [u8], index: u64, expected_major: u8) -> Option<&'bytes [u8]> {
        let mut carrier = Self::positioned(bytes, index)?;
        let (major, length) = carrier.head()?;
        if major != expected_major {
            return None;
        }
        carrier.take(usize::try_from(length).ok()?)
    }

    #[cfg(feature = "sqlite")]
    fn array_field(bytes: &'bytes [u8], index: u64) -> Option<(u64, Self)> {
        let mut carrier = Self::positioned(bytes, index)?;
        let (major, count) = carrier.head()?;
        (major == 4).then_some((count, carrier))
    }

    fn positioned(bytes: &'bytes [u8], index: u64) -> Option<Self> {
        let mut carrier = Self(bytes);
        let (major, count) = carrier.head()?;
        if major != 4 || count <= index {
            return None;
        }
        // Callers supply fixed native prefixes containing only scalar fields.
        for _ in 0..index {
            let (major, length) = carrier.head()?;
            match major {
                0 | 1 => (),
                2 | 3 => {
                    carrier.take(usize::try_from(length).ok()?)?;
                }
                _ => return None,
            }
        }
        Some(carrier)
    }

    fn head(&mut self) -> Option<(u8, u64)> {
        let first = self.take(1)?[0];
        let additional = first & 31;
        let width = match additional {
            0..=23 => return Some((first >> 5, u64::from(additional))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return None,
        };
        let value = self
            .take(width)?
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
        Some((first >> 5, value))
    }

    fn take(&mut self, length: usize) -> Option<&'bytes [u8]> {
        let selected = self.0.get(..length)?;
        self.0 = &self.0[length..];
        Some(selected)
    }
}

/// Closed failures of the bounded attribution read, without protected details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkReplayAuthorityReadErrorV1 {
    /// Required native evidence or its supported read boundary is absent.
    #[error("Fork Replay evidence is unavailable")]
    Unavailable,
    /// Native evidence fails its owning validator or exact expected identity.
    #[error("Fork Replay evidence is corrupt")]
    CorruptAuthority,
    /// A structural, aggregate or elapsed-time ceiling is exceeded.
    #[error("Fork Replay read bounds are exceeded")]
    BoundsExceeded,
    /// The adapter cannot establish the required serialized read.
    #[error("Fork Replay storage is unavailable")]
    StorageUnavailable,
}

type ReadResult<T> = Result<T, ForkReplayAuthorityReadErrorV1>;

/// An exact publication coordinate selected by an installed verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkReplayRequirementV1 {
    child: TimelineId,
    head: Seq,
    record: Hash,
    origin: Option<Hash>,
}

impl ForkReplayRequirementV1 {
    /// Check a structural coordinate. This does not select or authorize it.
    ///
    /// # Errors
    /// Rejects zero required record or imported-origin identities.
    pub fn new(
        child: TimelineId,
        head: Seq,
        record: Hash,
        origin: Option<Hash>,
    ) -> ReadResult<Self> {
        if record == Hash::zero() || origin == Some(Hash::zero()) {
            return Err(ForkReplayAuthorityReadErrorV1::CorruptAuthority);
        }
        Ok(Self {
            child,
            head,
            record,
            origin,
        })
    }

    /// The required child Fork.
    #[must_use]
    pub const fn child_timeline_id(self) -> TimelineId {
        self.child
    }

    /// The publication's logical head, possibly an inherited historical cut.
    #[must_use]
    pub const fn publication_logical_head(self) -> Seq {
        self.head
    }

    /// The exact retained FSM1 record identity.
    #[must_use]
    pub const fn signed_manifest_record_id(self) -> Hash {
        self.record
    }

    /// The code-2 origin, or `None` for local attribution.
    #[must_use]
    pub const fn authority_origin_digest(self) -> Option<Hash> {
        self.origin
    }
}

/// An installed operation's finite traversal and cumulative work ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkReplayReadLimitsV1 {
    depth: usize,
    visits: usize,
    rows: usize,
    bytes: usize,
    elapsed_micros: u64,
}

impl ForkReplayReadLimitsV1 {
    /// Validate structural limits; only the installed verifier binds them to use.
    ///
    /// # Errors
    /// Rejects zero/unlimited ceilings, more than 256 MiB combined bytes or a
    /// duration exceeding the existing 30-second protected guard.
    pub fn new(
        depth: usize,
        visits: usize,
        rows: usize,
        bytes: usize,
        elapsed_micros: u64,
    ) -> ReadResult<Self> {
        if [depth, visits, rows, bytes]
            .into_iter()
            .any(|value| value == 0 || value == usize::MAX)
            || bytes > 256 * 1024 * 1024
            || elapsed_micros == 0
            || elapsed_micros > 30_000_000
        {
            return Err(ForkReplayAuthorityReadErrorV1::BoundsExceeded);
        }
        Ok(Self {
            depth,
            visits,
            rows,
            bytes,
            elapsed_micros,
        })
    }

    /// Parent links allowed in any one traversal, separate from total visits.
    #[must_use]
    pub const fn max_fork_depth_per_traversal(self) -> usize {
        self.depth
    }

    /// All Timeline metadata node visits across phases and Compare arms.
    #[must_use]
    pub const fn max_ancestry_node_visits(self) -> usize {
        self.visits
    }

    /// All inspected suffix rows across phases and Compare arms.
    #[must_use]
    pub const fn max_suffix_rows(self) -> usize {
        self.rows
    }

    /// Combined operation bytes, including native records and materialized Events.
    #[must_use]
    pub const fn max_native_bytes(self) -> usize {
        self.bytes
    }

    /// Elapsed microseconds measured from the existing guard's original start.
    #[must_use]
    pub const fn max_elapsed_micros(self) -> u64 {
        self.elapsed_micros
    }
}

/// One cumulative ledger borrowed across both phases and both Compare arms.
///
/// The ledger borrows the monotonic source and carries the original guard mark;
/// an adapter cannot reset either epoch. A rejected charge permanently closes
/// this ledger. It never refunds work or restores a prior counter snapshot.
pub struct ForkReplayReadBudgetV1<'clock> {
    limits: ForkReplayReadLimitsV1,
    started: MonotonicMarkV1,
    last_mark: MonotonicMarkV1,
    clock: &'clock mut dyn GuardMonotonicSourceV1,
    visits: usize,
    rows: usize,
    bytes: usize,
    failed: bool,
}

impl<'clock> ForkReplayReadBudgetV1<'clock> {
    /// Start one ledger at the release guard's existing start, never at read time.
    ///
    /// # Errors
    /// Rejects an already elapsed or regressed guard clock.
    pub fn new(
        limits: ForkReplayReadLimitsV1,
        started: MonotonicMarkV1,
        clock: &'clock mut dyn GuardMonotonicSourceV1,
    ) -> ReadResult<Self> {
        let mut budget = Self {
            limits,
            started,
            last_mark: started,
            clock,
            visits: 0,
            rows: 0,
            bytes: 0,
            failed: false,
        };
        budget.check_time().map(|()| budget)
    }

    /// The immutable installed operation ceilings.
    #[must_use]
    pub const fn limits(&self) -> ForkReplayReadLimitsV1 {
        self.limits
    }

    /// Bytes still available before a bounded Event read allocates its result.
    #[must_use]
    pub const fn remaining_native_bytes(&self) -> usize {
        self.limits.bytes - self.bytes
    }

    /// Check the original guard clock around each bounded batch.
    ///
    /// # Errors
    /// Fails permanently on a regressed/elapsed mark or prior rejected charge.
    pub fn check_time(&mut self) -> ReadResult<()> {
        let within = !self.failed && {
            let mark = self.clock.mark();
            let monotonic = mark.checked_elapsed_since(self.last_mark).is_some();
            let within = monotonic
                && mark
                    .checked_elapsed_since(self.started)
                    .is_some_and(|elapsed| {
                        elapsed.as_micros() <= u128::from(self.limits.elapsed_micros)
                    });
            if within {
                self.last_mark = mark;
            }
            within
        };
        self.accept(within)
    }

    /// Charge one metadata node before reading it; depth counts parent links.
    ///
    /// # Errors
    /// Rejects per-traversal depth or cumulative visits before the node read.
    pub fn charge_node(&mut self, depth: usize) -> ReadResult<()> {
        self.check_time()?;
        let within = depth <= self.limits.depth && charge(&mut self.visits, 1, self.limits.visits);
        self.accept(within)
    }

    /// Charge suffix rows before enumeration, allocation or cloning.
    ///
    /// # Errors
    /// Rejects cumulative row overflow or an exhausted ledger.
    pub fn charge_rows(&mut self, rows: usize) -> ReadResult<()> {
        self.check_time()?;
        let within = charge(&mut self.rows, rows, self.limits.rows);
        self.accept(within)
    }

    /// Charge native and Event bytes before copying, decoding or encoding them.
    ///
    /// # Errors
    /// Rejects cumulative byte overflow or an exhausted ledger.
    pub fn charge_bytes(&mut self, bytes: usize) -> ReadResult<()> {
        self.check_time()?;
        let within = charge(&mut self.bytes, bytes, self.limits.bytes);
        self.accept(within)
    }

    pub(crate) fn charge_canonical(
        &mut self,
        length: Result<usize, pos_core::CanonicalLengthErrorV1>,
    ) -> ReadResult<()> {
        match length {
            Ok(bytes) => self.charge_bytes(bytes),
            Err(_) => self.accept(false),
        }
    }

    const fn accept(&mut self, within: bool) -> ReadResult<()> {
        if within {
            Ok(())
        } else {
            self.failed = true;
            Err(ForkReplayAuthorityReadErrorV1::BoundsExceeded)
        }
    }
}

fn charge(used: &mut usize, amount: usize, ceiling: usize) -> bool {
    used.checked_add(amount)
        .filter(|next| *next <= ceiling)
        .is_some_and(|next| {
            *used = next;
            true
        })
}

/// Exact, non-authorizing publication evidence returned by an adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkReplayAuthorityEvidenceV1 {
    requirement: ForkReplayRequirementV1,
    admission_digest: Hash,
    operation_id: Hash,
    operation_bytes: Vec<u8>,
}

impl ForkReplayAuthorityEvidenceV1 {
    pub(crate) fn from_committed(
        requirement: ForkReplayRequirementV1,
        committed: &CommittedForkManifestV1,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<Self> {
        if committed.receipt.child_timeline_id != requirement.child
            || committed.receipt.final_logical_head != requirement.head.as_u64()
            || committed.record_id != requirement.record
            || committed.authority_origin_digest != requirement.origin
        {
            return Err(ForkReplayAuthorityReadErrorV1::CorruptAuthority);
        }
        let operation_bytes = if let Some(origin) = requirement.origin {
            // The typed projection creates no local FPO1 byte buffer.
            let mut context = NativeReadContextV1::protected(budget);
            crate::fork_manifest_publication::charge_publication_copy(
                &committed.operation,
                crate::fork_event_authority::ValidatedOriginV1::Imported(origin),
                &mut context,
            )
            .map_err(|_| ForkReplayAuthorityReadErrorV1::BoundsExceeded)?;
            context
                .bytes(origin.as_bytes().len())
                .map_err(|_| ForkReplayAuthorityReadErrorV1::BoundsExceeded)?;
            let imported = pos_core::ImportedForkPublicationOperationV1::from_local(
                committed.operation.clone(),
                origin,
            );
            context
                .check()
                .map_err(|_| ForkReplayAuthorityReadErrorV1::BoundsExceeded)?;
            budget.charge_canonical(imported.canonical_cbor_len())?;
            imported.to_canonical_cbor()
        } else {
            budget.charge_canonical(committed.operation.canonical_cbor_len())?;
            committed.operation.to_canonical_cbor()
        };
        // The evidence copies two native digest fields; no second byte buffer.
        budget.charge_bytes(32)?;
        budget.charge_bytes(32)?;
        Ok(Self {
            requirement,
            admission_digest: committed.operation.input().admission_digest,
            operation_id: committed.operation.input().operation_id,
            operation_bytes,
        })
    }
    /// The coordinate that was validated, not a protected-use capability.
    #[must_use]
    pub const fn requirement(&self) -> ForkReplayRequirementV1 {
        self.requirement
    }

    /// The validated FAR1 identity.
    #[must_use]
    pub const fn admission_digest(&self) -> Hash {
        self.admission_digest
    }

    /// The exact validated publication operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> Hash {
        self.operation_id
    }

    /// Exact FPO1 bytes, including code-2 origin for an imported publication.
    #[must_use]
    pub fn operation_bytes(&self) -> &[u8] {
        &self.operation_bytes
    }
}

/// Object-safe adapter read bridge.
///
/// Its implementation must use a held store
/// interval and the existing transaction-internal validator (b), never a new
/// nested transaction, signer, permit or recovery decision.
pub trait ForkReplayAuthorityReadPortV1 {
    /// Establish the existing read interval on the caller's original ledger.
    ///
    /// # Errors
    /// Refuses before unsupported native work. Any newly acquired interval
    /// is settled even when a post-acquisition budget check fails.
    fn begin_fork_replay_read_interval(
        &self,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<pos_core::ErasureProtectedEffectIntervalV1, ForkReplayLineageReadErrorV1>;

    /// Obtain the logical head through guarded native metadata and visibility.
    ///
    /// # Errors
    /// Fails closed on unavailable history, invalid native cuts, missing held
    /// interval, or exhaustion of the shared operation ledger.
    fn fork_replay_logical_head(
        &self,
        timeline_id: TimelineId,
        effective_max_fork_depth: usize,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<Seq, ForkReplayLineageReadErrorV1>;

    /// Materialize one complete inclusive logical range through native owners.
    ///
    /// The operation ledger and each arm's existing Event envelope are both
    /// enforced before allocation, without ordinary bounded-read fallback.
    ///
    /// # Errors
    /// Returns closed visibility, native structure, interval or bounds errors;
    /// a refused ledger wins and no partial successful history is returned.
    fn read_fork_replay_events(
        &self,
        timeline_id: TimelineId,
        range: SeqRange,
        bounds: EventReadBounds,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<Vec<pos_core::Event>, ForkReplayLineageReadErrorV1>;

    /// Read one actual lineage coordinate with bounded full-ancestry visibility.
    ///
    /// Reuses the caller's held interval and original operation ledger. The
    /// effective depth cap is the stricter installed arm/operation ceiling.
    /// This diagnostic coordinate grants no signing or release authority.
    ///
    /// # Errors
    /// Returns closed read, erasure-access or containment failures. A refused
    /// ledger takes precedence over an observed native failure.
    fn read_fork_replay_lineage_node(
        &self,
        timeline_id: TimelineId,
        depth: usize,
        effective_max_fork_depth: usize,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<Option<ForkReplayLineageNodeV1>, ForkReplayLineageReadErrorV1>;

    /// Validate one required publication under the caller's cumulative ledger.
    ///
    /// # Errors
    /// Returns a closed evidence, storage or bounds failure before materialization.
    fn validate_fork_replay_authority(
        &self,
        requirement: &ForkReplayRequirementV1,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> ReadResult<ForkReplayAuthorityEvidenceV1>;
}

/// A visible actual Timeline coordinate, without names, owners or Events.
#[derive(Debug, Eq, PartialEq)]
pub struct ForkReplayLineageNodeV1 {
    timeline_id: TimelineId,
    fork_point: Option<(TimelineId, Seq)>,
}

/// Construct a deliberately unvalidated node for downstream read-port fault tests.
///
/// This fixture carries no authority and is unavailable in the deployment graph.
#[cfg(any(test, feature = "test-support"))]
#[must_use]
pub const fn test_fork_replay_lineage_node(
    timeline_id: TimelineId,
    fork_point: Option<(TimelineId, Seq)>,
) -> ForkReplayLineageNodeV1 {
    ForkReplayLineageNodeV1::new(timeline_id, fork_point)
}

impl ForkReplayLineageNodeV1 {
    pub(crate) const fn new(
        timeline_id: TimelineId,
        fork_point: Option<(TimelineId, Seq)>,
    ) -> Self {
        Self {
            timeline_id,
            fork_point,
        }
    }

    /// Borrow the selected native Timeline identity.
    #[must_use]
    pub const fn timeline_id(&self) -> &TimelineId {
        &self.timeline_id
    }

    /// Borrow the actual parent/cut, or identify an actual root.
    #[must_use]
    pub const fn fork_point(&self) -> Option<&(TimelineId, Seq)> {
        self.fork_point.as_ref()
    }
}

/// Closed lineage failures; no native values or formatted provenance escape.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkReplayLineageReadErrorV1 {
    /// Existing bounded read failure, without changing its four-case contract.
    #[error("Fork Replay lineage read failed")]
    Read(ForkReplayAuthorityReadErrorV1),
    /// The member's installed erasure gate denied Read access.
    #[error("Fork Replay lineage access is frozen")]
    AccessFrozen,
    /// The member's containment or inventory freshness could not be established.
    #[error("Fork Replay lineage containment is unavailable")]
    ContainmentUnavailable,
}

pub(crate) type LineageReadResult<T> = Result<T, ForkReplayLineageReadErrorV1>;

pub(crate) struct LineageReadContextV1<'budget, 'clock> {
    budget: &'budget mut ForkReplayReadBudgetV1<'clock>,
    cap: usize,
    read_deadline: Option<(Instant, u64)>,
}

impl<'budget, 'clock> LineageReadContextV1<'budget, 'clock> {
    pub(crate) fn new(
        budget: &'budget mut ForkReplayReadBudgetV1<'clock>,
        cap: usize,
    ) -> LineageReadResult<Self> {
        budget
            .check_time()
            .map_err(ForkReplayLineageReadErrorV1::Read)?;
        budget
            .accept(cap <= budget.limits().max_fork_depth_per_traversal())
            .map_err(ForkReplayLineageReadErrorV1::Read)?;
        Ok(Self {
            budget,
            cap,
            read_deadline: None,
        })
    }

    pub(crate) fn for_events(
        budget: &'budget mut ForkReplayReadBudgetV1<'clock>,
        bounds: EventReadBounds,
    ) -> LineageReadResult<Self> {
        let started = Instant::now();
        let cap = bounds
            .max_fork_depth()
            .min(budget.limits().max_fork_depth_per_traversal());
        let mut context = Self::new(budget, cap)?;
        context.read_deadline = Some((started, bounds.max_elapsed_micros()));
        context.check().map(|()| context)
    }

    pub(crate) fn check(&mut self) -> LineageReadResult<()> {
        self.budget
            .check_time()
            .and_then(|()| self.budget.accept(within_read_deadline(self.read_deadline)))
            .map_err(ForkReplayLineageReadErrorV1::Read)
    }

    pub(crate) fn require(&mut self, within: bool) -> LineageReadResult<()> {
        self.check().and_then(|()| {
            self.budget
                .accept(within)
                .map_err(ForkReplayLineageReadErrorV1::Read)
        })
    }

    #[cfg(feature = "sqlite")]
    pub(crate) const fn native(&mut self) -> NativeReadContextV1<'_, 'clock> {
        NativeReadContextV1::for_event_read(&mut *self.budget, self.read_deadline)
    }

    /// Always post-check a completed batch, including failed native work.
    pub(crate) fn step<T>(
        &mut self,
        effect: impl FnOnce(&mut Self) -> LineageReadResult<T>,
    ) -> LineageReadResult<T> {
        self.check().and_then(|()| {
            let result = effect(self);
            self.check().and(result)
        })
    }

    pub(crate) fn bytes(&mut self, bytes: usize) -> LineageReadResult<()> {
        self.budget
            .charge_bytes(bytes)
            .map_err(ForkReplayLineageReadErrorV1::Read)
    }

    pub(crate) fn row(&mut self) -> LineageReadResult<()> {
        self.budget
            .charge_rows(1)
            .map_err(ForkReplayLineageReadErrorV1::Read)
    }

    fn node(&mut self, depth: Option<usize>) -> LineageReadResult<()> {
        self.check().and_then(|()| {
            if let Some(depth) = depth.filter(|depth| *depth <= self.cap) {
                self.budget
                    .charge_node(depth)
                    .map_err(ForkReplayLineageReadErrorV1::Read)
            } else {
                self.budget
                    .accept(false)
                    .map_err(ForkReplayLineageReadErrorV1::Read)
            }
        })
    }
}

fn within_read_deadline(deadline: Option<(Instant, u64)>) -> bool {
    deadline.is_none_or(|(started, limit)| {
        limit != 0 && started.elapsed().as_micros() <= u128::from(limit)
    })
}

/// Purpose-specific, exclusively owned plaintext staging. Native owners fund
/// each Event before pushing it; all failed/post-check/unwind exits scrub it.
#[derive(Default)]
pub(crate) struct ReplayEventStagingV1(Vec<pos_core::Event>);

impl ReplayEventStagingV1 {
    pub(crate) fn push(&mut self, event: pos_core::Event) -> &mut pos_core::Event {
        self.0.push(event);
        let index = self.0.len() - 1;
        &mut self.0[index]
    }

    pub(crate) fn into_events(mut self) -> Vec<pos_core::Event> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for ReplayEventStagingV1 {
    fn drop(&mut self) {
        let scrubbed = pos_core::store::zeroize_event_plaintext_staging(&mut self.0);
        debug_assert!(scrubbed);
    }
}

/// Validate the complete Event count before allocating a result; Seq zero is
/// a range boundary, never a committed Event coordinate.
pub(crate) fn complete_event_range(
    head: u64,
    range: SeqRange,
    bounds: EventReadBounds,
    context: &mut LineageReadContextV1<'_, '_>,
) -> LineageReadResult<(u64, u64)> {
    context.step(|context| {
        let from = range.from.as_u64().max(1);
        let to = range.to.map_or(head, Seq::as_u64);
        if to > head {
            return Err(ForkReplayLineageReadErrorV1::Read(
                ForkReplayAuthorityReadErrorV1::Unavailable,
            ));
        }
        let count = if from > to { 0 } else { to - (from - 1) };
        let maximum = u64::try_from(bounds.max_events()).unwrap_or(u64::MAX);
        context.require(count <= maximum)?;
        Ok((from, to))
    })
}

pub(crate) const fn corrupt<T>() -> LineageReadResult<T> {
    Err(ForkReplayLineageReadErrorV1::Read(
        ForkReplayAuthorityReadErrorV1::CorruptAuthority,
    ))
}

pub(crate) const fn gate_error(error: ErasureContainmentErrorV1) -> ForkReplayLineageReadErrorV1 {
    match error {
        ErasureContainmentErrorV1::AccessFrozen => ForkReplayLineageReadErrorV1::AccessFrozen,
        ErasureContainmentErrorV1::RecoveryUnavailable => {
            ForkReplayLineageReadErrorV1::ContainmentUnavailable
        }
    }
}

/// Runs every member inside its adapter's Read fence. The borrowed prefix is
/// checked and the ID inserted only after the gate grants access.
pub(crate) fn read_visible_lineage(
    target: TimelineId,
    depth: usize,
    context: &mut LineageReadContextV1<'_, '_>,
    mut member: impl FnMut(
        TimelineId,
        &mut Vec<TimelineId>,
        &mut LineageReadContextV1<'_, '_>,
    ) -> LineageReadResult<Option<(ForkReplayLineageNodeV1, Seq)>>,
) -> LineageReadResult<Option<ForkReplayLineageNodeV1>> {
    context.step(|context| {
        let mut visited = Vec::new();
        let mut current = target;
        let mut result = None;
        loop {
            context.node(depth.checked_add(visited.len()))?;
            let metadata = member(current, &mut visited, context)?;
            let Some((node, _head)) = metadata else {
                return Ok(None);
            };
            let parent = node.fork_point();
            let next = parent
                .map(|(parent, _)| context.bytes(16).map(|()| *parent))
                .transpose()?;
            if result.is_none() {
                result = Some(node);
            }
            if let Some(parent) = next {
                current = parent;
            } else {
                return Ok(result);
            }
        }
    })
}

pub(crate) fn remember_member(
    timeline: TimelineId,
    visited: &mut Vec<TimelineId>,
    context: &mut LineageReadContextV1<'_, '_>,
) -> LineageReadResult<()> {
    for previous in visited.iter() {
        context.step(|_| {
            if *previous == timeline {
                corrupt()
            } else {
                Ok(())
            }
        })?;
    }
    context.bytes(16)?;
    visited.push(timeline);
    context.check()
}

/// Move the charged native carriers into one root-first history. No ordinary
/// metadata lookup or second native plan is constructed (ADR-118 H/M).
pub(crate) fn read_visible_history(
    target: TimelineId,
    context: &mut LineageReadContextV1<'_, '_>,
    mut member: impl FnMut(
        TimelineId,
        &mut Vec<TimelineId>,
        &mut LineageReadContextV1<'_, '_>,
    ) -> LineageReadResult<Option<(ForkReplayLineageNodeV1, Seq)>>,
) -> LineageReadResult<Vec<(ForkReplayLineageNodeV1, Seq)>> {
    context.step(|context| {
        let mut visited = Vec::new();
        let mut history = Vec::new();
        let mut current = target;
        loop {
            context.node(Some(visited.len()))?;
            let (node, head) = member(current, &mut visited, context)?.ok_or(
                ForkReplayLineageReadErrorV1::Read(ForkReplayAuthorityReadErrorV1::Unavailable),
            )?;
            let parent = node
                .fork_point()
                .map(|(parent, _)| context.bytes(16).map(|()| *parent))
                .transpose()?;
            history.push((node, head));
            if let Some(parent) = parent {
                current = parent;
            } else {
                return context.step(|_| {
                    history.reverse();
                    Ok(history)
                });
            }
        }
    })
}

/// Existing stitched segment arithmetic over already charged native fields.
pub(crate) fn history_segment(
    history: &[(ForkReplayLineageNodeV1, Seq)],
    index: usize,
    context: &mut LineageReadContextV1<'_, '_>,
) -> LineageReadResult<(u64, u64)> {
    context.step(|_| {
        let (node, head) = &history[index];
        let prefix = node.fork_point().map_or(0, |(_, cut)| cut.as_u64());
        let length = history
            .get(index + 1)
            .map_or(Ok(head.as_u64()), |(next, _)| {
                next.fork_point()
                    .and_then(|(_, cut)| cut.as_u64().checked_sub(prefix))
                    .ok_or(ForkReplayLineageReadErrorV1::Read(
                        ForkReplayAuthorityReadErrorV1::CorruptAuthority,
                    ))
            })?;
        if length > head.as_u64() {
            corrupt()
        } else {
            Ok((prefix, length))
        }
    })
}

pub(crate) fn history_head(
    history: &[(ForkReplayLineageNodeV1, Seq)],
    context: &mut LineageReadContextV1<'_, '_>,
) -> LineageReadResult<u64> {
    history
        .iter()
        .enumerate()
        .try_fold(0_u64, |head, (index, _)| {
            history_segment(history, index, context).and_then(|(_, length)| {
                context.step(|_| {
                    head.checked_add(length)
                        .ok_or(ForkReplayLineageReadErrorV1::Read(
                            ForkReplayAuthorityReadErrorV1::CorruptAuthority,
                        ))
                })
            })
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod canonical_length_mapping_tests {
    use super::*;
    use pos_core::trusted_clock::ScriptedGuardMonotonicSourceV1;
    use std::time::Duration;

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    fn admission(identifier: &str) -> Fallible<pos_core::ImportedForkAttributionAdmissionV1> {
        use pos_core::{
            ForkAttributionIssuerV1, ImportedForkAttributionAdmissionInputV1,
            ImportedForkAttributionAdmissionV1, PublicKey,
        };
        let digest = Hash::from_bytes([1; 32]);
        Ok(ImportedForkAttributionAdmissionV1::new(
            ImportedForkAttributionAdmissionInputV1 {
                import_operation_id: digest,
                authority_origin_digest: digest,
                full_envelope_digest: digest,
                issuer: ForkAttributionIssuerV1::new(
                    identifier,
                    u64::MAX,
                    PublicKey::from_bytes([2; 32]),
                )?,
                issuer_policy_digest: digest,
                issuer_policy_generation: u64::MAX,
                child_timeline_id: TimelineId::new(),
                final_logical_head: u64::MAX,
                closure_root: digest,
                fork_admission_digest: digest,
            },
        )?)
    }

    struct DecoderOutcome {
        value: Result<
            pos_core::ImportedForkAttributionAdmissionV1,
            crate::ForkManifestPublicationErrorV1,
        >,
        remaining: usize,
        open: bool,
    }

    fn decode_with_budget(bytes: &[u8], byte_limit: usize) -> Fallible<DecoderOutcome> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, byte_limit, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let value = NativeReadContextV1::protected(&mut budget).imported_admission(bytes);
        let remaining = budget.remaining_native_bytes();
        Ok(DecoderOutcome {
            value,
            remaining,
            open: budget.check_time().is_ok(),
        })
    }

    #[test]
    fn imported_decoder_debits_each_real_buffer_and_latches_before_one_under() -> Fallible<()> {
        for identifier in ["issuer".to_owned(), "🦀".repeat(32)] {
            let record = admission(&identifier)?;
            let bytes = record.to_canonical_cbor();
            // Existing encoders, not the borrowed gate or length methods,
            // independently measure all four real decoder allocations.
            let issuer_bytes = record.input().issuer.to_canonical_cbor().len();
            let exact = identifier.len() + issuer_bytes + bytes.len() + issuer_bytes;
            let outcome = decode_with_budget(&bytes, exact)?;
            assert_eq!(outcome.value?, record);
            assert_eq!(outcome.remaining, 0);
            assert!(outcome.open);
            let outcome = decode_with_budget(&bytes, exact - 1)?;
            assert_eq!(
                outcome.value,
                Err(crate::ForkManifestPublicationErrorV1::PublicationConflict)
            );
            assert!(!outcome.open);
            assert_eq!(
                NativeReadContextV1::ordinary().imported_admission(&bytes)?,
                record
            );
        }
        Ok(())
    }

    #[test]
    fn imported_decoder_gate_preserves_native_acceptance_on_current_bytes() -> Fallible<()> {
        use pos_core::ImportedForkAttributionAdmissionV1;
        let bytes = admission("issuer")?.to_canonical_cbor();
        let assert_parity = |candidate: &[u8]| -> Fallible<()> {
            let native = ImportedForkAttributionAdmissionV1::from_canonical_cbor(candidate);
            let guarded = decode_with_budget(candidate, 65_536)?.value;
            assert_eq!(guarded.is_ok(), native.is_ok());
            if let Ok(native) = native {
                assert_eq!(guarded?, native);
            }
            Ok(())
        };
        assert_parity(&bytes)?;
        for end in 0..bytes.len() {
            assert_parity(&bytes[..end])?;
        }
        for index in 0..bytes.len() {
            for replacement in [0, 0xff] {
                let mut changed = bytes.clone();
                changed[index] = replacement;
                assert_parity(&changed)?;
            }
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_parity(&trailing)?;
        assert_parity(&vec![
            0;
            pos_core::MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1
                + 1
        ])?;
        for (additional, width) in [(24, 1), (25, 2), (26, 4), (27, 8)] {
            let mut nonpreferred = vec![0x80 | additional];
            nonpreferred.extend_from_slice(&12_u64.to_be_bytes()[8 - width..]);
            nonpreferred.extend_from_slice(&bytes[1..]);
            assert_parity(&nonpreferred)?;
        }
        let mut too_long = admission(&"x".repeat(128))?.to_canonical_cbor();
        let issuer = AdmissionCarrierV1::field(&too_long, 5, 2).ok_or("no issuer carrier")?;
        let issuer_start = issuer.as_ptr().addr() - too_long.as_ptr().addr();
        let identifier = AdmissionCarrierV1::field(issuer, 2, 3).ok_or("no identifier carrier")?;
        let identifier_start = identifier.as_ptr().addr() - too_long.as_ptr().addr();
        too_long[issuer_start - 1] += 1;
        too_long[identifier_start - 1] = 129;
        too_long.insert(identifier_start + 128, b'x');
        assert_parity(&too_long)?;
        // Ordinary callers still use exactly the owning core decoder.
        assert!(NativeReadContextV1::ordinary()
            .imported_admission(&trailing)
            .is_err());
        Ok(())
    }

    #[test]
    fn imported_decoder_checks_original_deadline_before_and_after_its_bounded_batch() -> Fallible<()>
    {
        let bytes = admission("issuer")?.to_canonical_cbor();
        for (zero_marks, final_mark, succeeds) in [
            (2, Duration::from_secs(2), false),
            (5, Duration::from_secs(2), false),
            (7, Duration::from_secs(2), false),
            (7, Duration::from_secs(1), true),
        ] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new(
                std::iter::repeat_n(Duration::ZERO, zero_marks).chain([final_mark]),
            );
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 65_536, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let decoded = NativeReadContextV1::protected(&mut budget).imported_admission(&bytes);
            assert_eq!(decoded.is_ok(), succeeds);
            assert_eq!(budget.check_time().is_ok(), succeeds);
        }
        Ok(())
    }

    #[test]
    fn borrowed_carrier_handles_all_definite_widths_and_rejects_bad_prefixes() {
        let payload = b"issuer";
        for (additional, width) in [(24, 1), (25, 2), (26, 4), (27, 8)] {
            let mut bytes = vec![0x83, 0x64];
            bytes.extend_from_slice(b"FAI1");
            bytes.push(1);
            bytes.push(0x60 | additional);
            bytes.extend_from_slice(&6_u64.to_be_bytes()[8 - width..]);
            bytes.extend_from_slice(payload);
            assert_eq!(
                AdmissionCarrierV1::field(&bytes, 2, 3),
                Some(payload.as_slice())
            );
            // Nonpreferred width remains visible to the core decoder, not
            // normalized or accepted as native validity by this span reader.
        }
        for bytes in [
            vec![],
            vec![0x9f],
            vec![0x80],
            vec![0x40],
            vec![0x81, 0x9f],
            vec![0x81, 0x5f],
            vec![0x81, 0x78],
            vec![0x81, 0x7b, 0xff],
            vec![0x82, 0x81, 0, 0x61, b'x'],
        ] {
            assert_eq!(AdmissionCarrierV1::field(&bytes, 0, 3), None);
            assert_eq!(AdmissionCarrierV1::field(&bytes, 1, 3), None);
        }
        assert_eq!(
            AdmissionCarrierV1::field(&[0x82, 0x20, 0x61, b'x'], 1, 3),
            Some(b"x".as_slice())
        );
        assert_eq!(
            AdmissionCarrierV1::field(
                &[0x81, 0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                0,
                3
            ),
            None
        );
    }

    #[test]
    fn an_unrepresentable_native_length_permanently_closes_the_operation_ledger() -> ReadResult<()>
    {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1, 1_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        // The native counter tests exercise actual overflow arithmetic. This
        // narrow injection tests only its closed-error mapping without asking
        // a fixture to allocate a target-address-space-sized string.
        assert_eq!(
            budget.charge_canonical(Err(pos_core::CanonicalLengthErrorV1::LengthOverflow)),
            Err(ForkReplayAuthorityReadErrorV1::BoundsExceeded),
        );
        assert_eq!(
            budget.charge_canonical(Ok(0)),
            Err(ForkReplayAuthorityReadErrorV1::BoundsExceeded)
        );
        Ok(())
    }
}
