//! ADR-114 bounded, read-only Fork attribution validation.
//!
//! Requirements and limits are structural values. Only their binding into an
//! installed runtime verifier's protected-use result selects required evidence;
//! none of these values grants signing, append or protected-release authority.

use crate::CommittedForkManifestV1;
use pos_core::{
    trusted_clock::{GuardMonotonicSourceV1, MonotonicMarkV1},
    Hash, Seq, TimelineId,
};

pub(crate) mod sizes;

pub(crate) trait CanonicalSizeV1 {
    fn canonical_size(&self) -> Result<usize, pos_core::CanonicalLengthErrorV1>;
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
        let within = !self.failed
            && self
                .clock
                .mark()
                .checked_elapsed_since(self.started)
                .is_some_and(|elapsed| {
                    elapsed.as_micros() <= u128::from(self.limits.elapsed_micros)
                });
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
            let imported = pos_core::ImportedForkPublicationOperationV1::from_local(
                committed.operation.clone(),
                origin,
            );
            budget.charge_canonical(imported.canonical_cbor_len())?;
            imported.to_canonical_cbor()
        } else {
            budget.charge_canonical(committed.operation.canonical_cbor_len())?;
            committed.operation.to_canonical_cbor()
        };
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

/// Count an existing registry's native CBOR representation without buffering it.
pub(crate) fn charge_registry(
    registry: &pos_core::KeyRegistryStateV1,
    budget: &mut ForkReplayReadBudgetV1<'_>,
) -> ReadResult<()> {
    struct Counter<'borrow, 'clock>(&'borrow mut ForkReplayReadBudgetV1<'clock>);
    impl std::io::Write for Counter<'_, '_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .charge_bytes(bytes.len())
                .map(|()| bytes.len())
                .map_err(std::io::Error::other)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    ciborium::into_writer(registry, Counter(budget))
        .map_err(|_| ForkReplayAuthorityReadErrorV1::BoundsExceeded)
}

/// Object-safe adapter read bridge.
///
/// Its implementation must use a held store
/// interval and the existing transaction-internal validator (b), never a new
/// nested transaction, signer, permit or recovery decision.
pub trait ForkReplayAuthorityReadPortV1 {
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod canonical_length_mapping_tests {
    use super::*;
    use pos_core::trusted_clock::ScriptedGuardMonotonicSourceV1;
    use std::time::Duration;

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
