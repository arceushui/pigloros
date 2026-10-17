//! Value types of the composition fallback registry port.
//!
//! The requests are plain caller-built values. Every state, ledger, and receipt type is opaque:
//! its fields are crate-private, so only the registry adapters can mint one, and it exposes read
//! accessors only.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::{
    EntityId, EventId, FallbackSkippedCandidateV1, FallbackTriggerBasisV1, FallbackTriggerCodeV1,
    Hash, ImplementationKeyV1, Seq, TimelineId,
};

/// The domain of [`FallbackConformanceSetsV1::digest`].
const CONFORMANCE_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.Composition.FallbackConformance.v1\0";

/// Where an operation's Event goes: the Timeline the community passes step, and the
/// composition's host entity on it.
///
/// The Timeline is part of the registry key; the entity is recorded at the first operation and
/// every later operation must name it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompositionFallbackTargetV1 {
    /// The Timeline that hosts the declaration and activation Events.
    pub timeline: TimelineId,
    /// The entity that authors every Event the registry appends.
    pub entity: EntityId,
}

/// The host-supplied conformance sets of one declaration, frozen into its ledger row.
///
/// Each entry key maps to the Stable passing-profile digests of that entry's declared primary
/// (ADR-119 section 4.1, rule 7). The registry does not evaluate rule 7; it retains the digest
/// of the sets so a retried declaration is byte-identical only with the same sets.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FallbackConformanceSetsV1 {
    sets: BTreeMap<String, BTreeSet<Hash>>,
}

impl FallbackConformanceSetsV1 {
    /// Wrap the per-entry profile digest sets.
    #[must_use]
    pub const fn new(sets: BTreeMap<String, BTreeSet<Hash>>) -> Self {
        Self { sets }
    }

    /// Return the per-entry profile digest sets.
    #[must_use]
    pub const fn sets(&self) -> &BTreeMap<String, BTreeSet<Hash>> {
        &self.sets
    }

    /// BLAKE3-256 over the length-prefixed entry keys and their sorted digests.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CONFORMANCE_DIGEST_DOMAIN_V1);
        hasher.update(&(self.sets.len() as u64).to_le_bytes());
        for (entry_key, digests) in &self.sets {
            update_text(&mut hasher, entry_key);
            hasher.update(&(digests.len() as u64).to_le_bytes());
            digests.iter().for_each(|digest| {
                hasher.update(digest.as_bytes());
            });
        }
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }
}

/// Feed one length-prefixed text into `hasher`.
pub(crate) fn update_text(hasher: &mut blake3::Hasher, text: &str) {
    hasher.update(&(text.len() as u64).to_le_bytes());
    hasher.update(text.as_bytes());
}

/// One `declare` request (ADR-119 section 4.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackDeclareRequestV1 {
    /// The composition scope; the DFP1 scope must equal it.
    pub scope: String,
    /// The Timeline and entity of the declaration Event.
    pub target: CompositionFallbackTargetV1,
    /// The state revision the caller derived its decision from.
    pub expected_state_revision: u64,
    /// The target Timeline's Logical Head the caller derived its decision from.
    pub expected_logical_head: Seq,
    /// The canonical DFP1 bytes.
    pub policy_bytes: Vec<u8>,
    /// The host-supplied conformance sets of the declared primaries.
    pub conformance: FallbackConformanceSetsV1,
}

/// One `activate` request (ADR-119 section 4.3).
///
/// The registry assigns the activation ordinal and names the current policy digest itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackActivateRequestV1 {
    /// The composition scope.
    pub scope: String,
    /// The Timeline and entity of the activation Event.
    pub target: CompositionFallbackTargetV1,
    /// The state revision the caller derived its decision from.
    pub expected_state_revision: u64,
    /// The target Timeline's Logical Head the caller derived its decision from.
    pub expected_logical_head: Seq,
    /// The entry whose tenure closes.
    pub entry_key: String,
    /// The ordinal of the closing tenure; the new tenure is this plus one.
    pub closing_tenure_ordinal: u64,
    /// The entry's effective implementation.
    pub from: ImplementationKeyV1,
    /// The implementation the new tenure runs.
    pub to: ImplementationKeyV1,
    /// The trigger code the activation records.
    pub trigger_code: FallbackTriggerCodeV1,
    /// The cause code and origin of the activation.
    pub trigger_basis: FallbackTriggerBasisV1,
    /// The candidates the boundary skipped, at most two.
    pub skipped: Vec<FallbackSkippedCandidateV1>,
    /// The Tick of the owning boundary, recorded in the ledger only.
    pub tick: u64,
}

/// The recorded state of one entry: its tenure, effective implementation, and chain position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackEntryStateV1 {
    pub(crate) tenure_ordinal: u64,
    pub(crate) effective_digest: Hash,
    pub(crate) chain_position: u8,
}

impl FallbackEntryStateV1 {
    /// The ordinal of the entry's current tenure; tenure 0 is the composer's base.
    #[must_use]
    pub const fn tenure_ordinal(&self) -> u64 {
        self.tenure_ordinal
    }

    /// The IMK1 digest of the entry's effective implementation.
    #[must_use]
    pub const fn effective_digest(&self) -> Hash {
        self.effective_digest
    }

    /// The index of the effective implementation in `[primary, candidates...]`.
    #[must_use]
    pub const fn chain_position(&self) -> u8 {
        self.chain_position
    }
}

/// The folded registry state of one `(scope, timeline)`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FallbackRegistryStateV1 {
    pub(crate) state_revision: u64,
    pub(crate) policy_digest: Option<Hash>,
    pub(crate) activation_ordinal: u64,
    pub(crate) entries: BTreeMap<String, FallbackEntryStateV1>,
}

impl FallbackRegistryStateV1 {
    /// The number of declaration and activation Events folded.
    #[must_use]
    pub const fn state_revision(&self) -> u64 {
        self.state_revision
    }

    /// The current policy digest, or `None` before the first declaration.
    #[must_use]
    pub const fn policy_digest(&self) -> Option<Hash> {
        self.policy_digest
    }

    /// The ordinal of the latest activation, or 0 before the first.
    #[must_use]
    pub const fn activation_ordinal(&self) -> u64 {
        self.activation_ordinal
    }

    /// Every recorded entry, by entry key, including entries frozen by a re-base.
    #[must_use]
    pub const fn entries(&self) -> &BTreeMap<String, FallbackEntryStateV1> {
        &self.entries
    }
}

/// The stored row of one `(scope, timeline)`: the recorded entity and the folded state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackRegistryRowV1 {
    pub(crate) entity: EntityId,
    pub(crate) state: FallbackRegistryStateV1,
}

impl FallbackRegistryRowV1 {
    /// The entity recorded at the row's first operation.
    #[must_use]
    pub const fn entity(&self) -> EntityId {
        self.entity
    }

    /// The folded state.
    #[must_use]
    pub const fn state(&self) -> &FallbackRegistryStateV1 {
        &self.state
    }
}

/// The identity of one committed declaration or activation Event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackEventIdentityV1 {
    pub(crate) event_id: EventId,
    pub(crate) seq: Seq,
    pub(crate) payload_digest: Hash,
}

impl FallbackEventIdentityV1 {
    /// The store-assigned Event ID.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    /// The logical Timeline sequence of the Event.
    #[must_use]
    pub const fn seq(&self) -> Seq {
        self.seq
    }

    /// BLAKE3-256 of the Event payload.
    #[must_use]
    pub const fn payload_digest(&self) -> Hash {
        self.payload_digest
    }
}

/// The operation-specific part of one ledger row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FallbackLedgerBodyV1 {
    /// A declaration or withdrawal.
    Declaration {
        /// The digest of the frozen conformance sets.
        conformance_digest: Hash,
    },
    /// An activation.
    Activation {
        /// The entry whose tenure closed.
        entry_key: String,
        /// The ordinal of the closed tenure.
        closing_tenure_ordinal: u64,
        /// The registry-assigned activation ordinal.
        activation_ordinal: u64,
        /// The Tick of the owning boundary.
        tick: u64,
    },
}

/// One append-only ledger row: one committed operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackLedgerRowV1 {
    pub(crate) row_seq: u64,
    pub(crate) entity: EntityId,
    pub(crate) state_revision: u64,
    pub(crate) policy_digest: Hash,
    pub(crate) request_digest: Hash,
    pub(crate) event: FallbackEventIdentityV1,
    pub(crate) body: FallbackLedgerBodyV1,
}

impl FallbackLedgerRowV1 {
    /// The row's 1-based position in its `(scope, timeline)` ledger.
    #[must_use]
    pub const fn row_seq(&self) -> u64 {
        self.row_seq
    }

    /// The entity that authored the Event.
    #[must_use]
    pub const fn entity(&self) -> EntityId {
        self.entity
    }

    /// The state revision after the operation.
    #[must_use]
    pub const fn state_revision(&self) -> u64 {
        self.state_revision
    }

    /// The declared policy digest, or the policy in force for an activation.
    #[must_use]
    pub const fn policy_digest(&self) -> Hash {
        self.policy_digest
    }

    /// The digest of the request, which decides whether a repeat is byte-identical.
    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.request_digest
    }

    /// The committed Event.
    #[must_use]
    pub const fn event(&self) -> FallbackEventIdentityV1 {
        self.event
    }

    /// The operation-specific fields.
    #[must_use]
    pub const fn body(&self) -> &FallbackLedgerBodyV1 {
        &self.body
    }

    /// Whether this row is the declaration of `policy_digest`.
    pub(crate) fn declares(&self, policy_digest: Hash) -> bool {
        matches!(self.body, FallbackLedgerBodyV1::Declaration { .. })
            && self.policy_digest == policy_digest
    }

    /// Whether this row is the activation that closed `(entry_key, closing_tenure_ordinal)`.
    pub(crate) fn closes(&self, key: &str, closing: u64) -> bool {
        matches!(
            &self.body,
            FallbackLedgerBodyV1::Activation { entry_key, closing_tenure_ordinal, .. }
                if entry_key == key && *closing_tenure_ordinal == closing
        )
    }
}

/// Whether an operation committed or returned the original result of a byte-identical repeat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackCommitOutcomeV1 {
    /// The operation committed its row change, Event, and ledger row.
    Committed,
    /// A byte-identical repeat: the original ledger row is returned and nothing is written.
    IdempotentReplay,
}

/// The result of one `declare` or `activate`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackCommitReceiptV1 {
    pub(crate) row: FallbackLedgerRowV1,
    pub(crate) outcome: FallbackCommitOutcomeV1,
}

impl FallbackCommitReceiptV1 {
    /// The ledger row of the committed operation.
    #[must_use]
    pub const fn row(&self) -> &FallbackLedgerRowV1 {
        &self.row
    }

    /// Whether this call committed.
    #[must_use]
    pub const fn outcome(&self) -> FallbackCommitOutcomeV1 {
        self.outcome
    }
}

/// Whether `provision_fallback_registry` created the tables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackProvisionOutcomeV1 {
    /// The tables were created.
    Created,
    /// The complete table set already existed.
    Unchanged,
}
