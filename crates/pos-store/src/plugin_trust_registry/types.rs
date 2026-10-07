//! Value types of the Plugin trust policy registry port.
//!
//! Every retained, receipt, and ledger type is opaque: its fields are
//! crate-private, so only the registry adapters can mint one, and it exposes
//! read accessors only. None of them carries a PMF1 signature-validity claim,
//! and no registry method accepts one as live authority (ADR-103 revision 4,
//! decision 1).

use pos_core::{Event, EventDraft, EventId, SchemaVersion, Seq, TimelineId};

/// The activation Event the trusted composition supplies to an admission or a rollback.
///
/// The registry never constructs, edits, or interprets the payload; the
/// composition owns its semantics and the hosting Timeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationEventInputV1 {
    /// The Timeline that hosts the activation Event.
    pub timeline: TimelineId,
    /// The already validated Event draft.
    pub draft: EventDraft,
}

impl ActivationEventInputV1 {
    /// BLAKE3-256 of the draft payload, computed by the registry itself.
    pub(crate) fn payload_digest(&self) -> [u8; 32] {
        *blake3::hash(self.draft.payload.as_slice()).as_bytes()
    }
}

/// The retained identity of one committed activation Event.
///
/// The first six accessors are the identity compared by idempotency; the
/// origin sequence is an extra retained fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationEventIdentityV1 {
    pub(crate) timeline: TimelineId,
    pub(crate) event_id: EventId,
    pub(crate) seq: Seq,
    pub(crate) event_type: String,
    pub(crate) schema_version: SchemaVersion,
    pub(crate) payload_digest: [u8; 32],
    pub(crate) origin_logical_seq: Option<Seq>,
}

impl ActivationEventIdentityV1 {
    /// Capture the identity of the Event the guarded append just returned.
    pub(crate) fn from_event(
        timeline: TimelineId,
        event: &Event,
        payload_digest: [u8; 32],
    ) -> Self {
        Self {
            timeline,
            event_id: event.id,
            seq: event.seq,
            event_type: event.event_type.as_str().to_owned(),
            schema_version: event.schema_version,
            payload_digest,
            origin_logical_seq: event.origin.map(|origin| origin.origin_logical_seq),
        }
    }

    /// Whether `input` names the same Timeline, type, schema version, and payload digest.
    pub(crate) fn matches_input(&self, input: &ActivationEventInputV1) -> bool {
        self.timeline == input.timeline
            && self.event_type == input.draft.event_type.as_str()
            && self.schema_version == input.draft.schema_version
            && self.payload_digest == input.payload_digest()
    }

    /// The Timeline that hosts the Event.
    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline
    }

    /// The store-assigned Event ID.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    /// The logical Timeline sequence, `Event.seq` as the guarded append returned it.
    #[must_use]
    pub const fn seq(&self) -> Seq {
        self.seq
    }

    /// The Event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// The Event schema version.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// BLAKE3-256 of the Event payload.
    #[must_use]
    pub const fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    /// The first-commit logical sequence, when the store reported one.
    #[must_use]
    pub const fn origin_logical_seq(&self) -> Option<Seq> {
        self.origin_logical_seq
    }
}

/// Whether an operation committed new state or returned an earlier result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginTrustCommitOutcomeV1 {
    /// The operation committed a new decision.
    Committed,
    /// An identical earlier decision was returned; only the UTC floor was raised.
    IdempotentReplay,
}

/// The result of `provision`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisionOutcomeV1 {
    /// The scope was created.
    Created,
    /// The scope already existed under the same anchor; nothing was written.
    Unchanged,
}

/// Whether `advance_policy` changed anything besides the UTC floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyAdvanceKindV1 {
    /// The TPS1 digest or a floor changed.
    Advanced,
    /// Only the highest trusted UTC second may have changed.
    Unchanged,
}

/// The result of `advance_policy`: plain data that carries no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyAdvanceOutcomeV1 {
    /// Whether the policy advanced.
    pub outcome: PolicyAdvanceKindV1,
    /// The retained TPS1 full-byte digest after the operation.
    pub tps1_digest: [u8; 32],
    /// The retained TPS1 epoch after the operation.
    pub tps1_epoch: u64,
    /// The PTR1 `(root_version, digest)` floor after the operation.
    pub ptr1_floor: Option<(u64, [u8; 32])>,
    /// The PRV1 `(policy_epoch, digest)` floor after the operation.
    pub prv1_floor: Option<(u64, [u8; 32])>,
}

/// One retained, admitted release decision. Claims trust-policy admission only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedReleaseDecisionV1 {
    pub(crate) scope: String,
    pub(crate) plugin_id: String,
    pub(crate) pmf1_digest: [u8; 32],
    pub(crate) release_digest: [u8; 32],
    pub(crate) previous_release_digest: Option<[u8; 32]>,
    pub(crate) tps1_digest: [u8; 32],
    pub(crate) tps1_epoch: u64,
    pub(crate) tps1_effective_position: u64,
    pub(crate) terminal_root: (u64, [u8; 32]),
    pub(crate) terminal_revocation: (u64, [u8; 32]),
    pub(crate) trusted_utc_second: i64,
    pub(crate) tick: u64,
    pub(crate) activation_event: ActivationEventIdentityV1,
}

impl RetainedReleaseDecisionV1 {
    /// The exact policy scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The exact Plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.pmf1_digest
    }

    /// The PMF1 release digest (field 27).
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.release_digest
    }

    /// The PMF1 previous-release digest (field 24).
    #[must_use]
    pub const fn previous_release_digest(&self) -> Option<[u8; 32]> {
        self.previous_release_digest
    }

    /// The authenticated TPS1 full-byte digest.
    #[must_use]
    pub const fn tps1_digest(&self) -> [u8; 32] {
        self.tps1_digest
    }

    /// The authenticated TPS1 epoch.
    #[must_use]
    pub const fn tps1_epoch(&self) -> u64 {
        self.tps1_epoch
    }

    /// The TPS1 effective Timeline position, an uninterpreted retained fact.
    #[must_use]
    pub const fn tps1_effective_position(&self) -> u64 {
        self.tps1_effective_position
    }

    /// The evidence's terminal PTR1 `(root_version, digest)`.
    #[must_use]
    pub const fn terminal_root(&self) -> (u64, [u8; 32]) {
        self.terminal_root
    }

    /// The evidence's terminal PRV1 `(policy_epoch, digest)`.
    #[must_use]
    pub const fn terminal_revocation(&self) -> (u64, [u8; 32]) {
        self.terminal_revocation
    }

    /// The trusted UTC second of the transaction.
    #[must_use]
    pub const fn trusted_utc_second(&self) -> i64 {
        self.trusted_utc_second
    }

    /// The host Tick of the transaction.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// The identity of the activation Event committed with the decision.
    #[must_use]
    pub const fn activation_event(&self) -> &ActivationEventIdentityV1 {
        &self.activation_event
    }
}

/// The receipt of one `admit`: the retained decision plus how it was reached.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedPluginReleaseReceiptV1 {
    pub(crate) decision: RetainedReleaseDecisionV1,
    pub(crate) outcome: PluginTrustCommitOutcomeV1,
}

impl AdmittedPluginReleaseReceiptV1 {
    /// The decision, original on an idempotent replay.
    #[must_use]
    pub const fn decision(&self) -> &RetainedReleaseDecisionV1 {
        &self.decision
    }

    /// Whether this call committed or replayed.
    #[must_use]
    pub const fn outcome(&self) -> PluginTrustCommitOutcomeV1 {
        self.outcome
    }
}

/// The facts of one committed rollback, kept in its ledger row and read through its receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RollbackFactsV1 {
    pub(crate) scope: String,
    pub(crate) plugin_id: String,
    pub(crate) target_pmf1_digest: [u8; 32],
    pub(crate) target_release_digest: [u8; 32],
    pub(crate) replaced_pmf1_digest: [u8; 32],
    pub(crate) tps1_digest: [u8; 32],
    pub(crate) tps1_epoch: u64,
    pub(crate) tps1_effective_position: u64,
    pub(crate) terminal_root: (u64, [u8; 32]),
    pub(crate) terminal_revocation: (u64, [u8; 32]),
    pub(crate) trusted_utc_second: i64,
    pub(crate) tick: u64,
    pub(crate) activation_event: ActivationEventIdentityV1,
}

/// The receipt of one `rollback`. Claims trust-policy admission only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginRollbackReceiptV1 {
    pub(crate) facts: RollbackFactsV1,
    pub(crate) outcome: PluginTrustCommitOutcomeV1,
}

impl PluginRollbackReceiptV1 {
    /// The exact policy scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.facts.scope
    }

    /// The exact Plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.facts.plugin_id
    }

    /// The target release's complete PMF1 digest.
    #[must_use]
    pub const fn target_pmf1_digest(&self) -> [u8; 32] {
        self.facts.target_pmf1_digest
    }

    /// The target release's PMF1 release digest.
    #[must_use]
    pub const fn target_release_digest(&self) -> [u8; 32] {
        self.facts.target_release_digest
    }

    /// The complete PMF1 digest of the release the rollback replaced.
    #[must_use]
    pub const fn replaced_pmf1_digest(&self) -> [u8; 32] {
        self.facts.replaced_pmf1_digest
    }

    /// The authenticated TPS1 full-byte digest.
    #[must_use]
    pub const fn tps1_digest(&self) -> [u8; 32] {
        self.facts.tps1_digest
    }

    /// The authenticated TPS1 epoch.
    #[must_use]
    pub const fn tps1_epoch(&self) -> u64 {
        self.facts.tps1_epoch
    }

    /// The TPS1 effective Timeline position, an uninterpreted retained fact.
    #[must_use]
    pub const fn tps1_effective_position(&self) -> u64 {
        self.facts.tps1_effective_position
    }

    /// The evidence's terminal PTR1 `(root_version, digest)`.
    #[must_use]
    pub const fn terminal_root(&self) -> (u64, [u8; 32]) {
        self.facts.terminal_root
    }

    /// The evidence's terminal PRV1 `(policy_epoch, digest)`.
    #[must_use]
    pub const fn terminal_revocation(&self) -> (u64, [u8; 32]) {
        self.facts.terminal_revocation
    }

    /// The trusted UTC second of the transaction.
    #[must_use]
    pub const fn trusted_utc_second(&self) -> i64 {
        self.facts.trusted_utc_second
    }

    /// The host Tick of the transaction.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.facts.tick
    }

    /// The identity of the activation Event committed with the rollback.
    #[must_use]
    pub const fn activation_event(&self) -> &ActivationEventIdentityV1 {
        &self.facts.activation_event
    }

    /// Whether this call committed or replayed.
    #[must_use]
    pub const fn outcome(&self) -> PluginTrustCommitOutcomeV1 {
        self.outcome
    }
}

/// The active release of one `(scope, exact Plugin ID)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveReleaseV1 {
    pub(crate) scope: String,
    pub(crate) plugin_id: String,
    pub(crate) pmf1_digest: [u8; 32],
    pub(crate) release_digest: [u8; 32],
    pub(crate) activation_event: ActivationEventIdentityV1,
}

impl ActiveReleaseV1 {
    /// The exact policy scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The exact Plugin ID.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// The active release's complete PMF1 digest.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.pmf1_digest
    }

    /// The active release's PMF1 release digest.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.release_digest
    }

    /// The identity of the Event that made this release active.
    #[must_use]
    pub const fn activation_event(&self) -> &ActivationEventIdentityV1 {
        &self.activation_event
    }
}

/// The retained policy state of one scope. It carries no Plugin ID and no decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedPolicyStateV1 {
    pub(crate) scope: String,
    pub(crate) tps1_epoch: u64,
    pub(crate) tps1_digest: [u8; 32],
    pub(crate) tps1_effective_position: u64,
    pub(crate) tps1_bytes: Vec<u8>,
    pub(crate) ptr1_floor: Option<(u64, [u8; 32])>,
    pub(crate) prv1_floor: Option<(u64, [u8; 32])>,
    pub(crate) highest_trusted_utc_second: Option<i64>,
}

impl RetainedPolicyStateV1 {
    /// The exact policy scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The retained TPS1 epoch.
    #[must_use]
    pub const fn tps1_epoch(&self) -> u64 {
        self.tps1_epoch
    }

    /// The retained TPS1 full-byte digest.
    #[must_use]
    pub const fn tps1_digest(&self) -> [u8; 32] {
        self.tps1_digest
    }

    /// The retained TPS1 effective Timeline position.
    #[must_use]
    pub const fn tps1_effective_position(&self) -> u64 {
        self.tps1_effective_position
    }

    /// The exact retained canonical TPS1 bytes.
    #[must_use]
    pub fn tps1_bytes(&self) -> &[u8] {
        &self.tps1_bytes
    }

    /// The PTR1 `(root_version, digest)` floor, absent until the first advance or admission.
    #[must_use]
    pub const fn ptr1_floor(&self) -> Option<(u64, [u8; 32])> {
        self.ptr1_floor
    }

    /// The PRV1 `(policy_epoch, digest)` floor, absent until the first advance or admission.
    #[must_use]
    pub const fn prv1_floor(&self) -> Option<(u64, [u8; 32])> {
        self.prv1_floor
    }

    /// The highest committed trusted UTC second, absent until the first transaction.
    #[must_use]
    pub const fn highest_trusted_utc_second(&self) -> Option<i64> {
        self.highest_trusted_utc_second
    }
}

/// The kind of one append-only ledger row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginTrustLedgerKindV1 {
    /// The scope was provisioned.
    Provision,
    /// The policy advanced without a release.
    Advance,
    /// A release was admitted and activated.
    Admission,
    /// A retained release was re-activated.
    Rollback,
}

/// The kind-specific columns of a ledger row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PluginTrustLedgerBodyV1 {
    Provision,
    Advance {
        utc: i64,
        tick: u64,
    },
    Admission {
        decision: Box<RetainedReleaseDecisionV1>,
        previous_active_pmf1_digest: Option<[u8; 32]>,
    },
    Rollback(Box<RollbackFactsV1>),
}

/// The release columns shared by `Admission` and `Rollback` rows.
struct ReleaseColumnsV1<'a> {
    plugin_id: &'a str,
    pmf1_digest: [u8; 32],
    release_digest: [u8; 32],
    previous_active_pmf1_digest: Option<[u8; 32]>,
    event: &'a ActivationEventIdentityV1,
}

impl PluginTrustLedgerBodyV1 {
    const fn kind(&self) -> PluginTrustLedgerKindV1 {
        match self {
            Self::Provision => PluginTrustLedgerKindV1::Provision,
            Self::Advance { .. } => PluginTrustLedgerKindV1::Advance,
            Self::Admission { .. } => PluginTrustLedgerKindV1::Admission,
            Self::Rollback(_) => PluginTrustLedgerKindV1::Rollback,
        }
    }

    const fn coordinates(&self) -> Option<(i64, u64)> {
        match self {
            Self::Provision => None,
            Self::Advance { utc, tick } => Some((*utc, *tick)),
            Self::Admission { decision, .. } => Some((decision.trusted_utc_second, decision.tick)),
            Self::Rollback(facts) => Some((facts.trusted_utc_second, facts.tick)),
        }
    }

    fn release(&self) -> Option<ReleaseColumnsV1<'_>> {
        match self {
            Self::Provision | Self::Advance { .. } => None,
            Self::Admission {
                decision,
                previous_active_pmf1_digest,
            } => Some(ReleaseColumnsV1 {
                plugin_id: &decision.plugin_id,
                pmf1_digest: decision.pmf1_digest,
                release_digest: decision.release_digest,
                previous_active_pmf1_digest: *previous_active_pmf1_digest,
                event: &decision.activation_event,
            }),
            Self::Rollback(facts) => Some(ReleaseColumnsV1 {
                plugin_id: &facts.plugin_id,
                pmf1_digest: facts.target_pmf1_digest,
                release_digest: facts.target_release_digest,
                previous_active_pmf1_digest: Some(facts.replaced_pmf1_digest),
                event: &facts.activation_event,
            }),
        }
    }
}

/// One append-only ledger row, keyed `(scope, row_seq)` with `row_seq` from 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginTrustLedgerRowV1 {
    pub(crate) row_seq: u64,
    pub(crate) tps1_digest: [u8; 32],
    pub(crate) tps1_epoch: u64,
    pub(crate) tps1_effective_position: u64,
    pub(crate) ptr1_floor: Option<(u64, [u8; 32])>,
    pub(crate) prv1_floor: Option<(u64, [u8; 32])>,
    pub(crate) body: PluginTrustLedgerBodyV1,
}

impl PluginTrustLedgerRowV1 {
    /// The strictly increasing row sequence, starting at 1.
    #[must_use]
    pub const fn row_seq(&self) -> u64 {
        self.row_seq
    }

    /// The row kind.
    #[must_use]
    pub const fn kind(&self) -> PluginTrustLedgerKindV1 {
        self.body.kind()
    }

    /// The retained TPS1 full-byte digest after the operation.
    #[must_use]
    pub const fn tps1_digest(&self) -> [u8; 32] {
        self.tps1_digest
    }

    /// The retained TPS1 epoch after the operation.
    #[must_use]
    pub const fn tps1_epoch(&self) -> u64 {
        self.tps1_epoch
    }

    /// The retained TPS1 effective Timeline position after the operation.
    #[must_use]
    pub const fn tps1_effective_position(&self) -> u64 {
        self.tps1_effective_position
    }

    /// The PTR1 floor after the operation; absent for a `Provision` row.
    #[must_use]
    pub const fn ptr1_floor(&self) -> Option<(u64, [u8; 32])> {
        self.ptr1_floor
    }

    /// The PRV1 floor after the operation; absent for a `Provision` row.
    #[must_use]
    pub const fn prv1_floor(&self) -> Option<(u64, [u8; 32])> {
        self.prv1_floor
    }

    /// The transaction's trusted UTC second; absent for a `Provision` row.
    #[must_use]
    pub fn trusted_utc_second(&self) -> Option<i64> {
        self.body.coordinates().map(|(utc, _)| utc)
    }

    /// The transaction's host Tick; absent for a `Provision` row.
    #[must_use]
    pub fn tick(&self) -> Option<u64> {
        self.body.coordinates().map(|(_, tick)| tick)
    }

    /// The exact Plugin ID of an `Admission` or `Rollback` row.
    #[must_use]
    pub fn plugin_id(&self) -> Option<&str> {
        self.body.release().map(|release| release.plugin_id)
    }

    /// The complete PMF1 digest of an `Admission` row, or the target of a `Rollback` row.
    #[must_use]
    pub fn pmf1_digest(&self) -> Option<[u8; 32]> {
        self.body.release().map(|release| release.pmf1_digest)
    }

    /// The release digest of an `Admission` row, or of the target of a `Rollback` row.
    #[must_use]
    pub fn release_digest(&self) -> Option<[u8; 32]> {
        self.body.release().map(|release| release.release_digest)
    }

    /// The previously active complete PMF1 digest; absent for a first activation.
    #[must_use]
    pub fn previous_active_pmf1_digest(&self) -> Option<[u8; 32]> {
        self.body
            .release()
            .and_then(|release| release.previous_active_pmf1_digest)
    }

    /// The identity of the activation Event of an `Admission` or `Rollback` row.
    #[must_use]
    pub fn activation_event(&self) -> Option<&ActivationEventIdentityV1> {
        self.body.release().map(|release| release.event)
    }
}
