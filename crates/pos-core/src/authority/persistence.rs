//! Durable authority-grant and revocation state owned by the trusted host.

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;

use super::{
    bytes, decode_bounded_array, decode_hash, decode_timeline, decode_u64, encode_value,
    expect_header, hash_value, timeline_bytes, uint, validate_hash, validate_timeline_id,
    AuthorityErrorV1, CapabilityGrantV1, DelegationChainV1, Hash, Seq, TimelineId,
};
use crate::CanonicalBytes;

const PERSISTENCE_MAGIC: [u8; 4] = *b"APS1";
const REVOCATION_MAGIC: [u8; 4] = *b"CRF1";
const VERSION: u8 = 1;

/// Maximum grants retained in one V1 authority persistence state.
pub const MAX_PERSISTED_AUTHORITY_GRANTS: usize = 4_096;
/// Maximum canonical bytes in one V1 authority persistence state.
pub const MAX_PERSISTED_AUTHORITY_STATE_BYTES: usize = 16 * 1_024 * 1_024;

/// Closed persistence failures that do not reveal protected record existence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorityPersistenceErrorV1 {
    #[error("authority persistence record is invalid")]
    InvalidRecord,
    #[error("authority persistence operation conflicts with recorded state")]
    Conflict,
    #[error("authority revocation epoch is stale")]
    StaleEpoch,
    #[error("authority mutation violates Timeline Order")]
    TimelineOrder,
    #[error("authority persistence is unavailable")]
    Unavailable,
}

impl From<AuthorityErrorV1> for AuthorityPersistenceErrorV1 {
    fn from(_: AuthorityErrorV1) -> Self {
        Self::InvalidRecord
    }
}

/// Result of an idempotent grant or revocation commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityCommitOutcomeV1 {
    Committed,
    Unchanged,
}

/// Unvalidated fields for one immutable capability-revocation fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationDraftV1 {
    pub grant_id: Hash,
    pub authority_timeline: TimelineId,
    pub fence_position: Seq,
    pub revocation_epoch: u64,
    pub policy_revision: Hash,
    pub authority_registry_digest: Hash,
}

/// Immutable revocation fence for one capability grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRevocationV1 {
    grant_id: Hash,
    authority_timeline: TimelineId,
    fence_position: Seq,
    revocation_epoch: u64,
    policy_revision: Hash,
    authority_registry_digest: Hash,
}

impl CapabilityRevocationV1 {
    /// Validate an immutable revocation fence.
    ///
    /// # Errors
    /// Returns a closed validation error for zero identities, positions, epochs, or digests.
    pub fn try_from_draft(
        draft: CapabilityRevocationDraftV1,
    ) -> Result<Self, AuthorityPersistenceErrorV1> {
        validate_hash(draft.grant_id)
            .and_then(|()| validate_timeline_id(draft.authority_timeline))
            .and_then(|()| validate_hash(draft.policy_revision))
            .and_then(|()| validate_hash(draft.authority_registry_digest))
            .map_err(AuthorityPersistenceErrorV1::from)
            .and_then(|()| {
                if draft.fence_position == Seq::ZERO || draft.revocation_epoch == 0 {
                    Err(AuthorityPersistenceErrorV1::InvalidRecord)
                } else {
                    Ok(Self {
                        grant_id: draft.grant_id,
                        authority_timeline: draft.authority_timeline,
                        fence_position: draft.fence_position,
                        revocation_epoch: draft.revocation_epoch,
                        policy_revision: draft.policy_revision,
                        authority_registry_digest: draft.authority_registry_digest,
                    })
                }
            })
    }

    #[must_use]
    pub const fn grant_id(&self) -> Hash {
        self.grant_id
    }

    #[must_use]
    pub const fn authority_timeline(&self) -> TimelineId {
        self.authority_timeline
    }

    #[must_use]
    pub const fn fence_position(&self) -> Seq {
        self.fence_position
    }

    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    #[must_use]
    pub const fn policy_revision(&self) -> Hash {
        self.policy_revision
    }

    #[must_use]
    pub const fn authority_registry_digest(&self) -> Hash {
        self.authority_registry_digest
    }

    /// Encode the exact deterministic-CBOR CRF1 record.
    ///
    /// # Errors
    /// Returns a closed error if canonical encoding fails.
    pub fn encode(&self) -> Result<CanonicalBytes, AuthorityPersistenceErrorV1> {
        encode_value(&Value::Array(vec![
            bytes(&REVOCATION_MAGIC),
            uint(VERSION),
            hash_value(self.grant_id),
            bytes(&timeline_bytes(self.authority_timeline)),
            uint(self.fence_position.as_u64()),
            uint(self.revocation_epoch),
            hash_value(self.policy_revision),
            hash_value(self.authority_registry_digest),
        ]))
        .map(CanonicalBytes::from_vec)
        .map_err(AuthorityPersistenceErrorV1::from)
    }

    /// Decode and validate one exact deterministic-CBOR CRF1 record.
    ///
    /// # Errors
    /// Returns a closed error for malformed, noncanonical, or unsupported input.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, AuthorityPersistenceErrorV1> {
        decode_bounded_array(bytes.as_slice(), 1_024, 8)
            .map_err(AuthorityPersistenceErrorV1::from)
            .and_then(|fields| {
                expect_header(&fields, REVOCATION_MAGIC)
                    .map_err(AuthorityPersistenceErrorV1::from)?;
                Self::try_from_draft(CapabilityRevocationDraftV1 {
                    grant_id: decode_hash(&fields[2])?,
                    authority_timeline: decode_timeline(&fields[3])?,
                    fence_position: Seq::from_u64(decode_u64(&fields[4])?),
                    revocation_epoch: decode_u64(&fields[5])?,
                    policy_revision: decode_hash(&fields[6])?,
                    authority_registry_digest: decode_hash(&fields[7])?,
                })
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TimelineAuthorityStateV1 {
    revocation_epoch: u64,
    head_position: Seq,
}

/// Complete current authority state resolved from durable immutable records.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorityPersistenceStateV1 {
    grants: BTreeMap<Hash, CapabilityGrantV1>,
    revocations: BTreeMap<Hash, CapabilityRevocationV1>,
    timelines: BTreeMap<TimelineId, TimelineAuthorityStateV1>,
}

/// One resolved root-to-leaf chain and its current invalidation identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedAuthorityV1 {
    chain: DelegationChainV1,
    revocation_epoch: u64,
    head_position: Seq,
}

impl PersistedAuthorityV1 {
    #[must_use]
    pub const fn chain(&self) -> &DelegationChainV1 {
        &self.chain
    }

    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    #[must_use]
    pub const fn head_position(&self) -> Seq {
        self.head_position
    }
}

impl AuthorityPersistenceStateV1 {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Commit one immutable grant, returning `Unchanged` for an exact retry.
    ///
    /// # Errors
    /// Returns a closed error for conflicting identity, missing parent, stale epoch,
    /// invalid delegation, or non-monotonic Timeline position.
    pub fn issue_grant(
        &mut self,
        grant: CapabilityGrantV1,
    ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        if let Some(existing) = self.grants.get(&grant.grant_id()) {
            return if existing == &grant {
                Ok(AuthorityCommitOutcomeV1::Unchanged)
            } else {
                Err(AuthorityPersistenceErrorV1::Conflict)
            };
        }
        if grant.revocation_fence().is_some() {
            return Err(AuthorityPersistenceErrorV1::InvalidRecord);
        }
        if grant
            .parent_grant_id()
            .is_some_and(|parent| !self.grants.contains_key(&parent))
        {
            return Err(AuthorityPersistenceErrorV1::Conflict);
        }
        let timeline = grant.issuance_timeline();
        let current = self
            .timelines
            .get(&timeline)
            .copied()
            .unwrap_or(TimelineAuthorityStateV1 {
                revocation_epoch: 0,
                head_position: Seq::ZERO,
            });
        if grant.revocation_epoch() != current.revocation_epoch {
            return Err(AuthorityPersistenceErrorV1::StaleEpoch);
        }
        if grant.issuance_seq() <= current.head_position
            || self.coordinate_is_recorded(timeline, grant.issuance_seq())
        {
            return Err(AuthorityPersistenceErrorV1::TimelineOrder);
        }
        let grant_id = grant.grant_id();
        let issuance_seq = grant.issuance_seq();
        self.grants.insert(grant_id, grant);
        let previous_timeline = self.timelines.insert(
            timeline,
            TimelineAuthorityStateV1 {
                revocation_epoch: current.revocation_epoch,
                head_position: issuance_seq,
            },
        );
        let valid_chain = self.resolve(grant_id);
        if valid_chain.is_err() {
            self.grants.remove(&grant_id);
            match previous_timeline {
                Some(previous) => {
                    self.timelines.insert(timeline, previous);
                }
                None => {
                    self.timelines.remove(&timeline);
                }
            }
            return valid_chain.map(|_| AuthorityCommitOutcomeV1::Committed);
        }
        Ok(AuthorityCommitOutcomeV1::Committed)
    }

    /// Commit one immutable revocation fence and advance the Timeline epoch atomically.
    ///
    /// # Errors
    /// Returns a closed error for an exact-identity conflict, stale epoch, mismatched
    /// policy provenance, or non-monotonic Timeline position.
    pub fn revoke_grant(
        &mut self,
        revocation: CapabilityRevocationV1,
    ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1> {
        if let Some(existing) = self.revocations.get(&revocation.grant_id()) {
            return if existing == &revocation {
                Ok(AuthorityCommitOutcomeV1::Unchanged)
            } else {
                Err(AuthorityPersistenceErrorV1::Conflict)
            };
        }
        let Some(grant) = self.grants.get(&revocation.grant_id()) else {
            return Err(AuthorityPersistenceErrorV1::Conflict);
        };
        let timeline_matches = revocation.authority_timeline() == grant.issuance_timeline();
        let policy_matches = revocation.policy_revision() == grant.policy_revision();
        let registry_matches =
            revocation.authority_registry_digest() == grant.authority_registry_digest();
        if !(timeline_matches && policy_matches && registry_matches) {
            return Err(AuthorityPersistenceErrorV1::Conflict);
        }
        let Some(current) = self
            .timelines
            .get(&revocation.authority_timeline())
            .copied()
        else {
            return Err(AuthorityPersistenceErrorV1::InvalidRecord);
        };
        if revocation.revocation_epoch() != current.revocation_epoch.saturating_add(1) {
            return Err(AuthorityPersistenceErrorV1::StaleEpoch);
        }
        if revocation.fence_position() <= current.head_position
            || self.coordinate_is_recorded(
                revocation.authority_timeline(),
                revocation.fence_position(),
            )
        {
            return Err(AuthorityPersistenceErrorV1::TimelineOrder);
        }
        self.timelines.insert(
            revocation.authority_timeline(),
            TimelineAuthorityStateV1 {
                revocation_epoch: revocation.revocation_epoch(),
                head_position: revocation.fence_position(),
            },
        );
        self.revocations.insert(revocation.grant_id(), revocation);
        Ok(AuthorityCommitOutcomeV1::Committed)
    }

    /// Resolve one root-to-leaf delegation chain at the current persisted epoch.
    ///
    /// # Errors
    /// Returns the same closed conflict for a missing leaf, missing parent, or cycle.
    pub fn resolve(
        &self,
        leaf_grant_id: Hash,
    ) -> Result<PersistedAuthorityV1, AuthorityPersistenceErrorV1> {
        let mut chain = Vec::new();
        let mut next = Some(leaf_grant_id);
        while let Some(grant_id) = next {
            if chain.len() > usize::from(super::MAX_AUTHORITY_DELEGATION_DEPTH) {
                return Err(AuthorityPersistenceErrorV1::Conflict);
            }
            let Some(grant) = self.grants.get(&grant_id) else {
                return Err(AuthorityPersistenceErrorV1::Conflict);
            };
            if chain
                .iter()
                .any(|existing: &CapabilityGrantV1| existing.grant_id() == grant_id)
            {
                return Err(AuthorityPersistenceErrorV1::Conflict);
            }
            chain.push(grant.clone());
            next = grant.parent_grant_id();
        }
        chain.reverse();
        let timeline = chain
            .last()
            .map(CapabilityGrantV1::issuance_timeline)
            .ok_or(AuthorityPersistenceErrorV1::Conflict)?;
        let current = self
            .timelines
            .get(&timeline)
            .copied()
            .ok_or(AuthorityPersistenceErrorV1::InvalidRecord)?;
        let resolved = chain
            .iter()
            .map(|grant| {
                let fence = self
                    .revocations
                    .get(&grant.grant_id())
                    .map(CapabilityRevocationV1::fence_position);
                grant.with_persisted_revocation(current.revocation_epoch, fence)
            })
            .collect();
        DelegationChainV1::try_from_grants(resolved)
            .map_err(AuthorityPersistenceErrorV1::from)
            .map(|chain| PersistedAuthorityV1 {
                chain,
                revocation_epoch: current.revocation_epoch,
                head_position: current.head_position,
            })
    }

    pub fn grants(&self) -> impl Iterator<Item = &CapabilityGrantV1> {
        self.grants.values()
    }

    pub fn revocations(&self) -> impl Iterator<Item = &CapabilityRevocationV1> {
        self.revocations.values()
    }

    /// Encode the exact deterministic-CBOR APS1 state used by durable adapters.
    ///
    /// # Errors
    /// Returns a closed error when a retained record cannot be encoded or exceeds V1 bounds.
    pub fn to_persistence_bytes(&self) -> Result<Vec<u8>, AuthorityPersistenceErrorV1> {
        if self.grants.len() > MAX_PERSISTED_AUTHORITY_GRANTS
            || self.revocations.len() > MAX_PERSISTED_AUTHORITY_GRANTS
            || self.timelines.len() > MAX_PERSISTED_AUTHORITY_GRANTS
        {
            return Err(AuthorityPersistenceErrorV1::InvalidRecord);
        }
        let grants = self
            .grants
            .values()
            .map(|grant| grant.encode().map(|encoded| bytes(encoded.as_slice())))
            .collect::<Result<Vec<_>, _>>()?;
        let revocations = self
            .revocations
            .values()
            .map(|revocation| revocation.encode().map(|encoded| bytes(encoded.as_slice())))
            .collect::<Result<Vec<_>, _>>()?;
        let timelines = self
            .timelines
            .iter()
            .map(|(timeline, state)| {
                Value::Array(vec![
                    bytes(&timeline_bytes(*timeline)),
                    uint(state.revocation_epoch),
                    uint(state.head_position.as_u64()),
                ])
            })
            .collect();
        encode_value(&Value::Array(vec![
            bytes(&PERSISTENCE_MAGIC),
            uint(VERSION),
            Value::Array(grants),
            Value::Array(revocations),
            Value::Array(timelines),
        ]))
        .map_err(AuthorityPersistenceErrorV1::from)
        .and_then(|encoded| {
            if encoded.len() <= MAX_PERSISTED_AUTHORITY_STATE_BYTES {
                Ok(encoded)
            } else {
                Err(AuthorityPersistenceErrorV1::InvalidRecord)
            }
        })
    }

    /// Decode, reconstruct, and validate an exact deterministic-CBOR APS1 state.
    ///
    /// # Errors
    /// Returns a closed error without accepting missing, malformed, reordered, or
    /// conflicting authority evidence.
    pub fn from_persistence_bytes(bytes: &[u8]) -> Result<Self, AuthorityPersistenceErrorV1> {
        let fields = decode_bounded_array(bytes, MAX_PERSISTED_AUTHORITY_STATE_BYTES, 5)
            .map_err(AuthorityPersistenceErrorV1::from)?;
        expect_header(&fields, PERSISTENCE_MAGIC).map_err(AuthorityPersistenceErrorV1::from)?;
        let grant_values = bounded_values(&fields[2])?;
        let revocation_values = bounded_values(&fields[3])?;
        let timeline_values = bounded_values(&fields[4])?;
        let mut state = Self::new();
        let mut previous_grant = None;
        for value in grant_values {
            let encoded = canonical_bytes(value)?;
            let grant = CapabilityGrantV1::decode(&encoded)?;
            require_strict_order(previous_grant, grant.grant_id())?;
            previous_grant = Some(grant.grant_id());
            state.grants.insert(grant.grant_id(), grant);
        }
        let mut previous_revocation = None;
        for value in revocation_values {
            let encoded = canonical_bytes(value)?;
            let revocation = CapabilityRevocationV1::decode(&encoded)?;
            require_strict_order(previous_revocation, revocation.grant_id())?;
            previous_revocation = Some(revocation.grant_id());
            state.revocations.insert(revocation.grant_id(), revocation);
        }
        let mut previous_timeline = None;
        for value in timeline_values {
            let Value::Array(row) = value else {
                return Err(AuthorityPersistenceErrorV1::InvalidRecord);
            };
            if row.len() != 3 {
                return Err(AuthorityPersistenceErrorV1::InvalidRecord);
            }
            let timeline = decode_timeline(&row[0])?;
            if previous_timeline.is_some_and(|previous| previous >= timeline) {
                return Err(AuthorityPersistenceErrorV1::InvalidRecord);
            }
            previous_timeline = Some(timeline);
            state.timelines.insert(
                timeline,
                TimelineAuthorityStateV1 {
                    revocation_epoch: decode_u64(&row[1])?,
                    head_position: Seq::from_u64(decode_u64(&row[2])?),
                },
            );
        }
        state.validate().map(|()| state)
    }

    fn validate(&self) -> Result<(), AuthorityPersistenceErrorV1> {
        let mut coordinates = BTreeSet::new();
        for grant in self.grants.values() {
            let timeline = self
                .timelines
                .get(&grant.issuance_timeline())
                .ok_or(AuthorityPersistenceErrorV1::InvalidRecord)?;
            if grant.revocation_fence().is_some()
                || grant.revocation_epoch() > timeline.revocation_epoch
                || grant.issuance_seq() > timeline.head_position
                || !coordinates.insert((grant.issuance_timeline(), grant.issuance_seq()))
            {
                return Err(AuthorityPersistenceErrorV1::InvalidRecord);
            }
            self.resolve(grant.grant_id())?;
        }
        for revocation in self.revocations.values() {
            let grant = self
                .grants
                .get(&revocation.grant_id())
                .ok_or(AuthorityPersistenceErrorV1::InvalidRecord)?;
            let timeline = self
                .timelines
                .get(&revocation.authority_timeline())
                .ok_or(AuthorityPersistenceErrorV1::InvalidRecord)?;
            let revocation_timeline = revocation.authority_timeline();
            let grant_timeline = grant.issuance_timeline();
            let provenance_matches = revocation_timeline == grant_timeline
                && revocation.policy_revision() == grant.policy_revision()
                && revocation.authority_registry_digest() == grant.authority_registry_digest();
            if !provenance_matches
                || revocation.revocation_epoch() <= grant.revocation_epoch()
                || revocation.revocation_epoch() > timeline.revocation_epoch
                || revocation.fence_position() <= grant.issuance_seq()
                || revocation.fence_position() > timeline.head_position
                || !coordinates
                    .insert((revocation.authority_timeline(), revocation.fence_position()))
            {
                return Err(AuthorityPersistenceErrorV1::InvalidRecord);
            }
        }
        for (timeline_id, timeline) in &self.timelines {
            let mut positions = self
                .grants
                .values()
                .filter(|grant| grant.issuance_timeline() == *timeline_id)
                .map(CapabilityGrantV1::issuance_seq)
                .chain(
                    self.revocations
                        .values()
                        .filter(|revocation| revocation.authority_timeline() == *timeline_id)
                        .map(CapabilityRevocationV1::fence_position),
                )
                .collect::<Vec<_>>();
            let mut epochs = self
                .revocations
                .values()
                .filter(|revocation| revocation.authority_timeline() == *timeline_id)
                .map(CapabilityRevocationV1::revocation_epoch)
                .collect::<Vec<_>>();
            positions.sort_unstable();
            epochs.sort_unstable();
            let head_matches = positions.last().copied() == Some(timeline.head_position);
            let epoch_count_matches =
                u64::try_from(epochs.len()).ok() == Some(timeline.revocation_epoch);
            let epochs_are_contiguous = epochs.iter().enumerate().all(|(index, epoch)| {
                u64::try_from(index)
                    .ok()
                    .and_then(|number| number.checked_add(1))
                    == Some(*epoch)
            });
            if !head_matches || !epoch_count_matches || !epochs_are_contiguous {
                return Err(AuthorityPersistenceErrorV1::InvalidRecord);
            }
        }
        Ok(())
    }

    fn coordinate_is_recorded(&self, timeline: TimelineId, position: Seq) -> bool {
        self.grants
            .values()
            .any(|grant| grant.issuance_timeline() == timeline && grant.issuance_seq() == position)
            || self.revocations.values().any(|revocation| {
                revocation.authority_timeline() == timeline
                    && revocation.fence_position() == position
            })
    }
}

/// Storage seam implemented by durable and in-memory adapters.
pub trait AuthorityPersistencePortV1 {
    /// Atomically persist one immutable capability grant.
    ///
    /// # Errors
    /// Returns a closed persistence error for conflicts, stale state, ordering,
    /// validation, or adapter unavailability.
    fn issue_capability_grant(
        &mut self,
        grant: &CapabilityGrantV1,
    ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1>;

    /// Atomically persist a revocation fence and advance its Timeline epoch.
    ///
    /// # Errors
    /// Returns a closed persistence error for conflicts, stale state, ordering,
    /// validation, or adapter unavailability.
    fn revoke_capability_grant(
        &mut self,
        revocation: &CapabilityRevocationV1,
    ) -> Result<AuthorityCommitOutcomeV1, AuthorityPersistenceErrorV1>;

    /// Load a current root-to-leaf delegation chain.
    ///
    /// # Errors
    /// Returns a closed conflict for unavailable identities and a closed validation
    /// or adapter error for untrustworthy persisted evidence.
    fn load_authority(
        &self,
        leaf_grant_id: Hash,
    ) -> Result<PersistedAuthorityV1, AuthorityPersistenceErrorV1>;
}

fn bounded_values(value: &Value) -> Result<&[Value], AuthorityPersistenceErrorV1> {
    match value {
        Value::Array(values) if values.len() <= MAX_PERSISTED_AUTHORITY_GRANTS => Ok(values),
        _ => Err(AuthorityPersistenceErrorV1::InvalidRecord),
    }
}

fn canonical_bytes(value: &Value) -> Result<CanonicalBytes, AuthorityPersistenceErrorV1> {
    match value {
        Value::Bytes(bytes) => Ok(CanonicalBytes::from_vec(bytes.clone())),
        _ => Err(AuthorityPersistenceErrorV1::InvalidRecord),
    }
}

fn require_strict_order(
    previous: Option<Hash>,
    current: Hash,
) -> Result<(), AuthorityPersistenceErrorV1> {
    if previous.is_some_and(|previous| previous >= current) {
        Err(AuthorityPersistenceErrorV1::InvalidRecord)
    } else {
        Ok(())
    }
}
