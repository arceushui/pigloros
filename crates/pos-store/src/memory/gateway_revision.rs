//! `MemoryStore` adapter for Gateway-managed revisions (#304).
//!
//! Revisions, tombstones and idempotency records are process-local maps of
//! this adapter instance. A commit reads the instance's mode binding and
//! attached epoch exactly as the append choke point does (ADR-134 §8), and
//! erasure replaces a stored revision with its tombstone, dropping its
//! content.

use std::{collections::BTreeMap, num::NonZeroU64};

use pos_core::{
    admit_gateway_revision_v1, GatewayModeBindingRecordV1, GatewayRevisionCommitV1,
    GatewayRevisionDraftV1, GatewayRevisionErasurePermitV1, GatewayRevisionErrorV1,
    GatewayRevisionKeyV1, GatewayRevisionKindV1, GatewayRevisionPortV1, GatewayRevisionStateV1,
    GatewayRevisionTombstoneV1,
};

use super::MemoryStore;

/// The idempotency identity of one request: Principal, family and key
/// digest.
type RequestIdentityV1 = ([u8; 16], GatewayRevisionKindV1, [u8; 32]);

/// The revision an earlier request committed and that request's digest.
type StoredRequestV1 = (GatewayRevisionKeyV1, [u8; 32]);

/// Every revision state and idempotency record of one adapter instance.
#[derive(Debug, Default)]
pub(super) struct MemoryGatewayRevisionsV1 {
    states: BTreeMap<GatewayRevisionKeyV1, GatewayRevisionStateV1>,
    requests: BTreeMap<RequestIdentityV1, StoredRequestV1>,
}

impl MemoryGatewayRevisionsV1 {
    /// The highest revision of the `kind` resource `resource_id`, stored or
    /// erased.
    fn head(&self, kind: GatewayRevisionKindV1, resource_id: [u8; 16]) -> Option<NonZeroU64> {
        self.states
            .keys()
            .filter(|key| key.kind() == kind && key.resource_id() == resource_id)
            .map(GatewayRevisionKeyV1::revision)
            .max()
    }

    /// The answer to a retry of a stored request.
    fn replay(
        &self,
        stored: &StoredRequestV1,
        draft: &GatewayRevisionDraftV1,
    ) -> Result<GatewayRevisionCommitV1, GatewayRevisionErrorV1> {
        let (key, request_digest) = stored;
        if *request_digest == draft.idempotency().request_digest() {
            self.states
                .get(key)
                .cloned()
                .map(GatewayRevisionCommitV1::Replayed)
                .ok_or(GatewayRevisionErrorV1::InvalidRecord)
        } else {
            Err(GatewayRevisionErrorV1::IdempotencyConflict)
        }
    }

    /// Admit a fresh request under `mode` and record it.
    fn admit(
        &mut self,
        identity: RequestIdentityV1,
        draft: &GatewayRevisionDraftV1,
        mode: GatewayModeBindingRecordV1,
    ) -> Result<GatewayRevisionCommitV1, GatewayRevisionErrorV1> {
        let parent = draft.parent_key().and_then(|key| self.states.get(&key));
        let head = self.head(draft.idempotency().kind(), draft.resource_id());
        admit_gateway_revision_v1(draft, parent, head).map(|()| {
            let record = draft.to_record(mode);
            let key = record.tombstone().key();
            self.states
                .insert(key, GatewayRevisionStateV1::Present(record.clone()));
            self.requests
                .insert(identity, (key, draft.idempotency().request_digest()));
            GatewayRevisionCommitV1::Committed(record)
        })
    }
}

impl GatewayRevisionPortV1 for MemoryStore {
    fn commit_gateway_revision(
        &mut self,
        draft: GatewayRevisionDraftV1,
    ) -> Result<GatewayRevisionCommitV1, GatewayRevisionErrorV1> {
        let request = draft.idempotency();
        let identity = (request.principal_id(), request.kind(), request.key_digest());
        let revisions = &mut self.gateway_revisions;
        match revisions.requests.get(&identity) {
            Some(stored) => revisions.replay(stored, &draft),
            None => self
                .mode_binding
                .revision_mode()
                .and_then(|mode| revisions.admit(identity, &draft, mode)),
        }
    }

    fn load_gateway_revision(
        &self,
        key: GatewayRevisionKeyV1,
    ) -> Result<Option<GatewayRevisionStateV1>, GatewayRevisionErrorV1> {
        Ok(self.gateway_revisions.states.get(&key).cloned())
    }

    fn erase_gateway_revision(
        &mut self,
        permit: GatewayRevisionErasurePermitV1,
    ) -> Result<Option<GatewayRevisionTombstoneV1>, GatewayRevisionErrorV1> {
        let key = permit.key();
        let states = &mut self.gateway_revisions.states;
        let tombstone = states.get(&key).map(|state| *state.tombstone());
        if let Some(tombstone) = tombstone {
            states.insert(key, GatewayRevisionStateV1::Erased(tombstone));
        }
        Ok(tombstone)
    }
}
