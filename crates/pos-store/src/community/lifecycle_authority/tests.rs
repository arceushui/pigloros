//! The evaluator loads the chain from the domain's own store at evaluation,
//! so a revocation committed after a successful call refuses the next
//! evaluation of the same call (ADR-129 A5.4 and A5.6 I6).
//!
//! This lives inside the sealed `community` module because only the domain
//! owner can revoke in a domain's store once it holds it.

use std::error::Error as StdError;

use pos_core::community_lifecycle::{
    community_authentication_nonce_v1, community_capability_attestation_digest_v1, ArtifactRefV1,
    CommunityActorRowV1, CommunityAuthorityCatalogueInputV1, CommunityAuthorityCatalogueV1,
    CommunityInitializationSourceV1, CommunityLifecycleErrorV1 as Error,
};
use pos_core::fork_authentication::{
    principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
    ForkAuthenticationPolicyV1,
};
use pos_core::trusted_clock::{ScriptedTrustedWallSourceV1, SystemGuardMonotonicSourceV1};
use pos_core::{
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityTrustRootSealV1, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1,
    CapabilityScopeV1, EntityId, Hash, PrincipalRefV1, Seq, TimelineId,
};
use pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1;
use ulid::Ulid;

use super::{
    CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1,
    CommunityLifecycleAuthorityInputV1, CommunityLifecycleAuthorityV1,
};
use crate::community::MemoryCommunityDomainV1;
use crate::memory::MemoryStore;
use crate::trusted_clock::MemoryTrustedClockAuthorityV1;

type Fallible<T> = Result<T, Box<dyn StdError>>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const REGISTRY: Hash = Hash::from_bytes([31; 32]);
const POLICY: Hash = Hash::from_bytes([32; 32]);
const SEED: [u8; 32] = [7; 32];

const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([byte; 16]))
}

fn caller() -> Fallible<PrincipalRefV1> {
    Ok(PrincipalRefV1::try_new([0x11; 16], "community.local")?)
}

fn grant(target: TimelineId) -> Fallible<CapabilityGrantV1> {
    Ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: Hash::from_bytes([1; 32]),
        grantor: PrincipalRefV1::try_new([1; 16], "community.local")?,
        grantee: AuthorityGranteeV1::Principal(caller()?),
        trust_domain: "community.local".to_owned(),
        scope: CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: vec![
                CommunityAdministrativeRequestV1::derive(&initialize(target))?.resource(),
            ],
            actions: vec!["community.initialize.v1".to_owned()],
            purposes: vec!["lifecycle-administration".to_owned()],
            audiences: vec!["community-host".to_owned()],
            actor_entity_ids: vec![EntityId::from_ulid(Ulid::from_bytes([8; 16]))],
            subject_ids: vec![],
            participant_ids: vec![],
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 1,
            budget: 1,
            environment_constraints: vec![],
        })?,
        valid_from_position: Seq::from_u64(1),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: vec![],
        consent_references: vec![],
        policy_revision: POLICY,
        issuance_timeline: timeline(7),
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: REGISTRY,
    })?)
}

const fn initialize(target: TimelineId) -> CommunityAdministrativeOperationV1 {
    CommunityAdministrativeOperationV1::Initialize {
        timeline: target,
        operation_id: [0x10; 16],
        initial_source: CommunityInitializationSourceV1::Initializer(ArtifactRefV1 {
            schema_id: 0x4353_0001,
            byte_length: 42,
            digest: [0x30; 32],
        }),
        expected_prior_generation: None,
        expected_prior_head_digest: None,
    }
}

#[test]
fn a_revocation_after_a_successful_call_refuses_the_same_call() -> Fallible<()> {
    let target = timeline(0x2a);
    let leaf = grant(target)?;
    let attestation = AuthorityRegistrySnapshotV1::try_new(
        &SEAL,
        REGISTRY,
        vec![Hash::from_bytes([41; 32])],
        vec![leaf.binding_digest()?],
        vec![],
    )?;
    let host = AuthorityPersistenceHostV1::new(&attestation);
    let mut store = MemoryStore::new();
    store.bind_authority_persistence(host.persistence_binding())?;
    store.issue_capability_grant(host.authorize_grant(&leaf)?, &leaf)?;
    let mut domain =
        MemoryCommunityDomainV1::new(store, [0x5a; 16], MemoryTrustedClockAuthorityV1::new())?;

    let key = ForkAuthenticationAdapterSigningKeyV1::from_seed(SEED)?;
    let policy = ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
        adapter_id: "community-adapter".to_owned(),
        verifying_key: key.public_key(),
        minimum_assurance: 1,
        registry_bindings: vec![Hash::from_bytes([60; 32])],
    }])?;
    let catalogue = CommunityAuthorityCatalogueV1::new(
        &SEAL,
        CommunityAuthorityCatalogueInputV1 {
            fap1_digest: policy.digest()?,
            audience: "community-host".to_owned(),
            actor_rows: vec![CommunityActorRowV1 {
                principal_digest: principal_digest_v1(&caller()?)?,
                actor_entity_id: EntityId::from_ulid(Ulid::from_bytes([8; 16])),
            }],
            capability_policy_revision: POLICY,
            consent_policy_revision: Hash::from_bytes([33; 32]),
            authority_registry_digest: REGISTRY,
            capability_attestation_digest: community_capability_attestation_digest_v1(&attestation),
            trust_scope: "community.trust".to_owned(),
        },
    )?;
    let request = CommunityAdministrativeRequestV1::derive(&initialize(target))?;
    let credential = key
        .sign_authenticated_principal(AuthenticatedPrincipalRecordV1 {
            principal: caller()?,
            adapter_id: "community-adapter".to_owned(),
            assurance: 1,
            issued_at: 100,
            expires_at: 1_000_000,
            registry_binding: Hash::from_bytes([60; 32]),
            operation_nonce: community_authentication_nonce_v1(
                catalogue.digest(),
                &request.resource(),
                request.action().as_str(),
                &request.operation_constraint(),
            ),
        })?
        .to_canonical_cbor()?;
    let mut authority = CommunityLifecycleAuthorityV1::new(
        &SEAL,
        CommunityLifecycleAuthorityInputV1 {
            catalogue,
            authentication_policy: policy,
            attestation,
            fork_admission_policies: vec![],
            member_recipient: "community-recipient".to_owned(),
            store_incarnation: [0x5a; 16],
        },
        ScriptedTrustedWallSourceV1::from_micros([500]),
        SystemGuardMonotonicSourceV1,
    )?;
    let call = authority.authenticate(&credential, request, &mut domain)?;
    assert!(authority
        .authorize_administrative(&call, &domain, leaf.grant_id())
        .is_ok());

    let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
        grant_id: leaf.grant_id(),
        authority_timeline: timeline(7),
        fence_position: Seq::from_u64(2),
        revocation_epoch: 1,
        policy_revision: POLICY,
        authority_registry_digest: REGISTRY,
    })?;
    domain
        .store
        .revoke_capability_grant(host.authorize_revocation(&leaf, &revocation)?, &revocation)?;
    assert_eq!(
        authority
            .authorize_administrative(&call, &domain, leaf.grant_id())
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}
