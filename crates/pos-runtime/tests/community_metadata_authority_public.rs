//! ADR-129 §3 metadata-only service authority at its public Runtime seam.
//!
//! Every decision is evaluated against a real `MemoryStore` grant chain; the
//! exact resource, category, action, purpose and audience strings come from
//! the accepted ADR text, not from the implementation.

use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMetadataPolicyInputV1, CommunityMetadataPolicyV1,
};
use pos_core::trusted_clock::ScriptedTrustedWallSourceV1;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CapabilityGrantDraftV1, CapabilityGrantV1,
    CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    EntityId, Hash, PersistedAuthorityV1, PrincipalRefV1, Seq, TimelineId, WallTime,
};
use pos_runtime::community_plugin_host::{
    metadata_resource, CommunityMetadataActionV1 as Action, CommunityMetadataAuthorityInputV1,
    CommunityMetadataAuthorityV1, CommunityMetadataPurposeV1 as Purpose, CommunityMetadataUseV1,
};
use pos_store::memory::MemoryStore;
use ulid::Ulid;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const INCARNATION: [u8; 16] = [0x5a; 16];
const REGISTRY: Hash = Hash::from_bytes([31; 32]);
const POLICY_REVISION: Hash = Hash::from_bytes([32; 32]);
const CONSENT_REVISION: Hash = Hash::from_bytes([33; 32]);
const LEAF: Hash = Hash::from_bytes([34; 32]);
const AUDIENCE: &str = "community-owner";
const ACTIONS: [(Action, &str); 3] = [
    (Action::Inspect, "inspect"),
    (Action::Write, "write"),
    (Action::Dispose, "dispose"),
];
const PURPOSES: [(Purpose, &str); 3] = [
    (Purpose::OwnerEnforcement, "owner-enforcement"),
    (Purpose::OwnerRecovery, "owner-recovery"),
    (Purpose::OwnerDisposition, "owner-disposition"),
];

const fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([7; 16]))
}

const fn actor() -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([8; 16]))
}

fn principal(byte: u8) -> Fallible<PrincipalRefV1> {
    Ok(PrincipalRefV1::try_new([byte; 16], "local.test")?)
}

fn owner() -> Fallible<AuthenticatedPrincipalResultV1> {
    Ok(AuthenticatedPrincipalResultV1::try_from_draft(
        AuthenticatedPrincipalDraftV1 {
            principal: principal(2)?,
            adapter_id: "local-adapter".to_owned(),
            assurance: AssuranceLevelV1::try_new(1)?,
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(1_000_000),
            binding_digest: Hash::from_bytes([39; 32]),
        },
    )?)
}

fn grant(resource: String, action: &str, purpose: &str) -> Fallible<CapabilityGrantV1> {
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec![resource],
        actions: vec![action.to_owned()],
        purposes: vec![purpose.to_owned()],
        audiences: vec![AUDIENCE.to_owned()],
        actor_entity_ids: vec![actor()],
        subject_ids: vec![],
        participant_ids: vec![],
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 1,
        budget: 1,
        environment_constraints: vec![],
    })?;
    Ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: LEAF,
        grantor: principal(1)?,
        grantee: AuthorityGranteeV1::Principal(principal(2)?),
        trust_domain: "local.test".to_owned(),
        scope,
        valid_from_position: Seq::from_u64(1),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: vec![],
        consent_references: vec![],
        policy_revision: POLICY_REVISION,
        issuance_timeline: authority_timeline(),
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: REGISTRY,
    })?)
}

struct Granted {
    store: MemoryStore,
    registry: AuthorityRegistrySnapshotV1,
    host: AuthorityPersistenceHostV1,
    grant: CapabilityGrantV1,
}

impl Granted {
    fn new(action: &str, purpose: &str) -> Fallible<Self> {
        let grant = grant(metadata_resource(INCARNATION), action, purpose)?;
        let registry = AuthorityRegistrySnapshotV1::try_new(
            REGISTRY,
            vec![owner()?.registry_binding_digest()],
            vec![grant.binding_digest()?],
            vec![],
        )?;
        let host = AuthorityPersistenceHostV1::new(&registry);
        let mut store = MemoryStore::new();
        store.bind_authority_persistence(host.persistence_binding())?;
        store.issue_capability_grant(host.authorize_grant(&grant)?, &grant)?;
        Ok(Self {
            store,
            registry,
            host,
            grant,
        })
    }

    fn persisted(&self) -> Fallible<PersistedAuthorityV1> {
        Ok(self.store.load_authority(LEAF)?)
    }

    fn authority(&self, audience: &str, samples: &[u64]) -> Fallible<CommunityMetadataAuthorityV1> {
        Ok(CommunityMetadataAuthorityV1::new(
            CommunityMetadataAuthorityInputV1 {
                registry: self.registry.clone(),
                principal: owner()?,
                actor_entity_id: actor(),
                principal_role: AuthorityRoleV1::Actor,
                audience: audience.to_owned(),
                consent_policy_revision: CONSENT_REVISION,
                capability_policy_revision: POLICY_REVISION,
            },
            ScriptedTrustedWallSourceV1::from_micros(samples.iter().copied()),
        ))
    }
}

fn policy(owner_binding: Hash, leaf: Hash) -> Fallible<CommunityMetadataPolicyV1> {
    Ok(CommunityMetadataPolicyV1::new(
        CommunityMetadataPolicyInputV1 {
            metadata_owner_registry_binding: owner_binding,
            metadata_authority_leaf_grant: leaf,
            compiled_schema_catalogue_digest: Hash::from_bytes([36; 32]),
            metadata_not_after_micros: 1_000_000_000,
        },
    )?)
}

const fn metadata_use(action: Action, purpose: Purpose) -> CommunityMetadataUseV1 {
    CommunityMetadataUseV1 {
        store_incarnation: INCARNATION,
        action,
        purpose,
    }
}

#[test]
fn closed_strings_and_resource_are_the_exact_adr129_spellings() {
    for (action, expected) in ACTIONS {
        assert_eq!(action.as_str(), expected);
    }
    for (purpose, expected) in PURPOSES {
        assert_eq!(purpose.as_str(), expected);
    }
    let mut incarnation = [0; 16];
    for (index, byte) in incarnation.iter_mut().enumerate() {
        *byte = u8::try_from(index * 17).unwrap_or_default();
    }
    assert_eq!(
        metadata_resource(incarnation),
        "community-metadata:00112233445566778899aabbccddeeff"
    );
    assert_eq!(
        metadata_resource([0xab; 16]),
        format!("community-metadata:{}", "ab".repeat(16))
    );
}

#[test]
fn each_scoped_action_and_purpose_is_authorized_alone() -> TestResult {
    for (granted_action, action_text) in ACTIONS {
        for (granted_purpose, purpose_text) in PURPOSES {
            let world = Granted::new(action_text, purpose_text)?;
            let persisted = world.persisted()?;
            let policy = policy(owner()?.registry_binding_digest(), LEAF)?;
            for (action, _) in ACTIONS {
                for (purpose, _) in PURPOSES {
                    let mut authority = world.authority(AUDIENCE, &[500])?;
                    let decision =
                        authority.authorize(&policy, &persisted, metadata_use(action, purpose));
                    if action == granted_action && purpose == granted_purpose {
                        let decision = decision?;
                        assert!(decision.is_allowed());
                        assert_eq!(decision.grant_id(), Some(LEAF));
                        assert_eq!(decision.at_position(), persisted.head_position());
                        assert_eq!(decision.authority_registry_digest(), REGISTRY);
                    } else {
                        assert_eq!(decision.err(), Some(Error::EvidenceUnavailable));
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn another_store_incarnation_is_a_different_resource() -> TestResult {
    let world = Granted::new("inspect", "owner-enforcement")?;
    let policy = policy(owner()?.registry_binding_digest(), LEAF)?;
    let mut authority = world.authority(AUDIENCE, &[500])?;
    let foreign = CommunityMetadataUseV1 {
        store_incarnation: [0x5b; 16],
        ..metadata_use(Action::Inspect, Purpose::OwnerEnforcement)
    };
    assert_eq!(
        authority
            .authorize(&policy, &world.persisted()?, foreign)
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn revoked_grant_is_unavailable() -> TestResult {
    let mut world = Granted::new("inspect", "owner-enforcement")?;
    let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
        grant_id: LEAF,
        authority_timeline: authority_timeline(),
        fence_position: Seq::from_u64(2),
        revocation_epoch: 1,
        policy_revision: POLICY_REVISION,
        authority_registry_digest: REGISTRY,
    })?;
    let permit = world.host.authorize_revocation(&world.grant, &revocation)?;
    world.store.revoke_capability_grant(permit, &revocation)?;
    let policy = policy(owner()?.registry_binding_digest(), LEAF)?;
    let mut authority = world.authority(AUDIENCE, &[500])?;
    assert_eq!(
        authority
            .authorize(
                &policy,
                &world.persisted()?,
                metadata_use(Action::Inspect, Purpose::OwnerEnforcement),
            )
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn policy_must_name_the_installed_principal_and_the_loaded_leaf() -> TestResult {
    let world = Granted::new("inspect", "owner-enforcement")?;
    let persisted = world.persisted()?;
    let owner_binding = owner()?.registry_binding_digest();
    for policy in [
        policy(Hash::from_bytes([40; 32]), LEAF)?,
        policy(owner_binding, Hash::from_bytes([41; 32]))?,
    ] {
        let mut authority = world.authority(AUDIENCE, &[500])?;
        assert_eq!(
            authority
                .authorize(
                    &policy,
                    &persisted,
                    metadata_use(Action::Inspect, Purpose::OwnerEnforcement),
                )
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

#[test]
fn missing_wall_sample_invalid_audience_or_expired_principal_is_unavailable() -> TestResult {
    let world = Granted::new("inspect", "owner-enforcement")?;
    let persisted = world.persisted()?;
    let policy = policy(owner()?.registry_binding_digest(), LEAF)?;
    let inspect = metadata_use(Action::Inspect, Purpose::OwnerEnforcement);
    for (audience, samples) in [
        (AUDIENCE, vec![]),
        ("", vec![500]),
        (AUDIENCE, vec![2_000_000]),
    ] {
        let mut authority = world.authority(audience, &samples)?;
        assert_eq!(
            authority.authorize(&policy, &persisted, inspect).err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    let mut authority = world.authority(AUDIENCE, &[500, 600])?;
    assert!(authority
        .authorize(&policy, &persisted, inspect)?
        .is_allowed());
    assert!(authority
        .authorize(&policy, &persisted, inspect)?
        .is_allowed());
    assert!(authority.authorize(&policy, &persisted, inspect).is_err());
    Ok(())
}
