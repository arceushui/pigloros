//! ADR-133 `CommunityLifecycleHostV1::open_memory` at its public seam.
//!
//! The host composes the real Runtime metadata authority with the real Store
//! retained-Memory domain over a `MemoryStore` grant chain.

use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityMetadataPolicyInputV1, CommunityMetadataPolicyV1,
};
use pos_core::trusted_clock::ScriptedTrustedWallSourceV1;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CapabilityGrantDraftV1, CapabilityGrantV1,
    CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    EntityId, Hash, PrincipalRefV1, Seq, TimelineId, WallTime,
};
use pos_plugin_supervisor::host_composition::{
    CommunityBootstrapRequestV1, CommunityDomainOpenedV1 as Opened, CommunityInstalledCatalogueV1,
    CommunityLifecycleHostV1, MemoryCommunityDomainV1,
};
use pos_runtime::community_plugin_host::{
    metadata_resource, CommunityMetadataAuthorityInputV1, CommunityMetadataAuthorityV1,
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
const CATALOGUE: Hash = Hash::from_bytes([36; 32]);
const NATIVE: Hash = Hash::from_bytes([37; 32]);
const AUDIENCE: &str = "community-owner";
const BOTH: &[&str] = &["inspect", "write"];

const fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([7; 16]))
}

const fn anchor_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x7e; 16]))
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

fn grant(actions: &[&str]) -> Fallible<CapabilityGrantV1> {
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec![metadata_resource(INCARNATION)],
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        purposes: vec!["owner-enforcement".to_owned()],
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

struct Installation {
    registry: AuthorityRegistrySnapshotV1,
    domain: MemoryCommunityDomainV1,
}

impl Installation {
    /// Persist the grant (optionally revoked) before the store becomes a
    /// domain, exactly as a trusted composition provisions it.
    fn new(actions: Option<&[&str]>, revoked: bool) -> Fallible<Self> {
        let granted = actions.map(grant).transpose()?;
        let bindings = granted
            .iter()
            .map(CapabilityGrantV1::binding_digest)
            .collect::<Result<Vec<_>, _>>()?;
        let registry = AuthorityRegistrySnapshotV1::try_new(
            REGISTRY,
            vec![owner()?.registry_binding_digest()],
            bindings,
            vec![],
        )?;
        let host = AuthorityPersistenceHostV1::new(&registry);
        let mut store = MemoryStore::new();
        store.bind_authority_persistence(host.persistence_binding())?;
        if let Some(grant) = &granted {
            store.issue_capability_grant(host.authorize_grant(grant)?, grant)?;
            if revoked {
                let revocation =
                    CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
                        grant_id: LEAF,
                        authority_timeline: authority_timeline(),
                        fence_position: Seq::from_u64(2),
                        revocation_epoch: 1,
                        policy_revision: POLICY_REVISION,
                        authority_registry_digest: REGISTRY,
                    })?;
                store.revoke_capability_grant(
                    host.authorize_revocation(grant, &revocation)?,
                    &revocation,
                )?;
            }
        }
        Ok(Self {
            registry,
            domain: MemoryCommunityDomainV1::new(store, INCARNATION)?,
        })
    }

    fn catalogue(&self, catalogue: Hash, native: Hash) -> Fallible<CommunityInstalledCatalogueV1> {
        let authority = CommunityMetadataAuthorityV1::new(
            CommunityMetadataAuthorityInputV1 {
                registry: self.registry.clone(),
                principal: owner()?,
                actor_entity_id: actor(),
                principal_role: AuthorityRoleV1::Actor,
                audience: AUDIENCE.to_owned(),
                consent_policy_revision: CONSENT_REVISION,
                capability_policy_revision: POLICY_REVISION,
            },
            ScriptedTrustedWallSourceV1::from_micros([500]),
        );
        let policy = CommunityMetadataPolicyV1::new(CommunityMetadataPolicyInputV1 {
            metadata_owner_registry_binding: owner()?.registry_binding_digest(),
            metadata_authority_leaf_grant: LEAF,
            compiled_schema_catalogue_digest: Hash::from_bytes([38; 32]),
            metadata_not_after_micros: 1_000_000_000,
        })?;
        Ok(CommunityInstalledCatalogueV1::new(
            authority, policy, catalogue, native,
        )?)
    }

    fn open_as(
        &mut self,
        catalogue: Hash,
        native: Hash,
        request: CommunityBootstrapRequestV1,
    ) -> Fallible<Result<Opened, Error>> {
        let installed = self.catalogue(catalogue, native)?;
        Ok(
            CommunityLifecycleHostV1::open_memory(installed, &mut self.domain, request)
                .map(|(_host, opened)| opened),
        )
    }

    fn open(&mut self, request: CommunityBootstrapRequestV1) -> Fallible<Result<Opened, Error>> {
        self.open_as(CATALOGUE, NATIVE, request)
    }
}

fn request(control: u8, generation: u8) -> Fallible<CommunityBootstrapRequestV1> {
    Ok(CommunityBootstrapRequestV1::new(
        [control; 16],
        anchor_timeline(),
        [generation; 16],
    )?)
}

#[test]
fn empty_domain_bootstraps_then_resolves_the_original_control() -> TestResult {
    let mut installation = Installation::new(Some(BOTH), false)?;
    assert!(!installation.domain.is_bootstrapped());
    assert_eq!(installation.open(request(1, 9)?)?, Ok(Opened::Bootstrapped));
    assert!(installation.domain.is_bootstrapped());
    assert_eq!(
        installation.open(request(1, 9)?)?,
        Ok(Opened::ResolvedOriginal)
    );
    assert_eq!(installation.open(request(2, 9)?)?, Ok(Opened::Existing));
    assert_eq!(installation.open(request(1, 8)?)?, Err(Error::Conflict));
    assert_eq!(
        installation.open(request(1, 9)?)?,
        Ok(Opened::ResolvedOriginal)
    );
    Ok(())
}

#[test]
fn missing_or_revoked_metadata_grant_is_unavailable() -> TestResult {
    for (actions, revoked) in [(None, false), (Some(BOTH), true)] {
        let mut installation = Installation::new(actions, revoked)?;
        assert_eq!(
            installation.open(request(1, 9)?)?,
            Err(Error::EvidenceUnavailable)
        );
        assert!(!installation.domain.is_bootstrapped());
    }
    Ok(())
}

#[test]
fn bootstrap_needs_write_and_reopening_needs_inspect() -> TestResult {
    let mut inspect_only = Installation::new(Some(&["inspect"][..]), false)?;
    assert_eq!(
        inspect_only.open(request(1, 9)?)?,
        Err(Error::EvidenceUnavailable)
    );
    assert!(!inspect_only.domain.is_bootstrapped());

    let mut write_only = Installation::new(Some(&["write"][..]), false)?;
    assert_eq!(write_only.open(request(1, 9)?)?, Ok(Opened::Bootstrapped));
    assert_eq!(
        write_only.open(request(1, 9)?)?,
        Err(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn reopening_under_another_installed_catalogue_or_native_profile_is_unavailable() -> TestResult {
    let mut installation = Installation::new(Some(BOTH), false)?;
    assert_eq!(installation.open(request(1, 9)?)?, Ok(Opened::Bootstrapped));
    for (catalogue, native) in [
        (Hash::from_bytes([41; 32]), NATIVE),
        (CATALOGUE, Hash::from_bytes([42; 32])),
    ] {
        assert_eq!(
            installation.open_as(catalogue, native, request(1, 9)?)?,
            Err(Error::EvidenceUnavailable)
        );
    }
    assert_eq!(
        installation.open(request(1, 9)?)?,
        Ok(Opened::ResolvedOriginal)
    );
    Ok(())
}

#[test]
fn installed_catalogue_refuses_zero_identities() -> TestResult {
    let installation = Installation::new(Some(BOTH), false)?;
    for (catalogue, native) in [(Hash::zero(), NATIVE), (CATALOGUE, Hash::zero())] {
        assert_eq!(
            installation
                .catalogue(catalogue, native)
                .err()
                .map(|error| error.to_string()),
            Some(Error::InvalidBinding.to_string())
        );
    }
    Ok(())
}
