//! Shared fixtures of the community initialize planner (#560 A3c-2c-2).
//!
//! A [`World`] is one Memory community domain over a Plugin trust registry
//! store, with administrative grants issued through the trusted
//! persistence host and the lifecycle authority installed over them. A
//! [`Roster`] is a two-member `plugin-a` roster, [`planner`] plans its
//! code-0 initialization and [`graph`] mints its protected initial graph as
//! the 2c-3 commit will. The public planner tests and the planner's unit
//! tests include this one file; the items are public so that no test crate
//! sees them as unused.

use std::error::Error as StdError;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciborium::Value;
use pos_core::community_lifecycle::{
    community_capability_attestation_digest_v1, community_initializer_set_ref_v1, ArtifactRefV1,
    CommunityActorRowV1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityAuthorityCatalogueInputV1, CommunityAuthorityCatalogueV1,
    CommunityDurableBackendV1, CommunityDurableProfileInputV1, CommunityDurableProfileV1,
    CommunityGenerationAdmissionV1, CommunityInitializationRequestV1,
    CommunityInitializationSourceV1, CommunityKeyIntentInputV1, CommunityKeyIntentV1,
    CommunityMemberBindingV1, CommunityMemberSlotsV1, CommunityProfileMemberV1,
    CommunityProfileRetentionV1, CommunityRecordKindsV1, CommunityStateContentV1,
};
use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as LifecycleError, CommunityMetadataPolicyInputV1,
    CommunityMetadataPolicyV1, CommunityPluginHostErrorV1, CommunityQuarantineReasonV1,
    RevocationBasisV1,
};
use pos_core::fork_authentication::{
    principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
    ForkAuthenticationPolicyV1,
};
use pos_core::store::EventStore;
use pos_core::trusted_clock::{
    GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1, ScriptedTrustedWallSourceV1,
    SystemGuardMonotonicSourceV1,
};
use pos_core::{AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1};
use pos_core::{
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityTrustRootSealV1, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1, EntityId, Hash,
    ImplementationKeyV1, PrincipalRefV1, Seq, TimelineId,
};
use pos_core::{TimelineMeta, TimelineMode, WallTime};
use pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1;
use pos_store::community::{
    metadata_resource, CommunityAdministrativeOperationV1, CommunityAdministrativeRequestV1,
    CommunityArtifactProtectorV1, CommunityAuthorityAdmissionV1, CommunityAuthorityCallV1,
    CommunityBootstrapRequestV1, CommunityDomainBindingV1, CommunityDomainOpenedV1,
    CommunityInitializationContextV1, CommunityInitializationGraphInputV1,
    CommunityInitializationGraphV1, CommunityInitializationInstallationV1,
    CommunityInitializationMemberV1, CommunityInitializationPlannerV1,
    CommunityInitializationReceiptV1, CommunityInitializationRecordsV1, CommunityInitializeCallV1,
    CommunityInitializeFormV1, CommunityInitializerOwnerV1, CommunityLifecycleAuthorityInputV1,
    CommunityLifecycleAuthorityV1, CommunityMetadataAuthorityInputV1, CommunityMetadataAuthorityV1,
    CommunityPreExecutionFailureInputV1, CommunityPreExecutionFailureV1,
    CommunityPreExecutionTrustV1, CommunityProtectionCohortV1, CommunityQuarantineContextV1,
    CommunitySetReasonCallV1, MemoryCommunityDomainV1,
};
use pos_store::memory::MemoryStore;
use pos_store::MemoryTrustedClockAuthorityV1;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::plugin_trust_registry_fixtures::{
    release_one, spec, tps_after, Env, Harness, ManifestSpec, Material, Spec, TpsSpec,
};
use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;

/// A fallible fixture step.
pub type Fallible<T> = Result<T, Box<dyn StdError>>;

/// CAP1 authority registry digest.
pub const REGISTRY: Hash = Hash::from_bytes([31; 32]);
/// CAP1 capability policy revision.
pub const POLICY_REVISION: Hash = Hash::from_bytes([32; 32]);
/// CAP1 consent policy revision.
pub const CONSENT_REVISION: Hash = Hash::from_bytes([33; 32]);
/// The FAP1 adapter's registry binding.
pub const FAP_BINDING: Hash = Hash::from_bytes([60; 32]);
/// CAP1 audience.
pub const AUDIENCE: &str = "community-host";
/// The FAP1 adapter.
pub const ADAPTER: &str = "community-adapter";
/// The adapter signing key seed.
pub const SEED: [u8; 32] = [7; 32];
/// The installed member recipient.
pub const RECIPIENT: &str = "community-recipient";
/// The protected store incarnation.
pub const INCARNATION: [u8; 16] = [0x5a; 16];
/// The CGI1 operation identity.
pub const OPERATION: [u8; 16] = [0x10; 16];
/// The planned generation.
pub const GENERATION: [u8; 16] = [0x20; 16];
/// Another generation.
pub const OTHER_GENERATION: [u8; 16] = [0x21; 16];
/// The trusted wall sample of every call.
pub const NOW: u64 = 500;
/// Credential issue time.
pub const ISSUED: u64 = 100;
/// Credential expiry.
pub const EXPIRES: u64 = 30_000_100;
/// The CDP1 horizon.
pub const HORIZON: u64 = 40_000_000;
/// The roster's State schema.
pub const SCHEMA: Hash = Hash::from_bytes([0x22; 32]);
/// The roster entries.
pub const ENTRIES: [&str; 2] = ["Entry-A_1", "Entry-B_1"];
/// Each roster row's installed CNT1 State limit.
pub const STATE_LIMITS: [u64; 2] = [4096, 100];
/// The CAP1 Plugin trust scope.
pub const TRUST_SCOPE: &str = "scope";
/// Each member's CMB1 envelope address.
pub const ADDRESSES: [Hash; 2] = [Hash::from_bytes([0x71; 32]), Hash::from_bytes([0x72; 32])];
/// The administrative grants every [`World`] issues.
pub const LEAVES: [Hash; 2] = [Hash::from_bytes([1; 32]), Hash::from_bytes([2; 32])];

/// A hash of one repeated byte.
#[must_use]
pub const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

/// The planned Timeline.
#[must_use]
pub const fn target() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x0e; 16]))
}

/// Another Timeline.
#[must_use]
pub const fn other_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x2f; 16]))
}

/// The authority Timeline of every grant.
#[must_use]
pub const fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([7; 16]))
}

/// The CAP1 actor.
#[must_use]
pub const fn actor() -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([8; 16]))
}

/// The authenticated caller.
///
/// # Errors
/// Returns the principal refusal.
pub fn caller() -> Fallible<PrincipalRefV1> {
    Ok(PrincipalRefV1::try_new([0x11; 16], "community.local")?)
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]
        })
        .map(char::from)
        .collect()
}

/// Preferred CBOR of `value`.
///
/// # Errors
/// Returns the writer error.
pub fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

/// `H(M, bytes)`: BLAKE3 of `PiglorOS.Community.<M>.v1`, a zero byte and
/// the bytes.
#[must_use]
pub fn adr_h(m: &str, preimage: &[u8]) -> Hash {
    let mut input = b"PiglorOS.Community.".to_vec();
    input.extend_from_slice(m.as_bytes());
    input.extend_from_slice(b".v1\0");
    input.extend_from_slice(preimage);
    Hash::from_bytes(*blake3::hash(&input).as_bytes())
}

/// `community:<T32>:lifecycle`.
#[must_use]
pub fn lifecycle_resource(timeline: TimelineId) -> String {
    format!("community:{}:lifecycle", hex(&timeline.inner().to_bytes()))
}

/// The R6.2 nonce, written out from the ADR.
///
/// # Errors
/// Returns the writer error.
pub fn oracle_nonce(
    catalogue: Hash,
    resource: &str,
    action: &str,
    constraint: &str,
) -> Fallible<[u8; 32]> {
    let preimage = encode(&Value::Array(vec![
        Value::Bytes(catalogue.as_bytes().to_vec()),
        Value::Text(resource.to_owned()),
        Value::Text(action.to_owned()),
        Value::Text(constraint.to_owned()),
    ]))?;
    Ok(*adr_h("AuthenticationNonce", &preimage).as_bytes())
}

/// A roster of two `plugin-a` members whose PMF1 and release default to
/// `manifest`'s.
pub struct Roster {
    /// The members' implementation.
    pub implementation: ImplementationKeyV1,
    /// The members' PMF1.
    pub pmf1: Hash,
    /// The members' initializer State.
    pub state: Vec<u8>,
}

impl Roster {
    /// A roster of `manifest`'s release, or of `pmf1` and `release` when set.
    ///
    /// # Errors
    /// Returns the fixture construction error.
    pub fn new(
        manifest: &ManifestSpec,
        pmf1: Option<Hash>,
        release: Option<Hash>,
    ) -> Fallible<Self> {
        Ok(Self {
            implementation: ImplementationKeyV1::new(
                manifest.plugin_id.clone(),
                "host-v1".into(),
                release.unwrap_or(Hash::from_bytes(manifest.release_digest()?)),
            )?,
            pmf1: pmf1.unwrap_or(Hash::from_bytes(manifest.pmf1_digest()?)),
            state: CommunityStateContentV1::new(SCHEMA, b"state")?
                .to_canonical_cbor()
                .to_vec(),
        })
    }

    /// The `release_one` roster.
    ///
    /// # Errors
    /// Returns the fixture construction error.
    pub fn release_one() -> Fallible<Self> {
        Self::new(&release_one(), None, None)
    }

    /// The initializer reference of the roster State.
    #[must_use]
    pub fn initializer(&self) -> ArtifactRefV1 {
        ArtifactRefV1 {
            schema_id: 0x4353_0001,
            byte_length: self.state.len() as u64,
            digest: *adr_h("CSC1", &self.state).as_bytes(),
        }
    }

    /// The two CDP1 roster rows.
    ///
    /// # Errors
    /// Returns the fixture construction error.
    pub fn rows(&self) -> Fallible<Vec<CommunityProfileMemberV1<'_>>> {
        ENTRIES
            .iter()
            .map(|entry| {
                Ok(CommunityProfileMemberV1::new(
                    entry,
                    &self.implementation,
                    self.pmf1,
                    SCHEMA,
                    hash(6),
                    self.initializer(),
                    10,
                )?)
            })
            .collect()
    }
}

/// The CDP1 over `roster`.
///
/// # Errors
/// Returns the fixture construction error.
pub fn profile<'a>(
    roster: &'a [CommunityProfileMemberV1<'a>],
) -> Fallible<CommunityDurableProfileV1<'a>> {
    profile_until(roster, HORIZON, hash(1), hash(9))
}

/// The CDP1 over `roster` with generation horizon `horizon`, execution
/// profile `execution` and authority catalogue `catalogue`.
///
/// # Errors
/// Returns the fixture construction error.
pub fn profile_until<'a>(
    roster: &'a [CommunityProfileMemberV1<'a>],
    horizon: u64,
    execution: Hash,
    catalogue: Hash,
) -> Fallible<CommunityDurableProfileV1<'a>> {
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            backend: CommunityDurableBackendV1::RetainedMemory,
            execution_profile_digest: execution,
            roster,
            source_catalogue_digest: hash(2),
            authority_catalogue_digest: catalogue,
            retention: CommunityProfileRetentionV1 {
                generation_not_after_micros: horizon,
                recovery_window_micros: 1,
                quarantine_not_after_micros: HORIZON,
                metadata_not_after_micros: HORIZON,
                recording_not_after_micros: HORIZON,
            },
        },
    )?)
}

/// The installed planner of a code-0 initialization of `timeline`.
///
/// # Errors
/// Returns the planner refusal.
pub fn planner_at<'a>(
    seal: &'static AuthorityTrustRootSealV1,
    profile: &'a CommunityDurableProfileV1<'a>,
    timeline: TimelineId,
) -> Fallible<CommunityInitializationPlannerV1<'a>> {
    Ok(CommunityInitializationPlannerV1::new(
        seal,
        CommunityInitializationInstallationV1 {
            store_incarnation: INCARNATION,
            profile,
            native_profile_digest: hash(0x61),
            installed_owner_catalogue_digest: hash(0x62),
            installation_id: [0x63; 16],
            state_limit_bytes: &STATE_LIMITS,
        },
        CommunityInitializeFormV1 {
            timeline,
            operation_id: OPERATION,
            initial_source: CommunityInitializationSourceV1::Initializer(
                community_initializer_set_ref_v1(profile),
            ),
        },
    )?)
}

/// The installed planner of a code-0 initialization of [`target`].
///
/// # Errors
/// Returns the planner refusal.
pub fn planner<'a>(
    seal: &'static AuthorityTrustRootSealV1,
    profile: &'a CommunityDurableProfileV1<'a>,
) -> Fallible<CommunityInitializationPlannerV1<'a>> {
    planner_at(seal, profile, target())
}

/// One CKP1 key intent: `byte` names its protection operation, and the
/// intent allows the one record `kind`, which `purpose` must admit.
///
/// # Errors
/// Returns the intent refusal.
pub fn key(
    byte: u8,
    purpose: CommunityArtifactPurposeV1,
    kind: CommunityArtifactKindV1,
) -> Fallible<CommunityKeyIntentV1> {
    Ok(CommunityKeyIntentV1::new(CommunityKeyIntentInputV1 {
        protection_operation_id: [byte; 16],
        parent_operation: CommunityArtifactOperationV1::Initialization(OPERATION),
        timeline: target(),
        generation: GENERATION,
        purpose,
        scope_set_digest: adr_h("ScopeSet", &[0x80]),
        evidence_not_after_micros: HORIZON,
        allowed_record_kinds: CommunityRecordKindsV1::empty().with(kind),
        member_slots: CommunityMemberSlotsV1::empty(),
        material_fingerprint: hash(byte),
        authority_request_digest: hash(0x44),
    })?)
}

/// An administrative grant `id`, issued at `seq`, on the lifecycle
/// resources of `timelines`.
///
/// # Errors
/// Returns the grant refusal.
pub fn grant(id: Hash, seq: u64, timelines: &[TimelineId]) -> Fallible<CapabilityGrantV1> {
    let mut resources: Vec<String> = timelines.iter().copied().map(lifecycle_resource).collect();
    resources.sort_unstable();
    let capability = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources,
        actions: vec![
            "community.initialize.v1".to_owned(),
            "community.transition.v1".to_owned(),
        ],
        purposes: vec!["lifecycle-administration".to_owned()],
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
        grant_id: id,
        grantor: PrincipalRefV1::try_new([1; 16], "community.local")?,
        grantee: AuthorityGranteeV1::Principal(caller()?),
        trust_domain: "community.local".to_owned(),
        scope: capability,
        valid_from_position: Seq::from_u64(seq),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: vec![],
        consent_references: vec![],
        policy_revision: POLICY_REVISION,
        issuance_timeline: authority_timeline(),
        issuance_seq: Seq::from_u64(seq),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: REGISTRY,
    })?)
}

/// The adapter signing key.
///
/// # Errors
/// Returns the key refusal.
pub fn signing_key() -> Fallible<ForkAuthenticationAdapterSigningKeyV1> {
    Ok(ForkAuthenticationAdapterSigningKeyV1::from_seed(SEED)?)
}

/// The community FAP1.
///
/// # Errors
/// Returns the policy refusal.
pub fn fap1() -> Fallible<ForkAuthenticationPolicyV1> {
    Ok(ForkAuthenticationPolicyV1::new(vec![
        ForkAuthenticationAdapterPolicyV1 {
            adapter_id: ADAPTER.to_owned(),
            verifying_key: signing_key()?.public_key(),
            minimum_assurance: 2,
            registry_bindings: vec![FAP_BINDING],
        },
    ])?)
}

/// A domain over a store with the [`LEAVES`] grants on [`target`], its
/// clock, and the authority installed with CAP1 trust scope `scope`.
pub struct World {
    /// The protected domain.
    pub domain: MemoryCommunityDomainV1,
    /// The installed lifecycle authority.
    pub authority: CommunityLifecycleAuthorityV1,
    /// H(CAP1).
    pub catalogue: Hash,
}

impl World {
    /// Issue the [`LEAVES`] grants into `store` and install the authority.
    ///
    /// # Errors
    /// Returns the fixture construction error.
    pub fn new(
        seal: &'static AuthorityTrustRootSealV1,
        store: MemoryStore,
        scope: &str,
        clock: MemoryTrustedClockAuthorityV1,
    ) -> Fallible<Self> {
        Self::with_grants(
            seal,
            store,
            scope,
            clock,
            Vec::new(),
            SystemGuardMonotonicSourceV1,
        )
    }

    /// Issue the [`LEAVES`] grants and then `extra` into `store`, and install
    /// the authority with the guard monotonic source `mono`.
    ///
    /// # Errors
    /// Returns the fixture construction error.
    pub fn with_grants(
        seal: &'static AuthorityTrustRootSealV1,
        mut store: MemoryStore,
        scope: &str,
        clock: MemoryTrustedClockAuthorityV1,
        extra: Vec<CapabilityGrantV1>,
        mono: impl GuardMonotonicSourceV1 + 'static,
    ) -> Fallible<Self> {
        let mut grants = LEAVES
            .iter()
            .zip(1..)
            .map(|(leaf, seq)| grant(*leaf, seq, &[target(), other_timeline()]))
            .collect::<Fallible<Vec<_>>>()?;
        grants.extend(extra);
        let mut bindings = grants
            .iter()
            .map(CapabilityGrantV1::binding_digest)
            .collect::<Result<Vec<_>, _>>()?;
        bindings.sort_unstable();
        let attestation =
            AuthorityRegistrySnapshotV1::try_new(seal, REGISTRY, vec![hash(41)], bindings, vec![])?;
        let host = AuthorityPersistenceHostV1::new(&attestation);
        store.bind_authority_persistence(host.persistence_binding())?;
        for grant in &grants {
            let permit = host.authorize_grant(grant)?;
            store.issue_capability_grant(permit, grant)?;
        }
        let catalogue = CommunityAuthorityCatalogueV1::new(
            seal,
            CommunityAuthorityCatalogueInputV1 {
                fap1_digest: fap1()?.digest()?,
                audience: AUDIENCE.to_owned(),
                actor_rows: vec![CommunityActorRowV1 {
                    principal_digest: principal_digest_v1(&caller()?)?,
                    actor_entity_id: actor(),
                }],
                capability_policy_revision: POLICY_REVISION,
                consent_policy_revision: CONSENT_REVISION,
                authority_registry_digest: REGISTRY,
                capability_attestation_digest: community_capability_attestation_digest_v1(
                    &attestation,
                ),
                trust_scope: scope.to_owned(),
            },
        )?;
        let digest = catalogue.digest();
        Ok(Self {
            domain: MemoryCommunityDomainV1::new(store, INCARNATION, clock)?,
            authority: CommunityLifecycleAuthorityV1::new(
                seal,
                CommunityLifecycleAuthorityInputV1 {
                    catalogue,
                    authentication_policy: fap1()?,
                    attestation,
                    fork_admission_policies: vec![],
                    member_recipient: RECIPIENT.to_owned(),
                    store_incarnation: INCARNATION,
                },
                ScriptedTrustedWallSourceV1::from_micros([NOW; 64]),
                mono,
            )?,
            catalogue: digest,
        })
    }

    /// The installed authority's `Active` decision for `request` on the
    /// first leaf.
    ///
    /// # Errors
    /// Returns the authentication or evaluation refusal.
    pub fn admit(
        &mut self,
        request: CommunityAdministrativeRequestV1,
    ) -> Fallible<CommunityAuthorityAdmissionV1> {
        Ok(self.call_and_admit(request, LEAVES[0])?.1)
    }

    /// One authenticated call for `request` and its `Active` decision on
    /// `leaf`.
    ///
    /// # Errors
    /// Returns the authentication or evaluation refusal.
    pub fn call_and_admit(
        &mut self,
        request: CommunityAdministrativeRequestV1,
        leaf: Hash,
    ) -> Fallible<(CommunityAuthorityCallV1, CommunityAuthorityAdmissionV1)> {
        let credential = self.credential(request)?;
        let call = self
            .authority
            .authenticate(&credential, request, &mut self.domain)?;
        let admission = self
            .authority
            .authorize_administrative(&call, &self.domain, leaf)?;
        Ok((call, admission))
    }

    /// A canonical FAE1 for `request`, signed by the pinned adapter.
    ///
    /// # Errors
    /// Returns the signing or encoding error.
    pub fn credential(&self, request: CommunityAdministrativeRequestV1) -> Fallible<Vec<u8>> {
        self.credential_until(request, EXPIRES)
    }

    /// A canonical FAE1 for `request` that expires at `expires_at`.
    ///
    /// # Errors
    /// Returns the signing or encoding error.
    pub fn credential_until(
        &self,
        request: CommunityAdministrativeRequestV1,
        expires_at: u64,
    ) -> Fallible<Vec<u8>> {
        let record = AuthenticatedPrincipalRecordV1 {
            principal: caller()?,
            adapter_id: ADAPTER.to_owned(),
            assurance: 2,
            issued_at: ISSUED,
            expires_at,
            registry_binding: FAP_BINDING,
            operation_nonce: oracle_nonce(
                self.catalogue,
                &request.resource(),
                request.action().as_str(),
                &request.operation_constraint(),
            )?,
        };
        Ok(signing_key()?
            .sign_authenticated_principal(record)?
            .to_canonical_cbor()?)
    }
}

/// A harness store whose `scope` has `release_one` active, when `admit`.
/// Keep the harness alive while the store is used.
///
/// # Errors
/// Returns the fixture construction or registry error.
pub fn trusted_store(admit: bool) -> Fallible<(MemoryStore, Harness)> {
    let mut harness = Harness::new()?;
    if admit {
        let genesis = harness.env.genesis()?;
        harness.admit(&genesis, &release_one(), 1)??;
    }
    let store = std::mem::replace(&mut harness.store, MemoryStore::new());
    Ok((store, harness))
}

/// How the scope's adopted trust policy revokes the admitted `release_one`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Revocation {
    /// No revocation: the release is still trusted.
    None,
    /// PRV1 revokes the release digest.
    Artifact,
    /// PRV1 revokes the publisher key epoch 1.
    PublisherKey,
    /// The operator-signed TPS1 alone denies the release digest.
    OperatorDenial,
}

/// A harness store whose `scope` has `release_one` admitted and revoked.
///
/// For a revocation, an adopted policy revokes it at UTC 51, Tick 6. The
/// policy material the trust gate evaluates is returned with it (the
/// genesis material for [`Revocation::None`]). Keep the harness alive while
/// the store is used.
///
/// # Errors
/// Returns the fixture construction or registry error.
pub fn revoked_store(revocation: Revocation) -> Fallible<(MemoryStore, Harness, Material)> {
    let (mut harness, material) = revoked_harness(revocation)?;
    let store = std::mem::replace(&mut harness.store, MemoryStore::new());
    Ok((store, harness, material))
}

/// A second scope `other` in `harness`'s store whose adopted policy
/// revokes `release_one` by artifact, with its environment and material.
///
/// # Errors
/// Returns the fixture construction or registry error.
pub fn foreign_scope(harness: &mut Harness) -> Fallible<(Env, Material)> {
    let installed = std::mem::replace(&mut harness.env, Env::new("other")?);
    PluginTrustPolicyRegistryV1::provision(
        &mut harness.store,
        &harness.env.anchor,
        &harness.env.genesis_tps1,
    )?;
    let genesis = harness.env.genesis()?;
    harness.admit(&genesis, &release_one(), 2)??;
    let material = harness.env.material(
        &Spec {
            epochs: 2,
            revoked_artifacts: vec![release_one().release_digest()?],
            ..Spec::default().at(51, 6)
        },
        &tps_after(&genesis),
    )?;
    harness.advance(&material)??;
    let foreign = std::mem::replace(&mut harness.env, installed);
    Ok((foreign, material))
}

fn revoked_harness(revocation: Revocation) -> Fallible<(Harness, Material)> {
    let mut harness = Harness::new()?;
    let genesis = harness.env.genesis()?;
    harness.admit(&genesis, &release_one(), 1)??;
    let release = release_one().release_digest()?;
    let adopted = match revocation {
        Revocation::None => None,
        Revocation::Artifact => Some((
            Spec {
                epochs: 2,
                revoked_artifacts: vec![release],
                ..Spec::default().at(51, 6)
            },
            tps_after(&genesis),
        )),
        Revocation::PublisherKey => Some((
            Spec {
                epochs: 2,
                revoked_publisher_epochs: vec![1],
                ..Spec::default().at(51, 6)
            },
            tps_after(&genesis),
        )),
        Revocation::OperatorDenial => Some((
            spec(1, 2).at(51, 6),
            TpsSpec {
                extra_artifacts: vec![release],
                ..tps_after(&genesis)
            },
        )),
    };
    let material = match adopted {
        None => genesis,
        Some((chain, tps)) => {
            let material = harness.env.material(&chain, &tps)?;
            harness.advance(&material)??;
            material
        }
    };
    Ok((harness, material))
}

/// The protected initial graph of `records` for `generation`, minted as
/// the 2c-3 commit will: one `ExecutionState` cohort whose scope cover is
/// the CSB1.
///
/// # Errors
/// Returns the fixture construction or assembly error.
pub fn graph(
    seal: &'static AuthorityTrustRootSealV1,
    planner: &CommunityInitializationPlannerV1<'_>,
    profile: &CommunityDurableProfileV1<'_>,
    roster: &Roster,
    records: &CommunityInitializationRecordsV1,
    generation: [u8; 16],
) -> Fallible<CommunityInitializationGraphV1> {
    let bindings = planner.bindings(generation)?;
    let members: Vec<CommunityMemberBindingV1<'_>> = bindings
        .member_bindings()
        .map(|bytes| CommunityMemberBindingV1::from_canonical_cbor(bytes, &roster.implementation))
        .collect::<Result<_, _>>()?;
    let entries: Vec<CommunityInitializationMemberV1<'_>> = members
        .iter()
        .zip(ADDRESSES)
        .map(
            |(binding, binding_envelope_address)| CommunityInitializationMemberV1 {
                binding,
                binding_envelope_address,
            },
        )
        .collect();
    let request = CommunityInitializationRequestV1::from_canonical_cbor(records.request())?;
    let owner = CommunityInitializerOwnerV1::new(
        seal,
        profile,
        vec![Zeroizing::new(roster.state.clone()); 2],
    )?;
    let mut protector = CommunityArtifactProtectorV1::provision(
        seal,
        CommunityProtectionCohortV1 {
            parent_operation: CommunityArtifactOperationV1::Initialization(OPERATION),
            timeline: target(),
            generation,
            purpose: CommunityArtifactPurposeV1::ExecutionState,
            scope_set_digest: adr_h("ScopeSet", &[0x80]),
            scope_cover_digest: records.scope_binding_digest(),
            evidence_not_after_micros: HORIZON,
            allowed_record_kinds: CommunityRecordKindsV1::empty()
                .with(CommunityArtifactKindV1::StateContent)
                .with(CommunityArtifactKindV1::StateRevisionOrHead)
                .with(CommunityArtifactKindV1::ExecutionProvenance)
                .with(CommunityArtifactKindV1::ClassificationProof),
            member_slots: CommunityMemberSlotsV1::new(&[0, 1])?,
            authority_request_digest: hash(0x44),
        },
    )?;
    Ok(CommunityInitializationGraphV1::assemble(
        seal,
        CommunityInitializationGraphInputV1 {
            store_incarnation: INCARNATION,
            producer_ordinal: 7,
            request: &request,
            profile,
            members: &entries,
            owner_binding_digest: bindings.owner_binding_digest(),
            host_provenance_digest: records.provenance_digest(),
            event_logical_head: Seq::ZERO,
        },
        &owner,
        &mut protector,
    )?)
}

/// The leaf of the [`data_grant`] of every [`Bootstrapped`] domain.
pub const DATA_LEAF: Hash = Hash::from_bytes([3; 32]);
/// The leaf of the metadata grant of every [`Bootstrapped`] domain.
pub const METADATA_LEAF: Hash = Hash::from_bytes([4; 32]);
/// The installed metadata owner's audience.
pub const METADATA_AUDIENCE: &str = "community-owner";
/// The bootstrap control identity.
pub const BOOTSTRAP_CONTROL: [u8; 16] = [0xc1; 16];
/// The CSI1 installed catalogue identity.
pub const INSTALLED_CATALOGUE: Hash = Hash::from_bytes([0x64; 32]);
/// The qualified native profile identity, as [`planner_at`] installs it.
pub const NATIVE_PROFILE: Hash = Hash::from_bytes([0x61; 32]);

/// `community:<T32>:member:<M64>` of `entry` under `implementation`.
///
/// # Errors
/// Returns the encoding error.
pub fn member_resource(
    timeline: TimelineId,
    entry: &str,
    implementation: &ImplementationKeyV1,
) -> Fallible<String> {
    let imk1 = encode(&Value::Array(vec![
        Value::Bytes(b"IMK1".to_vec()),
        Value::Integer(1.into()),
        Value::Text(implementation.plugin_id().to_owned()),
        Value::Text(implementation.version().to_owned()),
        Value::Bytes(implementation.release_digest().as_bytes().to_vec()),
    ]))?;
    let preimage = encode(&Value::Array(vec![
        Value::Text(entry.to_owned()),
        Value::Bytes(imk1),
    ]))?;
    Ok(format!(
        "community:{}:member:{}",
        hex(&timeline.inner().to_bytes()),
        hex(adr_h("StableMember", &preimage).as_bytes())
    ))
}

/// One grant that admits every decision of a code-0 initialize of `timeline`
/// and the administrative decision of a pass Abort (`community.pass.abort.v1`).
///
/// It covers the administrative request, `roster`'s initializer `read` and
/// every member's `execute`. The CAV1 has one authority row per chain
/// coordinate, so one operation's decisions on one authority Timeline come
/// from one chain.
///
/// # Errors
/// Returns the grant refusal.
pub fn data_grant(
    id: Hash,
    seq: u64,
    roster: &Roster,
    timeline: TimelineId,
) -> Fallible<CapabilityGrantV1> {
    let mut resources = ENTRIES
        .iter()
        .map(|entry| member_resource(timeline, entry, &roster.implementation))
        .collect::<Fallible<Vec<_>>>()?;
    resources.push(format!(
        "community-initializer:{}",
        hex(&roster.initializer().digest)
    ));
    resources.push(lifecycle_resource(timeline));
    resources.sort_unstable();
    issued(
        id,
        seq,
        caller()?,
        CapabilityScopeDraftV1 {
            resources,
            actions: vec![
                "community.initialize.v1".to_owned(),
                "community.pass.abort.v1".to_owned(),
                "execute".to_owned(),
                "read".to_owned(),
            ],
            purposes: vec!["lifecycle-administration".to_owned()],
            audiences: vec![AUDIENCE.to_owned(), RECIPIENT.to_owned()],
            actor_entity_ids: vec![actor()],
            subject_ids: vec![],
            participant_ids: vec![],
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 1,
            budget: 1,
            environment_constraints: vec![],
        },
    )
}

/// The installed metadata owner's authentication result.
///
/// # Errors
/// Returns the construction refusal.
pub fn metadata_principal(
    seal: &'static AuthorityTrustRootSealV1,
) -> Fallible<AuthenticatedPrincipalResultV1> {
    Ok(AuthenticatedPrincipalResultV1::try_from_draft(
        seal,
        AuthenticatedPrincipalDraftV1 {
            principal: PrincipalRefV1::try_new([0x22; 16], "community.local")?,
            adapter_id: "metadata-adapter".to_owned(),
            assurance: AssuranceLevelV1::try_new(1)?,
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(EXPIRES),
            binding_digest: hash(39),
        },
    )?)
}

/// The metadata owner's grant on this incarnation's metadata resource.
///
/// # Errors
/// Returns the grant refusal.
pub fn metadata_grant(
    seal: &'static AuthorityTrustRootSealV1,
    id: Hash,
    seq: u64,
) -> Fallible<CapabilityGrantV1> {
    issued(
        id,
        seq,
        metadata_principal(seal)?.principal().clone(),
        CapabilityScopeDraftV1 {
            resources: vec![metadata_resource(INCARNATION)],
            actions: vec!["inspect".to_owned(), "write".to_owned()],
            purposes: vec!["owner-enforcement".to_owned()],
            audiences: vec![METADATA_AUDIENCE.to_owned()],
            actor_entity_ids: vec![actor()],
            subject_ids: vec![],
            participant_ids: vec![],
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 1,
            budget: 1,
            environment_constraints: vec![],
        },
    )
}

fn issued(
    id: Hash,
    seq: u64,
    grantee: PrincipalRefV1,
    scope: CapabilityScopeDraftV1,
) -> Fallible<CapabilityGrantV1> {
    Ok(CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: id,
        grantor: PrincipalRefV1::try_new([1; 16], "community.local")?,
        grantee: AuthorityGranteeV1::Principal(grantee),
        trust_domain: "community.local".to_owned(),
        scope: CapabilityScopeV1::try_from_draft(scope)?,
        valid_from_position: Seq::from_u64(seq),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: vec![],
        consent_references: vec![],
        policy_revision: POLICY_REVISION,
        issuance_timeline: authority_timeline(),
        issuance_seq: Seq::from_u64(seq),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: REGISTRY,
    })?)
}

/// A bootstrapped domain on [`target`] / [`GENERATION`], ready to initialize.
///
/// It keeps its metadata authority, the guard monotonic script shared with
/// its lifecycle authority, and the trust harness that must stay alive.
pub struct Bootstrapped {
    /// The domain and its lifecycle authority.
    pub world: World,
    /// The installed NMP1.
    pub policy: CommunityMetadataPolicyV1,
    /// The installed metadata authority.
    pub metadata: CommunityMetadataAuthorityV1,
    /// The lifecycle authority's guard monotonic script.
    pub mono: Arc<Mutex<ScriptedGuardMonotonicSourceV1>>,
    /// The trust registry harness.
    pub harness: Harness,
}

impl Bootstrapped {
    /// Bootstrap a domain whose `release_one` is active when `admit`, and
    /// whose store holds the [`target`] Timeline when `timeline`, under an
    /// NMP1 with the [`HORIZON`] metadata horizon.
    ///
    /// # Errors
    /// Returns the fixture construction or bootstrap error.
    pub fn new(
        seal: &'static AuthorityTrustRootSealV1,
        roster: &Roster,
        admit: bool,
        timeline: bool,
    ) -> Fallible<Self> {
        Self::until(seal, roster, admit, timeline, HORIZON)
    }

    /// [`Bootstrapped::new`] under an NMP1 with metadata horizon
    /// `metadata_horizon`.
    ///
    /// # Errors
    /// Returns the fixture construction or bootstrap error.
    pub fn until(
        seal: &'static AuthorityTrustRootSealV1,
        roster: &Roster,
        admit: bool,
        timeline: bool,
        metadata_horizon: u64,
    ) -> Fallible<Self> {
        let (store, harness) = trusted_store(admit)?;
        Self::over(seal, roster, store, harness, timeline, metadata_horizon)
    }

    /// [`Bootstrapped::new`] over a store whose `release_one` is admitted
    /// and then revoked by `revocation`, with the trust-gate material.
    ///
    /// # Errors
    /// Returns the fixture construction or bootstrap error.
    pub fn revoked(
        seal: &'static AuthorityTrustRootSealV1,
        roster: &Roster,
        revocation: Revocation,
    ) -> Fallible<(Self, Material)> {
        let (store, harness, material) = revoked_store(revocation)?;
        Self::over(seal, roster, store, harness, true, HORIZON).map(|domain| (domain, material))
    }

    /// [`Bootstrapped::revoked`] by artifact, whose store also holds the
    /// [`foreign_scope`] `other`, returned with its environment and
    /// material.
    ///
    /// # Errors
    /// Returns the fixture construction or bootstrap error.
    pub fn revoked_with_foreign(
        seal: &'static AuthorityTrustRootSealV1,
        roster: &Roster,
    ) -> Fallible<(Self, Material, Env, Material)> {
        let (mut harness, material) = revoked_harness(Revocation::Artifact)?;
        let (env, foreign) = foreign_scope(&mut harness)?;
        let store = std::mem::replace(&mut harness.store, MemoryStore::new());
        Self::over(seal, roster, store, harness, true, HORIZON)
            .map(|domain| (domain, material, env, foreign))
    }

    fn over(
        seal: &'static AuthorityTrustRootSealV1,
        roster: &Roster,
        mut store: MemoryStore,
        harness: Harness,
        timeline: bool,
        metadata_horizon: u64,
    ) -> Fallible<Self> {
        if timeline {
            store.create_timeline_with_meta(TimelineMeta {
                id: target(),
                mode: TimelineMode::Live,
                name: None,
                owner: None,
                fork_point: None,
            })?;
        }
        let mono = Arc::new(Mutex::new(ScriptedGuardMonotonicSourceV1::new([])));
        let metadata_grant = metadata_grant(seal, METADATA_LEAF, 4)?;
        let registry = metadata_registry(seal)?;
        let mut world = World::with_grants(
            seal,
            store,
            TRUST_SCOPE,
            MemoryTrustedClockAuthorityV1::new(),
            vec![data_grant(DATA_LEAF, 3, roster, target())?, metadata_grant],
            Arc::clone(&mono),
        )?;
        let policy = CommunityMetadataPolicyV1::new(CommunityMetadataPolicyInputV1 {
            metadata_owner_registry_binding: metadata_principal(seal)?.registry_binding_digest(),
            metadata_authority_leaf_grant: METADATA_LEAF,
            compiled_schema_catalogue_digest: hash(0x65),
            metadata_not_after_micros: metadata_horizon,
        })?;
        let mut metadata = metadata_authority(seal, registry, 64)?;
        let opened = world.domain.open(
            CommunityDomainBindingV1 {
                metadata_policy: &policy,
                installed_catalogue_digest: INSTALLED_CATALOGUE,
                native_profile_digest: NATIVE_PROFILE,
            },
            &mut metadata,
            CommunityBootstrapRequestV1::new(BOOTSTRAP_CONTROL, target(), GENERATION)?,
        )?;
        if opened != CommunityDomainOpenedV1::Bootstrapped {
            return Err("the domain must bootstrap".into());
        }
        Ok(Self {
            world,
            policy,
            metadata,
            mono,
            harness,
        })
    }

    /// The installed domain binding.
    #[must_use]
    pub const fn binding(&self) -> CommunityDomainBindingV1<'_> {
        CommunityDomainBindingV1 {
            metadata_policy: &self.policy,
            installed_catalogue_digest: INSTALLED_CATALOGUE,
            native_profile_digest: NATIVE_PROFILE,
        }
    }

    /// Script the lifecycle authority's next guard monotonic marks.
    pub fn script_mono(&self, offsets: &[Duration]) {
        let mut mono = self
            .mono
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for offset in offsets {
            mono.push(*offset);
        }
    }
}

/// The metadata owner's registry snapshot: its principal and its grant.
///
/// # Errors
/// Returns the construction refusal.
pub fn metadata_registry(
    seal: &'static AuthorityTrustRootSealV1,
) -> Fallible<AuthorityRegistrySnapshotV1> {
    Ok(AuthorityRegistrySnapshotV1::try_new(
        seal,
        REGISTRY,
        vec![metadata_principal(seal)?.registry_binding_digest()],
        vec![metadata_grant(seal, METADATA_LEAF, 4)?.binding_digest()?],
        vec![],
    )?)
}

/// The metadata owner's authority over `registry`, with `samples` trusted
/// wall samples at [`NOW`].
///
/// # Errors
/// Returns the construction refusal.
pub fn metadata_authority(
    seal: &'static AuthorityTrustRootSealV1,
    registry: AuthorityRegistrySnapshotV1,
    samples: usize,
) -> Fallible<CommunityMetadataAuthorityV1> {
    Ok(CommunityMetadataAuthorityV1::new(
        seal,
        CommunityMetadataAuthorityInputV1 {
            registry,
            principal: metadata_principal(seal)?,
            actor_entity_id: actor(),
            principal_role: AuthorityRoleV1::Actor,
            audience: METADATA_AUDIENCE.to_owned(),
            consent_policy_revision: CONSENT_REVISION,
            capability_policy_revision: POLICY_REVISION,
        },
        ScriptedTrustedWallSourceV1::from_micros(vec![NOW; samples]),
    ))
}

/// The default installation of `profile` on this fixture's incarnation.
#[must_use]
pub const fn installation<'a>(
    profile: &'a CommunityDurableProfileV1<'a>,
) -> CommunityInitializationInstallationV1<'a> {
    CommunityInitializationInstallationV1 {
        store_incarnation: INCARNATION,
        profile,
        native_profile_digest: NATIVE_PROFILE,
        installed_owner_catalogue_digest: hash(0x62),
        installation_id: [0x63; 16],
        state_limit_bytes: &STATE_LIMITS,
    }
}

/// Initialize [`target`]'s first generation under `profile` with every
/// grant (code 0, [`OPERATION`]).
///
/// # Errors
/// Returns the fixture construction error; the call result is the value.
pub fn initialize_target(
    seal: &'static AuthorityTrustRootSealV1,
    domain: &mut Bootstrapped,
    roster: &Roster,
    profile: &CommunityDurableProfileV1<'_>,
) -> Fallible<Result<CommunityInitializationReceiptV1, LifecycleError>> {
    let form = CommunityInitializeFormV1 {
        timeline: target(),
        operation_id: OPERATION,
        initial_source: CommunityInitializationSourceV1::Initializer(
            community_initializer_set_ref_v1(profile),
        ),
    };
    let request = CommunityAdministrativeRequestV1::derive(
        &CommunityAdministrativeOperationV1::Initialize {
            timeline: form.timeline,
            operation_id: form.operation_id,
            initial_source: form.initial_source,
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
    )?;
    let credential = domain.world.credential(request)?;
    let owner = CommunityInitializerOwnerV1::new(
        seal,
        profile,
        vec![Zeroizing::new(roster.state.clone()); 2],
    )?;
    let policy = CommunityMetadataPolicyV1::new(*domain.policy.as_input())?;
    let context = CommunityInitializationContextV1 {
        installation: installation(profile),
        binding: CommunityDomainBindingV1 {
            metadata_policy: &policy,
            installed_catalogue_digest: INSTALLED_CATALOGUE,
            native_profile_digest: NATIVE_PROFILE,
        },
        initializer: &owner,
    };
    let world = &mut domain.world;
    Ok(world.domain.initialize(
        seal,
        context,
        &mut world.authority,
        &mut domain.metadata,
        CommunityInitializeCallV1 {
            credential: &credential,
            form,
            administrative_leaf: DATA_LEAF,
            initializer_leaves: &[DATA_LEAF],
            member_leaves: &[DATA_LEAF, DATA_LEAF],
        },
    ))
}

/// The selected head an initialization committed: its CGA1's initial CSH1.
///
/// # Errors
/// Returns the CGA1 codec refusal.
pub fn initial_head(receipt: &CommunityInitializationReceiptV1) -> Fallible<Hash> {
    Ok(
        CommunityGenerationAdmissionV1::from_canonical_cbor(receipt.generation_admission())?
            .as_input()
            .initial_selected_head_digest,
    )
}

/// The control identity of a first `SetReason`.
pub const CONTROL: [u8; 16] = [0x40; 16];

/// One initialized domain whose registry revokes the member release, with
/// the trust-gate material and [`target`]'s committed head.
pub struct QuarantineCase {
    /// The domain and its authorities.
    pub domain: Bootstrapped,
    /// The generation's roster.
    pub roster: Roster,
    /// The trust-gate material the store re-evaluates.
    pub material: Material,
    /// [`target`]'s committed selected head.
    pub head: Hash,
}

impl QuarantineCase {
    /// Initialize [`target`] on a domain revoked by `revocation`, under the
    /// default profile.
    ///
    /// # Errors
    /// Returns the fixture construction or initialization error.
    pub fn new(seal: &'static AuthorityTrustRootSealV1, revocation: Revocation) -> Fallible<Self> {
        let roster = Roster::release_one()?;
        let (mut domain, material) = Bootstrapped::revoked(seal, &roster, revocation)?;
        let rows = roster.rows()?;
        let profile = profile_until(&rows, HORIZON, hash(1), domain.world.catalogue)?;
        let receipt = initialize_target(seal, &mut domain, &roster, &profile)??;
        let head = initial_head(&receipt)?;
        Ok(Self {
            domain,
            roster,
            material,
            head,
        })
    }
}

/// What one `SetReason` names and claims; each field may be varied.
#[derive(Clone, Copy)]
pub struct Claim<'a> {
    /// The failure's Timeline.
    pub timeline: TimelineId,
    /// The failure's stable entry.
    pub entry: &'a str,
    /// The failure's host error.
    pub host: CommunityPluginHostErrorV1,
    /// The bound reason.
    pub reason: CommunityQuarantineReasonV1,
    /// The control identity.
    pub control: [u8; 16],
    /// The expected ledger.
    pub ledger: Option<Hash>,
    /// The expected generation.
    pub generation: [u8; 16],
    /// The expected head; `None` uses the committed head.
    pub head: Option<Hash>,
    /// The claimed TPS1 digest; `None` uses the material's.
    pub tps1: Option<Hash>,
    /// The failure's IMK1; `None` uses the roster's.
    pub implementation: Option<&'a ImplementationKeyV1>,
    /// The trust gate's anchor and material; `None` uses the case's.
    pub trust: Option<(&'a PluginTrustPolicyAnchorV1, &'a Material)>,
}

/// The first-use claim of a release revoked with `basis` on [`target`]'s
/// first entry.
#[must_use]
pub const fn claim(basis: RevocationBasisV1) -> Claim<'static> {
    Claim {
        timeline: target(),
        entry: ENTRIES[0],
        host: CommunityPluginHostErrorV1::ArtifactRevoked { basis },
        reason: CommunityQuarantineReasonV1::Revoked,
        control: CONTROL,
        ledger: None,
        generation: GENERATION,
        head: None,
        tps1: None,
        implementation: None,
        trust: None,
    }
}

/// Run one `SetReason` of `claim` on `case` through `run`.
///
/// The failure is sealed with `seal` and names the release `manifest`; the
/// context installs the CDP1 `profile`. `run` gets the domain's world and
/// metadata authority.
///
/// # Errors
/// Returns the fixture construction error.
pub fn with_set_reason<T>(
    seal: &'static AuthorityTrustRootSealV1,
    case: &mut QuarantineCase,
    profile: &CommunityDurableProfileV1<'_>,
    manifest: &ManifestSpec,
    claim: Claim<'_>,
    run: impl FnOnce(
        &mut World,
        &mut CommunityMetadataAuthorityV1,
        CommunityQuarantineContextV1<'_>,
        CommunitySetReasonCallV1<'_>,
    ) -> T,
) -> Fallible<T> {
    let projection = manifest.projection()?;
    let policy = CommunityMetadataPolicyV1::new(*case.domain.policy.as_input())?;
    let retained = Hash::from_bytes(case.material.tps1_digest());
    let (anchor, material) = claim
        .trust
        .unwrap_or((&case.domain.harness.env.anchor, &case.material));
    let failure = CommunityPreExecutionFailureV1::new(
        seal,
        CommunityPreExecutionFailureInputV1 {
            timeline: claim.timeline,
            stable_entry: claim.entry,
            implementation: claim.implementation.unwrap_or(&case.roster.implementation),
            host_failure: claim.host,
            trust_policy_snapshot_digest: claim.tps1.unwrap_or(retained),
            trust: CommunityPreExecutionTrustV1 {
                anchor,
                tps1_bytes: &material.tps1,
                evidence: &material.evidence,
                projection: &projection,
                trusted_utc: material.trusted()?,
                tick: material.tick,
            },
        },
    );
    Ok(run(
        &mut case.domain.world,
        &mut case.domain.metadata,
        CommunityQuarantineContextV1 {
            profile,
            binding: CommunityDomainBindingV1 {
                metadata_policy: &policy,
                installed_catalogue_digest: INSTALLED_CATALOGUE,
                native_profile_digest: NATIVE_PROFILE,
            },
        },
        CommunitySetReasonCallV1 {
            failure: &failure,
            control_operation_id: claim.control,
            reason: claim.reason,
            expected_ledger_digest: claim.ledger,
            expected_generation: claim.generation,
            expected_state_head_digest: claim.head.unwrap_or(case.head),
        },
    ))
}

/// The CDP1 `rows` under `quarantine` as its quarantine horizon.
///
/// # Errors
/// Returns the CDP1 refusal.
pub fn profile_with_quarantine<'a>(
    rows: &'a [CommunityProfileMemberV1<'a>],
    catalogue: Hash,
    quarantine: u64,
) -> Fallible<CommunityDurableProfileV1<'a>> {
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            retention: CommunityProfileRetentionV1 {
                quarantine_not_after_micros: quarantine,
                ..profile_until(rows, HORIZON, hash(1), catalogue)?
                    .as_input()
                    .retention
            },
            ..*profile_until(rows, HORIZON, hash(1), catalogue)?.as_input()
        },
    )?)
}
