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

use ciborium::Value;
use pos_core::community_lifecycle::{
    community_capability_attestation_digest_v1, community_initializer_set_ref_v1, ArtifactRefV1,
    CommunityActorRowV1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityAuthorityCatalogueInputV1, CommunityAuthorityCatalogueV1,
    CommunityDurableBackendV1, CommunityDurableProfileInputV1, CommunityDurableProfileV1,
    CommunityInitializationRequestV1, CommunityInitializationSourceV1, CommunityKeyIntentInputV1,
    CommunityKeyIntentV1, CommunityMemberBindingV1, CommunityMemberSlotsV1,
    CommunityProfileMemberV1, CommunityProfileRetentionV1, CommunityRecordKindsV1,
    CommunityStateContentV1,
};
use pos_core::fork_authentication::{
    principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
    ForkAuthenticationPolicyV1,
};
use pos_core::trusted_clock::{ScriptedTrustedWallSourceV1, SystemGuardMonotonicSourceV1};
use pos_core::{
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityTrustRootSealV1, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1, EntityId, Hash,
    ImplementationKeyV1, PrincipalRefV1, Seq, TimelineId,
};
use pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1;
use pos_store::community::{
    CommunityAdministrativeRequestV1, CommunityArtifactProtectorV1, CommunityAuthorityAdmissionV1,
    CommunityAuthorityCallV1, CommunityInitializationGraphInputV1, CommunityInitializationGraphV1,
    CommunityInitializationInstallationV1, CommunityInitializationMemberV1,
    CommunityInitializationPlannerV1, CommunityInitializationRecordsV1, CommunityInitializeFormV1,
    CommunityInitializerOwnerV1, CommunityLifecycleAuthorityInputV1, CommunityLifecycleAuthorityV1,
    CommunityProtectionCohortV1, MemoryCommunityDomainV1,
};
use pos_store::memory::MemoryStore;
use pos_store::MemoryTrustedClockAuthorityV1;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::plugin_trust_registry_fixtures::{release_one, Harness, ManifestSpec};

/// A fallible fixture step.
pub type Fallible<T> = Result<T, Box<dyn StdError>>;

/// The trust-root seal of the test composition.
pub const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
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
pub const HORIZON: u64 = 1_000;
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
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            backend: CommunityDurableBackendV1::RetainedMemory,
            execution_profile_digest: hash(1),
            roster,
            source_catalogue_digest: hash(2),
            authority_catalogue_digest: hash(9),
            retention: CommunityProfileRetentionV1 {
                generation_not_after_micros: HORIZON,
                recovery_window_micros: 1,
                quarantine_not_after_micros: HORIZON,
                metadata_not_after_micros: HORIZON,
            },
        },
    )?)
}

/// The installed planner of a code-0 initialization of `timeline`.
///
/// # Errors
/// Returns the planner refusal.
pub fn planner_at<'a>(
    profile: &'a CommunityDurableProfileV1<'a>,
    timeline: TimelineId,
) -> Fallible<CommunityInitializationPlannerV1<'a>> {
    Ok(CommunityInitializationPlannerV1::new(
        &SEAL,
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
    profile: &'a CommunityDurableProfileV1<'a>,
) -> Fallible<CommunityInitializationPlannerV1<'a>> {
    planner_at(profile, target())
}

/// One CKP1 key intent: `byte` names its protection operation.
///
/// # Errors
/// Returns the intent refusal.
pub fn key(byte: u8, purpose: CommunityArtifactPurposeV1) -> Fallible<CommunityKeyIntentV1> {
    Ok(CommunityKeyIntentV1::new(CommunityKeyIntentInputV1 {
        protection_operation_id: [byte; 16],
        parent_operation: CommunityArtifactOperationV1::Initialization(OPERATION),
        timeline: target(),
        generation: GENERATION,
        purpose,
        scope_set_digest: adr_h("ScopeSet", &[0x80]),
        evidence_not_after_micros: HORIZON,
        allowed_record_kinds: CommunityRecordKindsV1::empty()
            .with(CommunityArtifactKindV1::LifecycleControl),
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
        mut store: MemoryStore,
        scope: &str,
        clock: MemoryTrustedClockAuthorityV1,
    ) -> Fallible<Self> {
        let grants = LEAVES
            .iter()
            .zip(1..)
            .map(|(leaf, seq)| grant(*leaf, seq, &[target(), other_timeline()]))
            .collect::<Fallible<Vec<_>>>()?;
        let mut bindings = grants
            .iter()
            .map(CapabilityGrantV1::binding_digest)
            .collect::<Result<Vec<_>, _>>()?;
        bindings.sort_unstable();
        let attestation = AuthorityRegistrySnapshotV1::try_new(
            &SEAL,
            REGISTRY,
            vec![hash(41)],
            bindings,
            vec![],
        )?;
        let host = AuthorityPersistenceHostV1::new(&attestation);
        store.bind_authority_persistence(host.persistence_binding())?;
        for grant in &grants {
            let permit = host.authorize_grant(grant)?;
            store.issue_capability_grant(permit, grant)?;
        }
        let catalogue = CommunityAuthorityCatalogueV1::new(
            &SEAL,
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
                &SEAL,
                CommunityLifecycleAuthorityInputV1 {
                    catalogue,
                    authentication_policy: fap1()?,
                    attestation,
                    fork_admission_policies: vec![],
                    member_recipient: RECIPIENT.to_owned(),
                    store_incarnation: INCARNATION,
                },
                ScriptedTrustedWallSourceV1::from_micros([NOW; 64]),
                SystemGuardMonotonicSourceV1,
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
        let record = AuthenticatedPrincipalRecordV1 {
            principal: caller()?,
            adapter_id: ADAPTER.to_owned(),
            assurance: 2,
            issued_at: ISSUED,
            expires_at: EXPIRES,
            registry_binding: FAP_BINDING,
            operation_nonce: oracle_nonce(
                self.catalogue,
                &request.resource(),
                request.action().as_str(),
                &request.operation_constraint(),
            )?,
        };
        let credential = signing_key()?
            .sign_authenticated_principal(record)?
            .to_canonical_cbor()?;
        let call = self
            .authority
            .authenticate(&credential, request, &mut self.domain)?;
        let admission = self
            .authority
            .authorize_administrative(&call, &self.domain, leaf)?;
        Ok((call, admission))
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

/// The protected initial graph of `records` for `generation`, minted as
/// the 2c-3 commit will: one `ExecutionState` cohort whose scope cover is
/// the CSB1.
///
/// # Errors
/// Returns the fixture construction or assembly error.
pub fn graph(
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
        &SEAL,
        profile,
        vec![Zeroizing::new(roster.state.clone()); 2],
    )?;
    let mut protector = CommunityArtifactProtectorV1::provision(
        &SEAL,
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
        &SEAL,
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
