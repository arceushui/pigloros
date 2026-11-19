//! The CAV1 current view of a planned code-0 initialization (#560
//! A3c-2c-2; ADR-129 §3, R6.5, R6.7) through the planner's public seam:
//! authority rows from the domain's own chain, trust rows from the domain's
//! own Plugin trust registry (I26, owner decisions 10 and 11 of
//! 2026-11-19), key rows (decision 3), the clock latch and the inventory
//! generation (G5).
#![cfg(target_os = "linux")]

#[path = "support/plugin_trust_registry_fixtures.rs"]
pub mod fixtures;

use std::error::Error as StdError;

use ciborium::Value;
use fixtures::{release_one, Harness, ManifestSpec};
use pos_core::community_lifecycle::CommunityMaterializationV1;
use pos_core::community_lifecycle::{
    community_capability_attestation_digest_v1, community_initializer_set_ref_v1, ArtifactRefV1,
    CommunityActorRowV1, CommunityArtifactKindV1, CommunityArtifactOperationV1,
    CommunityArtifactPurposeV1, CommunityAuthorityCatalogueInputV1, CommunityAuthorityCatalogueV1,
    CommunityAuthorityEvidenceV1, CommunityCurrentViewV1, CommunityDurableBackendV1,
    CommunityDurableProfileInputV1, CommunityDurableProfileV1, CommunityInitializationRequestV1,
    CommunityInitializationSourceV1 as Source, CommunityKeyIntentInputV1, CommunityKeyIntentV1,
    CommunityKeyStateV1, CommunityLifecycleErrorV1 as Error, CommunityMemberBindingV1,
    CommunityMemberSlotsV1, CommunityPassFrontierV1, CommunityProfileMemberV1,
    CommunityProfileRetentionV1, CommunityRecordKindsV1, CommunityStateContentV1,
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
    ImplementationKeyV1, KeyRoleV1, PrincipalRefV1, Seq, TimelineId,
};
use pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1;
use pos_store::community::{
    CommunityAdministrativeRequestV1 as Request, CommunityArtifactProtectorV1,
    CommunityAuthorityAdmissionV1, CommunityAuthorityCallV1,
    CommunityInitializationEvidenceInputV1, CommunityInitializationGraphInputV1,
    CommunityInitializationGraphV1, CommunityInitializationInstallationV1,
    CommunityInitializationMemberV1, CommunityInitializationPlannerV1, CommunityInitializeFormV1,
    CommunityInitializerOwnerV1, CommunityLifecycleAuthorityInputV1, CommunityLifecycleAuthorityV1,
    CommunityProtectionCohortV1, MemoryCommunityDomainV1,
};
use pos_store::memory::MemoryStore;
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryV1;
use pos_store::MemoryTrustedClockAuthorityV1;
use ulid::Ulid;
use zeroize::Zeroizing;

type Fallible<T> = Result<T, Box<dyn StdError>>;
type TestResult = Fallible<()>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

const REGISTRY: Hash = Hash::from_bytes([31; 32]);
const POLICY_REVISION: Hash = Hash::from_bytes([32; 32]);
const CONSENT_REVISION: Hash = Hash::from_bytes([33; 32]);
const FAP_BINDING: Hash = Hash::from_bytes([60; 32]);
const AUDIENCE: &str = "community-host";
const ADAPTER: &str = "community-adapter";
const SEED: [u8; 32] = [7; 32];
const INCARNATION: [u8; 16] = [0x5a; 16];
const OPERATION: [u8; 16] = [0x10; 16];
const GENERATION: [u8; 16] = [0x20; 16];
const NOW: u64 = 500;
const ISSUED: u64 = 100;
const EXPIRES: u64 = 30_000_100;
const HORIZON: u64 = 1_000;
const SCHEMA: Hash = Hash::from_bytes([0x22; 32]);
const ENTRIES: [&str; 2] = ["Entry-A_1", "Entry-B_1"];
const STATE_LIMITS: [u64; 2] = [4096, 100];
const TRUST_SCOPE: &str = "scope";
const ADDRESSES: [Hash; 2] = [Hash::from_bytes([0x71; 32]), Hash::from_bytes([0x72; 32])];

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

const fn target() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x0e; 16]))
}

const fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([7; 16]))
}

const fn actor() -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([8; 16]))
}

fn caller() -> Fallible<PrincipalRefV1> {
    Ok(PrincipalRefV1::try_new([0x11; 16], "community.local")?)
}

fn hex(bytes: &[u8]) -> String {
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

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

/// `H(M, bytes)`: BLAKE3 of `PiglorOS.Community.<M>.v1`, a zero byte and
/// the bytes.
fn adr_h(m: &str, preimage: &[u8]) -> Hash {
    let mut input = b"PiglorOS.Community.".to_vec();
    input.extend_from_slice(m.as_bytes());
    input.extend_from_slice(b".v1\0");
    input.extend_from_slice(preimage);
    Hash::from_bytes(*blake3::hash(&input).as_bytes())
}

fn lifecycle_resource(timeline: TimelineId) -> String {
    format!("community:{}:lifecycle", hex(&timeline.inner().to_bytes()))
}

fn oracle_nonce(
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

// ------------------------------------------------------------ installation

/// A roster of two `plugin-a` members whose PMF1 and release are `manifest`'s.
struct Roster {
    implementation: ImplementationKeyV1,
    pmf1: Hash,
    state: Vec<u8>,
}

impl Roster {
    fn new(manifest: &ManifestSpec, pmf1: Option<Hash>, release: Option<Hash>) -> Fallible<Self> {
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

    fn rows(&self) -> Fallible<Vec<CommunityProfileMemberV1<'_>>> {
        ENTRIES
            .iter()
            .map(|entry| {
                Ok(CommunityProfileMemberV1::new(
                    entry,
                    &self.implementation,
                    self.pmf1,
                    SCHEMA,
                    hash(6),
                    ArtifactRefV1 {
                        schema_id: 0x4353_0001,
                        byte_length: self.state.len() as u64,
                        digest: *adr_h("CSC1", &self.state).as_bytes(),
                    },
                )?)
            })
            .collect()
    }
}

fn profile<'a>(
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

fn planner<'a>(
    profile: &'a CommunityDurableProfileV1<'a>,
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
            timeline: target(),
            operation_id: OPERATION,
            initial_source: Source::Initializer(community_initializer_set_ref_v1(profile)),
        },
    )?)
}

/// One CKP1 key intent: `byte` names its protection operation.
fn key(byte: u8, purpose: CommunityArtifactPurposeV1) -> Fallible<CommunityKeyIntentV1> {
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

// ------------------------------------------------------------- authority

fn grant(timelines: &[TimelineId]) -> Fallible<CapabilityGrantV1> {
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
        grant_id: hash(1),
        grantor: PrincipalRefV1::try_new([1; 16], "community.local")?,
        grantee: AuthorityGranteeV1::Principal(caller()?),
        trust_domain: "community.local".to_owned(),
        scope: capability,
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

fn signing_key() -> Fallible<ForkAuthenticationAdapterSigningKeyV1> {
    Ok(ForkAuthenticationAdapterSigningKeyV1::from_seed(SEED)?)
}

fn fap1() -> Fallible<ForkAuthenticationPolicyV1> {
    Ok(ForkAuthenticationPolicyV1::new(vec![
        ForkAuthenticationAdapterPolicyV1 {
            adapter_id: ADAPTER.to_owned(),
            verifying_key: signing_key()?.public_key(),
            minimum_assurance: 2,
            registry_bindings: vec![FAP_BINDING],
        },
    ])?)
}

/// A domain over `store` with one administrative grant, its clock
/// `clock`, and the authority installed with CAP1 trust scope `scope`.
struct World {
    domain: MemoryCommunityDomainV1,
    authority: CommunityLifecycleAuthorityV1,
    catalogue: Hash,
    leaf: Hash,
}

impl World {
    fn new(
        mut store: MemoryStore,
        scope: &str,
        clock: MemoryTrustedClockAuthorityV1,
    ) -> Fallible<Self> {
        let leaf = grant(&[target()])?;
        let attestation = AuthorityRegistrySnapshotV1::try_new(
            &SEAL,
            REGISTRY,
            vec![hash(41)],
            vec![leaf.binding_digest()?],
            vec![],
        )?;
        let host = AuthorityPersistenceHostV1::new(&attestation);
        store.bind_authority_persistence(host.persistence_binding())?;
        let permit = host.authorize_grant(&leaf)?;
        store.issue_capability_grant(permit, &leaf)?;
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
                    member_recipient: "community-recipient".to_owned(),
                    store_incarnation: INCARNATION,
                },
                ScriptedTrustedWallSourceV1::from_micros([NOW; 16]),
                SystemGuardMonotonicSourceV1,
            )?,
            catalogue: digest,
            leaf: leaf.grant_id(),
        })
    }

    /// The installed authority's `Active` decision for `request`.
    fn admit(&mut self, request: Request) -> Fallible<CommunityAuthorityAdmissionV1> {
        Ok(self.call_and_admit(request)?.1)
    }

    /// One authenticated call for `request` and its `Active` decision.
    fn call_and_admit(
        &mut self,
        request: Request,
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
            .authorize_administrative(&call, &self.domain, self.leaf)?;
        Ok((call, admission))
    }
}

/// A harness store whose `scope` has `release_one` active, when `admit`.
fn trusted_store(admit: bool) -> Fallible<(MemoryStore, Harness)> {
    let mut harness = Harness::new()?;
    if admit {
        let genesis = harness.env.genesis()?;
        harness.admit(&genesis, &release_one(), 1)??;
    }
    let store = std::mem::replace(&mut harness.store, MemoryStore::new());
    Ok((store, harness))
}

// ------------------------------------------------------------------ tests

/// I26 (planner part) and R6.7: every CAV1 row of a code-0 initialize.
#[test]
fn the_view_reads_every_row_from_the_domain() -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let policy = store.retained_policy_state(TRUST_SCOPE)?;
    let roster = Roster::new(&release_one(), None, None)?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner = planner(&profile)?;
    let mut world = World::new(store, TRUST_SCOPE, MemoryTrustedClockAuthorityV1::new())?;
    let admission = world.admit(planner.request())?;
    let again = world.admit(planner.request())?;
    let metadata = key(0x0b, CommunityArtifactPurposeV1::LifecycleControl)?;
    let cohort = key(0x0a, CommunityArtifactPurposeV1::ExecutionState)?;
    let view = planner.current_view(
        &world.domain,
        &world.authority,
        GENERATION,
        &[&admission, &again],
        &[&metadata, &cohort],
    )?;
    assert_eq!(view.inventory_generation(), 0);
    let decoded = CommunityCurrentViewV1::from_canonical_cbor(view.view())?;
    assert_eq!(decoded.digest(), view.view_digest());
    let fields = decoded.as_input();
    assert_eq!(fields.store_incarnation, INCARNATION);
    assert_eq!(fields.timeline, target());
    assert_eq!(fields.generation, GENERATION);
    assert_eq!(fields.inventory_generation, 0);
    assert!(fields.frontier == CommunityPassFrontierV1::Initial);
    assert!(fields.selected_head.is_none());
    assert!(fields.scope_rows.is_empty());
    // Two decisions on one chain give one authority row.
    assert_eq!(fields.authority_rows.len(), 1);
    let authority = fields.authority_rows[0];
    assert_eq!(authority.authority_timeline, authority_timeline());
    assert_eq!(
        authority.head_seq,
        admission.request().at_position().as_u64()
    );
    assert_eq!(authority.revocation_epoch, 0);
    assert_eq!(authority.registry_digest, REGISTRY);
    assert_eq!(authority.capability_policy_revision, POLICY_REVISION);
    assert_eq!(authority.consent_policy_revision, CONSENT_REVISION);
    // Two members of one Plugin give one trust row.
    assert_eq!(fields.trust_rows.len(), 1);
    let trust = &fields.trust_rows[0];
    assert_eq!(trust.scope, TRUST_SCOPE);
    assert_eq!(trust.plugin_id, "plugin-a");
    assert_eq!(trust.policy_digest, Hash::from_bytes(policy.tps1_digest()));
    assert_eq!(
        trust.policy_floor,
        policy.ptr1_floor().map_or(0, |(floor, _)| floor)
    );
    assert_eq!(
        trust.release_floor,
        policy.prv1_floor().map_or(0, |(floor, _)| floor)
    );
    assert_eq!(
        trust.highest_trusted_utc_second,
        u64::try_from(policy.highest_trusted_utc_second().unwrap_or(0))?
    );
    assert_eq!(trust.active_manifest_digest, roster.pmf1);
    assert_eq!(
        trust.active_release_digest,
        Hash::from_bytes(release_one().release_digest()?)
    );
    // Key rows are in owner-text order, whatever order they came in.
    let keys: Vec<_> = fields.key_rows.iter().collect();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].owner, cohort.key_owner_text());
    assert_eq!(keys[1].owner, metadata.key_owner_text());
    for (row, intent) in keys.iter().zip([&cohort, &metadata]) {
        assert_eq!(row.role, KeyRoleV1::CommunityArtifactEncryption);
        assert_eq!(row.epoch, 1);
        assert!(row.state == CommunityKeyStateV1::Available);
        assert_eq!(row.key_intent_digest, intent.digest());
    }
    assert_eq!(fields.clock_latch.overrun_count, 0);
    assert!(!fields.clock_latch.latched);
    Ok(())
}

/// R6.5(4), decisions 10 and 11: no active release, or one whose PMF1 or
/// release differs from the member's, is `AdmissionDenied`; a missing
/// scope is 12.
#[test]
fn trust_rows_deny_or_refuse() -> TestResult {
    // (admit release_one, member PMF1, member release, CAP1 trust scope)
    let cases = [
        (false, None, None, TRUST_SCOPE, Error::AdmissionDenied),
        (
            true,
            Some(hash(0x99)),
            None,
            TRUST_SCOPE,
            Error::AdmissionDenied,
        ),
        (
            true,
            None,
            Some(hash(0x98)),
            TRUST_SCOPE,
            Error::AdmissionDenied,
        ),
        (true, None, None, "other-scope", Error::EvidenceUnavailable),
    ];
    for (admit, pmf1, release, scope, expected) in cases {
        let (store, _harness) = trusted_store(admit)?;
        let roster = Roster::new(&release_one(), pmf1, release)?;
        let rows = roster.rows()?;
        let profile = profile(&rows)?;
        let planner = planner(&profile)?;
        let mut world = World::new(store, scope, MemoryTrustedClockAuthorityV1::new())?;
        let admission = world.admit(planner.request())?;
        assert_eq!(
            planner
                .current_view(
                    &world.domain,
                    &world.authority,
                    GENERATION,
                    &[&admission],
                    &[]
                )
                .err(),
            Some(expected)
        );
    }
    Ok(())
}

/// Another domain, an unloadable chain and a clock with no latch row are 12.
#[test]
fn the_view_refuses_unavailable_evidence() -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let roster = Roster::new(&release_one(), None, None)?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner = planner(&profile)?;
    let clock = MemoryTrustedClockAuthorityV1::new();
    let mut world = World::new(store, TRUST_SCOPE, clock.handle())?;
    let admission = world.admit(planner.request())?;
    // A domain sharing the clock but holding no grant chain.
    let bare = MemoryCommunityDomainV1::new(MemoryStore::new(), INCARNATION, clock.handle())?;
    // A domain whose clock never reserved.
    let unlatched = MemoryCommunityDomainV1::new(
        MemoryStore::new(),
        INCARNATION,
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    let foreign = MemoryCommunityDomainV1::new(
        MemoryStore::new(),
        [1; 16],
        MemoryTrustedClockAuthorityV1::new(),
    )?;
    for domain in [&bare, &unlatched, &foreign] {
        assert_eq!(
            planner
                .current_view(domain, &world.authority, GENERATION, &[&admission], &[])
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

/// The protected initial graph of `records`, minted as the 2c-3 commit
/// will: one `ExecutionState` cohort whose scope cover is the CSB1.
fn graph(
    planner: &CommunityInitializationPlannerV1<'_>,
    profile: &CommunityDurableProfileV1<'_>,
    roster: &Roster,
    records: &pos_store::community::CommunityInitializationRecordsV1,
) -> Fallible<CommunityInitializationGraphV1> {
    let bindings = planner.bindings(GENERATION)?;
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
            generation: GENERATION,
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

/// The facts one planned initialization's CAU1 is built from.
struct Operation<'a> {
    world: &'a mut World,
    planner: &'a CommunityInitializationPlannerV1<'a>,
    profile: &'a CommunityDurableProfileV1<'a>,
    call: &'a CommunityAuthorityCallV1,
    admission: &'a CommunityAuthorityAdmissionV1,
    records: &'a pos_store::community::CommunityInitializationRecordsV1,
    graph: &'a CommunityInitializationGraphV1,
    input: CommunityInitializationEvidenceInputV1<'a>,
}

/// Plan, view and assemble one initialization, then run `check` on it.
fn with_operation(check: impl FnOnce(Operation<'_>) -> TestResult) -> TestResult {
    let (store, _harness) = trusted_store(true)?;
    let roster = Roster::new(&release_one(), None, None)?;
    let rows = roster.rows()?;
    let profile = profile(&rows)?;
    let planner = planner(&profile)?;
    let mut world = World::new(store, TRUST_SCOPE, MemoryTrustedClockAuthorityV1::new())?;
    let (call, admission) = world.call_and_admit(planner.request())?;
    let records = planner.records(GENERATION, &admission, &ADDRESSES)?;
    let view = planner.current_view(
        &world.domain,
        &world.authority,
        GENERATION,
        &[&admission],
        &[],
    )?;
    let graph = graph(&planner, &profile, &roster, &records)?;
    let input = CommunityInitializationEvidenceInputV1 {
        call: &call,
        records: &records,
        view: &view,
        decisions: &[&admission, &admission],
        graph: &graph,
    };
    check(Operation {
        world: &mut world,
        planner: &planner,
        profile: &profile,
        call: &call,
        admission: &admission,
        records: &records,
        graph: &graph,
        input,
    })
}

/// R6.6 and A5.3(4): CAU1 binds the CGI1, every protected record, the
/// CAV1, the call's decisions, the recipient (G6) and the clock bound (G1).
#[test]
fn the_authority_evidence_binds_the_whole_operation() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            call,
            admission,
            records,
            graph,
            input,
            ..
        } = operation;
        let view = input.view;
        let evidence = planner.authority_evidence(&world.authority, GENERATION, input)?;
        assert_eq!(evidence.inventory_generation(), 0);
        let decoded = CommunityAuthorityEvidenceV1::from_canonical_cbor(evidence.evidence())?;
        assert_eq!(decoded.digest(), evidence.evidence_digest());
        let fields = decoded.as_input();
        assert_eq!(fields.store_incarnation, INCARNATION);
        assert_eq!(fields.timeline, target());
        assert_eq!(fields.generation, GENERATION);
        assert!(fields.operation == CommunityArtifactOperationV1::Initialization(OPERATION));
        assert_eq!(fields.input_identity, records.request_digest());
        let mut objects: Vec<(Hash, Hash, Hash)> = graph
            .records()
            .iter()
            .map(|record| {
                let protected = record.protected();
                (
                    protected.object_address(),
                    protected.registration().fields().artifact_digest,
                    protected.registration().address(),
                )
            })
            .collect();
        objects.sort_unstable();
        assert_eq!(objects.len(), 10);
        assert_eq!(
            fields
                .object_bindings
                .iter()
                .map(|row| (
                    row.object_address,
                    row.artifact_digest,
                    row.registration_address
                ))
                .collect::<Vec<_>>(),
            objects
        );
        assert_eq!(fields.inventory_generation, 0);
        assert_eq!(fields.current_premise_digest, view.view_digest());
        // The decision given twice is one row.
        assert_eq!(fields.decision_rows.len(), 1);
        let row = fields.decision_rows[0];
        let request = admission.request();
        assert_eq!(
            row.decision_digest,
            Hash::from_bytes(admission.authorization_ref().digest)
        );
        assert_eq!(row.request_digest, request.binding_digest());
        assert_eq!(row.leaf_grant_id, world.leaf);
        assert_eq!(row.authority_timeline, authority_timeline());
        assert_eq!(row.head_seq, request.at_position().as_u64());
        assert_eq!(row.revocation_epoch, 0);
        assert_eq!(row.policy_revision, POLICY_REVISION);
        assert_eq!(
            fields.recipient_identity_digest,
            adr_h(
                "RecipientIdentity",
                &encode(&Value::Text("community-recipient".into()))?
            )
        );
        assert_eq!(fields.clock_bound.reservation_id, call.reservation_id());
        assert_eq!(fields.clock_bound.reservation_sample_micros, NOW);
        assert_eq!(
            fields.clock_bound.decision_bound_micros,
            call.decision_bound().as_micros()
        );
        assert_eq!(fields.evidence_not_after_micros, HORIZON);

        Ok(())
    })
}

/// A call of another request, and no administrative decision, refuse.
#[test]
fn the_authority_evidence_refuses_another_call_or_no_administrative_decision() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            profile,
            input,
            ..
        } = operation;
        let (other, _) = world.call_and_admit(Request::derive(
            &pos_store::community::CommunityAdministrativeOperationV1::Initialize {
                timeline: target(),
                operation_id: [0x11; 16],
                initial_source: Source::Initializer(community_initializer_set_ref_v1(profile)),
                expected_prior_generation: None,
                expected_prior_head_digest: None,
            },
        )?)?;
        for input in [
            CommunityInitializationEvidenceInputV1 {
                call: &other,
                ..input
            },
            CommunityInitializationEvidenceInputV1 {
                decisions: &[],
                ..input
            },
        ] {
            assert_eq!(
                planner
                    .authority_evidence(&world.authority, GENERATION, input)
                    .err(),
                Some(Error::InvalidBinding)
            );
        }
        Ok(())
    })
}

/// ADR-128 §3: one COA1 per protected record, binding the CAU1.
#[test]
fn every_protected_record_gets_its_coa1() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            records,
            graph,
            input,
            ..
        } = operation;
        let evidence = planner.authority_evidence(&world.authority, GENERATION, input)?;
        let admissions = planner.admissions(graph, &evidence)?;
        assert_eq!(admissions.len(), graph.records().len());
        let owner = planner.bindings(GENERATION)?.owner_binding_digest();
        for (admission, record) in admissions.iter().zip(graph.records()) {
            let fields = admission.as_input();
            let protected = record.protected();
            assert_eq!(fields.protected_object_address, protected.object_address());
            assert_eq!(
                fields.artifact_digest,
                protected.registration().fields().artifact_digest
            );
            assert_eq!(
                fields.registration_address,
                protected.registration().address()
            );
            assert_eq!(fields.owner_binding_digest, owner);
            assert_eq!(fields.scope_cover_digest, records.scope_binding_digest());
            assert_eq!(fields.evidence_not_after_micros, HORIZON);
            assert_eq!(fields.admission_inventory_generation, 0);
            assert_eq!(fields.authority_evidence_digest, evidence.evidence_digest());
        }
        Ok(())
    })
}

/// Note 22661, item 7: one CMI1 per protected record, each naming its own
/// record's COA1; a COA1 list of another length is refused.
#[test]
fn every_protected_record_gets_its_cmi1() -> TestResult {
    with_operation(|operation| {
        let Operation {
            world,
            planner,
            graph,
            input,
            ..
        } = operation;
        let evidence = planner.authority_evidence(&world.authority, GENERATION, input)?;
        let admissions = planner.admissions(graph, &evidence)?;
        let materializations = planner.materializations(GENERATION, graph, &admissions)?;
        assert_eq!(materializations.len(), graph.records().len());
        for ((bytes, admission), record) in materializations
            .iter()
            .zip(&admissions)
            .zip(graph.records())
        {
            let materialization = CommunityMaterializationV1::from_canonical_cbor(bytes)?;
            let fields = materialization.as_input();
            assert_eq!(
                fields.materialization.attestation_address,
                admission.digest()
            );
            assert_eq!(
                fields.materialization.object_address,
                record.protected().object_address()
            );
            assert_eq!(fields.record_magic, record.record_magic());
            assert_eq!(fields.timeline, target());
            assert_eq!(fields.generation, GENERATION);
        }
        assert_eq!(
            planner
                .materializations(GENERATION, graph, &admissions[1..])
                .err(),
            Some(Error::InvalidBinding)
        );
        Ok(())
    })
}
