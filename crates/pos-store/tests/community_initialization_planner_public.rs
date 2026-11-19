//! The backend-neutral initialize planner (#560 A3c-2c-2) through its public
//! seam: the P6 check before any authority call (I31), the R6.3 anchor-T
//! check and anchor-G derivation, COB1 and the host-derived CMB1s (G2), and
//! the CGI1, CSB1 (G4), CBQ1 (G3) and CPV1 of the owner decisions on #560,
//! note 22722.
//!
//! Grants are issued into a real `MemoryStore` through the trusted
//! persistence host, and the CGI1 refs come from the installed authority's
//! own decision. Every expected typed-ref and scope-set digest is computed
//! independently with `ciborium` and `blake3` from the ADR formulas.

use std::error::Error as StdError;

use ciborium::Value;
use pos_core::community_lifecycle::{
    community_capability_attestation_digest_v1, community_initializer_set_ref_v1, ArtifactRefV1,
    CommunityActorRowV1, CommunityArtifactOperationV1 as ArtifactOperation,
    CommunityAuthorityCatalogueInputV1, CommunityAuthorityCatalogueV1, CommunityBudgetQuoteV1,
    CommunityDueMemberBudgetV1, CommunityDurableBackendV1, CommunityDurableProfileInputV1,
    CommunityDurableProfileV1, CommunityGenerationIdsV1, CommunityInitializationRequestV1,
    CommunityInitializationSourceV1 as Source, CommunityLifecycleErrorV1 as Error,
    CommunityMemberBindingInputV1, CommunityMemberBindingV1, CommunityMetadataAnchorV1,
    CommunityMetadataPolicyInputV1, CommunityMetadataPolicyV1, CommunityOriginalProvenanceV1,
    CommunityOwnerBindingInputV1, CommunityOwnerBindingV1, CommunityProfileMemberV1,
    CommunityProfileRetentionV1, CommunityScopeBindingV1, CommunitySelectionInputV1,
    CommunitySelectionV1, CommunityStateContentV1, CommunityTimelineFloorV1,
    CommunityTimelineFloorsV1, CommunityTypedInputRefV1,
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
    CommunityAdministrativeActionV1 as Action, CommunityAdministrativeOperationV1 as Operation,
    CommunityAdministrativeRequestV1 as Request, CommunityAuthorityAdmissionV1,
    CommunityInitializationInstallationV1, CommunityInitializationPlannerV1,
    CommunityInitializeFormV1, CommunityLifecycleAuthorityInputV1, CommunityLifecycleAuthorityV1,
    MemoryCommunityDomainV1,
};
use pos_store::memory::MemoryStore;
use pos_store::MemoryTrustedClockAuthorityV1;
use ulid::Ulid;

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
const OTHER_OPERATION: [u8; 16] = [0x11; 16];
const GENERATION: [u8; 16] = [0x20; 16];
const ANCHOR_GENERATION: [u8; 16] = [0x21; 16];
const NOW: u64 = 500;
const ISSUED: u64 = 100;
const EXPIRES: u64 = 30_000_100;
const HORIZON: u64 = 1_000;
const SCHEMA: Hash = Hash::from_bytes([0x22; 32]);
const NATIVE_PROFILE: Hash = Hash::from_bytes([0x61; 32]);
const OWNER_CATALOGUE: Hash = Hash::from_bytes([0x62; 32]);
const INSTALLATION: [u8; 16] = [0x63; 16];
const EXECUTION_PROFILE: Hash = Hash::from_bytes([1; 32]);
const SOURCE_CATALOGUE: Hash = Hash::from_bytes([2; 32]);
const AUTHORITY_CATALOGUE: Hash = Hash::from_bytes([9; 32]);
const ENTRIES: [&str; 2] = ["Entry-A_1", "Entry-B_1"];
const TUPLES: [Hash; 2] = [Hash::from_bytes([6; 32]), Hash::from_bytes([7; 32])];
const ADDRESSES: [Hash; 2] = [Hash::from_bytes([0x71; 32]), Hash::from_bytes([0x72; 32])];

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

const fn target() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x0e; 16]))
}

const fn other_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x2f; 16]))
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

struct Fixture {
    implementation: ImplementationKeyV1,
    states: [Vec<u8>; 2],
}

impl Fixture {
    fn new() -> Fallible<Self> {
        Ok(Self {
            implementation: ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(3))?,
            states: [
                CommunityStateContentV1::new(SCHEMA, b"state-a")?
                    .to_canonical_cbor()
                    .to_vec(),
                CommunityStateContentV1::new(SCHEMA, b"state-b")?
                    .to_canonical_cbor()
                    .to_vec(),
            ],
        })
    }

    fn initializer(&self, slot: usize) -> ArtifactRefV1 {
        ArtifactRefV1 {
            schema_id: 0x4353_0001,
            byte_length: self.states[slot].len() as u64,
            digest: *adr_h("CSC1", &self.states[slot]).as_bytes(),
        }
    }

    fn rows(&self) -> Fallible<Vec<CommunityProfileMemberV1<'_>>> {
        (0..2)
            .map(|slot| {
                Ok(CommunityProfileMemberV1::new(
                    ENTRIES[slot],
                    &self.implementation,
                    hash(4),
                    SCHEMA,
                    TUPLES[slot],
                    self.initializer(slot),
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
            execution_profile_digest: EXECUTION_PROFILE,
            roster,
            source_catalogue_digest: SOURCE_CATALOGUE,
            authority_catalogue_digest: AUTHORITY_CATALOGUE,
            retention: CommunityProfileRetentionV1 {
                generation_not_after_micros: HORIZON,
                recovery_window_micros: 1,
                quarantine_not_after_micros: HORIZON,
                metadata_not_after_micros: HORIZON,
            },
        },
    )?)
}

const fn installation<'a>(
    profile: &'a CommunityDurableProfileV1<'a>,
) -> CommunityInitializationInstallationV1<'a> {
    CommunityInitializationInstallationV1 {
        store_incarnation: INCARNATION,
        profile,
        native_profile_digest: NATIVE_PROFILE,
        installed_owner_catalogue_digest: OWNER_CATALOGUE,
        installation_id: INSTALLATION,
    }
}

fn form(profile: &CommunityDurableProfileV1<'_>) -> CommunityInitializeFormV1 {
    CommunityInitializeFormV1 {
        timeline: target(),
        operation_id: OPERATION,
        initial_source: Source::Initializer(community_initializer_set_ref_v1(profile)),
    }
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

/// A domain whose store holds one administrative grant, and the authority
/// installed over it.
struct World {
    domain: MemoryCommunityDomainV1,
    authority: CommunityLifecycleAuthorityV1,
    catalogue: Hash,
    leaf: Hash,
}

impl World {
    fn new() -> Fallible<Self> {
        let leaf = grant(&[target(), other_timeline()])?;
        let attestation = AuthorityRegistrySnapshotV1::try_new(
            &SEAL,
            REGISTRY,
            vec![hash(41)],
            vec![leaf.binding_digest()?],
            vec![],
        )?;
        let host = AuthorityPersistenceHostV1::new(&attestation);
        let mut store = MemoryStore::new();
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
                trust_scope: "community.trust".to_owned(),
            },
        )?;
        let digest = catalogue.digest();
        Ok(Self {
            domain: MemoryCommunityDomainV1::new(
                store,
                INCARNATION,
                MemoryTrustedClockAuthorityV1::new(),
            )?,
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
        Ok(self
            .authority
            .authorize_administrative(&call, &self.domain, self.leaf)?)
    }
}

fn initialize_request(timeline: TimelineId, operation_id: [u8; 16]) -> Fallible<Request> {
    Ok(Request::derive(&Operation::Initialize {
        timeline,
        operation_id,
        initial_source: Source::Initializer(ArtifactRefV1 {
            schema_id: 0x4341_0004,
            byte_length: 1,
            digest: [1; 32],
        }),
        expected_prior_generation: None,
        expected_prior_head_digest: None,
    })?)
}

// ------------------------------------------------------------- oracles

/// The canonical variant-3 typed ref of slot `slot`'s CMB1 (R6.1(6)).
fn member_ref(slot: u8, address: Hash, digest: Hash) -> Fallible<Vec<u8>> {
    let locator = encode(&Value::Array(vec![
        Value::Bytes(target().inner().to_bytes().to_vec()),
        Value::Bytes(GENERATION.to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(OPERATION.to_vec()),
        Value::Integer(11.into()),
        Value::Integer(slot.into()),
    ]))?;
    encode(&Value::Array(vec![
        Value::Integer(3.into()),
        Value::Bytes(b"CMB1".to_vec()),
        Value::Bytes(locator),
        Value::Bytes(address.as_bytes().to_vec()),
        Value::Bytes(digest.as_bytes().to_vec()),
    ]))
}

fn expected_owner_binding() -> Fallible<CommunityOwnerBindingV1> {
    let fixture = Fixture::new()?;
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    Ok(CommunityOwnerBindingV1::new(
        CommunityOwnerBindingInputV1 {
            store_incarnation: INCARNATION,
            timeline: target(),
            generation: GENERATION,
            native_profile_digest: NATIVE_PROFILE,
            installed_owner_catalogue_digest: OWNER_CATALOGUE,
            authority_catalogue_digest: AUTHORITY_CATALOGUE,
            durable_profile_digest: profile.digest(),
            installation_id: INSTALLATION,
            evidence_not_after_micros: HORIZON,
        },
    )?)
}

// ------------------------------------------------------------------ tests

/// I31: the caller's initializer-set ref must equal the R6.1(7)
/// derivation, and only the code-0 shape is accepted, before any
/// authority call.
#[test]
fn the_planner_accepts_only_the_p6_initializer_set() -> TestResult {
    let fixture = Fixture::new()?;
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    let good = form(&profile);
    let planner = CommunityInitializationPlannerV1::new(&SEAL, installation(&profile), good)?;
    assert_eq!(planner.request(), initialize_request(target(), OPERATION)?);
    assert_eq!(planner.request().action(), Action::Initialize);
    let Source::Initializer(reference) = good.initial_source else {
        return Err("initializer source expected".into());
    };
    let refused = [
        CommunityInitializeFormV1 {
            initial_source: Source::Initializer(ArtifactRefV1 {
                byte_length: reference.byte_length + 1,
                ..reference
            }),
            ..good
        },
        CommunityInitializeFormV1 {
            initial_source: Source::PriorState(hash(70)),
            ..good
        },
        CommunityInitializeFormV1 {
            timeline: TimelineId::from_ulid(Ulid::from_bytes([0; 16])),
            ..good
        },
        CommunityInitializeFormV1 {
            operation_id: [0; 16],
            ..good
        },
    ];
    for refused in refused {
        assert_eq!(
            CommunityInitializationPlannerV1::new(&SEAL, installation(&profile), refused).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

fn metadata_policy() -> Fallible<CommunityMetadataPolicyV1> {
    Ok(CommunityMetadataPolicyV1::new(
        CommunityMetadataPolicyInputV1 {
            metadata_owner_registry_binding: hash(81),
            metadata_authority_leaf_grant: hash(82),
            compiled_schema_catalogue_digest: hash(83),
            metadata_not_after_micros: HORIZON,
        },
    )?)
}

fn selection<'a>(
    incarnation: [u8; 16],
    floors: &'a [CommunityTimelineFloorV1<'a>],
) -> Fallible<CommunitySelectionV1<'a>> {
    Ok(CommunitySelectionV1::new(CommunitySelectionInputV1 {
        store_incarnation: incarnation,
        installed_catalogue_digest: hash(84),
        native_profile_digest: NATIVE_PROFILE,
        highest_native_producer_ordinal: 0,
        timeline_floors: CommunityTimelineFloorsV1::from_floors(floors),
        metadata_not_after_micros: HORIZON,
    })?)
}

const fn floor(timeline: TimelineId) -> CommunityTimelineFloorV1<'static> {
    CommunityTimelineFloorV1 {
        timeline,
        highest_pass_ordinal: 0,
        active_generation: Some(ANCHOR_GENERATION),
        closed_generations: CommunityGenerationIdsV1::from_ids(&[]),
        selected_head: Some(hash(85)),
        closed: false,
    }
}

/// I24 (planner part): code 0 is admissible only on `anchor_T`, whose G is
/// `anchor_G` until a committed CGI1 has consumed it.
#[test]
fn the_anchor_generation_is_derived_only_on_the_anchor_timeline() -> TestResult {
    let fixture = Fixture::new()?;
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    let planner =
        CommunityInitializationPlannerV1::new(&SEAL, installation(&profile), form(&profile))?;
    let policy = metadata_policy()?;
    let anchor = CommunityMetadataAnchorV1::new(INCARNATION, target(), ANCHOR_GENERATION, &policy)?;

    let empty = selection(INCARNATION, &[])?;
    assert_eq!(
        planner.generation(&anchor, &empty)?,
        Some(ANCHOR_GENERATION)
    );
    // Another Timeline's row leaves `anchor_G` unconsumed. The rows are in
    // Timeline order: the anchor row is first, then the other one.
    let others = [floor(other_timeline())];
    let other = selection(INCARNATION, &others)?;
    assert_eq!(
        planner.generation(&anchor, &other)?,
        Some(ANCHOR_GENERATION)
    );
    let consumed_rows = [floor(target()), floor(other_timeline())];
    let consumed = selection(INCARNATION, &consumed_rows)?;
    assert_eq!(planner.generation(&anchor, &consumed)?, None);
    let only_anchor = [floor(target())];
    let anchored = selection(INCARNATION, &only_anchor)?;
    assert_eq!(planner.generation(&anchor, &anchored)?, None);

    let elsewhere =
        CommunityMetadataAnchorV1::new(INCARNATION, other_timeline(), ANCHOR_GENERATION, &policy)?;
    let foreign_anchor =
        CommunityMetadataAnchorV1::new([1; 16], target(), ANCHOR_GENERATION, &policy)?;
    let foreign_selection = selection([1; 16], &[])?;
    for (anchor, selection) in [
        (&elsewhere, &empty),
        (&foreign_anchor, &empty),
        (&anchor, &foreign_selection),
    ] {
        assert_eq!(
            planner.generation(anchor, selection).err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

/// G2: COB1 binds the installed inputs, and each CMB1 is its roster row
/// plus that COB1.
#[test]
fn bindings_derive_cob1_and_each_cmb1_from_the_roster() -> TestResult {
    let fixture = Fixture::new()?;
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    let planner =
        CommunityInitializationPlannerV1::new(&SEAL, installation(&profile), form(&profile))?;
    let bindings = planner.bindings(GENERATION)?;
    let owner = expected_owner_binding()?;
    assert_eq!(
        bindings.owner_binding(),
        owner.to_canonical_cbor().as_slice()
    );
    assert_eq!(bindings.owner_binding_digest(), owner.digest());
    let members: Vec<&[u8]> = bindings.member_bindings().collect();
    let digests: Vec<Hash> = bindings.member_binding_digests().collect();
    assert_eq!(members.len(), 2);
    for slot in 0..2 {
        let expected = CommunityMemberBindingV1::new(CommunityMemberBindingInputV1 {
            stable_entry: ENTRIES[slot],
            implementation: &fixture.implementation,
            pmf1_digest: hash(4),
            state_schema_digest: SCHEMA,
            negotiated_tuple_digest: TUPLES[slot],
            initial_state_content_digest: adr_h("CSC1", &fixture.states[slot]),
            protected_owner_binding_digest: owner.digest(),
        })?;
        assert_eq!(members[slot], expected.to_canonical_cbor().as_slice());
        assert_eq!(digests[slot], expected.digest());
    }
    assert_eq!(planner.bindings([0; 16]).err(), Some(Error::InvalidBinding));
    let zero_installation = CommunityInitializationInstallationV1 {
        installation_id: [0; 16],
        ..installation(&profile)
    };
    let zero = CommunityInitializationPlannerV1::new(&SEAL, zero_installation, form(&profile))?;
    assert_eq!(zero.bindings(GENERATION).err(), Some(Error::InvalidBinding));
    Ok(())
}

/// G3, G4 and A5.3(0): the CGI1 takes the decision's refs and the CDP1
/// horizon; CSB1 has one empty-scope row per CMB1 ref; CBQ1 is the
/// initialization quote; CPV1 names the same refs.
#[test]
fn records_mint_cgi1_csb1_cbq1_and_cpv1() -> TestResult {
    let fixture = Fixture::new()?;
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    let planner =
        CommunityInitializationPlannerV1::new(&SEAL, installation(&profile), form(&profile))?;
    let mut world = World::new()?;
    let admission = world.admit(planner.request())?;
    let records = planner.records(GENERATION, &admission, &ADDRESSES)?;
    let digests: Vec<Hash> = planner
        .bindings(GENERATION)?
        .member_binding_digests()
        .collect();

    let request = CommunityInitializationRequestV1::from_canonical_cbor(records.request())?;
    assert_eq!(records.request_digest(), request.digest());
    let fields = request.as_input();
    assert_eq!(fields.operation_id, OPERATION);
    assert_eq!(fields.timeline, target());
    assert_eq!(fields.generation, GENERATION);
    assert_eq!(fields.expected_prior_generation, None);
    assert_eq!(fields.expected_prior_head_digest, None);
    assert_eq!(fields.profile_digest, profile.digest());
    assert_eq!(
        fields.member_binding_digests.iter().collect::<Vec<_>>(),
        digests
    );
    assert!(fields.initial_source == form(&profile).initial_source);
    assert_eq!(fields.principal_ref, admission.principal_ref());
    assert_eq!(fields.authorization_ref, admission.authorization_ref());
    assert_eq!(fields.evidence_not_after_micros, HORIZON);

    let empty_scope = adr_h("ScopeSet", &[0x80]);
    let refs = [
        member_ref(0, ADDRESSES[0], digests[0])?,
        member_ref(1, ADDRESSES[1], digests[1])?,
    ];
    let mut coverage: Vec<(Hash, Hash)> = refs
        .iter()
        .map(|reference| (adr_h("TypedInputRef", reference), empty_scope))
        .collect();
    coverage.sort_unstable();
    let scope = CommunityScopeBindingV1::from_canonical_cbor(records.scope_binding())?;
    assert_eq!(records.scope_binding_digest(), scope.digest());
    let scope_fields = scope.as_input();
    assert_eq!(scope_fields.store_incarnation, INCARNATION);
    assert_eq!(scope_fields.timeline, target());
    assert_eq!(scope_fields.generation, GENERATION);
    assert!(scope_fields.operation == ArtifactOperation::Initialization(OPERATION));
    assert_eq!(scope_fields.input_identity, request.digest());
    assert_eq!(
        scope_fields
            .coverage_rows
            .iter()
            .map(|row| row.map(|row| (row.typed_input_ref_digest, row.scope_set_digest)))
            .collect::<Result<Vec<_>, Error>>()?,
        coverage
    );
    assert!(scope_fields.scope_members.is_empty());
    assert_eq!(scope_fields.policy_revision, SOURCE_CATALOGUE);
    assert_eq!(scope_fields.evidence_not_after_micros, HORIZON);

    let mut due = vec![
        CommunityDueMemberBudgetV1 {
            member_binding_digest: digests[0],
            negotiated_tuple_digest: TUPLES[0],
        },
        CommunityDueMemberBudgetV1 {
            member_binding_digest: digests[1],
            negotiated_tuple_digest: TUPLES[1],
        },
    ];
    due.sort_by_key(|row| row.member_binding_digest);
    let quote =
        CommunityBudgetQuoteV1::initialization(target(), GENERATION, profile.digest(), due)?;
    assert_eq!(records.budget_quote(), quote.to_canonical_cbor().as_slice());
    assert_eq!(records.budget_quote_digest(), quote.digest());

    let provenance = CommunityOriginalProvenanceV1::from_canonical_cbor(records.provenance())?;
    assert_eq!(records.provenance_digest(), provenance.digest());
    let provenance_fields = provenance.as_input();
    assert_eq!(provenance_fields.store_incarnation, INCARNATION);
    assert!(provenance_fields.operation == ArtifactOperation::Initialization(OPERATION));
    assert_eq!(provenance_fields.input_identity, request.digest());
    assert_eq!(provenance_fields.scope_binding_digest, scope.digest());
    assert_eq!(provenance_fields.rule_bundle_digest, EXECUTION_PROFILE);
    assert_eq!(provenance_fields.budget_identity, quote.digest());
    assert_eq!(provenance_fields.evidence_not_after_micros, HORIZON);
    let sources: Vec<Hash> = provenance_fields
        .source_root_refs
        .iter()
        .map(|reference| reference.map(CommunityTypedInputRefV1::digest))
        .collect::<Result<_, Error>>()?;
    assert_eq!(
        sources,
        refs.iter()
            .map(|reference| adr_h("TypedInputRef", reference))
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// The CGI1 refs come only from this exact request's decision, and every
/// roster slot needs one nonzero CMB1 envelope address.
#[test]
fn records_refuse_another_decision_and_bad_addresses() -> TestResult {
    let fixture = Fixture::new()?;
    let rows = fixture.rows()?;
    let profile = profile(&rows)?;
    let planner =
        CommunityInitializationPlannerV1::new(&SEAL, installation(&profile), form(&profile))?;
    let mut world = World::new()?;
    let transition = Request::derive(&Operation::Initialize {
        timeline: target(),
        operation_id: OPERATION,
        initial_source: Source::PriorState(hash(70)),
        expected_prior_generation: Some([0x9a; 16]),
        expected_prior_head_digest: Some(hash(72)),
    })?;
    for request in [
        initialize_request(other_timeline(), OPERATION)?,
        initialize_request(target(), OTHER_OPERATION)?,
        transition,
    ] {
        let admission = world.admit(request)?;
        assert_eq!(
            planner.records(GENERATION, &admission, &ADDRESSES).err(),
            Some(Error::InvalidBinding)
        );
    }
    let admission = world.admit(planner.request())?;
    for addresses in [&ADDRESSES[..1], &[ADDRESSES[0], Hash::zero()][..]] {
        assert_eq!(
            planner.records(GENERATION, &admission, addresses).err(),
            Some(Error::InvalidBinding)
        );
    }
    assert_eq!(
        planner.records([0; 16], &admission, &ADDRESSES).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}
