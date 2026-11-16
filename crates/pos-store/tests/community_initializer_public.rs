//! Installed catalogue initializer owner and its `read` mapping (ADR-129
//! revision 6, R6.1 and R6.4) through their public seam: the R6.4 V4/V5
//! vectors, installation refusals (I19), the exact 86-byte resource (I18)
//! and the closure of the initializer mapping against the administrative
//! one (I33).
//!
//! Every expected byte string, digest and request field is written out
//! independently from the ADR text with `ciborium` and `blake3`. Grants are
//! issued into a real `MemoryStore` through the trusted persistence host, as
//! a composition root does.

use std::error::Error as StdError;

use ciborium::Value;
use pos_core::community_lifecycle::{
    community_capability_attestation_digest_v1, community_initializer_set_ref_v1, ArtifactRefV1,
    CommunityActorRowV1, CommunityAuthorityCatalogueInputV1, CommunityAuthorityCatalogueV1,
    CommunityDurableBackendV1, CommunityDurableProfileInputV1, CommunityDurableProfileV1,
    CommunityInitializationSourceV1 as Source, CommunityLifecycleErrorV1 as Error,
    CommunityProfileMemberV1, CommunityProfileRetentionV1, CommunityStateContentV1,
    COMMUNITY_INITIALIZER_SET_SCHEMA_V1,
};
use pos_core::fork_authentication::{
    principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
    ForkAuthenticationPolicyV1,
};
use pos_core::trusted_clock::ScriptedTrustedWallSourceV1;
use pos_core::{
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityTrustRootSealV1, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1, EntityId, Hash,
    ImplementationKeyV1, PrincipalRefV1, Seq, TimelineId,
};
use pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1;
use pos_store::community::{
    CommunityAdministrativeOperationV1 as Operation, CommunityAdministrativeRequestV1 as Request,
    CommunityAuthorityAdmissionV1, CommunityInitializerOwnerV1, CommunityLifecycleAuthorityInputV1,
    CommunityLifecycleAuthorityV1, MemoryCommunityDomainV1,
};
use pos_store::memory::MemoryStore;
use ulid::Ulid;
use zeroize::Zeroizing;

type Fallible<T> = Result<T, Box<dyn StdError>>;
/// A row's initializer ref, its State schema and the States installed for it.
type Case = (ArtifactRefV1, Hash, Vec<Zeroizing<Vec<u8>>>);
type TestResult = Fallible<()>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();

const REGISTRY: Hash = Hash::from_bytes([31; 32]);
const POLICY_REVISION: Hash = Hash::from_bytes([32; 32]);
const CONSENT_REVISION: Hash = Hash::from_bytes([33; 32]);
const FAP_BINDING: Hash = Hash::from_bytes([60; 32]);
const AUDIENCE: &str = "community-host";
const RECIPIENT: &str = "community-recipient";
const ADAPTER: &str = "community-adapter";
const SEED: [u8; 32] = [7; 32];
const INCARNATION: [u8; 16] = [0x5a; 16];
const OPERATION: [u8; 16] = [0x10; 16];
const CONTROL: [u8; 16] = [0xc0; 16];
const NOW: u64 = 500;
/// The R6.4 V4 State schema, `22`×32.
const V4_SCHEMA: Hash = Hash::from_bytes([0x22; 32]);
const V4_DIGEST: &str = "30580207e39eea249823d3071fb7a1ea1215e41d8a2a35b2e0d35ff77d20f3c1";
const V4_REF: &str =
    "831a43530001182a582030580207e39eea249823d3071fb7a1ea1215e41d8a2a35b2e0d35ff77d20f3c1";
const V5_DIGEST: &str = "edced38860cae62f1007c7ca288d688ca069447568f96879b31ce17bda5d454a";

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

fn unhex(value: &str) -> Fallible<Vec<u8>> {
    (0..value.len())
        .step_by(2)
        .map(|at| Ok(u8::from_str_radix(&value[at..at + 2], 16)?))
        .collect()
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

fn adr_h(m: &str, preimage: &[u8]) -> Hash {
    let mut input = b"PiglorOS.Community.".to_vec();
    input.extend_from_slice(m.as_bytes());
    input.extend_from_slice(b".v1\0");
    input.extend_from_slice(preimage);
    Hash::from_bytes(*blake3::hash(&input).as_bytes())
}

/// A canonical CSC1 `[magic, 1, schema, state]`, built with `ciborium`.
fn csc1(schema: Hash, state: &[u8]) -> Fallible<Vec<u8>> {
    encode(&Value::Array(vec![
        Value::Bytes(b"CSC1".to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(schema.as_bytes().to_vec()),
        Value::Bytes(state.to_vec()),
    ]))
}

/// P8: `[0x4353_0001, len(CSC1), H(CSC1)]`.
fn p8_ref(csc1: &[u8]) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: 0x4353_0001,
        byte_length: csc1.len() as u64,
        digest: *adr_h("CSC1", csc1).as_bytes(),
    }
}

fn ref_value(reference: ArtifactRefV1) -> Value {
    Value::Array(vec![
        Value::Integer(reference.schema_id.into()),
        Value::Integer(reference.byte_length.into()),
        Value::Bytes(reference.digest.to_vec()),
    ])
}

fn initializer_resource(digest: &[u8]) -> String {
    format!("community-initializer:{}", hex(digest))
}

fn implementation() -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        "plugin-a".into(),
        "host-v1".into(),
        hash(3),
    )?)
}

/// One roster row with `initializer` and State schema `schema`.
fn row<'a>(
    entry: &'a str,
    implementation: &'a ImplementationKeyV1,
    schema: Hash,
    initializer: ArtifactRefV1,
) -> Fallible<CommunityProfileMemberV1<'a>> {
    Ok(CommunityProfileMemberV1::new(
        entry,
        implementation,
        hash(4),
        schema,
        hash(6),
        initializer,
    )?)
}

fn profile<'a>(
    roster: &'a [CommunityProfileMemberV1<'a>],
    catalogue: Hash,
) -> Fallible<CommunityDurableProfileV1<'a>> {
    Ok(CommunityDurableProfileV1::new(
        CommunityDurableProfileInputV1 {
            backend: CommunityDurableBackendV1::RetainedMemory,
            execution_profile_digest: hash(1),
            roster,
            source_catalogue_digest: hash(2),
            authority_catalogue_digest: catalogue,
            retention: CommunityProfileRetentionV1 {
                generation_not_after_micros: 1_000,
                recovery_window_micros: 1,
                quarantine_not_after_micros: 1_000,
                metadata_not_after_micros: 1_000,
            },
        },
    )?)
}

fn states(bytes: &[&[u8]]) -> Vec<Zeroizing<Vec<u8>>> {
    bytes
        .iter()
        .map(|state| Zeroizing::new(state.to_vec()))
        .collect()
}

/// R6.4 V4 and V5, bit-exact: the empty-State CSC1, its digest, resource
/// and ref, and the one-member initializer-set ref.
#[test]
fn v4_and_v5_reproduce_bit_exactly() -> TestResult {
    let v4 = unhex(&format!("844443534331015820{}40", "22".repeat(32)))?;
    assert_eq!(v4.len(), 42);
    assert_eq!(csc1(V4_SCHEMA, &[])?, v4);
    assert_eq!(
        CommunityStateContentV1::new(V4_SCHEMA, &[])?
            .to_canonical_cbor()
            .as_slice(),
        v4.as_slice()
    );
    let reference = p8_ref(&v4);
    assert_eq!(hex(&reference.digest), V4_DIGEST);
    assert_eq!(encode(&ref_value(reference))?, unhex(V4_REF)?);
    let resource = initializer_resource(&reference.digest);
    assert_eq!(resource.len(), 86);
    assert_eq!(resource, format!("community-initializer:{V4_DIGEST}"));

    let implementation = implementation()?;
    let roster = [row("Entry-A_1", &implementation, V4_SCHEMA, reference)?];
    let set = community_initializer_set_ref_v1(&profile(&roster, hash(9))?);
    let mut list = vec![0x81];
    list.extend_from_slice(&unhex(V4_REF)?);
    assert_eq!(list.len(), 43);
    assert_eq!(adr_h("InitializerSet", &list), Hash::from_bytes(set.digest));
    assert_eq!(
        set,
        ArtifactRefV1 {
            schema_id: COMMUNITY_INITIALIZER_SET_SCHEMA_V1,
            byte_length: 43,
            digest: *Hash::from_bytes(set.digest).as_bytes(),
        }
    );
    assert_eq!(COMMUNITY_INITIALIZER_SET_SCHEMA_V1, 0x4341_0004);
    assert_eq!(hex(&set.digest), V5_DIGEST);
    // Installation accepts the V4 State for its row.
    CommunityInitializerOwnerV1::new(&SEAL, &profile(&roster, hash(9))?, states(&[&v4]))?;
    Ok(())
}

/// P6: the set lists every row's ref in roster order, so rows sharing one
/// State list it twice and reordering the roster changes the ref.
#[test]
fn the_initializer_set_lists_every_row_in_roster_order() -> TestResult {
    let implementation = implementation()?;
    let first = csc1(V4_SCHEMA, b"first")?;
    let second = csc1(V4_SCHEMA, b"second")?;
    let roster = [
        row("Entry-A_1", &implementation, V4_SCHEMA, p8_ref(&first))?,
        row("Entry-B_1", &implementation, V4_SCHEMA, p8_ref(&second))?,
        row("Entry-C_1", &implementation, V4_SCHEMA, p8_ref(&first))?,
    ];
    let list = encode(&Value::Array(
        [&first, &second, &first]
            .into_iter()
            .map(|state| ref_value(p8_ref(state)))
            .collect(),
    ))?;
    let set = community_initializer_set_ref_v1(&profile(&roster, hash(9))?);
    assert_eq!(set.byte_length, list.len() as u64);
    assert_eq!(Hash::from_bytes(set.digest), adr_h("InitializerSet", &list));
    // Three rows, two distinct States, both installed.
    CommunityInitializerOwnerV1::new(
        &SEAL,
        &profile(&roster, hash(9))?,
        states(&[&first, &second, &first]),
    )?;
    Ok(())
}

/// I19: installation refuses States that violate P8, carry another schema,
/// are not canonical CSC1, or do not match the roster one to one.
#[test]
fn installation_refuses_states_that_do_not_match_their_rows() -> TestResult {
    let implementation = implementation()?;
    let state = csc1(V4_SCHEMA, b"state")?;
    let other = csc1(V4_SCHEMA, b"other")?;
    let foreign_schema = csc1(hash(0x33), b"state")?;
    let exact = p8_ref(&state);
    let mut noncanonical = state.clone();
    noncanonical.push(0);
    let cases: Vec<Case> = vec![
        // Other bytes under this row's ref.
        (exact, V4_SCHEMA, states(&[&other])),
        // A ref with another length, schema ID or digest.
        (
            ArtifactRefV1 {
                byte_length: exact.byte_length - 1,
                ..exact
            },
            V4_SCHEMA,
            states(&[&state]),
        ),
        (
            ArtifactRefV1 {
                schema_id: 0x4353_0002,
                ..exact
            },
            V4_SCHEMA,
            states(&[&state]),
        ),
        (
            ArtifactRefV1 {
                digest: *blake3::hash(&state).as_bytes(),
                ..exact
            },
            V4_SCHEMA,
            states(&[&state]),
        ),
        // The exact ref of a State whose schema is not the row's.
        (
            p8_ref(&foreign_schema),
            V4_SCHEMA,
            states(&[&foreign_schema]),
        ),
        // Bytes that are not a canonical CSC1, under their own P8 ref.
        (p8_ref(&noncanonical), V4_SCHEMA, states(&[&noncanonical])),
        // Too few and too many States.
        (exact, V4_SCHEMA, states(&[])),
        (exact, V4_SCHEMA, states(&[&state, &state])),
    ];
    for (reference, schema, installed) in cases {
        let roster = [row("Entry-A_1", &implementation, schema, reference)?];
        assert_eq!(
            CommunityInitializerOwnerV1::new(&SEAL, &profile(&roster, hash(9))?, installed).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

// ------------------------------------------------- the initializer mapping

#[derive(Clone)]
struct Scope {
    resources: Vec<String>,
    actions: Vec<String>,
    audience: String,
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort_unstable();
    values
}

fn grant(id: u8, scope: &Scope) -> Fallible<CapabilityGrantV1> {
    let seq = u64::from(id);
    let capability = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: sorted(scope.resources.clone()),
        actions: sorted(scope.actions.clone()),
        purposes: vec!["lifecycle-administration".to_owned()],
        audiences: vec![scope.audience.clone()],
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
        grant_id: hash(id),
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

fn snapshot(grants: &[CapabilityGrantV1]) -> Fallible<AuthorityRegistrySnapshotV1> {
    let mut bindings = grants
        .iter()
        .map(CapabilityGrantV1::binding_digest)
        .collect::<Result<Vec<_>, _>>()?;
    bindings.sort_unstable();
    Ok(AuthorityRegistrySnapshotV1::try_new(
        &SEAL,
        REGISTRY,
        vec![hash(41)],
        bindings,
        vec![],
    )?)
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

/// A domain holding `grants`, its installed lifecycle authority and H(CAP1).
struct World {
    domain: MemoryCommunityDomainV1,
    authority: CommunityLifecycleAuthorityV1,
    catalogue: Hash,
}

impl World {
    fn new(grants: &[CapabilityGrantV1]) -> Fallible<Self> {
        let attestation = snapshot(grants)?;
        let host = AuthorityPersistenceHostV1::new(&attestation);
        let mut store = MemoryStore::new();
        store.bind_authority_persistence(host.persistence_binding())?;
        for grant in grants {
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
                trust_scope: "community.trust".to_owned(),
            },
        )?;
        let digest = catalogue.digest();
        Ok(Self {
            domain: MemoryCommunityDomainV1::new(store, INCARNATION)?,
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
            )?,
            catalogue: digest,
        })
    }

    fn admit(
        &mut self,
        operation: &Operation,
        owner: &CommunityInitializerOwnerV1,
        initializer: Hash,
        leaf: Hash,
    ) -> Fallible<Result<CommunityAuthorityAdmissionV1, Error>> {
        let request = Request::derive(operation)?;
        let nonce = adr_h(
            "AuthenticationNonce",
            &encode(&Value::Array(vec![
                Value::Bytes(self.catalogue.as_bytes().to_vec()),
                Value::Text(request.resource()),
                Value::Text(request.action().as_str().to_owned()),
                Value::Text(request.operation_constraint()),
            ]))?,
        );
        let credential = signing_key()?
            .sign_authenticated_principal(AuthenticatedPrincipalRecordV1 {
                principal: caller()?,
                adapter_id: ADAPTER.to_owned(),
                assurance: 2,
                issued_at: 100,
                expires_at: 30_000_100,
                registry_binding: FAP_BINDING,
                operation_nonce: *nonce.as_bytes(),
            })?
            .to_canonical_cbor()?;
        let call = self.authority.authenticate(&credential, request)?;
        Ok(self
            .authority
            .authorize_initializer(&call, owner, initializer, &self.domain, leaf))
    }
}

const fn initialize() -> Operation {
    Operation::Initialize {
        timeline: target(),
        operation_id: OPERATION,
        initial_source: Source::Initializer(ArtifactRefV1 {
            schema_id: 0x4353_0001,
            byte_length: 42,
            digest: [0x30; 32],
        }),
        expected_prior_generation: None,
        expected_prior_head_digest: None,
    }
}

const fn transition() -> Operation {
    Operation::Initialize {
        timeline: target(),
        operation_id: OPERATION,
        initial_source: Source::PriorState(hash(71)),
        expected_prior_generation: Some([0x9a; 16]),
        expected_prior_head_digest: Some(hash(72)),
    }
}

const fn refused_operations() -> [Operation; 3] {
    [
        Operation::ForkCurrent {
            initial_source: Source::Fork {
                timeline: target(),
                cut: Seq::from_u64(0),
                selected_head_digest: hash(73),
                operation_id: [0xf0; 16],
            },
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
        Operation::Retire {
            timeline: target(),
            control_operation_id: CONTROL,
        },
        Operation::QuarantineReset {
            timeline: target(),
            control_operation_id: CONTROL,
        },
    ]
}

fn initializer_scope(digest: &str) -> Scope {
    Scope {
        resources: vec![format!("community-initializer:{digest}")],
        actions: vec!["read".to_owned()],
        audience: RECIPIENT.to_owned(),
    }
}

/// I18 and I33: the host emits exactly the 86-byte lower-case
/// `community-initializer:<D64>` read request; a grant on another digest,
/// in upper case, or of the administrative mapping does not authorize it,
/// and an initializer grant authorizes no administrative request.
#[test]
fn initializer_requests_name_the_exact_lowercase_digest() -> TestResult {
    let state = csc1(V4_SCHEMA, b"state")?;
    let other = csc1(V4_SCHEMA, b"other")?;
    let digest = hex(&p8_ref(&state).digest);
    let exact = grant(1, &initializer_scope(&digest))?;
    let upper = grant(2, &initializer_scope(&digest.to_uppercase()))?;
    let foreign = grant(3, &initializer_scope(&hex(&p8_ref(&other).digest)))?;
    let administrative = grant(
        4,
        &Scope {
            resources: vec![format!(
                "community:{}:lifecycle",
                hex(&target().inner().to_bytes())
            )],
            actions: vec![
                "community.initialize.v1".to_owned(),
                "community.transition.v1".to_owned(),
                "read".to_owned(),
            ],
            audience: RECIPIENT.to_owned(),
        },
    )?;
    let wrong_audience = grant(
        5,
        &Scope {
            audience: AUDIENCE.to_owned(),
            ..initializer_scope(&digest)
        },
    )?;
    let mut world = World::new(&[
        exact.clone(),
        upper.clone(),
        foreign.clone(),
        administrative.clone(),
        wrong_audience.clone(),
    ])?;
    let implementation = implementation()?;
    let roster = [
        row("Entry-A_1", &implementation, V4_SCHEMA, p8_ref(&state))?,
        row("Entry-B_1", &implementation, V4_SCHEMA, p8_ref(&other))?,
    ];
    let owner = CommunityInitializerOwnerV1::new(
        &SEAL,
        &profile(&roster, world.catalogue)?,
        states(&[&state, &other]),
    )?;
    let initializer = Hash::from_bytes(p8_ref(&state).digest);

    for operation in [initialize(), transition()] {
        let admission = world.admit(&operation, &owner, initializer, exact.grant_id())??;
        let built = admission.request();
        assert_eq!(built.resource(), format!("community-initializer:{digest}"));
        assert_eq!(built.resource().len(), 86);
        assert_eq!(built.action(), "read");
        assert_eq!(built.data_category(), "community.initial-state");
        assert_eq!(built.purpose(), "lifecycle-administration");
        assert_eq!(built.audience(), RECIPIENT);
        assert_eq!(
            built.environment_constraints().to_vec(),
            vec![Request::derive(&operation)?.operation_constraint()]
        );
        assert!(built.subject_id().is_none());
        for leaf in [
            upper.grant_id(),
            foreign.grant_id(),
            administrative.grant_id(),
            wrong_audience.grant_id(),
        ] {
            assert_eq!(
                world.admit(&operation, &owner, initializer, leaf)?.err(),
                Some(Error::EvidenceUnavailable)
            );
        }
    }
    Ok(())
}

/// The mapping exists only for an installed State of an initialize or
/// transition call, under the owner installed for this H(CAP1).
#[test]
fn initializer_requests_need_an_installed_state_and_catalogue() -> TestResult {
    let state = csc1(V4_SCHEMA, b"state")?;
    let digest = hex(&p8_ref(&state).digest);
    let exact = grant(1, &initializer_scope(&digest))?;
    let mut world = World::new(std::slice::from_ref(&exact))?;
    let implementation = implementation()?;
    let roster = [row(
        "Entry-A_1",
        &implementation,
        V4_SCHEMA,
        p8_ref(&state),
    )?];
    let owner = CommunityInitializerOwnerV1::new(
        &SEAL,
        &profile(&roster, world.catalogue)?,
        states(&[&state]),
    )?;
    let foreign_owner =
        CommunityInitializerOwnerV1::new(&SEAL, &profile(&roster, hash(9))?, states(&[&state]))?;
    let initializer = Hash::from_bytes(p8_ref(&state).digest);
    assert!(world
        .admit(&initialize(), &owner, initializer, exact.grant_id())?
        .is_ok());
    for (operation, owner, initializer) in [
        (initialize(), &foreign_owner, initializer),
        (initialize(), &owner, hash(0x44)),
    ] {
        assert_eq!(
            world
                .admit(&operation, owner, initializer, exact.grant_id())?
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    for operation in refused_operations() {
        assert_eq!(
            world
                .admit(&operation, &owner, initializer, exact.grant_id())?
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}
