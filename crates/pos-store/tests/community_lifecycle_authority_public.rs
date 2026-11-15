//! Installed community administrative and in-operation execution authority
//! (ADR-129 A5.1, A5.8 and revision 6 R6.2) through its public seam.
//!
//! Every expected request, resource, nonce and digest is written out
//! independently from the ADR text with `ciborium` and `blake3`, not from the
//! implementation's helpers. Grants are issued into a real `MemoryStore`
//! through the trusted persistence host, as a composition root does.

use std::error::Error as StdError;

use ciborium::Value;
use pos_core::community_lifecycle::{
    community_capability_attestation_digest_v1, ArtifactRefV1, CommunityActorRowV1,
    CommunityAuthorityCatalogueInputV1, CommunityAuthorityCatalogueV1,
    CommunityInitializationSourceV1 as Source, CommunityLifecycleErrorV1 as Error,
    CommunityMemberBindingInputV1, CommunityMemberBindingV1,
};
use pos_core::fork_authentication::{
    principal_digest_v1, AuthenticatedPrincipalEvidenceV1, AuthenticatedPrincipalRecordV1,
    ForkAuthenticationAdapterPolicyV1, ForkAuthenticationPolicyV1,
};
use pos_core::trusted_clock::ScriptedTrustedWallSourceV1;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistencePortV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityTrustRootSealV1,
    AuthorizationRequestDraftV1, AuthorizationRequestV1, CapabilityGrantDraftV1, CapabilityGrantV1,
    CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    ConsentEvidenceV1, EntityId, Hash, ImplementationKeyV1, PrincipalRefV1, Seq, TimelineId,
    WallTime,
};
use pos_crypto::fork_authentication::ForkAuthenticationAdapterSigningKeyV1;
use pos_store::community::{
    CommunityAdministrativeActionV1 as Action, CommunityAdministrativeOperationV1 as Operation,
    CommunityAdministrativeRequestV1 as Request, CommunityAuthorityAdmissionV1,
    CommunityLifecycleAuthorityInputV1, CommunityLifecycleAuthorityV1, CommunityMemberActionV1,
    CommunityMemberUseV1,
};
use pos_store::memory::MemoryStore;
use ulid::Ulid;

type Fallible<T> = Result<T, Box<dyn StdError>>;
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
const OPERATION: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const FORK_OPERATION: [u8; 16] = [0xf0; 16];
const CONTROL: [u8; 16] = [0xc0; 16];
const NOW: u64 = 500;
const ISSUED: u64 = 100;
const EXPIRES: u64 = 30_000_100;
const ALL_ACTIONS: [&str; 5] = [
    "community.initialize.v1",
    "community.transition.v1",
    "community.fork.v1",
    "community.retire.v1",
    "community.quarantine.reset.v1",
];

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

/// T = `000102…0f`, the ADR-129 R6.4 V3 Timeline.
fn target() -> TimelineId {
    let mut bytes = [0; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::try_from(index).unwrap_or_default();
    }
    TimelineId::from_ulid(Ulid::from_bytes(bytes))
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

/// The R6.4 V1 principal: ID `11`×16, trust domain `community.local`.
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

fn lifecycle_resource(timeline: TimelineId) -> String {
    format!("community:{}:lifecycle", hex(&timeline.inner().to_bytes()))
}

fn constraint(kind: char, operation: [u8; 16]) -> String {
    format!("community.operation:{kind}:{}", hex(&operation))
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

const fn initializer() -> Source {
    Source::Initializer(ArtifactRefV1 {
        schema_id: 0x4353_0001,
        byte_length: 42,
        digest: [0x30; 32],
    })
}

fn initialize() -> Operation {
    Operation::Initialize {
        timeline: target(),
        operation_id: OPERATION,
        initial_source: initializer(),
        expected_prior_generation: None,
        expected_prior_head_digest: None,
    }
}

fn transition() -> Operation {
    Operation::Initialize {
        timeline: target(),
        operation_id: OPERATION,
        initial_source: Source::PriorState(hash(71)),
        expected_prior_generation: Some([0x9a; 16]),
        expected_prior_head_digest: Some(hash(72)),
    }
}

const fn fork_source(parent: TimelineId) -> Source {
    Source::Fork {
        timeline: parent,
        cut: Seq::from_u64(0),
        selected_head_digest: hash(73),
        operation_id: FORK_OPERATION,
    }
}

fn fork() -> Operation {
    Operation::ForkCurrent {
        initial_source: fork_source(target()),
        expected_prior_generation: None,
        expected_prior_head_digest: None,
    }
}

fn retire() -> Operation {
    Operation::Retire {
        timeline: target(),
        control_operation_id: CONTROL,
    }
}

fn reset() -> Operation {
    Operation::QuarantineReset {
        timeline: target(),
        control_operation_id: CONTROL,
    }
}

fn operations() -> [Operation; 5] {
    [initialize(), transition(), fork(), retire(), reset()]
}

/// The grant scope a test issues.
#[derive(Clone)]
struct Scope {
    resources: Vec<String>,
    actions: Vec<String>,
    audience: String,
    constraints: Vec<String>,
    consent_references: Vec<Hash>,
}

fn administrative(timeline: TimelineId, actions: &[&str]) -> Scope {
    Scope {
        resources: vec![lifecycle_resource(timeline)],
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        audience: AUDIENCE.to_owned(),
        constraints: vec![],
        consent_references: vec![],
    }
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort_unstable();
    values
}

fn grant(id: u8, seq: u64, epoch: u64, scope: &Scope) -> Fallible<CapabilityGrantV1> {
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
        environment_constraints: sorted(scope.constraints.clone()),
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
        consent_references: scope.consent_references.clone(),
        policy_revision: POLICY_REVISION,
        issuance_timeline: authority_timeline(),
        issuance_seq: Seq::from_u64(seq),
        revocation_epoch: epoch,
        revocation_fence: None,
        authority_registry_digest: REGISTRY,
    })?)
}

fn snapshot(grants: &[&CapabilityGrantV1]) -> Fallible<AuthorityRegistrySnapshotV1> {
    let mut bindings = grants
        .iter()
        .map(|grant| grant.binding_digest())
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

fn signing_key(seed: [u8; 32]) -> Fallible<ForkAuthenticationAdapterSigningKeyV1> {
    Ok(ForkAuthenticationAdapterSigningKeyV1::from_seed(seed)?)
}

fn fap1(seed: [u8; 32]) -> Fallible<ForkAuthenticationPolicyV1> {
    Ok(ForkAuthenticationPolicyV1::new(vec![
        ForkAuthenticationAdapterPolicyV1 {
            adapter_id: ADAPTER.to_owned(),
            verifying_key: signing_key(seed)?.public_key(),
            minimum_assurance: 2,
            registry_bindings: vec![FAP_BINDING],
        },
    ])?)
}

fn catalogue_input(
    attestation: &AuthorityRegistrySnapshotV1,
) -> Fallible<CommunityAuthorityCatalogueInputV1> {
    Ok(CommunityAuthorityCatalogueInputV1 {
        fap1_digest: fap1(SEED)?.digest()?,
        audience: AUDIENCE.to_owned(),
        actor_rows: vec![CommunityActorRowV1 {
            principal_digest: principal_digest_v1(&caller()?)?,
            actor_entity_id: actor(),
        }],
        capability_policy_revision: POLICY_REVISION,
        consent_policy_revision: CONSENT_REVISION,
        authority_registry_digest: REGISTRY,
        capability_attestation_digest: community_capability_attestation_digest_v1(attestation),
        trust_scope: "community.trust".to_owned(),
    })
}

fn install(
    catalogue: CommunityAuthorityCatalogueV1,
    attestation: AuthorityRegistrySnapshotV1,
    samples: &[u64],
) -> Fallible<CommunityLifecycleAuthorityV1> {
    Ok(CommunityLifecycleAuthorityV1::new(
        &SEAL,
        CommunityLifecycleAuthorityInputV1 {
            catalogue,
            authentication_policy: fap1(SEED)?,
            attestation,
            fork_admission_policies: vec![],
        },
        ScriptedTrustedWallSourceV1::from_micros(samples.iter().copied()),
    )?)
}

/// A store holding `issued` through a persistence host built from
/// `host_snapshot`, and the authority installed with `attestation`.
struct World {
    store: MemoryStore,
    host: AuthorityPersistenceHostV1,
    authority: CommunityLifecycleAuthorityV1,
    catalogue: Hash,
}

impl World {
    fn new(grants: &[CapabilityGrantV1]) -> Fallible<Self> {
        let all = grants.iter().collect::<Vec<_>>();
        let attestation = snapshot(&all)?;
        Self::with(grants, &attestation, attestation.clone())
    }

    fn with(
        grants: &[CapabilityGrantV1],
        host_snapshot: &AuthorityRegistrySnapshotV1,
        attestation: AuthorityRegistrySnapshotV1,
    ) -> Fallible<Self> {
        let host = AuthorityPersistenceHostV1::new(host_snapshot);
        let mut store = MemoryStore::new();
        store.bind_authority_persistence(host.persistence_binding())?;
        for grant in grants {
            let permit = host.authorize_grant(grant)?;
            store.issue_capability_grant(permit, grant)?;
        }
        let catalogue = CommunityAuthorityCatalogueV1::new(&SEAL, catalogue_input(&attestation)?)?;
        let digest = catalogue.digest();
        Ok(Self {
            store,
            host,
            authority: install(catalogue, attestation, &[NOW; 64])?,
            catalogue: digest,
        })
    }

    fn record(&self, operation: &Operation) -> Fallible<AuthenticatedPrincipalRecordV1> {
        let request = Request::derive(operation)?;
        Ok(AuthenticatedPrincipalRecordV1 {
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
        })
    }

    fn credential(&self, operation: &Operation) -> Fallible<Vec<u8>> {
        sign(self.record(operation)?, SEED)
    }

    fn admit(
        &mut self,
        operation: &Operation,
        leaf: Hash,
    ) -> Result<CommunityAuthorityAdmissionV1, Error> {
        let credential = self
            .credential(operation)
            .map_err(|_| Error::InvalidEncoding)?;
        let persisted = self
            .store
            .load_authority(leaf)
            .map_err(|_| Error::StorageUnavailable)?;
        Request::derive(operation)
            .and_then(|request| self.authority.authenticate(&credential, request))
            .and_then(|call| self.authority.authorize_administrative(&call, &persisted))
    }

    fn revoke(&mut self, grant: &CapabilityGrantV1, fence: u64, epoch: u64) -> TestResult {
        let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
            grant_id: grant.grant_id(),
            authority_timeline: authority_timeline(),
            fence_position: Seq::from_u64(fence),
            revocation_epoch: epoch,
            policy_revision: POLICY_REVISION,
            authority_registry_digest: REGISTRY,
        })?;
        let permit = self.host.authorize_revocation(grant, &revocation)?;
        self.store.revoke_capability_grant(permit, &revocation)?;
        Ok(())
    }
}

fn sign(record: AuthenticatedPrincipalRecordV1, seed: [u8; 32]) -> Fallible<Vec<u8>> {
    Ok(signing_key(seed)?
        .sign_authenticated_principal(record)?
        .to_canonical_cbor()?)
}

/// A5.1 action derivation and A5.5 step 1: every shape outside the table is
/// `InvalidBinding` before any authority call; the host emits the exact
/// lower-case 52-byte resource and 54-byte operation constraint (I1, I5).
#[test]
fn derivation_follows_the_closed_action_table() -> TestResult {
    let parent = other_timeline();
    for (operation, action, timeline, kind, identity) in [
        (initialize(), Action::Initialize, target(), 'i', OPERATION),
        (transition(), Action::Transition, target(), 'i', OPERATION),
        (
            Operation::Initialize {
                timeline: target(),
                operation_id: OPERATION,
                initial_source: initializer(),
                expected_prior_generation: Some([0x9a; 16]),
                expected_prior_head_digest: Some(hash(72)),
            },
            Action::Transition,
            target(),
            'i',
            OPERATION,
        ),
        (
            Operation::ForkCurrent {
                initial_source: fork_source(parent),
                expected_prior_generation: None,
                expected_prior_head_digest: None,
            },
            Action::Fork,
            parent,
            'f',
            FORK_OPERATION,
        ),
        (retire(), Action::Retire, target(), 'c', CONTROL),
        (reset(), Action::QuarantineReset, target(), 'c', CONTROL),
    ] {
        let request = Request::derive(&operation)?;
        assert_eq!(request.action(), action);
        assert_eq!(request.timeline(), timeline);
        assert_eq!(request.resource(), lifecycle_resource(timeline));
        assert_eq!(request.resource().len(), 52);
        assert_eq!(request.operation_constraint(), constraint(kind, identity));
        assert_eq!(request.operation_constraint().len(), 54);
    }
    assert_eq!(
        Request::derive(&initialize())?.resource(),
        "community:000102030405060708090a0b0c0d0e0f:lifecycle"
    );
    let actions = [
        Action::Initialize,
        Action::Transition,
        Action::Fork,
        Action::Retire,
        Action::QuarantineReset,
    ]
    .map(Action::as_str);
    assert_eq!(actions, ALL_ACTIONS);
    Ok(())
}

/// A5.1 and I5: every shape outside the table, and any zero Timeline or
/// operation identity, is `InvalidBinding` before any authority call.
#[test]
fn derivation_refuses_every_shape_outside_the_table() {
    let parent = other_timeline();
    let zero = TimelineId::from_ulid(Ulid::from_bytes([0; 16]));
    for invalid in [
        Operation::Initialize {
            timeline: target(),
            operation_id: OPERATION,
            initial_source: fork_source(parent),
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
        Operation::Initialize {
            timeline: target(),
            operation_id: OPERATION,
            initial_source: Source::PriorState(hash(71)),
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
        Operation::Initialize {
            timeline: target(),
            operation_id: OPERATION,
            initial_source: initializer(),
            expected_prior_generation: Some([0x9a; 16]),
            expected_prior_head_digest: None,
        },
        Operation::Initialize {
            timeline: target(),
            operation_id: OPERATION,
            initial_source: initializer(),
            expected_prior_generation: None,
            expected_prior_head_digest: Some(hash(72)),
        },
        Operation::Initialize {
            timeline: target(),
            operation_id: OPERATION,
            initial_source: fork_source(parent),
            expected_prior_generation: Some([0x9a; 16]),
            expected_prior_head_digest: Some(hash(72)),
        },
        Operation::ForkCurrent {
            initial_source: initializer(),
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
        Operation::ForkCurrent {
            initial_source: fork_source(parent),
            expected_prior_generation: Some([0x9a; 16]),
            expected_prior_head_digest: None,
        },
        Operation::ForkCurrent {
            initial_source: fork_source(parent),
            expected_prior_generation: None,
            expected_prior_head_digest: Some(hash(72)),
        },
        Operation::Initialize {
            timeline: zero,
            operation_id: OPERATION,
            initial_source: initializer(),
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
        Operation::Initialize {
            timeline: target(),
            operation_id: [0; 16],
            initial_source: initializer(),
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
        Operation::ForkCurrent {
            initial_source: fork_source(zero),
            expected_prior_generation: None,
            expected_prior_head_digest: None,
        },
        Operation::Retire {
            timeline: zero,
            control_operation_id: CONTROL,
        },
        Operation::QuarantineReset {
            timeline: target(),
            control_operation_id: [0; 16],
        },
    ] {
        assert_eq!(Request::derive(&invalid), Err(Error::InvalidBinding));
    }
}

/// R6.2(2) and I30: FAP1, registry and attestation pins and disjoint Fork
/// keys are composition checks; a defect refuses installation.
#[test]
fn installation_refuses_every_mismatched_pin() -> TestResult {
    let leaf = grant(1, 1, 0, &administrative(target(), &ALL_ACTIONS))?;
    let attestation = snapshot(&[&leaf])?;
    let other = snapshot(&[])?;
    let good = catalogue_input(&attestation)?;
    let attempt = |input: CommunityAuthorityCatalogueInputV1,
                   attestation: AuthorityRegistrySnapshotV1,
                   forks: Vec<ForkAuthenticationPolicyV1>|
     -> Fallible<Result<CommunityLifecycleAuthorityV1, Error>> {
        Ok(CommunityLifecycleAuthorityV1::new(
            &SEAL,
            CommunityLifecycleAuthorityInputV1 {
                catalogue: CommunityAuthorityCatalogueV1::new(&SEAL, input)?,
                authentication_policy: fap1(SEED)?,
                attestation,
                fork_admission_policies: forks,
            },
            ScriptedTrustedWallSourceV1::from_micros([NOW]),
        ))
    };
    let foreign_registry = AuthorityRegistrySnapshotV1::try_new(
        &SEAL,
        hash(34),
        vec![hash(41)],
        attestation.capability_bindings().to_vec(),
        vec![],
    )?;
    let refusals = [
        (
            CommunityAuthorityCatalogueInputV1 {
                fap1_digest: fap1([9; 32])?.digest()?,
                ..good.clone()
            },
            attestation.clone(),
            vec![],
        ),
        (
            CommunityAuthorityCatalogueInputV1 {
                capability_attestation_digest: community_capability_attestation_digest_v1(
                    &foreign_registry,
                ),
                ..good.clone()
            },
            foreign_registry,
            vec![],
        ),
        (good.clone(), other, vec![]),
        (good.clone(), attestation.clone(), vec![fap1(SEED)?]),
        (
            good.clone(),
            attestation.clone(),
            vec![fap1([9; 32])?, fap1(SEED)?],
        ),
    ];
    for (input, attestation, forks) in refusals {
        assert_eq!(
            attempt(input, attestation, forks)?.err(),
            Some(Error::InvalidBinding)
        );
    }
    assert!(attempt(good, attestation, vec![fap1([9; 32])?])?.is_ok());
    Ok(())
}

/// A5.1, A5.3(2), I8, I13, I22 and I25: the owner builds the exact request
/// from the verified FAE1, CAP1 and the loaded chain, and derives both refs
/// from the decision it evaluated.
#[test]
fn an_authorized_initialize_binds_the_exact_request_and_refs() -> TestResult {
    let leaf = grant(
        1,
        1,
        0,
        &administrative(target(), &["community.initialize.v1"]),
    )?;
    let mut world = World::new(std::slice::from_ref(&leaf))?;
    let credential = world.credential(&initialize())?;
    let request = Request::derive(&initialize())?;
    let call = world.authority.authenticate(&credential, request)?;
    assert_eq!(call.request(), &request);
    assert_eq!(call.at_time(), WallTime::from_micros(NOW));
    assert_eq!(call.expires_at(), WallTime::from_micros(EXPIRES));
    let persisted = world.store.load_authority(leaf.grant_id())?;
    let admission = world
        .authority
        .authorize_administrative(&call, &persisted)?;

    let mut evidence_input = b"pigloros/authenticated-principal-evidence/v1".to_vec();
    evidence_input.extend_from_slice(&credential);
    let authenticated = AuthenticatedPrincipalResultV1::try_from_draft(
        &SEAL,
        AuthenticatedPrincipalDraftV1 {
            principal: caller()?,
            adapter_id: ADAPTER.to_owned(),
            assurance: AssuranceLevelV1::try_new(2)?,
            issued_at: WallTime::from_micros(ISSUED),
            expires_at: WallTime::from_micros(EXPIRES),
            binding_digest: Hash::from_bytes(*blake3::hash(&evidence_input).as_bytes()),
        },
    )?;
    let expected = AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
        authenticated,
        actor_entity_id: actor(),
        subject_id: None,
        participant_id: None,
        plugin_id: None,
        installation_id: None,
        principal_role: AuthorityRoleV1::Actor,
        resource: "community:000102030405060708090a0b0c0d0e0f:lifecycle".to_owned(),
        data_category: "community.lifecycle-control".to_owned(),
        action: "community.initialize.v1".to_owned(),
        purpose: "lifecycle-administration".to_owned(),
        audience: AUDIENCE.to_owned(),
        at_time: WallTime::from_micros(NOW),
        authority_timeline: authority_timeline(),
        at_position: Seq::from_u64(1),
        consent_timeline: None,
        consent_at_position: None,
        use_count: 1,
        budget: 1,
        consent_policy_revision: CONSENT_REVISION,
        capability_policy_revision: POLICY_REVISION,
        revocation_epoch: 0,
        revocation_state_current: true,
        authority_registry_digest: REGISTRY,
        consent: ConsentEvidenceV1::NotRequired,
        environment_constraints: vec![
            "community.operation:i:101112131415161718191a1b1c1d1e1f".to_owned()
        ],
    })?;
    assert_eq!(admission.request(), &expected);
    let decision = admission.decision();
    assert!(decision.is_allowed());
    assert_eq!(decision.request_digest(), expected.binding_digest());
    assert_eq!(decision.grant_id(), Some(leaf.grant_id()));
    assert_eq!(decision.actor_entity_id(), actor());

    let aud = decision.encode()?;
    assert_eq!(
        admission.authorization_ref(),
        ArtifactRefV1 {
            schema_id: 0x4341_0002,
            byte_length: aud.as_slice().len() as u64,
            digest: *blake3::hash(aud.as_slice()).as_bytes(),
        }
    );
    // R6.4 V1 and V2.
    assert_eq!(
        caller()?.encode()?.as_slice(),
        unhex("844450524e310150111111111111111111111111111111116f636f6d6d756e6974792e6c6f63616c")?
    );
    let principal_ref = admission.principal_ref();
    let encoded_ref = encode(&Value::Array(vec![
        Value::Integer(principal_ref.schema_id.into()),
        Value::Integer(principal_ref.byte_length.into()),
        Value::Bytes(principal_ref.digest.to_vec()),
    ]))?;
    assert_eq!(
        encoded_ref,
        unhex(
            "831a43410003182858202b2851add5bc8cffcf7a04d0c6c1f2fc2e3204e3f2d50e1dfe82ef7fb3b45ad2"
        )?
    );
    Ok(())
}

/// I21, I22 and I34: every credential defect, and a principal with no CAP1
/// actor row, gives 12 before any grant is evaluated.
#[test]
fn every_credential_defect_gives_12() -> TestResult {
    let leaf = grant(1, 1, 0, &administrative(target(), &ALL_ACTIONS))?;
    let mut world = World::new(std::slice::from_ref(&leaf))?;
    let request = Request::derive(&initialize())?;
    let base = world.record(&initialize())?;
    let good = world.credential(&initialize())?;
    let decoded = AuthenticatedPrincipalEvidenceV1::from_canonical_cbor(&good)?;
    let mut flipped = *decoded.signature();
    flipped[0] ^= 1;
    let bad_signature =
        AuthenticatedPrincipalEvidenceV1::new(base.clone(), flipped)?.to_canonical_cbor()?;
    let mut trailing = good.clone();
    trailing.push(0);
    let stranger = PrincipalRefV1::try_new([0x12; 16], "community.local")?;
    let own = (
        lifecycle_resource(target()),
        "community.initialize.v1",
        constraint('i', OPERATION),
    );
    let with = |edit: &dyn Fn(&mut AuthenticatedPrincipalRecordV1)| {
        let mut record = base.clone();
        edit(&mut record);
        record
    };
    let other_nonces = [
        oracle_nonce(hash(99), &own.0, own.1, &own.2)?,
        oracle_nonce(
            world.catalogue,
            &lifecycle_resource(other_timeline()),
            own.1,
            &own.2,
        )?,
        oracle_nonce(world.catalogue, &own.0, "community.transition.v1", &own.2)?,
        oracle_nonce(world.catalogue, &own.0, own.1, &constraint('i', [0x5a; 16]))?,
        [0x5a; 32],
    ];
    let mut credentials = vec![bad_signature, trailing, Vec::new()];
    credentials.push(sign(base.clone(), [9; 32])?);
    for record in [
        with(&|record| record.adapter_id = "other-adapter".to_owned()),
        with(&|record| record.assurance = 1),
        with(&|record| record.registry_binding = hash(61)),
        with(&|record| record.issued_at = NOW + 1),
        with(&|record| record.expires_at = NOW),
        with(&|record| record.principal = stranger.clone()),
    ] {
        credentials.push(sign(record, SEED)?);
    }
    for operation_nonce in other_nonces {
        credentials.push(sign(
            AuthenticatedPrincipalRecordV1 {
                operation_nonce,
                ..base.clone()
            },
            SEED,
        )?);
    }
    for credential in credentials {
        assert_eq!(
            world.authority.authenticate(&credential, request).err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    assert!(world.authority.authenticate(&good, request).is_ok());

    // No trusted wall sample.
    let attestation = snapshot(&[&leaf])?;
    let mut silent = install(
        CommunityAuthorityCatalogueV1::new(&SEAL, catalogue_input(&attestation)?)?,
        attestation,
        &[],
    )?;
    assert_eq!(
        silent.authenticate(&good, request).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// R6.2(3)(iii): `issued_at ≤ now < expires_at` at the exact boundaries.
#[test]
fn credential_validity_holds_from_issue_until_expiry() -> TestResult {
    let leaf = grant(1, 1, 0, &administrative(target(), &ALL_ACTIONS))?;
    let attestation = snapshot(&[&leaf])?;
    let world = World::new(std::slice::from_ref(&leaf))?;
    let request = Request::derive(&initialize())?;
    let credential = world.credential(&initialize())?;
    let mut authority = install(
        CommunityAuthorityCatalogueV1::new(&SEAL, catalogue_input(&attestation)?)?,
        attestation,
        &[ISSUED - 1, ISSUED, EXPIRES - 1, EXPIRES],
    )?;
    let outcomes = (0..4)
        .map(|_| authority.authenticate(&credential, request).is_ok())
        .collect::<Vec<_>>();
    assert_eq!(outcomes, [false, true, true, false]);
    Ok(())
}

/// I2: in the 5×5 administrative grant/operation matrix only the diagonal is
/// admitted, and the same chain loaded fresh decides every call (I6 basis).
#[test]
fn only_the_diagonal_of_the_administrative_matrix_is_admitted() -> TestResult {
    let grants = ALL_ACTIONS
        .iter()
        .zip(1..)
        .map(|(action, id)| grant(id, u64::from(id), 0, &administrative(target(), &[*action])))
        .collect::<Fallible<Vec<_>>>()?;
    let mut world = World::new(&grants)?;
    for (row, granted) in grants.iter().enumerate() {
        for (column, operation) in operations().iter().enumerate() {
            let outcome = world.admit(operation, granted.grant_id());
            assert_eq!(
                outcome.is_ok(),
                row == column,
                "grant {row}, operation {column}"
            );
            if row != column {
                assert_eq!(outcome.err(), Some(Error::EvidenceUnavailable));
            }
        }
    }
    Ok(())
}

/// I1, I4 and Q8: a grant on another Timeline, on upper-case hex, for another
/// operation or with consent references never authorizes; an unconstrained
/// grant and an exact one-shot pin do.
#[test]
fn only_the_exact_timeline_and_operation_constraint_authorize() -> TestResult {
    let upper = format!(
        "community:{}:lifecycle",
        hex(&target().inner().to_bytes()).to_uppercase()
    );
    let scopes = [
        (administrative(other_timeline(), &ALL_ACTIONS), false),
        (
            Scope {
                resources: vec![upper],
                ..administrative(target(), &ALL_ACTIONS)
            },
            false,
        ),
        (
            Scope {
                constraints: vec![constraint('i', [0x5a; 16])],
                ..administrative(target(), &ALL_ACTIONS)
            },
            false,
        ),
        (
            Scope {
                constraints: vec![constraint('c', OPERATION)],
                ..administrative(target(), &ALL_ACTIONS)
            },
            false,
        ),
        (
            Scope {
                consent_references: vec![hash(80)],
                ..administrative(target(), &ALL_ACTIONS)
            },
            false,
        ),
        (
            Scope {
                audience: "another-host".to_owned(),
                ..administrative(target(), &ALL_ACTIONS)
            },
            false,
        ),
        (
            Scope {
                constraints: vec![constraint('i', OPERATION)],
                ..administrative(target(), &ALL_ACTIONS)
            },
            true,
        ),
        (administrative(target(), &ALL_ACTIONS), true),
    ];
    for (scope, admitted) in scopes {
        let leaf = grant(1, 1, 0, &scope)?;
        let mut world = World::new(std::slice::from_ref(&leaf))?;
        let outcome = world.admit(&initialize(), leaf.grant_id());
        assert_eq!(outcome.is_ok(), admitted);
        if !admitted {
            assert_eq!(outcome.err(), Some(Error::EvidenceUnavailable));
        }
    }
    // Fork is authorized on the parent T only (I4).
    for (parent, admitted) in [(target(), true), (other_timeline(), false)] {
        let leaf = grant(1, 1, 0, &administrative(parent, &["community.fork.v1"]))?;
        let mut world = World::new(std::slice::from_ref(&leaf))?;
        assert_eq!(world.admit(&fork(), leaf.grant_id()).is_ok(), admitted);
    }
    Ok(())
}

/// R6.2(5), I23 and I6: only grants whose as-issued binding the installed
/// attestation set lists are admitted; a sibling revocation leaves an
/// untouched grant usable, and the revoked grant gives 12.
#[test]
fn attestation_admits_issued_grants_across_a_sibling_revocation() -> TestResult {
    let scope = administrative(target(), &ALL_ACTIONS);
    let attested = grant(1, 1, 0, &scope)?;
    let sibling = grant(2, 2, 0, &scope)?;
    let rogue = grant(3, 3, 0, &scope)?;
    let attestation = snapshot(&[&attested, &sibling])?;
    let host_snapshot = snapshot(&[&attested, &sibling, &rogue])?;
    let mut world = World::with(
        &[attested.clone(), sibling.clone(), rogue.clone()],
        &host_snapshot,
        attestation,
    )?;
    assert!(world.admit(&initialize(), attested.grant_id()).is_ok());
    assert_eq!(
        world.admit(&initialize(), rogue.grant_id()).err(),
        Some(Error::EvidenceUnavailable)
    );

    world.revoke(&sibling, 4, 1)?;
    let restamped = world.store.load_authority(attested.grant_id())?;
    assert_ne!(
        restamped.chain().grants()[0].binding_digest()?,
        attested.binding_digest()?
    );
    let admission = world.admit(&initialize(), attested.grant_id())?;
    assert_eq!(admission.request().revocation_epoch(), 1);
    assert_eq!(admission.request().at_position(), Seq::from_u64(4));
    assert_eq!(
        world.admit(&initialize(), sibling.grant_id()).err(),
        Some(Error::EvidenceUnavailable)
    );
    world.revoke(&attested, 5, 2)?;
    assert_eq!(
        world.admit(&initialize(), attested.grant_id()).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

fn implementation(release: u8) -> Fallible<ImplementationKeyV1> {
    Ok(ImplementationKeyV1::new(
        "plugin-a".into(),
        "host-v1".into(),
        hash(release),
    )?)
}

const fn member_input(implementation: &ImplementationKeyV1) -> CommunityMemberBindingInputV1<'_> {
    CommunityMemberBindingInputV1 {
        stable_entry: "Entry-A_1",
        implementation,
        pmf1_digest: hash(4),
        state_schema_digest: hash(5),
        negotiated_tuple_digest: hash(6),
        initial_state_content_digest: hash(7),
        protected_owner_binding_digest: hash(8),
    }
}

fn member_resource(timeline: TimelineId, implementation: &ImplementationKeyV1) -> Fallible<String> {
    let imk1 = encode(&Value::Array(vec![
        Value::Bytes(b"IMK1".to_vec()),
        Value::Integer(1.into()),
        Value::Text(implementation.plugin_id().to_owned()),
        Value::Text(implementation.version().to_owned()),
        Value::Bytes(implementation.release_digest().as_bytes().to_vec()),
    ]))?;
    let preimage = encode(&Value::Array(vec![
        Value::Text("Entry-A_1".to_owned()),
        Value::Bytes(imk1),
    ]))?;
    Ok(format!(
        "community:{}:member:{}",
        hex(&timeline.inner().to_bytes()),
        hex(adr_h("StableMember", &preimage).as_bytes())
    ))
}

fn member_scope(timeline: TimelineId, implementation: &ImplementationKeyV1) -> Fallible<Scope> {
    Ok(Scope {
        resources: vec![member_resource(timeline, implementation)?],
        actions: vec!["execute".to_owned(), "read".to_owned()],
        audience: RECIPIENT.to_owned(),
        constraints: vec![],
        consent_references: vec![],
    })
}

const fn member_use<'a>(
    member: &'a CommunityMemberBindingV1<'a>,
    action: CommunityMemberActionV1,
) -> CommunityMemberUseV1<'a> {
    CommunityMemberUseV1 {
        member,
        action,
        audience: RECIPIENT,
    }
}

/// A5.2(3a), A5.8, I2 and I14: a member request names
/// `community:<T32>:member:<M64>` for the call's own Timeline (the parent T
/// for Fork), the in-operation purpose and the installed recipient, with the
/// call's operation constraint.
#[test]
fn member_requests_use_the_call_timeline_member_and_constraint() -> TestResult {
    let release = implementation(3)?;
    let changed = implementation(9)?;
    let member = CommunityMemberBindingV1::new(member_input(&release))?;
    let released = CommunityMemberBindingV1::new(member_input(&changed))?;
    let member_grant = grant(1, 1, 0, &member_scope(target(), &release)?)?;
    let child_grant = grant(2, 2, 0, &member_scope(other_timeline(), &release)?)?;
    let admin_grant = grant(3, 3, 0, &administrative(target(), &ALL_ACTIONS))?;
    let mut world = World::new(&[
        member_grant.clone(),
        child_grant.clone(),
        admin_grant.clone(),
    ])?;
    let member_chain = world.store.load_authority(member_grant.grant_id())?;
    let child_chain = world.store.load_authority(child_grant.grant_id())?;
    let admin_chain = world.store.load_authority(admin_grant.grant_id())?;

    for operation in [initialize(), transition(), fork()] {
        let request = Request::derive(&operation)?;
        let credential = world.credential(&operation)?;
        let call = world.authority.authenticate(&credential, request)?;
        for action in [
            CommunityMemberActionV1::Read,
            CommunityMemberActionV1::Execute,
        ] {
            let admission = world.authority.authorize_member(
                &call,
                member_use(&member, action),
                &member_chain,
            )?;
            let built = admission.request();
            assert_eq!(built.resource(), member_resource(target(), &release)?);
            assert_eq!(built.resource().len(), 114);
            assert_eq!(built.data_category(), "community.execution-state");
            assert_eq!(
                built.action(),
                if action == CommunityMemberActionV1::Read {
                    "read"
                } else {
                    "execute"
                }
            );
            assert_eq!(built.purpose(), "lifecycle-administration");
            assert_eq!(built.audience(), RECIPIENT);
            assert_eq!(
                built.environment_constraints().to_vec(),
                vec![request.operation_constraint()]
            );
            assert_eq!(built.authenticated().principal(), &caller()?);
            for refused in [
                world.authority.authorize_member(
                    &call,
                    member_use(&released, action),
                    &member_chain,
                ),
                world
                    .authority
                    .authorize_member(&call, member_use(&member, action), &child_chain),
                world
                    .authority
                    .authorize_member(&call, member_use(&member, action), &admin_chain),
                world.authority.authorize_member(
                    &call,
                    CommunityMemberUseV1 {
                        audience: AUDIENCE,
                        ..member_use(&member, action)
                    },
                    &member_chain,
                ),
            ] {
                assert_eq!(refused.err(), Some(Error::EvidenceUnavailable));
            }
        }
        assert_eq!(
            world
                .authority
                .authorize_administrative(&call, &member_chain)
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }

    Ok(())
}

/// A5.2(4): retire and reset use no State, so no member request is built.
#[test]
fn retire_and_reset_calls_admit_no_member_request() -> TestResult {
    let release = implementation(3)?;
    let member = CommunityMemberBindingV1::new(member_input(&release))?;
    let member_grant = grant(1, 1, 0, &member_scope(target(), &release)?)?;
    let admin_grant = grant(3, 3, 0, &administrative(target(), &ALL_ACTIONS))?;
    let mut world = World::new(&[member_grant.clone(), admin_grant.clone()])?;
    let member_chain = world.store.load_authority(member_grant.grant_id())?;
    let admin_chain = world.store.load_authority(admin_grant.grant_id())?;
    for operation in [retire(), reset()] {
        let request = Request::derive(&operation)?;
        let credential = world.credential(&operation)?;
        let call = world.authority.authenticate(&credential, request)?;
        assert!(world
            .authority
            .authorize_administrative(&call, &admin_chain)
            .is_ok());
        assert_eq!(
            world
                .authority
                .authorize_member(
                    &call,
                    CommunityMemberUseV1 {
                        member: &member,
                        action: CommunityMemberActionV1::Read,
                        audience: RECIPIENT,
                    },
                    &member_chain,
                )
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}
