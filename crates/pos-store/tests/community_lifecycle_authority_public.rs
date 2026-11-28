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
use pos_core::trusted_clock::{ScriptedTrustedWallSourceV1, SystemGuardMonotonicSourceV1};
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
    CommunityAuthorityCallV1, CommunityLifecycleAuthorityInputV1, CommunityLifecycleAuthorityV1,
    CommunityMemberActionV1, MemoryCommunityDomainV1,
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
const RECIPIENT: &str = "community-recipient";
const ADAPTER: &str = "community-adapter";
const SEED: [u8; 32] = [7; 32];
const INCARNATION: [u8; 16] = [0x5a; 16];
const OPERATION: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const FORK_OPERATION: [u8; 16] = [0xf0; 16];
const CONTROL: [u8; 16] = [0xc0; 16];
const NOW: u64 = 500;
const ISSUED: u64 = 100;
const EXPIRES: u64 = 30_000_100;
const ALL_ACTIONS: [&str; 6] = [
    "community.initialize.v1",
    "community.transition.v1",
    "community.fork.v1",
    "community.retire.v1",
    "community.quarantine.reset.v1",
    "community.pass.abort.v1",
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

fn pass_abort() -> Operation {
    Operation::PassAbort {
        timeline: target(),
        reservation_operation_id: CONTROL,
    }
}

fn operations() -> [Operation; 6] {
    [
        initialize(),
        transition(),
        fork(),
        retire(),
        reset(),
        pass_abort(),
    ]
}

/// The grant scope a test issues.
#[derive(Clone)]
struct Scope {
    resources: Vec<String>,
    actions: Vec<String>,
    purposes: Vec<String>,
    audience: String,
    constraints: Vec<String>,
    consent_references: Vec<Hash>,
}

fn administrative(timeline: TimelineId, actions: &[&str]) -> Scope {
    Scope {
        resources: vec![lifecycle_resource(timeline)],
        actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        purposes: vec!["lifecycle-administration".to_owned()],
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
        purposes: scope.purposes.clone(),
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
            member_recipient: RECIPIENT.to_owned(),
            store_incarnation: INCARNATION,
        },
        ScriptedTrustedWallSourceV1::from_micros(samples.iter().copied()),
        SystemGuardMonotonicSourceV1,
    )?)
}

/// A revocation applied before the store becomes the domain's.
type Revocation<'a> = (&'a CapabilityGrantV1, u64, u64);

/// A domain whose store holds `grants` issued through a persistence host
/// built from `host_snapshot`, with `revocations` applied before the store is
/// handed over, and the authority installed with `attestation`.
struct World {
    domain: MemoryCommunityDomainV1,
    authority: CommunityLifecycleAuthorityV1,
    catalogue: Hash,
}

impl World {
    fn new(grants: &[CapabilityGrantV1]) -> Fallible<Self> {
        let all = grants.iter().collect::<Vec<_>>();
        let attestation = snapshot(&all)?;
        Self::with(grants, &attestation, attestation.clone(), &[])
    }

    fn with(
        grants: &[CapabilityGrantV1],
        host_snapshot: &AuthorityRegistrySnapshotV1,
        attestation: AuthorityRegistrySnapshotV1,
        revocations: &[Revocation<'_>],
    ) -> Fallible<Self> {
        let host = AuthorityPersistenceHostV1::new(host_snapshot);
        let mut store = MemoryStore::new();
        store.bind_authority_persistence(host.persistence_binding())?;
        for grant in grants {
            let permit = host.authorize_grant(grant)?;
            store.issue_capability_grant(permit, grant)?;
        }
        for (grant, fence, epoch) in revocations {
            let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
                grant_id: grant.grant_id(),
                authority_timeline: authority_timeline(),
                fence_position: Seq::from_u64(*fence),
                revocation_epoch: *epoch,
                policy_revision: POLICY_REVISION,
                authority_registry_digest: REGISTRY,
            })?;
            let permit = host.authorize_revocation(grant, &revocation)?;
            store.revoke_capability_grant(permit, &revocation)?;
        }
        if let Some((grant, _, _)) = revocations.first() {
            // The store re-stamps every loaded grant after a revocation.
            let loaded = store.load_authority(grants[0].grant_id())?;
            assert_ne!(
                loaded.chain().grants()[0].binding_digest()?,
                grants[0].binding_digest()?,
                "revoking {:?} must re-stamp the chain",
                grant.grant_id()
            );
        }
        let catalogue = CommunityAuthorityCatalogueV1::new(&SEAL, catalogue_input(&attestation)?)?;
        let digest = catalogue.digest();
        Ok(Self {
            domain: MemoryCommunityDomainV1::new(
                store,
                INCARNATION,
                MemoryTrustedClockAuthorityV1::new(),
            )?,
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

    /// The FAE1 of a `run_pass` call, with the execution nonce built from the
    /// ADR field list (R8.1(4)).
    fn execution_credential(
        &self,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) -> Fallible<Vec<u8>> {
        self.execution_credential_until(EXPIRES, timeline, reservation_operation_id)
    }

    /// An execution FAE1 that expires at `expires_at`.
    fn execution_credential_until(
        &self,
        expires_at: u64,
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) -> Fallible<Vec<u8>> {
        let preimage = encode(&Value::Array(vec![
            Value::Bytes(self.catalogue.as_bytes().to_vec()),
            Value::Bytes(timeline.inner().to_bytes().to_vec()),
            Value::Text("execute".to_owned()),
            Value::Text(constraint('r', reservation_operation_id)),
        ]))?;
        sign(
            AuthenticatedPrincipalRecordV1 {
                principal: caller()?,
                adapter_id: ADAPTER.to_owned(),
                assurance: 2,
                issued_at: ISSUED,
                expires_at,
                registry_binding: FAP_BINDING,
                operation_nonce: *adr_h("ExecutionNonce", &preimage).as_bytes(),
            },
            SEED,
        )
    }

    fn execution_call(
        &mut self,
        credential: &[u8],
        timeline: TimelineId,
        reservation_operation_id: [u8; 16],
    ) -> Result<CommunityAuthorityCallV1, Error> {
        self.authority.authenticate(
            credential,
            Request::run_pass(timeline, reservation_operation_id)?,
            &mut self.domain,
        )
    }

    fn call(&mut self, operation: &Operation) -> Fallible<CommunityAuthorityCallV1> {
        let credential = self.credential(operation)?;
        Ok(self.authority.authenticate(
            &credential,
            Request::derive(operation)?,
            &mut self.domain,
        )?)
    }

    fn admit(
        &mut self,
        operation: &Operation,
        leaf: Hash,
    ) -> Result<CommunityAuthorityAdmissionV1, Error> {
        let call = self.call(operation).map_err(|_| Error::InvalidEncoding)?;
        self.authority
            .authorize_administrative(&call, &self.domain, leaf)
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
        (pass_abort(), Action::PassAbort, target(), 'r', CONTROL),
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
        Action::PassAbort,
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
        Operation::PassAbort {
            timeline: zero,
            reservation_operation_id: CONTROL,
        },
        Operation::PassAbort {
            timeline: target(),
            reservation_operation_id: [0; 16],
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
                   forks: Vec<ForkAuthenticationPolicyV1>,
                   recipient: String|
     -> Fallible<Result<CommunityLifecycleAuthorityV1, Error>> {
        Ok(CommunityLifecycleAuthorityV1::new(
            &SEAL,
            CommunityLifecycleAuthorityInputV1 {
                catalogue: CommunityAuthorityCatalogueV1::new(&SEAL, input)?,
                authentication_policy: fap1(SEED)?,
                attestation,
                fork_admission_policies: forks,
                member_recipient: recipient,
                store_incarnation: INCARNATION,
            },
            ScriptedTrustedWallSourceV1::from_micros([NOW]),
            SystemGuardMonotonicSourceV1,
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
            attempt(input, attestation, forks, RECIPIENT.to_owned())?.err(),
            Some(Error::InvalidBinding)
        );
    }
    for recipient in [String::new(), "r".repeat(129)] {
        assert_eq!(
            attempt(good.clone(), attestation.clone(), vec![], recipient)?.err(),
            Some(Error::InvalidBinding)
        );
    }
    assert!(attempt(good.clone(), attestation.clone(), vec![], "r".repeat(128))?.is_ok());
    assert_eq!(
        CommunityLifecycleAuthorityV1::new(
            &SEAL,
            CommunityLifecycleAuthorityInputV1 {
                catalogue: CommunityAuthorityCatalogueV1::new(&SEAL, good.clone())?,
                authentication_policy: fap1(SEED)?,
                attestation: attestation.clone(),
                fork_admission_policies: vec![],
                member_recipient: RECIPIENT.to_owned(),
                store_incarnation: [0; 16],
            },
            ScriptedTrustedWallSourceV1::from_micros([NOW]),
            SystemGuardMonotonicSourceV1,
        )
        .err(),
        Some(Error::InvalidBinding)
    );
    assert!(attempt(
        good,
        attestation,
        vec![fap1([9; 32])?],
        RECIPIENT.to_owned()
    )?
    .is_ok());
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
    let call = world
        .authority
        .authenticate(&credential, request, &mut world.domain)?;
    assert_eq!(call.request(), &request);
    // The domain clock's first committed reservation.
    assert_eq!(call.reservation_id(), 1);
    assert_eq!(world.call(&initialize())?.reservation_id(), 2);
    assert_eq!(call.at_time(), WallTime::from_micros(NOW));
    assert_eq!(call.expires_at(), WallTime::from_micros(EXPIRES));
    // G1: D = t_r + 32 s is later than this 30 s credential's expiry.
    assert_eq!(call.decision_bound(), WallTime::from_micros(EXPIRES));
    let admission =
        world
            .authority
            .authorize_administrative(&call, &world.domain, leaf.grant_id())?;

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
    assert_eq!(admission.leaf_grant_id(), leaf.grant_id());
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
            world
                .authority
                .authenticate(&credential, request, &mut world.domain)
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    assert!(world
        .authority
        .authenticate(&good, request, &mut world.domain)
        .is_ok());

    // No trusted wall sample.
    let attestation = snapshot(&[&leaf])?;
    let mut silent = install(
        CommunityAuthorityCatalogueV1::new(&SEAL, catalogue_input(&attestation)?)?,
        attestation,
        &[],
    )?;
    assert_eq!(
        silent.authenticate(&good, request, &mut world.domain).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// Owner decision on #560, note 22722, G1: the call's decision bound is the
/// earlier of the reservation's `D = t_r + 32 s` and the credential's expiry,
/// and `t_r` is the call's `at_time`.
#[test]
fn the_decision_bound_is_the_earlier_of_the_reservation_bound_and_expiry() -> TestResult {
    let leaf = grant(1, 1, 0, &administrative(target(), &ALL_ACTIONS))?;
    let mut world = World::new(std::slice::from_ref(&leaf))?;
    let request = Request::derive(&initialize())?;
    let short = world.credential(&initialize())?;
    let long = sign(
        AuthenticatedPrincipalRecordV1 {
            expires_at: NOW + 40_000_000,
            ..world.record(&initialize())?
        },
        SEED,
    )?;
    let short_call = world
        .authority
        .authenticate(&short, request, &mut world.domain)?;
    let long_call = world
        .authority
        .authenticate(&long, request, &mut world.domain)?;
    assert_eq!(short_call.decision_bound(), WallTime::from_micros(EXPIRES));
    assert_eq!(long_call.at_time(), WallTime::from_micros(NOW));
    assert_eq!(
        long_call.decision_bound(),
        WallTime::from_micros(NOW + 32_000_000)
    );
    Ok(())
}

/// R6.2(3)(iii): `issued_at ≤ now < expires_at` at the exact boundaries.
#[test]
fn credential_validity_holds_from_issue_until_expiry() -> TestResult {
    let leaf = grant(1, 1, 0, &administrative(target(), &ALL_ACTIONS))?;
    let attestation = snapshot(&[&leaf])?;
    let mut world = World::new(std::slice::from_ref(&leaf))?;
    let request = Request::derive(&initialize())?;
    let credential = world.credential(&initialize())?;
    let mut authority = install(
        CommunityAuthorityCatalogueV1::new(&SEAL, catalogue_input(&attestation)?)?,
        attestation,
        &[ISSUED - 1, ISSUED, EXPIRES - 1, EXPIRES],
    )?;
    let outcomes = (0..4)
        .map(|_| {
            authority
                .authenticate(&credential, request, &mut world.domain)
                .is_ok()
        })
        .collect::<Vec<_>>();
    assert_eq!(outcomes, [false, true, true, false]);
    Ok(())
}

/// I2: in the 6×6 administrative grant/operation matrix only the diagonal is
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
    let grants = [attested.clone(), sibling.clone(), rogue.clone()];
    let attestation = snapshot(&[&attested, &sibling])?;
    let host_snapshot = snapshot(&[&attested, &sibling, &rogue])?;
    let mut world = World::with(&grants, &host_snapshot, attestation.clone(), &[])?;
    assert!(world.admit(&initialize(), attested.grant_id()).is_ok());
    assert_eq!(
        world.admit(&initialize(), rogue.grant_id()).err(),
        Some(Error::EvidenceUnavailable)
    );

    let mut revoked_sibling = World::with(
        &grants,
        &host_snapshot,
        attestation.clone(),
        &[(&sibling, 4, 1)],
    )?;
    let admission = revoked_sibling.admit(&initialize(), attested.grant_id())?;
    assert_eq!(admission.request().revocation_epoch(), 1);
    assert_eq!(admission.request().at_position(), Seq::from_u64(4));
    assert_eq!(
        revoked_sibling
            .admit(&initialize(), sibling.grant_id())
            .err(),
        Some(Error::EvidenceUnavailable)
    );

    let mut revoked_both = World::with(
        &grants,
        &host_snapshot,
        attestation,
        &[(&sibling, 4, 1), (&attested, 5, 2)],
    )?;
    assert_eq!(
        revoked_both.admit(&initialize(), attested.grant_id()).err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// A5.9 and the call binding: a call is honoured only by the authority that
/// authenticated it, and a missing leaf locator gives 12.
#[test]
fn a_call_is_refused_by_another_authority_and_for_an_unknown_leaf() -> TestResult {
    let leaf = grant(1, 1, 0, &administrative(target(), &ALL_ACTIONS))?;
    let mut world = World::new(std::slice::from_ref(&leaf))?;
    let call = world.call(&initialize())?;
    let attestation = snapshot(&[&leaf])?;
    let other = install(
        CommunityAuthorityCatalogueV1::new(
            &SEAL,
            CommunityAuthorityCatalogueInputV1 {
                trust_scope: "community.other".to_owned(),
                ..catalogue_input(&attestation)?
            },
        )?,
        attestation,
        &[NOW],
    )?;
    assert!(world
        .authority
        .authorize_administrative(&call, &world.domain, leaf.grant_id())
        .is_ok());
    assert_eq!(
        other
            .authorize_administrative(&call, &world.domain, leaf.grant_id())
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(
        world
            .authority
            .authorize_administrative(&call, &world.domain, hash(99))
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    // The binding is to the composition's incarnation label, not to a store
    // identity: another domain object presenting the installed label is
    // accepted on purpose, and its evidence still comes from its own store
    // and must verify against the attested snapshot. A second, legitimate
    // domain under another incarnation is not the domain this authority was
    // installed for.
    let other_domain = World::new(std::slice::from_ref(&leaf))?.domain;
    let mut second = MemoryStore::new();
    let host = AuthorityPersistenceHostV1::new(&snapshot(&[&leaf])?);
    second.bind_authority_persistence(host.persistence_binding())?;
    second.issue_capability_grant(host.authorize_grant(&leaf)?, &leaf)?;
    let mut foreign =
        MemoryCommunityDomainV1::new(second, [0x5b; 16], MemoryTrustedClockAuthorityV1::new())?;
    assert!(world
        .authority
        .authorize_administrative(&call, &other_domain, leaf.grant_id())
        .is_ok());
    assert_eq!(
        world
            .authority
            .authorize_administrative(&call, &foreign, leaf.grant_id())
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    // Nor does a foreign domain reserve a call: authentication refuses it
    // before its clock is touched.
    let credential = world.credential(&initialize())?;
    assert_eq!(
        world
            .authority
            .authenticate(&credential, Request::derive(&initialize())?, &mut foreign)
            .err(),
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
        purposes: vec!["lifecycle-administration".to_owned()],
        audience: RECIPIENT.to_owned(),
        constraints: vec![],
        consent_references: vec![],
    })
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
    let caller_audience = grant(
        4,
        4,
        0,
        &Scope {
            audience: AUDIENCE.to_owned(),
            ..member_scope(target(), &release)?
        },
    )?;
    let mut world = World::new(&[
        member_grant.clone(),
        child_grant.clone(),
        admin_grant.clone(),
        caller_audience.clone(),
    ])?;

    for operation in [initialize(), transition(), fork()] {
        let request = Request::derive(&operation)?;
        let call = world.call(&operation)?;
        let authority = &world.authority;
        let domain = &world.domain;
        for action in [
            CommunityMemberActionV1::Read,
            CommunityMemberActionV1::Execute,
        ] {
            let admission = authority.authorize_member(
                &call,
                &member,
                action,
                domain,
                member_grant.grant_id(),
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
            // Another release, a child-T grant, an administrative grant and a
            // grant scoped to a caller-chosen audience never match.
            for refused in [
                authority.authorize_member(
                    &call,
                    &released,
                    action,
                    domain,
                    member_grant.grant_id(),
                ),
                authority.authorize_member(&call, &member, action, domain, child_grant.grant_id()),
                authority.authorize_member(&call, &member, action, domain, admin_grant.grant_id()),
                authority.authorize_member(
                    &call,
                    &member,
                    action,
                    domain,
                    caller_audience.grant_id(),
                ),
            ] {
                assert_eq!(refused.err(), Some(Error::EvidenceUnavailable));
            }
        }
        assert_eq!(
            authority
                .authorize_administrative(&call, domain, member_grant.grant_id())
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
    for operation in [retire(), reset()] {
        let call = world.call(&operation)?;
        assert!(world
            .authority
            .authorize_administrative(&call, &world.domain, admin_grant.grant_id())
            .is_ok());
        assert_eq!(
            world
                .authority
                .authorize_member(
                    &call,
                    &member,
                    CommunityMemberActionV1::Read,
                    &world.domain,
                    member_grant.grant_id(),
                )
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

/// R6.2(3): a credential that fails verification or its nonce consumes no
/// trusted wall sample, so one sample still serves the next valid call.
#[test]
fn a_refused_credential_consumes_no_wall_sample() -> TestResult {
    let leaf = grant(1, 1, 0, &administrative(target(), &ALL_ACTIONS))?;
    let mut world = World::new(std::slice::from_ref(&leaf))?;
    let attestation = snapshot(&[&leaf])?;
    let mut authority = install(
        CommunityAuthorityCatalogueV1::new(&SEAL, catalogue_input(&attestation)?)?,
        attestation,
        &[NOW],
    )?;
    let request = Request::derive(&initialize())?;
    let wrong_nonce = sign(
        AuthenticatedPrincipalRecordV1 {
            operation_nonce: [0x5a; 32],
            ..world.record(&initialize())?
        },
        SEED,
    )?;
    for refused in [
        vec![0xff; 16],
        wrong_nonce,
        sign(world.record(&initialize())?, [9; 32])?,
    ] {
        assert_eq!(
            authority
                .authenticate(&refused, request, &mut world.domain)
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    assert!(authority
        .authenticate(
            &world.credential(&initialize())?,
            request,
            &mut world.domain
        )
        .is_ok());
    Ok(())
}

/// The reservation operation of the `run_pass` calls below.
const RESERVATION: [u8; 16] = [0x30; 16];

/// The member scope of a `run_pass` grant: the execution purpose.
fn execution_scope(timeline: TimelineId, implementation: &ImplementationKeyV1) -> Fallible<Scope> {
    Ok(Scope {
        purposes: vec!["community-execution".to_owned()],
        ..member_scope(timeline, implementation)?
    })
}

/// R8.1(2)-(4): a `run_pass` FAE1 carries the execution nonce, so it serves
/// no administrative request and an administrative FAE1 serves no `run_pass`;
/// the call's member `execute` request has the R8.1(3) fields; and a zero
/// Timeline or reservation identity has no request.
#[test]
fn an_execution_credential_serves_only_its_run_pass_request() -> TestResult {
    let release = implementation(3)?;
    let member = CommunityMemberBindingV1::new(member_input(&release))?;
    let member_grant = grant(1, 1, 0, &execution_scope(target(), &release)?)?;
    let child_grant = grant(2, 2, 0, &execution_scope(other_timeline(), &release)?)?;
    let admin_grant = grant(3, 3, 0, &administrative(target(), &ALL_ACTIONS))?;
    let lifecycle_purpose = grant(4, 4, 0, &member_scope(target(), &release)?)?;
    let mut world = World::new(&[
        member_grant.clone(),
        child_grant.clone(),
        admin_grant.clone(),
        lifecycle_purpose.clone(),
    ])?;
    let credential = world.execution_credential(target(), RESERVATION)?;
    let call = world.execution_call(&credential, target(), RESERVATION)?;
    let admission = world.authority.authorize_execution_member(
        &call,
        &member,
        &world.domain,
        member_grant.grant_id(),
    )?;
    let built = admission.request();
    assert_eq!(built.resource(), member_resource(target(), &release)?);
    assert_eq!(built.resource().len(), 114);
    assert_eq!(built.data_category(), "community.execution-state");
    assert_eq!(built.action(), "execute");
    assert_eq!(built.purpose(), "community-execution");
    assert_eq!(built.audience(), RECIPIENT);
    assert_eq!(
        built.environment_constraints().to_vec(),
        vec![constraint('r', RESERVATION)]
    );
    assert_eq!(built.authenticated().principal(), &caller()?);
    // A grant of another Timeline, an administrative grant and a grant of the
    // in-operation purpose never match.
    for leaf in [&child_grant, &admin_grant, &lifecycle_purpose] {
        assert_eq!(
            world
                .authority
                .authorize_execution_member(&call, &member, &world.domain, leaf.grant_id())
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    // An execution call has no administrative decision.
    assert_eq!(
        world
            .authority
            .authorize_administrative(&call, &world.domain, admin_grant.grant_id())
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    // An execution call serves no other member request (`read`, nor `execute` under the
    // in-operation purpose); the initializer read is refused in
    // `community_initializer_public.rs`.
    for action in [
        CommunityMemberActionV1::Read,
        CommunityMemberActionV1::Execute,
    ] {
        assert_eq!(
            world
                .authority
                .authorize_member(
                    &call,
                    &member,
                    action,
                    &world.domain,
                    member_grant.grant_id()
                )
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    // An administrative call has no member `execute`, although its
    // operation constraint is the same `r` constraint.
    let abort = world.call(&pass_abort())?;
    assert_eq!(
        world
            .authority
            .authorize_execution_member(&abort, &member, &world.domain, member_grant.grant_id())
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}

/// R8.1(4): the execution nonce separates the credentials by domain and
/// binds the Timeline and the reservation operation; a zero Timeline or
/// reservation identity has no request.
#[test]
fn the_execution_nonce_separates_domains_and_binds_its_fields() -> TestResult {
    let release = implementation(3)?;
    let member_grant = grant(1, 1, 0, &execution_scope(target(), &release)?)?;
    let mut world = World::new(&[member_grant])?;
    let credential = world.execution_credential(target(), RESERVATION)?;
    assert!(world
        .execution_call(&credential, target(), RESERVATION)
        .is_ok());
    let administrative = world.credential(&pass_abort())?;
    assert_eq!(
        world
            .execution_call(&administrative, target(), RESERVATION)
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    assert_eq!(
        world
            .authority
            .authenticate(
                &credential,
                Request::derive(&pass_abort())?,
                &mut world.domain
            )
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    // The nonce binds the Timeline and the reservation operation.
    for (timeline, operation) in [(other_timeline(), RESERVATION), (target(), [0x31; 16])] {
        assert_eq!(
            world.execution_call(&credential, timeline, operation).err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    for (timeline, operation) in [
        (
            TimelineId::from_ulid(Ulid::from_bytes([0; 16])),
            RESERVATION,
        ),
        (target(), [0; 16]),
    ] {
        assert_eq!(
            Request::run_pass(timeline, operation).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

/// R8.1(5), R8.1(8) step 3a: `authenticate` gives 12 for a `run_pass` call
/// whose sample plus the 27 s decision deadline passes its decision bound, and
/// accepts one that ends exactly at it. The bound is `B = min(t_r + 32 s,
/// expires_at)`, so both sides of the minimum are checked.
#[test]
fn a_run_pass_call_must_fit_its_decision_deadline_by_its_bound() -> TestResult {
    let release = implementation(3)?;
    let member_grant = grant(1, 1, 0, &execution_scope(target(), &release)?)?;
    let mut world = World::new(&[member_grant])?;
    let deadline = 27_000_000;
    // B = expires_at: exactly the deadline fits, a microsecond less does not.
    let fits = world.execution_credential_until(NOW + deadline, target(), RESERVATION)?;
    let call = world.execution_call(&fits, target(), RESERVATION)?;
    assert_eq!(call.decision_bound(), WallTime::from_micros(NOW + deadline));
    let short = world.execution_credential_until(NOW + deadline - 1, target(), RESERVATION)?;
    assert_eq!(
        world.execution_call(&short, target(), RESERVATION).err(),
        Some(Error::EvidenceUnavailable)
    );
    // B = D = t_r + 32 s, below the expiry: the call fits.
    let long = world.execution_credential_until(NOW + 40_000_000, target(), RESERVATION)?;
    let call = world.execution_call(&long, target(), RESERVATION)?;
    assert_eq!(
        call.decision_bound(),
        WallTime::from_micros(NOW + 32_000_000)
    );
    // The check belongs to `run_pass`: a short administrative call is kept.
    let short_admin = sign(
        AuthenticatedPrincipalRecordV1 {
            expires_at: NOW + 1_000,
            ..world.record(&pass_abort())?
        },
        SEED,
    )?;
    assert!(world
        .authority
        .authenticate(
            &short_admin,
            Request::derive(&pass_abort())?,
            &mut world.domain
        )
        .is_ok());
    Ok(())
}

/// The Event-history scope of a `run_pass` grant: `read` on each owner's
/// `community-events:<U32>` under `purpose`.
fn event_scope(owners: &[TimelineId], purpose: &str) -> Scope {
    Scope {
        resources: owners
            .iter()
            .map(|owner| format!("community-events:{}", hex(&owner.inner().to_bytes())))
            .collect(),
        actions: vec!["read".to_owned()],
        purposes: vec![purpose.to_owned()],
        audience: RECIPIENT.to_owned(),
        constraints: vec![],
        consent_references: vec![],
    }
}

/// The grants of the Event-history tests, in the order of [`event_world`].
struct EventGrants {
    events: CapabilityGrantV1,
    other: CapabilityGrantV1,
    in_operation: CapabilityGrantV1,
    caller_audience: CapabilityGrantV1,
}

/// A world with the Event-history grants and an authenticated `run_pass` call.
fn event_world() -> Fallible<(World, EventGrants, CommunityAuthorityCallV1)> {
    let grants = EventGrants {
        events: grant(1, 1, 0, &event_scope(&[target()], "community-execution"))?,
        other: grant(
            2,
            2,
            0,
            &event_scope(&[other_timeline()], "community-execution"),
        )?,
        in_operation: grant(
            3,
            3,
            0,
            &event_scope(&[target()], "lifecycle-administration"),
        )?,
        caller_audience: grant(
            4,
            4,
            0,
            &Scope {
                audience: AUDIENCE.to_owned(),
                ..event_scope(&[target()], "community-execution")
            },
        )?,
    };
    let mut world = World::new(&[
        grants.events.clone(),
        grants.other.clone(),
        grants.in_operation.clone(),
        grants.caller_audience.clone(),
    ])?;
    let credential = world.execution_credential(target(), RESERVATION)?;
    let call = world.execution_call(&credential, target(), RESERVATION)?;
    Ok((world, grants, call))
}

/// R9.5: an Event-history request names `community-events:<U32>`, the
/// execution purpose and the installed recipient, with the call's `r`
/// constraint and no subject.
#[test]
fn an_event_history_request_has_the_r9_5_fields() -> TestResult {
    let (world, grants, call) = event_world()?;
    let admission = world.authority.authorize_event_history(
        &call,
        target(),
        &world.domain,
        grants.events.grant_id(),
    )?;
    let built = admission.request();
    assert_eq!(
        built.resource(),
        format!("community-events:{}", hex(&target().inner().to_bytes()))
    );
    assert_eq!(built.resource().len(), 49);
    assert_eq!(built.data_category(), "community.event-history");
    assert_eq!(built.action(), "read");
    assert_eq!(built.purpose(), "community-execution");
    assert_eq!(built.audience(), RECIPIENT);
    assert_eq!(
        built.environment_constraints().to_vec(),
        vec![constraint('r', RESERVATION)]
    );
    assert!(built.subject_id().is_none());
    assert_eq!(built.authenticated().principal(), &caller()?);
    Ok(())
}

/// R9.5: each owning Timeline has its own decision on its own resource, and
/// a grant of one owner never serves another.
#[test]
fn each_owning_timeline_needs_its_own_event_history_grant() -> TestResult {
    let (world, grants, call) = event_world()?;
    let first = world.authority.authorize_event_history(
        &call,
        target(),
        &world.domain,
        grants.events.grant_id(),
    )?;
    let second = world.authority.authorize_event_history(
        &call,
        other_timeline(),
        &world.domain,
        grants.other.grant_id(),
    )?;
    assert_eq!(
        second.request().resource(),
        format!(
            "community-events:{}",
            hex(&other_timeline().inner().to_bytes())
        )
    );
    assert_ne!(first.request().resource(), second.request().resource());
    for (owner, leaf) in [
        (other_timeline(), grants.events.grant_id()),
        (target(), grants.other.grant_id()),
    ] {
        assert_eq!(
            world
                .authority
                .authorize_event_history(&call, owner, &world.domain, leaf)
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    Ok(())
}

/// R9.5: a grant of the in-operation purpose or of a caller-chosen audience
/// never matches, and an administrative call has no Event-history request.
#[test]
fn an_event_history_request_refuses_another_purpose_audience_or_call() -> TestResult {
    let (mut world, grants, call) = event_world()?;
    for leaf in [&grants.in_operation, &grants.caller_audience] {
        assert_eq!(
            world
                .authority
                .authorize_event_history(&call, target(), &world.domain, leaf.grant_id())
                .err(),
            Some(Error::EvidenceUnavailable)
        );
    }
    let abort = world.call(&pass_abort())?;
    assert_eq!(
        world
            .authority
            .authorize_event_history(&abort, target(), &world.domain, grants.events.grant_id())
            .err(),
        Some(Error::EvidenceUnavailable)
    );
    Ok(())
}
