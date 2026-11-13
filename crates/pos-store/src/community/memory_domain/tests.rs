//! Retained-Memory domain bootstrap, retry, admission and tamper behavior.
//!
//! Oracles are built from the ADR-128/129 preimages with the `blake3` and
//! `ciborium` crates directly, not from the implementation's helpers.

use std::error::Error as StdError;

use ciborium::Value;
use pos_core::community_lifecycle::{
    CommunityArtifactKindV1, CommunityArtifactOperationV1, CommunityArtifactPurposeV1,
    CommunityCopyHolderV1, CommunityCopyInventoryV1, CommunityCopyStateV1,
    CommunityLifecycleErrorV1 as Error, CommunityMetadataAnchorV1, CommunityMetadataPolicyInputV1,
    CommunityMetadataPolicyV1, CommunityMetadataSchemaV1, CommunityMetadataScopeInputV1,
    CommunityMetadataScopeV1, CommunityScopeMembersV1, CommunitySelectionV1,
};
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorityPersistenceHostV1,
    AuthorityPersistencePortV1, AuthorityRegistrySnapshotV1, AuthorityRoleV1,
    AuthorizationDecisionV1, AuthorizationOutcomeV1, AuthorizationRequestDraftV1,
    AuthorizationRequestV1, CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityRevocationDraftV1,
    CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1, ConsentEvidenceV1, EntityId,
    Hash, PrincipalRefV1, Seq, TimelineId, WallTime,
};
use ulid::Ulid;

use super::super::private_hash::{plaintext_commitment, private_digest, scope_set_digest};
use super::super::vault::VaultKeyV1;
use super::{
    bootstrap_intent, BootstrapRecordIds, BootstrapRecordV1, CommunityBootstrapRequestV1,
    CommunityDomainBindingV1, CommunityDomainOpenedV1, MemoryCommunityDomainV1,
};
use crate::memory::MemoryStore;

type Fallible<T> = Result<T, Box<dyn StdError>>;
type TestResult = Fallible<()>;

const INCARNATION: [u8; 16] = [0x5a; 16];
const REGISTRY: Hash = Hash::from_bytes([31; 32]);
const POLICY_REVISION: Hash = Hash::from_bytes([32; 32]);
const CONSENT_REVISION: Hash = Hash::from_bytes([33; 32]);
const LEAF: Hash = Hash::from_bytes([34; 32]);
const OTHER_LEAF: Hash = Hash::from_bytes([35; 32]);
const CATALOGUE: Hash = Hash::from_bytes([36; 32]);
const NATIVE: Hash = Hash::from_bytes([37; 32]);
const SCHEMAS: Hash = Hash::from_bytes([38; 32]);
const HORIZON: u64 = 1_000_000_000;
const AUDIENCE: &str = "community-owner";
const CONTROL: [u8; 16] = [0xc1; 16];
const ANCHOR_GENERATION: [u8; 16] = [0x9a; 16];

const fn anchor_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([0x7e; 16]))
}

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

fn resource(incarnation: [u8; 16]) -> String {
    format!("community-metadata:{}", hex(&incarnation))
}

fn grant(grant_id: Hash, seq: u64) -> Fallible<CapabilityGrantV1> {
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec![resource(INCARNATION)],
        actions: vec!["inspect".to_owned(), "write".to_owned()],
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
        grant_id,
        grantor: principal(1)?,
        grantee: AuthorityGranteeV1::Principal(principal(2)?),
        trust_domain: "local.test".to_owned(),
        scope,
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

fn policy(compiled: Hash) -> Fallible<CommunityMetadataPolicyV1> {
    Ok(CommunityMetadataPolicyV1::new(
        CommunityMetadataPolicyInputV1 {
            metadata_owner_registry_binding: owner()?.registry_binding_digest(),
            metadata_authority_leaf_grant: LEAF,
            compiled_schema_catalogue_digest: compiled,
            metadata_not_after_micros: HORIZON,
        },
    )?)
}

struct World {
    domain: MemoryCommunityDomainV1,
    policy: CommunityMetadataPolicyV1,
    registry: AuthorityRegistrySnapshotV1,
    host: AuthorityPersistenceHostV1,
    grants: Vec<CapabilityGrantV1>,
}

impl World {
    fn new(grant_ids: &[Hash]) -> Fallible<Self> {
        let grants = grant_ids
            .iter()
            .zip(1..)
            .map(|(id, seq)| grant(*id, seq))
            .collect::<Fallible<Vec<_>>>()?;
        let mut bindings = grants
            .iter()
            .map(CapabilityGrantV1::binding_digest)
            .collect::<Result<Vec<_>, _>>()?;
        bindings.sort_unstable();
        let registry = AuthorityRegistrySnapshotV1::try_new(
            REGISTRY,
            vec![owner()?.registry_binding_digest()],
            bindings,
            vec![],
        )?;
        let host = AuthorityPersistenceHostV1::new(&registry);
        let mut store = MemoryStore::new();
        store.bind_authority_persistence(host.persistence_binding())?;
        for grant in &grants {
            store.issue_capability_grant(host.authorize_grant(grant)?, grant)?;
        }
        Ok(Self {
            domain: MemoryCommunityDomainV1::new(store, INCARNATION)?,
            policy: policy(SCHEMAS)?,
            registry,
            host,
            grants,
        })
    }

    fn decision_for(&self, leaf: Hash) -> Fallible<AuthorizationDecisionV1> {
        let persisted = self.domain.store.load_authority(leaf)?;
        let request = AuthorizationRequestV1::try_from_draft(AuthorizationRequestDraftV1 {
            authenticated: owner()?,
            actor_entity_id: actor(),
            subject_id: None,
            participant_id: None,
            plugin_id: None,
            installation_id: None,
            principal_role: AuthorityRoleV1::Actor,
            resource: resource(INCARNATION),
            data_category: "community.owner-metadata".to_owned(),
            action: "write".to_owned(),
            purpose: "owner-enforcement".to_owned(),
            audience: AUDIENCE.to_owned(),
            at_time: WallTime::from_micros(500),
            authority_timeline: authority_timeline(),
            at_position: persisted.head_position(),
            consent_timeline: None,
            consent_at_position: None,
            use_count: 1,
            budget: 1,
            consent_policy_revision: CONSENT_REVISION,
            capability_policy_revision: POLICY_REVISION,
            revocation_epoch: persisted.revocation_epoch(),
            revocation_state_current: true,
            authority_registry_digest: REGISTRY,
            consent: ConsentEvidenceV1::NotRequired,
            environment_constraints: vec![],
        })?;
        Ok(AuthorityEvaluatorV1::authorize(
            &request,
            persisted.chain(),
            &self.registry,
        ))
    }

    fn decision(&self) -> Fallible<AuthorizationDecisionV1> {
        self.decision_for(LEAF)
    }

    fn open_with(
        &mut self,
        request: CommunityBootstrapRequestV1,
        decision: &AuthorizationDecisionV1,
    ) -> Result<CommunityDomainOpenedV1, Error> {
        let binding = CommunityDomainBindingV1 {
            metadata_policy: &self.policy,
            installed_catalogue_digest: CATALOGUE,
            native_profile_digest: NATIVE,
        };
        self.domain.open(binding, request, decision)
    }

    fn open(&mut self, request: CommunityBootstrapRequestV1) -> Fallible<CommunityDomainOpenedV1> {
        let decision = self.decision()?;
        Ok(self.open_with(request, &decision)?)
    }

    fn record(&self) -> Fallible<&BootstrapRecordV1> {
        self.domain
            .bootstrap
            .as_ref()
            .ok_or_else(|| "bootstrap record expected".into())
    }

    fn record_mut(&mut self) -> Fallible<&mut BootstrapRecordV1> {
        self.domain
            .bootstrap
            .as_mut()
            .ok_or_else(|| "bootstrap record expected".into())
    }

    fn key(&self) -> Fallible<&VaultKeyV1> {
        let id = self.record()?.protection_id;
        self.domain
            .keys
            .get(&id)
            .ok_or_else(|| "bootstrap key expected".into())
    }

    fn revoke(&mut self, index: usize, fence: u64, epoch: u64) -> TestResult {
        let grant = &self.grants[index];
        let revocation = CapabilityRevocationV1::try_from_draft(CapabilityRevocationDraftV1 {
            grant_id: grant.grant_id(),
            authority_timeline: authority_timeline(),
            fence_position: Seq::from_u64(fence),
            revocation_epoch: epoch,
            policy_revision: POLICY_REVISION,
            authority_registry_digest: REGISTRY,
        })?;
        let permit = self.host.authorize_revocation(grant, &revocation)?;
        self.domain
            .store
            .revoke_capability_grant(permit, &revocation)?;
        Ok(())
    }
}

fn request() -> Fallible<CommunityBootstrapRequestV1> {
    Ok(CommunityBootstrapRequestV1::new(
        CONTROL,
        anchor_timeline(),
        ANCHOR_GENERATION,
    )?)
}

fn bootstrapped() -> Fallible<World> {
    let mut world = World::new(&[LEAF])?;
    assert_eq!(
        world.open(request()?)?,
        CommunityDomainOpenedV1::Bootstrapped
    );
    Ok(world)
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

fn oracle(domain: &[u8], preimage: &[u8]) -> Hash {
    let mut input = domain.to_vec();
    input.push(0);
    input.extend_from_slice(preimage);
    Hash::from_bytes(*blake3::hash(&input).as_bytes())
}

fn array(bytes: &[u8]) -> Fallible<Vec<Value>> {
    match ciborium::from_reader(bytes)? {
        Value::Array(values) => Ok(values),
        _ => Err("CBOR array expected".into()),
    }
}

fn bytes_of(value: &Value) -> Fallible<&[u8]> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err("CBOR byte string expected".into()),
    }
}

fn assert_unavailable(world: &mut World) -> TestResult {
    let decision = world.decision()?;
    assert_eq!(
        world.open_with(request()?, &decision),
        Err(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn incarnation_and_request_identities_must_be_nonzero() -> TestResult {
    assert_eq!(
        MemoryCommunityDomainV1::new(MemoryStore::new(), [0; 16]).err(),
        Some(Error::InvalidBinding)
    );
    let zero_timeline = TimelineId::from_ulid(Ulid::from_bytes([0; 16]));
    for (control, timeline, generation) in [
        ([0; 16], anchor_timeline(), ANCHOR_GENERATION),
        (CONTROL, zero_timeline, ANCHOR_GENERATION),
        (CONTROL, anchor_timeline(), [0; 16]),
    ] {
        assert_eq!(
            CommunityBootstrapRequestV1::new(control, timeline, generation).err(),
            Some(Error::InvalidBinding)
        );
    }
    let domain = MemoryCommunityDomainV1::new(MemoryStore::new(), INCARNATION)?;
    assert_eq!(domain.store_incarnation(), INCARNATION);
    assert!(!domain.is_bootstrapped());
    Ok(())
}

#[test]
fn empty_domain_bootstraps_exactly_one_intent_anchor_selection_and_copy() -> TestResult {
    let world = bootstrapped()?;
    let decision = world.decision()?;
    assert!(world.domain.is_bootstrapped());
    assert_eq!(world.domain.keys.len(), 1);
    let record = world.record()?;
    let key = world.key()?;
    let intent = key.intent().as_input();
    assert_eq!(intent.protection_operation_id, record.protection_id);
    assert!(intent.parent_operation == CommunityArtifactOperationV1::Control(CONTROL));
    assert_eq!(intent.timeline, anchor_timeline());
    assert_eq!(intent.generation, ANCHOR_GENERATION);
    assert!(intent.purpose == CommunityArtifactPurposeV1::LifecycleControl);
    assert_eq!(
        intent.scope_set_digest,
        oracle(b"PiglorOS.Community.ScopeSet.v1", &[0x80])
    );
    assert_eq!(intent.evidence_not_after_micros, HORIZON);
    assert_eq!(
        intent
            .allowed_record_kinds
            .iter()
            .map(CommunityArtifactKindV1::code)
            .collect::<Vec<_>>(),
        vec![6]
    );
    assert_eq!(intent.member_slots.iter().count(), 0);
    assert_ne!(intent.material_fingerprint, Hash::zero());
    assert_ne!(
        intent.material_fingerprint,
        pos_crypto::key_roles::key_material_digest(&[0; 32])
    );
    assert_eq!(intent.authority_request_digest, decision.request_digest());
    assert_eq!(key.burned_credits(), 2);
    assert_eq!(
        key.intent().key_owner_text(),
        format!(
            "community:{}:{}:3:c:{}",
            hex(&anchor_timeline().inner().to_bytes()),
            hex(&ANCHOR_GENERATION),
            hex(&record.protection_id)
        )
    );

    let anchor = CommunityMetadataAnchorV1::from_canonical_cbor(&record.anchor, &world.policy)?;
    assert_eq!(anchor.as_input().store_incarnation, INCARNATION);

    let selection_plain = key.open(&record.selection)?;
    let selection = CommunitySelectionV1::from_canonical_cbor(&selection_plain)?;
    let selection = selection.as_input();
    assert_eq!(selection.store_incarnation, INCARNATION);
    assert_eq!(selection.installed_catalogue_digest, CATALOGUE);
    assert_eq!(selection.native_profile_digest, NATIVE);
    assert_eq!(selection.highest_native_producer_ordinal, 0);
    assert!(selection.timeline_floors.is_empty());
    assert_eq!(selection.metadata_not_after_micros, HORIZON);

    let copy_plain = key.open(&record.key_copy)?;
    let copy = CommunityCopyInventoryV1::from_canonical_cbor(&copy_plain)?;
    let copy = copy.as_input();
    assert_eq!(copy.copy_id, record.copy_id);
    assert_eq!(copy.revision, 1);
    assert_eq!(copy.holder, CommunityCopyHolderV1::KeyVault);
    assert_eq!(copy.holder_digest, key.intent().digest());
    assert_eq!(copy.state, CommunityCopyStateV1::Owned);
    assert_eq!(copy.deadline_micros, HORIZON);
    assert!(copy.parent_operation == CommunityArtifactOperationV1::Control(CONTROL));
    Ok(())
}

#[test]
fn owner_commitment_matches_the_independent_adr128_preimage() -> TestResult {
    let world = bootstrapped()?;
    let record = world.record()?;
    let plaintext = world.key()?.open(&record.selection)?;
    let mut preimage = vec![0, 6];
    preimage.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    preimage.extend_from_slice(&plaintext);
    let expected = oracle(b"PiglorOS.Community.OwnerPlaintext.v1", &preimage);
    assert_eq!(record.selection.commitment, expected);
    assert_eq!(
        plaintext_commitment(CommunityArtifactKindV1::LifecycleControl, &plaintext),
        expected
    );
    assert_ne!(
        plaintext_commitment(CommunityArtifactKindV1::StateContent, &plaintext),
        expected
    );
    assert_eq!(
        private_digest(b"PiglorOS.Community.Test.v1", &[b"ab", b"c"]),
        oracle(b"PiglorOS.Community.Test.v1", b"abc")
    );
    assert_eq!(
        scope_set_digest(&[0x80]),
        oracle(b"PiglorOS.Community.ScopeSet.v1", &[0x80])
    );
    Ok(())
}

#[test]
fn cne1_identity_and_framing_match_the_independent_wire_oracle() -> TestResult {
    let world = bootstrapped()?;
    let record = world.record()?;
    let plaintext = world.key()?.open(&record.selection)?;
    let sealed = &record.selection;
    assert_eq!(
        sealed.address,
        oracle(
            b"PiglorOS.Community.NativeEvidenceEnvelope.v1",
            &sealed.envelope
        )
    );
    let cne1 = array(&sealed.envelope)?;
    assert_eq!(cne1.len(), 5);
    assert_eq!(bytes_of(&cne1[0])?, b"CNE1".as_slice());
    assert_eq!(cne1[1], Value::Integer(1.into()));
    assert_eq!(bytes_of(&cne1[2])?, b"CSI1".as_slice());
    let cover = bytes_of(&cne1[3])?;
    let cover_fields = array(cover)?;
    assert_eq!(bytes_of(&cover_fields[0])?, b"CSM1".as_slice());
    assert_eq!(bytes_of(&cover_fields[2])?, INCARNATION.as_slice());
    assert_eq!(
        bytes_of(&cover_fields[3])?,
        anchor_timeline().inner().to_bytes().as_slice()
    );
    assert_eq!(bytes_of(&cover_fields[4])?, ANCHOR_GENERATION.as_slice());
    assert_eq!(bytes_of(&cover_fields[5])?, record.protection_id.as_slice());
    assert_eq!(cover_fields[6], Value::Array(vec![]));
    assert_eq!(cover_fields[7], Value::Integer(HORIZON.into()));

    let envelope = array(bytes_of(&cne1[4])?)?;
    assert_eq!(envelope.len(), 5);
    assert_eq!(bytes_of(&envelope[0])?, b"COE1".as_slice());
    assert_eq!(bytes_of(&envelope[3])?.len(), 12);
    assert_eq!(bytes_of(&envelope[4])?.len(), plaintext.len() + 16);
    let header = array(bytes_of(&envelope[2])?)?;
    assert_eq!(header.len(), 13);
    assert_eq!(bytes_of(&header[0])?, b"COH1".as_slice());
    assert_eq!(header[4], Value::Integer(3.into()));
    assert_eq!(header[5], Value::Integer(2.into()));
    assert_eq!(bytes_of(&header[6])?, record.protection_id.as_slice());
    assert_eq!(header[7], Value::Integer(6.into()));
    assert_eq!(
        header[8],
        Value::Text(world.key()?.intent().key_owner_text().to_owned())
    );
    assert_eq!(header[9], Value::Integer(7.into()));
    assert_eq!(header[10], Value::Integer(1.into()));
    assert_eq!(
        bytes_of(&header[11])?,
        oracle(b"PiglorOS.Community.ScopeCover.v1", cover)
            .as_bytes()
            .as_slice()
    );
    assert_eq!(header[12], Value::Integer(HORIZON.into()));
    assert_ne!(record.selection.address, record.key_copy.address);
    Ok(())
}

#[test]
fn retrying_the_original_control_resolves_without_new_material() -> TestResult {
    let mut world = bootstrapped()?;
    let intent = world.key()?.intent().digest();
    let protection_id = world.record()?.protection_id;
    let selection = world.record()?.selection.address;
    assert_eq!(
        world.open(request()?)?,
        CommunityDomainOpenedV1::ResolvedOriginal
    );
    assert_eq!(world.domain.keys.len(), 1);
    assert_eq!(world.record()?.protection_id, protection_id);
    assert_eq!(world.key()?.intent().digest(), intent);
    assert_eq!(world.key()?.burned_credits(), 2);
    assert_eq!(world.record()?.selection.address, selection);

    let other = CommunityBootstrapRequestV1::new([0xc2; 16], anchor_timeline(), ANCHOR_GENERATION)?;
    assert_eq!(world.open(other)?, CommunityDomainOpenedV1::Existing);
    let moved = CommunityBootstrapRequestV1::new(CONTROL, anchor_timeline(), [0x9b; 16])?;
    let decision = world.decision()?;
    assert_eq!(world.open_with(moved, &decision), Err(Error::Conflict));
    assert_eq!(world.domain.keys.len(), 1);
    assert_eq!(world.key()?.intent().digest(), intent);
    Ok(())
}

#[test]
fn missing_grant_is_unavailable_and_creates_nothing() -> TestResult {
    let granted = World::new(&[LEAF])?;
    let decision = granted.decision()?;
    let mut world = World::new(&[OTHER_LEAF])?;
    assert_eq!(
        world.open_with(request()?, &decision),
        Err(Error::EvidenceUnavailable)
    );
    assert!(!world.domain.is_bootstrapped());
    assert!(world.domain.keys.is_empty());
    Ok(())
}

#[test]
fn revoked_grant_decision_is_unavailable() -> TestResult {
    let mut world = World::new(&[LEAF])?;
    world.revoke(0, 2, 1)?;
    let decision = world.decision()?;
    assert_eq!(decision.outcome(), AuthorizationOutcomeV1::RevokedAtFence);
    assert_eq!(decision.grant_id(), Some(LEAF));
    assert_unavailable(&mut world)?;
    assert!(world.domain.keys.is_empty());
    Ok(())
}

#[test]
fn decision_for_another_leaf_is_unavailable() -> TestResult {
    let mut world = World::new(&[LEAF, OTHER_LEAF])?;
    let decision = world.decision_for(OTHER_LEAF)?;
    assert!(decision.is_allowed());
    assert_eq!(
        decision.at_position(),
        world
            .domain
            .metadata_authority(&world.policy)?
            .head_position()
    );
    assert_eq!(
        world.open_with(request()?, &decision),
        Err(Error::EvidenceUnavailable)
    );
    assert!(world.domain.keys.is_empty());
    Ok(())
}

#[test]
fn stale_decision_is_unavailable() -> TestResult {
    let mut world = World::new(&[LEAF, OTHER_LEAF])?;
    let stale = world.decision()?;
    assert!(stale.is_allowed());
    world.revoke(1, 3, 1)?;
    assert_eq!(
        world.open_with(request()?, &stale),
        Err(Error::EvidenceUnavailable)
    );
    assert!(world.domain.keys.is_empty());
    Ok(())
}

#[test]
fn missing_or_conflicting_key_intent_is_unavailable() -> TestResult {
    let mut world = bootstrapped()?;
    let id = world.record()?.protection_id;
    let original = world
        .domain
        .keys
        .remove(&id)
        .ok_or("bootstrap key expected")?;
    assert_unavailable(&mut world)?;

    let ids = BootstrapRecordIds {
        request: CommunityBootstrapRequestV1::new(
            [0xc3; 16],
            anchor_timeline(),
            ANCHOR_GENERATION,
        )?,
        protection_id: id,
        copy_id: [1; 16],
    };
    let conflicting = VaultKeyV1::provision(bootstrap_intent(&ids, HORIZON, LEAF))?;
    world.domain.keys.insert(id, conflicting);
    assert_unavailable(&mut world)?;

    world.domain.keys.insert(id, original);
    assert_eq!(
        world.open(request()?)?,
        CommunityDomainOpenedV1::ResolvedOriginal
    );
    Ok(())
}

#[test]
fn missing_or_conflicting_anchor_is_unavailable() -> TestResult {
    let mut world = bootstrapped()?;
    let original = std::mem::take(&mut world.record_mut()?.anchor);
    assert_unavailable(&mut world)?;

    let foreign = policy(Hash::from_bytes([40; 32]))?;
    let cases = [
        (INCARNATION, anchor_timeline(), ANCHOR_GENERATION, &foreign),
        (
            [0x5b; 16],
            anchor_timeline(),
            ANCHOR_GENERATION,
            &world.policy,
        ),
        (
            INCARNATION,
            TimelineId::from_ulid(Ulid::from_bytes([0x7f; 16])),
            ANCHOR_GENERATION,
            &world.policy,
        ),
        (INCARNATION, anchor_timeline(), [0x9b; 16], &world.policy),
    ]
    .into_iter()
    .map(|(incarnation, timeline, generation, policy)| {
        CommunityMetadataAnchorV1::new(incarnation, timeline, generation, policy)
            .map(|anchor| anchor.to_canonical_cbor())
    })
    .collect::<Result<Vec<_>, _>>()?;
    for anchor in cases {
        world.record_mut()?.anchor = anchor;
        assert_unavailable(&mut world)?;
    }
    world.record_mut()?.anchor = original;
    assert_eq!(
        world.open(request()?)?,
        CommunityDomainOpenedV1::ResolvedOriginal
    );
    Ok(())
}

#[test]
fn missing_or_conflicting_selection_is_unavailable() -> TestResult {
    let mut world = bootstrapped()?;
    let record = world.record_mut()?;
    std::mem::swap(&mut record.selection, &mut record.key_copy);
    assert_unavailable(&mut world)?;
    let record = world.record_mut()?;
    std::mem::swap(&mut record.selection, &mut record.key_copy);

    let address = world.record()?.selection.address;
    world.record_mut()?.selection.address = Hash::zero();
    assert_unavailable(&mut world)?;
    world.record_mut()?.selection.address = address;

    let commitment = world.record()?.selection.commitment;
    world.record_mut()?.selection.commitment = Hash::zero();
    assert_unavailable(&mut world)?;
    world.record_mut()?.selection.commitment = commitment;

    let decision = world.decision()?;
    let policy = policy(SCHEMAS)?;
    for (catalogue, native) in [
        (Hash::from_bytes([41; 32]), NATIVE),
        (CATALOGUE, Hash::from_bytes([42; 32])),
    ] {
        let binding = CommunityDomainBindingV1 {
            metadata_policy: &policy,
            installed_catalogue_digest: catalogue,
            native_profile_digest: native,
        };
        assert_eq!(
            world.domain.open(binding, request()?, &decision),
            Err(Error::EvidenceUnavailable)
        );
    }
    assert_eq!(
        world.open(request()?)?,
        CommunityDomainOpenedV1::ResolvedOriginal
    );
    Ok(())
}

#[test]
fn selection_from_another_incarnation_is_unavailable() -> TestResult {
    let mut world = bootstrapped()?;
    let decision = world.decision()?;
    let foreign = [0x5b; 16];
    world.domain.store_incarnation = foreign;
    world.record_mut()?.anchor = CommunityMetadataAnchorV1::new(
        foreign,
        anchor_timeline(),
        ANCHOR_GENERATION,
        &world.policy,
    )?
    .to_canonical_cbor();
    assert_eq!(
        world.open_with(request()?, &decision),
        Err(Error::EvidenceUnavailable)
    );
    Ok(())
}

#[test]
fn missing_or_conflicting_copy_record_is_unavailable() -> TestResult {
    let mut world = bootstrapped()?;
    let copy_id = world.record()?.copy_id;
    world.record_mut()?.copy_id = [2; 16];
    assert_unavailable(&mut world)?;
    world.record_mut()?.copy_id = copy_id;

    let selection = world.record()?.selection.envelope.clone();
    let address = world.record()?.selection.address;
    let commitment = world.record()?.selection.commitment;
    let record = world.record_mut()?;
    let original = std::mem::replace(
        &mut record.key_copy,
        super::SealedMetadataV1 {
            envelope: selection,
            address,
            commitment,
        },
    );
    assert_unavailable(&mut world)?;
    world.record_mut()?.key_copy = original;
    assert_eq!(
        world.open(request()?)?,
        CommunityDomainOpenedV1::ResolvedOriginal
    );
    Ok(())
}

#[test]
fn bootstrap_key_is_decrypt_only_and_burns_a_credit_per_attempt() -> TestResult {
    let mut world = bootstrapped()?;
    let id = world.record()?.protection_id;
    let scope_input = CommunityMetadataScopeInputV1 {
        store_incarnation: INCARNATION,
        metadata_anchor_timeline: anchor_timeline(),
        metadata_anchor_generation: ANCHOR_GENERATION,
        protection_operation_id: id,
        scope_members: CommunityScopeMembersV1::from_members(&[]),
        metadata_not_after_micros: HORIZON,
    };
    let scope = CommunityMetadataScopeV1::new(scope_input)?;
    let key = world
        .domain
        .keys
        .get_mut(&id)
        .ok_or("bootstrap key expected")?;
    assert_eq!(
        key.seal(&scope, CommunityMetadataSchemaV1::Csi1, b"late")
            .err(),
        Some(Error::CapacityExhausted)
    );
    assert_eq!(key.burned_credits(), 3);
    let other = VaultKeyV1::provision(bootstrap_intent(
        &BootstrapRecordIds {
            request: request()?,
            protection_id: [3; 16],
            copy_id: [4; 16],
        },
        HORIZON,
        LEAF,
    ))?;
    assert_ne!(
        other.intent().as_input().material_fingerprint,
        world.key()?.intent().as_input().material_fingerprint
    );
    assert_eq!(other.burned_credits(), 0);
    Ok(())
}
