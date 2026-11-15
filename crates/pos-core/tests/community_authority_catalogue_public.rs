//! CAP1, the pinned R6.4 vectors, the stable member digest and the two
//! read-only R6.2(5) authority helpers (ADR-129 revision 6).
//!
//! Wire oracles are built with `ciborium` and digests with `blake3` directly
//! from the ADR field lists, not from the implementation's encoders.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    community_authentication_nonce_v1, community_capability_attestation_digest_v1,
    CommunityActorRowV1 as Row, CommunityAuthorityCatalogueInputV1 as Input,
    CommunityAuthorityCatalogueV1 as Catalogue, CommunityLifecycleErrorV1 as Error,
    CommunityMemberBindingInputV1 as MemberInput, CommunityMemberBindingV1 as Member,
    COMMUNITY_AUD_SCHEMA_V1, COMMUNITY_PRINCIPAL_SCHEMA_V1, MAX_COMMUNITY_ACTOR_ROWS_V1,
    MAX_COMMUNITY_AUTHORITY_CATALOGUE_BYTES_V1,
};
use pos_core::{
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, CapabilityGrantDraftV1, CapabilityGrantV1,
    CapabilityRevocationDraftV1, CapabilityRevocationV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    EntityId, Hash, ImplementationKeyV1, PrincipalRefV1, Seq, TimelineId,
};
use ulid::Ulid;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn entity(value: u8) -> EntityId {
    EntityId::from_ulid(Ulid::from_bytes([value; 16]))
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

fn unhex(value: &str) -> Fallible<Vec<u8>> {
    (0..value.len())
        .step_by(2)
        .map(|at| Ok(u8::from_str_radix(&value[at..at + 2], 16)?))
        .collect()
}

/// ADR-129 §2 `H(M, bytes)`: BLAKE3 of `PiglorOS.Community.<M>.v1`, a zero
/// byte, then the bytes.
fn adr_h(m: &str, preimage: &[u8]) -> Hash {
    let mut input = b"PiglorOS.Community.".to_vec();
    input.extend_from_slice(m.as_bytes());
    input.extend_from_slice(b".v1\0");
    input.extend_from_slice(preimage);
    Hash::from_bytes(*blake3::hash(&input).as_bytes())
}

fn row(digest: u8, actor: u8) -> Row {
    Row {
        principal_digest: hash(digest),
        actor_entity_id: entity(actor),
    }
}

fn input() -> Input {
    Input {
        fap1_digest: hash(1),
        audience: "community-host".to_owned(),
        actor_rows: vec![row(2, 3), row(4, 5)],
        capability_policy_revision: hash(6),
        consent_policy_revision: hash(7),
        authority_registry_digest: hash(8),
        capability_attestation_digest: hash(9),
        trust_scope: "community.trust".to_owned(),
    }
}

fn oracle(input: &Input) -> Fallible<Vec<u8>> {
    encode(&Value::Array(vec![
        bytes(b"CAP1"),
        uint(1),
        Value::Array(vec![text("pos.community.authority-mapping"), uint(6)]),
        bytes(input.fap1_digest.as_bytes()),
        text(&input.audience),
        Value::Array(
            input
                .actor_rows
                .iter()
                .map(|row| {
                    Value::Array(vec![
                        bytes(row.principal_digest.as_bytes()),
                        bytes(&row.actor_entity_id.inner().to_bytes()),
                    ])
                })
                .collect(),
        ),
        bytes(input.capability_policy_revision.as_bytes()),
        bytes(input.consent_policy_revision.as_bytes()),
        bytes(input.authority_registry_digest.as_bytes()),
        bytes(input.capability_attestation_digest.as_bytes()),
        text(&input.trust_scope),
        uint(0x4341_0002),
        uint(0x4341_0003),
    ]))
}

#[test]
fn cap1_encodes_the_thirteen_adr_fields_and_its_digest() -> TestResult {
    let catalogue = Catalogue::new(input())?;
    let encoded = catalogue.to_canonical_cbor();
    assert_eq!(encoded, oracle(&input())?);
    assert_eq!(catalogue.digest(), adr_h("CAP1", &encoded));
    assert_eq!(catalogue.as_input(), &input());
    assert_eq!(COMMUNITY_AUD_SCHEMA_V1, 0x4341_0002);
    assert_eq!(COMMUNITY_PRINCIPAL_SCHEMA_V1, 0x4341_0003);
    Ok(())
}

#[test]
fn cap1_maps_only_its_listed_principals_to_actors() -> TestResult {
    let catalogue = Catalogue::new(input())?;
    assert_eq!(catalogue.actor_for(hash(2)), Some(entity(3)));
    assert_eq!(catalogue.actor_for(hash(4)), Some(entity(5)));
    for absent in [1, 3, 5] {
        assert_eq!(catalogue.actor_for(hash(absent)), None);
    }
    Ok(())
}

#[test]
fn cap1_text_and_row_bounds_hold_at_the_limit_and_one_over() -> TestResult {
    let at_limit = Input {
        audience: "a".repeat(128),
        trust_scope: "s".repeat(128),
        actor_rows: (1..=64).map(|value| row(value, value)).collect(),
        ..input()
    };
    let widest = Catalogue::new(at_limit.clone())?;
    let encoded = widest.to_canonical_cbor();
    assert_eq!(encoded, oracle(&at_limit)?);
    assert!(encoded.len() <= MAX_COMMUNITY_AUTHORITY_CATALOGUE_BYTES_V1);
    assert_eq!(MAX_COMMUNITY_ACTOR_ROWS_V1, 64);
    for bounded in [
        Input {
            audience: String::new(),
            ..input()
        },
        Input {
            audience: "a".repeat(129),
            ..input()
        },
        Input {
            actor_rows: vec![],
            ..input()
        },
        Input {
            actor_rows: (1..=65).map(|value| row(value, value)).collect(),
            ..input()
        },
    ] {
        assert_eq!(Catalogue::new(bounded), Err(Error::BoundsExceeded));
    }
    Ok(())
}

#[test]
fn cap1_refuses_zero_links_bad_rows_and_an_invalid_trust_scope() {
    let zero = Hash::zero();
    for invalid in [
        Input {
            fap1_digest: zero,
            ..input()
        },
        Input {
            capability_policy_revision: zero,
            ..input()
        },
        Input {
            consent_policy_revision: zero,
            ..input()
        },
        Input {
            authority_registry_digest: zero,
            ..input()
        },
        Input {
            capability_attestation_digest: zero,
            ..input()
        },
        Input {
            actor_rows: vec![Row {
                principal_digest: zero,
                actor_entity_id: entity(3),
            }],
            ..input()
        },
        Input {
            actor_rows: vec![row(2, 0)],
            ..input()
        },
        Input {
            actor_rows: vec![row(4, 5), row(2, 3)],
            ..input()
        },
        Input {
            actor_rows: vec![row(2, 3), row(2, 5)],
            ..input()
        },
        Input {
            trust_scope: String::new(),
            ..input()
        },
        Input {
            trust_scope: "Community".to_owned(),
            ..input()
        },
        Input {
            trust_scope: "s".repeat(129),
            ..input()
        },
    ] {
        assert_eq!(Catalogue::new(invalid), Err(Error::InvalidBinding));
    }
}

/// R6.4 V6: registry `44`×32 and one binding `55`×32.
#[test]
fn attestation_digest_reproduces_vector_v6() -> TestResult {
    let snapshot = AuthorityRegistrySnapshotV1::try_new(
        Hash::from_bytes([0x44; 32]),
        vec![hash(1)],
        vec![Hash::from_bytes([0x55; 32])],
        vec![],
    )?;
    let mut preimage = unhex("825820")?;
    preimage.extend_from_slice(&[0x44; 32]);
    preimage.extend_from_slice(&unhex("815820")?);
    preimage.extend_from_slice(&[0x55; 32]);
    assert_eq!(preimage.len(), 70);
    let digest = community_capability_attestation_digest_v1(&snapshot);
    assert_eq!(digest, adr_h("CapabilityAttestation", &preimage));
    assert_eq!(
        digest.as_bytes().to_vec(),
        unhex("74406e84a516d0bdd7160edf6f3e0b9820dc0c281f7c1a4b736a75230a9437a6")?
    );
    Ok(())
}

#[test]
fn attestation_digest_binds_every_sorted_binding_and_the_registry() -> TestResult {
    let snapshot = |registry: u8, bindings: Vec<Hash>| {
        AuthorityRegistrySnapshotV1::try_new(hash(registry), vec![hash(1)], bindings, vec![])
    };
    let both = snapshot(2, vec![hash(3), hash(4)])?;
    let oracle = encode(&Value::Array(vec![
        bytes(hash(2).as_bytes()),
        Value::Array(vec![bytes(hash(3).as_bytes()), bytes(hash(4).as_bytes())]),
    ]))?;
    assert_eq!(
        community_capability_attestation_digest_v1(&both),
        adr_h("CapabilityAttestation", &oracle)
    );
    assert_eq!(both.capability_bindings(), &[hash(3), hash(4)]);
    for other in [
        snapshot(2, vec![hash(3)])?,
        snapshot(5, vec![hash(3), hash(4)])?,
        snapshot(2, vec![])?,
    ] {
        assert_ne!(
            community_capability_attestation_digest_v1(&other),
            community_capability_attestation_digest_v1(&both)
        );
    }
    Ok(())
}

/// R6.4 V3: T = `000102…0f`, k = `i`, O = `101112…1f`, H(CAP1) = `33`×32.
#[test]
fn authentication_nonce_reproduces_vector_v3() -> TestResult {
    let resource = "community:000102030405060708090a0b0c0d0e0f:lifecycle";
    let constraint = "community.operation:i:101112131415161718191a1b1c1d1e1f";
    let action = "community.initialize.v1";
    assert_eq!((resource.len(), constraint.len()), (52, 54));
    let mut preimage = unhex("845820")?;
    preimage.extend_from_slice(&[0x33; 32]);
    preimage.extend_from_slice(&unhex("7834")?);
    preimage.extend_from_slice(resource.as_bytes());
    preimage.push(0x77);
    preimage.extend_from_slice(action.as_bytes());
    preimage.extend_from_slice(&unhex("7836")?);
    preimage.extend_from_slice(constraint.as_bytes());
    assert_eq!(preimage.len(), 169);
    let nonce = community_authentication_nonce_v1(
        Hash::from_bytes([0x33; 32]),
        resource,
        action,
        constraint,
    );
    assert_eq!(&nonce, adr_h("AuthenticationNonce", &preimage).as_bytes());
    assert_eq!(
        nonce.to_vec(),
        unhex("3a72b211788b6606dbd3b6dffe30726554a9408302adf27ac2bf8694e5533fe7")?
    );
    let base = (Hash::from_bytes([0x33; 32]), resource, action, constraint);
    for (catalogue, resource, action, constraint) in [
        (hash(1), base.1, base.2, base.3),
        (
            base.0,
            "community:000102030405060708090a0b0c0d0e0e:lifecycle",
            base.2,
            base.3,
        ),
        (base.0, base.1, "community.transition.v1", base.3),
        (
            base.0,
            base.1,
            base.2,
            "community.operation:c:101112131415161718191a1b1c1d1e1f",
        ),
    ] {
        assert_ne!(
            community_authentication_nonce_v1(catalogue, resource, action, constraint),
            nonce
        );
    }
    Ok(())
}

#[test]
fn stable_member_digest_hashes_the_stable_entry_and_exact_imk1() -> TestResult {
    const fn member_input(implementation: &ImplementationKeyV1) -> MemberInput<'_> {
        MemberInput {
            stable_entry: "Entry-A_1",
            implementation,
            pmf1_digest: hash(4),
            state_schema_digest: hash(5),
            negotiated_tuple_digest: hash(6),
            initial_state_content_digest: hash(7),
            protected_owner_binding_digest: hash(8),
        }
    }
    let implementation = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(3))?;
    let member = Member::new(member_input(&implementation))?;
    let imk1 = encode(&Value::Array(vec![
        bytes(b"IMK1"),
        uint(1),
        text("plugin-a"),
        text("host-v1"),
        bytes(hash(3).as_bytes()),
    ]))?;
    let preimage = encode(&Value::Array(vec![text("Entry-A_1"), bytes(&imk1)]))?;
    assert_eq!(
        member.stable_member_digest(),
        adr_h("StableMember", &preimage)
    );
    assert_ne!(member.stable_member_digest(), member.digest());

    let release = ImplementationKeyV1::new("plugin-a".into(), "host-v1".into(), hash(9))?;
    let released = Member::new(member_input(&release))?;
    assert_ne!(
        released.stable_member_digest(),
        member.stable_member_digest()
    );
    let same_entry = Member::new(MemberInput {
        initial_state_content_digest: hash(10),
        ..member_input(&implementation)
    })?;
    assert_eq!(
        same_entry.stable_member_digest(),
        member.stable_member_digest()
    );
    Ok(())
}

const REGISTRY: Hash = hash(31);
const POLICY: Hash = hash(32);

fn authority_timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([7; 16]))
}

fn principal(value: u8) -> Fallible<PrincipalRefV1> {
    Ok(PrincipalRefV1::try_new([value; 16], "local.test")?)
}

fn grant(
    id: u8,
    seq: u64,
    epoch: u64,
    parent: Option<&CapabilityGrantV1>,
) -> Fallible<CapabilityGrantV1> {
    let scope = CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["world".to_owned()],
        actions: vec!["act".to_owned(), pos_core::DELEGATE_ACTION_V1.to_owned()],
        purposes: vec!["simulation".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![entity(8)],
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
        grantor: parent.map_or_else(
            || principal(1),
            |parent| Ok(parent.grantee().principal().clone()),
        )?,
        grantee: AuthorityGranteeV1::Principal(principal(id)?),
        trust_domain: "local.test".to_owned(),
        scope,
        valid_from_position: Seq::from_u64(seq),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: parent.map(CapabilityGrantV1::grant_id),
        delegation_depth: u8::from(parent.is_some()),
        max_delegation_depth: 1,
        permitted_delegate_classes: vec![pos_core::DelegateClassV1::Principal],
        consent_references: vec![],
        policy_revision: POLICY,
        issuance_timeline: authority_timeline(),
        issuance_seq: Seq::from_u64(seq),
        revocation_epoch: epoch,
        revocation_fence: None,
        authority_registry_digest: REGISTRY,
    })?)
}

fn revocation(
    grant: &CapabilityGrantV1,
    fence: u64,
    epoch: u64,
) -> Fallible<CapabilityRevocationV1> {
    Ok(CapabilityRevocationV1::try_from_draft(
        CapabilityRevocationDraftV1 {
            grant_id: grant.grant_id(),
            authority_timeline: authority_timeline(),
            fence_position: Seq::from_u64(fence),
            revocation_epoch: epoch,
            policy_revision: POLICY,
            authority_registry_digest: REGISTRY,
        },
    )?)
}

fn sorted_bindings(grants: &[&CapabilityGrantV1]) -> Fallible<Vec<Hash>> {
    let mut bindings = grants
        .iter()
        .map(|grant| grant.binding_digest())
        .collect::<Result<Vec<_>, _>>()?;
    bindings.sort_unstable();
    Ok(bindings)
}

/// R6.2(5): a loaded chain is re-stamped with the current epoch and fences,
/// while `issued_binding_digests` returns each grant exactly as it was
/// issued: no fence, and the epoch counting only earlier revocations.
#[test]
fn issued_bindings_undo_the_revocation_re_stamp_in_chain_order() -> TestResult {
    let sibling = grant(2, 1, 0, None)?;
    let root = grant(3, 2, 0, None)?;
    let early_leaf = grant(4, 3, 0, Some(&root))?;
    let sibling_revocation = revocation(&sibling, 4, 1)?;
    let late_leaf = grant(5, 5, 1, Some(&root))?;
    let leaf_revocation = revocation(&early_leaf, 6, 2)?;
    let all = [&sibling, &root, &early_leaf, &late_leaf];
    let registry = AuthorityRegistrySnapshotV1::try_new(
        REGISTRY,
        vec![hash(40)],
        sorted_bindings(&all)?,
        vec![],
    )?;
    let host = AuthorityPersistenceHostV1::new(&registry);
    let mut state = AuthorityPersistenceStateV1::new();
    for grant in [&sibling, &root, &early_leaf] {
        state.issue_grant(host.authorize_grant(grant)?, grant.clone())?;
    }
    let before = state.resolve(early_leaf.grant_id())?;
    assert_eq!(
        before.issued_binding_digests()?,
        vec![root.binding_digest()?, early_leaf.binding_digest()?]
    );
    state.revoke_grant(
        host.authorize_revocation(&sibling, &sibling_revocation)?,
        sibling_revocation,
    )?;
    state.issue_grant(host.authorize_grant(&late_leaf)?, late_leaf.clone())?;
    state.revoke_grant(
        host.authorize_revocation(&early_leaf, &leaf_revocation)?,
        leaf_revocation,
    )?;

    for (leaf, expected) in [(&early_leaf, &early_leaf), (&late_leaf, &late_leaf)] {
        let persisted = state.resolve(leaf.grant_id())?;
        let current = persisted
            .chain()
            .grants()
            .iter()
            .map(CapabilityGrantV1::binding_digest)
            .collect::<Result<Vec<_>, _>>()?;
        assert_ne!(
            current,
            vec![root.binding_digest()?, expected.binding_digest()?]
        );
        assert_eq!(
            persisted.issued_binding_digests()?,
            vec![root.binding_digest()?, expected.binding_digest()?]
        );
    }
    Ok(())
}

#[test]
fn capability_bindings_return_the_sorted_attested_set() -> TestResult {
    let snapshot = AuthorityRegistrySnapshotV1::try_new(
        REGISTRY,
        vec![hash(40)],
        vec![hash(2), hash(9)],
        vec![],
    )?;
    assert_eq!(snapshot.capability_bindings(), &[hash(2), hash(9)]);
    let empty = AuthorityRegistrySnapshotV1::try_new(REGISTRY, vec![hash(40)], vec![], vec![])?;
    assert!(empty.capability_bindings().is_empty());
    Ok(())
}
