use ciborium::Value;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityErrorV1, AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorityRegistrySnapshotV1,
    AuthorityRoleV1, AuthorizationDecisionV1, AuthorizationOutcomeV1, AuthorizationRequestDraftV1,
    AuthorizationRequestV1, CanonicalBytes, CapabilityGrantDraftV1, CapabilityGrantV1,
    CapabilityScopeDraftV1, CapabilityScopeV1, ConsentEvidenceV1, ConsentGrantRefDraftV1,
    ConsentGrantRefV1, DelegateClassV1, EntityId, Hash, PluginId, PrincipalRefV1, Seq, TimelineId,
    WallTime, DELEGATE_ACTION_V1, MAX_AUTHORITY_DELEGATION_DEPTH, MAX_AUTHORITY_SELECTORS,
    MAX_AUTHORITY_TEXT_BYTES,
};
use ulid::Ulid;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

fn entity(value: u128) -> EntityId {
    EntityId::from_ulid(Ulid::from(value))
}

fn plugin(value: u128) -> PluginId {
    PluginId::from_ulid(Ulid::from(value))
}

fn timeline(value: u128) -> TimelineId {
    TimelineId::from_ulid(Ulid::from(value))
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn principal(value: u8) -> PrincipalRefV1 {
    ok(PrincipalRefV1::try_new([value; 16], "local.test"))
}

fn authenticated(principal: PrincipalRefV1) -> AuthenticatedPrincipalResultV1 {
    ok(AuthenticatedPrincipalResultV1::try_from_draft(
        AuthenticatedPrincipalDraftV1 {
            principal,
            adapter_id: "test-passkey".to_owned(),
            assurance: ok(AssuranceLevelV1::try_new(2)),
            issued_at: WallTime::from_micros(10),
            expires_at: WallTime::from_micros(100),
            binding_digest: hash(7),
        },
    ))
}

fn consent_grant() -> ConsentGrantRefV1 {
    consent_grant_with_id(8)
}

fn consent_grant_with_id(consent_id: u8) -> ConsentGrantRefV1 {
    ok(ConsentGrantRefV1::try_from_draft(consent_draft(consent_id)))
}

fn consent_draft(consent_id: u8) -> ConsentGrantRefDraftV1 {
    ConsentGrantRefDraftV1 {
        consent_id: hash(consent_id),
        subject_id: entity(50),
        data_categories: vec!["profile".to_owned()],
        purposes: vec!["care".to_owned(), "planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        action_classes: vec!["read".to_owned()],
        valid_from: WallTime::from_micros(10),
        valid_until: WallTime::from_micros(100),
        withdrawal_retention_policy: "erase-derived-data".to_owned(),
        policy_revision: hash(9),
        issuer: principal(4),
        issuer_evidence: hash(6),
        revocation_fence: None,
        authority_registry_digest: hash(7),
    }
}

fn scope(
    actor_entity_ids: Vec<EntityId>,
    actions: Vec<&str>,
    plugin_id: Option<PluginId>,
) -> CapabilityScopeV1 {
    scope_with_subjects(actor_entity_ids, vec![entity(50)], actions, plugin_id)
}

fn scope_with_subjects(
    actor_entity_ids: Vec<EntityId>,
    subject_ids: Vec<EntityId>,
    actions: Vec<&str>,
    plugin_id: Option<PluginId>,
) -> CapabilityScopeV1 {
    scope_for_role(
        actor_entity_ids,
        subject_ids,
        actions,
        plugin_id,
        AuthorityRoleV1::Actor,
    )
}

fn scope_for_role(
    actor_entity_ids: Vec<EntityId>,
    subject_ids: Vec<EntityId>,
    actions: Vec<&str>,
    plugin_id: Option<PluginId>,
    principal_role: AuthorityRoleV1,
) -> CapabilityScopeV1 {
    ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["journal".to_owned(), "profile".to_owned()],
        actions: actions.into_iter().map(str::to_owned).collect(),
        purposes: vec!["care".to_owned(), "planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids,
        subject_ids,
        participant_ids: vec![entity(20)],
        plugin_id,
        principal_roles: vec![principal_role],
        max_uses: 10,
        budget: 100,
        environment_constraints: vec!["device-bound".to_owned(), "local-only".to_owned()],
    }))
}

fn grant_draft(
    grant_id: u8,
    grantor: PrincipalRefV1,
    grantee: AuthorityGranteeV1,
    scope: CapabilityScopeV1,
) -> CapabilityGrantDraftV1 {
    CapabilityGrantDraftV1 {
        grant_id: hash(grant_id),
        grantor,
        grantee,
        scope,
        valid_from_position: Seq::from_u64(10),
        valid_until_position: Seq::from_u64(100),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 2,
        permitted_delegate_classes: vec![DelegateClassV1::Principal],
        consent_references: vec![hash(8)],
        policy_revision: hash(9),
        issuance_timeline: timeline(30),
        issuance_seq: Seq::from_u64(5),
        revocation_epoch: 3,
        revocation_fence: None,
        authority_registry_digest: hash(7),
    }
}

fn root_grant(principal: PrincipalRefV1, actor_ids: Vec<EntityId>) -> CapabilityGrantV1 {
    ok(CapabilityGrantV1::try_from_draft(grant_draft(
        1,
        principal.clone(),
        AuthorityGranteeV1::Principal(principal),
        scope(actor_ids, vec![DELEGATE_ACTION_V1, "read"], None),
    )))
}

fn delegation_parent() -> CapabilityGrantV1 {
    ok(CapabilityGrantV1::try_from_draft(grant_draft(
        1,
        principal(1),
        AuthorityGranteeV1::Principal(principal(2)),
        scope(
            vec![entity(10), entity(11)],
            vec![DELEGATE_ACTION_V1, "read"],
            None,
        ),
    )))
}

fn delegation_child() -> CapabilityGrantDraftV1 {
    let mut draft = grant_draft(
        2,
        principal(2),
        AuthorityGranteeV1::Principal(principal(3)),
        scope(vec![entity(10)], vec!["read"], None),
    );
    draft.parent_grant_id = Some(hash(1));
    draft.delegation_depth = 1;
    draft.max_delegation_depth = 1;
    draft.valid_from_position = Seq::from_u64(20);
    draft.valid_until_position = Seq::from_u64(90);
    draft
}

fn assert_delegation_invalid(child: CapabilityGrantDraftV1) {
    assert_eq!(
        decision_for(
            &request(principal(3), entity(10)),
            &[
                delegation_parent(),
                ok(CapabilityGrantV1::try_from_draft(child)),
            ],
        )
        .outcome(),
        AuthorizationOutcomeV1::DelegationInvalid
    );
}

fn request_draft(
    authenticated: AuthenticatedPrincipalResultV1,
    actor_entity_id: EntityId,
) -> AuthorizationRequestDraftV1 {
    AuthorizationRequestDraftV1 {
        authenticated,
        actor_entity_id,
        subject_id: Some(entity(50)),
        participant_id: Some(entity(20)),
        plugin_id: None,
        installation_id: None,
        principal_role: AuthorityRoleV1::Actor,
        resource: "journal".to_owned(),
        data_category: "profile".to_owned(),
        action: "read".to_owned(),
        purpose: "care".to_owned(),
        audience: "local-host".to_owned(),
        at_time: WallTime::from_micros(50),
        authority_timeline: timeline(30),
        at_position: Seq::from_u64(50),
        use_count: 2,
        budget: 50,
        policy_revision: hash(9),
        revocation_epoch: 3,
        revocation_state_current: true,
        authority_registry_digest: hash(7),
        consent: ConsentEvidenceV1::Active {
            grants: vec![consent_grant()],
        },
        environment_constraints: vec!["device-bound".to_owned(), "local-only".to_owned()],
    }
}

fn request(principal: PrincipalRefV1, actor_entity_id: EntityId) -> AuthorizationRequestV1 {
    ok(AuthorizationRequestV1::try_from_draft(request_draft(
        authenticated(principal),
        actor_entity_id,
    )))
}

fn decision_for(
    request: &AuthorizationRequestV1,
    chain: &[CapabilityGrantV1],
) -> AuthorizationDecisionV1 {
    let mut capability_bindings: Vec<_> = chain
        .iter()
        .map(|grant| ok(grant.binding_digest()))
        .collect();
    capability_bindings.sort_unstable();
    let consent_bindings = match request.consent() {
        ConsentEvidenceV1::Active { grants } => grants
            .iter()
            .map(ConsentGrantRefV1::binding_digest)
            .collect(),
        _ => Vec::new(),
    };
    let trusted_registry = ok(AuthorityRegistrySnapshotV1::try_new(
        hash(7),
        vec![hash(7)],
        capability_bindings,
        consent_bindings,
    ));
    let decision = AuthorityEvaluatorV1::authorize(request, chain, &trusted_registry);
    assert_eq!(
        ok(AuthorizationDecisionV1::decode(&ok(decision.encode()))),
        decision
    );
    decision
}

fn encode_value(value: &Value) -> CanonicalBytes {
    let mut bytes = Vec::new();
    ok(ciborium::into_writer(value, &mut bytes));
    CanonicalBytes::from_vec(bytes)
}

fn array_fields(value: Value) -> Vec<Value> {
    match value {
        Value::Array(fields) => fields,
        _ => std::panic::resume_unwind(Box::new(
            "public authority encoding must be an array".to_owned(),
        )),
    }
}

fn array_fields_mut(value: &mut Value) -> &mut Vec<Value> {
    match value {
        Value::Array(fields) => fields,
        _ => std::panic::resume_unwind(Box::new(
            "nested authority encoding must be an array".to_owned(),
        )),
    }
}

fn changed_array(encoded: &CanonicalBytes, change: impl FnOnce(&mut Vec<Value>)) -> CanonicalBytes {
    let value: Value = ok(ciborium::from_reader(encoded.as_slice()));
    let mut fields = array_fields(value);
    change(&mut fields);
    encode_value(&Value::Array(fields))
}

#[test]
fn principal_and_adapter_results_are_canonical_public_contracts() {
    let principal = principal(1);
    assert_eq!(principal.principal_id(), &[1; 16]);
    assert_eq!(principal.trust_domain(), "local.test");
    assert_eq!(
        ok(PrincipalRefV1::decode(&ok(principal.encode()))),
        principal
    );

    let authenticated = authenticated(principal.clone());
    assert_eq!(authenticated.principal(), &principal);
    assert_eq!(authenticated.adapter_id(), "test-passkey");
    assert_eq!(authenticated.assurance().get(), 2);
    assert_eq!(authenticated.issued_at(), WallTime::from_micros(10));
    assert_eq!(authenticated.expires_at(), WallTime::from_micros(100));
    assert_eq!(authenticated.binding_digest(), hash(7));
    assert_eq!(
        ok(AuthenticatedPrincipalResultV1::decode(&ok(
            authenticated.encode()
        ))),
        authenticated
    );

    assert_eq!(
        AssuranceLevelV1::try_new(0),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PrincipalRefV1::try_new([0; 16], "local.test"),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PrincipalRefV1::try_new([1; 16], ""),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        PrincipalRefV1::try_new([1; 16], "x".repeat(MAX_AUTHORITY_TEXT_BYTES + 1)),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );

    let mut bad_adapter = AuthenticatedPrincipalDraftV1 {
        principal,
        adapter_id: String::new(),
        assurance: ok(AssuranceLevelV1::try_new(1)),
        issued_at: WallTime::from_micros(10),
        expires_at: WallTime::from_micros(10),
        binding_digest: Hash::zero(),
    };
    assert_eq!(
        AuthenticatedPrincipalResultV1::try_from_draft(bad_adapter.clone()),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    bad_adapter.adapter_id = "adapter".to_owned();
    assert_eq!(
        AuthenticatedPrincipalResultV1::try_from_draft(bad_adapter.clone()),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    bad_adapter.expires_at = WallTime::from_micros(11);
    assert_eq!(
        AuthenticatedPrincipalResultV1::try_from_draft(bad_adapter),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn one_principal_can_act_through_multiple_explicit_entity_contexts() {
    let principal_ref = principal(1);
    let actors = vec![entity(10), entity(11)];
    let grant = root_grant(principal_ref.clone(), actors.clone());

    for actor in actors {
        let request = request(principal_ref.clone(), actor);
        let decision = decision_for(&request, std::slice::from_ref(&grant));
        assert!(decision.is_allowed());
        assert_eq!(decision.outcome(), AuthorizationOutcomeV1::Active);
        assert_eq!(decision.principal(), &principal_ref);
        assert_eq!(decision.actor_entity_id(), actor);
        assert_eq!(decision.grant_id(), Some(hash(1)));
        assert_eq!(decision.policy_revision(), hash(9));
        assert_eq!(decision.authority_timeline(), timeline(30));
        assert_eq!(decision.at_position(), Seq::from_u64(50));
        assert_ne!(decision.request_digest(), Hash::zero());
        assert_ne!(decision.decision_digest(), Hash::zero());
        assert_eq!(
            ok(AuthorizationDecisionV1::decode(&ok(decision.encode()))),
            decision
        );
    }

    let other_principal = principal(2);
    let denied = decision_for(
        &request(other_principal, entity(10)),
        std::slice::from_ref(&grant),
    );
    assert_eq!(denied.outcome(), AuthorizationOutcomeV1::PrincipalMismatch);
    assert!(!denied.is_allowed());
}

#[test]
fn consent_is_evaluated_before_capability_and_fails_closed() {
    let principal_ref = principal(1);
    let cases = [
        (
            ConsentEvidenceV1::Missing,
            AuthorizationOutcomeV1::ConsentMissing,
        ),
        (
            ConsentEvidenceV1::NotRequired,
            AuthorizationOutcomeV1::ConsentMissing,
        ),
        (
            ConsentEvidenceV1::RevokedAtFence,
            AuthorizationOutcomeV1::ConsentRevokedAtFence,
        ),
        (
            ConsentEvidenceV1::Expired,
            AuthorizationOutcomeV1::ConsentExpired,
        ),
        (
            ConsentEvidenceV1::Indeterminate,
            AuthorizationOutcomeV1::IndeterminateFailClosed,
        ),
    ];
    for (consent, expected) in cases {
        let mut draft = request_draft(authenticated(principal_ref.clone()), entity(99));
        draft.consent = consent;
        let request = ok(AuthorizationRequestV1::try_from_draft(draft));
        assert_eq!(decision_for(&request, &[]).outcome(), expected);
    }

    let mut no_subject = request_draft(authenticated(principal_ref.clone()), entity(10));
    no_subject.subject_id = None;
    no_subject.consent = ConsentEvidenceV1::NotRequired;
    let no_subject_grant = ok(CapabilityGrantV1::try_from_draft(grant_draft(
        2,
        principal_ref.clone(),
        AuthorityGranteeV1::Principal(principal_ref.clone()),
        scope_with_subjects(vec![entity(10)], Vec::new(), vec!["read"], None),
    )));
    assert!(decision_for(
        &ok(AuthorizationRequestV1::try_from_draft(no_subject)),
        std::slice::from_ref(&no_subject_grant)
    )
    .is_allowed());

    let mut indeterminate = request_draft(authenticated(principal_ref), entity(10));
    indeterminate.subject_id = None;
    indeterminate.consent = ConsentEvidenceV1::Indeterminate;
    assert_eq!(
        decision_for(
            &ok(AuthorizationRequestV1::try_from_draft(indeterminate)),
            &[]
        )
        .outcome(),
        AuthorizationOutcomeV1::IndeterminateFailClosed
    );

    assert_eq!(
        decision_for(&request(principal(1), entity(10)), &[]).outcome(),
        AuthorizationOutcomeV1::CapabilityMissing
    );
}

#[test]
fn complete_consent_references_bind_every_authority_dimension() {
    let consent = consent_grant();
    assert_eq!(consent.consent_id(), hash(8));
    assert_eq!(consent.subject_id(), entity(50));
    assert_eq!(consent.data_categories(), &["profile"]);
    assert_eq!(consent.purposes(), &["care", "planning"]);
    assert_eq!(consent.audiences(), &["local-host"]);
    assert_eq!(consent.action_classes(), &["read"]);
    assert_eq!(consent.valid_from(), WallTime::from_micros(10));
    assert_eq!(consent.valid_until(), WallTime::from_micros(100));
    assert_eq!(consent.withdrawal_retention_policy(), "erase-derived-data");
    assert_eq!(consent.policy_revision(), hash(9));
    assert_eq!(consent.issuer(), &principal(4));
    assert_eq!(consent.issuer_evidence(), hash(6));
    assert_eq!(consent.revocation_fence(), None);
    assert_eq!(consent.authority_registry_digest(), hash(7));

    let principal_ref = principal(1);
    let actor = entity(10);
    let grant = root_grant(principal_ref.clone(), vec![actor]);
    for change in 0..5 {
        let mut consent = consent_draft(8);
        match change {
            0 => consent.subject_id = entity(51),
            1 => consent.data_categories = vec!["location".to_owned()],
            2 => consent.purposes = vec!["sale".to_owned()],
            3 => consent.audiences = vec!["remote".to_owned()],
            _ => consent.action_classes = vec!["write".to_owned()],
        }
        let mut request = request_draft(authenticated(principal_ref.clone()), actor);
        request.consent = ConsentEvidenceV1::Active {
            grants: vec![ok(ConsentGrantRefV1::try_from_draft(consent))],
        };
        assert_eq!(
            decision_for(
                &ok(AuthorizationRequestV1::try_from_draft(request)),
                std::slice::from_ref(&grant),
            )
            .outcome(),
            AuthorizationOutcomeV1::ConsentMissing
        );
    }

    let mut expired = consent_draft(8);
    expired.valid_until = WallTime::from_micros(50);
    let mut revoked = consent_draft(8);
    revoked.revocation_fence = Some(Seq::from_u64(50));
    for (consent, expected) in [
        (expired, AuthorizationOutcomeV1::ConsentExpired),
        (revoked, AuthorizationOutcomeV1::ConsentRevokedAtFence),
    ] {
        let mut request = request_draft(authenticated(principal_ref.clone()), actor);
        request.consent = ConsentEvidenceV1::Active {
            grants: vec![ok(ConsentGrantRefV1::try_from_draft(consent))],
        };
        assert_eq!(
            decision_for(
                &ok(AuthorizationRequestV1::try_from_draft(request)),
                std::slice::from_ref(&grant),
            )
            .outcome(),
            expected
        );
    }
}

#[test]
fn host_registry_snapshot_is_required_for_authoritative_evaluation() {
    let principal_ref = principal(1);
    let actor = entity(10);
    let request = request(principal_ref.clone(), actor);
    let grant = root_grant(principal_ref, vec![actor]);
    let untrusted = ok(AuthorityRegistrySnapshotV1::try_new(
        hash(7),
        vec![hash(6)],
        vec![hash(1)],
        vec![hash(8)],
    ));
    assert_eq!(untrusted.registry_digest(), hash(7));
    assert_eq!(
        AuthorityEvaluatorV1::authorize(&request, &[grant], &untrusted).outcome(),
        AuthorizationOutcomeV1::IndeterminateFailClosed
    );
}

#[test]
fn one_entity_can_be_operated_by_different_authorized_principals_over_time() {
    let actor = entity(10);
    for (principal_value, grant_id, position) in [(1, 1, 40), (2, 2, 60)] {
        let principal_ref = principal(principal_value);
        let grant = ok(CapabilityGrantV1::try_from_draft(grant_draft(
            grant_id,
            principal_ref.clone(),
            AuthorityGranteeV1::Principal(principal_ref.clone()),
            scope(vec![actor], vec![DELEGATE_ACTION_V1, "read"], None),
        )));
        let mut request = request_draft(authenticated(principal_ref.clone()), actor);
        request.at_position = Seq::from_u64(position);
        let decision = decision_for(
            &ok(AuthorizationRequestV1::try_from_draft(request)),
            &[grant],
        );
        assert!(decision.is_allowed());
        assert_eq!(decision.principal(), &principal_ref);
        assert_eq!(decision.actor_entity_id(), actor);
    }
}

#[test]
fn approver_and_evaluator_roles_are_explicitly_scoped_and_audited() {
    let actor = entity(10);
    for (grant_id, role) in [
        (3, AuthorityRoleV1::Approver),
        (4, AuthorityRoleV1::Evaluator),
    ] {
        let principal_ref = principal(grant_id);
        let grant = ok(CapabilityGrantV1::try_from_draft(grant_draft(
            grant_id,
            principal_ref.clone(),
            AuthorityGranteeV1::Principal(principal_ref.clone()),
            scope_for_role(
                vec![actor],
                vec![entity(50)],
                vec![DELEGATE_ACTION_V1, "read"],
                None,
                role,
            ),
        )));
        let mut request = request_draft(authenticated(principal_ref), actor);
        request.principal_role = role;
        let decision = decision_for(
            &ok(AuthorizationRequestV1::try_from_draft(request)),
            &[grant],
        );
        assert!(decision.is_allowed());
        assert_eq!(decision.principal_role(), role);
    }
}

#[test]
fn valid_delegation_is_bounded_and_strictly_attenuated() {
    let root = principal(1);
    let delegate = principal(2);
    let recipient = principal(3);
    let actor = entity(10);
    let parent = ok(CapabilityGrantV1::try_from_draft(grant_draft(
        1,
        root,
        AuthorityGranteeV1::Principal(delegate.clone()),
        scope(
            vec![actor, entity(11)],
            vec![DELEGATE_ACTION_V1, "read"],
            None,
        ),
    )));
    let mut child_draft = grant_draft(
        2,
        delegate,
        AuthorityGranteeV1::Principal(recipient.clone()),
        scope(vec![actor], vec!["read"], None),
    );
    child_draft.parent_grant_id = Some(parent.grant_id());
    child_draft.delegation_depth = 1;
    child_draft.max_delegation_depth = 1;
    child_draft.valid_from_position = Seq::from_u64(20);
    child_draft.valid_until_position = Seq::from_u64(90);
    let child = ok(CapabilityGrantV1::try_from_draft(child_draft));
    let request = request(recipient, actor);

    let decision = decision_for(&request, &[parent.clone(), child.clone()]);
    assert_eq!(decision.outcome(), AuthorizationOutcomeV1::Active);
    assert_eq!(decision.principal_role(), AuthorityRoleV1::Actor);
    assert_eq!(decision.subject_id(), Some(entity(50)));
    assert_eq!(decision.participant_id(), Some(entity(20)));
    assert_eq!(decision.originating_principal(), Some(&principal(1)));
    assert_eq!(decision.acting_delegates(), &[principal(2), principal(3)]);
    assert_eq!(decision.authority_registry_digest(), hash(7));
    assert_eq!(ok(CapabilityGrantV1::decode(&ok(parent.encode()))), parent);
    assert_eq!(ok(CapabilityGrantV1::decode(&ok(child.encode()))), child);
}

#[test]
fn authority_records_reject_noncanonical_and_malformed_encodings() {
    let encoded = ok(principal(1).encode()).as_slice().to_vec();
    let principal_value: Value = ok(ciborium::from_reader(encoded.as_slice()));
    assert_eq!(
        array_fields(principal_value)[0],
        Value::Bytes(b"PRN1".to_vec())
    );
    let mut wrong_magic = encoded.clone();
    wrong_magic[2] = b'X';
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(wrong_magic)),
        Err(AuthorityErrorV1::InvalidEncoding)
    );
    let mut wrong_version = encoded.clone();
    wrong_version[6] = 2;
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(wrong_version)),
        Err(AuthorityErrorV1::UnsupportedVersion)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(trailing)),
        Err(AuthorityErrorV1::InvalidEncoding)
    );
    let mut noncanonical = vec![0x98, 0x04];
    noncanonical.extend_from_slice(&encoded[1..]);
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(noncanonical)),
        Err(AuthorityErrorV1::InvalidEncoding)
    );
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(Vec::new())),
        Err(AuthorityErrorV1::InvalidEncoding)
    );
    assert_eq!(
        PrincipalRefV1::decode(&encode_value(&Value::Array(Vec::new()))),
        Err(AuthorityErrorV1::InvalidEncoding)
    );
    assert_eq!(
        PrincipalRefV1::decode(&encode_value(&Value::Text("principal".to_owned()))),
        Err(AuthorityErrorV1::InvalidEncoding)
    );

    let request = request(principal(1), entity(10));
    let grant = root_grant(principal(1), vec![entity(10)]);
    let decision = decision_for(&request, &[grant]);
    let grant_value: Value = ok(ciborium::from_reader(
        ok(root_grant(principal(1), vec![entity(10)]).encode()).as_slice(),
    ));
    assert_eq!(array_fields(grant_value)[0], Value::Bytes(b"CPG1".to_vec()));
    let decision_value: Value = ok(ciborium::from_reader(ok(decision.encode()).as_slice()));
    assert_eq!(
        array_fields(decision_value)[0],
        Value::Bytes(b"AUD1".to_vec())
    );
    let mut tampered = ok(decision.encode()).as_slice().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        AuthorizationDecisionV1::decode(&CanonicalBytes::from_vec(tampered)),
        Err(AuthorityErrorV1::DigestMismatch)
    );
}

#[test]
fn authenticated_result_decoder_rejects_every_malformed_public_field() {
    let encoded = ok(authenticated(principal(1)).encode());
    for field in 2..8 {
        let malformed = changed_array(&encoded, |fields| {
            fields[field] = Value::Bool(false);
        });
        assert_eq!(
            AuthenticatedPrincipalResultV1::decode(&malformed),
            Err(AuthorityErrorV1::InvalidEncoding),
            "field {field} accepted the wrong CBOR type"
        );
    }

    let wrong_principal_length = changed_array(&encoded, |fields| {
        fields[2] = Value::Array(Vec::new());
    });
    assert_eq!(
        AuthenticatedPrincipalResultV1::decode(&wrong_principal_length),
        Err(AuthorityErrorV1::InvalidEncoding)
    );
}

#[test]
fn capability_decoder_rejects_every_malformed_public_field() {
    let principal_ref = principal(1);
    let encoded = ok(root_grant(principal_ref, vec![entity(10)]).encode());
    for field in 2..19 {
        let malformed = changed_array(&encoded, |fields| {
            fields[field] = Value::Text("wrong-type".to_owned());
        });
        assert_eq!(
            CapabilityGrantV1::decode(&malformed),
            Err(AuthorityErrorV1::InvalidEncoding),
            "field {field} accepted the wrong CBOR type"
        );
    }

    for scope_field in 0..12 {
        let malformed = changed_array(&encoded, |fields| {
            let scope_fields = array_fields_mut(&mut fields[5]);
            scope_fields[scope_field] = Value::Text("wrong-type".to_owned());
        });
        assert_eq!(
            CapabilityGrantV1::decode(&malformed),
            Err(AuthorityErrorV1::InvalidEncoding),
            "scope field {scope_field} accepted the wrong CBOR type"
        );
    }

    let wrong_scope_length = changed_array(&encoded, |fields| {
        fields[5] = Value::Array(Vec::new());
    });
    assert_eq!(
        CapabilityGrantV1::decode(&wrong_scope_length),
        Err(AuthorityErrorV1::InvalidEncoding)
    );
    let wrong_principal_grantee_tag = changed_array(&encoded, |fields| {
        let grantee = array_fields_mut(&mut fields[4]);
        grantee[0] = Value::Integer(1.into());
    });
    assert_eq!(
        CapabilityGrantV1::decode(&wrong_principal_grantee_tag),
        Err(AuthorityErrorV1::UnknownEnum)
    );
    let wrong_grantee_length = changed_array(&encoded, |fields| {
        fields[4] = Value::Array(Vec::new());
    });
    assert_eq!(
        CapabilityGrantV1::decode(&wrong_grantee_length),
        Err(AuthorityErrorV1::InvalidEncoding)
    );

    let plugin_id = plugin(2);
    let plugin_grant = ok(CapabilityGrantV1::try_from_draft(grant_draft(
        4,
        principal(1),
        AuthorityGranteeV1::PluginInstallation {
            controller: principal(1),
            plugin_id,
            installation_id: [3; 16],
        },
        scope(vec![entity(10)], vec!["read"], Some(plugin_id)),
    )));
    let plugin_encoded = ok(plugin_grant.encode());
    let wrong_plugin_grantee_tag = changed_array(&plugin_encoded, |fields| {
        let grantee = array_fields_mut(&mut fields[4]);
        grantee[0] = Value::Integer(0.into());
    });
    assert_eq!(
        CapabilityGrantV1::decode(&wrong_plugin_grantee_tag),
        Err(AuthorityErrorV1::UnknownEnum)
    );
}

#[test]
fn decision_decoder_rejects_every_malformed_public_field() {
    let request = request(principal(1), entity(10));
    let grant = root_grant(principal(1), vec![entity(10)]);
    let encoded = ok(decision_for(&request, &[grant]).encode());

    for field in 2..19 {
        let malformed = changed_array(&encoded, |fields| {
            fields[field] = Value::Text("wrong-type".to_owned());
        });
        assert_eq!(
            AuthorizationDecisionV1::decode(&malformed),
            Err(AuthorityErrorV1::InvalidEncoding),
            "field {field} accepted the wrong CBOR type"
        );
    }

    let invalid_outcome = changed_array(&encoded, |fields| {
        fields[16] = Value::Integer(99.into());
    });
    assert_eq!(
        AuthorizationDecisionV1::decode(&invalid_outcome),
        Err(AuthorityErrorV1::UnknownEnum)
    );
    for digest_field in [12, 15, 17, 18] {
        let zero_digest = changed_array(&encoded, |fields| {
            fields[digest_field] = Value::Bytes(vec![0; 32]);
        });
        assert_eq!(
            AuthorizationDecisionV1::decode(&zero_digest),
            Err(AuthorityErrorV1::FieldOutOfBounds),
            "digest field {digest_field} accepted the zero digest"
        );
    }
}

#[test]
fn constructors_reject_unbounded_unordered_and_zero_identity_fields() {
    let base = CapabilityScopeDraftV1 {
        resources: vec!["journal".to_owned()],
        actions: vec!["read".to_owned()],
        purposes: vec!["care".to_owned()],
        audiences: vec!["host".to_owned()],
        actor_entity_ids: vec![entity(1)],
        subject_ids: Vec::new(),
        participant_ids: Vec::new(),
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 1,
        budget: 1,
        environment_constraints: Vec::new(),
    };
    let mut invalid = base.clone();
    invalid.resources.clear();
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.actions = vec!["read".to_owned(), "read".to_owned()];
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::NonCanonicalOrder)
    );
    let mut invalid = base.clone();
    invalid.actor_entity_ids = vec![entity(0)];
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.plugin_id = Some(plugin(0));
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.max_uses = 0;
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base;
    invalid.resources = (0..=MAX_AUTHORITY_SELECTORS)
        .map(|value| format!("resource-{value:02}"))
        .collect();
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );

    assert_eq!(MAX_AUTHORITY_DELEGATION_DEPTH, 16);
    assert_eq!(MAX_AUTHORITY_TEXT_BYTES, 128);
}

#[test]
fn scope_and_request_fields_are_explicit_and_every_dimension_is_enforced() {
    let principal = principal(1);
    let actor = entity(10);
    let grant = root_grant(principal.clone(), vec![actor]);
    let valid = request_draft(authenticated(principal.clone()), actor);
    let request = ok(AuthorizationRequestV1::try_from_draft(valid.clone()));

    assert_eq!(request.authenticated().principal(), &principal);
    assert_eq!(request.actor_entity_id(), actor);
    assert_eq!(request.subject_id(), Some(entity(50)));
    assert_eq!(request.participant_id(), Some(entity(20)));
    assert_eq!(request.plugin_id(), None);
    assert_eq!(request.installation_id(), None);
    assert_eq!(request.principal_role(), AuthorityRoleV1::Actor);
    assert_eq!(request.resource(), "journal");
    assert_eq!(request.data_category(), "profile");
    assert_eq!(request.action(), "read");
    assert_eq!(request.purpose(), "care");
    assert_eq!(request.audience(), "local-host");
    assert_eq!(request.at_time(), WallTime::from_micros(50));
    assert_eq!(request.authority_timeline(), timeline(30));
    assert_eq!(request.at_position(), Seq::from_u64(50));
    assert_eq!(request.use_count(), 2);
    assert_eq!(request.budget(), 50);
    assert_eq!(request.policy_revision(), hash(9));
    assert_eq!(request.revocation_epoch(), 3);
    assert!(request.revocation_state_current());
    assert_eq!(request.authority_registry_digest(), hash(7));
    assert_eq!(
        request.consent(),
        &ConsentEvidenceV1::Active {
            grants: vec![consent_grant()]
        }
    );
    assert_eq!(
        request.environment_constraints(),
        &["device-bound".to_owned(), "local-only".to_owned()]
    );

    let mut mismatches = Vec::new();
    let mut draft = valid.clone();
    draft.resource = "unknown".to_owned();
    mismatches.push((draft, AuthorizationOutcomeV1::ScopeMismatch));
    let mut draft = valid.clone();
    draft.data_category = "medical".to_owned();
    mismatches.push((draft, AuthorizationOutcomeV1::ConsentMissing));
    let mut draft = valid.clone();
    draft.action = "write".to_owned();
    mismatches.push((draft, AuthorizationOutcomeV1::ConsentMissing));
    let mut draft = valid.clone();
    draft.purpose = "sale".to_owned();
    mismatches.push((draft, AuthorizationOutcomeV1::ConsentMissing));
    let mut draft = valid.clone();
    draft.audience = "remote".to_owned();
    mismatches.push((draft, AuthorizationOutcomeV1::ConsentMissing));
    let mut draft = valid.clone();
    draft.actor_entity_id = entity(99);
    mismatches.push((draft, AuthorizationOutcomeV1::ScopeMismatch));
    let mut draft = valid.clone();
    draft.participant_id = Some(entity(99));
    mismatches.push((draft, AuthorizationOutcomeV1::ScopeMismatch));
    let mut draft = valid.clone();
    draft.participant_id = None;
    mismatches.push((draft, AuthorizationOutcomeV1::ScopeMismatch));
    let mut draft = valid.clone();
    draft.plugin_id = Some(plugin(5));
    draft.installation_id = Some([5; 16]);
    mismatches.push((draft, AuthorizationOutcomeV1::ScopeMismatch));
    let mut draft = valid.clone();
    draft.use_count = 11;
    mismatches.push((draft, AuthorizationOutcomeV1::ScopeMismatch));
    let mut draft = valid.clone();
    draft.budget = 101;
    mismatches.push((draft, AuthorizationOutcomeV1::ScopeMismatch));
    let mut draft = valid;
    draft.environment_constraints = vec!["local-only".to_owned()];
    mismatches.push((draft, AuthorizationOutcomeV1::ScopeMismatch));

    for (draft, expected) in mismatches {
        let request = ok(AuthorizationRequestV1::try_from_draft(draft));
        assert_eq!(
            decision_for(&request, std::slice::from_ref(&grant)).outcome(),
            expected
        );
    }
}

#[test]
fn grant_contract_exposes_all_bound_authority_and_plugin_context() {
    let principal = principal(1);
    let plugin_id = plugin(2);
    let grant = ok(CapabilityGrantV1::try_from_draft(grant_draft(
        4,
        principal.clone(),
        AuthorityGranteeV1::PluginInstallation {
            controller: principal.clone(),
            plugin_id,
            installation_id: [3; 16],
        },
        scope(vec![entity(10)], vec!["read"], Some(plugin_id)),
    )));

    assert_eq!(grant.grant_id(), hash(4));
    assert_eq!(grant.grantor(), &principal);
    assert_eq!(grant.grantee().principal(), &principal);
    assert_eq!(grant.grantee().plugin_id(), Some(plugin_id));
    assert_eq!(grant.grantee().installation_id(), Some([3; 16]));
    assert_eq!(grant.scope().resources(), &["journal", "profile"]);
    assert_eq!(grant.scope().actions(), &["read"]);
    assert_eq!(grant.scope().purposes(), &["care", "planning"]);
    assert_eq!(grant.scope().audiences(), &["local-host"]);
    assert_eq!(grant.scope().actor_entity_ids(), &[entity(10)]);
    assert_eq!(grant.scope().subject_ids(), &[entity(50)]);
    assert_eq!(grant.scope().participant_ids(), &[entity(20)]);
    assert_eq!(grant.scope().plugin_id(), Some(plugin_id));
    assert_eq!(grant.scope().principal_roles(), &[AuthorityRoleV1::Actor]);
    assert_eq!(grant.scope().max_uses(), 10);
    assert_eq!(grant.scope().budget(), 100);
    assert_eq!(
        grant.scope().environment_constraints(),
        &["device-bound".to_owned(), "local-only".to_owned()]
    );
    assert_eq!(grant.valid_from_position(), Seq::from_u64(10));
    assert_eq!(grant.valid_until_position(), Seq::from_u64(100));
    assert_eq!(grant.parent_grant_id(), None);
    assert_eq!(grant.delegation_depth(), 0);
    assert_eq!(grant.max_delegation_depth(), 2);
    assert_eq!(
        grant.permitted_delegate_classes(),
        &[DelegateClassV1::Principal]
    );
    assert_eq!(grant.consent_references(), &[hash(8)]);
    assert_eq!(grant.policy_revision(), hash(9));
    assert_eq!(grant.issuance_timeline(), timeline(30));
    assert_eq!(grant.issuance_seq(), Seq::from_u64(5));
    assert_eq!(grant.revocation_epoch(), 3);
    assert_eq!(grant.revocation_fence(), None);
    assert_eq!(grant.authority_registry_digest(), hash(7));
    assert_ne!(ok(grant.binding_digest()), Hash::zero());
    assert_eq!(ok(CapabilityGrantV1::decode(&ok(grant.encode()))), grant);

    let mut request = request_draft(authenticated(principal), entity(10));
    request.plugin_id = Some(plugin_id);
    request.installation_id = Some([3; 16]);
    assert!(decision_for(
        &ok(AuthorizationRequestV1::try_from_draft(request.clone())),
        std::slice::from_ref(&grant)
    )
    .is_allowed());

    request.installation_id = Some([4; 16]);
    assert_eq!(
        decision_for(
            &ok(AuthorizationRequestV1::try_from_draft(request)),
            &[grant]
        )
        .outcome(),
        AuthorizationOutcomeV1::ScopeMismatch
    );
}

#[test]
fn authentication_revocation_expiry_and_coordinates_fail_closed() {
    let principal = principal(1);
    let actor = entity(10);
    let root = root_grant(principal.clone(), vec![actor]);

    let mut draft = request_draft(authenticated(principal.clone()), actor);
    draft.at_time = WallTime::from_micros(100);
    assert_eq!(
        decision_for(&ok(AuthorizationRequestV1::try_from_draft(draft)), &[]).outcome(),
        AuthorizationOutcomeV1::AuthenticationExpired
    );

    let mut draft = request_draft(authenticated(principal.clone()), actor);
    draft.consent = ConsentEvidenceV1::Active {
        grants: vec![consent_grant_with_id(7)],
    };
    assert_eq!(
        decision_for(
            &ok(AuthorizationRequestV1::try_from_draft(draft)),
            std::slice::from_ref(&root)
        )
        .outcome(),
        AuthorizationOutcomeV1::ParentInvalid
    );

    let mut draft = request_draft(authenticated(principal.clone()), actor);
    draft.revocation_state_current = false;
    assert_eq!(
        decision_for(
            &ok(AuthorizationRequestV1::try_from_draft(draft)),
            std::slice::from_ref(&root)
        )
        .outcome(),
        AuthorizationOutcomeV1::RevocationStateStale
    );

    for change in 0..3 {
        let mut draft = request_draft(authenticated(principal.clone()), actor);
        match change {
            0 => draft.revocation_epoch = 4,
            1 => {
                draft.policy_revision = hash(10);
                let mut consent = consent_draft(8);
                consent.policy_revision = hash(10);
                draft.consent = ConsentEvidenceV1::Active {
                    grants: vec![ok(ConsentGrantRefV1::try_from_draft(consent))],
                };
            }
            _ => draft.authority_timeline = timeline(31),
        }
        assert_eq!(
            decision_for(
                &ok(AuthorizationRequestV1::try_from_draft(draft)),
                std::slice::from_ref(&root)
            )
            .outcome(),
            AuthorizationOutcomeV1::IndeterminateFailClosed
        );
    }

    let mut expired = grant_draft(
        2,
        principal.clone(),
        AuthorityGranteeV1::Principal(principal.clone()),
        scope(vec![actor], vec!["read"], None),
    );
    expired.valid_until_position = Seq::from_u64(50);
    assert_eq!(
        decision_for(
            &request(principal.clone(), actor),
            &[ok(CapabilityGrantV1::try_from_draft(expired))]
        )
        .outcome(),
        AuthorizationOutcomeV1::Expired
    );

    let mut revoked = grant_draft(
        3,
        principal.clone(),
        AuthorityGranteeV1::Principal(principal.clone()),
        scope(vec![actor], vec!["read"], None),
    );
    revoked.revocation_fence = Some(Seq::from_u64(50));
    assert_eq!(
        decision_for(
            &request(principal, actor),
            &[ok(CapabilityGrantV1::try_from_draft(revoked))]
        )
        .outcome(),
        AuthorizationOutcomeV1::RevokedAtFence
    );
}

#[test]
fn malformed_grants_are_rejected_before_evaluation() {
    let principal = principal(1);
    let actor = entity(10);
    let scope = scope(vec![actor], vec!["read"], None);
    let base = grant_draft(
        1,
        principal.clone(),
        AuthorityGranteeV1::Principal(principal.clone()),
        scope,
    );

    let mut invalid = base.clone();
    invalid.grant_id = Hash::zero();
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.policy_revision = Hash::zero();
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.valid_until_position = invalid.valid_from_position;
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.parent_grant_id = Some(hash(2));
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.max_delegation_depth = MAX_AUTHORITY_DELEGATION_DEPTH + 1;
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.consent_references = vec![hash(8), hash(8)];
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::NonCanonicalOrder)
    );
    let mut invalid = base.clone();
    invalid.revocation_fence = Some(Seq::from_u64(9));
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.issuance_timeline = timeline(0);
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base;
    invalid.grantee = AuthorityGranteeV1::PluginInstallation {
        controller: principal,
        plugin_id: plugin(1),
        installation_id: [0; 16],
    };
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn malformed_requests_are_rejected_before_evaluation() {
    let principal = principal(1);
    let actor = entity(10);
    let base = request_draft(authenticated(principal.clone()), actor);
    let mut invalid = base.clone();
    invalid.resource.clear();
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.actor_entity_id = entity(0);
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.authority_timeline = timeline(0);
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base.clone();
    invalid.environment_constraints = vec!["z".to_owned(), "a".to_owned()];
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::NonCanonicalOrder)
    );
    let mut invalid = base.clone();
    invalid.use_count = 0;
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
    let mut invalid = base;
    invalid.consent = ConsentEvidenceV1::Active { grants: Vec::new() };
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );

    let mut invalid = request_draft(authenticated(principal), actor);
    invalid.consent = ConsentEvidenceV1::Active {
        grants: vec![consent_grant_with_id(9), consent_grant_with_id(8)],
    };
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::NonCanonicalOrder)
    );
    assert_eq!(
        AuthorityRegistrySnapshotV1::try_new(Hash::zero(), vec![hash(1)], vec![hash(2)], vec![]),
        Err(AuthorityErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn delegation_rejects_broken_links_impersonation_cycles_and_amplification() {
    let actor = entity(10);
    let mut variants = Vec::new();
    let mut child = delegation_child();
    child.parent_grant_id = Some(hash(99));
    variants.push(child);
    let mut child = delegation_child();
    child.grantor = principal(4);
    variants.push(child);
    let mut child = delegation_child();
    child.max_delegation_depth = 3;
    variants.push(child);
    let mut child = delegation_child();
    child.valid_from_position = Seq::from_u64(5);
    variants.push(child);
    let mut child = delegation_child();
    child.valid_until_position = Seq::from_u64(101);
    variants.push(child);
    let mut child = delegation_child();
    child.consent_references = vec![hash(8), hash(10)];
    variants.push(child);
    let mut child = delegation_child();
    child.scope = scope(vec![actor, entity(12)], vec!["read"], None);
    variants.push(child);
    let mut child = delegation_child();
    child.scope = scope(vec![actor], vec!["execute", "read"], None);
    variants.push(child);
    let mut child = delegation_child();
    child.scope = ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["journal".to_owned(), "profile".to_owned()],
        actions: vec!["read".to_owned()],
        purposes: vec!["care".to_owned(), "planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![actor],
        subject_ids: vec![entity(50)],
        participant_ids: vec![entity(20)],
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 11,
        budget: 100,
        environment_constraints: vec!["device-bound".to_owned(), "local-only".to_owned()],
    }));
    variants.push(child);
    let mut child = delegation_child();
    child.scope = ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["journal".to_owned(), "profile".to_owned()],
        actions: vec!["read".to_owned()],
        purposes: vec!["care".to_owned(), "planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![actor],
        subject_ids: vec![entity(50)],
        participant_ids: vec![entity(20)],
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 10,
        budget: 101,
        environment_constraints: vec!["device-bound".to_owned(), "local-only".to_owned()],
    }));
    variants.push(child);
    let mut child = delegation_child();
    child.scope = ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["journal".to_owned(), "profile".to_owned()],
        actions: vec!["read".to_owned()],
        purposes: vec!["care".to_owned(), "planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids: vec![actor],
        subject_ids: vec![entity(50)],
        participant_ids: vec![entity(20)],
        plugin_id: None,
        principal_roles: vec![AuthorityRoleV1::Actor],
        max_uses: 10,
        budget: 100,
        environment_constraints: vec!["local-only".to_owned()],
    }));
    variants.push(child);

    for child in variants {
        assert_delegation_invalid(child);
    }

    let mut repeated = delegation_child();
    repeated.grant_id = hash(1);
    assert_delegation_invalid(repeated);

    let orphan = delegation_child();
    assert_eq!(
        decision_for(
            &request(principal(3), actor),
            &[ok(CapabilityGrantV1::try_from_draft(orphan))]
        )
        .outcome(),
        AuthorizationOutcomeV1::ParentInvalid
    );
}

#[test]
fn plugins_cannot_delegate_or_escape_their_installation_scope() {
    let controller = principal(1);
    let recipient = principal(2);
    let actor = entity(10);
    let plugin_id = plugin(4);
    let plugin_parent = ok(CapabilityGrantV1::try_from_draft(grant_draft(
        1,
        controller.clone(),
        AuthorityGranteeV1::PluginInstallation {
            controller: controller.clone(),
            plugin_id,
            installation_id: [5; 16],
        },
        scope(
            vec![actor],
            vec![DELEGATE_ACTION_V1, "read"],
            Some(plugin_id),
        ),
    )));
    let mut child = grant_draft(
        2,
        controller,
        AuthorityGranteeV1::Principal(recipient.clone()),
        scope(vec![actor], vec!["read"], None),
    );
    child.parent_grant_id = Some(hash(1));
    child.delegation_depth = 1;
    child.max_delegation_depth = 1;
    child.valid_from_position = Seq::from_u64(20);
    child.valid_until_position = Seq::from_u64(90);

    assert_eq!(
        decision_for(
            &request(recipient, actor),
            &[plugin_parent, ok(CapabilityGrantV1::try_from_draft(child))]
        )
        .outcome(),
        AuthorizationOutcomeV1::DelegationInvalid
    );
}

#[test]
fn ancestor_changes_invalidate_every_descendant() {
    let root_principal = principal(1);
    let delegate = principal(2);
    let recipient = principal(3);
    let actor = entity(10);
    let parent_draft = grant_draft(
        1,
        root_principal,
        AuthorityGranteeV1::Principal(delegate.clone()),
        scope(vec![actor], vec![DELEGATE_ACTION_V1, "read"], None),
    );
    let mut child_draft = grant_draft(
        2,
        delegate,
        AuthorityGranteeV1::Principal(recipient.clone()),
        scope(vec![actor], vec!["read"], None),
    );
    child_draft.parent_grant_id = Some(hash(1));
    child_draft.delegation_depth = 1;
    child_draft.max_delegation_depth = 1;
    child_draft.valid_from_position = Seq::from_u64(20);
    child_draft.valid_until_position = Seq::from_u64(90);
    let child = ok(CapabilityGrantV1::try_from_draft(child_draft));
    let request = request(recipient, actor);

    for change in 0..3 {
        let mut parent = parent_draft.clone();
        match change {
            0 => parent.policy_revision = hash(10),
            1 => parent.revocation_epoch = 4,
            _ => parent.issuance_timeline = timeline(31),
        }
        assert_eq!(
            decision_for(
                &request,
                &[ok(CapabilityGrantV1::try_from_draft(parent)), child.clone()]
            )
            .outcome(),
            AuthorizationOutcomeV1::ParentInvalid
        );
    }

    let mut parent = parent_draft;
    parent.revocation_fence = Some(Seq::from_u64(50));
    assert_eq!(
        decision_for(
            &request,
            &[ok(CapabilityGrantV1::try_from_draft(parent)), child]
        )
        .outcome(),
        AuthorizationOutcomeV1::RevokedAtFence
    );
}
