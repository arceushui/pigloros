use ciborium::Value;
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityErrorV1, AuthorityEvaluatorV1, AuthorityGranteeV1, AuthorizationDecisionV1,
    AuthorizationOutcomeV1, AuthorizationRequestDraftV1, AuthorizationRequestV1, CanonicalBytes,
    CapabilityGrantDraftV1, CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1,
    ConsentEvidenceV1, EntityId, Hash, PluginId, PrincipalRefV1, TimelineId, DELEGATE_ACTION_V1,
    MAX_AUTHORITY_DELEGATION_DEPTH, MAX_AUTHORITY_SCOPE_MEMBERS, MAX_AUTHORITY_TEXT_BYTES,
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

fn hash(value: u8) -> Hash {
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
            issued_at_micros: 10,
            expires_at_micros: 100,
            binding_digest: hash(7),
        },
    ))
}

fn scope(
    actor_entity_ids: Vec<EntityId>,
    actions: Vec<&str>,
    plugin_id: Option<PluginId>,
) -> CapabilityScopeV1 {
    ok(CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
        resources: vec!["journal".to_owned(), "profile".to_owned()],
        actions: actions.into_iter().map(str::to_owned).collect(),
        purposes: vec!["care".to_owned(), "planning".to_owned()],
        audiences: vec!["local-host".to_owned()],
        actor_entity_ids,
        participant_ids: vec![entity(20)],
        plugin_id,
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
        valid_from_position: 10,
        valid_until_position: 100,
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 2,
        consent_references: vec![hash(8)],
        policy_revision: hash(9),
        issuance_timeline: timeline(30),
        issuance_seq: 5,
        revocation_epoch: 3,
        revocation_fence: None,
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
    draft.valid_from_position = 20;
    draft.valid_until_position = 90;
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
        resource: "journal".to_owned(),
        action: "read".to_owned(),
        purpose: "care".to_owned(),
        audience: "local-host".to_owned(),
        at_time_micros: 50,
        authority_timeline: timeline(30),
        at_position: 50,
        use_count: 2,
        budget: 50,
        policy_revision: hash(9),
        revocation_epoch: 3,
        revocation_state_current: true,
        consent: ConsentEvidenceV1::Active { reference: hash(8) },
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
    AuthorityEvaluatorV1::authorize(request, chain)
}

fn encode_value(value: &Value) -> CanonicalBytes {
    let mut bytes = Vec::new();
    ok(ciborium::into_writer(value, &mut bytes));
    CanonicalBytes::from_vec(bytes)
}

#[test]
fn principal_and_adapter_results_are_canonical_public_contracts() {
    let principal = principal(1);
    assert_eq!(principal.principal_id(), &[1; 16]);
    assert_eq!(principal.trust_domain(), "local.test");
    assert_eq!(ok(PrincipalRefV1::decode(&ok(principal.encode()))), principal);

    let authenticated = authenticated(principal.clone());
    assert_eq!(authenticated.principal(), &principal);
    assert_eq!(authenticated.adapter_id(), "test-passkey");
    assert_eq!(authenticated.assurance().get(), 2);
    assert_eq!(authenticated.issued_at_micros(), 10);
    assert_eq!(authenticated.expires_at_micros(), 100);
    assert_eq!(authenticated.binding_digest(), hash(7));
    assert_eq!(
        ok(AuthenticatedPrincipalResultV1::decode(&ok(authenticated.encode()))),
        authenticated
    );

    assert_eq!(AssuranceLevelV1::try_new(0), Err(AuthorityErrorV1::WrongFieldType));
    assert_eq!(
        PrincipalRefV1::try_new([0; 16], "local.test"),
        Err(AuthorityErrorV1::ZeroIdentity)
    );
    assert_eq!(
        PrincipalRefV1::try_new([1; 16], ""),
        Err(AuthorityErrorV1::InvalidText)
    );
    assert_eq!(
        PrincipalRefV1::try_new([1; 16], "x".repeat(MAX_AUTHORITY_TEXT_BYTES + 1)),
        Err(AuthorityErrorV1::InvalidText)
    );

    let mut bad_adapter = AuthenticatedPrincipalDraftV1 {
        principal,
        adapter_id: String::new(),
        assurance: ok(AssuranceLevelV1::try_new(1)),
        issued_at_micros: 10,
        expires_at_micros: 10,
        binding_digest: Hash::zero(),
    };
    assert_eq!(
        AuthenticatedPrincipalResultV1::try_from_draft(bad_adapter.clone()),
        Err(AuthorityErrorV1::InvalidText)
    );
    bad_adapter.adapter_id = "adapter".to_owned();
    assert_eq!(
        AuthenticatedPrincipalResultV1::try_from_draft(bad_adapter.clone()),
        Err(AuthorityErrorV1::InvalidInterval)
    );
    bad_adapter.expires_at_micros = 11;
    assert_eq!(
        AuthenticatedPrincipalResultV1::try_from_draft(bad_adapter),
        Err(AuthorityErrorV1::ZeroIdentity)
    );
}

#[test]
fn one_principal_can_act_through_multiple_explicit_entity_contexts() {
    let principal = principal(1);
    let actors = vec![entity(10), entity(11)];
    let grant = root_grant(principal.clone(), actors.clone());

    for actor in actors {
        let request = request(principal.clone(), actor);
        let decision = decision_for(&request, std::slice::from_ref(&grant));
        assert!(decision.is_allowed());
        assert_eq!(decision.outcome(), AuthorizationOutcomeV1::Active);
        assert_eq!(decision.principal(), &principal);
        assert_eq!(decision.actor_entity_id(), actor);
        assert_eq!(decision.grant_id(), Some(hash(1)));
        assert_eq!(decision.policy_revision(), hash(9));
        assert_eq!(decision.authority_timeline(), timeline(30));
        assert_eq!(decision.at_position(), 50);
        assert_ne!(decision.request_digest(), Hash::zero());
        assert_ne!(decision.decision_digest(), Hash::zero());
        assert_eq!(ok(AuthorizationDecisionV1::decode(&ok(decision.encode()))), decision);
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
    let principal = principal(1);
    let grant = root_grant(principal.clone(), vec![entity(10)]);
    let cases = [
        (ConsentEvidenceV1::Missing, AuthorizationOutcomeV1::ConsentMissing),
        (ConsentEvidenceV1::NotRequired, AuthorizationOutcomeV1::ConsentMissing),
        (
            ConsentEvidenceV1::RevokedAtFence,
            AuthorizationOutcomeV1::ConsentRevokedAtFence,
        ),
        (ConsentEvidenceV1::Expired, AuthorizationOutcomeV1::ConsentExpired),
        (
            ConsentEvidenceV1::Indeterminate,
            AuthorizationOutcomeV1::IndeterminateFailClosed,
        ),
    ];
    for (consent, expected) in cases {
        let mut draft = request_draft(authenticated(principal.clone()), entity(99));
        draft.consent = consent;
        let request = ok(AuthorizationRequestV1::try_from_draft(draft));
        assert_eq!(decision_for(&request, &[]).outcome(), expected);
    }

    let mut no_subject = request_draft(authenticated(principal.clone()), entity(10));
    no_subject.subject_id = None;
    no_subject.consent = ConsentEvidenceV1::NotRequired;
    assert!(decision_for(
        &ok(AuthorizationRequestV1::try_from_draft(no_subject)),
        std::slice::from_ref(&grant)
    )
    .is_allowed());

    let mut indeterminate = request_draft(authenticated(principal), entity(10));
    indeterminate.subject_id = None;
    indeterminate.consent = ConsentEvidenceV1::Indeterminate;
    assert_eq!(
        decision_for(&ok(AuthorizationRequestV1::try_from_draft(indeterminate)), &[]).outcome(),
        AuthorizationOutcomeV1::IndeterminateFailClosed
    );
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
        scope(vec![actor, entity(11)], vec![DELEGATE_ACTION_V1, "read"], None),
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
    child_draft.valid_from_position = 20;
    child_draft.valid_until_position = 90;
    let child = ok(CapabilityGrantV1::try_from_draft(child_draft));
    let request = request(recipient, actor);

    let decision = decision_for(&request, &[parent.clone(), child.clone()]);
    assert_eq!(decision.outcome(), AuthorizationOutcomeV1::Active);
    assert_eq!(ok(CapabilityGrantV1::decode(&ok(parent.encode()))), parent);
    assert_eq!(ok(CapabilityGrantV1::decode(&ok(child.encode()))), child);
}

#[test]
fn authority_records_reject_noncanonical_and_malformed_encodings() {
    let encoded = ok(principal(1).encode()).as_slice().to_vec();
    let mut wrong_magic = encoded.clone();
    wrong_magic[2] = b'X';
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(wrong_magic)),
        Err(AuthorityErrorV1::WrongMagic)
    );
    let mut wrong_version = encoded.clone();
    wrong_version[6] = 2;
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(wrong_version)),
        Err(AuthorityErrorV1::WrongVersion)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(trailing)),
        Err(AuthorityErrorV1::TrailingBytes)
    );
    let mut noncanonical = vec![0x98, 0x04];
    noncanonical.extend_from_slice(&encoded[1..]);
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(noncanonical)),
        Err(AuthorityErrorV1::NonCanonicalEncoding)
    );
    assert_eq!(
        PrincipalRefV1::decode(&CanonicalBytes::from_vec(Vec::new())),
        Err(AuthorityErrorV1::Cbor)
    );
    assert_eq!(
        PrincipalRefV1::decode(&encode_value(&Value::Array(Vec::new()))),
        Err(AuthorityErrorV1::WrongArrayLength)
    );
    assert_eq!(
        PrincipalRefV1::decode(&encode_value(&Value::Text("principal".to_owned()))),
        Err(AuthorityErrorV1::WrongFieldType)
    );

    let request = request(principal(1), entity(10));
    let grant = root_grant(principal(1), vec![entity(10)]);
    let decision = decision_for(&request, &[grant]);
    let mut tampered = ok(decision.encode()).as_slice().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        AuthorizationDecisionV1::decode(&CanonicalBytes::from_vec(tampered)),
        Err(AuthorityErrorV1::DecisionDigestMismatch)
    );
}

#[test]
fn constructors_reject_unbounded_unordered_and_zero_identity_fields() {
    let base = CapabilityScopeDraftV1 {
        resources: vec!["journal".to_owned()],
        actions: vec!["read".to_owned()],
        purposes: vec!["care".to_owned()],
        audiences: vec!["host".to_owned()],
        actor_entity_ids: vec![entity(1)],
        participant_ids: Vec::new(),
        plugin_id: None,
        max_uses: 1,
        budget: 1,
        environment_constraints: Vec::new(),
    };
    let mut invalid = base.clone();
    invalid.resources.clear();
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::InvalidScope)
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
        Err(AuthorityErrorV1::ZeroIdentity)
    );
    let mut invalid = base.clone();
    invalid.plugin_id = Some(plugin(0));
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ZeroIdentity)
    );
    let mut invalid = base.clone();
    invalid.max_uses = 0;
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::InvalidScope)
    );
    let mut invalid = base;
    invalid.resources = (0..=MAX_AUTHORITY_SCOPE_MEMBERS)
        .map(|value| format!("resource-{value:02}"))
        .collect();
    assert_eq!(
        CapabilityScopeV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::InvalidScope)
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
    assert_eq!(request.resource(), "journal");
    assert_eq!(request.action(), "read");
    assert_eq!(request.purpose(), "care");
    assert_eq!(request.audience(), "local-host");
    assert_eq!(request.at_time_micros(), 50);
    assert_eq!(request.authority_timeline(), timeline(30));
    assert_eq!(request.at_position(), 50);
    assert_eq!(request.use_count(), 2);
    assert_eq!(request.budget(), 50);
    assert_eq!(request.policy_revision(), hash(9));
    assert_eq!(request.revocation_epoch(), 3);
    assert!(request.revocation_state_current());
    assert_eq!(request.consent(), ConsentEvidenceV1::Active { reference: hash(8) });
    assert_eq!(
        request.environment_constraints(),
        &["device-bound".to_owned(), "local-only".to_owned()]
    );

    let mut mismatches = Vec::new();
    let mut draft = valid.clone();
    draft.resource = "unknown".to_owned();
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.action = "write".to_owned();
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.purpose = "sale".to_owned();
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.audience = "remote".to_owned();
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.actor_entity_id = entity(99);
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.participant_id = Some(entity(99));
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.participant_id = None;
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.plugin_id = Some(plugin(5));
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.use_count = 11;
    mismatches.push(draft);
    let mut draft = valid.clone();
    draft.budget = 101;
    mismatches.push(draft);
    let mut draft = valid;
    draft.environment_constraints = vec!["local-only".to_owned()];
    mismatches.push(draft);

    for draft in mismatches {
        let request = ok(AuthorizationRequestV1::try_from_draft(draft));
        assert_eq!(
            decision_for(&request, std::slice::from_ref(&grant)).outcome(),
            AuthorizationOutcomeV1::ScopeMismatch
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
    assert_eq!(grant.scope().resources(), &["journal", "profile"]);
    assert_eq!(grant.scope().actions(), &["read"]);
    assert_eq!(grant.scope().purposes(), &["care", "planning"]);
    assert_eq!(grant.scope().audiences(), &["local-host"]);
    assert_eq!(grant.scope().actor_entity_ids(), &[entity(10)]);
    assert_eq!(grant.scope().participant_ids(), &[entity(20)]);
    assert_eq!(grant.scope().plugin_id(), Some(plugin_id));
    assert_eq!(grant.scope().max_uses(), 10);
    assert_eq!(grant.scope().budget(), 100);
    assert_eq!(
        grant.scope().environment_constraints(),
        &["device-bound".to_owned(), "local-only".to_owned()]
    );
    assert_eq!(grant.valid_from_position(), 10);
    assert_eq!(grant.valid_until_position(), 100);
    assert_eq!(grant.parent_grant_id(), None);
    assert_eq!(grant.delegation_depth(), 0);
    assert_eq!(grant.max_delegation_depth(), 2);
    assert_eq!(grant.consent_references(), &[hash(8)]);
    assert_eq!(grant.policy_revision(), hash(9));
    assert_eq!(grant.issuance_timeline(), timeline(30));
    assert_eq!(grant.issuance_seq(), 5);
    assert_eq!(grant.revocation_epoch(), 3);
    assert_eq!(grant.revocation_fence(), None);
    assert_eq!(ok(CapabilityGrantV1::decode(&ok(grant.encode()))), grant);

    let mut request = request_draft(authenticated(principal), entity(10));
    request.plugin_id = Some(plugin_id);
    assert!(decision_for(
        &ok(AuthorizationRequestV1::try_from_draft(request)),
        &[grant]
    )
    .is_allowed());
}

#[test]
fn authentication_revocation_expiry_and_coordinates_fail_closed() {
    let principal = principal(1);
    let actor = entity(10);
    let root = root_grant(principal.clone(), vec![actor]);

    let mut draft = request_draft(authenticated(principal.clone()), actor);
    draft.at_time_micros = 100;
    assert_eq!(
        decision_for(&ok(AuthorizationRequestV1::try_from_draft(draft)), &[]).outcome(),
        AuthorizationOutcomeV1::AuthenticationExpired
    );

    let mut draft = request_draft(authenticated(principal.clone()), actor);
    draft.consent = ConsentEvidenceV1::Active { reference: hash(7) };
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
            1 => draft.policy_revision = hash(10),
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
    expired.valid_until_position = 50;
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
    revoked.revocation_fence = Some(50);
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
        scope.clone(),
    );

    let mut invalid = base.clone();
    invalid.grant_id = Hash::zero();
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ZeroIdentity)
    );
    let mut invalid = base.clone();
    invalid.policy_revision = Hash::zero();
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ZeroIdentity)
    );
    let mut invalid = base.clone();
    invalid.valid_until_position = invalid.valid_from_position;
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::InvalidInterval)
    );
    let mut invalid = base.clone();
    invalid.parent_grant_id = Some(hash(2));
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::InvalidDelegationDepth)
    );
    let mut invalid = base.clone();
    invalid.max_delegation_depth = MAX_AUTHORITY_DELEGATION_DEPTH + 1;
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::InvalidDelegationDepth)
    );
    let mut invalid = base.clone();
    invalid.consent_references = vec![hash(8), hash(8)];
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::NonCanonicalOrder)
    );
    let mut invalid = base.clone();
    invalid.revocation_fence = Some(9);
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::InvalidInterval)
    );
    let mut invalid = base.clone();
    invalid.issuance_timeline = timeline(0);
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ZeroIdentity)
    );
    let mut invalid = base;
    invalid.grantee = AuthorityGranteeV1::PluginInstallation {
        controller: principal.clone(),
        plugin_id: plugin(1),
        installation_id: [0; 16],
    };
    assert_eq!(
        CapabilityGrantV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ZeroIdentity)
    );
}

#[test]
fn malformed_requests_are_rejected_before_evaluation() {
    let principal = principal(1);
    let actor = entity(10);
    let base = request_draft(authenticated(principal), actor);
    let mut invalid = base.clone();
    invalid.resource.clear();
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::InvalidText)
    );
    let mut invalid = base.clone();
    invalid.actor_entity_id = entity(0);
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ZeroIdentity)
    );
    let mut invalid = base.clone();
    invalid.authority_timeline = timeline(0);
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ZeroIdentity)
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
        Err(AuthorityErrorV1::InvalidScope)
    );
    let mut invalid = base;
    invalid.consent = ConsentEvidenceV1::Active { reference: Hash::zero() };
    assert_eq!(
        AuthorizationRequestV1::try_from_draft(invalid),
        Err(AuthorityErrorV1::ZeroIdentity)
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
    child.max_delegation_depth = 2;
    variants.push(child);
    let mut child = delegation_child();
    child.valid_from_position = 5;
    variants.push(child);
    let mut child = delegation_child();
    child.valid_until_position = 101;
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
        participant_ids: vec![entity(20)],
        plugin_id: None,
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
        participant_ids: vec![entity(20)],
        plugin_id: None,
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
        participant_ids: vec![entity(20)],
        plugin_id: None,
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
    child.valid_from_position = 20;
    child.valid_until_position = 90;

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
    child_draft.valid_from_position = 20;
    child_draft.valid_until_position = 90;
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
    parent.revocation_fence = Some(50);
    assert_eq!(
        decision_for(
            &request,
            &[ok(CapabilityGrantV1::try_from_draft(parent)), child]
        )
        .outcome(),
        AuthorizationOutcomeV1::RevokedAtFence
    );
}
