//! The public Gateway boundary for human ingress (#319).
//!
//! Wave 8 has no installed Gateway action profile, so the production
//! composition fails closed and no first-party action has another route.
//! Authentication and authorization are proven at the public
//! `GatewayAuthorization` seam the Gateway consults before any admission.

use std::sync::Arc;

use piglor_gateway::{
    Gateway, GatewayAuthenticationAdapter, GatewayAuthenticationError,
    GatewayAuthenticationRequest, GatewayAuthorization, GatewayAuthorizationRequest, GatewayError,
    HumanActionRequest, LocalAuthenticationAdapter,
};
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    AuthorityGranteeV1, AuthorityPersistenceHostV1, AuthorityPersistenceStateV1,
    AuthorityRegistrySnapshotV1, AuthorityRoleV1, AuthorityViewV1, CapabilityGrantDraftV1,
    CapabilityGrantV1, CapabilityScopeDraftV1, CapabilityScopeV1, EntityId,
    ErasureRecoveryLimitsV1, Hash, Kind, PrincipalRefV1, ProposedAction, Seq, TimelineId, WallTime,
};
use pos_plugin_world::{encode_actuator_pair_v1, ActionKindV1, WorldActionV1};
use pos_runtime::ErasureExecutionHostV1;
use pos_store::StoreConfig;

use super::{harness::Capture, support::TestOk};

const ACTION: &str = "world.action.v1";
const CAPABILITY: &str = "world.action.v1.submit";

/// An authentication adapter whose provider is unavailable.
struct UnavailableAuthentication;

impl GatewayAuthenticationAdapter for UnavailableAuthentication {
    fn authenticate(
        &self,
        _request: &GatewayAuthenticationRequest,
    ) -> Result<AuthenticatedPrincipalResultV1, GatewayAuthenticationError> {
        Err(GatewayAuthenticationError::Unavailable)
    }
}

/// Host-pinned authority that lets one actor submit world actions.
struct PinnedAuthority {
    authenticated: AuthenticatedPrincipalResultV1,
    view: AuthorityViewV1,
    registry: AuthorityRegistrySnapshotV1,
}

fn pinned_authority(actor: EntityId) -> PinnedAuthority {
    let principal = PrincipalRefV1::try_new([1; 16], "gateway.test").test_ok();
    let authenticated =
        AuthenticatedPrincipalResultV1::try_from_draft(AuthenticatedPrincipalDraftV1 {
            principal: principal.clone(),
            adapter_id: "fixture".to_owned(),
            assurance: AssuranceLevelV1::try_new(1).test_ok(),
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(u64::MAX),
            binding_digest: Hash::from_bytes([2; 32]),
        })
        .test_ok();
    let registry_digest = Hash::from_bytes([3; 32]);
    let grant = CapabilityGrantV1::try_from_draft(CapabilityGrantDraftV1 {
        grant_id: Hash::from_bytes([5; 32]),
        grantor: principal.clone(),
        grantee: AuthorityGranteeV1::Principal(principal),
        trust_domain: "gateway.test".to_owned(),
        scope: CapabilityScopeV1::try_from_draft(CapabilityScopeDraftV1 {
            resources: vec!["timeline.events".to_owned(), ACTION.to_owned()],
            actions: vec!["read".to_owned(), CAPABILITY.to_owned()],
            purposes: vec!["action".to_owned(), "read".to_owned()],
            audiences: vec!["gateway".to_owned()],
            actor_entity_ids: vec![actor],
            subject_ids: Vec::new(),
            participant_ids: Vec::new(),
            plugin_id: None,
            principal_roles: vec![AuthorityRoleV1::Actor],
            max_uses: 1,
            budget: 1,
            environment_constraints: Vec::new(),
        })
        .test_ok(),
        valid_from_position: Seq::from_u64(1),
        valid_until_position: Seq::from_u64(50),
        parent_grant_id: None,
        delegation_depth: 0,
        max_delegation_depth: 0,
        permitted_delegate_classes: Vec::new(),
        consent_references: Vec::new(),
        policy_revision: Hash::from_bytes([4; 32]),
        issuance_timeline: TimelineId::new(),
        issuance_seq: Seq::from_u64(1),
        revocation_epoch: 0,
        revocation_fence: None,
        authority_registry_digest: registry_digest,
    })
    .test_ok();
    let registry = AuthorityRegistrySnapshotV1::try_new(
        registry_digest,
        vec![authenticated.registry_binding_digest()],
        vec![grant.binding_digest().test_ok()],
        Vec::new(),
    )
    .test_ok();
    let host = AuthorityPersistenceHostV1::new(&registry);
    let mut state = AuthorityPersistenceStateV1::new();
    state
        .issue_grant(host.authorize_grant(&grant).test_ok(), grant.clone())
        .test_ok();
    PinnedAuthority {
        authenticated,
        view: state.view(grant.grant_id()).test_ok(),
        registry,
    }
}

fn authorization(
    pinned: &PinnedAuthority,
    adapter: Arc<dyn GatewayAuthenticationAdapter>,
    revocation_state_current: bool,
) -> GatewayAuthorization {
    GatewayAuthorization::new_with_revocation_state(
        adapter,
        pinned.view.clone(),
        pinned.registry.clone(),
        revocation_state_current,
    )
}

fn decide(authorization: &GatewayAuthorization, actor: EntityId) -> String {
    authorization
        .authorize(GatewayAuthorizationRequest::action(
            actor,
            TimelineId::new(),
            ACTION,
            CAPABILITY,
            WallTime::from_micros(10),
        ))
        .map_or_else(|error| error.to_string(), |_| "allowed".to_owned())
}

/// PCF-FP-001: authentication precedes authorization, and both precede any
/// domain approval or admission of a human request.
#[must_use]
pub fn authorization_precedence() -> Capture {
    let mut capture = Capture::default();
    let actor = EntityId::new();
    let outsider = EntityId::new();
    let pinned = pinned_authority(actor);
    let local = Arc::new(LocalAuthenticationAdapter::new(
        pinned.authenticated.clone(),
    ));
    capture.record(
        "none",
        "rung.authentication",
        decide(
            &authorization(&pinned, Arc::new(UnavailableAuthentication), true),
            outsider,
        ),
    );
    capture.record(
        "none",
        "rung.authorization",
        decide(&authorization(&pinned, local.clone(), true), outsider),
    );
    capture.record(
        "none",
        "authorized",
        decide(&authorization(&pinned, local.clone(), true), actor),
    );
    capture.record(
        "none",
        "stale-revocation-state",
        decide(&authorization(&pinned, local, false), actor),
    );
    capture
}

fn world_action(actor: EntityId, body: EntityId) -> ProposedAction {
    let payload = WorldActionV1 {
        actor_entity_id: actor,
        body_entity_id: body,
        action_kind: ActionKindV1::Impulse,
        params_cbor: encode_actuator_pair_v1(1.0, 0.0).test_ok(),
        action_scope: 0,
        catalogue_version: 1,
        tick: 1,
    }
    .encode()
    .test_ok();
    ProposedAction::new(Kind::new(ACTION), actor, payload, Kind::new(CAPABILITY))
}

/// The fail-closed outcome of composing an action-capable Gateway.
fn composition(composed: Result<Gateway, GatewayError>) -> String {
    match composed {
        Ok(gateway) => {
            drop(gateway);
            "composed".to_owned()
        }
        Err(GatewayError::ActionRegistry(_)) => "fails-closed".to_owned(),
        Err(error) => error.to_string(),
    }
}

fn host(config: StoreConfig) -> ErasureExecutionHostV1 {
    ErasureExecutionHostV1::open_verified_empty(config, ErasureRecoveryLimitsV1::compiled_maximum())
        .test_ok()
}

/// PCF-ING-003: the production Gateway composition fails closed without an
/// installed action profile, and a Gateway without Principal authorization
/// has no human route, even for a valid first-party action.
#[must_use]
pub fn first_party_has_no_privileged_route() -> Capture {
    let mut capture = Capture::default();
    let directory = tempfile::tempdir().test_ok();
    let sqlite = |name: &str| StoreConfig::Sqlite {
        path: directory.path().join(name).to_string_lossy().into_owned(),
    };
    let backends = [
        ("memory", StoreConfig::Memory, StoreConfig::Memory),
        (
            "sqlite",
            sqlite("authorized.sqlite"),
            sqlite("unauthorized.sqlite"),
        ),
    ];
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .test_ok();
    for (store, authorized_store, unauthorized_store) in backends {
        let actor = EntityId::new();
        let body = EntityId::new();
        let pinned = pinned_authority(actor);
        let local = Arc::new(LocalAuthenticationAdapter::new(
            pinned.authenticated.clone(),
        ));
        runtime.block_on(async {
            capture.record(
                store,
                "authorized-composition",
                composition(Gateway::new_with_erasure_host_and_authorization(
                    host(authorized_store),
                    [body],
                    authorization(&pinned, local, true),
                )),
            );

            let gateway = Gateway::new_with_erasure_host(host(unauthorized_store)).test_ok();
            let timeline = gateway
                .create_timeline("first-party")
                .await
                .test_ok()
                .id()
                .to_string();
            let outcome = gateway
                .submit_human_action(HumanActionRequest {
                    timeline_id: &timeline,
                    proposal: world_action(actor, body),
                    idempotency_key: Some("first-party"),
                    observed_through: None,
                })
                .await;
            capture.record(
                store,
                "unauthorized-gateway",
                outcome.map_or_else(|error| error.to_string(), |_| "committed".to_owned()),
            );
            let page = gateway.read_events_page(&timeline, 0, 16).await.test_ok();
            capture.record(store, "committed", page.events.len());
            gateway.shutdown().await.test_ok();
            drop(gateway);
        });
    }
    capture
}
