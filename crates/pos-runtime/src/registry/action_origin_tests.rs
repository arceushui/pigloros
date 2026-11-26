//! The origin of every `submit_action` refusal (ADR-141 §2, P2).

use pos_core::{event::CanonicalBytes, ids::EntityId};

use super::test_ext::{TestErrorExt, TestValueExt};
use super::*;

const ORIGIN_ACTION: &str = "origin.action";

struct OriginPlugin(PluginId);

impl Plugin for OriginPlugin {
    fn id(&self) -> PluginId {
        self.0
    }

    fn name(&self) -> &'static str {
        "origin-plugin"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(ORIGIN_ACTION)],
            owned_entity_kinds: vec![],
            has_driver: false,
            has_reducer: false,
        }
    }
}

/// An approver that refuses every proposal with one fixed reason.
struct RefusingApprover(ActionRejected);

impl ActionApprover for RefusingApprover {
    fn approve(&self, _proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        Err(self.0.clone())
    }
}

/// An approver whose draft exceeds the proposed-action payload bound.
struct OversizedOriginDraftApprover;

impl ActionApprover for OversizedOriginDraftApprover {
    fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        Ok(EventDraft::new(
            proposal.actor_entity_id,
            proposal.event_type.clone(),
            CanonicalBytes::from_vec(vec![0; 4097]),
        ))
    }
}

fn origin_registry() -> PluginRegistry {
    PluginRegistry::new().with_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))
}

fn registry_with_origin_approver(approver: Box<dyn ActionApprover>) -> PluginRegistry {
    let mut registry = origin_registry();
    registry
        .register_generated_with_approver(
            &OriginPlugin(PluginId::new()),
            None,
            None,
            Some(approver),
            [Kind::new(ORIGIN_ACTION)],
        )
        .test_ok();
    registry
}

fn origin_proposal(event_type: &str) -> ProposedAction {
    ProposedAction::new(
        Kind::new(event_type),
        EntityId::new(),
        CanonicalBytes::from_static(b"origin"),
        Kind::new(format!("{event_type}.submit")),
    )
}

fn submission_error(registry: &PluginRegistry, event_type: &str) -> ActionSubmissionError {
    registry
        .submit_action(TimelineId::new(), &origin_proposal(event_type))
        .test_err()
}

const fn tagged_rejection(
    origin: ActionRejectionOriginV1,
    reason: ActionRejected,
) -> ActionSubmissionError {
    ActionSubmissionError::Rejected { origin, reason }
}

/// Insert an approver-map entry for `event_type` whose entry has `approver`
/// and no bound output policy.
fn insert_unbound_entry(
    registry: &mut PluginRegistry,
    event_type: &str,
    approver: Option<Box<dyn ActionApprover>>,
) {
    let plugin_id = PluginId::new();
    let owner_id = registry.factual_owner_id_for(None, None, event_type);
    registry.plugins.insert(
        plugin_id,
        PluginEntry {
            name: event_type.to_owned(),
            version: "test".to_owned(),
            owned_event_types: Vec::new(),
            from_plugin: false,
            driver: None,
            approver,
            last_tick: None,
            event_cursor: Seq::ZERO,
            registration: None,
            output_admission: None,
            manifest_slot: None,
            event_observation: DriverEventObservation::default(),
            pass_state: PassState::new(owner_id),
            chain: StepChainV1::Lookup,
        },
    );
    registry
        .approver_map
        .insert(Kind::new(event_type), plugin_id);
}

#[test]
fn every_approver_refusal_is_attributed_to_the_approver() {
    let reasons = [
        ActionRejected::UnknownEventType,
        ActionRejected::CapabilityNotGranted,
        ActionRejected::InvalidActorEntityId,
        ActionRejected::DomainValidationFailed("approver".to_owned()),
        ActionRejected::PayloadTooLarge { size: 9, max: 8 },
    ];
    for reason in reasons {
        let registry = registry_with_origin_approver(Box::new(RefusingApprover(reason.clone())));
        assert_eq!(
            submission_error(&registry, ORIGIN_ACTION),
            tagged_rejection(ActionRejectionOriginV1::Approver, reason)
        );
    }
}

#[test]
fn an_oversized_approver_draft_is_attributed_to_the_approved_output() {
    let registry = registry_with_origin_approver(Box::new(OversizedOriginDraftApprover));
    assert_eq!(
        submission_error(&registry, ORIGIN_ACTION),
        tagged_rejection(
            ActionRejectionOriginV1::ApprovedOutput,
            ActionRejected::PayloadTooLarge {
                size: 4097,
                max: 4096,
            },
        )
    );
}

#[test]
fn a_missing_plugin_is_attributed_to_the_registry() {
    let mut registry = origin_registry();
    registry
        .approver_map
        .insert(Kind::new("origin.missing"), PluginId::new());
    assert_eq!(
        submission_error(&registry, "origin.missing"),
        tagged_rejection(
            ActionRejectionOriginV1::Registry,
            ActionRejected::UnknownEventType,
        )
    );
}

#[test]
fn a_missing_approver_is_attributed_to_the_registry() {
    let mut registry = origin_registry();
    insert_unbound_entry(&mut registry, "origin.unapproved", None);
    assert_eq!(
        submission_error(&registry, "origin.unapproved"),
        tagged_rejection(
            ActionRejectionOriginV1::Registry,
            ActionRejected::UnknownEventType,
        )
    );
}

#[test]
fn a_missing_output_policy_is_attributed_to_the_registry() {
    let mut registry = origin_registry();
    let approver = Box::new(RefusingApprover(ActionRejected::InvalidActorEntityId));
    insert_unbound_entry(&mut registry, "origin.unbound", Some(approver));
    assert_eq!(
        submission_error(&registry, "origin.unbound"),
        tagged_rejection(
            ActionRejectionOriginV1::Registry,
            ActionRejected::DomainValidationFailed(
                "action approver has no bound output policy".to_owned(),
            ),
        )
    );
}

#[test]
fn the_rejection_names_its_origin_and_reason() {
    let error = tagged_rejection(
        ActionRejectionOriginV1::ApprovedOutput,
        ActionRejected::CapabilityNotGranted,
    );
    assert_eq!(
        error.to_string(),
        "ApprovedOutput rejected the action: capability not granted"
    );
}
