use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use pos_core::{
    ActionApprover, ActionRejected, CanonicalBytes, Capability, EntityId, EventDraft, Hash, Kind,
    Plugin, PluginId, ProposedAction, Seq, TimelineId,
};
use pos_runtime::{
    DomainImplementationKindV1, Driver, ObservationView, PluginAvailabilityV1,
    PluginCompositionErrorV1, PluginExecutionModeV1, PluginIsolationV1, PluginPinFieldV1,
    PluginPinV1, PluginRegistrationV1, PluginRegistry, RequiredPluginCompositionV1,
    RequiredPluginV1, RuntimeError, StepOutput, MAX_REQUIRED_PLUGINS_V1,
};

trait TestValueExt<T> {
    fn test_ok(self) -> T;
}

impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected composition fixture error: {error:?}"
            )))
        })
    }
}

struct TestPlugin {
    id: PluginId,
    name: &'static str,
    version: &'static str,
    has_driver: bool,
    event_type: Option<&'static str>,
}

impl Plugin for TestPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn version(&self) -> &'static str {
        self.version
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: self.event_type.into_iter().map(Kind::new).collect(),
            has_driver: self.has_driver,
            ..Capability::default()
        }
    }
}

struct CountingDriver(Arc<AtomicUsize>);

impl Driver for CountingDriver {
    fn name(&self) -> &'static str {
        "counting-driver"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(StepOutput::empty())
    }
}

const fn digest(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn pin(
    byte: u8,
    implementation_kind: DomainImplementationKindV1,
    isolation: PluginIsolationV1,
    roles: &[&str],
) -> PluginPinV1 {
    PluginPinV1::try_new(
        implementation_kind,
        isolation,
        digest(byte),
        roles.iter().map(|role| (*role).to_owned()).collect(),
    )
    .test_ok()
}

fn requirement(plugin: &TestPlugin, pin: PluginPinV1) -> RequiredPluginV1 {
    RequiredPluginV1::try_new(plugin.id, plugin.version, pin).test_ok()
}

const fn plugin(id: PluginId, name: &'static str) -> TestPlugin {
    TestPlugin {
        id,
        name,
        version: "1.2.3",
        has_driver: false,
        event_type: None,
    }
}

struct AcceptingApprover;

impl ActionApprover for AcceptingApprover {
    fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        Ok(EventDraft::new(
            proposal.actor_entity_id,
            proposal.event_type.clone(),
            proposal.payload.clone(),
        ))
    }
}

#[test]
fn exact_native_plugin_and_governed_public_adapter_resolve_in_required_order() {
    let world = plugin(PluginId::new(), "first-party-world");
    let evaluation = plugin(PluginId::new(), "community-evaluator-adapter");
    let world_pin = pin(
        1,
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        &["world"],
    );
    let evaluation_pin = pin(
        2,
        DomainImplementationKindV1::PublicAdapter,
        PluginIsolationV1::GovernedCommunity,
        &["evaluation"],
    );
    let mut registry = PluginRegistry::new();
    registry
        .register_pinned(
            &world,
            PluginRegistrationV1::new(world_pin.clone(), PluginAvailabilityV1::Available),
            None,
            None,
        )
        .test_ok();
    registry
        .register_pinned(
            &evaluation,
            PluginRegistrationV1::new(evaluation_pin.clone(), PluginAvailabilityV1::Available),
            None,
            None,
        )
        .test_ok();

    let local = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Local,
        vec![
            requirement(&world, world_pin.clone()),
            requirement(&evaluation, evaluation_pin.clone()),
        ],
    )
    .test_ok();
    let resolved = registry.resolve_required_composition(&local).test_ok();
    assert_eq!(resolved.mode(), PluginExecutionModeV1::Local);
    assert_eq!(resolved.plugins()[0].plugin_id(), world.id);
    assert_eq!(resolved.plugins()[0].name(), world.name);
    assert_eq!(resolved.plugins()[0].version(), world.version);
    assert_eq!(resolved.plugins()[0].pin(), &world_pin);
    assert_eq!(resolved.plugins()[1].plugin_id(), evaluation.id);
    assert_eq!(resolved.plugins()[1].pin(), &evaluation_pin);
    assert_eq!(registry.composition().plugins[0].pin, Some(world_pin));

    let air_gapped = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::AirGapped,
        vec![
            requirement(
                &world,
                pin(
                    1,
                    DomainImplementationKindV1::Plugin,
                    PluginIsolationV1::OperatorTrustedNative,
                    &["world"],
                ),
            ),
            requirement(&evaluation, evaluation_pin),
        ],
    )
    .test_ok();
    assert_eq!(
        registry
            .resolve_required_composition(&air_gapped)
            .test_err(),
        PluginCompositionErrorV1::ExecutionModeMismatch
    );

    let mut air_gapped_registry = PluginRegistry::new_air_gapped();
    air_gapped_registry
        .register_pinned(
            &world,
            PluginRegistrationV1::new(
                air_gapped.plugins()[0].pin().clone(),
                PluginAvailabilityV1::Available,
            ),
            None,
            None,
        )
        .test_ok();
    air_gapped_registry
        .register_pinned(
            &evaluation,
            PluginRegistrationV1::new(
                air_gapped.plugins()[1].pin().clone(),
                PluginAvailabilityV1::Available,
            ),
            None,
            None,
        )
        .test_ok();
    assert_eq!(
        air_gapped_registry
            .resolve_required_composition(&air_gapped)
            .test_ok()
            .mode(),
        PluginExecutionModeV1::AirGapped
    );
}

#[test]
fn pin_and_requirement_metadata_are_bounded() {
    assert_eq!(
        PluginPinV1::try_new(
            DomainImplementationKindV1::Plugin,
            PluginIsolationV1::OperatorTrustedNative,
            Hash::zero(),
            vec!["world".to_owned()],
        ),
        Err(PluginCompositionErrorV1::InvalidMetadata)
    );
    for roles in [
        Vec::new(),
        vec![String::new()],
        vec!["world".to_owned(), "world".to_owned()],
    ] {
        assert_eq!(
            PluginPinV1::try_new(
                DomainImplementationKindV1::Plugin,
                PluginIsolationV1::OperatorTrustedNative,
                digest(1),
                roles,
            ),
            Err(PluginCompositionErrorV1::InvalidMetadata)
        );
    }

    let valid_pin = pin(
        1,
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        &["world"],
    );
    let nil_id = serde_json::from_str("\"00000000000000000000000000\"").test_ok();
    assert_eq!(
        RequiredPluginV1::try_new(nil_id, "1.0.0", valid_pin.clone()),
        Err(PluginCompositionErrorV1::InvalidMetadata)
    );
    assert_eq!(
        RequiredPluginV1::try_new(PluginId::new(), String::new(), valid_pin),
        Err(PluginCompositionErrorV1::InvalidMetadata)
    );
    assert_eq!(
        RequiredPluginCompositionV1::try_new(PluginExecutionModeV1::Local, Vec::new()),
        Err(PluginCompositionErrorV1::EmptyComposition)
    );
}

#[test]
fn complete_requirement_rejects_duplicate_owners_and_oversized_compositions() {
    let duplicate_id = PluginId::new();
    let duplicate_plugins = vec![
        RequiredPluginV1::try_new(
            duplicate_id,
            "1.0.0",
            pin(
                2,
                DomainImplementationKindV1::Plugin,
                PluginIsolationV1::OperatorTrustedNative,
                &["world"],
            ),
        )
        .test_ok(),
        RequiredPluginV1::try_new(
            duplicate_id,
            "1.0.0",
            pin(
                3,
                DomainImplementationKindV1::Plugin,
                PluginIsolationV1::OperatorTrustedNative,
                &["society"],
            ),
        )
        .test_ok(),
    ];
    assert_eq!(
        RequiredPluginCompositionV1::try_new(PluginExecutionModeV1::Local, duplicate_plugins,),
        Err(PluginCompositionErrorV1::DuplicateImplementation {
            plugin_id: duplicate_id,
        })
    );

    let first = plugin(PluginId::new(), "world-one");
    let second = plugin(PluginId::new(), "world-two");
    let duplicate_role = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Local,
        vec![
            requirement(
                &first,
                pin(
                    4,
                    DomainImplementationKindV1::Plugin,
                    PluginIsolationV1::OperatorTrustedNative,
                    &["world"],
                ),
            ),
            requirement(
                &second,
                pin(
                    5,
                    DomainImplementationKindV1::Plugin,
                    PluginIsolationV1::OperatorTrustedNative,
                    &["world"],
                ),
            ),
        ],
    );
    assert_eq!(
        duplicate_role,
        Err(PluginCompositionErrorV1::DuplicateRole {
            role: "world".to_owned(),
        })
    );

    let oversized = (0..=MAX_REQUIRED_PLUGINS_V1)
        .map(|index| {
            RequiredPluginV1::try_new(
                PluginId::new(),
                "1.0.0",
                pin(
                    6,
                    DomainImplementationKindV1::Plugin,
                    PluginIsolationV1::OperatorTrustedNative,
                    &[format!("role-{index}").as_str()],
                ),
            )
            .test_ok()
        })
        .collect();
    assert_eq!(
        RequiredPluginCompositionV1::try_new(PluginExecutionModeV1::Local, oversized),
        Err(PluginCompositionErrorV1::CompositionTooLarge)
    );
}

#[test]
fn resolution_rejects_missing_unpinned_and_reordered_implementations_without_fallback() {
    let registered = plugin(PluginId::new(), "registered-world");
    let expected = plugin(PluginId::new(), "expected-world");
    let world_pin = pin(
        7,
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        &["world"],
    );
    let mut registry = PluginRegistry::new();
    registry
        .register_pinned(
            &registered,
            PluginRegistrationV1::new(world_pin.clone(), PluginAvailabilityV1::Available),
            None,
            None,
        )
        .test_ok();
    let missing = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Local,
        vec![requirement(&expected, world_pin.clone())],
    )
    .test_ok();
    assert_eq!(
        registry.resolve_required_composition(&missing),
        Err(PluginCompositionErrorV1::MissingImplementation {
            plugin_id: expected.id,
        })
    );

    let mut legacy = PluginRegistry::new();
    legacy.register(&registered, None, None).test_ok();
    let required = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Local,
        vec![requirement(&registered, world_pin.clone())],
    )
    .test_ok();
    assert_eq!(
        legacy.resolve_required_composition(&required),
        Err(PluginCompositionErrorV1::UnpinnedImplementation {
            plugin_id: registered.id,
        })
    );

    let society = plugin(PluginId::new(), "society");
    let society_pin = pin(
        8,
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        &["society"],
    );
    registry
        .register_pinned(
            &society,
            PluginRegistrationV1::new(society_pin.clone(), PluginAvailabilityV1::Available),
            None,
            None,
        )
        .test_ok();
    let reordered = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Local,
        vec![
            requirement(&society, society_pin),
            requirement(&registered, world_pin),
        ],
    )
    .test_ok();
    assert_eq!(
        registry.resolve_required_composition(&reordered),
        Err(PluginCompositionErrorV1::ExecutionOrderMismatch)
    );
}

#[test]
fn resolution_rejects_every_incompatible_pin_field() {
    let registered = plugin(PluginId::new(), "world");
    let registered_pin = pin(
        9,
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        &["world"],
    );
    let mut registry = PluginRegistry::new();
    registry
        .register_pinned(
            &registered,
            PluginRegistrationV1::new(registered_pin.clone(), PluginAvailabilityV1::Available),
            None,
            None,
        )
        .test_ok();

    let cases = [
        ("9.9.9", registered_pin, PluginPinFieldV1::Version),
        (
            registered.version,
            pin(
                10,
                DomainImplementationKindV1::Plugin,
                PluginIsolationV1::OperatorTrustedNative,
                &["world"],
            ),
            PluginPinFieldV1::ConfigurationDigest,
        ),
        (
            registered.version,
            pin(
                9,
                DomainImplementationKindV1::PublicAdapter,
                PluginIsolationV1::OperatorTrustedNative,
                &["world"],
            ),
            PluginPinFieldV1::ImplementationKind,
        ),
        (
            registered.version,
            pin(
                9,
                DomainImplementationKindV1::Plugin,
                PluginIsolationV1::GovernedCommunity,
                &["world"],
            ),
            PluginPinFieldV1::Isolation,
        ),
        (
            registered.version,
            pin(
                9,
                DomainImplementationKindV1::Plugin,
                PluginIsolationV1::OperatorTrustedNative,
                &["world", "society"],
            ),
            PluginPinFieldV1::Roles,
        ),
    ];
    for (version, expected_pin, field) in cases {
        let required = RequiredPluginCompositionV1::try_new(
            PluginExecutionModeV1::Local,
            vec![RequiredPluginV1::try_new(registered.id, version, expected_pin).test_ok()],
        )
        .test_ok();
        assert_eq!(
            registry.resolve_required_composition(&required),
            Err(PluginCompositionErrorV1::IncompatibleImplementation {
                plugin_id: registered.id,
                field,
            })
        );
    }
}

#[test]
fn every_non_available_state_fails_closed_before_resolution() {
    for availability in [
        PluginAvailabilityV1::Disabled,
        PluginAvailabilityV1::Unavailable,
        PluginAvailabilityV1::Revoked,
        PluginAvailabilityV1::Trapped,
        PluginAvailabilityV1::ResourceExhausted,
    ] {
        let registered = plugin(PluginId::new(), "unavailable-world");
        let registered_pin = pin(
            11,
            DomainImplementationKindV1::Plugin,
            PluginIsolationV1::OperatorTrustedNative,
            &["world"],
        );
        let mut registry = PluginRegistry::new();
        registry
            .register_pinned(
                &registered,
                PluginRegistrationV1::new(registered_pin.clone(), availability),
                None,
                None,
            )
            .test_ok();
        let required = RequiredPluginCompositionV1::try_new(
            PluginExecutionModeV1::Local,
            vec![requirement(&registered, registered_pin)],
        )
        .test_ok();
        assert_eq!(
            registry.resolve_required_composition(&required),
            Err(PluginCompositionErrorV1::ImplementationUnavailable {
                plugin_id: registered.id,
                availability,
            })
        );
    }
}

#[test]
fn registration_rejects_duplicate_role_ownership_before_mutation() {
    let first = plugin(PluginId::new(), "first-world");
    let second = plugin(PluginId::new(), "second-world");
    let mut registry = PluginRegistry::new();
    registry
        .register_pinned(
            &first,
            PluginRegistrationV1::new(
                pin(
                    12,
                    DomainImplementationKindV1::Plugin,
                    PluginIsolationV1::OperatorTrustedNative,
                    &["world"],
                ),
                PluginAvailabilityV1::Available,
            ),
            None,
            None,
        )
        .test_ok();
    let result = registry.register_pinned(
        &second,
        PluginRegistrationV1::new(
            pin(
                13,
                DomainImplementationKindV1::Plugin,
                PluginIsolationV1::OperatorTrustedNative,
                &["world"],
            ),
            PluginAvailabilityV1::Available,
        ),
        None,
        None,
    );
    assert_eq!(
        result.test_err().to_string(),
        "domain role 'world' has more than one owner"
    );
    assert_eq!(registry.len(), 1);
}

#[test]
fn pinned_action_policy_retains_the_single_approver_route() {
    let action = TestPlugin {
        id: PluginId::new(),
        name: "world-action-policy",
        version: "1.2.3",
        has_driver: false,
        event_type: Some("world.action"),
    };
    let action_pin = pin(
        15,
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        &["domain-action-policy"],
    );
    let mut registry = PluginRegistry::new();
    registry
        .register_pinned_with_approver(
            &action,
            PluginRegistrationV1::new(action_pin.clone(), PluginAvailabilityV1::Available),
            None,
            None,
            Some(Box::new(AcceptingApprover)),
            [Kind::new("world.action")],
        )
        .test_ok();
    let required = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Local,
        vec![requirement(&action, action_pin)],
    )
    .test_ok();
    registry.resolve_required_composition(&required).test_ok();

    let actor = EntityId::new();
    let draft = registry
        .submit_action(&ProposedAction::new(
            Kind::new("world.action"),
            actor,
            CanonicalBytes::from_static(b"walk"),
            Kind::new("world.action.submit"),
        ))
        .test_ok();
    assert_eq!(draft.entity, actor);
    assert_eq!(draft.event_type.as_str(), "world.action");
}

trait TestErrorExt<T, E> {
    fn test_err(self) -> E;
}

impl<T, E: std::fmt::Debug> TestErrorExt<T, E> for Result<T, E> {
    fn test_err(self) -> E {
        self.err().unwrap_or_else(|| {
            std::panic::resume_unwind(Box::new("expected composition fixture failure"))
        })
    }
}

#[test]
fn replay_resolves_only_replay_evidence_and_never_invokes_live_drivers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let registered = TestPlugin {
        id: PluginId::new(),
        name: "replay-world",
        version: "1.2.3",
        has_driver: true,
        event_type: None,
    };
    let registered_pin = pin(
        14,
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        &["world"],
    );
    let mut replay = PluginRegistry::new_replay();
    replay
        .register_pinned(
            &registered,
            PluginRegistrationV1::new(registered_pin.clone(), PluginAvailabilityV1::Available),
            None,
            Some(Box::new(CountingDriver(Arc::clone(&calls)))),
        )
        .test_ok();
    let replay_requirement = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Replay,
        vec![requirement(&registered, registered_pin.clone())],
    )
    .test_ok();
    assert_eq!(
        replay
            .resolve_required_composition(&replay_requirement)
            .test_ok()
            .mode(),
        PluginExecutionModeV1::Replay
    );
    assert_eq!(
        replay.step_all(TimelineId::new()).test_err().to_string(),
        "recorder mode mismatch: expected Live, got Replay"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        replay
            .tick_cadenced(TimelineId::new(), 0)
            .test_err()
            .to_string(),
        "recorder mode mismatch: expected Live, got Replay"
    );
    assert_eq!(
        replay
            .step_all_anchored(TimelineId::new(), Seq::ZERO)
            .test_err()
            .to_string(),
        "recorder mode mismatch: expected Live, got Replay"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let local_requirement = RequiredPluginCompositionV1::try_new(
        PluginExecutionModeV1::Local,
        vec![requirement(&registered, registered_pin)],
    )
    .test_ok();
    assert_eq!(
        replay.resolve_required_composition(&local_requirement),
        Err(PluginCompositionErrorV1::ExecutionModeMismatch)
    );
    assert_eq!(
        PluginRegistry::new().resolve_required_composition(&replay_requirement),
        Err(PluginCompositionErrorV1::ExecutionModeMismatch)
    );
}
