//! The Scenario Room store command on a bound in-memory host (#1398).

use pos_core::{AppendDedupKey, AppendDedupScope, ErasureRecoveryLimitsV1};
use pos_runtime::{RoomParticipantKindV1, RoomParticipantV1, RoomPluginRefV1, RoomRuleV1};
use pos_store::StoreConfig;

use super::*;
use crate::mode_profile::{test_bound_host, GatewayModeProfileIdV1};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOVERNANCE: &str = "01JC0GATEWAYW90G0VERN00001";
const PERSONA: &str = "01JC0GATEWAYF1XTVREACT0R00";

fn entity(text: &str) -> Result<EntityId, ulid::DecodeError> {
    ulid::Ulid::from_string(text).map(EntityId::from_ulid)
}

fn host(bound: bool) -> Result<ErasureExecutionHostV1, Box<dyn std::error::Error>> {
    let mut host = ErasureExecutionHostV1::open_verified_empty(
        StoreConfig::Memory,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    if bound {
        drop(test_bound_host(&mut host, GatewayModeProfileIdV1::Local));
    }
    Ok(host)
}

fn admission() -> Result<RoomAdmissionV1, ulid::DecodeError> {
    Ok(RoomAdmissionV1 {
        catalogue: crate::scenario_room::room_catalogue(),
        governance_record: Some(entity(GOVERNANCE)?),
        max_events: 16,
        max_timelines: 16,
    })
}

fn input(value_micro: i64) -> Result<ScenarioRoomInputV1, ulid::DecodeError> {
    Ok(ScenarioRoomInputV1 {
        schema_version: 1,
        tick_duration_ms: 100,
        max_ticks: 600,
        scheduler_seed: [4; 32],
        scheduler_policy: 0,
        intervention_policy: 1,
        plugins: vec![RoomPluginRefV1 {
            plugin_id: "gateway-world-actions".to_owned(),
            version: "0.1.0".to_owned(),
        }],
        rules: vec![RoomRuleV1 {
            rule_id: "gateway-world-actions.impulse.scale".to_owned(),
            value_micro,
        }],
        participants: vec![RoomParticipantV1 {
            entity_id: entity(PERSONA)?,
            kind: RoomParticipantKindV1::Persona,
        }],
        initial_conditions: Vec::new(),
        governance_ref: entity(GOVERNANCE)?,
        privacy_export_ref: entity(GOVERNANCE)?,
    })
}

fn claim(key: u8, digest: u8) -> RoomClaimV1 {
    RoomClaimV1 {
        identity: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([1; 32]),
        ),
        request_digest: [digest; 32],
    }
}

fn create(
    host: &mut ErasureExecutionHostV1,
    key: u8,
    digest: u8,
    value_micro: i64,
    admission: &RoomAdmissionV1,
) -> Result<RoomResult<RoomOutcomeV1>, ulid::DecodeError> {
    Ok(run_room_operation(
        host,
        RoomOperationV1::Create {
            claim: claim(key, digest),
            input: Box::new(input(value_micro)?),
        },
        admission,
    ))
}

fn derive(
    host: &mut ErasureExecutionHostV1,
    key: u8,
    room_id: EntityId,
    parent_revision: u64,
    value_micro: i64,
) -> Result<RoomResult<RoomOutcomeV1>, Box<dyn std::error::Error>> {
    Ok(run_room_operation(
        host,
        RoomOperationV1::Derive {
            claim: claim(key, 9),
            room_id,
            parent_revision,
            input: Box::new(input(value_micro)?),
        },
        &admission()?,
    ))
}

/// `(committed, room, revision)` of an outcome.
fn shape(outcome: &RoomOutcomeV1) -> (bool, EntityId, u64) {
    let (committed, stored) = match outcome {
        RoomOutcomeV1::Committed(stored) => (true, stored),
        RoomOutcomeV1::Existing(stored) => (false, stored),
    };
    (
        committed,
        stored.descriptor.room_id(),
        stored.descriptor.revision().get(),
    )
}

/// The value of a room result, or its refusal as a test error.
fn ok<T>(result: RoomResult<T>) -> Result<T, String> {
    result.map_err(|error| format!("{error:?}"))
}

fn refusal<T>(result: RoomResult<T>) -> String {
    result
        .err()
        .map_or_else(String::new, |error| format!("{error:?}"))
}

#[test]
fn a_room_is_created_retried_derived_and_read() -> TestResult {
    let mut host = host(true)?;
    let admission = admission()?;
    let created = ok(create(&mut host, 1, 1, 250_000, &admission)?)?;
    let (committed, room, revision) = shape(&created);
    assert_eq!((committed, revision), (true, 1));
    if let RoomOutcomeV1::Committed(stored) = &created {
        assert_eq!(stored.seq.as_u64(), 1);
        assert_eq!(stored.produced_under.1.get(), 1);
        assert_eq!(
            stored.produced_under.0.profile_id(),
            "gateway-mode-local-v1"
        );
    }
    // An exact retry returns the room; the same key with another request
    // is a conflict.
    assert_eq!(
        shape(&ok(create(&mut host, 1, 1, 250_000, &admission)?)?),
        (false, room, 1)
    );
    assert_eq!(
        refusal(create(&mut host, 1, 2, 250_000, &admission)?),
        "IdempotencyConflict"
    );
    // Derive from the head, then the ADR-041 section 7 duplicate and a
    // stale proposal.
    assert_eq!(
        shape(&ok(derive(&mut host, 2, room, 1, 500_000)?)?),
        (true, room, 2)
    );
    assert_eq!(
        shape(&ok(derive(&mut host, 2, room, 1, 500_000)?)?),
        (false, room, 2)
    );
    assert_eq!(
        shape(&ok(derive(&mut host, 3, room, 1, 500_000)?)?),
        (false, room, 2)
    );
    assert_eq!(
        refusal(derive(&mut host, 4, room, 1, 750_000)?),
        "StaleParent"
    );
    // A retry of the stale proposal is stale again.
    assert_eq!(
        refusal(derive(&mut host, 4, room, 1, 750_000)?),
        "StaleParent"
    );
    // Content equal to the head's is still a new revision.
    assert_eq!(
        shape(&ok(derive(&mut host, 5, room, 2, 500_000)?)?),
        (true, room, 3)
    );
    for revision in [1, 2, 3] {
        let read = run_room_operation(
            &mut host,
            RoomOperationV1::Read {
                room_id: room,
                revision,
            },
            &admission,
        );
        assert_eq!(shape(&ok(read)?), (false, room, revision));
    }
    for revision in [0, 4] {
        let read = run_room_operation(
            &mut host,
            RoomOperationV1::Read {
                room_id: room,
                revision,
            },
            &admission,
        );
        assert_eq!(refusal(read), "NotFound");
    }
    assert_eq!(refusal(derive(&mut host, 6, room, 9, 1)?), "NotFound");
    assert_eq!(
        refusal(derive(&mut host, 6, EntityId::new(), 1, 1)?),
        "NotFound"
    );
    Ok(())
}

#[test]
fn a_retry_finds_its_room_among_others_and_finishes_an_unfinished_claim() -> TestResult {
    let mut host = host(true)?;
    let admission = admission()?;
    let (_, first, _) = shape(&ok(create(&mut host, 1, 1, 1, &admission)?)?);
    let (_, second, _) = shape(&ok(create(&mut host, 2, 2, 2, &admission)?)?);
    assert_ne!(first, second);
    assert_eq!(
        shape(&ok(create(&mut host, 2, 2, 2, &admission)?)?),
        (false, second, 1)
    );
    // A claim whose room never committed is finished by its retry.
    assert!(matches!(
        claim_request(&mut host, &claim(3, 3), &admission),
        Ok(Claimed::New(_))
    ));
    let finished = ok(create(&mut host, 3, 3, 3, &admission)?)?;
    assert!(shape(&finished).0);
    Ok(())
}

#[test]
fn admission_refusals_commit_nothing() -> TestResult {
    let mut host = host(true)?;
    let mut ungoverned = admission()?;
    ungoverned.governance_record = None;
    assert_eq!(
        refusal(create(&mut host, 1, 1, 1, &ungoverned)?),
        "GovernanceUnknown"
    );
    ungoverned.governance_record = Some(EntityId::new());
    assert_eq!(
        refusal(create(&mut host, 1, 1, 1, &ungoverned)?),
        "GovernanceUnknown"
    );
    let unbundled = RoomAdmissionV1 {
        catalogue: ScenarioRoomCatalogueV1::default(),
        ..admission()?
    };
    assert_eq!(
        refusal(create(&mut host, 1, 1, 1, &unbundled)?),
        "Room(PluginNotBundled)"
    );
    let (_, room, _) = shape(&ok(create(&mut host, 1, 1, 1, &admission()?)?)?);
    let mut invalid = input(1)?;
    invalid.tick_duration_ms = 0;
    let refused = run_room_operation(
        &mut host,
        RoomOperationV1::Derive {
            claim: claim(2, 2),
            room_id: room,
            parent_revision: 1,
            input: Box::new(invalid),
        },
        &admission()?,
    );
    assert_eq!(refusal(refused), "Room(InvalidField(TickDurationMs))");
    assert_eq!(refusal(derive(&mut host, 2, room, 1, 1)?).len(), 0);
    Ok(())
}

#[test]
fn every_ceiling_refuses_before_a_commit() -> TestResult {
    for (max_timelines, max_events) in [(0, 16), (1, 16), (16, 0)] {
        let mut host = host(true)?;
        let limited = RoomAdmissionV1 {
            max_timelines,
            max_events,
            ..admission()?
        };
        assert_eq!(
            refusal(create(&mut host, 1, 1, 1, &limited)?),
            "LimitReached",
            "{max_timelines} {max_events}"
        );
    }
    Ok(())
}

#[test]
fn an_unbound_store_cannot_disclose_the_mode_a_revision_was_produced_under() -> TestResult {
    let mut host = host(false)?;
    assert_eq!(
        refusal(create(&mut host, 1, 1, 1, &admission()?)?),
        "ModeUnavailable"
    );
    Ok(())
}

#[test]
fn a_revision_identity_is_never_appended_twice() -> TestResult {
    let mut host = host(true)?;
    let admission = admission()?;
    let created = ok(create(&mut host, 1, 1, 1, &admission)?)?;
    let RoomOutcomeV1::Committed(stored) = created else {
        return Err("the first create commits".into());
    };
    let again = append_revision(
        &mut host,
        stored.timeline,
        &stored.descriptor,
        stored.event_id,
        &admission,
    );
    assert!(refusal(again).starts_with("Store("));
    Ok(())
}
