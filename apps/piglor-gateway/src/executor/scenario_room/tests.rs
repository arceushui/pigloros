//! The Scenario Room store command on a bound in-memory host (#1398).

use pos_core::{ErasureRecoveryLimitsV1, GatewayModeBindingHostV1, GatewayModeProfileRefV1};
use pos_runtime::{RoomParticipantKindV1, RoomParticipantV1, RoomPluginRefV1, RoomRuleV1};
use pos_store::StoreConfig;

use super::*;
use crate::mode_profile::test_bound_host;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOVERNANCE: &str = "01JC0GATEWAYW90G0VERN00001";
const PERSONA: &str = "01JC0GATEWAYF1XTVREACT0R00";
/// The golden GMP1 digests `scripts/check_gateway_contract.py` pins.
const LOCAL_DIGEST: &str = "26d6c7e75b11df673a1ef2d3210733b4ca431648eab0b9ae93bf4a6f6e69da3f";
const AIR_GAPPED_DIGEST: &str = "455883a475edbf5cc24907a03e6e46a476ceec6227ecdb8429999646dac447e5";

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

const fn claim(key: u8, digest: u8) -> RoomClaimV1 {
    RoomClaimV1 {
        key: [key; 32],
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

fn derive_with(
    host: &mut ErasureExecutionHostV1,
    key: u8,
    room_id: EntityId,
    parent_revision: u64,
    input: ScenarioRoomInputV1,
    admission: &RoomAdmissionV1,
) -> RoomResult<RoomOutcomeV1> {
    run_room_operation(
        host,
        RoomOperationV1::Derive {
            claim: claim(key, 9),
            room_id,
            parent_revision,
            input: Box::new(input),
        },
        admission,
    )
}

fn derive(
    host: &mut ErasureExecutionHostV1,
    key: u8,
    room_id: EntityId,
    parent_revision: u64,
    value_micro: i64,
) -> Result<RoomResult<RoomOutcomeV1>, Box<dyn std::error::Error>> {
    Ok(derive_with(
        host,
        key,
        room_id,
        parent_revision,
        input(value_micro)?,
        &admission()?,
    ))
}

fn read(
    host: &mut ErasureExecutionHostV1,
    room_id: EntityId,
    revision: u64,
) -> Result<RoomResult<RoomOutcomeV1>, Box<dyn std::error::Error>> {
    Ok(run_room_operation(
        host,
        RoomOperationV1::Read { room_id, revision },
        &admission()?,
    ))
}

/// The stored revision of an outcome and whether it just committed.
fn stored_of(outcome: &RoomOutcomeV1) -> (bool, &StoredRoomRevisionV1) {
    match outcome {
        RoomOutcomeV1::Committed(stored) => (true, stored),
        RoomOutcomeV1::Existing(stored) => (false, stored),
    }
}

/// `(committed, room, revision)` of an outcome.
fn shape(outcome: &RoomOutcomeV1) -> (bool, EntityId, u64) {
    let (committed, stored) = stored_of(outcome);
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
    let (committed, stored) = stored_of(&created);
    assert!(committed);
    assert_eq!(stored.descriptor.revision().get(), 1);
    assert_eq!(stored.seq.as_u64(), 1);
    assert_eq!(stored.produced_under.0, GatewayModeProfileIdV1::Local);
    assert_eq!(stored.produced_under.2.get(), 1);
    // The served descriptor is exactly the stored payload's JSON.
    assert_eq!(
        crate::scenario_room::revision_json(stored)["descriptor"],
        serde_json::from_slice::<serde_json::Value>(stored.descriptor.payload())?
    );
    let room = stored.descriptor.room_id();
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
    // Revision 2 commits from the head; then its ADR-041 section 7
    // duplicate, an exact retry and a stale proposal.
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
    // A stale proposal claims nothing: the same key may then derive anew.
    assert_eq!(
        shape(&ok(derive(&mut host, 4, room, 2, 750_000)?)?),
        (true, room, 3)
    );
    // Content equal to the head's is still a new revision.
    assert_eq!(
        shape(&ok(derive(&mut host, 5, room, 3, 750_000)?)?),
        (true, room, 4)
    );
    for revision in 1..=4 {
        assert_eq!(
            shape(&ok(read(&mut host, room, revision)?)?),
            (false, room, revision)
        );
    }
    for revision in [0, 5] {
        assert_eq!(refusal(read(&mut host, room, revision)?), "NotFound");
    }
    assert_eq!(refusal(derive(&mut host, 6, room, 9, 1)?), "NotFound");
    assert_eq!(
        refusal(derive(&mut host, 6, EntityId::new(), 1, 1)?),
        "NotFound"
    );
    Ok(())
}

#[test]
fn a_claim_finishes_its_interrupted_room() -> TestResult {
    let mut host = host(true)?;
    let admission = admission()?;
    // A claim whose room Timeline exists without its revision (an attempt
    // the host interrupted) is finished in that Timeline.
    let causation = ok(claim_request(
        &mut host,
        &claim(2, 2),
        &admission,
        ClaimPlace::Requests,
        |_| Ok(()),
    ))?;
    let room = EntityId::from_ulid(causation.inner());
    let timeline = ok(create_root(
        &mut host,
        &room_timeline_name(room),
        &admission,
    ))?;
    let finished = ok(create(&mut host, 2, 2, 2, &admission)?)?;
    let (committed, stored) = stored_of(&finished);
    assert!(committed);
    assert_eq!(
        (stored.timeline, stored.descriptor.room_id()),
        (timeline.id(), room)
    );
    // A claim with no Timeline yet creates it.
    let causation = ok(claim_request(
        &mut host,
        &claim(3, 3),
        &admission,
        ClaimPlace::Requests,
        |_| Ok(()),
    ))?;
    assert_eq!(
        shape(&ok(create(&mut host, 3, 3, 3, &admission)?)?),
        (true, EntityId::from_ulid(causation.inner()), 1)
    );
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
    // None of the refusals claimed the key: it creates a room now.
    let (_, room, _) = shape(&ok(create(&mut host, 1, 1, 1, &admission()?)?)?);
    let mut invalid = input(1)?;
    invalid.tick_duration_ms = 0;
    assert_eq!(
        refusal(derive_with(&mut host, 2, room, 1, invalid, &admission()?)),
        "Room(InvalidField(TickDurationMs))"
    );
    let mut ungoverned = input(1)?;
    ungoverned.governance_ref = EntityId::new();
    assert_eq!(
        refusal(derive_with(
            &mut host,
            2,
            room,
            1,
            ungoverned,
            &admission()?
        )),
        "GovernanceUnknown"
    );
    assert_eq!(
        shape(&ok(derive(&mut host, 2, room, 1, 1)?)?),
        (true, room, 2)
    );
    Ok(())
}

#[test]
fn every_ceiling_refuses_before_the_claim() -> TestResult {
    for (max_timelines, max_events, expected) in [
        (0, 16, "TimelineCeiling"),
        (1, 16, "TimelineCeiling"),
        (16, 0, "EventCeiling"),
    ] {
        let mut host = host(true)?;
        let limited = RoomAdmissionV1 {
            max_timelines,
            max_events,
            ..admission()?
        };
        assert_eq!(
            refusal(create(&mut host, 1, 1, 1, &limited)?),
            expected,
            "{max_timelines} {max_events}"
        );
        // Nothing was claimed: an unlimited host creates under the same key.
        assert!(shape(&ok(create(&mut host, 1, 1, 1, &admission()?)?)?).0);
    }
    // A room at its Event ceiling refuses a derive before the claim, and
    // the request Timeline at its ceiling refuses a new claim.
    let mut host = host(true)?;
    let one = RoomAdmissionV1 {
        max_events: 1,
        ..admission()?
    };
    let (_, room, _) = shape(&ok(create(&mut host, 1, 1, 1, &one)?)?);
    assert_eq!(
        refusal(derive_with(&mut host, 2, room, 1, input(2)?, &one)),
        "EventCeiling"
    );
    assert_eq!(refusal(create(&mut host, 3, 3, 3, &one)?), "EventCeiling");
    // The host's root ceiling also refuses a room's own Timeline.
    let mut host = host(true)?;
    let two = RoomAdmissionV1 {
        max_timelines: 2,
        ..admission()?
    };
    let causation = ok(claim_request(
        &mut host,
        &claim(4, 4),
        &two,
        ClaimPlace::Requests,
        |_| Ok(()),
    ))?;
    drop(ok(create_root(&mut host, "other", &two))?);
    // The claim already exists, so its retry runs no headroom check and
    // meets the ceiling when it creates the room's Timeline.
    drop(causation);
    assert_eq!(
        refusal(create(&mut host, 4, 4, 4, &two)?),
        "TimelineCeiling"
    );
    Ok(())
}

#[test]
fn an_unbound_store_refuses_before_anything_commits() -> TestResult {
    let mut host = host(false)?;
    assert_eq!(
        refusal(create(&mut host, 1, 1, 1, &admission()?)?),
        "ModeUnavailable"
    );
    assert_eq!(
        refusal(derive(&mut host, 1, EntityId::new(), 1, 1)?),
        "ModeUnavailable"
    );
    assert!(ok(host_timelines(&mut host))?.is_empty());
    Ok(())
}

fn reference(
    id: &str,
    digest: &str,
) -> Result<GatewayModeProfileRefV1, Box<dyn std::error::Error>> {
    let mut bytes = [0; 32];
    for (byte, pair) in bytes.iter_mut().zip(digest.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(GatewayModeProfileRefV1::try_new(id, bytes)?)
}

#[test]
fn a_revision_keeps_the_mode_its_commit_was_produced_under() -> TestResult {
    let mut host = host(true)?;
    let (_, room, _) = shape(&ok(create(&mut host, 1, 1, 1, &admission()?)?)?);
    let permit = GatewayModeBindingHostV1::new().authorize_migration(
        reference("gateway-mode-local-v1", LOCAL_DIGEST)?,
        reference("gateway-mode-air-gapped-v1", AIR_GAPPED_DIGEST)?,
    )?;
    let migrated = host.gateway_mode_binding().migrate_mode(permit)?;
    assert_eq!(migrated.binding_epoch().get(), 2);
    let first = ok(read(&mut host, room, 1)?)?;
    let (_, stored) = stored_of(&first);
    assert_eq!(
        (stored.produced_under.0, stored.produced_under.2.get()),
        (GatewayModeProfileIdV1::Local, 1)
    );
    let second = ok(derive(&mut host, 2, room, 1, 2)?)?;
    let (_, stored) = stored_of(&second);
    assert_eq!(
        (stored.produced_under.0, stored.produced_under.2.get()),
        (GatewayModeProfileIdV1::AirGapped, 2)
    );
    Ok(())
}

#[test]
fn a_revision_identity_is_never_appended_twice() -> TestResult {
    let mut host = host(true)?;
    let admission = admission()?;
    let created = ok(create(&mut host, 1, 1, 1, &admission)?)?;
    let (_, stored) = stored_of(&created);
    let again = append_revision(
        &mut host,
        stored.timeline,
        &stored.descriptor,
        stored.event_id,
        &admission,
    );
    assert_eq!(refusal(again), format!("{:?}", identity_reused()));
    Ok(())
}
