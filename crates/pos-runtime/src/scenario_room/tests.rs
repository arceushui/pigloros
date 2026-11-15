//! The ADR-041 descriptor seam (#1397). The golden values come from an
//! independent Python encoding of the Proposed ADR-041 amendment of #303
//! (`json.dumps(sort_keys=True, separators=(",", ":"))` and `blake3`).

use pos_core::{Kind, Plugin, PluginId, TimelineId};

use super::*;
use crate::composition::{
    DomainImplementationKindV1, PluginAvailabilityV1, PluginIsolationV1, PluginPinV1,
    PluginRegistrationV1,
};
use crate::driver::{Driver, ObservationView, StepOutput};
use crate::error::RuntimeError;
use crate::PluginRegistry;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GOLDEN_PAYLOAD: &str = concat!(
    r#"{"correlation_id":"5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f","#,
    r#""descriptor_hash":"12936318b503514ccaa4078d8f292f2adc59d1eeef43c095e54b4e9a5194ef75","#,
    r#""governance_ref":"01JC0GATEWAYW90G0VERN00001","#,
    r#""initial_conditions":[{"dimension":"trust","entity_id":"01JC0GATEWAYW90S0C1ETY0001","value_micro":600000}],"#,
    r#""intervention_policy":1,"max_ticks":600,"#,
    r#""participants":[{"entity_id":"01JC0GATEWAYF1XTVREACT0R00","kind":"persona"},{"entity_id":"01JC0GATEWAYW90S0C1ETY0001","kind":"society"}],"#,
    r#""plugin_composition_hash":"8cf19a4bf9e50cd198bf1f101ebc90fb59af3cffc44410f82c1411c73cf96a9f","#,
    r#""plugins":[{"plugin_id":"society","version":"0.1.0"},{"plugin_id":"world","version":"0.1.0"}],"#,
    r#""privacy_export_ref":"01JC0GATEWAYW90PR1VACY0001","revision":1,"#,
    r#""room_id":"01JC0GATEWAYW9R00M00000001","#,
    r#""rule_set_hash":"d0f89c295323c9e77534f5a4f64777ede809074d55ac90fa03d74e59b2cfc5bf","#,
    r#""rules":[{"rule_id":"society.nudge.scale","value_micro":250000},{"rule_id":"world.gravity","value_micro":-9800000}],"#,
    r#""scheduler_policy":0,"#,
    r#""scheduler_seed":"0404040404040404040404040404040404040404040404040404040404040404","#,
    r#""schema_version":1,"tick_duration_ms":100}"#,
);

fn entity_id(text: &str) -> Result<EntityId, ulid::DecodeError> {
    ulid::Ulid::from_string(text).map(EntityId::from_ulid)
}

fn digest(text: &str) -> Result<Hash, Box<dyn std::error::Error>> {
    hex_bytes::<32>(text)
        .map(Hash::from_bytes)
        .ok_or_else(|| "golden digest is not 64 lower-case hex digits".into())
}

fn correlation() -> Result<RoomCorrelationIdV1, Box<dyn std::error::Error>> {
    RoomCorrelationIdV1::from_bytes([0x5f; 16]).ok_or_else(|| "zero correlation".into())
}

fn catalogue() -> ScenarioRoomCatalogueV1 {
    ScenarioRoomCatalogueV1::from_registered(
        [
            ("world", "0.1.0", Hash::from_bytes([1; 32])),
            ("society", "0.1.0", Hash::from_bytes([2; 32])),
        ]
        .into_iter(),
    )
}

fn plugin(plugin_id: &str) -> RoomPluginRefV1 {
    RoomPluginRefV1 {
        plugin_id: plugin_id.to_owned(),
        version: "0.1.0".to_owned(),
    }
}

fn rule(rule_id: &str, value_micro: i64) -> RoomRuleV1 {
    RoomRuleV1 {
        rule_id: rule_id.to_owned(),
        value_micro,
    }
}

/// The golden input, with every list out of its canonical order.
fn input() -> Result<ScenarioRoomInputV1, ulid::DecodeError> {
    let society = entity_id("01JC0GATEWAYW90S0C1ETY0001")?;
    Ok(ScenarioRoomInputV1 {
        schema_version: 1,
        tick_duration_ms: 100,
        max_ticks: 600,
        scheduler_seed: [4; 32],
        scheduler_policy: 0,
        intervention_policy: 1,
        plugins: vec![plugin("world"), plugin("society")],
        rules: vec![
            rule("world.gravity", -9_800_000),
            rule("society.nudge.scale", 250_000),
        ],
        participants: vec![
            RoomParticipantV1 {
                entity_id: society,
                kind: RoomParticipantKindV1::Society,
            },
            RoomParticipantV1 {
                entity_id: entity_id("01JC0GATEWAYF1XTVREACT0R00")?,
                kind: RoomParticipantKindV1::Persona,
            },
        ],
        initial_conditions: vec![RoomInitialConditionV1 {
            entity_id: society,
            dimension: "trust".to_owned(),
            value_micro: 600_000,
        }],
        governance_ref: entity_id("01JC0GATEWAYW90G0VERN00001")?,
        privacy_export_ref: entity_id("01JC0GATEWAYW90PR1VACY0001")?,
    })
}

fn room_id() -> Result<EntityId, ulid::DecodeError> {
    entity_id("01JC0GATEWAYW9R00M00000001")
}

fn admit(input: ScenarioRoomInputV1) -> Result<ScenarioRoomDescriptorV1, ScenarioRoomErrorV1> {
    let room_id = EntityId::from_ulid(ulid::Ulid::from_parts(1, 1));
    let correlation_id = RoomCorrelationIdV1([0x5f; 16]);
    ScenarioRoomDescriptorV1::admit_first(room_id, correlation_id, input, &catalogue())
}

fn refusal(
    edit: impl FnOnce(&mut ScenarioRoomInputV1),
) -> Result<Option<ScenarioRoomErrorV1>, ulid::DecodeError> {
    let mut changed = input()?;
    edit(&mut changed);
    Ok(admit(changed).err())
}

fn invalid(field: ScenarioRoomFieldV1) -> Option<ScenarioRoomErrorV1> {
    Some(ScenarioRoomErrorV1::InvalidField(field))
}

fn limit(limit: ScenarioRoomLimitV1) -> Option<ScenarioRoomErrorV1> {
    Some(ScenarioRoomErrorV1::LimitExceeded(limit))
}

#[test]
fn the_first_revision_matches_the_independent_golden_encoding() -> TestResult {
    let descriptor =
        ScenarioRoomDescriptorV1::admit_first(room_id()?, correlation()?, input()?, &catalogue())?;
    assert_eq!(std::str::from_utf8(descriptor.payload())?, GOLDEN_PAYLOAD);
    assert_eq!(
        descriptor.plugin_composition_hash(),
        digest("8cf19a4bf9e50cd198bf1f101ebc90fb59af3cffc44410f82c1411c73cf96a9f")?
    );
    assert_eq!(
        descriptor.rule_set_hash(),
        digest("d0f89c295323c9e77534f5a4f64777ede809074d55ac90fa03d74e59b2cfc5bf")?
    );
    assert_eq!(
        descriptor.descriptor_hash(),
        digest("12936318b503514ccaa4078d8f292f2adc59d1eeef43c095e54b4e9a5194ef75")?
    );
    assert_eq!(descriptor.room_id(), room_id()?);
    assert_eq!(descriptor.revision(), NonZeroU64::MIN);
    assert_eq!(descriptor.correlation_id(), correlation()?);
    assert_eq!(
        descriptor.input().plugins,
        vec![plugin("society"), plugin("world")]
    );
    assert_eq!(
        descriptor.input().participants[0].kind,
        RoomParticipantKindV1::Persona
    );
    Ok(())
}

#[test]
fn a_stored_payload_reads_back_to_the_same_revision() -> TestResult {
    let descriptor =
        ScenarioRoomDescriptorV1::admit_first(room_id()?, correlation()?, input()?, &catalogue())?;
    assert_eq!(
        ScenarioRoomDescriptorV1::from_payload(descriptor.payload())?,
        descriptor
    );
    Ok(())
}

#[test]
fn a_corrupt_or_non_canonical_payload_is_refused() {
    let tampered = [
        String::from("not json"),
        GOLDEN_PAYLOAD.replace(r#""max_ticks":600,"#, r#""max_ticks":600,"extra":1,"#),
        GOLDEN_PAYLOAD.replace(r#","max_ticks""#, r#", "max_ticks""#),
        GOLDEN_PAYLOAD.replace("12936318", "12936319"),
        GOLDEN_PAYLOAD.replace("d0f89c29", "d0f89c2a"),
        GOLDEN_PAYLOAD.replace("01JC0GATEWAYW9R00M00000001", "01jc0gatewayw9r00m00000001"),
        GOLDEN_PAYLOAD.replace("01JC0GATEWAYW9R00M00000001", "not-a-ulid"),
        GOLDEN_PAYLOAD.replace("01JC0GATEWAYW90G0VERN00001", "not-a-ulid"),
        GOLDEN_PAYLOAD.replace("01JC0GATEWAYW90PR1VACY0001", "not-a-ulid"),
        GOLDEN_PAYLOAD.replace(
            r#"{"dimension":"trust","entity_id":"01JC0GATEWAYW90S0C1ETY0001""#,
            r#"{"dimension":"trust","entity_id":"not-a-ulid""#,
        ),
        GOLDEN_PAYLOAD.replace(r#""kind":"persona""#, r#""kind":"robot""#),
        GOLDEN_PAYLOAD.replace(r#""revision":1,"#, r#""revision":0,"#),
        GOLDEN_PAYLOAD.replace(r#""revision":1,"#, r#""revision":9007199254740992,"#),
        GOLDEN_PAYLOAD.replace(
            "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f",
            "00000000000000000000000000000000",
        ),
        GOLDEN_PAYLOAD.replace(
            "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f",
            "5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F",
        ),
        GOLDEN_PAYLOAD.replace("5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f", "5f5f"),
        GOLDEN_PAYLOAD.replace("8cf19a4b", "8cf19agb"),
        GOLDEN_PAYLOAD.replace("0404040404", "040404040g"),
        GOLDEN_PAYLOAD.replace("d0f89c29", "d0f89cg9"),
        GOLDEN_PAYLOAD.replace("12936318", "1293631g"),
        GOLDEN_PAYLOAD.replace(r#""schema_version":1"#, r#""schema_version":2"#),
    ];
    for payload in tampered {
        assert_eq!(
            ScenarioRoomDescriptorV1::from_payload(payload.as_bytes()),
            Err(ScenarioRoomErrorV1::CorruptPayload),
            "{payload}"
        );
    }
}

#[test]
fn list_order_does_not_change_the_revision() -> TestResult {
    let mut reordered = input()?;
    reordered.plugins.reverse();
    reordered.rules.reverse();
    reordered.participants.reverse();
    assert_eq!(admit(reordered)?, admit(input()?)?);
    Ok(())
}

#[test]
fn every_member_change_changes_the_descriptor_hash() -> TestResult {
    let base = admit(input()?)?.descriptor_hash();
    let edits: &[fn(&mut ScenarioRoomInputV1)] = &[
        |input| input.tick_duration_ms = 101,
        |input| input.max_ticks = 601,
        |input| input.scheduler_seed = [5; 32],
        |input| input.scheduler_policy = 1,
        |input| input.intervention_policy = 2,
        |input| input.rules[0].value_micro = 1,
        |input| input.participants[1].kind = RoomParticipantKindV1::Agent,
        |input| input.initial_conditions[0].value_micro = 1,
        |input| input.governance_ref = EntityId::from_ulid(ulid::Ulid::from_parts(9, 9)),
        |input| input.privacy_export_ref = EntityId::from_ulid(ulid::Ulid::from_parts(9, 9)),
    ];
    for edit in edits {
        let mut changed = input()?;
        edit(&mut changed);
        assert_ne!(admit(changed)?.descriptor_hash(), base);
    }
    Ok(())
}

#[test]
fn the_next_revision_keeps_the_room_and_derives_a_new_hash() -> TestResult {
    let first = admit(input()?)?;
    let mut changed = input()?;
    changed.rules[0].value_micro = 500_000;
    let second = first.admit_next(changed.clone(), &catalogue())?;
    assert_eq!(second.room_id(), first.room_id());
    assert_eq!(second.correlation_id(), first.correlation_id());
    assert_eq!(second.revision().get(), 2);
    assert_ne!(second.descriptor_hash(), first.descriptor_hash());
    // An identical concurrent proposal from the same parent is the same
    // revision, so it shares the append identity (ADR-041 section 7).
    let twin = first.admit_next(changed, &catalogue())?;
    assert_eq!(twin.append_identity(), second.append_identity());
    assert_ne!(
        second.append_identity().dedup_key,
        first.append_identity().dedup_key
    );
    assert_eq!(
        second.append_identity().scope,
        first.append_identity().scope
    );
    // Restoring an earlier configuration is a new revision (section 9).
    let restored = second.admit_next(input()?, &catalogue())?;
    assert_eq!(restored.revision().get(), 3);
    assert_ne!(restored.descriptor_hash(), first.descriptor_hash());
    Ok(())
}

#[test]
fn the_append_identity_uses_the_amendment_contexts() -> TestResult {
    let descriptor = admit(input()?)?;
    let identity = descriptor.append_identity();
    assert_eq!(
        identity.dedup_key.as_bytes(),
        blake3::derive_key(
            "PiglorOS ScenarioRoom AppendDedup v1",
            descriptor.descriptor_hash().as_bytes()
        )
    );
    assert_eq!(
        identity.scope.as_bytes(),
        blake3::derive_key(
            "PiglorOS ScenarioRoom AppendDedupScope v1",
            &descriptor.room_id().inner().to_bytes()
        )
    );
    let other_room = ScenarioRoomDescriptorV1::admit_first(
        EntityId::from_ulid(ulid::Ulid::from_parts(2, 2)),
        correlation()?,
        input()?,
        &catalogue(),
    )?;
    assert_ne!(other_room.append_identity().scope, identity.scope);
    Ok(())
}

#[test]
fn the_revision_stops_at_the_safe_integer_bound() -> TestResult {
    let at = |revision: u64| -> Result<ScenarioRoomDescriptorV1, Box<dyn std::error::Error>> {
        let input = canonical_input(input()?)?;
        Ok(ScenarioRoomDescriptorV1::assemble(
            room_id()?,
            NonZeroU64::new(revision).ok_or("zero revision")?,
            correlation()?,
            input,
            Hash::from_bytes([3; 32]),
        )?)
    };
    let below = at(MAX_ROOM_SAFE_INTEGER_V1 - 1)?.admit_next(input()?, &catalogue())?;
    assert_eq!(below.revision().get(), MAX_ROOM_SAFE_INTEGER_V1);
    assert_eq!(
        below.admit_next(input()?, &catalogue()).err(),
        limit(ScenarioRoomLimitV1::Revision)
    );
    assert_eq!(
        at(u64::MAX)?.admit_next(input()?, &catalogue()).err(),
        limit(ScenarioRoomLimitV1::Revision)
    );
    Ok(())
}

#[test]
fn an_unknown_schema_version_is_refused() -> TestResult {
    assert_eq!(
        refusal(|input| input.schema_version = 2)?,
        Some(ScenarioRoomErrorV1::UnsupportedSchemaVersion)
    );
    Ok(())
}

#[test]
fn each_list_bound_admits_its_limit_and_refuses_one_more() -> TestResult {
    let persona = |index: u64| RoomParticipantV1 {
        entity_id: EntityId::from_ulid(ulid::Ulid::from_parts(1, u128::from(index))),
        kind: RoomParticipantKindV1::Agent,
    };
    let plugins = |count: usize| {
        (0..count)
            .map(|index| plugin(&format!("plugin-{index}")))
            .collect::<Vec<_>>()
    };
    let rules = |count: usize| {
        (0..count)
            .map(|index| rule(&format!("world.r{index}"), 0))
            .collect::<Vec<_>>()
    };
    let participants = |count: usize| (1_u64..).take(count).map(persona).collect::<Vec<_>>();
    let conditions = |count: usize| {
        (0..count)
            .map(|index| RoomInitialConditionV1 {
                entity_id: persona(1).entity_id,
                dimension: format!("d{index}"),
                value_micro: 0,
            })
            .collect::<Vec<_>>()
    };
    let mut over = input()?;
    over.plugins = plugins(MAX_ROOM_PLUGINS_V1 + 1);
    assert_eq!(admit(over).err(), limit(ScenarioRoomLimitV1::Plugins));
    let mut at = input()?;
    at.plugins = plugins(MAX_ROOM_PLUGINS_V1);
    at.rules.clear();
    assert_eq!(admit(at).err(), Some(ScenarioRoomErrorV1::PluginNotBundled));

    let mut over = input()?;
    over.rules = rules(MAX_ROOM_RULES_V1 + 1);
    assert_eq!(admit(over).err(), limit(ScenarioRoomLimitV1::Rules));
    let mut over = input()?;
    over.participants = participants(MAX_ROOM_PARTICIPANTS_V1 + 1);
    assert_eq!(admit(over).err(), limit(ScenarioRoomLimitV1::Participants));
    let mut over = input()?;
    over.initial_conditions = conditions(MAX_ROOM_INITIAL_CONDITIONS_V1 + 1);
    assert_eq!(
        admit(over).err(),
        limit(ScenarioRoomLimitV1::InitialConditions)
    );

    // At its limit a list passes its own bound. Rules fit the payload; 64
    // participants or 64 initial conditions cannot, so the payload bound is
    // what refuses them.
    let mut at = input()?;
    at.rules = rules(MAX_ROOM_RULES_V1);
    assert_eq!(admit(at)?.input().rules.len(), MAX_ROOM_RULES_V1);
    let mut at = input()?;
    at.participants = participants(MAX_ROOM_PARTICIPANTS_V1);
    at.initial_conditions = Vec::new();
    assert_eq!(admit(at).err(), limit(ScenarioRoomLimitV1::DescriptorBytes));
    let mut at = input()?;
    at.participants = participants(1);
    at.initial_conditions = conditions(MAX_ROOM_INITIAL_CONDITIONS_V1);
    assert_eq!(admit(at).err(), limit(ScenarioRoomLimitV1::DescriptorBytes));
    Ok(())
}

#[test]
fn the_payload_bound_admits_exactly_4096_bytes() -> TestResult {
    let sized = |padding: usize| -> Result<ScenarioRoomInputV1, ulid::DecodeError> {
        let mut sized = input()?;
        sized.rules = (0..20)
            .map(|index| rule(&format!("world.{index:03}{}", "x".repeat(110)), 0))
            .collect();
        sized
            .rules
            .push(rule(&format!("world.{}", "y".repeat(padding)), 0));
        Ok(sized)
    };
    let base = admit(sized(1)?)?.payload().len();
    let padding = MAX_ROOM_DESCRIPTOR_BYTES_V1 + 1 - base;
    assert_eq!(
        admit(sized(padding)?)?.payload().len(),
        MAX_ROOM_DESCRIPTOR_BYTES_V1
    );
    assert_eq!(
        admit(sized(padding + 1)?).err(),
        limit(ScenarioRoomLimitV1::DescriptorBytes)
    );
    Ok(())
}

#[test]
fn malformed_scalars_are_refused() -> TestResult {
    use ScenarioRoomFieldV1 as Field;
    assert_eq!(
        refusal(|input| input.tick_duration_ms = 0)?,
        invalid(Field::TickDurationMs)
    );
    assert_eq!(
        refusal(|input| input.max_ticks = 0)?,
        invalid(Field::MaxTicks)
    );
    assert_eq!(
        refusal(|input| input.max_ticks = MAX_ROOM_TICKS_V1 + 1)?,
        invalid(Field::MaxTicks)
    );
    assert_eq!(refusal(|input| input.max_ticks = MAX_ROOM_TICKS_V1)?, None);
    assert_eq!(refusal(|input| input.tick_duration_ms = 1)?, None);
    Ok(())
}

#[test]
fn malformed_plugins_are_refused() -> TestResult {
    use ScenarioRoomFieldV1 as Field;
    assert_eq!(
        refusal(|input| input.plugins.clear())?,
        invalid(Field::Plugins)
    );
    for plugin_id in [
        "",
        "World",
        "1world",
        "wor ld",
        "wor.ld",
        "w\u{f6}rld",
        &"w".repeat(129),
    ] {
        assert_eq!(
            refusal(|input| input.plugins[0].plugin_id = plugin_id.to_owned())?,
            invalid(Field::PluginId),
            "{plugin_id}"
        );
    }
    for version in [
        "0.1",
        "0..1",
        "0.1.x",
        "0.1.0.1",
        &format!("0.1.{}", "1".repeat(61)),
    ] {
        assert_eq!(
            refusal(|input| input.plugins[0].version = version.to_owned())?,
            invalid(Field::PluginVersion),
            "{version}"
        );
    }
    assert_eq!(
        refusal(|input| input.plugins.push(plugin("world")))?,
        invalid(Field::Plugins)
    );
    // A well-formed but unbundled name or version, and the longest name.
    assert_eq!(
        refusal(|input| input.plugins[0].version = "0.2.0".to_owned())?,
        Some(ScenarioRoomErrorV1::PluginNotBundled)
    );
    assert_eq!(
        refusal(|input| {
            input.rules.clear();
            input.plugins[0].plugin_id = format!("w-_0{}", "w".repeat(124));
        })?,
        Some(ScenarioRoomErrorV1::PluginNotBundled)
    );
    assert_eq!(
        refusal(|input| input.plugins[0].version = format!("0.1.{}", "0".repeat(60)))?,
        Some(ScenarioRoomErrorV1::PluginNotBundled)
    );
    Ok(())
}

#[test]
fn malformed_rules_are_refused() -> TestResult {
    use ScenarioRoomFieldV1 as Field;
    assert_eq!(
        refusal(|input| input.rules[0].rule_id = "World.gravity".to_owned())?,
        invalid(Field::RuleId)
    );
    for value in [MAX_ROOM_SAFE_INTEGER_V1.cast_signed() + 1, i64::MIN] {
        assert_eq!(
            refusal(|input| input.rules[0].value_micro = value)?,
            invalid(Field::RuleValue)
        );
    }
    for value in [
        MAX_ROOM_SAFE_INTEGER_V1.cast_signed(),
        -MAX_ROOM_SAFE_INTEGER_V1.cast_signed(),
    ] {
        assert_eq!(refusal(|input| input.rules[0].value_micro = value)?, None);
    }
    assert_eq!(
        refusal(|input| input.rules.push(rule("world.gravity", 1)))?,
        invalid(Field::Rules)
    );
    assert_eq!(
        refusal(|input| input.rules[0].rule_id = "world".to_owned())?,
        None
    );
    for rule_id in ["geo", "geo.gravity", "worldx.gravity"] {
        assert_eq!(
            refusal(|input| input.rules[0].rule_id = rule_id.to_owned())?,
            Some(ScenarioRoomErrorV1::RuleWithoutPlugin),
            "{rule_id}"
        );
    }
    assert_eq!(refusal(|input| input.rules.clear())?, None);
    Ok(())
}

#[test]
fn malformed_participants_and_conditions_are_refused() -> TestResult {
    use ScenarioRoomFieldV1 as Field;
    let stranger = EntityId::from_ulid(ulid::Ulid::from_parts(7, 7));
    assert_eq!(
        refusal(|input| input.participants.clear())?,
        invalid(Field::Participants)
    );
    assert_eq!(
        refusal(|input| {
            let duplicate = input.participants[0].clone();
            input.participants.push(duplicate);
        })?,
        invalid(Field::Participants)
    );
    for dimension in ["Trust", "tr\u{fc}st"] {
        assert_eq!(
            refusal(|input| input.initial_conditions[0].dimension = dimension.to_owned())?,
            invalid(Field::Dimension),
            "{dimension}"
        );
    }
    assert_eq!(
        refusal(|input| input.initial_conditions[0].value_micro = i64::MAX)?,
        invalid(Field::ConditionValue)
    );
    assert_eq!(
        refusal(|input| {
            let duplicate = input.initial_conditions[0].clone();
            input.initial_conditions.push(duplicate);
        })?,
        invalid(Field::InitialConditions)
    );
    assert_eq!(
        refusal(|input| input.initial_conditions[0].entity_id = stranger)?,
        invalid(Field::ConditionEntity)
    );
    assert_eq!(refusal(|input| input.initial_conditions.clear())?, None);
    Ok(())
}

#[test]
fn an_ambiguous_catalogue_name_is_not_bundled() -> TestResult {
    let ambiguous = ScenarioRoomCatalogueV1::from_registered(
        [
            ("world", "0.1.0", Hash::from_bytes([1; 32])),
            ("world", "0.1.0", Hash::from_bytes([3; 32])),
            ("society", "0.1.0", Hash::from_bytes([2; 32])),
        ]
        .into_iter(),
    );
    assert_eq!(
        ScenarioRoomDescriptorV1::admit_first(room_id()?, correlation()?, input()?, &ambiguous)
            .err(),
        Some(ScenarioRoomErrorV1::PluginNotBundled)
    );
    Ok(())
}

#[test]
fn the_capability_set_hash_matches_the_independent_golden_encoding() -> TestResult {
    let names = [
        Kind::new("b.type"),
        Kind::new("a.type"),
        Kind::new("a.type"),
    ];
    assert_eq!(
        capability_set_hash_v1(names.iter()),
        digest("b37b2343dc454dd08d49892289a409d3bf29fbd15189944324450e661b3b9c5f")?
    );
    assert_eq!(
        capability_set_hash_v1(names.iter().rev()),
        capability_set_hash_v1(names.iter())
    );
    assert_eq!(
        capability_set_hash_v1(std::iter::empty()),
        digest("29a9462cbf5263a962f021f538c9ec1c1b32f724c508b224d585494b626bfdfc")?
    );
    Ok(())
}

struct TestPlugin {
    id: PluginId,
    name: &'static str,
    version: &'static str,
    event_type: &'static str,
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
            owned_event_types: vec![Kind::new(self.event_type)],
            ..Capability::default()
        }
    }
}

struct NamedDriver;

impl Driver for NamedDriver {
    fn name(&self) -> &'static str {
        "driver-only"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }
}

fn test_plugin(name: &'static str, event_type: &'static str) -> TestPlugin {
    TestPlugin {
        id: PluginId::new(),
        name,
        version: "0.1.0",
        event_type,
    }
}

fn pin(roles: &[&str]) -> Result<PluginPinV1, crate::PluginCompositionErrorV1> {
    PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        Hash::from_bytes([7; 32]),
        roles.iter().map(|role| (*role).to_owned()).collect(),
    )
}

/// The catalogue entry of `society`, pinned with `roles` at `availability`.
fn pinned_society(
    roles: &[&str],
    availability: PluginAvailabilityV1,
) -> Result<Result<Hash, ScenarioRoomErrorV1>, Box<dyn std::error::Error>> {
    let mut registry = PluginRegistry::new();
    registry.register_pinned_generated(
        &test_plugin("society", "society.room-test.v1"),
        PluginRegistrationV1::new(pin(roles)?, availability),
        None,
        None,
    )?;
    Ok(registry
        .scenario_room_catalogue_v1()
        .resolve(&plugin("society")))
}

#[test]
fn a_registry_catalogue_holds_its_plugin_registrations_only() -> TestResult {
    let world = test_plugin("world", "world.room-test.v1");
    let mut registry = PluginRegistry::new();
    registry.register_generated(&world, None, None)?;
    registry.register_test_driver(Box::new(NamedDriver));
    let catalogue = registry.scenario_room_catalogue_v1();
    // The one capability name is the Plugin's registered schema name.
    assert!(registry.schemas.contains("world.room-test.v1"));
    assert_eq!(
        catalogue.resolve(&plugin("world")),
        Ok(digest(
            "259ffcb43ac16778e0ae8782a3cb6caeb391a4513989af23b672be89f0dc0a46"
        )?)
    );
    assert_eq!(
        catalogue.resolve(&RoomPluginRefV1 {
            plugin_id: "driver-only".to_owned(),
            version: "0.1.0".to_owned(),
        }),
        Err(ScenarioRoomErrorV1::PluginNotBundled)
    );
    Ok(())
}

#[test]
fn only_an_available_pinned_registration_is_bundled_whatever_its_role_order() -> TestResult {
    let available = pinned_society(&["society", "guest"], PluginAvailabilityV1::Available)?;
    assert_eq!(
        available,
        Ok(capability_set_hash_v1(
            [Kind::new("society.room-test.v1")].iter()
        ))
    );
    assert_eq!(
        pinned_society(&["guest", "society"], PluginAvailabilityV1::Available)?,
        available
    );
    for availability in [
        PluginAvailabilityV1::Disabled,
        PluginAvailabilityV1::Unavailable,
        PluginAvailabilityV1::Revoked,
        PluginAvailabilityV1::Trapped,
        PluginAvailabilityV1::ResourceExhausted,
    ] {
        assert_eq!(
            pinned_society(&["society"], availability)?,
            Err(ScenarioRoomErrorV1::PluginNotBundled),
            "{availability:?}"
        );
    }
    Ok(())
}

#[test]
fn two_registrations_of_one_name_and_version_are_ambiguous() -> TestResult {
    let mut registry = PluginRegistry::new();
    registry.register_generated(&test_plugin("world", "world.first.v1"), None, None)?;
    registry.register_generated(&test_plugin("world", "world.second.v1"), None, None)?;
    assert_eq!(
        registry
            .scenario_room_catalogue_v1()
            .resolve(&plugin("world")),
        Err(ScenarioRoomErrorV1::PluginNotBundled)
    );
    Ok(())
}

#[test]
fn the_correlation_id_comes_only_from_nonzero_entropy() -> TestResult {
    let generated = RoomCorrelationIdV1::generate()?;
    assert_ne!(generated.as_bytes(), &[0; 16]);
    assert_eq!(
        RoomCorrelationIdV1::generate_with(|_| Err(getrandom::Error::UNSUPPORTED)),
        Err(ScenarioRoomErrorV1::EntropyUnavailable)
    );
    assert_eq!(
        RoomCorrelationIdV1::generate_with(|_| Ok(())),
        Err(ScenarioRoomErrorV1::EntropyUnavailable)
    );
    let drawn = RoomCorrelationIdV1::generate_with(|bytes| {
        bytes.fill(0);
        bytes[15] = 1;
        Ok(())
    })?;
    assert_eq!(drawn.as_bytes()[15], 1);
    Ok(())
}

#[test]
fn every_participant_kind_has_one_wire_name() {
    for (kind, name) in [
        (RoomParticipantKindV1::Persona, "persona"),
        (RoomParticipantKindV1::Agent, "agent"),
        (RoomParticipantKindV1::Society, "society"),
        (RoomParticipantKindV1::WorldBody, "world-body"),
    ] {
        assert_eq!(kind.as_str(), name);
        assert_eq!(RoomParticipantKindV1::from_wire(name), Some(kind));
    }
    assert_eq!(RoomParticipantKindV1::from_wire("world_body"), None);
}

#[test]
fn the_errors_name_their_cause() {
    assert_eq!(
        ScenarioRoomErrorV1::InvalidField(ScenarioRoomFieldV1::PluginId).to_string(),
        "invalid Scenario Room descriptor field PluginId"
    );
    assert_eq!(
        ScenarioRoomErrorV1::LimitExceeded(ScenarioRoomLimitV1::Plugins).to_string(),
        "Scenario Room limit exceeded: Plugins"
    );
}
