use ciborium::value::{Integer, Value as Cbor};
use pos_core::{
    checked_repro_manifest_v2_input_len, AdapterRecord, Hash, ManifestPluginEntryV1,
    ManifestPluginFieldV1, ManifestPluginRosterErrorV1, ManifestPluginRosterV1, PluginId,
    ReproManifest, ReproManifestV2, ReproManifestV2Error, TimelineId, WallTime,
    MAX_REPRO_MANIFEST_V2_ADAPTER_RECORDS, MAX_REPRO_MANIFEST_V2_INPUT_BYTES,
};
use serde_json::{json, Value as Json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Failure = ReproManifestV2Error;
type RosterFailure = ManifestPluginRosterErrorV1;
type Fields = Vec<(&'static str, Cbor)>;

const LEGACY: [&str; 5] = [
    "plugin_versions",
    "output_policy_digests",
    "replay_policy_identities",
    "replay_policy_closures",
    "replay_policy_closure_identities",
];
const JSON_REQUIRED: [&str; 6] = [
    "timeline_id",
    "head_hash",
    "created_at",
    "adapter_records",
    "manifest_plugin_roster_version",
    "manifest_plugin_entries",
];
const CBOR_REQUIRED: [&str; 5] = [
    "timeline_id",
    "head_hash",
    "created_at",
    "adapter_records",
    "manifest_plugin_roster",
];
const CAP: usize = MAX_REPRO_MANIFEST_V2_ADAPTER_RECORDS;
const ENTRIES: &str = "manifest_plugin_entries";
const VERSION: &str = "manifest_format_version";

fn unsupported(found: Option<u64>) -> Failure {
    Failure::UnsupportedManifestVersion { found }
}

fn ambiguous(field: &'static str) -> Failure {
    Failure::AmbiguousLegacyManifest { field }
}

fn missing(field: &'static str) -> Failure {
    Failure::MissingField { field }
}

fn malformed(transport: &'static str) -> Failure {
    Failure::InvalidEncoding { transport }
}

fn wrong(field: &'static str, transport: &'static str) -> Failure {
    Failure::WrongTransportField { field, transport }
}

fn duplicate(key: &str) -> Failure {
    Failure::DuplicateKey {
        key: key.to_owned(),
    }
}

fn unknown(field: &str) -> Failure {
    Failure::UnknownField {
        field: field.to_owned(),
    }
}

fn streaming() -> Failure {
    Failure::TooManyElements {
        field: "an array",
        max: CAP,
    }
}

fn unsorted(slot: &str) -> Failure {
    Failure::Roster(RosterFailure::UnsortedSlots {
        slot: slot.to_owned(),
    })
}

fn repeated_slot(slot: &str) -> Failure {
    Failure::Roster(RosterFailure::DuplicateSlot {
        slot: slot.to_owned(),
    })
}

fn repeated_id(slot: &str) -> Failure {
    Failure::Roster(RosterFailure::DuplicatePluginId {
        slot: slot.to_owned(),
    })
}

fn bad_slot(slot: &str) -> Failure {
    Failure::Roster(RosterFailure::InvalidSlot {
        slot: slot.to_owned(),
    })
}

fn bad_name(slot: &str) -> Failure {
    Failure::Roster(RosterFailure::InvalidField {
        slot: slot.to_owned(),
        field: ManifestPluginFieldV1::PluginName,
    })
}

fn invalid_of(failure: &Failure) -> Option<&'static str> {
    match failure {
        Failure::InvalidField { field, .. } => Some(*field),
        _ => None,
    }
}

fn canon_of(failure: &Failure) -> Option<&'static str> {
    match failure {
        Failure::NonCanonical { field, .. } => Some(*field),
        _ => None,
    }
}

fn plugin_id(byte: u8) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

fn entry(slot: &str, byte: u8, closure: &[u8]) -> TestResult<ManifestPluginEntryV1> {
    Ok(ManifestPluginEntryV1::new(
        slot,
        plugin_id(byte),
        "Sensor",
        "1.0.0",
        Hash::from_bytes([byte; 32]),
        closure.to_vec(),
    )?)
}

// Four rows share the display name `Sensor`; closures of length 1, 2, 3 and 0 cover padding.
fn roster() -> TestResult<ManifestPluginRosterV1> {
    Ok(ManifestPluginRosterV1::new(vec![
        entry("sensor.c", 3, &[4, 5, 6])?,
        entry("sensor.a", 1, &[1])?,
        entry("sensor.d", 4, &[])?,
        entry("sensor.b", 2, &[2, 3])?,
    ])?)
}

fn record(byte: u8, call_index: u64, wall: u64) -> AdapterRecord {
    AdapterRecord {
        plugin_id: plugin_id(byte),
        call_index,
        input_hash: Hash::from_bytes([byte; 32]),
        output_hash: Hash::from_bytes([byte + 1; 32]),
        wall_time: WallTime::from_micros(wall),
    }
}

fn timeline() -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([7; 16]))
}

fn construct(
    records: Vec<AdapterRecord>,
    label: Option<String>,
    created: u64,
) -> TestResult<Result<ReproManifestV2, Failure>> {
    Ok(ReproManifestV2::new(
        timeline(),
        Hash::from_bytes([9; 32]),
        WallTime::from_micros(created),
        roster()?,
        records,
        label,
    ))
}

fn build(
    records: Vec<AdapterRecord>,
    label: Option<&str>,
    created: u64,
) -> TestResult<ReproManifestV2> {
    Ok(construct(records, label.map(str::to_owned), created)??)
}

fn manifest() -> TestResult<ReproManifestV2> {
    build(vec![record(5, 3, 77)], Some("run-1"), 1_000_000)
}

fn via_json(source: &ReproManifestV2) -> TestResult<ReproManifestV2> {
    Ok(ReproManifestV2::from_json(source.to_json()?.as_bytes())?)
}

fn via_cbor(source: &ReproManifestV2) -> TestResult<ReproManifestV2> {
    Ok(ReproManifestV2::from_cbor(&source.to_cbor()?)?)
}

fn json_doc(source: &ReproManifestV2) -> TestResult<Json> {
    Ok(serde_json::from_str(&source.to_json()?)?)
}

fn rejection<T>(result: Result<T, Failure>) -> TestResult<Failure> {
    Ok(result.err().ok_or("the document was accepted")?)
}

fn json_fail(edit: impl FnOnce(&mut Json)) -> TestResult<Failure> {
    let mut doc = json_doc(&manifest()?)?;
    edit(&mut doc);
    rejection(ReproManifestV2::from_json(doc.to_string().as_bytes()))
}

fn text_fail(text: &str) -> TestResult<Failure> {
    rejection(ReproManifestV2::from_json(text.as_bytes()))
}

fn remove_key(doc: &mut Json, key: &str) {
    if let Some(map) = doc.as_object_mut() {
        map.remove(key);
    }
}

fn top_fail(key: &str, value: Json) -> TestResult<Failure> {
    json_fail(|doc| doc[key] = value)
}

fn top_missing(key: &str) -> TestResult<Failure> {
    json_fail(|doc| remove_key(doc, key))
}

fn entry_fail(index: usize, key: &str, value: Json) -> TestResult<Failure> {
    json_fail(|doc| doc[ENTRIES][index][key] = value)
}

fn entry_missing(key: &str) -> TestResult<Failure> {
    json_fail(|doc| remove_key(&mut doc[ENTRIES][0], key))
}

fn record_fail(key: &str, value: Json) -> TestResult<Failure> {
    json_fail(|doc| doc["adapter_records"][0][key] = value)
}

fn record_missing(key: &str) -> TestResult<Failure> {
    json_fail(|doc| remove_key(&mut doc["adapter_records"][0], key))
}

fn uint(value: u64) -> Cbor {
    Cbor::Integer(value.into())
}

fn text(value: &str) -> Cbor {
    Cbor::Text(value.to_owned())
}

fn cbor_record(byte: u8, call_index: u64, wall: u64) -> Cbor {
    let pairs = [
        ("plugin_id", Cbor::Bytes(vec![byte; 16])),
        ("wall_time", uint(wall)),
        ("call_index", uint(call_index)),
        ("input_hash", Cbor::Bytes(vec![byte; 32])),
        ("output_hash", Cbor::Bytes(vec![byte + 1; 32])),
    ];
    Cbor::Map(
        pairs
            .into_iter()
            .map(|(key, value)| (text(key), value))
            .collect(),
    )
}

// The layout from the module docs, written without the crate's encoder.
fn base_fields() -> TestResult<Fields> {
    let records = Cbor::Array(vec![cbor_record(5, 3, 77)]);
    let roster_bytes = Cbor::Bytes(roster()?.to_canonical_cbor());
    Ok(vec![
        ("label", text("run-1")),
        ("head_hash", Cbor::Bytes(vec![9; 32])),
        ("created_at", uint(1_000_000)),
        ("timeline_id", Cbor::Bytes(vec![7; 16])),
        ("adapter_records", records),
        ("manifest_plugin_roster", roster_bytes),
        ("manifest_format_version", uint(2)),
    ])
}

fn cbor_doc(fields: &Fields) -> TestResult<Vec<u8>> {
    let pairs = fields
        .iter()
        .map(|(key, value)| (text(key), value.clone()))
        .collect();
    let mut out = Vec::new();
    ciborium::into_writer(&Cbor::Map(pairs), &mut out)?;
    Ok(out)
}

fn set(mut fields: Fields, key: &str, value: Cbor) -> Fields {
    if let Some(pair) = fields.iter_mut().find(|pair| pair.0 == key) {
        pair.1 = value;
    }
    fields
}

fn without(mut fields: Fields, key: &str) -> Fields {
    fields.retain(|pair| pair.0 != key);
    fields
}

fn with(mut fields: Fields, key: &'static str, value: Cbor) -> Fields {
    fields.push((key, value));
    fields
}

fn cbor_fail(fields: &Fields) -> TestResult<Failure> {
    rejection(ReproManifestV2::from_cbor(&cbor_doc(fields)?))
}

fn cbor_set(key: &str, value: Cbor) -> TestResult<Failure> {
    cbor_fail(&set(base_fields()?, key, value))
}

fn cbor_add(key: &'static str, value: Cbor) -> TestResult<Failure> {
    cbor_fail(&with(base_fields()?, key, value))
}

fn cbor_drop(key: &str) -> TestResult<Failure> {
    cbor_fail(&without(base_fields()?, key))
}

fn member(key: &str, value: &Json) -> String {
    format!("{}:{value}", Json::from(key))
}

fn legacy_json() -> Json {
    json!({
        "timeline_id": "00",
        "head_hash": "00",
        "created_at": 1,
        "plugin_versions": {},
        "output_policy_digests": {},
        "replay_policy_identities": {},
        "replay_policy_closures": {},
        "replay_policy_closure_identities": {},
        "adapter_records": [],
        "label": "old",
    })
}

// A real old manifest, built with the real type's constructors and field.
fn old_manifest(label: Option<&str>) -> ReproManifest {
    let mut old = ReproManifest::new(
        timeline(),
        Hash::from_bytes([9; 32]),
        WallTime::from_micros(1),
    );
    old.label = label.map(str::to_owned);
    old
}

fn old_cbor_pairs(old: &ReproManifest) -> TestResult<Vec<(Cbor, Cbor)>> {
    match Cbor::serialized(old)? {
        Cbor::Map(pairs) => Ok(pairs),
        _ => Err("an old manifest serializes as a map".into()),
    }
}

fn cbor_bytes(value: &Cbor) -> TestResult<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

const GOLDEN: &str = "{\"adapter_records\":[{\"call_index\":3,\"input_hash\":\"@I@\",\
\"output_hash\":\"@O@\",\"plugin_id\":\"@P@\",\"wall_time\":77}],\"created_at\":5,\
\"head_hash\":\"@H@\",\"label\":\"x\",\"manifest_format_version\":2,\
\"manifest_plugin_entries\":[{\"closure_bytes\":\"AQ==\",\"eop1_digest\":\"@D@\",\
\"plugin_id\":\"@E@\",\"plugin_name\":\"Sensor\",\"plugin_version\":\"1.0.0\",\
\"stable_slot\":\"sensor.a\"}],\"manifest_plugin_roster_version\":1,\
\"timeline_id\":\"@T@\"}";
const GOLDEN_FILL: [(&str, u8, usize); 7] = [
    ("@I@", 5, 32),
    ("@O@", 6, 32),
    ("@P@", 5, 16),
    ("@H@", 9, 32),
    ("@D@", 1, 32),
    ("@E@", 1, 16),
    ("@T@", 7, 16),
];

fn hex(byte: u8, count: usize) -> String {
    format!("{byte:02x}").repeat(count)
}

// Values that are well-formed but are never a valid unsigned integer, in CBOR.
fn other_cbor_values() -> TestResult<Vec<Cbor>> {
    let beyond_i64 = Integer::try_from(i128::from(i64::MIN) - 1)?;
    Ok(vec![
        Cbor::Null,
        Cbor::Bool(true),
        Cbor::Float(2.0),
        Cbor::Integer((-1_i64).into()),
        Cbor::Integer(beyond_i64),
    ])
}

#[test]
fn json_round_trip_keeps_same_name_rows_digests_and_closures() -> TestResult {
    let source = manifest()?;
    let json_text = source.to_json()?;
    let back = via_json(&source)?;
    assert_eq!(back, source);
    let rows = back.plugin_roster().entries();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].plugin_name(), rows[1].plugin_name());
    assert_ne!(rows[0].eop1_digest(), rows[1].eop1_digest());
    assert_ne!(rows[0].plugin_id(), rows[1].plugin_id());
    let closures: Vec<&[u8]> = rows
        .iter()
        .map(ManifestPluginEntryV1::closure_bytes)
        .collect();
    let expected: [&[u8]; 4] = [&[1], &[2, 3], &[4, 5, 6], &[]];
    assert_eq!(closures, expected);
    let id_member = format!("\"plugin_id\":\"{}\"", "01".repeat(16));
    assert!(json_text.contains(&id_member));
    assert!(json_text.contains("\"closure_bytes\":\"AgM=\""));
    assert!(json_text.contains("\"manifest_plugin_roster_version\":1"));
    assert!(json_text.contains("\"manifest_format_version\":2"));
    assert!(LEGACY.iter().all(|name| !json_text.contains(name)));
    Ok(())
}

#[test]
fn getters_return_what_was_built() -> TestResult {
    let source = manifest()?;
    assert_eq!(source.label(), Some("run-1"));
    assert_eq!(source.timeline_id(), timeline());
    assert_eq!(source.head_hash(), Hash::from_bytes([9; 32]));
    assert_eq!(source.created_at(), WallTime::from_micros(1_000_000));
    assert_eq!(source.adapter_records(), [record(5, 3, 77)]);
    assert_eq!(source.plugin_roster(), &roster()?);
    Ok(())
}

#[test]
fn cbor_round_trip_keeps_same_name_rows_digests_and_closures() -> TestResult {
    let source = manifest()?;
    let back = via_cbor(&source)?;
    assert_eq!(back, source);
    let rows = back.plugin_roster().entries();
    assert_eq!(rows[0].plugin_name(), rows[1].plugin_name());
    assert_ne!(rows[0].eop1_digest(), rows[1].eop1_digest());
    assert_eq!(rows[1].closure_bytes(), [2, 3]);
    Ok(())
}

#[test]
fn cbor_layout_is_the_documented_deterministic_map() -> TestResult {
    let source = manifest()?;
    assert_eq!(source.to_cbor()?, cbor_doc(&base_fields()?)?);
    let unlabeled = build(vec![record(5, 3, 77)], None, 1_000_000)?;
    let fields = without(base_fields()?, "label");
    assert_eq!(unlabeled.to_cbor()?, cbor_doc(&fields)?);
    Ok(())
}

#[test]
fn json_accepts_whitespace_and_any_member_order() -> TestResult {
    let source = manifest()?;
    let doc = json_doc(&source)?;
    let pretty = serde_json::to_string_pretty(&doc)?;
    assert_eq!(ReproManifestV2::from_json(pretty.as_bytes())?, source);
    let object = doc.as_object().ok_or("the manifest is an object")?;
    let members: Vec<String> = object
        .iter()
        .rev()
        .map(|(key, value)| member(key, value))
        .collect();
    let reversed = format!("{{{}}}", members.join(","));
    assert_eq!(ReproManifestV2::from_json(reversed.as_bytes())?, source);
    Ok(())
}

#[test]
fn manifests_without_a_label_round_trip_in_both_transports() -> TestResult {
    let source = build(Vec::new(), None, 0)?;
    assert_eq!(via_json(&source)?, source);
    assert_eq!(via_cbor(&source)?, source);
    assert_eq!(source.label(), None);
    Ok(())
}

#[test]
fn integer_widths_round_trip_in_both_transports() -> TestResult {
    let widths = [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ];
    for width in widths {
        let source = build(vec![record(5, width, width)], None, width)?;
        assert_eq!(via_json(&source)?, source);
        assert_eq!(via_cbor(&source)?, source);
    }
    Ok(())
}

fn full_roster() -> TestResult<ManifestPluginRosterV1> {
    let mut rows = Vec::new();
    for index in 0..=255_u8 {
        let bytes = u128::from(index).to_be_bytes();
        rows.push(ManifestPluginEntryV1::new(
            format!("s{index:03}"),
            PluginId::from_ulid(ulid::Ulid::from_bytes(bytes)),
            "Sensor",
            "1.0.0",
            Hash::from_bytes([index.max(1); 32]),
            vec![index],
        )?);
    }
    Ok(ManifestPluginRosterV1::new(rows)?)
}

#[test]
fn a_roster_of_exactly_256_entries_round_trips() -> TestResult {
    let source = ReproManifestV2::new(
        timeline(),
        Hash::from_bytes([9; 32]),
        WallTime::from_micros(1),
        full_roster()?,
        Vec::new(),
        None,
    )?;
    assert_eq!(source.plugin_roster().entries().len(), 256);
    assert_eq!(via_json(&source)?, source);
    assert_eq!(via_cbor(&source)?, source);
    Ok(())
}

#[test]
fn json_roster_count_is_checked_before_any_entry_is_decoded() -> TestResult {
    let too_many = Json::Array(vec![json!(0); 257]);
    let failure = top_fail(ENTRIES, too_many)?;
    assert_eq!(failure, Failure::Roster(RosterFailure::RosterTooLarge));
    let at_cap = Json::Array(vec![json!(0); 256]);
    let failure = top_fail(ENTRIES, at_cap)?;
    assert_eq!(invalid_of(&failure), Some(ENTRIES));
    Ok(())
}

#[test]
fn old_and_missing_version_json_documents_are_unsupported() -> TestResult {
    let old = legacy_json().to_string();
    assert_eq!(text_fail(&old)?, unsupported(None));
    let mut one = legacy_json();
    one["manifest_format_version"] = json!(1);
    assert_eq!(text_fail(&one.to_string())?, unsupported(Some(1)));
    let missing_version = top_missing("manifest_format_version")?;
    assert_eq!(missing_version, unsupported(None));
    let quoted = top_fail("manifest_format_version", json!("2"))?;
    assert_eq!(quoted, unsupported(None));
    let three = top_fail("manifest_format_version", json!(3))?;
    assert_eq!(three, unsupported(Some(3)));
    for other in [json!(2.0), json!(null), json!(true), json!(-2)] {
        assert_eq!(top_fail(VERSION, other)?, unsupported(None));
    }
    Ok(())
}

#[test]
fn real_old_manifests_report_an_unsupported_version_in_both_transports() -> TestResult {
    for label in [None, Some("old-run")] {
        let old = old_manifest(label);
        let json = serde_json::to_string(&old)?;
        assert_eq!(json.contains("\"label\":null"), label.is_none());
        assert_eq!(text_fail(&json)?, unsupported(None));
        let pairs = old_cbor_pairs(&old)?;
        let null_label = pairs.contains(&(text("label"), Cbor::Null));
        assert_eq!(null_label, label.is_none());
        let cbor = cbor_bytes(&Cbor::Map(pairs))?;
        let failure = rejection(ReproManifestV2::from_cbor(&cbor))?;
        assert_eq!(failure, unsupported(None));
    }
    let mut versioned = serde_json::to_value(old_manifest(None))?;
    versioned[VERSION] = json!(1);
    assert_eq!(text_fail(&versioned.to_string())?, unsupported(Some(1)));
    Ok(())
}

#[test]
fn real_old_manifests_with_a_roster_are_ambiguous_in_both_transports() -> TestResult {
    for label in [None, Some("old-run")] {
        let old = old_manifest(label);
        let mut doc = serde_json::to_value(&old)?;
        doc[ENTRIES] = json!([]);
        assert_eq!(text_fail(&doc.to_string())?, ambiguous(ENTRIES));
        let mut pairs = old_cbor_pairs(&old)?;
        pairs.push((text("manifest_plugin_roster"), Cbor::Bytes(Vec::new())));
        let cbor = cbor_bytes(&Cbor::Map(pairs))?;
        let failure = rejection(ReproManifestV2::from_cbor(&cbor))?;
        assert_eq!(failure, ambiguous("manifest_plugin_roster"));
    }
    Ok(())
}

#[test]
fn null_bool_float_and_negative_values_fail_their_field_in_cbor() -> TestResult {
    for other in other_cbor_values()? {
        let label = cbor_set("label", other.clone())?;
        assert_eq!(invalid_of(&label), Some("label"));
        let created = cbor_set("created_at", other)?;
        assert_eq!(invalid_of(&created), Some("created_at"));
    }
    Ok(())
}

#[test]
fn json_text_is_pinned_exactly() -> TestResult {
    // serde_json sorts object keys unless its `preserve_order` feature is on; this pins the text.
    let roster = ManifestPluginRosterV1::new(vec![entry("sensor.a", 1, &[1])?])?;
    let source = ReproManifestV2::new(
        timeline(),
        Hash::from_bytes([9; 32]),
        WallTime::from_micros(5),
        roster,
        vec![record(5, 3, 77)],
        Some("x".to_owned()),
    )?;
    let mut expected = GOLDEN.to_owned();
    for (token, byte, count) in GOLDEN_FILL {
        expected = expected.replace(token, &hex(byte, count));
    }
    assert_eq!(source.to_json()?, expected);
    Ok(())
}

#[test]
fn mixed_json_documents_are_ambiguous_even_with_empty_old_maps() -> TestResult {
    for name in LEGACY {
        let failure = top_fail(name, json!({}))?;
        assert_eq!(failure, ambiguous(name));
    }
    let field = "manifest_plugin_roster_version";
    let old_version = json_fail(|doc| {
        doc["manifest_format_version"] = json!(1);
        doc["plugin_versions"] = json!({});
    })?;
    assert_eq!(old_version, ambiguous(field));
    let no_version = json_fail(|doc| {
        remove_key(doc, "manifest_format_version");
        doc["plugin_versions"] = json!({});
    })?;
    assert_eq!(no_version, ambiguous(field));
    Ok(())
}

#[test]
fn old_missing_version_and_mixed_cbor_documents_are_rejected() -> TestResult {
    let old = vec![
        ("timeline_id", Cbor::Bytes(vec![7; 16])),
        ("plugin_versions", Cbor::Map(Vec::new())),
    ];
    assert_eq!(cbor_fail(&old)?, unsupported(None));
    let version = VERSION;
    assert_eq!(cbor_set(version, uint(1))?, unsupported(Some(1)));
    for other in other_cbor_values()? {
        assert_eq!(cbor_set(version, other)?, unsupported(None));
    }
    assert_eq!(cbor_set(version, text("2"))?, unsupported(None));
    for name in LEGACY {
        let failure = cbor_add(name, Cbor::Map(Vec::new()))?;
        assert_eq!(failure, ambiguous(name));
    }
    let unversioned = without(base_fields()?, version);
    let mixed = with(unversioned, "plugin_versions", uint(0));
    assert_eq!(cbor_fail(&mixed)?, ambiguous("manifest_plugin_roster"));
    Ok(())
}

#[test]
fn json_duplicate_keys_are_rejected_at_every_level() -> TestResult {
    let source = manifest()?.to_json()?;
    let top = format!("{{\"head_hash\":\"{}\",{}", "00".repeat(32), &source[1..]);
    assert_eq!(text_fail(&top)?, duplicate("head_hash"));
    let slot_twice = "\"stable_slot\":\"x\",\"stable_slot\":";
    let in_entry = source.replacen("\"stable_slot\":", slot_twice, 1);
    assert_eq!(text_fail(&in_entry)?, duplicate("stable_slot"));
    let call_twice = "\"call_index\":1,\"call_index\":";
    let in_record = source.replacen("\"call_index\":", call_twice, 1);
    assert_eq!(text_fail(&in_record)?, duplicate("call_index"));
    Ok(())
}

#[test]
fn cbor_duplicate_keys_are_rejected_before_a_generic_decoder_can_discard_them() -> TestResult {
    let repeat = cbor_add("head_hash", Cbor::Bytes(vec![0; 32]))?;
    assert_eq!(repeat, duplicate("head_hash"));
    let Cbor::Map(mut pairs) = cbor_record(5, 3, 77) else {
        return Err("a record is a map".into());
    };
    pairs.push((text("call_index"), uint(9)));
    let records = Cbor::Array(vec![Cbor::Map(pairs)]);
    let nested = cbor_set("adapter_records", records)?;
    assert_eq!(nested, duplicate("call_index"));
    Ok(())
}

#[test]
fn unknown_fields_are_rejected_in_both_transports() -> TestResult {
    assert_eq!(top_fail("extra", json!(1))?, unknown("extra"));
    assert_eq!(entry_fail(0, "extra", json!(1))?, unknown("extra"));
    assert_eq!(record_fail("extra", json!(1))?, unknown("extra"));
    assert_eq!(cbor_add("extra", uint(1))?, unknown("extra"));
    let long = "k".repeat(100);
    assert_eq!(top_fail(&long, json!(1))?, unknown(&"k".repeat(64)));
    Ok(())
}

#[test]
fn the_other_transports_roster_fields_are_rejected() -> TestResult {
    let foreign = top_fail("manifest_plugin_roster", json!("00"))?;
    assert_eq!(foreign, wrong("manifest_plugin_roster", "JSON"));
    let entries = cbor_add(ENTRIES, Cbor::Array(Vec::new()))?;
    assert_eq!(entries, wrong(ENTRIES, "CBOR"));
    let version = "manifest_plugin_roster_version";
    assert_eq!(cbor_add(version, uint(1))?, wrong(version, "CBOR"));
    Ok(())
}

#[test]
fn every_required_field_must_be_present() -> TestResult {
    for name in JSON_REQUIRED {
        assert_eq!(top_missing(name)?, missing(name));
    }
    for name in CBOR_REQUIRED {
        assert_eq!(cbor_drop(name)?, missing(name));
    }
    assert_eq!(entry_missing("closure_bytes")?, missing("closure_bytes"));
    assert_eq!(record_missing("wall_time")?, missing("wall_time"));
    Ok(())
}

#[test]
fn json_top_level_values_must_have_the_documented_shape() -> TestResult {
    let short = top_fail("head_hash", json!("00"))?;
    assert_eq!(invalid_of(&short), Some("head_hash"));
    let number = top_fail("head_hash", json!(5))?;
    assert_eq!(invalid_of(&number), Some("head_hash"));
    let garbage = top_fail("head_hash", json!("0g".repeat(32)))?;
    assert_eq!(canon_of(&garbage), Some("head_hash"));
    let shouting = top_fail("head_hash", json!("AB".repeat(32)))?;
    assert_eq!(canon_of(&shouting), Some("head_hash"));
    let id = top_fail("timeline_id", json!("00".repeat(15)))?;
    assert_eq!(invalid_of(&id), Some("timeline_id"));
    let created = top_fail("created_at", json!("x"))?;
    assert_eq!(invalid_of(&created), Some("created_at"));
    let records = top_fail("adapter_records", json!("x"))?;
    assert_eq!(invalid_of(&records), Some("adapter_records"));
    let label = top_fail("label", json!(5))?;
    assert_eq!(invalid_of(&label), Some("label"));
    let null_label = top_fail("label", Json::Null)?;
    assert_eq!(invalid_of(&null_label), Some("label"));
    let negative = top_fail("created_at", json!(-1))?;
    assert_eq!(invalid_of(&negative), Some("created_at"));
    let float = top_fail("created_at", json!(1.5))?;
    assert_eq!(invalid_of(&float), Some("created_at"));
    let flag = top_fail("head_hash", json!(true))?;
    assert_eq!(invalid_of(&flag), Some("head_hash"));
    Ok(())
}

#[test]
fn json_record_and_entry_values_must_have_the_documented_shape() -> TestResult {
    let row = top_fail("adapter_records", json!([1]))?;
    assert_eq!(invalid_of(&row), Some("adapter_records"));
    let call = record_fail("call_index", json!("x"))?;
    assert_eq!(invalid_of(&call), Some("call_index"));
    let digest = record_fail("input_hash", json!("00"))?;
    assert_eq!(invalid_of(&digest), Some("input_hash"));
    let version = top_fail("manifest_plugin_roster_version", json!(2))?;
    assert_eq!(invalid_of(&version), Some("manifest_plugin_roster_version"));
    let rows = top_fail(ENTRIES, json!("x"))?;
    assert_eq!(invalid_of(&rows), Some(ENTRIES));
    let not_object = entry_fail(0, "plugin_name", json!(5))?;
    assert_eq!(invalid_of(&not_object), Some("plugin_name"));
    let closure = entry_fail(0, "closure_bytes", json!(5))?;
    assert_eq!(invalid_of(&closure), Some("closure_bytes"));
    let eop1 = entry_fail(0, "eop1_digest", json!("00"))?;
    assert_eq!(invalid_of(&eop1), Some("eop1_digest"));
    let flat = top_fail(ENTRIES, json!([1]))?;
    assert_eq!(invalid_of(&flat), Some(ENTRIES));
    Ok(())
}

#[test]
fn noncanonical_base64_closures_are_rejected() -> TestResult {
    let cases = [
        "AQ", "AQ=", "AR==", "A===", "AQ=A", " AQ==", "AQ==\n", "AQ===", "AQ-_", "=AQ=",
    ];
    for case in cases {
        let failure = entry_fail(0, "closure_bytes", json!(case))?;
        assert_eq!(canon_of(&failure), Some("closure_bytes"), "{case}");
    }
    Ok(())
}

#[test]
fn json_roster_rules_are_enforced() -> TestResult {
    let unsorted_rows = json_fail(|doc| {
        if let Some(rows) = doc[ENTRIES].as_array_mut() {
            rows.swap(0, 1);
        }
    })?;
    assert_eq!(unsorted_rows, unsorted("sensor.a"));
    let same_slot = entry_fail(1, "stable_slot", json!("sensor.a"))?;
    assert_eq!(same_slot, repeated_slot("sensor.a"));
    let first = json_doc(&manifest()?)?[ENTRIES][0]["plugin_id"].clone();
    let same_id = entry_fail(1, "plugin_id", first)?;
    assert_eq!(same_id, repeated_id("sensor.b"));
    let nameless = entry_fail(0, "plugin_name", json!(""))?;
    assert_eq!(nameless, bad_name("sensor.a"));
    let spaced = entry_fail(0, "stable_slot", json!("a b"))?;
    assert_eq!(spaced, bad_slot("a b"));
    Ok(())
}

#[test]
fn cbor_structure_must_be_one_exact_deterministic_map() -> TestResult {
    let good = manifest()?.to_cbor()?;
    let mut trailing = good.clone();
    trailing.push(0);
    let failure = rejection(ReproManifestV2::from_cbor(&trailing))?;
    assert_eq!(failure, malformed("CBOR"));
    let cases: [&[u8]; 3] = [&[], &good[..good.len() - 1], &[0x82, 0, 0]];
    for bytes in cases {
        let failure = rejection(ReproManifestV2::from_cbor(bytes))?;
        assert_eq!(failure, malformed("CBOR"));
    }
    let mut keyed = Vec::new();
    ciborium::into_writer(&Cbor::Map(vec![(uint(1), uint(2))]), &mut keyed)?;
    let failure = rejection(ReproManifestV2::from_cbor(&keyed))?;
    assert_eq!(failure, malformed("CBOR"));
    let mut reversed = base_fields()?;
    reversed.reverse();
    assert_eq!(canon_of(&cbor_fail(&reversed)?), Some("manifest"));
    let mut indefinite = good;
    indefinite[0] = 0xbf;
    indefinite.push(0xff);
    let failure = rejection(ReproManifestV2::from_cbor(&indefinite))?;
    assert_eq!(canon_of(&failure), Some("manifest"));
    Ok(())
}

#[test]
fn cbor_values_must_have_the_documented_shape() -> TestResult {
    let id = cbor_set("timeline_id", Cbor::Bytes(vec![7; 15]))?;
    assert_eq!(invalid_of(&id), Some("timeline_id"));
    let hex = cbor_set("timeline_id", text(&"07".repeat(16)))?;
    assert_eq!(invalid_of(&hex), Some("timeline_id"));
    let head = cbor_set("head_hash", text("x"))?;
    assert_eq!(invalid_of(&head), Some("head_hash"));
    let created = cbor_set("created_at", text("x"))?;
    assert_eq!(invalid_of(&created), Some("created_at"));
    let records = cbor_set("adapter_records", uint(1))?;
    assert_eq!(invalid_of(&records), Some("adapter_records"));
    let label = cbor_set("label", Cbor::Bytes(vec![1]))?;
    assert_eq!(invalid_of(&label), Some("label"));
    let roster_text = cbor_set("manifest_plugin_roster", text("x"))?;
    assert_eq!(invalid_of(&roster_text), Some("manifest_plugin_roster"));
    let row = cbor_set("adapter_records", Cbor::Array(vec![uint(1)]))?;
    assert_eq!(invalid_of(&row), Some("adapter_records"));
    Ok(())
}

#[test]
fn cbor_roster_bytes_must_be_exact_canonical_mpr1() -> TestResult {
    let garbage = cbor_set("manifest_plugin_roster", Cbor::Bytes(vec![0xff]))?;
    assert_eq!(garbage, Failure::Roster(RosterFailure::InvalidEncoding));
    let mut wide = roster()?.to_canonical_cbor();
    wide.splice(0..1, [0x98, 0x02]);
    let failure = cbor_set("manifest_plugin_roster", Cbor::Bytes(wide))?;
    assert_eq!(failure, Failure::Roster(RosterFailure::NonCanonical));
    Ok(())
}

#[test]
fn input_size_cap_is_checked_before_parsing() -> TestResult {
    let max = MAX_REPRO_MANIFEST_V2_INPUT_BYTES;
    assert_eq!(max, 1_610_612_736);
    assert_eq!(checked_repro_manifest_v2_input_len(max), Ok(max));
    let refusal = Failure::InputTooLarge { max };
    let over = checked_repro_manifest_v2_input_len(max + 1);
    assert_eq!(over, Err(refusal.clone()));
    let way_over = checked_repro_manifest_v2_input_len(usize::MAX);
    assert_eq!(way_over, Err(refusal.clone()));
    // One 1.5 GiB buffer feeds both transports. The zeroing is lazy (calloc-backed), so the pages
    // are never touched: the cap check must refuse before any byte is read.
    let huge = vec![0_u8; max + 1];
    assert_eq!(rejection(ReproManifestV2::from_json(&huge))?, refusal);
    assert_eq!(rejection(ReproManifestV2::from_cbor(&huge))?, refusal);
    Ok(())
}

#[test]
fn adapter_record_cap_is_checked_while_streaming() -> TestResult {
    assert_eq!(CAP, 1_048_576);
    let over = top_fail("adapter_records", Json::Array(vec![json!(0); CAP + 1]))?;
    assert_eq!(over, streaming());
    let at_cap = top_fail("adapter_records", Json::Array(vec![json!(0); CAP]))?;
    assert_eq!(invalid_of(&at_cap), Some("adapter_records"));
    let over = cbor_set("adapter_records", Cbor::Array(vec![uint(0); CAP + 1]))?;
    assert_eq!(over, streaming());
    let at_cap = cbor_set("adapter_records", Cbor::Array(vec![uint(0); CAP]))?;
    assert_eq!(invalid_of(&at_cap), Some("adapter_records"));
    Ok(())
}

#[test]
fn adapter_record_and_label_caps_are_checked_on_construction() -> TestResult {
    let accepted = build(vec![record(1, 0, 0); CAP], None, 0)?;
    assert_eq!(accepted.adapter_records().len(), CAP);
    drop(accepted);
    let failure = rejection(construct(vec![record(1, 0, 0); CAP + 1], None, 0)?)?;
    let expected = Failure::TooManyElements {
        field: "adapter_records",
        max: CAP,
    };
    assert_eq!(failure, expected);
    let label = Some("a".repeat(257));
    let failure = rejection(construct(Vec::new(), label, 0)?)?;
    assert_eq!(failure, Failure::LabelTooLong { len: 257 });
    Ok(())
}

#[test]
fn labels_are_bounded_to_256_utf8_bytes_in_both_transports() -> TestResult {
    let exact = "a".repeat(256);
    let source = build(Vec::new(), Some(&exact), 0)?;
    assert_eq!(via_json(&source)?, source);
    assert_eq!(via_cbor(&source)?, source);
    let long = "a".repeat(257);
    let refusal = Failure::LabelTooLong { len: 257 };
    assert_eq!(top_fail("label", json!(long))?, refusal);
    assert_eq!(cbor_set("label", text(&long))?, refusal);
    // Longer than the CBOR decoder's scratch buffer, so the text arrives as an owned string.
    let owned = cbor_set("label", text(&"a".repeat(5000)))?;
    assert_eq!(owned, Failure::LabelTooLong { len: 5000 });
    let multibyte = top_fail("label", json!("é".repeat(129)))?;
    assert_eq!(multibyte, Failure::LabelTooLong { len: 258 });
    Ok(())
}

#[test]
fn messages_name_the_field_and_say_what_to_change() -> TestResult {
    let source = manifest()?.to_json()?;
    let top = format!("{{\"head_hash\":\"{}\",{}", "00".repeat(32), &source[1..]);
    let failures = vec![
        text_fail(&legacy_json().to_string())?,
        text_fail(&top)?,
        top_fail("extra", json!(1))?,
        top_missing("head_hash")?,
        top_fail("head_hash", json!("00"))?,
        top_fail("head_hash", json!("AB".repeat(32)))?,
        top_fail("label", json!("x".repeat(300)))?,
        top_fail("manifest_plugin_roster", json!("0"))?,
        top_fail("plugin_versions", json!({}))?,
        top_fail("manifest_format_version", json!(3))?,
        entry_fail(0, "stable_slot", json!("a b"))?,
        text_fail("[")?,
        Failure::InputTooLarge { max: 7 },
        Failure::UnsupportedManifestVersion { found: None },
    ];
    let needles = [
        "manifest_format_version",
        "duplicate key `head_hash`",
        "unknown field `extra`: remove it",
        "missing required field `head_hash`: add",
        "invalid `head_hash`",
        "lowercase hex",
        "shorten it",
        "manifest_plugin_entries in",
        "remove plugin_versions",
        "(3)",
        "slot",
        "malformed JSON manifest",
        "larger than 7 bytes",
        "missing or not an unsigned integer",
    ];
    for (failure, needle) in failures.iter().zip(needles) {
        let message = failure.to_string();
        assert!(message.contains(needle), "{message:?} lacks {needle:?}");
    }
    Ok(())
}

#[test]
fn json_documents_must_be_one_object_without_trailing_text() -> TestResult {
    assert_eq!(text_fail("[1]")?, malformed("JSON"));
    assert_eq!(text_fail("{} 1")?, malformed("JSON"));
    assert_eq!(text_fail("")?, malformed("JSON"));
    Ok(())
}

#[test]
fn too_many_elements_message_names_the_field_and_limit() {
    let message = streaming().to_string();
    let needle = "an array has more than 1048576 elements: keep at most 1048576";
    assert!(message.contains(needle));
    let built = Failure::TooManyElements {
        field: "adapter_records",
        max: CAP,
    };
    let message = built.to_string();
    let needle = "adapter_records has more than 1048576 elements";
    assert!(message.contains(needle));
}
