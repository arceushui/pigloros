use std::sync::Arc;

use pos_core::{
    checked_manifest_plugin_roster_size_v1, Hash, ManifestPluginEntryV1, ManifestPluginFieldV1,
    ManifestPluginRosterErrorV1, ManifestPluginRosterV1, PluginId,
    MAX_MANIFEST_PLUGIN_CLOSURE_BYTES_V1, MAX_MANIFEST_PLUGIN_ROSTER_BYTES_V1,
    MAX_MANIFEST_PLUGIN_ROSTER_ENTRIES_V1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type RosterError = ManifestPluginRosterErrorV1;
type Field = ManifestPluginFieldV1;

const INVALID: RosterError = RosterError::InvalidEncoding;
const NONCANONICAL: RosterError = RosterError::NonCanonical;
const TOO_LARGE: RosterError = RosterError::RosterTooLarge;
const BAD_MAGIC: RosterError = RosterError::UnsupportedMagic;

// Independent literal of the native OPC1 maximum, never read from production.
const CLOSURE_LIMIT_BYTES: usize = 5_374_516;
const CLOSURE_LIMIT: u64 = CLOSURE_LIMIT_BYTES as u64;
const SECRET: &[u8] = b"SECRET-CLOSURE-BYTES";

// A small CBOR writer, deliberately independent of the production encoder.
fn wide_head(major: u8, value: u64, width: usize) -> Vec<u8> {
    let additional = match width {
        1 => 24,
        2 => 25,
        4 => 26,
        _ => 27,
    };
    let mut out = vec![(major << 5) | additional];
    out.extend_from_slice(&value.to_be_bytes()[8 - width..]);
    out
}

fn head(major: u8, value: u64) -> Vec<u8> {
    match value {
        0..=23 => vec![(major << 5) | value.to_be_bytes()[7]],
        24..=255 => wide_head(major, value, 1),
        256..=65_535 => wide_head(major, value, 2),
        65_536..=4_294_967_295 => wide_head(major, value, 4),
        _ => wide_head(major, value, 8),
    }
}

fn bstr(payload: &[u8]) -> Vec<u8> {
    let mut out = head(2, payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

fn tstr(text: &str) -> Vec<u8> {
    let mut out = head(3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
    out
}

fn magic() -> Vec<u8> {
    bstr(b"MPR1")
}

fn shell(magic: Vec<u8>, count: Vec<u8>) -> Vec<u8> {
    [head(4, 2), magic, count].concat()
}

fn roster_cbor(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = shell(magic(), head(4, entries.len() as u64));
    out.extend(entries.concat());
    out
}

const fn id_bytes(id: u16) -> [u8; 16] {
    let [high, low] = id.to_be_bytes();
    let mut out = [0; 16];
    out[14] = high;
    out[15] = low;
    out
}

const fn plugin(id: u16) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from_bytes(id_bytes(id)))
}

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

struct Row {
    slot: String,
    id: u16,
    name: String,
    version: String,
    digest: u8,
    closure: Vec<u8>,
}

fn row(slot: &str, id: u16) -> Row {
    Row {
        slot: slot.to_owned(),
        id,
        name: "plug".to_owned(),
        version: "1.0".to_owned(),
        digest: 7,
        closure: b"closure".to_vec(),
    }
}

fn named(name: String) -> Row {
    Row {
        name,
        ..row("a", 1)
    }
}

fn versioned(version: String) -> Row {
    Row {
        version,
        ..row("a", 1)
    }
}

fn digested(digest: u8) -> Row {
    Row {
        digest,
        ..row("a", 1)
    }
}

fn closed(slot: &str, id: u16, closure: Vec<u8>) -> Row {
    Row {
        closure,
        ..row(slot, id)
    }
}

impl Row {
    fn entry(&self) -> Result<ManifestPluginEntryV1, RosterError> {
        ManifestPluginEntryV1::new(
            self.slot.clone(),
            plugin(self.id),
            self.name.clone(),
            self.version.clone(),
            hash(self.digest),
            Arc::from(self.closure.as_slice()),
        )
    }

    fn fields(&self) -> [Vec<u8>; 7] {
        [
            head(4, 6),
            tstr(&self.slot),
            bstr(&id_bytes(self.id)),
            tstr(&self.name),
            tstr(&self.version),
            bstr(&[self.digest; 32]),
            bstr(&self.closure),
        ]
    }

    fn cbor(&self) -> Vec<u8> {
        self.fields().concat()
    }
}

fn numbered_rows(count: u16) -> Vec<Row> {
    (1..=count)
        .map(|index| row(&format!("s{index:03}"), index))
        .collect()
}

fn build(batch: &[Row]) -> Result<ManifestPluginRosterV1, RosterError> {
    let mut entries = Vec::new();
    for item in batch {
        entries.push(item.entry()?);
    }
    ManifestPluginRosterV1::new(entries)
}

fn wire(batch: &[Row]) -> Vec<u8> {
    let encoded = batch.iter().map(Row::cbor).collect::<Vec<_>>();
    roster_cbor(&encoded)
}

// One single-row roster whose field at `index` is replaced by raw bytes.
fn with_field(index: usize, replacement: Vec<u8>) -> Vec<u8> {
    let mut fields = row("a", 1).fields();
    fields[index] = replacement;
    roster_cbor(&[fields.concat()])
}

fn decode(bytes: &[u8]) -> Result<ManifestPluginRosterV1, RosterError> {
    ManifestPluginRosterV1::from_canonical_cbor(bytes)
}

fn duplicate_slot(slot: &str) -> RosterError {
    RosterError::DuplicateSlot {
        slot: slot.to_owned(),
    }
}

fn duplicate_id(slot: &str) -> RosterError {
    RosterError::DuplicatePluginId {
        slot: slot.to_owned(),
    }
}

fn invalid_slot(slot: &str) -> RosterError {
    RosterError::InvalidSlot {
        slot: slot.to_owned(),
    }
}

fn unsorted(slot: &str) -> RosterError {
    RosterError::UnsortedSlots {
        slot: slot.to_owned(),
    }
}

fn invalid_field(slot: &str, field: Field) -> RosterError {
    RosterError::InvalidField {
        slot: slot.to_owned(),
        field,
    }
}

fn slots_of(roster: &ManifestPluginRosterV1) -> Vec<&str> {
    roster
        .entries()
        .iter()
        .map(ManifestPluginEntryV1::stable_slot)
        .collect()
}

fn build_rejects(batch: &[Row], error: RosterError) {
    assert_eq!(build(batch).err(), Some(error));
}

fn decode_rejects(bytes: &[u8], error: RosterError) {
    assert_eq!(decode(bytes).err(), Some(error));
}

fn field_rejects(index: usize, replacement: Vec<u8>, error: RosterError) {
    decode_rejects(&with_field(index, replacement), error);
}

// Accepted rows must match the independent literal and decode back equal.
fn assert_roundtrip(batch: &[Row]) -> TestResult {
    let roster = build(batch)?;
    let bytes = roster.to_canonical_cbor();
    assert_eq!(bytes, wire(batch));
    assert_eq!(decode(&bytes)?, roster);
    Ok(())
}

#[test]
fn empty_roster_is_the_literal_seven_bytes() -> TestResult {
    let literal = [0x82, 0x44, b'M', b'P', b'R', b'1', 0x80];
    let roster = ManifestPluginRosterV1::new(Vec::new())?;
    assert!(roster.entries().is_empty());
    assert_eq!(roster.to_canonical_cbor(), literal);
    assert_eq!(decode(&literal)?, roster);
    Ok(())
}

#[test]
fn one_entry_roster_matches_the_literal_vector() -> TestResult {
    let batch = [row("slot-a", 1)];
    let roster = build(&batch)?;
    let bytes = roster.to_canonical_cbor();
    let prefix = [0x82, 0x44, 0x4d, 0x50, 0x52, 0x31, 0x81, 0x86, 0x66];
    assert_eq!(bytes[..9], prefix);
    assert_eq!(bytes, wire(&batch));
    let decoded = decode(&bytes)?;
    assert_eq!(decoded, roster);
    let [entry] = decoded.entries() else {
        return Err("expected exactly one entry".into());
    };
    assert_eq!(entry.stable_slot(), "slot-a");
    assert_eq!(entry.plugin_id(), plugin(1));
    assert_eq!(entry.plugin_name(), "plug");
    assert_eq!(entry.plugin_version(), "1.0");
    assert_eq!(entry.eop1_digest(), hash(7));
    assert_eq!(entry.closure_bytes(), b"closure");
    Ok(())
}

#[test]
fn full_256_entry_roster_roundtrips_against_the_literal() -> TestResult {
    assert_eq!(MAX_MANIFEST_PLUGIN_ROSTER_ENTRIES_V1, 256);
    let batch = numbered_rows(256);
    let roster = build(&batch)?;
    let bytes = roster.to_canonical_cbor();
    assert_eq!(bytes[6..9], [0x99, 0x01, 0x00]);
    assert_eq!(bytes, wire(&batch));
    assert_eq!(roster.entries().len(), 256);
    assert_eq!(decode(&bytes)?, roster);
    Ok(())
}

#[test]
fn same_name_plugins_keep_distinct_ids_digests_and_closures() -> TestResult {
    let first = Row {
        name: "same".to_owned(),
        digest: 1,
        closure: b"one".to_vec(),
        ..row("alpha", 1)
    };
    let second = Row {
        name: "same".to_owned(),
        digest: 2,
        closure: b"two".to_vec(),
        ..row("beta", 2)
    };
    let batch = [first, second];
    assert_roundtrip(&batch)?;
    let decoded = decode(&wire(&batch))?;
    let [left, right] = decoded.entries() else {
        return Err("expected exactly two entries".into());
    };
    assert_eq!(left.plugin_name(), right.plugin_name());
    assert_ne!(left.plugin_id(), right.plugin_id());
    assert_eq!(left.eop1_digest(), hash(1));
    assert_eq!(right.eop1_digest(), hash(2));
    assert_eq!(left.closure_bytes(), b"one");
    assert_eq!(right.closure_bytes(), b"two");
    Ok(())
}

#[test]
fn new_sorts_entries_given_in_any_order() -> TestResult {
    let scrambled = [row("c", 3), row("a", 1), row("b", 2)];
    let roster = build(&scrambled)?;
    assert_eq!(slots_of(&roster), ["a", "b", "c"]);
    let ordered = [row("a", 1), row("b", 2), row("c", 3)];
    assert_eq!(roster.to_canonical_cbor(), wire(&ordered));
    // Sorting compares raw bytes: uppercase and punctuation sort before lowercase.
    let mixed = [row("a", 1), row("Z", 2), row("-", 3), row("_", 4)];
    assert_eq!(slots_of(&build(&mixed)?), ["-", "Z", "_", "a"]);
    Ok(())
}

#[test]
fn slots_order_by_raw_bytes_not_by_case_or_collation() -> TestResult {
    let sorted = ["-", ".", "0", "A", "Z", "_", "a"];
    let batch = sorted
        .iter()
        .zip(1..)
        .map(|(slot, id)| row(slot, id))
        .collect::<Vec<_>>();
    assert_roundtrip(&batch)?;
    decode_rejects(&wire(&[row("a", 1), row("Z", 2)]), unsorted("Z"));
    Ok(())
}

#[test]
fn duplicate_slots_ids_and_disorder_reject_with_the_precise_slot() {
    let same_slot = [row("a", 1), row("a", 2)];
    build_rejects(&same_slot, duplicate_slot("a"));
    decode_rejects(&wire(&same_slot), duplicate_slot("a"));
    let same_id = [row("a", 1), row("b", 1)];
    build_rejects(&same_id, duplicate_id("b"));
    decode_rejects(&wire(&same_id), duplicate_id("b"));
    let reversed_id = [row("b", 1), row("a", 1)];
    build_rejects(&reversed_id, duplicate_id("b"));
    let unsorted_rows = [row("b", 1), row("a", 2)];
    decode_rejects(&wire(&unsorted_rows), unsorted("a"));
    let both = [row("a", 1), row("a", 1)];
    build_rejects(&both, duplicate_slot("a"));
    let separated = [row("b", 1), row("a", 2), row("b", 3)];
    build_rejects(&separated, duplicate_slot("b"));
    decode_rejects(&wire(&separated), unsorted("a"));
}

#[test]
fn slot_grammar_rejects_in_both_directions() {
    for slot in ["", "bad slot", "a/b", "a:b", "a\n", "caf\u{e9}"] {
        let batch = [row(slot, 1)];
        build_rejects(&batch, invalid_slot(slot));
        decode_rejects(&wire(&batch), invalid_slot(slot));
    }
    let overlong = "a".repeat(65);
    build_rejects(&[row(&overlong, 1)], invalid_slot(&overlong));
    // A decoder reports only the first 64 bytes of an over-long slot.
    decode_rejects(&wire(&[row(&overlong, 1)]), invalid_slot(&overlong[..64]));
    let truncated = [head(4, 6), head(3, 200), b"abc".to_vec()].concat();
    decode_rejects(&roster_cbor(&[truncated]), invalid_slot("abc"));
    let invalid_utf8 = [head(3, 1), vec![0xff]].concat();
    field_rejects(1, invalid_utf8, INVALID);
}

#[test]
fn slot_boundaries_accept_64_and_every_grammar_class() -> TestResult {
    assert_roundtrip(&[row(&"a".repeat(64), 1)])?;
    assert_roundtrip(&[row("A-z_0.9", 1)])?;
    assert_roundtrip(&[row("0", 1)])
}

#[test]
fn name_boundaries_accept_128_and_reject_129_bytes() -> TestResult {
    assert_roundtrip(&[named("n".repeat(128))])?;
    assert_roundtrip(&[named("\u{e9}".repeat(64))])?;
    for name in ["n".repeat(129), "\u{e9}".repeat(65), String::new()] {
        let batch = [named(name)];
        build_rejects(&batch, invalid_field("a", Field::PluginName));
        decode_rejects(&wire(&batch), invalid_field("a", Field::PluginName));
    }
    Ok(())
}

#[test]
fn version_boundaries_accept_64_and_reject_65_bytes() -> TestResult {
    assert_roundtrip(&[versioned("v".repeat(64))])?;
    for version in ["v".repeat(65), String::new()] {
        let batch = [versioned(version)];
        build_rejects(&batch, invalid_field("a", Field::PluginVersion));
        decode_rejects(&wire(&batch), invalid_field("a", Field::PluginVersion));
    }
    Ok(())
}

#[test]
fn zero_digest_rejects_and_a_nonzero_digest_is_accepted() -> TestResult {
    let zero = [digested(0)];
    build_rejects(&zero, invalid_field("a", Field::Eop1Digest));
    decode_rejects(&wire(&zero), invalid_field("a", Field::Eop1Digest));
    assert_roundtrip(&[digested(1)])
}

#[test]
fn closure_bound_matches_the_native_opc1_maximum() -> TestResult {
    assert_eq!(MAX_MANIFEST_PLUGIN_CLOSURE_BYTES_V1, CLOSURE_LIMIT_BYTES);
    assert_roundtrip(&[closed("a", 1, vec![0xab; CLOSURE_LIMIT_BYTES])])?;
    let over = closed("a", 1, vec![0xab; CLOSURE_LIMIT_BYTES + 1]);
    build_rejects(&[over], invalid_field("a", Field::ClosureBytes));
    assert_roundtrip(&[closed("a", 1, Vec::new())])
}

#[test]
fn declared_closure_length_is_checked_before_any_bytes_are_read() {
    let too_big = invalid_field("a", Field::ClosureBytes);
    field_rejects(6, head(2, CLOSURE_LIMIT + 1), too_big.clone());
    field_rejects(6, head(2, u64::MAX), too_big);
    field_rejects(6, head(2, CLOSURE_LIMIT), INVALID);
}

#[test]
fn entry_count_above_256_rejects_before_any_entry_is_read() {
    build_rejects(&numbered_rows(257), TOO_LARGE);
    let declared = shell(magic(), head(4, 257));
    decode_rejects(&declared, TOO_LARGE);
    let huge = shell(magic(), wide_head(4, u64::MAX, 8));
    decode_rejects(&huge, TOO_LARGE);
    let absent = shell(magic(), head(4, 256));
    decode_rejects(&absent, INVALID);
}

#[test]
fn checked_size_logic_enforces_the_fixed_one_gibibyte_cap() {
    let cap = MAX_MANIFEST_PLUGIN_ROSTER_BYTES_V1;
    assert_eq!(cap, 1_073_741_824);
    assert_eq!(checked_manifest_plugin_roster_size_v1(5, 7), Ok(12));
    assert_eq!(checked_manifest_plugin_roster_size_v1(0, cap), Ok(cap));
    assert_eq!(checked_manifest_plugin_roster_size_v1(cap, 0), Ok(cap));
    assert_eq!(checked_manifest_plugin_roster_size_v1(cap - 1, 1), Ok(cap));
    let over = Err(TOO_LARGE);
    assert_eq!(checked_manifest_plugin_roster_size_v1(0, cap + 1), over);
    assert_eq!(checked_manifest_plugin_roster_size_v1(cap, 1), over);
    assert_eq!(checked_manifest_plugin_roster_size_v1(usize::MAX, 1), over);
}

fn shared_entry(index: u16, closure: &Arc<[u8]>) -> Result<ManifestPluginEntryV1, RosterError> {
    ManifestPluginEntryV1::new(
        format!("s{index:03}"),
        plugin(index),
        "n".to_owned(),
        "1".to_owned(),
        hash(1),
        Arc::clone(closure),
    )
}

// Entries share one maximum-size closure, so no gibibyte is ever allocated.
// The last entry's closure length tunes the checked total to the exact cap.
fn shared_closure_roster(
    shared: u16,
    tail_closure: usize,
) -> Result<ManifestPluginRosterV1, RosterError> {
    let closure: Arc<[u8]> = Arc::from(vec![0_u8; CLOSURE_LIMIT_BYTES]);
    let mut entries = Vec::new();
    for index in 1..=shared {
        entries.push(shared_entry(index, &closure)?);
    }
    let tail: Arc<[u8]> = Arc::from(vec![0_u8; tail_closure]);
    entries.push(shared_entry(shared + 1, &tail)?);
    ManifestPluginRosterV1::new(entries)
}

#[test]
fn aggregate_cap_accepts_the_exact_cap_and_rejects_one_byte_more() -> TestResult {
    // 15 roster framing bytes, 199 maximum-closure entries of 5_374_610
    // checked bytes each, and a 94-byte-framed final entry fill the cap.
    let exact = shared_closure_roster(199, 4_194_325)?;
    assert_eq!(exact.entries().len(), 200);
    let rejected = shared_closure_roster(199, 4_194_326).err();
    assert_eq!(rejected, Some(TOO_LARGE));
    let full = shared_closure_roster(199, CLOSURE_LIMIT_BYTES).err();
    assert_eq!(full, Some(TOO_LARGE));
    Ok(())
}

#[test]
fn truncated_extended_and_trailing_inputs_reject() {
    let bytes = wire(&[row("a", 1), row("b", 2)]);
    for cut in 0..bytes.len() {
        decode_rejects(&bytes[..cut], INVALID);
    }
    let trailing = [bytes.clone(), vec![0x00]].concat();
    decode_rejects(&trailing, INVALID);
    let extra_entry = [bytes, row("c", 3).cbor()].concat();
    decode_rejects(&extra_entry, INVALID);
    let empty_trailing = [shell(magic(), head(4, 0)), vec![0x80]].concat();
    decode_rejects(&empty_trailing, INVALID);
}

#[test]
fn non_preferred_roster_heads_are_noncanonical() {
    let outer = [wide_head(4, 2, 1), magic(), head(4, 0)].concat();
    decode_rejects(&outer, NONCANONICAL);
    let wide_magic = [wide_head(2, 4, 1), b"MPR1".to_vec()].concat();
    decode_rejects(&shell(wide_magic, head(4, 0)), NONCANONICAL);
    let wide_count = shell(magic(), wide_head(4, 0, 1));
    decode_rejects(&wide_count, NONCANONICAL);
    let widest_count = shell(magic(), wide_head(4, 0, 8));
    decode_rejects(&widest_count, NONCANONICAL);
    let header = shell(magic(), wide_head(4, 1, 2));
    let padded = [header, row("a", 1).cbor()].concat();
    decode_rejects(&padded, NONCANONICAL);
}

#[test]
fn non_preferred_entry_forms_are_noncanonical() {
    let slot = [wide_head(3, 1, 1), b"a".to_vec()].concat();
    let plugin_id = [wide_head(2, 16, 1), id_bytes(1).to_vec()].concat();
    let name = [wide_head(3, 4, 2), b"plug".to_vec()].concat();
    let version = [wide_head(3, 3, 4), b"1.0".to_vec()].concat();
    let digest = [wide_head(2, 32, 8), vec![7; 32]].concat();
    let closure = [wide_head(2, 7, 1), b"closure".to_vec()].concat();
    field_rejects(0, wide_head(4, 6, 1), NONCANONICAL);
    field_rejects(1, slot, NONCANONICAL);
    field_rejects(2, plugin_id, NONCANONICAL);
    field_rejects(3, name, NONCANONICAL);
    field_rejects(4, version, NONCANONICAL);
    field_rejects(5, digest, NONCANONICAL);
    field_rejects(6, closure, NONCANONICAL);
}

#[test]
fn indefinite_tagged_and_map_roster_items_reject() {
    let indefinite_outer = [vec![0x9f], magic(), head(4, 0), vec![0xff]].concat();
    decode_rejects(&indefinite_outer, INVALID);
    let indefinite_list = shell(magic(), vec![0x9f, 0xff]);
    decode_rejects(&indefinite_list, INVALID);
    let tagged_outer = [vec![0xc0], shell(magic(), head(4, 0))].concat();
    decode_rejects(&tagged_outer, INVALID);
    let map_outer = [vec![0xa2], magic(), head(4, 0)].concat();
    decode_rejects(&map_outer, INVALID);
    let map_list = shell(magic(), vec![0xa0]);
    decode_rejects(&map_list, INVALID);
}

#[test]
fn indefinite_tagged_map_and_float_entry_items_reject() {
    field_rejects(0, vec![0x9f], INVALID);
    field_rejects(0, vec![0xa6], INVALID);
    field_rejects(0, vec![0x9c], INVALID);
    field_rejects(1, vec![0x7f, 0x61, 0x61, 0xff], INVALID);
    field_rejects(6, vec![0x5f, 0x41, 0x00, 0xff], INVALID);
    field_rejects(1, [vec![0xc0], tstr("a")].concat(), INVALID);
    field_rejects(4, vec![0xfa, 0x3f, 0x80, 0x00, 0x00], INVALID);
}

#[test]
fn wrong_types_lengths_and_encodings_reject() {
    decode_rejects(&[], INVALID);
    field_rejects(1, bstr(b"a"), INVALID);
    field_rejects(2, bstr(&[1; 15]), INVALID);
    field_rejects(2, bstr(&[1; 17]), INVALID);
    field_rejects(2, tstr("sixteen-bytes-id"), INVALID);
    field_rejects(5, bstr(&[7; 31]), INVALID);
    field_rejects(5, bstr(&[7; 33]), INVALID);
    field_rejects(6, tstr("closure"), INVALID);
    field_rejects(3, [head(3, 1), vec![0xff]].concat(), INVALID);
}

#[test]
fn wrong_magic_rejects_as_unsupported() {
    let candidates: [&[u8]; 5] = [b"MPR2", b"MPR", b"MPR1x", b"mpr1", b""];
    for candidate in candidates {
        let bytes = shell(bstr(candidate), head(4, 0));
        decode_rejects(&bytes, BAD_MAGIC);
    }
    let text_magic = shell(tstr("MPR1"), head(4, 0));
    decode_rejects(&text_magic, INVALID);
    let truncated = shell([head(2, 4), b"MP".to_vec()].concat(), head(4, 0));
    decode_rejects(&truncated, INVALID);
}

#[test]
fn wrong_field_counts_reject() {
    let one_field = [head(4, 1), magic()].concat();
    decode_rejects(&one_field, INVALID);
    let three_fields = [head(4, 3), magic(), head(4, 0), head(0, 0)].concat();
    decode_rejects(&three_fields, INVALID);
    let mut five = row("a", 1).fields();
    five[0] = head(4, 5);
    let five_fields = roster_cbor(&[five[..6].concat()]);
    decode_rejects(&five_fields, INVALID);
    let mut seven = row("a", 1).fields();
    seven[0] = head(4, 7);
    let seven_fields = roster_cbor(&[[seven.concat(), head(0, 0)].concat()]);
    decode_rejects(&seven_fields, INVALID);
}

fn message(error: &RosterError, expected: &str) {
    assert_eq!(error.to_string(), expected);
}

#[test]
fn unit_error_messages_are_stable_and_actionable() {
    message(
        &INVALID,
        "invalid MPR1 encoding: expected one definite-length CBOR roster \
         [h'4d505231', [entry, ...]] of six-field entries with no tags, maps, floats or \
         trailing bytes",
    );
    message(
        &NONCANONICAL,
        "noncanonical MPR1 encoding: use shortest-form integers and lengths, or re-encode \
         with to_canonical_cbor",
    );
    message(
        &TOO_LARGE,
        "MPR1 roster too large: use at most 256 entries and at most 1073741824 bytes",
    );
    message(
        &BAD_MAGIC,
        "unsupported MPR1 magic: the roster must start with the 4-byte string MPR1",
    );
}

#[test]
fn slot_error_messages_name_the_slot_and_the_rule() {
    message(
        &invalid_slot("Foo Bar"),
        "invalid slot `Foo Bar`: use 1-64 ASCII bytes from A-Z a-z 0-9 . _ - (no spaces or \
         other characters)",
    );
    message(
        &invalid_slot("a\nb"),
        "invalid slot `a\\nb`: use 1-64 ASCII bytes from A-Z a-z 0-9 . _ - (no spaces or \
         other characters)",
    );
    message(
        &duplicate_slot("alpha"),
        "duplicate slot `alpha`: give every entry a unique stable slot",
    );
    message(
        &duplicate_id("beta"),
        "duplicate PluginId at slot `beta`: give every entry a distinct PluginId",
    );
    message(
        &unsorted("alpha"),
        "slot `alpha` is out of order: MPR1 requires strictly ascending raw-byte slot order \
         (ManifestPluginRosterV1::new sorts for you)",
    );
}

#[test]
fn field_error_messages_state_the_limit() {
    message(
        &invalid_field("a", Field::PluginName),
        "slot `a`: plugin_name must be 1-128 UTF-8 bytes",
    );
    message(
        &invalid_field("a", Field::PluginVersion),
        "slot `a`: plugin_version must be 1-64 UTF-8 bytes",
    );
    message(
        &invalid_field("a", Field::Eop1Digest),
        "slot `a`: eop1_digest must not be all zero",
    );
    message(
        &invalid_field("a", Field::ClosureBytes),
        "slot `a`: closure_bytes must be at most 5374516 bytes (the native OPC1 maximum)",
    );
}

fn rejection_text(batch: &[Row]) -> String {
    let bad = build(batch).err();
    bad.as_ref().map_or_else(String::new, ToString::to_string)
}

#[test]
fn rejections_from_the_public_api_carry_the_actionable_text() {
    let prefix = "invalid slot `Foo Bar`: use 1-64 ASCII bytes";
    assert!(rejection_text(&[row("Foo Bar", 1)]).starts_with(prefix));
    let expected = "duplicate slot `a`: give every entry a unique stable slot";
    assert_eq!(rejection_text(&[row("a", 1), row("a", 2)]), expected);
}

#[test]
fn diagnostics_never_echo_closure_bytes() -> TestResult {
    let duplicate = [
        closed("a", 1, SECRET.to_vec()),
        closed("a", 2, SECRET.to_vec()),
    ];
    let error = build(&duplicate).err().ok_or("expected a rejection")?;
    assert!(!error.to_string().contains("SECRET"));
    assert!(!format!("{error:?}").contains("SECRET"));
    let roster = build(&[closed("a", 1, SECRET.to_vec())])?;
    let rendered = format!("{roster:?} {:?}", roster.entries());
    assert!(!rendered.contains("SECRET"));
    assert!(!rendered.contains("83, 69, 67"));
    assert!(rendered.contains("closure_len: 20"));
    Ok(())
}

#[test]
fn documented_usage_flow_round_trips_two_same_name_plugins() -> TestResult {
    let second = ManifestPluginEntryV1::new(
        "sensor.b",
        plugin(2),
        "Sensor",
        "1.0.0",
        hash(2),
        vec![2_u8],
    )?;
    let first = ManifestPluginEntryV1::new(
        "sensor.a",
        plugin(1),
        "Sensor",
        "1.0.0",
        hash(1),
        vec![1_u8],
    )?;
    let roster = ManifestPluginRosterV1::new(vec![second, first])?;
    assert_eq!(slots_of(&roster), ["sensor.a", "sensor.b"]);
    let bytes = roster.to_canonical_cbor();
    assert_eq!(decode(&bytes)?, roster);
    Ok(())
}
