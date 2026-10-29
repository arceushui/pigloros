//! Public tests of the independent `metric_profile` recomputation (ADR-062 Revision 7 slice 2).
//!
//! Every fixture test reads the committed `metric-conformance` fixtures: the family payload
//! names each sub-case and its member digest, the `MCS1` composite carries the member bytes, and
//! the oracle carries the expected `MTR1`/`MQR1` bytes or the closed failure. The remaining tests
//! build inputs in-test to pin the decoder, the precedence and the arithmetic bounds.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::PathBuf;

use ciborium::value::Value;
use pos_reference::metric_profile::{
    accept_result_v1, quantize_probability_v1, recompute_quantization_v1, recompute_result_v1,
    MetricErrorV1, MetricFailure, ALGORITHM_ID, MAX_NESTING_DEPTH, MAX_QUANTIZATION_PATTERNS,
    MAX_RECORDS,
};
use serde_json::Value as Json;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const INPUT_DOMAIN: &[u8] = b"PiglorOS.MetricInput.v1\0";

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance")
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn json(path: &str) -> TestResult<Json> {
    let bytes = std::fs::read(fixtures().join(path))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn text<'a>(value: &'a Json, key: &str) -> TestResult<&'a str> {
    Ok(value.get(key).and_then(Json::as_str).ok_or(key)?)
}

fn list<'a>(value: &'a Json, key: &str) -> TestResult<&'a Vec<Json>> {
    Ok(value.get(key).and_then(Json::as_array).ok_or(key)?)
}

/// The members of one family's `MCS1` composite, by BLAKE3 hex digest.
fn members(family: &str) -> TestResult<BTreeMap<String, Vec<u8>>> {
    let bytes = std::fs::read(fixtures().join(format!("inputs/metric-conformance/{family}.mcs1")))?;
    let value: Value = ciborium::de::from_reader(bytes.as_slice())?;
    let fields = value.as_array().ok_or("MCS1 is not an array")?;
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].as_text(), Some("MCS1"));
    let mut members = BTreeMap::new();
    for entry in fields[2].as_array().ok_or("MCS1 members")? {
        let pair = entry.as_array().ok_or("MCS1 member pair")?;
        let digest = pair[0].as_bytes().ok_or("member digest")?;
        let member = pair[1].as_bytes().ok_or("member bytes")?;
        assert_eq!(hex(blake3::hash(member).as_bytes()), hex(digest));
        members.insert(hex(digest), member.clone());
    }
    Ok(members)
}

/// One sub-case of a family payload with its member bytes.
struct SubCase {
    id: String,
    record: String,
    member: Vec<u8>,
    expect: Json,
}

fn subcases(family: &str) -> TestResult<Vec<SubCase>> {
    let payload = json(&format!("inputs/metric-conformance/{family}.json"))?;
    assert_eq!(
        text(&payload, "schema")?,
        "pigloros.metric-conformance.case.v2"
    );
    let members = members(family)?;
    let mut found = Vec::new();
    for subcase in list(&payload, "subcases")? {
        let Some(member) = subcase.get("member") else {
            continue;
        };
        let bytes = members
            .get(text(member, "blake3")?)
            .ok_or("sub-case member missing from MCS1")?;
        assert_eq!(
            member.get("bytes").and_then(Json::as_u64),
            u64::try_from(bytes.len()).ok()
        );
        found.push(SubCase {
            id: text(subcase, "id")?.to_owned(),
            record: text(member, "record")?.to_owned(),
            member: bytes.clone(),
            expect: subcase.get("expect").cloned().ok_or("expect")?,
        });
    }
    Ok(found)
}

/// The canonical-output oracle entries of a family, by sub-case id.
fn output_oracle(family: &str) -> TestResult<BTreeMap<String, Json>> {
    let oracle = json(&format!("oracles/metric-conformance/{family}.json"))?;
    let output = oracle.get("output").ok_or("canonical output")?;
    let mut entries = BTreeMap::new();
    for entry in list(output, "subcases")? {
        entries.insert(text(entry, "id")?.to_owned(), entry.clone());
    }
    Ok(entries)
}

/// The failure oracle entries of a family, by sub-case id.
fn failure_oracle(family: &str) -> TestResult<BTreeMap<String, Json>> {
    let oracle = json(&format!("oracles/metric-conformance/{family}.json"))?;
    let mut entries = BTreeMap::new();
    for entry in list(&oracle, "subcases")? {
        entries.insert(text(entry, "id")?.to_owned(), entry.clone());
    }
    Ok(entries)
}

fn expect_oracle_failure(found: &MetricFailure, oracle: &Json) -> TestResult {
    assert_eq!(format!("{:?}", found.error), text(oracle, "error")?);
    assert_eq!(
        Some(u64::from(found.error.code())),
        oracle.get("code").and_then(Json::as_u64)
    );
    assert_eq!(found.first_coordinate, text(oracle, "first_coordinate")?);
    Ok(())
}

fn rejected(result: Result<Vec<u8>, MetricFailure>) -> TestResult<MetricFailure> {
    Ok(result.err().ok_or("the input was accepted")?)
}

/// The accepted bytes; the failure, if any, is reported by the assertion.
fn accepted(result: Result<Vec<u8>, MetricFailure>) -> TestResult<Vec<u8>> {
    assert_eq!(result.as_ref().err(), None);
    Ok(result.ok().ok_or("the input was rejected")?)
}

fn failure(error: MetricErrorV1, coordinate: &str) -> MetricFailure {
    MetricFailure {
        error,
        first_coordinate: coordinate.to_owned(),
    }
}

#[test]
fn ind1_recomputes_every_positive_and_deletion_redaction_oracle() -> TestResult {
    let mut recomputed = Vec::new();
    for family in ["positive", "deletion-redaction", "independent-evaluation"] {
        let oracle = output_oracle(family)?;
        for subcase in subcases(family)? {
            if subcase.record != "MTI1" {
                continue;
            }
            let entry = oracle.get(&subcase.id).ok_or("oracle entry")?;
            let result = recompute_result_v1(&subcase.member);
            assert_eq!(result.as_ref().err(), None, "{}", subcase.id);
            let result = accepted(result)?;
            assert_eq!(hex(&result), text(entry, "hex")?, "{}", subcase.id);
            let digest = hex(blake3::hash(&result).as_bytes());
            assert_eq!(digest, text(entry, "blake3")?, "{}", subcase.id);
            assert_eq!(digest, text(&subcase.expect, "blake3")?, "{}", subcase.id);
            expect_result_digests(
                &subcase.member,
                &result,
                entry.get("values").ok_or("values")?,
            )?;
            assert_eq!(accept_result_v1(&result), Ok(()), "{}", subcase.id);
            recomputed.push(subcase.id);
        }
    }
    let expected = [
        "pos.1", "pos.2", "pos.3a", "pos.3b", "pos.3c", "pos.3d", "pos.3e", "pos.4", "pos.5",
        "pos.6a", "pos.6b", "pos.8a", "pos.8b", "pos.8c", "del.1a", "del.1b", "del.2", "del.3",
        "ind.1",
    ];
    assert_eq!(recomputed, expected);
    Ok(())
}

/// The input digest is bound to the member bytes and the result digest to fields 0 to 11.
fn expect_result_digests(member: &[u8], result: &[u8], values: &Json) -> TestResult {
    let decoded: Value = ciborium::de::from_reader(result)?;
    let fields = decoded.as_array().ok_or("MTR1 array")?;
    assert_eq!(fields.len(), 13);
    let input_digest = hex(fields[5].as_bytes().ok_or("input digest")?);
    let mut domain_input = INPUT_DOMAIN.to_vec();
    domain_input.extend_from_slice(member);
    assert_eq!(input_digest, hex(blake3::hash(&domain_input).as_bytes()));
    assert_eq!(input_digest, text(values, "input_digest")?);
    let result_digest = hex(fields[12].as_bytes().ok_or("result digest")?);
    assert_eq!(result_digest, text(values, "result_digest")?);
    Ok(())
}

#[test]
fn del3_canary_identifier_never_appears_in_the_result() -> TestResult {
    let canary = b"synthetic-secret-canary-del3";
    let subcase = subcases("deletion-redaction")?
        .into_iter()
        .find(|subcase| subcase.id == "del.3")
        .ok_or("del.3")?;
    assert!(subcase
        .member
        .windows(canary.len())
        .any(|window| window == canary));
    let result = accepted(recompute_result_v1(&subcase.member))?;
    assert!(!result.windows(canary.len()).any(|window| window == canary));
    Ok(())
}

#[test]
fn ind3_recomputes_the_quantization_vectors_from_bit_patterns() -> TestResult {
    let mut recomputed = Vec::new();
    for family in ["positive", "independent-evaluation"] {
        let oracle = output_oracle(family)?;
        for subcase in subcases(family)? {
            if subcase.record != "MTQ1" {
                continue;
            }
            let entry = oracle.get(&subcase.id).ok_or("oracle entry")?;
            let result = accepted(recompute_quantization_v1(&subcase.member))?;
            assert_eq!(hex(&result), text(entry, "hex")?, "{}", subcase.id);
            assert_eq!(
                hex(blake3::hash(&result).as_bytes()),
                text(&subcase.expect, "blake3")?
            );
            recomputed.push(subcase.id);
        }
    }
    assert_eq!(recomputed, ["pos.7", "ind.3"]);
    Ok(())
}

#[test]
fn quantizer_matches_the_normative_vectors_without_clamping() {
    let invalid = Err(MetricErrorV1::InvalidProbability);
    let vectors = [
        (0.0_f64.to_bits(), Ok(0)),
        ((-0.0_f64).to_bits(), Ok(0)),
        (1.0_f64.to_bits(), Ok(1_000_000)),
        (0.1_f64.to_bits(), Ok(100_000)),
        (0.15_f64.to_bits(), Ok(150_000)),
        (0.007_812_5_f64.to_bits(), Ok(7_812)),
        (0.023_437_5_f64.to_bits(), Ok(23_438)),
        (1, Ok(0)),
        (0x3EA0_C6F7_A0B5_ED8D, Ok(0)),
        (1.000_001_f64.to_bits(), invalid),
        (f64::NAN.to_bits(), invalid),
        (f64::INFINITY.to_bits(), invalid),
        (f64::NEG_INFINITY.to_bits(), invalid),
        ((-0.5_f64).to_bits(), invalid),
        (0x8000_0000_0000_0001, invalid),
    ];
    for (bits, expected) in vectors {
        assert_eq!(quantize_probability_v1(bits), expected, "{bits:#018x}");
    }
}

#[test]
fn malformed_subcases_give_the_oracle_error_and_first_coordinate() -> TestResult {
    let oracle = failure_oracle("malformed")?;
    let mut checked = 0;
    for subcase in subcases("malformed")? {
        let entry = oracle.get(&subcase.id).ok_or("oracle entry")?;
        assert_eq!(text(entry, "kind")?, "metric-error");
        let found = rejected(recompute_result_v1(&subcase.member))?;
        expect_oracle_failure(&found, entry)?;
        expect_oracle_failure(&found, &subcase.expect)?;
        checked += 1;
    }
    assert_eq!(checked, oracle.len());
    for prefix in (1..=13).map(|case| format!("mal.{case}")) {
        assert!(
            oracle
                .keys()
                .any(|id| id.trim_end_matches(char::is_alphabetic) == prefix),
            "{prefix}"
        );
    }
    Ok(())
}

#[test]
fn res1_declared_record_count_above_the_bound_is_resource_limit() -> TestResult {
    let oracle = failure_oracle("resource-exhaustion")?;
    let subcase = subcases("resource-exhaustion")?
        .into_iter()
        .find(|subcase| subcase.id == "res.1")
        .ok_or("res.1")?;
    let found = rejected(recompute_result_v1(&subcase.member))?;
    expect_oracle_failure(&found, oracle.get("res.1").ok_or("res.1 oracle")?)?;
    assert_eq!(found, failure(MetricErrorV1::ResourceLimit, "record_count"));
    Ok(())
}

#[test]
fn dgr1_and_dgr3_are_refused_with_no_fallback() -> TestResult {
    let oracle = failure_oracle("downgrade")?;
    let cases = subcases("downgrade")?;
    let dgr1 = cases
        .iter()
        .find(|subcase| subcase.id == "dgr.1")
        .ok_or("dgr.1")?;
    let found = rejected(recompute_result_v1(&dgr1.member))?;
    expect_oracle_failure(&found, oracle.get("dgr.1").ok_or("dgr.1 oracle")?)?;
    let dgr3 = cases
        .iter()
        .find(|subcase| subcase.id == "dgr.3")
        .ok_or("dgr.3")?;
    assert_eq!(dgr3.record, "MTR1");
    let refused = accept_result_v1(&dgr3.member)
        .err()
        .ok_or("a foreign-major MTR1 was accepted")?;
    expect_oracle_failure(&refused, oracle.get("dgr.3").ok_or("dgr.3 oracle")?)?;
    // An MTR1 is never read as an input either.
    let as_input = rejected(recompute_result_v1(&dgr3.member))?;
    assert_eq!(as_input, failure(MetricErrorV1::InvalidEncoding, "input"));
    Ok(())
}

// --- In-test encoder ---

#[derive(Clone, Debug)]
enum Cbor {
    Unsigned(u64),
    Negative(u64),
    Text(Vec<u8>),
    Bytes(Vec<u8>),
    Array(Vec<Self>),
    Bool(bool),
    Null,
    /// Bytes written verbatim, for non-canonical forms.
    Raw(Vec<u8>),
}

fn head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let bytes = argument.to_be_bytes();
    let (info, width) = match argument {
        0..=23 => (bytes[7], 0),
        24..=0xff => (24, 1),
        0x100..=0xffff => (25, 2),
        0x1_0000..=0xffff_ffff => (26, 4),
        _ => (27, 8),
    };
    out.push((major << 5) | info);
    out.extend_from_slice(&bytes[8 - width..]);
}

fn length(items: usize) -> u64 {
    u64::try_from(items).unwrap_or(u64::MAX)
}

fn encode_into(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::Unsigned(number) => head(out, 0, *number),
        Cbor::Negative(number) => head(out, 1, *number),
        Cbor::Text(content) => {
            head(out, 3, length(content.len()));
            out.extend_from_slice(content);
        }
        Cbor::Bytes(content) => {
            head(out, 2, length(content.len()));
            out.extend_from_slice(content);
        }
        Cbor::Array(items) => {
            head(out, 4, length(items.len()));
            for item in items {
                encode_into(item, out);
            }
        }
        Cbor::Bool(flag) => out.push(if *flag { 0xf5 } else { 0xf4 }),
        Cbor::Null => out.push(0xf6),
        Cbor::Raw(bytes) => out.extend_from_slice(bytes),
    }
}

fn encode(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

fn tstr(text: &str) -> Cbor {
    Cbor::Text(text.as_bytes().to_vec())
}

fn record(prediction: &str, entity: &str, micros: u64, state: u64, outcome: Option<u64>) -> Cbor {
    Cbor::Array(vec![
        tstr(prediction),
        tstr(entity),
        Cbor::Unsigned(micros),
        Cbor::Unsigned(state),
        outcome.map_or(Cbor::Null, Cbor::Unsigned),
        Cbor::Bool(false),
    ])
}

/// The eight `MTI1` fields with `record_count` equal to the number of records.
fn input_fields(minimum: u64, records: Vec<Cbor>) -> Vec<Cbor> {
    vec![
        tstr("MTI1"),
        Cbor::Unsigned(1),
        tstr(ALGORITHM_ID),
        Cbor::Unsigned(1),
        Cbor::Unsigned(0),
        Cbor::Unsigned(minimum),
        Cbor::Unsigned(length(records.len())),
        Cbor::Array(records),
    ]
}

/// A valid two-record input: `a` positive at 0.3 and `b` negative at 0.6, one entity.
fn base_fields() -> Vec<Cbor> {
    input_fields(
        1,
        vec![
            record("a", "e", 300_000, 0, Some(1)),
            record("b", "e", 600_000, 0, Some(0)),
        ],
    )
}

fn with_field(index: usize, value: Cbor) -> Vec<u8> {
    let mut fields = base_fields();
    fields[index] = value;
    encode(&Cbor::Array(fields))
}

fn with_record_field(record_index: usize, field: usize, value: Cbor) -> Vec<u8> {
    let mut fields = base_fields();
    if let Cbor::Array(records) = &mut fields[7] {
        if let Cbor::Array(record) = &mut records[record_index] {
            record[field] = value;
        }
    }
    encode(&Cbor::Array(fields))
}

fn expect_failure(input: &[u8], error: MetricErrorV1, coordinate: &str) -> TestResult {
    let found = rejected(recompute_result_v1(input))?;
    assert_eq!(found, failure(error, coordinate), "{}", hex(input));
    Ok(())
}

fn nested(levels: usize, leaf: Cbor) -> Cbor {
    (0..levels).fold(leaf, |inner, _| Cbor::Array(vec![inner]))
}

// --- Decoder, precedence and bounds ---

#[test]
fn the_base_input_is_valid_and_every_truncated_prefix_is_invalid_encoding() -> TestResult {
    let input = encode(&Cbor::Array(base_fields()));
    accepted(recompute_result_v1(&input))?;
    for end in 0..input.len() {
        let found = rejected(recompute_result_v1(&input[..end]))?;
        assert_eq!(found.error, MetricErrorV1::InvalidEncoding, "prefix {end}");
    }
    let mut trailing = input;
    trailing.push(0xf6);
    expect_failure(&trailing, MetricErrorV1::InvalidEncoding, "trailing")
}

#[test]
fn structural_defects_are_invalid_encoding_at_their_coordinate() -> TestResult {
    let invalid = MetricErrorV1::InvalidEncoding;
    expect_failure(&encode(&tstr("MTI1")), invalid, "input")?;
    let mut seven = base_fields();
    seven.pop();
    expect_failure(&encode(&Cbor::Array(seven)), invalid, "input")?;
    expect_failure(&with_field(7, tstr("records")), invalid, "records")?;
    let short_record = Cbor::Array(vec![tstr("a"), tstr("e")]);
    let records = Cbor::Array(vec![record("a", "e", 1, 1, None), short_record]);
    expect_failure(&with_field(7, records), invalid, "records/1")?;
    // A map, a tag, a float and the undefined or one-byte simple values.
    for raw in [
        vec![0xa0],
        vec![0xc1, 0x00],
        vec![0xf9, 0x3c, 0x00],
        vec![0xf7],
        vec![0xf8, 0x20],
    ] {
        expect_failure(
            &with_record_field(0, 2, Cbor::Raw(raw)),
            invalid,
            "records/0/2",
        )?;
    }
    // Non-preferred one-, two- and four-byte heads, and a reserved additional information.
    for raw in [
        vec![0x18, 0x05],
        vec![0x19, 0x00, 0xff],
        vec![0x1a, 0x00, 0x00, 0xff, 0xff],
        vec![0x1c],
    ] {
        expect_failure(
            &with_record_field(1, 2, Cbor::Raw(raw)),
            invalid,
            "records/1/2",
        )?;
    }
    // A text whose declared length cannot fit the input.
    let huge = Cbor::Raw(vec![0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    expect_failure(&with_record_field(0, 0, huge), invalid, "records/0/0")?;
    // A structural defect inside a nested array carries the nested path.
    let inner = Cbor::Array(vec![Cbor::Unsigned(1), Cbor::Raw(vec![0xa0])]);
    expect_failure(&with_record_field(0, 2, inner), invalid, "records/0/2/1")
}

#[test]
fn nested_arrays_are_walked_up_to_the_depth_cap() -> TestResult {
    let invalid = MetricErrorV1::InvalidEncoding;
    // A record field is level 4; nesting to the cap is well formed but the wrong type.
    let deepest = nested(MAX_NESTING_DEPTH - 3, Cbor::Unsigned(1));
    expect_failure(&with_record_field(0, 2, deepest), invalid, "records/0/2")?;
    // A defect after the deep field still ranks first, because it is structural.
    let deepest = nested(MAX_NESTING_DEPTH - 3, Cbor::Unsigned(1));
    let mut fields = base_fields();
    if let Cbor::Array(records) = &mut fields[7] {
        if let Cbor::Array(first) = &mut records[0] {
            first[2] = deepest;
        }
        if let Cbor::Array(second) = &mut records[1] {
            second[2] = Cbor::Raw(vec![0xf9, 0x00, 0x00]);
        }
    }
    expect_failure(&encode(&Cbor::Array(fields)), invalid, "records/1/2")?;
    // One level deeper than the cap is rejected at the array that exceeds it.
    let too_deep = nested(MAX_NESTING_DEPTH - 2, Cbor::Unsigned(1));
    let coordinate = format!("records/0/2{}", "/0".repeat(MAX_NESTING_DEPTH - 3));
    expect_failure(&with_record_field(0, 2, too_deep), invalid, &coordinate)?;
    let header = nested(MAX_NESTING_DEPTH, Cbor::Null);
    let coordinate = format!("magic{}", "/0".repeat(MAX_NESTING_DEPTH - 1));
    expect_failure(&with_field(0, header), invalid, &coordinate)
}

#[test]
fn a_well_formed_field_of_the_wrong_type_is_invalid_encoding_at_that_field() -> TestResult {
    let invalid = MetricErrorV1::InvalidEncoding;
    let header = [
        (0, Cbor::Unsigned(1), "magic"),
        (1, tstr("1"), "version"),
        (
            2,
            Cbor::Bytes(ALGORITHM_ID.as_bytes().to_vec()),
            "algorithm_id",
        ),
        (3, Cbor::Negative(0), "algorithm_major"),
        (4, Cbor::Null, "binning"),
        (5, Cbor::Bool(true), "minimum_scored_records"),
        (6, Cbor::Array(vec![]), "record_count"),
    ];
    for (index, value, coordinate) in header {
        expect_failure(&with_field(index, value), invalid, coordinate)?;
    }
    let record = [
        (0, Cbor::Bytes(b"a".to_vec()), "records/0/0"),
        (1, Cbor::Unsigned(7), "records/0/1"),
        (2, Cbor::Negative(5), "records/0/2"),
        (3, tstr("0"), "records/0/3"),
        (4, Cbor::Bool(true), "records/0/4"),
        (5, Cbor::Unsigned(0), "records/0/5"),
    ];
    for (field, value, coordinate) in record {
        expect_failure(&with_record_field(0, field, value), invalid, coordinate)?;
    }
    // A wrong-type header field ranks after a structural defect in a record (G2).
    let mut fields = base_fields();
    fields[1] = tstr("1");
    if let Cbor::Array(records) = &mut fields[7] {
        if let Cbor::Array(second) = &mut records[1] {
            second[2] = Cbor::Raw(vec![0xa0]);
        }
    }
    expect_failure(&encode(&Cbor::Array(fields)), invalid, "records/1/2")
}

#[test]
fn record_semantics_follow_index_order() -> TestResult {
    let outcome = MetricErrorV1::InvalidOutcome;
    expect_failure(
        &with_record_field(1, 3, Cbor::Unsigned(4)),
        outcome,
        "records/1/3",
    )?;
    let pending = Cbor::Array(vec![
        tstr("c"),
        tstr("e"),
        Cbor::Unsigned(1),
        Cbor::Unsigned(2),
        Cbor::Null,
        Cbor::Bool(true),
    ]);
    let fields = input_fields(1, vec![record("a", "e", 1, 0, Some(0)), pending]);
    expect_failure(&encode(&Cbor::Array(fields)), outcome, "records/1/5")?;
    // A later failure in the same record or in a later record never displaces an earlier one.
    let fields = input_fields(
        1,
        vec![
            record("b", "e", 1, 0, Some(0)),
            record("", "e", 1_000_001, 0, Some(0)),
            record("a", "e", 1, 0, Some(0)),
        ],
    );
    expect_failure(
        &encode(&Cbor::Array(fields)),
        MetricErrorV1::InvalidIdentifier,
        "records/1/0",
    )?;
    let long = "x".repeat(65);
    expect_failure(
        &with_record_field(1, 1, tstr(&long)),
        MetricErrorV1::InvalidIdentifier,
        "records/1/1",
    )
}

#[test]
fn supplied_flags_are_counted_and_redacted_or_unavailable_records_are_excluded() -> TestResult {
    let mut supplied = record("a", "e", 300_000, 0, Some(1));
    if let Cbor::Array(fields) = &mut supplied {
        fields[5] = Cbor::Bool(true);
    }
    let records = vec![
        supplied,
        record("b", "e", 600_000, 0, Some(0)),
        record("c", "f", 100_000, 2, None),
        record("d", "g", 100_000, 3, None),
    ];
    let result = accepted(recompute_result_v1(&encode(&Cbor::Array(input_fields(
        1, records,
    )))))?;
    let decoded: Value = ciborium::de::from_reader(result.as_slice())?;
    let fields = decoded.as_array().ok_or("MTR1")?;
    let counts: Vec<u64> = fields[7]
        .as_array()
        .ok_or("counts")?
        .iter()
        .filter_map(|count| {
            count
                .as_integer()
                .and_then(|number| u64::try_from(number).ok())
        })
        .collect();
    assert_eq!(counts, [4, 2, 0, 1, 1, 1, 1]);
    assert_eq!(fields[9].as_integer(), Some(3.into()));
    Ok(())
}

/// One record per index with zero-padded, strictly ascending prediction ids.
fn bound_records(count: u64, entity: fn(u64) -> String, outcome: fn(u64) -> u64) -> Vec<Cbor> {
    (0..count)
        .map(|index| {
            record(
                &format!("{index:07}"),
                &entity(index),
                1_000_000,
                0,
                Some(outcome(index)),
            )
        })
        .collect()
}

fn computed_values(input: &[u8]) -> TestResult<(Vec<i128>, Vec<i128>, Vec<i128>)> {
    let result = accepted(recompute_result_v1(input))?;
    let decoded: Value = ciborium::de::from_reader(result.as_slice())?;
    let fields = decoded.as_array().ok_or("MTR1")?;
    let integers = |value: &Value| -> TestResult<Vec<i128>> {
        Ok(value
            .as_array()
            .ok_or("array")?
            .iter()
            .filter_map(|item| item.as_integer().map(i128::from))
            .collect())
    };
    let bins = fields[11].as_array().ok_or("bins")?;
    Ok((
        integers(&fields[7])?,
        integers(&fields[10])?,
        integers(&bins[9])?,
    ))
}

fn one_entity(_: u64) -> String {
    "e".to_owned()
}

fn own_entity(index: u64) -> String {
    format!("e{index}")
}

const fn never(_: u64) -> u64 {
    0
}

const fn alternate(index: u64) -> u64 {
    index % 2
}

#[test]
fn exactly_two_to_the_eighteen_records_compute_at_extreme_values() -> TestResult {
    let n = i128::from(MAX_RECORDS);
    let sum = n * 1_000_000;
    // Every prediction 1.0 against a negative outcome, one entity: the largest squared errors.
    let worst = encode(&Cbor::Array(input_fields(
        MAX_RECORDS,
        bound_records(MAX_RECORDS, one_entity, never),
    )));
    let (counts, metrics, last_bin) = computed_values(&worst)?;
    assert_eq!(counts, [n, n, 0, 0, 0, 0, 1]);
    assert_eq!(
        metrics,
        [1_000_000, 1_000_000, 1_000_000, 1_000_000, 0, 0, -1_000_000, 0, -1_000_000]
    );
    assert_eq!(last_bin, [n, sum, 0]);
    // Half positive in one entity of 2^18 records: the largest leave-one-out term.
    let half = encode(&Cbor::Array(input_fields(
        1,
        bound_records(MAX_RECORDS, one_entity, alternate),
    )));
    let (_, metrics, last_bin) = computed_values(&half)?;
    assert_eq!(
        metrics,
        [500_000, 500_000, 500_000, 500_000, 0, 250_000, -250_000, 250_002, -249_998]
    );
    assert_eq!(last_bin, [n, sum, n / 2]);
    // Half positive with 2^18 singleton entities.
    let singletons = encode(&Cbor::Array(input_fields(
        1,
        bound_records(MAX_RECORDS, own_entity, alternate),
    )));
    let (counts, metrics, _) = computed_values(&singletons)?;
    assert_eq!(counts[6], n);
    assert_eq!(
        metrics,
        [500_000, 500_000, 500_000, 500_000, 0, 250_000, -250_000, 500_000, 0]
    );
    Ok(())
}

#[test]
fn two_to_the_eighteen_plus_one_records_is_resource_limit() -> TestResult {
    let records = bound_records(MAX_RECORDS + 1, one_entity, never);
    let input = encode(&Cbor::Array(input_fields(1, records)));
    expect_failure(&input, MetricErrorV1::ResourceLimit, "record_count")?;
    // The bound is on the declared count, before the records are compared or read.
    let declared = with_field(6, Cbor::Unsigned(MAX_RECORDS + 1));
    expect_failure(&declared, MetricErrorV1::ResourceLimit, "record_count")?;
    let minimum = with_field(5, Cbor::Unsigned(MAX_RECORDS));
    let found = accepted(recompute_result_v1(&minimum))?;
    assert_eq!(accept_result_v1(&found), Ok(()));
    Ok(())
}

// --- MTQ1 and MTR1 records ---

fn quantization(magic: &str, version: u64, patterns: Cbor) -> Vec<u8> {
    encode(&Cbor::Array(vec![
        tstr(magic),
        Cbor::Unsigned(version),
        patterns,
    ]))
}

fn expect_quantization_failure(input: &[u8], error: MetricErrorV1, coordinate: &str) -> TestResult {
    let found = rejected(recompute_quantization_v1(input))?;
    assert_eq!(found, failure(error, coordinate));
    Ok(())
}

#[test]
fn quantization_inputs_are_strictly_decoded() -> TestResult {
    let one = || Cbor::Array(vec![Cbor::Unsigned(1.0_f64.to_bits())]);
    let valid = quantization("MTQ1", 1, one());
    assert_eq!(
        accepted(recompute_quantization_v1(&valid))?,
        [0x83, 0x64, b'M', b'Q', b'R', b'1', 0x01, 0x81, 0x1a, 0x00, 0x0f, 0x42, 0x40]
    );
    for end in 0..valid.len() {
        let found = rejected(recompute_quantization_v1(&valid[..end]))?;
        assert_eq!(found.error, MetricErrorV1::InvalidEncoding);
    }
    let version = MetricErrorV1::UnsupportedVersion;
    expect_quantization_failure(&quantization("MTQ2", 1, one()), version, "magic")?;
    expect_quantization_failure(&quantization("MTQ1", 2, one()), version, "version")?;
    let invalid = MetricErrorV1::InvalidEncoding;
    expect_quantization_failure(&quantization("MTQ1", 1, Cbor::Null), invalid, "patterns")?;
    expect_quantization_failure(
        &quantization("MTQ1", 1, Cbor::Array(vec![])),
        invalid,
        "patterns",
    )?;
    let typed = Cbor::Array(vec![tstr("0"), Cbor::Unsigned(0)]);
    expect_quantization_failure(&quantization("MTQ1", 1, typed), invalid, "patterns/0")?;
    let too_many = (0..=MAX_QUANTIZATION_PATTERNS)
        .map(Cbor::Unsigned)
        .collect();
    let limit = MetricErrorV1::ResourceLimit;
    expect_quantization_failure(
        &quantization("MTQ1", 1, Cbor::Array(too_many)),
        limit,
        "patterns",
    )?;
    let mut trailing = valid;
    trailing.push(0x00);
    expect_quantization_failure(&trailing, invalid, "trailing")?;
    expect_quantization_failure(&[0x82, 0x00, 0x00], invalid, "input")
}

fn foreign_result(index: usize, value: Value) -> TestResult<Vec<u8>> {
    let input = encode(&Cbor::Array(base_fields()));
    let result = accepted(recompute_result_v1(&input))?;
    let decoded: Value = ciborium::de::from_reader(result.as_slice())?;
    let mut fields = decoded.into_array().ok().ok_or("MTR1")?;
    fields[index] = value;
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&Value::Array(fields), &mut bytes)?;
    Ok(bytes)
}

#[test]
fn results_of_another_version_or_algorithm_are_not_accepted() -> TestResult {
    let version = MetricErrorV1::UnsupportedVersion;
    let algorithm = MetricErrorV1::UnsupportedAlgorithm;
    let cases = [
        (0, Value::Text("MTR2".into()), version, "magic"),
        (1, Value::Integer(2.into()), version, "version"),
        (
            2,
            Value::Text("pigloros.metric.other".into()),
            algorithm,
            "algorithm_id",
        ),
        (3, Value::Integer(2.into()), algorithm, "algorithm_major"),
        (
            1,
            Value::Text("1".into()),
            MetricErrorV1::InvalidEncoding,
            "version",
        ),
    ];
    for (index, value, error, coordinate) in cases {
        let found = accept_result_v1(&foreign_result(index, value)?).err();
        assert_eq!(found, Some(failure(error, coordinate)));
    }
    let valid = foreign_result(4, Value::Integer(0.into()))?;
    assert_eq!(accept_result_v1(&valid), Ok(()));
    let mut trailing = valid.clone();
    trailing.push(0x00);
    assert_eq!(
        accept_result_v1(&trailing),
        Err(failure(MetricErrorV1::InvalidEncoding, "trailing"))
    );
    for end in 0..valid.len() {
        assert!(accept_result_v1(&valid[..end]).is_err(), "prefix {end}");
    }
    assert_eq!(
        accept_result_v1(&encode(&Cbor::Array(base_fields()))),
        Err(failure(MetricErrorV1::InvalidEncoding, "result"))
    );
    Ok(())
}

const fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == ':'
}

#[test]
fn the_metric_profile_module_imports_no_plugin_or_conformance_code() -> TestResult {
    const PRIMITIVES: [&str; 5] = ["i128", "u32", "u64", "u128", "usize"];
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(crate_root.join("Cargo.toml"))?;
    let workspace_crates: Vec<&str> = manifest
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pos-") || line.contains("path ="))
        .collect();
    assert!(workspace_crates.is_empty(), "{workspace_crates:?}");
    for forbidden in ["pos-plugin", "pos-conformance", "plugins/"] {
        assert!(!manifest.contains(forbidden), "{forbidden}");
    }
    let source = std::fs::read_to_string(crate_root.join("src/metric_profile.rs"))?;
    let imports: Vec<&str> = source
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("use ") || line.starts_with("extern crate"))
        .collect();
    assert_eq!(
        imports,
        ["use std::cmp::Ordering;", "use std::collections::BTreeMap;"]
    );
    // Beyond `std`, the only path the module names is `blake3`, for the digests.
    let code: Vec<&str> = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect();
    for forbidden in ["pos_", "crate::", "super::", "plugins", "eval::"] {
        assert!(
            !code.iter().any(|line| line.contains(forbidden)),
            "{forbidden}"
        );
    }
    let roots: BTreeSet<&str> = code
        .iter()
        .flat_map(|line| line.split(|c: char| !is_path_char(c)))
        .filter_map(|token| token.split_once("::").map(|(root, _)| root))
        .filter(|root| root.starts_with(|c: char| c.is_ascii_lowercase()))
        .filter(|root| !PRIMITIVES.contains(root))
        .collect();
    let expected: BTreeSet<&str> = ["blake3", "std"].into_iter().collect();
    assert_eq!(roots, expected);
    Ok(())
}
