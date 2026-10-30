//! plugins/eval's public `MTI1`/`MTR1`/`MTQ1`/`MQR1` codecs and section 4.3 computation
//! (ADR-062 Revision 7 slice 3), pinned with inputs built in-test: the section 4.6 decode
//! order and coordinates, the owner-confirmed gap-fills (nesting cap 16, `MTQ1` shape, header
//! text UTF-8), rounding, quantization and the arithmetic bound at 2^18 records.

use ciborium::Value;
use pos_plugin_eval::{
    decode_quantization_input_v1, encode_quantization_result_v1, quantize_probability,
    MetricErrorV1, MetricFailureV1, MetricInputV1, MetricOutcomeV1, MetricRecordStateV1,
    MetricRecordV1, MetricRedactionStateV1, MAX_METRIC_IDENTIFIER_BYTES, MAX_METRIC_RECORDS,
    MAX_NESTING_DEPTH, MAX_QUANTIZATION_PATTERNS, METRIC_ALGORITHM_ID, METRIC_ALGORITHM_MAJOR,
    MICROS_PER_UNIT,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    // `Vec<u8>` is an infallible sink and every test value is well formed.
    assert!(ciborium::into_writer(value, &mut out).is_ok());
    out
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn record(
    id: &str,
    entity: &str,
    micros: u64,
    state: u64,
    outcome: Value,
    supplied: bool,
) -> Value {
    Value::Array(vec![
        text(id),
        text(entity),
        uint(micros),
        uint(state),
        outcome,
        Value::Bool(supplied),
    ])
}

fn observed(id: &str, micros: u64, outcome: u64) -> Value {
    record(id, "entity", micros, 0, uint(outcome), false)
}

/// A valid two-record input: header fields, then records `a` and `b`.
fn fields() -> Vec<Value> {
    vec![
        text("MTI1"),
        uint(1),
        text(METRIC_ALGORITHM_ID),
        uint(METRIC_ALGORITHM_MAJOR),
        uint(0),
        uint(1),
        uint(2),
        Value::Array(vec![observed("a", 300_000, 1), observed("b", 777_777, 0)]),
    ]
}

fn with_field(index: usize, value: Value) -> Vec<u8> {
    let mut fields = fields();
    fields[index] = value;
    encode(&Value::Array(fields))
}

fn with_record_field(field: usize, value: Value) -> Vec<u8> {
    let mut fields = fields();
    if let Value::Array(records) = &mut fields[7] {
        if let Value::Array(items) = &mut records[1] {
            items[field] = value;
        }
    }
    encode(&Value::Array(fields))
}

/// The valid input with the encoding of record `b`'s probability (777777) replaced by `raw`.
fn splice(raw: &[u8]) -> Vec<u8> {
    let valid = encode(&Value::Array(fields()));
    let marker = [0x1a, 0x00, 0x0b, 0xde, 0x31];
    let at = valid
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap_or_default();
    [&valid[..at], raw, &valid[at + marker.len()..]].concat()
}

fn rejected(bytes: &[u8]) -> (MetricErrorV1, String) {
    MetricInputV1::decode(bytes).map_or_else(
        |failure| (failure.error, failure.coordinate),
        |input| (MetricErrorV1::ResourceLimit, format!("accepted {input:?}")),
    )
}

fn expect(bytes: &[u8], error: MetricErrorV1, coordinate: &str) {
    assert_eq!(rejected(bytes), (error, coordinate.to_owned()));
}

fn nested(levels: usize, leaf: Value) -> Value {
    (0..levels).fold(leaf, |inner, _| Value::Array(vec![inner]))
}

#[test]
fn a_valid_input_round_trips_and_exposes_its_records() -> TestResult {
    let bytes = encode(&Value::Array(fields()));
    let input = MetricInputV1::decode(&bytes)?;
    assert_eq!(input.as_bytes(), bytes.as_slice());
    assert_eq!(input.minimum_scored_records(), 1);
    assert_eq!(
        input.records(),
        [
            MetricRecordV1 {
                prediction_id: "a".to_owned(),
                entity_id: "entity".to_owned(),
                probability_micros: 300_000,
                state: MetricRecordStateV1::Observed {
                    outcome: true,
                    predictor_supplied: false,
                },
            },
            MetricRecordV1 {
                prediction_id: "b".to_owned(),
                entity_id: "entity".to_owned(),
                probability_micros: 777_777,
                state: MetricRecordStateV1::Observed {
                    outcome: false,
                    predictor_supplied: false,
                },
            },
        ]
    );
    assert_eq!(MetricInputV1::from_records(1, input.records())?, input);
    let mut unsorted = input.records().to_vec();
    unsorted.reverse();
    assert_eq!(
        MetricInputV1::from_records(1, &unsorted),
        Err(MetricFailureV1 {
            error: MetricErrorV1::NonCanonicalOrder,
            coordinate: "records/1/0".to_owned(),
        })
    );
    Ok(())
}

#[test]
fn every_truncation_is_invalid_encoding() {
    let bytes = encode(&Value::Array(fields()));
    for end in 0..bytes.len() {
        assert_eq!(rejected(&bytes[..end]).0, MetricErrorV1::InvalidEncoding);
    }
    assert_eq!(rejected(&bytes[..0]).1, "input");
    assert_eq!(rejected(&bytes[..bytes.len() - 1]).1, "records/1/5");
}

#[test]
fn structural_defects_are_invalid_encoding_at_the_defective_item() {
    let invalid = MetricErrorV1::InvalidEncoding;
    expect(&encode(&Value::Map(vec![])), invalid, "input");
    let mut short = fields();
    short.pop();
    expect(&encode(&Value::Array(short)), invalid, "input");
    expect(&with_field(7, uint(0)), invalid, "records");
    expect(&with_field(7, Value::Map(vec![])), invalid, "records");
    let five = Value::Array(vec![text("c"); 5]);
    let mut wrong_record = fields();
    wrong_record[7] = Value::Array(vec![observed("a", 1, 1), five]);
    expect(&encode(&Value::Array(wrong_record)), invalid, "records/1");
    for raw in [
        &[0xf9, 0x38, 0x00][..],                                     // half float
        &[0xfa, 0x3f, 0x00, 0x00, 0x00][..],                         // single float
        &[0xfb, 0x3f, 0xe0, 0, 0, 0, 0, 0, 0][..],                   // double float
        &[0xf9, 0x7e, 0x00][..],                                     // NaN
        &[0xf7][..],                                                 // undefined
        &[0xf8, 0x20][..],                                           // one-byte simple value
        &[0xc1, 0x01][..],                                           // tag
        &[0xa0][..],                                                 // map
        &[0x9f, 0xff][..],                                           // indefinite array
        &[0x7f, 0xff][..],                                           // indefinite text
        &[0x18, 0x05][..],                                           // non-preferred one-byte head
        &[0x19, 0x00, 0x10][..],                                     // non-preferred two-byte head
        &[0x1a, 0x00, 0x00, 0x00, 0x10][..],                         // non-preferred four-byte head
        &[0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0xde, 0x31][..], // eight-byte head
        &[0x1c][..], // reserved additional information
    ] {
        expect(&splice(raw), invalid, "records/1/2");
    }
    // A byte string is well formed: it is the wrong type when the field is read (G2).
    expect(&splice(&[0x41, 0x00]), invalid, "records/1/2");
    // A defect inside a nested array carries the nested path.
    expect(&splice(&[0x82, 0x00, 0xa0]), invalid, "records/1/2/1");
    let mut trailing = encode(&Value::Array(fields()));
    trailing.push(0x00);
    expect(&trailing, invalid, "trailing");
    // A structural defect outranks every header failure before it.
    let mut both = fields();
    both[0] = text("MTI2");
    both[7] = Value::Array(vec![
        observed("a", 1, 1),
        record("b", "e", 1, 0, Value::Float(0.5), false),
    ]);
    expect(&encode(&Value::Array(both)), invalid, "records/1/4");
}

#[test]
fn arrays_nest_to_sixteen_levels_and_no_deeper() {
    let invalid = MetricErrorV1::InvalidEncoding;
    // A record field is level 4: thirteen arrays reach level 16 and are only the wrong type.
    let deepest = nested(MAX_NESTING_DEPTH - 3, uint(1));
    expect(&with_record_field(2, deepest), invalid, "records/1/2");
    let too_deep = nested(MAX_NESTING_DEPTH - 2, uint(1));
    let coordinate = format!("records/1/2{}", "/0".repeat(MAX_NESTING_DEPTH - 3));
    expect(&with_record_field(2, too_deep), invalid, &coordinate);
    // A header field is level 2.
    expect(
        &with_field(0, nested(MAX_NESTING_DEPTH - 1, Value::Null)),
        invalid,
        "magic",
    );
    let coordinate = format!("magic{}", "/0".repeat(MAX_NESTING_DEPTH - 1));
    expect(
        &with_field(0, nested(MAX_NESTING_DEPTH, Value::Null)),
        invalid,
        &coordinate,
    );
}

#[test]
fn header_fields_fail_in_index_order() {
    let version = MetricErrorV1::UnsupportedVersion;
    let algorithm = MetricErrorV1::UnsupportedAlgorithm;
    expect(&with_field(0, text("MTI2")), version, "magic");
    expect(&with_field(1, uint(2)), version, "version");
    expect(
        &with_field(2, text("pigloros.metric.other")),
        algorithm,
        "algorithm_id",
    );
    expect(&with_field(3, uint(2)), algorithm, "algorithm_major");
    expect(
        &with_field(4, uint(1)),
        MetricErrorV1::InvalidBinning,
        "binning",
    );
    let minimum = MetricErrorV1::InvalidMinimum;
    for value in [0, MAX_METRIC_RECORDS + 1, 1 << 33] {
        expect(
            &with_field(5, uint(value)),
            minimum,
            "minimum_scored_records",
        );
    }
    let limit = MetricErrorV1::ResourceLimit;
    expect(
        &with_field(6, uint(MAX_METRIC_RECORDS + 1)),
        limit,
        "record_count",
    );
    expect(
        &with_field(6, uint(3)),
        MetricErrorV1::InconsistentLength,
        "records",
    );
    // Several header defects: the first in index order wins.
    let mut several = fields();
    several[1] = uint(2);
    several[4] = uint(1);
    expect(&encode(&Value::Array(several)), version, "version");
    // Invalid UTF-8 in a header text is that field's failure, not a structural one (G12).
    let valid = encode(&Value::Array(fields()));
    let mut magic = valid.clone();
    magic[2] = 0xff;
    expect(&magic, version, "magic");
    let mut algorithm_id = valid;
    algorithm_id[9] = 0xff;
    expect(&algorithm_id, algorithm, "algorithm_id");
}

#[test]
fn a_well_formed_field_of_the_wrong_type_is_invalid_encoding_at_that_field() {
    let invalid = MetricErrorV1::InvalidEncoding;
    for (index, value, coordinate) in [
        (0, uint(1), "magic"),
        (1, text("1"), "version"),
        (
            2,
            Value::Bytes(METRIC_ALGORITHM_ID.as_bytes().to_vec()),
            "algorithm_id",
        ),
        (3, Value::Integer((-1).into()), "algorithm_major"),
        (4, Value::Null, "binning"),
        (5, Value::Bool(true), "minimum_scored_records"),
        (6, Value::Array(vec![]), "record_count"),
    ] {
        expect(&with_field(index, value), invalid, coordinate);
    }
    for (index, value) in [
        (0, uint(7)),
        (1, Value::Bool(false)),
        (2, text("0")),
        (3, Value::Null),
        (4, Value::Bool(true)),
        (5, uint(1)),
    ] {
        expect(
            &with_record_field(index, value),
            invalid,
            &format!("records/1/{index}"),
        );
    }
}

#[test]
fn record_fields_fail_in_index_order() {
    let identifier = MetricErrorV1::InvalidIdentifier;
    let long = "x".repeat(MAX_METRIC_IDENTIFIER_BYTES + 1);
    expect(&with_record_field(0, text("")), identifier, "records/1/0");
    expect(
        &with_record_field(1, text(&long)),
        identifier,
        "records/1/1",
    );
    let mut invalid_utf8 = encode(&Value::Array(fields()));
    // Record `b` ends with its entity text "entity" (6 bytes), probability (5), state,
    // outcome and flag (1 each).
    let entity = invalid_utf8.len() - 14;
    invalid_utf8[entity] = 0xff;
    expect(&invalid_utf8, identifier, "records/1/1");
    let longest = "y".repeat(MAX_METRIC_IDENTIFIER_BYTES);
    assert!(MetricInputV1::decode(&with_record_field(1, text(&longest))).is_ok());
    expect(
        &with_record_field(0, text("a")),
        MetricErrorV1::DuplicatePrediction,
        "records/1/0",
    );
    expect(
        &with_record_field(0, text("0")),
        MetricErrorV1::NonCanonicalOrder,
        "records/1/0",
    );
    let probability = MetricErrorV1::InvalidProbability;
    expect(
        &with_record_field(2, uint(1_000_001)),
        probability,
        "records/1/2",
    );
    expect(
        &with_record_field(2, uint(1 << 40)),
        probability,
        "records/1/2",
    );
    let outcome = MetricErrorV1::InvalidOutcome;
    expect(&with_record_field(3, uint(4)), outcome, "records/1/3");
    expect(&with_record_field(4, Value::Null), outcome, "records/1/4");
    expect(&with_record_field(4, uint(2)), outcome, "records/1/4");
    for state in 1..=3 {
        let mut with_outcome = fields();
        with_outcome[7] = Value::Array(vec![
            observed("a", 1, 1),
            record("b", "e", 1, state, uint(0), false),
        ]);
        expect(&encode(&Value::Array(with_outcome)), outcome, "records/1/4");
        let mut supplied = fields();
        supplied[7] = Value::Array(vec![
            observed("a", 1, 1),
            record("b", "e", 1, state, Value::Null, true),
        ]);
        expect(&encode(&Value::Array(supplied)), outcome, "records/1/5");
    }
}

fn computed(
    records: Vec<Value>,
    minimum: u64,
) -> Result<pos_plugin_eval::MetricResultV1, MetricFailureV1> {
    let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
    let mut fields = fields();
    fields[5] = uint(minimum);
    fields[6] = uint(count);
    fields[7] = Value::Array(records);
    MetricInputV1::decode(&encode(&Value::Array(fields))).map(|input| input.compute())
}

#[test]
fn every_state_is_counted_and_below_the_minimum_no_metric_is_reported() -> TestResult {
    let records = vec![
        record("a", "e1", 100_000, 0, uint(1), true),
        record("b", "e1", 200_000, 1, Value::Null, false),
        record("c", "e2", 300_000, 2, Value::Null, false),
        record("d", "e2", 400_000, 3, Value::Null, false),
        record("e", "e3", 500_000, 0, uint(0), false),
    ];
    let result = computed(records.clone(), 3)?;
    assert_eq!(result.outcome, MetricOutcomeV1::InsufficientSamples);
    assert_eq!(result.minimum_scored_records, 3);
    assert_eq!(
        result.redaction_state,
        MetricRedactionStateV1::EvidenceMissing
    );
    let counts = result.counts;
    assert_eq!(
        [
            counts.record_count,
            counts.scored,
            counts.pending,
            counts.redacted,
            counts.unavailable,
            counts.predictor_supplied,
            counts.scored_entities,
        ],
        [5, 2, 1, 1, 1, 1, 2]
    );
    let bytes = result.encode();
    // metrics and bins are null, followed by the 32-byte result digest.
    assert_eq!(bytes[bytes.len() - 36..bytes.len() - 34], [0xf6, 0xf6]);
    let computed = computed(records[..3].to_vec(), 1)?;
    assert_eq!(
        computed.redaction_state,
        MetricRedactionStateV1::RedactedViews
    );
    assert!(matches!(computed.outcome, MetricOutcomeV1::Computed { .. }));
    let empty = computed_none()?;
    assert_eq!(empty.outcome, MetricOutcomeV1::InsufficientSamples);
    assert_eq!(empty.redaction_state, MetricRedactionStateV1::None);
    Ok(())
}

fn computed_none() -> Result<pos_plugin_eval::MetricResultV1, MetricFailureV1> {
    computed(Vec::new(), 1)
}

#[test]
fn two_to_the_eighteen_records_compute_without_overflow() -> TestResult {
    let records: Vec<MetricRecordV1> = (0..MAX_METRIC_RECORDS)
        .map(|index| MetricRecordV1 {
            prediction_id: format!("p{index:06}"),
            entity_id: "e".to_owned(),
            probability_micros: if index % 2 == 0 { 0 } else { MICROS_PER_UNIT },
            state: MetricRecordStateV1::Observed {
                outcome: index % 2 == 0,
                predictor_supplied: false,
            },
        })
        .collect();
    let input = MetricInputV1::from_records(1, &records)?;
    let result = input.compute();
    // Computed with exact fractions by the offline generator's arithmetic.
    let expected = concat!(
        "8d644d5452310178227069676c6f726f732e6d65747269632e62696e6172792d63616c6962726174696f6e01",
        "005820f1e333e6fa3ff76a11808d4ce5ea5966c3ddd12b312f93c53bc5958e2e8424cd00871a000400001a00",
        "04000000000000010100891a000f42401a000f42401a000f42401a0003d0903a000b71af1a0003d0903a000b",
        "71af1a0003d0923a000b71ad8a831a00020000001a0002000083000000830000008300000083000000830000",
        "00830000008300000083000000831a000200001b0000001e8480000000582023b62b2261539a350fec0265f0",
        "11a8323f6cc6ecea3409265a145511ecb092f3",
    );
    let hex: String = result
        .encode()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(hex, expected);
    Ok(())
}

#[test]
fn quantization_follows_the_bit_pattern_with_no_clamping() {
    let invalid = Err(MetricErrorV1::InvalidProbability);
    for bits in [
        f64::NAN.to_bits(),
        (-f64::NAN).to_bits(),
        f64::INFINITY.to_bits(),
        f64::NEG_INFINITY.to_bits(),
        (-1.0_f64).to_bits(),
        0x8000_0000_0000_0001, // the negative smallest subnormal
        1.5_f64.to_bits(),
        f64::MAX.to_bits(),
        0x3ff0_0000_0000_0001, // the next value above 1
    ] {
        assert_eq!(quantize_probability(bits), invalid, "{bits:#x}");
    }
    for (bits, micros) in [
        (0.5_f64.to_bits(), 500_000),
        (0x3fef_ffff_ffff_ffff, 1_000_000), // the largest value below 1
        (0x000f_ffff_ffff_ffff, 0),         // the largest subnormal
        (1e-6_f64.to_bits(), 1),
        (0.000_000_5_f64.to_bits(), 0), // the nearest double rounds down
        (0.000_001_5_f64.to_bits(), 2), // the nearest double rounds up
        (0.25_f64.to_bits(), 250_000),
    ] {
        assert_eq!(quantize_probability(bits), Ok(micros), "{bits:#x}");
    }
}

fn quantization(magic: &str, version: Value, patterns: Value) -> Vec<u8> {
    encode(&Value::Array(vec![text(magic), version, patterns]))
}

fn quantization_failure(bytes: &[u8]) -> (MetricErrorV1, String) {
    decode_quantization_input_v1(bytes).map_or_else(
        |failure| (failure.error, failure.coordinate),
        |patterns| {
            (
                MetricErrorV1::ResourceLimit,
                format!("accepted {patterns:?}"),
            )
        },
    )
}

#[test]
fn quantization_inputs_are_strictly_decoded() -> TestResult {
    let one = || Value::Array(vec![uint(1.0_f64.to_bits()), uint(0)]);
    let valid = quantization("MTQ1", uint(1), one());
    assert_eq!(
        decode_quantization_input_v1(&valid)?,
        [1.0_f64.to_bits(), 0]
    );
    for end in 0..valid.len() {
        assert_eq!(
            quantization_failure(&valid[..end]).0,
            MetricErrorV1::InvalidEncoding
        );
    }
    let invalid = MetricErrorV1::InvalidEncoding;
    let version = MetricErrorV1::UnsupportedVersion;
    let deep = format!("patterns/0{}", "/0".repeat(MAX_NESTING_DEPTH - 2));
    let cases = [
        (quantization("MTQ2", uint(1), one()), version, "magic"),
        (quantization("MTQ1", uint(2), one()), version, "version"),
        (quantization("MTQ1", text("1"), one()), invalid, "version"),
        (
            quantization("MTQ1", uint(1), Value::Null),
            invalid,
            "patterns",
        ),
        (
            quantization("MTQ1", uint(1), Value::Array(vec![])),
            invalid,
            "patterns",
        ),
        (
            quantization("MTQ1", uint(1), Value::Array(vec![uint(0), text("0")])),
            invalid,
            "patterns/1",
        ),
        (
            quantization(
                "MTQ1",
                uint(1),
                Value::Array((0..=MAX_QUANTIZATION_PATTERNS).map(uint).collect()),
            ),
            MetricErrorV1::ResourceLimit,
            "patterns",
        ),
        (
            quantization(
                "MTQ1",
                uint(1),
                Value::Array(vec![nested(MAX_NESTING_DEPTH - 1, uint(0))]),
            ),
            invalid,
            deep.as_str(),
        ),
        (
            encode(&Value::Array(vec![text("MTQ1"), uint(1)])),
            invalid,
            "input",
        ),
    ];
    for (bytes, error, coordinate) in cases {
        assert_eq!(quantization_failure(&bytes), (error, coordinate.to_owned()));
    }
    let longest = Value::Array((1..=MAX_QUANTIZATION_PATTERNS).map(uint).collect());
    assert_eq!(
        decode_quantization_input_v1(&quantization("MTQ1", uint(1), longest))?.len(),
        4_096
    );
    let mut trailing = valid;
    trailing.push(0x00);
    assert_eq!(
        quantization_failure(&trailing),
        (invalid, "trailing".to_owned())
    );
    // Invalid UTF-8 in the magic is the version failure (G12).
    let mut magic = quantization("MTQ1", uint(1), one());
    magic[2] = 0xff;
    assert_eq!(quantization_failure(&magic), (version, "magic".to_owned()));
    Ok(())
}

#[test]
fn quantization_results_encode_failures_as_one_item_arrays() {
    let entries = [
        Ok(0),
        Err(MetricErrorV1::InvalidProbability),
        Ok(MICROS_PER_UNIT),
    ];
    assert_eq!(
        encode_quantization_result_v1(&entries),
        [
            0x83, 0x64, b'M', b'Q', b'R', b'1', 0x01, 0x83, 0x00, 0x81, 0x05, 0x1a, 0x00, 0x0f,
            0x42, 0x40,
        ]
    );
}

#[test]
fn the_closed_error_set_keeps_its_wire_codes() {
    let errors = [
        MetricErrorV1::InvalidEncoding,
        MetricErrorV1::UnsupportedVersion,
        MetricErrorV1::UnsupportedAlgorithm,
        MetricErrorV1::InvalidBinning,
        MetricErrorV1::InconsistentLength,
        MetricErrorV1::InvalidProbability,
        MetricErrorV1::InvalidOutcome,
        MetricErrorV1::InvalidIdentifier,
        MetricErrorV1::DuplicatePrediction,
        MetricErrorV1::NonCanonicalOrder,
        MetricErrorV1::InvalidMinimum,
        MetricErrorV1::ResourceLimit,
    ];
    let codes: Vec<u8> = errors.iter().copied().map(MetricErrorV1::code).collect();
    assert_eq!(codes, (0..=11).collect::<Vec<u8>>());
    let failure = MetricFailureV1 {
        error: MetricErrorV1::InvalidProbability,
        coordinate: "records/17/2".to_owned(),
    };
    assert_eq!(failure.to_string(), "InvalidProbability at records/17/2");
}
