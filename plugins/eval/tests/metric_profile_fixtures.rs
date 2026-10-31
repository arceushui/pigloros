//! ADR-062 Revision 7 slice 3: plugins/eval's own metric profile reproduces the committed
//! metric-conformance oracles byte for byte from the committed `MTI1`/`MTQ1` members.
//!
//! The oracles were written by the offline exact-fraction generator and recomputed by
//! pos-reference; this test only reads the public fixture files and calls eval's public API.

use std::collections::BTreeMap;

use ciborium::Value;
use pos_plugin_eval::{
    decode_quantization_input_v1, encode_quantization_result_v1, quantize_probability,
    MetricFailureV1, MetricInputV1,
};
use serde_json::Value as Json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// One fixture family: its case payload, auxiliary composite and oracle.
struct Family {
    name: &'static str,
    input: &'static str,
    composite: &'static [u8],
    oracle: &'static str,
}

macro_rules! family {
    ($name:literal) => {
        Family {
            name: $name,
            input: include_str!(concat!(
                "../../../fixtures/conformance/inputs/metric-conformance/",
                $name,
                ".json"
            )),
            composite: include_bytes!(concat!(
                "../../../fixtures/conformance/inputs/metric-conformance/",
                $name,
                ".mcs1"
            )),
            oracle: include_str!(concat!(
                "../../../fixtures/conformance/oracles/metric-conformance/",
                $name,
                ".json"
            )),
        }
    };
}

const FAMILIES: [Family; 7] = [
    family!("positive"),
    family!("denied"),
    family!("malformed"),
    family!("resource-exhaustion"),
    family!("deletion-redaction"),
    family!("downgrade"),
    family!("independent-evaluation"),
];

fn missing(what: &str) -> Box<dyn std::error::Error> {
    format!("fixture is missing {what}").into()
}

fn hex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    (0..text.len())
        .step_by(2)
        .map(|index| {
            text.get(index..index + 2)
                .ok_or_else(|| missing("a whole hex byte"))
                .and_then(|pair| u8::from_str_radix(pair, 16).map_err(Into::into))
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]])
        .map(char::from)
        .collect()
}

/// The members of an `MCS1 = ["MCS1", 1, [* [digest32, member]]]` composite, by digest.
fn members(composite: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    let root: Value = ciborium::from_reader(composite)?;
    let fields = root.as_array().ok_or_else(|| missing("an MCS1 array"))?;
    assert_eq!(fields.first().and_then(Value::as_text), Some("MCS1"));
    let entries = fields
        .get(2)
        .and_then(Value::as_array)
        .ok_or_else(|| missing("MCS1 members"))?;
    entries
        .iter()
        .map(|entry| {
            let pair = entry.as_array().ok_or_else(|| missing("a member pair"))?;
            let digest = pair.first().and_then(Value::as_bytes);
            let member = pair.get(1).and_then(Value::as_bytes);
            match (digest, member) {
                (Some(digest), Some(member)) => {
                    assert_eq!(
                        blake3::hash(member).as_bytes().as_slice(),
                        digest.as_slice()
                    );
                    Ok((to_hex(digest), member.clone()))
                }
                _ => Err(missing("a digest and member")),
            }
        })
        .collect()
}

fn text<'a>(value: &'a Json, key: &str) -> Result<&'a str, Box<dyn std::error::Error>> {
    value
        .get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| missing(key))
}

/// The canonical `MTR1`/`MQR1` bytes of each result sub-case, by sub-case id. Entries
/// without bytes (the generator check `ind.2`) carry no output.
fn oracle_outputs(oracle: &Json) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    oracle
        .pointer("/output/subcases")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|entry| Some((entry.get("id")?.as_str()?, entry.get("hex")?.as_str()?)))
        .map(|(id, bytes)| Ok((id.to_owned(), hex(bytes)?)))
        .collect()
}

/// What eval's public API produced for one sub-case member.
enum Produced {
    Bytes(Vec<u8>),
    Failure(MetricFailureV1),
}

fn produce(record: &str, member: &[u8]) -> Produced {
    let produced = match record {
        "MTI1" => MetricInputV1::decode(member).map(|input| input.compute().encode()),
        _ => decode_quantization_input_v1(member).map(|patterns| {
            let entries: Vec<_> = patterns.into_iter().map(quantize_probability).collect();
            encode_quantization_result_v1(&entries)
        }),
    };
    produced.map_or_else(Produced::Failure, Produced::Bytes)
}

/// Kinds that the subject's metric codecs do not decide: transport, capability, budget,
/// contract and generator outcomes, and the evaluator's acceptance of a foreign `MTR1`.
const NOT_SUBJECT_KINDS: [&str; 6] = [
    "denied",
    "transport-rejection",
    "resource-limit",
    "incompatible-contract",
    "generator-check",
    "result-rejected",
];

#[test]
fn every_committed_metric_oracle_is_reproduced_by_eval() -> TestResult {
    let mut results = 0;
    let mut failures = 0;
    for family in &FAMILIES {
        let input: Json = serde_json::from_str(family.input)?;
        let oracle: Json = serde_json::from_str(family.oracle)?;
        let members = members(family.composite)?;
        let outputs = oracle_outputs(&oracle)?;
        let subcases = input
            .get("subcases")
            .and_then(Json::as_array)
            .ok_or_else(|| missing("subcases"))?;
        for subcase in subcases {
            let id = text(subcase, "id")?;
            let expect = subcase.get("expect").ok_or_else(|| missing("expect"))?;
            let kind = text(expect, "kind")?;
            if NOT_SUBJECT_KINDS.contains(&kind) {
                continue;
            }
            let member = subcase.get("member").ok_or_else(|| missing("member"))?;
            let bytes = members
                .get(text(member, "blake3")?)
                .ok_or_else(|| missing("a member of the composite"))?;
            match (kind, produce(text(member, "record")?, bytes)) {
                ("result", Produced::Bytes(produced)) => {
                    let expected = outputs.get(id).ok_or_else(|| missing("an oracle output"))?;
                    assert_eq!(to_hex(&produced), to_hex(expected), "{}: {id}", family.name);
                    assert_eq!(
                        blake3::hash(&produced).to_hex().as_str(),
                        text(expect, "blake3")?,
                        "{id}"
                    );
                    if let Some(marker) = expect.get("absent_marker").and_then(Json::as_str) {
                        let marker = marker.as_bytes();
                        assert!(!produced
                            .windows(marker.len())
                            .any(|window| window == marker));
                    }
                    results += 1;
                }
                ("metric-error", Produced::Failure(failure)) => {
                    let code = expect.get("code").and_then(Json::as_u64);
                    assert_eq!(Some(u64::from(failure.error.code())), code, "{id}");
                    assert_eq!(
                        failure.coordinate,
                        text(expect, "first_coordinate")?,
                        "{id}"
                    );
                    failures += 1;
                }
                (kind, Produced::Bytes(_)) => {
                    return Err(format!("{id}: expected {kind}, eval produced a result").into());
                }
                (kind, Produced::Failure(failure)) => {
                    return Err(format!("{id}: expected {kind}, eval failed {failure}").into());
                }
            }
        }
    }
    // pos.1-pos.8 (15 results), del.1-del.3 (4) and ind.1/ind.3 (2) are reproduced; every
    // committed MetricErrorV1 oracle (41 at this slice) is decided identically.
    assert!(results >= 21, "{results} results");
    assert!(failures >= 41, "{failures} failures");
    Ok(())
}

#[test]
fn the_worked_example_and_quantization_vectors_are_named_cases() -> TestResult {
    let input: Json = serde_json::from_str(FAMILIES[0].input)?;
    let members = members(FAMILIES[0].composite)?;
    let member = |id: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let subcases = input
            .get("subcases")
            .and_then(Json::as_array)
            .ok_or_else(|| missing("subcases"))?;
        let subcase = subcases
            .iter()
            .find(|subcase| subcase.get("id").and_then(Json::as_str) == Some(id))
            .ok_or_else(|| missing(id))?;
        let digest = subcase
            .pointer("/member/blake3")
            .and_then(Json::as_str)
            .ok_or_else(|| missing("a member digest"))?;
        members
            .get(digest)
            .cloned()
            .ok_or_else(|| missing("a member"))
    };
    let worked = MetricInputV1::decode(&member("pos.1")?)?;
    let result = worked.compute();
    assert_eq!(result.counts.scored, 4);
    assert_eq!(result.counts.pending, 1);
    assert_eq!(result.counts.scored_entities, 2);
    let pos_plugin_eval::MetricOutcomeV1::Computed { values, bins } = result.outcome else {
        return Err("the worked example is computed".into());
    };
    assert_eq!(
        [
            values.brier,
            values.crps,
            values.ece,
            values.population_avg_brier,
            values.lift_vs_population_avg,
            values.persistence_brier,
            values.lift_vs_persistence,
            values.personal_base_rate_brier,
            values.lift_vs_personal_base_rate,
        ],
        [97_500, 97_500, 275_000, 255_625, 158_125, 250_000, 152_500, 375_000, 277_500]
    );
    assert_eq!(
        [bins[2], bins[5], bins[7], bins[9]].map(|bin| (
            bin.count,
            bin.probability_sum_micros,
            bin.positives
        )),
        [
            (1, 200_000, 0),
            (1, 500_000, 0),
            (1, 700_000, 1),
            (1, 900_000, 1)
        ]
    );

    let patterns = decode_quantization_input_v1(&member("pos.7")?)?;
    let quantized: Vec<_> = patterns
        .iter()
        .map(|bits| quantize_probability(*bits))
        .collect();
    for (bits, expected) in [
        (0x0000_0000_0000_0000, Ok(0)),
        (0x8000_0000_0000_0000, Ok(0)),
        (0x3ff0_0000_0000_0000, Ok(1_000_000)),
        (0.1_f64.to_bits(), Ok(100_000)),
        (0.15_f64.to_bits(), Ok(150_000)),
        (0.007_812_5_f64.to_bits(), Ok(7_812)),
        ((3.0 * 0.007_812_5_f64).to_bits(), Ok(23_438)),
        (1, Ok(0)),
        (1.000_001_f64.to_bits(), Err(())),
    ] {
        let position = patterns
            .iter()
            .position(|pattern| *pattern == bits)
            .ok_or_else(|| missing("a normative pos.7 vector"))?;
        assert_eq!(quantized[position].map_err(|_| ()), expected, "{bits:#x}");
    }
    Ok(())
}
