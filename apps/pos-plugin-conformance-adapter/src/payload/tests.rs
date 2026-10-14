//! R8-A14: the grammar, key set by key set.

use serde_json::{json, Value};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const H32: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const H16: &str = "02020202020202020202020202020202";

fn release() -> Value {
    json!({"manifest": H32, "blobs": [H32, H32]})
}

fn material() -> Value {
    json!({"anchor": H32, "tps1": H32, "ptr1": [H32], "prv1": [H32, H32]})
}

fn retained() -> Value {
    json!({"plugin_id": "p", "invocation_id_hex": H16})
}

fn pass() -> Value {
    json!({
        "step": "pass",
        "members": [
            {"plugin_id": "p"},
            {"plugin_id": "p", "at": "absent"},
            {"plugin_id": "p", "at": release()},
        ],
        "instant_micros": 50_000_000,
        "tick": 5,
        "invocation_id": H16,
        "random_domain": H32,
        "timeline_seq": 3,
        "observation": "00ff",
        "simulation_time": 7,
    })
}

fn scan() -> Value {
    json!({
        "step": "scan", "marker": "m", "in": ["events", "state", "outcome"],
        "retained": retained(),
    })
}

fn subcase(id: &str, steps: Value, expect: Value) -> Value {
    let mut document = json!({"id": id});
    document["steps"] = steps;
    document["expect"] = expect;
    document
}

/// A payload that uses every object of the grammar once.
fn base() -> Value {
    let install = json!({
        "step": "install", "release": release(), "material": material(),
        "instant_micros": 40_000_000, "tick": 5,
    });
    let bind = json!({
        "step": "bind", "release": release(), "material": null, "plugin_id": "p",
        "instant_micros": 50_000_000, "tick": 5,
        "initial_state": {"schema": H32, "bytes": "00"}, "event_type": "e",
    });
    let refresh = json!({
        "step": "refresh", "material": material(), "instant_micros": 1, "tick": 2,
    });
    let digest = |compute: Value| json!({"kind": "digest", "compute": compute, "value": H32});
    let profile = json!({
        "what": "profile_digest", "ceilings": [1, 2, 3, 4, 5],
        "runtime": {
            "version": "v", "features": ["a"], "engine": [524_288, true, false],
            "traps": [["OutOfFuel", "FuelExhausted"]],
        },
    });
    let mut subcases = vec![
        subcase(
            "pos.1",
            json!([install, bind, refresh, pass(), scan()]),
            json!({"kind": "committed", "output_digest": H32}),
        ),
        subcase(
            "den.01",
            json!([]),
            json!({
                "kind": "refused", "error": "CapabilityDenied",
                "class": "PreExecutionRejection", "index": 0,
            }),
        ),
        subcase(
            "den.13",
            json!([]),
            json!({
                "kind": "refused", "error": "ArtifactRevoked",
                "class": "PreExecutionRejection", "basis": "PublisherKey",
            }),
        ),
        subcase(
            "den.03",
            json!([]),
            json!({
                "kind": "refused", "error": "IncompatibleAbi",
                "class": "PreExecutionRejection",
            }),
        ),
        subcase(
            "res.1",
            json!([]),
            json!({"kind": "failed", "error": "FuelExhausted", "class": "Authoritative"}),
        ),
        subcase(
            "del.1",
            json!([scan()]),
            json!({"kind": "absent", "marker": "m", "retained": retained()}),
        ),
        subcase(
            "ind.1",
            json!([]),
            digest(json!({"what": "blake3_of", "input": "x"})),
        ),
        subcase(
            "ind.2a",
            json!([]),
            digest(json!({"what": "release_identity", "field": "pmf1"})),
        ),
        subcase(
            "ind.3",
            json!([]),
            digest(json!({"what": "output_digest", "pass_index": 0})),
        ),
        subcase("ind.4", json!([]), digest(profile)),
    ];
    let mut malformed = subcase("mal.6", json!([]), json!({"kind": "malformed"}));
    malformed["nested"] = json!(H32);
    subcases.push(malformed);
    json!({
        "schema": SCHEMA_ID,
        "family": "positive",
        "subcases": subcases,
    })
}

fn parse(value: &Value) -> Result<CaseV1, InvalidCaseV1> {
    CaseV1::parse(value.to_string().as_bytes(), FixtureFamily::Positive)
}

/// The payload after `change`, parsed.
fn changed(change: impl FnOnce(&mut Value)) -> Result<CaseV1, InvalidCaseV1> {
    let mut value = base();
    change(&mut value);
    parse(&value)
}

fn at<'a>(value: &'a mut Value, pointer: &str) -> &'a mut Value {
    value
        .pointer_mut(pointer)
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new(format!("no value at {pointer}"))))
}

#[test]
fn every_object_of_the_grammar_is_accepted_exactly() -> TestResult {
    let case = parse(&base())?;
    assert_eq!(case.subcases.len(), 11);
    assert_eq!(case.provider, None);
    assert!(matches!(case.subcases[0].steps[3], StepV1::Pass(_)));
    Ok(())
}

/// Every object of the grammar, by the pointer of an instance in `base()`.
const OBJECTS: &[&str] = &[
    "",
    "/subcases/0",
    "/subcases/0/steps/0",
    "/subcases/0/steps/0/release",
    "/subcases/0/steps/0/material",
    "/subcases/0/steps/1",
    "/subcases/0/steps/1/initial_state",
    "/subcases/0/steps/2",
    "/subcases/0/steps/3",
    "/subcases/0/steps/3/members/0",
    "/subcases/0/steps/3/members/2/at",
    "/subcases/0/steps/4",
    "/subcases/0/steps/4/retained",
    "/subcases/0/expect",
    "/subcases/1/expect",
    "/subcases/2/expect",
    "/subcases/4/expect",
    "/subcases/5/expect",
    "/subcases/5/expect/retained",
    "/subcases/6/expect",
    "/subcases/6/expect/compute",
    "/subcases/7/expect/compute",
    "/subcases/8/expect/compute",
    "/subcases/9/expect/compute",
    "/subcases/9/expect/compute/runtime",
    "/subcases/10/expect",
];

#[test]
fn an_unknown_key_is_payload_invalid_in_every_object() {
    for pointer in OBJECTS {
        let result = changed(|value| at(value, pointer)["extra"] = json!(1));
        assert_eq!(result, Err(InvalidCaseV1), "{pointer}");
    }
}

#[test]
fn a_missing_key_is_payload_invalid_in_every_object() {
    for pointer in OBJECTS {
        let mut value = base();
        let keys: Vec<String> = at(&mut value, pointer)
            .as_object()
            .map(|object| object.keys().cloned().collect())
            .unwrap_or_default();
        for key in keys {
            // `at` is optional, `index` and `basis` are conditional, and `nested` is checked below.
            if matches!(key.as_str(), "at" | "index" | "basis" | "nested") {
                continue;
            }
            let result = changed(|value| {
                if let Some(object) = at(value, pointer).as_object_mut() {
                    object.remove(&key);
                }
            });
            assert_eq!(result, Err(InvalidCaseV1), "{pointer} without {key}");
        }
    }
}

#[test]
fn a_null_is_only_accepted_where_the_grammar_says_material_or_null() {
    let null_material = changed(|value| *at(value, "/subcases/0/steps/0/material") = Value::Null);
    assert!(null_material.is_ok());
    for pointer in [
        "/subcases/0/steps/0/release",
        "/subcases/0/steps/1/event_type",
    ] {
        let result = changed(|value| *at(value, pointer) = Value::Null);
        assert_eq!(result, Err(InvalidCaseV1), "{pointer}");
    }
    for pointer in ["/subcases/10/nested", "/subcases/0/steps/3/members/2/at"] {
        let result = changed(|value| *at(value, pointer) = Value::Null);
        assert_eq!(result, Err(InvalidCaseV1), "{pointer}");
    }
}

#[test]
fn hex_of_the_wrong_length_or_case_is_payload_invalid() {
    let wrong: Vec<(&str, String)> = vec![
        ("/subcases/0/steps/0/release/manifest", "0101".to_owned()),
        ("/subcases/0/steps/0/release/manifest", "AB".repeat(32)),
        ("/subcases/0/steps/0/release/blobs/0", format!("{H32}00")),
        ("/subcases/0/steps/3/invocation_id", format!("{H16}00")),
        ("/subcases/0/steps/3/invocation_id", "AB".repeat(16)),
        ("/subcases/0/steps/3/random_domain", H32[..62].to_owned()),
        ("/subcases/0/steps/3/observation", "0".to_owned()),
        ("/subcases/0/steps/3/observation", "0F".to_owned()),
        ("/subcases/0/steps/1/initial_state/bytes", "zz".to_owned()),
        ("/subcases/0/expect/output_digest", "00".to_owned()),
        ("/subcases/10/nested", "00".to_owned()),
    ];
    for (pointer, text) in wrong {
        let result = changed(|value| *at(value, pointer) = json!(text));
        assert_eq!(result, Err(InvalidCaseV1), "{pointer} = {text}");
    }
    let empty = changed(|value| *at(value, "/subcases/0/steps/3/observation") = json!(""));
    assert!(empty.is_ok(), "hexb accepts the empty string");
}

#[test]
fn numbers_must_be_integers_from_zero_to_two_to_the_fifty_third_minus_one() {
    let pointer = "/subcases/0/steps/3/tick";
    let accepted = [json!(0), json!(9_007_199_254_740_991_u64)];
    for number in accepted {
        let result = changed(|value| *at(value, pointer) = number.clone());
        assert!(result.is_ok(), "{number}");
    }
    let refused = [
        json!(9_007_199_254_740_992_u64),
        json!(u64::MAX),
        json!(-1),
        json!(1.5),
        json!(1.0),
        json!("1"),
        json!(true),
        Value::Null,
    ];
    for number in refused {
        let result = changed(|value| *at(value, pointer) = number.clone());
        assert_eq!(result, Err(InvalidCaseV1), "{number}");
    }
}

#[test]
fn text_is_printable_ascii() {
    let pointer = "/subcases/0/steps/1/plugin_id";
    for text in ["", "a b~", "p"] {
        let result = changed(|value| *at(value, pointer) = json!(text));
        assert!(result.is_ok(), "{text:?}");
    }
    for text in ["tab\t", "new\nline", "\u{7f}", "é", "nul\u{0}"] {
        let result = changed(|value| *at(value, pointer) = json!(text));
        assert_eq!(result, Err(InvalidCaseV1), "{text:?}");
    }
    let number = changed(|value| *at(value, pointer) = json!(5));
    assert_eq!(number, Err(InvalidCaseV1));
}

#[test]
fn the_envelope_is_checked() {
    let cases: Vec<(&str, Value)> = vec![
        ("/schema", json!("pigloros.plugin-conformance.case.v1")),
        ("/family", json!("denied")),
        ("/family", json!(1)),
        ("/subcases", json!({})),
    ];
    for (pointer, replacement) in cases {
        let result = changed(|value| *at(value, pointer) = replacement.clone());
        assert_eq!(result, Err(InvalidCaseV1), "{pointer}");
    }
    assert_eq!(parse(&json!([])), Err(InvalidCaseV1));
    assert_eq!(
        CaseV1::parse(b"not json", FixtureFamily::Positive),
        Err(InvalidCaseV1)
    );
}

fn plain(index: usize) -> Value {
    let compute = json!({"what": "blake3_of", "input": "x"});
    let expect = json!({"kind": "digest", "compute": compute, "value": H32});
    subcase(&format!("ind.{index}"), json!([]), expect)
}

#[test]
fn at_most_sixty_four_subcases() -> TestResult {
    let mut value = base();
    value["subcases"] = Value::Array((0..64).map(plain).collect());
    assert_eq!(parse(&value)?.subcases.len(), 64);
    value["subcases"] = Value::Array((0..65).map(plain).collect());
    assert_eq!(parse(&value), Err(InvalidCaseV1));
    Ok(())
}

#[test]
fn at_least_one_subcase_and_no_repeated_id() -> TestResult {
    let mut value = base();
    value["subcases"] = json!([]);
    assert_eq!(parse(&value), Err(InvalidCaseV1), "an empty case passes vacuously");
    value["subcases"] = Value::Array(vec![plain(1)]);
    assert_eq!(parse(&value)?.subcases.len(), 1);
    value["subcases"] = Value::Array(vec![plain(1), plain(2), plain(1)]);
    assert_eq!(parse(&value), Err(InvalidCaseV1), "a repeated sub-case ID");
    Ok(())
}

#[test]
fn the_family_must_be_the_attempts() {
    let value = base();
    let bytes = value.to_string();
    for family in FixtureFamily::ALL {
        let result = CaseV1::parse(bytes.as_bytes(), *family);
        assert_eq!(
            result.is_ok(),
            *family == FixtureFamily::Positive,
            "{family:?}"
        );
    }
}

fn header() -> Value {
    json!({
        "provider_id": PROVIDER_ID,
        "contract_version": CONTRACT_VERSION,
        "abi_major": 0,
        "abi_minor": 0,
        "from_abi_minor": 1,
    })
}

fn downgrade(change: impl FnOnce(&mut Value)) -> Result<CaseV1, InvalidCaseV1> {
    let mut value = base();
    value["family"] = json!("downgrade");
    value["provider"] = header();
    change(&mut value);
    CaseV1::parse(value.to_string().as_bytes(), FixtureFamily::Downgrade)
}

#[test]
fn the_provider_header_is_required_in_downgrade_and_only_there() {
    assert!(downgrade(|_| ()).is_ok());
    let removed = downgrade(|value| {
        if let Some(object) = value.as_object_mut() {
            object.remove("provider");
        }
    });
    assert_eq!(removed, Err(InvalidCaseV1));
    let nulled = downgrade(|value| value["provider"] = Value::Null);
    assert_eq!(nulled, Err(InvalidCaseV1));
    let mut value = base();
    value["provider"] = header();
    assert_eq!(
        parse(&value),
        Err(InvalidCaseV1),
        "provider in another family"
    );
}

#[test]
fn the_provider_header_equals_the_transition() {
    let wrong = [
        ("provider_id", json!("pigloros.fixture.other")),
        ("contract_version", json!("1.0.0")),
        ("abi_major", json!(1)),
        ("abi_minor", json!(1)),
        ("from_abi_minor", json!(0)),
        ("from_abi_minor", json!(2)),
    ];
    for (key, replacement) in wrong {
        let result = downgrade(|value| value["provider"][key] = replacement.clone());
        assert_eq!(result, Err(InvalidCaseV1), "{key}");
    }
    let unknown = downgrade(|value| value["provider"]["extra"] = json!(1));
    assert_eq!(unknown, Err(InvalidCaseV1));
    for key in header()
        .as_object()
        .map(|object| object.keys().cloned())
        .into_iter()
        .flatten()
    {
        let missing = downgrade(|value| {
            if let Some(object) = value["provider"].as_object_mut() {
                object.remove(&key);
            }
        });
        assert_eq!(missing, Err(InvalidCaseV1), "{key}");
    }
}

#[test]
fn nested_and_the_malformed_expectation_belong_to_mal_6_only() {
    let renamed = changed(|value| *at(value, "/subcases/10/id") = json!("mal.7"));
    assert_eq!(renamed, Err(InvalidCaseV1), "mal.6 without its id");
    let without = changed(|value| {
        if let Some(object) = at(value, "/subcases/10").as_object_mut() {
            object.remove("nested");
        }
    });
    assert_eq!(without, Err(InvalidCaseV1), "mal.6 without nested");
    let elsewhere = changed(|value| at(value, "/subcases/0")["nested"] = json!(H32));
    assert_eq!(elsewhere, Err(InvalidCaseV1), "nested outside mal.6");
    let expecting = changed(|value| {
        *at(value, "/subcases/10/expect") = json!({"kind": "failed", "error": "e", "class": "c"});
    });
    assert_eq!(
        expecting,
        Err(InvalidCaseV1),
        "mal.6 expecting something else"
    );
    let moved = changed(|value| *at(value, "/subcases/3/expect") = json!({"kind": "malformed"}));
    assert_eq!(moved, Err(InvalidCaseV1), "malformed outside mal.6");
}

#[test]
fn basis_and_index_appear_exactly_for_their_errors() {
    let wrong = [
        ("/subcases/1/expect/index", None),
        ("/subcases/2/expect/basis", None),
        ("/subcases/3/expect/index", Some(json!(0))),
        ("/subcases/3/expect/basis", Some(json!("Expired"))),
        ("/subcases/1/expect/basis", Some(json!("Expired"))),
        ("/subcases/2/expect/index", Some(json!(0))),
    ];
    for (pointer, replacement) in wrong {
        let result = changed(|value| {
            let (parent, key) = pointer.rsplit_once('/').unwrap_or_default();
            if let Some(object) = at(value, parent).as_object_mut() {
                match &replacement {
                    Some(number) => object.insert(key.to_owned(), number.clone()),
                    None => object.remove(key),
                };
            }
        });
        assert_eq!(result, Err(InvalidCaseV1), "{pointer}");
    }
    let nulled = changed(|value| *at(value, "/subcases/1/expect/index") = Value::Null);
    assert_eq!(nulled, Err(InvalidCaseV1));
}

#[test]
fn the_other_conditional_errors_take_their_keys() {
    for (error, key, given) in [
        ("ArtifactTrustDenied", "basis", json!("Expired")),
        ("MissingFeature", "index", json!(3)),
    ] {
        let mut expect = json!({"kind": "refused", "error": error, "class": "c"});
        expect[key] = given;
        let result = changed(|value| *at(value, "/subcases/3/expect") = expect.clone());
        assert!(result.is_ok(), "{error}");
    }
}

#[test]
fn an_absent_expectation_needs_exactly_one_matching_scan() {
    let two = changed(|value| {
        if let Some(steps) = at(value, "/subcases/5/steps").as_array_mut() {
            steps.push(scan());
        }
    });
    assert_eq!(two, Err(InvalidCaseV1), "two scans");
    let none = changed(|value| *at(value, "/subcases/5/steps") = json!([]));
    assert_eq!(none, Err(InvalidCaseV1), "no scan");
    let marker = changed(|value| *at(value, "/subcases/5/expect/marker") = json!("other"));
    assert_eq!(marker, Err(InvalidCaseV1), "another marker");
    let plugin = changed(|value| *at(value, "/subcases/5/expect/retained/plugin_id") = json!("q"));
    assert_eq!(plugin, Err(InvalidCaseV1), "another Plugin ID");
    let pointer = "/subcases/5/expect/retained/invocation_id_hex";
    let id = changed(|value| *at(value, pointer) = json!("x"));
    assert_eq!(id, Err(InvalidCaseV1), "another invocation ID");
    let other_steps = changed(|value| {
        *at(value, "/subcases/5/steps") = json!([scan(), {
            "step": "refresh", "material": null, "instant_micros": 1, "tick": 2,
        }]);
    });
    assert!(other_steps.is_ok(), "other steps do not count as scans");
}

#[test]
fn a_step_or_expectation_kind_outside_the_grammar_is_payload_invalid() {
    let step = changed(|value| *at(value, "/subcases/0/steps/0/step") = json!("migrate"));
    assert_eq!(step, Err(InvalidCaseV1));
    let untagged = changed(|value| {
        if let Some(object) = at(value, "/subcases/0/steps/0").as_object_mut() {
            object.remove("step");
        }
    });
    assert_eq!(untagged, Err(InvalidCaseV1));
    let kind = changed(|value| *at(value, "/subcases/0/expect/kind") = json!("operational"));
    assert_eq!(kind, Err(InvalidCaseV1));
    let compute = changed(|value| *at(value, "/subcases/6/expect/compute/what") = json!("sha"));
    assert_eq!(compute, Err(InvalidCaseV1));
    let field = changed(|value| *at(value, "/subcases/7/expect/compute/field") = json!("digest"));
    assert_eq!(field, Err(InvalidCaseV1));
    let source = changed(|value| *at(value, "/subcases/0/steps/4/in") = json!(["logs"]));
    assert_eq!(source, Err(InvalidCaseV1));
    let at_text = changed(|value| *at(value, "/subcases/0/steps/3/members/1/at") = json!("gone"));
    assert_eq!(at_text, Err(InvalidCaseV1));
}

#[test]
fn the_profile_compute_arrays_have_their_exact_shapes() {
    let pointer = "/subcases/9/expect/compute";
    let wrong = [
        ("ceilings", json!([1, 2, 3, 4])),
        ("ceilings", json!([1, 2, 3, 4, 5, 6])),
        ("runtime/engine", json!([1, true])),
        ("runtime/engine", json!([1, true, false, true])),
        ("runtime/traps", json!([["OutOfFuel"]])),
        (
            "runtime/traps",
            json!([["OutOfFuel", "FuelExhausted", "x"]]),
        ),
    ];
    for (path, replacement) in wrong {
        let place = format!("{pointer}/{path}");
        let result = changed(|value| *at(value, &place) = replacement.clone());
        assert_eq!(result, Err(InvalidCaseV1), "{path}");
    }
}

#[test]
fn a_nested_document_is_parsed_by_the_same_grammar() -> TestResult {
    let document = subcase("n.1", json!([]), json!({"kind": "malformed"})).to_string();
    let parsed = SubCaseV1::parse_document(document.as_bytes())?;
    assert_eq!(parsed.id.as_str(), "n.1");
    let nested_key = format!(
        "{{\"id\":\"n\",\"steps\":[],\"expect\":{{\"kind\":\"malformed\"}},\"nested\":\"{H32}\"}}"
    );
    let refused = [
        b"[]".as_slice(),
        b"not json",
        br#"{"id":"n","steps":[],"expect":{"kind":"malformed"},"x":1}"#,
        br#"{"id":"n","steps":[],"expect":{"kind":"refused","error":"CapabilityDenied","class":"c"}}"#,
        nested_key.as_bytes(),
    ];
    for bytes in refused {
        assert_eq!(SubCaseV1::parse_document(bytes), Err(InvalidCaseV1));
    }
    Ok(())
}

#[test]
fn the_family_names_are_the_payload_names() {
    let names: Vec<&str> = FixtureFamily::ALL.iter().map(|f| family_text(*f)).collect();
    assert_eq!(
        names,
        [
            "positive",
            "denied",
            "malformed",
            "resource-exhaustion",
            "deletion-redaction",
            "downgrade",
            "independent-evaluation",
        ]
    );
}
