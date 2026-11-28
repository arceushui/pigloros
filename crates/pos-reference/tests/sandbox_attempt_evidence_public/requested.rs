//! RQE1: the R9 §7.1 and §7.2 vectors, the R10 §8.2 vector, and R9 §6
//! rules 1 to 3 as R10 §7 extends them.

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    DbusProperty, DbusValue, RequestedConfigurationEvidence, RequestedConfigurationEvidenceFields,
    RequestedConfigurationStatus, SandboxProviderProtocolError as ProtocolError,
};

use super::oracle::{
    bounds_raw_size, checks_envelope, encode, filled, integer, rejects_every_retyped_node,
    rejects_malformed_encodings, seal, text, unhex, with, TestResult,
};
use super::vectors::{RQE1_A, RQE1_A_DIGEST, RQE1_B, RQE1_B_DIGEST, RQE1_C, RQE1_C_DIGEST};

fn decode(bytes: &[u8]) -> Result<(), ProtocolError> {
    RequestedConfigurationEvidence::from_canonical_cbor(bytes).map(|_| ())
}

fn property(name: &str, value: DbusValue) -> DbusProperty {
    DbusProperty {
        name: name.to_owned(),
        value,
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// The R9 §7.1 fields, written out from the R9 text.
fn vector_a_fields() -> RequestedConfigurationEvidenceFields {
    let requested = vec![
        property("TasksMax", DbusValue::U64(64)),
        property("NoNewPrivileges", DbusValue::Bool(true)),
        property(
            "RestrictAddressFamilies",
            DbusValue::FlaggedStrings(true, strings(&["AF_UNIX"])),
        ),
    ];
    let mut readback = requested.clone();
    readback.insert(
        2,
        property(
            "RootImagePolicy",
            DbusValue::String("root=verity+signed+absent".to_owned()),
        ),
    );
    RequestedConfigurationEvidenceFields {
        attempt_id: [0x11; 16],
        agr1_digest: [0x22; 32],
        status: RequestedConfigurationStatus::Verified,
        requested: Some(requested),
        readback: Some(readback),
    }
}

fn dbus(code: u64, payload: Value) -> Value {
    Value::Array(vec![integer(code), payload])
}

fn entry(name: &str, value: Value) -> Value {
    Value::Array(vec![text(name), value])
}

/// Sort properties by the canonical encoding of their names.
fn sorted(entries: Vec<Value>) -> TestResult<Vec<Value>> {
    let mut keyed = Vec::new();
    for entry in entries {
        let key = match &entry {
            Value::Array(parts) => encode(&parts[0])?,
            _ => return Err("property is not an array".into()),
        };
        keyed.push((key, entry));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, entry)| entry).collect())
}

/// One property of every value code, with its R9 §4.3 readback.
fn every_code() -> TestResult<(Vec<Value>, Vec<Value>)> {
    let shared = vec![
        entry("Type", dbus(1, text("exec"))),
        entry("UMask", dbus(3, integer(63))),
        entry("NoNewPrivileges", dbus(0, Value::Bool(true))),
        entry("MemoryMax", dbus(2, integer(1024))),
        entry(
            "CapabilityBoundingSet",
            dbus(4, Value::Array(vec![text("")])),
        ),
        entry(
            "SystemCallFilter",
            dbus(
                5,
                Value::Array(vec![Value::Bool(true), Value::Array(vec![text("read")])]),
            ),
        ),
        entry(
            "BindReadOnlyPaths",
            dbus(
                6,
                Value::Array(vec![Value::Array(vec![
                    text("/launcher"),
                    text("/run/launcher"),
                    Value::Bool(false),
                    integer(1),
                ])]),
            ),
        ),
        entry(
            "TemporaryFileSystem",
            dbus(
                7,
                Value::Array(vec![Value::Array(vec![text("/work"), text("size=4096")])]),
            ),
        ),
        entry(
            "ExecStart",
            dbus(
                8,
                Value::Array(vec![Value::Array(vec![
                    text("/run/launcher"),
                    Value::Array(vec![text("/run/launcher"), text("00ff")]),
                    Value::Bool(false),
                ])]),
            ),
        ),
    ];
    let mut requested = shared.clone();
    requested.push(entry(
        "ExtraFileDescriptors",
        dbus(9, Value::Array(vec![text("release")])),
    ));
    requested.push(entry("StandardInputFileDescriptor", dbus(10, Value::Null)));
    let mut readback = shared;
    readback.push(entry(
        "ExtraFileDescriptors",
        dbus(4, Value::Array(vec![text("release")])),
    ));
    readback.push(entry("StandardInputFileDescriptor", dbus(1, text(""))));
    readback.push(entry("RootImagePolicy", dbus(1, text("root=verity"))));
    Ok((sorted(requested)?, sorted(readback)?))
}

fn record(
    status: u64,
    requested: Option<Vec<Value>>,
    readback: Option<Vec<Value>>,
) -> TestResult<Vec<u8>> {
    seal(
        "RQE1",
        vec![
            text("RQE1"),
            integer(1),
            filled(0x11, 16),
            filled(0x22, 32),
            integer(status),
            requested.map_or(Value::Null, Value::Array),
            readback.map_or(Value::Null, Value::Array),
        ],
    )
}

fn every_code_record() -> TestResult<Vec<u8>> {
    let (requested, readback) = every_code()?;
    record(0, Some(requested), Some(readback))
}

/// Only the requested list, with no readback (status 3), so a list rule
/// is tested alone.
fn requested_only(requested: Vec<Value>) -> TestResult<Vec<u8>> {
    record(3, Some(requested), None)
}

fn one_property(value: Value) -> TestResult<Vec<u8>> {
    requested_only(vec![entry("Value", value)])
}

#[test]
fn rqe1_vectors_decode_and_encode_byte_for_byte() -> TestResult {
    let bytes = unhex(RQE1_A)?;
    let decoded = RequestedConfigurationEvidence::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded.fields(), &vector_a_fields());
    assert_eq!(decoded.digest().to_vec(), unhex(RQE1_A_DIGEST)?);
    assert_eq!(decoded.canonical_bytes(), bytes.as_slice());
    let encoded = RequestedConfigurationEvidence::new(&vector_a_fields())?;
    assert_eq!(encoded, decoded);

    let bytes = unhex(RQE1_B)?;
    let fields = RequestedConfigurationEvidenceFields {
        status: RequestedConfigurationStatus::NotRequested,
        requested: None,
        readback: None,
        ..vector_a_fields()
    };
    let decoded = RequestedConfigurationEvidence::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded.fields(), &fields);
    assert_eq!(decoded.digest().to_vec(), unhex(RQE1_B_DIGEST)?);
    assert_eq!(
        RequestedConfigurationEvidence::new(&fields)?.canonical_bytes(),
        bytes.as_slice()
    );
    Ok(())
}

#[test]
fn rqe1_every_value_code_round_trips() -> TestResult {
    let bytes = every_code_record()?;
    let decoded = RequestedConfigurationEvidence::from_canonical_cbor(&bytes)?;
    let requested = decoded.fields().requested.clone().ok_or("requested list")?;
    let mut codes = requested
        .iter()
        .map(|property| property.value.code())
        .collect::<Vec<_>>();
    codes.sort_unstable();
    assert_eq!(codes, (0..=10).collect::<Vec<_>>());
    let values = requested
        .into_iter()
        .map(|property| property.value)
        .collect::<Vec<_>>();
    for expected in [
        DbusValue::String("exec".to_owned()),
        DbusValue::U32(63),
        DbusValue::Bool(true),
        DbusValue::U64(1024),
        DbusValue::StringArray(strings(&[""])),
        DbusValue::FlaggedStrings(true, strings(&["read"])),
        DbusValue::BindPaths(vec![(
            "/launcher".to_owned(),
            "/run/launcher".to_owned(),
            false,
            1,
        )]),
        DbusValue::StringPairs(vec![("/work".to_owned(), "size=4096".to_owned())]),
        DbusValue::Commands(vec![(
            "/run/launcher".to_owned(),
            strings(&["/run/launcher", "00ff"]),
            false,
        )]),
        DbusValue::DescriptorNames(strings(&["release"])),
        DbusValue::Descriptor,
    ] {
        assert!(values.contains(&expected), "{expected:?} did not decode");
    }
    assert_eq!(
        RequestedConfigurationEvidence::new(decoded.fields())?.canonical_bytes(),
        bytes.as_slice()
    );
    Ok(())
}

#[test]
fn rqe1_rule_1_envelope_size_and_types() -> TestResult {
    checks_envelope(&unhex(RQE1_A)?, decode)?;
    rejects_malformed_encodings(&unhex(RQE1_A)?, decode);
    bounds_raw_size(1024 * 1024, decode);
    rejects_every_retyped_node(&unhex(RQE1_A)?, decode)?;
    rejects_every_retyped_node(&every_code_record()?, decode)?;
    rejects_every_retyped_node(&unhex(RQE1_B)?, decode)
}

#[test]
fn rqe1_rule_2_zero_identities_and_status_nullability() -> TestResult {
    let vector = unhex(RQE1_A)?;
    for (index, length) in [(2, 16), (3, 32)] {
        assert_eq!(
            decode(&with(&vector, &[index], filled(0, length))?),
            Err(ProtocolError::FieldOutOfBounds)
        );
    }
    assert_eq!(
        decode(&with(&vector, &[4], integer(4))?),
        Err(ProtocolError::FieldOutOfBounds)
    );
    let fields = vector_a_fields();
    let requested = fields.requested.ok_or("requested")?;
    let readback = fields.readback.ok_or("readback")?;
    for status in 0_u8..=3 {
        for (has_requested, has_readback) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let shaped = RequestedConfigurationEvidenceFields {
                attempt_id: [0x11; 16],
                agr1_digest: [0x22; 32],
                status: RequestedConfigurationStatus::try_from(status)?,
                requested: has_requested.then(|| requested.clone()),
                readback: has_readback.then(|| readback.clone()),
            };
            let legal = matches!(
                (status, has_requested, has_readback),
                (0 | 2, true, true) | (1, false, false) | (3, true, false)
            );
            let result = RequestedConfigurationEvidence::new(&shaped).map(|_| ());
            if legal {
                assert_eq!(result, Ok(()), "status {status} rejected");
            } else {
                assert_eq!(
                    result,
                    Err(ProtocolError::InconsistentFields),
                    "status {status} accepted {has_requested} {has_readback}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn rqe1_property_lists_are_bounded() -> TestResult {
    let named = |count: usize| {
        (0..count)
            .map(|index| entry(&format!("P{index:03}"), dbus(2, integer(1))))
            .collect::<Vec<_>>()
    };
    assert_eq!(decode(&requested_only(named(128))?), Ok(()));
    assert_eq!(
        decode(&requested_only(named(129))?),
        Err(ProtocolError::FieldOutOfBounds)
    );
    assert_eq!(
        decode(&requested_only(Vec::new())?),
        Err(ProtocolError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn rqe1_property_names_follow_the_cddl_rule() -> TestResult {
    let longest = format!("A{}", "b".repeat(63));
    let too_long = format!("{longest}c");
    for (name, accepted) in [
        ("A", true),
        ("Z9", true),
        (longest.as_str(), true),
        (too_long.as_str(), false),
        ("", false),
        ("aB", false),
        ("9B", false),
        ("Tasks_Max", false),
        ("Tasks Max", false),
        ("TasksMäx", false),
    ] {
        let result = decode(&requested_only(vec![entry(name, dbus(2, integer(1)))])?);
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::FieldOutOfBounds)
        };
        assert_eq!(result, expected, "name {name:?}");
    }
    Ok(())
}

#[test]
fn rqe1_rule_3_properties_are_strictly_sorted_length_first() -> TestResult {
    let short = entry("Zz", dbus(2, integer(1)));
    let long = entry("Aaa", dbus(2, integer(1)));
    assert_eq!(
        decode(&requested_only(vec![short.clone(), long.clone()])?),
        Ok(())
    );
    assert_eq!(
        decode(&requested_only(vec![long, short.clone()])?),
        Err(ProtocolError::NonCanonicalOrder)
    );
    assert_eq!(
        decode(&requested_only(vec![short.clone(), short])?),
        Err(ProtocolError::NonCanonicalOrder)
    );
    Ok(())
}

#[test]
fn rqe1_value_codes_and_payloads_are_bounded() -> TestResult {
    let longest = "x".repeat(262_144);
    let texts = |count: usize| Value::Array((0..count).map(|_| text("a")).collect());
    let bind = Value::Array(vec![text("/a"), text("/b"), Value::Bool(true), integer(0)]);
    let pair = Value::Array(vec![text("/work"), text("size=1")]);
    let command =
        |arguments: usize| Value::Array(vec![text("/l"), texts(arguments), Value::Bool(false)]);
    let repeated = |value: &Value, count: usize| Value::Array(vec![value.clone(); count]);
    for (value, accepted) in [
        (dbus(12, integer(0)), false),
        (dbus(1, text(&longest)), true),
        (dbus(1, text(&format!("{longest}y"))), false),
        (dbus(3, integer(u64::from(u32::MAX))), true),
        (dbus(3, integer(u64::from(u32::MAX) + 1)), false),
        (dbus(2, integer(u64::MAX)), true),
        (dbus(4, texts(512)), true),
        (
            dbus(5, Value::Array(vec![Value::Bool(false), texts(512)])),
            true,
        ),
        (dbus(6, repeated(&bind, 64)), true),
        (dbus(6, repeated(&bind, 65)), false),
        (dbus(7, repeated(&pair, 64)), true),
        (dbus(7, repeated(&pair, 65)), false),
        (dbus(8, repeated(&command(256), 8)), true),
        (dbus(8, repeated(&command(0), 9)), false),
        (dbus(8, Value::Array(vec![command(257)])), false),
        (dbus(9, texts(8)), true),
        (dbus(9, texts(9)), false),
        (dbus(9, Value::Array(vec![text(&"n".repeat(255))])), true),
        (dbus(9, Value::Array(vec![text(&"n".repeat(256))])), false),
        (dbus(9, Value::Array(vec![text("")])), false),
    ] {
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::FieldOutOfBounds)
        };
        assert_eq!(decode(&one_property(value)?), expected);
    }
    Ok(())
}

/// Code 11 is `SuccessExitStatus`'s `(aiai)` (R17-E6): at most 255 exit statuses and 64 signals,
/// each in `0..=255` and strictly increasing.
#[test]
fn rqe1_code_11_lists_exit_statuses_and_signals() -> TestResult {
    let numbers = |first: u64, last: u64| Value::Array((first..=last).map(integer).collect());
    let pair = |statuses: Value, signals: Value| dbus(11, Value::Array(vec![statuses, signals]));
    let empty = || Value::Array(Vec::new());
    for (value, accepted) in [
        (pair(numbers(1, 255), numbers(1, 64)), true),
        (pair(empty(), empty()), true),
        (pair(numbers(0, 0), numbers(1, 1)), true),
        (pair(numbers(0, 255), numbers(1, 64)), false),
        (pair(numbers(1, 255), numbers(1, 65)), false),
        (pair(numbers(1, 256), numbers(1, 64)), false),
        (
            pair(Value::Array(vec![integer(2), integer(1)]), empty()),
            false,
        ),
        (
            pair(Value::Array(vec![integer(1), integer(1)]), empty()),
            false,
        ),
        (pair(empty(), Value::Array(vec![integer(300)])), false),
        (pair(Value::Array(vec![integer(256)]), empty()), false),
        (pair(Value::Array(vec![integer(255)]), empty()), true),
        (dbus(11, Value::Array(vec![empty()])), false),
        (dbus(11, integer(0)), false),
    ] {
        assert_eq!(
            decode(&one_property(value.clone())?).is_ok(),
            accepted,
            "{value:?}"
        );
    }
    Ok(())
}

#[test]
fn rqe1_records_above_one_mebibyte_are_rejected() -> TestResult {
    let longest = text(&"x".repeat(262_144));
    let properties = (0..4)
        .map(|index| entry(&format!("P{index}"), dbus(1, longest.clone())))
        .collect();
    assert_eq!(
        decode(&requested_only(properties)?),
        Err(ProtocolError::FieldOutOfBounds)
    );
    Ok(())
}

/// Replace one readback entry's value, keeping the list sorted.
fn readback_with(status: u64, name: &str, value: &Value) -> TestResult<Vec<u8>> {
    let (requested, mut readback) = every_code()?;
    for property in &mut readback {
        if let Value::Array(parts) = property {
            if parts[0] == text(name) {
                parts[1] = value.clone();
            }
        }
    }
    record(status, Some(requested), Some(readback))
}

#[test]
fn rqe1_rule_3_readback_codes_follow_the_table() -> TestResult {
    for status in [0, 2] {
        for (name, value) in [
            ("RootImagePolicy", dbus(4, Value::Array(Vec::new()))),
            (
                "ExtraFileDescriptors",
                dbus(9, Value::Array(vec![text("release")])),
            ),
            ("MemoryMax", dbus(3, integer(1024))),
            ("Type", dbus(2, integer(1))),
            // R10: code 10 is never read back.
            ("StandardInputFileDescriptor", dbus(10, Value::Null)),
            (
                "StandardInputFileDescriptor",
                dbus(4, Value::Array(Vec::new())),
            ),
        ] {
            assert_eq!(
                decode(&readback_with(status, name, &value)?),
                Err(ProtocolError::InconsistentFields),
                "status {status} accepted {name}"
            );
        }
        // A changed value under the right code is a mismatch, not a code error.
        assert_eq!(
            decode(&readback_with(status, "MemoryMax", &dbus(2, integer(7)))?),
            Ok(())
        );
    }
    Ok(())
}

#[test]
fn rqe1_rule_3_verified_readback_names_requested_and_root_image_policy() -> TestResult {
    let (requested, readback) = every_code()?;
    let without = |name: &str| {
        readback
            .iter()
            .filter(|entry| match entry {
                Value::Array(parts) => parts[0] != text(name),
                _ => true,
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    let unknown = sorted(
        readback
            .iter()
            .cloned()
            .chain([entry("Unrequested", dbus(1, text("x")))])
            .collect(),
    )?;
    for (status, listed, accepted) in [
        (0, without("RootImagePolicy"), false),
        (0, without("UMask"), false),
        (2, without("RootImagePolicy"), true),
        (2, without("UMask"), true),
        (0, unknown.clone(), false),
        (2, unknown, false),
    ] {
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::InconsistentFields)
        };
        assert_eq!(
            decode(&record(status, Some(requested.clone()), Some(listed))?),
            expected
        );
    }
    Ok(())
}

#[test]
fn rqe1_encoder_applies_the_decoder_rules() -> TestResult {
    let mut fields = vector_a_fields();
    fields.requested = Some(vec![property("tasks", DbusValue::U64(1))]);
    assert_eq!(
        RequestedConfigurationEvidence::new(&fields),
        Err(ProtocolError::FieldOutOfBounds)
    );
    let mut unsorted = vector_a_fields();
    if let Some(requested) = unsorted.requested.as_mut() {
        requested.reverse();
    }
    assert_eq!(
        RequestedConfigurationEvidence::new(&unsorted),
        Err(ProtocolError::NonCanonicalOrder)
    );
    let mut descriptors = vector_a_fields();
    descriptors.status = RequestedConfigurationStatus::ReadbackUnavailable;
    descriptors.readback = None;
    descriptors.requested = Some(vec![property(
        "ExtraFileDescriptors",
        DbusValue::DescriptorNames(strings(&["release"])),
    )]);
    let decoded = RequestedConfigurationEvidence::new(&descriptors)?;
    assert_eq!(decoded.fields(), &descriptors);
    Ok(())
}

#[test]
fn rqe1_rule_3_requested_codes_follow_the_table() -> TestResult {
    let flagged = || Value::Array(vec![Value::Bool(true), Value::Array(Vec::new())]);
    let empty = || Value::Array(Vec::new());
    for (name, code, payload) in [
        ("RootDirectory", 1, text("/run/root")),
        ("SystemCallFilter", 5, flagged()),
        ("RestrictAddressFamilies", 5, flagged()),
        ("BindReadOnlyPaths", 6, empty()),
        ("MemoryMax", 2, integer(1)),
        ("MemorySwapMax", 2, integer(1)),
        ("TasksMax", 2, integer(1)),
        ("CPUQuotaPerSecUSec", 2, integer(1)),
        ("RuntimeMaxUSec", 2, integer(1)),
        ("LimitNOFILE", 2, integer(1)),
        ("LimitFSIZE", 2, integer(1)),
        ("FileDescriptorStoreMax", 3, integer(1)),
        ("TemporaryFileSystem", 7, empty()),
        ("ExecStart", 8, empty()),
        ("ExtraFileDescriptors", 9, empty()),
        ("StandardInput", 1, text("null")),
        ("StandardOutput", 1, text("null")),
        ("StandardError", 1, text("null")),
        ("StandardInputFileDescriptor", 10, Value::Null),
        ("StandardOutputFileDescriptor", 10, Value::Null),
        ("StandardErrorFileDescriptor", 10, Value::Null),
    ] {
        assert_eq!(
            decode(&requested_only(vec![entry(name, dbus(code, payload))])?),
            Ok(()),
            "{name}"
        );
        // Every fixed name rejects a value of another code.
        let wrong = if code == 2 {
            dbus(3, integer(1))
        } else {
            dbus(2, integer(1))
        };
        assert_eq!(
            decode(&requested_only(vec![entry(name, wrong)])?),
            Err(ProtocolError::InconsistentFields),
            "{name}"
        );
    }
    assert_eq!(
        decode(&requested_only(vec![entry(
            "RootImagePolicy",
            dbus(1, text("x"))
        )])?),
        Err(ProtocolError::InconsistentFields)
    );
    // A static hardening property keeps its own signature.
    assert_eq!(
        decode(&requested_only(vec![entry("Type", dbus(1, text("exec")))])?),
        Ok(())
    );
    for status in [0, 2] {
        let (mut requested, mut readback) = every_code()?;
        for list in [&mut requested, &mut readback] {
            for property in list.iter_mut() {
                if let Value::Array(parts) = property {
                    if parts[0] == text("MemoryMax") {
                        parts[1] = dbus(3, integer(1024));
                    }
                }
            }
        }
        assert_eq!(
            decode(&record(status, Some(requested), Some(readback))?),
            Err(ProtocolError::InconsistentFields),
            "status {status}"
        );
    }
    Ok(())
}

const STDIO_ENUMS: [&str; 3] = ["StandardError", "StandardInput", "StandardOutput"];
const STDIO_DESCRIPTORS: [&str; 3] = [
    "StandardErrorFileDescriptor",
    "StandardInputFileDescriptor",
    "StandardOutputFileDescriptor",
];

/// The R10 §8.2 fields, written out from the R10 text.
fn vector_c_fields() -> RequestedConfigurationEvidenceFields {
    let enums = STDIO_ENUMS.map(|name| property(name, DbusValue::String("null".to_owned())));
    let requested = enums
        .iter()
        .cloned()
        .chain(STDIO_DESCRIPTORS.map(|name| property(name, DbusValue::Descriptor)))
        .collect();
    let readback = enums
        .into_iter()
        .chain([property(
            "RootImagePolicy",
            DbusValue::String("root=verity+signed+absent".to_owned()),
        )])
        .chain(STDIO_DESCRIPTORS.map(|name| property(name, DbusValue::String(String::new()))))
        .collect();
    RequestedConfigurationEvidenceFields {
        attempt_id: [0x11; 16],
        agr1_digest: [0x22; 32],
        status: RequestedConfigurationStatus::Verified,
        requested: Some(requested),
        readback: Some(readback),
    }
}

/// RQE1-C with every entry named `name` in the list at `list` (5 requested,
/// 6 readback) replaced by `value`, or removed when it is `None`.
fn vector_c_with(
    status: u64,
    list: usize,
    name: &str,
    value: Option<&Value>,
) -> TestResult<Vec<u8>> {
    super::oracle::edit(&unhex(RQE1_C)?, |fields| {
        fields[4] = integer(status);
        let Value::Array(entries) = &mut fields[list] else {
            return Err("property list".into());
        };
        entries.retain_mut(|entry| match entry {
            Value::Array(parts) if parts[0] == text(name) => value.is_some_and(|value| {
                parts[1] = value.clone();
                true
            }),
            _ => true,
        });
        Ok(())
    })
}

#[test]
fn rqe1_c_vector_decodes_and_encodes_byte_for_byte() -> TestResult {
    let bytes = unhex(RQE1_C)?;
    let decoded = RequestedConfigurationEvidence::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded.fields(), &vector_c_fields());
    assert_eq!(decoded.digest().to_vec(), unhex(RQE1_C_DIGEST)?);
    assert_eq!(
        RequestedConfigurationEvidence::new(&vector_c_fields())?.canonical_bytes(),
        bytes.as_slice()
    );
    rejects_every_retyped_node(&bytes, decode)
}

#[test]
fn rqe1_r10_rule_3_code_10_names_only_the_stdio_descriptors() -> TestResult {
    for name in ["StandardInput", "ExtraFileDescriptors", "Unfixed"] {
        assert_eq!(
            decode(&requested_only(vec![entry(name, dbus(10, Value::Null))])?),
            Err(ProtocolError::InconsistentFields),
            "{name}"
        );
    }
    assert_eq!(
        decode(&requested_only(vec![entry(
            "StandardOutputFileDescriptor",
            dbus(10, integer(1))
        )])?),
        Err(ProtocolError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn rqe1_r10_rule_3_a_verified_readback_has_the_stdio_values() -> TestResult {
    let null = || Some(dbus(1, text("null")));
    let empty = || Some(dbus(1, text("")));
    for (list, name, value, verified) in [
        // `StandardErrorFileDescriptor` omitted from `requested`.
        (5, "StandardErrorFileDescriptor", None, false),
        (6, "StandardErrorFileDescriptor", None, false),
        (6, "StandardOutput", Some(dbus(1, text("journal"))), false),
        (6, "StandardInput", Some(dbus(1, text("fd"))), false),
        (6, "StandardError", Some(dbus(1, text("inherit"))), false),
        (
            6,
            "StandardInputFileDescriptor",
            Some(dbus(1, text("stdin"))),
            false,
        ),
        (
            6,
            "StandardErrorFileDescriptor",
            Some(dbus(1, text("x"))),
            false,
        ),
        (6, "StandardOutputFileDescriptor", empty(), true),
        (6, "StandardError", null(), true),
    ] {
        assert_eq!(
            decode(&vector_c_with(0, list, name, value.as_ref())?),
            if verified {
                Ok(())
            } else {
                Err(ProtocolError::InconsistentFields)
            },
            "status 0: {name} {value:?}"
        );
        // A mismatch records whatever was read back under the right code.
        if value.is_some() {
            assert_eq!(
                decode(&vector_c_with(2, list, name, value.as_ref())?),
                Ok(())
            );
        }
    }
    Ok(())
}
