use pos_conformance::{
    execute_non_interference_pair, execute_wave8_non_interference_matrix,
    non_interference_capture_profiles_v1, non_interference_normalization_policy_v1,
    non_interference_surface_names_v1, normalize_non_interference_capture_v1, ExecutionModeV1,
    NonInterferenceCaptureV1, NonInterferenceExecutionErrorV1, NonInterferenceFixturePairV1,
    NonInterferenceMatrixMemberV1, NonInterferenceRawCaptureV1, NonInterferenceRawOperationalV1,
    NonInterferenceVariantV1, NON_INTERFERENCE_CASE_COUNT_V1,
};
use std::cell::Cell;
use std::fmt::Debug;

fn test_ok<T, E: Debug>(value: Result<T, E>) -> T {
    match value {
        Ok(value) => value,
        Err(error) => std::panic::resume_unwind(Box::new(format!(
            "unexpected non-interference fixture error: {error:?}"
        ))),
    }
}

fn test_some<T>(value: Option<T>) -> T {
    value.unwrap_or_else(|| {
        std::panic::resume_unwind(Box::new("expected non-interference divergence"))
    })
}

fn capture(bytes: &[u8]) -> NonInterferenceCaptureV1 {
    capture_for("NI-TOOL-001", bytes)
}

fn capture_for(fixture_id: &str, bytes: &[u8]) -> NonInterferenceCaptureV1 {
    test_ok(normalize_non_interference_capture_v1(
        fixture_id,
        raw_capture_for(fixture_id, bytes),
    ))
}

fn raw_capture_for(fixture_id: &str, bytes: &[u8]) -> NonInterferenceRawCaptureV1 {
    let names = non_interference_surface_names_v1(fixture_id).unwrap_or_default();
    NonInterferenceRawCaptureV1 {
        surface_names: names.iter().map(|name| (*name).to_owned()).collect(),
        authoritative: names.iter().map(|_| bytes.to_vec()).collect(),
        public: names.iter().map(|_| b"public-outcome".to_vec()).collect(),
        operational: names
            .iter()
            .map(|_| raw_operational_for(fixture_id))
            .collect(),
        unexpected_network_accesses: 0,
        provenance_digest: [9; 32],
    }
}

fn raw_operational_for(fixture_id: &str) -> NonInterferenceRawOperationalV1 {
    match fixture_id {
        "NI-TOOL-001" => NonInterferenceRawOperationalV1::CategoryCountDigest {
            category: 7,
            count: 1,
            digest: [8; 32],
            excluded_sensitive: b"provider text".to_vec(),
        },
        "NI-CACHE-002" => NonInterferenceRawOperationalV1::CountClass {
            class: 2,
            count: 1,
            excluded_sensitive: b"cache key and latency".to_vec(),
        },
        "NI-STATE-003" | "NI-NET-010" => NonInterferenceRawOperationalV1::CategoryCount {
            category: 3,
            count: 1,
            excluded_sensitive: b"diagnostic details".to_vec(),
        },
        "NI-OBS-004" | "NI-CRASH-012" => {
            NonInterferenceRawOperationalV1::CategoryCountPaddedLength {
                category: 4,
                count: 1,
                padded_length: 64,
                excluded_sensitive: b"stack path and raw identifiers".to_vec(),
            }
        }
        "NI-TIME-005" => NonInterferenceRawOperationalV1::OmitOperational {
            excluded_sensitive: b"wall time and duration".to_vec(),
        },
        _ => NonInterferenceRawOperationalV1::ByteExact(b"byte-exact".to_vec()),
    }
}

fn fixture() -> NonInterferenceFixturePairV1 {
    test_ok(NonInterferenceFixturePairV1::try_new(
        "NI-TOOL-001",
        NonInterferenceVariantV1::Denial,
        ExecutionModeV1::AirGapped,
        b"authorized-input".to_vec(),
        b"control-private-tool-result".to_vec(),
        b"canary-private-tool-result".to_vec(),
    ))
}

#[test]
fn complete_matrix_executes_every_control_and_canary_through_the_public_input() {
    let calls = Cell::new(0_u16);
    let cases = test_ok(execute_wave8_non_interference_matrix([7; 32], |run| {
        let call = calls.get();
        assert_eq!(
            run.member,
            if call.is_multiple_of(2) {
                NonInterferenceMatrixMemberV1::Control
            } else {
                NonInterferenceMatrixMemberV1::Canary
            }
        );
        assert!(!run
            .subject
            .permitted_input
            .windows(run.unauthorized_value.len())
            .any(|window| window == run.unauthorized_value));
        calls.set(call.saturating_add(1));
        let mut observed = run.subject.permitted_input.to_vec();
        observed.extend_from_slice(b":host-produced");
        Ok(capture_for(run.subject.fixture_id, &observed))
    }));

    assert_eq!(cases.len(), NON_INTERFERENCE_CASE_COUNT_V1);
    assert_eq!(usize::from(calls.get()), NON_INTERFERENCE_CASE_COUNT_V1 * 2);
    assert!(cases.iter().all(|case| {
        case.authoritative_equal
            && case.public_equal
            && case.operational_equal
            && case.first_divergence.is_none()
            && case.first_cross_mode_divergence.is_none()
            && case.authoritative_digest == case.canary_authoritative_digest
            && case.public_digest == case.canary_public_digest
            && case.operational_digest == case.canary_operational_digest
    }));
}

#[test]
fn captured_difference_reports_the_first_safe_coordinate_without_secret_bytes() {
    let call = Cell::new(0_u8);
    let pair = fixture();
    let result = test_ok(execute_non_interference_pair(&pair, |_| {
        let bytes = if call.replace(call.get().saturating_add(1)) == 0 {
            b"same-a".as_slice()
        } else {
            b"same-b".as_slice()
        };
        Ok(capture(bytes))
    }));

    assert!(!result.authoritative_equal);
    assert!(result.public_equal);
    assert!(result.operational_equal);
    let coordinate = test_some(result.first_divergence.as_ref());
    assert_eq!(coordinate.fixture_id, "NI-TOOL-001");
    assert_eq!(coordinate.surface_ordinal, 0);
    assert_eq!(coordinate.byte_offset, 5);

    let json = test_ok(serde_json::to_vec(&result));
    assert!(!json
        .windows(pair.control_unauthorized_value.len())
        .any(|window| window == pair.control_unauthorized_value));
    assert!(!json
        .windows(pair.canary_unauthorized_value.len())
        .any(|window| window == pair.canary_unauthorized_value));
}

#[test]
fn fixture_admission_rejects_more_than_the_declared_unauthorized_delta() {
    assert_eq!(
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"authorized-input includes control-secret".to_vec(),
            b"control-secret".to_vec(),
            b"canary-secret".to_vec(),
        ),
        Err(NonInterferenceExecutionErrorV1::FixtureInvalid)
    );

    let mut wrong_digest = fixture();
    wrong_digest.fixture_digest[0] ^= 1;
    assert_eq!(
        execute_non_interference_pair(&wrong_digest, |_| Ok(capture(b"unused"))),
        Err(NonInterferenceExecutionErrorV1::FixtureInvalid)
    );

    let mut invalid_fields = fixture();
    invalid_fields.permitted_input.clear();
    assert_eq!(
        execute_non_interference_pair(&invalid_fields, |_| Ok(capture(b"unused"))),
        Err(NonInterferenceExecutionErrorV1::FixtureInvalid)
    );
}

#[test]
fn unavailable_capture_and_unexpected_network_access_fail_closed() {
    assert_eq!(
        execute_non_interference_pair(&fixture(), |_| {
            Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
        }),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );

    assert_eq!(
        execute_non_interference_pair(&fixture(), |_| {
            let mut raw = raw_capture_for("NI-TOOL-001", b"captured");
            raw.unexpected_network_accesses = 1;
            normalize_non_interference_capture_v1("NI-TOOL-001", raw)
        }),
        Err(NonInterferenceExecutionErrorV1::UnexpectedNetworkAccess)
    );

    let call = Cell::new(false);
    assert_eq!(
        execute_non_interference_pair(&fixture(), |_| {
            if call.replace(true) {
                Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
            } else {
                Ok(capture(b"control"))
            }
        }),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );

    let call = Cell::new(false);
    assert_eq!(
        execute_non_interference_pair(&fixture(), |_| {
            let mut raw = raw_capture_for("NI-TOOL-001", b"captured");
            if call.replace(true) {
                raw.provenance_digest = [0; 32];
            }
            normalize_non_interference_capture_v1("NI-TOOL-001", raw)
        }),
        Err(NonInterferenceExecutionErrorV1::CaptureOutOfBounds)
    );
}

#[test]
fn every_fixture_bound_fails_closed() {
    let invalid_fixtures = [
        NonInterferenceFixturePairV1::try_new(
            "unknown",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"input".to_vec(),
            b"control".to_vec(),
            b"canary".to_vec(),
        ),
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            Vec::new(),
            b"control".to_vec(),
            b"canary".to_vec(),
        ),
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            vec![b'i'; 1024 * 1024 + 1],
            b"control".to_vec(),
            b"canary".to_vec(),
        ),
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"input".to_vec(),
            Vec::new(),
            b"canary".to_vec(),
        ),
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"input".to_vec(),
            b"control".to_vec(),
            Vec::new(),
        ),
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"input".to_vec(),
            vec![b'x'; 1024 * 1024 + 1],
            b"canary".to_vec(),
        ),
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"input".to_vec(),
            b"control".to_vec(),
            vec![b'x'; 1024 * 1024 + 1],
        ),
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"input".to_vec(),
            b"same".to_vec(),
            b"same".to_vec(),
        ),
        NonInterferenceFixturePairV1::try_new(
            "NI-TOOL-001",
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"authorized canary-secret input".to_vec(),
            b"control-secret".to_vec(),
            b"canary-secret".to_vec(),
        ),
    ];
    assert!(invalid_fixtures
        .iter()
        .all(|result| result == &Err(NonInterferenceExecutionErrorV1::FixtureInvalid)));
}

#[test]
fn in_bound_adversarial_near_match_is_admitted_in_linear_work() {
    let permitted = vec![b'a'; 1024 * 1024];
    let mut control = vec![b'a'; 512 * 1024];
    control.push(b'b');
    let pair = test_ok(NonInterferenceFixturePairV1::try_new(
        "NI-TOOL-001",
        NonInterferenceVariantV1::Success,
        ExecutionModeV1::Local,
        permitted,
        control,
        b"canary-value".to_vec(),
    ));
    assert_eq!(pair.fixture_id, "NI-TOOL-001");
    assert_ne!(pair.fixture_digest, [0; 32]);
}

#[test]
fn every_capture_bound_fails_closed() {
    let mut empty_value = raw_capture_for("NI-TOOL-001", b"captured");
    empty_value.authoritative[0].clear();
    let mut excessive_bytes = raw_capture_for("NI-TOOL-001", b"captured");
    excessive_bytes.authoritative[0] = vec![0; 1024 * 1024 + 1];
    let mut missing_provenance = raw_capture_for("NI-TOOL-001", b"captured");
    missing_provenance.provenance_digest = [0; 32];
    for raw in [empty_value, excessive_bytes, missing_provenance] {
        assert_eq!(
            normalize_non_interference_capture_v1("NI-TOOL-001", raw),
            Err(NonInterferenceExecutionErrorV1::CaptureOutOfBounds)
        );
    }
}

#[test]
fn capture_inventory_is_complete_ordered_and_fixture_bound() {
    assert!(non_interference_surface_names_v1("unknown").is_none());
    assert!(non_interference_normalization_policy_v1("unknown").is_none());
    assert_eq!(
        non_interference_normalization_policy_v1("NI-TOOL-001"),
        Some("count/category/digest; provider text absent")
    );
    let mut captures = Vec::new();

    let mut wrong_name = raw_capture_for("NI-TOOL-001", b"captured");
    wrong_name.surface_names[0] = "unknown surface".to_owned();
    captures.push(wrong_name);

    let mut reordered = raw_capture_for("NI-TOOL-001", b"captured");
    reordered.surface_names.swap(0, 1);
    captures.push(reordered);

    let mut missing_authoritative = raw_capture_for("NI-TOOL-001", b"captured");
    missing_authoritative.authoritative.pop();
    captures.push(missing_authoritative);

    let mut missing_public = raw_capture_for("NI-TOOL-001", b"captured");
    missing_public.public.pop();
    captures.push(missing_public);

    let mut missing_operational = raw_capture_for("NI-TOOL-001", b"captured");
    missing_operational.operational.pop();
    captures.push(missing_operational);

    for raw in captures {
        assert_eq!(
            normalize_non_interference_capture_v1("NI-TOOL-001", raw),
            Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
        );
    }
}

#[test]
fn canonical_capture_profiles_match_the_adr_059_public_contract() {
    let expected = [
        (
            "NI-TOOL-001",
            &[
                "Imported-service registry",
                "tool result handle",
                "Plugin imports",
                "staged EventDrafts",
                "public outcome",
                "audit record",
            ][..],
        ),
        (
            "NI-CACHE-002",
            &[
                "Cache API return",
                "snapshot bytes",
                "Plugin inputs",
                "typed errors",
                "logs/metrics",
                "evaluator bundle",
            ][..],
        ),
        (
            "NI-STATE-003",
            &[
                "Migration request/result",
                "activated state",
                "PluginInvocation",
                "PluginOutput",
                "EventDrafts",
                "quarantine/error",
            ][..],
        ),
        (
            "NI-OBS-004",
            &[
                "Structured logs",
                "metric names/labels/counts",
                "trace spans",
                "crash artifact",
                "public support bundle",
            ][..],
        ),
        (
            "NI-TIME-005",
            &[
                "Plugin imports",
                "deterministic deadline",
                "safe-stop record",
                "status/error",
                "logs/metrics",
                "evaluator input",
            ][..],
        ),
        (
            "NI-PUBLIC-006",
            &[
                "HTTP/Plugin error",
                "status transition",
                "cursor bytes",
                "page count",
                "response length/padding",
            ][..],
        ),
        (
            "NI-EVAL-007",
            &[
                "Export bundle",
                "manifest",
                "fixture descriptor",
                "evaluator stdin/files",
                "ConformanceReport",
            ][..],
        ),
        (
            "NI-FORK-008",
            &[
                "Fork parent/cut",
                "CounterfactualPlan",
                "RecomputationFrontier",
                "SuffixInvalidation",
                "snapshots",
                "checkpoints",
                "result",
                "ReproManifest",
                "exports",
            ][..],
        ),
        (
            "NI-ARCHIVE-009",
            &[
                "Member table",
                "archive bytes",
                "decompressed bundle",
                "digest",
                "evaluator import",
                "logs",
            ][..],
        ),
        (
            "NI-NET-010",
            &[
                "Capability checks",
                "attempted-call records",
                "retry count",
                "Plugin output",
                "Timeline",
                "logs",
                "evaluator bundle",
            ][..],
        ),
        (
            "NI-SERVICE-011",
            &[
                "Exact request digest",
                "frozen response projection",
                "call ordinal",
                "PluginInvocation",
                "generated dependency edges",
            ][..],
        ),
        (
            "NI-CRASH-012",
            &[
                "Guest error",
                "host error mapping",
                "quarantine",
                "crash report",
                "support archive",
                "next Tick status",
            ][..],
        ),
    ];
    let profiles = non_interference_capture_profiles_v1();
    assert_eq!(profiles.len(), expected.len());
    for (profile, (fixture_id, surfaces)) in profiles.iter().zip(expected) {
        assert_eq!(profile.fixture_id, fixture_id);
        assert!(profile
            .surface_names
            .iter()
            .map(String::as_str)
            .eq(surfaces.iter().copied()));
        assert_eq!(
            profile.variants,
            [
                NonInterferenceVariantV1::Success,
                NonInterferenceVariantV1::Denial,
                NonInterferenceVariantV1::WarmCache,
                NonInterferenceVariantV1::ColdCache,
            ]
        );
        assert_eq!(
            profile.modes,
            [
                ExecutionModeV1::Local,
                ExecutionModeV1::AirGapped,
                ExecutionModeV1::Replay,
                ExecutionModeV1::Fork,
            ]
        );
        assert_eq!(profile.normalization_version, 1);
        assert_eq!(profile.max_surface_bytes, 1024 * 1024);
        assert_ne!(profile.profile_digest, [0; 32]);
    }
}

#[test]
fn typed_normalizers_remove_only_declared_sensitive_operational_fields() {
    let secret = b"must-not-survive-normalization";
    for profile in non_interference_capture_profiles_v1() {
        let mut raw = raw_capture_for(&profile.fixture_id, b"authoritative");
        for operational in &mut raw.operational {
            match operational {
                NonInterferenceRawOperationalV1::CategoryCountDigest {
                    excluded_sensitive, ..
                }
                | NonInterferenceRawOperationalV1::CountClass {
                    excluded_sensitive, ..
                }
                | NonInterferenceRawOperationalV1::CategoryCount {
                    excluded_sensitive, ..
                }
                | NonInterferenceRawOperationalV1::CategoryCountPaddedLength {
                    excluded_sensitive,
                    ..
                }
                | NonInterferenceRawOperationalV1::OmitOperational { excluded_sensitive } => {
                    *excluded_sensitive = secret.to_vec();
                }
                NonInterferenceRawOperationalV1::ByteExact(_) => {}
            }
        }
        let normalized = test_ok(normalize_non_interference_capture_v1(
            &profile.fixture_id,
            raw,
        ));
        assert!(normalized
            .operational
            .iter()
            .all(|surface| !surface.windows(secret.len()).any(|window| window == secret)));
    }
}

#[test]
fn typed_normalizers_reject_wrong_shape_and_invalid_allowed_values() {
    let mut wrong_type = raw_capture_for("NI-CACHE-002", b"captured");
    wrong_type.operational[0] = NonInterferenceRawOperationalV1::ByteExact(b"opaque".to_vec());
    assert_eq!(
        normalize_non_interference_capture_v1("NI-CACHE-002", wrong_type),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );

    let mut zero_digest = raw_capture_for("NI-TOOL-001", b"captured");
    zero_digest.operational[0] = NonInterferenceRawOperationalV1::CategoryCountDigest {
        category: 1,
        count: 1,
        digest: [0; 32],
        excluded_sensitive: Vec::new(),
    };
    assert_eq!(
        normalize_non_interference_capture_v1("NI-TOOL-001", zero_digest),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );

    let mut invalid_padding = raw_capture_for("NI-OBS-004", b"captured");
    invalid_padding.operational[0] = NonInterferenceRawOperationalV1::CategoryCountPaddedLength {
        category: 1,
        count: 1,
        padded_length: 63,
        excluded_sensitive: Vec::new(),
    };
    assert_eq!(
        normalize_non_interference_capture_v1("NI-OBS-004", invalid_padding),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );

    let mut empty_exact = raw_capture_for("NI-PUBLIC-006", b"captured");
    empty_exact.operational[0] = NonInterferenceRawOperationalV1::ByteExact(Vec::new());
    assert_eq!(
        normalize_non_interference_capture_v1("NI-PUBLIC-006", empty_exact),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );
}

#[test]
fn captured_output_digests_bind_the_row_surface_profile() {
    let execute = |fixture_id| {
        let pair = test_ok(NonInterferenceFixturePairV1::try_new(
            fixture_id,
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            b"same-permitted-input".to_vec(),
            b"same-control-secret".to_vec(),
            b"same-canary-secret".to_vec(),
        ));
        test_ok(execute_non_interference_pair(&pair, |_| {
            Ok(capture_for(fixture_id, b"same-captured-bytes"))
        }))
    };
    let tool = execute("NI-TOOL-001");
    let cache = execute("NI-CACHE-002");

    assert_ne!(tool.authoritative_digest, cache.authoritative_digest);
    assert_ne!(tool.public_digest, cache.public_digest);
    assert_ne!(tool.operational_digest, cache.operational_digest);
}

#[test]
fn divergence_order_covers_length_surface_and_category_boundaries() {
    let cases = [
        (capture(b"same"), capture(b"same-longer"), (0_u16, 4_u64)),
        (
            capture(b"same"),
            {
                let mut raw = raw_capture_for("NI-TOOL-001", b"same");
                raw.authoritative[1] = b"extra".to_vec();
                test_ok(normalize_non_interference_capture_v1("NI-TOOL-001", raw))
            },
            (1, 0),
        ),
        (
            capture(b"same"),
            {
                let mut raw = raw_capture_for("NI-TOOL-001", b"same");
                raw.public[0] = b"Public-outcome".to_vec();
                test_ok(normalize_non_interference_capture_v1("NI-TOOL-001", raw))
            },
            (0, 4),
        ),
        (
            capture(b"same"),
            {
                let mut raw = raw_capture_for("NI-TOOL-001", b"same");
                raw.operational[0] = NonInterferenceRawOperationalV1::CategoryCountDigest {
                    category: 7,
                    count: 2,
                    digest: [8; 32],
                    excluded_sensitive: b"different secret".to_vec(),
                };
                test_ok(normalize_non_interference_capture_v1("NI-TOOL-001", raw))
            },
            (0, 23),
        ),
    ];
    for (control, canary, expected) in cases {
        let call = Cell::new(false);
        let result = test_ok(execute_non_interference_pair(&fixture(), |_| {
            Ok(if call.replace(true) {
                canary.clone()
            } else {
                control.clone()
            })
        }));
        let coordinate = test_some(result.first_divergence);
        assert_eq!(
            (coordinate.surface_ordinal, coordinate.byte_offset),
            expected
        );
    }
}

#[test]
fn unknown_serialized_fixture_and_result_fields_are_rejected() {
    let mut fixture_json = test_ok(serde_json::to_value(fixture()));
    fixture_json["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<NonInterferenceFixturePairV1>(fixture_json).is_err());

    let result = test_ok(execute_non_interference_pair(&fixture(), |_| {
        Ok(capture(b"same"))
    }));
    let mut result_json = test_ok(serde_json::to_value(result));
    result_json["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<pos_conformance::NonInterferenceCaseV1>(result_json).is_err());
}

#[test]
fn divergent_outcomes_round_trip_at_the_strict_public_wire_seam() {
    let call = Cell::new(false);
    let outcome = test_ok(execute_non_interference_pair(&fixture(), |_| {
        Ok(if call.replace(true) {
            capture(b"canary")
        } else {
            capture(b"control")
        })
    }));
    let encoded = test_ok(outcome.to_canonical_cbor());
    assert_eq!(
        test_ok(pos_conformance::NonInterferenceCaseV1::from_canonical_cbor(
            &encoded
        )),
        outcome
    );

    let mut value: ciborium::Value = test_ok(ciborium::from_reader(encoded.as_slice()));
    for (field, invalid) in [
        (0, ciborium::Value::Integer(1_u64.into())),
        (1, ciborium::Value::Integer(99_u64.into())),
        (2, ciborium::Value::Integer(99_u64.into())),
        (3, ciborium::Value::Text("not-a-surface".to_owned())),
        (4, ciborium::Value::Text("not-an-offset".to_owned())),
    ] {
        let mut malformed = value.clone();
        let fields = malformed
            .as_array_mut()
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("outcome must be an array")));
        let coordinate = fields[14]
            .as_array_mut()
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("coordinate must be an array")));
        coordinate[field] = invalid;
        let mut bytes = Vec::new();
        test_ok(ciborium::into_writer(&malformed, &mut bytes));
        assert!(pos_conformance::NonInterferenceCaseV1::from_canonical_cbor(&bytes).is_err());
    }

    let fields = value
        .as_array_mut()
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("outcome must be an array")));
    let coordinate = fields[14]
        .as_array_mut()
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("coordinate must be an array")));
    coordinate[3] = ciborium::Value::Integer(65_536_u64.into());
    let mut invalid = Vec::new();
    test_ok(ciborium::into_writer(&value, &mut invalid));
    assert!(pos_conformance::NonInterferenceCaseV1::from_canonical_cbor(&invalid).is_err());

    let mut trailing = test_ok(outcome.to_canonical_cbor());
    trailing.push(0);
    assert!(pos_conformance::NonInterferenceCaseV1::from_canonical_cbor(&trailing).is_err());
}

#[test]
fn complete_matrix_propagates_a_missing_host_execution() {
    assert_eq!(
        execute_wave8_non_interference_matrix([3; 32], |_| {
            Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
        }),
        Err(NonInterferenceExecutionErrorV1::CaptureUnavailable)
    );
}

#[test]
fn complete_matrix_reports_the_first_cross_mode_surface_difference() {
    let cases = test_ok(execute_wave8_non_interference_matrix([4; 32], |run| {
        let bytes = if run.subject.mode == ExecutionModeV1::AirGapped {
            b"air-gapped".as_slice()
        } else {
            b"local-output".as_slice()
        };
        Ok(capture_for(run.subject.fixture_id, bytes))
    }));

    assert!(cases[0].first_cross_mode_divergence.is_none());
    let air_gapped = test_some(cases[1].first_cross_mode_divergence.as_ref());
    assert_eq!(air_gapped.fixture_id, "NI-TOOL-001");
    assert_eq!(air_gapped.variant, NonInterferenceVariantV1::Success);
    assert_eq!(air_gapped.mode, ExecutionModeV1::AirGapped);
    assert_eq!(air_gapped.surface_ordinal, 0);
    assert_eq!(air_gapped.byte_offset, 0);

    let encoded = test_ok(cases[1].to_canonical_cbor());
    assert_eq!(
        test_ok(pos_conformance::NonInterferenceCaseV1::from_canonical_cbor(
            &encoded
        )),
        cases[1]
    );
    let mut malformed: ciborium::Value = test_ok(ciborium::from_reader(encoded.as_slice()));
    let fields = malformed
        .as_array_mut()
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("outcome must be an array")));
    fields[15] = ciborium::Value::Text("not-a-coordinate".to_owned());
    let mut malformed_bytes = Vec::new();
    test_ok(ciborium::into_writer(&malformed, &mut malformed_bytes));
    assert!(pos_conformance::NonInterferenceCaseV1::from_canonical_cbor(&malformed_bytes).is_err());

    assert!(cases[2].first_cross_mode_divergence.is_none());
    assert!(cases[3].first_cross_mode_divergence.is_none());
}
