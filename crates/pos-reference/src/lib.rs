#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! A deliberately dependency-light second evaluator for Wave 8 evidence.
//!
//! This crate parses the portable JSON envelope as untyped data and does not
//! import the conformance crate, experiment host, or any plugin. It exists to
//! prove that a separately implemented consumer can classify the same fixture.

/// Divergence classes emitted by the independent JSON evaluator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceDivergenceV1 {
    Equal,
    Metadata,
    AuthoritativeEvents,
    Projections,
    CausalTrace,
    Observability,
}

/// Independent JSON comparison result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceComparisonV1 {
    pub equal: bool,
    pub divergence: ReferenceDivergenceV1,
}

/// Error returned when a fixture is not a Wave 8 evidence object.
#[derive(Debug, thiserror::Error)]
pub enum ReferenceError {
    #[error("evidence JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("evidence JSON root must be an object")]
    RootNotObject,
    #[error("evidence JSON is missing field '{0}'")]
    MissingField(&'static str),
}

/// Compare two JSON evidence artifacts without importing the implementation's
/// Rust types.
///
/// Execution mode is intentionally ignored so Local and Air-Gapped artifacts
/// with the same authoritative inputs can be compared as one fixture.
///
/// # Errors
/// Returns an error when either JSON value is malformed or incomplete.
pub fn compare_json(left: &str, right: &str) -> Result<ReferenceComparisonV1, ReferenceError> {
    let left = parse(left)?;
    let right = parse(right)?;
    let manifest_fields = [
        "format_version",
        "input_digest",
        "fork_cut_seq",
        "seed",
        "resource_limit",
        "network_enabled",
        "plugin_versions",
    ];
    if manifest_fields.iter().any(|field| {
        field_value(&left, "manifest", field) != field_value(&right, "manifest", field)
    }) {
        return Ok(result(ReferenceDivergenceV1::Metadata));
    }
    for (field, divergence) in [
        (
            "authoritative_events",
            ReferenceDivergenceV1::AuthoritativeEvents,
        ),
        ("projections", ReferenceDivergenceV1::Projections),
        ("causal_trace", ReferenceDivergenceV1::CausalTrace),
    ] {
        if field_value(&left, "", field) != field_value(&right, "", field) {
            return Ok(result(divergence));
        }
    }
    if [
        "uncertainty",
        "participant_views",
        "plugin_failures",
        "consent_audit",
    ]
    .iter()
    .any(|field| field_value(&left, "", field) != field_value(&right, "", field))
    {
        return Ok(result(ReferenceDivergenceV1::Observability));
    }
    Ok(result(ReferenceDivergenceV1::Equal))
}

fn result(divergence: ReferenceDivergenceV1) -> ReferenceComparisonV1 {
    ReferenceComparisonV1 {
        equal: divergence == ReferenceDivergenceV1::Equal,
        divergence,
    }
}

fn parse(value: &str) -> Result<serde_json::Map<String, serde_json::Value>, ReferenceError> {
    let value = serde_json::from_str::<serde_json::Value>(value)?;
    let serde_json::Value::Object(object) = value else {
        return Err(ReferenceError::RootNotObject);
    };
    for field in [
        "format_version",
        "manifest",
        "authoritative_events",
        "projections",
        "causal_trace",
        "uncertainty",
        "participant_views",
        "plugin_failures",
        "consent_audit",
    ] {
        if !object.contains_key(field) {
            return Err(ReferenceError::MissingField(field));
        }
    }
    let manifest = object
        .get("manifest")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReferenceError::MissingField("manifest"))?;
    for field in [
        "format_version",
        "input_digest",
        "fork_cut_seq",
        "seed",
        "resource_limit",
        "network_enabled",
        "plugin_versions",
    ] {
        if !manifest.contains_key(field) {
            return Err(ReferenceError::MissingField(field));
        }
    }
    Ok(object)
}

fn field_value<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    parent: &str,
    field: &str,
) -> Option<&'a serde_json::Value> {
    let value = if parent.is_empty() {
        object.get(field)
    } else {
        object.get(parent)?.get(field)
    };
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        serde_json::json!({
            "format_version": 1,
            "manifest": {
                "format_version": 1,
                "input_digest": [1],
                "execution_mode": "local",
                "fork_cut_seq": 1,
                "seed": 1,
                "resource_limit": 10,
                "network_enabled": false,
                "plugin_versions": {"world": "1"}
            },
            "authoritative_events": [{"seq": 1}],
            "projections": [],
            "causal_trace": [],
            "uncertainty": [],
            "participant_views": [],
            "plugin_failures": [],
            "consent_audit": {"subject": "s"}
        })
        .to_string()
    }

    #[test]
    fn classifies_equal_and_each_divergence() {
        let left = fixture();
        assert_eq!(
            compare_json(&left, &left).unwrap().divergence,
            ReferenceDivergenceV1::Equal
        );
        for (field, expected) in [
            ("seed", ReferenceDivergenceV1::Metadata),
            (
                "authoritative_events",
                ReferenceDivergenceV1::AuthoritativeEvents,
            ),
            ("projections", ReferenceDivergenceV1::Projections),
            ("causal_trace", ReferenceDivergenceV1::CausalTrace),
            ("uncertainty", ReferenceDivergenceV1::Observability),
        ] {
            let mut value: serde_json::Value = serde_json::from_str(&left).unwrap();
            if field == "seed" {
                value["manifest"][field] = serde_json::json!(2);
            } else {
                value[field] = serde_json::json!([{"changed": true}]);
            }
            assert_eq!(
                compare_json(&left, &value.to_string()).unwrap().divergence,
                expected
            );
        }
    }

    #[test]
    fn rejects_invalid_or_incomplete_json() {
        assert!(matches!(
            compare_json("[]", "{}"),
            Err(ReferenceError::RootNotObject)
        ));
        assert!(matches!(
            compare_json("{}", &fixture()),
            Err(ReferenceError::MissingField("format_version"))
        ));
        assert!(matches!(
            compare_json("not-json", &fixture()),
            Err(ReferenceError::Json(_))
        ));
    }
}
