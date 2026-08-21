#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! A deliberately dependency-light second evaluator for Wave 8 evidence.
//!
//! This crate parses the portable JSON envelope as untyped data and does not
//! import the conformance crate, experiment host, or any plugin. It exists to
//! prove that a separately implemented consumer can classify the same fixture.

use std::collections::{BTreeMap, BTreeSet};

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
    #[error("independent Fork evaluator rejected evidence: {0}")]
    InvalidForkEvidence(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceEvent {
    seq: u64,
    event_type: String,
    causation_seq: Option<u64>,
}

/// Independently validate a baseline/counterfactual Fork evidence pair.
///
/// This evaluator intentionally works only from untyped JSON and reimplements
/// the causal-tail checks without importing the host or conformance crate.
/// Callers receive a stable classified error rather than an implementation
/// panic when a fixture is incomplete.
///
/// # Errors
/// Returns [`ReferenceError`] when either JSON artifact is malformed or the
/// independent Fork invariants do not hold.
pub fn verify_fork_json(
    baseline: &str,
    counterfactual: &str,
    intervention_event_type: &str,
) -> Result<(), ReferenceError> {
    let baseline = parse(baseline)?;
    let counterfactual = parse(counterfactual)?;
    let baseline_manifest = baseline
        .get("manifest")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReferenceError::MissingField("manifest"))?;
    let counterfactual_manifest = counterfactual
        .get("manifest")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReferenceError::MissingField("manifest"))?;
    if baseline_manifest.get("input_digest") != counterfactual_manifest.get("input_digest")
        || baseline_manifest.get("fork_cut_seq") != counterfactual_manifest.get("fork_cut_seq")
    {
        return Err(ReferenceError::InvalidForkEvidence("manifest mismatch"));
    }
    let Some(cut) = counterfactual_manifest
        .get("fork_cut_seq")
        .and_then(serde_json::Value::as_u64)
    else {
        return Err(ReferenceError::InvalidForkEvidence("fork cut is absent"));
    };
    let baseline_events = events(&baseline)?;
    let counterfactual_events = events(&counterfactual)?;
    let prefix = |events: &[ReferenceEvent]| {
        events
            .iter()
            .filter(|event| event.seq <= cut)
            .cloned()
            .collect::<Vec<_>>()
    };
    if prefix(&baseline_events) != prefix(&counterfactual_events) {
        return Err(ReferenceError::InvalidForkEvidence("prefix mismatch"));
    }
    let baseline_suffix = baseline_events
        .iter()
        .filter(|event| event.seq > cut)
        .collect::<Vec<_>>();
    let counterfactual_suffix = counterfactual_events
        .iter()
        .filter(|event| event.seq > cut)
        .collect::<Vec<_>>();
    if baseline_suffix.is_empty() || counterfactual_suffix.len() < 2 {
        return Err(ReferenceError::InvalidForkEvidence("suffix is empty"));
    }
    let Some(intervention) = counterfactual_suffix
        .iter()
        .find(|event| event.event_type == intervention_event_type)
    else {
        return Err(ReferenceError::InvalidForkEvidence(
            "intervention is absent",
        ));
    };
    let by_seq = counterfactual_events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<BTreeMap<_, _>>();
    let has_complete_tail = counterfactual_suffix
        .iter()
        .filter(|event| event.seq > intervention.seq)
        .any(|candidate| {
            let tail = counterfactual_suffix
                .iter()
                .filter(|event| event.seq >= candidate.seq)
                .collect::<Vec<_>>();
            tail.len() >= 3
                && tail
                    .iter()
                    .all(|event| reaches(event, intervention.seq, &by_seq))
        });
    if !has_complete_tail {
        return Err(ReferenceError::InvalidForkEvidence(
            "causal tail is incomplete",
        ));
    }
    if baseline_suffix == counterfactual_suffix {
        return Err(ReferenceError::InvalidForkEvidence("suffix was copied"));
    }
    Ok(())
}

fn events(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<ReferenceEvent>, ReferenceError> {
    let values = object
        .get("authoritative_events")
        .and_then(serde_json::Value::as_array)
        .ok_or(ReferenceError::MissingField("authoritative_events"))?;
    values
        .iter()
        .map(|value| {
            let event = value
                .as_object()
                .ok_or(ReferenceError::InvalidForkEvidence(
                    "Event is not an object",
                ))?;
            let seq = event.get("seq").and_then(serde_json::Value::as_u64).ok_or(
                ReferenceError::InvalidForkEvidence("Event sequence is invalid"),
            )?;
            let event_type = event
                .get("event_type")
                .and_then(serde_json::Value::as_str)
                .ok_or(ReferenceError::InvalidForkEvidence("Event type is invalid"))?
                .to_owned();
            let causation_seq = event
                .get("causation_seq")
                .and_then(|value| (!value.is_null()).then(|| value.as_u64()))
                .flatten();
            Ok(ReferenceEvent {
                seq,
                event_type,
                causation_seq,
            })
        })
        .collect()
}

fn reaches(
    event: &ReferenceEvent,
    intervention_seq: u64,
    by_seq: &BTreeMap<u64, &ReferenceEvent>,
) -> bool {
    let mut current = event;
    let mut seen = BTreeSet::new();
    loop {
        if current.seq == intervention_seq {
            return true;
        }
        if !seen.insert(current.seq) {
            return false;
        }
        let Some(cause_seq) = current.causation_seq else {
            return false;
        };
        let Some(cause) = by_seq.get(&cause_seq) else {
            return false;
        };
        current = cause;
    }
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
