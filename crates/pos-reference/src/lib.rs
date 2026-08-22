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
    #[error("evidence JSON contains an unknown field '{0}'")]
    UnexpectedField(String),
    #[error("independent Fork evaluator rejected evidence: {0}")]
    InvalidForkEvidence(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceEvent {
    seq: u64,
    entity: String,
    event_type: String,
    payload_digest: serde_json::Value,
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
    verify_reference_kernel(&baseline_events)?;
    verify_reference_kernel(&counterfactual_events)?;
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
    let complete_endogenous_suffix = counterfactual_suffix
        .iter()
        .filter(|event| event.seq > intervention.seq)
        .find(|candidate| {
            let tail = counterfactual_suffix
                .iter()
                .filter(|event| event.seq >= candidate.seq)
                .collect::<Vec<_>>();
            !tail.is_empty()
                && tail
                    .iter()
                    .all(|event| reaches(event, intervention.seq, &by_seq))
        });
    if complete_endogenous_suffix.is_none() {
        return Err(ReferenceError::InvalidForkEvidence(
            "causal tail is incomplete",
        ));
    }
    if baseline_suffix == counterfactual_suffix {
        return Err(ReferenceError::InvalidForkEvidence("suffix was copied"));
    }
    Ok(())
}

/// Reproduce the public causal contract of the proof fixture without linking
/// the runtime, reducers, or plugin implementations. This is intentionally a
/// small independent model: it checks the reaction chain, not private payload
/// representation or generated Event IDs.
fn verify_reference_kernel(events: &[ReferenceEvent]) -> Result<(), ReferenceError> {
    let event_types = events
        .iter()
        .map(|event| event.event_type.as_str())
        .collect::<BTreeSet<_>>();
    for required in [
        "world.observation.v1",
        "proof.agent.reaction.v1",
        "society.signal",
    ] {
        if !event_types.contains(required) {
            return Err(ReferenceError::InvalidForkEvidence(
                "independent fixture reaction is incomplete",
            ));
        }
    }
    let by_seq = events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<BTreeMap<_, _>>();
    for event in events {
        let Some(cause_seq) = event.causation_seq else {
            continue;
        };
        let Some(cause) = by_seq.get(&cause_seq) else {
            return Err(ReferenceError::InvalidForkEvidence(
                "independent causal source is missing",
            ));
        };
        let valid = match event.event_type.as_str() {
            "proof.agent.reaction.v1" => cause.event_type == "world.observation.v1",
            "society.signal" => cause.event_type == "proof.agent.reaction.v1",
            "world.observation.v1" => {
                cause.event_type == "world.action.v1" || cause.event_type == "world.observation.v1"
            }
            _ => true,
        };
        if !valid {
            return Err(ReferenceError::InvalidForkEvidence(
                "independent causal relation is invalid",
            ));
        }
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
            let entity = event
                .get("entity")
                .and_then(serde_json::Value::as_str)
                .ok_or(ReferenceError::InvalidForkEvidence(
                    "Event entity is invalid",
                ))?
                .to_owned();
            let payload_digest =
                event
                    .get("payload_digest")
                    .cloned()
                    .ok_or(ReferenceError::InvalidForkEvidence(
                        "Event payload digest is missing",
                    ))?;
            let causation_seq = event
                .get("causation_seq")
                .and_then(|value| (!value.is_null()).then(|| value.as_u64()))
                .flatten();
            Ok(ReferenceEvent {
                seq,
                entity,
                event_type,
                payload_digest,
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
        let cause = by_seq[&cause_seq];
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
        "reproducibility_class",
        "execution_profile",
        "execution_profile_digest",
        "trust_policy_snapshot_digest",
        "artifact_closure_digest",
        "evaluator_digest",
        "replay_claim",
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
    let required = [
        "format_version",
        "manifest",
        "authoritative_events",
        "projections",
        "causal_trace",
        "uncertainty",
        "participant_views",
        "plugin_failures",
        "consent_audit",
    ];
    for field in required {
        if !object.contains_key(field) {
            return Err(ReferenceError::MissingField(field));
        }
    }
    for field in object.keys() {
        if !required.contains(&field.as_str()) {
            return Err(ReferenceError::UnexpectedField(field.clone()));
        }
    }
    let manifest = object
        .get("manifest")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReferenceError::MissingField("manifest"))?;
    let manifest_fields = [
        "format_version",
        "input_digest",
        "execution_mode",
        "fork_cut_seq",
        "seed",
        "resource_limit",
        "network_enabled",
        "reproducibility_class",
        "execution_profile",
        "execution_profile_digest",
        "trust_policy_snapshot_digest",
        "artifact_closure_digest",
        "evaluator_digest",
        "replay_claim",
        "plugin_versions",
    ];
    for field in manifest_fields {
        if !manifest.contains_key(field) {
            return Err(ReferenceError::MissingField(field));
        }
    }
    for field in manifest.keys() {
        if !manifest_fields.contains(&field.as_str()) {
            return Err(ReferenceError::UnexpectedField(field.clone()));
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

    fn parse_json(value: &str) -> Result<serde_json::Value, ReferenceError> {
        Ok(serde_json::from_str(value)?)
    }

    fn object_mut(
        value: &mut serde_json::Value,
    ) -> Result<&mut serde_json::Map<String, serde_json::Value>, ReferenceError> {
        value
            .as_object_mut()
            .ok_or(ReferenceError::InvalidForkEvidence(
                "test object is missing",
            ))
    }

    fn array_mut(
        value: &mut serde_json::Value,
    ) -> Result<&mut Vec<serde_json::Value>, ReferenceError> {
        value
            .as_array_mut()
            .ok_or(ReferenceError::InvalidForkEvidence("test array is missing"))
    }

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
                "reproducibility_class": "profile_recomputation",
                "execution_profile": "deterministic-v1",
                "execution_profile_digest": [3],
                "trust_policy_snapshot_digest": [4],
                "artifact_closure_digest": [5],
                "evaluator_digest": [6],
                "replay_claim": "exact",
                "plugin_versions": {"world": "1"}
            },
            "authoritative_events": [{
                "seq": 1,
                "entity": "body",
                "event_type": "world.observation.v1",
                "payload_digest": [1],
                "causation_seq": null
            }],
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
    fn classifies_equal_and_each_divergence() -> Result<(), ReferenceError> {
        let left = fixture();
        assert_eq!(
            compare_json(&left, &left)?.divergence,
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
            let mut value = parse_json(&left)?;
            if field == "seed" {
                value["manifest"][field] = serde_json::json!(2);
            } else {
                value[field] = serde_json::json!([{"changed": true}]);
            }
            assert_eq!(
                compare_json(&left, &value.to_string())?.divergence,
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_invalid_or_incomplete_json() -> Result<(), ReferenceError> {
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
        let mut value = parse_json(&fixture())?;
        value["unknown"] = serde_json::json!(true);
        assert!(matches!(
            compare_json(&value.to_string(), &fixture()),
            Err(ReferenceError::UnexpectedField(field)) if field == "unknown"
        ));
        Ok(())
    }

    fn fork_fixture() -> (String, String) {
        let manifest = serde_json::json!({
            "format_version": 1,
            "input_digest": [1],
            "execution_mode": "local",
            "fork_cut_seq": 1,
            "seed": 1,
            "resource_limit": 10,
            "network_enabled": false,
            "reproducibility_class": "profile_recomputation",
            "execution_profile": "deterministic-v1",
            "execution_profile_digest": [3],
            "trust_policy_snapshot_digest": [4],
            "artifact_closure_digest": [5],
            "evaluator_digest": [6],
            "replay_claim": "exact",
            "plugin_versions": {"world": "1"}
        });
        let event = |seq, entity, event_type, payload_digest, causation_seq| {
            serde_json::json!({
                "seq": seq,
                "entity": entity,
                "event_type": event_type,
                "payload_digest": [payload_digest],
                "causation_seq": causation_seq
            })
        };
        let baseline = serde_json::json!({
            "format_version": 1,
            "manifest": manifest,
            "authoritative_events": [
                event(1, "body", "world.observation.v1", 1, serde_json::Value::Null),
                event(2, "agent", "proof.agent.reaction.v1", 2, serde_json::json!(1)),
                event(3, "society", "society.signal", 3, serde_json::json!(2))
            ],
            "projections": [],
            "causal_trace": [],
            "uncertainty": [],
            "participant_views": [],
            "plugin_failures": [],
            "consent_audit": {"subject": "s"}
        });
        let mut counterfactual = baseline.clone();
        counterfactual["authoritative_events"] = serde_json::json!([
            event(
                1,
                "body",
                "world.observation.v1",
                1,
                serde_json::Value::Null
            ),
            event(2, "world", "world.action.v1", 4, serde_json::json!(1)),
            event(3, "body", "world.observation.v1", 5, serde_json::json!(2)),
            event(
                4,
                "agent",
                "proof.agent.reaction.v1",
                6,
                serde_json::json!(3)
            ),
            event(5, "society", "society.signal", 7, serde_json::json!(4))
        ]);
        (baseline.to_string(), counterfactual.to_string())
    }

    #[test]
    fn independently_verifies_fork_and_rejects_each_boundary() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
        assert!(verify_fork_json(&baseline, &counterfactual, "world.action.v1").is_ok());

        let mut value = parse_json(&counterfactual)?;
        value["manifest"]["input_digest"] = serde_json::json!([9]);
        assert!(matches!(
            verify_fork_json(&baseline, &value.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence("manifest mismatch"))
        ));

        let mut no_cut_baseline = parse_json(&baseline)?;
        let mut no_cut_counterfactual = parse_json(&counterfactual)?;
        no_cut_baseline["manifest"]["fork_cut_seq"] = serde_json::Value::Null;
        no_cut_counterfactual["manifest"]["fork_cut_seq"] = serde_json::Value::Null;
        assert!(matches!(
            verify_fork_json(
                &no_cut_baseline.to_string(),
                &no_cut_counterfactual.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence("fork cut is absent"))
        ));

        let mut prefix = parse_json(&counterfactual)?;
        prefix["authoritative_events"][0]["payload_digest"] = serde_json::json!([9]);
        assert!(matches!(
            verify_fork_json(&baseline, &prefix.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence("prefix mismatch"))
        ));

        let mut no_suffix = parse_json(&baseline)?;
        no_suffix["manifest"]["fork_cut_seq"] = serde_json::json!(5);
        assert!(matches!(
            verify_fork_json(
                &no_suffix.to_string(),
                &no_suffix.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence("suffix is empty"))
        ));

        let mut no_intervention = parse_json(&counterfactual)?;
        no_intervention["authoritative_events"][1]["event_type"] =
            serde_json::json!("world.observation.v1");
        assert!(matches!(
            verify_fork_json(&baseline, &no_intervention.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "intervention is absent"
            ))
        ));

        let mut incomplete_tail = parse_json(&counterfactual)?;
        incomplete_tail["authoritative_events"][2]["causation_seq"] = serde_json::json!(1);
        assert!(matches!(
            verify_fork_json(&baseline, &incomplete_tail.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "causal tail is incomplete"
            ))
        ));
        Ok(())
    }

    #[test]
    fn independently_rejects_kernel_boundaries() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
        let mut incomplete_kernel = parse_json(&counterfactual)?;
        incomplete_kernel["authoritative_events"] = serde_json::json!([{
            "seq": 1,
            "entity": "body",
            "event_type": "world.observation.v1",
            "payload_digest": [1],
            "causation_seq": null
        }]);
        assert!(matches!(
            verify_fork_json(&baseline, &incomplete_kernel.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "independent fixture reaction is incomplete"
            ))
        ));

        let mut missing_source = parse_json(&counterfactual)?;
        missing_source["authoritative_events"][3]["causation_seq"] = serde_json::json!(99);
        assert!(matches!(
            verify_fork_json(&baseline, &missing_source.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "independent causal source is missing"
            ))
        ));

        let mut invalid_relation = parse_json(&counterfactual)?;
        invalid_relation["authoritative_events"][3]["causation_seq"] = serde_json::json!(5);
        assert!(matches!(
            verify_fork_json(&baseline, &invalid_relation.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "independent causal relation is invalid"
            ))
        ));
        Ok(())
    }

    #[test]
    fn independently_rejects_cyclic_and_copied_suffixes() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
        let mut cycle_baseline = parse_json(&baseline)?;
        cycle_baseline["manifest"]["fork_cut_seq"] = serde_json::json!(3);
        array_mut(&mut cycle_baseline["authoritative_events"])?.extend([
            serde_json::json!({
                "seq": 4, "entity": "world", "event_type": "custom.action",
                "payload_digest": [8], "causation_seq": 3
            }),
            serde_json::json!({
                "seq": 5, "entity": "custom", "event_type": "custom.event",
                "payload_digest": [9], "causation_seq": 4
            }),
        ]);
        let mut cycle_counterfactual = cycle_baseline.clone();
        array_mut(&mut cycle_counterfactual["authoritative_events"])?.extend([
            serde_json::json!({
                "seq": 6, "entity": "custom", "event_type": "custom.event",
                "payload_digest": [10], "causation_seq": 7
            }),
            serde_json::json!({
                "seq": 7, "entity": "custom", "event_type": "custom.event",
                "payload_digest": [11], "causation_seq": 6
            }),
        ]);
        cycle_counterfactual["authoritative_events"][4]["causation_seq"] = serde_json::json!(7);
        cycle_counterfactual["authoritative_events"][5]["causation_seq"] = serde_json::json!(6);
        assert!(matches!(
            verify_fork_json(
                &cycle_baseline.to_string(),
                &cycle_counterfactual.to_string(),
                "custom.action"
            ),
            Err(ReferenceError::InvalidForkEvidence(
                "causal tail is incomplete"
            ))
        ));

        let mut copied_suffix = parse_json(&baseline)?;
        copied_suffix["manifest"]["fork_cut_seq"] = serde_json::json!(1);
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &copied_suffix.to_string(),
                "proof.agent.reaction.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence("suffix was copied"))
        ));

        let mut short_counterfactual = parse_json(&counterfactual)?;
        short_counterfactual["manifest"]["fork_cut_seq"] = serde_json::json!(4);
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &short_counterfactual.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence("manifest mismatch"))
        ));
        Ok(())
    }

    #[test]
    fn rejects_malformed_reference_events_and_manifests() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
        let mut cases = Vec::new();
        cases.push(serde_json::json!("not-an-event"));
        cases.push(serde_json::json!({"entity": "body"}));
        cases.push(serde_json::json!({"seq": 1, "entity": "body"}));
        cases.push(serde_json::json!({
            "seq": 1,
            "entity": "body",
            "event_type": "world.observation.v1"
        }));
        cases.push(serde_json::json!({
            "seq": 1,
            "entity": 7,
            "event_type": "world.observation.v1",
            "payload_digest": [1]
        }));
        for event in cases {
            let mut value = parse_json(&counterfactual)?;
            value["authoritative_events"] = serde_json::json!([event]);
            assert!(matches!(
                verify_fork_json(&baseline, &value.to_string(), "world.action.v1"),
                Err(ReferenceError::InvalidForkEvidence(_))
            ));
        }

        let mut missing_manifest = parse_json(&counterfactual)?;
        object_mut(&mut missing_manifest)?.remove("manifest");
        assert!(matches!(
            verify_fork_json(&baseline, &missing_manifest.to_string(), "world.action.v1"),
            Err(ReferenceError::MissingField("manifest"))
        ));
        let mut bad_manifest = parse_json(&counterfactual)?;
        bad_manifest["manifest"] = serde_json::json!(true);
        assert!(matches!(
            verify_fork_json(&baseline, &bad_manifest.to_string(), "world.action.v1"),
            Err(ReferenceError::MissingField("manifest"))
        ));
        let mut missing_events = parse_json(&counterfactual)?;
        object_mut(&mut missing_events)?.remove("authoritative_events");
        assert!(matches!(
            verify_fork_json(&baseline, &missing_events.to_string(), "world.action.v1"),
            Err(ReferenceError::MissingField("authoritative_events"))
        ));

        let mut missing_manifest_field = parse_json(&counterfactual)?;
        object_mut(&mut missing_manifest_field["manifest"])?.remove("evaluator_digest");
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &missing_manifest_field.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::MissingField("evaluator_digest"))
        ));
        let mut unknown_manifest_field = parse_json(&counterfactual)?;
        unknown_manifest_field["manifest"]["unknown"] = serde_json::json!(true);
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &unknown_manifest_field.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::UnexpectedField(field)) if field == "unknown"
        ));
        Ok(())
    }
}
