#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

//! A deliberately dependency-light second evaluator for Wave 8 evidence.
//!
//! This crate parses the portable JSON envelope as untyped data and does not
//! import the conformance crate, experiment host, or any plugin. It exists to
//! prove that a separately implemented consumer can classify the same fixture.

use std::collections::{BTreeMap, BTreeSet};

pub mod adapter_transport;
pub mod evaluator;
pub mod evaluator_build_identity;
pub mod evaluator_protocol;
pub mod process_adapter;
pub mod profile;
pub mod signed_bundle;

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

/// The semantic output of the independent fixture reproducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceFixtureResultV1 {
    pub event_count: u64,
    pub event_type_counts: Vec<(String, u64)>,
    pub causal_edges: Vec<(u64, u64)>,
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
    tick: u64,
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
    let cut = validate_pair_metadata(&baseline, &counterfactual)?;
    validate_contract(&baseline)?;
    validate_contract(&counterfactual)?;
    verify_fork_suffix(&baseline, &counterfactual, cut, intervention_event_type)
}

/// Reproduce the public reaction-chain result from one portable fixture.
///
/// This is a second implementation of the fixture's public semantics. It
/// consumes only the JSON event summaries and independently derives counts and
/// causal edges; it does not call the host, conformance crate, or Plugins.
///
/// # Errors
/// Returns [`ReferenceError`] when the fixture is malformed or does not carry
/// the complete physical-to-agent-to-society chain.
pub fn reproduce_fixture_json(value: &str) -> Result<ReferenceFixtureResultV1, ReferenceError> {
    let object = parse(value)?;
    let events = events(&object)?;
    verify_reference_kernel(&events)?;
    let has_agent_observation_edge = events.iter().any(|event| {
        event.event_type == "proof.agent.reaction.v1"
            && event.causation_seq.is_some_and(|cause_seq| {
                events.iter().any(|cause| {
                    cause.seq == cause_seq && cause.event_type == "world.observation.v1"
                })
            })
    });
    let has_society_agent_edge = events.iter().any(|event| {
        event.event_type == "society.signal"
            && event.causation_seq.is_some_and(|cause_seq| {
                events.iter().any(|cause| {
                    cause.seq == cause_seq && cause.event_type == "proof.agent.reaction.v1"
                })
            })
    });
    if !has_agent_observation_edge || !has_society_agent_edge {
        return Err(ReferenceError::InvalidForkEvidence(
            "independent fixture reaction chain is incomplete",
        ));
    }
    let mut counts = BTreeMap::<String, u64>::new();
    for event in &events {
        let count = counts.entry(event.event_type.clone()).or_default();
        *count = count.saturating_add(1);
    }
    let causal_edges = events
        .iter()
        .filter_map(|event| event.causation_seq.map(|cause| (cause, event.seq)))
        .collect();
    Ok(ReferenceFixtureResultV1 {
        event_count: u64::try_from(events.len()).unwrap_or(u64::MAX),
        event_type_counts: counts.into_iter().collect(),
        causal_edges,
    })
}

fn validate_pair_metadata(
    baseline: &serde_json::Map<String, serde_json::Value>,
    counterfactual: &serde_json::Map<String, serde_json::Value>,
) -> Result<u64, ReferenceError> {
    let baseline_manifest = manifest(baseline)?;
    let counterfactual_manifest = manifest(counterfactual)?;
    if baseline_manifest.get("input_digest") != counterfactual_manifest.get("input_digest")
        || baseline_manifest.get("fork_cut_seq") != counterfactual_manifest.get("fork_cut_seq")
    {
        return Err(ReferenceError::InvalidForkEvidence("manifest mismatch"));
    }
    counterfactual_manifest
        .get("fork_cut_seq")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ReferenceError::InvalidForkEvidence("fork cut is absent"))
}

fn manifest(
    evidence: &serde_json::Map<String, serde_json::Value>,
) -> Result<&serde_json::Map<String, serde_json::Value>, ReferenceError> {
    evidence
        .get("manifest")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReferenceError::MissingField("manifest"))
}

fn validate_contract(
    evidence: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), ReferenceError> {
    let contract = evidence
        .get("contract")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReferenceError::MissingField("contract"))?;
    let boundary = contract
        .get("plugin_boundary")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReferenceError::InvalidForkEvidence(
            "plugin boundary is not an object",
        ))?;
    validate_plugin_boundary_shape(boundary)?;
    let matrix = contract
        .get("non_interference")
        .ok_or(ReferenceError::InvalidForkEvidence(
            "non-interference matrix is missing",
        ))?;
    validate_non_interference_matrix(matrix)
}

fn verify_fork_suffix(
    baseline: &serde_json::Map<String, serde_json::Value>,
    counterfactual: &serde_json::Map<String, serde_json::Value>,
    cut: u64,
    intervention_event_type: &str,
) -> Result<(), ReferenceError> {
    let baseline_events = events(baseline)?;
    let counterfactual_events = events(counterfactual)?;
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
    let endogenous_counterfactual_suffix = counterfactual_suffix
        .iter()
        .filter(|event| is_endogenous_event(&event.event_type))
        .copied()
        .collect::<Vec<_>>();
    let complete_endogenous_suffix = endogenous_counterfactual_suffix
        .iter()
        .filter(|event| event.seq > intervention.seq)
        .find(|candidate| {
            let tail = endogenous_counterfactual_suffix
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

fn is_endogenous_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "world.action.v1" | "world.observation.v1" | "proof.agent.reaction.v1" | "society.signal"
    )
}

/// Reproduce the public causal contract of the proof fixture without linking
/// the runtime, reducers, or plugin implementations. This is intentionally a
/// small independent model: it checks the reaction chain, not private payload
/// representation or generated Event IDs.
fn verify_reference_kernel(events: &[ReferenceEvent]) -> Result<(), ReferenceError> {
    if events.first().is_none_or(|event| event.seq != 1)
        || events
            .windows(2)
            .any(|pair| pair[1].seq != pair[0].seq.saturating_add(1))
    {
        return Err(ReferenceError::InvalidForkEvidence(
            "independent Event sequence is not contiguous",
        ));
    }
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
            let tick = event
                .get("tick")
                .and_then(serde_json::Value::as_u64)
                .ok_or(ReferenceError::InvalidForkEvidence("Event tick is invalid"))?;
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
            let causation_seq = match event.get("causation_seq") {
                None | Some(serde_json::Value::Null) => None,
                Some(value) => Some(value.as_u64().ok_or(ReferenceError::InvalidForkEvidence(
                    "Event causation sequence is invalid",
                ))?),
            };
            Ok(ReferenceEvent {
                seq,
                tick,
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
        "scenario_room_digest",
        "scheduler_digest",
        "budget_digest",
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
        "host_closure",
        "contract",
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
        "host_closure",
        "contract",
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
        "scenario_room_digest",
        "scheduler_digest",
        "budget_digest",
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
    validate_contract_shape(&object)?;
    Ok(object)
}

fn validate_contract_shape(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), ReferenceError> {
    let contract = object
        .get("contract")
        .and_then(serde_json::Value::as_object)
        .ok_or(ReferenceError::InvalidForkEvidence(
            "contract is not an object",
        ))?;
    let required = [
        "scenario_room",
        "plugin_boundary",
        "knowledge_snapshots",
        "authorization_decisions",
        "counterfactual",
        "atomicity",
        "non_interference",
    ];
    for field in required {
        if !contract.contains_key(field) {
            return Err(ReferenceError::InvalidForkEvidence(
                "contract field is missing",
            ));
        }
    }
    if contract
        .keys()
        .any(|field| !required.contains(&field.as_str()))
        || !contract
            .get("scenario_room")
            .is_some_and(serde_json::Value::is_object)
        || !contract
            .get("plugin_boundary")
            .is_some_and(serde_json::Value::is_object)
        || !contract
            .get("counterfactual")
            .is_some_and(serde_json::Value::is_object)
        || !contract
            .get("knowledge_snapshots")
            .is_some_and(serde_json::Value::is_array)
        || !contract
            .get("authorization_decisions")
            .is_some_and(serde_json::Value::is_array)
        || !contract
            .get("atomicity")
            .is_some_and(serde_json::Value::is_array)
        || !contract
            .get("non_interference")
            .is_some_and(serde_json::Value::is_array)
    {
        return Err(ReferenceError::InvalidForkEvidence(
            "contract shape is invalid",
        ));
    }
    Ok(())
}

fn validate_plugin_boundary_shape(
    boundary: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), ReferenceError> {
    let required = [
        "manifest_version",
        "plugin_id",
        "world",
        "abi_major",
        "min_abi_minor",
        "max_abi_minor",
        "wit_digest",
        "component_digest",
        "imported_interfaces",
        "exported_interfaces",
        "network_allowed",
        "filesystem_allowed",
        "fresh_worker_required",
        "memory_bytes",
        "fuel",
        "host_call_limit",
        "event_draft_limit",
        "state_bytes_limit",
        "observation_bytes_limit",
        "manifest_digest",
        "release_digest",
    ];
    if required.iter().any(|field| !boundary.contains_key(*field))
        || boundary
            .keys()
            .any(|field| !required.contains(&field.as_str()))
        || boundary.get("manifest_version") != Some(&serde_json::json!(1))
        || boundary.get("world")
            != Some(&serde_json::json!("pigloros:plugin/community-plugin@0.1.0"))
        || boundary.get("abi_major") != Some(&serde_json::json!(0))
        || boundary.get("min_abi_minor") != Some(&serde_json::json!(1))
        || boundary.get("max_abi_minor") != Some(&serde_json::json!(1))
        || boundary.get("imported_interfaces") != Some(&serde_json::json!(["host-v1"]))
        || boundary.get("exported_interfaces") != Some(&serde_json::json!(["guest-v1"]))
        || boundary.get("network_allowed") != Some(&serde_json::json!(false))
        || boundary.get("filesystem_allowed") != Some(&serde_json::json!(false))
        || boundary.get("fresh_worker_required") != Some(&serde_json::json!(true))
        || boundary
            .get("plugin_id")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        || boundary
            .get("wit_digest")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
        || boundary
            .get("component_digest")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
        || boundary
            .get("manifest_digest")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
        || boundary
            .get("release_digest")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        return Err(ReferenceError::InvalidForkEvidence(
            "plugin boundary semantics are invalid",
        ));
    }
    Ok(())
}

fn validate_non_interference_matrix(value: &serde_json::Value) -> Result<(), ReferenceError> {
    let cases = value.as_array().ok_or(ReferenceError::InvalidForkEvidence(
        "non-interference matrix is not an array",
    ))?;
    if cases.len() != 192 {
        return Err(ReferenceError::InvalidForkEvidence(
            "non-interference matrix has the wrong size",
        ));
    }
    let fixtures = [
        "NI-TOOL-001",
        "NI-CACHE-002",
        "NI-STATE-003",
        "NI-OBS-004",
        "NI-TIME-005",
        "NI-PUBLIC-006",
        "NI-EVAL-007",
        "NI-FORK-008",
        "NI-ARCHIVE-009",
        "NI-NET-010",
        "NI-SERVICE-011",
        "NI-CRASH-012",
    ];
    let variants = ["success", "denial", "warm_cache", "cold_cache"];
    let modes = ["local", "air_gapped", "replay", "fork"];
    let mut index = 0;
    for fixture in fixtures {
        for variant in variants {
            for mode in modes {
                let case = cases[index]
                    .as_object()
                    .ok_or(ReferenceError::InvalidForkEvidence(
                        "non-interference case is not an object",
                    ))?;
                let required = [
                    "fixture_id",
                    "variant",
                    "mode",
                    "control_input_digest",
                    "canary_input_digest",
                    "authoritative_digest",
                    "public_digest",
                    "operational_digest",
                    "authoritative_equal",
                    "public_equal",
                    "operational_equal",
                    "provenance_digest",
                ];
                if required.iter().any(|field| !case.contains_key(*field))
                    || case.keys().any(|field| !required.contains(&field.as_str()))
                    || case.get("fixture_id") != Some(&serde_json::json!(fixture))
                    || case.get("variant") != Some(&serde_json::json!(variant))
                    || case.get("mode") != Some(&serde_json::json!(mode))
                    || case.get("authoritative_equal") != Some(&serde_json::json!(true))
                    || case.get("public_equal") != Some(&serde_json::json!(true))
                    || case.get("operational_equal") != Some(&serde_json::json!(true))
                    || case.get("control_input_digest") == case.get("canary_input_digest")
                    || [
                        "control_input_digest",
                        "canary_input_digest",
                        "authoritative_digest",
                        "public_digest",
                        "operational_digest",
                        "provenance_digest",
                    ]
                    .iter()
                    .any(|field| {
                        case.get(*field)
                            .and_then(serde_json::Value::as_array)
                            .is_none_or(Vec::is_empty)
                    })
                {
                    return Err(ReferenceError::InvalidForkEvidence(
                        "non-interference case is invalid",
                    ));
                }
                index += 1;
            }
        }
    }
    Ok(())
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
                "plugin_versions": {"world": "1"},
                "scenario_room_digest": [7],
                "scheduler_digest": [8],
                "budget_digest": [9]
            },
            "authoritative_events": [{
                "seq": 1,
                "tick": 1,
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
            "host_closure": {"subject": "s"},
            "contract": {
                "scenario_room": {},
                "plugin_boundary": {
                    "manifest_version": 1,
                    "plugin_id": "pigloros.wave8.proof-plugin",
                    "world": "pigloros:plugin/community-plugin@0.1.0",
                    "abi_major": 0,
                    "min_abi_minor": 1,
                    "max_abi_minor": 1,
                    "wit_digest": [1],
                    "component_digest": [1],
                    "imported_interfaces": ["host-v1"],
                    "exported_interfaces": ["guest-v1"],
                    "network_allowed": false,
                    "filesystem_allowed": false,
                    "fresh_worker_required": true,
                    "memory_bytes": 1,
                    "fuel": 1,
                    "host_call_limit": 1,
                    "event_draft_limit": 1,
                    "state_bytes_limit": 1,
                    "observation_bytes_limit": 1,
                    "manifest_digest": [1],
                    "release_digest": [1]
                },
                "knowledge_snapshots": [],
                "authorization_decisions": [],
                "counterfactual": {},
                "atomicity": [],
                "non_interference": []
            }
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

    #[test]
    fn rejects_fixture_without_the_complete_reaction_chain() -> Result<(), ReferenceError> {
        let mut value = parse_json(&fixture())?;
        value["authoritative_events"] = serde_json::json!([
            {
                "seq": 1,
                "tick": 1,
                "entity": "body",
                "event_type": "world.observation.v1",
                "payload_digest": [1],
                "causation_seq": null
            },
            {
                "seq": 2,
                "tick": 1,
                "entity": "agent",
                "event_type": "proof.agent.reaction.v1",
                "payload_digest": [2],
                "causation_seq": null
            },
            {
                "seq": 3,
                "tick": 2,
                "entity": "society",
                "event_type": "society.signal",
                "payload_digest": [3],
                "causation_seq": null
            }
        ]);
        assert!(matches!(
            reproduce_fixture_json(&value.to_string()),
            Err(ReferenceError::InvalidForkEvidence(
                "independent fixture reaction chain is incomplete"
            ))
        ));
        Ok(())
    }

    #[test]
    fn rejects_reference_pair_boundaries() -> Result<(), ReferenceError> {
        assert!(matches!(parse("not-json"), Err(ReferenceError::Json(_))));
        assert!(matches!(
            reproduce_fixture_json("not-json"),
            Err(ReferenceError::Json(_))
        ));
        let (baseline, counterfactual) = fork_fixture();
        assert!(matches!(
            verify_fork_json("not-json", &counterfactual, "world.action.v1"),
            Err(ReferenceError::Json(_))
        ));
        assert!(matches!(
            verify_fork_json(&baseline, "not-json", "world.action.v1"),
            Err(ReferenceError::Json(_))
        ));
        let mut invalid_baseline = parse_json(&baseline)?;
        object_mut(&mut invalid_baseline)?.remove("contract");
        assert!(verify_fork_json(
            &invalid_baseline.to_string(),
            &counterfactual,
            "world.action.v1"
        )
        .is_err());
        let mut invalid_contract = parse_json(&baseline)?;
        invalid_contract["contract"]["plugin_boundary"]["network_allowed"] =
            serde_json::json!(true);
        assert!(verify_fork_json(
            &invalid_contract.to_string(),
            &counterfactual,
            "world.action.v1"
        )
        .is_err());
        let mut malformed_events = parse_json(&baseline)?;
        malformed_events["authoritative_events"] = serde_json::json!(["bad"]);
        assert!(reproduce_fixture_json(&malformed_events.to_string()).is_err());
        let mut invalid_sequence = parse_json(&baseline)?;
        invalid_sequence["authoritative_events"][0]["seq"] = serde_json::json!(2);
        assert!(reproduce_fixture_json(&invalid_sequence.to_string()).is_err());
        let mut invalid_suffix = parse_json(&baseline)?;
        invalid_suffix["authoritative_events"] = serde_json::json!(["bad"]);
        assert!(verify_fork_json(
            &invalid_suffix.to_string(),
            &counterfactual,
            "world.action.v1"
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn rejects_reference_contract_boundaries() -> Result<(), ReferenceError> {
        assert!(matches!(
            validate_pair_metadata(&serde_json::Map::new(), &serde_json::Map::new()),
            Err(ReferenceError::MissingField("manifest"))
        ));
        let mut baseline = serde_json::Map::new();
        baseline.insert("manifest".to_owned(), serde_json::json!({}));
        assert!(matches!(
            validate_pair_metadata(&baseline, &serde_json::Map::new()),
            Err(ReferenceError::MissingField("manifest"))
        ));
        assert!(matches!(
            validate_contract(&serde_json::Map::new()),
            Err(ReferenceError::MissingField("contract"))
        ));
        let mut invalid_boundary = serde_json::Map::new();
        invalid_boundary.insert(
            "contract".to_owned(),
            serde_json::json!({"plugin_boundary": null}),
        );
        assert!(matches!(
            validate_contract(&invalid_boundary),
            Err(ReferenceError::InvalidForkEvidence(
                "plugin boundary is not an object"
            ))
        ));

        let (_, counterfactual) = fork_fixture();
        let mut missing_matrix = parse_json(&counterfactual)?;
        object_mut(&mut missing_matrix["contract"])?.remove("non_interference");
        assert!(matches!(
            validate_contract(object_mut(&mut missing_matrix)?),
            Err(ReferenceError::InvalidForkEvidence(
                "non-interference matrix is missing"
            ))
        ));
        Ok(())
    }

    #[test]
    fn rejects_reference_event_boundaries() {
        let empty = serde_json::Map::new();
        assert!(matches!(
            events(&empty),
            Err(ReferenceError::MissingField("authoritative_events"))
        ));
        for value in [
            serde_json::json!("not-an-event"),
            serde_json::json!({}),
            serde_json::json!({"seq": 1}),
            serde_json::json!({"seq": 1, "tick": 1}),
            serde_json::json!({"seq": 1, "tick": 1, "event_type": 7}),
            serde_json::json!({"seq": 1, "tick": 1, "event_type": "x"}),
            serde_json::json!({"seq": 1, "tick": 1, "event_type": "x", "entity": 7}),
            serde_json::json!({"seq": 1, "tick": 1, "event_type": "x", "entity": "e"}),
            serde_json::json!({"seq": 1, "tick": 1, "event_type": "x", "entity": "e", "payload_digest": [1], "causation_seq": "bad"}),
        ] {
            let mut object = serde_json::Map::new();
            object.insert(
                "authoritative_events".to_owned(),
                serde_json::json!([value]),
            );
            assert!(matches!(
                events(&object),
                Err(ReferenceError::InvalidForkEvidence(_))
            ));
        }

        assert!(matches!(
            compare_json("not-json", &fixture()),
            Err(ReferenceError::Json(_))
        ));
        assert!(matches!(
            compare_json(&fixture(), "not-json"),
            Err(ReferenceError::Json(_))
        ));
        assert!(matches!(
            validate_non_interference_matrix(&serde_json::Value::Bool(false)),
            Err(ReferenceError::InvalidForkEvidence(
                "non-interference matrix is not an array"
            ))
        ));
        let object = serde_json::Map::new();
        assert_eq!(field_value(&object, "", "missing"), None);
        assert_eq!(field_value(&object, "missing", "field"), None);
    }

    fn non_interference_fixture() -> serde_json::Value {
        let fixtures = [
            "NI-TOOL-001",
            "NI-CACHE-002",
            "NI-STATE-003",
            "NI-OBS-004",
            "NI-TIME-005",
            "NI-PUBLIC-006",
            "NI-EVAL-007",
            "NI-FORK-008",
            "NI-ARCHIVE-009",
            "NI-NET-010",
            "NI-SERVICE-011",
            "NI-CRASH-012",
        ];
        let variants = ["success", "denial", "warm_cache", "cold_cache"];
        let modes = ["local", "air_gapped", "replay", "fork"];
        let mut cases = Vec::with_capacity(192);
        for fixture in fixtures {
            for variant in variants {
                for mode in modes {
                    cases.push(serde_json::json!({
                        "fixture_id": fixture,
                        "variant": variant,
                        "mode": mode,
                        "control_input_digest": [1],
                        "canary_input_digest": [2],
                        "authoritative_digest": [3],
                        "public_digest": [4],
                        "operational_digest": [5],
                        "authoritative_equal": true,
                        "public_equal": true,
                        "operational_equal": true,
                        "provenance_digest": [6]
                    }));
                }
            }
        }
        serde_json::Value::Array(cases)
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
            "plugin_versions": {"world": "1"},
            "scenario_room_digest": [7],
            "scheduler_digest": [8],
            "budget_digest": [9]
        });
        let event = |seq, entity, event_type, payload_digest, causation_seq| {
            serde_json::json!({
                "seq": seq,
                "tick": seq,
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
            "host_closure": {"subject": "s"},
            "contract": {
                "scenario_room": {},
                "plugin_boundary": {
                    "manifest_version": 1,
                    "plugin_id": "pigloros.wave8.proof-plugin",
                    "world": "pigloros:plugin/community-plugin@0.1.0",
                    "abi_major": 0,
                    "min_abi_minor": 1,
                    "max_abi_minor": 1,
                    "wit_digest": [1],
                    "component_digest": [1],
                    "imported_interfaces": ["host-v1"],
                    "exported_interfaces": ["guest-v1"],
                    "network_allowed": false,
                    "filesystem_allowed": false,
                    "fresh_worker_required": true,
                    "memory_bytes": 1,
                    "fuel": 1,
                    "host_call_limit": 1,
                    "event_draft_limit": 1,
                    "state_bytes_limit": 1,
                    "observation_bytes_limit": 1,
                    "manifest_digest": [1],
                    "release_digest": [1]
                },
                "knowledge_snapshots": [],
                "authorization_decisions": [],
                "counterfactual": {},
                "atomicity": [],
                "non_interference": non_interference_fixture()
            }
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
        let mut noncontiguous = parse_json(&baseline)?;
        noncontiguous["authoritative_events"][1]["seq"] = serde_json::json!(3);
        noncontiguous["authoritative_events"][2]["seq"] = serde_json::json!(4);
        assert!(matches!(
            verify_fork_json(
                &noncontiguous.to_string(),
                &counterfactual,
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence(
                "independent Event sequence is not contiguous"
            ))
        ));

        let mut incomplete_kernel = parse_json(&counterfactual)?;
        incomplete_kernel["authoritative_events"] = serde_json::json!([{
            "seq": 1,
            "tick": 1,
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
        let mut cyclic_tail = parse_json(&counterfactual)?;
        cyclic_tail["authoritative_events"][2]["causation_seq"] = serde_json::json!(3);
        let cyclic_result =
            verify_fork_json(&baseline, &cyclic_tail.to_string(), "world.action.v1");
        assert!(
            matches!(
                cyclic_result,
                Err(ReferenceError::InvalidForkEvidence(
                    "causal tail is incomplete"
                ))
            ),
            "{cyclic_result:?}"
        );

        let mut cycle_baseline = parse_json(&baseline)?;
        cycle_baseline["manifest"]["fork_cut_seq"] = serde_json::json!(3);
        array_mut(&mut cycle_baseline["authoritative_events"])?.extend([
            serde_json::json!({
                "seq": 4, "tick": 2, "entity": "world", "event_type": "custom.action",
                "payload_digest": [8], "causation_seq": 3
            }),
            serde_json::json!({
                "seq": 5, "tick": 2, "entity": "custom", "event_type": "custom.event",
                "payload_digest": [9], "causation_seq": 4
            }),
        ]);
        let mut cycle_counterfactual = cycle_baseline.clone();
        array_mut(&mut cycle_counterfactual["authoritative_events"])?.extend([
            serde_json::json!({
                "seq": 6, "tick": 3, "entity": "custom", "event_type": "custom.event",
                "payload_digest": [10], "causation_seq": 7
            }),
            serde_json::json!({
                "seq": 7, "tick": 3, "entity": "custom", "event_type": "custom.event",
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
        rejects_missing_evidence_fields()?;
        rejects_malformed_event_shapes()?;
        rejects_malformed_manifest_fields()
    }

    fn rejects_missing_evidence_fields() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
        let mut missing_baseline_manifest = parse_json(&baseline)?;
        missing_baseline_manifest["manifest"] = serde_json::Value::Null;
        assert!(matches!(
            verify_fork_json(
                &missing_baseline_manifest.to_string(),
                &counterfactual,
                "world.action.v1"
            ),
            Err(ReferenceError::MissingField("manifest"))
        ));

        let mut missing_counterfactual_manifest = parse_json(&counterfactual)?;
        missing_counterfactual_manifest["manifest"] = serde_json::Value::Null;
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &missing_counterfactual_manifest.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::MissingField("manifest"))
        ));

        let mut missing_contract = parse_json(&baseline)?;
        missing_contract["contract"] = serde_json::Value::Null;
        let missing_contract_result = verify_fork_json(
            &missing_contract.to_string(),
            &counterfactual,
            "world.action.v1",
        );
        assert!(
            matches!(
                missing_contract_result,
                Err(ReferenceError::InvalidForkEvidence(
                    "contract is not an object"
                ))
            ),
            "{missing_contract_result:?}"
        );

        let mut invalid_boundary = parse_json(&baseline)?;
        invalid_boundary["contract"]["plugin_boundary"] = serde_json::Value::Null;
        assert!(matches!(
            verify_fork_json(
                &invalid_boundary.to_string(),
                &counterfactual,
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence(
                "contract shape is invalid"
            ))
        ));

        let mut missing_matrix = parse_json(&baseline)?;
        if let Some(contract) = missing_matrix["contract"].as_object_mut() {
            contract.remove("non_interference");
        }
        assert!(matches!(
            verify_fork_json(
                &missing_matrix.to_string(),
                &counterfactual,
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence(
                "contract field is missing"
            ))
        ));
        Ok(())
    }

    fn rejects_malformed_event_shapes() -> Result<(), ReferenceError> {
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
        Ok(())
    }

    fn rejects_malformed_manifest_fields() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
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

    #[test]
    fn rejects_every_contract_and_matrix_shape_boundary() -> Result<(), ReferenceError> {
        rejects_contract_field_shapes()?;
        rejects_plugin_boundary_shapes()?;
        rejects_matrix_shapes()
    }

    fn rejects_contract_field_shapes() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
        let contract_fields = [
            "scenario_room",
            "plugin_boundary",
            "knowledge_snapshots",
            "authorization_decisions",
            "counterfactual",
            "atomicity",
            "non_interference",
        ];
        for field in contract_fields {
            let mut value = parse_json(&counterfactual)?;
            object_mut(&mut value["contract"])?.remove(field);
            assert!(matches!(
                verify_fork_json(&baseline, &value.to_string(), "world.action.v1"),
                Err(ReferenceError::InvalidForkEvidence(
                    "contract field is missing"
                ))
            ));
        }

        for field in [
            "scenario_room",
            "plugin_boundary",
            "counterfactual",
            "knowledge_snapshots",
            "authorization_decisions",
            "atomicity",
            "non_interference",
        ] {
            let mut value = parse_json(&counterfactual)?;
            value["contract"][field] = serde_json::json!(true);
            assert!(matches!(
                verify_fork_json(&baseline, &value.to_string(), "world.action.v1"),
                Err(ReferenceError::InvalidForkEvidence(
                    "contract shape is invalid"
                ))
            ));
        }
        let mut unknown_contract = parse_json(&counterfactual)?;
        unknown_contract["contract"]["unknown"] = serde_json::json!(true);
        assert!(matches!(
            verify_fork_json(&baseline, &unknown_contract.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "contract shape is invalid"
            ))
        ));
        Ok(())
    }

    fn rejects_plugin_boundary_shapes() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
        let boundary_fields = [
            ("manifest_version", serde_json::json!(2)),
            ("plugin_id", serde_json::json!("")),
            (
                "world",
                serde_json::json!("pigloros:plugin/incorrect@0.1.0"),
            ),
            ("abi_major", serde_json::json!(1)),
            ("min_abi_minor", serde_json::json!(2)),
            ("max_abi_minor", serde_json::json!(2)),
            ("imported_interfaces", serde_json::json!(["other"])),
            ("exported_interfaces", serde_json::json!(["other"])),
            ("network_allowed", serde_json::json!(true)),
            ("filesystem_allowed", serde_json::json!(true)),
            ("fresh_worker_required", serde_json::json!(false)),
            ("wit_digest", serde_json::json!([])),
            ("component_digest", serde_json::json!([])),
            ("manifest_digest", serde_json::json!([])),
            ("release_digest", serde_json::json!([])),
        ];
        for (field, invalid) in boundary_fields {
            let mut value = parse_json(&counterfactual)?;
            value["contract"]["plugin_boundary"][field] = invalid;
            assert!(matches!(
                verify_fork_json(&baseline, &value.to_string(), "world.action.v1"),
                Err(ReferenceError::InvalidForkEvidence(
                    "plugin boundary semantics are invalid"
                ))
            ));
        }
        let mut missing_boundary_field = parse_json(&counterfactual)?;
        object_mut(&mut missing_boundary_field["contract"]["plugin_boundary"])?.remove("fuel");
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &missing_boundary_field.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence(
                "plugin boundary semantics are invalid"
            ))
        ));
        let mut unknown_boundary_field = parse_json(&counterfactual)?;
        unknown_boundary_field["contract"]["plugin_boundary"]["unknown"] = serde_json::json!(1);
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &unknown_boundary_field.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence(
                "plugin boundary semantics are invalid"
            ))
        ));
        Ok(())
    }

    fn rejects_matrix_shapes() -> Result<(), ReferenceError> {
        let (baseline, counterfactual) = fork_fixture();
        let matrix_cases = [
            ("fixture_id", serde_json::json!("wrong")),
            ("variant", serde_json::json!("wrong")),
            ("mode", serde_json::json!("wrong")),
            ("authoritative_equal", serde_json::json!(false)),
            ("public_equal", serde_json::json!(false)),
            ("operational_equal", serde_json::json!(false)),
            ("control_input_digest", serde_json::json!([2])),
            ("canary_input_digest", serde_json::json!([])),
            ("authoritative_digest", serde_json::json!([])),
            ("public_digest", serde_json::json!([])),
            ("operational_digest", serde_json::json!([])),
            ("provenance_digest", serde_json::json!([])),
        ];
        for (field, invalid) in matrix_cases {
            let mut value = parse_json(&counterfactual)?;
            value["contract"]["non_interference"][0][field] = invalid;
            assert!(matches!(
                verify_fork_json(&baseline, &value.to_string(), "world.action.v1"),
                Err(ReferenceError::InvalidForkEvidence(
                    "non-interference case is invalid"
                ))
            ));
        }
        let mut matrix_not_array = parse_json(&counterfactual)?;
        matrix_not_array["contract"]["non_interference"] = serde_json::json!(true);
        assert!(matches!(
            verify_fork_json(&baseline, &matrix_not_array.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "contract shape is invalid"
            ))
        ));
        let mut matrix_wrong_size = parse_json(&counterfactual)?;
        matrix_wrong_size["contract"]["non_interference"] = serde_json::json!([]);
        assert!(matches!(
            verify_fork_json(&baseline, &matrix_wrong_size.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "non-interference matrix has the wrong size"
            ))
        ));
        let mut matrix_not_object = parse_json(&counterfactual)?;
        matrix_not_object["contract"]["non_interference"][0] = serde_json::json!(true);
        assert!(matches!(
            verify_fork_json(&baseline, &matrix_not_object.to_string(), "world.action.v1"),
            Err(ReferenceError::InvalidForkEvidence(
                "non-interference case is not an object"
            ))
        ));
        let mut matrix_missing_field = parse_json(&counterfactual)?;
        object_mut(&mut matrix_missing_field["contract"]["non_interference"][0])?
            .remove("fixture_id");
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &matrix_missing_field.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence(
                "non-interference case is invalid"
            ))
        ));
        let mut matrix_unknown_field = parse_json(&counterfactual)?;
        matrix_unknown_field["contract"]["non_interference"][0]["unknown"] = serde_json::json!(1);
        assert!(matches!(
            verify_fork_json(
                &baseline,
                &matrix_unknown_field.to_string(),
                "world.action.v1"
            ),
            Err(ReferenceError::InvalidForkEvidence(
                "non-interference case is invalid"
            ))
        ));
        Ok(())
    }
}
