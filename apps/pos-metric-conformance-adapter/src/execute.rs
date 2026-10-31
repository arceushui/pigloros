//! One sub-case run through plugins/eval, and the output record of a `canonical-output` family.
//!
//! plugins/eval is the implementation under test: an `MTI1` member is decoded and computed by
//! [`MetricInputV1`], an `MTQ1` member by [`decode_quantization_input_v1`],
//! [`quantize_probability`] and [`encode_quantization_result_v1`]. The output record names
//! each result with its BLAKE3, its bytes and a readable view of its fields taken from the
//! values plugins/eval computed; no `MTR1` is decoded.

use pos_plugin_eval::{
    decode_quantization_input_v1, encode_quantization_result_v1, quantize_probability,
    MetricErrorV1, MetricFailureV1, MetricInputV1, MetricOutcomeV1, MetricRedactionStateV1,
    MetricResultV1,
};
use pos_reference::adapter_transport::{write_attempt, TransportError};
use pos_reference::evaluator::{AttemptArtifact, AttemptTransportCaps, CaseAttempt};
use serde_json::{json, Value};

use crate::payload::{GateV1, InputV1, OutcomeV1, OutputRecordV1, StepV1, SubCaseV1};
use crate::CAPABILITY_ID;

/// The aggregate attempt ceiling of the oversized-member probe: the #222 transport's compiled
/// maximum, 1 GiB.
const MAX_ATTEMPT_BYTES: u64 = 1024 * 1024 * 1024;

/// What the subject observed for one sub-case.
enum ObservedV1 {
    /// plugins/eval produced a result record.
    Output {
        record: OutputRecordV1,
        bytes: Vec<u8>,
        values: Value,
    },
    /// plugins/eval refused the member.
    MetricError(MetricFailureV1),
    /// The gate denied the capability or network use.
    Denied,
    /// The #222 transport rejected the member.
    TransportRejection(TransportError),
    /// The gate refused the execution steps.
    ResourceLimit,
    /// The gate refused the provider contract.
    IncompatibleContract,
    /// The gate passed and the sub-case carries no input.
    NoInput,
    /// The sub-case is not the subject's to decide.
    EvaluatorOwned(&'static str),
}

impl ObservedV1 {
    /// The outcome compared with the expectation.
    fn outcome(&self) -> OutcomeV1 {
        match self {
            Self::Output { record, bytes, .. } => OutcomeV1::Result {
                record: *record,
                digest: blake3::hash(bytes).to_hex().to_string(),
            },
            Self::MetricError(failure) => OutcomeV1::MetricError {
                code: failure.error.code(),
                error: error_name(failure.error),
                coordinate: failure.coordinate.clone(),
            },
            Self::Denied => OutcomeV1::Denied,
            Self::TransportRejection(error) => OutcomeV1::TransportRejection(format!("{error:?}")),
            Self::ResourceLimit => OutcomeV1::ResourceLimit,
            Self::IncompatibleContract => OutcomeV1::IncompatibleContract,
            Self::NoInput => OutcomeV1::NoInput,
            Self::EvaluatorOwned(kind) => OutcomeV1::EvaluatorOwned(*kind),
        }
    }
}

/// The record of one sub-case.
pub(super) struct RecordV1 {
    id: String,
    observed: ObservedV1,
    matched: bool,
    steps: u64,
}

impl RecordV1 {
    /// Whether the subject observed exactly the expected outcome.
    pub(super) const fn matched(&self) -> bool {
        self.matched
    }

    /// The execution steps the sub-case consumed: one per member plugins/eval decoded.
    pub(super) const fn steps(&self) -> u64 {
        self.steps
    }
}

/// The profile name of a closed `MetricErrorV1`.
fn error_name(error: MetricErrorV1) -> String {
    format!("{error:?}")
}

/// Lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 0x0f)],
            ]
        })
        .map(char::from)
        .collect()
}

/// A readable view of an `MTR1` from the values plugins/eval computed. Its last field is the
/// 32-byte `result_digest32` byte string, so the digest is the last 32 bytes of the record.
fn metric_values(result: &MetricResultV1, bytes: &[u8]) -> Value {
    let (kind, metrics, bins) = match &result.outcome {
        MetricOutcomeV1::Computed { values, bins } => (
            "Computed",
            json!({
                "brier_micros": values.brier,
                "crps_micros": values.crps,
                "ece_micros": values.ece,
                "lift_vs_persistence_micros": values.lift_vs_persistence,
                "lift_vs_personal_base_rate_micros": values.lift_vs_personal_base_rate,
                "lift_vs_population_avg_micros": values.lift_vs_population_avg,
                "persistence_brier_micros": values.persistence_brier,
                "personal_base_rate_brier_micros": values.personal_base_rate_brier,
                "population_avg_brier_micros": values.population_avg_brier,
            }),
            Value::Array(
                bins.iter()
                    .map(|bin| json!([bin.count, bin.probability_sum_micros, bin.positives]))
                    .collect(),
            ),
        ),
        MetricOutcomeV1::InsufficientSamples => ("InsufficientSamples", Value::Null, Value::Null),
    };
    let redaction_state = match result.redaction_state {
        MetricRedactionStateV1::None => "None",
        MetricRedactionStateV1::RedactedViews => "RedactedViews",
        MetricRedactionStateV1::EvidenceMissing => "EvidenceMissing",
    };
    let counts = &result.counts;
    json!({
        "bins": bins,
        "counts": {
            "pending": counts.pending,
            "predictor_supplied": counts.predictor_supplied,
            "record_count": counts.record_count,
            "redacted": counts.redacted,
            "scored": counts.scored,
            "scored_entities": counts.scored_entities,
            "unavailable": counts.unavailable,
        },
        "input_digest": hex(&result.input_digest),
        "metrics": metrics,
        "minimum_scored_records": result.minimum_scored_records,
        "redaction_state": redaction_state,
        "result_digest": hex(&bytes[bytes.len().saturating_sub(32)..]),
        "result_kind": kind,
    })
}

/// plugins/eval decodes and computes one `MTI1` member.
fn metric(bytes: &[u8]) -> ObservedV1 {
    MetricInputV1::decode(bytes).map_or_else(ObservedV1::MetricError, |input| {
        let result = input.compute();
        let bytes = result.encode();
        let values = metric_values(&result, &bytes);
        ObservedV1::Output {
            record: OutputRecordV1::Metric,
            bytes,
            values,
        }
    })
}

/// plugins/eval decodes and quantizes one `MTQ1` member.
fn quantization(bytes: &[u8]) -> ObservedV1 {
    decode_quantization_input_v1(bytes).map_or_else(ObservedV1::MetricError, |patterns| {
        let entries: Vec<Result<u32, MetricErrorV1>> =
            patterns.iter().copied().map(quantize_probability).collect();
        let values = json!({
            "entries": patterns
                .iter()
                .zip(entries.iter().copied())
                .map(|(bits, entry)| json!({
                    "error": entry.err().map(error_name),
                    "pattern": format!("{bits:016x}"),
                    "probability_micros": entry.ok(),
                }))
                .collect::<Vec<Value>>(),
        });
        ObservedV1::Output {
            record: OutputRecordV1::Quantization,
            bytes: encode_quantization_result_v1(&entries),
            values,
        }
    })
}

/// Send a zero-filled member of `length` bytes through the #222 transport (the EAI1 writer's
/// bounds) under the member ceiling `ceiling`.
fn transported(attempt: &CaseAttempt, length: usize, ceiling: u64) -> Result<(), TransportError> {
    let bytes = vec![0_u8; length];
    let probe = CaseAttempt {
        auxiliary: vec![AttemptArtifact {
            digest: *blake3::hash(&bytes).as_bytes(),
            bytes,
        }],
        transport_caps: AttemptTransportCaps {
            max_member_bytes: ceiling,
            max_attempt_bytes: MAX_ATTEMPT_BYTES,
        },
        ..attempt.clone()
    };
    write_attempt(std::io::sink(), &probe)
}

/// The observation of an input and whether plugins/eval decoded a member.
fn compute(attempt: &CaseAttempt, input: Option<&InputV1>) -> (ObservedV1, bool) {
    match input {
        None => (ObservedV1::NoInput, false),
        Some(InputV1::Metric(bytes)) => (metric(bytes), true),
        Some(InputV1::Quantization(bytes)) => (quantization(bytes), true),
        Some(InputV1::Oversized { length, ceiling }) => transported(attempt, *length, *ceiling)
            .map_or_else(
                |error| (ObservedV1::TransportRejection(error), false),
                |()| (metric(&vec![0_u8; *length]), true),
            ),
    }
}

/// The refusal of the gate, if it refuses.
fn refusal(gate: &GateV1, attempt: &CaseAttempt) -> Option<ObservedV1> {
    match gate {
        GateV1::Capability(capability) => {
            (capability != CAPABILITY_ID).then_some(ObservedV1::Denied)
        }
        GateV1::Network => Some(ObservedV1::Denied),
        GateV1::Steps(requested) => {
            (*requested > attempt.budget.execution_steps).then_some(ObservedV1::ResourceLimit)
        }
        GateV1::Contract { own } => (!own).then_some(ObservedV1::IncompatibleContract),
    }
}

/// Run one sub-case: its gate, then its input.
pub(super) fn run_subcase(subcase: &SubCaseV1, attempt: &CaseAttempt) -> RecordV1 {
    let (observed, decoded) = match &subcase.step {
        StepV1::EvaluatorOwned(kind) => (ObservedV1::EvaluatorOwned(*kind), false),
        StepV1::Subject { gate, input } => gate
            .as_ref()
            .and_then(|gate| refusal(gate, attempt))
            .map_or_else(
                || compute(attempt, input.as_ref()),
                |refused| (refused, false),
            ),
    };
    RecordV1 {
        id: subcase.id.clone(),
        matched: observed.outcome() == subcase.expect,
        steps: u64::from(decoded),
        observed,
    }
}

/// The output entry of one sub-case.
fn entry(record: &RecordV1) -> Value {
    let id = record.id.as_str();
    match &record.observed {
        ObservedV1::Output {
            record: kind,
            bytes,
            values,
        } => json!({
            "blake3": blake3::hash(bytes).to_hex().as_str(),
            "hex": hex(bytes),
            "id": id,
            "record": kind.name(),
            "values": values,
        }),
        ObservedV1::MetricError(failure) => json!({
            "code": failure.error.code(),
            "error": error_name(failure.error),
            "first_coordinate": failure.coordinate,
            "id": id,
            "kind": "metric-error",
        }),
        ObservedV1::TransportRejection(error) => json!({
            "error": format!("{error:?}"),
            "id": id,
            "kind": "transport-rejection",
        }),
        ObservedV1::Denied => json!({"id": id, "kind": "denied"}),
        ObservedV1::ResourceLimit => json!({"id": id, "kind": "resource-limit"}),
        ObservedV1::IncompatibleContract => json!({"id": id, "kind": "incompatible-contract"}),
        ObservedV1::NoInput => json!({"id": id, "kind": "no-input"}),
        ObservedV1::EvaluatorOwned(kind) => json!({"id": id, "kind": kind}),
    }
}

/// The output record of a `canonical-output` family: RFC 8785 JSON (every key is ASCII and
/// `serde_json` orders object keys) followed by one LF byte, like the oracle.
pub(super) fn output_record(case_id: &str, family: &str, records: &[RecordV1]) -> Vec<u8> {
    let record = json!({
        "case_id": case_id,
        "claim_layer": "metric-conformance",
        "family": family,
        "oracle": {"kind": "canonical-output"},
        "output": {"subcases": records.iter().map(entry).collect::<Vec<Value>>()},
    });
    let mut bytes = record.to_string().into_bytes();
    bytes.push(b'\n');
    bytes
}
