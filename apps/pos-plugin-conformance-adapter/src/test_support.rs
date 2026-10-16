//! Attempts, composites and runners for the tests of the case driver.

use std::sync::Mutex;

use ciborium::value::Value;
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{
    AttemptArtifact, AttemptTransportCaps, CaseAttempt, SubjectObservation,
};
use pos_reference::evaluator_domain::{ClaimLayer, ExecutionMode, FixtureFamily};
use pos_reference::profile::DeterministicBudget;
use pos_runtime::community_plugin_host::CommunityPluginModeV1;
use serde_json::{json, Value as Json};

use crate::hex;
use crate::payload::SubCaseV1;
use crate::schema_digests::placeholder_schema;
use crate::{PiecesV1, SubCaseRecordV1, SubCaseRunnerV1, SCHEMA_ID};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[must_use]
pub fn hex_of(bytes: &[u8]) -> String {
    hex::encode(&digest(bytes))
}

#[must_use]
pub fn artifact(bytes: Vec<u8>) -> AttemptArtifact {
    AttemptArtifact {
        digest: digest(&bytes),
        bytes,
    }
}

/// The canonical `PCW2` composite of `entries`, in the given order.
///
/// # Errors
/// Returns the encoding or decoding error.
pub fn composite_of(entries: &[([u8; 32], &[u8])]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let list = entries
        .iter()
        .map(|(d, b)| Value::Array(vec![Value::Bytes(d.to_vec()), Value::Bytes(b.to_vec())]))
        .collect();
    let value = Value::Array(vec![
        Value::Text("PCW2".to_owned()),
        Value::Integer(1_u8.into()),
        Value::Array(list),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out)?;
    Ok(out)
}

/// The entries of `blobs`, sorted by digest.
#[must_use]
pub fn sorted<'a>(blobs: &[&'a [u8]]) -> Vec<([u8; 32], &'a [u8])> {
    let mut entries: Vec<([u8; 32], &[u8])> = blobs.iter().map(|b| (digest(b), *b)).collect();
    entries.sort();
    entries
}

/// The canonical `PCW2` composite of `blobs`, sorted by digest.
///
/// # Errors
/// Returns the encoding or decoding error.
pub fn composite(blobs: &[&[u8]]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    composite_of(&sorted(blobs))
}

/// An attempt of `family` in `mode`, whose schema member is the pinned one, with `payload` and
/// the auxiliary members `auxiliary` (an evidence member is not added).
pub fn attempt(
    family: FixtureFamily,
    mode: ExecutionMode,
    payload: Vec<u8>,
    auxiliary: Vec<Vec<u8>>,
) -> CaseAttempt {
    CaseAttempt {
        case_id: "case-1".to_owned(),
        claim_layer: ClaimLayer::PluginConformance,
        family,
        mode,
        fixture_digest: [9; 32],
        schema: artifact(placeholder_schema(family).to_vec()),
        payload: artifact(payload),
        auxiliary: auxiliary.into_iter().map(artifact).collect(),
        budget: DeterministicBudget {
            memory_bytes: 1,
            cpu_fuel: 1,
            host_calls: 1,
            event_count: 1,
            output_bytes: 1_048_576,
            storage_bytes: 1,
            execution_steps: 1,
            simulation_time_ns: 1,
        },
        watchdog_ms: 60_000,
        network_allowed: false,
        capability_ids: Vec::new(),
        transport_caps: AttemptTransportCaps {
            max_member_bytes: 16_777_216,
            max_attempt_bytes: 33_554_432,
        },
    }
}

/// The EAI1 stream of `attempt`.
///
/// # Errors
/// Returns the encoding or decoding error.
pub fn stream(attempt: &CaseAttempt) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    write_attempt(&mut out, attempt)?;
    Ok(out)
}

/// The observation written to `out`.
///
/// # Errors
/// Returns the encoding or decoding error.
pub fn observation(out: &[u8]) -> Result<SubjectObservation, Box<dyn std::error::Error>> {
    Ok(read_observation(out, 1_048_576)?)
}

/// A sub-case that needs no piece: it computes the BLAKE3 of `input`.
#[must_use]
pub fn blake3_subcase(id: &str, input: &str) -> Json {
    let expected = hex_of(input.as_bytes());
    json!({
        "id": id,
        "steps": [],
        "expect": {
            "kind": "digest",
            "compute": {"what": "blake3_of", "input": input},
            "value": expected,
        },
    })
}

/// The payload document of `family` over `subcases`.
#[must_use]
pub fn payload(family: &str, subcases: Vec<Json>) -> Json {
    let mut document = json!({"schema": SCHEMA_ID, "family": family});
    document["subcases"] = Json::Array(subcases);
    document
}

/// A record of sub-case `id` that matched, with nothing else.
#[must_use]
pub fn matched(id: &str) -> SubCaseRecordV1 {
    SubCaseRecordV1 {
        matched: true,
        ..SubCaseRecordV1::empty(id)
    }
}

/// A runner that answers every sub-case with `answer` and records the calls.
pub struct FakeRunner<F> {
    answer: F,
    calls: Mutex<Vec<(String, CommunityPluginModeV1)>>,
}

impl<F: Fn(&SubCaseV1) -> SubCaseRecordV1> FakeRunner<F> {
    pub fn new(answer: F) -> Self {
        Self {
            answer,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// The sub-case IDs and modes the runner was asked for, in order.
    pub fn calls(&self) -> Vec<(String, CommunityPluginModeV1)> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }
}

impl<F: Fn(&SubCaseV1) -> SubCaseRecordV1> SubCaseRunnerV1 for FakeRunner<F> {
    fn run(
        &self,
        subcase: &SubCaseV1,
        _pieces: &PiecesV1,
        mode: CommunityPluginModeV1,
    ) -> SubCaseRecordV1 {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push((subcase.id.as_str().to_owned(), mode));
        }
        (self.answer)(subcase)
    }
}

/// The Ed25519 base point, a valid verification key.
#[must_use]
pub fn operator_key() -> Vec<u8> {
    let mut key = vec![0x66; 32];
    key[0] = 0x58;
    key
}

/// A canonical `PCA1` anchor piece.
#[must_use]
pub fn anchor_bytes() -> Vec<u8> {
    let value = Value::Array(vec![
        Value::Text("PCA1".to_owned()),
        Value::Integer(1_u8.into()),
        Value::Text("scope".to_owned()),
        Value::Bytes(vec![1; 32]),
        Value::Bytes(operator_key()),
        Value::Bytes(vec![3; 32]),
    ]);
    let mut out = Vec::new();
    drop(ciborium::into_writer(&value, &mut out));
    out
}

/// The pieces every release and material of the interpreter tests names: the releases `a` and
/// `b`, one TPS1, one PTR1, one PRV1 and a good anchor.
#[must_use]
pub fn pieces() -> PiecesV1 {
    PiecesV1::from_blobs([
        b"manifest-a".to_vec(),
        b"blob-a".to_vec(),
        b"manifest-b".to_vec(),
        b"blob-b".to_vec(),
        b"tps1".to_vec(),
        b"ptr1".to_vec(),
        b"prv1".to_vec(),
        anchor_bytes(),
    ])
}

/// The `release` object of release `name` (`a` or `b`).
#[must_use]
pub fn release(name: &str) -> Json {
    json!({
        "manifest": hex_of(format!("manifest-{name}").as_bytes()),
        "blobs": [hex_of(format!("blob-{name}").as_bytes())],
    })
}

/// The `material` object of the interpreter tests.
#[must_use]
pub fn material() -> Json {
    json!({
        "anchor": hex_of(&anchor_bytes()),
        "tps1": hex_of(b"tps1"),
        "ptr1": [hex_of(b"ptr1")],
        "prv1": [hex_of(b"prv1")],
    })
}

/// A sub-case document.
#[must_use]
pub fn subcase(id: &str, steps: Vec<Json>, expect: Json) -> Json {
    let mut document = json!({"id": id});
    document["steps"] = Json::Array(steps);
    document["expect"] = expect;
    document
}

/// The sub-case of `value`.
///
/// # Errors
/// Returns the encoding or decoding error.
pub fn parsed(value: &Json) -> Result<SubCaseV1, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(value.clone())?)
}
