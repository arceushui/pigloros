use ed25519_dalek::Verifier;
use pos_core::CanonicalBytes;
use serde::{Deserialize, Serialize};

const MAX_REPORT_BYTES: usize = 64 * 1024;
const FIXTURES: [(&str, &[&str], u8); 12] = [
    (
        "NI-TOOL-001",
        &[
            "Imported-service registry",
            "tool result handle",
            "Plugin imports",
            "staged EventDrafts",
            "public outcome",
            "audit record",
        ],
        0,
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
        ],
        1,
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
        ],
        2,
    ),
    (
        "NI-OBS-004",
        &[
            "Structured logs",
            "metric names/labels/counts",
            "trace spans",
            "crash artifact",
            "public support bundle",
        ],
        3,
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
        ],
        4,
    ),
    (
        "NI-PUBLIC-006",
        &[
            "HTTP/Plugin error",
            "status transition",
            "cursor bytes",
            "page count",
            "response length/padding",
        ],
        5,
    ),
    (
        "NI-EVAL-007",
        &[
            "Export bundle",
            "manifest",
            "fixture descriptor",
            "evaluator stdin/files",
            "ConformanceReport",
        ],
        5,
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
        ],
        5,
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
        ],
        5,
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
        ],
        2,
    ),
    (
        "NI-SERVICE-011",
        &[
            "Exact request digest",
            "frozen response projection",
            "call ordinal",
            "PluginInvocation",
            "generated dependency edges",
        ],
        5,
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
        ],
        3,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Variant {
    Success,
    Denial,
    WarmCache,
    ColdCache,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Local,
    AirGapped,
    Replay,
    Fork,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinate {
    fixture_id: String,
    variant: Variant,
    mode: Mode,
    surface_ordinal: u16,
    byte_offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeRef {
    #[serde(rename = "m")]
    mode: Mode,
    #[serde(rename = "g")]
    genuine_execution: bool,
    #[serde(rename = "r")]
    result_digest: [u8; 32],
    #[serde(rename = "a")]
    artifact_digest: [u8; 32],
    #[serde(rename = "p")]
    execution_provenance_digest: [u8; 32],
    #[serde(rename = "e")]
    equal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    #[serde(rename = "i")]
    fixture_id: String,
    #[serde(rename = "v")]
    variant: Variant,
    #[serde(rename = "f")]
    fixture_digest: [u8; 32],
    #[serde(rename = "p")]
    profile_digest: [u8; 32],
    #[serde(rename = "n")]
    normalization_digest: [u8; 32],
    #[serde(rename = "m")]
    modes: Vec<ModeRef>,
    #[serde(rename = "d")]
    first_divergence: Option<Coordinate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedReport {
    #[serde(rename = "m")]
    magic: String,
    #[serde(rename = "v")]
    version: u16,
    #[serde(rename = "f")]
    fixture_set_digest: [u8; 32],
    #[serde(rename = "p")]
    profile_set_digest: [u8; 32],
    #[serde(rename = "n")]
    normalization_set_digest: [u8; 32],
    #[serde(rename = "a")]
    artifact_set_digest: [u8; 32],
    #[serde(rename = "e")]
    execution_provenance_digest: [u8; 32],
    #[serde(rename = "o")]
    outcomes: Vec<Outcome>,
    #[serde(rename = "k")]
    signer_public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    #[serde(rename = "m")]
    magic: String,
    #[serde(rename = "v")]
    version: u16,
    #[serde(rename = "f")]
    fixture_set_digest: [u8; 32],
    #[serde(rename = "p")]
    profile_set_digest: [u8; 32],
    #[serde(rename = "n")]
    normalization_set_digest: [u8; 32],
    #[serde(rename = "a")]
    artifact_set_digest: [u8; 32],
    #[serde(rename = "e")]
    execution_provenance_digest: [u8; 32],
    #[serde(rename = "o")]
    outcomes: Vec<Outcome>,
    #[serde(rename = "k")]
    signer_public_key: [u8; 32],
    #[serde(rename = "d")]
    report_digest: [u8; 32],
    #[serde(rename = "s")]
    signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IndependentNonInterferenceReportErrorV1 {
    #[error("independent evaluator rejected report shape")]
    InvalidShape,
    #[error("independent evaluator rejected report digest")]
    DigestInvalid,
    #[error("independent evaluator rejected report signature")]
    SignatureInvalid,
    #[error("independent evaluator rejected noncanonical report")]
    NonCanonical,
    #[error("independent evaluator rejected oversized report")]
    TooLarge,
}

/// Independently verify NIR1 and return whether all 192 mode executions agree.
///
/// # Errors
/// Rejects malformed, noncanonical, incomplete, reordered, synthetic,
/// digest-mismatched, or incorrectly signed reports.
pub fn verify_non_interference_report_v1(
    bytes: &[u8],
) -> Result<bool, IndependentNonInterferenceReportErrorV1> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err(IndependentNonInterferenceReportErrorV1::TooLarge);
    }
    let canonical = CanonicalBytes::from_vec(bytes.to_vec());
    let report: Report = pos_crypto::canonical::decode(&canonical)
        .map_err(|_| IndependentNonInterferenceReportErrorV1::NonCanonical)?;
    if encode(&report)? != bytes {
        return Err(IndependentNonInterferenceReportErrorV1::NonCanonical);
    }
    validate_shape(&report)?;
    let unsigned = UnsignedReport {
        magic: report.magic.clone(),
        version: report.version,
        fixture_set_digest: report.fixture_set_digest,
        profile_set_digest: report.profile_set_digest,
        normalization_set_digest: report.normalization_set_digest,
        artifact_set_digest: report.artifact_set_digest,
        execution_provenance_digest: report.execution_provenance_digest,
        outcomes: report.outcomes.clone(),
        signer_public_key: report.signer_public_key,
    };
    let unsigned = encode(&unsigned)?;
    if report.report_digest != domain_digest(b"PiglorOS.NonInterference.Report.v1", &unsigned) {
        return Err(IndependentNonInterferenceReportErrorV1::DigestInvalid);
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&report.signer_public_key)
        .map_err(|_| IndependentNonInterferenceReportErrorV1::SignatureInvalid)?;
    let signature: [u8; 64] = report
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| IndependentNonInterferenceReportErrorV1::SignatureInvalid)?;
    key.verify(
        &signature_message(&unsigned),
        &ed25519_dalek::Signature::from_bytes(&signature),
    )
    .map_err(|_| IndependentNonInterferenceReportErrorV1::SignatureInvalid)?;
    Ok(report
        .outcomes
        .iter()
        .all(|outcome| outcome.modes.iter().all(|mode| mode.equal)))
}

fn validate_shape(report: &Report) -> Result<(), IndependentNonInterferenceReportErrorV1> {
    if report.magic != "NIR1" || report.version != 1 || report.outcomes.len() != 48 {
        return Err(IndependentNonInterferenceReportErrorV1::InvalidShape);
    }
    let variants = [
        Variant::Success,
        Variant::Denial,
        Variant::WarmCache,
        Variant::ColdCache,
    ];
    let modes = [Mode::Local, Mode::AirGapped, Mode::Replay, Mode::Fork];
    for ((outcome, (fixture_id, surfaces, normalization)), variant) in report
        .outcomes
        .iter()
        .zip(
            FIXTURES
                .iter()
                .flat_map(|value| std::iter::repeat_n(value, 4)),
        )
        .zip(variants.into_iter().cycle())
    {
        let profile = profile_digest(fixture_id, surfaces, *normalization);
        if outcome.fixture_id != *fixture_id
            || outcome.variant != variant
            || outcome.fixture_digest == [0; 32]
            || outcome.profile_digest != profile
            || outcome.normalization_digest
                != domain_digest(b"PiglorOS.NonInterference.Normalization.v1", &profile)
            || outcome.modes.len() != 4
        {
            return Err(IndependentNonInterferenceReportErrorV1::InvalidShape);
        }
        for (mode, expected) in outcome.modes.iter().zip(modes) {
            if mode.mode != expected
                || !mode.genuine_execution
                || mode.result_digest == [0; 32]
                || mode.artifact_digest == [0; 32]
                || mode.execution_provenance_digest == [0; 32]
            {
                return Err(IndependentNonInterferenceReportErrorV1::InvalidShape);
            }
        }
        match (
            outcome.modes.iter().find(|mode| !mode.equal),
            &outcome.first_divergence,
        ) {
            (None, None) => {}
            (Some(mode), Some(coordinate))
                if coordinate.fixture_id == outcome.fixture_id
                    && coordinate.variant == outcome.variant
                    && coordinate.mode == mode.mode => {}
            _ => return Err(IndependentNonInterferenceReportErrorV1::InvalidShape),
        }
    }
    let aggregates = aggregate_fields(&report.outcomes);
    if [
        report.fixture_set_digest,
        report.profile_set_digest,
        report.normalization_set_digest,
        report.artifact_set_digest,
        report.execution_provenance_digest,
    ] != aggregates
        || report.report_digest == [0; 32]
    {
        return Err(IndependentNonInterferenceReportErrorV1::DigestInvalid);
    }
    Ok(())
}

fn profile_digest(fixture_id: &str, surfaces: &[&str], normalization: u8) -> [u8; 32] {
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, fixture_id.as_bytes());
    for surface in surfaces {
        append_bytes(&mut bytes, surface.as_bytes());
    }
    bytes.extend_from_slice(&[0, 1, 2, 3]);
    bytes.extend_from_slice(&[0, 1, 2, 3]);
    bytes.push(normalization);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&(1024_u64 * 1024).to_be_bytes());
    domain_digest(b"PiglorOS.NonInterference.CaptureProfile.v1", &bytes)
}

fn aggregate_fields(outcomes: &[Outcome]) -> [[u8; 32]; 5] {
    [
        aggregate(
            b"PiglorOS.NonInterference.FixtureSet.v1",
            outcomes.iter().map(|v| v.fixture_digest),
        ),
        aggregate(
            b"PiglorOS.NonInterference.ProfileSet.v1",
            outcomes.iter().map(|v| v.profile_digest),
        ),
        aggregate(
            b"PiglorOS.NonInterference.NormalizationSet.v1",
            outcomes.iter().map(|v| v.normalization_digest),
        ),
        aggregate(
            b"PiglorOS.NonInterference.ArtifactSet.v1",
            outcomes
                .iter()
                .flat_map(|v| v.modes.iter().map(|m| m.artifact_digest)),
        ),
        aggregate(
            b"PiglorOS.NonInterference.ExecutionProvenanceSet.v1",
            outcomes
                .iter()
                .flat_map(|v| v.modes.iter().map(|m| m.execution_provenance_digest)),
        ),
    ]
}

fn aggregate(domain: &[u8], values: impl IntoIterator<Item = [u8; 32]>) -> [u8; 32] {
    domain_digest(domain, &values.into_iter().flatten().collect::<Vec<_>>())
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn signature_message(unsigned: &[u8]) -> Vec<u8> {
    let mut message = b"PiglorOS.NonInterference.Report.Signature.v1\0".to_vec();
    message.extend_from_slice(unsigned);
    message
}

fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, IndependentNonInterferenceReportErrorV1> {
    pos_crypto::canonical::encode(value)
        .map(|bytes| bytes.as_slice().to_vec())
        .map_err(|_| IndependentNonInterferenceReportErrorV1::NonCanonical)
}
