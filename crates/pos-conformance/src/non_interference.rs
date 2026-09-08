use crate::{
    ExecutionModeV1, NonInterferenceCaseV1, NonInterferenceDivergenceCoordinateV1,
    NonInterferenceVariantV1, NON_INTERFERENCE_CASE_COUNT_V1, NON_INTERFERENCE_FIXTURE_IDS_V1,
};
use serde::{Deserialize, Serialize};

const MAX_PERMITTED_INPUT_BYTES: usize = 1024 * 1024;
const MAX_UNAUTHORIZED_VALUE_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

/// Return the canonical ADR-059 capture surface order for one matrix row.
#[must_use]
pub fn non_interference_surface_names_v1(fixture_id: &str) -> Option<&'static [&'static str]> {
    match fixture_id {
        "NI-TOOL-001" => Some(&[
            "Imported-service registry",
            "tool result handle",
            "Plugin imports",
            "staged EventDrafts",
            "public outcome",
            "audit record",
        ]),
        "NI-CACHE-002" => Some(&[
            "Cache API return",
            "snapshot bytes",
            "Plugin inputs",
            "typed errors",
            "logs/metrics",
            "evaluator bundle",
        ]),
        "NI-STATE-003" => Some(&[
            "Migration request/result",
            "activated state",
            "PluginInvocation",
            "PluginOutput",
            "EventDrafts",
            "quarantine/error",
        ]),
        "NI-OBS-004" => Some(&[
            "Structured logs",
            "metric names/labels/counts",
            "trace spans",
            "crash artifact",
            "public support bundle",
        ]),
        "NI-TIME-005" => Some(&[
            "Plugin imports",
            "deterministic deadline",
            "safe-stop record",
            "status/error",
            "logs/metrics",
            "evaluator input",
        ]),
        "NI-PUBLIC-006" => Some(&[
            "HTTP/Plugin error",
            "status transition",
            "cursor bytes",
            "page count",
            "response length/padding",
        ]),
        "NI-EVAL-007" => Some(&[
            "Export bundle",
            "manifest",
            "fixture descriptor",
            "evaluator stdin/files",
            "ConformanceReport",
        ]),
        "NI-FORK-008" => Some(&[
            "Fork parent/cut",
            "CounterfactualPlan",
            "RecomputationFrontier",
            "SuffixInvalidation",
            "snapshots",
            "checkpoints",
            "result",
            "ReproManifest",
            "exports",
        ]),
        "NI-ARCHIVE-009" => Some(&[
            "Member table",
            "archive bytes",
            "decompressed bundle",
            "digest",
            "evaluator import",
            "logs",
        ]),
        "NI-NET-010" => Some(&[
            "Capability checks",
            "attempted-call records",
            "retry count",
            "Plugin output",
            "Timeline",
            "logs",
            "evaluator bundle",
        ]),
        "NI-SERVICE-011" => Some(&[
            "Exact request digest",
            "frozen response projection",
            "call ordinal",
            "PluginInvocation",
            "generated dependency edges",
        ]),
        "NI-CRASH-012" => Some(&[
            "Guest error",
            "host error mapping",
            "quarantine",
            "crash report",
            "support archive",
            "next Tick status",
        ]),
        _ => None,
    }
}

/// Return the canonical ADR-059 operational normalization rule for one row.
#[must_use]
pub fn non_interference_normalization_policy_v1(fixture_id: &str) -> Option<&'static str> {
    match fixture_id {
        "NI-TOOL-001" => Some("count/category/digest; provider text absent"),
        "NI-CACHE-002" => Some("bounded hit-class counters; keys/values/latency absent"),
        "NI-STATE-003" => Some("migration phase/category; canary bytes/digests absent"),
        "NI-OBS-004" => Some("schema/category/count/padded length; text/stack/path/raw IDs absent"),
        "NI-TIME-005" => Some("wall timestamps/durations absent"),
        "NI-PUBLIC-006" => Some("byte-exact public shape; operational diagnostics absent"),
        "NI-EVAL-007" => Some("evaluator members/names/order/bytes/digests byte-exact"),
        "NI-FORK-008" => Some("artifact bytes/digests/order and ReplayClaim byte-exact"),
        "NI-ARCHIVE-009" => {
            Some("canonical members/decompressed bytes; profile-fixed archive bytes")
        }
        "NI-NET-010" => Some("category/count only; endpoint/body/timing absent"),
        "NI-SERVICE-011" => Some("request/projection/ordinal/edges/output byte-exact"),
        "NI-CRASH-012" => Some("safe category/count/padded length; diagnostics absent"),
        _ => None,
    }
}

/// Closed failures from fixture admission or host-owned capture.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NonInterferenceExecutionErrorV1 {
    #[error("non-interference fixture is invalid")]
    FixtureInvalid,
    #[error("a required non-interference capture is unavailable")]
    CaptureUnavailable,
    #[error("non-interference capture exceeded its deterministic bounds")]
    CaptureOutOfBounds,
    #[error("a deterministic non-interference run attempted live network access")]
    UnexpectedNetworkAccess,
}

/// A signed/content-addressable control/canary input pair.
///
/// The public subject invocation is derived only from `permitted_input`. The
/// two unauthorized values remain host-owned and are used solely to bind the
/// distinct control and canary fixture identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceFixturePairV1 {
    pub fixture_id: String,
    pub variant: NonInterferenceVariantV1,
    pub mode: ExecutionModeV1,
    pub permitted_input: Vec<u8>,
    pub control_unauthorized_value: Vec<u8>,
    pub canary_unauthorized_value: Vec<u8>,
    pub fixture_digest: [u8; 32],
}

impl NonInterferenceFixturePairV1 {
    /// Admit a pair whose only control/canary semantic difference is the
    /// host-owned unauthorized value.
    ///
    /// # Errors
    /// Returns [`NonInterferenceExecutionErrorV1::FixtureInvalid`] for an
    /// unknown coordinate, empty/equal secrets, or a mismatched digest.
    pub fn try_new(
        fixture_id: impl Into<String>,
        variant: NonInterferenceVariantV1,
        mode: ExecutionModeV1,
        permitted_input: Vec<u8>,
        control_unauthorized_value: Vec<u8>,
        canary_unauthorized_value: Vec<u8>,
    ) -> Result<Self, NonInterferenceExecutionErrorV1> {
        let mut value = Self {
            fixture_id: fixture_id.into(),
            variant,
            mode,
            permitted_input,
            control_unauthorized_value,
            canary_unauthorized_value,
            fixture_digest: [0; 32],
        };
        value.validate_fields()?;
        value.fixture_digest = value.expected_digest();
        Ok(value)
    }

    /// Validate a deserialized fixture pair, including its content address.
    ///
    /// # Errors
    /// Returns a closed fixture error without exposing either unauthorized
    /// value.
    pub fn validate(&self) -> Result<(), NonInterferenceExecutionErrorV1> {
        self.validate_fields()?;
        if self.fixture_digest == [0; 32] || self.fixture_digest != self.expected_digest() {
            return Err(NonInterferenceExecutionErrorV1::FixtureInvalid);
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), NonInterferenceExecutionErrorV1> {
        if !NON_INTERFERENCE_FIXTURE_IDS_V1.contains(&self.fixture_id.as_str())
            || self.permitted_input.is_empty()
            || self.permitted_input.len() > MAX_PERMITTED_INPUT_BYTES
            || self.control_unauthorized_value.len() > MAX_UNAUTHORIZED_VALUE_BYTES
            || self.canary_unauthorized_value.len() > MAX_UNAUTHORIZED_VALUE_BYTES
            || self.control_unauthorized_value == self.canary_unauthorized_value
            || contains_subslice(&self.permitted_input, &self.control_unauthorized_value)
            || contains_subslice(&self.permitted_input, &self.canary_unauthorized_value)
        {
            return Err(NonInterferenceExecutionErrorV1::FixtureInvalid);
        }
        Ok(())
    }

    fn expected_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, self.fixture_id.as_bytes());
        bytes.push(variant_code(self.variant));
        bytes.push(mode_code(self.mode));
        append_bytes(&mut bytes, &self.permitted_input);
        append_bytes(&mut bytes, &self.control_unauthorized_value);
        append_bytes(&mut bytes, &self.canary_unauthorized_value);
        domain_digest(b"PiglorOS.NonInterferenceFixture.v1", &bytes)
    }

    fn invocation(&self) -> NonInterferenceInvocationV1<'_> {
        NonInterferenceInvocationV1 {
            fixture_id: &self.fixture_id,
            variant: self.variant,
            mode: self.mode,
            permitted_input: &self.permitted_input,
        }
    }
}

/// The complete input visible to the implementation under test.
///
/// There is deliberately no accessor for either unauthorized fixture value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonInterferenceInvocationV1<'a> {
    pub fixture_id: &'a str,
    pub variant: NonInterferenceVariantV1,
    pub mode: ExecutionModeV1,
    pub permitted_input: &'a [u8],
}

/// Which member of an admitted control/canary pair the host must execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonInterferenceMatrixMemberV1 {
    Control,
    Canary,
}

/// Host-side input for one real matrix execution.
///
/// The host receives the changed unauthorized value so it can place it in the
/// fixture's declared denied channel. The nested subject invocation is the
/// only value that may cross the Plugin/evaluator boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonInterferenceHostRunV1<'a> {
    pub member: NonInterferenceMatrixMemberV1,
    pub subject: NonInterferenceInvocationV1<'a>,
    pub unauthorized_value: &'a [u8],
}

/// Host-captured outputs from one real subject execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonInterferenceCaptureV1 {
    /// Every ADR-059 row surface, in its canonical order.
    pub surface_names: Vec<String>,
    pub authoritative: Vec<Vec<u8>>,
    pub public: Vec<Vec<u8>>,
    pub operational: Vec<Vec<u8>>,
    pub unexpected_network_accesses: u32,
    pub provenance_digest: [u8; 32],
}

impl NonInterferenceCaptureV1 {
    fn validate(&self, fixture_id: &str) -> Result<(), NonInterferenceExecutionErrorV1> {
        if self.unexpected_network_accesses != 0 {
            return Err(NonInterferenceExecutionErrorV1::UnexpectedNetworkAccess);
        }
        let expected_names = non_interference_surface_names_v1(fixture_id)
            .ok_or(NonInterferenceExecutionErrorV1::CaptureUnavailable)?;
        if !self
            .surface_names
            .iter()
            .map(String::as_str)
            .eq(expected_names.iter().copied())
            || self.authoritative.len() != expected_names.len()
            || self.public.len() != expected_names.len()
            || self.operational.len() != expected_names.len()
        {
            return Err(NonInterferenceExecutionErrorV1::CaptureUnavailable);
        }
        let bytes = self
            .surface_names
            .iter()
            .map(String::len)
            .chain(
                self.authoritative
                    .iter()
                    .chain(&self.public)
                    .chain(&self.operational)
                    .map(Vec::len),
            )
            .fold(0_usize, usize::saturating_add);
        if self
            .authoritative
            .iter()
            .chain(&self.public)
            .chain(&self.operational)
            .any(Vec::is_empty)
            || bytes > MAX_CAPTURE_BYTES
            || self.provenance_digest == [0; 32]
        {
            return Err(NonInterferenceExecutionErrorV1::CaptureOutOfBounds);
        }
        Ok(())
    }
}

/// Execute and compare one admitted pair through a public subject seam.
///
/// The executor is called twice with the same permitted invocation. Raw
/// captured surfaces are reduced to digests and a safe coordinate before the
/// result leaves this function.
///
/// # Errors
/// Returns a closed admission/capture failure. Divergence is evidence, not an
/// execution error, and is represented in the returned case.
pub fn execute_non_interference_pair<F>(
    fixture: &NonInterferenceFixturePairV1,
    execute: F,
) -> Result<NonInterferenceCaseV1, NonInterferenceExecutionErrorV1>
where
    F: FnMut(
        &NonInterferenceHostRunV1<'_>,
    ) -> Result<NonInterferenceCaptureV1, NonInterferenceExecutionErrorV1>,
{
    execute_pair_with_captures(fixture, execute).map(|(case, _, _)| case)
}

fn execute_pair_with_captures<F>(
    fixture: &NonInterferenceFixturePairV1,
    mut execute: F,
) -> Result<
    (
        NonInterferenceCaseV1,
        NonInterferenceCaptureV1,
        NonInterferenceCaptureV1,
    ),
    NonInterferenceExecutionErrorV1,
>
where
    F: FnMut(
        &NonInterferenceHostRunV1<'_>,
    ) -> Result<NonInterferenceCaptureV1, NonInterferenceExecutionErrorV1>,
{
    let invocation = fixture.invocation();
    fixture
        .validate()
        .and_then(|()| {
            execute(&NonInterferenceHostRunV1 {
                member: NonInterferenceMatrixMemberV1::Control,
                subject: invocation,
                unauthorized_value: &fixture.control_unauthorized_value,
            })
        })
        .and_then(|control| control.validate(&fixture.fixture_id).map(|()| control))
        .and_then(|control| {
            execute(&NonInterferenceHostRunV1 {
                member: NonInterferenceMatrixMemberV1::Canary,
                subject: invocation,
                unauthorized_value: &fixture.canary_unauthorized_value,
            })
            .and_then(|canary| canary.validate(&fixture.fixture_id).map(|()| canary))
            .map(|canary| case_with_captures(fixture, control, canary))
        })
}

fn case_with_captures(
    fixture: &NonInterferenceFixturePairV1,
    control: NonInterferenceCaptureV1,
    canary: NonInterferenceCaptureV1,
) -> (
    NonInterferenceCaseV1,
    NonInterferenceCaptureV1,
    NonInterferenceCaptureV1,
) {
    let authoritative_equal = control.authoritative == canary.authoritative;
    let public_equal = control.public == canary.public;
    let operational_equal = control.operational == canary.operational;
    let first_divergence = first_divergence(fixture, &control, &canary);
    let authoritative_digest = capture_digest(b"authoritative", fixture, &control.authoritative);
    let canary_authoritative_digest =
        capture_digest(b"authoritative", fixture, &canary.authoritative);
    let public_digest = capture_digest(b"public", fixture, &control.public);
    let canary_public_digest = capture_digest(b"public", fixture, &canary.public);
    let operational_digest = capture_digest(b"operational", fixture, &control.operational);
    let canary_operational_digest = capture_digest(b"operational", fixture, &canary.operational);
    let mut provenance = Vec::new();
    provenance.extend_from_slice(&fixture.fixture_digest);
    provenance.extend_from_slice(&control.provenance_digest);
    provenance.extend_from_slice(&canary.provenance_digest);

    let case = NonInterferenceCaseV1 {
        fixture_id: fixture.fixture_id.clone(),
        variant: fixture.variant,
        mode: fixture.mode,
        control_input_digest: input_digest(
            b"PiglorOS.NonInterference.ControlInput.v1",
            &fixture.permitted_input,
            &fixture.control_unauthorized_value,
        ),
        canary_input_digest: input_digest(
            b"PiglorOS.NonInterference.CanaryInput.v1",
            &fixture.permitted_input,
            &fixture.canary_unauthorized_value,
        ),
        authoritative_digest,
        canary_authoritative_digest,
        public_digest,
        canary_public_digest,
        operational_digest,
        canary_operational_digest,
        authoritative_equal,
        public_equal,
        operational_equal,
        first_divergence,
        first_cross_mode_divergence: None,
        provenance_digest: domain_digest(b"PiglorOS.NonInterference.Provenance.v1", &provenance),
    };
    (case, control, canary)
}

/// Execute the complete canonical 12 × 4 × 4 matrix.
///
/// # Errors
/// Returns the first closed fixture or capture failure. It never converts a
/// missing execution into a skipped/pass result.
pub fn execute_wave8_non_interference_matrix<F>(
    seed: [u8; 32],
    mut execute: F,
) -> Result<Vec<NonInterferenceCaseV1>, NonInterferenceExecutionErrorV1>
where
    F: FnMut(
        &NonInterferenceHostRunV1<'_>,
    ) -> Result<NonInterferenceCaptureV1, NonInterferenceExecutionErrorV1>,
{
    let variants = [
        NonInterferenceVariantV1::Success,
        NonInterferenceVariantV1::Denial,
        NonInterferenceVariantV1::WarmCache,
        NonInterferenceVariantV1::ColdCache,
    ];
    let modes = [
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Replay,
        ExecutionModeV1::Fork,
    ];
    let mut cases = Vec::with_capacity(NON_INTERFERENCE_CASE_COUNT_V1);
    for fixture_id in NON_INTERFERENCE_FIXTURE_IDS_V1 {
        for variant in variants {
            let permitted = matrix_value(seed, fixture_id, variant, b"permitted");
            let mut local_capture = None;
            for mode in modes {
                let control = matrix_value(seed, fixture_id, variant, b"control-unauthorized");
                let canary = matrix_value(seed, fixture_id, variant, b"canary-unauthorized");
                let fixture = matrix_fixture(fixture_id, variant, mode, permitted, control, canary);
                let (mut case, control_capture, _) =
                    execute_pair_with_captures(&fixture, &mut execute)?;
                if let Some(local) = &local_capture {
                    case.first_cross_mode_divergence =
                        first_divergence(&fixture, local, &control_capture);
                } else {
                    local_capture = Some(control_capture);
                }
                cases.push(case);
            }
        }
    }
    Ok(cases)
}

fn matrix_fixture(
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
    permitted_input: [u8; 32],
    control_unauthorized_value: [u8; 32],
    canary_unauthorized_value: [u8; 32],
) -> NonInterferenceFixturePairV1 {
    let mut fixture = NonInterferenceFixturePairV1 {
        fixture_id: fixture_id.to_owned(),
        variant,
        mode,
        permitted_input: permitted_input.to_vec(),
        control_unauthorized_value: control_unauthorized_value.to_vec(),
        canary_unauthorized_value: canary_unauthorized_value.to_vec(),
        fixture_digest: [0; 32],
    };
    fixture.fixture_digest = fixture.expected_digest();
    fixture
}

fn first_divergence(
    fixture: &NonInterferenceFixturePairV1,
    control: &NonInterferenceCaptureV1,
    canary: &NonInterferenceCaptureV1,
) -> Option<NonInterferenceDivergenceCoordinateV1> {
    for (surface_ordinal, index) in (0_u16..).zip(0..control.surface_names.len()) {
        if let Some(byte_offset) = first_surface_difference(control, canary, index) {
            return Some(coordinate(fixture, surface_ordinal, byte_offset));
        }
    }
    None
}

fn first_surface_difference(
    control: &NonInterferenceCaptureV1,
    canary: &NonInterferenceCaptureV1,
    index: usize,
) -> Option<u64> {
    let mut offset = 0_u64;
    for (left, right) in [
        (&control.authoritative[index], &canary.authoritative[index]),
        (&control.public[index], &canary.public[index]),
        (&control.operational[index], &canary.operational[index]),
    ] {
        if let Some(difference) = first_byte_difference(left, right) {
            return Some(offset.saturating_add(difference));
        }
        offset = offset.saturating_add(left.len() as u64);
    }
    None
}

fn coordinate(
    fixture: &NonInterferenceFixturePairV1,
    surface_ordinal: u16,
    byte_offset: u64,
) -> NonInterferenceDivergenceCoordinateV1 {
    NonInterferenceDivergenceCoordinateV1 {
        fixture_id: fixture.fixture_id.clone(),
        variant: fixture.variant,
        mode: fixture.mode,
        surface_ordinal,
        byte_offset,
    }
}

fn first_byte_difference(left: &[u8], right: &[u8]) -> Option<u64> {
    left.iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .or_else(|| (left.len() != right.len()).then_some(left.len().min(right.len())))
        .map(|offset| offset as u64)
}

fn capture_digest(
    domain: &[u8],
    fixture: &NonInterferenceFixturePairV1,
    surfaces: &[Vec<u8>],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, fixture.fixture_id.as_bytes());
    append_bytes(
        &mut bytes,
        non_interference_normalization_policy_v1(&fixture.fixture_id)
            .unwrap_or_default()
            .as_bytes(),
    );
    for (name, surface) in non_interference_surface_names_v1(&fixture.fixture_id)
        .unwrap_or_default()
        .iter()
        .zip(surfaces)
    {
        append_bytes(&mut bytes, name.as_bytes());
        append_bytes(&mut bytes, surface);
    }
    domain_digest(domain, &bytes)
}

fn input_digest(domain: &[u8], permitted: &[u8], unauthorized: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, permitted);
    append_bytes(&mut bytes, unauthorized);
    domain_digest(domain, &bytes)
}

fn matrix_value(
    seed: [u8; 32],
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    role: &[u8],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&seed);
    append_bytes(&mut bytes, fixture_id.as_bytes());
    bytes.push(variant_code(variant));
    append_bytes(&mut bytes, role);
    domain_digest(b"PiglorOS.NonInterference.MatrixInput.v1", &bytes)
}

fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(value);
    *hasher.finalize().as_bytes()
}

const fn variant_code(variant: NonInterferenceVariantV1) -> u8 {
    match variant {
        NonInterferenceVariantV1::Success => 0,
        NonInterferenceVariantV1::Denial => 1,
        NonInterferenceVariantV1::WarmCache => 2,
        NonInterferenceVariantV1::ColdCache => 3,
    }
}

const fn mode_code(mode: ExecutionModeV1) -> u8 {
    match mode {
        ExecutionModeV1::Local => 0,
        ExecutionModeV1::AirGapped => 1,
        ExecutionModeV1::Replay => 2,
        ExecutionModeV1::Fork => 3,
    }
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }

    let mut prefix_lengths = vec![0; needle.len()];
    let mut matched = 0;
    for index in 1..needle.len() {
        while matched > 0 && needle[index] != needle[matched] {
            matched = prefix_lengths[matched - 1];
        }
        if needle[index] == needle[matched] {
            matched += 1;
            prefix_lengths[index] = matched;
        }
    }

    matched = 0;
    for byte in haystack {
        while matched > 0 && *byte != needle[matched] {
            matched = prefix_lengths[matched - 1];
        }
        if *byte == needle[matched] {
            matched += 1;
            if matched == needle.len() {
                return true;
            }
        }
    }
    false
}
