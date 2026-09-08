use crate::{
    domain_digest, ExecutionModeV1, NonInterferenceCaseV1, NonInterferenceDivergenceCoordinateV1,
    NonInterferenceVariantV1, NON_INTERFERENCE_CASE_COUNT_V1, NON_INTERFERENCE_FIXTURE_IDS_V1,
};
use serde::{Deserialize, Serialize};

const MAX_PERMITTED_INPUT_BYTES: usize = 1024 * 1024;
const MAX_UNAUTHORIZED_VALUE_BYTES: usize = 1024 * 1024;
const MAX_SURFACE_BYTES: usize = 1024 * 1024;
const NORMALIZATION_VERSION_V1: u16 = 1;

/// Executable operational normalization selected by a canonical capture profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonInterferenceNormalizationV1 {
    CategoryCountDigest,
    CountClass,
    CategoryCount,
    CategoryCountPaddedLength,
    OmitOperational,
    ByteExact,
}

#[derive(Clone, Copy)]
struct NonInterferenceSurfaceDefinitionV1 {
    name: &'static str,
    normalization: NonInterferenceNormalizationV1,
}

impl NonInterferenceNormalizationV1 {
    const fn description(self) -> &'static str {
        match self {
            Self::CategoryCountDigest => "count/category/digest; sensitive text absent",
            Self::CountClass => "bounded count/class; sensitive values and timing absent",
            Self::CategoryCount => "category/count only; diagnostic details absent",
            Self::CategoryCountPaddedLength => {
                "safe category/count/padded length; diagnostics absent"
            }
            Self::OmitOperational => "operational timestamps and durations absent",
            Self::ByteExact => "declared operational surface is byte-exact",
        }
    }
}

/// Canonical typed profile for one ADR-059 matrix row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceCaptureProfileV1 {
    pub fixture_id: String,
    pub surface_names: Vec<String>,
    /// Operational normalizer fixed for each surface at the same ordinal.
    pub surface_normalizations: Vec<NonInterferenceNormalizationV1>,
    pub variants: Vec<NonInterferenceVariantV1>,
    pub modes: Vec<ExecutionModeV1>,
    pub normalization_version: u16,
    pub max_surface_bytes: u64,
    pub profile_digest: [u8; 32],
}

/// One raw operational surface captured before allowed normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NonInterferenceRawOperationalV1 {
    CategoryCountDigest {
        category: u16,
        count: u32,
        digest: [u8; 32],
        excluded_sensitive: Vec<u8>,
    },
    CountClass {
        class: u16,
        count: u32,
        excluded_sensitive: Vec<u8>,
    },
    CategoryCount {
        category: u16,
        count: u32,
        excluded_sensitive: Vec<u8>,
    },
    CategoryCountPaddedLength {
        category: u16,
        count: u32,
        padded_length: u32,
        excluded_sensitive: Vec<u8>,
    },
    OmitOperational {
        excluded_sensitive: Vec<u8>,
    },
    ByteExact(Vec<u8>),
}

/// Host-owned raw capture input. Only the normalizer can produce the capture
/// accepted by the matrix runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonInterferenceRawCaptureV1 {
    pub surface_names: Vec<String>,
    pub authoritative: Vec<Vec<u8>>,
    pub public: Vec<Vec<u8>>,
    pub operational: Vec<NonInterferenceRawOperationalV1>,
    pub unexpected_network_accesses: u32,
    pub provenance_digest: [u8; 32],
}

/// Return all twelve canonical ADR-059 capture profiles in matrix order.
#[must_use]
pub fn non_interference_capture_profiles_v1() -> Vec<NonInterferenceCaptureProfileV1> {
    crate::NON_INTERFERENCE_FIXTURE_IDS_V1
        .iter()
        .filter_map(|fixture_id| capture_profile(fixture_id))
        .collect()
}

fn capture_profile(fixture_id: &str) -> Option<NonInterferenceCaptureProfileV1> {
    let definitions = surface_definitions(fixture_id)?;
    let surface_names = definitions
        .iter()
        .map(|value| value.name.to_owned())
        .collect::<Vec<_>>();
    let surface_normalizations = definitions
        .iter()
        .map(|value| value.normalization)
        .collect();
    let variants = vec![
        NonInterferenceVariantV1::Success,
        NonInterferenceVariantV1::Denial,
        NonInterferenceVariantV1::WarmCache,
        NonInterferenceVariantV1::ColdCache,
    ];
    let modes = vec![
        ExecutionModeV1::Local,
        ExecutionModeV1::AirGapped,
        ExecutionModeV1::Replay,
        ExecutionModeV1::Fork,
    ];
    let mut profile = NonInterferenceCaptureProfileV1 {
        fixture_id: fixture_id.to_owned(),
        surface_names,
        surface_normalizations,
        variants,
        modes,
        normalization_version: NORMALIZATION_VERSION_V1,
        max_surface_bytes: MAX_SURFACE_BYTES as u64,
        profile_digest: [0; 32],
    };
    profile.profile_digest = profile_digest(&profile);
    Some(profile)
}

fn surface_definitions(fixture_id: &str) -> Option<Vec<NonInterferenceSurfaceDefinitionV1>> {
    use NonInterferenceNormalizationV1::{
        ByteExact, CategoryCount, CategoryCountDigest, CategoryCountPaddedLength, CountClass,
        OmitOperational,
    };
    match fixture_id.as_bytes() {
        b"NI-TOOL-001" => Some(vec![
            surface("Imported-service registry", CategoryCountDigest),
            surface("tool result handle", CategoryCountDigest),
            surface("Plugin imports", CategoryCountDigest),
            surface("staged EventDrafts", CategoryCountDigest),
            surface("public outcome", CategoryCountDigest),
            surface("audit record", CategoryCountDigest),
        ]),
        b"NI-CACHE-002" => Some(vec![
            surface("Cache API return", CountClass),
            surface("snapshot bytes", CountClass),
            surface("Plugin inputs", CountClass),
            surface("typed errors", CountClass),
            surface("logs/metrics", CountClass),
            surface("evaluator bundle", CountClass),
        ]),
        b"NI-STATE-003" => Some(vec![
            surface("Migration request/result", CategoryCount),
            surface("activated state", CategoryCount),
            surface("PluginInvocation", CategoryCount),
            surface("PluginOutput", CategoryCount),
            surface("EventDrafts", CategoryCount),
            surface("quarantine/error", CategoryCount),
        ]),
        b"NI-OBS-004" => Some(vec![
            surface("Structured logs", CategoryCountPaddedLength),
            surface("metric names/labels/counts", CategoryCountPaddedLength),
            surface("trace spans", CategoryCountPaddedLength),
            surface("crash artifact", CategoryCountPaddedLength),
            surface("public support bundle", CategoryCountPaddedLength),
        ]),
        b"NI-TIME-005" => Some(vec![
            surface("Plugin imports", ByteExact),
            surface("deterministic deadline", OmitOperational),
            surface("safe-stop record", ByteExact),
            surface("status/error", CategoryCount),
            surface("logs/metrics", CategoryCount),
            surface("evaluator input", ByteExact),
        ]),
        b"NI-PUBLIC-006" => Some(vec![
            surface("HTTP/Plugin error", CategoryCount),
            surface("status transition", CategoryCount),
            surface("cursor bytes", CategoryCount),
            surface("page count", CategoryCount),
            surface("response length/padding", CategoryCount),
        ]),
        _ => remaining_surface_definitions(fixture_id),
    }
}

fn remaining_surface_definitions(
    fixture_id: &str,
) -> Option<Vec<NonInterferenceSurfaceDefinitionV1>> {
    use NonInterferenceNormalizationV1::{ByteExact, CategoryCount, CategoryCountPaddedLength};
    match fixture_id.as_bytes() {
        b"NI-EVAL-007" => Some(vec![
            surface("Export bundle", ByteExact),
            surface("manifest", ByteExact),
            surface("fixture descriptor", ByteExact),
            surface("evaluator stdin/files", ByteExact),
            surface("ConformanceReport", ByteExact),
        ]),
        b"NI-FORK-008" => Some(vec![
            surface("Fork parent/cut", ByteExact),
            surface("CounterfactualPlan", ByteExact),
            surface("RecomputationFrontier", ByteExact),
            surface("SuffixInvalidation", ByteExact),
            surface("snapshots", ByteExact),
            surface("checkpoints", ByteExact),
            surface("result", ByteExact),
            surface("ReproManifest", ByteExact),
            surface("exports", ByteExact),
        ]),
        b"NI-ARCHIVE-009" => Some(vec![
            surface("Member table", ByteExact),
            surface("archive bytes", ByteExact),
            surface("decompressed bundle", ByteExact),
            surface("digest", ByteExact),
            surface("evaluator import", ByteExact),
            surface("logs", ByteExact),
        ]),
        b"NI-NET-010" => Some(vec![
            surface("Capability checks", CategoryCount),
            surface("attempted-call records", CategoryCount),
            surface("retry count", CategoryCount),
            surface("Plugin output", CategoryCount),
            surface("Timeline", CategoryCount),
            surface("logs", CategoryCount),
            surface("evaluator bundle", CategoryCount),
        ]),
        b"NI-SERVICE-011" => Some(vec![
            surface("Exact request digest", ByteExact),
            surface("frozen response projection", ByteExact),
            surface("call ordinal", ByteExact),
            surface("PluginInvocation", ByteExact),
            surface("generated dependency edges", ByteExact),
        ]),
        b"NI-CRASH-012" => Some(vec![
            surface("Guest error", CategoryCountPaddedLength),
            surface("host error mapping", CategoryCountPaddedLength),
            surface("quarantine", CategoryCountPaddedLength),
            surface("crash report", CategoryCountPaddedLength),
            surface("support archive", CategoryCountPaddedLength),
            surface("next Tick status", CategoryCountPaddedLength),
        ]),
        _ => None,
    }
}

const fn surface(
    name: &'static str,
    normalization: NonInterferenceNormalizationV1,
) -> NonInterferenceSurfaceDefinitionV1 {
    NonInterferenceSurfaceDefinitionV1 {
        name,
        normalization,
    }
}

/// Return the canonical ADR-059 capture surface order for one matrix row.
#[must_use]
pub fn non_interference_surface_names_v1(fixture_id: &str) -> Option<Vec<&'static str>> {
    surface_definitions(fixture_id).map(|definitions| {
        definitions
            .iter()
            .map(|definition| definition.name)
            .collect()
    })
}

/// Return the canonical ADR-059 operational normalization rule for one row.
#[must_use]
pub fn non_interference_normalization_policy_v1(fixture_id: &str) -> Option<&'static str> {
    let definitions = surface_definitions(fixture_id)?;
    let values = definitions
        .iter()
        .map(|definition| definition.normalization)
        .collect::<Vec<_>>();
    if values.windows(2).all(|pair| pair[0] == pair[1]) {
        Some(values[0].description())
    } else {
        Some("surface-specific typed normalization")
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
        let _ = value.validate_fields()?;
        value.fixture_digest = value.expected_digest();
        Ok(value)
    }

    /// Validate a deserialized fixture pair, including its content address.
    ///
    /// # Errors
    /// Returns a closed fixture error without exposing either unauthorized
    /// value.
    pub fn validate(&self) -> Result<(), NonInterferenceExecutionErrorV1> {
        self.validated_profile().map(drop)
    }

    fn validated_profile(
        &self,
    ) -> Result<NonInterferenceCaptureProfileV1, NonInterferenceExecutionErrorV1> {
        let profile = self.validate_fields()?;
        if self.fixture_digest == [0; 32] || self.fixture_digest != self.expected_digest() {
            return Err(NonInterferenceExecutionErrorV1::FixtureInvalid);
        }
        Ok(profile)
    }

    fn validate_fields(
        &self,
    ) -> Result<NonInterferenceCaptureProfileV1, NonInterferenceExecutionErrorV1> {
        let profile = capture_profile(&self.fixture_id)
            .ok_or(NonInterferenceExecutionErrorV1::FixtureInvalid)?;
        if self.permitted_input.is_empty()
            || self.permitted_input.len() > MAX_PERMITTED_INPUT_BYTES
            || self.control_unauthorized_value.len() > MAX_UNAUTHORIZED_VALUE_BYTES
            || self.canary_unauthorized_value.len() > MAX_UNAUTHORIZED_VALUE_BYTES
            || self.control_unauthorized_value == self.canary_unauthorized_value
            || contains_subslice(&self.permitted_input, &self.control_unauthorized_value)
            || contains_subslice(&self.permitted_input, &self.canary_unauthorized_value)
        {
            return Err(NonInterferenceExecutionErrorV1::FixtureInvalid);
        }
        Ok(profile)
    }

    fn expected_digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        append_bytes(&mut bytes, self.fixture_id.as_bytes());
        bytes.push(variant_code(self.variant));
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
    normalization_digest: [u8; 32],
}

/// Normalize a host-owned raw capture according to its canonical row profile.
///
/// Excluded sensitive operational fields are deliberately absent from the
/// returned value. Authoritative and public surfaces remain byte-exact.
///
/// # Errors
/// Returns a closed error for an unknown profile, incomplete inventory,
/// mismatched typed normalizer, live network access, or a deterministic bound
/// violation.
pub fn normalize_non_interference_capture_v1(
    fixture_id: &str,
    raw: NonInterferenceRawCaptureV1,
) -> Result<NonInterferenceCaptureV1, NonInterferenceExecutionErrorV1> {
    let profile =
        capture_profile(fixture_id).ok_or(NonInterferenceExecutionErrorV1::CaptureUnavailable)?;
    let surface_count = profile.surface_names.len();
    if raw.surface_names != profile.surface_names
        || [
            raw.authoritative.len(),
            raw.public.len(),
            raw.operational.len(),
        ]
        .iter()
        .any(|length| *length != surface_count)
    {
        return Err(NonInterferenceExecutionErrorV1::CaptureUnavailable);
    }
    if raw.unexpected_network_accesses != 0 {
        return Err(NonInterferenceExecutionErrorV1::UnexpectedNetworkAccess);
    }
    if raw.provenance_digest == [0; 32]
        || raw
            .authoritative
            .iter()
            .chain(&raw.public)
            .any(|value| value.is_empty() || value.len() > MAX_SURFACE_BYTES)
        || raw
            .operational
            .iter()
            .any(|value| value.raw_byte_len() > MAX_SURFACE_BYTES)
    {
        return Err(NonInterferenceExecutionErrorV1::CaptureOutOfBounds);
    }
    let operational = profile
        .surface_normalizations
        .iter()
        .zip(&raw.operational)
        .map(|(normalization, value)| normalize_operational(*normalization, value))
        .collect::<Result<Vec<_>, _>>()?;
    let mut capture = NonInterferenceCaptureV1 {
        surface_names: raw.surface_names,
        authoritative: raw.authoritative,
        public: raw.public,
        operational,
        unexpected_network_accesses: raw.unexpected_network_accesses,
        provenance_digest: raw.provenance_digest,
        normalization_digest: [0; 32],
    };
    capture.normalization_digest = normalized_capture_digest(&profile, &capture);
    capture.validate(&profile).map(|()| capture)
}

impl NonInterferenceRawOperationalV1 {
    const fn raw_byte_len(&self) -> usize {
        match self {
            Self::CategoryCountDigest {
                excluded_sensitive, ..
            }
            | Self::CountClass {
                excluded_sensitive, ..
            }
            | Self::CategoryCount {
                excluded_sensitive, ..
            }
            | Self::CategoryCountPaddedLength {
                excluded_sensitive, ..
            }
            | Self::OmitOperational { excluded_sensitive } => excluded_sensitive.len(),
            Self::ByteExact(value) => value.len(),
        }
    }
}

fn normalized_capture_digest(
    profile: &NonInterferenceCaptureProfileV1,
    capture: &NonInterferenceCaptureV1,
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&profile.profile_digest);
    for name in &capture.surface_names {
        append_bytes(&mut bytes, name.as_bytes());
    }
    for value in capture
        .authoritative
        .iter()
        .chain(&capture.public)
        .chain(&capture.operational)
    {
        append_bytes(&mut bytes, value);
    }
    bytes.extend_from_slice(&capture.unexpected_network_accesses.to_be_bytes());
    bytes.extend_from_slice(&capture.provenance_digest);
    domain_digest(b"PiglorOS.NonInterference.NormalizedCapture.v1", &bytes)
}

fn normalize_operational(
    normalization: NonInterferenceNormalizationV1,
    raw: &NonInterferenceRawOperationalV1,
) -> Result<Vec<u8>, NonInterferenceExecutionErrorV1> {
    let mut output = Vec::new();
    match (normalization, raw) {
        (
            NonInterferenceNormalizationV1::CategoryCountDigest,
            NonInterferenceRawOperationalV1::CategoryCountDigest {
                category,
                count,
                digest,
                excluded_sensitive: _,
            },
        ) if *digest != [0; 32] => {
            output.extend_from_slice(&category.to_be_bytes());
            output.extend_from_slice(&count.to_be_bytes());
            output.extend_from_slice(digest);
        }
        (
            NonInterferenceNormalizationV1::CountClass,
            NonInterferenceRawOperationalV1::CountClass {
                class,
                count,
                excluded_sensitive: _,
            },
        )
        | (
            NonInterferenceNormalizationV1::CategoryCount,
            NonInterferenceRawOperationalV1::CategoryCount {
                category: class,
                count,
                excluded_sensitive: _,
            },
        ) => {
            output.extend_from_slice(&class.to_be_bytes());
            output.extend_from_slice(&count.to_be_bytes());
        }
        (
            NonInterferenceNormalizationV1::CategoryCountPaddedLength,
            NonInterferenceRawOperationalV1::CategoryCountPaddedLength {
                category,
                count,
                padded_length,
                excluded_sensitive: _,
            },
        ) if *padded_length > 0 && padded_length.is_power_of_two() => {
            output.extend_from_slice(&category.to_be_bytes());
            output.extend_from_slice(&count.to_be_bytes());
            output.extend_from_slice(&padded_length.to_be_bytes());
        }
        (
            NonInterferenceNormalizationV1::OmitOperational,
            NonInterferenceRawOperationalV1::OmitOperational {
                excluded_sensitive: _,
            },
        ) => output.push(0),
        (
            NonInterferenceNormalizationV1::ByteExact,
            NonInterferenceRawOperationalV1::ByteExact(value),
        ) if !value.is_empty() && value.len() <= MAX_SURFACE_BYTES => {
            output.extend_from_slice(value);
        }
        _ => return Err(NonInterferenceExecutionErrorV1::CaptureUnavailable),
    }
    Ok(output)
}

fn profile_digest(profile: &NonInterferenceCaptureProfileV1) -> [u8; 32] {
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, profile.fixture_id.as_bytes());
    for (name, normalization) in profile
        .surface_names
        .iter()
        .zip(&profile.surface_normalizations)
    {
        append_bytes(&mut bytes, name.as_bytes());
        bytes.push(normalization_code(*normalization));
    }
    for variant in &profile.variants {
        bytes.push(variant_code(*variant));
    }
    for mode in &profile.modes {
        bytes.push(mode_code(*mode));
    }
    bytes.extend_from_slice(&profile.normalization_version.to_be_bytes());
    bytes.extend_from_slice(&profile.max_surface_bytes.to_be_bytes());
    domain_digest(b"PiglorOS.NonInterference.CaptureProfile.v1", &bytes)
}

const fn normalization_code(value: NonInterferenceNormalizationV1) -> u8 {
    match value {
        NonInterferenceNormalizationV1::CategoryCountDigest => 0,
        NonInterferenceNormalizationV1::CountClass => 1,
        NonInterferenceNormalizationV1::CategoryCount => 2,
        NonInterferenceNormalizationV1::CategoryCountPaddedLength => 3,
        NonInterferenceNormalizationV1::OmitOperational => 4,
        NonInterferenceNormalizationV1::ByteExact => 5,
    }
}

impl NonInterferenceCaptureV1 {
    fn validate(
        &self,
        profile: &NonInterferenceCaptureProfileV1,
    ) -> Result<(), NonInterferenceExecutionErrorV1> {
        if self.unexpected_network_accesses != 0 {
            return Err(NonInterferenceExecutionErrorV1::UnexpectedNetworkAccess);
        }
        let surface_count = profile.surface_names.len();
        if self.surface_names != profile.surface_names
            || (
                self.authoritative.len(),
                self.public.len(),
                self.operational.len(),
            ) != (surface_count, surface_count, surface_count)
            || self.normalization_digest != normalized_capture_digest(profile, self)
        {
            return Err(NonInterferenceExecutionErrorV1::CaptureUnavailable);
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
    let profile = fixture.validated_profile()?;
    let control = execute(&NonInterferenceHostRunV1 {
        member: NonInterferenceMatrixMemberV1::Control,
        subject: invocation,
        unauthorized_value: &fixture.control_unauthorized_value,
    })?;
    control.validate(&profile)?;
    let canary = execute(&NonInterferenceHostRunV1 {
        member: NonInterferenceMatrixMemberV1::Canary,
        subject: invocation,
        unauthorized_value: &fixture.canary_unauthorized_value,
    })?;
    canary.validate(&profile)?;
    Ok(case_with_captures(fixture, &profile, control, canary))
}

fn case_with_captures(
    fixture: &NonInterferenceFixturePairV1,
    profile: &NonInterferenceCaptureProfileV1,
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
    let authoritative_digest =
        capture_digest(b"authoritative", fixture, profile, &control.authoritative);
    let canary_authoritative_digest =
        capture_digest(b"authoritative", fixture, profile, &canary.authoritative);
    let public_digest = capture_digest(b"public", fixture, profile, &control.public);
    let canary_public_digest = capture_digest(b"public", fixture, profile, &canary.public);
    let operational_digest = capture_digest(b"operational", fixture, profile, &control.operational);
    let canary_operational_digest =
        capture_digest(b"operational", fixture, profile, &canary.operational);
    let mut provenance = Vec::new();
    provenance.extend_from_slice(&fixture.fixture_digest);
    provenance.extend_from_slice(&control.provenance_digest);
    provenance.extend_from_slice(&canary.provenance_digest);

    let case = NonInterferenceCaseV1 {
        fixture_id: fixture.fixture_id.clone(),
        variant: fixture.variant,
        mode: fixture.mode,
        fixture_digest: fixture.fixture_digest,
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
    profile: &NonInterferenceCaptureProfileV1,
    surfaces: &[Vec<u8>],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    append_bytes(&mut bytes, fixture.fixture_id.as_bytes());
    bytes.extend_from_slice(&profile.profile_digest);
    for (name, surface) in profile.surface_names.iter().zip(surfaces) {
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
