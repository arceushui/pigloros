use crate::{
    domain_digest, non_interference_capture_profiles_v1, ExecutionModeV1,
    NonInterferenceDivergenceCoordinateV1, NonInterferenceVariantV1,
    NON_INTERFERENCE_FIXTURE_IDS_V1,
};
use ed25519_dalek::{Signer, Verifier};
use pos_core::{CanonicalBytes, Signature};
use serde::{Deserialize, Serialize};

pub const NON_INTERFERENCE_REPORT_MAGIC_V1: &str = "NIR1";
pub const MAX_NON_INTERFERENCE_REPORT_BYTES_V1: usize = 64 * 1024;
pub const NON_INTERFERENCE_REPORT_OUTCOME_COUNT_V1: usize = 48;
pub const NON_INTERFERENCE_EXECUTION_ARTIFACT_MAGIC_V1: &str = "NIA1";
pub const MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1: usize = 4 * 1024;

/// Return the canonical executable-normalization digest for one ADR-059 row.
#[must_use]
pub fn non_interference_normalization_digest_v1(fixture_id: &str) -> Option<[u8; 32]> {
    non_interference_capture_profiles_v1()
        .into_iter()
        .find(|profile| profile.fixture_id == fixture_id)
        .map(|profile| normalization_digest(profile.profile_digest))
}

/// One immutable execution-result reference for a required mode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceModeResultRefV1 {
    #[serde(rename = "m")]
    pub mode: ExecutionModeV1,
    #[serde(rename = "r")]
    pub result_digest: [u8; 32],
    #[serde(rename = "a")]
    pub artifact_digest: [u8; 32],
    #[serde(rename = "p")]
    pub execution_provenance_digest: [u8; 32],
    #[serde(rename = "e")]
    pub equal: bool,
}

/// Immutable content-addressed result supplied by a concrete #193 executor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonInterferenceExecutionArtifactBodyV1 {
    pub fixture_id: String,
    pub variant: NonInterferenceVariantV1,
    pub mode: ExecutionModeV1,
    pub fixture_digest: [u8; 32],
    pub profile_digest: [u8; 32],
    pub normalization_digest: [u8; 32],
    pub result_digest: [u8; 32],
    pub execution_provenance_digest: [u8; 32],
    pub equal: bool,
    pub divergence: Option<NonInterferenceDivergenceCoordinateV1>,
}

/// Immutable content-addressed result supplied by a concrete #193 executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceExecutionArtifactV1 {
    #[serde(rename = "m")]
    pub magic: String,
    #[serde(rename = "v")]
    pub version: u16,
    #[serde(rename = "i")]
    pub fixture_id: String,
    #[serde(rename = "x")]
    pub variant: NonInterferenceVariantV1,
    #[serde(rename = "o")]
    pub mode: ExecutionModeV1,
    #[serde(rename = "f")]
    pub fixture_digest: [u8; 32],
    #[serde(rename = "p")]
    pub profile_digest: [u8; 32],
    #[serde(rename = "n")]
    pub normalization_digest: [u8; 32],
    #[serde(rename = "r")]
    pub result_digest: [u8; 32],
    #[serde(rename = "e")]
    pub execution_provenance_digest: [u8; 32],
    #[serde(rename = "q")]
    pub equal: bool,
    #[serde(rename = "d")]
    pub divergence: Option<NonInterferenceDivergenceCoordinateV1>,
    #[serde(rename = "k")]
    pub executor_public_key: [u8; 32],
    #[serde(rename = "s")]
    pub signature: Signature,
}

impl NonInterferenceExecutionArtifactV1 {
    /// Construct and sign one immutable executor result.
    ///
    /// # Errors
    /// Returns a closed error when the coordinate or bound digests are invalid.
    pub fn sign(
        body: NonInterferenceExecutionArtifactBodyV1,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, NonInterferenceReportErrorV1> {
        let mut artifact = Self {
            magic: NON_INTERFERENCE_EXECUTION_ARTIFACT_MAGIC_V1.to_owned(),
            version: 1,
            fixture_id: body.fixture_id,
            variant: body.variant,
            mode: body.mode,
            fixture_digest: body.fixture_digest,
            profile_digest: body.profile_digest,
            normalization_digest: body.normalization_digest,
            result_digest: body.result_digest,
            execution_provenance_digest: body.execution_provenance_digest,
            equal: body.equal,
            divergence: body.divergence,
            executor_public_key: signing_key.verifying_key().to_bytes(),
            signature: Signature::from_bytes([0; 64]),
        };
        artifact.validate_unsigned_shape()?;
        artifact.signature = Signature::from_bytes(
            signing_key
                .sign(&execution_artifact_signature_message(
                    &artifact.unsigned_bytes()?,
                ))
                .to_bytes(),
        );
        Ok(artifact)
    }

    /// Encode the validated signed artifact as canonical CBOR.
    ///
    /// # Errors
    /// Returns a closed error when its shape, signature, or encoding is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, NonInterferenceReportErrorV1> {
        self.validate_shape()?;
        encode(self)
    }

    /// Decode and validate one bounded canonical signed artifact.
    ///
    /// # Errors
    /// Returns a closed error for oversized, malformed, noncanonical, or unsigned input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, NonInterferenceReportErrorV1> {
        if bytes.len() > MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1 {
            return Err(NonInterferenceReportErrorV1::TooLarge);
        }
        let canonical = CanonicalBytes::from_vec(bytes.to_vec());
        let artifact: Self = pos_crypto::canonical::decode(&canonical)
            .map_err(|_| NonInterferenceReportErrorV1::NonCanonical)?;
        if encode(&artifact)?.as_slice() != bytes {
            return Err(NonInterferenceReportErrorV1::NonCanonical);
        }
        artifact.validate_shape().map(|()| artifact)
    }

    /// Return the content address of the complete signed artifact.
    ///
    /// # Errors
    /// Returns a closed error when the artifact cannot be validated or encoded.
    pub fn content_digest(&self) -> Result<[u8; 32], NonInterferenceReportErrorV1> {
        self.to_canonical_cbor()
            .map(|bytes| domain_digest(b"PiglorOS.NonInterference.ExecutionArtifact.v1", &bytes))
    }

    fn validate_shape(&self) -> Result<(), NonInterferenceReportErrorV1> {
        self.validate_unsigned_shape()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.executor_public_key)
            .map_err(|_| NonInterferenceReportErrorV1::SignatureInvalid)?;
        key.verify(
            &execution_artifact_signature_message(&self.unsigned_bytes()?),
            &ed25519_dalek::Signature::from_bytes(self.signature.as_bytes()),
        )
        .map_err(|_| NonInterferenceReportErrorV1::SignatureInvalid)
    }

    fn validate_unsigned_shape(&self) -> Result<(), NonInterferenceReportErrorV1> {
        let profile = non_interference_capture_profiles_v1()
            .into_iter()
            .find(|profile| profile.fixture_id == self.fixture_id)
            .ok_or(NonInterferenceReportErrorV1::InvalidShape)?;
        if self.magic != NON_INTERFERENCE_EXECUTION_ARTIFACT_MAGIC_V1
            || self.version != 1
            || self.profile_digest != profile.profile_digest
            || self.normalization_digest != normalization_digest(profile.profile_digest)
            || self.fixture_digest == [0; 32]
            || self.result_digest == [0; 32]
            || self.execution_provenance_digest == [0; 32]
            || self.executor_public_key == [0; 32]
        {
            return Err(NonInterferenceReportErrorV1::InvalidShape);
        }
        match (self.equal, &self.divergence) {
            (true, None) => {}
            (false, Some(coordinate))
                if coordinate.fixture_id == self.fixture_id
                    && coordinate.variant == self.variant
                    && coordinate.mode == self.mode
                    && usize::from(coordinate.surface_ordinal) < profile.surface_names.len()
                    && coordinate.byte_offset <= profile.max_surface_bytes.saturating_mul(3) => {}
            _ => return Err(NonInterferenceReportErrorV1::InvalidShape),
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, NonInterferenceReportErrorV1> {
        encode(&UnsignedNonInterferenceExecutionArtifactV1 {
            magic: self.magic.clone(),
            version: self.version,
            fixture_id: self.fixture_id.clone(),
            variant: self.variant,
            mode: self.mode,
            fixture_digest: self.fixture_digest,
            profile_digest: self.profile_digest,
            normalization_digest: self.normalization_digest,
            result_digest: self.result_digest,
            execution_provenance_digest: self.execution_provenance_digest,
            equal: self.equal,
            divergence: self.divergence.clone(),
            executor_public_key: self.executor_public_key,
        })
    }
}

#[derive(Serialize)]
struct UnsignedNonInterferenceExecutionArtifactV1 {
    #[serde(rename = "m")]
    magic: String,
    #[serde(rename = "v")]
    version: u16,
    #[serde(rename = "i")]
    fixture_id: String,
    #[serde(rename = "x")]
    variant: NonInterferenceVariantV1,
    #[serde(rename = "o")]
    mode: ExecutionModeV1,
    #[serde(rename = "f")]
    fixture_digest: [u8; 32],
    #[serde(rename = "p")]
    profile_digest: [u8; 32],
    #[serde(rename = "n")]
    normalization_digest: [u8; 32],
    #[serde(rename = "r")]
    result_digest: [u8; 32],
    #[serde(rename = "e")]
    execution_provenance_digest: [u8; 32],
    #[serde(rename = "q")]
    equal: bool,
    #[serde(rename = "d")]
    divergence: Option<NonInterferenceDivergenceCoordinateV1>,
    #[serde(rename = "k")]
    executor_public_key: [u8; 32],
}

/// One row/variant outcome, containing all four ordered mode executions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceReportOutcomeV1 {
    #[serde(rename = "i")]
    pub fixture_id: String,
    #[serde(rename = "v")]
    pub variant: NonInterferenceVariantV1,
    #[serde(rename = "f")]
    pub fixture_digest: [u8; 32],
    #[serde(rename = "p")]
    pub profile_digest: [u8; 32],
    #[serde(rename = "n")]
    pub normalization_digest: [u8; 32],
    #[serde(rename = "m")]
    pub modes: Vec<NonInterferenceModeResultRefV1>,
    #[serde(rename = "d")]
    pub first_divergence: Option<NonInterferenceDivergenceCoordinateV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedNonInterferenceReportV1 {
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
    outcomes: Vec<NonInterferenceReportOutcomeV1>,
    #[serde(rename = "k")]
    signer_public_key: [u8; 32],
}

/// Signed, content-addressed, bounded ADR-059 report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonInterferenceReportV1 {
    #[serde(rename = "m")]
    pub magic: String,
    #[serde(rename = "v")]
    pub version: u16,
    #[serde(rename = "f")]
    pub fixture_set_digest: [u8; 32],
    #[serde(rename = "p")]
    pub profile_set_digest: [u8; 32],
    #[serde(rename = "n")]
    pub normalization_set_digest: [u8; 32],
    #[serde(rename = "a")]
    pub artifact_set_digest: [u8; 32],
    #[serde(rename = "e")]
    pub execution_provenance_digest: [u8; 32],
    #[serde(rename = "o")]
    pub outcomes: Vec<NonInterferenceReportOutcomeV1>,
    #[serde(rename = "k")]
    pub signer_public_key: [u8; 32],
    #[serde(rename = "d")]
    pub report_digest: [u8; 32],
    #[serde(rename = "s")]
    pub signature: Signature,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NonInterferenceReportErrorV1 {
    #[error("non-interference report shape is invalid")]
    InvalidShape,
    #[error("non-interference report digest is invalid")]
    DigestInvalid,
    #[error("non-interference report signature is invalid")]
    SignatureInvalid,
    #[error("non-interference report is not canonical")]
    NonCanonical,
    #[error("non-interference evidence exceeds its declared size bound")]
    TooLarge,
    #[error("non-interference report contains a prohibited secret")]
    SecretDetected,
    #[error("non-interference report encoding failed")]
    EncodingFailed,
}

impl NonInterferenceReportV1 {
    /// Construct and sign a complete report after validating all 48 ordered
    /// row/variant outcomes and 192 mode references.
    ///
    /// # Errors
    /// Returns a closed report error for incomplete, reordered, malformed,
    /// oversized, or secret-bearing evidence.
    pub fn sign(
        outcomes: Vec<NonInterferenceReportOutcomeV1>,
        signing_key: &ed25519_dalek::SigningKey,
        prohibited_secrets: &[&[u8]],
    ) -> Result<Self, NonInterferenceReportErrorV1> {
        validate_outcomes(&outcomes)?;
        let fixture_set_digest = aggregate_digest(
            b"PiglorOS.NonInterference.FixtureSet.v1",
            outcomes.iter().map(|value| value.fixture_digest),
        );
        let profile_set_digest = aggregate_digest(
            b"PiglorOS.NonInterference.ProfileSet.v1",
            outcomes.iter().map(|value| value.profile_digest),
        );
        let normalization_set_digest = aggregate_digest(
            b"PiglorOS.NonInterference.NormalizationSet.v1",
            outcomes.iter().map(|value| value.normalization_digest),
        );
        let artifact_set_digest = aggregate_digest(
            b"PiglorOS.NonInterference.ArtifactSet.v1",
            outcomes
                .iter()
                .flat_map(|value| value.modes.iter().map(|mode| mode.artifact_digest)),
        );
        let execution_provenance_digest = aggregate_digest(
            b"PiglorOS.NonInterference.ExecutionProvenanceSet.v1",
            outcomes.iter().flat_map(|value| {
                value
                    .modes
                    .iter()
                    .map(|mode| mode.execution_provenance_digest)
            }),
        );
        let mut report = Self {
            magic: NON_INTERFERENCE_REPORT_MAGIC_V1.to_owned(),
            version: 1,
            fixture_set_digest,
            profile_set_digest,
            normalization_set_digest,
            artifact_set_digest,
            execution_provenance_digest,
            outcomes,
            signer_public_key: signing_key.verifying_key().to_bytes(),
            report_digest: [0; 32],
            signature: Signature::from_bytes([0; 64]),
        };
        let unsigned = report.unsigned_bytes()?;
        report.report_digest = report_digest(&unsigned);
        report.signature =
            Signature::from_bytes(signing_key.sign(&signature_message(&unsigned)).to_bytes());
        let encoded = report.to_canonical_cbor()?;
        if prohibited_secrets
            .iter()
            .any(|secret| !secret.is_empty() && contains_subslice(&encoded, secret))
        {
            return Err(NonInterferenceReportErrorV1::SecretDetected);
        }
        Ok(report)
    }

    /// Verify bounds, canonical profile/order, aggregate digests, content
    /// address, and Ed25519 signature.
    ///
    /// # Errors
    /// Returns a closed error for any invalid report invariant.
    pub fn validate(
        &self,
        trusted_signer_public_key: &[u8; 32],
        trusted_executor_public_keys: &[[u8; 32]],
        execution_artifacts: &[Vec<u8>],
    ) -> Result<(), NonInterferenceReportErrorV1> {
        if &self.signer_public_key != trusted_signer_public_key {
            return Err(NonInterferenceReportErrorV1::SignatureInvalid);
        }
        self.validate_integrity()?;
        self.validate_execution_artifacts(trusted_executor_public_keys, execution_artifacts)
    }

    fn validate_integrity(&self) -> Result<(), NonInterferenceReportErrorV1> {
        if self.magic != NON_INTERFERENCE_REPORT_MAGIC_V1 || self.version != 1 {
            return Err(NonInterferenceReportErrorV1::InvalidShape);
        }
        validate_outcomes(&self.outcomes)?;
        let rebuilt = Self::unsigned_aggregates(&self.outcomes);
        if [
            self.fixture_set_digest,
            self.profile_set_digest,
            self.normalization_set_digest,
            self.artifact_set_digest,
            self.execution_provenance_digest,
        ] != rebuilt
        {
            return Err(NonInterferenceReportErrorV1::DigestInvalid);
        }
        let unsigned = self.unsigned_bytes()?;
        if self.report_digest == [0; 32] || self.report_digest != report_digest(&unsigned) {
            return Err(NonInterferenceReportErrorV1::DigestInvalid);
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(&self.signer_public_key)
            .map_err(|_| NonInterferenceReportErrorV1::SignatureInvalid)?;
        key.verify(
            &signature_message(&unsigned),
            &ed25519_dalek::Signature::from_bytes(self.signature.as_bytes()),
        )
        .map_err(|_| NonInterferenceReportErrorV1::SignatureInvalid)?;
        Ok(())
    }

    /// Encode the verified report as deterministic canonical CBOR.
    ///
    /// # Errors
    /// Returns a closed error if validation or encoding fails.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, NonInterferenceReportErrorV1> {
        self.validate_integrity()?;
        encode(self)
    }

    /// Decode only current, canonical, bounded NIR1 reports.
    ///
    /// # Errors
    /// Returns a closed error for malformed, noncanonical, oversized, or
    /// unverifiable bytes.
    pub fn from_canonical_cbor(
        bytes: &[u8],
        trusted_signer_public_key: &[u8; 32],
        trusted_executor_public_keys: &[[u8; 32]],
        execution_artifacts: &[Vec<u8>],
    ) -> Result<Self, NonInterferenceReportErrorV1> {
        if bytes.len() > MAX_NON_INTERFERENCE_REPORT_BYTES_V1 {
            return Err(NonInterferenceReportErrorV1::TooLarge);
        }
        let canonical = CanonicalBytes::from_vec(bytes.to_vec());
        let report: Self = pos_crypto::canonical::decode(&canonical)
            .map_err(|_| NonInterferenceReportErrorV1::NonCanonical)?;
        if encode(&report)?.as_slice() != bytes {
            return Err(NonInterferenceReportErrorV1::NonCanonical);
        }
        report
            .validate(
                trusted_signer_public_key,
                trusted_executor_public_keys,
                execution_artifacts,
            )
            .map(|()| report)
    }

    #[must_use]
    pub fn is_conformant(&self) -> bool {
        self.outcomes
            .iter()
            .all(|outcome| outcome.modes.iter().all(|mode| mode.equal))
    }

    fn unsigned(&self) -> UnsignedNonInterferenceReportV1 {
        UnsignedNonInterferenceReportV1 {
            magic: self.magic.clone(),
            version: self.version,
            fixture_set_digest: self.fixture_set_digest,
            profile_set_digest: self.profile_set_digest,
            normalization_set_digest: self.normalization_set_digest,
            artifact_set_digest: self.artifact_set_digest,
            execution_provenance_digest: self.execution_provenance_digest,
            outcomes: self.outcomes.clone(),
            signer_public_key: self.signer_public_key,
        }
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, NonInterferenceReportErrorV1> {
        encode(&self.unsigned())
    }

    fn unsigned_aggregates(outcomes: &[NonInterferenceReportOutcomeV1]) -> [[u8; 32]; 5] {
        [
            aggregate_digest(
                b"PiglorOS.NonInterference.FixtureSet.v1",
                outcomes.iter().map(|value| value.fixture_digest),
            ),
            aggregate_digest(
                b"PiglorOS.NonInterference.ProfileSet.v1",
                outcomes.iter().map(|value| value.profile_digest),
            ),
            aggregate_digest(
                b"PiglorOS.NonInterference.NormalizationSet.v1",
                outcomes.iter().map(|value| value.normalization_digest),
            ),
            aggregate_digest(
                b"PiglorOS.NonInterference.ArtifactSet.v1",
                outcomes
                    .iter()
                    .flat_map(|value| value.modes.iter().map(|mode| mode.artifact_digest)),
            ),
            aggregate_digest(
                b"PiglorOS.NonInterference.ExecutionProvenanceSet.v1",
                outcomes.iter().flat_map(|value| {
                    value
                        .modes
                        .iter()
                        .map(|mode| mode.execution_provenance_digest)
                }),
            ),
        ]
    }

    fn validate_execution_artifacts(
        &self,
        trusted_executor_public_keys: &[[u8; 32]],
        execution_artifacts: &[Vec<u8>],
    ) -> Result<(), NonInterferenceReportErrorV1> {
        if execution_artifacts.len() != 192 || trusted_executor_public_keys.is_empty() {
            return Err(NonInterferenceReportErrorV1::InvalidShape);
        }
        let mut resolved = std::collections::BTreeMap::new();
        for bytes in execution_artifacts {
            let artifact = NonInterferenceExecutionArtifactV1::from_canonical_cbor(bytes)?;
            let digest = domain_digest(b"PiglorOS.NonInterference.ExecutionArtifact.v1", bytes);
            if resolved.insert(digest, artifact).is_some() {
                return Err(NonInterferenceReportErrorV1::InvalidShape);
            }
        }
        for outcome in &self.outcomes {
            for reference in &outcome.modes {
                let artifact = resolved
                    .get(&reference.artifact_digest)
                    .ok_or(NonInterferenceReportErrorV1::InvalidShape)?;
                if artifact.fixture_id != outcome.fixture_id
                    || artifact.variant != outcome.variant
                    || artifact.mode != reference.mode
                    || artifact.fixture_digest != outcome.fixture_digest
                    || artifact.profile_digest != outcome.profile_digest
                    || artifact.normalization_digest != outcome.normalization_digest
                    || artifact.result_digest != reference.result_digest
                    || artifact.execution_provenance_digest != reference.execution_provenance_digest
                    || artifact.equal != reference.equal
                    || !trusted_executor_public_keys.contains(&artifact.executor_public_key)
                {
                    return Err(NonInterferenceReportErrorV1::InvalidShape);
                }
            }
            let first_failed = outcome.modes.iter().position(|reference| !reference.equal);
            if first_failed.and_then(|index| {
                resolved[&outcome.modes[index].artifact_digest]
                    .divergence
                    .as_ref()
            }) != outcome.first_divergence.as_ref()
            {
                return Err(NonInterferenceReportErrorV1::InvalidShape);
            }
        }
        Ok(())
    }
}

fn validate_outcomes(
    outcomes: &[NonInterferenceReportOutcomeV1],
) -> Result<(), NonInterferenceReportErrorV1> {
    let profiles = non_interference_capture_profiles_v1();
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
    if outcomes.len() != NON_INTERFERENCE_REPORT_OUTCOME_COUNT_V1 {
        return Err(NonInterferenceReportErrorV1::InvalidShape);
    }
    for ((outcome, fixture_id), variant) in outcomes
        .iter()
        .zip(
            NON_INTERFERENCE_FIXTURE_IDS_V1
                .iter()
                .flat_map(|fixture| std::iter::repeat_n(*fixture, 4)),
        )
        .zip(variants.into_iter().cycle())
    {
        let profile = profiles
            .iter()
            .find(|profile| profile.fixture_id == fixture_id)
            .ok_or(NonInterferenceReportErrorV1::InvalidShape)?;
        if outcome.fixture_id != fixture_id
            || outcome.variant != variant
            || outcome.fixture_digest == [0; 32]
            || outcome.profile_digest != profile.profile_digest
            || outcome.normalization_digest != normalization_digest(profile.profile_digest)
            || outcome.modes.len() != modes.len()
        {
            return Err(NonInterferenceReportErrorV1::InvalidShape);
        }
        for (mode, expected_mode) in outcome.modes.iter().zip(modes) {
            if mode.mode != expected_mode
                || mode.result_digest == [0; 32]
                || mode.artifact_digest == [0; 32]
                || mode.execution_provenance_digest == [0; 32]
            {
                return Err(NonInterferenceReportErrorV1::InvalidShape);
            }
        }
        if outcome
            .modes
            .iter()
            .skip(1)
            .any(|mode| mode.result_digest != outcome.modes[0].result_digest)
        {
            return Err(NonInterferenceReportErrorV1::InvalidShape);
        }
        let first_failed = outcome.modes.iter().find(|mode| !mode.equal);
        match (first_failed, &outcome.first_divergence) {
            (None, None) => {}
            (Some(mode), Some(coordinate))
                if coordinate.fixture_id == outcome.fixture_id
                    && coordinate.variant == outcome.variant
                    && coordinate.mode == mode.mode
                    && usize::from(coordinate.surface_ordinal) < profile.surface_names.len()
                    && coordinate.byte_offset <= profile.max_surface_bytes.saturating_mul(3) => {}
            _ => return Err(NonInterferenceReportErrorV1::InvalidShape),
        }
    }
    Ok(())
}

fn normalization_digest(profile_digest: [u8; 32]) -> [u8; 32] {
    domain_digest(
        b"PiglorOS.NonInterference.Normalization.v1",
        &profile_digest,
    )
}

fn aggregate_digest(domain: &[u8], values: impl IntoIterator<Item = [u8; 32]>) -> [u8; 32] {
    let bytes = values.into_iter().flatten().collect::<Vec<_>>();
    domain_digest(domain, &bytes)
}

fn report_digest(unsigned: &[u8]) -> [u8; 32] {
    domain_digest(b"PiglorOS.NonInterference.Report.v1", unsigned)
}

fn signature_message(unsigned: &[u8]) -> Vec<u8> {
    let mut message = b"PiglorOS.NonInterference.Report.Signature.v1\0".to_vec();
    message.extend_from_slice(unsigned);
    message
}

fn execution_artifact_signature_message(unsigned: &[u8]) -> Vec<u8> {
    let mut message = b"PiglorOS.NonInterference.ExecutionArtifact.Signature.v1\0".to_vec();
    message.extend_from_slice(unsigned);
    message
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, NonInterferenceReportErrorV1> {
    pos_crypto::canonical::encode(value)
        .map(|bytes| bytes.as_slice().to_vec())
        .map_err(|_| NonInterferenceReportErrorV1::EncodingFailed)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
