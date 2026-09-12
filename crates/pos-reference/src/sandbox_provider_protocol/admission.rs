//! Fail-closed provider and image admission for the root-owned selector.

use std::ops::Deref;

use ciborium::value::Value;

use crate::evaluator::CaseAttempt;
use crate::evaluator_protocol::{EvaluationRequest, RequiredProviderCapability};

use super::codec::{
    array, bounded_array, bytes_value, decode_document, encode, identifier, key_id, record_digest,
    require_canonical_order, require_signature, signed, text, text_value, uint, uint_value,
    valid_identifier, valid_key_id, verify_digest, verify_signature,
};
use super::{
    AdmissionAuthority, AdmissionGrant, ExecuteAuthority, LaunchPolicy, ProviderCapability,
    ReceiptAuthority, SandboxAdministratorPolicy, SandboxArchitecture, SandboxExecuteRequest,
    SandboxExecutionMode, SandboxLimit, SandboxProviderManifest, SandboxProviderProtocolError,
    SandboxProviderReceipt, SandboxProviderResult, SandboxRevocationSnapshot, SandboxSyscallSet,
    SandboxTerminalOutcome, SandboxTrustError, SandboxTrustRole, SandboxTrustSnapshot,
    SignedImageManifest,
};

const CAPABILITY_SET_DOMAIN: &[u8] = b"PiglorOS.ProviderCapabilitySet.v1\0";
const REQUIRED_FEATURE_SET_DOMAIN: &[u8] = b"PiglorOS.RequiredHostFeatureSet.v1\0";
const READBACK_SET_DOMAIN: &[u8] = b"PiglorOS.SandboxReadbackSet.v1\0";
const MAX_BROKER_HARD_CAP_BYTES: usize = 1024;
const LIMIT_COUNT: usize = 17;
const MAX_NETWORK_PLANS: usize = 256;
const CONCURRENT_ATTEMPTS_LIMIT_ID: usize = 13;
const MAX_CONCURRENT_ATTEMPTS: u64 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProviderSelectionBinding {
    manifest: [u8; 32],
    binary: [u8; 32],
    profile: [u8; 32],
    report: [u8; 32],
    syscall_set: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConformanceSubjectBinding {
    profile: [u8; 32],
    binary: [u8; 32],
    public_contract: [u8; 32],
    capabilities: [u8; 32],
    required_features: [u8; 32],
    host_profile: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GrantBinding {
    request_id: [u8; 16],
    attempt_id: [u8; 16],
    authority: AdmissionAuthority,
    epochs: [u64; 3],
    input: [u8; 32],
    exchange_plans: Vec<[u8; 32]>,
    launch_policy: [u8; 32],
    effective_limits: [u8; 32],
    readback_set: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectorCommitmentAuthority {
    provider_manifest: [u8; 32],
    provider_binary: [u8; 32],
    host_profile: [u8; 32],
    syscall_set: [u8; 32],
    administrator_policy: [u8; 32],
    launch_policy: [u8; 32],
    image: [u8; 32],
}

/// Selector-derived authority that an AGR1 must reproduce exactly.
///
/// Its fields are deliberately private: callers provide authenticated EVR1,
/// EAI1, and NXP1 sources, while this module derives ELM1 and RBS1 itself.
/// A commitment cannot be assembled from provider-supplied expectation digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectorGrantCommitment {
    authority: SelectorCommitmentAuthority,
    required_provider_capability: RequiredProviderCapability,
    evr1_digest: [u8; 32],
    execution_profile_digest: [u8; 32],
    fixture_digest: [u8; 32],
    capability_ids: Vec<String>,
    network_plan_digests: Vec<[u8; 32]>,
    effective_limits: Vec<SandboxLimit>,
    effective_limits_digest: [u8; 32],
    readback_set: Vec<u8>,
    expected_readback_set_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReceiptBinding {
    attempt_id: [u8; 16],
    authority: ReceiptAuthority,
    epochs: [u64; 3],
    host_profile: [u8; 32],
    effective_limits: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecuteBinding {
    policy: [u8; 32],
    policy_epoch: u64,
    authority: SelectedExecuteAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SelectedExecuteAuthority {
    launch_policy: [u8; 32],
    image: [u8; 32],
    administrator_policy: [u8; 32],
    trust: [u8; 32],
    revocation: [u8; 32],
    provider_manifest: [u8; 32],
    conformance_profile: [u8; 32],
    conformance_report: [u8; 32],
    host_profile: [u8; 32],
}

struct DecodedProviderAdmission {
    manifest: SandboxProviderManifest,
    syscall_set: SandboxSyscallSet,
    host_profile: HostCapabilityProfile,
    conformance_report: ProviderConformanceReport,
}

/// An AGR1 that the selected provider authenticated for one exact execute request.
///
/// This capability is constructed only by [`AdmittedSandboxProvider::authenticate_grant`].
/// It prevents a separately decoded, merely well-formed AGR1 from entering the
/// terminal-evidence sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedAdmissionGrant(AdmissionGrant);

impl Deref for AuthenticatedAdmissionGrant {
    type Target = AdmissionGrant;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An SPR1 that is bound to one [`AuthenticatedAdmissionGrant`].
///
/// This capability is constructed only by
/// [`AdmittedSandboxProvider::authenticate_receipt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSandboxProviderReceipt(SandboxProviderReceipt);

impl Deref for AuthenticatedSandboxProviderReceipt {
    type Target = SandboxProviderReceipt;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An SPY1 terminal result bound to authenticated AGR1 and SPR1 evidence.
///
/// This capability is constructed only by
/// [`AdmittedSandboxProvider::authenticate_terminal_result`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSandboxProviderResult(SandboxProviderResult);

impl Deref for AuthenticatedSandboxProviderResult {
    type Target = SandboxProviderResult;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// One HCP1 feature probe and the digest of its independently retained evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostFeatureProof {
    /// Provider-neutral feature identifier.
    pub feature_id: String,
    /// Whether the required probe passed.
    pub passed: bool,
    /// Digest of the exact probe evidence.
    pub evidence_digest: [u8; 32],
}

/// Runtime-signed capability profile for one exact host class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostCapabilityProfile {
    /// Architecture observed by the provider.
    pub architecture: SandboxArchitecture,
    /// Bounded kernel release identity.
    pub kernel_release: String,
    /// Canonically ordered feature proofs.
    pub feature_proofs: Vec<HostFeatureProof>,
    /// Requested-configuration evidence digest.
    pub requested_configuration_evidence: [u8; 32],
    /// Kernel-observation evidence digest.
    pub kernel_observation_evidence: [u8; 32],
    /// Negative-probe evidence digest.
    pub negative_probe_evidence: [u8; 32],
    /// Provider runtime-attestation signer.
    pub runtime_attestation_key_id: String,
    /// Exact HCP1 self-digest.
    pub profile_digest: [u8; 32],
    signature: [u8; 64],
}

impl HostCapabilityProfile {
    /// Decode and fully validate exact canonical HCP1 bytes.
    ///
    /// # Errors
    /// Returns a closed protocol error for malformed or internally inconsistent input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let document = decode_document(bytes)?;
        let (fields, profile_digest, signature) = signed::<9>(&document, "HCP1")?;
        let profile = Self {
            architecture: SandboxArchitecture::decode(uint(&fields[2])?)?,
            kernel_release: text(&fields[3])?.to_owned(),
            feature_proofs: decode_feature_proofs(&fields[4])?,
            requested_configuration_evidence: super::codec::digest32(&fields[5])?,
            kernel_observation_evidence: super::codec::digest32(&fields[6])?,
            negative_probe_evidence: super::codec::digest32(&fields[7])?,
            runtime_attestation_key_id: key_id(&fields[8])?,
            profile_digest,
            signature,
        };
        profile.validate(fields).map(|()| profile)
    }

    /// Verify HCP1 with a caller-authorized provider runtime key.
    ///
    /// # Errors
    /// Returns a closed protocol error when validation or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = self.unsigned_value();
        self.validate(&unsigned)?;
        verify_signature("HCP1", &self.profile_digest, &self.signature, key)
    }

    fn validate(&self, unsigned: &[Value; 9]) -> Result<(), SandboxProviderProtocolError> {
        if self.kernel_release.is_empty()
            || self.kernel_release.len() > 128
            || self.feature_proofs.is_empty()
            || self.feature_proofs.len() > 256
            || !valid_key_id(&self.runtime_attestation_key_id)
            || [
                self.requested_configuration_evidence,
                self.kernel_observation_evidence,
                self.negative_probe_evidence,
            ]
            .contains(&[0; 32])
            || self.feature_proofs.iter().any(|proof| {
                !valid_identifier(&proof.feature_id) || proof.evidence_digest == [0; 32]
            })
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_canonical_order(
            &self
                .feature_proofs
                .iter()
                .map(feature_proof_value)
                .collect::<Vec<_>>(),
        )?;
        require_signature(&self.signature)?;
        verify_digest("HCP1", unsigned, self.profile_digest)
    }

    fn unsigned_value(&self) -> [Value; 9] {
        [
            text_value("HCP1"),
            uint_value(1),
            uint_value(self.architecture.code()),
            text_value(&self.kernel_release),
            Value::Array(
                self.feature_proofs
                    .iter()
                    .map(feature_proof_value)
                    .collect(),
            ),
            bytes_value(&self.requested_configuration_evidence),
            bytes_value(&self.kernel_observation_evidence),
            bytes_value(&self.negative_probe_evidence),
            text_value(&self.runtime_attestation_key_id),
        ]
    }
}

/// Independent reviewer-signed PCR1 result for one provider/host class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConformanceReport {
    /// Exact PCF1 profile digest.
    pub pcf1_digest: [u8; 32],
    /// Exact provider binary digest.
    pub provider_binary_digest: [u8; 32],
    /// Exact public provider-contract digest.
    pub public_contract_digest: [u8; 32],
    /// Digest of the exact SPM1 capability array.
    pub capability_set_digest: [u8; 32],
    /// Digest of the required host-feature identifiers.
    pub required_hcp1_feature_set_digest: [u8; 32],
    /// Architecture on which conformance passed.
    pub architecture: SandboxArchitecture,
    /// Exact tested HCP1 digest.
    pub tested_hcp1_digest: [u8; 32],
    /// Independent conformance-reviewer signer.
    pub conformance_reviewer_key_id: String,
    /// Exact PCR1 self-digest.
    pub report_digest: [u8; 32],
    signature: [u8; 64],
}

impl ProviderConformanceReport {
    /// Decode a passing exact canonical PCR1 record.
    ///
    /// # Errors
    /// Rejects malformed input and every result other than the closed Passed value zero.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, SandboxProviderProtocolError> {
        let document = decode_document(bytes)?;
        let (fields, report_digest, signature) = signed::<11>(&document, "PCR1")?;
        if uint(&fields[9])? != 0 {
            return Err(SandboxProviderProtocolError::InconsistentFields);
        }
        let report = Self {
            pcf1_digest: super::codec::digest32(&fields[2])?,
            provider_binary_digest: super::codec::digest32(&fields[3])?,
            public_contract_digest: super::codec::digest32(&fields[4])?,
            capability_set_digest: super::codec::digest32(&fields[5])?,
            required_hcp1_feature_set_digest: super::codec::digest32(&fields[6])?,
            architecture: SandboxArchitecture::decode(uint(&fields[7])?)?,
            tested_hcp1_digest: super::codec::digest32(&fields[8])?,
            conformance_reviewer_key_id: key_id(&fields[10])?,
            report_digest,
            signature,
        };
        report.validate(fields).map(|()| report)
    }

    /// Verify PCR1 with a caller-authorized independent reviewer key.
    ///
    /// # Errors
    /// Returns a closed protocol error when validation or signature verification fails.
    pub fn verify_signature(
        &self,
        key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), SandboxProviderProtocolError> {
        let unsigned = self.unsigned_value();
        self.validate(&unsigned)?;
        verify_signature("PCR1", &self.report_digest, &self.signature, key)
    }

    fn validate(&self, unsigned: &[Value; 11]) -> Result<(), SandboxProviderProtocolError> {
        if [
            self.pcf1_digest,
            self.provider_binary_digest,
            self.public_contract_digest,
            self.capability_set_digest,
            self.required_hcp1_feature_set_digest,
            self.tested_hcp1_digest,
        ]
        .contains(&[0; 32])
            || !valid_key_id(&self.conformance_reviewer_key_id)
        {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds);
        }
        require_signature(&self.signature)?;
        verify_digest("PCR1", unsigned, self.report_digest)
    }

    fn unsigned_value(&self) -> [Value; 11] {
        [
            text_value("PCR1"),
            uint_value(1),
            bytes_value(&self.pcf1_digest),
            bytes_value(&self.provider_binary_digest),
            bytes_value(&self.public_contract_digest),
            bytes_value(&self.capability_set_digest),
            bytes_value(&self.required_hcp1_feature_set_digest),
            uint_value(self.architecture.code()),
            bytes_value(&self.tested_hcp1_digest),
            uint_value(0),
            text_value(&self.conformance_reviewer_key_id),
        ]
    }
}

/// Closed reasons why the selector cannot expose a provider socket.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SandboxAdmissionError {
    /// One input violates its canonical wire contract.
    #[error(transparent)]
    Protocol(#[from] SandboxProviderProtocolError),
    /// A signer is absent, revoked, or authorized for a different role.
    #[error(transparent)]
    Trust(#[from] SandboxTrustError),
    /// APT1 does not select the exact supplied artifact.
    #[error("sandbox admission artifact is not selected by policy")]
    PolicyMismatch,
    /// Content bytes do not match their signed digest or declared length.
    #[error("sandbox admission artifact bytes do not match")]
    ArtifactMismatch,
    /// Duplicated SPM1/PCR1/HCP1 subjects disagree.
    #[error("sandbox conformance subjects do not agree")]
    ConformanceMismatch,
    /// SCS1, PCR1, HCP1, SPM1, or SIM1 architectures disagree.
    #[error("sandbox admission architecture does not agree")]
    ArchitectureMismatch,
    /// A required host feature is absent, failed, or bound by a different digest.
    #[error("sandbox host capability is insufficient")]
    HostCapabilityMismatch,
    /// SIM1 does not bind an authenticated certificate mapping.
    #[error("sandbox image certificate mapping does not agree")]
    CertificateMismatch,
    /// The exact provider or image identity is currently revoked.
    #[error("sandbox admission artifact is revoked")]
    Revoked,
}

/// Exact immutable artifacts supplied to one provider-admission decision.
#[derive(Clone, Copy, Debug)]
pub struct SandboxProviderAdmissionInputs<'a> {
    /// Canonical signed SPM1 bytes.
    pub provider_manifest: &'a [u8],
    /// Stream-verified content digest of the retained provider executable.
    pub provider_binary_digest: [u8; 32],
    /// Exact independently installed broker hard-cap bytes selected by APT1.
    pub broker_hard_caps: &'a [u8],
    /// Canonical independently signed PCR1 bytes.
    pub conformance_report: &'a [u8],
    /// Canonical runtime-signed current HCP1 bytes.
    pub host_profile: &'a [u8],
    /// Canonical selected SCS1 bytes.
    pub syscall_set: &'a [u8],
    /// Canonically ordered installed host-feature identifiers.
    pub required_features: &'a [String],
}

/// A provider released only after every selector-owned admission check succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedSandboxProvider {
    policy: SandboxAdministratorPolicy,
    manifest: SandboxProviderManifest,
    syscall_set: SandboxSyscallSet,
    host_profile: HostCapabilityProfile,
    conformance_report: ProviderConformanceReport,
    trust: SandboxTrustSnapshot,
    revocation: SandboxRevocationSnapshot,
    runtime_key: ed25519_dalek::VerifyingKey,
    broker_hard_caps: Vec<SandboxLimit>,
    broker_hard_caps_digest: [u8; 32],
    required_features: Vec<String>,
}

/// SIM1 and exact image bytes released by selector-owned admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedSandboxImage {
    manifest: SignedImageManifest,
}

impl AdmittedSandboxImage {
    /// Authenticated image manifest bound to exact admitted bytes.
    #[must_use]
    pub const fn manifest(&self) -> &SignedImageManifest {
        &self.manifest
    }
}

impl AdmittedSandboxProvider {
    /// Authenticate and cross-bind one complete provider admission set.
    ///
    /// `required_features` is the installed, canonically ordered feature-ID set
    /// whose domain-separated digest is repeated by SPM1 and PCR1.
    ///
    /// # Errors
    /// Fails closed on any malformed, forged, revoked, unselected, unequal, or
    /// byte-mismatched artifact. No provider capability is returned on failure.
    pub fn admit(
        policy: &SandboxAdministratorPolicy,
        trust: &SandboxTrustSnapshot,
        revocation: &SandboxRevocationSnapshot,
        inputs: SandboxProviderAdmissionInputs<'_>,
    ) -> Result<Self, SandboxAdmissionError> {
        let decoded = DecodedProviderAdmission {
            manifest: SandboxProviderManifest::from_canonical_cbor(inputs.provider_manifest)?,
            syscall_set: SandboxSyscallSet::from_canonical_cbor(inputs.syscall_set)?,
            host_profile: HostCapabilityProfile::from_canonical_cbor(inputs.host_profile)?,
            conformance_report: ProviderConformanceReport::from_canonical_cbor(
                inputs.conformance_report,
            )?,
        };
        Self::validate_selected_provider(
            policy,
            revocation,
            inputs.provider_binary_digest,
            inputs.broker_hard_caps,
            &decoded,
        )?;
        let broker_hard_caps = decode_broker_hard_caps(inputs.broker_hard_caps)?;
        let broker_hard_caps_digest = digest_bytes(inputs.broker_hard_caps);
        let runtime_key = Self::authenticate_provider_signers(trust, revocation, &decoded)?;
        Self::validate_conformance(inputs.required_features, &decoded)?;
        Ok(Self {
            policy: policy.clone(),
            manifest: decoded.manifest,
            syscall_set: decoded.syscall_set,
            host_profile: decoded.host_profile,
            conformance_report: decoded.conformance_report,
            trust: trust.clone(),
            revocation: revocation.clone(),
            runtime_key,
            broker_hard_caps,
            broker_hard_caps_digest,
            required_features: inputs.required_features.to_vec(),
        })
    }

    fn validate_selected_provider(
        policy: &SandboxAdministratorPolicy,
        revocation: &SandboxRevocationSnapshot,
        provider_binary_digest: [u8; 32],
        broker_hard_caps: &[u8],
        decoded: &DecodedProviderAdmission,
    ) -> Result<(), SandboxAdmissionError> {
        let DecodedProviderAdmission {
            manifest,
            syscall_set,
            conformance_report,
            ..
        } = decoded;
        let selection = policy.selection();
        let supplied_selection = ProviderSelectionBinding {
            manifest: manifest.manifest_digest,
            binary: manifest.binary_digest,
            profile: manifest.pcf1_digest,
            report: conformance_report.report_digest,
            syscall_set: syscall_set.syscall_set_digest,
        };
        let policy_selection = ProviderSelectionBinding {
            manifest: selection.provider_manifest,
            binary: selection.provider_binary,
            profile: selection.conformance_profile,
            report: selection.conformance_report,
            syscall_set: selection.syscall_set,
        };
        if policy_selection != supplied_selection {
            return Err(SandboxAdmissionError::PolicyMismatch);
        }
        if digest_bytes(broker_hard_caps) != selection.broker_hard_caps {
            return Err(SandboxAdmissionError::ArtifactMismatch);
        }
        if revocation.provider_revoked(&manifest.manifest_digest)
            || revocation.provider_revoked(&manifest.binary_digest)
        {
            return Err(SandboxAdmissionError::Revoked);
        }
        if provider_binary_digest != manifest.binary_digest {
            return Err(SandboxAdmissionError::ArtifactMismatch);
        }
        Ok(())
    }

    fn authenticate_provider_signers(
        trust: &SandboxTrustSnapshot,
        revocation: &SandboxRevocationSnapshot,
        decoded: &DecodedProviderAdmission,
    ) -> Result<ed25519_dalek::VerifyingKey, SandboxAdmissionError> {
        let DecodedProviderAdmission {
            manifest,
            host_profile,
            conformance_report,
            ..
        } = decoded;
        if manifest.trust_epoch != trust.trust_epoch() {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        let release_key = revocation.active_key(
            trust,
            &manifest.provider_release_key_id,
            SandboxTrustRole::ProviderRelease,
        )?;
        manifest.verify_signature(&release_key)?;
        let runtime_key = revocation.active_key(
            trust,
            &manifest.runtime_attestation_key_id,
            SandboxTrustRole::ProviderRuntimeAttestation,
        )?;
        if host_profile.runtime_attestation_key_id != manifest.runtime_attestation_key_id {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        host_profile.verify_signature(&runtime_key)?;
        let reviewer_key = revocation.active_key(
            trust,
            &conformance_report.conformance_reviewer_key_id,
            SandboxTrustRole::IndependentConformanceReviewer,
        )?;
        conformance_report.verify_signature(&reviewer_key)?;
        Ok(runtime_key)
    }

    fn validate_conformance(
        required_features: &[String],
        decoded: &DecodedProviderAdmission,
    ) -> Result<(), SandboxAdmissionError> {
        let DecodedProviderAdmission {
            manifest,
            syscall_set,
            host_profile,
            conformance_report,
        } = decoded;
        let capability_digest = capability_set_digest(&manifest.capabilities)?;
        let feature_digest = required_feature_set_digest(required_features)?;
        let reported_subject = ConformanceSubjectBinding {
            profile: conformance_report.pcf1_digest,
            binary: conformance_report.provider_binary_digest,
            public_contract: conformance_report.public_contract_digest,
            capabilities: conformance_report.capability_set_digest,
            required_features: conformance_report.required_hcp1_feature_set_digest,
            host_profile: conformance_report.tested_hcp1_digest,
        };
        let admitted_subject = ConformanceSubjectBinding {
            profile: manifest.pcf1_digest,
            binary: manifest.binary_digest,
            public_contract: manifest.public_contract_digest,
            capabilities: capability_digest,
            required_features: feature_digest,
            host_profile: host_profile.profile_digest,
        };
        if reported_subject != admitted_subject
            || manifest.required_hcp1_feature_set_digest != feature_digest
        {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        if host_profile.feature_proofs.len() != super::REQUIRED_HOST_FEATURES.len()
            || !super::REQUIRED_HOST_FEATURES.iter().all(|required| {
                host_profile
                    .feature_proofs
                    .iter()
                    .any(|proof| proof.feature_id == *required)
            })
            || host_profile
                .feature_proofs
                .iter()
                .any(|proof| !proof.passed)
        {
            return Err(SandboxAdmissionError::HostCapabilityMismatch);
        }
        let architecture = syscall_set.architecture;
        if conformance_report.architecture != architecture
            || host_profile.architecture != architecture
            || manifest.architectures.binary_search(&architecture).is_err()
        {
            return Err(SandboxAdmissionError::ArchitectureMismatch);
        }
        Ok(())
    }

    /// Admit exact SIM1, root-image, and executable bytes for this provider.
    ///
    /// # Errors
    /// Rejects unselected or revoked image identities, incorrect image authority,
    /// certificate mappings, epochs, architecture, lengths, or byte digests.
    pub fn admit_image(
        &self,
        manifest_bytes: &[u8],
        root_image: &[u8],
        executable: &[u8],
    ) -> Result<AdmittedSandboxImage, SandboxAdmissionError> {
        let image = SignedImageManifest::from_canonical_cbor(manifest_bytes)?;
        if !self.policy.accepts_image(&image.manifest_digest) {
            return Err(SandboxAdmissionError::PolicyMismatch);
        }
        if self.revocation.image_revoked(&image.manifest_digest)
            || self
                .revocation
                .image_revoked(&image.root_image_blake3_digest)
            || self
                .revocation
                .image_revoked(&image.executable_blake3_digest)
        {
            return Err(SandboxAdmissionError::Revoked);
        }
        if image.architecture != self.syscall_set.architecture {
            return Err(SandboxAdmissionError::ArchitectureMismatch);
        }
        if image.image_trust_epoch != self.trust.trust_epoch() {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        let image_length =
            u64::try_from(root_image.len()).map_err(|_| SandboxAdmissionError::ArtifactMismatch)?;
        if image.root_image_length != image_length
            || image.root_image_blake3_digest != digest_bytes(root_image)
            || image.executable_blake3_digest != digest_bytes(executable)
        {
            return Err(SandboxAdmissionError::ArtifactMismatch);
        }
        let certificate_matches = self.trust.certificates().iter().any(|certificate| {
            certificate.fingerprint == image.signing_certificate_sha256
                && certificate.keyring_serial == image.kernel_keyring_serial
                && certificate.epoch == image.image_trust_epoch
        });
        if !certificate_matches {
            return Err(SandboxAdmissionError::CertificateMismatch);
        }
        let image_key = self.revocation.active_key(
            &self.trust,
            &image.image_project_key_id,
            SandboxTrustRole::ImageProject,
        )?;
        image.verify_signature(&image_key)?;
        Ok(AdmittedSandboxImage { manifest: image })
    }

    /// Admit an exact LPS1 for an already admitted image.
    ///
    /// # Errors
    /// Rejects an unselected launch policy or a policy bound to another image.
    pub fn admit_launch_policy(
        &self,
        bytes: &[u8],
        image: &AdmittedSandboxImage,
    ) -> Result<LaunchPolicy, SandboxAdmissionError> {
        let launch = LaunchPolicy::from_canonical_cbor(bytes)?;
        if !self.policy.accepts_launch_policy(&launch.policy_digest) {
            return Err(SandboxAdmissionError::PolicyMismatch);
        }
        if launch.sim1_digest != image.manifest.manifest_digest {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        Ok(launch)
    }

    /// Derive the only ELM1 and RBS1 commitments that an AGR1 may carry.
    ///
    /// The selector supplies the authenticated EVR1 request, its selected EAI1
    /// attempt, and the ordered NXP1 plans. This method derives the expected
    /// digests from those sources and from the already admitted provider,
    /// image, launch policy, and BHC1 bytes; no caller can provide an expected
    /// ELM1 or RBS1 digest.
    ///
    /// # Errors
    /// Rejects incomplete, substituted, noncanonical, or unsupported selector
    /// authority before returning a commitment.
    pub fn derive_selector_grant_commitment(
        &self,
        image: &AdmittedSandboxImage,
        launch: &LaunchPolicy,
        evaluation: &EvaluationRequest,
        attempt: &CaseAttempt,
        network_plans: &[super::NetworkExchangePlan],
    ) -> Result<SelectorGrantCommitment, SandboxAdmissionError> {
        SelectorGrantCommitment::derive(self, image, launch, evaluation, attempt, network_plans)
    }

    /// Authenticate AGR1 and bind it to the exact selected SPX1 authority.
    ///
    /// # Errors
    /// Rejects a forged grant or any request, attempt, artifact, epoch, input,
    /// exchange-plan, launch-policy, or runtime-key substitution.
    pub fn authenticate_grant(
        &self,
        bytes: &[u8],
        request: &SandboxExecuteRequest,
        image: &AdmittedSandboxImage,
        launch: &LaunchPolicy,
        commitment: &SelectorGrantCommitment,
    ) -> Result<AuthenticatedAdmissionGrant, SandboxAdmissionError> {
        if !commitment.matches(self, image, launch) {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        self.validate_execute_authority(request, image, launch)?;
        let grant = AdmissionGrant::from_canonical_cbor(bytes)?;
        if grant.runtime_attestation_key_id != self.manifest.runtime_attestation_key_id {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        grant.verify_signature(&self.runtime_key)?;
        let request_authority = &request.authority;
        let grant_authority = &grant.authority;
        let expected_plans = request
            .network_plans
            .iter()
            .map(|plan| plan.plan_digest)
            .collect::<Vec<_>>();
        if request_authority.evr1_digest != commitment.evr1_digest
            || request_authority.execution_profile_digest != commitment.execution_profile_digest
            || request_authority.fixture_digest != commitment.fixture_digest
            || request.capability_ids != commitment.capability_ids
            || expected_plans != commitment.network_plan_digests
            || !self.supports_capabilities(&request.capability_ids)
        {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        let actual = GrantBinding {
            request_id: grant.request_id,
            attempt_id: grant.attempt_id,
            authority: grant_authority.clone(),
            epochs: [
                grant.trust_epoch,
                grant.revocation_epoch,
                grant.policy_epoch,
            ],
            input: grant.input_digest,
            exchange_plans: grant.exchange_plan_digests.clone(),
            launch_policy: grant.expected_launch_policy_digest,
            effective_limits: grant.elm1_digest,
            readback_set: grant.expected_readback_set_digest,
        };
        let expected = GrantBinding {
            request_id: request.request.request_id,
            attempt_id: request.attempt_id,
            authority: AdmissionAuthority {
                evr1_digest: request_authority.evr1_digest,
                fixture_contract_digest: request_authority.fixture_contract_digest,
                fixture_digest: request_authority.fixture_digest,
                execution_profile_digest: request_authority.execution_profile_digest,
                lps1_digest: request_authority.lps1_digest,
                sim1_digest: request_authority.sim1_digest,
                apt1_digest: request_authority.apt1_digest,
                trs1_digest: request_authority.trs1_digest,
                rvs1_digest: request_authority.rvs1_digest,
                spm1_digest: request_authority.spm1_digest,
                pcf1_digest: request_authority.pcf1_digest,
                pcr1_digest: request_authority.pcr1_digest,
                hcp1_digest: request_authority.hcp1_digest,
            },
            epochs: [
                self.trust.trust_epoch(),
                self.revocation.revocation_epoch(),
                self.policy.policy_epoch(),
            ],
            input: request.adapter_input.digest,
            exchange_plans: expected_plans,
            launch_policy: launch.policy_digest,
            effective_limits: commitment.effective_limits_digest,
            readback_set: commitment.expected_readback_set_digest,
        };
        if actual != expected {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        Ok(AuthenticatedAdmissionGrant(grant))
    }

    /// Authenticate an SPR1 and bind it to the admitted provider and AGR1.
    ///
    /// # Errors
    /// Rejects a forged receipt or any lifecycle authority substitution.
    pub fn authenticate_receipt(
        &self,
        bytes: &[u8],
        grant: &AuthenticatedAdmissionGrant,
    ) -> Result<AuthenticatedSandboxProviderReceipt, SandboxAdmissionError> {
        let receipt = SandboxProviderReceipt::from_canonical_cbor(bytes)?;
        if receipt.runtime_attestation_key_id != self.manifest.runtime_attestation_key_id {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        receipt.verify_signature(&self.runtime_key)?;
        let authority = &receipt.authority;
        let actual = ReceiptBinding {
            attempt_id: receipt.attempt_id,
            authority: authority.clone(),
            epochs: [
                receipt.trust_epoch,
                receipt.revocation_epoch,
                receipt.policy_epoch,
            ],
            host_profile: receipt.hcp1_digest,
            effective_limits: receipt.elm1_digest,
        };
        let expected = ReceiptBinding {
            attempt_id: grant.attempt_id,
            authority: ReceiptAuthority {
                agr1_digest: grant.grant_digest,
                spm1_digest: self.manifest.manifest_digest,
                provider_binary_digest: self.manifest.binary_digest,
                lps1_digest: grant.authority.lps1_digest,
                sim1_digest: grant.authority.sim1_digest,
                apt1_digest: self.policy.policy_digest(),
                trs1_digest: self.trust.snapshot_digest(),
                rvs1_digest: self.revocation.snapshot_digest(),
            },
            epochs: [
                self.trust.trust_epoch(),
                self.revocation.revocation_epoch(),
                self.policy.policy_epoch(),
            ],
            host_profile: self.host_profile.profile_digest,
            effective_limits: grant.elm1_digest,
        };
        if actual != expected {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        Ok(AuthenticatedSandboxProviderReceipt(receipt))
    }

    /// Authenticate a post-admission SPY1 against its exact AGR1 and SPR1.
    ///
    /// # Errors
    /// Rejects a forged result, pre-admission outcome, identity substitution,
    /// or lifecycle evidence that does not match the authenticated receipt.
    pub fn authenticate_terminal_result(
        &self,
        bytes: &[u8],
        request: &SandboxExecuteRequest,
        grant: &AuthenticatedAdmissionGrant,
        receipt: &AuthenticatedSandboxProviderReceipt,
    ) -> Result<AuthenticatedSandboxProviderResult, SandboxAdmissionError> {
        let result = SandboxProviderResult::from_canonical_cbor(bytes)?;
        if result.runtime_attestation_key_id != self.manifest.runtime_attestation_key_id {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        result.verify_signature(&self.runtime_key)?;
        if matches!(
            result.outcome,
            SandboxTerminalOutcome::UnavailableBeforeAdmission | SandboxTerminalOutcome::Rejected
        ) || result.request_id != request.request.request_id
            || result.attempt_id != request.attempt_id
            || grant.request_id != result.request_id
            || grant.attempt_id != result.attempt_id
        {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        result.validate_receipt_lifecycle(receipt)?;
        Ok(AuthenticatedSandboxProviderResult(result))
    }

    /// Authenticate the complete SAU1 chain referenced by SPR1 and mirrored by SPY1.
    ///
    /// # Errors
    /// Rejects forged, reordered, incomplete, substituted, or incorrectly bound events.
    pub fn authenticate_audit_chain(
        &self,
        records: &[Vec<u8>],
        receipt: &AuthenticatedSandboxProviderReceipt,
        result: &AuthenticatedSandboxProviderResult,
    ) -> Result<Vec<super::SandboxAuditRecord>, SandboxAdmissionError> {
        receipt.verify_signature(&self.runtime_key)?;
        result.verify_signature(&self.runtime_key)?;
        super::audit::authenticate_audit_chain(records, receipt, result, &self.runtime_key)
            .map_err(Into::into)
    }

    fn validate_execute_authority(
        &self,
        request: &SandboxExecuteRequest,
        image: &AdmittedSandboxImage,
        launch: &LaunchPolicy,
    ) -> Result<(), SandboxAdmissionError> {
        let authority = &request.authority;
        let actual = ExecuteBinding {
            policy: request.request.apt1_digest,
            policy_epoch: request.request.policy_epoch,
            authority: SelectedExecuteAuthority::from_execute(authority),
        };
        let expected = ExecuteBinding {
            policy: self.policy.policy_digest(),
            policy_epoch: self.policy.policy_epoch(),
            authority: SelectedExecuteAuthority {
                launch_policy: launch.policy_digest,
                image: image.manifest.manifest_digest,
                administrator_policy: self.policy.policy_digest(),
                trust: self.trust.snapshot_digest(),
                revocation: self.revocation.snapshot_digest(),
                provider_manifest: self.manifest.manifest_digest,
                conformance_profile: self.manifest.pcf1_digest,
                conformance_report: self.conformance_report.report_digest,
                host_profile: self.host_profile.profile_digest,
            },
        };
        if actual != expected {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        Ok(())
    }

    fn supports_capabilities(&self, requested: &[String]) -> bool {
        requested.iter().all(|required| {
            self.manifest
                .capabilities
                .iter()
                .any(|available| available.capability_id == *required)
        })
    }

    /// Decide whether SPM1 exposes the exact requested capability version at
    /// no less than the requested minimum strength.
    #[must_use]
    pub fn supports_required_capability(&self, required: &RequiredProviderCapability) -> bool {
        self.manifest.capabilities.iter().any(|available| {
            available.capability_id == required.capability_id
                && available.capability_version == required.capability_version
                && available.minimum_strength >= required.minimum_strength
        })
    }

    /// Authenticated SPM1 selected for this capability.
    #[must_use]
    pub const fn manifest(&self) -> &SandboxProviderManifest {
        &self.manifest
    }

    /// Exact selected architecture-qualified SCS1.
    #[must_use]
    pub const fn syscall_set(&self) -> &SandboxSyscallSet {
        &self.syscall_set
    }

    /// Current runtime-signed HCP1 used by admission.
    #[must_use]
    pub const fn host_profile(&self) -> &HostCapabilityProfile {
        &self.host_profile
    }

    /// Independent passing PCR1 used by admission.
    #[must_use]
    pub const fn conformance_report(&self) -> &ProviderConformanceReport {
        &self.conformance_report
    }
}

impl SelectedExecuteAuthority {
    const fn from_execute(authority: &ExecuteAuthority) -> Self {
        Self {
            launch_policy: authority.lps1_digest,
            image: authority.sim1_digest,
            administrator_policy: authority.apt1_digest,
            trust: authority.trs1_digest,
            revocation: authority.rvs1_digest,
            provider_manifest: authority.spm1_digest,
            conformance_profile: authority.pcf1_digest,
            conformance_report: authority.pcr1_digest,
            host_profile: authority.hcp1_digest,
        }
    }
}

fn decode_feature_proofs(
    value: &Value,
) -> Result<Vec<HostFeatureProof>, SandboxProviderProtocolError> {
    bounded_array(value, 1)?
        .iter()
        .map(|value| {
            let fields = array::<3>(value)?;
            let passed = match uint(&fields[1])? {
                0 => false,
                1 => true,
                _ => return Err(SandboxProviderProtocolError::InvalidEncoding),
            };
            Ok(HostFeatureProof {
                feature_id: identifier(&fields[0])?,
                passed,
                evidence_digest: super::codec::digest32(&fields[2])?,
            })
        })
        .collect()
}

fn feature_proof_value(proof: &HostFeatureProof) -> Value {
    Value::Array(vec![
        text_value(&proof.feature_id),
        uint_value(u64::from(proof.passed)),
        bytes_value(&proof.evidence_digest),
    ])
}

impl SelectorGrantCommitment {
    fn derive(
        provider: &AdmittedSandboxProvider,
        image: &AdmittedSandboxImage,
        launch: &LaunchPolicy,
        evaluation: &EvaluationRequest,
        attempt: &CaseAttempt,
        network_plans: &[super::NetworkExchangePlan],
    ) -> Result<Self, SandboxAdmissionError> {
        evaluation
            .to_canonical_cbor()
            .map_err(|_| SandboxAdmissionError::ConformanceMismatch)?;
        let requirement = evaluation
            .sandbox_requirement
            .as_ref()
            .ok_or(SandboxAdmissionError::ConformanceMismatch)?;
        if requirement.lps1_digest != launch.policy_digest
            || requirement.sim1_digest != image.manifest.manifest_digest
            || requirement.apt1_digest != provider.policy.policy_digest()
            || requirement.policy_epoch != provider.policy.policy_epoch()
            || u64::from(attempt.mode) != launch.execution_mode.code()
            || attempt.fixture_digest == [0; 32]
            || !attempt
                .capability_ids
                .contains(&requirement.required_provider_capability.capability_id)
            || !provider.supports_required_capability(&requirement.required_provider_capability)
        {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        if network_plans.len() > MAX_NETWORK_PLANS {
            return Err(SandboxProviderProtocolError::FieldOutOfBounds.into());
        }
        super::execution::validate_network_plans(network_plans)?;
        let effective_limits =
            derive_effective_limits(&provider.broker_hard_caps, launch, attempt)?;
        let network_plan_digests = network_plans
            .iter()
            .map(|plan| plan.plan_digest)
            .collect::<Vec<_>>();
        let derived_artifacts = effective_limits_digest(
            &effective_limits,
            provider.broker_hard_caps_digest,
            provider.policy.policy_digest(),
            launch.policy_digest,
            evaluation.execution_profile_digest,
            attempt.fixture_digest,
            &provider.manifest.runtime_attestation_key_id,
        )
        .and_then(|effective_limits_digest| {
            expected_fdl1_digest(launch.execution_mode)
                .map(|expected_fdl1_digest| (effective_limits_digest, expected_fdl1_digest))
        })
        .and_then(|(effective_limits_digest, expected_fdl1_digest)| {
            readback_set(
                provider,
                image,
                launch,
                &requirement.required_provider_capability,
                effective_limits_digest,
                expected_fdl1_digest,
                &network_plan_digests,
            )
            .map(|(readback_set, expected_readback_set_digest)| {
                (
                    effective_limits_digest,
                    readback_set,
                    expected_readback_set_digest,
                )
            })
        });
        let (effective_limits_digest, readback_set, expected_readback_set_digest) =
            derived_artifacts?;
        Ok(Self {
            authority: selector_commitment_authority(provider, image, launch),
            required_provider_capability: requirement.required_provider_capability.clone(),
            evr1_digest: evaluation.request_digest,
            execution_profile_digest: evaluation.execution_profile_digest,
            fixture_digest: attempt.fixture_digest,
            capability_ids: attempt.capability_ids.clone(),
            network_plan_digests,
            effective_limits,
            effective_limits_digest,
            readback_set,
            expected_readback_set_digest,
        })
    }

    fn matches(
        &self,
        provider: &AdmittedSandboxProvider,
        image: &AdmittedSandboxImage,
        launch: &LaunchPolicy,
    ) -> bool {
        self.authority == selector_commitment_authority(provider, image, launch)
    }

    /// Selector-derived ELM1 limits retained for provider-independent audit.
    #[must_use]
    pub fn effective_limits(&self) -> &[SandboxLimit] {
        &self.effective_limits
    }

    /// Selector-derived ELM1 digest that AGR1 must reproduce.
    #[must_use]
    pub const fn effective_limits_digest(&self) -> [u8; 32] {
        self.effective_limits_digest
    }

    /// Exact selector-derived RBS1 bytes retained for audit and golden vectors.
    #[must_use]
    pub fn expected_readback_set(&self) -> &[u8] {
        &self.readback_set
    }

    /// Selector-derived RBS1 digest that AGR1 must reproduce.
    #[must_use]
    pub const fn expected_readback_set_digest(&self) -> [u8; 32] {
        self.expected_readback_set_digest
    }
}

const fn selector_commitment_authority(
    provider: &AdmittedSandboxProvider,
    image: &AdmittedSandboxImage,
    launch: &LaunchPolicy,
) -> SelectorCommitmentAuthority {
    SelectorCommitmentAuthority {
        provider_manifest: provider.manifest.manifest_digest,
        provider_binary: provider.manifest.binary_digest,
        host_profile: provider.host_profile.profile_digest,
        syscall_set: provider.syscall_set.syscall_set_digest,
        administrator_policy: provider.policy.policy_digest(),
        launch_policy: launch.policy_digest,
        image: image.manifest.manifest_digest,
    }
}

fn decode_broker_hard_caps(
    bytes: &[u8],
) -> Result<Vec<SandboxLimit>, SandboxProviderProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_BROKER_HARD_CAP_BYTES {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    let document = decode_document(bytes)?;
    let fields = array::<3>(&document)?;
    if text(&fields[0])? != "BHC1" || uint(&fields[1])? != 1 {
        return Err(SandboxProviderProtocolError::UnsupportedVersion);
    }
    decode_exact_limits(&fields[2])
}

fn decode_exact_limits(value: &Value) -> Result<Vec<SandboxLimit>, SandboxProviderProtocolError> {
    let Value::Array(values) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    if values.len() != LIMIT_COUNT {
        return Err(SandboxProviderProtocolError::FieldOutOfBounds);
    }
    values
        .iter()
        .enumerate()
        .map(|(expected_id, value)| {
            let fields = array::<2>(value)?;
            let limit_id = u8::try_from(uint(&fields[0])?)
                .map_err(|_| SandboxProviderProtocolError::FieldOutOfBounds)?;
            if usize::from(limit_id) != expected_id {
                return Err(SandboxProviderProtocolError::NonCanonicalOrder);
            }
            Ok(SandboxLimit {
                limit_id,
                value: uint(&fields[1])?,
            })
        })
        .collect()
}

fn derive_effective_limits(
    broker: &[SandboxLimit],
    launch: &LaunchPolicy,
    attempt: &CaseAttempt,
) -> Result<Vec<SandboxLimit>, SandboxProviderProtocolError> {
    if broker.len() != LIMIT_COUNT
        || launch.effective_limits.len() != LIMIT_COUNT
        || !broker.iter().zip(&launch.effective_limits).enumerate().all(
            |(limit_id, (broker, launch))| {
                usize::from(broker.limit_id) == limit_id && broker.limit_id == launch.limit_id
            },
        )
    {
        return Err(SandboxProviderProtocolError::InconsistentFields);
    }
    let limits = broker
        .iter()
        .zip(&launch.effective_limits)
        .map(|(broker, policy)| SandboxLimit {
            limit_id: broker.limit_id,
            value: broker
                .value
                .min(policy.value)
                .min(attempt_limit(broker.limit_id, attempt)),
        })
        .collect::<Vec<_>>();
    if limits[4].value == 0 || limits[CONCURRENT_ATTEMPTS_LIMIT_ID].value > MAX_CONCURRENT_ATTEMPTS
    {
        return Err(SandboxProviderProtocolError::InconsistentFields);
    }
    Ok(limits)
}

const fn attempt_limit(limit_id: u8, attempt: &CaseAttempt) -> u64 {
    match limit_id {
        0 => attempt.budget.memory_bytes,
        4 => attempt.watchdog_ms,
        8 => attempt.budget.output_bytes,
        9 => attempt.budget.storage_bytes,
        _ => u64::MAX,
    }
}

fn effective_limits_digest(
    limits: &[SandboxLimit],
    broker_caps_digest: [u8; 32],
    apt1_digest: [u8; 32],
    lps1_digest: [u8; 32],
    execution_profile_digest: [u8; 32],
    fixture_digest: [u8; 32],
    runtime_attestation_key_id: &str,
) -> Result<[u8; 32], SandboxProviderProtocolError> {
    record_digest(
        "ELM1",
        &Value::Array(vec![
            text_value("ELM1"),
            uint_value(1),
            limit_values(limits),
            bytes_value(&broker_caps_digest),
            bytes_value(&apt1_digest),
            bytes_value(&lps1_digest),
            bytes_value(&execution_profile_digest),
            bytes_value(&fixture_digest),
            text_value(runtime_attestation_key_id),
        ]),
    )
}

fn expected_fdl1_digest(
    mode: SandboxExecutionMode,
) -> Result<[u8; 32], SandboxProviderProtocolError> {
    let entries = match mode {
        SandboxExecutionMode::Local => vec![fd_layout_entry(3, 0), fd_layout_entry(4, 1)],
        SandboxExecutionMode::AirGapped
        | SandboxExecutionMode::Replay
        | SandboxExecutionMode::Fork => vec![fd_layout_entry(3, 1)],
    };
    record_digest(
        "FDL1",
        &Value::Array(vec![
            text_value("FDL1"),
            uint_value(1),
            uint_value(mode.code()),
            Value::Array(entries),
        ]),
    )
}

fn readback_set(
    provider: &AdmittedSandboxProvider,
    image: &AdmittedSandboxImage,
    launch: &LaunchPolicy,
    required_capability: &RequiredProviderCapability,
    effective_limits_digest: [u8; 32],
    expected_fdl1_digest: [u8; 32],
    network_plan_digests: &[[u8; 32]],
) -> Result<(Vec<u8>, [u8; 32]), SandboxProviderProtocolError> {
    let unsigned = Value::Array(vec![
        text_value("RBS1"),
        uint_value(1),
        uint_value(0),
        text_value(&provider.manifest.provider_id),
        bytes_value(&provider.manifest.manifest_digest),
        bytes_value(&provider.manifest.binary_digest),
        bytes_value(&provider.manifest.public_contract_digest),
        bytes_value(&provider.host_profile.profile_digest),
        uint_value(provider.syscall_set.architecture.code()),
        text_value(&provider.manifest.runtime_attestation_key_id),
        Value::Array(vec![
            text_value(&required_capability.capability_id),
            uint_value(required_capability.capability_version),
            uint_value(required_capability.minimum_strength),
        ]),
        uint_value(launch.execution_mode.code()),
        bytes_value(&launch.policy_digest),
        bytes_value(&image.manifest.manifest_digest),
        bytes_value(&provider.syscall_set.syscall_set_digest),
        bytes_value(&effective_limits_digest),
        bytes_value(&expected_fdl1_digest),
        Value::Array(
            provider
                .required_features
                .iter()
                .map(|feature| text_value(feature))
                .collect(),
        ),
        Value::Array(
            network_plan_digests
                .iter()
                .map(|digest| bytes_value(digest))
                .collect(),
        ),
    ]);
    let digest = digest_value(READBACK_SET_DOMAIN, &unsigned)?;
    let bytes = encode(&Value::Array(vec![unsigned, bytes_value(&digest)]))?;
    Ok((bytes, digest))
}

fn limit_values(limits: &[SandboxLimit]) -> Value {
    Value::Array(
        limits
            .iter()
            .map(|limit| {
                Value::Array(vec![
                    uint_value(u64::from(limit.limit_id)),
                    uint_value(limit.value),
                ])
            })
            .collect(),
    )
}

fn fd_layout_entry(fd: u64, role: u64) -> Value {
    Value::Array(vec![uint_value(fd), uint_value(role)])
}

fn capability_set_digest(
    capabilities: &[ProviderCapability],
) -> Result<[u8; 32], SandboxProviderProtocolError> {
    let values = capabilities
        .iter()
        .map(|capability| {
            Value::Array(vec![
                text_value(&capability.capability_id),
                uint_value(capability.capability_version),
                uint_value(capability.minimum_strength),
            ])
        })
        .collect();
    digest_value(CAPABILITY_SET_DOMAIN, &Value::Array(values))
}

fn required_feature_set_digest(
    required_features: &[String],
) -> Result<[u8; 32], SandboxAdmissionError> {
    if !required_features
        .iter()
        .map(String::as_str)
        .eq(super::REQUIRED_HOST_FEATURES)
    {
        return Err(SandboxAdmissionError::HostCapabilityMismatch);
    }
    let value = Value::Array(
        required_features
            .iter()
            .map(|feature| text_value(feature))
            .collect(),
    );
    digest_value(REQUIRED_FEATURE_SET_DOMAIN, &value).map_err(Into::into)
}

fn digest_value(domain: &[u8], value: &Value) -> Result<[u8; 32], SandboxProviderProtocolError> {
    let encoded = encode(value)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
