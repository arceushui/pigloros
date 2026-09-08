//! Fail-closed provider and image admission for the root-owned selector.

use ciborium::value::Value;

use super::codec::{
    array, bounded_array, bytes_value, decode_document, encode, identifier, key_id,
    require_canonical_order, require_signature, signed, text, text_value, uint, uint_value,
    valid_identifier, valid_key_id, verify_digest, verify_signature,
};
use super::{
    ProviderCapability, SandboxAdministratorPolicy, SandboxArchitecture, SandboxProviderManifest,
    SandboxProviderProtocolError, SandboxRevocationSnapshot, SandboxSyscallSet, SandboxTrustError,
    SandboxTrustRole, SandboxTrustSnapshot, SignedImageManifest,
};

const CAPABILITY_SET_DOMAIN: &[u8] = b"PiglorOS.ProviderCapabilitySet.v1\0";
const REQUIRED_FEATURE_SET_DOMAIN: &[u8] = b"PiglorOS.RequiredHostFeatureSet.v1\0";

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
    /// Exact installed provider executable bytes.
    pub provider_binary: &'a [u8],
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
    manifest: SandboxProviderManifest,
    syscall_set: SandboxSyscallSet,
    host_profile: HostCapabilityProfile,
    conformance_report: ProviderConformanceReport,
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
        let manifest = SandboxProviderManifest::from_canonical_cbor(inputs.provider_manifest)?;
        let syscall_set = SandboxSyscallSet::from_canonical_cbor(inputs.syscall_set)?;
        let host_profile = HostCapabilityProfile::from_canonical_cbor(inputs.host_profile)?;
        let conformance_report =
            ProviderConformanceReport::from_canonical_cbor(inputs.conformance_report)?;
        let selection = policy.selection();

        if selection.provider_manifest != manifest.manifest_digest
            || selection.provider_binary != manifest.binary_digest
            || selection.conformance_profile != manifest.pcf1_digest
            || selection.conformance_report != conformance_report.report_digest
            || selection.syscall_set != syscall_set.syscall_set_digest
        {
            return Err(SandboxAdmissionError::PolicyMismatch);
        }
        if revocation.provider_revoked(&manifest.manifest_digest)
            || revocation.provider_revoked(&manifest.binary_digest)
        {
            return Err(SandboxAdmissionError::Revoked);
        }
        if digest_bytes(inputs.provider_binary) != manifest.binary_digest {
            return Err(SandboxAdmissionError::ArtifactMismatch);
        }
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

        let capability_digest = capability_set_digest(&manifest.capabilities)?;
        let feature_digest = required_feature_set_digest(inputs.required_features)?;
        if conformance_report.pcf1_digest != manifest.pcf1_digest
            || conformance_report.provider_binary_digest != manifest.binary_digest
            || conformance_report.public_contract_digest != manifest.public_contract_digest
            || conformance_report.capability_set_digest != capability_digest
            || conformance_report.required_hcp1_feature_set_digest != feature_digest
            || manifest.required_hcp1_feature_set_digest != feature_digest
            || conformance_report.tested_hcp1_digest != host_profile.profile_digest
        {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        if inputs.required_features.iter().any(|required| {
            !host_profile
                .feature_proofs
                .iter()
                .any(|proof| proof.feature_id == required.as_str() && proof.passed)
        }) {
            return Err(SandboxAdmissionError::HostCapabilityMismatch);
        }
        let architecture = syscall_set.architecture;
        if conformance_report.architecture != architecture
            || host_profile.architecture != architecture
            || manifest.architectures.binary_search(&architecture).is_err()
        {
            return Err(SandboxAdmissionError::ArchitectureMismatch);
        }

        Ok(Self {
            manifest,
            syscall_set,
            host_profile,
            conformance_report,
        })
    }

    /// Admit exact SIM1, root-image, and executable bytes for this provider.
    ///
    /// # Errors
    /// Rejects unselected or revoked image identities, incorrect image authority,
    /// certificate mappings, epochs, architecture, lengths, or byte digests.
    pub fn admit_image(
        &self,
        policy: &SandboxAdministratorPolicy,
        trust: &SandboxTrustSnapshot,
        revocation: &SandboxRevocationSnapshot,
        manifest_bytes: &[u8],
        root_image: &[u8],
        executable: &[u8],
    ) -> Result<SignedImageManifest, SandboxAdmissionError> {
        let image = SignedImageManifest::from_canonical_cbor(manifest_bytes)?;
        if !policy.accepts_image(&image.manifest_digest) {
            return Err(SandboxAdmissionError::PolicyMismatch);
        }
        if revocation.image_revoked(&image.manifest_digest)
            || revocation.image_revoked(&image.root_image_blake3_digest)
            || revocation.image_revoked(&image.executable_blake3_digest)
        {
            return Err(SandboxAdmissionError::Revoked);
        }
        if image.architecture != self.syscall_set.architecture {
            return Err(SandboxAdmissionError::ArchitectureMismatch);
        }
        if image.image_trust_epoch != trust.trust_epoch() {
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
        let certificate_matches = trust.certificates().iter().any(|certificate| {
            certificate.fingerprint == image.signing_certificate_sha256
                && certificate.keyring_serial == image.kernel_keyring_serial
                && certificate.epoch == image.image_trust_epoch
        });
        if !certificate_matches {
            return Err(SandboxAdmissionError::CertificateMismatch);
        }
        let image_key = revocation.active_key(
            trust,
            &image.image_project_key_id,
            SandboxTrustRole::ImageProject,
        )?;
        image.verify_signature(&image_key)?;
        Ok(image)
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
    if required_features.is_empty()
        || required_features.len() > 256
        || required_features
            .iter()
            .any(|feature| !valid_identifier(feature))
        || !required_features
            .windows(2)
            .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
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
