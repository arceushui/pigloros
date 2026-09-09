//! Fail-closed provider and image admission for the root-owned selector.

use ciborium::value::Value;

use crate::evaluator_protocol::RequiredProviderCapability;

use super::codec::{
    array, bounded_array, bytes_value, decode_document, encode, identifier, key_id,
    require_canonical_order, require_signature, signed, text, text_value, uint, uint_value,
    valid_identifier, valid_key_id, verify_digest, verify_signature,
};
use super::{
    AdmissionAuthority, AdmissionGrant, ExecuteAuthority, LaunchPolicy, ProviderCapability,
    ReceiptAuthority, SandboxAdministratorPolicy, SandboxArchitecture, SandboxExecuteRequest,
    SandboxProviderManifest, SandboxProviderProtocolError, SandboxProviderReceipt,
    SandboxProviderResult, SandboxRevocationSnapshot, SandboxSyscallSet, SandboxTerminalOutcome,
    SandboxTrustError, SandboxTrustRole, SandboxTrustSnapshot, SelectorRevocationState,
    SignedImageManifest,
};

const CAPABILITY_SET_DOMAIN: &[u8] = b"PiglorOS.ProviderCapabilitySet.v1\0";
const REQUIRED_FEATURE_SET_DOMAIN: &[u8] = b"PiglorOS.RequiredHostFeatureSet.v1\0";
const REQUIRED_HCP1_FEATURE_IDS: [&str; 16] = [
    "cgroup-v2-cpu",
    "cgroup-v2-memory",
    "cgroup-v2-pids",
    "cgroup-kill",
    "managed-attempt-exec",
    "process-isolation-controls",
    "signed-root-image",
    "mount-namespace",
    "pid-namespace",
    "ipc-namespace",
    "uts-namespace",
    "user-namespace",
    "network-namespace",
    "nftables-atomic",
    "broker-lifecycle",
    "limit-observation",
];

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
            || self.feature_proofs.len() != REQUIRED_HCP1_FEATURE_IDS.len()
            || self.feature_proofs.iter().any(|proof| !proof.passed)
            || REQUIRED_HCP1_FEATURE_IDS.iter().any(|required| {
                !self
                    .feature_proofs
                    .iter()
                    .any(|proof| proof.feature_id == *required)
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

/// Selector-derived authority that an AGR1 must reproduce exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxGrantExpectations {
    /// Exact provider capability selected by EVR1.
    pub required_provider_capability: RequiredProviderCapability,
    /// Exact selector-derived ELM1 digest.
    pub effective_limits_digest: [u8; 32],
    /// Exact selector-derived readback-set digest.
    pub expected_readback_set_digest: [u8; 32],
}

/// Exact root-owned inputs used to establish one executable selector session.
#[derive(Clone, Debug)]
pub struct RootSelectorAdmissionInputs<'a> {
    /// Provider, conformance, host, and syscall artifacts selected by APT1.
    pub provider: SandboxProviderAdmissionInputs<'a>,
    /// Canonical signed SIM1 bytes.
    pub image_manifest: &'a [u8],
    /// Exact immutable root-image bytes selected by SIM1.
    pub root_image: &'a [u8],
    /// Exact immutable subject executable bytes selected by SIM1 and EVR1.
    pub executable: &'a [u8],
    /// EVR1 subject artifact digest that must identify `executable`.
    pub subject_artifact_digest: [u8; 32],
    /// Canonical selected LPS1 bytes.
    pub launch_policy: &'a [u8],
    /// Selector-derived capability and effective-limit bindings for AGR1.
    pub grant_expectations: SandboxGrantExpectations,
}

/// Root-selector authority after provider, image, launch, and host admission.
///
/// Keeping these values together prevents execution evidence from being
/// authenticated against independently selected or caller-substituted state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootSelectorAdmission {
    provider: AdmittedSandboxProvider,
    image: AdmittedSandboxImage,
    launch: LaunchPolicy,
    grant_expectations: SandboxGrantExpectations,
}

/// Complete provider lifecycle evidence released by root-selector admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSandboxExecution {
    grant: AdmissionGrant,
    receipt: SandboxProviderReceipt,
    result: SandboxProviderResult,
    audit: Vec<super::SandboxAuditRecord>,
}

impl AuthenticatedSandboxExecution {
    /// Authenticated admission grant for the selected attempt.
    #[must_use]
    pub const fn grant(&self) -> &AdmissionGrant {
        &self.grant
    }

    /// Authenticated terminal provider result.
    #[must_use]
    pub const fn result(&self) -> &SandboxProviderResult {
        &self.result
    }

    /// Authenticated receipt whose digest is the CNR1 provenance identity.
    #[must_use]
    pub const fn receipt(&self) -> &SandboxProviderReceipt {
        &self.receipt
    }

    /// Complete authenticated audit chain.
    #[must_use]
    pub fn audit(&self) -> &[super::SandboxAuditRecord] {
        &self.audit
    }

    /// Exact authenticated SPR1 self-digest for CNR1 case provenance.
    #[must_use]
    pub const fn provenance_digest(&self) -> [u8; 32] {
        self.receipt.receipt_digest
    }
}

impl RootSelectorAdmission {
    /// Establish one root-owned session from an exact, immutable authority set.
    ///
    /// # Errors
    /// Fails closed unless provider, image, executable, launch policy, trust,
    /// revocation, conformance, host, capability, and architecture bindings all
    /// identify the same selected execution authority.
    pub fn establish(
        policy: &SandboxAdministratorPolicy,
        trust: &SandboxTrustSnapshot,
        revocation: &SandboxRevocationSnapshot,
        inputs: RootSelectorAdmissionInputs<'_>,
    ) -> Result<Self, SandboxAdmissionError> {
        let provider = AdmittedSandboxProvider::admit(policy, trust, revocation, inputs.provider)?;
        let image = provider.admit_image(
            inputs.image_manifest,
            inputs.root_image,
            inputs.executable,
            inputs.subject_artifact_digest,
        )?;
        let launch = provider.admit_launch_policy(inputs.launch_policy, &image)?;
        Ok(Self {
            provider,
            image,
            launch,
            grant_expectations: inputs.grant_expectations,
        })
    }

    /// Authenticate the entire post-admission provider lifecycle atomically.
    ///
    /// # Errors
    /// Rejects any malformed, forged, substituted, incomplete, or
    /// inconsistently bound SPX1/AGR1/SPR1/SPY1/SAU1 evidence.
    pub fn authenticate_execution(
        &self,
        request: &SandboxExecuteRequest,
        grant_bytes: &[u8],
        receipt_bytes: &[u8],
        result_bytes: &[u8],
        audit_records: &[Vec<u8>],
    ) -> Result<AuthenticatedSandboxExecution, SandboxAdmissionError> {
        let grant = self.authenticate_grant(request, grant_bytes)?;
        self.authenticate_after_grant(request, grant, receipt_bytes, result_bytes, audit_records)
    }

    /// Authenticate AGR1 before consuming any post-admission evidence.
    ///
    /// # Errors
    /// Rejects a forged grant or any mismatch with the admitted selector session.
    pub fn authenticate_grant(
        &self,
        request: &SandboxExecuteRequest,
        grant_bytes: &[u8],
    ) -> Result<AdmissionGrant, SandboxAdmissionError> {
        self.provider.authenticate_grant(
            grant_bytes,
            request,
            &self.image,
            &self.launch,
            &self.grant_expectations,
        )
    }

    /// Authenticate SPR1, SPY1, and the complete SAU1 chain after AGR1.
    ///
    /// # Errors
    /// Rejects malformed, forged, substituted, incomplete, or inconsistent evidence.
    pub fn authenticate_after_grant(
        &self,
        request: &SandboxExecuteRequest,
        grant: AdmissionGrant,
        receipt_bytes: &[u8],
        result_bytes: &[u8],
        audit_records: &[Vec<u8>],
    ) -> Result<AuthenticatedSandboxExecution, SandboxAdmissionError> {
        let receipt = self.provider.authenticate_receipt(receipt_bytes, &grant)?;
        let result =
            self.provider
                .authenticate_terminal_result(result_bytes, request, &grant, &receipt)?;
        let audit = self
            .provider
            .authenticate_audit_chain(audit_records, &receipt, &result)?;
        Ok(AuthenticatedSandboxExecution {
            grant,
            receipt,
            result,
            audit,
        })
    }

    /// Authenticate a signed provider terminal emitted before AGR1 admission.
    ///
    /// # Errors
    /// Rejects post-admission outcomes, substituted identities, or a forged runtime signature.
    pub fn authenticate_pre_admission_result(
        &self,
        request: &SandboxExecuteRequest,
        result_bytes: &[u8],
    ) -> Result<SandboxProviderResult, SandboxAdmissionError> {
        let result = SandboxProviderResult::from_canonical_cbor(result_bytes)?;
        if result.runtime_attestation_key_id != self.provider.manifest.runtime_attestation_key_id
            || result.request_id != request.request.request_id
            || result.attempt_id != request.attempt_id
            || !matches!(
                result.outcome,
                SandboxTerminalOutcome::UnavailableBeforeAdmission
                    | SandboxTerminalOutcome::Rejected
            )
        {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        result.verify_signature(&self.provider.runtime_key)?;
        Ok(result)
    }

    /// Authenticate a signed provider error against the selected execution request.
    ///
    /// # Errors
    /// Rejects a foreign runtime key, forged signature, or any present substituted identity.
    pub fn authenticate_provider_error(
        &self,
        request: &SandboxExecuteRequest,
        error_bytes: &[u8],
    ) -> Result<super::SandboxProviderError, SandboxAdmissionError> {
        let error = super::SandboxProviderError::from_canonical_cbor(error_bytes)?;
        if error.runtime_attestation_key_id != self.provider.manifest.runtime_attestation_key_id
            || error.operation.is_some_and(|operation| operation != 1)
            || error
                .request_id
                .is_some_and(|request_id| request_id != request.request.request_id)
            || error
                .request_digest
                .is_some_and(|digest| digest != request.request_digest)
            || error
                .attempt_id
                .is_some_and(|attempt_id| attempt_id != request.attempt_id)
        {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        error.verify_signature(&self.provider.runtime_key)?;
        Ok(error)
    }

    /// Exact launch policy retained by this admitted selector session.
    #[must_use]
    pub const fn launch_policy(&self) -> &LaunchPolicy {
        &self.launch
    }

    /// Create revocation state bound to this admitted provider's authenticated
    /// runtime key, rather than to a key supplied at acknowledgement time.
    ///
    /// # Errors
    /// Fails if the retained runtime authority no longer resolves from the
    /// admitted trust and revocation snapshots.
    pub fn revocation_state(
        &self,
    ) -> Result<SelectorRevocationState, super::SandboxRevocationUpdateError> {
        SelectorRevocationState::new(
            self.provider.revocation.clone(),
            &self.provider.trust,
            self.provider.manifest.runtime_attestation_key_id.clone(),
        )
    }
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
            inputs.provider_binary,
            inputs.broker_hard_caps,
            &decoded,
        )?;
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
        })
    }

    fn validate_selected_provider(
        policy: &SandboxAdministratorPolicy,
        revocation: &SandboxRevocationSnapshot,
        provider_binary: &[u8],
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
        if digest_bytes(provider_binary) != manifest.binary_digest {
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
        if required_features.iter().any(|required| {
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
        subject_artifact_digest: [u8; 32],
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
        let image_length = root_image.len() as u64;
        if image.root_image_length != image_length
            || image.root_image_blake3_digest != digest_bytes(root_image)
            || image.executable_blake3_digest != digest_bytes(executable)
            || image.executable_blake3_digest != subject_artifact_digest
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
        expectations: &SandboxGrantExpectations,
    ) -> Result<AdmissionGrant, SandboxAdmissionError> {
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
            effective_limits: expectations.effective_limits_digest,
            readback_set: expectations.expected_readback_set_digest,
        };
        if actual != expected
            || !request
                .capability_ids
                .contains(&expectations.required_provider_capability.capability_id)
            || !self.supports_capabilities(&request.capability_ids)
            || !self.supports_required_capability(&expectations.required_provider_capability)
        {
            return Err(SandboxAdmissionError::ConformanceMismatch);
        }
        Ok(grant)
    }

    /// Authenticate an SPR1 and bind it to the admitted provider and AGR1.
    ///
    /// # Errors
    /// Rejects a forged receipt or any lifecycle authority substitution.
    pub fn authenticate_receipt(
        &self,
        bytes: &[u8],
        grant: &AdmissionGrant,
    ) -> Result<SandboxProviderReceipt, SandboxAdmissionError> {
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
        Ok(receipt)
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
        grant: &AdmissionGrant,
        receipt: &SandboxProviderReceipt,
    ) -> Result<SandboxProviderResult, SandboxAdmissionError> {
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
        Ok(result)
    }

    /// Authenticate the complete SAU1 chain referenced by SPR1 and mirrored by SPY1.
    ///
    /// # Errors
    /// Rejects forged, reordered, incomplete, substituted, or incorrectly bound events.
    pub fn authenticate_audit_chain(
        &self,
        records: &[Vec<u8>],
        receipt: &SandboxProviderReceipt,
        result: &SandboxProviderResult,
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
    fn supports_required_capability(&self, required: &RequiredProviderCapability) -> bool {
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
