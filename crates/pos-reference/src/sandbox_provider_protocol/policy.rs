//! Administrator-signed selection of exact provider and admission artifacts.

use super::codec::{
    bounded_array, decode_document, digest32, key_id, require_canonical_order, signed, uint,
    verify_digest, verify_signature,
};
use super::{SandboxRevocationSnapshot, SandboxTrustError, SandboxTrustRole, SandboxTrustSnapshot};

/// Exact immutable artifacts selected by an authenticated APT1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPolicySelection {
    /// Selected SPM1 self-digest.
    pub provider_manifest: [u8; 32],
    /// Exact provider executable digest.
    pub provider_binary: [u8; 32],
    /// Independently installed provider hard caps.
    pub broker_hard_caps: [u8; 32],
    /// Required PCF1 conformance profile.
    pub conformance_profile: [u8; 32],
    /// Independently signed PCR1 report.
    pub conformance_report: [u8; 32],
    /// Exact architecture-qualified SCS1 policy.
    pub syscall_set: [u8; 32],
}

/// APT1 verified against its exact TRS1 and RVS1 snapshots.
///
/// This record authorizes artifact identities. Actual artifact verification,
/// architecture agreement and host admission remain separate requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxAdministratorPolicy {
    policy_epoch: u64,
    selection: SandboxPolicySelection,
    accepted_launch_policies: Vec<[u8; 32]>,
    accepted_images: Vec<[u8; 32]>,
    policy_digest: [u8; 32],
}

impl SandboxAdministratorPolicy {
    /// Authenticate an APT1 and its exact trust/revocation authority bindings.
    ///
    /// # Errors
    /// Rejects malformed records, invalid or revoked policy signers, mismatched
    /// snapshot digests/epochs, and an explicitly revoked selected provider.
    pub fn authenticate(
        bytes: &[u8],
        trust: &SandboxTrustSnapshot,
        revocation: &SandboxRevocationSnapshot,
    ) -> Result<Self, SandboxTrustError> {
        let (policy, _) = Self::authenticate_record(bytes, trust, revocation)?;
        if revocation.provider_revoked(&policy.selection.provider_manifest)
            || revocation.provider_revoked(&policy.selection.provider_binary)
        {
            return Err(SandboxTrustError::Revoked);
        }
        Ok(policy)
    }

    /// Validate a signed, strictly revocation-only APT1 successor.
    ///
    /// Unlike execution admission, this accepts revoking the selected provider.
    /// It returns no policy or execution authority under that revoked state.
    ///
    /// # Errors
    /// Rejects forged or unbound policies, non-successor revocation epochs,
    /// changed selection, non-increasing policy epochs, and unauthorized signer rotation.
    pub fn validate_revocation_successor(
        previous_bytes: &[u8],
        next_bytes: &[u8],
        trust: &SandboxTrustSnapshot,
        previous_revocation: &SandboxRevocationSnapshot,
        next_revocation: &SandboxRevocationSnapshot,
    ) -> Result<(), SandboxTrustError> {
        previous_revocation.validate_immediate_epoch_for_same_registry(next_revocation)?;
        let (previous, previous_signer) =
            Self::authenticate_record(previous_bytes, trust, previous_revocation)?;
        let (next, next_signer) = Self::authenticate_record(next_bytes, trust, next_revocation)?;
        if next.policy_epoch <= previous.policy_epoch
            || next.selection != previous.selection
            || next.accepted_launch_policies != previous.accepted_launch_policies
            || next.accepted_images != previous.accepted_images
        {
            return Err(SandboxTrustError::AuthorityMismatch);
        }
        previous_revocation.active_key(
            trust,
            &next_signer,
            SandboxTrustRole::AdministratorPolicy,
        )?;
        if previous_signer != next_signer
            && next_revocation.active_key(
                trust,
                &previous_signer,
                SandboxTrustRole::AdministratorPolicy,
            ) != Err(SandboxTrustError::Revoked)
        {
            return Err(SandboxTrustError::AuthorityMismatch);
        }
        Ok(())
    }

    fn authenticate_record(
        bytes: &[u8],
        trust: &SandboxTrustSnapshot,
        revocation: &SandboxRevocationSnapshot,
    ) -> Result<(Self, String), SandboxTrustError> {
        let document = decode_document(bytes)?;
        let (fields, policy_digest, signature) = signed::<16>(&document, "APT1")?;
        let policy_epoch = uint(&fields[2])?;
        let selection = SandboxPolicySelection {
            provider_manifest: digest32(&fields[3])?,
            provider_binary: digest32(&fields[4])?,
            broker_hard_caps: digest32(&fields[7])?,
            conformance_profile: digest32(&fields[8])?,
            conformance_report: digest32(&fields[9])?,
            syscall_set: digest32(&fields[14])?,
        };
        let policies = bounded_array(&fields[5], 0)?;
        let images = bounded_array(&fields[6], 0)?;
        let accepted_launch_policies = policies
            .iter()
            .map(digest32)
            .collect::<Result<Vec<_>, _>>()?;
        let accepted_images = images.iter().map(digest32).collect::<Result<Vec<_>, _>>()?;
        let trust_digest = digest32(&fields[10])?;
        let revocation_digest = digest32(&fields[11])?;
        let trust_epoch = uint(&fields[12])?;
        let revocation_epoch = uint(&fields[13])?;
        let signer = key_id(&fields[15])?;
        require_canonical_order(policies)?;
        require_canonical_order(images)?;
        verify_digest("APT1", fields, policy_digest)?;
        let key = revocation.active_key(trust, &signer, SandboxTrustRole::AdministratorPolicy)?;
        verify_signature("APT1", &policy_digest, &signature, &key)?;
        if trust_digest != trust.snapshot_digest()
            || revocation_digest != revocation.snapshot_digest()
            || trust_epoch != trust.trust_epoch()
            || revocation_epoch != revocation.revocation_epoch()
        {
            return Err(SandboxTrustError::AuthorityMismatch);
        }
        Ok((
            Self {
                policy_epoch,
                selection,
                accepted_launch_policies,
                accepted_images,
                policy_digest,
            },
            signer,
        ))
    }

    /// Administrator policy epoch, independent of trust and revocation epochs.
    #[must_use]
    pub const fn policy_epoch(&self) -> u64 {
        self.policy_epoch
    }

    /// Exact APT1 self-digest.
    #[must_use]
    pub const fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// Immutable selected artifact identities.
    #[must_use]
    pub const fn selection(&self) -> &SandboxPolicySelection {
        &self.selection
    }

    /// Whether this APT1 authorizes an exact LPS1 digest.
    #[must_use]
    pub fn accepts_launch_policy(&self, digest: &[u8; 32]) -> bool {
        self.accepted_launch_policies.binary_search(digest).is_ok()
    }

    /// Whether this APT1 authorizes an exact SIM1 digest.
    ///
    /// Current revocation and image-byte verification must still pass.
    #[must_use]
    pub fn accepts_image(&self, digest: &[u8; 32]) -> bool {
        self.accepted_images.binary_search(digest).is_ok()
    }
}
