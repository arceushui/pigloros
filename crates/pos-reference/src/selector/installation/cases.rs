//! Installed CFB1/TPS1 case reconstruction for the root selector.

use std::io::{Read, Seek, SeekFrom};

use super::{authority::InstalledSelectorAuthority, InstallationObjectKind};
use crate::evaluator::{case_attempt, CaseAttempt};
use crate::evaluator_protocol::EvaluationRequest;
use crate::profile::Profile;
use crate::selector::SelectorBoundaryError;
use crate::signed_bundle::{preflight_signed_bundle_reader, verify_signed_bundle_reader};

/// A selector-only case reconstructed from retained installed authority.
///
/// Its fields are intentionally private: no evaluator or caller can construct
/// a substitute case from decoded CFB1/CPF1 values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedInstalledCase {
    attempt: CaseAttempt,
    fixture_contract_digest: [u8; 32],
    profile_digest: [u8; 32],
    bundle_digest: [u8; 32],
}

impl ResolvedInstalledCase {
    /// Exact attempt independently rebuilt from the installed verified closure.
    #[must_use]
    pub const fn attempt(&self) -> &CaseAttempt {
        &self.attempt
    }

    /// Verified `FixtureContract` binding selected by CPF1.
    #[must_use]
    pub const fn fixture_contract_digest(&self) -> [u8; 32] {
        self.fixture_contract_digest
    }

    /// Verified CPF1 identity.
    #[must_use]
    pub const fn profile_digest(&self) -> [u8; 32] {
        self.profile_digest
    }

    /// Exact complete installed CFB1 digest.
    #[must_use]
    pub const fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }
}

impl InstalledSelectorAuthority {
    /// Resolve one canonical selected fixture from independently installed CFB1 and TPS1.
    ///
    /// The EVR1 digests select both retained files. CFB1 is preflighted and
    /// bound to authenticated CPF1 hard caps before full closure allocation;
    /// TPS1 is independently selected from the installation, never from an
    /// evaluator-provided archive member.
    ///
    /// # Errors
    /// Rejects absent installed artifacts, swapped identities, invalid CFB1 or
    /// TPS1 signatures/profiles, unsupported ordinals/modes/adapters, and any
    /// request binding that disagrees with the verified closure.
    pub fn resolve_installed_case(
        &self,
        request: &EvaluationRequest,
        ordinal: u16,
    ) -> Result<ResolvedInstalledCase, SelectorBoundaryError> {
        let bundle = self.installed().artifact(
            InstallationObjectKind::from_code(14)
                .or(Err(SelectorBoundaryError::ArtifactInvalid))?,
            request.fixture_bundle_digest,
        )?;
        let policy = self.installed().artifact(
            InstallationObjectKind::from_code(15)
                .or(Err(SelectorBoundaryError::ArtifactInvalid))?,
            request.trust_policy_snapshot_digest,
        )?;
        let policy_bytes = bounded_bytes(policy, 16 * 1024 * 1024)?;
        let mut archive = bundle.file.try_clone().or(Err(SelectorBoundaryError::Io))?;
        archive
            .seek(SeekFrom::Start(0))
            .or(Err(SelectorBoundaryError::Io))?;
        let preflight = preflight_signed_bundle_reader(&mut archive, &policy_bytes, request)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        let hard_caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), request)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        preflight
            .enforce_selected_caps(hard_caps.into())
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        let verified = verify_signed_bundle_reader(&mut archive, &policy_bytes, request)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        let profile = Profile::from_bundle(&verified, request)
            .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        let fixture = profile
            .selected_fixtures(request)
            .into_iter()
            .nth(usize::from(ordinal))
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        if !fixture.modes.contains(&verified.mode) {
            return Err(SelectorBoundaryError::ArtifactInvalid);
        }
        let attempt = case_attempt(
            &verified,
            fixture,
            verified.mode,
            profile.evaluator_hard_caps,
        )
        .or(Err(SelectorBoundaryError::ArtifactInvalid))?;
        Ok(ResolvedInstalledCase {
            attempt,
            fixture_contract_digest: profile.fixture_contract_digest(),
            profile_digest: profile.profile_digest,
            bundle_digest: verified.archive_digest,
        })
    }
}

fn bounded_bytes(
    artifact: &crate::selector::ImmutableSandboxArtifact,
    limit: u64,
) -> Result<Vec<u8>, SelectorBoundaryError> {
    if artifact.length() > limit {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    let mut file = artifact
        .file
        .try_clone()
        .or(Err(SelectorBoundaryError::Io))?;
    file.seek(SeekFrom::Start(0))
        .or(Err(SelectorBoundaryError::Io))?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(artifact.length()).or(Err(SelectorBoundaryError::ArtifactInvalid))?,
    );
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .or(Err(SelectorBoundaryError::Io))?;
    if bytes.len() as u64 != artifact.length() {
        return Err(SelectorBoundaryError::ArtifactInvalid);
    }
    Ok(bytes)
}
