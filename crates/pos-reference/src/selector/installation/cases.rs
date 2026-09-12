//! Descriptor-held CFB1/TPS1 case reconstruction for root-selector composition.

use std::fs::File;
use std::io::{Seek, SeekFrom};

use super::{
    authority::AuthenticatedSelectorBootstrap, InstallationObjectKind, ResolvedInstalledCase,
    MANIFEST_LIMIT,
};
use crate::evaluator::case_attempt;
use crate::evaluator_protocol::EvaluationRequest;
use crate::profile::Profile;
use crate::selector::SelectorBoundaryError;
use crate::signed_bundle::{preflight_signed_bundle_reader, verify_signed_bundle_reader};

const CFB1_OBJECT: InstallationObjectKind = InstallationObjectKind(14);
const TPS1_OBJECT: InstallationObjectKind = InstallationObjectKind(15);

impl AuthenticatedSelectorBootstrap {
    /// Resolves one EVR1-selected CFB1/TPS1 case from retained SIC1 descriptors.
    ///
    /// CFB1 is preflighted against CPF1-selected hard caps before full closure
    /// materialization. TPS1 comes only from the typed SIC1 index; it cannot be
    /// supplied in EVR1 or substituted from a CFB1 member.
    ///
    /// # Errors
    /// Returns a closed failure when either selected descriptor is absent or
    /// inconsistent, or the verified closure does not admit the requested
    /// ordinal, mode, or EVR1 binding.
    pub(crate) fn resolve_installed_case(
        &self,
        request: &EvaluationRequest,
        ordinal: u16,
    ) -> Result<ResolvedInstalledCase, SelectorBoundaryError> {
        let (mut archive, policy_bytes) = self.retained_case_descriptors(request)?;
        let preflight = preflight_signed_bundle_reader(&mut archive, &policy_bytes, request)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let hard_caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), request)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        preflight
            .enforce_selected_caps(hard_caps.into())
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let verified = verify_signed_bundle_reader(&mut archive, &policy_bytes, request)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let profile = Profile::from_bundle(&verified, request)
            .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        let fixture = profile
            .selected_fixtures(request)
            .into_iter()
            .nth(usize::from(ordinal))
            .filter(|fixture| fixture.modes.contains(&verified.mode))
            .ok_or(SelectorBoundaryError::ArtifactInvalid)?;
        let attempt = case_attempt(
            &verified,
            fixture,
            verified.mode,
            profile.evaluator_hard_caps,
        )
        .map_err(|_| SelectorBoundaryError::ArtifactInvalid)?;
        Ok(ResolvedInstalledCase {
            attempt,
            fixture_contract_digest: profile.fixture_contract_digest(),
            profile_digest: profile.profile_digest,
            bundle_digest: verified.archive_digest,
        })
    }

    fn retained_case_descriptors(
        &self,
        request: &EvaluationRequest,
    ) -> Result<(File, Vec<u8>), SelectorBoundaryError> {
        let installed = self.installed();
        let bundle = installed.artifact(CFB1_OBJECT, request.fixture_bundle_digest)?;
        let policy = installed.artifact(TPS1_OBJECT, request.trust_policy_snapshot_digest)?;
        let policy_bytes = policy.read_control(MANIFEST_LIMIT)?;
        let mut archive = bundle
            .file()
            .try_clone()
            .map_err(|_| SelectorBoundaryError::Io)?;
        archive
            .seek(SeekFrom::Start(0))
            .map_err(|_| SelectorBoundaryError::Io)?;
        Ok((archive, policy_bytes))
    }
}
