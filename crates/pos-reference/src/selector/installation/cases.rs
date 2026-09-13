//! Descriptor-held CFB1/TPS1 case reconstruction for root-selector composition.

use std::fs::File;
use std::io::{Seek, SeekFrom};

use super::{
    authority::AuthenticatedSelectorBootstrap, InstallationObjectKind, ResolvedInstalledCase,
    MANIFEST_LIMIT,
};
use crate::evaluator::{case_attempt, selector_bounded_hard_caps};
use crate::evaluator_protocol::EvaluationRequest;
use crate::profile::Profile;
use crate::selector::SelectorBoundaryError;
use crate::signed_bundle::{preflight_signed_bundle_reader, verify_signed_bundle_reader};

const CFB1_OBJECT: InstallationObjectKind = InstallationObjectKind(14);
const TPS1_OBJECT: InstallationObjectKind = InstallationObjectKind(15);

fn artifact_invalid<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::ArtifactInvalid
}

fn io_error<T>(_: T) -> SelectorBoundaryError {
    SelectorBoundaryError::Io
}

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
        self.retained_case_descriptors(request)
            .and_then(|(mut archive, policy_bytes)| {
                preflight_signed_bundle_reader(&mut archive, &policy_bytes, request)
                    .map_err(artifact_invalid)
                    .map(|preflight| (archive, policy_bytes, preflight))
            })
            .and_then(|(archive, policy_bytes, preflight)| {
                Profile::authenticated_hard_caps(preflight.profile_bytes(), request)
                    .map_err(artifact_invalid)
                    .map(|hard_caps| (archive, policy_bytes, preflight, hard_caps))
            })
            .and_then(|(archive, policy_bytes, preflight, hard_caps)| {
                preflight
                    .enforce_selected_caps(hard_caps.into())
                    .map_err(artifact_invalid)
                    .map(|()| (archive, policy_bytes, hard_caps))
            })
            .and_then(|(mut archive, policy_bytes, hard_caps)| {
                verify_signed_bundle_reader(&mut archive, &policy_bytes, request)
                    .map_err(artifact_invalid)
                    .map(|verified| (verified, hard_caps))
            })
            .and_then(|(verified, hard_caps)| {
                Profile::from_bundle(&verified, request)
                    .map_err(artifact_invalid)
                    .map(|profile| (verified, hard_caps, profile))
            })
            .and_then(|(verified, hard_caps, profile)| {
                profile
                    .selected_fixtures(request)
                    .into_iter()
                    .nth(usize::from(ordinal))
                    .filter(|fixture| fixture.modes.contains(&verified.mode))
                    .cloned()
                    .ok_or(SelectorBoundaryError::ArtifactInvalid)
                    .map(|fixture| (verified, hard_caps, profile, fixture))
            })
            .and_then(|(verified, hard_caps, profile, fixture)| {
                case_attempt(
                    &verified,
                    &fixture,
                    verified.mode,
                    selector_bounded_hard_caps(hard_caps, request),
                )
                .map_err(artifact_invalid)
                .map(|attempt| ResolvedInstalledCase {
                    attempt,
                    fixture_contract_digest: profile.fixture_contract_digest(),
                    profile_digest: profile.profile_digest,
                    bundle_digest: verified.archive_digest,
                })
            })
    }

    fn retained_case_descriptors(
        &self,
        request: &EvaluationRequest,
    ) -> Result<(File, Vec<u8>), SelectorBoundaryError> {
        let installed = self.installed();
        installed
            .artifact(CFB1_OBJECT, request.fixture_bundle_digest)
            .and_then(|bundle| {
                installed
                    .artifact(TPS1_OBJECT, request.trust_policy_snapshot_digest)
                    .map(|policy| (bundle, policy))
            })
            .and_then(|(bundle, policy)| {
                policy
                    .read_control(MANIFEST_LIMIT)
                    .map(|policy_bytes| (bundle, policy_bytes))
            })
            .and_then(|(bundle, policy_bytes)| {
                bundle
                    .file()
                    .try_clone()
                    .map_err(io_error)
                    .map(|archive| (archive, policy_bytes))
            })
            .and_then(|(mut archive, policy_bytes)| {
                archive
                    .seek(SeekFrom::Start(0))
                    .map_err(io_error)
                    .map(|_| (archive, policy_bytes))
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn error_mappers_preserve_the_closed_failure_class() {
        assert_eq!(artifact_invalid(()), SelectorBoundaryError::ArtifactInvalid);
        assert_eq!(io_error(()), SelectorBoundaryError::Io);
    }
}
