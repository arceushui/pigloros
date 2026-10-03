//! Host entry point for the ADR-112 protected-use handoff.

use pos_core::trusted_clock::{
    handoff_checked, ApplicableExpiriesV1, AuthorizedArtifactUseV1, ProtectedHandoffTargetV1,
    ReleaseGuardV1, StagedProtectedOutputV1, SystemGuardMonotonicSourceV1,
    SystemTrustedWallSourceV1, TrustedClockErrorV1,
};

/// Hand a staged protected value over with the host's production trusted
/// sources.
///
/// This wrapper cannot mint a handoff token. It only delegates to
/// [`pos_core::trusted_clock::handoff_checked`], which runs the final in-guard
/// checks, the move, the post-handoff overrun check and the guard release.
/// After it returns, the host commits any pending overrun latch with
/// [`pos_core::trusted_clock::commit_pending_overrun_latch`].
///
/// # Errors
/// Returns the fail-closed outcome of the final in-guard checks.
pub fn handoff<T: ProtectedHandoffTargetV1>(
    guard: ReleaseGuardV1<'_>,
    expiries: &ApplicableExpiriesV1,
    staged: StagedProtectedOutputV1<T>,
) -> Result<AuthorizedArtifactUseV1<T::Committed>, TrustedClockErrorV1> {
    handoff_checked(
        guard,
        expiries,
        staged,
        &mut SystemTrustedWallSourceV1,
        &mut SystemGuardMonotonicSourceV1,
    )
}
