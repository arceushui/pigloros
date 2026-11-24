//! Installation wiring and reservation horizons of a community pass
//! (#560 A4c-3b; ADR-129 revisions 10 and 13, R10.4(3), R10.7 step 5c,
//! R13.2).
//!
//! The owner horizons are an installation input the composition root
//! supplies ([`CommunityOwnerHorizonsV1`]), never a runtime or caller value:
//! the recording owner's admitted horizon bounds the CDP1 recording horizon
//! at installation, and the other required owners' admitted evidence
//! horizon is the owner term of `H_g` and `H_r` at every Reserve.

use pos_core::community_lifecycle::{
    check_community_pass_installation_v1, CommunityDurableProfileV1,
    CommunityLifecycleErrorV1 as Error, CommunityPassInstallationV1, CommunityQuarantineKeyV1,
    COMMUNITY_DECISION_DEADLINE_MICROS_V1,
};
use pos_core::{Hash, TimelineId};

/// The largest positive trusted horizon, `i64::MAX` microseconds.
const MAXIMUM_HORIZON_MICROS: u64 = i64::MAX as u64;

/// The owners' admitted retention horizons, as installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityOwnerHorizonsV1 {
    /// The recording owner's admitted retention horizon for COH1 purpose 2
    /// `ReplayRecording` (R10.4(3)).
    pub recording_micros: u64,
    /// The earliest admitted evidence-retention horizon of every other
    /// required owner (R13.2(1)).
    pub evidence_micros: u64,
}

impl CommunityOwnerHorizonsV1 {
    fn validate(self) -> Result<(), Error> {
        if [self.recording_micros, self.evidence_micros]
            .iter()
            .any(|horizon| *horizon == 0 || *horizon > MAXIMUM_HORIZON_MICROS)
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(())
        }
    }
}

/// Check a CDP1 at installation: the recording horizon must not exceed the
/// recording owner's admitted horizon (R10.4(3)), and the minimum required
/// pass must fit (R10.4(5), R11.5(3), R13.3).
///
/// # Errors
/// Returns `InvalidBinding` for a zero or out-of-range owner horizon and for
/// a recording horizon above the owner's, then the errors of
/// [`check_community_pass_installation_v1`]. Any error rejects the CDP1.
pub fn install_community_pass_profile_v1(
    profile: &CommunityDurableProfileV1<'_>,
    state_limit_bytes: &[u64],
    owners: CommunityOwnerHorizonsV1,
) -> Result<CommunityPassInstallationV1, Error> {
    owners.validate()?;
    if profile.as_input().retention.recording_not_after_micros > owners.recording_micros {
        return Err(Error::InvalidBinding);
    }
    check_community_pass_installation_v1(profile, state_limit_bytes)
}

/// The horizons one Reserve fixes from its trusted sample (R13.2(1)).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityReservationHorizonsV1 {
    /// `H_g`: `min(generation_not_after, metadata_not_after, owners)`, the
    /// horizon of the records a selected State needs.
    pub generation_micros: u64,
    /// `H_r`: `min(reserve time + recovery window, H_g)`, the horizon of
    /// the outcome evidence; it equals the CPR1 `evidence_not_after`.
    pub outcome_micros: u64,
}

/// Compute `H_g` and `H_r` from the Reserve writer's trusted sample
/// `reserve_time_micros` (annex "Fixed retention choice", R13.2(1)).
///
/// # Errors
/// Returns `InvalidBinding` for an invalid owner horizon and
/// `BoundsExceeded` when the reserve time plus the recovery window
/// overflows the trusted horizon range; nothing runs before it.
pub fn community_reservation_horizons_v1(
    profile: &CommunityDurableProfileV1<'_>,
    owners: CommunityOwnerHorizonsV1,
    reserve_time_micros: u64,
) -> Result<CommunityReservationHorizonsV1, Error> {
    owners.validate()?;
    let retention = profile.as_input().retention;
    let window_end = reserve_time_micros
        .checked_add(retention.recovery_window_micros)
        .filter(|end| *end <= MAXIMUM_HORIZON_MICROS)
        .ok_or(Error::BoundsExceeded)?;
    let generation = retention
        .generation_not_after_micros
        .min(retention.metadata_not_after_micros)
        .min(owners.evidence_micros);
    Ok(CommunityReservationHorizonsV1 {
        generation_micros: generation,
        outcome_micros: window_end.min(generation),
    })
}

/// The reservation horizon bound the planner judges observation reuse by.
///
/// It is `min(t_r + 27 s + recovery window, generation_not_after)` (R10.7
/// step 5c). The Reserve writer re-checks with the exact horizon and gives
/// 6 on a mismatch.
#[must_use]
pub fn community_reuse_horizon_bound_v1(
    profile: &CommunityDurableProfileV1<'_>,
    reservation_sample_micros: u64,
) -> u64 {
    let retention = profile.as_input().retention;
    reservation_sample_micros
        .saturating_add(COMMUNITY_DECISION_DEADLINE_MICROS_V1)
        .saturating_add(retention.recovery_window_micros)
        .min(retention.generation_not_after_micros)
}

/// The CQK1 digest of every roster member of `profile`, due or not, in
/// roster order (R10.6): what the planner reads and the Reserve writer
/// re-reads from the quarantine index.
///
/// # Errors
/// Returns the CQK1 errors of a roster row.
pub fn community_roster_quarantine_keys_v1(
    profile: &CommunityDurableProfileV1<'_>,
    timeline: TimelineId,
) -> Result<Vec<Hash>, Error> {
    profile
        .as_input()
        .roster
        .iter()
        .map(|member| {
            CommunityQuarantineKeyV1::new(timeline, member.stable_entry(), member.implementation())
                .map(|key| key.digest())
        })
        .collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
