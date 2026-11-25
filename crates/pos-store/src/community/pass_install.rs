//! Installation wiring and reservation horizons of a community pass
//! (#560 A4c-3b; ADR-129 revisions 10, 13 and 15, R10.4(3), R10.7 step 5c,
//! R13.2, R15.8).
//!
//! The owner horizons are an installation input the composition root
//! supplies ([`CommunityOwnerHorizonsV1`]), never a runtime or caller value.
//! Installation refuses a CDP1 whose recording or metadata deadline exceeds
//! its owner's admitted horizon (3); generation is not refused but clamped:
//! every Reserve recomputes `H_g` from the installed generation, metadata
//! and owner evidence horizons (R15.8(2)). One call,
//! [`MemoryCommunityDomainV1::install_pass_horizons`], installs the CDP1 and
//! its owner horizons together, after the minimum-pass check.

use pos_core::community_lifecycle::{
    check_community_pass_installation_v1, CommunityDurableProfileV1,
    CommunityLifecycleErrorV1 as Error, CommunityPassInstallationV1, CommunityProfileRetentionV1,
    CommunityQuarantineKeyV1,
};
use pos_core::{Hash, TimelineId};

use super::pass_planner::decision_bound;

/// The largest positive trusted horizon, `i64::MAX` microseconds.
const MAXIMUM_HORIZON_MICROS: u64 = i64::MAX as u64;

/// The owners' admitted retention horizons, as installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommunityOwnerHorizonsV1 {
    /// The recording owner's admitted retention horizon for COH1 purpose 2
    /// `ReplayRecording` (R10.4(3)).
    pub recording_micros: u64,
    /// The metadata owner's admitted horizon (R15.8).
    pub metadata_micros: u64,
    /// The earliest admitted evidence-retention horizon of every other
    /// required owner (R13.2(1)).
    pub evidence_micros: u64,
}

impl CommunityOwnerHorizonsV1 {
    fn validate(self) -> Result<(), Error> {
        if [
            self.recording_micros,
            self.metadata_micros,
            self.evidence_micros,
        ]
        .iter()
        .any(|horizon| *horizon == 0 || *horizon > MAXIMUM_HORIZON_MICROS)
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(())
        }
    }

    /// The owner horizons are valid and the CDP1's recording and metadata
    /// deadlines do not exceed them (R10.4(3), R15.8(2)).
    fn admit(self, retention: CommunityProfileRetentionV1) -> Result<(), Error> {
        self.validate()?;
        if retention.recording_not_after_micros > self.recording_micros
            || retention.metadata_not_after_micros > self.metadata_micros
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(())
        }
    }
}

/// Check a CDP1 against its owner horizons and its minimum pass at installation.
///
/// The recording and metadata deadlines must not exceed their owners'
/// admitted horizons (R10.4(3), R15.8), and the minimum required pass must
/// fit (R10.4(5), R11.5(3), R13.3). Generation is clamped through `H_g` at
/// every Reserve instead.
///
/// # Errors
/// Returns `InvalidBinding` for a zero or out-of-range owner horizon and for
/// a recording or metadata horizon above the owner's, then the errors of
/// [`check_community_pass_installation_v1`]. Any error rejects the CDP1.
pub fn install_community_pass_profile_v1(
    profile: &CommunityDurableProfileV1<'_>,
    state_limit_bytes: &[u64],
    owners: CommunityOwnerHorizonsV1,
) -> Result<CommunityPassInstallationV1, Error> {
    owners.admit(profile.as_input().retention)?;
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

/// `H_g` and `H_r` for a trusted sample (annex "Fixed retention choice",
/// R13.2(1)). Saturating, so it cannot fail; an end past the trusted range
/// is then a plain horizon the later checks compare.
pub(super) fn reservation_horizons(
    retention: CommunityProfileRetentionV1,
    owners: CommunityOwnerHorizonsV1,
    reserve_time_micros: u64,
) -> CommunityReservationHorizonsV1 {
    let generation = retention
        .generation_not_after_micros
        .min(retention.metadata_not_after_micros)
        .min(owners.evidence_micros);
    CommunityReservationHorizonsV1 {
        generation_micros: generation,
        outcome_micros: reserve_time_micros
            .saturating_add(retention.recovery_window_micros)
            .min(generation),
    }
}

/// The installed horizon inputs the Reserve writer computes `H_g` and `H_r`
/// from, with its own trusted sample (R13.4(2)).
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(super) struct CommunityHorizonPolicyV1 {
    pub(super) retention: CommunityProfileRetentionV1,
    pub(super) owners: CommunityOwnerHorizonsV1,
    /// `H(CDP1)` of the installed profile: every Reserve request binds it.
    pub(super) profile_digest: Hash,
}

#[cfg(target_os = "linux")]
impl super::memory_domain::MemoryCommunityDomainV1 {
    /// Install a CDP1 and its owner horizons for the Reserve writer.
    ///
    /// It runs [`install_community_pass_profile_v1`] first, so the minimum
    /// pass and the recording and metadata owner horizons are checked, and
    /// only then installs what every Reserve recomputes `H_g` and `H_r`
    /// from (R13.4(2), R15.8). A reinstallation is quiescent (R15.8(3)): it
    /// is refused while any pass is unresolved.
    ///
    /// # Errors
    /// Returns `PassUnresolved` (7) while a pass is unresolved, then the
    /// errors of [`install_community_pass_profile_v1`]; nothing is
    /// installed on a refusal.
    pub fn install_pass_horizons(
        &mut self,
        _seal: &'static pos_core::AuthorityTrustRootSealV1,
        profile: &CommunityDurableProfileV1<'_>,
        state_limit_bytes: &[u64],
        owners: CommunityOwnerHorizonsV1,
    ) -> Result<CommunityPassInstallationV1, Error> {
        if self
            .pass_records
            .values()
            .any(|record| record.status.unresolved())
        {
            return Err(Error::PassUnresolved);
        }
        install_community_pass_profile_v1(profile, state_limit_bytes, owners).inspect(|_| {
            self.pass_horizons = Some(CommunityHorizonPolicyV1 {
                retention: profile.as_input().retention,
                owners,
                profile_digest: profile.digest(),
            });
        })
    }
}

/// Compute `H_g` and `H_r` from a trusted sample `reserve_time_micros`
/// (annex "Fixed retention choice", R13.2(1)).
///
/// The writer computes the same values from its own sample (R13.4(2)) and
/// refuses a record that differs.
///
/// # Errors
/// Returns `InvalidBinding` for an invalid owner horizon.
pub fn community_reservation_horizons_v1(
    profile: &CommunityDurableProfileV1<'_>,
    owners: CommunityOwnerHorizonsV1,
    reserve_time_micros: u64,
) -> Result<CommunityReservationHorizonsV1, Error> {
    owners
        .validate()
        .map(|()| reservation_horizons(profile.as_input().retention, owners, reserve_time_micros))
}

/// The reservation horizon bound the planner judges observation reuse by.
///
/// It is `min(t_r + 27 s + recovery window, generation_not_after)` (R10.7
/// step 5c), a conservative upper bound of the exact `H_r`: it ignores the
/// metadata and owner terms. The Reserve writer re-checks with the exact
/// horizon and gives 6 on a mismatch. No production caller exists yet.
#[must_use]
pub fn community_reuse_horizon_bound_v1(
    profile: &CommunityDurableProfileV1<'_>,
    reservation_sample_micros: u64,
) -> u64 {
    let retention = profile.as_input().retention;
    decision_bound(reservation_sample_micros)
        .saturating_add(retention.recovery_window_micros)
        .min(retention.generation_not_after_micros)
}

/// The CQK1 digest of every roster member, due or not, in roster order
/// (R10.6): what the planner reads and the Reserve writer re-reads from the
/// quarantine index.
pub(super) fn roster_quarantine_keys<'a>(
    profile: &'a CommunityDurableProfileV1<'_>,
    timeline: TimelineId,
) -> impl Iterator<Item = Result<Hash, Error>> + 'a {
    profile.as_input().roster.iter().map(move |member| {
        CommunityQuarantineKeyV1::new(timeline, member.stable_entry(), member.implementation())
            .map(|key| key.digest())
    })
}

/// The CQK1 digest of every roster member of `profile`, in roster order.
///
/// # Errors
/// Returns the CQK1 errors of a roster row.
pub fn community_roster_quarantine_keys_v1(
    profile: &CommunityDurableProfileV1<'_>,
    timeline: TimelineId,
) -> Result<Vec<Hash>, Error> {
    roster_quarantine_keys(profile, timeline).collect()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
