use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::trusted_clock::{
    open_release_guard, reserve_trusted_clock, ApplicableExpiriesV1, ExpiryPremisesV1,
    ReleaseGuardV1, StagedArtifactBytesV1, StagedProtectedOutputV1, SystemGuardMonotonicSourceV1,
    SystemTrustedWallSourceV1, TrustedClockErrorV1, TrustedWallSourceV1, WaitBudgetV1,
};
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1, Hash,
    PrincipalRefV1, TimelineId, WallTime,
};
use pos_store::trusted_clock::MemoryTrustedClockAuthorityV1;
use std::fmt::Debug;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DAY: u64 = 86_400_000_000;

fn ok<T, Error: Debug>(value: Result<T, Error>) -> T {
    value.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!(
            "unexpected runtime trusted-clock error: {error:?}"
        )))
    })
}

fn far_future() -> u64 {
    ok(SystemTrustedWallSourceV1.sample()).as_micros() + 1_000 * DAY
}

fn lease(deadline: u64) -> WorldRetentionLeaseV1 {
    let policy = ok(WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
        policy_revision: 1,
        purpose: "world".to_owned(),
        audience_policy_hash: Hash::from_bytes([7; 32]),
        minimum_post_admission_days: 90,
        maximum_active_days: 30,
        maximum_total_days: 120,
    }));
    let input = WorldRetentionLeaseInputV1 {
        timeline_id: TimelineId::new(),
        policy_hash: policy.digest(),
        started_at_micros: deadline - 120 * DAY,
        admission_closes_at_micros: deadline - 90 * DAY,
        retention_deadline_micros: deadline,
    };
    ok(WorldRetentionLeaseV1::new(&policy, input))
}

fn authenticated(expires_at: u64) -> AuthenticatedPrincipalResultV1 {
    let draft = AuthenticatedPrincipalDraftV1 {
        principal: ok(PrincipalRefV1::try_new([1; 16], "operators")),
        adapter_id: "test-passkey".to_owned(),
        assurance: ok(AssuranceLevelV1::try_new(2)),
        issued_at: WallTime::from_micros(1),
        expires_at: WallTime::from_micros(expires_at),
        binding_digest: Hash::from_bytes([7; 32]),
    };
    ok(AuthenticatedPrincipalResultV1::try_from_draft(draft))
}

fn guarded(
    port: &mut MemoryTrustedClockAuthorityV1,
) -> Result<(ReleaseGuardV1<'_>, ApplicableExpiriesV1), TrustedClockErrorV1> {
    let far = far_future();
    let mut store = port.handle();
    let mut wall = SystemTrustedWallSourceV1;
    let mut mono = SystemGuardMonotonicSourceV1;
    let mut wait = WaitBudgetV1::new();
    let reservation = reserve_trusted_clock(&mut store, &mut wall, &mut mono, &mut wait, None)?;
    let guard = open_release_guard(port, reservation, &mut wait, &mut mono)?;
    let leases = [lease(far)];
    let access = authenticated(far);
    let premises = ExpiryPremisesV1 {
        retention_leases: &leases,
        consent_grants: &[],
        consent_references: &[],
        access: Some(&access),
    };
    let expiries = guard.applicable_expiries(&premises)?;
    Ok((guard, expiries))
}

fn staged() -> StagedProtectedOutputV1<StagedArtifactBytesV1> {
    StagedProtectedOutputV1::stage(StagedArtifactBytesV1::new(vec![5, 5]))
}

#[test]
fn runtime_handoff_releases_through_the_checked_minter() -> TestResult {
    let mut port = MemoryTrustedClockAuthorityV1::new();
    let (guard, expiries) = guarded(&mut port)?;
    let released = pos_runtime::handoff(guard, &expiries, staged())?;
    assert_eq!(released.value(), &vec![5, 5]);
    assert_eq!(released.overrun_signal(), None);
    Ok(())
}

#[test]
fn runtime_handoff_keeps_the_final_checks() -> TestResult {
    let mut first = MemoryTrustedClockAuthorityV1::new();
    let mut other = MemoryTrustedClockAuthorityV1::new();
    let (other_guard, other_expiries) = guarded(&mut other)?;
    drop(other_guard);
    let (guard, _expiries) = guarded(&mut first)?;
    let refused = pos_runtime::handoff(guard, &other_expiries, staged());
    assert_eq!(refused.err(), Some(TrustedClockErrorV1::AuthorityRegressed));
    Ok(())
}
