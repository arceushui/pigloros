#![cfg(feature = "test-support")]

use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::trusted_clock::TrustedClockErrorV1 as Fence;
use pos_core::trusted_clock::{
    acknowledge_trusted_clock_overrun, commit_pending_overrun_latch, handoff_checked,
    open_release_guard, principal_digest, reserve_trusted_clock, wall_time_from_epoch_duration,
    wall_time_from_system_time, AuthorizedArtifactUseV1, ExpiryPremisesV1, GuardMonotonicSourceV1,
    HostAdministrativeActionV1, HostAdministrativeAuthorizationV1, HostAuthorizationProvenanceV1,
    OverrunAckReasonV1, ScriptedGuardMonotonicSourceV1, ScriptedTrustedWallSourceV1,
    ScriptedWallSampleV1, StagedArtifactBytesV1, StagedProtectedOutputV1,
    SystemGuardMonotonicSourceV1, SystemTrustedWallSourceV1, TrustedClockHighWaterRowV1,
    TrustedClockOverrunAcknowledgementV1, TrustedClockOverrunKindV1, TrustedClockOverrunLatchRowV1,
    TrustedClockPortErrorV1, TrustedClockReservationV1, TrustedClockRowsV1,
    TrustedClockStorePortV1, TrustedWallSourceV1, WaitBudgetV1, WaitPhaseV1,
    PROTECTED_RELEASE_LATCHED_SIGNAL, TRUSTED_CLOCK_FENCE_OVERRUN_SIGNAL,
    TRUSTED_CLOCK_FORMAT_VERSION_V1, TRUSTED_CLOCK_GUARD_BUDGET, TRUSTED_CLOCK_MARGIN,
    TRUSTED_CLOCK_RESERVATION_WINDOW, TRUSTED_CLOCK_WAIT_BUDGET,
};
use pos_core::trusted_clock_fixture::{TrustedClockFixtureFaultV1 as Fault, TrustedClockFixtureV1};
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
    ConsentGrantRefDraftV1, ConsentGrantRefV1, ConsentGrantStatusV1, ConsentGrantedV1, EntityId,
    Hash, PrincipalRefV1, Seq, TimelineId, WallTime,
};
use std::fmt::Debug;
use std::time::{Duration, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Release = Result<AuthorizedArtifactUseV1<Vec<u8>>, Fence>;
type Reserved = Result<TrustedClockReservationV1, Fence>;

const SECOND: u64 = 1_000_000;
const DAY: u64 = 86_400 * SECOND;
const W: u64 = 32 * SECOND;
const T0: u64 = 1_800_000_000 * SECOND;
const E: u64 = T0 + 1_000 * SECOND;
const FAR: u64 = T0 + 1_000 * DAY;
const MAX_MICROS: u64 = i64::MAX.unsigned_abs();
const ZERO: Duration = Duration::ZERO;
const DURABILITY: Fence = Fence::DurabilityUnavailable;
const COMMIT_FAILED: Fence = Fence::ReservationCommitFailed;
const CORRUPT: Fence = Fence::HighWaterCorrupt;
const RESERVATION_WAIT: Fence = Fence::WaitBudgetExceeded(WaitPhaseV1::Reservation);
const GUARD_WAIT: Fence = Fence::WaitBudgetExceeded(WaitPhaseV1::Guard);

fn ok<T, Error: Debug>(value: Result<T, Error>) -> T {
    value.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!(
            "unexpected trusted-clock fixture error: {error:?}"
        )))
    })
}

const fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn micros(value: u64) -> i64 {
    ok(i64::try_from(value))
}

fn still() -> ScriptedGuardMonotonicSourceV1 {
    ScriptedGuardMonotonicSourceV1::new([ZERO])
}

fn mono_at(offsets: &[Duration]) -> ScriptedGuardMonotonicSourceV1 {
    ScriptedGuardMonotonicSourceV1::new(offsets.iter().copied())
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

fn principal(byte: u8) -> PrincipalRefV1 {
    ok(PrincipalRefV1::try_new([byte; 16], "operators"))
}

fn authenticated(byte: u8, expires_at: u64) -> AuthenticatedPrincipalResultV1 {
    let draft = AuthenticatedPrincipalDraftV1 {
        principal: principal(byte),
        adapter_id: "test-passkey".to_owned(),
        assurance: ok(AssuranceLevelV1::try_new(2)),
        issued_at: WallTime::from_micros(1),
        expires_at: WallTime::from_micros(expires_at),
        binding_digest: Hash::from_bytes([7; 32]),
    };
    ok(AuthenticatedPrincipalResultV1::try_from_draft(draft))
}

fn consent_reference(valid_until: u64) -> ConsentGrantRefV1 {
    ok(ConsentGrantRefV1::try_from_draft(ConsentGrantRefDraftV1 {
        consent_id: Hash::from_bytes([3; 32]),
        subject_id: EntityId::new(),
        grantee_id: EntityId::new(),
        data_categories: vec!["profile".to_owned()],
        purposes: vec!["care".to_owned()],
        audiences: vec!["local-host".to_owned()],
        action_classes: vec!["read".to_owned()],
        valid_from: WallTime::from_micros(1),
        valid_until: WallTime::from_micros(valid_until),
        withdrawal_retention_policy: "erase-derived-data".to_owned(),
        policy_revision: Hash::from_bytes([9; 32]),
        issuer: principal(4),
        issuer_evidence: Hash::from_bytes([6; 32]),
        consent_timeline: TimelineId::new(),
        grant_position: Seq::from_u64(5),
        status: ConsentGrantStatusV1::Active,
        revocation_fence: None,
        authority_registry_digest: Hash::from_bytes([8; 32]),
    }))
}

fn consent_grant(expiry_secs: u32) -> ConsentGrantedV1 {
    ConsentGrantedV1 {
        subject_id: EntityId::new(),
        grantee_id: EntityId::new(),
        purpose: "care".to_owned(),
        modalities: 1,
        min_geo_resolution: 0,
        fork_permitted: false,
        export_permitted: false,
        retention_days: 0,
        expiry_secs,
        grant_seq: 1,
    }
}

fn staged() -> StagedProtectedOutputV1<StagedArtifactBytesV1> {
    StagedProtectedOutputV1::stage(StagedArtifactBytesV1::new(vec![7, 7]))
}

fn authorization(byte: u8) -> HostAdministrativeAuthorizationV1 {
    HostAdministrativeAuthorizationV1::new(
        HostAdministrativeActionV1::AcknowledgeTrustedClockOverrun,
        principal(byte),
        Hash::from_bytes([5; 32]),
        HostAuthorizationProvenanceV1::from_digest([4; 32]),
    )
}

fn reserve_with(fixture: &TrustedClockFixtureV1, sample: ScriptedWallSampleV1) -> Reserved {
    let mut store = fixture.clone();
    let mut wall = ScriptedTrustedWallSourceV1::new([sample]);
    let mut wait = WaitBudgetV1::new();
    reserve_trusted_clock(&mut store, &mut wall, &mut still(), &mut wait, None)
}

fn reserve_at(fixture: &TrustedClockFixtureV1, at: u64) -> Reserved {
    let sample = ScriptedWallSampleV1::SinceEpoch(Duration::from_micros(at));
    reserve_with(fixture, sample)
}

fn reserve_on(
    fixture: &TrustedClockFixtureV1,
    at: u64,
    mono: &mut ScriptedGuardMonotonicSourceV1,
) -> Reserved {
    let mut store = fixture.clone();
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([at]);
    let mut wait = WaitBudgetV1::new();
    reserve_trusted_clock(&mut store, &mut wall, mono, &mut wait, None)
}

fn release_with(
    fixture: &TrustedClockFixtureV1,
    reservation: TrustedClockReservationV1,
    deadline: u64,
    samples: &[u64],
    mono: &mut ScriptedGuardMonotonicSourceV1,
) -> Release {
    let mut port = fixture.clone();
    let leases = [lease(deadline)];
    let access = authenticated(1, FAR);
    let premises = ExpiryPremisesV1 {
        retention_leases: &leases,
        consent_grants: &[],
        consent_references: &[],
        access: Some(&access),
    };
    let mut wait = WaitBudgetV1::new();
    let guard = open_release_guard(&mut port, reservation, &mut wait, mono)?;
    let expiries = guard.applicable_expiries(&premises)?;
    let mut wall = ScriptedTrustedWallSourceV1::from_micros(samples.iter().copied());
    handoff_checked(guard, &expiries, staged(), &mut wall, mono)
}

fn release(
    fixture: &TrustedClockFixtureV1,
    reservation: TrustedClockReservationV1,
    deadline: u64,
    final_sample: u64,
) -> Release {
    let samples = [final_sample, final_sample];
    release_with(fixture, reservation, deadline, &samples, &mut still())
}

fn reserve_and_release(at: u64, final_sample: u64, deadline: u64) -> Release {
    let fixture = TrustedClockFixtureV1::new();
    let reservation = reserve_at(&fixture, at)?;
    release(&fixture, reservation, deadline, final_sample)
}

fn high_water_row(fixture: &TrustedClockFixtureV1) -> TrustedClockHighWaterRowV1 {
    let rows = fixture.rows();
    ok(rows.high_water.first().cloned().ok_or("missing row"))
}

fn latch_row(fixture: &TrustedClockFixtureV1) -> TrustedClockOverrunLatchRowV1 {
    let rows = fixture.rows();
    ok(rows.overrun_latch.first().copied().ok_or("missing row"))
}

fn initialized(at: u64) -> TrustedClockFixtureV1 {
    let fixture = TrustedClockFixtureV1::new();
    let _reservation = ok(reserve_at(&fixture, at));
    fixture
}

fn with_rows(edit: impl FnOnce(&mut TrustedClockRowsV1)) -> TrustedClockFixtureV1 {
    let fixture = initialized(T0);
    let mut rows = fixture.rows();
    edit(&mut rows);
    fixture.set_rows(rows);
    fixture
}

fn overrun(fixture: &TrustedClockFixtureV1, post: Duration, post_sample: u64) -> Release {
    let mut mono = mono_at(&[ZERO; 5]);
    mono.push(post);
    let reservation = reserve_on(fixture, T0, &mut mono)?;
    release_with(fixture, reservation, FAR, &[T0, post_sample], &mut mono)
}

fn latched(fixture: &TrustedClockFixtureV1) -> TrustedClockFixtureV1 {
    let _released = ok(overrun(fixture, Duration::from_secs(33), T0));
    let committed = commit_pending_overrun_latch(&mut fixture.clone());
    assert_eq!(committed, Ok(true));
    fixture.clone()
}

fn acknowledge(
    fixture: &TrustedClockFixtureV1,
    operator: &AuthenticatedPrincipalResultV1,
    authorized: u8,
    expected_overrun_count: u64,
    at: u64,
) -> Result<(), Fence> {
    let authorization = authorization(authorized);
    let request = TrustedClockOverrunAcknowledgementV1 {
        operator,
        authorization: &authorization,
        expected_overrun_count,
        reason: OverrunAckReasonV1::SuspendOrVmPause,
    };
    let mut store = fixture.clone();
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([at]);
    acknowledge_trusted_clock_overrun(&mut store, &mut wall, &request)
}

// ---------------------------------------------------------------------------
// Sources, constants and values
// ---------------------------------------------------------------------------

#[test]
fn conversions_round_nanoseconds_up_and_reject_out_of_range_values() -> TestResult {
    let convert = wall_time_from_epoch_duration;
    let unavailable = Err(Fence::SourceUnavailable);
    assert_eq!(convert(Duration::from_nanos(1))?.as_micros(), 1);
    assert_eq!(convert(Duration::from_nanos(1_000))?.as_micros(), 1);
    assert_eq!(convert(Duration::from_nanos(1_001))?.as_micros(), 2);
    let maximum = convert(Duration::from_micros(MAX_MICROS))?;
    assert_eq!(maximum.as_micros(), MAX_MICROS);
    let beyond = Duration::from_micros(MAX_MICROS + 1);
    assert_eq!(convert(beyond), unavailable);
    assert_eq!(convert(Duration::MAX), unavailable);
    assert_eq!(wall_time_from_system_time(UNIX_EPOCH)?.as_micros(), 0);
    let before_epoch = UNIX_EPOCH
        .checked_sub(Duration::from_nanos(1))
        .ok_or("pre-epoch time")?;
    assert_eq!(wall_time_from_system_time(before_epoch), unavailable);
    assert!(SystemTrustedWallSourceV1.sample()?.as_micros() > 0);
    let mut system = SystemGuardMonotonicSourceV1;
    let first = system.mark();
    assert!(system.mark().checked_elapsed_since(first).is_some());
    Ok(())
}

#[test]
fn scripted_sources_replay_through_the_conversions() -> TestResult {
    let after_epoch = UNIX_EPOCH + Duration::from_micros(5);
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([3]);
    wall.push(ScriptedWallSampleV1::System(after_epoch));
    wall.push(ScriptedWallSampleV1::Unavailable);
    assert_eq!(wall.remaining(), 3);
    assert_eq!(wall.sample()?.as_micros(), 3);
    assert_eq!(wall.sample()?.as_micros(), 5);
    assert_eq!(wall.sample(), Err(Fence::SourceUnavailable));
    assert_eq!(wall.sample(), Err(Fence::SourceUnavailable));
    let mut mono = mono_at(&[Duration::from_secs(2)]);
    mono.push(Duration::from_secs(1));
    let later = mono.mark();
    let earlier = mono.mark();
    let elapsed = later.checked_elapsed_since(earlier);
    assert_eq!(elapsed, Some(Duration::from_secs(1)));
    assert_eq!(earlier.checked_elapsed_since(later), None);
    assert_eq!(mono.mark(), earlier);
    Ok(())
}

#[test]
fn constants_codes_and_values_are_stable() {
    let window = TRUSTED_CLOCK_GUARD_BUDGET + TRUSTED_CLOCK_MARGIN;
    assert_eq!(TRUSTED_CLOCK_RESERVATION_WINDOW, window);
    assert_eq!(TRUSTED_CLOCK_WAIT_BUDGET, ms(250));
    assert_eq!(TRUSTED_CLOCK_FORMAT_VERSION_V1, 1);
    let overrun = "trusted_clock_fence_overrun";
    assert_eq!(TRUSTED_CLOCK_FENCE_OVERRUN_SIGNAL, overrun);
    let latched = "protected_release_latched";
    assert_eq!(PROTECTED_RELEASE_LATCHED_SIGNAL, latched);
    let kinds = [
        TrustedClockOverrunKindV1::MonotonicBudgetExceeded,
        TrustedClockOverrunKindV1::WallBeyondDecisionBound,
        TrustedClockOverrunKindV1::MonotonicRegression,
    ];
    assert_eq!(kinds.map(TrustedClockOverrunKindV1::code), [1, 2, 3]);
    let reasons = [
        OverrunAckReasonV1::BenignStall,
        OverrunAckReasonV1::SuspendOrVmPause,
        OverrunAckReasonV1::OtherRecordedIncident,
    ];
    assert_eq!(reasons.map(OverrunAckReasonV1::code), [1, 2, 3]);
    let display = "trusted-clock fence unavailable: WaitBudgetExceeded(Guard)";
    assert_eq!(GUARD_WAIT.to_string(), display);
    let authorization = authorization(2);
    let action = HostAdministrativeActionV1::AcknowledgeTrustedClockOverrun;
    assert_eq!(authorization.action(), action);
    assert_eq!(authorization.principal(), &principal(2));
    assert_eq!(authorization.trust_revision(), Hash::from_bytes([5; 32]));
    assert_eq!(authorization.provenance().digest(), &[4; 32]);
    let digest = principal_digest(&principal(2));
    assert_eq!(digest, principal_digest(&principal(2)));
    assert_ne!(digest, principal_digest(&principal(3)));
}

#[test]
fn wait_budget_is_shared_across_phases() {
    let mut budget = WaitBudgetV1::default();
    assert_eq!(budget, WaitBudgetV1::new());
    assert_eq!(budget.remaining(), TRUSTED_CLOCK_WAIT_BUDGET);
    let owner = budget.charge(WaitPhaseV1::OwnerLocks, ms(200));
    assert_eq!(owner, Ok(()));
    assert_eq!(budget.remaining(), ms(50));
    let reservation = budget.charge(WaitPhaseV1::Reservation, ms(60));
    assert_eq!(reservation, Err(RESERVATION_WAIT));
    let guard = budget.charge(WaitPhaseV1::Guard, ms(50));
    assert_eq!(guard, Ok(()));
    assert_eq!(budget.remaining(), ZERO);
}

// ---------------------------------------------------------------------------
// Reservation and migration
// ---------------------------------------------------------------------------

#[test]
fn first_reservation_migrates_rows_and_commits_the_sample() -> TestResult {
    let fixture = TrustedClockFixtureV1::new();
    let reservation = reserve_at(&fixture, T0)?;
    assert_eq!(reservation.reservation_seq(), 1);
    assert_eq!(reservation.sampled_at(), WallTime::from_micros(T0));
    let bound = WallTime::from_micros(T0 + W);
    assert_eq!(reservation.decision_bound(), bound);
    let row = high_water_row(&fixture);
    assert_eq!(row.format_version, 1);
    assert_eq!(row.clock_domain.len(), 16);
    assert_eq!(row.high_water_micros, micros(T0));
    assert_eq!(row.reserved_until_micros, micros(T0 + W));
    assert_eq!(row.reservation_seq, 1);
    let unlatched = TrustedClockOverrunLatchRowV1::UNLATCHED;
    assert_eq!(latch_row(&fixture), unlatched);
    assert!(!fixture.writer_held());
    let next = reserve_at(&fixture, T0 + SECOND)?;
    assert_eq!(next.reservation_seq(), 2);
    let row_after = high_water_row(&fixture);
    assert_eq!(row_after.clock_domain, row.clock_domain);
    assert_eq!(row_after.reserved_until_micros, micros(T0 + SECOND + W));
    Ok(())
}

#[test]
fn reserved_until_never_decreases() -> TestResult {
    let far = micros(FAR);
    let fixture = with_rows(|rows| rows.high_water[0].reserved_until_micros = far);
    reserve_at(&fixture, T0)?;
    let reserved_until = high_water_row(&fixture).reserved_until_micros;
    assert_eq!(reserved_until, far);
    Ok(())
}

#[test]
fn missing_rows_with_catalog_entries_stay_missing() {
    let fixture = TrustedClockFixtureV1::new();
    fixture.set_catalog_entries(1);
    let refused = reserve_at(&fixture, T0).err();
    assert_eq!(refused, Some(Fence::HighWaterMissing));
    assert_eq!(fixture.rows(), TrustedClockRowsV1::default());
    let latch_missing = with_rows(|rows| rows.overrun_latch.clear());
    latch_missing.set_catalog_entries(3);
    let refused = reserve_at(&latch_missing, T0 + SECOND).err();
    assert_eq!(refused, Some(Fence::HighWaterMissing));
    assert!(latch_missing.rows().overrun_latch.is_empty());
    assert!(!latch_missing.writer_held());
}

#[test]
fn migration_recreates_only_missing_rows_while_the_catalog_is_empty() -> TestResult {
    let fixture = with_rows(|rows| rows.overrun_latch.clear());
    let domain = high_water_row(&fixture).clock_domain;
    let reservation = reserve_at(&fixture, T0 + SECOND)?;
    assert_eq!(reservation.reservation_seq(), 2);
    assert_eq!(high_water_row(&fixture).clock_domain, domain);
    let unlatched = TrustedClockOverrunLatchRowV1::UNLATCHED;
    assert_eq!(latch_row(&fixture), unlatched);
    let rolled_back = with_rows(|rows| rows.overrun_latch.clear());
    let refused = reserve_at(&rolled_back, T0 - 1).err();
    assert_eq!(refused, Some(Fence::Rollback));
    assert!(rolled_back.rows().overrun_latch.is_empty());
    Ok(())
}

#[test]
fn reservation_faults_fail_closed_without_changing_rows() {
    let cases = [
        (Fault::DurabilityMismatch, DURABILITY),
        (Fault::DurabilityError, DURABILITY),
        (Fault::BeginBusy, RESERVATION_WAIT),
        (Fault::BeginStorage, DURABILITY),
        (Fault::ReadError, CORRUPT),
        (Fault::WriteHighWater, COMMIT_FAILED),
        (Fault::Commit, COMMIT_FAILED),
    ];
    for (fault, expected) in cases {
        let fixture = initialized(T0);
        let before = fixture.rows();
        fixture.arm(fault);
        assert_eq!(reserve_at(&fixture, T0 + SECOND).err(), Some(expected));
        assert_eq!(fixture.rows(), before);
        assert!(!fixture.writer_held());
    }
}

#[test]
fn migration_faults_fail_closed_without_creating_rows() {
    let cases = [
        (Fault::CatalogError, CORRUPT),
        (Fault::DomainError, DURABILITY),
        (Fault::WriteHighWater, COMMIT_FAILED),
        (Fault::WriteLatch, COMMIT_FAILED),
    ];
    for (fault, expected) in cases {
        let fixture = TrustedClockFixtureV1::new();
        fixture.arm(fault);
        assert_eq!(reserve_at(&fixture, T0).err(), Some(expected));
        assert_eq!(fixture.rows(), TrustedClockRowsV1::default());
    }
    let unavailable = Some(Fence::SourceUnavailable);
    let sample = ScriptedWallSampleV1::Unavailable;
    let fresh = TrustedClockFixtureV1::new();
    let refused = reserve_with(&fresh, sample).err();
    assert_eq!(refused, unavailable);
    assert_eq!(fresh.rows(), TrustedClockRowsV1::default());
    let ready = initialized(T0);
    let refused = reserve_with(&ready, sample).err();
    assert_eq!(refused, unavailable);
}

#[test]
fn rollback_at_reserve_leaves_the_row_unchanged_and_never_reopens() -> TestResult {
    let fixture = TrustedClockFixtureV1::new();
    let expired = reserve_at(&fixture, E - W)?;
    let refused = release(&fixture, expired, E, E - W).err();
    assert_eq!(refused, Some(Fence::Expired));
    let before = fixture.rows();
    for at in [E - W - 1, E - W - SECOND, E - W - 31 * SECOND, E - W - DAY] {
        assert_eq!(reserve_at(&fixture, at).err(), Some(Fence::Rollback));
        assert_eq!(fixture.rows(), before);
    }
    let again = reserve_at(&fixture, E - W)?;
    let refused = release(&fixture, again, E, E - W).err();
    assert_eq!(refused, Some(Fence::Expired));
    Ok(())
}

#[test]
fn forward_jump_holds_release_closed_until_time_catches_up() -> TestResult {
    let fixture = initialized(T0);
    let jumped = T0 + 10 * DAY;
    let _jumped = reserve_at(&fixture, jumped)?;
    assert_eq!(high_water_row(&fixture).high_water_micros, micros(jumped));
    let before = fixture.rows();
    let refused = reserve_at(&fixture, T0 + SECOND).err();
    assert_eq!(refused, Some(Fence::Rollback));
    assert_eq!(fixture.rows(), before);
    let caught_up = reserve_at(&fixture, jumped)?;
    let released = release(&fixture, caught_up, FAR, jumped)?;
    assert_eq!(released.value(), &vec![7, 7]);
    Ok(())
}

#[test]
fn unsupported_formats_fail_closed() {
    let high_water = with_rows(|rows| rows.high_water[0].format_version = 2);
    let refused = reserve_at(&high_water, T0 + 1).err();
    assert_eq!(refused, Some(Fence::UnsupportedFormat));
    let latch = with_rows(|rows| rows.overrun_latch[0].format_version = 2);
    let refused = reserve_at(&latch, T0 + 1).err();
    assert_eq!(refused, Some(Fence::UnsupportedFormat));
}

#[test]
fn corrupt_rows_fail_closed() {
    let edits: [fn(&mut TrustedClockRowsV1); 13] = [
        |rows| rows.high_water[0].reserved_until_micros = micros(T0) - 1,
        |rows| rows.high_water[0].clock_domain.truncate(15),
        |rows| rows.high_water[0].high_water_micros = -1,
        |rows| rows.high_water[0].reservation_seq = -1,
        |rows| rows.high_water.push(rows.high_water[0].clone()),
        |rows| rows.overrun_latch.push(rows.overrun_latch[0]),
        |rows| rows.overrun_latch[0].latched = 2,
        |rows| rows.overrun_latch[0].latched = -1,
        |rows| rows.overrun_latch[0].overrun_count = -1,
        |rows| rows.overrun_latch[0].last_overrun_reservation = -1,
        |rows| rows.overrun_latch[0].last_overrun_kind = 4,
        |rows| rows.overrun_latch[0].last_overrun_kind = -1,
        |rows| rows.overrun_latch[0].last_overrun_at_micros = -1,
    ];
    for edit in edits {
        let fixture = with_rows(edit);
        let before = fixture.rows();
        assert_eq!(reserve_at(&fixture, T0 + 1).err(), Some(CORRUPT));
        assert_eq!(fixture.rows(), before);
    }
}

#[test]
fn boundary_rows_remain_valid() -> TestResult {
    let fixture = with_rows(|rows| {
        rows.overrun_latch[0].last_overrun_kind = 3;
        rows.high_water[0].reserved_until_micros = rows.high_water[0].high_water_micros;
    });
    reserve_at(&fixture, T0)?;
    let zero = TrustedClockFixtureV1::new();
    reserve_at(&zero, 0)?;
    assert_eq!(high_water_row(&zero).high_water_micros, 0);
    reserve_at(&zero, 0)?;
    Ok(())
}

#[test]
fn checked_arithmetic_overflows_fail_closed() {
    let seq = with_rows(|rows| rows.high_water[0].reservation_seq = i64::MAX);
    assert_eq!(reserve_at(&seq, T0 + 1).err(), Some(Fence::Overflow));
    let bound = TrustedClockFixtureV1::new();
    let refused = reserve_at(&bound, MAX_MICROS).err();
    assert_eq!(refused, Some(Fence::Overflow));
    assert_eq!(bound.rows(), TrustedClockRowsV1::default());
}

#[test]
fn wait_budget_spans_owner_locks_and_reservation() -> TestResult {
    let fixture = initialized(T0);
    let mut store = fixture.clone();
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([T0 + 1]);
    let mut mono = mono_at(&[ZERO, ms(60)]);
    let mut wait = WaitBudgetV1::new();
    wait.charge(WaitPhaseV1::OwnerLocks, ms(200))?;
    let refused = reserve_trusted_clock(&mut store, &mut wall, &mut mono, &mut wait, None);
    assert_eq!(refused.err(), Some(RESERVATION_WAIT));
    assert!(!fixture.writer_held());
    let mut regressed = mono_at(&[Duration::from_secs(1), ZERO]);
    let mut wait = WaitBudgetV1::new();
    let refused = reserve_trusted_clock(&mut store, &mut wall, &mut regressed, &mut wait, None);
    assert_eq!(refused.err(), Some(Fence::Rollback));
    assert!(!fixture.writer_held());
    Ok(())
}

// ---------------------------------------------------------------------------
// Guard, expiries and handoff
// ---------------------------------------------------------------------------

#[test]
fn expiry_bound_is_exclusive_at_one_microsecond() -> TestResult {
    let released = reserve_and_release(E - W - 1, E - W - 1, E)?;
    assert_eq!(released.value(), &vec![7, 7]);
    assert_eq!(released.overrun_signal(), None);
    for at in [E - W, E - W + 1] {
        let fixture = TrustedClockFixtureV1::new();
        let reservation = reserve_at(&fixture, at)?;
        let refused = release(&fixture, reservation, E, at).err();
        assert_eq!(refused, Some(Fence::Expired));
        assert_eq!(high_water_row(&fixture).high_water_micros, micros(at));
        assert!(!fixture.writer_held());
    }
    let rounded = TrustedClockFixtureV1::new();
    let below = Duration::from_micros(E - W) - Duration::from_nanos(1);
    let reservation = reserve_with(&rounded, ScriptedWallSampleV1::SinceEpoch(below))?;
    assert_eq!(reservation.sampled_at(), WallTime::from_micros(E - W));
    let refused = release(&rounded, reservation, E, E - W).err();
    assert_eq!(refused, Some(Fence::Expired));
    Ok(())
}

#[test]
fn final_sample_must_lie_inside_the_reservation_window() -> TestResult {
    let at_bound = reserve_and_release(T0, T0 + W, FAR)?;
    assert_eq!(at_bound.overrun_signal(), None);
    reserve_and_release(T0, T0, FAR)?;
    let late = reserve_and_release(T0, T0 + W + 1, FAR).err();
    assert_eq!(late, Some(Fence::WindowExceeded));
    let suspended = reserve_and_release(T0, T0 + 40 * SECOND, FAR).err();
    assert_eq!(suspended, Some(Fence::WindowExceeded));
    let early = reserve_and_release(T0, T0 - 1, FAR).err();
    assert_eq!(early, Some(Fence::Rollback));
    let fixture = TrustedClockFixtureV1::new();
    let reservation = reserve_at(&fixture, T0)?;
    let unavailable = release_with(&fixture, reservation, FAR, &[], &mut still());
    assert_eq!(unavailable.err(), Some(Fence::SourceUnavailable));
    assert!(!fixture.writer_held());
    Ok(())
}

#[test]
fn guard_budget_is_thirty_seconds_from_g0() -> TestResult {
    let fixture = TrustedClockFixtureV1::new();
    let mut mono = mono_at(&[ZERO; 4]);
    mono.push(TRUSTED_CLOCK_GUARD_BUDGET);
    let reservation = reserve_on(&fixture, T0, &mut mono)?;
    let released = release_with(&fixture, reservation, FAR, &[T0, T0], &mut mono)?;
    assert_eq!(released.overrun_signal(), None);
    let mut mono = mono_at(&[ZERO; 4]);
    let past_budget = TRUSTED_CLOCK_GUARD_BUDGET + Duration::from_micros(1);
    mono.push(past_budget);
    let reservation = reserve_on(&fixture, T0, &mut mono)?;
    let late = release_with(&fixture, reservation, FAR, &[T0, T0], &mut mono);
    assert_eq!(late.err(), Some(Fence::WindowExceeded));
    let mut regressed = mono_at(&[Duration::from_secs(5); 4]);
    regressed.push(ZERO);
    let reservation = reserve_on(&fixture, T0, &mut regressed)?;
    let refused = release_with(&fixture, reservation, FAR, &[T0, T0], &mut regressed);
    assert_eq!(refused.err(), Some(Fence::Rollback));
    Ok(())
}

#[test]
fn owner_lock_g0_starts_the_guard_budget_before_the_reservation() -> TestResult {
    let fixture = initialized(T0);
    let mut store = fixture.clone();
    let ten = Duration::from_secs(10);
    let mut mono = mono_at(&[ZERO, ten, ten, ten, ten]);
    let g0 = mono.mark();
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([T0]);
    let mut wait = WaitBudgetV1::new();
    let reserved = reserve_trusted_clock(&mut store, &mut wall, &mut mono, &mut wait, Some(g0));
    let past_budget = TRUSTED_CLOCK_GUARD_BUDGET + Duration::from_micros(1);
    mono.push(past_budget);
    let late = release_with(&fixture, reserved?, FAR, &[T0, T0], &mut mono);
    assert_eq!(late.err(), Some(Fence::WindowExceeded));
    Ok(())
}

#[test]
fn guard_wait_and_port_faults_release_the_lock() -> TestResult {
    let cases = [
        (Fault::GuardBusy, GUARD_WAIT),
        (Fault::GuardStorage, DURABILITY),
        (Fault::GuardRead, CORRUPT),
    ];
    for (fault, expected) in cases {
        let fixture = TrustedClockFixtureV1::new();
        let reservation = reserve_at(&fixture, T0)?;
        fixture.arm(fault);
        let refused = release(&fixture, reservation, FAR, T0).err();
        assert_eq!(refused, Some(expected));
        assert!(!fixture.writer_held());
    }
    let fixture = TrustedClockFixtureV1::new();
    let mut slow = mono_at(&[ZERO; 3]);
    slow.push(ms(251));
    let reservation = reserve_on(&fixture, T0, &mut slow)?;
    let refused = release_with(&fixture, reservation, FAR, &[T0, T0], &mut slow);
    assert_eq!(refused.err(), Some(GUARD_WAIT));
    let mut regressed = mono_at(&[Duration::from_secs(1); 3]);
    regressed.push(ZERO);
    let reservation = reserve_on(&fixture, T0, &mut regressed)?;
    let refused = release_with(&fixture, reservation, FAR, &[T0, T0], &mut regressed);
    assert_eq!(refused.err(), Some(Fence::Rollback));
    assert!(!fixture.writer_held());
    Ok(())
}

#[test]
fn guard_reread_detects_regressed_or_missing_authority() -> TestResult {
    let edits: [fn(&mut TrustedClockRowsV1); 3] = [
        |rows| rows.high_water[0].clock_domain = vec![9; 16],
        |rows| rows.high_water[0].reservation_seq = 0,
        |rows| rows.high_water[0].high_water_micros = micros(T0) - 1,
    ];
    for edit in edits {
        let fixture = TrustedClockFixtureV1::new();
        let reservation = reserve_at(&fixture, T0)?;
        let mut rows = fixture.rows();
        edit(&mut rows);
        fixture.set_rows(rows);
        let refused = release(&fixture, reservation, FAR, T0).err();
        assert_eq!(refused, Some(Fence::AuthorityRegressed));
        assert!(!fixture.writer_held());
    }
    let fixture = TrustedClockFixtureV1::new();
    let reservation = reserve_at(&fixture, T0)?;
    fixture.set_rows(TrustedClockRowsV1::default());
    let refused = release(&fixture, reservation, FAR, T0).err();
    assert_eq!(refused, Some(Fence::HighWaterMissing));
    Ok(())
}

#[test]
fn later_reservation_raises_the_final_sample_floor() -> TestResult {
    let floor = T0 + 5 * SECOND;
    let fixture = TrustedClockFixtureV1::new();
    let first = reserve_at(&fixture, T0)?;
    let second = reserve_at(&fixture, floor)?;
    assert_eq!(second.reservation_seq(), first.reservation_seq() + 1);
    let mut port = fixture.clone();
    let mut wait = WaitBudgetV1::new();
    let guard = open_release_guard(&mut port, first, &mut wait, &mut still())?;
    assert_eq!(guard.high_water(), WallTime::from_micros(floor));
    assert_eq!(guard.reservation().reservation_seq(), 1);
    assert!(fixture.writer_held());
    let blocked = reserve_at(&fixture, floor).err();
    assert_eq!(blocked, Some(RESERVATION_WAIT));
    let leases = [lease(FAR)];
    let access = authenticated(1, FAR);
    let premises = ExpiryPremisesV1 {
        retention_leases: &leases,
        consent_grants: &[],
        consent_references: &[],
        access: Some(&access),
    };
    let expiries = guard.applicable_expiries(&premises)?;
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([floor - 1]);
    let below = handoff_checked(guard, &expiries, staged(), &mut wall, &mut still());
    assert_eq!(below.err(), Some(Fence::Rollback));
    assert!(!fixture.writer_held());
    let released = release(&fixture, second, FAR, floor)?;
    assert_eq!(released.value(), &vec![7, 7]);
    Ok(())
}

#[test]
fn guards_may_finish_out_of_reservation_order() -> TestResult {
    let later = T0 + 10 * SECOND;
    let fixture = TrustedClockFixtureV1::new();
    let first = reserve_at(&fixture, T0)?;
    let second = reserve_at(&fixture, later)?;
    let refused = release(&fixture, second, later + W, later).err();
    assert_eq!(refused, Some(Fence::Expired));
    let released = release(&fixture, first, FAR, later)?;
    assert_eq!(released.value(), &vec![7, 7]);
    Ok(())
}

#[test]
fn applicable_expiries_take_the_checked_minimum() -> TestResult {
    let fixture = TrustedClockFixtureV1::new();
    let reservation = reserve_at(&fixture, T0)?;
    let mut port = fixture.clone();
    let mut wait = WaitBudgetV1::new();
    let guard = open_release_guard(&mut port, reservation, &mut wait, &mut still())?;
    let leases = [lease(FAR), lease(FAR - SECOND)];
    let access = authenticated(1, FAR - 2 * SECOND);
    let x = u32::try_from((T0 + 100 * SECOND) / SECOND)?;
    let grants = [consent_grant(0), consent_grant(x)];
    let references = [consent_reference(FAR - 3 * SECOND)];
    let mut premises = ExpiryPremisesV1 {
        retention_leases: &leases,
        consent_grants: &grants[..1],
        consent_references: &[],
        access: Some(&access),
    };
    let earliest = guard.applicable_expiries(&premises)?.earliest_expiry();
    assert_eq!(earliest, WallTime::from_micros(FAR - 2 * SECOND));
    premises.consent_references = &references;
    let earliest = guard.applicable_expiries(&premises)?.earliest_expiry();
    assert_eq!(earliest, WallTime::from_micros(FAR - 3 * SECOND));
    premises.consent_grants = &grants;
    let earliest = guard.applicable_expiries(&premises)?.earliest_expiry();
    assert_eq!(earliest, WallTime::from_micros(u64::from(x) * SECOND));
    premises.retention_leases = &[];
    let unknown = guard.applicable_expiries(&premises);
    assert_eq!(unknown, Err(Fence::ExpiryUnknown));
    premises.retention_leases = &leases;
    premises.access = None;
    let unknown = guard.applicable_expiries(&premises);
    assert_eq!(unknown, Err(Fence::ExpiryUnknown));
    Ok(())
}

#[test]
fn absolute_consent_expiry_releases_one_microsecond_before_its_bound() -> TestResult {
    let x_micros = T0 + 100 * SECOND;
    let x = u32::try_from(x_micros / SECOND)?;
    let fixture = TrustedClockFixtureV1::new();
    let reservation = reserve_at(&fixture, x_micros - 1 - W)?;
    let mut port = fixture.clone();
    let mut wait = WaitBudgetV1::new();
    let guard = open_release_guard(&mut port, reservation, &mut wait, &mut still())?;
    let leases = [lease(FAR)];
    let access = authenticated(1, FAR);
    let grants = [consent_grant(x)];
    let premises = ExpiryPremisesV1 {
        retention_leases: &leases,
        consent_grants: &grants,
        consent_references: &[],
        access: Some(&access),
    };
    let expiries = guard.applicable_expiries(&premises)?;
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([x_micros - W, x_micros - W]);
    let released = handoff_checked(guard, &expiries, staged(), &mut wall, &mut still())?;
    assert_eq!(released.value(), &vec![7, 7]);
    Ok(())
}

#[test]
fn expiries_from_another_guard_are_refused() -> TestResult {
    let leases = [lease(FAR)];
    let access = authenticated(1, FAR);
    let premises = ExpiryPremisesV1 {
        retention_leases: &leases,
        consent_grants: &[],
        consent_references: &[],
        access: Some(&access),
    };
    let first = TrustedClockFixtureV1::new();
    let other = TrustedClockFixtureV1::new();
    let mut first_port = first.clone();
    let mut other_port = other.clone();
    let mut wait = WaitBudgetV1::new();
    let reservation = reserve_at(&other, T0)?;
    let other_guard = open_release_guard(&mut other_port, reservation, &mut wait, &mut still())?;
    let other_expiries = other_guard.applicable_expiries(&premises)?;
    drop(other_guard);
    let reservation = reserve_at(&first, T0)?;
    let mut wait = WaitBudgetV1::new();
    let guard = open_release_guard(&mut first_port, reservation, &mut wait, &mut still())?;
    let stale = guard.applicable_expiries(&premises)?;
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([T0, T0]);
    let refused = handoff_checked(guard, &other_expiries, staged(), &mut wall, &mut still());
    assert_eq!(refused.err(), Some(Fence::AuthorityRegressed));
    let reservation = reserve_at(&first, T0)?;
    let mut wait = WaitBudgetV1::new();
    let guard = open_release_guard(&mut first_port, reservation, &mut wait, &mut still())?;
    let refused = handoff_checked(guard, &stale, staged(), &mut wall, &mut still());
    assert_eq!(refused.err(), Some(Fence::AuthorityRegressed));
    assert!(!first.writer_held());
    Ok(())
}

// ---------------------------------------------------------------------------
// Overrun latch and acknowledgement
// ---------------------------------------------------------------------------

#[test]
fn post_handoff_overruns_are_signalled_and_latched() -> TestResult {
    let late = Duration::from_secs(32) + Duration::from_micros(1);
    let budget = TrustedClockOverrunKindV1::MonotonicBudgetExceeded;
    let beyond = TrustedClockOverrunKindV1::WallBeyondDecisionBound;
    let kinds = [
        (late, T0, budget),
        (Duration::from_secs(32), T0 + W + 1, beyond),
    ];
    for (post, post_sample, kind) in kinds {
        let fixture = TrustedClockFixtureV1::new();
        let released = overrun(&fixture, post, post_sample)?;
        assert_eq!(released.value(), &vec![7, 7]);
        assert_eq!(released.overrun_signal(), Some(kind));
        assert!(!fixture.writer_held());
        let mut store = fixture.clone();
        assert_eq!(commit_pending_overrun_latch(&mut store), Ok(true));
        let latch = latch_row(&fixture);
        assert_eq!(latch.latched, 1);
        assert_eq!(latch.overrun_count, 1);
        assert_eq!(latch.last_overrun_reservation, 1);
        assert_eq!(latch.last_overrun_kind, i64::from(kind.code()));
        assert_eq!(latch.last_overrun_at_micros, micros(post_sample));
        assert_eq!(commit_pending_overrun_latch(&mut store), Ok(false));
        let refused = reserve_at(&fixture, T0).err();
        assert_eq!(refused, Some(Fence::OverrunLatched));
    }
    Ok(())
}

#[test]
fn regressed_or_unavailable_post_samples_latch() -> TestResult {
    let fixture = TrustedClockFixtureV1::new();
    let mut mono = mono_at(&[Duration::from_secs(1); 5]);
    mono.push(ZERO);
    let reservation = reserve_on(&fixture, T0, &mut mono)?;
    let released = release_with(&fixture, reservation, FAR, &[T0, T0], &mut mono)?;
    let regression = TrustedClockOverrunKindV1::MonotonicRegression;
    assert_eq!(released.overrun_signal(), Some(regression));
    let unavailable = TrustedClockFixtureV1::new();
    let reservation = reserve_at(&unavailable, T0)?;
    let released = release_with(&unavailable, reservation, FAR, &[T0], &mut still())?;
    let beyond = TrustedClockOverrunKindV1::WallBeyondDecisionBound;
    assert_eq!(released.overrun_signal(), Some(beyond));
    let mut store = unavailable.clone();
    assert_eq!(commit_pending_overrun_latch(&mut store), Ok(true));
    let latch = latch_row(&unavailable);
    assert_eq!(latch.last_overrun_at_micros, micros(T0 + W));
    Ok(())
}

#[test]
fn acknowledgement_is_authorized_counted_and_audited() -> TestResult {
    let fixture = latched(&TrustedClockFixtureV1::new());
    let high_water = high_water_row(&fixture);
    let operator = authenticated(2, FAR);
    let expiring = authenticated(2, T0 + SECOND);
    let unauthorized = Err(Fence::AcknowledgementUnauthorized);
    let stale = Err(Fence::StaleAcknowledgement);
    let outcome = acknowledge(&fixture, &operator, 2, 0, T0 + SECOND);
    assert_eq!(outcome, stale);
    let outcome = acknowledge(&fixture, &operator, 2, u64::MAX, T0 + SECOND);
    assert_eq!(outcome, stale);
    let outcome = acknowledge(&fixture, &operator, 3, 1, T0 + SECOND);
    assert_eq!(outcome, unauthorized);
    let outcome = acknowledge(&fixture, &expiring, 2, 1, T0 + SECOND);
    assert_eq!(outcome, unauthorized);
    let rollback = acknowledge(&fixture, &operator, 2, 1, T0 - 1);
    assert_eq!(rollback, Err(Fence::Rollback));
    assert_eq!(latch_row(&fixture).latched, 1);
    assert!(fixture.acknowledgements().is_empty());
    acknowledge(&fixture, &operator, 2, 1, T0 + 2 * SECOND)?;
    assert_eq!(latch_row(&fixture).latched, 0);
    assert_eq!(latch_row(&fixture).overrun_count, 1);
    assert_eq!(high_water_row(&fixture), high_water);
    let audit = fixture.acknowledgements();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].acknowledged_overrun_count, 1);
    let operator_digest = principal_digest(&principal(2));
    assert_eq!(audit[0].operator_principal_digest, operator_digest);
    assert_eq!(audit[0].authorization_provenance_digest, [4; 32]);
    assert_eq!(audit[0].trust_revision_digest, [5; 32]);
    assert_eq!(audit[0].acknowledged_at_micros, micros(T0 + 2 * SECOND));
    assert_eq!(audit[0].reason_code, 2);
    let outcome = acknowledge(&fixture, &operator, 2, 1, T0 + 3 * SECOND);
    assert_eq!(outcome, stale);
    let reservation = reserve_at(&fixture, T0 + 3 * SECOND)?;
    let released = release(&fixture, reservation, FAR, T0 + 3 * SECOND)?;
    assert_eq!(released.overrun_signal(), None);
    Ok(())
}

#[test]
fn acknowledgement_faults_fail_closed() {
    let cases = [
        (Fault::DurabilityMismatch, DURABILITY),
        (Fault::BeginBusy, RESERVATION_WAIT),
        (Fault::ReadError, CORRUPT),
        (Fault::WriteLatch, COMMIT_FAILED),
        (Fault::AppendAcknowledgement, COMMIT_FAILED),
        (Fault::Commit, DURABILITY),
    ];
    let operator = authenticated(2, FAR);
    for (fault, expected) in cases {
        let fixture = latched(&TrustedClockFixtureV1::new());
        fixture.arm(fault);
        let outcome = acknowledge(&fixture, &operator, 2, 1, T0 + 1);
        assert_eq!(outcome, Err(expected));
        assert_eq!(latch_row(&fixture).latched, 1);
        assert!(fixture.acknowledgements().is_empty());
        assert!(!fixture.writer_held());
    }
    let missing = with_rows(|rows| rows.high_water.clear());
    let refused = acknowledge(&missing, &operator, 2, 1, T0 + 1);
    assert_eq!(refused, Err(Fence::HighWaterMissing));
    let ready = initialized(T0);
    let mut store = ready.clone();
    let mut wall = ScriptedTrustedWallSourceV1::new([ScriptedWallSampleV1::Unavailable]);
    let authorization = authorization(2);
    let request = TrustedClockOverrunAcknowledgementV1 {
        operator: &operator,
        authorization: &authorization,
        expected_overrun_count: 1,
        reason: OverrunAckReasonV1::BenignStall,
    };
    let refused = acknowledge_trusted_clock_overrun(&mut store, &mut wall, &request);
    assert_eq!(refused, Err(Fence::SourceUnavailable));
}

#[test]
fn pending_flag_is_keyed_by_authority_identity() -> TestResult {
    let fixture = TrustedClockFixtureV1::new();
    let other = initialized(T0);
    let waiting = reserve_at(&fixture, T0)?;
    let released = overrun(&fixture, Duration::from_secs(33), T0)?;
    assert!(released.overrun_signal().is_some());
    fixture.arm(Fault::WriteLatch);
    let failed = commit_pending_overrun_latch(&mut fixture.clone());
    assert_eq!(failed, Err(COMMIT_FAILED));
    let refused = release(&fixture, waiting, FAR, T0).err();
    assert_eq!(refused, Some(Fence::OverrunLatched));
    let unaffected = reserve_at(&other, T0)?;
    let released = release(&other, unaffected, FAR, T0)?;
    assert_eq!(released.overrun_signal(), None);
    assert_eq!(latch_row(&fixture).latched, 0);
    fixture.arm(Fault::Commit);
    let refused = reserve_at(&fixture, T0).err();
    assert_eq!(refused, Some(Fence::OverrunLatched));
    assert_eq!(latch_row(&fixture).latched, 0);
    let refused = reserve_at(&fixture, T0).err();
    assert_eq!(refused, Some(Fence::OverrunLatched));
    assert_eq!(latch_row(&fixture).latched, 1);
    assert_eq!(latch_row(&fixture).overrun_count, 1);
    acknowledge(&fixture, &authenticated(2, FAR), 2, 1, T0)?;
    let reservation = reserve_at(&fixture, T0)?;
    let released = release(&fixture, reservation, FAR, T0)?;
    assert_eq!(released.overrun_signal(), None);
    assert_eq!(latch_row(&fixture).latched, 0);
    Ok(())
}

#[test]
fn latch_commit_failures_keep_the_pending_flag() -> TestResult {
    let fixture = TrustedClockFixtureV1::new();
    overrun(&fixture, Duration::from_secs(33), T0)?;
    let mut store = fixture.clone();
    let cases = [
        (Fault::DurabilityError, DURABILITY),
        (Fault::BeginBusy, RESERVATION_WAIT),
        (Fault::ReadError, CORRUPT),
        (Fault::Commit, DURABILITY),
    ];
    for (fault, expected) in cases {
        fixture.arm(fault);
        assert_eq!(commit_pending_overrun_latch(&mut store), Err(expected));
        assert_eq!(latch_row(&fixture).latched, 0);
        assert!(!fixture.writer_held());
    }
    let mut rows = fixture.rows();
    rows.overrun_latch[0].overrun_count = i64::MAX;
    fixture.set_rows(rows);
    let overflow = commit_pending_overrun_latch(&mut store);
    assert_eq!(overflow, Err(Fence::Overflow));
    assert_eq!(reserve_at(&fixture, T0).err(), Some(Fence::Overflow));
    let mut rows = fixture.rows();
    rows.overrun_latch[0].overrun_count = 0;
    fixture.set_rows(rows);
    assert_eq!(commit_pending_overrun_latch(&mut store), Ok(true));
    assert_eq!(latch_row(&fixture).latched, 1);
    Ok(())
}

#[test]
fn fixture_ports_reject_writes_outside_a_transaction() {
    let fixture = initialized(T0);
    let mut store = fixture.clone();
    assert_eq!(store.read_rows(), Ok(fixture.rows()));
    let row = high_water_row(&fixture);
    let storage = Err(TrustedClockPortErrorV1::Storage);
    assert_eq!(store.write_high_water(&row), storage);
    assert_eq!(store.commit(), storage);
    assert_eq!(fixture.rows().high_water, vec![row]);
}
