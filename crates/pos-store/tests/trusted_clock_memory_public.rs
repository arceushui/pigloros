use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::trusted_clock::TrustedClockErrorV1 as Fence;
use pos_core::trusted_clock::{
    acknowledge_trusted_clock_overrun, commit_pending_overrun_latch, handoff_checked,
    open_release_guard, reserve_trusted_clock, AuthorizedArtifactUseV1, ExpiryPremisesV1,
    HostAdministrativeActionV1, HostAdministrativeAuthorizationV1, HostAuthorizationProvenanceV1,
    OverrunAckReasonV1, ReleaseGuardPortV1, ScriptedGuardMonotonicSourceV1,
    ScriptedTrustedWallSourceV1, StagedArtifactBytesV1, StagedProtectedOutputV1,
    TrustedClockAcknowledgementRowV1, TrustedClockHighWaterRowV1,
    TrustedClockOverrunAcknowledgementV1, TrustedClockOverrunLatchRowV1, TrustedClockPortErrorV1,
    TrustedClockReservationV1, TrustedClockRowsV1, TrustedClockStorePortV1, WaitBudgetV1,
    WaitPhaseV1,
};
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1, Hash,
    PrincipalRefV1, TimelineId, WallTime,
};
use pos_store::MemoryTrustedClockAuthorityV1;
use std::fmt::Debug;
use std::time::{Duration, Instant};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Release = Result<AuthorizedArtifactUseV1<Vec<u8>>, Fence>;
type Reserved = Result<TrustedClockReservationV1, Fence>;

const SECOND: u64 = 1_000_000;
const DAY: u64 = 86_400 * SECOND;
const T0: u64 = 1_800_000_000 * SECOND;
const FAR: u64 = T0 + 1_000 * DAY;
const ZERO: Duration = Duration::ZERO;
const STORAGE: TrustedClockPortErrorV1 = TrustedClockPortErrorV1::Storage;
const RESERVATION_WAIT: Fence = Fence::WaitBudgetExceeded(WaitPhaseV1::Reservation);

fn ok<T, Error: Debug>(value: Result<T, Error>) -> T {
    value.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!(
            "unexpected memory trusted-clock error: {error:?}"
        )))
    })
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

fn authenticated(byte: u8) -> AuthenticatedPrincipalResultV1 {
    let draft = AuthenticatedPrincipalDraftV1 {
        principal: principal(byte),
        adapter_id: "test-passkey".to_owned(),
        assurance: ok(AssuranceLevelV1::try_new(2)),
        issued_at: WallTime::from_micros(1),
        expires_at: WallTime::from_micros(FAR),
        binding_digest: Hash::from_bytes([7; 32]),
    };
    ok(AuthenticatedPrincipalResultV1::try_from_draft(draft))
}

fn mono(offsets: &[Duration]) -> ScriptedGuardMonotonicSourceV1 {
    ScriptedGuardMonotonicSourceV1::new(offsets.iter().copied())
}

fn reserve(
    authority: &MemoryTrustedClockAuthorityV1,
    at: u64,
    mono: &mut ScriptedGuardMonotonicSourceV1,
) -> Reserved {
    let mut store = authority.handle();
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([at]);
    let mut wait = WaitBudgetV1::new();
    reserve_trusted_clock(&mut store, &mut wall, mono, &mut wait, None)
}

fn release(
    authority: &MemoryTrustedClockAuthorityV1,
    reservation: TrustedClockReservationV1,
    samples: &[u64],
    mono: &mut ScriptedGuardMonotonicSourceV1,
) -> Release {
    let mut port = authority.handle();
    let leases = [lease(FAR)];
    let access = authenticated(1);
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
    let staged = StagedProtectedOutputV1::stage(StagedArtifactBytesV1::new(vec![3]));
    handoff_checked(guard, &expiries, staged, &mut wall, mono)
}

fn latch(authority: &MemoryTrustedClockAuthorityV1) -> TrustedClockOverrunLatchRowV1 {
    let rows = authority.rows();
    ok(rows.overrun_latch.first().copied().ok_or("missing row"))
}

#[test]
fn handles_share_one_identity_and_release_inside_the_window() -> TestResult {
    let authority = MemoryTrustedClockAuthorityV1::new();
    let first = reserve(&authority, T0, &mut mono(&[ZERO]))?;
    assert_eq!(first.reservation_seq(), 1);
    assert_eq!(authority.rows().high_water.len(), 1);
    let second = reserve(&authority.handle(), T0 + SECOND, &mut mono(&[ZERO]))?;
    assert_eq!(second.reservation_seq(), 2);
    let high_water = authority.rows().high_water[0].high_water_micros;
    assert_eq!(high_water, i64::try_from(T0 + SECOND)?);
    let samples = [T0 + SECOND, T0 + SECOND];
    let released = release(&authority, first, &samples, &mut mono(&[ZERO]))?;
    assert_eq!(released.value(), &vec![3]);
    assert_eq!(released.overrun_signal(), None);
    let refused = release(&authority, second, &[T0], &mut mono(&[ZERO]));
    assert_eq!(refused.err(), Some(Fence::Rollback));
    Ok(())
}

#[test]
fn a_held_guard_bounds_other_handles_by_the_wait_budget() -> TestResult {
    let authority = MemoryTrustedClockAuthorityV1::new();
    let reservation = reserve(&authority, T0, &mut mono(&[ZERO]))?;
    let mut port = authority.handle();
    let mut wait = WaitBudgetV1::new();
    let guard = open_release_guard(&mut port, reservation, &mut wait, &mut mono(&[ZERO]))?;
    let started = Instant::now();
    let refused = reserve(&authority, T0, &mut mono(&[ZERO])).err();
    let waited = started.elapsed();
    assert_eq!(refused, Some(RESERVATION_WAIT));
    assert!(waited >= Duration::from_millis(200));
    assert!(waited < Duration::from_secs(5));
    drop(guard);
    let reservation = reserve(&authority, T0, &mut mono(&[ZERO]))?;
    assert_eq!(reservation.reservation_seq(), 2);
    Ok(())
}

#[test]
fn waiting_handles_resume_when_the_lock_is_released() {
    let authority = MemoryTrustedClockAuthorityV1::new();
    let mut holder = authority.handle();
    let mut waiter = authority.handle();
    assert_eq!(holder.begin_immediate(ZERO), Ok(()));
    let resumed = std::thread::scope(|scope| {
        let waiting = scope.spawn(move || {
            let begun = waiter.begin_immediate(Duration::from_secs(5));
            waiter.rollback();
            begun
        });
        std::thread::sleep(Duration::from_millis(50));
        holder.rollback();
        match waiting.join() {
            Ok(begun) => begun,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    });
    assert_eq!(resumed, Ok(()));
}

#[test]
fn dropping_a_handle_releases_its_lock() {
    let authority = MemoryTrustedClockAuthorityV1::new();
    let mut holder = authority.handle();
    assert_eq!(holder.begin_immediate(ZERO), Ok(()));
    let mut other = authority.handle();
    let busy = Err(TrustedClockPortErrorV1::Busy);
    assert_eq!(other.begin_guard(ZERO), busy);
    drop(holder);
    assert_eq!(other.begin_guard(ZERO), Ok(()));
    other.rollback_and_release();
    assert_eq!(other.begin_guard(ZERO), Ok(()));
}

#[test]
fn a_nested_begin_is_a_storage_error() {
    let authority = MemoryTrustedClockAuthorityV1::new();
    let mut handle = authority.handle();
    assert_eq!(handle.begin_immediate(ZERO), Ok(()));
    assert_eq!(handle.begin_immediate(ZERO), Err(STORAGE));
    assert_eq!(handle.begin_guard(ZERO), Err(STORAGE));
    handle.rollback();
    assert_eq!(handle.begin_guard(ZERO), Ok(()));
    handle.rollback_and_release();
    assert_eq!(handle.begin_immediate(ZERO), Ok(()));
}

#[test]
fn ports_report_rows_only_inside_a_transaction() {
    let authority = MemoryTrustedClockAuthorityV1::new();
    let mut store = authority.handle();
    let high_water = TrustedClockHighWaterRowV1 {
        format_version: 1,
        clock_domain: vec![1; 16],
        high_water_micros: 0,
        reserved_until_micros: 0,
        reservation_seq: 0,
    };
    let acknowledgement = TrustedClockAcknowledgementRowV1 {
        acknowledged_overrun_count: 1,
        operator_principal_digest: [1; 32],
        authorization_provenance_digest: [2; 32],
        trust_revision_digest: [3; 32],
        acknowledged_at_micros: 0,
        reason_code: 1,
    };
    let latch_row = TrustedClockOverrunLatchRowV1::UNLATCHED;
    assert_eq!(store.verify_durability_pragmas(), Ok(true));
    assert_eq!(store.authoritative_catalog_entries(), Ok(0));
    assert_eq!(store.read_rows(), Err(STORAGE));
    assert_eq!(store.write_high_water(&high_water), Err(STORAGE));
    assert_eq!(store.write_overrun_latch(&latch_row), Err(STORAGE));
    let appended = store.append_acknowledgement(&acknowledgement);
    assert_eq!(appended, Err(STORAGE));
    assert_eq!(store.commit(), Err(STORAGE));
    assert_eq!(store.reread_rows(), Ok(TrustedClockRowsV1::default()));
    let domain = ok(store.generate_clock_domain());
    assert_ne!(domain, [0; 16]);
    assert!(authority.acknowledgements().is_empty());
}

#[test]
fn overrun_latch_and_acknowledgement_share_the_identity() -> TestResult {
    let authority = MemoryTrustedClockAuthorityV1::new();
    let mut scripted = mono(&[ZERO; 5]);
    scripted.push(Duration::from_secs(33));
    let reservation = reserve(&authority, T0, &mut scripted)?;
    let released = release(&authority, reservation, &[T0, T0], &mut scripted)?;
    assert!(released.overrun_signal().is_some());
    let mut store = authority.handle();
    assert_eq!(commit_pending_overrun_latch(&mut store), Ok(true));
    assert_eq!(latch(&authority).latched, 1);
    let refused = reserve(&authority, T0, &mut mono(&[ZERO])).err();
    assert_eq!(refused, Some(Fence::OverrunLatched));
    let operator = authenticated(2);
    let authorization = HostAdministrativeAuthorizationV1::new(
        HostAdministrativeActionV1::AcknowledgeTrustedClockOverrun,
        principal(2),
        Hash::from_bytes([5; 32]),
        HostAuthorizationProvenanceV1::from_digest([4; 32]),
    );
    let request = TrustedClockOverrunAcknowledgementV1 {
        operator: &operator,
        authorization: &authorization,
        expected_overrun_count: 1,
        reason: OverrunAckReasonV1::OtherRecordedIncident,
    };
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([T0]);
    acknowledge_trusted_clock_overrun(&mut store, &mut wall, &request)?;
    assert_eq!(latch(&authority).latched, 0);
    let audit = authority.acknowledgements();
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].reason_code, 3);
    let reservation = reserve(&authority, T0, &mut mono(&[ZERO]))?;
    let released = release(&authority, reservation, &[T0, T0], &mut mono(&[ZERO]))?;
    assert_eq!(released.overrun_signal(), None);
    Ok(())
}
