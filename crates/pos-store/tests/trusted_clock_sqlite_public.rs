#![cfg(feature = "sqlite")]

use pos_core::retention::{
    WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
    WorldRetentionPolicyV1,
};
use pos_core::trusted_clock::TrustedClockErrorV1 as Fence;
use pos_core::trusted_clock::{
    acknowledge_trusted_clock_overrun, commit_pending_overrun_latch, handoff_checked,
    open_release_guard, reserve_trusted_clock, AuthorizedArtifactUseV1, ExpiryPremisesV1,
    HostAdministrativeActionV1, HostAdministrativeAuthorizationV1, HostAuthorizationProvenanceV1,
    OverrunAckReasonV1, ScriptedGuardMonotonicSourceV1, ScriptedTrustedWallSourceV1,
    StagedArtifactBytesV1, StagedProtectedOutputV1, TrustedClockOverrunAcknowledgementV1,
    TrustedClockPortErrorV1, TrustedClockReservationV1, TrustedClockStorePortV1, WaitBudgetV1,
    WaitPhaseV1,
};
use pos_core::{
    AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1, CoreError,
    Hash, PrincipalRefV1, TimelineId, WallTime,
};
use pos_store::trusted_clock::SqliteTrustedClockAuthorityV1;
use rusqlite::Connection;
use std::fmt::Debug;
use std::time::{Duration, Instant};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Release = Result<AuthorizedArtifactUseV1<Vec<u8>>, Fence>;
type Reserved = Result<TrustedClockReservationV1, Fence>;

const SECOND: u64 = 1_000_000;
const DAY: u64 = 86_400 * SECOND;
const T0: u64 = 1_800_000_000 * SECOND;
const FAR: u64 = T0 + 1_000 * DAY;
const ZERO: Duration = Duration::ZERO;
const RESERVATION_WAIT: Fence = Fence::WaitBudgetExceeded(WaitPhaseV1::Reservation);
const GUARD_WAIT: Fence = Fence::WaitBudgetExceeded(WaitPhaseV1::Guard);
const SEQ_SQL: &str = "SELECT reservation_seq FROM trusted_clock_high_water";
const LATCHED_SQL: &str = "SELECT latched FROM trusted_clock_overrun_latch";
const ACK_SQL: &str = "SELECT ack_seq FROM trusted_clock_overrun_acknowledgements";
const ACK_INSERT: &str = "INSERT INTO trusted_clock_overrun_acknowledgements VALUES
    (1, 1, zeroblob(32), zeroblob(32), zeroblob(32), 0, 1)";

fn ok<T, Error: Debug>(value: Result<T, Error>) -> T {
    value.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!(
            "unexpected SQLite trusted-clock error: {error:?}"
        )))
    })
}

fn authority_path(directory: &TempDir) -> String {
    directory
        .path()
        .join("authority.db")
        .to_string_lossy()
        .into_owned()
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

fn reserve_on(
    authority: &mut SqliteTrustedClockAuthorityV1,
    at: u64,
    mono: &mut ScriptedGuardMonotonicSourceV1,
) -> Reserved {
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([at]);
    let mut wait = WaitBudgetV1::new();
    reserve_trusted_clock(authority, &mut wall, mono, &mut wait, None)
}

fn reserve(authority: &mut SqliteTrustedClockAuthorityV1, at: u64) -> Reserved {
    reserve_on(authority, at, &mut mono(&[ZERO]))
}

fn release_on(
    authority: &mut SqliteTrustedClockAuthorityV1,
    reservation: TrustedClockReservationV1,
    samples: &[u64],
    mono: &mut ScriptedGuardMonotonicSourceV1,
) -> Release {
    let leases = [lease(FAR)];
    let access = authenticated(1);
    let premises = ExpiryPremisesV1 {
        retention_leases: &leases,
        consent_grants: &[],
        consent_references: &[],
        access: Some(&access),
    };
    let mut wait = WaitBudgetV1::new();
    let guard = open_release_guard(authority, reservation, &mut wait, mono)?;
    let expiries = guard.applicable_expiries(&premises)?;
    let mut wall = ScriptedTrustedWallSourceV1::from_micros(samples.iter().copied());
    let staged = StagedProtectedOutputV1::stage(StagedArtifactBytesV1::new(vec![9]));
    handoff_checked(guard, &expiries, staged, &mut wall, mono)
}

fn release(
    authority: &mut SqliteTrustedClockAuthorityV1,
    reservation: TrustedClockReservationV1,
    final_sample: u64,
) -> Release {
    let samples = [final_sample, final_sample];
    release_on(authority, reservation, &samples, &mut mono(&[ZERO]))
}

fn integer(connection: &Connection, sql: &str) -> i64 {
    ok(connection.query_row(sql, [], |row| row.get(0)))
}

fn initialized(directory: &TempDir) -> SqliteTrustedClockAuthorityV1 {
    let path = authority_path(directory);
    let mut authority = ok(SqliteTrustedClockAuthorityV1::open(&path));
    let _reservation = ok(reserve(&mut authority, T0));
    authority
}

#[test]
fn reservations_persist_with_full_durability_across_reopen() -> TestResult {
    let directory = TempDir::new()?;
    let path = authority_path(&directory);
    let mut authority = SqliteTrustedClockAuthorityV1::open(&path)?;
    let reservation = reserve(&mut authority, T0)?;
    assert_eq!(reservation.reservation_seq(), 1);
    let raw = Connection::open(&path)?;
    let journal: String = raw.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert_eq!(journal, "wal");
    let released = release(&mut authority, reservation, T0 + SECOND)?;
    assert_eq!(released.value(), &vec![9]);
    let _second = reserve(&mut authority, T0 + 2 * SECOND)?;
    drop(authority);
    let mut reopened = SqliteTrustedClockAuthorityV1::open(&path)?;
    let refused = reserve(&mut reopened, T0 + 2 * SECOND - 1).err();
    assert_eq!(refused, Some(Fence::Rollback));
    assert_eq!(integer(&raw, SEQ_SQL), 2);
    let reservation = reserve(&mut reopened, T0 + 3 * SECOND)?;
    assert_eq!(reservation.reservation_seq(), 3);
    let released = release(&mut reopened, reservation, T0 + 3 * SECOND)?;
    assert_eq!(released.overrun_signal(), None);
    Ok(())
}

#[test]
fn separate_connections_on_one_file_serialize_reservations() -> TestResult {
    let directory = TempDir::new()?;
    let path = authority_path(&directory);
    let mut first = SqliteTrustedClockAuthorityV1::open(&path)?;
    let mut second = SqliteTrustedClockAuthorityV1::open(&path)?;
    let earlier = reserve(&mut first, T0)?;
    let later = reserve(&mut second, T0 + 5 * SECOND)?;
    assert_eq!(later.reservation_seq(), earlier.reservation_seq() + 1);
    let refused = release(&mut first, earlier, T0 + SECOND).err();
    assert_eq!(refused, Some(Fence::Rollback));
    let released = release(&mut second, later, T0 + 5 * SECOND)?;
    assert_eq!(released.value(), &vec![9]);
    Ok(())
}

#[test]
fn a_held_writer_lock_bounds_reservation_and_guard_waits() -> TestResult {
    let directory = TempDir::new()?;
    let mut authority = initialized(&directory);
    let raw = Connection::open(authority_path(&directory))?;
    raw.execute_batch("BEGIN IMMEDIATE")?;
    let started = Instant::now();
    let refused = reserve(&mut authority, T0).err();
    let waited = started.elapsed();
    assert_eq!(refused, Some(RESERVATION_WAIT));
    // The raw writer holds the lock until ROLLBACK, far longer than the
    // 250 ms wait budget, so the refusal must come from the budget. The 3 s
    // ceiling only proves the wait was bounded; it leaves slack for loaded CI
    // runners while staying far below "waited for the ROLLBACK".
    assert!(waited < Duration::from_secs(3));
    raw.execute_batch("ROLLBACK")?;
    let reservation = reserve(&mut authority, T0)?;
    raw.execute_batch("BEGIN IMMEDIATE")?;
    let started = Instant::now();
    let refused = release(&mut authority, reservation, T0).err();
    let waited = started.elapsed();
    assert_eq!(refused, Some(GUARD_WAIT));
    // Same bounded-wait check as above, with the same CI slack.
    assert!(waited < Duration::from_secs(3));
    raw.execute_batch("ROLLBACK")?;
    let reservation = reserve(&mut authority, T0)?;
    let released = release(&mut authority, reservation, T0)?;
    assert_eq!(released.value(), &vec![9]);
    Ok(())
}

#[test]
fn a_nested_begin_is_a_storage_error() {
    let directory = ok(TempDir::new());
    let mut authority = initialized(&directory);
    assert_eq!(authority.begin_immediate(ZERO), Ok(()));
    let nested = authority.begin_immediate(ZERO);
    assert_eq!(nested, Err(TrustedClockPortErrorV1::Storage));
    authority.rollback();
    assert_eq!(authority.authoritative_catalog_entries(), Ok(0));
}

#[test]
fn shared_memory_authority_fails_the_durability_read_back() -> TestResult {
    let process = std::process::id();
    let path = format!("file:trusted-clock-{process}?mode=memory&cache=shared");
    let mut authority = SqliteTrustedClockAuthorityV1::open(&path)?;
    let refused = reserve(&mut authority, T0).err();
    assert_eq!(refused, Some(Fence::DurabilityUnavailable));
    Ok(())
}

#[test]
fn opening_fails_closed_for_unusable_files() -> TestResult {
    let directory = TempDir::new()?;
    let missing = directory.path().join("missing").join("authority.db");
    let missing = missing.to_string_lossy().into_owned();
    assert!(SqliteTrustedClockAuthorityV1::open(&missing).is_err());
    let garbage = directory.path().join("garbage.db");
    std::fs::write(&garbage, [0x5a; 4096])?;
    let garbage = garbage.to_string_lossy().into_owned();
    assert!(SqliteTrustedClockAuthorityV1::open(&garbage).is_err());
    Ok(())
}

#[test]
fn unreadable_or_mistyped_rows_fail_closed() -> TestResult {
    let corruptions = [
        "DROP TABLE trusted_clock_high_water",
        "DROP TABLE trusted_clock_overrun_latch",
        "DROP TABLE trusted_clock_high_water;
         CREATE TABLE trusted_clock_high_water (singleton, format_version, clock_domain,
             high_water_micros, reserved_until_micros, reservation_seq);
         INSERT INTO trusted_clock_high_water VALUES (1, 'one', x'00', 0, 0, 0)",
        "DROP TABLE trusted_clock_overrun_latch;
         CREATE TABLE trusted_clock_overrun_latch (singleton, format_version, latched,
             overrun_count, last_overrun_reservation, last_overrun_kind,
             last_overrun_at_micros);
         INSERT INTO trusted_clock_overrun_latch VALUES (1, 'one', 0, 0, 0, 0, 0)",
    ];
    let expected = [
        Fence::DurabilityUnavailable,
        Fence::DurabilityUnavailable,
        Fence::HighWaterCorrupt,
        Fence::HighWaterCorrupt,
    ];
    for (corruption, expected) in corruptions.into_iter().zip(expected) {
        let directory = TempDir::new()?;
        let mut authority = initialized(&directory);
        let raw = Connection::open(authority_path(&directory))?;
        raw.execute_batch(corruption)?;
        let refused = reserve(&mut authority, T0).err();
        assert_eq!(refused, Some(expected));
    }
    Ok(())
}

#[test]
fn acknowledgement_rows_are_append_only() -> TestResult {
    let directory = TempDir::new()?;
    let path = authority_path(&directory);
    let _authority = SqliteTrustedClockAuthorityV1::open(&path)?;
    let raw = Connection::open(&path)?;
    raw.execute_batch(ACK_INSERT)?;
    let replace = ACK_INSERT.replace("INSERT", "INSERT OR REPLACE");
    let rewrites = [
        "UPDATE trusted_clock_overrun_acknowledgements SET reason_code = 2",
        "DELETE FROM trusted_clock_overrun_acknowledgements",
        replace.as_str(),
    ];
    for rewrite in rewrites {
        let refused = raw
            .execute_batch(rewrite)
            .err()
            .map(|error| error.to_string());
        let message = refused.unwrap_or_default();
        assert!(message.contains("append-only"), "{rewrite}: {message}");
    }
    assert_eq!(integer(&raw, ACK_SQL), 1);
    let reason = integer(
        &raw,
        "SELECT reason_code FROM trusted_clock_overrun_acknowledgements",
    );
    assert_eq!(reason, 1);
    raw.execute_batch(&ACK_INSERT.replace("(1,", "(2,"))?;
    let count = integer(
        &raw,
        "SELECT count(*) FROM trusted_clock_overrun_acknowledgements",
    );
    assert_eq!(count, 2);
    Ok(())
}

#[test]
fn a_weakened_acknowledgement_trigger_fails_reopen_closed() -> TestResult {
    let directory = TempDir::new()?;
    let path = authority_path(&directory);
    drop(SqliteTrustedClockAuthorityV1::open(&path)?);
    let raw = Connection::open(&path)?;
    raw.execute_batch(
        "DROP TRIGGER trusted_clock_overrun_acknowledgements_no_delete;
         CREATE TRIGGER trusted_clock_overrun_acknowledgements_no_delete
             BEFORE DELETE ON trusted_clock_overrun_acknowledgements
             WHEN 0
         BEGIN
             SELECT RAISE(ABORT, 'trusted_clock_overrun_acknowledgements is append-only');
         END;",
    )?;
    let reopened = SqliteTrustedClockAuthorityV1::open(&path).err();
    assert!(matches!(reopened, Some(CoreError::Storage(_))));
    raw.execute_batch(ACK_INSERT)?;
    raw.execute_batch("DELETE FROM trusted_clock_overrun_acknowledgements")?;
    let remaining = "SELECT count(*) FROM trusted_clock_overrun_acknowledgements";
    assert_eq!(integer(&raw, remaining), 0);
    Ok(())
}

#[test]
fn a_swapped_or_regressed_authority_is_detected_in_the_guard() -> TestResult {
    let edits = [
        "UPDATE trusted_clock_high_water SET clock_domain = randomblob(16)",
        "UPDATE trusted_clock_high_water SET reservation_seq = 0",
    ];
    for edit in edits {
        let directory = TempDir::new()?;
        let mut authority = initialized(&directory);
        let reservation = reserve(&mut authority, T0)?;
        let raw = Connection::open(authority_path(&directory))?;
        raw.execute_batch(edit)?;
        let refused = release(&mut authority, reservation, T0).err();
        assert_eq!(refused, Some(Fence::AuthorityRegressed));
    }
    Ok(())
}

#[test]
fn overrun_latch_and_acknowledgement_are_durable() -> TestResult {
    let directory = TempDir::new()?;
    let path = authority_path(&directory);
    let mut authority = SqliteTrustedClockAuthorityV1::open(&path)?;
    let mut scripted = mono(&[ZERO; 5]);
    scripted.push(Duration::from_secs(33));
    let reservation = reserve_on(&mut authority, T0, &mut scripted)?;
    let released = release_on(&mut authority, reservation, &[T0, T0], &mut scripted)?;
    assert!(released.overrun_signal().is_some());
    assert_eq!(commit_pending_overrun_latch(&mut authority), Ok(true));
    let raw = Connection::open(&path)?;
    assert_eq!(integer(&raw, LATCHED_SQL), 1);
    let refused = reserve(&mut authority, T0).err();
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
        reason: OverrunAckReasonV1::BenignStall,
    };
    let mut wall = ScriptedTrustedWallSourceV1::from_micros([T0]);
    acknowledge_trusted_clock_overrun(&mut authority, &mut wall, &request)?;
    assert_eq!(integer(&raw, LATCHED_SQL), 0);
    assert_eq!(integer(&raw, ACK_SQL), 1);
    let reservation = reserve(&mut authority, T0)?;
    let released = release(&mut authority, reservation, T0)?;
    assert_eq!(released.overrun_signal(), None);
    Ok(())
}
