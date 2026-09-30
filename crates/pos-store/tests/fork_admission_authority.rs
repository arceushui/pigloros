use std::error::Error;

use pos_core::{clock::FixedAdmissionClock, Hash, PublicKey, Signature, WallTime};
use pos_crypto::fork_authentication::ForkHostSigningKeyV1;
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkAdmissionAuthorityBootstrapPortV1,
    ForkAdmissionAuthorityErrorV1, ForkAdmissionAuthoritySessionV1,
};
use rusqlite::Connection;

const HOST_SEED: [u8; 32] = [7; 32];
const POLICY_DIGEST: Hash = Hash::from_bytes([9; 32]);

fn bootstrap<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    signer: &ForkHostSigningKeyV1,
) -> Result<(), Box<dyn Error>> {
    let host_key = PublicKey::from_bytes(signer.public_key());
    let initialize = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let initialize_bytes = initialize.to_canonical_cbor()?;
    let initialize_signature = signer.sign_initialize(&initialize_bytes)?;
    let record = store.finalize_fork_admission_initialize(&initialize, &initialize_signature)?;
    assert_eq!(record.host_verifying_key(), host_key);
    assert_eq!(record.authentication_policy_digest(), POLICY_DIGEST);
    assert_eq!(
        store.begin_fork_admission_initialize(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized)
    );
    Ok(())
}

fn open_and_fence<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    signer: &ForkHostSigningKeyV1,
) -> Result<(), Box<dyn Error>> {
    let host_key = PublicKey::from_bytes(signer.public_key());
    let open = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let open_bytes = open.to_canonical_cbor()?;
    let open_signature = signer.sign_open(&open_bytes)?;
    let session = store.finalize_fork_admission_open(&open, &open_signature)?;
    store.advance_fork_admission_wall_fence(&session)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&open, &open_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    Ok(())
}

#[test]
fn public_session_identity_binds_complete_fao1_and_signature() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = MemoryStore::new();
    bootstrap(&mut store, &signer)?;
    let open = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_open(&open.canonical_bytes())?;
    let session = store.finalize_fork_admission_open(&open, &signature)?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros/fork-admission-session/v1");
    hasher.update(&open.canonical_bytes());
    hasher.update(signature.as_bytes());
    assert_eq!(
        session.identity(),
        Hash::from_bytes(*hasher.finalize().as_bytes())
    );
    store.advance_fork_admission_wall_fence(&session)?;
    Ok(())
}

#[test]
fn memory_bootstrap_open_is_one_use_and_fenced() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let mut store = MemoryStore::new();
    bootstrap(&mut store, &signer)?;
    open_and_fence(&mut store, &signer)
}

#[test]
fn public_custom_clock_cannot_bootstrap_authority() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let mut store =
        MemoryStore::with_clock(Box::new(FixedAdmissionClock(WallTime::from_micros(1))));
    assert_eq!(
        store.begin_fork_admission_initialize(
            PublicKey::from_bytes(signer.public_key()),
            POLICY_DIGEST
        ),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    );
    Ok(())
}

#[test]
fn public_authority_record_is_unavailable_before_bootstrap() -> Result<(), Box<dyn Error>> {
    let store = MemoryStore::new();
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    );
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let store = SqliteStore::open(&path.to_string_lossy())?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    );
    Ok(())
}

#[test]
fn sqlite_reopen_retains_host_and_fence() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    {
        let mut store = SqliteStore::open(&path)?;
        bootstrap(&mut store, &signer)?;
        open_and_fence(&mut store, &signer)?;
    }
    let mut reopened = SqliteStore::open(&path)?;
    assert_eq!(
        reopened
            .fork_admission_host_record()?
            .authentication_policy_digest(),
        POLICY_DIGEST
    );
    let host_key = PublicKey::from_bytes(signer.public_key());
    let open = reopened.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_open(&open.to_canonical_cbor()?)?;
    let session = reopened.finalize_fork_admission_open(&open, &signature)?;
    reopened.advance_fork_admission_wall_fence(&session)?;
    Ok(())
}

#[test]
fn rejected_initialize_consumes_the_issued_challenge() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = MemoryStore::new();
    let issued = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let substituted = pos_core::ForkAdmissionInitializeChallengeV1::new(
        Hash::from_bytes([8; 32]),
        issued.initialization_nonce(),
        host_key,
        POLICY_DIGEST,
    )?;
    let substitution_signature = signer.sign_initialize(&substituted.to_canonical_cbor()?)?;
    assert_eq!(
        store.finalize_fork_admission_initialize(&substituted, &substitution_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    let valid_signature = signer.sign_initialize(&issued.to_canonical_cbor()?)?;
    assert_eq!(
        store.finalize_fork_admission_initialize(&issued, &valid_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    Ok(())
}

#[test]
fn rejected_open_consumes_the_issued_challenge() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = MemoryStore::new();
    bootstrap(&mut store, &signer)?;
    let issued = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let substituted = pos_core::ForkAdmissionOpenChallengeV1::new(
        Hash::from_bytes([8; 32]),
        issued.open_nonce(),
        POLICY_DIGEST,
    )?;
    let substitution_signature = signer.sign_open(&substituted.to_canonical_cbor()?)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&substituted, &substitution_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    let valid_signature = signer.sign_open(&issued.to_canonical_cbor()?)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&issued, &valid_signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    Ok(())
}

#[test]
fn sqlite_handle_cannot_consume_another_handles_challenge() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut issuer = SqliteStore::open(&path)?;
    let mut foreign = SqliteStore::open(&path)?;
    let challenge = issuer.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.to_canonical_cbor()?)?;
    assert_eq!(
        foreign.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    issuer.finalize_fork_admission_initialize(&challenge, &signature)?;
    Ok(())
}

fn rejects_mismatched_open_and_consumes_bad_proof<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    signer: &ForkHostSigningKeyV1,
) -> Result<(), Box<dyn Error>> {
    bootstrap(store, signer)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    assert_eq!(
        store.begin_fork_admission_open(host_key, Hash::from_bytes([8; 32])),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    let challenge = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&challenge, &Signature::from_bytes([0; 64])),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    let signature = signer.sign_open(&challenge.to_canonical_cbor()?)?;
    assert!(matches!(
        store.finalize_fork_admission_open(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    ));
    Ok(())
}

#[test]
fn memory_open_rejects_mismatch_and_bad_proof() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let mut store = MemoryStore::new();
    rejects_mismatched_open_and_consumes_bad_proof(&mut store, &signer)
}

#[test]
fn sqlite_open_rejects_mismatch_and_bad_proof() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let mut store = SqliteStore::open(&path.to_string_lossy())?;
    rejects_mismatched_open_and_consumes_bad_proof(&mut store, &signer)
}

#[test]
fn sqlite_authority_lifecycle_rejects_corruption_and_stale_sessions() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, &signer)?;

    let first = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let first_signature = signer.sign_open(&first.to_canonical_cbor()?)?;
    let first_session = store.finalize_fork_admission_open(&first, &first_signature)?;
    let second = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let second_signature = signer.sign_open(&second.to_canonical_cbor()?)?;
    let second_session = store.finalize_fork_admission_open(&second, &second_signature)?;
    assert_eq!(
        store.advance_fork_admission_wall_fence(&first_session),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    store.advance_fork_admission_wall_fence(&second_session)?;
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET fah1_cbor = X'00' WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    let store = SqliteStore::open(&path)?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET fah1_cbor = NULL, last_authority_wall_time = -1 \
         WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    let store = SqliteStore::open(&path)?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_authority_finalize_rolls_back_a_rejected_durable_host_write() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = SqliteStore::open(&path)?;
    let challenge = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.to_canonical_cbor()?)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER reject_fork_admission_insert
         BEFORE INSERT ON fork_admission_authority
         BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
    )?;
    drop(connection);

    assert_eq!(
        store.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::StorageIndeterminate)
    );
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute_batch("DROP TRIGGER reject_fork_admission_insert")?;
    drop(connection);
    let mut reopened = SqliteStore::open(&path)?;
    let retry = reopened.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let retry_signature = signer.sign_initialize(&retry.to_canonical_cbor()?)?;
    reopened.finalize_fork_admission_initialize(&retry, &retry_signature)?;
    Ok(())
}

#[test]
fn public_authority_paths_fail_closed_without_a_production_clock() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let initialize = pos_core::ForkAdmissionInitializeChallengeV1::new(
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
        host_key,
        POLICY_DIGEST,
    )?;
    let initialize_signature = signer.sign_initialize(&initialize.canonical_bytes())?;
    let open = pos_core::ForkAdmissionOpenChallengeV1::new(
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
        POLICY_DIGEST,
    )?;
    let open_signature = signer.sign_open(&open.canonical_bytes())?;
    let mut disabled =
        MemoryStore::with_clock(Box::new(FixedAdmissionClock(WallTime::from_micros(1))));
    assert_eq!(
        disabled.finalize_fork_admission_initialize(&initialize, &initialize_signature),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    );
    assert_eq!(
        disabled.begin_fork_admission_open(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    );
    assert!(matches!(
        disabled.finalize_fork_admission_open(&open, &open_signature),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    ));

    let mut enabled = MemoryStore::new();
    bootstrap(&mut enabled, &signer)?;
    let challenge = enabled.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let session = enabled.finalize_fork_admission_open(
        &challenge,
        &signer.sign_open(&challenge.canonical_bytes())?,
    )?;
    assert_eq!(
        disabled.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityClockUnavailable)
    );
    Ok(())
}

#[test]
fn public_authority_paths_reject_missing_state_and_clock_rollback() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut empty = MemoryStore::new();
    assert_eq!(
        empty.begin_fork_admission_open(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    );
    let open = pos_core::ForkAdmissionOpenChallengeV1::new(
        Hash::from_bytes([1; 32]),
        Hash::from_bytes([2; 32]),
        POLICY_DIGEST,
    )?;
    assert!(matches!(
        empty.finalize_fork_admission_open(&open, &signer.sign_open(&open.canonical_bytes())?),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    ));

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, &signer)?;
    let challenge = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let session = store.finalize_fork_admission_open(
        &challenge,
        &signer.sign_open(&challenge.canonical_bytes())?,
    )?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET last_authority_wall_time = ?1 WHERE singleton = 1",
        [i64::MAX],
    )?;
    drop(connection);
    assert_eq!(
        store.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::ClockRollback)
    );
    Ok(())
}

#[test]
fn sqlite_authority_methods_fail_closed_when_durable_state_is_unreadable(
) -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, &signer)?;
    let open = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let session =
        store.finalize_fork_admission_open(&open, &signer.sign_open(&open.canonical_bytes())?)?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET fah1_cbor = 1 WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    assert_eq!(
        store.begin_fork_admission_open(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert!(matches!(
        store.finalize_fork_admission_open(&open, &signer.sign_open(&open.canonical_bytes())?),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    ));
    assert_eq!(
        store.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn sqlite_authority_initialize_paths_fail_closed_on_durable_state_errors(
) -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    let challenge = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "INSERT INTO fork_admission_authority (singleton, fah1_cbor, last_authority_wall_time) \
         VALUES (1, 1, 0)",
        [],
    )?;
    drop(connection);
    assert_eq!(
        store.begin_fork_admission_initialize(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert_eq!(
        store.finalize_fork_admission_initialize(
            &challenge,
            &signer.sign_initialize(&challenge.canonical_bytes())?
        ),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn public_authority_bootstrap_rejects_invalid_inputs_and_reused_initialization(
) -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut store = MemoryStore::new();

    assert_eq!(
        store.begin_fork_admission_initialize(PublicKey::from_bytes([0; 32]), POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    let challenge = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.canonical_bytes())?;
    store.finalize_fork_admission_initialize(&challenge, &signature)?;
    assert_eq!(
        store.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized)
    );

    let mut rejected = MemoryStore::new();
    let challenge = rejected.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    assert_eq!(
        rejected.finalize_fork_admission_initialize(&challenge, &Signature::from_bytes([0; 64])),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    Ok(())
}

#[test]
fn public_authority_fence_rejects_empty_and_unopened_sessions() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let mut issuer = MemoryStore::new();
    bootstrap(&mut issuer, &signer)?;
    let challenge = issuer.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let session = issuer.finalize_fork_admission_open(
        &challenge,
        &signer.sign_open(&challenge.canonical_bytes())?,
    )?;

    let mut empty = MemoryStore::new();
    assert_eq!(
        empty.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    );

    let mut unopened = MemoryStore::new();
    bootstrap(&mut unopened, &signer)?;
    assert_eq!(
        unopened.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    Ok(())
}

#[test]
fn sqlite_authority_fails_closed_for_malformed_rows_and_lock_contention(
) -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, &signer)?;
    drop(store);

    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE fork_admission_authority SET last_authority_wall_time = 'not-an-integer' \
         WHERE singleton = 1",
        [],
    )?;
    drop(connection);
    let store = SqliteStore::open(&path)?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    drop(store);

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission-lock.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    let lock = Connection::open(&path)?;
    lock.execute_batch("BEGIN EXCLUSIVE")?;
    assert_eq!(
        store.begin_fork_admission_initialize(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::StorageIndeterminate)
    );
    lock.execute_batch("ROLLBACK")?;
    Ok(())
}

fn open_session<S: ForkAdmissionAuthorityBootstrapPortV1>(
    store: &mut S,
    signer: &ForkHostSigningKeyV1,
) -> Result<ForkAdmissionAuthoritySessionV1, Box<dyn Error>> {
    let host_key = PublicKey::from_bytes(signer.public_key());
    let open = store.begin_fork_admission_open(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_open(&open.canonical_bytes())?;
    Ok(store.finalize_fork_admission_open(&open, &signature)?)
}

fn stored_fah1(path: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    Ok(Connection::open(path)?.query_row(
        "SELECT fah1_cbor FROM fork_admission_authority WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?)
}

fn bootstrapped_sqlite(
    directory: &tempfile::TempDir,
    signer: &ForkHostSigningKeyV1,
) -> Result<(SqliteStore, String), Box<dyn Error>> {
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    bootstrap(&mut store, signer)?;
    Ok((store, path))
}

#[test]
fn sqlite_malformed_column_types_are_corrupt_authority() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    for update in [
        "UPDATE fork_admission_authority SET fah1_cbor = 'text' WHERE singleton = 1",
        "UPDATE fork_admission_authority SET fah1_cbor = 1 WHERE singleton = 1",
        "UPDATE fork_admission_authority SET last_authority_wall_time = 1.5 WHERE singleton = 1",
        "UPDATE fork_admission_authority SET last_authority_wall_time = X'01' WHERE singleton = 1",
    ] {
        let directory = tempfile::tempdir()?;
        let (store, path) = bootstrapped_sqlite(&directory, &signer)?;
        Connection::open(&path)?.execute(update, [])?;
        assert_eq!(
            store.fork_admission_host_record(),
            Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority),
            "{update}"
        );
    }
    Ok(())
}

#[test]
fn sqlite_null_fah1_row_is_corrupt_and_never_overwritten() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut store = SqliteStore::open(&path)?;
    let challenge = store.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.canonical_bytes())?;
    Connection::open(&path)?.execute(
        "INSERT INTO fork_admission_authority (singleton, fah1_cbor, last_authority_wall_time) \
         VALUES (1, NULL, 0)",
        [],
    )?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert_eq!(
        store.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert_eq!(
        store.begin_fork_admission_initialize(host_key, POLICY_DIGEST),
        Err(ForkAdmissionAuthorityErrorV1::CorruptAuthority)
    );
    assert_eq!(stored_fah1(&path)?, None);
    Ok(())
}

#[test]
fn sqlite_fence_advance_never_rewrites_fah1() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let directory = tempfile::tempdir()?;
    let (mut store, path) = bootstrapped_sqlite(&directory, &signer)?;
    let fah1 = store.fork_admission_host_record()?.canonical_bytes();
    let session = open_session(&mut store, &signer)?;
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER immutable_fah1
         BEFORE UPDATE OF fah1_cbor ON fork_admission_authority
         BEGIN SELECT RAISE(ABORT, 'FAH1 is immutable'); END;",
    )?;
    store.advance_fork_admission_wall_fence(&session)?;
    assert_eq!(stored_fah1(&path)?, Some(fah1));

    connection.execute_batch(
        "CREATE TRIGGER reject_fence
         BEFORE UPDATE ON fork_admission_authority
         BEGIN SELECT RAISE(ABORT, 'rejected'); END;",
    )?;
    assert_eq!(
        store.advance_fork_admission_wall_fence(&session),
        Err(ForkAdmissionAuthorityErrorV1::StorageIndeterminate)
    );
    Ok(())
}

#[test]
fn sqlite_unreadable_authority_table_is_storage_indeterminate() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let directory = tempfile::tempdir()?;
    let (store, path) = bootstrapped_sqlite(&directory, &signer)?;
    Connection::open(&path)?.execute_batch("DROP TABLE fork_admission_authority")?;
    assert_eq!(
        store.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::StorageIndeterminate)
    );
    Ok(())
}

#[test]
fn already_initialized_finalize_consumes_the_outstanding_challenge() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let host_key = PublicKey::from_bytes(signer.public_key());
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fork-admission.db");
    let path = path.to_string_lossy().into_owned();
    let mut stale = SqliteStore::open(&path)?;
    let mut winner = SqliteStore::open(&path)?;
    let challenge = stale.begin_fork_admission_initialize(host_key, POLICY_DIGEST)?;
    let signature = signer.sign_initialize(&challenge.canonical_bytes())?;
    bootstrap(&mut winner, &signer)?;
    assert_eq!(
        stale.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityAlreadyInitialized)
    );

    // Even if the durable row later disappears, the rejected FAI1 stays spent.
    Connection::open(&path)?.execute_batch("DELETE FROM fork_admission_authority")?;
    assert_eq!(
        stale.finalize_fork_admission_initialize(&challenge, &signature),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    assert_eq!(
        stale.fork_admission_host_record(),
        Err(ForkAdmissionAuthorityErrorV1::AuthorityUninitialized)
    );
    Ok(())
}

#[test]
fn sqlite_reopen_rejects_a_different_host_key_and_prior_sessions() -> Result<(), Box<dyn Error>> {
    let signer = ForkHostSigningKeyV1::from_seed(HOST_SEED)?;
    let other_signer = ForkHostSigningKeyV1::from_seed([8; 32])?;
    let directory = tempfile::tempdir()?;
    let (mut store, path) = bootstrapped_sqlite(&directory, &signer)?;
    let prior_session = open_session(&mut store, &signer)?;
    store.advance_fork_admission_wall_fence(&prior_session)?;
    drop(store);

    let mut reopened = SqliteStore::open(&path)?;
    assert_eq!(
        reopened.begin_fork_admission_open(
            PublicKey::from_bytes(other_signer.public_key()),
            POLICY_DIGEST
        ),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    assert_eq!(
        reopened.advance_fork_admission_wall_fence(&prior_session),
        Err(ForkAdmissionAuthorityErrorV1::HostAuthorityMismatch)
    );
    let session = open_session(&mut reopened, &signer)?;
    reopened.advance_fork_admission_wall_fence(&session)?;
    Ok(())
}
