//! Public durable capture-retention and offline Replay seam of ADR-069 section 7.
#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs::{self, File};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    NetworkCaptureStore, NetworkCaptureStoreError, NetworkExchangeFailure, NetworkExchangePlan,
    NetworkExchangeReply, NetworkExchangeRequest, NetworkRetentionPolicy,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUEST: &[u8] = b"request";
const RESPONSE: &[u8] = b"response";
const ATTEMPT: [u8; 16] = [9; 16];

#[test]
fn persist_retains_exact_content_addressed_records_for_offline_replay() -> TestResult {
    let root = tempfile::tempdir()?;
    let plan = plan(0, REQUEST, RESPONSE)?;
    let reply = captured(&plan, REQUEST, RESPONSE)?;
    let transcript = reply
        .transcript()
        .ok_or("captured reply has a transcript")?;
    NetworkCaptureStore::open(&File::open(root.path())?)?.persist(&reply)?;

    let response_path = root
        .path()
        .join("responses")
        .join(hex(&hash(b"PiglorOS.NetworkResponseBytes.v1\0", RESPONSE)));
    let transcript_path = root
        .path()
        .join("transcripts")
        .join(hex(&transcript.digest()));
    assert_eq!(fs::read(&response_path)?, RESPONSE);
    assert_eq!(fs::read(&transcript_path)?, transcript.to_canonical_cbor()?);
    for path in [&response_path, &transcript_path] {
        assert_eq!(mode(path)?, 0o400);
    }
    for directory in ["responses", "transcripts"] {
        let directory = root.path().join(directory);
        assert_eq!(mode(&directory)?, 0o700);
        assert_eq!(entries(&directory)?, 1);
    }

    // A fresh store over the same root resolves the capture with no live I/O.
    let store = NetworkCaptureStore::open(&File::open(root.path())?)?;
    let replayed = store.replay(ATTEMPT, &plan, transcript.digest())?;
    assert_eq!(replayed.transcript(), transcript);
    assert_eq!(replayed.response_bytes(), RESPONSE);
    Ok(())
}

#[test]
fn persist_is_idempotent_and_shares_identical_response_artifacts() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = NetworkCaptureStore::open(&File::open(root.path())?)?;
    let first_plan = plan(0, REQUEST, RESPONSE)?;
    let second_plan = plan(1, REQUEST, RESPONSE)?;
    let first = captured(&first_plan, REQUEST, RESPONSE)?;
    let second = captured(&second_plan, REQUEST, RESPONSE)?;
    for reply in [&first, &first, &second] {
        store.persist(reply)?;
    }
    // Repeated occurrences keep distinct transcripts but one response artifact,
    // and no temporary file survives a duplicate publication.
    assert_eq!(entries(&root.path().join("responses"))?, 1);
    assert_eq!(entries(&root.path().join("transcripts"))?, 2);
    for (plan, reply) in [(&first_plan, &first), (&second_plan, &second)] {
        let digest = reply.transcript().ok_or("transcript")?.digest();
        assert_eq!(
            store.replay(ATTEMPT, plan, digest)?.response_bytes(),
            RESPONSE
        );
    }
    Ok(())
}

#[test]
fn empty_responses_are_retained_and_replayed() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = NetworkCaptureStore::open(&File::open(root.path())?)?;
    let plan = plan(0, b"", b"")?;
    let reply = captured(&plan, b"", b"")?;
    store.persist(&reply)?;
    let digest = reply.transcript().ok_or("transcript")?.digest();
    assert!(store
        .replay(ATTEMPT, &plan, digest)?
        .response_bytes()
        .is_empty());
    Ok(())
}

#[test]
fn failure_replies_never_become_retained_evidence() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = NetworkCaptureStore::open(&File::open(root.path())?)?;
    let request = NetworkExchangeRequest::new(&plan(0, REQUEST, RESPONSE)?, REQUEST)?;
    for failure in [
        NetworkExchangeFailure::RemoteUnavailable,
        NetworkExchangeFailure::DigestMismatch,
    ] {
        let error = store
            .persist(&request.failed(failure))
            .err()
            .ok_or("a failure reply must not persist")?;
        assert!(error.to_string().contains("no captured response"));
    }
    for directory in ["responses", "transcripts"] {
        assert_eq!(entries(&root.path().join(directory))?, 0);
    }
    Ok(())
}

#[test]
fn persist_rejects_conflicting_or_overlong_retained_records() -> TestResult {
    let plan = plan(0, REQUEST, RESPONSE)?;
    let reply = captured(&plan, REQUEST, RESPONSE)?;
    let transcript = reply.transcript().ok_or("transcript")?;
    let response_name = hex(&hash(b"PiglorOS.NetworkResponseBytes.v1\0", RESPONSE));
    let mut overlong = RESPONSE.to_vec();
    overlong.push(b'!');
    let mut record = transcript.to_canonical_cbor()?;
    record[3] ^= 1;
    for (directory, name, planted) in [
        ("responses", response_name.clone(), b"respons!".to_vec()),
        ("responses", response_name, overlong),
        ("transcripts", hex(&transcript.digest()), record),
    ] {
        let root = tempfile::tempdir()?;
        let store = NetworkCaptureStore::open(&File::open(root.path())?)?;
        let path = root.path().join(directory).join(name);
        fs::write(&path, &planted)?;
        let error = store
            .persist(&reply)
            .err()
            .ok_or("a conflicting record must not be accepted")?;
        assert!(error.to_string().contains("differs from the new capture"));
        // The retained record is never replaced and no temporary file remains.
        assert_eq!(fs::read(&path)?, planted);
        assert_eq!(entries(&root.path().join(directory))?, 1);
    }
    Ok(())
}

#[test]
fn replay_is_unavailable_for_missing_foreign_or_altered_captures() -> TestResult {
    let root = tempfile::tempdir()?;
    let store = NetworkCaptureStore::open(&File::open(root.path())?)?;
    let plan = plan(0, REQUEST, RESPONSE)?;
    let reply = captured(&plan, REQUEST, RESPONSE)?;
    let digest = reply.transcript().ok_or("transcript")?.digest();
    assert_unavailable(store.replay(ATTEMPT, &plan, digest))?;
    store.persist(&reply)?;
    store.replay(ATTEMPT, &plan, digest)?;

    let mut foreign_digest = digest;
    foreign_digest[0] ^= 1;
    let mut changed_plan = plan.clone();
    changed_plan.plan_digest[0] ^= 1;
    for (attempt, plan, digest) in [
        ([8; 16], plan.clone(), digest),
        (ATTEMPT, self::plan(1, REQUEST, RESPONSE)?, digest),
        (ATTEMPT, changed_plan, digest),
        (ATTEMPT, plan.clone(), foreign_digest),
    ] {
        assert_unavailable(store.replay(attempt, &plan, digest))?;
    }

    // A valid record retained under a name its report did not authorize.
    let transcripts = root.path().join("transcripts");
    fs::copy(
        transcripts.join(hex(&digest)),
        transcripts.join(hex(&foreign_digest)),
    )?;
    assert_unavailable(store.replay(ATTEMPT, &plan, foreign_digest))?;

    let response = root
        .path()
        .join("responses")
        .join(hex(&hash(b"PiglorOS.NetworkResponseBytes.v1\0", RESPONSE)));
    for altered in [
        b"respons!".as_slice(),
        b"responses".as_slice(),
        b"".as_slice(),
    ] {
        replace(&response, altered)?;
        assert_unavailable(store.replay(ATTEMPT, &plan, digest))?;
    }
    replace(&response, RESPONSE)?;
    store.replay(ATTEMPT, &plan, digest)?;
    let transcript = transcripts.join(hex(&digest));
    let record = fs::read(&transcript)?;
    replace(&transcript, &record[..record.len() - 1])?;
    assert_unavailable(store.replay(ATTEMPT, &plan, digest))?;
    fs::remove_file(&transcript)?;
    symlink(transcripts.join(hex(&foreign_digest)), &transcript)?;
    assert_unavailable(store.replay(ATTEMPT, &plan, digest))?;
    Ok(())
}

#[test]
fn open_rejects_unsafe_roots_and_retention_directories() -> TestResult {
    let root = tempfile::tempdir()?;
    for permitted in [0o700, 0o750, 0o755] {
        fs::set_permissions(root.path(), fs::Permissions::from_mode(permitted))?;
        NetworkCaptureStore::open(&File::open(root.path())?)?;
    }
    for unsafe_mode in [0o720, 0o702, 0o777] {
        fs::set_permissions(root.path(), fs::Permissions::from_mode(unsafe_mode))?;
        assert_unsafe(NetworkCaptureStore::open(&File::open(root.path())?))?;
    }
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    let file = root.path().join("file");
    fs::write(&file, b"")?;
    assert_unsafe(NetworkCaptureStore::open(&File::open(&file)?))?;

    for directory in ["responses", "transcripts"] {
        let path = root.path().join(directory);
        for unsafe_mode in [0o755, 0o750, 0o600] {
            fs::set_permissions(&path, fs::Permissions::from_mode(unsafe_mode))?;
            assert_unsafe(NetworkCaptureStore::open(&File::open(root.path())?))?;
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
    NetworkCaptureStore::open(&File::open(root.path())?)?;

    // Retention directories are never followed through links or replaced by files.
    let elsewhere = tempfile::tempdir()?;
    for directory in ["responses", "transcripts"] {
        let root = tempfile::tempdir()?;
        symlink(elsewhere.path(), root.path().join(directory))?;
        assert_io(NetworkCaptureStore::open(&File::open(root.path())?))?;
        let root = tempfile::tempdir()?;
        fs::write(root.path().join(directory), b"")?;
        assert_io(NetworkCaptureStore::open(&File::open(root.path())?))?;
    }
    assert_eq!(entries(elsewhere.path())?, 0);
    Ok(())
}

fn captured(
    plan: &NetworkExchangePlan,
    request: &[u8],
    response: &[u8],
) -> TestResult<NetworkExchangeReply> {
    Ok(NetworkExchangeRequest::new(plan, request)?.capture(ATTEMPT, response)?)
}

fn assert_unavailable<T>(result: Result<T, NetworkCaptureStoreError>) -> TestResult {
    let error = result.err().ok_or("Replay must be unavailable")?;
    assert!(error.to_string().contains("unavailable for Replay"));
    Ok(())
}

fn assert_unsafe<T>(result: Result<T, NetworkCaptureStoreError>) -> TestResult {
    let error = result.err().ok_or("an unsafe store must not open")?;
    assert!(error.to_string().contains("unsafe network capture store"));
    Ok(())
}

fn assert_io<T>(result: Result<T, NetworkCaptureStoreError>) -> TestResult {
    let error = result
        .err()
        .ok_or("an unsafe retention directory must not open")?;
    assert!(error.to_string().contains("I/O failed"));
    assert!(error.source().is_some());
    Ok(())
}

fn replace(path: &Path, bytes: &[u8]) -> TestResult {
    fs::remove_file(path)?;
    fs::write(path, bytes)?;
    Ok(())
}

fn entries(directory: &Path) -> TestResult<usize> {
    Ok(fs::read_dir(directory)?.count())
}

fn mode(path: &Path) -> TestResult<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o7777)
}

fn plan(occurrence: u64, request: &[u8], response: &[u8]) -> TestResult<NetworkExchangePlan> {
    let mut value = NetworkExchangePlan {
        exchange_id: [4; 16],
        occurrence,
        capability_id: "exact-endpoint".to_owned(),
        request_length: request.len() as u64,
        request_digest: hash(b"PiglorOS.NetworkRequestBytes.v1\0", request),
        response_maximum: (response.len() as u64).max(1),
        expected_response_digest: hash(b"PiglorOS.NetworkResponseBytes.v1\0", response),
        retention_policy_digest: NetworkRetentionPolicy::RetainIndefinitely.digest()?,
        plan_digest: [0; 32],
    };
    let fields = Value::Array(vec![
        text("NXP1"),
        uint(1),
        bytes(&value.exchange_id),
        uint(value.occurrence),
        text(&value.capability_id),
        uint(value.request_length),
        bytes(&value.request_digest),
        uint(value.response_maximum),
        bytes(&value.expected_response_digest),
        bytes(&value.retention_policy_digest),
    ]);
    let mut encoded = Vec::new();
    ciborium::into_writer(&fields, &mut encoded)?;
    value.plan_digest = hash(b"PiglorOS.NetworkExchangePlan.v1\0", &encoded);
    Ok(value)
}

fn hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let preimage: Vec<_> = domain.iter().chain(payload).copied().collect();
    *blake3::hash(&preimage).as_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(b"0123456789abcdef"[usize::from(nibble)]))
        .collect()
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
