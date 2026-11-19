//! The `recovery-peer` mode (ADR-069 R12 §5, invariant I16), as root in
//! the isolated container: the signed test SIC1 and SPI1 at their fixed
//! paths, a SIR1 whose previous-provider binding names the fixture's
//! runtime key, the fixed recovery directory and the fixed attempt registry.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ciborium::value::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::sandbox_provider_protocol::RevocationAcknowledgement;
use pos_reference::selector::installation::SANDBOX_ARTIFACT_ROOT;
use rustix::fs::{flock, FlockOperation};

use super::{endpoint_path, serve_with, RecoveryPeerError, RECOVERY_DIRECTORY, ROOT_UID};
use crate::provider_runtime::tests::{
    admitted, cancellation_context, encode, in_isolated_root, install_spi1, remove_spi1,
    revocation_update, revocation_update_revoking, spi1, TestResult, RUNTIME_SEED,
};
use crate::provider_runtime::ProviderRuntimeError;

/// The recovery endpoint ID the selector passes.
const ENDPOINT_ID: &str = "0123456789abcdef0123456789abcdef";
/// The fixture's SPM1 runtime-attestation key ID.
const KEY_ID: &str = "runtime";
const REGISTRY: &str = "/run/pigloros/sandbox/registry";

/// A distinct abstract manager name for each peer run.
static MANAGERS: AtomicUsize = AtomicUsize::new(0);

#[test]
fn the_endpoint_id_is_exactly_32_lowercase_hexadecimal_digits() -> TestResult {
    assert_eq!(
        endpoint_path(OsStr::new(ENDPOINT_ID))?,
        Path::new(RECOVERY_DIRECTORY).join(format!("{ENDPOINT_ID}.sock"))
    );
    let upper = ENDPOINT_ID.to_uppercase();
    let non_hex = format!("g{}", &ENDPOINT_ID[1..]);
    for refused in [
        OsStr::new(""),
        OsStr::new(&ENDPOINT_ID[1..]),
        OsStr::new(&upper),
        OsStr::new(&non_hex),
        OsStr::new("0123456789abcdef0123456789abcdef0"),
        OsStr::new("../../../../tmp/0123456789abcdef"),
        OsStr::from_bytes(&[0xff; 32]),
    ] {
        assert_eq!(
            endpoint_path(refused),
            Err(RecoveryPeerError::Arguments),
            "{refused:?}"
        );
        // Refused before anything is read or bound.
        assert_eq!(
            serve_with(refused, None, ROOT_UID),
            Err(RecoveryPeerError::Arguments)
        );
    }
    Ok(())
}

/// The bound recovery leaf.
fn leaf() -> PathBuf {
    Path::new(RECOVERY_DIRECTORY).join(format!("{ENDPOINT_ID}.sock"))
}

fn create_directory(path: &str, mode: u32) -> TestResult {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Write a SIR1 whose previous-provider binding names `public_key` under
/// the fixture's key ID, with its self-digest. The peer reads nothing else
/// from it.
fn write_sir1(public_key: [u8; 32]) -> TestResult {
    let bytes = |byte: u8, length: usize| Value::Bytes(vec![byte; length]);
    let int = |value: u64| Value::Integer(value.into());
    let unsigned = Value::Array(vec![
        Value::Text("SIR1".to_owned()),
        int(1),
        bytes(1, 8),
        bytes(2, 8),
        bytes(3, 8),
        Value::Array(vec![
            Value::Text("provider".to_owned()),
            bytes(4, 32),
            bytes(5, 32),
            bytes(6, 32),
            Value::Array(vec![
                Value::Text(KEY_ID.to_owned()),
                int(3),
                Value::Bytes(public_key.to_vec()),
                int(1),
            ]),
            bytes(7, 16),
            bytes(8, 16),
            int(100),
            int(200),
        ]),
        Value::Array(vec![bytes(9, 16), bytes(10, 16), bytes(11, 16)]),
        Value::Array(Vec::new()),
        Value::Array(Vec::new()),
    ]);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.SIR1.v1\0");
    hasher.update(&encode(&unsigned)?);
    let document = encode(&Value::Array(vec![
        unsigned,
        Value::Bytes(hasher.finalize().as_bytes().to_vec()),
    ]))?;
    let path = Path::new(SANDBOX_ARTIFACT_ROOT).join("installation-update.cbor");
    fs::write(&path, document)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

/// What one peer run did: its result, and every byte its client read.
type PeerRun = (Result<(), RecoveryPeerError>, Vec<u8>);

/// How the client ends its request.
#[derive(Clone, Copy)]
enum Client {
    /// It sends write EOF after its frames.
    Ends,
    /// It sends its frames and keeps its write side open.
    StaysOpen,
}

/// Run the peer accepting a peer of `uid`, wait for `READY=1`, set the
/// leaf's mode to `leaf_mode` if one is given, then connect and send
/// `frames`, ending as `client` does. A connection the peer refused, or
/// closed, reads nothing.
fn run_peer(
    uid: u32,
    frames: &[&[u8]],
    client: Client,
    leaf_mode: Option<u32>,
) -> TestResult<PeerRun> {
    let name = format!(
        "pigloros-recovery-peer-{}-{}",
        std::process::id(),
        MANAGERS.fetch_add(1, Ordering::SeqCst)
    );
    let manager = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name)?)?;
    manager.set_read_timeout(Some(Duration::from_secs(10)))?;
    let notify = OsString::from(format!("@{name}"));
    let peer = std::thread::spawn(move || serve_with(OsStr::new(ENDPOINT_ID), Some(&notify), uid));
    let mut ready = [0; 16];
    let length = manager.recv(&mut ready)?;
    assert_eq!(&ready[..length], b"READY=1");
    if let Some(mode) = leaf_mode {
        fs::set_permissions(leaf(), fs::Permissions::from_mode(mode))?;
    }
    let mut read = Vec::new();
    let mut request = Vec::new();
    for frame in frames {
        request.extend_from_slice(&u32::try_from(frame.len())?.to_be_bytes());
        request.extend_from_slice(frame);
    }
    if let Ok(mut stream) = UnixStream::connect(leaf()) {
        // A peer that refused the connection may already have closed it.
        stream.write_all(&request).ok();
        if matches!(client, Client::Ends) {
            stream.shutdown(std::net::Shutdown::Write).ok();
        }
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        match stream.read_to_end(&mut read) {
            Err(error) if error.kind() != ErrorKind::ConnectionReset => return Err(error.into()),
            _ => {}
        }
    }
    let outcome = peer.join().map_err(|_| "the recovery peer panicked")?;
    // The peer removes its own leaf when it exits.
    assert!(!leaf().exists());
    Ok((outcome, read))
}

/// The one RCA1 frame of `response`.
fn unframe(response: &[u8]) -> TestResult<&[u8]> {
    let (prefix, record) = response.split_at_checked(4).ok_or("no RCA1")?;
    assert_eq!(
        usize::try_from(u32::from_be_bytes(prefix.try_into()?))?,
        record.len()
    );
    Ok(record)
}

/// Steps 2 to 4: each refusal before the endpoint is bound, in order. On
/// return SIC1, SIR1, SPI1 and the recovery directory are in place.
fn refuses_before_binding() -> TestResult<VerifyingKey> {
    let serve = || serve_with(OsStr::new(ENDPOINT_ID), None, ROOT_UID);
    // Step 2: SIC1 without SIR1.
    assert!(matches!(
        serve(),
        Err(RecoveryPeerError::PendingRecovery(_))
    ));
    let runtime_key = SigningKey::from_bytes(&RUNTIME_SEED).verifying_key();
    write_sir1(runtime_key.to_bytes())?;
    // Step 3: no SPI1, then a key file that is not SIR1's key.
    assert!(matches!(
        serve(),
        Err(RecoveryPeerError::ProviderInstallation(_))
    ));
    install_spi1(&spi1(22)?, &[5; 32])?;
    assert_eq!(
        serve(),
        Err(RecoveryPeerError::ProviderInstallation(
            crate::ProviderInstallationError::KeyMismatch
        ))
    );
    remove_spi1()?;
    install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
    // Step 4: no recovery directory, then a node already at the leaf, which
    // is kept.
    let unsafe_endpoint = Err(RecoveryPeerError::Endpoint(
        ProviderRuntimeError::UnsafeEndpoint,
    ));
    assert_eq!(serve(), unsafe_endpoint);
    create_directory("/run/pigloros", 0o755)?;
    create_directory(RECOVERY_DIRECTORY, 0o700)?;
    fs::write(leaf(), b"")?;
    assert_eq!(serve(), unsafe_endpoint);
    assert!(fs::symlink_metadata(leaf())?.is_file());
    fs::remove_file(leaf())?;
    Ok(runtime_key)
}

/// Steps 6 and 7 that end without an RCA1: zero bytes for each.
fn refuses_without_an_acknowledgement(pair: &[&[u8]; 2]) -> TestResult {
    let refused = (Err(RecoveryPeerError::Refused), Vec::new());
    // The registry is missing, then held by a live owner, then holds a
    // record.
    assert_eq!(run_peer(ROOT_UID, pair, Client::Ends, None)?, refused);
    create_directory("/run/pigloros/sandbox", 0o700)?;
    create_directory(REGISTRY, 0o700)?;
    let held = File::open(REGISTRY)?;
    flock(&held, FlockOperation::NonBlockingLockExclusive)?;
    assert_eq!(run_peer(ROOT_UID, pair, Client::Ends, None)?, refused);
    drop(held);
    let intent = Path::new(REGISTRY).join("intent");
    fs::write(&intent, b"PAI1")?;
    assert_eq!(run_peer(ROOT_UID, pair, Client::Ends, None)?, refused);
    fs::remove_file(&intent)?;
    // A malformed exchange: RCC1 alone.
    assert_eq!(run_peer(ROOT_UID, &pair[..1], Client::Ends, None)?, refused);
    // A client that sends nothing and keeps its stream open is refused at
    // the 100 ms exchange deadline.
    let started = Instant::now();
    assert_eq!(run_peer(ROOT_UID, &[], Client::StaysOpen, None)?, refused);
    assert!(started.elapsed() < Duration::from_secs(5));
    // A connection that is not from root, and a leaf that changed after
    // readiness.
    assert_eq!(
        run_peer(4_242, &[], Client::Ends, None)?,
        (Err(RecoveryPeerError::ForeignPeer), Vec::new())
    );
    assert_eq!(
        run_peer(ROOT_UID, pair, Client::Ends, Some(0o644))?,
        (
            Err(RecoveryPeerError::Endpoint(
                ProviderRuntimeError::UnsafeEndpoint
            )),
            Vec::new()
        )
    );
    Ok(())
}

#[test]
fn the_recovery_peer_answers_one_exchange_of_the_pending_sir1() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::recovery_peer::tests::the_recovery_peer_answers_one_exchange_of_the_pending_sir1",
    )? {
        return Ok(());
    }
    // Step 2: no SIC1.
    assert!(matches!(
        serve_with(OsStr::new(ENDPOINT_ID), None, ROOT_UID),
        Err(RecoveryPeerError::PendingRecovery(_))
    ));
    let staged = StagedInstallation::stage()?;
    let admitted = admitted()?;
    let runtime_key = refuses_before_binding()?;
    let (update, next) = revocation_update(&admitted, &[], 1)?;
    let context = cancellation_context(&admitted, &update, vec![[5; 16]], vec![[5; 16]])?;
    let context_bytes = context.to_canonical_cbor()?;
    let pair = [context_bytes.as_slice(), update.as_slice()];
    refuses_without_an_acknowledgement(&pair)?;
    // No connection within the R12 §7.3 start bound: the peer exits.
    let started = Instant::now();
    assert_eq!(
        serve_with(OsStr::new(ENDPOINT_ID), None, ROOT_UID),
        Err(RecoveryPeerError::Endpoint(
            ProviderRuntimeError::EndpointUnavailable
        ))
    );
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert!(!leaf().exists());
    // Step 7: the exchange is acknowledged under SIR1's runtime key, with the
    // registry's activation marker present, and the lock is free again.
    fs::write(Path::new(REGISTRY).join("activation"), b"")?;
    let (outcome, read) = run_peer(ROOT_UID, &pair, Client::Ends, None)?;
    assert_eq!(outcome, Ok(()));
    assert!(!read.is_empty(), "the acknowledged exchange wrote no RCA1");
    let acknowledgement = RevocationAcknowledgement::authenticate_for_context(
        unframe(&read)?,
        KEY_ID,
        &runtime_key,
        &context,
        [70; 16],
        next,
    )?;
    assert_eq!(acknowledgement.cancelled_attempt_ids(), [[5; 16]]);
    // R12 §5.6: the next RVS1 revokes SIR1's runtime key, and the RCA1 is
    // still signed under it and authenticates.
    let (revoking, next) = revocation_update_revoking(&admitted, &[KEY_ID], &[], 2)?;
    let context = cancellation_context(&admitted, &revoking, Vec::new(), Vec::new())?;
    let context_bytes = context.to_canonical_cbor()?;
    let (outcome, read) = run_peer(
        ROOT_UID,
        &[context_bytes.as_slice(), revoking.as_slice()],
        Client::Ends,
        None,
    )?;
    assert_eq!(outcome, Ok(()));
    assert!(!read.is_empty(), "the revoking exchange wrote no RCA1");
    RevocationAcknowledgement::authenticate_for_context(
        unframe(&read)?,
        KEY_ID,
        &runtime_key,
        &context,
        [70; 16],
        next,
    )?;
    flock(
        &File::open(REGISTRY)?,
        FlockOperation::NonBlockingLockExclusive,
    )?;
    drop(staged);
    Ok(())
}
