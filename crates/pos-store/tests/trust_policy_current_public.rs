//! Public seam of the authenticated current-TPS1 read on the #448
//! deployment trust state store (ADR-136 §4: Gateway consumption of the
//! profile's TPS1 anchor).
#![cfg(all(feature = "sqlite", target_os = "linux"))]

use ed25519_dalek::{Signer, SigningKey};
use pos_conformance::TrustPolicySnapshotV1;
use pos_store::trust_policy_registry::{
    tps1_signed_by_operator_v1, DeploymentTrustPolicyRegistryV1, OperatorReleaseTrustV1,
    TrustPolicyRegistryErrorV1,
};
use std::path::Path;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn operator() -> SigningKey {
    SigningKey::from_bytes(&[41; 32])
}

fn signed(mut snapshot: TrustPolicySnapshotV1) -> TestResult<Vec<u8>> {
    let message = snapshot.operator_signature_message_v1()?;
    snapshot.operator_signature = operator().sign(&message).to_bytes();
    Ok(snapshot.to_canonical_cbor()?)
}

fn genesis_snapshot(expiry: &str) -> TestResult<TrustPolicySnapshotV1> {
    let bytes = pos_conformance::draft_trust_policy_snapshot_bytes_v1()?;
    let mut snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&bytes)?;
    expiry.clone_into(&mut snapshot.offline_valid_through);
    Ok(snapshot)
}

fn release(snapshot: &TrustPolicySnapshotV1, genesis: &[u8]) -> OperatorReleaseTrustV1 {
    OperatorReleaseTrustV1::new(
        snapshot.policy_id.clone(),
        operator().verifying_key().to_bytes(),
        *blake3::hash(genesis).as_bytes(),
    )
}

fn provisioned(path: &Path, expiry: &str) -> TestResult<(TrustPolicySnapshotV1, Vec<u8>)> {
    let snapshot = genesis_snapshot(expiry)?;
    let genesis = signed(snapshot.clone())?;
    DeploymentTrustPolicyRegistryV1::provision_explicit(
        path,
        &release(&snapshot, &genesis),
        &genesis,
    )?;
    Ok((snapshot, genesis))
}

#[test]
fn current_trust_policy_returns_the_exact_authenticated_genesis() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("trust.db");
    let (snapshot, genesis) = provisioned(&path, "2026-11-15T12:30:45Z")?;
    let registry =
        DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))?;
    let current = registry.current_trust_policy()?;
    assert_eq!(current.bytes(), genesis.as_slice());
    assert_eq!(current.digest(), *blake3::hash(&genesis).as_bytes());
    assert_eq!(
        current.snapshot().to_canonical_cbor()?,
        TrustPolicySnapshotV1::from_canonical_cbor(&genesis)?.to_canonical_cbor()?
    );
    assert_eq!(current.snapshot().epoch, 1);
    // 2026-11-15T12:30:45Z.
    assert_eq!(current.expiry(), 1_794_745_845);
    Ok(())
}

#[test]
fn current_trust_policy_refuses_a_replaced_state_file() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("trust.db");
    let (snapshot, genesis) = provisioned(&path, "9999-12-31T23:59:59Z")?;
    let registry =
        DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))?;
    let moved = directory.path().join("moved.db");
    std::fs::rename(&path, &moved)?;
    std::fs::copy(&moved, &path)?;
    assert_eq!(
        registry.current_trust_policy().err(),
        Some(TrustPolicyRegistryErrorV1::CorruptState)
    );
    Ok(())
}

#[test]
fn current_trust_policy_refuses_state_that_no_longer_authenticates() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("trust.db");
    let (snapshot, genesis) = provisioned(&path, "9999-12-31T23:59:59Z")?;
    let registry =
        DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))?;
    let mut forged = TrustPolicySnapshotV1::from_canonical_cbor(&genesis)?;
    forged.operator_signature = [7; 64];
    rewrite_state(&path, &forged.to_canonical_cbor()?)?;
    assert_eq!(
        registry.current_trust_policy().err(),
        Some(TrustPolicyRegistryErrorV1::CorruptState)
    );
    Ok(())
}

#[test]
fn current_trust_policy_refuses_a_signed_expiry_that_is_not_a_utc_time() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("trust.db");
    let (snapshot, genesis) = provisioned(&path, "9999-12-31T23:59:59Z")?;
    let registry =
        DeploymentTrustPolicyRegistryV1::open_current(&path, release(&snapshot, &genesis))?;
    // The TPS1 codec accepts any bounded expiry text; only the registry's
    // UTC reading refuses February 30.
    let unreadable = signed(genesis_snapshot("2026-02-30T00:00:00Z")?)?;
    rewrite_state(&path, &unreadable)?;
    assert_eq!(
        registry.current_trust_policy().err(),
        Some(TrustPolicyRegistryErrorV1::CorruptState)
    );
    Ok(())
}

#[test]
fn retained_tps1_is_checked_against_the_pinned_operator_key() -> TestResult {
    let genesis = signed(genesis_snapshot("9999-12-31T23:59:59Z")?)?;
    let operator_key = operator().verifying_key().to_bytes();
    assert!(tps1_signed_by_operator_v1(&genesis, &operator_key));
    // Another operator key, a forged signature or bytes that are not a
    // canonical TPS1 are refused.
    let other_key = SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes();
    assert!(!tps1_signed_by_operator_v1(&genesis, &other_key));
    let mut forged = TrustPolicySnapshotV1::from_canonical_cbor(&genesis)?;
    forged.operator_signature = [7; 64];
    assert!(!tps1_signed_by_operator_v1(
        &forged.to_canonical_cbor()?,
        &operator_key
    ));
    assert!(!tps1_signed_by_operator_v1(b"not a TPS1", &operator_key));
    Ok(())
}

/// Replace the stored TPS1 bytes while keeping the state row and its latest
/// audit row self-consistent, as an operator editing the file would.
fn rewrite_state(path: &Path, bytes: &[u8]) -> TestResult {
    let digest = blake3::hash(bytes);
    let connection = rusqlite::Connection::open(path)?;
    connection.execute(
        "UPDATE deployment_trust_state SET full_digest = ?1, exact_bytes = ?2 WHERE singleton = 1",
        rusqlite::params![digest.as_bytes().as_slice(), bytes],
    )?;
    connection.execute(
        "UPDATE deployment_trust_audit SET full_digest = ?1",
        rusqlite::params![digest.as_bytes().as_slice()],
    )?;
    Ok(())
}
