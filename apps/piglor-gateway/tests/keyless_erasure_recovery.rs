//! The key-less Local erasure composition over a store the Gateway
//! provisioned (#1450, ADR-136 acceptance test 11): the shared loader's
//! `LocalErasureRecoveryV1` recovers a store that holds a Local erasure
//! request, which the closed composition cannot, from valid credentials
//! only, and refuses missing or invalid ones with typed errors.
#![cfg(target_os = "linux")]

#[path = "../../../crates/pos-local-erasure-loader/tests/support/signing.rs"]
pub mod signing;

#[path = "support/keyless_store.rs"]
pub mod keyless_store;

use keyless_store::KeylessStore;
use pos_core::ErasureRecoveryLimitsV1;
use pos_local_erasure_loader::{
    LocalErasureLoadErrorV1, LocalErasureOpenErrorV1, LocalErasureRecoveryV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, LocalErasureCompositionErrorV1,
};
use signing::TestResult;

/// Whether `host` reads the state of `store`'s request.
fn reads_request(mut host: ErasureExecutionHostV1, store: &KeylessStore) -> TestResult<bool> {
    Ok(host.read_sender()?.erasure_state(store.request)?.is_some())
}

/// The closed composition cannot recover the fixture store: a composition
/// that fell back to it would never open a store with a request.
#[test]
fn the_closed_composition_cannot_recover_a_store_that_holds_a_request() -> TestResult {
    let store = KeylessStore::new()?;
    assert!(ErasureExecutionHostV1::open_with_authority(
        store.config(),
        &ErasureCoordinatorCompositionV1::closed(),
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )
    .is_err());
    Ok(())
}

/// Valid credentials recover the store read-write and read-only, and its
/// request's state reads back.
#[test]
fn valid_credentials_recover_the_store_and_its_request() -> TestResult {
    let store = KeylessStore::new()?;
    let source = store.valid_source("valid")?;
    let host = LocalErasureRecoveryV1::open_host(store.config(), &source)?;
    assert!(reads_request(host, &store)?);
    let host = LocalErasureRecoveryV1::open_read_only_host(&store.path, &source)?;
    assert!(reads_request(host, &store)?);
    Ok(())
}

/// Missing credentials, an invalid bundle and a bundle another root signed
/// are typed refusals, never the closed composition.
#[test]
fn missing_or_invalid_credentials_are_typed_refusals() -> TestResult {
    let store = KeylessStore::new()?;
    assert_eq!(
        LocalErasureRecoveryV1::open_host(store.config(), &store.missing_source()).err(),
        Some(LocalErasureOpenErrorV1::Load(
            LocalErasureLoadErrorV1::CredentialsMissing
        ))
    );
    for source in [
        store.invalid_bundle_source("invalid-bundle")?,
        store.forged_signature_source("forged-signature")?,
    ] {
        assert_eq!(
            LocalErasureRecoveryV1::open_host(store.config(), &source).err(),
            Some(LocalErasureOpenErrorV1::Load(
                LocalErasureLoadErrorV1::Composition(LocalErasureCompositionErrorV1::BundleInvalid)
            ))
        );
    }
    Ok(())
}
