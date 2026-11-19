//! R11 §8.2 and §10 invariant 23: the installed authority of an RCU1, with
//! SIR1 pending and after the next SIC1 was installed.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ciborium::value::Value;

use super::{AuthorityResolution, InstalledAuthorityObjects};
use crate::sandbox_provider_protocol::RevocationUpdateRequest;
use crate::selector::installation::tests::updates::{complete_live_update, UpdateFixture};
use crate::selector::installation::tests::{materialize_root_selector_state, TestResult};
use crate::selector::SelectorBoundaryError;

fn resolve_in(
    directory: &Path,
    rcu1: &[u8],
    resolution: AuthorityResolution,
) -> TestResult<Result<InstalledAuthorityObjects, SelectorBoundaryError>> {
    let root = File::open(directory)?;
    let owner = root.metadata()?.uid();
    Ok(InstalledAuthorityObjects::resolve_at(
        &root, owner, rcu1, resolution,
    ))
}

/// `rcu1` with the unsigned field `index` replaced by `digest`; its
/// signature no longer verifies, which resolution never checks.
fn with_digest(rcu1: &[u8], index: usize, digest: [u8; 32]) -> TestResult<Vec<u8>> {
    let mut document: Value = ciborium::from_reader(rcu1)?;
    let Value::Array(wrapper) = &mut document else {
        return Err("RCU1 is not an array".into());
    };
    let Some(Value::Array(fields)) = wrapper.first_mut() else {
        return Err("RCU1 has no unsigned fields".into());
    };
    fields[index] = Value::Bytes(digest.to_vec());
    let mut bytes = Vec::new();
    ciborium::into_writer(&document, &mut bytes)?;
    Ok(bytes)
}

#[test]
fn resolution_names_only_the_installed_current_or_published_transition() -> TestResult {
    let directory = tempfile::tempdir()?;
    drop(materialize_root_selector_state(directory.path())?);
    let fixture = UpdateFixture::at(directory.path())?;
    let admitted = fixture.admitted()?;
    let trust = admitted.bootstrap().trust().snapshot_digest();
    let current = admitted.bootstrap().revocation().snapshot_digest();
    let committed = fixture.commit_live_update()?;
    let rcu1 = committed.revocation_update_bytes().to_vec();
    // RCC1 binds the exact RCU1 bytes.
    let request = RevocationUpdateRequest::authenticate(
        &rcu1,
        admitted.bootstrap().trust(),
        admitted.bootstrap().revocation(),
    )?;
    assert!(committed.cancellation_context()?.binds(&request));
    // A context naming another RCU1's wire digest does not bind this one.
    let mut foreign = committed.cancellation_context()?;
    foreign.rcu1_wire_digest = [0x33; 32];
    assert!(!foreign.binds(&request));
    // (a) with SIR1 pending, in both modes.
    let live = AuthorityResolution::Live {
        retained_revocation_digest: current,
    };
    for resolution in [live, AuthorityResolution::Recovery] {
        let resolved = resolve_in(directory.path(), &rcu1, resolution)??;
        assert_eq!(
            (
                resolved.trust().snapshot_digest(),
                resolved.previous_revocation().snapshot_digest()
            ),
            (trust, current)
        );
    }
    // The live mode also requires the RVS1 retained at startup.
    let stale = AuthorityResolution::Live {
        retained_revocation_digest: [0x44; 32],
    };
    assert!(resolve_in(directory.path(), &rcu1, stale)?.is_err());
    assert!(resolve_in(directory.path(), b"\xff", AuthorityResolution::Recovery)?.is_err());
    // (b): the next SIC1 is installed, so its current RVS1 is RCU1's next.
    complete_live_update(committed)?;
    let resolved = resolve_in(directory.path(), &rcu1, AuthorityResolution::Recovery)??;
    assert_eq!(resolved.previous_revocation().snapshot_digest(), current);
    assert!(resolve_in(directory.path(), &rcu1, live)?.is_err());
    // An indexed previous RVS1 whose transition is neither (a) nor (b), and
    // an RVS1 that is not installed.
    let neither = with_digest(&rcu1, 5, [0x77; 32])?;
    assert!(resolve_in(directory.path(), &neither, AuthorityResolution::Recovery)?.is_err());
    let absent = with_digest(&rcu1, 3, [0x55; 32])?;
    assert!(resolve_in(directory.path(), &absent, AuthorityResolution::Recovery)?.is_err());
    Ok(())
}

#[test]
fn the_fixed_installation_must_exist() {
    // Outside the isolated container the fixed installation is absent, or
    // not this test's; either way nothing resolves for a non-RCU1.
    assert!(InstalledAuthorityObjects::resolve(b"\xff", AuthorityResolution::Recovery).is_err());
}
