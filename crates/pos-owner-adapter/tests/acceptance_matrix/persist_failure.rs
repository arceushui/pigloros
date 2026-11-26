#![cfg(any(test, feature = "test-support"))]
//! A persist failure releases no root: a failed enrollment write registers
//! nothing that unlocks, and a failed binding replacement withholds the root
//! (ADR-137 P3 and P5, ADR-110 §9).

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;

use super::{
    artifact_names, binding_name, owner, page, wrap_name, Fail, Fixture, TestResult,
    REGISTRY_REFUSED, SUBJECT, WRITE_REFUSED,
};

/// Unlock `SUBJECT` at epoch 1 and require that the adapter refuses the open.
fn unlock_is_unavailable(fixture: &mut Fixture) -> TestResult {
    let outcome = fixture.unlock(SUBJECT, 1, page(SUBJECT))?;
    assert_eq!(outcome.err(), Some(REGISTRY_REFUSED));
    Ok(())
}

#[test]
fn a_failed_staging_record_stages_nothing_and_nothing_unlocks() -> TestResult {
    let mut fixture = Fixture::new()?;
    let outcome = fixture.enroll_faulty(SUBJECT, Fail::Staging)?;
    assert_eq!(outcome, Err(WRITE_REFUSED));
    assert!(fixture.names()?.is_empty());
    assert!(fixture.ledger_rows()?.is_empty());
    assert!(fixture.staged().is_empty());
    assert!(fixture.store.registrations().is_empty());
    unlock_is_unavailable(&mut fixture)
}

#[test]
fn a_failed_wrap_write_deletes_the_attempt_and_nothing_unlocks() -> TestResult {
    let mut fixture = Fixture::new()?;
    let outcome = fixture.enroll_faulty(SUBJECT, Fail::BlockedWrap)?;
    assert_eq!(outcome, Err(WRITE_REFUSED));
    // P5 removed the blocker, the staged files, the row and the record.
    assert!(fixture.names()?.is_empty());
    assert!(fixture.ledger_rows()?.is_empty());
    assert!(fixture.staged().is_empty());
    assert!(fixture.store.registrations().is_empty());
    unlock_is_unavailable(&mut fixture)?;
    // A later enrollment is not blocked by the failed attempt.
    fixture.enroll(SUBJECT, page(SUBJECT))??;
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    Ok(())
}

#[test]
fn a_failed_registration_leaves_the_attempt_staged_and_nothing_unlocks() -> TestResult {
    let mut fixture = Fixture::new()?;
    let outcome = fixture.enroll_faulty(SUBJECT, Fail::Register)?;
    assert_eq!(outcome, Err(WRITE_REFUSED));
    // The outcome of step 6 is unknown, so P5 recovery owns the attempt.
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    let rows = fixture.ledger_rows()?;
    assert_eq!(
        rows.iter()
            .map(|row| (row.owner_id.as_str(), row.epoch))
            .collect::<Vec<_>>(),
        [(owner(SUBJECT).as_str(), 1)]
    );
    assert_eq!(fixture.staged(), [(owner(SUBJECT), 1)]);
    assert!(fixture.store.registrations().is_empty());
    // Staged files without a registry identity open no key.
    unlock_is_unavailable(&mut fixture)
}

#[test]
fn a_failed_binding_replacement_releases_no_root_and_a_retry_unlocks() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    let path = fixture.path(&binding_name(SUBJECT, 1));
    let enrolled = fixture.read(&binding_name(SUBJECT, 1))?;
    let wrap = fixture.read(&wrap_name(SUBJECT, 1))?;
    // The replacement refuses a binding file that is not private.
    fs::set_permissions(&path, Permissions::from_mode(0o644))?;
    let outcome = fixture.unlock(SUBJECT, 1, page(SUBJECT))?;
    assert_eq!(outcome.err(), Some(WRITE_REFUSED));
    assert_eq!(fixture.read(&binding_name(SUBJECT, 1))?, enrolled);
    assert_eq!(fixture.read(&wrap_name(SUBJECT, 1))?, wrap);
    // The failure kept the stored counter, so the next unlock still advances it.
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    let entry = fixture.unlock(SUBJECT, 1, page(SUBJECT))??;
    assert_eq!(entry.root_material_digest(), fixture.digest(SUBJECT, 1)?);
    assert_ne!(fixture.read(&binding_name(SUBJECT, 1))?, enrolled);
    Ok(())
}
