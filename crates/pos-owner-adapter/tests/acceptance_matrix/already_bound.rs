#![cfg(any(test, feature = "test-support"))]
//! A credential that a wrap or binding already holds cannot enroll again, for
//! another subject or for the same one, and leaves no artifact (ADR-091: one
//! credential and one wrap per subject and epoch).

use pos_owner_bridge::fake::honest::HonestConfig;

use super::{
    artifact_names, binding_name, page, Fixture, TestResult, ALREADY_BOUND, OTHER, SUBJECT,
};

/// An authenticator that holds the credential of `SUBJECT`.
fn same_credential() -> HonestConfig {
    page(SUBJECT)
}

#[test]
fn another_subject_cannot_enroll_a_bound_credential() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    let outcome = fixture.enroll(OTHER, same_credential())?;
    assert_eq!(outcome, Err(ALREADY_BOUND));
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    assert_eq!(fixture.ledger_rows()?.len(), 1);
    assert_eq!(fixture.store.registrations()?.len(), 1);
    assert!(fixture.staged()?.is_empty());
    // The refused enrollment disturbed nothing of the bound subject, and the
    // other subject enrolls under a credential of its own.
    let entry = fixture.unlock(SUBJECT, 1, page(SUBJECT))??;
    assert_eq!(entry.root_material_digest(), fixture.digest(SUBJECT, 1)?);
    fixture.enroll(OTHER, page(OTHER))??;
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT, OTHER]));
    Ok(())
}

#[test]
fn the_same_subject_cannot_enroll_its_credential_again() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    let outcome = fixture.enroll(SUBJECT, same_credential())?;
    assert_eq!(outcome, Err(ALREADY_BOUND));
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    assert_eq!(fixture.store.registrations()?.len(), 1);
    assert_eq!(fixture.ledger_rows()?.len(), 1);
    assert!(fixture.staged()?.is_empty());
    Ok(())
}

#[test]
fn a_wrap_alone_still_holds_its_credential() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    std::fs::remove_file(fixture.path(&binding_name(SUBJECT, 1)))?;
    let remaining = fixture.names()?;
    assert_eq!(remaining.len(), 1);
    let outcome = fixture.enroll(OTHER, same_credential())?;
    assert_eq!(outcome, Err(ALREADY_BOUND));
    assert_eq!(fixture.names()?, remaining);
    assert_eq!(fixture.store.registrations()?.len(), 1);
    assert!(fixture.staged()?.is_empty());
    Ok(())
}
