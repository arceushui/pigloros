#![cfg(any(test, feature = "test-support"))]
//! A cryptographic RNG failure aborts enrollment without a registry entry or
//! a wrapped record (ADR-091), and leaves other subjects' keys alone.

use super::{
    artifact_names, binding_name, page, FakeRandom, Fixture, TestResult, OTHER, SUBJECT,
    WRAP_REFUSED,
};

#[test]
fn an_rng_failure_leaves_no_artifact_ledger_row_record_or_registration() -> TestResult {
    let mut fixture = Fixture::new()?;
    let outcome = fixture.enroll_as(
        SUBJECT,
        page(SUBJECT),
        FakeRandom::failing_after(5, 0),
        |_| (),
    )?;
    assert_eq!(outcome, Err(WRAP_REFUSED));
    assert!(fixture.names()?.is_empty());
    assert!(fixture.ledger_rows()?.is_empty());
    assert!(fixture.staged()?.is_empty());
    assert!(fixture.store.registrations()?.is_empty());
    // Nothing was reserved: a healthy source enrolls the same subject at epoch 1.
    fixture.enroll(SUBJECT, page(SUBJECT))??;
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    assert_eq!(fixture.ledger_rows()?.len(), 1);
    Ok(())
}

#[test]
fn an_rng_failure_of_one_subject_does_not_disturb_another_subjects_key() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    let binding = fixture.read(&binding_name(SUBJECT, 1))?;
    let outcome = fixture.enroll_as(OTHER, page(OTHER), FakeRandom::failing_after(6, 0), |_| ())?;
    assert_eq!(outcome, Err(WRAP_REFUSED));
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    assert_eq!(fixture.ledger_rows()?.len(), 1);
    assert_eq!(fixture.store.registrations()?.len(), 1);
    assert!(fixture.staged()?.is_empty());
    assert_eq!(fixture.read(&binding_name(SUBJECT, 1))?, binding);
    let entry = fixture.unlock(SUBJECT, 1, page(SUBJECT))??;
    assert_eq!(entry.root_material_digest(), fixture.digest(SUBJECT, 1)?);
    Ok(())
}
