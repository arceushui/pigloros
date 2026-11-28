#![cfg(any(test, feature = "test-support"))]
//! A wrong PRF output never authenticates: enrollment abandons the candidate
//! before it stages anything, and unlock releases no root (ADR-091).

use pos_owner_bridge::fake::honest::HonestConfig;

use super::{
    artifact_names, binding_name, derived, page, Fixture, TestResult, SUBJECT, WRAP_REFUSED,
};

#[test]
fn a_confirmation_under_another_prf_abandons_the_enrollment() -> TestResult {
    let mut fixture = Fixture::new()?;
    let wrong = HonestConfig {
        substitute_get_prf: Some(derived("substituted prf output")),
        ..page(SUBJECT)
    };
    let outcome = fixture.enroll(SUBJECT, wrong)?;
    assert_eq!(outcome, Err(WRAP_REFUSED));
    assert!(fixture.names()?.is_empty());
    assert!(fixture.ledger_rows()?.is_empty());
    assert!(fixture.staged()?.is_empty());
    assert!(fixture.store.registrations()?.is_empty());
    // Nothing was left behind: the honest enrollment takes epoch 1.
    fixture.enroll(SUBJECT, page(SUBJECT))??;
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    Ok(())
}

#[test]
fn an_unlock_under_another_prf_releases_no_root_and_keeps_the_binding() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    let binding = fixture.read(&binding_name(SUBJECT, 1))?;
    let substituted = HonestConfig {
        substitute_get_prf: Some(derived("substituted prf output")),
        ..page(SUBJECT)
    };
    // An authenticator holding another PRF secret answers the same way.
    let other_secret = HonestConfig {
        prf_secret: derived("another authenticator secret"),
        ..page(SUBJECT)
    };
    for wrong in [substituted, other_secret] {
        let outcome = fixture.unlock(SUBJECT, 1, wrong)?;
        assert_eq!(outcome.err(), Some(WRAP_REFUSED));
        assert_eq!(fixture.read(&binding_name(SUBJECT, 1))?, binding);
    }
    let entry = fixture.unlock(SUBJECT, 1, page(SUBJECT))??;
    assert_eq!(entry.root_material_digest(), fixture.digest(SUBJECT, 1)?);
    Ok(())
}
