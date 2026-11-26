#![cfg(any(test, feature = "test-support"))]
//! A missing PRF fails closed: enrollment seals and stages nothing, and unlock
//! releases no root and leaves the binding alone (ADR-091, ADR-110 §11).

use pos_owner_bridge::fake::honest::{CreatePrf, HonestConfig};
use pos_owner_bridge::fake::signer::ReplyShape;

use super::{artifact_names, binding_name, page, Fixture, TestResult, PRF_UNSUPPORTED, SUBJECT};

/// A reply without the PRF result.
const fn no_prf(shape: &mut ReplyShape) {
    shape.prf = None;
}

fn enrollment_leaves_nothing(fixture: &Fixture) -> TestResult {
    assert!(fixture.names()?.is_empty());
    assert!(fixture.ledger_rows()?.is_empty());
    assert!(fixture.staged().is_empty());
    assert!(fixture.store.registrations().is_empty());
    Ok(())
}

#[test]
fn an_authenticator_without_prf_cannot_enroll() -> TestResult {
    let mut fixture = Fixture::new()?;
    let unsupported = HonestConfig {
        create_prf: CreatePrf::Unsupported,
        ..page(SUBJECT)
    };
    let outcome = fixture.enroll(SUBJECT, unsupported)?;
    assert_eq!(outcome, Err(PRF_UNSUPPORTED));
    enrollment_leaves_nothing(&fixture)?;
    // The honest authenticator enrolls into the same, untouched fixture.
    fixture.enroll(SUBJECT, page(SUBJECT))??;
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    Ok(())
}

#[test]
fn a_source_assertion_without_prf_cannot_enroll() -> TestResult {
    let mut fixture = Fixture::new()?;
    let silent = HonestConfig {
        create_prf: CreatePrf::EnabledOnly,
        tweak: Some(no_prf),
        ..page(SUBJECT)
    };
    let outcome = fixture.enroll(SUBJECT, silent)?;
    assert_eq!(outcome, Err(PRF_UNSUPPORTED));
    enrollment_leaves_nothing(&fixture)?;
    // Without the tweak the same restricted-assertion path enrolls.
    let restricted = HonestConfig {
        create_prf: CreatePrf::EnabledOnly,
        ..page(SUBJECT)
    };
    fixture.enroll(SUBJECT, restricted)??;
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    Ok(())
}

#[test]
fn an_unlock_assertion_without_prf_releases_no_root_and_keeps_the_binding() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    let binding = fixture.read(&binding_name(SUBJECT, 1))?;
    let silent = HonestConfig {
        tweak: Some(no_prf),
        ..page(SUBJECT)
    };
    let outcome = fixture.unlock(SUBJECT, 1, silent)?;
    assert_eq!(outcome.err(), Some(PRF_UNSUPPORTED));
    assert_eq!(fixture.read(&binding_name(SUBJECT, 1))?, binding);
    // The same wrap and binding unlock once the PRF is there.
    let entry = fixture.unlock(SUBJECT, 1, page(SUBJECT))??;
    assert_eq!(entry.root_material_digest(), fixture.digest(SUBJECT, 1)?);
    Ok(())
}
