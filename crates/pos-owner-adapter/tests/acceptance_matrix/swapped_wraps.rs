#![cfg(any(test, feature = "test-support"))]
//! Two subjects under one human: their keys, wraps, bindings and registry
//! identities stay apart, and every swap between them is refused (ADR-091).

use pos_core::EntityId;
use pos_owner_adapter::unlock::{SubjectKeyringEntry, UnlockStore};
use pos_owner_bridge::OwnerError;

use super::{
    artifact_names, binding_name, entity, owner, page, replaced, wrap_name, Fixture, SubjectId,
    TestResult, OTHER, REGISTRY_REFUSED, SUBJECT, WRAP_REFUSED,
};

/// A store whose registry identity has the root fingerprint `.0`.
struct Fingerprint([u8; 32]);

impl UnlockStore for Fingerprint {
    fn registered_root_material_digest(
        &mut self,
        _: &str,
        _: EntityId,
        _: u64,
    ) -> Result<[u8; 32], OwnerError> {
        Ok(self.0)
    }
}

/// Unlock `subject` and check that it releases its own root and its own wrap.
fn unlocks_its_own_key(fixture: &mut Fixture, subject: SubjectId) -> TestResult {
    let wrap = fixture.wrap(subject, 1)?;
    let entry = fixture.unlock(subject, 1, page(subject))??;
    assert_eq!(entry.root_material_digest(), fixture.digest(subject, 1)?);
    assert_eq!(entry.wrap(), &wrap);
    Ok(())
}

#[test]
fn two_subjects_under_one_human_hold_distinct_owners_wraps_and_keys() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT, OTHER])?;
    assert_ne!(owner(SUBJECT), owner(OTHER));
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT, OTHER]));
    for subject in [SUBJECT, OTHER] {
        let wrap = fixture.wrap(subject, 1)?;
        assert_eq!(wrap.owner_id(), owner(subject));
        assert_eq!(wrap.params().subject_id, entity(subject));
    }
    assert_ne!(fixture.wrap(SUBJECT, 1)?, fixture.wrap(OTHER, 1)?);
    assert_ne!(fixture.digest(SUBJECT, 1)?, fixture.digest(OTHER, 1)?);
    // Each subject's SNL1 row carries its own root fingerprint.
    let rows = fixture.ledger_rows()?;
    assert_eq!(rows.len(), 2);
    for subject in [SUBJECT, OTHER] {
        let row = rows.iter().find(|row| row.owner_id == owner(subject));
        assert_eq!(
            row.map(|row| row.root_material_digest),
            Some(fixture.digest(subject, 1)?)
        );
    }
    unlocks_its_own_key(&mut fixture, SUBJECT)?;
    unlocks_its_own_key(&mut fixture, OTHER)?;
    Ok(())
}

#[test]
fn swapped_wraps_are_refused_for_both_subjects_and_restoring_them_unlocks() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT, OTHER])?;
    let originals = [
        fixture.read(&wrap_name(SUBJECT, 1))?,
        fixture.read(&wrap_name(OTHER, 1))?,
    ];
    let bindings = [
        fixture.read(&binding_name(SUBJECT, 1))?,
        fixture.read(&binding_name(OTHER, 1))?,
    ];
    fixture.put(&wrap_name(SUBJECT, 1), &originals[1])?;
    fixture.put(&wrap_name(OTHER, 1), &originals[0])?;
    for subject in [SUBJECT, OTHER] {
        let outcome = fixture.unlock(subject, 1, page(subject))?;
        assert_eq!(outcome.err(), Some(REGISTRY_REFUSED));
    }
    // Neither refused unlock touched a binding.
    assert_eq!(fixture.read(&binding_name(SUBJECT, 1))?, bindings[0]);
    assert_eq!(fixture.read(&binding_name(OTHER, 1))?, bindings[1]);

    fixture.put(&wrap_name(SUBJECT, 1), &originals[0])?;
    fixture.put(&wrap_name(OTHER, 1), &originals[1])?;
    unlocks_its_own_key(&mut fixture, SUBJECT)?;
    unlocks_its_own_key(&mut fixture, OTHER)?;
    Ok(())
}

#[test]
fn swapped_bindings_are_refused_for_both_subjects_and_restoring_them_unlocks() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT, OTHER])?;
    let originals = [
        fixture.read(&binding_name(SUBJECT, 1))?,
        fixture.read(&binding_name(OTHER, 1))?,
    ];
    fixture.put(&binding_name(SUBJECT, 1), &originals[1])?;
    fixture.put(&binding_name(OTHER, 1), &originals[0])?;
    for subject in [SUBJECT, OTHER] {
        let outcome = fixture.unlock(subject, 1, page(subject))?;
        assert_eq!(outcome.err(), Some(REGISTRY_REFUSED));
    }

    fixture.put(&binding_name(SUBJECT, 1), &originals[0])?;
    fixture.put(&binding_name(OTHER, 1), &originals[1])?;
    unlocks_its_own_key(&mut fixture, SUBJECT)?;
    unlocks_its_own_key(&mut fixture, OTHER)?;
    Ok(())
}

/// A wrap that names its own subject but carries the other subject's wrapped
/// root authenticates under neither subject's PRF: no root is released.
#[test]
fn swapped_wrapped_roots_fail_to_authenticate_and_release_no_root() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT, OTHER])?;
    let originals = [
        fixture.read(&wrap_name(SUBJECT, 1))?,
        fixture.read(&wrap_name(OTHER, 1))?,
    ];
    let roots = [
        *fixture.wrap(SUBJECT, 1)?.wrapped_root(),
        *fixture.wrap(OTHER, 1)?.wrapped_root(),
    ];
    assert_ne!(roots[0], roots[1]);
    let bindings = [
        fixture.read(&binding_name(SUBJECT, 1))?,
        fixture.read(&binding_name(OTHER, 1))?,
    ];
    fixture.put(
        &wrap_name(SUBJECT, 1),
        &replaced(&originals[0], &roots[0], &roots[1])?,
    )?;
    fixture.put(
        &wrap_name(OTHER, 1),
        &replaced(&originals[1], &roots[1], &roots[0])?,
    )?;
    for subject in [SUBJECT, OTHER] {
        let outcome = fixture.unlock(subject, 1, page(subject))?;
        assert_eq!(outcome.err(), Some(WRAP_REFUSED));
    }
    assert_eq!(fixture.read(&binding_name(SUBJECT, 1))?, bindings[0]);
    assert_eq!(fixture.read(&binding_name(OTHER, 1))?, bindings[1]);

    fixture.put(&wrap_name(SUBJECT, 1), &originals[0])?;
    fixture.put(&wrap_name(OTHER, 1), &originals[1])?;
    unlocks_its_own_key(&mut fixture, SUBJECT)?;
    unlocks_its_own_key(&mut fixture, OTHER)?;
    Ok(())
}

/// A subject's root never opens under the other subject's registry identity.
#[test]
fn swapped_registry_fingerprints_are_refused_and_the_own_one_unlocks() -> TestResult {
    let fixture = Fixture::enrolled(&[SUBJECT, OTHER])?;
    let bindings = [
        fixture.read(&binding_name(SUBJECT, 1))?,
        fixture.read(&binding_name(OTHER, 1))?,
    ];
    for (subject, foreign) in [(SUBJECT, OTHER), (OTHER, SUBJECT)] {
        let mut store = Fingerprint(fixture.digest(foreign, 1)?);
        let outcome = fixture.unlock_against(&mut store, subject, 1)?;
        assert_eq!(outcome.err(), Some(REGISTRY_REFUSED));
    }
    assert_eq!(fixture.read(&binding_name(SUBJECT, 1))?, bindings[0]);
    assert_eq!(fixture.read(&binding_name(OTHER, 1))?, bindings[1]);
    for subject in [SUBJECT, OTHER] {
        let mut store = Fingerprint(fixture.digest(subject, 1)?);
        let outcome = fixture.unlock_against(&mut store, subject, 1)?;
        assert_eq!(
            outcome
                .as_ref()
                .map(SubjectKeyringEntry::root_material_digest)
                .ok(),
            Some(fixture.digest(subject, 1)?)
        );
    }
    Ok(())
}
