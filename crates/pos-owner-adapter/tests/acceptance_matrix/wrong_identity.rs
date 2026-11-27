#![cfg(any(test, feature = "test-support"))]
//! A wrong owner, subject, epoch or RP ID is refused, at unlock before any
//! ceremony and at enrollment before anything is staged (ADR-091, ADR-097 §5).
//!
//! The wrong-RP case is exercised at unlock only: the codec fixes the RP at
//! enrollment, and the page-reply `rpIdHash` case is covered at bridge level.

use std::fs;

use pos_crypto::subject_key::{
    SubjectKeyWrapParamsV1, SubjectKeyWrapV1, SubjectPrfOutputV1, SubjectRootKeyV1,
};
use pos_owner_bridge_codec::{
    decode_subject_credential_binding, encode_subject_credential_binding,
    SubjectCredentialBindingInputV1, SubjectCredentialBindingV1,
    MAX_SUBJECT_CREDENTIAL_BINDING_BYTES,
};

use super::{
    artifact_names, binding_name, derived, entity, owner, page, wrap_name, EnrollmentContext,
    FakeRandom, Fixture, TestResult, CREDENTIAL_ID, OTHER, REGISTRY_REFUSED, SUBJECT, WRAP_REFUSED,
};

/// A change to the context that the bridge enrolls under.
type Edit = fn(&mut EnrollmentContext);

const fn input_of(binding: SubjectCredentialBindingV1<'_>) -> SubjectCredentialBindingInputV1<'_> {
    SubjectCredentialBindingInputV1 {
        owner_id: binding.owner_id(),
        subject_id: binding.subject_id(),
        epoch: binding.epoch(),
        credential_id: binding.credential_id(),
        user_handle: binding.user_handle(),
        public_key: binding.public_key(),
        backup_eligible: binding.backup_eligible(),
        backup_state: binding.backup_state(),
        sign_count: binding.sign_count(),
        transports: binding.transports(),
    }
}

/// `bytes`, a binding, re-encoded with `edit` applied to its fields.
fn edited(
    bytes: &[u8],
    edit: impl FnOnce(&mut SubjectCredentialBindingInputV1<'_>),
) -> TestResult<Vec<u8>> {
    let stored = decode_subject_credential_binding(bytes)
        .ok()
        .ok_or("the binding did not decode")?;
    let mut input = input_of(stored);
    edit(&mut input);
    let binding = SubjectCredentialBindingV1::new(input)
        .ok()
        .ok_or("the edited binding is invalid")?;
    let mut buffer = [0_u8; MAX_SUBJECT_CREDENTIAL_BINDING_BYTES];
    let length = encode_subject_credential_binding(&binding, &mut buffer)
        .ok()
        .ok_or("the edited binding did not encode")?;
    Ok(buffer[..length].to_vec())
}

/// Valid `SubjectKeyWrapV1` bytes for `SUBJECT` at epoch 1 under `rp_id`.
fn wrap_fixture(rp_id: &str) -> TestResult<Vec<u8>> {
    let params = SubjectKeyWrapParamsV1 {
        subject_id: entity(SUBJECT),
        epoch: 1,
        rp_id: rp_id.to_owned(),
        credential_id: CREDENTIAL_ID.to_vec(),
        prf_input: derived("wrap fixture prf input"),
        wrap_salt: derived("wrap fixture wrap salt"),
        subkey_salt: derived("wrap fixture subkey salt"),
        wrap_nonce: derived("wrap fixture wrap nonce"),
    };
    let root = SubjectRootKeyV1::from_bytes(derived("wrap fixture root"));
    let wrap = SubjectKeyWrapV1::seal(
        params,
        &root,
        &SubjectPrfOutputV1::from_bytes(derived("wrap fixture prf output")),
    )?;
    Ok(wrap.to_bytes())
}

/// An enrolled pair holding `SUBJECT`'s wrap and binding bytes.
///
/// Both are read before the case changes anything.
struct Case {
    fixture: Fixture,
    wrap: Vec<u8>,
    binding: Vec<u8>,
}

impl Case {
    fn new() -> TestResult<Self> {
        let fixture = Fixture::enrolled(&[SUBJECT, OTHER])?;
        let wrap = fixture.read(&wrap_name(SUBJECT, 1))?;
        let binding = fixture.read(&binding_name(SUBJECT, 1))?;
        Ok(Self {
            fixture,
            wrap,
            binding,
        })
    }

    /// Unlock `SUBJECT` at epoch 1 and require the adapter's refusal.
    fn refused(&mut self) -> TestResult {
        let outcome = self.fixture.unlock(SUBJECT, 1, page(SUBJECT))?;
        assert_eq!(outcome.err(), Some(REGISTRY_REFUSED));
        Ok(())
    }

    /// Put the enrolled wrap and binding back and unlock `SUBJECT` for real.
    fn restored_unlocks(&mut self) -> TestResult {
        self.fixture.put(&wrap_name(SUBJECT, 1), &self.wrap)?;
        self.fixture.put(&binding_name(SUBJECT, 1), &self.binding)?;
        let entry = self.fixture.unlock(SUBJECT, 1, page(SUBJECT))??;
        assert_eq!(
            entry.root_material_digest(),
            self.fixture.digest(SUBJECT, 1)?
        );
        Ok(())
    }
}

#[test]
fn another_owners_wrap_and_binding_under_this_owners_names_are_refused() -> TestResult {
    let mut case = Case::new()?;
    let foreign = [
        case.fixture.read(&wrap_name(OTHER, 1))?,
        case.fixture.read(&binding_name(OTHER, 1))?,
    ];
    case.fixture.put(&wrap_name(SUBJECT, 1), &foreign[0])?;
    case.fixture.put(&binding_name(SUBJECT, 1), &foreign[1])?;
    case.refused()?;
    // The other owner's own artifacts were not touched.
    assert_eq!(case.fixture.read(&wrap_name(OTHER, 1))?, foreign[0]);
    assert_eq!(case.fixture.read(&binding_name(OTHER, 1))?, foreign[1]);
    case.restored_unlocks()
}

#[test]
fn a_binding_of_another_subject_is_refused() -> TestResult {
    let mut case = Case::new()?;
    let bytes = edited(&case.binding, |input| input.subject_id = OTHER)?;
    assert_ne!(bytes, case.binding);
    case.fixture.put(&binding_name(SUBJECT, 1), &bytes)?;
    case.refused()?;
    case.restored_unlocks()
}

#[test]
fn an_unknown_epoch_and_artifacts_of_another_epoch_are_refused() -> TestResult {
    let mut case = Case::new()?;
    // Epoch zero has no names, and epoch 2 was never enrolled.
    for epoch in [0, 2] {
        let outcome = case.fixture.unlock(SUBJECT, epoch, page(SUBJECT))?;
        assert_eq!(outcome.err(), Some(REGISTRY_REFUSED), "{epoch}");
    }
    // A binding that names epoch 2 does not serve epoch 1.
    let bytes = edited(&case.binding, |input| input.epoch = 2)?;
    case.fixture.put(&binding_name(SUBJECT, 1), &bytes)?;
    case.refused()?;
    case.fixture.put(&binding_name(SUBJECT, 1), &case.binding)?;

    // Both artifacts moved to epoch 2's names still hold epoch 1 contents.
    for name in [wrap_name, binding_name] {
        fs::rename(
            case.fixture.path(&name(SUBJECT, 1)),
            case.fixture.path(&name(SUBJECT, 2)),
        )?;
    }
    for epoch in [1, 2] {
        let outcome = case.fixture.unlock(SUBJECT, epoch, page(SUBJECT))?;
        assert_eq!(outcome.err(), Some(REGISTRY_REFUSED), "{epoch}");
    }
    for name in [wrap_name, binding_name] {
        fs::rename(
            case.fixture.path(&name(SUBJECT, 2)),
            case.fixture.path(&name(SUBJECT, 1)),
        )?;
    }
    case.restored_unlocks()
}

#[test]
fn a_wrap_of_another_relying_party_is_refused_before_any_ceremony() -> TestResult {
    let mut case = Case::new()?;
    let foreign = wrap_fixture("example.com")?;
    case.fixture.put(&wrap_name(SUBJECT, 1), &foreign)?;
    case.refused()?;
    // The same wrap under the one relying party passes the cross-check, so the
    // RP ID alone was refused: the unlock then reaches the ceremony and fails
    // to authenticate the unrelated wrap.
    case.fixture
        .put(&wrap_name(SUBJECT, 1), &wrap_fixture("localhost")?)?;
    let outcome = case.fixture.unlock(SUBJECT, 1, page(SUBJECT))?;
    assert_eq!(outcome.err(), Some(WRAP_REFUSED));
    case.restored_unlocks()
}

#[test]
fn an_enrollment_under_another_owner_subject_or_epoch_stages_nothing() -> TestResult {
    let mut fixture = Fixture::new()?;
    let edits: [(&str, Edit); 3] = [
        ("owner", |context| context.owner_id = owner(OTHER)),
        ("subject", |context| context.subject_id = OTHER),
        ("epoch", |context| context.epoch += 1),
    ];
    for (case, edit) in edits {
        let outcome = fixture.enroll_as(SUBJECT, page(SUBJECT), FakeRandom::seeded(5), edit)?;
        assert_eq!(outcome, Err(REGISTRY_REFUSED), "{case}");
        assert!(fixture.names()?.is_empty(), "{case}");
        assert!(fixture.ledger_rows()?.is_empty(), "{case}");
        assert!(fixture.staged()?.is_empty(), "{case}");
        assert!(fixture.store.registrations()?.is_empty(), "{case}");
    }
    // The adapter's own context enrolls: only the identity was refused.
    fixture.enroll(SUBJECT, page(SUBJECT))??;
    assert_eq!(fixture.names()?, artifact_names(&[SUBJECT]));
    Ok(())
}
