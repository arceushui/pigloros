use std::error::Error;
use std::io::Cursor;

use pos_reference::evaluator_protocol::EvaluationRequest;
use pos_reference::profile::Profile;
use pos_reference::signed_bundle::{
    preflight_signed_bundle_reader, verify_signed_bundle_reader, BundleError,
};

use super::support::{self, BundleMutation, ProfileMutation};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn retained_reader_reconstructs_a_signed_selected_fixture_closure() -> TestResult {
    let corpus = support::corpus()?;
    let request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    let mut archive = Cursor::new(&corpus.archive);
    let preflight = preflight_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request)?;
    let caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), &request)?;
    preflight.enforce_selected_caps(caps.into())?;
    let bundle = verify_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request)?;
    let profile = Profile::from_bundle(&bundle, &request)?;
    let fixture = profile
        .selected_fixtures(&request)
        .into_iter()
        .next()
        .ok_or("selected fixture absent")?;
    assert_eq!(bundle.archive_digest, request.fixture_bundle_digest);
    assert_eq!(
        profile.trust_policy_snapshot_digest,
        request.trust_policy_snapshot_digest
    );
    assert_ne!(profile.fixture_contract_digest(), [0; 32]);
    assert!(fixture.modes.contains(&bundle.mode));
    Ok(())
}

#[test]
fn retained_reader_rejects_absent_or_swapped_installed_artifact_digests() -> TestResult {
    let corpus = support::corpus()?;
    let request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    for request in [
        EvaluationRequest {
            fixture_bundle_digest: [91; 32],
            ..request.clone()
        },
        EvaluationRequest {
            trust_policy_snapshot_digest: [92; 32],
            ..request
        },
    ] {
        let mut archive = Cursor::new(&corpus.archive);
        assert!(
            preflight_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request).is_err()
        );
    }
    Ok(())
}

#[test]
fn retained_reader_rejects_a_noncanonical_archive_before_profile_allocation() -> TestResult {
    let corpus = support::corpus()?;
    let mut archive = vec![0x98, 4];
    archive.extend_from_slice(&corpus.archive[1..]);
    let mut request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    request.fixture_bundle_digest = *blake3::hash(&archive).as_bytes();
    let mut archive = Cursor::new(archive);
    assert_eq!(
        preflight_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request),
        Err(BundleError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn retained_reader_rejects_invalid_signature_and_profile_before_case_selection() -> TestResult {
    let corpus = support::corpus_with_bundle_mutation(BundleMutation::Signature)?;
    let request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    let mut archive = Cursor::new(&corpus.archive);
    assert_eq!(
        preflight_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request),
        Err(BundleError::SignatureInvalid)
    );

    let corpus = support::corpus_with_profile_mutation(ProfileMutation::FixtureAdapter)?;
    let request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    let mut archive = Cursor::new(&corpus.archive);
    let preflight = preflight_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request)?;
    let caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), &request)?;
    preflight.enforce_selected_caps(caps.into())?;
    let bundle = verify_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request)?;
    assert!(Profile::from_bundle(&bundle, &request).is_err());
    Ok(())
}

#[test]
fn retained_reader_rejects_unsupported_ordinal_or_mode_and_caps_before_members() -> TestResult {
    let corpus = support::corpus()?;
    let request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    let mut archive = Cursor::new(&corpus.archive);
    let preflight = preflight_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request)?;
    let caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), &request)?;
    preflight.enforce_selected_caps(caps.into())?;
    let bundle = verify_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request)?;
    let profile = Profile::from_bundle(&bundle, &request)?;
    assert!(profile
        .selected_fixtures(&request)
        .into_iter()
        .nth(u16::MAX.into())
        .is_none());
    assert!(!profile
        .fixtures
        .iter()
        .any(|fixture| fixture.modes.contains(&2)));

    let corpus =
        support::corpus_with_profile_mutation(ProfileMutation::SelectedClosureCapBoundary(0))?;
    let request = EvaluationRequest::from_canonical_cbor(&corpus.request)?;
    let mut archive = Cursor::new(&corpus.archive);
    let preflight = preflight_signed_bundle_reader(&mut archive, &corpus.trust_policy, &request)?;
    let caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), &request)?;
    assert_eq!(
        preflight.enforce_selected_caps(caps.into()),
        Err(BundleError::FieldOutOfBounds)
    );
    Ok(())
}
