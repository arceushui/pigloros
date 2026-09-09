#[allow(dead_code)]
#[path = "../../../../tests/support/mod.rs"]
mod signed_support;

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::evaluator_protocol::{EvaluationRequest, SubjectAdapterKind};
use crate::selector::installation::authority::InstalledSelectorAuthority;

type CaseTestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn install_raw_object(
    fixture: &InstallationFixture,
    manifest: &mut [Value],
    code: u8,
    object: &[u8],
) -> CaseTestResult {
    let kind = InstallationObjectKind::from_code(code)?;
    let digest = *blake3::hash(object).as_bytes();
    let path = fixture
        .directory
        .path()
        .join(kind.directory())
        .join(digest_name(digest));
    std::fs::write(path, object)?;
    std::fs::set_permissions(
        fixture
            .directory
            .path()
            .join(kind.directory())
            .join(digest_name(digest)),
        std::fs::Permissions::from_mode(kind.mode()),
    )?;
    let mut entries = array_values(&manifest[10])?.to_vec();
    entries[usize::from(code)] = Value::Array(vec![
        integer(u64::from(code)),
        bytes(digest),
        bytes(digest),
        integer(u64::try_from(object.len())?),
    ]);
    manifest[10] = Value::Array(entries);
    Ok(())
}

fn remove_raw_object(manifest: &mut [Value], code: u8) -> CaseTestResult {
    let mut entries = array_values(&manifest[10])?.to_vec();
    entries.remove(usize::from(code));
    manifest[10] = Value::Array(entries);
    Ok(())
}

fn install_case_fixture(
    archive: &[u8],
    trust_policy: &[u8],
    change_manifest: impl FnOnce(&mut Vec<Value>) -> CaseTestResult,
) -> CaseTestResult<(InstallationFixture, InstalledSelectorAuthority)> {
    let fixture = bootstrap::authenticated_fixture(|_| {})?;
    let installed = fixture.load()?;
    let document = crate::evaluator_protocol::decode_canonical(installed.manifest_bytes())?;
    let mut manifest = array_values(&array(&document, 2)?[0])?.to_vec();
    install_raw_object(&fixture, &mut manifest, 14, archive)?;
    install_raw_object(&fixture, &mut manifest, 15, trust_policy)?;
    change_manifest(&mut manifest)?;
    let path = fixture.directory.path().join(MANIFEST_NAME);
    std::fs::remove_file(&path)?;
    std::fs::write(&path, manifest_bytes(manifest)?)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    let authority = fixture.load()?.authenticate_authority()?;
    Ok((fixture, authority))
}

fn corpus_request(corpus: &signed_support::Corpus) -> CaseTestResult<EvaluationRequest> {
    Ok(EvaluationRequest::from_canonical_cbor(&corpus.request)?)
}

fn rebind(mut request: EvaluationRequest) -> CaseTestResult<EvaluationRequest> {
    request.output_capability.capability_digest = request.expected_output_capability_digest()?;
    request.request_digest = request.digest()?;
    Ok(request)
}

#[test]
fn installed_authority_reconstructs_the_signed_selected_case() -> CaseTestResult {
    let corpus = signed_support::corpus()?;
    let request = corpus_request(&corpus)?;
    let (_fixture, authority) =
        install_case_fixture(&corpus.archive, &corpus.trust_policy, |_| Ok(()))?;
    let resolved = authority.resolve_installed_case(&request, 0)?;
    assert_eq!(resolved.bundle_digest(), request.fixture_bundle_digest);
    assert_eq!(resolved.profile_digest(), request.profile_digest);
    assert_ne!(resolved.fixture_contract_digest(), [0; 32]);
    assert_eq!(resolved.attempt().case_id, "case-0");
    assert_eq!(resolved.attempt().mode, 0);
    Ok(())
}

#[test]
fn installed_authority_rejects_missing_or_swapped_cfb1_and_tps1() -> CaseTestResult {
    let corpus = signed_support::corpus()?;
    let request = corpus_request(&corpus)?;
    for code in [14, 15] {
        let (_fixture, authority) =
            install_case_fixture(&corpus.archive, &corpus.trust_policy, |manifest| {
                remove_raw_object(manifest, code)
            })?;
        assert!(authority.resolve_installed_case(&request, 0).is_err());
    }
    let (_fixture, authority) =
        install_case_fixture(&corpus.trust_policy, &corpus.archive, |_| Ok(()))?;
    assert!(authority.resolve_installed_case(&request, 0).is_err());
    Ok(())
}

#[test]
fn installed_authority_rejects_invalid_ordinal_mode_and_request_bindings() -> CaseTestResult {
    let corpus = signed_support::corpus()?;
    let request = corpus_request(&corpus)?;
    let (_fixture, authority) =
        install_case_fixture(&corpus.archive, &corpus.trust_policy, |_| Ok(()))?;
    assert!(authority.resolve_installed_case(&request, 7).is_err());
    for request in [
        rebind(EvaluationRequest {
            subject_adapter: SubjectAdapterKind::PublicGatewayProtocol,
            ..request.clone()
        })?,
        rebind(EvaluationRequest {
            execution_profile_digest: [99; 32],
            ..request
        })?,
    ] {
        assert!(authority.resolve_installed_case(&request, 0).is_err());
    }

    let corpus = signed_support::corpus_with_bundle_mutation(signed_support::BundleMutation::Mode)?;
    let request = corpus_request(&corpus)?;
    let (_fixture, authority) =
        install_case_fixture(&corpus.archive, &corpus.trust_policy, |_| Ok(()))?;
    assert!(authority.resolve_installed_case(&request, 0).is_err());
    Ok(())
}

#[test]
fn installed_authority_rejects_invalid_signed_closures_before_case_reconstruction() -> CaseTestResult
{
    let corpus =
        signed_support::corpus_with_bundle_mutation(signed_support::BundleMutation::Signature)?;
    let request = corpus_request(&corpus)?;
    let (_fixture, authority) =
        install_case_fixture(&corpus.archive, &corpus.trust_policy, |_| Ok(()))?;
    assert!(authority.resolve_installed_case(&request, 0).is_err());

    let corpus = signed_support::corpus_with_profile_mutation(
        signed_support::ProfileMutation::FixtureAdapter,
    )?;
    let request = corpus_request(&corpus)?;
    let (_fixture, authority) =
        install_case_fixture(&corpus.archive, &corpus.trust_policy, |_| Ok(()))?;
    assert!(authority.resolve_installed_case(&request, 0).is_err());

    let corpus = signed_support::corpus_with_profile_mutation(
        signed_support::ProfileMutation::SelectedClosureCapBoundary(0),
    )?;
    let request = corpus_request(&corpus)?;
    let (_fixture, authority) =
        install_case_fixture(&corpus.archive, &corpus.trust_policy, |_| Ok(()))?;
    assert!(authority.resolve_installed_case(&request, 0).is_err());
    Ok(())
}
