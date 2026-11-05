#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! ADR-062 Revision 8 slice G1 (#1236): the signed conformance-report attestation through its
//! public seams, `sign_report_attestation_v1` and `verify_report_attestation_v1`, with the
//! owner decisions of `ADR-062_R8_Report_Attestation_Binding` (split trust steps, subjects bound
//! to their CNR1 fields).
//!
//! The file name only places this suite before the slow `bundle_contract_*` suites in
//! `cargo test`'s alphabetical order. That is incidental: it keeps the bounded test phase of the
//! diff-mutation job from being spent in those pre-existing suites before it reaches the only
//! tests that kill mutants of `report_attestation.rs`, but it does not make them faster.

pub mod support;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pos_conformance::{
    sign_report_attestation_v1, verify_report_attestation_v1, BoundSubjectV1, BundleMemberRoleV1,
    CaseOutcomeStatusV1, CaseOutcomeV1, ClaimLayerV1, ConformanceArtifactRefusalV1,
    ConformanceBundleV1, ConformanceKeyRefusalV1, ConformanceProfileV1, ConformanceReportV1,
    ConformanceTrustAdmissionPortV1, ConformanceTrustRoleV1, ExecutionModeV1,
    ImplementationIdentityV1, IndependenceEvidenceV1, RedactionStateV1, ReplayClaimV1,
    ReportAttestationArtifactsV1, ReportAttestationErrorV1 as Error, SignatureMeaningV1,
    MAX_REPORT_ATTESTATION_BYTES_V1, REPORT_ATTESTATION_SUBJECT_NAMES_V1,
};
use pos_crypto::dsse::{
    key_id_v1, DsseEnvelopeV1, DsseParseErrorV1, DsseSignatureErrorV1, IN_TOTO_PAYLOAD_TYPE_V1,
};
use pos_crypto::jcs::JsonV1;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;
use std::sync::OnceLock;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One recorded artifact-revocation call: report digest, evaluator binary digest.
type RevocationCall = ([u8; 32], [u8; 32]);

/// One edit of a decoded Statement.
type Edit = fn(&mut Value);

/// One edit of a CNR1 report before its self digest is recomputed.
type ReportEdit = fn(&mut ConformanceReportV1);

const SUBJECT_ARTIFACT: &[u8] = b"subject artifact";
const EVALUATOR_BINARY: &[u8] = b"evaluator binary";

/// The materialized CFB1 archive, its CPF1 profile member and that profile's digest.
struct Fixture {
    archive: Vec<u8>,
    profile: Vec<u8>,
    profile_digest: [u8; 32],
}

static FIXTURE: OnceLock<Result<Fixture, String>> = OnceLock::new();

fn materialize() -> TestResult<Fixture> {
    let archive = support::current_archive()?;
    let bundle = ConformanceBundleV1::from_canonical_cbor(&archive)?;
    let profile = bundle
        .members
        .iter()
        .find(|member| member.role == BundleMemberRoleV1::Profile)
        .ok_or("the archive has no CPF1 profile member")?
        .bytes
        .clone();
    let profile_digest = ConformanceProfileV1::from_canonical_cbor(&profile)?.profile_digest;
    Ok(Fixture {
        archive,
        profile,
        profile_digest,
    })
}

fn fixture() -> TestResult<&'static Fixture> {
    FIXTURE
        .get_or_init(|| materialize().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| error.clone().into())
}

/// The four non-report subjects: a real CPF1 profile and CFB1 archive.
fn artifacts() -> TestResult<ReportAttestationArtifactsV1<'static>> {
    let fixture = fixture()?;
    Ok(ReportAttestationArtifactsV1 {
        subject_artifact: SUBJECT_ARTIFACT,
        profile_cpf1: &fixture.profile,
        fixture_bundle: &fixture.archive,
        evaluator_binary: EVALUATOR_BINARY,
    })
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn other_signer() -> SigningKey {
    SigningKey::from_bytes(&[8; 32])
}

/// The trust double: admits the report-signing keys it holds unless it refuses every key,
/// refuses the revoked digests it holds, and records every call of both steps.
struct TrustDouble {
    keys: Vec<VerifyingKey>,
    key_refusal: Option<ConformanceKeyRefusalV1>,
    revoked_reports: Vec<[u8; 32]>,
    revoked_binaries: Vec<[u8; 32]>,
    key_calls: RefCell<Vec<(ConformanceTrustRoleV1, [u8; 32])>>,
    revocation_calls: RefCell<Vec<RevocationCall>>,
}

impl TrustDouble {
    fn admitting(key: &SigningKey) -> Self {
        Self {
            keys: vec![key.verifying_key()],
            key_refusal: None,
            revoked_reports: Vec::new(),
            revoked_binaries: Vec::new(),
            key_calls: RefCell::new(Vec::new()),
            revocation_calls: RefCell::new(Vec::new()),
        }
    }

    fn refusing(refusal: ConformanceKeyRefusalV1) -> Self {
        Self {
            key_refusal: Some(refusal),
            ..Self::admitting(&signer())
        }
    }

    fn call_count(&self) -> usize {
        self.key_calls.borrow().len() + self.revocation_calls.borrow().len()
    }
}

impl ConformanceTrustAdmissionPortV1 for TrustDouble {
    fn admit_key(
        &self,
        role: ConformanceTrustRoleV1,
        key_id: &[u8; 32],
    ) -> Result<VerifyingKey, ConformanceKeyRefusalV1> {
        self.key_calls.borrow_mut().push((role, *key_id));
        if let Some(refusal) = self.key_refusal {
            return Err(refusal);
        }
        self.keys
            .iter()
            .copied()
            .find(|key| key_id_v1(key) == *key_id)
            .ok_or(ConformanceKeyRefusalV1::UnknownRoot)
    }

    fn check_artifact_revocation(
        &self,
        report_digest: &[u8; 32],
        evaluator_binary_digest: &[u8; 32],
    ) -> Result<(), ConformanceArtifactRefusalV1> {
        self.revocation_calls
            .borrow_mut()
            .push((*report_digest, *evaluator_binary_digest));
        if self.revoked_reports.contains(report_digest) {
            Err(ConformanceArtifactRefusalV1::RevokedReport)
        } else if self.revoked_binaries.contains(evaluator_binary_digest) {
            Err(ConformanceArtifactRefusalV1::RevokedEvaluatorBinary)
        } else {
            Ok(())
        }
    }
}

/// A misconfigured trust port that resolves every key id to one fixed key.
struct FixedKey(VerifyingKey);

impl ConformanceTrustAdmissionPortV1 for FixedKey {
    fn admit_key(
        &self,
        _role: ConformanceTrustRoleV1,
        _key_id: &[u8; 32],
    ) -> Result<VerifyingKey, ConformanceKeyRefusalV1> {
        Ok(self.0)
    }

    fn check_artifact_revocation(
        &self,
        _report_digest: &[u8; 32],
        _evaluator_binary_digest: &[u8; 32],
    ) -> Result<(), ConformanceArtifactRefusalV1> {
        Ok(())
    }
}

fn report(outcome: CaseOutcomeStatusV1) -> TestResult<ConformanceReportV1> {
    report_with(outcome, |_| {})
}

/// A valid CNR1 report bound to the fixture subjects, after `edit` and a fresh self digest.
fn report_with(
    outcome: CaseOutcomeStatusV1,
    edit: impl FnOnce(&mut ConformanceReportV1),
) -> TestResult<ConformanceReportV1> {
    let fixture = fixture()?;
    let failing = outcome == CaseOutcomeStatusV1::Fail;
    let case = CaseOutcomeV1 {
        case_id: "case-00001".to_owned(),
        fixture_digest: [3; 32],
        execution_profile_digest: [4; 32],
        mode: ExecutionModeV1::Local,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        outcome,
        first_coordinate: failing.then(|| vec![1, 2]),
        expected_digest: Some([7; 32]),
        actual_digest: Some(if failing { [8; 32] } else { [7; 32] }),
        expected_error: None,
        actual_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        provenance_digest: [6; 32],
    };
    let mut report = ConformanceReportV1 {
        report_id: [1; 16],
        subject_artifact_digest: *blake3::hash(SUBJECT_ARTIFACT).as_bytes(),
        profile_digest: fixture.profile_digest,
        normative_spec_digest: [4; 32],
        execution_profile_digest: [5; 32],
        fixture_bundle_digest: *blake3::hash(&fixture.archive).as_bytes(),
        evaluator_source_digest: [7; 32],
        evaluator_binary_digest: *blake3::hash(EVALUATOR_BINARY).as_bytes(),
        evaluator_protocol_digest: [9; 32],
        implementation: ImplementationIdentityV1 {
            implementation_id: "independent".to_owned(),
            source_digest: [10; 32],
            build_digest: [11; 32],
            binary_digest: [12; 32],
            public_contract_digest: [13; 32],
            organization_id: None,
        },
        independence: IndependenceEvidenceV1 {
            technical_independent: true,
            authorship_independent: true,
            organizational_independent: false,
            declaration_digest: [14; 32],
            shared_code_audit_digest: [15; 32],
            reviewer_ids: vec!["reviewer".to_owned()],
        },
        passed: u32::from(!failing),
        failed: u32::from(failing),
        skipped: 0,
        unavailable: 0,
        not_applicable: 0,
        cases: vec![case],
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        limitations_digest: [16; 32],
        evaluator_build_provenance_digest: [17; 32],
        report_digest: [0; 32],
    };
    edit(&mut report);
    report.report_digest = report.digest()?;
    report.validate()?;
    Ok(report)
}

fn passing_cnr1() -> TestResult<Vec<u8>> {
    Ok(report(CaseOutcomeStatusV1::Pass)?.to_canonical_cbor()?)
}

fn hex(bytes: [u8; 32]) -> String {
    blake3::Hash::from_bytes(bytes).to_hex().to_string()
}

fn digests(bytes: &[u8]) -> (String, String) {
    (
        blake3::hash(bytes).to_hex().to_string(),
        hex(Sha256::digest(bytes).into()),
    )
}

fn signed(cnr1: &[u8]) -> TestResult<Vec<u8>> {
    Ok(sign_report_attestation_v1(
        cnr1,
        artifacts()?,
        None,
        &signer(),
    )?)
}

fn statement_of(envelope: &[u8]) -> TestResult<Value> {
    let envelope = DsseEnvelopeV1::from_canonical_json(envelope, MAX_REPORT_ATTESTATION_BYTES_V1)?;
    Ok(serde_json::from_slice(envelope.payload())?)
}

/// Re-sign an edited Statement with the trusted key, so verification reaches the later steps.
fn resigned(statement: &Value) -> TestResult<Vec<u8>> {
    let payload = JsonV1::from_json_value(statement.clone())
        .ok_or("the edited Statement is JSON")?
        .canonical();
    Ok(DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, payload, &signer()).to_canonical_json())
}

fn verify(envelope: &[u8]) -> TestResult<Result<SignatureMeaningV1, Error>> {
    Ok(
        verify_report_attestation_v1(envelope, &TrustDouble::admitting(&signer()), artifacts()?)
            .map(|verified| verified.signature_meaning()),
    )
}

#[test]
fn golden_statement_predicate_and_envelope_round_trip_canonically() -> TestResult {
    let report = report(CaseOutcomeStatusV1::Pass)?;
    let cnr1 = report.to_canonical_cbor()?;
    let artifacts = artifacts()?;
    let subjects = [
        &cnr1[..],
        artifacts.subject_artifact,
        artifacts.profile_cpf1,
        artifacts.fixture_bundle,
        artifacts.evaluator_binary,
    ]
    .into_iter()
    .zip(REPORT_ATTESTATION_SUBJECT_NAMES_V1)
    .map(|(bytes, name)| {
        let (blake3_hex, sha256_hex) = digests(bytes);
        format!(
            r#"{{"digest":{{"blake3":"{blake3_hex}","sha256":"{sha256_hex}"}},"name":"{name}"}}"#
        )
    })
    .collect::<Vec<_>>()
    .join(",");
    let golden_statement = format!(
        concat!(
            r#"{{"_type":"https://in-toto.io/Statement/v1","#,
            r#""predicate":{{"diagnostics_digest_or_null":"{diagnostics}","#,
            r#""independence":{{"authorship":true,"organizational":false,"technical":true}},"#,
            r#""report_cnr1":"{cnr1}","report_digest":"{digest}","#,
            r#""schema":"PiglorOS.ConformanceReportPredicate.v1","#,
            r#""signature_meaning":"attribution-only"}},"#,
            r#""predicateType":"https://piglor.com/pigloros/attestation/conformance-report/v1","#,
            r#""subject":[{subjects}]}}"#,
        ),
        diagnostics = hex([42; 32]),
        cnr1 = STANDARD.encode(&cnr1),
        digest = hex(report.report_digest),
        subjects = subjects,
    );

    let trust = TrustDouble::admitting(&signer());
    let envelope = sign_report_attestation_v1(&cnr1, artifacts, Some([42; 32]), &signer())?;
    let parsed = DsseEnvelopeV1::from_canonical_json(&envelope, MAX_REPORT_ATTESTATION_BYTES_V1)?;
    assert_eq!(std::str::from_utf8(parsed.payload())?, golden_statement);
    assert!(parsed.has_payload_type(IN_TOTO_PAYLOAD_TYPE_V1));
    assert_eq!(parsed.verify(&signer().verifying_key()), Ok(()));
    assert_eq!(parsed.to_canonical_json(), envelope);
    assert_eq!(
        JsonV1::parse_canonical(parsed.payload()).map(|value| value.canonical()),
        Some(parsed.payload().to_vec())
    );

    let verified = verify_report_attestation_v1(&envelope, &trust, artifacts)?;
    assert_eq!(verified.report(), &report);
    assert_eq!(verified.report().to_canonical_cbor()?, cnr1);
    assert_eq!(verified.key_id(), &key_id_v1(&signer().verifying_key()));
    assert_eq!(verified.diagnostics_digest(), Some([42; 32]));
    assert_eq!(
        verified.signature_meaning(),
        SignatureMeaningV1::AttributionOnly
    );
    assert_eq!(
        trust.key_calls.borrow().as_slice(),
        &[(
            ConformanceTrustRoleV1::ReportSigning,
            key_id_v1(&signer().verifying_key()),
        )]
    );
    // Artifact revocation sees the digests of the parsed CNR1 report.
    assert_eq!(
        trust.revocation_calls.borrow().as_slice(),
        &[(report.report_digest, report.evaluator_binary_digest)]
    );

    // Signing is deterministic, and a report without diagnostics carries `null`.
    assert_eq!(
        sign_report_attestation_v1(&cnr1, artifacts, Some([42; 32]), &signer())?,
        envelope
    );
    let without = signed(&cnr1)?;
    assert_eq!(
        statement_of(&without)?["predicate"]["diagnostics_digest_or_null"],
        Value::Null
    );
    let verified = verify_report_attestation_v1(&without, &trust, artifacts)?;
    assert_eq!(verified.diagnostics_digest(), None);
    Ok(())
}

#[test]
fn a_valid_signature_over_a_failing_report_stays_a_failing_report() -> TestResult {
    let artifacts = artifacts()?;
    let failing = report(CaseOutcomeStatusV1::Fail)?;
    let envelope = signed(&failing.to_canonical_cbor()?)?;
    let verified =
        verify_report_attestation_v1(&envelope, &TrustDouble::admitting(&signer()), artifacts)?;
    assert_eq!(verified.report(), &failing);
    assert_eq!((verified.report().passed, verified.report().failed), (0, 1));
    assert_eq!(
        verified.report().cases[0].outcome,
        CaseOutcomeStatusV1::Fail
    );
    assert_eq!(
        verified.signature_meaning(),
        SignatureMeaningV1::AttributionOnly
    );
    assert_eq!(
        statement_of(&envelope)?["predicate"]["signature_meaning"],
        json!("attribution-only")
    );
    Ok(())
}

#[test]
fn only_a_valid_strict_cnr1_report_is_signed() -> TestResult {
    let artifacts = artifacts()?;
    let mut cnr1 = passing_cnr1()?;
    let last = cnr1.len() - 1;
    cnr1[last] ^= 1;
    for invalid in [&b"not CNR1"[..], &cnr1[..], &[][..]] {
        assert_eq!(
            sign_report_attestation_v1(invalid, artifacts, None, &signer()),
            Err(Error::EmbeddedReport)
        );
    }
    Ok(())
}

#[test]
fn oversized_or_malformed_input_is_refused_at_bounded_parse() -> TestResult {
    let artifacts = artifacts()?;
    let trust = TrustDouble::admitting(&signer());
    // One byte over the bound and not JSON at all: refused on length before any parse.
    let oversized = vec![0xff; MAX_REPORT_ATTESTATION_BYTES_V1 + 1];
    assert_eq!(
        verify_report_attestation_v1(&oversized, &trust, artifacts),
        Err(Error::BoundedParse(DsseParseErrorV1::Oversized))
    );
    // Exactly at the bound: parsed, and refused as malformed rather than oversized.
    let at_bound = vec![b' '; MAX_REPORT_ATTESTATION_BYTES_V1];
    assert_eq!(
        verify_report_attestation_v1(&at_bound, &trust, artifacts),
        Err(Error::BoundedParse(DsseParseErrorV1::Malformed))
    );
    let envelope = String::from_utf8(signed(&passing_cnr1()?)?)?;
    for malformed in [
        String::new(),
        "{}".to_owned(),
        "[".repeat(4096),
        envelope.replace(':', ": "),
        envelope.replacen('{', "{\"extra\":null,", 1),
    ] {
        assert_eq!(
            verify_report_attestation_v1(malformed.as_bytes(), &trust, artifacts),
            Err(Error::BoundedParse(DsseParseErrorV1::Malformed)),
            "{malformed:.80}"
        );
    }
    assert_eq!(trust.call_count(), 0);
    Ok(())
}

#[test]
fn a_foreign_payload_type_is_refused_before_key_admission() -> TestResult {
    let artifacts = artifacts()?;
    let envelope = signed(&passing_cnr1()?)?;
    let statement =
        DsseEnvelopeV1::from_canonical_json(&envelope, MAX_REPORT_ATTESTATION_BYTES_V1)?
            .payload()
            .to_vec();
    let edited = String::from_utf8(envelope)?.replace(
        "\"payloadType\":\"application/vnd.in-toto+json\"",
        "\"payloadType\":\"application/vnd.in-toto+jsom\"",
    );
    let resigned_type =
        DsseEnvelopeV1::sign("application/json", statement, &signer()).to_canonical_json();
    let trust = TrustDouble::admitting(&signer());
    for envelope in [edited.into_bytes(), resigned_type] {
        assert_eq!(
            verify_report_attestation_v1(&envelope, &trust, artifacts),
            Err(Error::PayloadType)
        );
    }
    assert_eq!(trust.call_count(), 0);
    Ok(())
}

#[test]
fn key_admission_refusals_and_an_unknown_key_id_are_closed() -> TestResult {
    let artifacts = artifacts()?;
    let envelope = signed(&passing_cnr1()?)?;
    for refusal in [
        ConformanceKeyRefusalV1::UnknownRoot,
        ConformanceKeyRefusalV1::RoleMismatch,
        ConformanceKeyRefusalV1::Revoked,
        ConformanceKeyRefusalV1::RolledBack,
        ConformanceKeyRefusalV1::SnapshotStale,
    ] {
        let trust = TrustDouble::refusing(refusal);
        assert_eq!(
            verify_report_attestation_v1(&envelope, &trust, artifacts),
            Err(Error::KeyAdmission(refusal))
        );
        assert_eq!(trust.call_count(), 1);
    }
    // The signer is not a root: refused before its signature is checked.
    assert_eq!(
        verify_report_attestation_v1(
            &envelope,
            &TrustDouble::admitting(&other_signer()),
            artifacts
        ),
        Err(Error::KeyAdmission(ConformanceKeyRefusalV1::UnknownRoot))
    );
    // A tampered key id names no admitted root.
    let tampered = String::from_utf8(envelope)?.replace(
        &hex(key_id_v1(&signer().verifying_key())),
        &hex(key_id_v1(&other_signer().verifying_key())),
    );
    assert_eq!(
        verify(tampered.as_bytes())?,
        Err(Error::KeyAdmission(ConformanceKeyRefusalV1::UnknownRoot))
    );
    Ok(())
}

#[test]
fn a_tampered_signature_or_payload_fails_the_signature_step() -> TestResult {
    let artifacts = artifacts()?;
    let envelope = signed(&passing_cnr1()?)?;
    let text = String::from_utf8(envelope.clone())?;
    let value: Value = serde_json::from_str(&text)?;
    let sig = value["signatures"][0]["sig"].as_str().ok_or("sig")?;
    let mut signature = STANDARD.decode(sig)?;
    signature[0] ^= 1;
    let bad_signature = text.replace(sig, &STANDARD.encode(&signature));
    assert_eq!(
        verify(bad_signature.as_bytes())?,
        Err(Error::Signature(DsseSignatureErrorV1::InvalidSignature))
    );

    let payload = value["payload"].as_str().ok_or("payload")?;
    let mut statement = statement_of(&envelope)?;
    statement["predicate"]["independence"]["organizational"] = json!(true);
    let edited = JsonV1::from_json_value(statement)
        .ok_or("Statement")?
        .canonical();
    let bad_payload = text.replace(payload, &STANDARD.encode(edited));
    assert_eq!(
        verify(bad_payload.as_bytes())?,
        Err(Error::Signature(DsseSignatureErrorV1::InvalidSignature))
    );

    // A port that resolves the key id to another key is caught by the key-id check.
    assert_eq!(
        verify_report_attestation_v1(
            &envelope,
            &FixedKey(other_signer().verifying_key()),
            artifacts
        ),
        Err(Error::Signature(DsseSignatureErrorV1::KeyIdMismatch))
    );
    Ok(())
}

#[test]
fn every_statement_and_predicate_shape_violation_is_refused() -> TestResult {
    let statement = statement_of(&signed(&passing_cnr1()?)?)?;
    let edits: [(&str, Edit); 26] = [
        ("_type", |s| {
            s["_type"] = json!("https://in-toto.io/Statement/v0.1");
        }),
        ("predicateType", |s| {
            s["predicateType"] =
                json!("https://piglor.com/pigloros/attestation/conformance-report/v2");
        }),
        ("schema", |s| {
            s["predicate"]["schema"] = json!("PiglorOS.ConformanceReportPredicate.v2");
        }),
        ("signature_meaning", |s| {
            s["predicate"]["signature_meaning"] = json!("correctness");
        }),
        ("extra Statement member", |s| s["extra"] = json!(null)),
        ("missing predicate member", |s| {
            if let Some(predicate) = s["predicate"].as_object_mut() {
                assert!(predicate.remove("diagnostics_digest_or_null").is_some());
            }
        }),
        ("extra predicate member", |s| {
            s["predicate"]["extra"] = json!(true);
        }),
        ("predicate not an object", |s| s["predicate"] = json!([])),
        ("four subjects", |s| {
            if let Some(subjects) = s["subject"].as_array_mut() {
                assert!(subjects.pop().is_some());
            }
        }),
        ("subject not an array", |s| s["subject"] = json!({})),
        ("subject not an object", |s| {
            s["subject"][4] = json!("evaluator-binary");
        }),
        ("subjects reordered", |s| {
            if let Some(subjects) = s["subject"].as_array_mut() {
                subjects.swap(1, 2);
            }
        }),
        ("extra digest algorithm", |s| {
            s["subject"][0]["digest"]["sha512"] = json!("00");
        }),
        ("missing digest algorithm", |s| {
            if let Some(digest) = s["subject"][3]["digest"].as_object_mut() {
                assert!(digest.remove("sha256").is_some());
            }
        }),
        ("uppercase digest", |s| {
            let upper = s["subject"][2]["digest"]["blake3"]
                .as_str()
                .map(str::to_uppercase);
            s["subject"][2]["digest"]["blake3"] = json!(upper);
        }),
        ("short sha256 digest", |s| {
            s["subject"][1]["digest"]["sha256"] = json!("00");
        }),
        ("independence not boolean", |s| {
            s["predicate"]["independence"]["technical"] = json!("true");
        }),
        ("authorship not boolean", |s| {
            s["predicate"]["independence"]["authorship"] = json!(1);
        }),
        ("organizational not boolean", |s| {
            s["predicate"]["independence"]["organizational"] = json!(null);
        }),
        ("extra independence member", |s| {
            s["predicate"]["independence"]["shared_code"] = json!(false);
        }),
        ("report_cnr1 not base64", |s| {
            s["predicate"]["report_cnr1"] = json!("%%%%");
        }),
        ("report_cnr1 not text", |s| {
            s["predicate"]["report_cnr1"] = json!(7);
        }),
        ("report_digest short", |s| {
            s["predicate"]["report_digest"] = json!("abcd");
        }),
        ("diagnostics digest invalid", |s| {
            s["predicate"]["diagnostics_digest_or_null"] = json!("zz");
        }),
        ("diagnostics digest not text", |s| {
            s["predicate"]["diagnostics_digest_or_null"] = json!(false);
        }),
        ("Statement not an object", |s| *s = json!([])),
    ];
    for (name, edit) in edits {
        let mut edited = statement.clone();
        edit(&mut edited);
        assert_eq!(
            verify(&resigned(&edited)?)?,
            Err(Error::StatementShape),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn a_payload_that_is_not_canonical_json_fails_the_shape_step() -> TestResult {
    for payload in [&b"not JSON"[..], b"{\"_type\": 1}"] {
        let envelope = DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, payload.to_vec(), &signer());
        assert_eq!(
            verify(&envelope.to_canonical_json())?,
            Err(Error::StatementShape)
        );
    }
    Ok(())
}

#[test]
fn each_subject_digest_is_recomputed() -> TestResult {
    let artifacts = artifacts()?;
    let cnr1 = passing_cnr1()?;
    let statement = statement_of(&signed(&cnr1)?)?;
    let other = digests(b"other bytes");
    for index in 0..REPORT_ATTESTATION_SUBJECT_NAMES_V1.len() {
        for (algorithm, replacement) in [("blake3", &other.0), ("sha256", &other.1)] {
            let mut edited = statement.clone();
            edited["subject"][index]["digest"][algorithm] = json!(replacement);
            assert_eq!(
                verify(&resigned(&edited)?)?,
                Err(Error::SubjectDigest),
                "{index} {algorithm}"
            );
        }
    }

    // The verifier's own artifacts are the reference: any other artifact bytes are refused.
    let envelope = signed(&cnr1)?;
    let trust = TrustDouble::admitting(&signer());
    for artifacts in [
        ReportAttestationArtifactsV1 {
            subject_artifact: b"x",
            ..artifacts
        },
        ReportAttestationArtifactsV1 {
            profile_cpf1: b"x",
            ..artifacts
        },
        ReportAttestationArtifactsV1 {
            fixture_bundle: b"x",
            ..artifacts
        },
        ReportAttestationArtifactsV1 {
            evaluator_binary: b"x",
            ..artifacts
        },
    ] {
        assert_eq!(
            verify_report_attestation_v1(&envelope, &trust, artifacts),
            Err(Error::SubjectDigest)
        );
    }

    // Embedded CNR1 bytes changed without their subject digests.
    let mut edited = statement;
    let mut tampered = cnr1;
    tampered[3] ^= 1;
    edited["predicate"]["report_cnr1"] = json!(STANDARD.encode(&tampered));
    assert_eq!(verify(&resigned(&edited)?)?, Err(Error::SubjectDigest));
    Ok(())
}

#[test]
fn embedded_bytes_that_are_not_a_strict_cnr1_report_are_refused() -> TestResult {
    let cnr1 = passing_cnr1()?;
    let statement = statement_of(&signed(&cnr1)?)?;
    let mut tampered = cnr1.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut trailing = cnr1;
    trailing.push(0);
    for bytes in [tampered, trailing, b"not CNR1".to_vec()] {
        // A signer that attests arbitrary bytes, with consistent subject digests.
        let (blake3_hex, sha256_hex) = digests(&bytes);
        let mut edited = statement.clone();
        edited["predicate"]["report_cnr1"] = json!(STANDARD.encode(&bytes));
        edited["subject"][0]["digest"] = json!({"blake3": blake3_hex, "sha256": sha256_hex});
        assert_eq!(verify(&resigned(&edited)?)?, Err(Error::EmbeddedReport));
    }
    Ok(())
}

#[test]
fn predicate_copies_that_differ_from_the_cnr1_report_are_refused() -> TestResult {
    let statement = statement_of(&signed(&passing_cnr1()?)?)?;
    let edits: [(&str, Edit); 4] = [
        ("report_digest", |s| {
            s["predicate"]["report_digest"] = json!(hex([0x5a; 32]));
        }),
        ("technical", |s| {
            s["predicate"]["independence"]["technical"] = json!(false);
        }),
        ("authorship", |s| {
            s["predicate"]["independence"]["authorship"] = json!(false);
        }),
        ("organizational", |s| {
            s["predicate"]["independence"]["organizational"] = json!(true);
        }),
    ];
    for (name, edit) in edits {
        let mut edited = statement.clone();
        edit(&mut edited);
        assert_eq!(
            verify(&resigned(&edited)?)?,
            Err(Error::PredicateMismatch),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn every_refusal_names_its_step() {
    for (error, expected) in [
        (
            Error::BoundedParse(DsseParseErrorV1::Oversized),
            "bounded parse",
        ),
        (Error::PayloadType, "payloadType"),
        (
            Error::KeyAdmission(ConformanceKeyRefusalV1::Revoked),
            "Revoked",
        ),
        (
            Error::SubjectBinding(BoundSubjectV1::Profile),
            "CNR1 field: Profile",
        ),
        (
            Error::ArtifactRevocation(ConformanceArtifactRefusalV1::RevokedReport),
            "revoked: RevokedReport",
        ),
        (
            Error::Signature(DsseSignatureErrorV1::InvalidSignature),
            "signature",
        ),
        (Error::StatementShape, "Statement shape"),
        (Error::SubjectDigest, "subject digest"),
        (Error::EmbeddedReport, "CNR1"),
        (Error::PredicateMismatch, "predicate copy"),
    ] {
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn each_bound_subject_must_reproduce_its_cnr1_field() -> TestResult {
    let artifacts = artifacts()?;
    let trust = TrustDouble::admitting(&signer());
    let cases: [(BoundSubjectV1, ReportEdit); 4] = [
        (BoundSubjectV1::SubjectArtifact, |report| {
            report.subject_artifact_digest = [0x50; 32];
        }),
        (BoundSubjectV1::Profile, |report| {
            report.profile_digest = [0x51; 32];
        }),
        (BoundSubjectV1::FixtureBundle, |report| {
            report.fixture_bundle_digest = [0x52; 32];
        }),
        (BoundSubjectV1::EvaluatorBinary, |report| {
            report.evaluator_binary_digest = [0x53; 32];
        }),
    ];
    for (subject, edit) in cases {
        // The Statement subjects match the artifacts; only the CNR1 field differs.
        let cnr1 = report_with(CaseOutcomeStatusV1::Pass, edit)?.to_canonical_cbor()?;
        let envelope = sign_report_attestation_v1(&cnr1, artifacts, None, &signer())?;
        assert_eq!(
            verify_report_attestation_v1(&envelope, &trust, artifacts),
            Err(Error::SubjectBinding(subject)),
            "{subject:?}"
        );
    }

    // Artifacts that are not a valid CPF1 profile or CFB1 archive reproduce no CNR1 field.
    let cnr1 = passing_cnr1()?;
    for (subject, unbound) in [
        (
            BoundSubjectV1::Profile,
            ReportAttestationArtifactsV1 {
                profile_cpf1: b"not CPF1",
                ..artifacts
            },
        ),
        (
            BoundSubjectV1::FixtureBundle,
            ReportAttestationArtifactsV1 {
                fixture_bundle: b"not CFB1",
                ..artifacts
            },
        ),
    ] {
        let envelope = sign_report_attestation_v1(&cnr1, unbound, None, &signer())?;
        assert_eq!(
            verify_report_attestation_v1(&envelope, &trust, unbound),
            Err(Error::SubjectBinding(subject)),
            "{subject:?}"
        );
    }
    // Binding runs before artifact revocation.
    assert!(trust.revocation_calls.borrow().is_empty());
    Ok(())
}

#[test]
fn revoked_report_or_evaluator_binary_digests_are_refused_after_the_cnr1_parse() -> TestResult {
    let artifacts = artifacts()?;
    let report = report(CaseOutcomeStatusV1::Pass)?;
    let envelope = signed(&report.to_canonical_cbor()?)?;
    let revoked_report = TrustDouble {
        revoked_reports: vec![report.report_digest],
        ..TrustDouble::admitting(&signer())
    };
    assert_eq!(
        verify_report_attestation_v1(&envelope, &revoked_report, artifacts),
        Err(Error::ArtifactRevocation(
            ConformanceArtifactRefusalV1::RevokedReport
        ))
    );
    assert_eq!(
        revoked_report.revocation_calls.borrow().as_slice(),
        &[(report.report_digest, report.evaluator_binary_digest)]
    );
    let revoked_binary = TrustDouble {
        revoked_binaries: vec![report.evaluator_binary_digest],
        ..TrustDouble::admitting(&signer())
    };
    assert_eq!(
        verify_report_attestation_v1(&envelope, &revoked_binary, artifacts),
        Err(Error::ArtifactRevocation(
            ConformanceArtifactRefusalV1::RevokedEvaluatorBinary
        ))
    );
    let unrelated = TrustDouble {
        revoked_reports: vec![[0x61; 32]],
        revoked_binaries: vec![[0x62; 32]],
        ..TrustDouble::admitting(&signer())
    };
    assert!(verify_report_attestation_v1(&envelope, &unrelated, artifacts).is_ok());

    // Revocation runs before the predicate copies are compared.
    let mut statement = statement_of(&envelope)?;
    statement["predicate"]["report_digest"] = json!(hex([0x5a; 32]));
    assert_eq!(
        verify_report_attestation_v1(&resigned(&statement)?, &revoked_report, artifacts),
        Err(Error::ArtifactRevocation(
            ConformanceArtifactRefusalV1::RevokedReport
        ))
    );

    // An embedded report that does not parse never reaches revocation.
    let mut statement = statement_of(&envelope)?;
    let (blake3_hex, sha256_hex) = digests(b"not CNR1");
    statement["predicate"]["report_cnr1"] = json!(STANDARD.encode(b"not CNR1"));
    statement["subject"][0]["digest"] = json!({"blake3": blake3_hex, "sha256": sha256_hex});
    let trust = TrustDouble::admitting(&signer());
    assert_eq!(
        verify_report_attestation_v1(&resigned(&statement)?, &trust, artifacts),
        Err(Error::EmbeddedReport)
    );
    assert!(trust.revocation_calls.borrow().is_empty());
    Ok(())
}
