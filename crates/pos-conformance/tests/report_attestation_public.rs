#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! ADR-062 Revision 8 slice G1 (#1236): the signed conformance-report attestation through its
//! public seams, `sign_report_attestation_v1` and `verify_report_attestation_v1`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pos_conformance::{
    sign_report_attestation_v1, verify_report_attestation_v1, CaseOutcomeStatusV1, CaseOutcomeV1,
    ClaimLayerV1, ConformanceReportV1, ConformanceTrustAdmissionPortV1, ConformanceTrustRefusalV1,
    ConformanceTrustRoleV1, ExecutionModeV1, ImplementationIdentityV1, IndependenceEvidenceV1,
    RedactionStateV1, ReplayClaimV1, ReportAttestationArtifactsV1,
    ReportAttestationErrorV1 as Error, SignatureMeaningV1, MAX_REPORT_ATTESTATION_BYTES_V1,
    REPORT_ATTESTATION_SUBJECT_NAMES_V1,
};
use pos_crypto::dsse::{
    key_id_v1, DsseEnvelopeV1, DsseParseErrorV1, DsseSignatureErrorV1, IN_TOTO_PAYLOAD_TYPE_V1,
};
use pos_crypto::jcs::JsonV1;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::cell::RefCell;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One recorded trust-admission call: role, key id, artifact digest.
type AdmissionCall = (ConformanceTrustRoleV1, [u8; 32], [u8; 32]);

/// One edit of a decoded Statement.
type Edit = fn(&mut Value);

const ARTIFACTS: ReportAttestationArtifactsV1<'static> = ReportAttestationArtifactsV1 {
    subject_artifact: b"subject artifact",
    profile_cpf1: b"CPF1 profile",
    fixture_bundle: b"fixture bundle",
    evaluator_binary: b"evaluator binary",
};

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn other_signer() -> SigningKey {
    SigningKey::from_bytes(&[8; 32])
}

/// The trust-admission double: admits the report-signing keys it holds, or refuses with a
/// fixed refusal, and records every call.
struct TrustDouble {
    keys: Vec<VerifyingKey>,
    refusal: Option<ConformanceTrustRefusalV1>,
    calls: RefCell<Vec<AdmissionCall>>,
}

impl TrustDouble {
    fn admitting(key: &SigningKey) -> Self {
        Self {
            keys: vec![key.verifying_key()],
            refusal: None,
            calls: RefCell::new(Vec::new()),
        }
    }

    const fn refusing(refusal: ConformanceTrustRefusalV1) -> Self {
        Self {
            keys: Vec::new(),
            refusal: Some(refusal),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.borrow().len()
    }
}

impl ConformanceTrustAdmissionPortV1 for TrustDouble {
    fn admit(
        &self,
        role: ConformanceTrustRoleV1,
        key_id: &[u8; 32],
        artifact_digest: &[u8; 32],
    ) -> Result<VerifyingKey, ConformanceTrustRefusalV1> {
        self.calls
            .borrow_mut()
            .push((role, *key_id, *artifact_digest));
        if let Some(refusal) = self.refusal {
            return Err(refusal);
        }
        self.keys
            .iter()
            .copied()
            .find(|key| key_id_v1(key) == *key_id)
            .ok_or(ConformanceTrustRefusalV1::UnknownRoot)
    }
}

/// A misconfigured trust port that resolves every key id to one fixed key.
struct FixedKey(VerifyingKey);

impl ConformanceTrustAdmissionPortV1 for FixedKey {
    fn admit(
        &self,
        _role: ConformanceTrustRoleV1,
        _key_id: &[u8; 32],
        _artifact_digest: &[u8; 32],
    ) -> Result<VerifyingKey, ConformanceTrustRefusalV1> {
        Ok(self.0)
    }
}

fn report(outcome: CaseOutcomeStatusV1) -> TestResult<ConformanceReportV1> {
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
        subject_artifact_digest: [2; 32],
        profile_digest: [3; 32],
        normative_spec_digest: [4; 32],
        execution_profile_digest: [5; 32],
        fixture_bundle_digest: [6; 32],
        evaluator_source_digest: [7; 32],
        evaluator_binary_digest: [8; 32],
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
        ARTIFACTS,
        None,
        &signer(),
    )?)
}

fn statement_of(envelope: &[u8]) -> TestResult<Value> {
    let envelope = DsseEnvelopeV1::from_json(envelope, MAX_REPORT_ATTESTATION_BYTES_V1)?;
    Ok(serde_json::from_slice(envelope.payload())?)
}

/// Re-sign an edited Statement with the trusted key, so verification reaches the later steps.
fn resigned(statement: &Value) -> TestResult<Vec<u8>> {
    let payload = JsonV1::from_json_value(statement.clone())
        .ok_or("the edited Statement is JSON")?
        .canonical();
    Ok(DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, payload, &signer()).to_json())
}

fn verify(envelope: &[u8]) -> Result<SignatureMeaningV1, Error> {
    verify_report_attestation_v1(envelope, &TrustDouble::admitting(&signer()), ARTIFACTS)
        .map(|verified| verified.signature_meaning())
}

#[test]
fn golden_statement_predicate_and_envelope_round_trip_canonically() -> TestResult {
    let report = report(CaseOutcomeStatusV1::Pass)?;
    let cnr1 = report.to_canonical_cbor()?;
    let subjects = [
        &cnr1[..],
        ARTIFACTS.subject_artifact,
        ARTIFACTS.profile_cpf1,
        ARTIFACTS.fixture_bundle,
        ARTIFACTS.evaluator_binary,
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
    let envelope = sign_report_attestation_v1(&cnr1, ARTIFACTS, Some([42; 32]), &signer())?;
    let parsed = DsseEnvelopeV1::from_json(&envelope, MAX_REPORT_ATTESTATION_BYTES_V1)?;
    assert_eq!(std::str::from_utf8(parsed.payload())?, golden_statement);
    assert!(parsed.has_payload_type(IN_TOTO_PAYLOAD_TYPE_V1));
    assert_eq!(parsed.verify(&signer().verifying_key()), Ok(()));
    assert_eq!(parsed.to_json(), envelope);
    assert_eq!(
        JsonV1::parse_canonical(parsed.payload()).map(|value| value.canonical()),
        Some(parsed.payload().to_vec())
    );

    let verified = verify_report_attestation_v1(&envelope, &trust, ARTIFACTS)?;
    assert_eq!(verified.report(), &report);
    assert_eq!(verified.report().to_canonical_cbor()?, cnr1);
    assert_eq!(verified.key_id(), &key_id_v1(&signer().verifying_key()));
    assert_eq!(verified.diagnostics_digest(), Some([42; 32]));
    assert_eq!(
        verified.signature_meaning(),
        SignatureMeaningV1::AttributionOnly
    );
    assert_eq!(
        trust.calls.borrow().as_slice(),
        &[(
            ConformanceTrustRoleV1::ReportSigning,
            key_id_v1(&signer().verifying_key()),
            *blake3::hash(parsed.payload()).as_bytes(),
        )]
    );

    // Signing is deterministic, and a report without diagnostics carries `null`.
    assert_eq!(
        sign_report_attestation_v1(&cnr1, ARTIFACTS, Some([42; 32]), &signer())?,
        envelope
    );
    let without = signed(&cnr1)?;
    assert_eq!(
        statement_of(&without)?["predicate"]["diagnostics_digest_or_null"],
        Value::Null
    );
    let verified = verify_report_attestation_v1(&without, &trust, ARTIFACTS)?;
    assert_eq!(verified.diagnostics_digest(), None);
    Ok(())
}

#[test]
fn a_valid_signature_over_a_failing_report_stays_a_failing_report() -> TestResult {
    let failing = report(CaseOutcomeStatusV1::Fail)?;
    let envelope = signed(&failing.to_canonical_cbor()?)?;
    let verified =
        verify_report_attestation_v1(&envelope, &TrustDouble::admitting(&signer()), ARTIFACTS)?;
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
    let mut cnr1 = passing_cnr1()?;
    let last = cnr1.len() - 1;
    cnr1[last] ^= 1;
    for invalid in [&b"not CNR1"[..], &cnr1[..], &[][..]] {
        assert_eq!(
            sign_report_attestation_v1(invalid, ARTIFACTS, None, &signer()),
            Err(Error::EmbeddedReport)
        );
    }
    Ok(())
}

#[test]
fn oversized_or_malformed_input_is_refused_at_bounded_parse() -> TestResult {
    let trust = TrustDouble::admitting(&signer());
    // One byte over the bound and not JSON at all: refused on length before any parse.
    let oversized = vec![0xff; MAX_REPORT_ATTESTATION_BYTES_V1 + 1];
    assert_eq!(
        verify_report_attestation_v1(&oversized, &trust, ARTIFACTS),
        Err(Error::BoundedParse(DsseParseErrorV1::Oversized))
    );
    // Exactly at the bound: parsed, and refused as malformed rather than oversized.
    let at_bound = vec![b' '; MAX_REPORT_ATTESTATION_BYTES_V1];
    assert_eq!(
        verify_report_attestation_v1(&at_bound, &trust, ARTIFACTS),
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
            verify_report_attestation_v1(malformed.as_bytes(), &trust, ARTIFACTS),
            Err(Error::BoundedParse(DsseParseErrorV1::Malformed)),
            "{malformed:.80}"
        );
    }
    assert_eq!(trust.call_count(), 0);
    Ok(())
}

#[test]
fn a_foreign_payload_type_is_refused_before_trust_admission() -> TestResult {
    let envelope = signed(&passing_cnr1()?)?;
    let statement = DsseEnvelopeV1::from_json(&envelope, MAX_REPORT_ATTESTATION_BYTES_V1)?
        .payload()
        .to_vec();
    let edited = String::from_utf8(envelope)?.replace(
        "\"payloadType\":\"application/vnd.in-toto+json\"",
        "\"payloadType\":\"application/vnd.in-toto+jsom\"",
    );
    let resigned_type = DsseEnvelopeV1::sign("application/json", statement, &signer()).to_json();
    let trust = TrustDouble::admitting(&signer());
    for envelope in [edited.into_bytes(), resigned_type] {
        assert_eq!(
            verify_report_attestation_v1(&envelope, &trust, ARTIFACTS),
            Err(Error::PayloadType)
        );
    }
    assert_eq!(trust.call_count(), 0);
    Ok(())
}

#[test]
fn trust_admission_refusals_and_an_unknown_key_id_are_closed() -> TestResult {
    let envelope = signed(&passing_cnr1()?)?;
    for refusal in [
        ConformanceTrustRefusalV1::UnknownRoot,
        ConformanceTrustRefusalV1::RoleMismatch,
        ConformanceTrustRefusalV1::Revoked,
        ConformanceTrustRefusalV1::RolledBack,
        ConformanceTrustRefusalV1::SnapshotStale,
    ] {
        let trust = TrustDouble::refusing(refusal);
        assert_eq!(
            verify_report_attestation_v1(&envelope, &trust, ARTIFACTS),
            Err(Error::TrustAdmission(refusal))
        );
        assert_eq!(trust.call_count(), 1);
    }
    // The signer is not a root: refused before its signature is checked.
    assert_eq!(
        verify_report_attestation_v1(
            &envelope,
            &TrustDouble::admitting(&other_signer()),
            ARTIFACTS
        ),
        Err(Error::TrustAdmission(
            ConformanceTrustRefusalV1::UnknownRoot
        ))
    );
    // A tampered key id names no admitted root.
    let tampered = String::from_utf8(envelope)?.replace(
        &hex(key_id_v1(&signer().verifying_key())),
        &hex(key_id_v1(&other_signer().verifying_key())),
    );
    assert_eq!(
        verify(tampered.as_bytes()),
        Err(Error::TrustAdmission(
            ConformanceTrustRefusalV1::UnknownRoot
        ))
    );
    Ok(())
}

#[test]
fn a_tampered_signature_or_payload_fails_the_signature_step() -> TestResult {
    let envelope = signed(&passing_cnr1()?)?;
    let text = String::from_utf8(envelope.clone())?;
    let value: Value = serde_json::from_str(&text)?;
    let sig = value["signatures"][0]["sig"].as_str().ok_or("sig")?;
    let mut signature = STANDARD.decode(sig)?;
    signature[0] ^= 1;
    let bad_signature = text.replace(sig, &STANDARD.encode(&signature));
    assert_eq!(
        verify(bad_signature.as_bytes()),
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
        verify(bad_payload.as_bytes()),
        Err(Error::Signature(DsseSignatureErrorV1::InvalidSignature))
    );

    // A port that resolves the key id to another key is caught by the key-id check.
    assert_eq!(
        verify_report_attestation_v1(
            &envelope,
            &FixedKey(other_signer().verifying_key()),
            ARTIFACTS
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
            verify(&resigned(&edited)?),
            Err(Error::StatementShape),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn a_payload_that_is_not_canonical_json_fails_the_shape_step() {
    for payload in [&b"not JSON"[..], b"{\"_type\": 1}"] {
        let envelope = DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, payload.to_vec(), &signer());
        assert_eq!(verify(&envelope.to_json()), Err(Error::StatementShape));
    }
}

#[test]
fn each_subject_digest_is_recomputed() -> TestResult {
    let cnr1 = passing_cnr1()?;
    let statement = statement_of(&signed(&cnr1)?)?;
    let other = digests(b"other bytes");
    for index in 0..REPORT_ATTESTATION_SUBJECT_NAMES_V1.len() {
        for (algorithm, replacement) in [("blake3", &other.0), ("sha256", &other.1)] {
            let mut edited = statement.clone();
            edited["subject"][index]["digest"][algorithm] = json!(replacement);
            assert_eq!(
                verify(&resigned(&edited)?),
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
            ..ARTIFACTS
        },
        ReportAttestationArtifactsV1 {
            profile_cpf1: b"x",
            ..ARTIFACTS
        },
        ReportAttestationArtifactsV1 {
            fixture_bundle: b"x",
            ..ARTIFACTS
        },
        ReportAttestationArtifactsV1 {
            evaluator_binary: b"x",
            ..ARTIFACTS
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
    assert_eq!(verify(&resigned(&edited)?), Err(Error::SubjectDigest));
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
        assert_eq!(verify(&resigned(&edited)?), Err(Error::EmbeddedReport));
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
            verify(&resigned(&edited)?),
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
            Error::TrustAdmission(ConformanceTrustRefusalV1::Revoked),
            "Revoked",
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
