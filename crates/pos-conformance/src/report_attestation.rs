//! The signed conformance-report attestation of ADR-062 Revision 8 section 5.1 (option P-A,
//! slice G1, #1236).
//!
//! The payload is an in-toto Statement v1 in RFC 8785 canonical JSON:
//!
//! ```text
//! {"_type":"https://in-toto.io/Statement/v1",
//!  "predicate":{"diagnostics_digest_or_null":<hex or null>,
//!               "independence":{"authorship":<bool>,"organizational":<bool>,"technical":<bool>},
//!               "report_cnr1":<base64 of the exact CNR1 bytes>,
//!               "report_digest":<hex of CNR1 field report_digest>,
//!               "schema":"PiglorOS.ConformanceReportPredicate.v1",
//!               "signature_meaning":"attribution-only"},
//!  "predicateType":"https://piglor.com/pigloros/attestation/conformance-report/v1",
//!  "subject":[{"digest":{"blake3":<hex>,"sha256":<hex>},"name":<name>}, ...five...]}
//! ```
//!
//! The five subjects are, in [`REPORT_ATTESTATION_SUBJECT_NAMES_V1`] order, the CNR1 report
//! bytes, the subject artifact, the CPF1 profile, the fixture bundle and the evaluator binary,
//! each by the BLAKE3 and SHA-256 digest of its bytes. The Statement is the payload of one DSSE
//! envelope (`payloadType` `application/vnd.in-toto+json`, Ed25519 over the PAE, key id the
//! BLAKE3 digest of the verifying key).
//!
//! # The `blake3` digest
//!
//! `blake3` is not in the in-toto DigestSet registry (`spec/v1/digest_set.md`), so generic
//! in-toto consumers ignore it and match subjects on `sha256`; that is why every subject carries
//! both (ADR-062 Revision 8 Q12). PiglorOS encodes a `blake3` value as 64 lowercase hexadecimal
//! characters, the 32-byte BLAKE3-256 digest of the subject bytes, the same encoding as
//! `sha256`.
//!
//! # Verification order
//!
//! [`verify_report_attestation_v1`] runs the order of section 5.1 as amended by
//! `ADR-062_R8_Report_Attestation_Binding` and stops at the first failing step with its closed
//! [`ReportAttestationErrorV1`]: bounded parse, `payloadType`, key admission, signature,
//! Statement shape, subject digests recomputed, embedded CNR1 parsed with the strict codec,
//! subjects bound to their CNR1 fields, artifact revocation, predicate copies equal to the CNR1
//! fields. The signature establishes attribution only: a valid signature over a failing report
//! yields that failing report. The CNR1 wire format is unchanged.
//!
//! The subject binding recomputes each CNR1 field as the CNR1 producer defines it: the CPF1
//! `profile_digest` of the validated profile, the BLAKE3 digest of the canonical CFB1 archive,
//! and the BLAKE3 digest of the evaluator binary. The subject artifact is not bound: CNR1 copies
//! its digest from the evaluator request, and no definition derives it from artifact bytes.

use crate::conformance_trust_admission::{
    ConformanceArtifactRefusalV1, ConformanceKeyRefusalV1, ConformanceTrustAdmissionPortV1,
    ConformanceTrustRoleV1,
};
use crate::{
    decode_hex_digest, hex_digest, ConformanceBundleV1, ConformanceProfileV1, ConformanceReportV1,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use pos_crypto::dsse::{
    DsseEnvelopeV1, DsseParseErrorV1, DsseSignatureErrorV1, IN_TOTO_PAYLOAD_TYPE_V1,
};
use pos_crypto::jcs::JsonV1;
use sha2::{Digest as _, Sha256};

/// The in-toto Statement `_type`.
pub const IN_TOTO_STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";
/// The `predicateType` of the conformance-report predicate (owner decision 2026-10-30).
pub const CONFORMANCE_REPORT_PREDICATE_TYPE_V1: &str =
    "https://piglor.com/pigloros/attestation/conformance-report/v1";
/// The predicate `schema` value.
pub const CONFORMANCE_REPORT_PREDICATE_SCHEMA_V1: &str = "PiglorOS.ConformanceReportPredicate.v1";
/// The only predicate `signature_meaning` value.
pub const ATTRIBUTION_ONLY_SIGNATURE_MEANING_V1: &str = "attribution-only";
/// The largest envelope the verifier parses (32 MiB, inclusive). A CNR1 report is at most
/// 16 MiB, so the largest signed envelope (two base64 layers) is below this bound.
pub const MAX_REPORT_ATTESTATION_BYTES_V1: usize = 33_554_432;
/// The subject names, in Statement order.
pub const REPORT_ATTESTATION_SUBJECT_NAMES_V1: [&str; 5] = [
    "conformance-report.cnr1",
    "subject-artifact",
    "conformance-profile.cpf1",
    "fixture-bundle",
    "evaluator-binary",
];

const PREDICATE_KEYS: [&str; 6] = [
    "diagnostics_digest_or_null",
    "independence",
    "report_cnr1",
    "report_digest",
    "schema",
    "signature_meaning",
];

/// The bytes of the four subjects besides the CNR1 report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportAttestationArtifactsV1<'a> {
    /// The implementation artifact under test.
    pub subject_artifact: &'a [u8],
    /// The CPF1 profile bytes.
    pub profile_cpf1: &'a [u8],
    /// The fixture bundle bytes.
    pub fixture_bundle: &'a [u8],
    /// The evaluator binary bytes.
    pub evaluator_binary: &'a [u8],
}

impl ReportAttestationArtifactsV1<'_> {
    /// The BLAKE3 and SHA-256 digests of the five subjects, in Statement order.
    fn subject_digests(&self, cnr1: &[u8]) -> [[[u8; 32]; 2]; 5] {
        [
            cnr1,
            self.subject_artifact,
            self.profile_cpf1,
            self.fixture_bundle,
            self.evaluator_binary,
        ]
        .map(|bytes| {
            [
                *blake3::hash(bytes).as_bytes(),
                Sha256::digest(bytes).into(),
            ]
        })
    }
}

/// What a signature on a report attestation means.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureMeaningV1 {
    /// The signer attributes the report to itself; it does not assert the report passed.
    AttributionOnly,
}

/// A subject whose digest is bound to a CNR1 field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundSubjectV1 {
    /// The CPF1 profile, bound to CNR1 `profile_digest`.
    Profile,
    /// The CFB1 fixture bundle, bound to CNR1 `fixture_bundle_digest`.
    FixtureBundle,
    /// The evaluator binary, bound to CNR1 `evaluator_binary_digest`.
    EvaluatorBinary,
}

/// The step of the verification order at which an attestation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReportAttestationErrorV1 {
    /// Step 1: the envelope is oversized or not one canonical single-signature envelope.
    #[error("report attestation refused at bounded parse: {0}")]
    BoundedParse(DsseParseErrorV1),
    /// Step 2: the `payloadType` is not `application/vnd.in-toto+json`.
    #[error("report attestation payloadType is not in-toto JSON")]
    PayloadType,
    /// Step 3: the key was not admitted for report signing.
    #[error("report attestation key was not admitted: {0:?}")]
    KeyAdmission(ConformanceKeyRefusalV1),
    /// Step 4: the signature does not verify with the admitted key.
    #[error("report attestation signature refused: {0}")]
    Signature(DsseSignatureErrorV1),
    /// Step 5: the payload is not the exact Statement and predicate shape.
    #[error("report attestation Statement shape is invalid")]
    StatementShape,
    /// Step 6: a subject digest differs from the recomputed digest.
    #[error("report attestation subject digest does not match its artifact")]
    SubjectDigest,
    /// Step 7 (and signing): the embedded CNR1 bytes are not a valid strict CNR1 report.
    #[error("report attestation embeds no valid CNR1 report")]
    EmbeddedReport,
    /// Step 8: a subject artifact does not reproduce its CNR1 field.
    #[error("report attestation subject is not bound to its CNR1 field: {0:?}")]
    SubjectBinding(BoundSubjectV1),
    /// Step 9: the report or evaluator binary digest of the CNR1 report is revoked.
    #[error("report attestation artifact is revoked: {0:?}")]
    ArtifactRevocation(ConformanceArtifactRefusalV1),
    /// Step 10: a predicate copy differs from the embedded CNR1 report.
    #[error("report attestation predicate copy differs from the CNR1 report")]
    PredicateMismatch,
}

/// A report attestation that passed every verification step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReportAttestationV1 {
    report: ConformanceReportV1,
    key_id: [u8; 32],
    diagnostics_digest: Option<[u8; 32]>,
}

impl VerifiedReportAttestationV1 {
    /// The embedded CNR1 report, exactly as reported: a failing report stays failing.
    #[must_use]
    pub const fn report(&self) -> &ConformanceReportV1 {
        &self.report
    }

    /// The key id of the admitted signer.
    #[must_use]
    pub const fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// The diagnostics digest, if the predicate named one.
    #[must_use]
    pub const fn diagnostics_digest(&self) -> Option<[u8; 32]> {
        self.diagnostics_digest
    }

    /// The meaning of the signature: always attribution only.
    #[must_use]
    pub const fn signature_meaning(&self) -> SignatureMeaningV1 {
        SignatureMeaningV1::AttributionOnly
    }
}

/// Sign the attestation of the exact CNR1 bytes `cnr1` and return the canonical envelope.
///
/// # Errors
/// Returns [`ReportAttestationErrorV1::EmbeddedReport`] when `cnr1` is not a valid strict CNR1
/// report.
pub fn sign_report_attestation_v1(
    cnr1: &[u8],
    artifacts: ReportAttestationArtifactsV1<'_>,
    diagnostics_digest: Option<[u8; 32]>,
    key: &SigningKey,
) -> Result<Vec<u8>, ReportAttestationErrorV1> {
    ConformanceReportV1::from_canonical_cbor(cnr1)
        .map_err(|_| ReportAttestationErrorV1::EmbeddedReport)
        .map(|report| {
            let statement = statement_value(cnr1, &report, &artifacts, diagnostics_digest);
            DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, statement.canonical(), key).to_json()
        })
}

fn statement_value(
    cnr1: &[u8],
    report: &ConformanceReportV1,
    artifacts: &ReportAttestationArtifactsV1<'_>,
    diagnostics_digest: Option<[u8; 32]>,
) -> JsonV1 {
    let subjects = REPORT_ATTESTATION_SUBJECT_NAMES_V1
        .into_iter()
        .zip(artifacts.subject_digests(cnr1))
        .map(|(name, [blake3_digest, sha256_digest])| {
            JsonV1::object([
                (
                    "digest",
                    JsonV1::object([
                        ("blake3", JsonV1::Text(hex_digest(&blake3_digest))),
                        ("sha256", JsonV1::Text(hex_digest(&sha256_digest))),
                    ]),
                ),
                ("name", JsonV1::text(name)),
            ])
        })
        .collect();
    let independence = &report.independence;
    let predicate = JsonV1::object([
        (
            "diagnostics_digest_or_null",
            diagnostics_digest.map_or(JsonV1::Null, |digest| JsonV1::Text(hex_digest(&digest))),
        ),
        (
            "independence",
            JsonV1::object([
                (
                    "authorship",
                    JsonV1::Bool(independence.authorship_independent),
                ),
                (
                    "organizational",
                    JsonV1::Bool(independence.organizational_independent),
                ),
                (
                    "technical",
                    JsonV1::Bool(independence.technical_independent),
                ),
            ]),
        ),
        ("report_cnr1", JsonV1::Text(STANDARD.encode(cnr1))),
        (
            "report_digest",
            JsonV1::Text(hex_digest(&report.report_digest)),
        ),
        (
            "schema",
            JsonV1::text(CONFORMANCE_REPORT_PREDICATE_SCHEMA_V1),
        ),
        (
            "signature_meaning",
            JsonV1::text(ATTRIBUTION_ONLY_SIGNATURE_MEANING_V1),
        ),
    ]);
    JsonV1::object([
        ("_type", JsonV1::text(IN_TOTO_STATEMENT_TYPE_V1)),
        ("predicate", predicate),
        (
            "predicateType",
            JsonV1::text(CONFORMANCE_REPORT_PREDICATE_TYPE_V1),
        ),
        ("subject", JsonV1::Array(subjects)),
    ])
}

/// The fields of a Statement that passed the shape step.
struct StatementV1 {
    subjects: [[[u8; 32]; 2]; 5],
    report_cnr1: Vec<u8>,
    report_digest: [u8; 32],
    /// `technical`, `authorship`, `organizational`.
    independence: [bool; 3],
    diagnostics_digest: Option<[u8; 32]>,
}

/// Verify a report attestation envelope in the fixed order of ADR-062 Revision 8 section 5.1.
///
/// `artifacts` are the bytes of the four non-report subjects; the report subject is recomputed
/// from the embedded CNR1 bytes.
///
/// # Errors
/// Returns the closed [`ReportAttestationErrorV1`] of the first step that fails.
pub fn verify_report_attestation_v1(
    envelope: &[u8],
    trust: &dyn ConformanceTrustAdmissionPortV1,
    artifacts: ReportAttestationArtifactsV1<'_>,
) -> Result<VerifiedReportAttestationV1, ReportAttestationErrorV1> {
    let envelope = DsseEnvelopeV1::from_json(envelope, MAX_REPORT_ATTESTATION_BYTES_V1)
        .map_err(ReportAttestationErrorV1::BoundedParse)?;
    if !envelope.has_payload_type(IN_TOTO_PAYLOAD_TYPE_V1) {
        return Err(ReportAttestationErrorV1::PayloadType);
    }
    let key = trust
        .admit_key(ConformanceTrustRoleV1::ReportSigning, envelope.key_id())
        .map_err(ReportAttestationErrorV1::KeyAdmission)?;
    envelope
        .verify(&key)
        .map_err(ReportAttestationErrorV1::Signature)?;
    let statement =
        parse_statement(envelope.payload()).ok_or(ReportAttestationErrorV1::StatementShape)?;
    if statement.subjects != artifacts.subject_digests(&statement.report_cnr1) {
        return Err(ReportAttestationErrorV1::SubjectDigest);
    }
    let report = ConformanceReportV1::from_canonical_cbor(&statement.report_cnr1)
        .map_err(|_| ReportAttestationErrorV1::EmbeddedReport)?;
    bind_subjects(&report, &artifacts, statement.subjects[4][0])
        .map_err(ReportAttestationErrorV1::SubjectBinding)?;
    trust
        .check_artifact_revocation(&report.report_digest, &report.evaluator_binary_digest)
        .map_err(ReportAttestationErrorV1::ArtifactRevocation)?;
    let independence = &report.independence;
    if statement.report_digest != report.report_digest
        || statement.independence
            != [
                independence.technical_independent,
                independence.authorship_independent,
                independence.organizational_independent,
            ]
    {
        return Err(ReportAttestationErrorV1::PredicateMismatch);
    }
    Ok(VerifiedReportAttestationV1 {
        report,
        key_id: *envelope.key_id(),
        diagnostics_digest: statement.diagnostics_digest,
    })
}

/// Require each bound subject to reproduce its CNR1 field; `evaluator_blake3` is the already
/// recomputed BLAKE3 subject digest of the evaluator binary.
fn bind_subjects(
    report: &ConformanceReportV1,
    artifacts: &ReportAttestationArtifactsV1<'_>,
    evaluator_blake3: [u8; 32],
) -> Result<(), BoundSubjectV1> {
    let profile_digest = ConformanceProfileV1::from_canonical_cbor(artifacts.profile_cpf1)
        .ok()
        .map(|profile| profile.profile_digest);
    if profile_digest != Some(report.profile_digest) {
        return Err(BoundSubjectV1::Profile);
    }
    let bundle_digest = ConformanceBundleV1::from_canonical_cbor(artifacts.fixture_bundle)
        .and_then(|bundle| bundle.archive_digest())
        .ok();
    if bundle_digest != Some(report.fixture_bundle_digest) {
        return Err(BoundSubjectV1::FixtureBundle);
    }
    if evaluator_blake3 == report.evaluator_binary_digest {
        Ok(())
    } else {
        Err(BoundSubjectV1::EvaluatorBinary)
    }
}

fn parse_statement(payload: &[u8]) -> Option<StatementV1> {
    let [statement_type, predicate, predicate_type, subjects] = JsonV1::parse_canonical(payload)?
        .into_members([
        "_type",
        "predicate",
        "predicateType",
        "subject",
    ])?;
    let [diagnostics, independence, report_cnr1, report_digest, schema, meaning] =
        predicate.into_members(PREDICATE_KEYS)?;
    let [authorship, organizational, technical] =
        independence.into_members(["authorship", "organizational", "technical"])?;
    let fixed = statement_type == JsonV1::text(IN_TOTO_STATEMENT_TYPE_V1)
        && predicate_type == JsonV1::text(CONFORMANCE_REPORT_PREDICATE_TYPE_V1)
        && schema == JsonV1::text(CONFORMANCE_REPORT_PREDICATE_SCHEMA_V1)
        && meaning == JsonV1::text(ATTRIBUTION_ONLY_SIGNATURE_MEANING_V1);
    if !fixed {
        return None;
    }
    Some(StatementV1 {
        subjects: parse_subjects(subjects)?,
        report_cnr1: STANDARD.decode(report_cnr1.into_text()?).ok()?,
        report_digest: hex_value(report_digest)?,
        independence: [
            technical.as_bool()?,
            authorship.as_bool()?,
            organizational.as_bool()?,
        ],
        diagnostics_digest: match diagnostics {
            JsonV1::Null => None,
            digest => Some(hex_value(digest)?),
        },
    })
}

fn parse_subjects(subjects: JsonV1) -> Option<[[[u8; 32]; 2]; 5]> {
    let items: [JsonV1; 5] = subjects.into_array()?.try_into().ok()?;
    let mut digests = [[[0; 32]; 2]; 5];
    for ((item, name), slot) in items
        .into_iter()
        .zip(REPORT_ATTESTATION_SUBJECT_NAMES_V1)
        .zip(&mut digests)
    {
        let [digest, subject_name] = item.into_members(["digest", "name"])?;
        if subject_name != JsonV1::text(name) {
            return None;
        }
        let [blake3_hex, sha256_hex] = digest.into_members(["blake3", "sha256"])?;
        *slot = [hex_value(blake3_hex)?, hex_value(sha256_hex)?];
    }
    Some(digests)
}

fn hex_value(value: JsonV1) -> Option<[u8; 32]> {
    value.into_text().as_deref().and_then(decode_hex_digest)
}
