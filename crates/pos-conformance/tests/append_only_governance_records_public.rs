#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! ADR-062 Revision 8 slice G3 (#1238): the seven append-only governance records (CWV1, CCF1,
//! CCR1, CIA1, CWD1, CRT1, CPR1) through their public codecs and validators, with the owner
//! decisions of wiki `ADR-062_R8_Governance_Records` (2026-11-06).
//!
//! Every fixture is a small in-memory record; nothing here materializes an archive. The file
//! name sorts this suite before the slow `bundle_contract_*` suites, so mutants of the
//! governance modules are killed early in the bounded diff-mutation test phase. The record
//! digest and correction subject digest are recomputed here independently with `blake3` and
//! `ciborium`.

use ciborium::value::Value;
use pos_conformance::{
    ArtifactDescriptorV1, CapabilityPolicyV1, CaseOutcomeStatusV1, CaseOutcomeV1, ClaimLayerV1,
    ConformanceAffectedReportV1, ConformanceArtifactKindV1, ConformanceConflictKindV1,
    ConformanceConflictResolutionV1, ConformanceConflictV1, ConformanceCorrectionReasonV1,
    ConformanceCorrectionV1, ConformanceGovernanceErrorV1 as Error, ConformanceImpactAnalysisV1,
    ConformanceImpactEffectV1, ConformanceProfileV1, ConformancePromotionV1, ConformanceReportV1,
    ConformanceRetentionV1, ConformanceWaiverEffectV1, ConformanceWaiverReasonV1,
    ConformanceWaiverV1, ConformanceWithdrawalReasonV1, ConformanceWithdrawalSourceKindV1,
    ConformanceWithdrawalSourceV1, ConformanceWithdrawalV1, EvaluatorHardCapsV1,
    EvaluatorProtocolV1, ExecutionModeV1, FixtureDescriptorV1, FixtureFamilyV1,
    FixtureProvenanceV1, FixtureProviderKeyV1, FixtureProviderRegistryBindingV1,
    ImplementationIdentityV1, IndependenceEvidenceV1, IndependenceRequirementsV1,
    OperationalSafetyV1, ProfileLifecycleV1, RedactionStateV1, ReplayClaimV1, StrictOracleKindV1,
    StrictOracleV1, SubjectAdapterKindV1, VerificationOutcomeV1, DETERMINISTIC_BUDGET_HARD_CAPS_V1,
    MAX_CONFORMANCE_GOVERNANCE_RECORD_BYTES_V1,
};
use std::fmt::Debug;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One struct edit of a record before its record digest is recomputed.
type Edit<R> = fn(&mut R);

/// The public codec of one governance record kind.
trait Record: Clone + Debug + PartialEq {
    const DOMAIN: &'static [u8];
    fn digest_mut(&mut self) -> &mut [u8; 32];
    fn computed(&self) -> [u8; 32];
    fn check(&self) -> Result<(), Error>;
    fn encode(&self) -> Result<Vec<u8>, Error>;
    fn decode(bytes: &[u8]) -> Result<Self, Error>;

    fn sealed(mut self) -> Self {
        *self.digest_mut() = self.computed();
        self
    }
}

macro_rules! record {
    ($record:ty, $domain:literal) => {
        impl Record for $record {
            const DOMAIN: &'static [u8] = $domain;

            fn digest_mut(&mut self) -> &mut [u8; 32] {
                &mut self.record_digest
            }

            fn computed(&self) -> [u8; 32] {
                self.computed_record_digest()
            }

            fn check(&self) -> Result<(), Error> {
                self.validate()
            }

            fn encode(&self) -> Result<Vec<u8>, Error> {
                self.to_canonical_cbor()
            }

            fn decode(bytes: &[u8]) -> Result<Self, Error> {
                <$record>::from_canonical_cbor(bytes)
            }
        }
    };
}

record!(ConformanceWaiverV1, b"PiglorOS.ConformanceWaiver.v1");
record!(ConformanceConflictV1, b"PiglorOS.ConformanceConflict.v1");
record!(
    ConformanceCorrectionV1,
    b"PiglorOS.ConformanceCorrection.v1"
);
record!(
    ConformanceImpactAnalysisV1,
    b"PiglorOS.ConformanceImpactAnalysis.v1"
);
record!(
    ConformanceWithdrawalV1,
    b"PiglorOS.ConformanceWithdrawal.v1"
);
record!(ConformanceRetentionV1, b"PiglorOS.ConformanceRetention.v1");
record!(ConformancePromotionV1, b"PiglorOS.ConformancePromotion.v1");

// ---------------------------------------------------------------------------------------------
// Fixtures

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn waiver(mode: ExecutionModeV1, previous: Option<[u8; 32]>) -> ConformanceWaiverV1 {
    ConformanceWaiverV1 {
        waiver_id: "waiver-1".to_owned(),
        profile_digest: [0x21; 32],
        case_id: "art-001".to_owned(),
        mode,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        reason: ConformanceWaiverReasonV1::EnvironmentUnavailable,
        rationale_digest: [2; 32],
        approver_ids: ids(&["alice", "bob"]),
        conflict_disclosure_digest: [3; 32],
        issued_epoch: 7,
        expiry_epoch: 300,
        previous_waiver_digest: previous,
        record_digest: [0; 32],
    }
    .sealed()
}

fn waivers() -> Vec<ConformanceWaiverV1> {
    vec![
        waiver(ExecutionModeV1::AirGapped, Some([4; 32])),
        waiver(ExecutionModeV1::Local, None),
        waiver(ExecutionModeV1::Replay, None),
        waiver(ExecutionModeV1::Fork, Some([5; 32])),
    ]
}

fn conflicts() -> Vec<ConformanceConflictV1> {
    let open = ConformanceConflictV1 {
        kind: ConformanceConflictKindV1::ImplementationDisagreement,
        profile_digest: [0x21; 32],
        report_digests: vec![[1; 32], [2; 32]],
        first_coordinate: Some(vec![1, 2, 3]),
        disclosure_digest: [5; 32],
        raised_by: "carol".to_owned(),
        epoch: 70_000,
        resolution: ConformanceConflictResolutionV1::Open,
        resolving_profile_digest: None,
        record_digest: [0; 32],
    }
    .sealed();
    let mut resolved = open.clone();
    resolved.kind = ConformanceConflictKindV1::SharedCode;
    resolved.first_coordinate = None;
    resolved.resolution = ConformanceConflictResolutionV1::ResolvedByNewProfileDigest;
    resolved.resolving_profile_digest = Some([0x22; 32]);
    vec![open, resolved.sealed()]
}

fn unbound_correction() -> ConformanceCorrectionV1 {
    ConformanceCorrectionV1 {
        corrected_artifact_kind: ConformanceArtifactKindV1::Fixture,
        old_digest: [0x31; 32],
        replacement_digest: [0x32; 32],
        impact_analysis_digest: [0; 32],
        reason: ConformanceCorrectionReasonV1::SecurityDefect,
        approver_ids: ids(&["alice", "dave"]),
        epoch: 1 << 33,
        record_digest: [0; 32],
    }
}

fn impact(subject: [u8; 32], digests: &[u8]) -> ConformanceImpactAnalysisV1 {
    let effects = [
        ConformanceImpactEffectV1::Withdrawn,
        ConformanceImpactEffectV1::RerunRequired,
        ConformanceImpactEffectV1::Unaffected,
    ];
    ConformanceImpactAnalysisV1 {
        correction_subject_digest: subject,
        affected_reports: digests
            .iter()
            .zip(effects.iter().cycle())
            .map(|(seed, effect)| ConformanceAffectedReportV1 {
                report_digest: [*seed; 32],
                effect: *effect,
            })
            .collect(),
        record_digest: [0; 32],
    }
    .sealed()
}

/// A CCR1 correction and the CIA1 impact analysis that bind each other.
fn correction_pair() -> (ConformanceCorrectionV1, ConformanceImpactAnalysisV1) {
    let mut correction = unbound_correction();
    let analysis = impact(correction.correction_subject_digest(), &[0x41, 0x42, 0x43]);
    correction.impact_analysis_digest = analysis.record_digest;
    (correction.sealed(), analysis)
}

fn withdrawals() -> Vec<ConformanceWithdrawalV1> {
    let corrected = ConformanceWithdrawalV1 {
        withdrawn_report_digest: [0x51; 32],
        withdrawn_claim_layers: vec![
            ClaimLayerV1::ArtifactIntegrity,
            ClaimLayerV1::ReplayConformance,
        ],
        reason: ConformanceWithdrawalReasonV1::Corrected,
        source: Some(ConformanceWithdrawalSourceV1 {
            kind: ConformanceWithdrawalSourceKindV1::Correction,
            record_digest: [0x61; 32],
        }),
        epoch: 9,
        signer_key_id: [0x62; 32],
        record_digest: [0; 32],
    }
    .sealed();
    let mut revoked = corrected.clone();
    revoked.withdrawn_claim_layers = vec![ClaimLayerV1::PluginConformance];
    revoked.reason = ConformanceWithdrawalReasonV1::KeyRevoked;
    revoked.source = None;
    vec![corrected, revoked.sealed()]
}

fn retention() -> TestResult<ConformanceRetentionV1> {
    Ok(ConformanceRetentionV1::new(
        [0x71; 32],
        ConformanceArtifactKindV1::Report,
        "2026-11-06",
        3,
    )?)
}

fn identity(id: &str, seed: u8, organization: Option<&str>) -> ImplementationIdentityV1 {
    ImplementationIdentityV1 {
        implementation_id: id.to_owned(),
        source_digest: [seed; 32],
        build_digest: [seed + 1; 32],
        binary_digest: [seed + 2; 32],
        public_contract_digest: [0x99; 32],
        organization_id: organization.map(str::to_owned),
    }
}

fn promotions() -> Vec<ConformancePromotionV1> {
    let stable = ConformancePromotionV1 {
        profile_digest: [0x21; 32],
        from_lifecycle: ProfileLifecycleV1::Candidate,
        to_lifecycle: ProfileLifecycleV1::Stable,
        first_report_digest: [0x81; 32],
        second_report_digest: [0x82; 32],
        first_implementation: identity("impl-a", 0x83, Some("org-a")),
        second_implementation: identity("impl-b", 0x86, None),
        shared_code_audit_digest: [0x89; 32],
        waiver_conflict_snapshot_digest: [0x8a; 32],
        approver_ids: ids(&["alice", "erin"]),
        epoch: 11,
        record_digest: [0; 32],
    }
    .sealed();
    let mut candidate = stable.clone();
    candidate.from_lifecycle = ProfileLifecycleV1::Draft;
    candidate.to_lifecycle = ProfileLifecycleV1::Candidate;
    vec![stable, candidate.sealed()]
}

// ---------------------------------------------------------------------------------------------
// Generic structural refusals

fn encode_value(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn fields_of(bytes: &[u8]) -> TestResult<Vec<Value>> {
    match ciborium::from_reader::<Value, _>(bytes)? {
        Value::Array(fields) => Ok(fields),
        _ => Err("record is not an array".into()),
    }
}

/// Recompute the record digest field independently: BLAKE3 over the domain, one NUL byte and
/// the canonical array of every earlier field.
fn reseal(fields: &mut [Value], domain: &[u8]) -> TestResult {
    let (digest, body) = fields.split_last_mut().ok_or("empty record")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&encode_value(&Value::Array(body.to_vec()))?);
    *digest = Value::Bytes(hasher.finalize().as_bytes().to_vec());
    Ok(())
}

fn resealed(mut fields: Vec<Value>, domain: &[u8]) -> TestResult<Vec<u8>> {
    reseal(&mut fields, domain)?;
    encode_value(&Value::Array(fields))
}

fn node_mut<'a>(fields: &'a mut [Value], path: &[usize]) -> TestResult<&'a mut Value> {
    let (first, rest) = path.split_first().ok_or("empty path")?;
    let mut node = fields.get_mut(*first).ok_or("path out of range")?;
    for index in rest {
        node = match node {
            Value::Array(items) => items.get_mut(*index).ok_or("path out of range")?,
            _ => return Err("path through a scalar".into()),
        };
    }
    Ok(node)
}

/// Every node path below the top-level array.
fn node_paths(value: &Value, prefix: &[usize], out: &mut Vec<Vec<usize>>) {
    if let Value::Array(items) = value {
        for (index, item) in items.iter().enumerate() {
            let mut path = prefix.to_vec();
            path.push(index);
            out.push(path.clone());
            node_paths(item, &path, out);
        }
    }
}

/// The exact round trip and the independent digest oracle of every fixture; returns the
/// fields of `fixtures[0]`.
fn round_trips<R: Record>(fixtures: &[R]) -> TestResult<Vec<Value>> {
    for fixture in fixtures {
        let bytes = fixture.encode()?;
        assert_eq!(&R::decode(&bytes)?, fixture);
        assert_eq!(R::decode(&bytes)?.encode()?, bytes);
        let fields = fields_of(&bytes)?;
        let mut oracle = fields.clone();
        reseal(&mut oracle, R::DOMAIN)?;
        assert_eq!(oracle, fields, "the record digest recomputes independently");
    }
    fields_of(&fixtures.first().ok_or("no fixture")?.encode()?)
}

/// A refused encoding: its name, bytes and expected error.
type Malformed = (&'static str, Vec<u8>, Error);

/// Byte-level encodings of `fields` that break one framing rule each.
fn malformed_framing(fields: &[Value]) -> TestResult<Vec<Malformed>> {
    let record = Value::Array(fields.to_vec());
    let bytes = encode_value(&record)?;
    let mut indefinite = vec![0x9f];
    for field in fields {
        indefinite.extend(encode_value(field)?);
    }
    indefinite.push(0xff);
    assert_eq!(
        bytes.get(6),
        Some(&1),
        "version follows a one-byte head and the magic"
    );
    let mut bad_utf8 = bytes.clone();
    bad_utf8[2] = 0xff;
    let mut tampered = bytes.clone();
    *tampered.last_mut().ok_or("empty")? ^= 1;
    let map = Value::Map(vec![(Value::Text("record".to_owned()), record.clone())]);
    let mut short_digest = fields.to_vec();
    *short_digest.last_mut().ok_or("empty")? = Value::Bytes(vec![0; 31]);
    let invalid = Error::InvalidEncoding;
    Ok(vec![
        ("trailing byte", [bytes.as_slice(), &[0]].concat(), invalid),
        ("map", encode_value(&map)?, invalid),
        (
            "tag",
            encode_value(&Value::Tag(24, Box::new(record)))?,
            invalid,
        ),
        ("indefinite length", indefinite, invalid),
        (
            "non-shortest integer",
            [&bytes[..6], &[0x18, 0x01], &bytes[7..]].concat(),
            invalid,
        ),
        ("invalid UTF-8", bad_utf8, invalid),
        (
            "empty array",
            encode_value(&Value::Array(Vec::new()))?,
            invalid,
        ),
        (
            "magic only",
            encode_value(&Value::Array(fields[..1].to_vec()))?,
            invalid,
        ),
        (
            "no record digest",
            encode_value(&Value::Array(fields[..2].to_vec()))?,
            invalid,
        ),
        (
            "tampered record digest",
            tampered,
            Error::RecordDigestMismatch,
        ),
        (
            "short record digest",
            encode_value(&Value::Array(short_digest))?,
            invalid,
        ),
        (
            "largest size",
            vec![0; MAX_CONFORMANCE_GOVERNANCE_RECORD_BYTES_V1],
            invalid,
        ),
        (
            "oversized",
            vec![0; MAX_CONFORMANCE_GOVERNANCE_RECORD_BYTES_V1 + 1],
            Error::FieldOutOfBounds,
        ),
    ])
}

/// Resealed encodings of `fields` with one field edited, missing or added.
fn malformed_fields<R: Record>(fields: &[Value]) -> TestResult<Vec<Malformed>> {
    let last = fields.len() - 1;
    let with = |index: usize, value: Value| -> TestResult<Vec<u8>> {
        let mut edited = fields.to_vec();
        *node_mut(&mut edited, &[index])? = value;
        resealed(edited, R::DOMAIN)
    };
    let mut missing = fields.to_vec();
    missing.remove(last - 1);
    let mut unknown = fields.to_vec();
    unknown.insert(last, Value::Null);
    let nested = |depth: usize| {
        (0..depth).fold(Value::Array(Vec::new()), |inner, _| {
            Value::Array(vec![inner])
        })
    };
    let wide = Value::Array(vec![Value::Integer(0.into()); 4097]);
    let invalid = Error::InvalidEncoding;
    Ok(vec![
        ("float", with(2, Value::Float(1.5))?, invalid),
        ("missing field", resealed(missing, R::DOMAIN)?, invalid),
        ("unknown field", resealed(unknown, R::DOMAIN)?, invalid),
        (
            "another magic",
            with(0, Value::Text("XXX1".to_owned()))?,
            Error::UnsupportedSchemaVersion,
        ),
        (
            "version 2",
            with(1, Value::Integer(2.into()))?,
            Error::UnsupportedSchemaVersion,
        ),
        (
            "negative integer",
            with(1, Value::Integer((-1).into()))?,
            invalid,
        ),
        ("deepest nesting", with(2, nested(2))?, invalid),
        (
            "nesting too deep",
            with(2, nested(3))?,
            Error::FieldOutOfBounds,
        ),
        ("too many items", with(2, wide)?, Error::FieldOutOfBounds),
    ])
}

/// Every node replaced by a value of another CBOR type, and every nested array with one more
/// item (a list item of the wrong type or a tuple of the wrong arity), is refused as
/// `InvalidEncoding`.
fn wrong_types<R: Record>(fields: &[Value]) -> TestResult {
    let last = fields.len() - 1;
    let mut paths = Vec::new();
    node_paths(&Value::Array(fields.to_vec()), &[], &mut paths);
    for path in paths {
        for extend in [false, true] {
            let mut edited = fields.to_vec();
            let node = node_mut(&mut edited, &path)?;
            if extend {
                let Value::Array(items) = node else {
                    continue;
                };
                items.push(Value::Null);
            } else if matches!(*node, Value::Integer(_)) {
                *node = Value::Text("x".to_owned());
            } else {
                *node = Value::Integer(0.into());
            }
            let encoded = if path[0] == last {
                encode_value(&Value::Array(edited))?
            } else {
                resealed(edited, R::DOMAIN)?
            };
            assert_eq!(
                R::decode(&encoded),
                Err(Error::InvalidEncoding),
                "wrong type at {path:?}, extended {extend}"
            );
        }
    }
    Ok(())
}

/// Unsorted and duplicate lists and every invalid closed code are refused.
fn order_and_codes<R: Record>(
    fields: &[Value],
    lists: &[usize],
    enums: &[(&[usize], u64)],
) -> TestResult {
    for &index in lists {
        for duplicate in [false, true] {
            let mut edited = fields.to_vec();
            let Value::Array(items) = node_mut(&mut edited, &[index])? else {
                return Err("list field is not an array".into());
            };
            if duplicate {
                items[1] = items[0].clone();
            } else {
                items.swap(0, 1);
            }
            assert_eq!(
                R::decode(&resealed(edited, R::DOMAIN)?),
                Err(Error::NonCanonicalOrder),
                "list {index}, duplicate {duplicate}"
            );
        }
    }
    for &(path, code) in enums {
        for invalid in [code, u64::MAX] {
            let mut edited = fields.to_vec();
            *node_mut(&mut edited, path)? = Value::Integer(invalid.into());
            assert_eq!(
                R::decode(&resealed(edited, R::DOMAIN)?),
                Err(Error::FieldOutOfBounds),
                "code {invalid} at {path:?}"
            );
        }
    }
    Ok(())
}

/// The exact round trip, the independent digest oracle and every structural refusal of one
/// record kind. `lists` names the top-level strictly ascending list fields of `fixtures[0]`;
/// `enums` names the path and first invalid code of every closed code in `fixtures[0]`.
fn structural<R: Record>(fixtures: &[R], lists: &[usize], enums: &[(&[usize], u64)]) -> TestResult {
    let fields = round_trips(fixtures)?;
    for (name, encoded, error) in malformed_framing(&fields)?
        .into_iter()
        .chain(malformed_fields::<R>(&fields)?)
    {
        assert_eq!(R::decode(&encoded), Err(error), "{name}");
    }
    wrong_types::<R>(&fields)?;
    order_and_codes::<R>(&fields, lists, enums)
}

/// Each edit, with the record digest recomputed, is refused with the named error.
fn refuses<R: Record>(base: &R, cases: &[(&str, Edit<R>, Error)]) {
    for (name, edit, error) in cases {
        let mut record = base.clone();
        edit(&mut record);
        let record = record.sealed();
        assert_eq!(record.check(), Err(*error), "{name}");
        assert_eq!(record.encode(), Err(*error), "{name}");
    }
}

/// Each edit, with the record digest recomputed, is valid and round-trips exactly.
fn accepts<R: Record>(base: &R, cases: &[(&str, Edit<R>)]) -> TestResult {
    for (name, edit) in cases {
        let mut record = base.clone();
        edit(&mut record);
        let record = record.sealed();
        assert_eq!(record.check(), Ok(()), "{name}");
        assert_eq!(R::decode(&record.encode()?)?, record, "{name}");
    }
    Ok(())
}

fn codes<T: Copy + Debug>(
    from_wire_code: fn(u64) -> Option<T>,
    wire_code: fn(T) -> u64,
    count: u64,
) {
    for code in 0..=255 {
        match from_wire_code(code) {
            Some(value) => {
                assert!(code < count, "{value:?}");
                assert_eq!(wire_code(value), code);
            }
            None => assert!(code >= count, "code {code}"),
        }
    }
    assert!(from_wire_code(u64::MAX).is_none());
}

#[test]
fn every_closed_code_round_trips_and_nothing_else_decodes() {
    codes(
        ConformanceArtifactKindV1::from_wire_code,
        ConformanceArtifactKindV1::wire_code,
        8,
    );
    codes(
        ConformanceWaiverReasonV1::from_wire_code,
        ConformanceWaiverReasonV1::wire_code,
        5,
    );
    codes(
        ConformanceConflictKindV1::from_wire_code,
        ConformanceConflictKindV1::wire_code,
        3,
    );
    codes(
        ConformanceConflictResolutionV1::from_wire_code,
        ConformanceConflictResolutionV1::wire_code,
        2,
    );
    codes(
        ConformanceCorrectionReasonV1::from_wire_code,
        ConformanceCorrectionReasonV1::wire_code,
        5,
    );
    codes(
        ConformanceImpactEffectV1::from_wire_code,
        ConformanceImpactEffectV1::wire_code,
        3,
    );
    codes(
        ConformanceWithdrawalReasonV1::from_wire_code,
        ConformanceWithdrawalReasonV1::wire_code,
        5,
    );
    codes(
        ConformanceWithdrawalSourceKindV1::from_wire_code,
        ConformanceWithdrawalSourceKindV1::wire_code,
        2,
    );
}

// ---------------------------------------------------------------------------------------------
// CWV1

fn artifact(path: &str) -> ArtifactDescriptorV1 {
    ArtifactDescriptorV1 {
        member_path: path.to_owned(),
        media_type: "application/cbor".to_owned(),
        byte_length: 1,
        blake3_digest: [0x11; 32],
    }
}

/// A CPF1 fixture descriptor run in Local and Air-Gapped mode. The waiver rules read only the
/// case id, `mandatory`, claim layer and modes.
fn fixture_descriptor(case_id: &str, mandatory: bool) -> FixtureDescriptorV1 {
    FixtureDescriptorV1 {
        case_id: case_id.to_owned(),
        mandatory,
        claim_layer: ClaimLayerV1::ArtifactIntegrity,
        family: FixtureFamilyV1::Positive,
        provider_key: FixtureProviderKeyV1 {
            provider_id: "pigloros.fixture.artifact-integrity".to_owned(),
            contract_version: "1.0.0".to_owned(),
            abi_major: 1,
            abi_minor: 0,
        },
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        execution_profile_digest: [0x12; 32],
        modes: vec![ExecutionModeV1::Local, ExecutionModeV1::AirGapped],
        schema: artifact("schema.cbor"),
        payload: artifact("payload.cbor"),
        auxiliary: Vec::new(),
        strict_oracle: StrictOracleV1 {
            kind: StrictOracleKindV1::Output,
            output: Some(artifact("expected.cbor")),
            failure: None,
            divergence: None,
        },
        expected_verification_outcome: VerificationOutcomeV1::VerifiedExact,
        expected_verification_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        deterministic_budget: DETERMINISTIC_BUDGET_HARD_CAPS_V1,
        operational_safety: OperationalSafetyV1 { watchdog_ms: 1_000 },
        capability_policy: CapabilityPolicyV1 {
            network_allowed: false,
            capability_ids: Vec::new(),
        },
        trust_policy_snapshot_digest: None,
        release_admission_digest: None,
        provenance: FixtureProvenanceV1 {
            licence_id: "MIT".to_owned(),
            notices_digest: [0x13; 32],
            sbom_digest: [0x14; 32],
            source_digest: [0x15; 32],
            build_digest: [0x16; 32],
            publication_review_digest: [0x17; 32],
            limitations_digest: [0x18; 32],
        },
        transition: None,
        fixture_digest: [0x19; 32],
    }
}

const fn hard_caps() -> EvaluatorHardCapsV1 {
    EvaluatorHardCapsV1 {
        max_profile_bytes: 1,
        max_cases: 1,
        max_bundle_members: 1,
        max_member_path_bytes: 1,
        max_member_bytes: 1,
        max_total_bundle_bytes: 1,
        max_compression_expansion: 1,
        max_structural_nesting: 1,
        max_coordinate_bytes: 1,
        max_diagnostic_bytes: 1,
        max_deterministic_memory_bytes: 1,
        max_deterministic_cpu_fuel: 1,
        max_deterministic_host_calls: 1,
        max_deterministic_event_count: 1,
        max_deterministic_output_bytes: 1,
        max_deterministic_storage_bytes: 1,
        max_deterministic_execution_steps: 1,
        max_deterministic_simulation_time_ns: 1,
    }
}

/// A CPF1 profile, digest `[0x21; 32]`, with the mandatory case `art-001` and the
/// non-mandatory case `art-002`.
fn profile() -> ConformanceProfileV1 {
    ConformanceProfileV1 {
        profile_id: "pigloros.w8.artifact-integrity".to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: ProfileLifecycleV1::Candidate,
        normative_spec_digest: [0x1a; 32],
        execution_matrix_digest: [0x1b; 32],
        execution_profile_digests: vec![[0x12; 32]],
        fixture_provider_registry: FixtureProviderRegistryBindingV1 {
            registry_artifact: artifact("registry.cbor"),
            required_provider_keys: Vec::new(),
        },
        fixtures: vec![
            fixture_descriptor("art-001", true),
            fixture_descriptor("art-002", false),
        ],
        allowed_divergences: Vec::new(),
        evaluator_protocol: EvaluatorProtocolV1 {
            protocol_id: "pigloros.evaluator".to_owned(),
            protocol_digest: [0x1c; 32],
            request_schema_digest: [0x1d; 32],
            report_schema_digest: [0x1e; 32],
            hard_caps: hard_caps(),
        },
        independence_requirements: IndependenceRequirementsV1 {
            technical_independence_required: true,
            authorship_independence_required: true,
            organizational_independence_required: false,
            trust_policy_snapshot_digest: [0x1f; 32],
            requirements_digest: [0x20; 32],
        },
        fixture_contract_policy_digest: [0x23; 32],
        limitations_digest: [0x24; 32],
        provenance_digest: [0x25; 32],
        previous_profile_digest: None,
        profile_digest: [0x21; 32],
    }
}

#[test]
fn cwv1_round_trips_exactly_and_refuses_every_malformed_encoding() -> TestResult {
    structural(
        &waivers(),
        &[9],
        &[(&[5], 4), (&[6], 7), (&[6], 256), (&[7], 5)],
    )
}

#[test]
fn cwv1_field_rules() -> TestResult {
    let base = waivers().remove(0);
    accepts(
        &base,
        &[
            ("128-byte waiver id", |w| w.waiver_id = "a".repeat(128)),
            ("128-byte case id", |w| w.case_id = "Ä".repeat(64)),
            ("32 approvers", |w| {
                w.approver_ids = (0..32)
                    .map(|index| format!("approver-{index:02}"))
                    .collect();
            }),
            ("expiry one after issue", |w| {
                w.expiry_epoch = w.issued_epoch + 1;
            }),
        ],
    )?;
    refuses(
        &base,
        &[
            (
                "empty waiver id",
                |w| w.waiver_id.clear(),
                Error::FieldOutOfBounds,
            ),
            (
                "uppercase waiver id",
                |w| w.waiver_id = "Waiver".to_owned(),
                Error::FieldOutOfBounds,
            ),
            (
                "129-byte waiver id",
                |w| w.waiver_id = "a".repeat(129),
                Error::FieldOutOfBounds,
            ),
            (
                "blank case id",
                |w| w.case_id = "  ".to_owned(),
                Error::FieldOutOfBounds,
            ),
            (
                "129-byte case id",
                |w| w.case_id = "a".repeat(129),
                Error::FieldOutOfBounds,
            ),
            (
                "no approver",
                |w| w.approver_ids.clear(),
                Error::FieldOutOfBounds,
            ),
            (
                "33 approvers",
                |w| {
                    w.approver_ids = (0..33)
                        .map(|index| format!("approver-{index:02}"))
                        .collect();
                },
                Error::FieldOutOfBounds,
            ),
            (
                "invalid approver id",
                |w| w.approver_ids[1] = "Bob".to_owned(),
                Error::FieldOutOfBounds,
            ),
            (
                "unsorted approvers",
                |w| w.approver_ids.reverse(),
                Error::NonCanonicalOrder,
            ),
            (
                "duplicate approvers",
                |w| w.approver_ids[1] = "alice".to_owned(),
                Error::NonCanonicalOrder,
            ),
            (
                "zero issue epoch",
                |w| w.issued_epoch = 0,
                Error::FieldOutOfBounds,
            ),
            (
                "expiry at issue",
                |w| w.expiry_epoch = w.issued_epoch,
                Error::ExpiryNotAfterIssue,
            ),
            (
                "expiry before issue",
                |w| w.expiry_epoch = w.issued_epoch - 1,
                Error::ExpiryNotAfterIssue,
            ),
        ],
    );
    Ok(())
}

#[test]
fn cwv1_waiver_on_a_mandatory_case_is_only_a_candidate_exception() {
    use ConformanceWaiverEffectV1::{CandidateException, DocumentedException};
    use ProfileLifecycleV1::{Candidate, Draft, Stable};
    let profile = profile();
    let mandatory = waivers().remove(0);
    let edited = |edit: Edit<ConformanceWaiverV1>| {
        let mut waiver = mandatory.clone();
        edit(&mut waiver);
        waiver.sealed()
    };
    let optional = edited(|w| {
        w.case_id = "art-002".to_owned();
        w.mode = ExecutionModeV1::Local;
    });
    let (issued, expiry) = (mandatory.issued_epoch, mandatory.expiry_epoch);
    assert_eq!(
        mandatory.effect(&profile, Candidate, issued),
        Ok(CandidateException)
    );
    assert_eq!(
        mandatory.effect(&profile, Candidate, expiry - 1),
        Ok(CandidateException)
    );
    assert_eq!(
        mandatory.effect(&profile, Stable, issued),
        Err(Error::MandatoryWaiverOutsideCandidate),
        "a waived mandatory case never satisfies Stable"
    );
    assert_eq!(
        mandatory.effect(&profile, Draft, issued),
        Err(Error::MandatoryWaiverOutsideCandidate)
    );
    assert_eq!(
        optional.effect(&profile, Stable, issued),
        Ok(DocumentedException)
    );
    assert_eq!(
        mandatory.effect(&profile, Candidate, issued - 1),
        Err(Error::WaiverNotInForce)
    );
    assert_eq!(
        mandatory.effect(&profile, Candidate, expiry),
        Err(Error::WaiverNotInForce)
    );
    let mut foreign = profile.clone();
    foreign.profile_digest = [0x26; 32];
    assert_eq!(
        mandatory.effect(&foreign, Candidate, issued),
        Err(Error::ProfileMismatch)
    );
    let mut unsealed = mandatory.clone();
    unsealed.record_digest = [0; 32];
    assert_eq!(
        unsealed.effect(&profile, Candidate, issued),
        Err(Error::RecordDigestMismatch)
    );
    let absent: [(&str, Edit<ConformanceWaiverV1>); 3] = [
        ("unknown case", |w| w.case_id = "art-003".to_owned()),
        ("other claim layer", |w| {
            w.claim_layer = ClaimLayerV1::ReplayConformance;
        }),
        ("mode the case does not run", |w| {
            w.mode = ExecutionModeV1::Replay;
        }),
    ];
    for (name, edit) in absent {
        assert_eq!(
            edited(edit).effect(&profile, Candidate, issued),
            Err(Error::CaseNotInProfile),
            "{name}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// CCF1

#[test]
fn ccf1_round_trips_exactly_and_refuses_every_malformed_encoding() -> TestResult {
    structural(&conflicts(), &[4], &[(&[2], 3), (&[9], 2)])
}

#[test]
fn ccf1_field_rules_and_resolution_only_by_a_new_profile_digest() -> TestResult {
    let [open, resolved]: [ConformanceConflictV1; 2] =
        conflicts().try_into().map_err(|_| "two conflicts")?;
    accepts(
        &open,
        &[
            ("64 reports", |c| {
                c.report_digests = (0..64).map(|seed| [seed; 32]).collect();
            }),
            ("128-byte coordinate", |c| {
                c.first_coordinate = Some(vec![0; 128]);
            }),
            ("empty coordinate", |c| {
                c.first_coordinate = Some(Vec::new());
            }),
        ],
    )?;
    refuses(
        &open,
        &[
            (
                "no report",
                |c| c.report_digests.clear(),
                Error::FieldOutOfBounds,
            ),
            (
                "65 reports",
                |c| c.report_digests = (0..65).map(|seed| [seed; 32]).collect(),
                Error::FieldOutOfBounds,
            ),
            (
                "129-byte coordinate",
                |c| c.first_coordinate = Some(vec![0; 129]),
                Error::FieldOutOfBounds,
            ),
            (
                "invalid raised-by",
                |c| c.raised_by = "Carol".to_owned(),
                Error::FieldOutOfBounds,
            ),
            ("zero epoch", |c| c.epoch = 0, Error::FieldOutOfBounds),
            (
                "unsorted reports",
                |c| c.report_digests.reverse(),
                Error::NonCanonicalOrder,
            ),
            (
                "open with a resolving digest",
                |c| c.resolving_profile_digest = Some([0x22; 32]),
                Error::InvalidResolution,
            ),
        ],
    );
    refuses(
        &resolved,
        &[
            (
                "resolved without a digest",
                |c| c.resolving_profile_digest = None,
                Error::InvalidResolution,
            ),
            (
                "resolved by the same profile",
                |c| c.resolving_profile_digest = Some(c.profile_digest),
                Error::InvalidResolution,
            ),
        ],
    );
    Ok(())
}

#[test]
fn ccf1_open_conflict_keeps_candidate() -> TestResult {
    let [open, resolved]: [ConformanceConflictV1; 2] =
        conflicts().try_into().map_err(|_| "two conflicts")?;
    assert_eq!(open.admits_lifecycle(ProfileLifecycleV1::Candidate), Ok(()));
    assert_eq!(
        open.admits_lifecycle(ProfileLifecycleV1::Stable),
        Err(Error::OpenConflict)
    );
    assert_eq!(
        resolved.admits_lifecycle(ProfileLifecycleV1::Stable),
        Ok(())
    );
    let mut unsealed = open;
    unsealed.record_digest = [0; 32];
    assert_eq!(
        unsealed.admits_lifecycle(ProfileLifecycleV1::Candidate),
        Err(Error::RecordDigestMismatch)
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// CCR1 and CIA1

#[test]
fn ccr1_round_trips_exactly_and_keeps_the_old_digest_published() -> TestResult {
    let (correction, _) = correction_pair();
    structural(
        std::slice::from_ref(&correction),
        &[7],
        &[(&[2], 8), (&[6], 5)],
    )?;
    let decoded = ConformanceCorrectionV1::from_canonical_cbor(&correction.to_canonical_cbor()?)?;
    assert_eq!(
        decoded.old_digest, [0x31; 32],
        "the old digest stays published"
    );
    assert_eq!(decoded.replacement_digest, [0x32; 32]);
    refuses(
        &correction,
        &[
            (
                "no approver",
                |c| c.approver_ids.clear(),
                Error::FieldOutOfBounds,
            ),
            ("zero epoch", |c| c.epoch = 0, Error::FieldOutOfBounds),
            (
                "replacement equals old",
                |c| c.replacement_digest = c.old_digest,
                Error::CorrectionWithoutChange,
            ),
        ],
    );
    Ok(())
}

#[test]
fn ccr1_correction_subject_digest_recomputes_independently() -> TestResult {
    let (correction, _) = correction_pair();
    let subject = Value::Array(vec![
        Value::Integer(ConformanceArtifactKindV1::Fixture.wire_code().into()),
        Value::Bytes(vec![0x31; 32]),
        Value::Bytes(vec![0x32; 32]),
    ]);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.ConformanceCorrectionSubject.v1\0");
    hasher.update(&encode_value(&subject)?);
    assert_eq!(
        correction.correction_subject_digest(),
        *hasher.finalize().as_bytes()
    );
    Ok(())
}

#[test]
fn cia1_round_trips_exactly_and_refuses_every_malformed_encoding() -> TestResult {
    let (_, analysis) = correction_pair();
    let empty = impact(analysis.correction_subject_digest, &[]);
    structural(&[analysis.clone(), empty], &[3], &[(&[3, 0, 1], 3)])?;
    let entries = |count: u16| -> Vec<ConformanceAffectedReportV1> {
        (0..count)
            .map(|index| {
                let mut report_digest = [0; 32];
                report_digest[..2].copy_from_slice(&index.to_be_bytes());
                ConformanceAffectedReportV1 {
                    report_digest,
                    effect: ConformanceImpactEffectV1::RerunRequired,
                }
            })
            .collect()
    };
    let mut full = analysis.clone();
    full.affected_reports = entries(4096);
    let full = full.sealed();
    assert_eq!(
        ConformanceImpactAnalysisV1::from_canonical_cbor(&full.to_canonical_cbor()?)?,
        full,
        "4,096 entries"
    );
    let mut over = full;
    over.affected_reports = entries(4097);
    assert_eq!(over.sealed().validate(), Err(Error::FieldOutOfBounds));
    refuses(
        &analysis,
        &[
            (
                "unsorted entries",
                |a| a.affected_reports.reverse(),
                Error::NonCanonicalOrder,
            ),
            (
                "duplicate entries",
                |a| {
                    a.affected_reports[1].report_digest = a.affected_reports[0].report_digest;
                },
                Error::NonCanonicalOrder,
            ),
        ],
    );
    Ok(())
}

#[test]
fn cia1_every_report_naming_the_old_digest_must_appear() {
    let (correction, analysis) = correction_pair();
    let edited = |edit: Edit<ConformanceCorrectionV1>| {
        let mut correction = correction.clone();
        edit(&mut correction);
        correction.sealed()
    };
    assert_eq!(
        analysis.validate_for(&correction, &[[0x41; 32], [0x43; 32]]),
        Ok(())
    );
    assert_eq!(analysis.validate_for(&correction, &[]), Ok(()));
    assert_eq!(
        analysis.validate_for(&correction, &[[0x41; 32], [0x44; 32]]),
        Err(Error::AffectedReportMissing),
        "a report naming the old digest is missing"
    );
    assert_eq!(
        analysis.validate_for(&edited(|c| c.replacement_digest = [0x33; 32]), &[]),
        Err(Error::CorrectionMismatch),
        "another correction subject"
    );
    assert_eq!(
        analysis.validate_for(&edited(|c| c.impact_analysis_digest = [0x34; 32]), &[]),
        Err(Error::CorrectionMismatch),
        "another impact analysis"
    );
    let mut unsealed_correction = correction.clone();
    unsealed_correction.record_digest = [0; 32];
    assert_eq!(
        analysis.validate_for(&unsealed_correction, &[]),
        Err(Error::RecordDigestMismatch)
    );
    let mut unsealed_analysis = analysis.clone();
    unsealed_analysis.record_digest = [0; 32];
    assert_eq!(
        unsealed_analysis.validate_for(&correction, &[]),
        Err(Error::RecordDigestMismatch)
    );
    assert_eq!(
        analysis
            .affected_reports
            .iter()
            .map(|entry| entry.effect)
            .collect::<Vec<_>>(),
        [
            ConformanceImpactEffectV1::Withdrawn,
            ConformanceImpactEffectV1::RerunRequired,
            ConformanceImpactEffectV1::Unaffected,
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// CWD1

fn report(report_id: u8) -> TestResult<ConformanceReportV1> {
    let mut report = ConformanceReportV1 {
        report_id: [report_id; 16],
        subject_artifact_digest: [0x52; 32],
        profile_digest: [0x21; 32],
        normative_spec_digest: [0x53; 32],
        execution_profile_digest: [0x54; 32],
        fixture_bundle_digest: [0x55; 32],
        evaluator_source_digest: [0x56; 32],
        evaluator_binary_digest: [0x57; 32],
        evaluator_protocol_digest: [0x58; 32],
        implementation: identity("impl-a", 0x83, None),
        independence: IndependenceEvidenceV1 {
            technical_independent: true,
            authorship_independent: true,
            organizational_independent: false,
            declaration_digest: [0x59; 32],
            shared_code_audit_digest: [0x5a; 32],
            reviewer_ids: vec!["reviewer".to_owned()],
        },
        cases: vec![CaseOutcomeV1 {
            case_id: "case-00001".to_owned(),
            fixture_digest: [3; 32],
            execution_profile_digest: [4; 32],
            mode: ExecutionModeV1::Local,
            claim_layer: ClaimLayerV1::ArtifactIntegrity,
            outcome: CaseOutcomeStatusV1::Pass,
            first_coordinate: None,
            expected_digest: Some([7; 32]),
            actual_digest: Some([7; 32]),
            expected_error: None,
            actual_error: None,
            replay_claim: ReplayClaimV1::Exact,
            redaction_state: RedactionStateV1::None,
            provenance_digest: [6; 32],
        }],
        passed: 1,
        failed: 0,
        skipped: 0,
        unavailable: 0,
        not_applicable: 0,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        limitations_digest: [0x5b; 32],
        evaluator_build_provenance_digest: [0x5c; 32],
        report_digest: [0; 32],
    };
    report.report_digest = report.digest()?;
    Ok(report)
}

#[test]
fn cwd1_round_trips_exactly_and_refuses_every_malformed_encoding() -> TestResult {
    structural(
        &withdrawals(),
        &[3],
        &[(&[3, 0], 7), (&[4], 5), (&[5, 0], 2)],
    )
}

#[test]
fn cwd1_source_matches_the_reason_code() -> TestResult {
    let base = withdrawals().remove(0);
    accepts(
        &base,
        &[
            ("conflict resolved by its conflict", |w| {
                w.reason = ConformanceWithdrawalReasonV1::ConflictResolved;
                w.source = w.source.map(|source| ConformanceWithdrawalSourceV1 {
                    kind: ConformanceWithdrawalSourceKindV1::Conflict,
                    ..source
                });
            }),
            ("evidence invalid without a source", |w| {
                w.reason = ConformanceWithdrawalReasonV1::EvidenceInvalid;
                w.source = None;
            }),
            ("submitter request without a source", |w| {
                w.reason = ConformanceWithdrawalReasonV1::SubmitterRequest;
                w.source = None;
            }),
        ],
    )?;
    refuses(
        &base,
        &[
            (
                "no claim layer",
                |w| w.withdrawn_claim_layers.clear(),
                Error::FieldOutOfBounds,
            ),
            ("zero epoch", |w| w.epoch = 0, Error::FieldOutOfBounds),
            (
                "unsorted claim layers",
                |w| w.withdrawn_claim_layers.reverse(),
                Error::NonCanonicalOrder,
            ),
            (
                "corrected without a source",
                |w| w.source = None,
                Error::InvalidWithdrawalSource,
            ),
            (
                "corrected by a conflict",
                |w| {
                    w.source = w.source.map(|source| ConformanceWithdrawalSourceV1 {
                        kind: ConformanceWithdrawalSourceKindV1::Conflict,
                        ..source
                    });
                },
                Error::InvalidWithdrawalSource,
            ),
            (
                "conflict resolved by a correction",
                |w| {
                    w.reason = ConformanceWithdrawalReasonV1::ConflictResolved;
                },
                Error::InvalidWithdrawalSource,
            ),
            (
                "key revoked with a source",
                |w| {
                    w.reason = ConformanceWithdrawalReasonV1::KeyRevoked;
                },
                Error::InvalidWithdrawalSource,
            ),
        ],
    );
    Ok(())
}

#[test]
fn cwd1_withdrawn_report_stays_readable_and_flagged() -> TestResult {
    let withdrawn = report(1)?;
    let bytes = withdrawn.to_canonical_cbor()?;
    let mut withdrawal = withdrawals().remove(0);
    withdrawal.withdrawn_report_digest = withdrawn.report_digest;
    let withdrawal = withdrawal.sealed();
    let flagged = withdrawal.flag(&bytes)?;
    assert_eq!(flagged.report, withdrawn);
    assert_eq!(
        flagged.report.to_canonical_cbor()?,
        bytes,
        "the report is unchanged"
    );
    assert_eq!(
        flagged.withdrawn_claim_layers,
        withdrawal.withdrawn_claim_layers
    );
    assert_eq!(flagged.withdrawal_digest, withdrawal.record_digest);
    assert_eq!(
        withdrawal.flag(&report(2)?.to_canonical_cbor()?),
        Err(Error::ReportMismatch)
    );
    assert_eq!(withdrawal.flag(&bytes[1..]), Err(Error::ReportUnreadable));
    let mut unsealed = withdrawal;
    unsealed.record_digest = [0; 32];
    assert_eq!(unsealed.flag(&bytes), Err(Error::RecordDigestMismatch));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// CRT1

#[test]
fn crt1_round_trips_exactly_and_refuses_every_malformed_encoding() -> TestResult {
    let record = retention()?;
    assert_eq!(record.earliest_removal_date, "2028-11-06");
    assert_eq!(record.earliest_removal_stable_major, 5);
    structural(&[record], &[], &[(&[3], 8)])
}

#[test]
fn crt1_removal_bounds_recompute_with_calendar_clamping() -> TestResult {
    let valid = [
        ("2028-02-29", "2030-02-28"),
        ("2000-02-29", "2002-02-28"),
        ("2026-01-31", "2028-01-31"),
        ("2026-04-30", "2028-04-30"),
        ("2026-12-31", "2028-12-31"),
        ("0001-01-01", "0003-01-01"),
        ("9997-12-31", "9999-12-31"),
    ];
    for (retired, removal) in valid {
        let record = ConformanceRetentionV1::new(
            [0x71; 32],
            ConformanceArtifactKindV1::Fixture,
            retired,
            0,
        )?;
        assert_eq!(record.earliest_removal_date, removal, "{retired}");
        assert_eq!(record.earliest_removal_stable_major, 2);
        assert_eq!(record.validate(), Ok(()));
    }
    let invalid = [
        "2100-02-29",
        "2027-02-29",
        "2026-04-31",
        "2026-06-31",
        "2026-09-31",
        "2026-11-31",
        "2026-01-32",
        "2026-13-01",
        "2026-00-10",
        "2026-01-00",
        "0000-01-01",
        "9998-01-01",
        "2026-1-01",
        "2026/01/01",
        "2026-01/01",
        "2026/01-01",
        "2026-01-011",
        "+026-01-01",
        "2026-+1-01",
        "",
    ];
    for retired in invalid {
        assert_eq!(
            ConformanceRetentionV1::new([0x71; 32], ConformanceArtifactKindV1::Fixture, retired, 0),
            Err(Error::FieldOutOfBounds),
            "{retired:?}"
        );
    }
    let highest = ConformanceRetentionV1::new(
        [0x71; 32],
        ConformanceArtifactKindV1::Fixture,
        "2026-11-06",
        u64::MAX - 2,
    )?;
    assert_eq!(highest.earliest_removal_stable_major, u64::MAX);
    assert_eq!(
        ConformanceRetentionV1::new(
            [0x71; 32],
            ConformanceArtifactKindV1::Fixture,
            "2026-11-06",
            u64::MAX - 1
        ),
        Err(Error::FieldOutOfBounds)
    );
    refuses(
        &retention()?,
        &[
            (
                "stored date not recomputed",
                |r| r.earliest_removal_date = "2028-11-07".to_owned(),
                Error::RetentionBoundMismatch,
            ),
            (
                "stored major not recomputed",
                |r| r.earliest_removal_stable_major = 6,
                Error::RetentionBoundMismatch,
            ),
            (
                "invalid retirement date",
                |r| r.retirement_date = "2026-02-30".to_owned(),
                Error::FieldOutOfBounds,
            ),
        ],
    );
    Ok(())
}

#[test]
fn crt1_removal_before_both_bounds_is_refused() -> TestResult {
    let record = retention()?;
    let cases = [
        ("both bounds met exactly", "2028-11-06", 5, Ok(())),
        ("both bounds passed", "2031-01-01", 9, Ok(())),
        (
            "one day early",
            "2028-11-05",
            5,
            Err(Error::RemovalTooEarly),
        ),
        (
            "one major early",
            "2028-11-06",
            4,
            Err(Error::RemovalTooEarly),
        ),
        (
            "date passed, major early",
            "2031-01-01",
            4,
            Err(Error::RemovalTooEarly),
        ),
        (
            "major passed, date early",
            "2027-01-01",
            9,
            Err(Error::RemovalTooEarly),
        ),
        (
            "invalid today",
            "2028-13-01",
            9,
            Err(Error::FieldOutOfBounds),
        ),
    ];
    for (name, today, major, expected) in cases {
        assert_eq!(record.check_removal(today, major), expected, "{name}");
    }
    let mut unsealed = record;
    unsealed.record_digest = [0; 32];
    assert_eq!(
        unsealed.check_removal("2031-01-01", 9),
        Err(Error::RecordDigestMismatch)
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// CPR1

#[test]
fn cpr1_round_trips_exactly_and_refuses_every_malformed_encoding() -> TestResult {
    structural(&promotions(), &[11], &[(&[3], 4), (&[4], 4)])
}

#[test]
fn cpr1_shape_rules() -> TestResult {
    let base = promotions().remove(0);
    accepts(
        &base,
        &[("128-byte implementation id", |p| {
            p.first_implementation.implementation_id = "a".repeat(128);
        })],
    )?;
    refuses(
        &base,
        &[
            (
                "Candidate to Candidate",
                |p| p.to_lifecycle = ProfileLifecycleV1::Candidate,
                Error::InvalidLifecycleTransition,
            ),
            (
                "Draft to Stable",
                |p| p.from_lifecycle = ProfileLifecycleV1::Draft,
                Error::InvalidLifecycleTransition,
            ),
            (
                "Stable to Retired",
                |p| {
                    p.from_lifecycle = ProfileLifecycleV1::Stable;
                    p.to_lifecycle = ProfileLifecycleV1::Retired;
                },
                Error::InvalidLifecycleTransition,
            ),
            (
                "Stable to Candidate",
                |p| {
                    p.from_lifecycle = ProfileLifecycleV1::Stable;
                    p.to_lifecycle = ProfileLifecycleV1::Candidate;
                },
                Error::InvalidLifecycleTransition,
            ),
            (
                "blank first implementation id",
                |p| p.first_implementation.implementation_id = " ".to_owned(),
                Error::FieldOutOfBounds,
            ),
            (
                "129-byte second implementation id",
                |p| p.second_implementation.implementation_id = "a".repeat(129),
                Error::FieldOutOfBounds,
            ),
            (
                "blank organization id",
                |p| p.first_implementation.organization_id = Some(String::new()),
                Error::FieldOutOfBounds,
            ),
            (
                "no approver",
                |p| p.approver_ids.clear(),
                Error::FieldOutOfBounds,
            ),
            ("zero epoch", |p| p.epoch = 0, Error::FieldOutOfBounds),
            (
                "equal report digests",
                |p| p.second_report_digest = p.first_report_digest,
                Error::NonCanonicalOrder,
            ),
            (
                "reversed report digests",
                |p| {
                    std::mem::swap(&mut p.first_report_digest, &mut p.second_report_digest);
                },
                Error::NonCanonicalOrder,
            ),
        ],
    );
    Ok(())
}
