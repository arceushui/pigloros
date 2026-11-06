#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! ADR-062 Revision 8 slice G4 (#1239): the CHS1 per-profile history chain and the Candidate ->
//! Stable promotion gate, through their public seams, with the owner decisions of wiki
//! `ADR-062_R8_Promotion_Gate` (2026-11-06).
//!
//! Every fixture is a small synthetic in-memory record built here; nothing materializes an
//! archive, and the two "implementations" of the positive test are test data, not a claim. The
//! file name sorts this suite before the slow `bundle_contract_*` suites so mutants of the gate
//! are killed early in the bounded diff-mutation test phase. Entry and snapshot digests are
//! recomputed independently with `blake3` and `ciborium`.

use ciborium::value::Value;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pos_conformance::{
    check_stable_promotion_v1, AllowedDivergenceV1, ArtifactDescriptorV1, CapabilityPolicyV1,
    CaseOutcomeStatusV1, CaseOutcomeV1, ClaimLayerV1, ConformanceAffectedReportV1,
    ConformanceArtifactKindV1, ConformanceArtifactRefusalV1, ConformanceConflictKindV1,
    ConformanceConflictResolutionV1, ConformanceConflictV1, ConformanceCorrectionReasonV1,
    ConformanceCorrectionV1, ConformanceGovernanceErrorV1 as Error, ConformanceHistoryEntryV1,
    ConformanceHistoryRecordKindV1 as Kind, ConformanceHistoryV1, ConformanceImpactAnalysisV1,
    ConformanceImpactEffectV1, ConformanceKeyRefusalV1, ConformanceProfileV1,
    ConformancePromotionGateInputV1, ConformancePromotionImplementationEvidenceV1,
    ConformancePromotionRefusalV1 as Refusal, ConformancePromotionReportEvidenceV1,
    ConformancePromotionReportsV1, ConformancePromotionV1, ConformanceReportV1,
    ConformanceRetentionV1, ConformanceTrustAdmissionPortV1, ConformanceTrustRoleV1,
    ConformanceWaiverReasonV1, ConformanceWaiverV1, ConformanceWithdrawalReasonV1,
    ConformanceWithdrawalV1, DivergenceMismatchKindV1, EvaluatorHardCapsV1, EvaluatorProtocolV1,
    ExecutionModeV1, FixtureDescriptorV1, FixtureFamilyV1, FixtureProvenanceV1,
    FixtureProviderKeyV1, FixtureProviderRegistryBindingV1, ImplementationIdentityV1,
    IndependenceEvidenceV1, IndependenceRequirementsV1, OperationalSafetyV1, ProfileLifecycleV1,
    RedactionStateV1, ReplayClaimV1, StrictOracleKindV1, StrictOracleV1, SubjectAdapterKindV1,
    VerificationOutcomeV1, CONFORMANCE_HISTORY_MAGIC_V1, DETERMINISTIC_BUDGET_HARD_CAPS_V1,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PROFILE: [u8; 32] = [0x21; 32];
const REPORT_KEY: [u8; 32] = [0x71; 32];
const EVALUATOR_KEY: [u8; 32] = [0x72; 32];
const AUDIT: [u8; 32] = [0xaa; 32];
const COORDINATE: &[u8] = b"tick/3";
const LOCAL: ExecutionModeV1 = ExecutionModeV1::Local;
const AIR: ExecutionModeV1 = ExecutionModeV1::AirGapped;

// ---------------------------------------------------------------------------------------------
// Independent oracles

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn oracle_digest(domain: &[u8], value: &Value) -> TestResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&encode(value)?);
    Ok(*hasher.finalize().as_bytes())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn oracle_entry_digest(entry: &ConformanceHistoryEntryV1) -> TestResult<[u8; 32]> {
    oracle_digest(
        b"PiglorOS.ConformanceHistoryEntry.v1",
        &Value::Array(vec![
            bytes(&entry.previous_digest),
            Value::Integer(entry.record_kind.wire_code().into()),
            bytes(&entry.record_digest),
        ]),
    )
}

// ---------------------------------------------------------------------------------------------
// Governance records

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// A history record: its kind, exact bytes and record digest.
type HistoryRecord = (Kind, Vec<u8>, [u8; 32]);

fn waiver(case_id: &str, profile: [u8; 32], expiry_epoch: u64) -> TestResult<HistoryRecord> {
    let mut record = ConformanceWaiverV1 {
        waiver_id: format!("waiver-{case_id}"),
        profile_digest: profile,
        case_id: case_id.to_owned(),
        mode: LOCAL,
        claim_layer: ClaimLayerV1::ReplayConformance,
        reason: ConformanceWaiverReasonV1::EnvironmentUnavailable,
        rationale_digest: [2; 32],
        approver_ids: ids(&["alice"]),
        conflict_disclosure_digest: [3; 32],
        issued_epoch: 5,
        expiry_epoch,
        previous_waiver_digest: None,
        record_digest: [0; 32],
    };
    record.record_digest = record.computed_record_digest();
    Ok((
        Kind::Waiver,
        record.to_canonical_cbor()?,
        record.record_digest,
    ))
}

fn conflict(
    kind: ConformanceConflictKindV1,
    resolution: ConformanceConflictResolutionV1,
    profile: [u8; 32],
) -> TestResult<HistoryRecord> {
    let mut record = ConformanceConflictV1 {
        kind,
        profile_digest: profile,
        report_digests: vec![[1; 32]],
        first_coordinate: None,
        disclosure_digest: [5; 32],
        raised_by: "carol".to_owned(),
        epoch: 6,
        resolution,
        resolving_profile_digest: (resolution
            == ConformanceConflictResolutionV1::ResolvedByNewProfileDigest)
            .then_some([0x22; 32]),
        record_digest: [0; 32],
    };
    record.record_digest = record.computed_record_digest();
    Ok((
        Kind::Conflict,
        record.to_canonical_cbor()?,
        record.record_digest,
    ))
}

fn correction() -> TestResult<HistoryRecord> {
    let mut record = ConformanceCorrectionV1 {
        corrected_artifact_kind: ConformanceArtifactKindV1::Fixture,
        old_digest: [0x31; 32],
        replacement_digest: [0x32; 32],
        impact_analysis_digest: [0x33; 32],
        reason: ConformanceCorrectionReasonV1::FixtureDefect,
        approver_ids: ids(&["alice"]),
        epoch: 7,
        record_digest: [0; 32],
    };
    record.record_digest = record.computed_record_digest();
    Ok((
        Kind::Correction,
        record.to_canonical_cbor()?,
        record.record_digest,
    ))
}

fn impact_analysis() -> TestResult<HistoryRecord> {
    let mut record = ConformanceImpactAnalysisV1 {
        correction_subject_digest: [0x34; 32],
        affected_reports: vec![ConformanceAffectedReportV1 {
            report_digest: [0x35; 32],
            effect: ConformanceImpactEffectV1::RerunRequired,
        }],
        record_digest: [0; 32],
    };
    record.record_digest = record.computed_record_digest();
    Ok((
        Kind::ImpactAnalysis,
        record.to_canonical_cbor()?,
        record.record_digest,
    ))
}

fn withdrawal() -> TestResult<HistoryRecord> {
    let mut record = ConformanceWithdrawalV1 {
        withdrawn_report_digest: [0x36; 32],
        withdrawn_claim_layers: vec![ClaimLayerV1::ReplayConformance],
        reason: ConformanceWithdrawalReasonV1::SubmitterRequest,
        source: None,
        epoch: 8,
        signer_key_id: [0x37; 32],
        record_digest: [0; 32],
    };
    record.record_digest = record.computed_record_digest();
    Ok((
        Kind::Withdrawal,
        record.to_canonical_cbor()?,
        record.record_digest,
    ))
}

fn retention(kind: ConformanceArtifactKindV1, digest: [u8; 32]) -> TestResult<HistoryRecord> {
    let record = ConformanceRetentionV1::new(digest, kind, "2026-11-06", 1)?;
    Ok((
        Kind::Retention,
        record.to_canonical_cbor()?,
        record.record_digest,
    ))
}

fn identity(id: &str, seed: u8) -> ImplementationIdentityV1 {
    ImplementationIdentityV1 {
        implementation_id: id.to_owned(),
        source_digest: [seed; 32],
        build_digest: [seed + 1; 32],
        binary_digest: [seed + 2; 32],
        public_contract_digest: [0x99; 32],
        organization_id: None,
    }
}

/// A CPR1 of `PROFILE` naming four distinct report digests, sealed.
fn promotion(from: ProfileLifecycleV1, to: ProfileLifecycleV1) -> ConformancePromotionV1 {
    let mut record = ConformancePromotionV1 {
        profile_digest: PROFILE,
        from_lifecycle: from,
        to_lifecycle: to,
        first_reports: ConformancePromotionReportsV1 {
            local_report_digest: [0x81; 32],
            air_gapped_report_digest: [0x82; 32],
        },
        second_reports: ConformancePromotionReportsV1 {
            local_report_digest: [0x83; 32],
            air_gapped_report_digest: [0x84; 32],
        },
        first_implementation: identity("impl-a", 0xa1),
        second_implementation: identity("impl-b", 0xb1),
        shared_code_audit_digest: AUDIT,
        waiver_conflict_snapshot_digest: [0x85; 32],
        approver_ids: ids(&["alice", "erin"]),
        epoch: 10,
        record_digest: [0; 32],
    };
    record.record_digest = record.computed_record_digest();
    record
}

fn promotion_record(from: ProfileLifecycleV1, to: ProfileLifecycleV1) -> TestResult<HistoryRecord> {
    let record = promotion(from, to);
    Ok((
        Kind::Promotion,
        record.to_canonical_cbor()?,
        record.record_digest,
    ))
}

/// A history of `profile` over `records`, and the records' bytes.
fn history_of(
    profile: [u8; 32],
    records: &[HistoryRecord],
) -> TestResult<(ConformanceHistoryV1, Vec<Vec<u8>>)> {
    let mut history = ConformanceHistoryV1::new(profile);
    for (kind, _, digest) in records {
        history = history.append(*kind, *digest)?;
    }
    Ok((
        history,
        records.iter().map(|(_, bytes, _)| bytes.clone()).collect(),
    ))
}

fn replay(
    profile: [u8; 32],
    records: &[HistoryRecord],
) -> TestResult<Result<ProfileLifecycleV1, Error>> {
    let (history, bytes) = history_of(profile, records)?;
    let slices: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    Ok(history.replay(&slices).map(|state| state.lifecycle()))
}

// ---------------------------------------------------------------------------------------------
// CHS1 history chain

#[test]
fn chs1_round_trips_exactly_and_recomputes_every_digest_independently() -> TestResult {
    let records = [
        promotion_record(ProfileLifecycleV1::Draft, ProfileLifecycleV1::Candidate)?,
        waiver("case-a", PROFILE, 50)?,
    ];
    let (history, _) = history_of(PROFILE, &records)?;
    assert_eq!(ConformanceHistoryV1::new(PROFILE).head_digest(), PROFILE);
    let bytes = history.to_canonical_cbor()?;
    assert_eq!(ConformanceHistoryV1::from_canonical_cbor(&bytes)?, history);
    let mut previous = PROFILE;
    let mut entries = Vec::new();
    for (entry, (kind, _, digest)) in history.entries.iter().zip(&records) {
        assert_eq!(
            (
                entry.previous_digest,
                entry.record_kind,
                entry.record_digest
            ),
            (previous, *kind, *digest)
        );
        assert_eq!(entry.entry_digest(), oracle_entry_digest(entry)?);
        previous = entry.entry_digest();
        entries.push(Value::Array(vec![
            bytes(&entry.previous_digest),
            Value::Integer(entry.record_kind.wire_code().into()),
            bytes(&entry.record_digest),
        ]));
    }
    assert_eq!(history.head_digest(), previous);
    let body = vec![
        Value::Text(CONFORMANCE_HISTORY_MAGIC_V1.to_owned()),
        Value::Integer(1.into()),
        bytes(&PROFILE),
        Value::Array(entries),
    ];
    let digest = oracle_digest(
        b"PiglorOS.ConformanceHistory.v1",
        &Value::Array(body.clone()),
    )?;
    assert_eq!(history.record_digest, digest);
    let mut sealed = body;
    sealed.push(bytes(&digest));
    assert_eq!(encode(&Value::Array(sealed))?, bytes);
    Ok(())
}

/// The decoded fields of `history` with one node edited, resealed with the record digest.
fn edited(history: &ConformanceHistoryV1, path: &[usize], value: Value) -> TestResult<Vec<u8>> {
    let Value::Array(mut fields) =
        ciborium::from_reader::<Value, _>(history.to_canonical_cbor()?.as_slice())?
    else {
        return Err("history is not an array".into());
    };
    let (first, rest) = path.split_first().ok_or("empty path")?;
    let mut node = fields.get_mut(*first).ok_or("path out of range")?;
    for index in rest {
        let Value::Array(items) = node else {
            return Err("path through a scalar".into());
        };
        node = items.get_mut(*index).ok_or("path out of range")?;
    }
    *node = value;
    fields.pop();
    let digest = oracle_digest(
        b"PiglorOS.ConformanceHistory.v1",
        &Value::Array(fields.clone()),
    )?;
    fields.push(bytes(&digest));
    encode(&Value::Array(fields))
}

#[test]
fn chs1_refuses_every_malformed_entry() -> TestResult {
    let (history, _) = history_of(PROFILE, &[correction()?, withdrawal()?])?;
    let entry = |index: usize| -> TestResult<Value> {
        let entry = history.entries.get(index).ok_or("no entry")?;
        Ok(Value::Array(vec![
            bytes(&entry.previous_digest),
            Value::Integer(entry.record_kind.wire_code().into()),
            bytes(&entry.record_digest),
        ]))
    };
    let invalid = Error::InvalidEncoding;
    let cases: Vec<(&str, Vec<u8>, Error)> = vec![
        (
            "profile not bytes",
            edited(&history, &[2], Value::Null)?,
            invalid,
        ),
        (
            "short profile",
            edited(&history, &[2], bytes(&[1; 31]))?,
            invalid,
        ),
        (
            "entries not a list",
            edited(&history, &[3], Value::Null)?,
            invalid,
        ),
        (
            "entry not a tuple",
            edited(&history, &[3, 0], Value::Null)?,
            invalid,
        ),
        (
            "entry arity",
            edited(&history, &[3, 0], Value::Array(vec![Value::Null]))?,
            invalid,
        ),
        (
            "previous not bytes",
            edited(&history, &[3, 0, 0], Value::Null)?,
            invalid,
        ),
        (
            "kind not a code",
            edited(&history, &[3, 0, 1], Value::Null)?,
            invalid,
        ),
        (
            "unknown kind",
            edited(&history, &[3, 0, 1], Value::Integer(7.into()))?,
            Error::FieldOutOfBounds,
        ),
        (
            "largest kind",
            edited(&history, &[3, 0, 1], Value::Integer(u64::MAX.into()))?,
            Error::FieldOutOfBounds,
        ),
        (
            "record not bytes",
            edited(&history, &[3, 0, 2], Value::Null)?,
            invalid,
        ),
        (
            "reordered entries",
            edited(&history, &[3], Value::Array(vec![entry(1)?, entry(0)?]))?,
            Error::BrokenHistoryLink,
        ),
        (
            "first entry not linked to the profile",
            edited(&history, &[3, 0, 0], bytes(&[0x22; 32]))?,
            Error::BrokenHistoryLink,
        ),
        (
            "rewritten record digest",
            edited(&history, &[3, 0, 2], bytes(&[0x44; 32]))?,
            Error::BrokenHistoryLink,
        ),
    ];
    for (name, encoded, error) in cases {
        assert_eq!(
            ConformanceHistoryV1::from_canonical_cbor(&encoded),
            Err(error),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn chs1_is_append_only_and_refuses_a_broken_reordered_or_rewritten_link() -> TestResult {
    let (history, _) = history_of(PROFILE, &[correction()?, withdrawal()?, impact_analysis()?])?;
    let heads: Vec<[u8; 32]> = history
        .entries
        .iter()
        .map(ConformanceHistoryEntryV1::entry_digest)
        .collect();
    for pinned in std::iter::once(PROFILE).chain(heads.iter().copied()) {
        assert_eq!(history.extends(&pinned), Ok(()));
    }
    let (rewritten, _) = history_of(PROFILE, &[withdrawal()?, correction()?, impact_analysis()?])?;
    assert_eq!(rewritten.validate(), Ok(()));
    for pinned in &heads {
        assert_eq!(
            rewritten.extends(pinned),
            Err(Error::HistoryNotAppendOnly),
            "a rewritten history does not keep the pinned prefix"
        );
    }
    let mut broken = history.clone();
    broken.entries[1].previous_digest = [0x45; 32];
    broken.record_digest = broken.computed_record_digest();
    let mut reordered = history.clone();
    reordered.entries.swap(0, 1);
    reordered.record_digest = reordered.computed_record_digest();
    let mut rewritten_link = history.clone();
    rewritten_link.entries[0].record_digest = [0x46; 32];
    rewritten_link.record_digest = rewritten_link.computed_record_digest();
    for invalid in [&broken, &reordered, &rewritten_link] {
        assert_eq!(invalid.validate(), Err(Error::BrokenHistoryLink));
        assert_eq!(invalid.to_canonical_cbor(), Err(Error::BrokenHistoryLink));
        assert_eq!(invalid.extends(&PROFILE), Err(Error::BrokenHistoryLink));
    }
    let mut tampered = history.clone();
    tampered.record_digest = [0; 32];
    assert_eq!(tampered.validate(), Err(Error::RecordDigestMismatch));
    assert_eq!(tampered.replay(&[]), Err(Error::RecordDigestMismatch));
    Ok(())
}

#[test]
fn chs1_holds_at_most_4096_entries() -> TestResult {
    let mut entries = Vec::new();
    let mut previous = PROFILE;
    for _ in 0..4096 {
        let entry = ConformanceHistoryEntryV1 {
            previous_digest: previous,
            record_kind: Kind::Correction,
            record_digest: [0x47; 32],
        };
        previous = entry.entry_digest();
        entries.push(entry);
    }
    let mut full = ConformanceHistoryV1 {
        profile_digest: PROFILE,
        entries,
        record_digest: [0; 32],
    };
    full.record_digest = full.computed_record_digest();
    assert_eq!(
        ConformanceHistoryV1::from_canonical_cbor(&full.to_canonical_cbor()?)?,
        full
    );
    assert_eq!(
        full.append(Kind::Correction, [0x47; 32]),
        Err(Error::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn chs1_lifecycle_moves_only_draft_candidate_stable_retired() -> TestResult {
    use ProfileLifecycleV1::{Candidate, Draft, Retired, Stable};
    let to_candidate = promotion_record(Draft, Candidate)?;
    let to_stable = promotion_record(Candidate, Stable)?;
    let retire = retention(ConformanceArtifactKindV1::ConformanceProfile, PROFILE)?;
    let other_retirement = retention(ConformanceArtifactKindV1::Fixture, [0x48; 32])?;
    let accepted: [(&str, Vec<HistoryRecord>, ProfileLifecycleV1); 6] = [
        ("empty", vec![], Draft),
        ("candidate", vec![to_candidate.clone()], Candidate),
        (
            "stable",
            vec![to_candidate.clone(), to_stable.clone()],
            Stable,
        ),
        (
            "retired from stable",
            vec![to_candidate.clone(), to_stable.clone(), retire.clone()],
            Retired,
        ),
        (
            "rollback retires a candidate",
            vec![to_candidate.clone(), retire.clone()],
            Retired,
        ),
        (
            "retiring another artifact keeps the lifecycle",
            vec![
                to_candidate.clone(),
                other_retirement,
                correction()?,
                impact_analysis()?,
                withdrawal()?,
            ],
            Candidate,
        ),
    ];
    for (name, records, lifecycle) in accepted {
        assert_eq!(replay(PROFILE, &records)?, Ok(lifecycle), "{name}");
    }
    let invalid = Error::InvalidLifecycleTransition;
    let refused: [(&str, Vec<HistoryRecord>); 6] = [
        ("skip to stable", vec![to_stable.clone()]),
        (
            "candidate twice",
            vec![to_candidate.clone(), to_candidate.clone()],
        ),
        ("draft retired", vec![retire.clone()]),
        (
            "retired twice",
            vec![to_candidate.clone(), retire.clone(), retire.clone()],
        ),
        (
            "promotion after retirement",
            vec![to_candidate.clone(), retire.clone(), to_stable.clone()],
        ),
        (
            "stable twice",
            vec![to_candidate, to_stable.clone(), to_stable],
        ),
    ];
    for (name, records) in refused {
        assert_eq!(replay(PROFILE, &records)?, Err(invalid), "{name}");
    }
    Ok(())
}

#[test]
fn chs1_replay_binds_each_record_to_its_entry_and_profile() -> TestResult {
    let other = [0x49; 32];
    let mismatch = [
        ("waiver of another profile", waiver("case-a", other, 50)?),
        (
            "conflict of another profile",
            conflict(
                ConformanceConflictKindV1::ConflictOfInterest,
                ConformanceConflictResolutionV1::Open,
                other,
            )?,
        ),
        (
            "retirement of another profile",
            retention(ConformanceArtifactKindV1::ConformanceProfile, other)?,
        ),
    ];
    let to_candidate = promotion_record(ProfileLifecycleV1::Draft, ProfileLifecycleV1::Candidate)?;
    for (name, record) in mismatch {
        assert_eq!(
            replay(PROFILE, &[to_candidate.clone(), record])?,
            Err(Error::ProfileMismatch),
            "{name}"
        );
    }
    assert_eq!(
        replay(other, &[to_candidate.clone()])?,
        Err(Error::ProfileMismatch),
        "a promotion of another profile"
    );
    let correction = correction()?;
    let (history, records) = history_of(PROFILE, &[to_candidate.clone(), correction.clone()])?;
    assert_eq!(
        history.replay(&[records[0].as_slice()]),
        Err(Error::HistoryRecordMismatch),
        "a missing record"
    );
    let misnamed = ConformanceHistoryV1::new(PROFILE)
        .append(Kind::Promotion, to_candidate.2)?
        .append(Kind::Withdrawal, correction.2)?;
    assert_eq!(
        misnamed.replay(&[records[0].as_slice(), withdrawal()?.1.as_slice()]),
        Err(Error::HistoryRecordMismatch),
        "a record that is not the one the entry names"
    );
    for kind in [
        Kind::Waiver,
        Kind::Conflict,
        Kind::Correction,
        Kind::ImpactAnalysis,
        Kind::Withdrawal,
        Kind::Retention,
        Kind::Promotion,
    ] {
        let history = ConformanceHistoryV1::new(PROFILE).append(kind, [0x4a; 32])?;
        assert_eq!(
            history
                .replay(&[records[1].as_slice()])
                .map(|state| state.lifecycle()),
            Err(if kind == Kind::Correction {
                Error::HistoryRecordMismatch
            } else {
                Error::UnsupportedSchemaVersion
            }),
            "{kind:?}: the record bytes must decode as the entry's kind"
        );
    }
    Ok(())
}

#[test]
fn chs1_snapshot_digest_covers_exactly_the_history_waivers_and_conflicts() -> TestResult {
    let records = [
        waiver("case-z", PROFILE, 50)?,
        conflict(
            ConformanceConflictKindV1::SharedCode,
            ConformanceConflictResolutionV1::ResolvedByNewProfileDigest,
            PROFILE,
        )?,
        waiver("case-a", PROFILE, 50)?,
        correction()?,
        conflict(
            ConformanceConflictKindV1::ConflictOfInterest,
            ConformanceConflictResolutionV1::Open,
            PROFILE,
        )?,
    ];
    let (history, bytes) = history_of(PROFILE, &records)?;
    let slices: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    let state = history.replay(&slices)?;
    assert_eq!(state.waivers().len(), 2);
    assert_eq!(state.conflicts().len(), 2);
    assert!(state.has_open_conflict());
    let sorted = |indices: [usize; 2]| {
        let mut digests: Vec<[u8; 32]> = indices.iter().map(|index| records[*index].2).collect();
        digests.sort_unstable();
        Value::Array(
            digests
                .iter()
                .map(|digest| bytes(digest.as_slice()))
                .collect(),
        )
    };
    assert_eq!(
        state.waiver_conflict_snapshot_digest(),
        oracle_digest(
            b"PiglorOS.ConformanceWaiverConflictSnapshot.v1",
            &Value::Array(vec![sorted([0, 2]), sorted([1, 4])]),
        )?
    );
    let (resolved, bytes) = history_of(PROFILE, &records[..2])?;
    let slices: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
    assert!(!resolved.replay(&slices)?.has_open_conflict());
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The synthetic profile, reports and trust port of the promotion gate

fn artifact(path: &str) -> ArtifactDescriptorV1 {
    ArtifactDescriptorV1 {
        member_path: path.to_owned(),
        media_type: "application/cbor".to_owned(),
        byte_length: 1,
        blake3_digest: [0x11; 32],
    }
}

fn fixture(
    case_id: &str,
    mandatory: bool,
    seed: u8,
    divergence: Option<AllowedDivergenceV1>,
) -> FixtureDescriptorV1 {
    let kind = if divergence.is_some() {
        StrictOracleKindV1::Divergence
    } else {
        StrictOracleKindV1::Output
    };
    FixtureDescriptorV1 {
        case_id: case_id.to_owned(),
        mandatory,
        claim_layer: ClaimLayerV1::ReplayConformance,
        family: FixtureFamilyV1::Positive,
        provider_key: FixtureProviderKeyV1 {
            provider_id: "pigloros.fixture.replay-conformance".to_owned(),
            contract_version: "1.0.0".to_owned(),
            abi_major: 1,
            abi_minor: 0,
        },
        subject_adapter: SubjectAdapterKindV1::ExportedArtifact,
        execution_profile_digest: [0x12; 32],
        modes: vec![LOCAL, AIR, ExecutionModeV1::Replay],
        schema: artifact("schema.cbor"),
        payload: artifact("payload.cbor"),
        auxiliary: Vec::new(),
        strict_oracle: StrictOracleV1 {
            kind,
            output: divergence.is_none().then(|| artifact("expected.cbor")),
            failure: None,
            divergence,
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
        fixture_digest: [seed; 32],
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

/// The authenticated CPF1 the caller holds: the mandatory exact case `case-a`, the mandatory
/// allowed-divergence case `case-b` at `COORDINATE` and the non-mandatory case `case-c`.
fn profile() -> ConformanceProfileV1 {
    let allowed = AllowedDivergenceV1 {
        classification: DivergenceMismatchKindV1::CanonicalBytes,
        first_coordinate: COORDINATE.to_vec(),
    };
    ConformanceProfileV1 {
        profile_id: "pigloros.w8.replay-conformance".to_owned(),
        semantic_version: "1.0.0".to_owned(),
        lifecycle: ProfileLifecycleV1::Draft,
        normative_spec_digest: [0x1a; 32],
        execution_matrix_digest: [0x1b; 32],
        execution_profile_digests: vec![[0x12; 32]],
        fixture_provider_registry: FixtureProviderRegistryBindingV1 {
            registry_artifact: artifact("registry.cbor"),
            required_provider_keys: Vec::new(),
        },
        fixtures: vec![
            fixture("case-a", true, 0x31, None),
            fixture("case-b", true, 0x32, Some(allowed.clone())),
            fixture("case-c", false, 0x33, None),
        ],
        allowed_divergences: vec![allowed],
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
        profile_digest: PROFILE,
    }
}

fn case(case_id: &str, seed: u8, mode: ExecutionModeV1) -> CaseOutcomeV1 {
    CaseOutcomeV1 {
        case_id: case_id.to_owned(),
        fixture_digest: [seed; 32],
        execution_profile_digest: [0x12; 32],
        mode,
        claim_layer: ClaimLayerV1::ReplayConformance,
        outcome: CaseOutcomeStatusV1::Pass,
        first_coordinate: None,
        expected_digest: Some([0x41; 32]),
        actual_digest: Some([0x41; 32]),
        expected_error: None,
        actual_error: None,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        provenance_digest: [0x40; 32],
    }
}

/// The unsealed report of `identity` in `mode`: `case-a` exact, `case-b` at the allowed
/// divergence and, in the Local report, a skipped Replay case that does not gate.
fn report(identity: &ImplementationIdentityV1, mode: ExecutionModeV1) -> ConformanceReportV1 {
    let local = mode == LOCAL;
    let mut divergent = case("case-b", 0x32, mode);
    divergent.expected_digest = Some([0x42; 32]);
    divergent.actual_digest = Some([0x43; 32]);
    divergent.first_coordinate = Some(COORDINATE.to_vec());
    let mut cases = vec![case("case-a", 0x31, mode), divergent];
    if local {
        let mut skipped = case("case-a", 0x31, ExecutionModeV1::Replay);
        skipped.outcome = CaseOutcomeStatusV1::Skip;
        skipped.actual_digest = None;
        cases.push(skipped);
    }
    ConformanceReportV1 {
        report_id: [identity.source_digest[0] ^ u8::from(local); 16],
        subject_artifact_digest: [0x52; 32],
        profile_digest: PROFILE,
        normative_spec_digest: [0x1a; 32],
        execution_profile_digest: if local { [0xd1; 32] } else { [0xd2; 32] },
        fixture_bundle_digest: if local { [0xf1; 32] } else { [0xf2; 32] },
        evaluator_source_digest: [0xe1; 32],
        evaluator_binary_digest: [0xe2; 32],
        evaluator_protocol_digest: [0x1c; 32],
        implementation: identity.clone(),
        independence: IndependenceEvidenceV1 {
            technical_independent: true,
            authorship_independent: true,
            organizational_independent: false,
            declaration_digest: [0x59; 32],
            shared_code_audit_digest: AUDIT,
            reviewer_ids: vec!["reviewer".to_owned()],
        },
        cases,
        passed: 0,
        failed: 0,
        skipped: 0,
        unavailable: 0,
        not_applicable: 0,
        replay_claim: ReplayClaimV1::Exact,
        redaction_state: RedactionStateV1::None,
        limitations_digest: [0x5b; 32],
        evaluator_build_provenance_digest: [0x5c; 32],
        report_digest: [0; 32],
    }
}

/// Sort the cases, recompute the counts and the report digest.
fn seal(report: &mut ConformanceReportV1) -> TestResult {
    report.cases.sort_by(|left, right| {
        (
            left.case_id.as_str(),
            left.mode,
            left.claim_layer,
            left.fixture_digest,
        )
            .cmp(&(
                right.case_id.as_str(),
                right.mode,
                right.claim_layer,
                right.fixture_digest,
            ))
    });
    let count = |outcome| {
        u32::try_from(
            report
                .cases
                .iter()
                .filter(|case| case.outcome == outcome)
                .count(),
        )
    };
    report.passed = count(CaseOutcomeStatusV1::Pass)?;
    report.failed = count(CaseOutcomeStatusV1::Fail)?;
    report.skipped = count(CaseOutcomeStatusV1::Skip)?;
    report.unavailable = count(CaseOutcomeStatusV1::Unavailable)?;
    report.not_applicable = count(CaseOutcomeStatusV1::NotApplicable)?;
    report.report_digest = report.digest()?;
    Ok(())
}

/// A G2 trust port test double: one report-signing root, one evaluator-release root and
/// revoked report and evaluator binary digests.
struct Trust {
    key: VerifyingKey,
    revoked_reports: Vec<[u8; 32]>,
    revoked_binaries: Vec<[u8; 32]>,
}

impl ConformanceTrustAdmissionPortV1 for Trust {
    fn admit_key(
        &self,
        role: ConformanceTrustRoleV1,
        key_id: &[u8; 32],
    ) -> Result<VerifyingKey, ConformanceKeyRefusalV1> {
        let (own, other) = match role {
            ConformanceTrustRoleV1::ReportSigning => (REPORT_KEY, EVALUATOR_KEY),
            ConformanceTrustRoleV1::EvaluatorRelease => (EVALUATOR_KEY, REPORT_KEY),
        };
        if *key_id == own {
            Ok(self.key)
        } else if *key_id == other {
            Err(ConformanceKeyRefusalV1::RoleMismatch)
        } else {
            Err(ConformanceKeyRefusalV1::UnknownRoot)
        }
    }

    fn check_artifact_revocation(
        &self,
        report_digest: &[u8; 32],
        evaluator_binary_digest: &[u8; 32],
    ) -> Result<(), ConformanceArtifactRefusalV1> {
        if self.revoked_reports.contains(report_digest) {
            Err(ConformanceArtifactRefusalV1::RevokedReport)
        } else if self.revoked_binaries.contains(evaluator_binary_digest) {
            Err(ConformanceArtifactRefusalV1::RevokedEvaluatorBinary)
        } else {
            Ok(())
        }
    }
}

/// One promotion attempt, edited before it is sealed and run.
struct Scenario {
    profile: ConformanceProfileV1,
    /// `[implementation][Local, Air-Gapped]`, unsealed.
    reports: [[ConformanceReportV1; 2]; 2],
    /// `[implementation][Local, Air-Gapped]`: the report-signing and evaluator-release key ids.
    keys: [[([u8; 32], [u8; 32]); 2]; 2],
    /// Whether the history holds the Draft -> Candidate promotion.
    candidate: bool,
    /// History records after the Draft -> Candidate promotion.
    records: Vec<HistoryRecord>,
    history_profile: [u8; 32],
    /// Edits the Stable CPR1 before it is sealed.
    promotion: fn(&mut ConformancePromotionV1),
    /// Edits the sealed reports.
    sealed: fn(&mut [[ConformanceReportV1; 2]; 2]),
    revoked_reports: fn(&[[ConformanceReportV1; 2]; 2]) -> Vec<[u8; 32]>,
    revoked_binaries: Vec<[u8; 32]>,
}

impl Scenario {
    fn new() -> Self {
        let first = identity("impl-a", 0xa1);
        let second = identity("impl-b", 0xb1);
        Self {
            profile: profile(),
            reports: [
                [report(&first, LOCAL), report(&first, AIR)],
                [report(&second, LOCAL), report(&second, AIR)],
            ],
            keys: [[(REPORT_KEY, EVALUATOR_KEY); 2]; 2],
            candidate: true,
            records: Vec::new(),
            history_profile: PROFILE,
            promotion: |_| {},
            sealed: |_| {},
            revoked_reports: |_| Vec::new(),
            revoked_binaries: Vec::new(),
        }
    }

    /// Edit both reports of the second implementation.
    fn second(mut self, edit: impl Fn(&mut ConformanceReportV1)) -> Self {
        self.reports[1].iter_mut().for_each(edit);
        self
    }

    /// Edit every report.
    fn all(mut self, edit: impl Fn(&mut ConformanceReportV1)) -> Self {
        self.reports.iter_mut().flatten().for_each(edit);
        self
    }

    fn run(mut self) -> TestResult<Result<(), Refusal>> {
        for report in self.reports.iter_mut().flatten() {
            seal(report)?;
        }
        if self.reports[0][0].report_digest > self.reports[1][0].report_digest {
            self.reports.swap(0, 1);
            self.keys.swap(0, 1);
        }
        let mut stable = promotion(ProfileLifecycleV1::Candidate, ProfileLifecycleV1::Stable);
        for (digests, reports) in [
            (&mut stable.first_reports, &self.reports[0]),
            (&mut stable.second_reports, &self.reports[1]),
        ] {
            digests.local_report_digest = reports[0].report_digest;
            digests.air_gapped_report_digest = reports[1].report_digest;
        }
        stable.first_implementation = self.reports[0][0].implementation.clone();
        stable.second_implementation = self.reports[1][0].implementation.clone();
        let mut records = Vec::new();
        if self.candidate {
            records.push(promotion_record(
                ProfileLifecycleV1::Draft,
                ProfileLifecycleV1::Candidate,
            )?);
        }
        records.extend(self.records.iter().cloned());
        let (history, bytes) = history_of(self.history_profile, &records)?;
        let slices: Vec<&[u8]> = bytes.iter().map(Vec::as_slice).collect();
        if let Ok(state) = history.replay(&slices) {
            stable.waiver_conflict_snapshot_digest = state.waiver_conflict_snapshot_digest();
        }
        (self.promotion)(&mut stable);
        stable.record_digest = stable.computed_record_digest();
        (self.sealed)(&mut self.reports);
        let trust = Trust {
            key: SigningKey::from_bytes(&[7; 32]).verifying_key(),
            revoked_reports: (self.revoked_reports)(&self.reports),
            revoked_binaries: self.revoked_binaries,
        };
        let evidence = |index: usize, mode: usize| ConformancePromotionReportEvidenceV1 {
            report: &self.reports[index][mode],
            report_key_id: self.keys[index][mode].0,
            evaluator_key_id: self.keys[index][mode].1,
        };
        let implementation = |index| ConformancePromotionImplementationEvidenceV1 {
            local: evidence(index, 0),
            air_gapped: evidence(index, 1),
        };
        let input = ConformancePromotionGateInputV1 {
            profile: &self.profile,
            history: &history,
            history_records: &slices,
            promotion: &stable,
            implementations: [implementation(0), implementation(1)],
        };
        Ok(check_stable_promotion_v1(&input, &trust))
    }
}

type Case = (&'static str, Scenario, Refusal);

fn refused(cases: Vec<Case>) -> TestResult {
    for (name, scenario, refusal) in cases {
        assert_eq!(scenario.run()?, Err(refusal), "{name}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The promotion gate

#[test]
fn two_synthetic_independent_implementations_pass_the_gate() -> TestResult {
    assert_eq!(Scenario::new().run()?, Ok(()));
    let mut documented = Scenario::new();
    documented.records = vec![
        waiver("case-c", PROFILE, 50)?,
        waiver("case-a", PROFILE, 10)?,
        conflict(
            ConformanceConflictKindV1::SharedCode,
            ConformanceConflictResolutionV1::ResolvedByNewProfileDigest,
            PROFILE,
        )?,
    ];
    assert_eq!(
        documented.run()?,
        Ok(()),
        "a non-mandatory waiver, an expired mandatory waiver and a resolved conflict"
    );
    let mut organizational = Scenario::new().all(|report| {
        report.independence.organizational_independent = true;
    });
    organizational
        .profile
        .independence_requirements
        .organizational_independence_required = true;
    assert_eq!(organizational.run()?, Ok(()));
    Ok(())
}

#[test]
fn false_second_implementations_are_refused() -> TestResult {
    refused(vec![
        (
            "a wrapper of the same engine",
            Scenario::new().second(|report| {
                report.implementation.implementation_id = "impl-a".to_owned();
            }),
            Refusal::SameImplementation,
        ),
        (
            "an alternate build of the same source",
            Scenario::new().second(|report| report.implementation.source_digest = [0xa1; 32]),
            Refusal::SameImplementation,
        ),
        (
            "a feature-flag variant of the same build",
            Scenario::new().second(|report| report.implementation.build_digest = [0xa2; 32]),
            Refusal::SameImplementation,
        ),
        (
            "the same binary",
            Scenario::new().second(|report| report.implementation.binary_digest = [0xa3; 32]),
            Refusal::SameImplementation,
        ),
        (
            "another public contract",
            Scenario::new()
                .second(|report| report.implementation.public_contract_digest = [0x98; 32]),
            Refusal::PublicContractMismatch,
        ),
        (
            "an evaluator posing as an implementation (source)",
            Scenario::new().second(|report| report.implementation.source_digest = [0xe1; 32]),
            Refusal::EvaluatorAsImplementation,
        ),
        (
            "an evaluator posing as an implementation (binary)",
            Scenario::new().second(|report| report.implementation.binary_digest = [0xe2; 32]),
            Refusal::EvaluatorAsImplementation,
        ),
    ])
}

fn failing_case(outcome: CaseOutcomeStatusV1) -> Scenario {
    Scenario::new().second(move |report| {
        let case = &mut report.cases[0];
        case.outcome = outcome;
        case.actual_digest = None;
    })
}

#[test]
fn every_mandatory_local_and_air_gapped_case_must_pass_in_both() -> TestResult {
    let mut local_only = Scenario::new();
    local_only.profile.fixtures[0].modes = vec![LOCAL];
    let mut air_only = Scenario::new();
    air_only.profile.fixtures[0].modes = vec![AIR];
    refused(vec![
        (
            "mandatory Skip",
            failing_case(CaseOutcomeStatusV1::Skip),
            Refusal::CaseNotPassed,
        ),
        (
            "mandatory Unavailable",
            failing_case(CaseOutcomeStatusV1::Unavailable),
            Refusal::CaseNotPassed,
        ),
        (
            "mandatory Fail",
            failing_case(CaseOutcomeStatusV1::Fail),
            Refusal::CaseNotPassed,
        ),
        (
            "mandatory NotApplicable",
            failing_case(CaseOutcomeStatusV1::NotApplicable),
            Refusal::CaseNotPassed,
        ),
        (
            "a non-executed mandatory case",
            Scenario::new().second(|report| {
                report.cases.retain(|case| case.case_id != "case-a");
            }),
            Refusal::CaseNotExecuted,
        ),
        (
            "Local-only evidence without Air-Gapped",
            Scenario::new().second(|report| {
                if report.cases.len() == 2 {
                    for case in &mut report.cases {
                        case.mode = LOCAL;
                    }
                }
            }),
            Refusal::CaseNotExecuted,
        ),
        (
            "a case of another claim layer",
            Scenario::new().second(|report| {
                report.cases[0].claim_layer = ClaimLayerV1::ArtifactIntegrity;
            }),
            Refusal::CaseNotExecuted,
        ),
        (
            "a case of another fixture",
            Scenario::new().second(|report| report.cases[0].fixture_digest = [0x34; 32]),
            Refusal::CaseNotExecuted,
        ),
        (
            "a mandatory fixture without Air-Gapped",
            local_only,
            Refusal::MandatoryModeMissing,
        ),
        (
            "a mandatory fixture without Local",
            air_only,
            Refusal::MandatoryModeMissing,
        ),
    ])
}

#[test]
fn only_the_same_profile_allowed_divergence_at_the_same_first_coordinate_passes() -> TestResult {
    let coordinate = |coordinate: &'static [u8]| {
        move |report: &mut ConformanceReportV1| {
            for case in &mut report.cases {
                if case.case_id == "case-b" {
                    case.first_coordinate = Some(coordinate.to_vec());
                }
            }
        }
    };
    refused(vec![
        (
            "an unequal first coordinate",
            Scenario::new().second(coordinate(b"tick/4")),
            Refusal::DivergenceNotAllowed,
        ),
        (
            "the same divergence outside the profile",
            Scenario::new().all(coordinate(b"tick/4")),
            Refusal::DivergenceNotAllowed,
        ),
        (
            "a divergence of an exact case",
            Scenario::new().second(|report| {
                report.cases[0].actual_digest = Some([0x44; 32]);
                report.cases[0].first_coordinate = Some(COORDINATE.to_vec());
            }),
            Refusal::DivergenceNotAllowed,
        ),
        (
            "different divergent bytes",
            Scenario::new().second(|report| {
                for case in &mut report.cases {
                    if case.case_id == "case-b" {
                        case.actual_digest = Some([0x44; 32]);
                    }
                }
            }),
            Refusal::OutcomeMismatch,
        ),
    ])
}

#[test]
fn waivers_and_conflicts_from_the_history_keep_the_profile_candidate() -> TestResult {
    let with = |records: Vec<HistoryRecord>| {
        let mut scenario = Scenario::new();
        scenario.records = records;
        scenario
    };
    refused(vec![
        (
            "an active waiver on a mandatory case",
            with(vec![waiver("case-a", PROFILE, 50)?]),
            Refusal::ActiveMandatoryWaiver,
        ),
        (
            "an open conflict",
            with(vec![conflict(
                ConformanceConflictKindV1::ImplementationDisagreement,
                ConformanceConflictResolutionV1::Open,
                PROFILE,
            )?]),
            Refusal::OpenConflict,
        ),
        (
            "a failing shared-code audit",
            with(vec![conflict(
                ConformanceConflictKindV1::SharedCode,
                ConformanceConflictResolutionV1::Open,
                PROFILE,
            )?]),
            Refusal::OpenConflict,
        ),
    ])
}

#[test]
fn independence_is_read_as_evidenced_never_inferred() -> TestResult {
    let mut organizational = Scenario::new();
    organizational
        .profile
        .independence_requirements
        .organizational_independence_required = true;
    refused(vec![
        (
            "a failing shared-code audit (not technically independent)",
            Scenario::new().second(|report| report.independence.technical_independent = false),
            Refusal::IndependenceNotEvidenced,
        ),
        (
            "missing authorship independence",
            Scenario::new().second(|report| report.independence.authorship_independent = false),
            Refusal::IndependenceNotEvidenced,
        ),
        (
            "missing organizational independence the profile requires",
            organizational,
            Refusal::IndependenceNotEvidenced,
        ),
        (
            "another shared-code audit",
            Scenario::new()
                .second(|report| report.independence.shared_code_audit_digest = [0xab; 32]),
            Refusal::SharedCodeAuditMismatch,
        ),
    ])
}

#[test]
fn unadmitted_evaluator_or_report_keys_and_revoked_artifacts_are_refused() -> TestResult {
    let keyed = |keys: ([u8; 32], [u8; 32])| {
        let mut scenario = Scenario::new();
        scenario.keys[1][1] = keys;
        scenario
    };
    let mut revoked_binary = Scenario::new();
    revoked_binary.revoked_binaries = vec![[0xe2; 32]];
    let mut revoked_report = Scenario::new();
    revoked_report.revoked_reports = |reports| vec![reports[1][1].report_digest];
    refused(vec![
        (
            "an unknown report key",
            keyed(([0x73; 32], EVALUATOR_KEY)),
            Refusal::KeyRefused(
                ConformanceTrustRoleV1::ReportSigning,
                ConformanceKeyRefusalV1::UnknownRoot,
            ),
        ),
        (
            "an evaluator key signing reports",
            keyed((EVALUATOR_KEY, EVALUATOR_KEY)),
            Refusal::KeyRefused(
                ConformanceTrustRoleV1::ReportSigning,
                ConformanceKeyRefusalV1::RoleMismatch,
            ),
        ),
        (
            "a report key posing as the evaluator key",
            keyed((REPORT_KEY, REPORT_KEY)),
            Refusal::KeyRefused(
                ConformanceTrustRoleV1::EvaluatorRelease,
                ConformanceKeyRefusalV1::RoleMismatch,
            ),
        ),
        (
            "a revoked report",
            revoked_report,
            Refusal::ArtifactRevoked(ConformanceArtifactRefusalV1::RevokedReport),
        ),
        (
            "a revoked evaluator binary",
            revoked_binary,
            Refusal::ArtifactRevoked(ConformanceArtifactRefusalV1::RevokedEvaluatorBinary),
        ),
    ])
}

#[test]
fn the_promotion_history_and_profile_must_agree() -> TestResult {
    let mut not_candidate = Scenario::new();
    not_candidate.candidate = false;
    let mut other_history = Scenario::new();
    other_history.history_profile = [0x49; 32];
    let mut other_profile = Scenario::new();
    other_profile.profile.profile_digest = [0x49; 32];
    let mut unreadable = Scenario::new();
    unreadable.records = vec![(Kind::Correction, vec![0], [0x4a; 32])];
    let edit = |edit: fn(&mut ConformancePromotionV1)| {
        let mut scenario = Scenario::new();
        scenario.promotion = edit;
        scenario
    };
    refused(vec![
        (
            "an invalid CPR1",
            edit(|promotion| promotion.approver_ids.clear()),
            Refusal::InvalidRecord(Error::FieldOutOfBounds),
        ),
        (
            "a promotion to Candidate",
            edit(|promotion| {
                promotion.from_lifecycle = ProfileLifecycleV1::Draft;
                promotion.to_lifecycle = ProfileLifecycleV1::Candidate;
            }),
            Refusal::NotStablePromotion,
        ),
        (
            "a CPR1 of another profile",
            other_profile,
            Refusal::ProfileMismatch,
        ),
        (
            "a history of another profile",
            other_history,
            Refusal::ProfileMismatch,
        ),
        (
            "an unreadable history record",
            unreadable,
            Refusal::InvalidRecord(Error::InvalidEncoding),
        ),
        ("a Draft profile", not_candidate, Refusal::NotCandidate),
        (
            "another waiver/conflict snapshot",
            edit(|promotion| promotion.waiver_conflict_snapshot_digest = [0x4b; 32]),
            Refusal::SnapshotMismatch,
        ),
    ])
}

#[test]
fn the_cpr1_names_exactly_the_four_reports() -> TestResult {
    let mut tampered = Scenario::new();
    tampered.sealed = |reports| reports[1][1].report_digest = [0x4c; 32];
    let mut renamed = Scenario::new();
    renamed.promotion = |promotion| promotion.second_reports.air_gapped_report_digest = [0x4d; 32];
    refused(vec![
        ("a tampered report", tampered, Refusal::InvalidReport),
        (
            "an implementation identity that differs between its reports",
            Scenario::new().second(|report| {
                if report.cases.len() == 2 {
                    report.implementation.organization_id = Some("org-b".to_owned());
                }
            }),
            Refusal::ReportNotNamed,
        ),
        (
            "a report the CPR1 does not name",
            renamed,
            Refusal::ReportNotNamed,
        ),
        (
            "a report of another profile",
            Scenario::new().second(|report| {
                if report.cases.len() == 2 {
                    report.profile_digest = [0x49; 32];
                }
            }),
            Refusal::ProfileMismatch,
        ),
    ])
}

#[test]
fn the_reports_share_protocol_bundle_and_execution_profile_per_mode() -> TestResult {
    let local = |edit: fn(&mut ConformanceReportV1)| {
        Scenario::new().second(move |report| {
            if report.cases.len() == 3 {
                edit(report);
            }
        })
    };
    let air = |edit: fn(&mut ConformanceReportV1)| {
        Scenario::new().second(move |report| {
            if report.cases.len() == 2 {
                edit(report);
            }
        })
    };
    let mismatch = Refusal::EvidenceMismatch;
    let mut first_protocol = Scenario::new();
    first_protocol.reports[0][0].evaluator_protocol_digest = [0x4e; 32];
    first_protocol.reports[1][0].evaluator_protocol_digest = [0x4e; 32];
    refused(vec![
        ("another evaluator protocol", first_protocol, mismatch),
        (
            "one other evaluator protocol",
            local(|report| report.evaluator_protocol_digest = [0x4e; 32]),
            mismatch,
        ),
        (
            "another Local fixture bundle",
            local(|report| report.fixture_bundle_digest = [0x4f; 32]),
            mismatch,
        ),
        (
            "another Local execution profile",
            local(|report| report.execution_profile_digest = [0x4f; 32]),
            mismatch,
        ),
        (
            "another Air-Gapped fixture bundle",
            air(|report| report.fixture_bundle_digest = [0x4f; 32]),
            mismatch,
        ),
        (
            "another Air-Gapped execution profile",
            air(|report| report.execution_profile_digest = [0x4f; 32]),
            mismatch,
        ),
    ])
}

#[test]
fn every_refusal_and_history_error_is_displayed() {
    let refusals = [
        Refusal::InvalidRecord(Error::BrokenHistoryLink),
        Refusal::NotStablePromotion,
        Refusal::ProfileMismatch,
        Refusal::NotCandidate,
        Refusal::SnapshotMismatch,
        Refusal::OpenConflict,
        Refusal::ActiveMandatoryWaiver,
        Refusal::InvalidReport,
        Refusal::ReportNotNamed,
        Refusal::SameImplementation,
        Refusal::PublicContractMismatch,
        Refusal::EvaluatorAsImplementation,
        Refusal::EvidenceMismatch,
        Refusal::MandatoryModeMissing,
        Refusal::CaseNotExecuted,
        Refusal::CaseNotPassed,
        Refusal::DivergenceNotAllowed,
        Refusal::OutcomeMismatch,
        Refusal::IndependenceNotEvidenced,
        Refusal::SharedCodeAuditMismatch,
        Refusal::KeyRefused(
            ConformanceTrustRoleV1::EvaluatorRelease,
            ConformanceKeyRefusalV1::Revoked,
        ),
        Refusal::ArtifactRevoked(ConformanceArtifactRefusalV1::RevokedReport),
    ];
    let mut messages: Vec<String> = refusals.iter().map(ToString::to_string).collect();
    messages.extend(
        [
            Error::BrokenHistoryLink,
            Error::HistoryNotAppendOnly,
            Error::HistoryRecordMismatch,
        ]
        .iter()
        .map(ToString::to_string),
    );
    let count = messages.len();
    messages.sort();
    messages.dedup();
    assert_eq!(messages.len(), count, "every message is distinct");
    assert!(messages.iter().all(|message| !message.is_empty()));
}

#[test]
fn every_history_record_kind_code_round_trips_and_nothing_else_decodes() {
    for code in 0..=255 {
        match Kind::from_wire_code(code) {
            Some(kind) => {
                assert!(code < 7, "{kind:?}");
                assert_eq!(kind.wire_code(), code);
            }
            None => assert!(code >= 7, "code {code}"),
        }
    }
    assert!(Kind::from_wire_code(u64::MAX).is_none());
}
