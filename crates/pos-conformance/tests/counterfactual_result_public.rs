use ciborium::value::Value;
use pos_conformance::counterfactual::result::{
    CounterfactualCheckpointRefV1 as CheckpointRef,
    CounterfactualResultContractErrorV1 as ResultError, CounterfactualResultV1,
    CounterfactualTerminalErrorCodeV1 as ErrorCode, CounterfactualTerminalErrorV1 as TerminalError,
    CounterfactualTerminalStateV1 as TerminalState, COUNTERFACTUAL_RESULT_MAGIC_V1,
    MAX_COUNTERFACTUAL_RESULT_BYTES_V1, MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1,
};
use pos_conformance::ReplayClaimV1;
use std::collections::BTreeSet;
use std::io::Cursor;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Edit = fn(&mut CounterfactualResultV1);

const GENERATION: u64 = 2;
const FIELD_CHECKPOINTS: usize = 9;
const FIELD_TERMINAL_STATE: usize = 10;
const FIELD_TERMINAL_ERROR: usize = 11;
const FIELD_REPLAY_CLAIM: usize = 15;
const FIELD_RESULT_DIGEST: usize = 19;

const fn checkpoint(tick: u64, seed: u8) -> CheckpointRef {
    CheckpointRef {
        tick,
        fork_generation: GENERATION,
        checkpoint_digest: [seed; 32],
    }
}

const fn terminal_error(code: ErrorCode, tick: u64) -> TerminalError {
    TerminalError {
        code,
        tick,
        scheduler_position: 7,
        safe_digest: Some([0x33; 32]),
    }
}

fn sealed(mut result: CounterfactualResultV1) -> Result<CounterfactualResultV1, ResultError> {
    result.result_digest = result.digest()?;
    Ok(result)
}

fn completed() -> Result<CounterfactualResultV1, ResultError> {
    sealed(CounterfactualResultV1 {
        result_id: [1; 16],
        plan_digest: [2; 32],
        fork_id: [3; 16],
        fork_generation: GENERATION,
        first_tick: 10,
        horizon_tick: 12,
        committed_through_tick: Some(12),
        checkpoints: vec![checkpoint(10, 0x40), checkpoint(12, 0x41)],
        terminal_state: TerminalState::Completed,
        terminal_error: None,
        suffix_digest: [4; 32],
        dependency_root: [5; 32],
        provenance_root: [6; 32],
        replay_claim: ReplayClaimV1::Exact,
        execution_profile_digest: [7; 32],
        trust_policy_snapshot_digest: [8; 32],
        evaluator_identity_digest: [9; 32],
        result_digest: [0; 32],
    })
}

fn failed() -> Result<CounterfactualResultV1, ResultError> {
    let mut result = completed()?;
    result.committed_through_tick = Some(11);
    result.checkpoints = vec![checkpoint(10, 0x40)];
    result.terminal_state = TerminalState::Failed;
    result.terminal_error = Some(terminal_error(ErrorCode::PluginFailure, 12));
    result.replay_claim = ReplayClaimV1::StructuralOnly;
    sealed(result)
}

fn resealed_validation(
    base: &CounterfactualResultV1,
    edit: impl Fn(&mut CounterfactualResultV1),
) -> Result<(), ResultError> {
    let mut result = base.clone();
    edit(&mut result);
    sealed(result)?.validate()
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn fields_of(bytes: &[u8]) -> TestResult<Vec<Value>> {
    match ciborium::from_reader(Cursor::new(bytes))? {
        Value::Array(fields) => Ok(fields),
        _ => Err("CFR1 must be an array".into()),
    }
}

fn with_field(bytes: &[u8], index: usize, value: Value) -> TestResult<Vec<u8>> {
    let mut fields = fields_of(bytes)?;
    fields[index] = value;
    encode(&Value::Array(fields))
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn digest_from(index: u32) -> [u8; 32] {
    let mut digest = [0xa5; 32];
    digest[..4].copy_from_slice(&index.to_be_bytes());
    digest
}

fn decoded(bytes: &[u8]) -> Result<CounterfactualResultV1, ResultError> {
    CounterfactualResultV1::from_canonical_cbor(bytes)
}

#[test]
fn completed_result_roundtrips_exact_wire_fields_and_domain_digest() -> TestResult {
    let result = completed()?;
    assert!(result.is_complete());
    assert_eq!(result.validate(), Ok(()));
    let bytes = result.to_canonical_cbor()?;
    assert_eq!(decoded(&bytes)?, result);

    let digest = |seed: u8| Value::Bytes(vec![seed; 32]);
    let checkpoint_value =
        |tick: u64, seed: u8| Value::Array(vec![uint(tick), uint(GENERATION), digest(seed)]);
    let mut expected = vec![
        Value::Text("CFR1".to_owned()),
        uint(1),
        Value::Bytes(vec![1; 16]),
        digest(2),
        Value::Bytes(vec![3; 16]),
        uint(GENERATION),
        uint(10),
        uint(12),
        uint(12),
        Value::Array(vec![checkpoint_value(10, 0x40), checkpoint_value(12, 0x41)]),
        uint(0),
        Value::Null,
        digest(4),
        digest(5),
        digest(6),
        uint(0),
        digest(7),
        digest(8),
        digest(9),
    ];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.CounterfactualResult.v1\0");
    hasher.update(&encode(&Value::Array(expected.clone()))?);
    assert_eq!(result.digest()?, *hasher.finalize().as_bytes());
    expected.push(Value::Bytes(result.result_digest.to_vec()));
    assert_eq!(fields_of(&bytes)?, expected);
    assert_eq!(
        Value::Text(COUNTERFACTUAL_RESULT_MAGIC_V1.to_owned()),
        expected[0]
    );
    Ok(())
}

#[test]
fn incomplete_results_roundtrip_with_safe_terminal_errors() -> TestResult {
    let result = failed()?;
    assert!(!result.is_complete());
    let bytes = result.to_canonical_cbor()?;
    assert_eq!(decoded(&bytes)?, result);
    assert_eq!(
        fields_of(&bytes)?[FIELD_TERMINAL_ERROR],
        Value::Array(vec![
            uint(21),
            uint(12),
            uint(7),
            Value::Bytes(vec![0x33; 32])
        ])
    );

    let mut nothing_committed = failed()?;
    nothing_committed.committed_through_tick = None;
    nothing_committed.checkpoints.clear();
    nothing_committed.terminal_error = Some(TerminalError {
        code: ErrorCode::ParentCutNotFound,
        tick: 10,
        scheduler_position: u32::MAX,
        safe_digest: None,
    });
    let nothing_committed = sealed(nothing_committed)?;
    let bytes = nothing_committed.to_canonical_cbor()?;
    assert_eq!(fields_of(&bytes)?[8], Value::Null);
    assert_eq!(decoded(&bytes)?, nothing_committed);

    let mut stopped = failed()?;
    stopped.terminal_state = TerminalState::SafeStopped;
    stopped.terminal_error = None;
    stopped.replay_claim = ReplayClaimV1::UnverifiableArtifactsMissing;
    let stopped = sealed(stopped)?;
    assert_eq!(decoded(&stopped.to_canonical_cbor()?)?, stopped);
    Ok(())
}

#[test]
fn every_closed_enum_code_has_one_exact_wire_value() -> TestResult {
    assert_eq!(
        ErrorCode::ALL.iter().collect::<BTreeSet<_>>().len(),
        ErrorCode::ALL.len()
    );
    assert_eq!(ErrorCode::ALL[0], ErrorCode::InvalidEncoding);
    assert_eq!(ErrorCode::ALL[24], ErrorCode::ProvenanceMissing);
    assert_eq!(ErrorCode::ALL[25], ErrorCode::DependencyGraphIncomplete);
    assert_eq!(ErrorCode::ALL[32], ErrorCode::MixedForkGeneration);
    for (index, code) in ErrorCode::ALL.into_iter().enumerate() {
        let mut result = failed()?;
        result.terminal_error = Some(terminal_error(code, 12));
        let result = sealed(result)?;
        let bytes = result.to_canonical_cbor()?;
        let fields = fields_of(&bytes)?;
        let Value::Array(error) = &fields[FIELD_TERMINAL_ERROR] else {
            return Err("terminal error must be an array".into());
        };
        assert_eq!(error[0], uint(u64::try_from(index)?));
        assert_eq!(decoded(&bytes)?, result);
    }
    for (index, state) in TerminalState::ALL.into_iter().enumerate() {
        assert_eq!(usize::from(state as u8), index);
    }
    assert_eq!(
        fields_of(&failed()?.to_canonical_cbor()?)?[FIELD_TERMINAL_STATE],
        uint(1)
    );
    let claims = [
        ReplayClaimV1::Exact,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
        ReplayClaimV1::StructuralOnly,
        ReplayClaimV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::IncompatibleProfile,
    ];
    for (index, claim) in claims.into_iter().enumerate() {
        let mut result = completed()?;
        result.replay_claim = claim;
        let result = sealed(result)?;
        let bytes = result.to_canonical_cbor()?;
        assert_eq!(
            fields_of(&bytes)?[FIELD_REPLAY_CLAIM],
            uint(u64::try_from(index)?)
        );
        assert_eq!(decoded(&bytes)?, result);
    }
    Ok(())
}

#[test]
fn decoder_rejects_unknown_enum_codes() -> TestResult {
    let completed_bytes = completed()?.to_canonical_cbor()?;
    for (field, code) in [(FIELD_TERMINAL_STATE, 3), (FIELD_REPLAY_CLAIM, 5)] {
        let bytes = with_field(&completed_bytes, field, uint(code))?;
        assert_eq!(decoded(&bytes), Err(ResultError::UnknownEnum));
    }
    let bytes = with_field(
        &failed()?.to_canonical_cbor()?,
        FIELD_TERMINAL_ERROR,
        Value::Array(vec![uint(33), uint(12), uint(7), Value::Null]),
    )?;
    assert_eq!(decoded(&bytes), Err(ResultError::UnknownEnum));
    Ok(())
}

#[test]
fn digest_binds_every_field_and_the_declared_digest_is_checked() -> TestResult {
    let base = completed()?;
    let identity_edits: [Edit; 11] = [
        |result| result.result_id[0] ^= 1,
        |result| result.plan_digest[0] ^= 1,
        |result| result.fork_id[0] ^= 1,
        |result| result.checkpoints[0].checkpoint_digest[0] ^= 1,
        |result| result.suffix_digest[0] ^= 1,
        |result| result.dependency_root[0] ^= 1,
        |result| result.provenance_root[0] ^= 1,
        |result| result.replay_claim = ReplayClaimV1::StructuralOnly,
        |result| result.execution_profile_digest[0] ^= 1,
        |result| result.trust_policy_snapshot_digest[0] ^= 1,
        |result| result.evaluator_identity_digest[0] ^= 1,
    ];
    let shape_edits: [Edit; 8] = [
        |result| result.fork_generation += 1,
        |result| result.first_tick += 1,
        |result| result.horizon_tick += 1,
        |result| result.committed_through_tick = None,
        |result| result.checkpoints[0].tick += 1,
        |result| result.checkpoints[0].fork_generation += 1,
        |result| result.terminal_state = TerminalState::SafeStopped,
        |result| result.terminal_error = Some(terminal_error(ErrorCode::PluginFailure, 13)),
    ];
    for edit in identity_edits {
        let mut result = base.clone();
        edit(&mut result);
        assert_ne!(result.digest()?, base.digest()?);
        assert_eq!(result.validate(), Err(ResultError::DigestMismatch));
        assert_eq!(sealed(result)?.validate(), Ok(()));
    }
    for edit in shape_edits {
        let mut result = base.clone();
        edit(&mut result);
        assert_ne!(result.digest()?, base.digest()?);
    }
    let error_base = failed()?;
    let error_edits: [fn(&mut TerminalError); 4] = [
        |error| error.code = ErrorCode::AtomicCommitFailed,
        |error| error.tick += 1,
        |error| error.scheduler_position += 1,
        |error| error.safe_digest = None,
    ];
    for edit in error_edits {
        let mut result = error_base.clone();
        if let Some(error) = result.terminal_error.as_mut() {
            edit(error);
        }
        assert_ne!(result.digest()?, error_base.digest()?);
    }

    let mut tampered = base.clone();
    tampered.result_digest[31] ^= 1;
    assert_eq!(tampered.validate(), Err(ResultError::DigestMismatch));
    assert_eq!(
        tampered.to_canonical_cbor(),
        Err(ResultError::DigestMismatch)
    );
    let bytes = with_field(
        &base.to_canonical_cbor()?,
        FIELD_RESULT_DIGEST,
        Value::Bytes(tampered.result_digest.to_vec()),
    )?;
    assert_eq!(decoded(&bytes), Err(ResultError::DigestMismatch));
    Ok(())
}

const ZERO_IDENTITY_EDITS: [Edit; 11] = [
    |result| result.result_id = [0; 16],
    |result| result.plan_digest = [0; 32],
    |result| result.fork_id = [0; 16],
    |result| result.checkpoints[0].checkpoint_digest = [0; 32],
    |result| result.suffix_digest = [0; 32],
    |result| result.dependency_root = [0; 32],
    |result| result.provenance_root = [0; 32],
    |result| result.execution_profile_digest = [0; 32],
    |result| result.trust_policy_snapshot_digest = [0; 32],
    |result| result.evaluator_identity_digest = [0; 32],
    |result| {
        if let Some(error) = result.terminal_error.as_mut() {
            error.safe_digest = Some([0; 32]);
        }
    },
];

fn minimal_nonzero<const LENGTH: usize>() -> [u8; LENGTH] {
    let mut value = [0; LENGTH];
    value[LENGTH - 1] = 1;
    value
}

#[test]
fn zero_identities_and_digests_are_rejected() -> TestResult {
    let base = failed()?;
    for edit in ZERO_IDENTITY_EDITS {
        let mut result = base.clone();
        edit(&mut result);
        assert_eq!(result.validate(), Err(ResultError::FieldOutOfBounds));
        let resealed = sealed(result)?;
        assert_eq!(resealed.validate(), Err(ResultError::FieldOutOfBounds));
        assert_eq!(
            resealed.to_canonical_cbor(),
            Err(ResultError::FieldOutOfBounds)
        );
    }
    let bytes = with_field(&base.to_canonical_cbor()?, 2, Value::Bytes(vec![0; 16]))?;
    assert_eq!(decoded(&bytes), Err(ResultError::FieldOutOfBounds));

    let mut minimal = base;
    minimal.result_id = minimal_nonzero();
    minimal.fork_id = minimal_nonzero();
    minimal.checkpoints[0].checkpoint_digest = minimal_nonzero();
    for digest in [
        &mut minimal.plan_digest,
        &mut minimal.suffix_digest,
        &mut minimal.dependency_root,
        &mut minimal.provenance_root,
        &mut minimal.execution_profile_digest,
        &mut minimal.trust_policy_snapshot_digest,
        &mut minimal.evaluator_identity_digest,
    ] {
        *digest = minimal_nonzero();
    }
    if let Some(error) = minimal.terminal_error.as_mut() {
        error.safe_digest = Some(minimal_nonzero());
    }
    let minimal = sealed(minimal)?;
    minimal.validate()?;
    assert_eq!(decoded(&minimal.to_canonical_cbor()?)?, minimal);
    Ok(())
}

#[test]
fn range_bounds_are_enforced_at_each_edge() -> TestResult {
    let base = completed()?;
    let cases: [(Edit, Result<(), ResultError>); 7] = [
        (
            |result| result.fork_generation = 0,
            Err(ResultError::FieldOutOfBounds),
        ),
        (
            |result| {
                result.first_tick = 13;
                result.committed_through_tick = None;
                result.checkpoints.clear();
                result.terminal_state = TerminalState::SafeStopped;
                result.replay_claim = ReplayClaimV1::StructuralOnly;
            },
            Err(ResultError::FieldOutOfBounds),
        ),
        (
            |result| {
                result.first_tick = 12;
                result.checkpoints = vec![checkpoint(12, 0x41)];
            },
            Ok(()),
        ),
        (
            |result| result.committed_through_tick = Some(13),
            Err(ResultError::FieldOutOfBounds),
        ),
        (
            |result| {
                result.committed_through_tick = Some(9);
                result.checkpoints.clear();
                result.terminal_state = TerminalState::SafeStopped;
                result.replay_claim = ReplayClaimV1::StructuralOnly;
            },
            Err(ResultError::FieldOutOfBounds),
        ),
        (
            |result| {
                result.committed_through_tick = Some(10);
                result.checkpoints = vec![checkpoint(10, 0x40)];
                result.terminal_state = TerminalState::SafeStopped;
                result.replay_claim = ReplayClaimV1::StructuralOnly;
            },
            Ok(()),
        ),
        (
            |result| {
                result.first_tick = u64::MAX;
                result.horizon_tick = u64::MAX;
                result.committed_through_tick = Some(u64::MAX);
                result.checkpoints = vec![checkpoint(u64::MAX, 0x41)];
            },
            Ok(()),
        ),
    ];
    for (edit, expected) in cases {
        assert_eq!(resealed_validation(&base, edit), expected);
    }
    Ok(())
}

#[test]
fn checkpoints_are_bounded_ordered_unique_and_single_generation() -> TestResult {
    let base = completed()?;
    let cases: [(Edit, ResultError); 7] = [
        (
            |result| result.checkpoints.insert(0, checkpoint(9, 0x3f)),
            ResultError::FieldOutOfBounds,
        ),
        (
            |result| {
                result.committed_through_tick = Some(11);
                result.terminal_state = TerminalState::SafeStopped;
                result.replay_claim = ReplayClaimV1::StructuralOnly;
            },
            ResultError::FieldOutOfBounds,
        ),
        (
            |result| {
                result.committed_through_tick = None;
                result.checkpoints = vec![checkpoint(10, 0x40)];
                result.terminal_state = TerminalState::SafeStopped;
                result.replay_claim = ReplayClaimV1::StructuralOnly;
            },
            ResultError::FieldOutOfBounds,
        ),
        (
            |result| result.checkpoints[0].fork_generation = GENERATION + 1,
            ResultError::MixedForkGeneration,
        ),
        (
            |result| result.checkpoints = vec![checkpoint(12, 0x41), checkpoint(10, 0x40)],
            ResultError::NonCanonicalOrder,
        ),
        (
            |result| result.checkpoints = vec![checkpoint(12, 0x40), checkpoint(12, 0x41)],
            ResultError::NonCanonicalOrder,
        ),
        (
            |result| result.checkpoints = vec![checkpoint(10, 0x41), checkpoint(12, 0x41)],
            ResultError::DuplicateIdentity,
        ),
    ];
    for (edit, expected) in cases {
        assert_eq!(resealed_validation(&base, edit), Err(expected));
    }
    Ok(())
}

fn maximum_checkpoints() -> Result<CounterfactualResultV1, ResultError> {
    let mut result = completed()?;
    let last_tick = u64::try_from(MAX_COUNTERFACTUAL_RESULT_CHECKPOINTS_V1).unwrap_or(0) - 1;
    result.first_tick = 0;
    result.horizon_tick = last_tick;
    result.committed_through_tick = Some(last_tick);
    result.checkpoints = (0..=u32::try_from(last_tick).unwrap_or(0))
        .map(|index| CheckpointRef {
            tick: u64::from(index),
            fork_generation: GENERATION,
            checkpoint_digest: digest_from(index),
        })
        .collect();
    sealed(result)
}

#[test]
fn checkpoint_list_accepts_exactly_its_bound() -> TestResult {
    let result = maximum_checkpoints()?;
    assert_eq!(result.checkpoints.len(), 65_536);
    let bytes = result.to_canonical_cbor()?;
    assert!(bytes.len() <= MAX_COUNTERFACTUAL_RESULT_BYTES_V1);
    assert_eq!(decoded(&bytes)?, result);

    let mut oversized = result;
    oversized.horizon_tick += 1;
    oversized.committed_through_tick = Some(oversized.horizon_tick);
    oversized.checkpoints.push(CheckpointRef {
        tick: oversized.horizon_tick,
        fork_generation: GENERATION,
        checkpoint_digest: [0xff; 32],
    });
    let oversized = sealed(oversized)?;
    assert_eq!(oversized.validate(), Err(ResultError::FieldOutOfBounds));

    let mut fields = fields_of(&bytes)?;
    if let Value::Array(checkpoints) = &mut fields[FIELD_CHECKPOINTS] {
        checkpoints.push(Value::Array(vec![
            uint(oversized.horizon_tick),
            uint(GENERATION),
            Value::Bytes(vec![0xff; 32]),
        ]));
    }
    let oversized_bytes = encode(&Value::Array(fields))?;
    assert_eq!(
        decoded(&oversized_bytes),
        Err(ResultError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn terminal_state_must_agree_with_range_error_and_checkpoints() -> TestResult {
    let complete = completed()?;
    let incomplete = failed()?;
    let cases: [(&CounterfactualResultV1, Edit); 9] = [
        (&complete, |result| {
            result.terminal_error = Some(terminal_error(ErrorCode::PluginFailure, 12));
        }),
        (&complete, |result| result.checkpoints.truncate(1)),
        (&complete, |result| result.checkpoints.clear()),
        (&incomplete, |result| {
            result.terminal_state = TerminalState::Completed;
            result.terminal_error = None;
        }),
        (&incomplete, |result| result.terminal_error = None),
        (&incomplete, |result| {
            result.terminal_error = Some(terminal_error(ErrorCode::PluginFailure, 11));
        }),
        (&incomplete, |result| {
            result.terminal_error = Some(terminal_error(ErrorCode::PluginFailure, 13));
        }),
        (&complete, |result| {
            result.terminal_state = TerminalState::Failed;
            result.terminal_error = Some(terminal_error(ErrorCode::PluginFailure, 13));
        }),
        (&incomplete, |result| {
            result.terminal_state = TerminalState::SafeStopped;
        }),
    ];
    for (base, edit) in cases {
        assert_eq!(
            resealed_validation(base, edit),
            Err(ResultError::InconsistentTerminalState)
        );
    }
    assert_eq!(
        resealed_validation(&complete, |result| {
            result.terminal_state = TerminalState::SafeStopped;
        }),
        Err(ResultError::InconsistentTerminalState)
    );
    assert_eq!(
        resealed_validation(&incomplete, |result| {
            result.committed_through_tick = None;
            result.checkpoints.clear();
            result.terminal_error = Some(terminal_error(ErrorCode::PluginFailure, 11));
        }),
        Err(ResultError::InconsistentTerminalState)
    );
    Ok(())
}

#[test]
fn incomplete_suffixes_cannot_claim_exact_success() -> TestResult {
    let incomplete = failed()?;
    for claim in [
        ReplayClaimV1::Exact,
        ReplayClaimV1::ExactAuthoritativeWithRedactedViews,
    ] {
        assert_eq!(
            resealed_validation(&incomplete, |result| result.replay_claim = claim),
            Err(ResultError::IncompleteSuffixClaim)
        );
    }
    for claim in [
        ReplayClaimV1::StructuralOnly,
        ReplayClaimV1::UnverifiableArtifactsMissing,
        ReplayClaimV1::IncompatibleProfile,
    ] {
        assert_eq!(
            resealed_validation(&incomplete, |result| result.replay_claim = claim),
            Ok(())
        );
    }
    assert_eq!(
        resealed_validation(&completed()?, |result| {
            result.replay_claim = ReplayClaimV1::ExactAuthoritativeWithRedactedViews;
        }),
        Ok(())
    );
    Ok(())
}

#[test]
fn decoder_enforces_size_limit_before_parsing() {
    let at_limit = vec![0; MAX_COUNTERFACTUAL_RESULT_BYTES_V1];
    assert_eq!(decoded(&at_limit), Err(ResultError::InvalidEncoding));
    let over_limit = vec![0; MAX_COUNTERFACTUAL_RESULT_BYTES_V1 + 1];
    assert_eq!(decoded(&over_limit), Err(ResultError::FieldOutOfBounds));
}

#[test]
fn decoder_rejects_closed_schema_and_malformed_cbor_forms() -> TestResult {
    let valid = completed()?.to_canonical_cbor()?;
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut short = fields_of(&valid)?;
    short.pop();
    let mut long = fields_of(&valid)?;
    long.push(Value::Null);
    let mut future_magic = short.clone();
    future_magic[0] = Value::Text("CFR2".to_owned());
    let mut future_version = short.clone();
    future_version[1] = uint(2);
    // Field 5 (fork generation 2) re-encoded with a one-byte length prefix.
    let generation_offset = 1 + 5 + 1 + 17 + 34 + 17;
    assert_eq!(valid[generation_offset], 0x02);
    let noncanonical = [
        &valid[..generation_offset],
        &[0x18_u8, 0x02][..],
        &valid[generation_offset + 1..],
    ]
    .concat();
    let mut invalid_utf8 = valid.clone();
    invalid_utf8[2..6].copy_from_slice(&[0xff; 4]);
    for (bytes, expected) in [
        (trailing, ResultError::InvalidEncoding),
        (encode(&Value::Array(short))?, ResultError::InvalidEncoding),
        (
            encode(&Value::Array(future_magic))?,
            ResultError::UnsupportedVersion,
        ),
        (
            encode(&Value::Array(future_version))?,
            ResultError::UnsupportedVersion,
        ),
        (encode(&Value::Array(long))?, ResultError::InvalidEncoding),
        (noncanonical, ResultError::InvalidEncoding),
        (invalid_utf8, ResultError::InvalidEncoding),
        (vec![0xa0], ResultError::InvalidEncoding),
        (vec![0xf9, 0x3c, 0x00], ResultError::InvalidEncoding),
        (
            with_field(&valid, 0, Value::Text("CFR2".to_owned()))?,
            ResultError::UnsupportedVersion,
        ),
        (
            with_field(&valid, 0, Value::Bytes(b"CFR1".to_vec()))?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(&valid, 1, uint(2))?,
            ResultError::UnsupportedVersion,
        ),
        (
            with_field(
                &valid,
                FIELD_CHECKPOINTS,
                Value::Array(vec![Value::Array(vec![
                    Value::Array(vec![uint(10)]),
                    uint(GENERATION),
                    Value::Bytes(vec![0x40; 32]),
                ])]),
            )?,
            ResultError::FieldOutOfBounds,
        ),
    ] {
        assert_eq!(decoded(&bytes), Err(expected));
    }
    Ok(())
}

#[test]
fn decoder_rejects_malformed_field_types() -> TestResult {
    let valid = completed()?.to_canonical_cbor()?;
    let failed_bytes = failed()?.to_canonical_cbor()?;
    let bad_error =
        |fields: Vec<Value>| with_field(&failed_bytes, FIELD_TERMINAL_ERROR, Value::Array(fields));
    for (bytes, expected) in [
        (
            with_field(&valid, 2, Value::Text("id".to_owned()))?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(&valid, 2, Value::Bytes(vec![1; 15]))?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(&valid, 5, Value::Bytes(vec![2]))?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(&valid, 5, Value::Integer((-1).into()))?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(&valid, 8, Value::Bool(true))?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_CHECKPOINTS, uint(0))?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(
                &valid,
                FIELD_CHECKPOINTS,
                Value::Array(vec![Value::Array(vec![uint(10), uint(GENERATION)])]),
            )?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_TERMINAL_ERROR, uint(0))?,
            ResultError::InvalidEncoding,
        ),
        (
            bad_error(vec![uint(21), uint(12), uint(7)])?,
            ResultError::InvalidEncoding,
        ),
        (
            bad_error(vec![uint(21), uint(12), uint(1 << 32), Value::Null])?,
            ResultError::FieldOutOfBounds,
        ),
        (
            bad_error(vec![uint(21), uint(12), uint(7), Value::Bytes(vec![0; 31])])?,
            ResultError::InvalidEncoding,
        ),
        (
            with_field(&valid, FIELD_RESULT_DIGEST, Value::Null)?,
            ResultError::InvalidEncoding,
        ),
    ] {
        assert_eq!(decoded(&bytes), Err(expected));
    }
    Ok(())
}

#[test]
fn invalid_records_are_never_encoded() -> TestResult {
    let mut result = completed()?;
    result.fork_generation = 0;
    assert_eq!(
        sealed(result)?.to_canonical_cbor(),
        Err(ResultError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn every_contract_error_has_a_distinct_public_message() {
    let messages = [
        (
            ResultError::InvalidEncoding,
            "invalid CFR1 counterfactual result encoding",
        ),
        (
            ResultError::UnsupportedVersion,
            "unsupported CFR1 counterfactual result version",
        ),
        (
            ResultError::FieldOutOfBounds,
            "CFR1 counterfactual result field is out of bounds",
        ),
        (
            ResultError::UnknownEnum,
            "CFR1 counterfactual result enum code is unknown",
        ),
        (
            ResultError::NonCanonicalOrder,
            "CFR1 counterfactual result checkpoints are not canonical",
        ),
        (
            ResultError::DuplicateIdentity,
            "CFR1 counterfactual result checkpoint is duplicated",
        ),
        (
            ResultError::MixedForkGeneration,
            "CFR1 counterfactual result mixes Fork generations",
        ),
        (
            ResultError::InconsistentTerminalState,
            "CFR1 counterfactual result terminal state is inconsistent",
        ),
        (
            ResultError::IncompleteSuffixClaim,
            "CFR1 counterfactual result claims exact success for an incomplete suffix",
        ),
        (
            ResultError::DigestMismatch,
            "CFR1 counterfactual result digest does not match",
        ),
    ];
    for (error, message) in messages {
        assert_eq!(error.to_string(), message);
    }
}
