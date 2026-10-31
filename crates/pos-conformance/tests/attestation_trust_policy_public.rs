#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! ADR-062 Revision 8 slice G2 (#1237): the CTP1 `ConformanceTrustPolicyV1` codec and the CTP1
//! implementation of `ConformanceTrustAdmissionPortV1`, through their public seams.
//!
//! The file name places this suite next to the report attestation suite, before the slow
//! `bundle_contract_*` suites in `cargo test`'s alphabetical order.

use ciborium::value::Value;
use ed25519_dalek::{Signer as _, SigningKey};
use pos_conformance::{
    conformance_revoked_key_id_v1, draft_trust_policy_snapshot_bytes_v1,
    ConformanceArtifactRefusalV1, ConformanceKeyRefusalV1,
    ConformanceTrustAdmissionErrorV1 as AdmissionError, ConformanceTrustAdmissionPortV1,
    ConformanceTrustAdmissionV1, ConformanceTrustAnchorV1,
    ConformanceTrustPolicyContractErrorV1 as PolicyError, ConformanceTrustPolicyV1,
    ConformanceTrustRoleV1, TrustPolicySnapshotContractErrorV1, TrustPolicySnapshotV1,
    CONFORMANCE_REVOKED_KEY_ID_PREFIX_V1, CONFORMANCE_TRUST_POLICY_MAGIC_V1,
    MAX_CONFORMANCE_TRUST_POLICY_BYTES_V1, MAX_CONFORMANCE_TRUST_REVOCATIONS_V1,
    MAX_CONFORMANCE_TRUST_ROOTS_V1,
};
use pos_crypto::dsse::key_id_v1;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One edit of a policy's lists, given a low and a high root.
type Reorder = fn(&mut ConformanceTrustPolicyV1, [u8; 32], [u8; 32]);

/// One edit of a policy.
type Edit = Box<dyn Fn(&mut ConformanceTrustPolicyV1)>;

fn boxed(edit: impl Fn(&mut ConformanceTrustPolicyV1) + 'static) -> Edit {
    Box::new(edit)
}

/// 2027-01-15T08:00:00Z.
const NOW: i64 = 1_800_000_000;
/// One second after [`NOW`].
const VALID_THROUGH: &str = "2027-01-15T08:00:01Z";
const DOMAIN: &[u8] = b"PiglorOS.CTP1.operator-signature.v1\0";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> [u8; 32] {
    key(seed).verifying_key().to_bytes()
}

fn key_id(seed: u8) -> [u8; 32] {
    key_id_v1(&key(seed).verifying_key())
}

fn operator() -> SigningKey {
    key(200)
}

fn operator_key() -> [u8; 32] {
    operator().verifying_key().to_bytes()
}

fn snapshot() -> TestResult<Vec<u8>> {
    Ok(draft_trust_policy_snapshot_bytes_v1()?)
}

const EVALUATOR: u8 = 1;
const REPORTER: u8 = 2;
const STRANGER: u8 = 3;

/// An unsigned epoch-1 policy over the draft TPS1 with one root per role.
fn base() -> TestResult<ConformanceTrustPolicyV1> {
    Ok(ConformanceTrustPolicyV1 {
        policy_id: "conformance-trust".to_owned(),
        epoch: 1,
        previous_policy_digest: None,
        trust_policy_snapshot_digest: *blake3::hash(&snapshot()?).as_bytes(),
        evaluator_release_roots: vec![public(EVALUATOR)],
        report_signing_roots: vec![public(REPORTER)],
        revoked_key_ids: Vec::new(),
        revoked_evaluator_binary_digests: Vec::new(),
        revoked_report_digests: Vec::new(),
        minimum_evaluator_protocol_version: "1.0.0".to_owned(),
        offline_valid_through: VALID_THROUGH.to_owned(),
        operator_signature: [0; 64],
    })
}

fn signed(mut policy: ConformanceTrustPolicyV1) -> TestResult<ConformanceTrustPolicyV1> {
    policy.operator_signature = operator()
        .sign(&policy.operator_signature_message_v1()?)
        .to_bytes();
    Ok(policy)
}

fn bytes(policy: ConformanceTrustPolicyV1) -> TestResult<Vec<u8>> {
    Ok(signed(policy)?.to_canonical_cbor()?)
}

fn with(edit: impl FnOnce(&mut ConformanceTrustPolicyV1)) -> TestResult<Vec<u8>> {
    let mut policy = base()?;
    edit(&mut policy);
    bytes(policy)
}

/// The successor of `previous` at `epoch`, linked to its exact bytes, after `edit`.
fn successor(
    previous: &[u8],
    epoch: u64,
    edit: impl FnOnce(&mut ConformanceTrustPolicyV1),
) -> TestResult<Vec<u8>> {
    let mut policy = ConformanceTrustPolicyV1::from_canonical_cbor(previous)?;
    policy.epoch = epoch;
    policy.previous_policy_digest = Some(*blake3::hash(previous).as_bytes());
    edit(&mut policy);
    bytes(policy)
}

/// The high-water mark pinning the policy with these exact bytes.
fn pinned(bytes: &[u8]) -> TestResult<ConformanceTrustAnchorV1> {
    Ok(ConformanceTrustAnchorV1 {
        epoch: decoded(bytes)?.epoch,
        policy_digest: *blake3::hash(bytes).as_bytes(),
    })
}

/// A mark no chain contains, for chains that fail before the mark is examined.
const UNUSED_MARK: ConformanceTrustAnchorV1 = ConformanceTrustAnchorV1 {
    epoch: 1,
    policy_digest: [0; 32],
};

/// The admission of `chain` over the TPS1 bytes `tps1`, pinned at `anchor`.
fn load_with(
    chain: &[&[u8]],
    tps1: &[u8],
    anchor: ConformanceTrustAnchorV1,
    now: i64,
) -> Result<ConformanceTrustAdmissionV1, AdmissionError> {
    ConformanceTrustAdmissionV1::from_chain_v1(chain, tps1, &operator_key(), anchor, now)
}

/// The admission of `chain` over the draft TPS1, pinned at its oldest policy.
fn load(
    chain: &[&[u8]],
    now: i64,
) -> TestResult<Result<ConformanceTrustAdmissionV1, AdmissionError>> {
    let anchor = chain
        .first()
        .map_or(UNUSED_MARK, |oldest| pinned(oldest).unwrap_or(UNUSED_MARK));
    Ok(load_with(chain, &snapshot()?, anchor, now))
}

/// The draft TPS1 after `edit`, re-encoded (its operator signature is not checked here).
fn snapshot_with(edit: impl FnOnce(&mut TrustPolicySnapshotV1)) -> TestResult<Vec<u8>> {
    let mut snapshot = TrustPolicySnapshotV1::from_canonical_cbor(&snapshot()?)?;
    edit(&mut snapshot);
    Ok(snapshot.to_canonical_cbor()?)
}

fn admit(
    trust: &ConformanceTrustAdmissionV1,
    role: ConformanceTrustRoleV1,
    seed: u8,
) -> Result<[u8; 32], ConformanceKeyRefusalV1> {
    trust
        .admit_key(role, &key_id(seed))
        .map(|key| key.to_bytes())
}

/// Decode canonical bytes as a CBOR value, for mutation.
fn value(bytes: &[u8]) -> TestResult<Value> {
    Ok(ciborium::from_reader(bytes)?)
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

fn fields(bytes: &[u8]) -> TestResult<Vec<Value>> {
    match value(bytes)? {
        Value::Array(fields) => Ok(fields),
        _ => Err("CTP1 is an array".into()),
    }
}

fn decoded(bytes: &[u8]) -> Result<ConformanceTrustPolicyV1, PolicyError> {
    ConformanceTrustPolicyV1::from_canonical_cbor(bytes)
}

#[test]
fn ctp1_round_trips_its_exact_canonical_bytes() -> TestResult {
    let mut policy = base()?;
    policy.previous_policy_digest = Some([0x44; 32]);
    policy.revoked_key_ids = vec![[1; 32], [2; 32]];
    policy.revoked_evaluator_binary_digests = vec![[3; 32]];
    policy.revoked_report_digests = vec![[4; 32]];
    let policy = signed(policy)?;
    // The record built independently with ciborium, field by field.
    let digest = |value: [u8; 32]| Value::Bytes(value.to_vec());
    let list = |values: &[[u8; 32]]| Value::Array(values.iter().copied().map(digest).collect());
    let unsigned = vec![
        Value::Text("CTP1".to_owned()),
        Value::Integer(1.into()),
        Value::Text("conformance-trust".to_owned()),
        Value::Integer(1.into()),
        digest([0x44; 32]),
        digest(*blake3::hash(&snapshot()?).as_bytes()),
        list(&[public(EVALUATOR)]),
        list(&[public(REPORTER)]),
        list(&[[1; 32], [2; 32]]),
        list(&[[3; 32]]),
        list(&[[4; 32]]),
        Value::Text("1.0.0".to_owned()),
        Value::Text(VALID_THROUGH.to_owned()),
    ];
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(&encode(&Value::Array(unsigned.clone()))?);
    assert_eq!(policy.operator_signature_message_v1()?, message);
    let mut golden = unsigned;
    golden.push(Value::Bytes(operator().sign(&message).to_bytes().to_vec()));
    let golden = encode(&Value::Array(golden))?;

    assert_eq!(policy.to_canonical_cbor()?, golden);
    assert_eq!(decoded(&golden)?, policy);
    assert_eq!(CONFORMANCE_TRUST_POLICY_MAGIC_V1, "CTP1");
    assert_eq!(
        policy.roots(ConformanceTrustRoleV1::EvaluatorRelease),
        &[public(EVALUATOR)]
    );
    assert_eq!(
        policy.roots(ConformanceTrustRoleV1::ReportSigning),
        &[public(REPORTER)]
    );
    assert!(policy.has_operator_signature(&operator().verifying_key()));
    assert!(!policy.has_operator_signature(&key(STRANGER).verifying_key()));

    // A record without a predecessor and with empty lists round-trips too.
    let mut empty = base()?;
    empty.evaluator_release_roots.clear();
    empty.report_signing_roots.clear();
    let empty = bytes(empty)?;
    assert_eq!(fields(&empty)?[4], Value::Null);
    assert_eq!(decoded(&empty)?.to_canonical_cbor()?, empty);
    Ok(())
}

#[test]
fn every_integer_width_is_encoded_in_its_shortest_form() -> TestResult {
    for epoch in [
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        let policy = with(|policy| policy.epoch = epoch)?;
        assert_eq!(fields(&policy)?[3], Value::Integer(epoch.into()), "{epoch}");
        // ciborium re-encodes every head in its shortest form.
        assert_eq!(encode(&value(&policy)?)?, policy, "{epoch}");
        assert_eq!(decoded(&policy)?.epoch, epoch);
    }
    Ok(())
}

#[test]
fn unknown_trailing_missing_map_tag_float_and_indefinite_encodings_are_refused() -> TestResult {
    let canonical = with(|_| {})?;
    let original = fields(&canonical)?;
    let rebuilt = |edit: &dyn Fn(&mut Vec<Value>)| -> TestResult<Vec<u8>> {
        let mut fields = original.clone();
        edit(&mut fields);
        encode(&Value::Array(fields))
    };

    let mut trailing = canonical.clone();
    trailing.push(0);
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&canonical[1..]);
    indefinite.push(0xff);
    // The version 1 written with a one-byte argument instead of inline.
    let mut non_minimal = canonical[..1].to_vec();
    non_minimal.extend_from_slice(&encode(&original[0])?);
    non_minimal.extend_from_slice(&[0x18, 0x01]);
    for field in &original[2..] {
        non_minimal.extend_from_slice(&encode(field)?);
    }
    // Invalid UTF-8 in the policy id: the CBOR item is structurally intact.
    let mut invalid_text = canonical;
    let id_at = invalid_text
        .windows(b"conformance-trust".len())
        .position(|window| window == b"conformance-trust")
        .ok_or("policy id")?;
    invalid_text[id_at] = 0xff;

    let cases: Vec<(&str, Vec<u8>, PolicyError)> = vec![
        ("empty", Vec::new(), PolicyError::InvalidEncoding),
        ("trailing byte", trailing, PolicyError::InvalidEncoding),
        ("indefinite array", indefinite, PolicyError::InvalidEncoding),
        (
            "non-minimal integer",
            non_minimal,
            PolicyError::InvalidEncoding,
        ),
        ("invalid UTF-8", invalid_text, PolicyError::InvalidEncoding),
        (
            "missing field",
            rebuilt(&|fields| {
                fields.pop();
            })?,
            PolicyError::InvalidEncoding,
        ),
        (
            "unknown extra field",
            rebuilt(&|fields| fields.push(Value::Null))?,
            PolicyError::InvalidEncoding,
        ),
        (
            "map record",
            encode(&Value::Map(vec![(Value::Integer(0.into()), Value::Null)]))?,
            PolicyError::InvalidEncoding,
        ),
        (
            "tagged field",
            rebuilt(&|fields| fields[3] = Value::Tag(1, Box::new(Value::Integer(1.into()))))?,
            PolicyError::InvalidEncoding,
        ),
        (
            "float field",
            rebuilt(&|fields| fields[3] = Value::Float(1.0))?,
            PolicyError::InvalidEncoding,
        ),
        (
            "unknown magic",
            rebuilt(&|fields| fields[0] = Value::Text("CTP2".to_owned()))?,
            PolicyError::UnsupportedSchemaVersion,
        ),
        (
            "unknown version",
            rebuilt(&|fields| fields[1] = Value::Integer(2.into()))?,
            PolicyError::UnsupportedSchemaVersion,
        ),
        (
            "nested too deep",
            rebuilt(&|fields| {
                fields[6] = Value::Array(vec![Value::Array(vec![Value::Array(Vec::new())])]);
            })?,
            PolicyError::FieldOutOfBounds,
        ),
        (
            "too many list items",
            rebuilt(&|fields| {
                fields[8] =
                    Value::Array(vec![Value::Null; MAX_CONFORMANCE_TRUST_REVOCATIONS_V1 + 2]);
            })?,
            PolicyError::FieldOutOfBounds,
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(decoded(&bytes), Err(expected), "{name}");
    }
    Ok(())
}

#[test]
fn every_field_of_the_wrong_type_is_refused() -> TestResult {
    let original = fields(&with(|_| {})?)?;
    let digest = Value::Bytes(vec![0; 32]);
    // For each field: a value of another CBOR type, and one more wrong value of a close type.
    let wrong: [(usize, Vec<Value>); 14] = [
        (0, vec![Value::Integer(0.into())]),
        (
            1,
            vec![Value::Text("1".to_owned()), Value::Integer((-1).into())],
        ),
        (2, vec![digest.clone()]),
        (3, vec![Value::Null, Value::Integer((-1).into())]),
        (4, vec![Value::Bool(false), Value::Bytes(vec![0; 31])]),
        (5, vec![Value::Null, Value::Bytes(vec![0; 33])]),
        (
            6,
            vec![digest, Value::Array(vec![Value::Bytes(vec![0; 31])])],
        ),
        (7, vec![Value::Null, Value::Array(vec![Value::Null])]),
        (8, vec![Value::Text(String::new())]),
        (9, vec![Value::Bool(true)]),
        (10, vec![Value::Integer(0.into())]),
        (11, vec![Value::Integer(1.into())]),
        (12, vec![Value::Null]),
        (13, vec![Value::Bytes(vec![0; 63]), Value::Null]),
    ];
    for (index, values) in wrong {
        for replacement in values {
            let mut fields = original.clone();
            fields[index] = replacement;
            assert_eq!(
                decoded(&encode(&Value::Array(fields))?),
                Err(PolicyError::InvalidEncoding),
                "field {index}"
            );
        }
    }
    // A record that is not an array at all.
    assert_eq!(
        decoded(&encode(&Value::Text("CTP1".to_owned()))?),
        Err(PolicyError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn oversized_input_is_refused_before_parsing() {
    assert_eq!(
        decoded(&vec![0xff; MAX_CONFORMANCE_TRUST_POLICY_BYTES_V1 + 1]),
        Err(PolicyError::FieldOutOfBounds)
    );
    // Exactly at the bound: parsed, and refused as malformed rather than oversized.
    assert_eq!(
        decoded(&vec![0xff; MAX_CONFORMANCE_TRUST_POLICY_BYTES_V1]),
        Err(PolicyError::InvalidEncoding)
    );
}

#[test]
fn root_and_revocation_lists_must_be_strictly_sorted() -> TestResult {
    let mut roots = [public(10), public(11)];
    roots.sort_unstable();
    let [low, high] = roots;
    let unsorted: [(&str, Reorder); 10] = [
        ("evaluator roots descending", |p, low, high| {
            p.evaluator_release_roots = vec![high, low];
        }),
        ("evaluator roots duplicate", |p, low, _| {
            p.evaluator_release_roots = vec![low, low];
        }),
        ("report roots descending", |p, low, high| {
            p.report_signing_roots = vec![high, low];
        }),
        ("report roots duplicate", |p, _, high| {
            p.report_signing_roots = vec![high, high];
        }),
        ("revoked keys descending", |p, _, _| {
            p.revoked_key_ids = vec![[2; 32], [1; 32]];
        }),
        ("revoked keys duplicate", |p, _, _| {
            p.revoked_key_ids = vec![[1; 32], [1; 32]];
        }),
        ("revoked binaries descending", |p, _, _| {
            p.revoked_evaluator_binary_digests = vec![[2; 32], [1; 32]];
        }),
        ("revoked binaries duplicate", |p, _, _| {
            p.revoked_evaluator_binary_digests = vec![[1; 32], [1; 32]];
        }),
        ("revoked reports descending", |p, _, _| {
            p.revoked_report_digests = vec![[2; 32], [1; 32]];
        }),
        ("revoked reports duplicate", |p, _, _| {
            p.revoked_report_digests = vec![[1; 32], [1; 32]];
        }),
    ];
    for (name, edit) in unsorted {
        let mut policy = base()?;
        edit(&mut policy, low, high);
        assert_eq!(
            policy.validate(),
            Err(PolicyError::NonCanonicalOrder),
            "{name}"
        );
        assert_eq!(
            policy.to_canonical_cbor(),
            Err(PolicyError::NonCanonicalOrder),
            "{name}"
        );
        assert_eq!(
            policy.operator_signature_message_v1(),
            Err(PolicyError::NonCanonicalOrder),
            "{name}"
        );
        // The same record on the wire.
        let mut wire = fields(&with(|_| {})?)?;
        let list = |values: &[[u8; 32]]| {
            Value::Array(
                values
                    .iter()
                    .map(|value| Value::Bytes(value.to_vec()))
                    .collect(),
            )
        };
        wire[6] = list(&policy.evaluator_release_roots);
        wire[7] = list(&policy.report_signing_roots);
        wire[8] = list(&policy.revoked_key_ids);
        wire[9] = list(&policy.revoked_evaluator_binary_digests);
        wire[10] = list(&policy.revoked_report_digests);
        assert_eq!(
            decoded(&encode(&Value::Array(wire))?),
            Err(PolicyError::NonCanonicalOrder),
            "{name}"
        );
    }
    // Ascending lists are accepted.
    let sorted = with(|policy| {
        policy.evaluator_release_roots = vec![low, high];
        policy.report_signing_roots = vec![public(REPORTER)];
        policy.revoked_key_ids = vec![[1; 32], [2; 32]];
    })?;
    assert_eq!(decoded(&sorted)?.evaluator_release_roots, vec![low, high]);
    Ok(())
}

#[test]
fn a_key_cannot_be_a_root_of_both_roles() -> TestResult {
    let mut policy = base()?;
    policy.evaluator_release_roots = vec![public(REPORTER)];
    assert_eq!(policy.validate(), Err(PolicyError::RootRoleConflict));
    let mut wire = fields(&with(|_| {})?)?;
    wire[6] = wire[7].clone();
    assert_eq!(
        decoded(&encode(&Value::Array(wire))?),
        Err(PolicyError::RootRoleConflict)
    );
    // A shared key among other roots of each role is still a conflict.
    let mut roots = [public(EVALUATOR), public(REPORTER), public(STRANGER)];
    roots.sort_unstable();
    let mut policy = base()?;
    policy.evaluator_release_roots = vec![roots[0], roots[1]];
    policy.report_signing_roots = vec![roots[1], roots[2]];
    assert_eq!(policy.validate(), Err(PolicyError::RootRoleConflict));
    Ok(())
}

/// `count` distinct valid roots in ascending order.
fn roots(count: usize) -> Vec<[u8; 32]> {
    let mut roots: Vec<[u8; 32]> = (50..=u8::MAX).take(count).map(public).collect();
    roots.sort_unstable();
    roots
}

/// `count` distinct digests in ascending order.
fn revocations(count: usize) -> Vec<[u8; 32]> {
    (0_u64..)
        .take(count)
        .map(|index| {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&index.to_be_bytes());
            digest
        })
        .collect()
}

const fn off_curve() -> [u8; 32] {
    let mut key = [0; 32];
    key[0] = 2;
    key
}

const OVER_ROOTS: usize = MAX_CONFORMANCE_TRUST_ROOTS_V1 + 1;
const OVER_REVOCATIONS: usize = MAX_CONFORMANCE_TRUST_REVOCATIONS_V1 + 1;

#[test]
fn every_out_of_bounds_field_is_refused() -> TestResult {
    let out_of_bounds: Vec<(&str, Edit)> = vec![
        ("empty policy id", boxed(|p| p.policy_id = String::new())),
        (
            "uppercase policy id",
            boxed(|p| p.policy_id = "Conformance".to_owned()),
        ),
        ("long policy id", boxed(|p| p.policy_id = "a".repeat(129))),
        ("epoch zero", boxed(|p| p.epoch = 0)),
        (
            "too many evaluator roots",
            boxed(|p| {
                p.evaluator_release_roots = roots(OVER_ROOTS);
                p.report_signing_roots.clear();
            }),
        ),
        (
            "too many report roots",
            boxed(|p| {
                p.report_signing_roots = roots(OVER_ROOTS);
                p.evaluator_release_roots.clear();
            }),
        ),
        (
            "too many revoked keys",
            boxed(|p| p.revoked_key_ids = revocations(OVER_REVOCATIONS)),
        ),
        (
            "too many revoked binaries",
            boxed(|p| p.revoked_evaluator_binary_digests = revocations(OVER_REVOCATIONS)),
        ),
        (
            "too many revoked reports",
            boxed(|p| p.revoked_report_digests = revocations(OVER_REVOCATIONS)),
        ),
        (
            "evaluator root off curve",
            boxed(|p| p.evaluator_release_roots = vec![off_curve()]),
        ),
        (
            "report root off curve",
            boxed(|p| p.report_signing_roots = vec![off_curve()]),
        ),
        (
            "empty minimum version",
            boxed(|p| p.minimum_evaluator_protocol_version.clear()),
        ),
        (
            "two-part minimum version",
            boxed(|p| p.minimum_evaluator_protocol_version = "1.0".to_owned()),
        ),
        (
            "long minimum version",
            boxed(|p| p.minimum_evaluator_protocol_version = format!("1.0.0-{}", "a".repeat(59))),
        ),
        (
            "offset time",
            boxed(|p| p.offline_valid_through = "2027-01-15T08:00:01+00:00".to_owned()),
        ),
        (
            "impossible date",
            boxed(|p| p.offline_valid_through = "2027-02-30T00:00:00Z".to_owned()),
        ),
    ];
    for (name, edit) in out_of_bounds {
        let mut policy = base()?;
        edit(&mut policy);
        assert_eq!(
            policy.validate(),
            Err(PolicyError::FieldOutOfBounds),
            "{name}"
        );
        assert_eq!(
            policy.to_canonical_cbor(),
            Err(PolicyError::FieldOutOfBounds),
            "{name}"
        );
    }
    Ok(())
}

#[test]
fn a_record_exactly_at_every_limit_is_valid() -> TestResult {
    let at_limit = with(|policy| {
        policy.policy_id = "a".repeat(128);
        policy.evaluator_release_roots = roots(MAX_CONFORMANCE_TRUST_ROOTS_V1);
        policy.report_signing_roots = vec![public(REPORTER)];
        policy.revoked_key_ids = revocations(MAX_CONFORMANCE_TRUST_REVOCATIONS_V1);
        policy.revoked_evaluator_binary_digests = revocations(MAX_CONFORMANCE_TRUST_REVOCATIONS_V1);
        policy.revoked_report_digests = revocations(MAX_CONFORMANCE_TRUST_REVOCATIONS_V1);
        policy.minimum_evaluator_protocol_version = format!("1.0.0-{}", "a".repeat(58));
    })?;
    // The 4096-entry list heads are in their shortest (two-byte) form.
    assert_eq!(encode(&value(&at_limit)?)?, at_limit);
    let policy = decoded(&at_limit)?;
    assert_eq!(
        policy.evaluator_release_roots.len(),
        MAX_CONFORMANCE_TRUST_ROOTS_V1
    );
    assert_eq!(
        policy.revoked_report_digests.len(),
        MAX_CONFORMANCE_TRUST_REVOCATIONS_V1
    );
    assert_eq!(policy.minimum_evaluator_protocol_version.len(), 64);
    assert_eq!(policy.policy_id.len(), 128);
    // One revocation over the limit on the wire is refused by the decoder too.
    let mut wire = fields(&at_limit)?;
    wire[9] = Value::Array(
        revocations(OVER_REVOCATIONS)
            .into_iter()
            .map(|digest| Value::Bytes(digest.to_vec()))
            .collect(),
    );
    assert_eq!(
        decoded(&encode(&Value::Array(wire))?),
        Err(PolicyError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn a_standing_policy_admits_each_role_only_its_own_roots() -> TestResult {
    let trust = load(&[&with(|_| {})?], NOW)??;
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::EvaluatorRelease, EVALUATOR),
        Ok(public(EVALUATOR))
    );
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
        Ok(public(REPORTER))
    );
    // An evaluator key used for a report, and the reverse.
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::ReportSigning, EVALUATOR),
        Err(ConformanceKeyRefusalV1::RoleMismatch)
    );
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::EvaluatorRelease, REPORTER),
        Err(ConformanceKeyRefusalV1::RoleMismatch)
    );
    for role in [
        ConformanceTrustRoleV1::EvaluatorRelease,
        ConformanceTrustRoleV1::ReportSigning,
    ] {
        assert_eq!(
            admit(&trust, role, STRANGER),
            Err(ConformanceKeyRefusalV1::UnknownRoot)
        );
    }
    assert_eq!(trust.policy(), &decoded(&with(|_| {})?)?);
    Ok(())
}

#[test]
fn a_revoked_key_id_is_refused_for_every_role() -> TestResult {
    let mut revoked = [key_id(REPORTER), key_id(STRANGER)];
    revoked.sort_unstable();
    let trust = load(
        &[&with(|policy| policy.revoked_key_ids = revoked.to_vec())?],
        NOW,
    )??;
    for role in [
        ConformanceTrustRoleV1::EvaluatorRelease,
        ConformanceTrustRoleV1::ReportSigning,
    ] {
        assert_eq!(
            admit(&trust, role, REPORTER),
            Err(ConformanceKeyRefusalV1::Revoked)
        );
        assert_eq!(
            admit(&trust, role, STRANGER),
            Err(ConformanceKeyRefusalV1::Revoked)
        );
    }
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::EvaluatorRelease, EVALUATOR),
        Ok(public(EVALUATOR))
    );
    // A revoked public key (rather than its key id) revokes nothing.
    let trust = load(
        &[&with(|policy| {
            policy.revoked_key_ids = vec![public(REPORTER)];
        })?],
        NOW,
    )??;
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
        Ok(public(REPORTER))
    );
    Ok(())
}

#[test]
fn revoked_report_and_evaluator_binary_digests_are_refused() -> TestResult {
    let trust = load(
        &[&with(|policy| {
            policy.revoked_report_digests = vec![[0x10; 32], [0x11; 32]];
            policy.revoked_evaluator_binary_digests = vec![[0x20; 32], [0x21; 32]];
        })?],
        NOW,
    )??;
    for (report, binary, expected) in [
        (
            [0x10; 32],
            [0x00; 32],
            Err(ConformanceArtifactRefusalV1::RevokedReport),
        ),
        (
            [0x11; 32],
            [0x21; 32],
            Err(ConformanceArtifactRefusalV1::RevokedReport),
        ),
        (
            [0x00; 32],
            [0x20; 32],
            Err(ConformanceArtifactRefusalV1::RevokedEvaluatorBinary),
        ),
        (
            [0x00; 32],
            [0x21; 32],
            Err(ConformanceArtifactRefusalV1::RevokedEvaluatorBinary),
        ),
        // Each digest is looked up in its own list only.
        ([0x20; 32], [0x10; 32], Ok(())),
        ([0x00; 32], [0x00; 32], Ok(())),
    ] {
        assert_eq!(trust.check_artifact_revocation(&report, &binary), expected);
    }
    Ok(())
}

#[test]
fn a_chain_that_rolls_back_refuses_every_key() -> TestResult {
    let first = with(|policy| {
        policy.revoked_key_ids = vec![[0x30; 32]];
        policy.revoked_evaluator_binary_digests = vec![[0x31; 32]];
        policy.revoked_report_digests = vec![[0x32; 32]];
    })?;
    let second = successor(&first, 2, |_| {})?;
    let third = successor(&second, 5, |policy| {
        policy.revoked_report_digests = vec![[0x32; 32], [0x33; 32]];
    })?;
    // A strictly increasing, linked chain that keeps every revocation stands.
    for chain in [
        vec![&first[..]],
        vec![&first[..], &second[..]],
        vec![&first[..], &second[..], &third[..]],
    ] {
        let trust = load(&chain, NOW)??;
        assert_eq!(
            admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
            Ok(public(REPORTER))
        );
    }
    assert_eq!(load(&[&first, &second, &third], NOW)??.policy().epoch, 5);

    let rolled_back: Vec<(&str, Vec<u8>)> = vec![
        ("lower epoch", successor(&second, 1, |_| {})?),
        ("equal epoch", successor(&second, 2, |_| {})?),
        (
            "removed revoked key",
            successor(&second, 3, |p| p.revoked_key_ids.clear())?,
        ),
        (
            "removed revoked binary",
            successor(&second, 3, |p| {
                p.revoked_evaluator_binary_digests.clear();
            })?,
        ),
        (
            "removed revoked report",
            successor(&second, 3, |p| p.revoked_report_digests.clear())?,
        ),
        (
            "replaced revocation",
            successor(&second, 3, |p| p.revoked_key_ids = vec![[0x34; 32]])?,
        ),
        (
            "no previous link",
            successor(&second, 3, |p| p.previous_policy_digest = None)?,
        ),
        (
            "broken previous link",
            successor(&second, 3, |p| {
                p.previous_policy_digest = Some(*blake3::hash(&first).as_bytes());
            })?,
        ),
    ];
    for (name, next) in rolled_back {
        let trust = load(&[&first, &second, &next], NOW)??;
        for (role, seed) in [
            (ConformanceTrustRoleV1::ReportSigning, REPORTER),
            (ConformanceTrustRoleV1::EvaluatorRelease, EVALUATOR),
            (ConformanceTrustRoleV1::ReportSigning, STRANGER),
        ] {
            assert_eq!(
                admit(&trust, role, seed),
                Err(ConformanceKeyRefusalV1::RolledBack),
                "{name}"
            );
        }
    }
    // A rollback inside the chain, followed by a valid link, still refuses.
    let lower = successor(&second, 1, |_| {})?;
    let after = successor(&lower, 9, |_| {})?;
    let trust = load(&[&first, &second, &lower, &after], NOW)??;
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
        Err(ConformanceKeyRefusalV1::RolledBack)
    );
    // A rolled-back chain is refused as such even when it is also stale.
    let trust = load(&[&second, &first], NOW + 1)??;
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
        Err(ConformanceKeyRefusalV1::RolledBack)
    );
    Ok(())
}

#[test]
fn a_policy_past_offline_valid_through_is_stale() -> TestResult {
    let policy = with(|_| {})?;
    // One second before the bound the policy stands; at and after it, it is stale.
    let trust = load(&[&policy], NOW)??;
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
        Ok(public(REPORTER))
    );
    for now in [NOW + 1, NOW + 2, i64::MAX] {
        let trust = load(&[&policy], now)??;
        for (role, seed) in [
            (ConformanceTrustRoleV1::ReportSigning, REPORTER),
            (ConformanceTrustRoleV1::EvaluatorRelease, EVALUATOR),
        ] {
            assert_eq!(
                admit(&trust, role, seed),
                Err(ConformanceKeyRefusalV1::SnapshotStale),
                "{now}"
            );
        }
    }
    // Only the current policy's bound counts.
    let expired = with(|p| p.offline_valid_through = "2020-01-01T00:00:00Z".to_owned())?;
    let current = successor(&expired, 2, |p| {
        p.offline_valid_through = VALID_THROUGH.to_owned();
    })?;
    let trust = load(&[&expired, &current], NOW)??;
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
        Ok(public(REPORTER))
    );
    Ok(())
}

#[test]
fn a_chain_that_cannot_be_authenticated_or_bound_is_not_loaded() -> TestResult {
    let policy = with(|_| {})?;
    let snapshot = snapshot()?;
    let mut off_curve = [0; 32];
    off_curve[0] = 2;
    assert_eq!(
        ConformanceTrustAdmissionV1::from_chain_v1(
            &[&policy],
            &snapshot,
            &off_curve,
            pinned(&policy)?,
            NOW
        ),
        Err(AdmissionError::OperatorKey)
    );
    assert_eq!(
        ConformanceTrustAdmissionV1::from_chain_v1(
            &[&policy],
            &snapshot,
            &key(STRANGER).verifying_key().to_bytes(),
            pinned(&policy)?,
            NOW
        ),
        Err(AdmissionError::OperatorSignature)
    );
    // A signature over other content: the epoch changed after signing.
    let mut tampered = decoded(&policy)?;
    tampered.epoch = 2;
    assert_eq!(
        load(&[&tampered.to_canonical_cbor()?], NOW)?,
        Err(AdmissionError::OperatorSignature)
    );
    // An unauthenticated predecessor is refused like the current policy.
    let mut unsigned = base()?;
    unsigned.operator_signature = [1; 64];
    let unsigned = unsigned.to_canonical_cbor()?;
    assert_eq!(
        load(&[&unsigned, &successor(&unsigned, 2, |_| {})?], NOW)?,
        Err(AdmissionError::OperatorSignature)
    );
    let mut trailing = policy.clone();
    trailing.push(0);
    assert_eq!(
        load(&[&policy, &trailing], NOW)?,
        Err(AdmissionError::Policy(PolicyError::InvalidEncoding))
    );
    assert_eq!(load(&[], NOW)?, Err(AdmissionError::EmptyChain));
    assert_eq!(
        load_with(&[&policy], b"not TPS1", pinned(&policy)?, NOW),
        Err(AdmissionError::Snapshot(
            TrustPolicySnapshotContractErrorV1::InvalidEncoding
        ))
    );
    // The current policy must extend this exact TPS1 snapshot; a predecessor need not.
    let elsewhere = with(|p| p.trust_policy_snapshot_digest = [0x55; 32])?;
    assert_eq!(
        load(&[&elsewhere], NOW)?,
        Err(AdmissionError::SnapshotBinding)
    );
    let rebound = successor(&elsewhere, 2, |p| {
        p.trust_policy_snapshot_digest = *blake3::hash(&snapshot).as_bytes();
    })?;
    assert!(load(&[&elsewhere, &rebound], NOW)?.is_ok());
    assert_eq!(
        load(
            &[
                &rebound,
                &successor(&rebound, 3, |p| p.trust_policy_snapshot_digest = [0x55; 32])?
            ],
            NOW
        )?,
        Err(AdmissionError::SnapshotBinding)
    );
    Ok(())
}

#[test]
fn every_error_names_its_reason() {
    for (error, expected) in [
        (
            AdmissionError::OperatorKey.to_string(),
            "operator key is invalid",
        ),
        (
            AdmissionError::Policy(PolicyError::RootRoleConflict).to_string(),
            "CTP1 record is invalid: CTP1 conformance trust policy key is a root of both roles",
        ),
        (
            AdmissionError::OperatorSignature.to_string(),
            "operator signature does not verify",
        ),
        (
            AdmissionError::Snapshot(TrustPolicySnapshotContractErrorV1::FieldOutOfBounds)
                .to_string(),
            "TPS1 snapshot is invalid",
        ),
        (AdmissionError::EmptyChain.to_string(), "chain is empty"),
        (
            AdmissionError::SnapshotBinding.to_string(),
            "does not extend the TPS1 snapshot",
        ),
        (PolicyError::InvalidEncoding.to_string(), "encoding"),
        (PolicyError::UnsupportedSchemaVersion.to_string(), "version"),
        (PolicyError::FieldOutOfBounds.to_string(), "out of bounds"),
        (PolicyError::NonCanonicalOrder.to_string(), "not canonical"),
    ] {
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn the_pinned_high_water_mark_refuses_older_or_divergent_chains() -> TestResult {
    let first = with(|_| {})?;
    let second = successor(&first, 2, |_| {})?;
    let third = successor(&second, 3, |_| {})?;
    // Another policy at the pinned epoch, and a chain that links past the pinned policy.
    let divergent = successor(&first, 2, |p| p.revoked_key_ids = vec![[0x40; 32]])?;
    let after_divergent = successor(&divergent, 3, |_| {})?;
    let skipping = successor(&first, 3, |_| {})?;
    let tps1 = snapshot()?;
    let mark = pinned(&second)?;
    let standing =
        |chain: &[&[u8]], anchor| -> TestResult<Result<[u8; 32], ConformanceKeyRefusalV1>> {
            Ok(admit(
                &load_with(chain, &tps1, anchor, NOW)?,
                ConformanceTrustRoleV1::ReportSigning,
                REPORTER,
            ))
        };
    // A chain that reaches the mark exactly, or continues past it, stands.
    for chain in [
        vec![&second[..]],
        vec![&first[..], &second[..]],
        vec![&first[..], &second[..], &third[..]],
    ] {
        assert_eq!(standing(&chain, mark)?, Ok(public(REPORTER)));
    }
    let rolled_back: [(&str, Vec<&[u8]>, ConformanceTrustAnchorV1); 5] = [
        (
            "an old chain",
            vec![&first[..], &second[..]],
            pinned(&third)?,
        ),
        ("one record below the mark", vec![&first[..]], mark),
        (
            "skips the pinned policy",
            vec![&first[..], &skipping[..]],
            mark,
        ),
        (
            "another policy at the pinned epoch",
            vec![&first[..], &divergent[..], &after_divergent[..]],
            mark,
        ),
        (
            "a mark whose epoch is not the pinned policy's",
            vec![&first[..], &second[..], &third[..]],
            ConformanceTrustAnchorV1 {
                epoch: 3,
                policy_digest: mark.policy_digest,
            },
        ),
    ];
    for (name, chain, anchor) in rolled_back {
        assert_eq!(
            standing(&chain, anchor)?,
            Err(ConformanceKeyRefusalV1::RolledBack),
            "{name}"
        );
    }
    Ok(())
}

/// The admission of the default policy bound to the draft TPS1 with these revoked key ids.
fn with_tps1_revocations(
    mut revoked: Vec<String>,
) -> TestResult<Result<ConformanceTrustAdmissionV1, AdmissionError>> {
    revoked.sort_unstable();
    let tps1 = snapshot_with(|s| s.revoked_key_ids = revoked)?;
    let policy = with(|p| p.trust_policy_snapshot_digest = *blake3::hash(&tps1).as_bytes())?;
    Ok(load_with(&[&policy], &tps1, pinned(&policy)?, NOW))
}

#[test]
fn a_ckr1_key_id_revoked_by_the_bound_tps1_is_refused_even_as_a_ctp1_root() -> TestResult {
    let hex = blake3::Hash::from_bytes(key_id(REPORTER))
        .to_hex()
        .to_string();
    assert_eq!(CONFORMANCE_REVOKED_KEY_ID_PREFIX_V1, "ckr1-");
    assert_eq!(
        conformance_revoked_key_id_v1(&key_id(REPORTER)),
        format!("ckr1-{hex}")
    );
    let trust = with_tps1_revocations(vec![
        conformance_revoked_key_id_v1(&key_id(REPORTER)),
        "unrelated-key".to_owned(),
    ])??;
    assert!(trust
        .policy()
        .report_signing_roots
        .contains(&public(REPORTER)));
    for role in [
        ConformanceTrustRoleV1::ReportSigning,
        ConformanceTrustRoleV1::EvaluatorRelease,
    ] {
        assert_eq!(
            admit(&trust, role, REPORTER),
            Err(ConformanceKeyRefusalV1::Revoked)
        );
    }
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::EvaluatorRelease, EVALUATOR),
        Ok(public(EVALUATOR))
    );

    // A bare key id, a Plugin-prefixed entry or a malformed `ckr1-` entry revokes nothing.
    let trust = with_tps1_revocations(vec![
        hex.clone(),
        format!("pkr1-{hex}"),
        format!("ptr1-{hex}"),
        format!("ckr1-{hex}0"),
        "ckr1-".to_owned(),
    ])??;
    assert_eq!(
        admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
        Ok(public(REPORTER))
    );
    // An uppercase entry is not even a valid TPS1 identifier, so it never revokes either.
    for uppercase in [
        format!("CKR1-{hex}"),
        format!("ckr1-{}", hex.to_uppercase()),
    ] {
        assert_eq!(
            with_tps1_revocations(vec![uppercase])?.err(),
            Some(AdmissionError::Snapshot(
                TrustPolicySnapshotContractErrorV1::FieldOutOfBounds
            ))
        );
    }
    Ok(())
}

#[test]
fn a_bound_tps1_past_offline_valid_through_makes_the_admission_stale() -> TestResult {
    for (tps1_valid_through, now, expected) in [
        (VALID_THROUGH, NOW, Ok(public(REPORTER))),
        (
            VALID_THROUGH,
            NOW + 1,
            Err(ConformanceKeyRefusalV1::SnapshotStale),
        ),
        (
            "2027-01-15T08:00:00Z",
            NOW,
            Err(ConformanceKeyRefusalV1::SnapshotStale),
        ),
        // An unreadable TPS1 bound is stale.
        ("never", NOW, Err(ConformanceKeyRefusalV1::SnapshotStale)),
    ] {
        let tps1 = snapshot_with(|s| s.offline_valid_through = tps1_valid_through.to_owned())?;
        // The CTP1 itself stays valid for years.
        let policy = with(|p| {
            p.trust_policy_snapshot_digest = *blake3::hash(&tps1).as_bytes();
            p.offline_valid_through = "2030-06-01T00:00:00Z".to_owned();
        })?;
        let trust = load_with(&[&policy], &tps1, pinned(&policy)?, now)?;
        assert_eq!(
            admit(&trust, ConformanceTrustRoleV1::ReportSigning, REPORTER),
            expected,
            "{tps1_valid_through} at {now}"
        );
    }
    Ok(())
}
