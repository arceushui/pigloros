//! CKP1 key intents and CKU1 credit counters are clear control data only.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityArtifactKindV1 as Kind, CommunityArtifactOperationV1 as Operation,
    CommunityArtifactPurposeV1 as Purpose, CommunityKeyIntentInputV1 as Input,
    CommunityKeyIntentV1 as Intent, CommunityKeyUseV1 as KeyUse,
    CommunityLifecycleErrorV1 as Error, CommunityMemberSlotsV1 as Slots, CommunityPassKeyV1,
    CommunityRecordKindsV1 as Kinds, MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const ALL_KINDS: [Kind; 9] = [
    Kind::StateContent,
    Kind::StateRevisionOrHead,
    Kind::PreparedInvocation,
    Kind::ExecutionProvenance,
    Kind::TraceAnnotation,
    Kind::ReplayReceiptOrRoot,
    Kind::LifecycleControl,
    Kind::BoundedRecordBundle,
    Kind::ClassificationProof,
];

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture array expected".into()),
    }
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]
        })
        .map(char::from)
        .collect()
}
fn oracle(domain: &[u8], canonical: &[u8]) -> Hash {
    let mut input = domain.to_vec();
    input.extend_from_slice(canonical);
    Hash::from_bytes(*blake3::hash(&input).as_bytes())
}

const fn input() -> Input {
    Input {
        protection_operation_id: [1; 16],
        parent_operation: Operation::Control([2; 16]),
        timeline: timeline(0xab),
        generation: [0xcd; 16],
        purpose: Purpose::LifecycleControl,
        scope_set_digest: hash(3),
        evidence_not_after_micros: 4,
        allowed_record_kinds: Kinds::empty()
            .with(Kind::LifecycleControl)
            .with(Kind::BoundedRecordBundle),
        member_slots: Slots::empty(),
        material_fingerprint: hash(5),
        authority_request_digest: hash(6),
    }
}

fn value(parent: (u64, Vec<u8>), kinds: &[u64], slots: &[u64]) -> Value {
    Value::Array(vec![
        bytes(b"CKP1"),
        uint(1),
        bytes(&[1; 16]),
        uint(parent.0),
        bytes(&parent.1),
        bytes(&[0xab; 16]),
        bytes(&[0xcd; 16]),
        uint(3),
        bytes(&[3; 32]),
        uint(4),
        Value::Array(kinds.iter().copied().map(uint).collect()),
        Value::Array(slots.iter().copied().map(uint).collect()),
        bytes(&[5; 32]),
        bytes(&[6; 32]),
    ])
}

fn control_value() -> Value {
    value((2, vec![2; 16]), &[6, 7], &[])
}

fn intent() -> Fallible<Intent> {
    Ok(Intent::new(input())?)
}

#[test]
fn kind_and_slot_sets_keep_closed_ascending_members() -> TestResult {
    let kinds = Kinds::empty()
        .with(Kind::ClassificationProof)
        .with(Kind::StateContent);
    for kind in ALL_KINDS {
        assert_eq!(
            kinds.contains(kind),
            matches!(kind, Kind::StateContent | Kind::ClassificationProof)
        );
    }
    assert_eq!(kinds.iter().map(Kind::code).collect::<Vec<_>>(), vec![0, 8]);
    assert!(Kinds::empty().iter().next().is_none());
    assert!(kinds.with(Kind::StateContent) == kinds);

    let slots = Slots::new(&[0, 7, 63])?;
    assert_eq!(slots.iter().collect::<Vec<_>>(), vec![0, 7, 63]);
    assert!(Slots::new(&[]).is_ok_and(|empty| empty == Slots::empty()));
    assert_eq!(Slots::new(&[64]).err(), Some(Error::BoundsExceeded));
    assert_eq!(Slots::new(&[5, 5]).err(), Some(Error::InvalidBinding));
    assert_eq!(Slots::new(&[6, 5]).err(), Some(Error::InvalidBinding));
    assert!(Slots::new(&[5, 6]).is_ok());
    Ok(())
}

#[test]
fn control_intent_has_the_exact_wire_owner_and_digest() -> TestResult {
    let intent = intent()?;
    let expected = encode(&control_value())?;
    assert_eq!(&*intent.to_canonical_cbor(), &expected);
    assert_eq!(
        intent.digest(),
        oracle(b"PiglorOS.Community.CKP1.v1\0", &expected)
    );
    assert_eq!(
        intent.key_owner_text(),
        format!(
            "community:{}:{}:3:c:{}",
            "ab".repeat(16),
            "cd".repeat(16),
            hex(&[1; 16])
        )
    );
    let decoded = Intent::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == input());
    assert_eq!(decoded.key_owner_text(), intent.key_owner_text());
    Ok(())
}

#[test]
fn pass_and_initialization_parents_and_member_slots_roundtrip() -> TestResult {
    let pass = CommunityPassKeyV1::new(timeline(0xab), [0xcd; 16], 9)?;
    let pass_bytes = encode(&Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[0xab; 16]),
        bytes(&[0xcd; 16]),
        uint(9),
    ]))?;
    for (operation, parent) in [
        (Operation::Pass(pass), (0, pass_bytes)),
        (Operation::Initialization([8; 16]), (1, vec![8; 16])),
    ] {
        let mut input = input();
        input.parent_operation = operation;
        input.purpose = Purpose::ExecutionState;
        input.allowed_record_kinds = Kinds::empty()
            .with(Kind::StateContent)
            .with(Kind::ExecutionProvenance);
        input.member_slots = Slots::new(&[0, 7, 63])?;
        let intent = Intent::new(input)?;
        let mut expected = value(parent, &[0, 3], &[0, 7, 63]);
        fields(&mut expected)?[7] = uint(0);
        let expected = encode(&expected)?;
        assert_eq!(&*intent.to_canonical_cbor(), &expected);
        assert!(*Intent::from_canonical_cbor(&expected)?.as_input() == input);
        assert!(intent.key_owner_text().contains(":0:c:"));
    }
    Ok(())
}

#[test]
fn every_local_binding_is_required() -> TestResult {
    let foreign_pass = CommunityPassKeyV1::new(timeline(0xac), [0xcd; 16], 1)?;
    for field in 0..12 {
        let mut input = input();
        match field {
            0 => input.protection_operation_id = [0; 16],
            1 => input.scope_set_digest = Hash::zero(),
            2 => input.material_fingerprint = Hash::zero(),
            3 => input.authority_request_digest = Hash::zero(),
            4 => input.allowed_record_kinds = Kinds::empty(),
            5 => input.purpose = Purpose::ExecutionState,
            6 => input.allowed_record_kinds = Kinds::empty().with(Kind::TraceAnnotation),
            7 => input.parent_operation = Operation::Pass(foreign_pass),
            8 => input.parent_operation = Operation::Control([0; 16]),
            9 => input.parent_operation = Operation::Initialization([0; 16]),
            10 => input.timeline = timeline(0),
            _ => input.generation = [0; 16],
        }
        assert_eq!(Intent::new(input).err(), Some(Error::InvalidBinding));
    }
    for invalid in [0, u64::MAX / 2 + 1] {
        let mut input = input();
        input.evidence_not_after_micros = invalid;
        assert_eq!(Intent::new(input).err(), Some(Error::BoundsExceeded));
    }
    Ok(())
}

#[test]
fn decoded_kinds_and_slots_are_bounded_and_strictly_ascending() -> TestResult {
    let cases: [(&[u64], &[u64], Error); 8] = [
        (&[7, 6], &[], Error::InvalidBinding),
        (&[6, 6], &[], Error::InvalidBinding),
        (&[0, 1, 2, 3, 4, 5, 6, 7, 8], &[], Error::InvalidBinding),
        (&[0, 1, 2, 3, 4, 5, 6, 7, 8, 8], &[], Error::BoundsExceeded),
        (&[6], &[64], Error::BoundsExceeded),
        (&[6], &[70_000], Error::BoundsExceeded),
        (&[6], &[2, 1], Error::InvalidBinding),
        (&[9], &[], Error::InvalidEncoding),
    ];
    for (kinds, slots, error) in cases {
        let bytes = encode(&value((2, vec![2; 16]), kinds, slots))?;
        assert_eq!(Intent::from_canonical_cbor(&bytes).err(), Some(error));
    }
    let all_slots: Vec<u64> = (0..64).collect();
    let bytes = encode(&value((2, vec![2; 16]), &[6], &all_slots))?;
    assert_eq!(
        Intent::from_canonical_cbor(&bytes)?
            .as_input()
            .member_slots
            .iter()
            .count(),
        64
    );
    let mut too_many = all_slots;
    too_many.push(64);
    let bytes = encode(&value((2, vec![2; 16]), &[6], &too_many))?;
    assert_eq!(
        Intent::from_canonical_cbor(&bytes).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn intent_framing_is_exact() -> TestResult {
    let mut trailing = encode(&control_value())?;
    trailing.push(0);
    assert_eq!(
        Intent::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut version = control_value();
    fields(&mut version)?[1] = uint(2);
    assert_eq!(
        Intent::from_canonical_cbor(&encode(&version)?).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(
        Intent::from_canonical_cbor(&vec![0; 65_537]).err(),
        Some(Error::BoundsExceeded)
    );
    let mut horizon = control_value();
    fields(&mut horizon)?[9] = uint(0);
    assert_eq!(
        Intent::from_canonical_cbor(&encode(&horizon)?).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

fn use_value(owner: &str, epoch: u64, ordinal: u64) -> Value {
    Value::Array(vec![
        bytes(b"CKU1"),
        uint(1),
        bytes(&[1; 16]),
        Value::Text(owner.to_owned()),
        uint(epoch),
        uint(ordinal),
    ])
}

#[test]
fn credits_burn_monotonically_up_to_the_key_budget() -> TestResult {
    let intent = intent()?;
    let zero = KeyUse::new(&intent, 0)?;
    assert_eq!(zero.highest_encryption_ordinal(), 0);
    let one = zero.next_credit()?;
    assert_eq!(one.highest_encryption_ordinal(), 1);
    assert_eq!(one.next_credit()?.highest_encryption_ordinal(), 2);
    let last = KeyUse::new(&intent, MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1)?;
    assert_eq!(last.next_credit().err(), Some(Error::CapacityExhausted));
    assert_eq!(
        KeyUse::new(&intent, MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1 - 1)?
            .next_credit()?
            .highest_encryption_ordinal(),
        MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1
    );
    assert_eq!(
        KeyUse::new(&intent, MAX_COMMUNITY_KEY_ENCRYPTION_ORDINAL_V1 + 1).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn credit_counter_is_bound_to_its_exact_intent_and_epoch() -> TestResult {
    let intent = intent()?;
    let owner = intent.key_owner_text().to_owned();
    let counter = KeyUse::new(&intent, 300)?;
    let expected = encode(&use_value(&owner, 1, 300))?;
    assert_eq!(&*counter.to_canonical_cbor(), &expected);
    assert_eq!(
        KeyUse::from_canonical_cbor(&expected, &intent)?.highest_encryption_ordinal(),
        300
    );

    let mut other_id = input();
    other_id.protection_operation_id = [9; 16];
    let mut other_owner = input();
    other_owner.timeline = timeline(0xac);
    for other in [other_id, other_owner] {
        assert_eq!(
            KeyUse::from_canonical_cbor(&expected, &Intent::new(other)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    for (epoch, ordinal, error) in [
        (2, 1, Error::InvalidBinding),
        (1, 65_537, Error::BoundsExceeded),
        (1, 1 << 40, Error::BoundsExceeded),
    ] {
        assert_eq!(
            KeyUse::from_canonical_cbor(&encode(&use_value(&owner, epoch, ordinal))?, &intent)
                .err(),
            Some(error)
        );
    }
    let mut trailing = expected;
    trailing.push(0);
    assert_eq!(
        KeyUse::from_canonical_cbor(&trailing, &intent).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}
