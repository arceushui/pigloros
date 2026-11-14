//! CCI1 copy descriptors carry no payload and never prove disposal.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityArtifactOperationV1 as Operation, CommunityArtifactPurposeV1 as Purpose,
    CommunityCopyHolderV1 as Holder, CommunityCopyInventoryInputV1 as Input,
    CommunityCopyInventoryV1 as Descriptor, CommunityCopyStateV1 as State,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const HOLDERS: [Holder; 8] = [
    Holder::Staging,
    Holder::SelectedCell,
    Holder::RetiredCell,
    Holder::Worker,
    Holder::Channel,
    Holder::NativeContext,
    Holder::KeyVault,
    Holder::EvidenceStore,
];
const STATES: [State; 5] = [
    State::Owned,
    State::DeliveryPending,
    State::ReleaseConfirmed,
    State::DisposalPending,
    State::Disposed,
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

const fn first() -> Input {
    Input {
        copy_id: [1; 16],
        revision: 1,
        predecessor: None,
        parent_operation: Operation::Control([2; 16]),
        timeline: timeline(0xab),
        generation: [0xcd; 16],
        holder: Holder::KeyVault,
        holder_digest: hash(3),
        purpose: Purpose::LifecycleControl,
        scope_set_digest: hash(4),
        object_commitment: None,
        state: State::Owned,
        deadline_micros: 5,
    }
}

fn first_value() -> Value {
    Value::Array(vec![
        bytes(b"CCI1"),
        uint(1),
        bytes(&[1; 16]),
        uint(1),
        Value::Null,
        uint(2),
        bytes(&[2; 16]),
        bytes(&[0xab; 16]),
        bytes(&[0xcd; 16]),
        uint(6),
        bytes(&[3; 32]),
        uint(3),
        bytes(&[4; 32]),
        Value::Null,
        uint(0),
        uint(5),
    ])
}

#[test]
fn first_revision_has_the_exact_wire() -> TestResult {
    let copy = Descriptor::new(first())?;
    let expected = encode(&first_value())?;
    assert_eq!(&*copy.to_canonical_cbor(), &expected);
    assert!(*Descriptor::from_canonical_cbor(&expected)?.as_input() == first());
    Ok(())
}

#[test]
fn later_revision_binds_its_predecessor_pass_and_object() -> TestResult {
    let pass = CommunityPassKeyV1::new(timeline(0xab), [0xcd; 16], 7)?;
    let input = Input {
        revision: 2,
        predecessor: Some(hash(8)),
        parent_operation: Operation::Pass(pass),
        object_commitment: Some(hash(9)),
        state: State::DeliveryPending,
        purpose: Purpose::ExecutionState,
        ..first()
    };
    let mut expected = first_value();
    let values = fields(&mut expected)?;
    values[3] = uint(2);
    values[4] = bytes(&[8; 32]);
    values[5] = uint(0);
    values[6] = Value::Bytes(pass.to_canonical_cbor());
    values[11] = uint(0);
    values[13] = bytes(&[9; 32]);
    values[14] = uint(1);
    let expected = encode(&expected)?;
    assert_eq!(
        &*Descriptor::new(input.clone())?.to_canonical_cbor(),
        &expected
    );
    assert!(*Descriptor::from_canonical_cbor(&expected)?.as_input() == input);
    Ok(())
}

#[test]
fn every_holder_and_state_has_its_fixed_code() -> TestResult {
    for (code, holder) in HOLDERS.into_iter().enumerate() {
        assert_eq!(usize::from(holder.code()), code);
        let mut value = first_value();
        fields(&mut value)?[9] = uint(code as u64);
        let decoded = Descriptor::from_canonical_cbor(&encode(&value)?)?;
        assert_eq!(decoded.as_input().holder, holder);
    }
    for (code, state) in STATES.into_iter().enumerate() {
        assert_eq!(usize::from(state.code()), code);
        let mut value = first_value();
        fields(&mut value)?[14] = uint(code as u64);
        let decoded = Descriptor::from_canonical_cbor(&encode(&value)?)?;
        assert_eq!(decoded.as_input().state, state);
    }
    for (field, code) in [(9, 8), (14, 5)] {
        let mut value = first_value();
        fields(&mut value)?[field] = uint(code);
        assert_eq!(
            Descriptor::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn revision_linkage_and_identities_are_required() -> TestResult {
    let foreign_pass = CommunityPassKeyV1::new(timeline(0xac), [0xcd; 16], 1)?;
    let cases = [
        Input {
            copy_id: [0; 16],
            ..first()
        },
        Input {
            revision: 0,
            ..first()
        },
        Input {
            predecessor: Some(hash(8)),
            ..first()
        },
        Input {
            revision: 2,
            ..first()
        },
        Input {
            revision: 2,
            predecessor: Some(Hash::zero()),
            ..first()
        },
        Input {
            holder_digest: Hash::zero(),
            ..first()
        },
        Input {
            scope_set_digest: Hash::zero(),
            ..first()
        },
        Input {
            object_commitment: Some(Hash::zero()),
            ..first()
        },
        Input {
            timeline: timeline(0),
            ..first()
        },
        Input {
            generation: [0; 16],
            ..first()
        },
        Input {
            parent_operation: Operation::Pass(foreign_pass),
            ..first()
        },
        Input {
            parent_operation: Operation::Control([0; 16]),
            ..first()
        },
    ];
    for input in cases {
        assert_eq!(Descriptor::new(input).err(), Some(Error::InvalidBinding));
    }
    for deadline_micros in [0, u64::MAX / 2 + 1] {
        assert_eq!(
            Descriptor::new(Input {
                deadline_micros,
                ..first()
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn copy_framing_is_exact() -> TestResult {
    let mut trailing = encode(&first_value())?;
    trailing.push(0);
    assert_eq!(
        Descriptor::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut version = first_value();
    fields(&mut version)?[1] = uint(2);
    assert_eq!(
        Descriptor::from_canonical_cbor(&encode(&version)?).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(
        Descriptor::from_canonical_cbor(&[0; 1025]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
