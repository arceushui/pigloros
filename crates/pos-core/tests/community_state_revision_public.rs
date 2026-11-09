//! CSR1 wire and local producing-link invariants, without live owner authority.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1, CommunityStateProducerV1 as Producer,
    CommunityStateRevisionInputV1 as Input, CommunityStateRevisionV1 as Revision,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
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

fn pass(ordinal: u64) -> Result<CommunityPassKeyV1, Error> {
    CommunityPassKeyV1::new(
        TimelineId::from_ulid(ulid::Ulid::from_bytes([7; 16])),
        [8; 16],
        ordinal,
    )
}

fn pass_value(ordinal: u64) -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[7; 16]),
        bytes(&[8; 16]),
        uint(ordinal),
    ])
}

const fn initial() -> Input {
    Input {
        producer_origin: Producer::Initialization {
            generation_request_digest: hash(1),
            operation_id: [2; 16],
        },
        member_binding_digest: hash(3),
        predecessor_revision_digest: None,
        state_content_digest: hash(4),
        producer_digest: hash(5),
        protected_owner_binding_digest: hash(6),
        evidence_not_after_micros: 1,
    }
}

fn stepped(ordinal: u64) -> Result<Input, Error> {
    Ok(Input {
        producer_origin: Producer::Pass(pass(ordinal)?),
        predecessor_revision_digest: Some(hash(9)),
        ..initial()
    })
}

fn fields(input: Input) -> Fallible<Vec<Value>> {
    let origin = match input.producer_origin {
        Producer::Initialization {
            generation_request_digest,
            operation_id,
        } => Value::Array(vec![
            uint(0),
            bytes(generation_request_digest.as_bytes()),
            bytes(&operation_id),
        ]),
        Producer::Pass(key) => {
            Value::Array(vec![uint(1), bytes(&encode(&pass_value(key.ordinal()))?)])
        }
    };
    Ok(vec![
        bytes(b"CSR1"),
        uint(1),
        origin,
        bytes(input.member_binding_digest.as_bytes()),
        input
            .predecessor_revision_digest
            .map_or(Value::Null, |v| bytes(v.as_bytes())),
        bytes(input.state_content_digest.as_bytes()),
        bytes(input.producer_digest.as_bytes()),
        bytes(input.protected_owner_binding_digest.as_bytes()),
        uint(input.evidence_not_after_micros),
    ])
}

#[test]
fn initialization_and_pass_have_exact_distinct_nine_field_encodings() -> TestResult {
    for mut input in [initial(), stepped(1)?, stepped(u64::MAX)?] {
        for horizon in [1, 24, 65_536, u64::MAX / 2] {
            input.evidence_not_after_micros = horizon;
            let expected = encode(&Value::Array(fields(input)?))?;
            let record = Revision::new(input)?;
            let encoded = record.to_canonical_cbor();
            assert_eq!(encoded.as_slice(), expected.as_slice());
            assert!(encoded.len() <= 512);
            assert!(record.as_input() == &input);
            assert!(Revision::from_canonical_cbor(&expected)?.as_input() == &input);
        }
    }
    Ok(())
}

#[test]
fn equal_content_does_not_reuse_the_producing_revision() -> TestResult {
    let first = stepped(1)?;
    let second = stepped(2)?;
    assert_eq!(first.state_content_digest, second.state_content_digest);
    assert_ne!(
        Revision::new(first)?.to_canonical_cbor().as_slice(),
        Revision::new(second)?.to_canonical_cbor().as_slice()
    );
    let mut changed_producer = first;
    changed_producer.producer_digest = hash(10);
    assert_ne!(
        Revision::new(first)?.to_canonical_cbor().as_slice(),
        Revision::new(changed_producer)?
            .to_canonical_cbor()
            .as_slice()
    );
    Ok(())
}

#[test]
fn only_initialization_has_no_predecessor_and_a_pass_cannot_use_zero() -> TestResult {
    for input in [
        Input {
            predecessor_revision_digest: Some(hash(9)),
            ..initial()
        },
        Input {
            predecessor_revision_digest: None,
            ..stepped(1)?
        },
        Input {
            predecessor_revision_digest: Some(Hash::zero()),
            ..stepped(1)?
        },
    ] {
        assert_eq!(Revision::new(input).err(), Some(Error::InvalidBinding));
        let wire = encode(&Value::Array(fields(input)?))?;
        assert_eq!(
            Revision::from_canonical_cbor(&wire).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut zero_pass = fields(stepped(1)?)?;
    zero_pass[2] = Value::Array(vec![uint(1), bytes(&encode(&pass_value(0))?)]);
    assert_eq!(
        Revision::from_canonical_cbor(&encode(&Value::Array(zero_pass))?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn identities_and_fixed_horizons_are_validated_before_retention() -> TestResult {
    let inputs = [
        Input {
            member_binding_digest: Hash::zero(),
            ..initial()
        },
        Input {
            state_content_digest: Hash::zero(),
            ..initial()
        },
        Input {
            producer_digest: Hash::zero(),
            ..initial()
        },
        Input {
            protected_owner_binding_digest: Hash::zero(),
            ..initial()
        },
        Input {
            producer_origin: Producer::Initialization {
                generation_request_digest: Hash::zero(),
                operation_id: [2; 16],
            },
            ..initial()
        },
        Input {
            producer_origin: Producer::Initialization {
                generation_request_digest: hash(1),
                operation_id: [0; 16],
            },
            ..initial()
        },
    ];
    for input in inputs {
        assert_eq!(Revision::new(input).err(), Some(Error::InvalidBinding));
        let wire = encode(&Value::Array(fields(input)?))?;
        assert_eq!(
            Revision::from_canonical_cbor(&wire).err(),
            Some(Error::InvalidBinding)
        );
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        let input = Input {
            evidence_not_after_micros: horizon,
            ..initial()
        };
        assert_eq!(Revision::new(input).err(), Some(Error::BoundsExceeded));
        let wire = encode(&Value::Array(fields(input)?))?;
        assert_eq!(
            Revision::from_canonical_cbor(&wire).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn every_truncation_trailing_input_and_outer_bound_refuses() -> TestResult {
    for input in [initial(), stepped(1)?] {
        let valid = encode(&Value::Array(fields(input)?))?;
        for length in 0..valid.len() {
            assert_eq!(
                Revision::from_canonical_cbor(&valid[..length]).err(),
                Some(Error::InvalidEncoding)
            );
        }
        let mut trailing = valid;
        trailing.push(0);
        assert_eq!(
            Revision::from_canonical_cbor(&trailing).err(),
            Some(Error::InvalidEncoding)
        );
    }
    assert_eq!(
        Revision::from_canonical_cbor(&[0; 512]).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Revision::from_canonical_cbor(&[0; 513]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn origin_tags_arity_and_nested_pass_framing_are_closed() -> TestResult {
    for origin in [
        Value::Array(vec![uint(2)]),
        Value::Array(vec![uint(0), bytes(&[1; 32])]),
        Value::Array(vec![uint(1), bytes(&encode(&pass_value(1))?), uint(0)]),
        Value::Null,
        Value::Array(vec![uint(1), bytes(&[0; 64])]),
    ] {
        let mut values = fields(stepped(1)?)?;
        values[2] = origin;
        assert_eq!(
            Revision::from_canonical_cbor(&encode(&Value::Array(values))?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut oversized = fields(stepped(1)?)?;
    oversized[2] = Value::Array(vec![uint(1), bytes(&[0; 65])]);
    assert_eq!(
        Revision::from_canonical_cbor(&encode(&Value::Array(oversized))?).err(),
        Some(Error::BoundsExceeded)
    );
    let mut version = fields(initial())?;
    version[1] = uint(2);
    assert_eq!(
        Revision::from_canonical_cbor(&encode(&Value::Array(version))?).err(),
        Some(Error::UnsupportedVersion)
    );
    Ok(())
}
