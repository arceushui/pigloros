//! Independent CFI1/CFO1 host/guest values. Failures are data, not authority.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    AtomicCommitFailureV1 as Atomic, CommunityDigestListV1 as Digests,
    CommunityGuestErrorCodeV1 as GuestCode, CommunityGuestErrorV1 as Guest,
    CommunityInvocationFailureInputV1 as Input, CommunityInvocationFailureV1 as Failure,
    CommunityLifecycleErrorV1 as Error, CommunityPassFailureInputV1 as PassInput,
    CommunityPassFailureV1 as PassFailure, CommunityPassKeyV1 as Pass,
    CommunityPluginHostErrorV1 as Host, ComponentTrapClassV1 as Trap, FieldRefV1,
    GuestPluginErrorV1 as OwnedGuest, PluginErrorCodeV1 as OwnedCode,
    RevocationBasisV1 as Revocation, TrapReproductionV1 as Reproduction,
    TrustDenialBasisV1 as Denial,
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
fn array(values: &[u64]) -> Value {
    Value::Array(values.iter().copied().map(uint).collect())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture is not an array".into()),
    }
}
fn pass() -> Result<Pass, Error> {
    Pass::new(
        TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        [2; 16],
        3,
    )
}
fn pass_value() -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(3),
    ])
}
fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.push(0);
    preimage.extend_from_slice(bytes);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}
const fn guest_default() -> Guest<'static> {
    Guest {
        code: GuestCode::DeterministicBudgetExhausted,
        canonical_coordinate: None,
        related_digest: None,
    }
}
fn failure_input(host: Host) -> Fallible<Input<'static>> {
    Ok(Input {
        pass_key: Some(pass()?),
        member_binding_digest: hash(4),
        invocation_id: Some([5; 16]),
        prepared_invocation_digest: Some(hash(6)),
        host_failure: host,
        guest_error: (host == Host::GuestDeclaredFailure).then_some(guest_default()),
        decision_provenance_digest: hash(7),
        evidence_not_after_micros: 8,
    })
}
fn fixture(host: Value, guest: Value) -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CFI1"),
        uint(1),
        bytes(&encode(&pass_value())?),
        bytes(&[4; 32]),
        bytes(&[5; 16]),
        bytes(&[6; 32]),
        host,
        guest,
        bytes(&[7; 32]),
        uint(8),
    ]))
}
fn host_cases() -> Vec<(Host, Value)> {
    let mut cases = vec![
        (Host::InvalidManifest, array(&[0])),
        (Host::IncompatibleAbi, array(&[3])),
        (Host::InvalidInvocation, array(&[6])),
        (Host::InvalidGuestOutput, array(&[7])),
        (Host::UnsupportedSchema, array(&[8])),
        (Host::StateMigrationFailed, array(&[9])),
        (Host::GuestDeclaredFailure, array(&[10])),
        (Host::WorkerCrashed, array(&[12])),
        (Host::FuelExhausted, array(&[13])),
        (Host::MemoryLimitExceeded, array(&[14])),
        (Host::HostCallLimitExceeded, array(&[15])),
        (Host::OutputLimitExceeded, array(&[16])),
        (Host::DeterministicDeadlineExceeded, array(&[17])),
        (Host::OperationalWatchdogStop, array(&[18])),
    ];
    for (code, basis) in [
        (0, Denial::Expired),
        (1, Denial::NotActive),
        (2, Denial::Untrusted),
        (3, Denial::PolicyMismatch),
        (4, Denial::TrustStateUnavailable),
    ] {
        cases.push((Host::ArtifactTrustDenied { basis }, array(&[1, code])));
    }
    for (code, basis) in [
        (0, Revocation::PublisherKey),
        (1, Revocation::Artifact),
        (2, Revocation::OperatorDenial),
    ] {
        cases.push((Host::ArtifactRevoked { basis }, array(&[2, code])));
    }
    for index in [0, 23, 24, 255] {
        cases.push((Host::MissingFeature { index }, array(&[4, index as u64])));
        cases.push((Host::CapabilityDenied { index }, array(&[5, index as u64])));
    }
    for (code, class) in [
        (0, Trap::Unreachable),
        (1, Trap::MemoryOutOfBounds),
        (2, Trap::TableOutOfBounds),
        (3, Trap::IndirectCall),
        (4, Trap::IntegerArithmetic),
        (5, Trap::StackExhausted),
        (6, Trap::Other),
    ] {
        for (reproduction_code, reproduction) in [
            (0, Reproduction::ReproducedByConformance),
            (1, Reproduction::Unverified),
        ] {
            cases.push((
                Host::ComponentTrap {
                    class,
                    reproduction,
                },
                array(&[11, code, reproduction_code]),
            ));
        }
    }
    for (code, failure) in [
        (0, Atomic::DeterministicTypedResult),
        (1, Atomic::Operational),
    ] {
        cases.push((Host::AtomicCommitFailed { failure }, array(&[19, code])));
    }
    cases
}
fn owned_guest_cases() -> Vec<(OwnedCode, Value)> {
    let field = FieldRefV1 {
        schema_id: u32::MAX,
        field_ordinal: u16::MAX,
    };
    vec![
        (
            OwnedCode::InvalidInvocation(field),
            array(&[0, u64::from(u32::MAX), u64::from(u16::MAX)]),
        ),
        (
            OwnedCode::UnsupportedSchema(u32::MAX),
            array(&[1, u64::from(u32::MAX)]),
        ),
        (
            OwnedCode::CapabilityRequired("cap/read".into()),
            Value::Array(vec![uint(2), Value::Text("cap/read".into())]),
        ),
        (
            OwnedCode::DependencyMissing([0; 32]),
            Value::Array(vec![uint(3), bytes(&[0; 32])]),
        ),
        (OwnedCode::DeterministicBudgetExhausted, array(&[4])),
        (
            OwnedCode::InvalidState(field),
            array(&[5, u64::from(u32::MAX), u64::from(u16::MAX)]),
        ),
        (
            OwnedCode::MigrationRejected(field),
            array(&[6, u64::from(u32::MAX), u64::from(u16::MAX)]),
        ),
        (
            OwnedCode::GuestDeclaredFailure(u16::MAX),
            array(&[7, u64::from(u16::MAX)]),
        ),
    ]
}

#[test]
fn every_closed_host_failure_has_exact_associated_fields_and_original_domain() -> TestResult {
    for (host, value) in host_cases() {
        let input = failure_input(host)?;
        let failure = Failure::new(input)?;
        let guest = if host == Host::GuestDeclaredFailure {
            Value::Array(vec![array(&[4]), Value::Null, Value::Null])
        } else {
            Value::Null
        };
        let expected = encode(&fixture(value, guest)?)?;
        assert_eq!(&*failure.to_canonical_cbor(), &expected);
        assert!(*Failure::from_canonical_cbor(&expected)?.as_input() == input);
        assert_eq!(
            failure.digest(),
            domain_hash(b"PiglorOS.Community.CFI1.v1", &expected)
        );
    }
    Ok(())
}

#[test]
fn all_guest_error_variants_preserve_optional_empty_and_nontext_coordinate_bytes() -> TestResult {
    for (code, code_value) in owned_guest_cases() {
        for coordinate in [None, Some(Vec::new()), Some(vec![0xff; 128])] {
            for related_digest in [None, Some([0; 32]), Some([9; 32])] {
                let owned = OwnedGuest {
                    code: code.clone(),
                    canonical_coordinate: coordinate.clone(),
                    related_digest,
                };
                let guest = Guest::from_guest_error(&owned);
                let input = Input {
                    guest_error: Some(guest),
                    ..failure_input(Host::GuestDeclaredFailure)?
                };
                let failure = Failure::new(input)?;
                let guest_value = Value::Array(vec![
                    code_value.clone(),
                    coordinate
                        .as_ref()
                        .map_or(Value::Null, |coordinate| bytes(coordinate)),
                    related_digest.map_or(Value::Null, |digest| bytes(&digest)),
                ]);
                let expected = encode(&fixture(array(&[10]), guest_value)?)?;
                assert_eq!(&*failure.to_canonical_cbor(), &expected);
                assert!(*Failure::from_canonical_cbor(&expected)?.as_input() == input);
            }
        }
    }
    Ok(())
}

#[test]
fn decoded_guest_labels_and_coordinate_ranges_borrow_the_original_private_input() -> TestResult {
    let owned = OwnedGuest {
        code: OwnedCode::CapabilityRequired("cap/read".into()),
        canonical_coordinate: Some(vec![0xff; 128]),
        related_digest: Some([9; 32]),
    };
    let borrowed = Guest::from_guest_error(&owned);
    assert_eq!(
        borrowed
            .canonical_coordinate
            .ok_or("missing coordinate")?
            .as_ptr(),
        owned
            .canonical_coordinate
            .as_ref()
            .ok_or("missing owned coordinate")?
            .as_ptr()
    );
    let encoded = Failure::new(Input {
        guest_error: Some(borrowed),
        ..failure_input(Host::GuestDeclaredFailure)?
    })?
    .to_canonical_cbor();
    let decoded = Failure::from_canonical_cbor(&encoded)?;
    let guest = decoded
        .as_input()
        .guest_error
        .ok_or("missing decoded guest")?;
    let GuestCode::CapabilityRequired(id) = guest.code else {
        return Err("wrong guest code".into());
    };
    for bytes in [
        id.as_bytes(),
        guest
            .canonical_coordinate
            .ok_or("missing decoded coordinate")?,
    ] {
        let offset = bytes.as_ptr() as usize - encoded.as_ptr() as usize;
        assert!(offset + bytes.len() <= encoded.len());
        assert_eq!(&encoded[offset..offset + bytes.len()], bytes);
    }
    Ok(())
}

#[test]
fn preexecution_failure_has_no_fabricated_pass_invocation_or_prepared_input() -> TestResult {
    for pass_present in [false, true] {
        for invocation_present in [false, true] {
            for prepared_present in [false, true] {
                let original = failure_input(Host::InvalidInvocation)?;
                let input = Input {
                    pass_key: if pass_present {
                        original.pass_key
                    } else {
                        None
                    },
                    invocation_id: if invocation_present {
                        original.invocation_id
                    } else {
                        None
                    },
                    prepared_invocation_digest: if prepared_present {
                        original.prepared_invocation_digest
                    } else {
                        None
                    },
                    ..original
                };
                let encoded = Failure::new(input)?.to_canonical_cbor();
                let mut expected = fixture(array(&[6]), Value::Null)?;
                let fields = fields(&mut expected)?;
                if !pass_present {
                    fields[2] = Value::Null;
                }
                if !invocation_present {
                    fields[4] = Value::Null;
                }
                if !prepared_present {
                    fields[5] = Value::Null;
                }
                assert_eq!(&*encoded, &encode(&expected)?);
                assert!(*Failure::from_canonical_cbor(&encoded)?.as_input() == input);
            }
        }
    }
    Ok(())
}

#[test]
fn guest_presence_required_links_indices_and_schema_bounds_fail_closed() -> TestResult {
    let base = failure_input(Host::InvalidInvocation)?;
    for input in [
        Input {
            member_binding_digest: Hash::zero(),
            ..base
        },
        Input {
            invocation_id: Some([0; 16]),
            ..base
        },
        Input {
            prepared_invocation_digest: Some(Hash::zero()),
            ..base
        },
        Input {
            decision_provenance_digest: Hash::zero(),
            ..base
        },
        Input {
            guest_error: Some(guest_default()),
            ..base
        },
        Input {
            host_failure: Host::GuestDeclaredFailure,
            guest_error: None,
            ..base
        },
    ] {
        assert_eq!(Failure::new(input).err(), Some(Error::InvalidBinding));
    }
    for host in [
        Host::MissingFeature { index: 256 },
        Host::CapabilityDenied { index: usize::MAX },
    ] {
        assert_eq!(
            Failure::new(Input {
                host_failure: host,
                ..base
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            Failure::new(Input {
                evidence_not_after_micros: horizon,
                ..base
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    assert!(Failure::new(Input {
        evidence_not_after_micros: u64::MAX / 2,
        ..base
    })
    .is_ok());
    let long = [0; 129];
    let input = Input {
        guest_error: Some(Guest {
            canonical_coordinate: Some(&long),
            ..guest_default()
        }),
        ..failure_input(Host::GuestDeclaredFailure)?
    };
    assert_eq!(Failure::new(input).err(), Some(Error::BoundsExceeded));
    for id in ["", "Upper", "bad id", "é", &"a".repeat(129)] {
        let input = Input {
            guest_error: Some(Guest {
                code: GuestCode::CapabilityRequired(id),
                ..guest_default()
            }),
            ..failure_input(Host::GuestDeclaredFailure)?
        };
        assert_eq!(Failure::new(input).err(), Some(Error::InvalidBinding));
    }
    let id = "a".repeat(128);
    assert!(Failure::new(Input {
        guest_error: Some(Guest {
            code: GuestCode::CapabilityRequired(&id),
            ..guest_default()
        }),
        ..failure_input(Host::GuestDeclaredFailure)?
    })
    .is_ok());
    Ok(())
}

#[test]
fn unknown_host_codes_payloads_and_wrong_tuple_shapes_are_rejected() -> TestResult {
    for (value, error) in [
        (array(&[20]), Error::InvalidEncoding),
        (array(&[]), Error::InvalidEncoding),
        (array(&[0, 0]), Error::InvalidEncoding),
        (array(&[1, 5]), Error::InvalidEncoding),
        (array(&[2, 3]), Error::InvalidEncoding),
        (array(&[11, 7, 0]), Error::InvalidEncoding),
        (array(&[11, 0, 2]), Error::InvalidEncoding),
        (array(&[19, 2]), Error::InvalidEncoding),
        (array(&[4, 256]), Error::BoundsExceeded),
        (array(&[5, u64::MAX]), Error::BoundsExceeded),
    ] {
        assert_eq!(
            Failure::from_canonical_cbor(&encode(&fixture(value, Value::Null)?)?).err(),
            Some(error)
        );
    }
    // An out-of-range PMF1 index is rejected before decoding a later guest
    // payload, even when that payload is malformed.
    for code in [4, 5] {
        assert_eq!(
            Failure::from_canonical_cbor(&encode(&fixture(
                array(&[code, 256]),
                Value::Bool(true),
            )?)?)
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn unknown_guest_codes_noncanonical_payload_shapes_and_scalar_overflow_refuse() -> TestResult {
    for (code, error) in [
        (array(&[8]), Error::InvalidEncoding),
        (array(&[4, 0]), Error::InvalidEncoding),
        (
            array(&[0, u64::from(u32::MAX) + 1, 0]),
            Error::BoundsExceeded,
        ),
        (array(&[1, u64::from(u32::MAX) + 1]), Error::BoundsExceeded),
        (
            array(&[5, 0, u64::from(u16::MAX) + 1]),
            Error::BoundsExceeded,
        ),
        (array(&[7, u64::from(u16::MAX) + 1]), Error::BoundsExceeded),
        (
            Value::Array(vec![uint(2), Value::Text("a".repeat(129))]),
            Error::BoundsExceeded,
        ),
        (
            Value::Array(vec![uint(2), Value::Text("Upper".into())]),
            Error::InvalidBinding,
        ),
        (
            Value::Array(vec![uint(3), bytes(&[0; 31])]),
            Error::InvalidEncoding,
        ),
    ] {
        let guest = Value::Array(vec![code, Value::Null, Value::Null]);
        assert_eq!(
            Failure::from_canonical_cbor(&encode(&fixture(array(&[10]), guest)?)?).err(),
            Some(error)
        );
    }
    for (coordinate, digest, error) in [
        (bytes(&[0; 129]), Value::Null, Error::BoundsExceeded),
        (Value::Null, bytes(&[0; 31]), Error::InvalidEncoding),
    ] {
        let guest = Value::Array(vec![array(&[4]), coordinate, digest]);
        assert_eq!(
            Failure::from_canonical_cbor(&encode(&fixture(array(&[10]), guest)?)?).err(),
            Some(error)
        );
    }
    Ok(())
}

#[test]
fn invocation_failure_rejects_every_truncation_trailer_version_and_oversize() -> TestResult {
    let encoded = encode(&fixture(
        array(&[10]),
        Value::Array(vec![array(&[4]), Value::Null, Value::Null]),
    )?)?;
    for end in 0..encoded.len() {
        assert!(Failure::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Failure::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Failure::from_canonical_cbor(&nonpreferred).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = fixture(array(&[0]), Value::Null)?;
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Failure::from_canonical_cbor(&encode(&unsupported)?).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(
        Failure::from_canonical_cbor(&vec![0; 4097]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn pass_failures_keep_exact_host_value_nullable_pass_and_borrowed_cfi_order() -> TestResult {
    let digests = [hash(9), hash(8)];
    for (host, value) in host_cases() {
        for pass_present in [false, true] {
            let input = PassInput {
                pass_key: if pass_present { Some(pass()?) } else { None },
                invocation_evidence_digests: Digests::from_digests(&digests),
                host_failure: host,
                host_decision_provenance_digest: hash(7),
                evidence_not_after_micros: 8,
            };
            let failure = PassFailure::new(input)?;
            let expected = encode(&Value::Array(vec![
                bytes(b"CFO1"),
                uint(1),
                if pass_present {
                    bytes(&encode(&pass_value())?)
                } else {
                    Value::Null
                },
                Value::Array(vec![bytes(&[9; 32]), bytes(&[8; 32])]),
                value.clone(),
                bytes(&[7; 32]),
                uint(8),
            ]))?;
            assert_eq!(&*failure.to_canonical_cbor(), &expected);
            assert_eq!(
                failure.digest(),
                domain_hash(b"PiglorOS.Community.CFO1.v1", &expected)
            );
            let decoded = PassFailure::from_canonical_cbor(&expected)?;
            assert!(*decoded.as_input() == input);
            let rows = decoded
                .as_input()
                .invocation_evidence_digests
                .as_canonical_rows()
                .ok_or("missing borrowed CFI rows")?;
            let offset = rows.as_ptr() as usize - expected.as_ptr() as usize;
            assert!(offset + rows.len() <= expected.len());
            assert_eq!(&expected[offset..offset + rows.len()], rows);
        }
    }
    Ok(())
}

#[test]
fn pass_failure_bounds_links_and_wire_framing_refuse_without_fresh_retry() -> TestResult {
    let base = PassInput {
        pass_key: None,
        invocation_evidence_digests: Digests::from_digests(&[]),
        host_failure: Host::ArtifactRevoked {
            basis: Revocation::Artifact,
        },
        host_decision_provenance_digest: hash(7),
        evidence_not_after_micros: 8,
    };
    let encoded = PassFailure::new(base)?.to_canonical_cbor();
    assert!(PassFailure::from_canonical_cbor(&encoded)?
        .as_input()
        .invocation_evidence_digests
        .is_empty());
    let full = [hash(8); 64];
    let excess = [hash(8); 65];
    let zero = [Hash::zero()];
    assert!(PassFailure::new(PassInput {
        invocation_evidence_digests: Digests::from_digests(&full),
        ..base
    })
    .is_ok());
    assert_eq!(
        PassFailure::new(PassInput {
            invocation_evidence_digests: Digests::from_digests(&excess),
            ..base
        })
        .err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        PassFailure::new(PassInput {
            invocation_evidence_digests: Digests::from_digests(&zero),
            ..base
        })
        .err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        PassFailure::new(PassInput {
            host_decision_provenance_digest: Hash::zero(),
            ..base
        })
        .err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        PassFailure::new(PassInput {
            host_failure: Host::MissingFeature { index: 256 },
            ..base
        })
        .err(),
        Some(Error::BoundsExceeded)
    );
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        assert_eq!(
            PassFailure::new(PassInput {
                evidence_not_after_micros: horizon,
                ..base
            })
            .err(),
            Some(Error::BoundsExceeded)
        );
    }
    for end in 0..encoded.len() {
        assert!(PassFailure::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert_eq!(
        PassFailure::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut wide = encoded.to_vec();
    wide.splice(6..7, [0x18, 1]);
    assert_eq!(
        PassFailure::from_canonical_cbor(&wide).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = encoded.to_vec();
    unsupported[6] = 2;
    assert_eq!(
        PassFailure::from_canonical_cbor(&unsupported).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(
        PassFailure::from_canonical_cbor(&vec![0; 16_385]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
