use core::convert::TryFrom;

use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, ControlRole, ControlState, OwnerBridgeCodecError,
    OwnerBridgeControlV1, CREATE_REPLY_BUFFER_CAPACITY, GET_REPLY_BUFFER_CAPACITY,
    REQUEST_BUFFER_CAPACITY,
};

const CEREMONY_ID: CeremonyId = CeremonyId::from_bytes([
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

#[test]
fn public_control_headers_round_trip_every_closed_state_and_accessor(
) -> Result<(), OwnerBridgeCodecError> {
    let request = OwnerBridgeControlV1::new_request(CeremonyKind::Create, 1, CEREMONY_ID, 1)?;
    assert_eq!(request.role(), ControlRole::Request);
    assert_eq!(request.kind(), CeremonyKind::Create);
    assert_eq!(request.generation(), 1);
    assert_eq!(request.ceremony_id(), CEREMONY_ID);
    assert_eq!(request.total_capacity(), REQUEST_BUFFER_CAPACITY);
    assert_eq!(request.payload_len(), 1);
    assert_eq!(request.state(), ControlState::Ready);
    assert_eq!(OwnerBridgeControlV1::decode(&request.encode()), Ok(request));

    for (kind, capacity) in [
        (CeremonyKind::Create, CREATE_REPLY_BUFFER_CAPACITY),
        (CeremonyKind::Get, GET_REPLY_BUFFER_CAPACITY),
    ] {
        let reply = OwnerBridgeControlV1::new_reply(kind, 2, CEREMONY_ID)?;
        assert_eq!(reply.role(), ControlRole::Reply);
        assert_eq!(reply.kind(), kind);
        assert_eq!(reply.total_capacity(), capacity);
        for (state, payload_len) in [
            (ControlState::Empty, 0),
            (ControlState::Writing, 0),
            (ControlState::Ready, 1),
            (ControlState::Consuming, 0),
            (ControlState::ReleaseRequested, 0),
            (ControlState::Releasing, 0),
            (ControlState::Failed, 0),
            (ControlState::Received, 0),
        ] {
            let transitioned = reply.with_reply_state(payload_len, state)?;
            assert_eq!(transitioned.state(), state);
            assert_eq!(
                OwnerBridgeControlV1::decode(&transitioned.encode()),
                Ok(transitioned)
            );
        }
    }
    Ok(())
}

#[test]
fn public_control_headers_reject_constructor_state_and_capacity_violations(
) -> Result<(), OwnerBridgeCodecError> {
    assert_eq!(
        OwnerBridgeControlV1::new_request(CeremonyKind::Get, 0, CEREMONY_ID, 1),
        Err(OwnerBridgeCodecError::InvalidControlBounds)
    );
    assert_eq!(
        OwnerBridgeControlV1::new_request(CeremonyKind::Get, 1, CEREMONY_ID, 0),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    assert_eq!(
        OwnerBridgeControlV1::new_request(CeremonyKind::Get, 1, CEREMONY_ID, 4_033),
        Err(OwnerBridgeCodecError::InvalidControlBounds)
    );
    assert_eq!(
        OwnerBridgeControlV1::new_reply(CeremonyKind::Get, 0, CEREMONY_ID),
        Err(OwnerBridgeCodecError::InvalidControlBounds)
    );

    let request = OwnerBridgeControlV1::new_request(CeremonyKind::Get, 1, CEREMONY_ID, 1)?;
    assert_eq!(
        request.with_reply_state(0, ControlState::Empty),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let reply = OwnerBridgeControlV1::new_reply(CeremonyKind::Get, 1, CEREMONY_ID)?;
    for state in [
        ControlState::Empty,
        ControlState::Received,
        ControlState::Failed,
    ] {
        assert_eq!(
            reply.with_reply_state(1, state),
            Err(OwnerBridgeCodecError::InvalidPayload)
        );
    }
    assert_eq!(
        reply.with_reply_state(0, ControlState::Ready),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
    assert_eq!(
        reply.with_reply_state(GET_REPLY_BUFFER_CAPACITY - 63, ControlState::Writing),
        Err(OwnerBridgeCodecError::InvalidControlBounds)
    );
    Ok(())
}

#[test]
fn public_control_header_decoder_rejects_tampered_fields() -> Result<(), OwnerBridgeCodecError> {
    assert_eq!(
        OwnerBridgeControlV1::decode(&[0; 63]),
        Err(OwnerBridgeCodecError::InvalidControlHeaderLength)
    );
    let baseline = OwnerBridgeControlV1::new_reply(CeremonyKind::Get, 1, CEREMONY_ID)?.encode();

    let cases: [(&str, usize, u8, OwnerBridgeCodecError); 7] = [
        ("magic", 0, b'X', OwnerBridgeCodecError::InvalidControlMagic),
        (
            "version",
            4,
            2,
            OwnerBridgeCodecError::InvalidControlVersion,
        ),
        ("reserved", 10, 1, OwnerBridgeCodecError::NonzeroReserved),
        ("flags", 44, 1, OwnerBridgeCodecError::NonzeroReserved),
        ("role", 8, 2, OwnerBridgeCodecError::InvalidControlValue),
        ("kind", 9, 2, OwnerBridgeCodecError::InvalidControlValue),
        ("state", 40, 8, OwnerBridgeCodecError::InvalidControlValue),
    ];
    for (label, offset, value, expected) in cases {
        let mut header = baseline;
        header[offset] = value;
        assert_eq!(
            OwnerBridgeControlV1::decode(&header),
            Err(expected),
            "{label}"
        );
    }

    let mut generation = baseline;
    generation[12..16].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(
        OwnerBridgeControlV1::decode(&generation),
        Err(OwnerBridgeCodecError::InvalidControlBounds)
    );

    let mut wrong_capacity = baseline;
    wrong_capacity[32..36].copy_from_slice(&REQUEST_BUFFER_CAPACITY.to_le_bytes());
    assert_eq!(
        OwnerBridgeControlV1::decode(&wrong_capacity),
        Err(OwnerBridgeCodecError::InvalidControlBounds)
    );

    let mut oversized_payload = baseline;
    oversized_payload[36..40].copy_from_slice(&GET_REPLY_BUFFER_CAPACITY.to_le_bytes());
    assert_eq!(
        OwnerBridgeControlV1::decode(&oversized_payload),
        Err(OwnerBridgeCodecError::InvalidControlBounds)
    );
    Ok(())
}

#[test]
fn public_control_enums_and_errors_have_closed_public_representations() {
    assert_eq!(ControlRole::try_from(0), Ok(ControlRole::Request));
    assert_eq!(ControlRole::try_from(1), Ok(ControlRole::Reply));
    assert_eq!(
        ControlRole::try_from(2),
        Err(OwnerBridgeCodecError::InvalidControlValue)
    );
    assert_eq!(CeremonyKind::try_from(0), Ok(CeremonyKind::Create));
    assert_eq!(CeremonyKind::try_from(1), Ok(CeremonyKind::Get));
    assert_eq!(
        CeremonyKind::try_from(2),
        Err(OwnerBridgeCodecError::InvalidControlValue)
    );
    assert_eq!(
        ControlState::try_from(8),
        Err(OwnerBridgeCodecError::InvalidControlValue)
    );

    let messages = [
        (
            OwnerBridgeCodecError::BufferTooSmall,
            "owner-bridge output buffer is too small",
        ),
        (
            OwnerBridgeCodecError::InvalidControlHeaderLength,
            "owner-bridge control header has an invalid length",
        ),
        (
            OwnerBridgeCodecError::InvalidControlMagic,
            "owner-bridge control header has an invalid magic",
        ),
        (
            OwnerBridgeCodecError::InvalidControlVersion,
            "owner-bridge control header has an invalid version",
        ),
        (
            OwnerBridgeCodecError::InvalidControlValue,
            "owner-bridge control header has an invalid value",
        ),
        (
            OwnerBridgeCodecError::NonzeroReserved,
            "owner-bridge input has a nonzero reserved field",
        ),
        (
            OwnerBridgeCodecError::InvalidControlBounds,
            "owner-bridge control header has invalid bounds",
        ),
        (
            OwnerBridgeCodecError::InvalidHttpRequest,
            "owner-bridge loopback HTTP request is invalid",
        ),
        (
            OwnerBridgeCodecError::InvalidCbor,
            "owner-bridge input is not valid deterministic CBOR",
        ),
        (
            OwnerBridgeCodecError::NonCanonicalCbor,
            "owner-bridge CBOR is not canonical",
        ),
        (
            OwnerBridgeCodecError::BoundsExceeded,
            "owner-bridge input exceeds a closed bound",
        ),
        (
            OwnerBridgeCodecError::TrailingBytes,
            "owner-bridge input has trailing bytes",
        ),
        (
            OwnerBridgeCodecError::InvalidPayload,
            "owner-bridge payload violates its closed schema",
        ),
    ];
    for (error, expected) in messages {
        assert_eq!(error.to_string(), expected);
    }
}
