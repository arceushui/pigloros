//! The CBOR item scanner that finds a reply's PRF item, and the codec-error mapping.

use std::ops::Range;

use pos_owner_bridge_codec::OwnerBridgeCodecError;

use super::{
    head, prf_span, protocol_from_codec, replace_prf, skip_item, PRF_NULL, PRF_PLACEHOLDER,
};
use crate::{BridgeError, ProtocolCode};

const fn protocol(code: ProtocolCode) -> BridgeError {
    BridgeError::Protocol(code)
}

/// A CBOR head for `major` and `value`, in its shortest form.
fn head_bytes(major: u8, value: usize) -> Vec<u8> {
    let major = major << 5;
    let low = u8::try_from(value).unwrap_or(u8::MAX);
    if value < 24 {
        vec![major | low]
    } else if value < 256 {
        vec![major | 0x18, low]
    } else if value < 65_536 {
        let wide = u16::try_from(value).unwrap_or(0);
        [vec![major | 0x19], wide.to_be_bytes().to_vec()].concat()
    } else {
        let wide = u32::try_from(value).unwrap_or(0);
        [vec![major | 0x1a], wide.to_be_bytes().to_vec()].concat()
    }
}

/// `payload` with its first byte replaced.
fn with_first(payload: &[u8], first: u8) -> Vec<u8> {
    [vec![first], payload.get(1..).unwrap_or_default().to_vec()].concat()
}

fn bstr(length: usize) -> Vec<u8> {
    [head_bytes(2, length), vec![7; length]].concat()
}

/// A ten-item reply whose first eight items are byte strings of `length` bytes.
fn reply(length: usize, prf_item: &[u8]) -> (Vec<u8>, Range<usize>) {
    let mut payload = vec![0x8a];
    for _ in 0..8 {
        payload.extend(bstr(length));
    }
    let start = payload.len();
    payload.extend_from_slice(prf_item);
    let end = payload.len();
    payload.push(0xf6);
    (payload, start..end)
}

#[test]
fn a_codec_failure_maps_to_its_protocol_code() {
    assert_eq!(
        protocol_from_codec(OwnerBridgeCodecError::NonCanonicalCbor),
        protocol(ProtocolCode::NonCanonical)
    );
    for bounds in [
        OwnerBridgeCodecError::BoundsExceeded,
        OwnerBridgeCodecError::BufferTooSmall,
        OwnerBridgeCodecError::InvalidControlBounds,
    ] {
        assert_eq!(
            protocol_from_codec(bounds),
            protocol(ProtocolCode::LengthOutOfBounds)
        );
    }
    assert_eq!(
        protocol_from_codec(OwnerBridgeCodecError::InvalidCbor),
        protocol(ProtocolCode::Malformed)
    );
}

#[test]
fn a_head_reads_every_argument_width_the_replies_use() {
    assert_eq!(head(&[0x0a], 0), Some((0, 10, 1)));
    assert_eq!(head(&[0x18, 0x64], 0), Some((0, 100, 2)));
    assert_eq!(head(&[0x59, 0x01, 0x2c], 0), Some((2, 300, 3)));
    assert_eq!(
        head(&[0x1a, 0x00, 0x01, 0x00, 0x00], 0),
        Some((0, 65_536, 5))
    );
    assert_eq!(head(&[0xff, 0x41], 1), Some((2, 1, 2)));
}

#[test]
fn a_head_that_is_unsupported_or_truncated_is_refused() {
    assert_eq!(head(&[], 0), None);
    assert_eq!(head(&[0x0a], 1), None);
    assert_eq!(head(&[0x18], 0), None);
    assert_eq!(head(&[0x19, 0x01], 0), None);
    assert_eq!(head(&[0x1a, 0, 0, 0], 0), None);
    assert_eq!(head(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 1], 0), None);
    assert_eq!(head(&[0x1c], 0), None);
    assert_eq!(head(&[0x1f], 0), None);
}

#[test]
fn an_item_is_skipped_to_its_end() {
    let cases: [(&[u8], Option<usize>); 17] = [
        (&[0x05], Some(1)),
        (&[0x18, 0x05], Some(2)),
        (&[0x20], Some(1)),
        (&[0x42, 1, 2], Some(3)),
        (&[0x42, 1], None),
        (&[0x61, b'a'], Some(2)),
        (&[0x82, 0x01, 0x02], Some(3)),
        (&[0x80], Some(1)),
        (&[0x81, 0x81, 0x01], None),
        (&[0x87, 1, 2, 3, 4, 5, 6, 7], None),
        (&[0x86, 1, 2, 3, 4, 5, 6], Some(7)),
        (&[0xf4], Some(1)),
        (&[0xf5], Some(1)),
        (&[0xf6], Some(1)),
        (&[0xf7], None),
        (&[0xf8, 0x14], None),
        (&[0xa0], None),
    ];
    for (input, expected) in cases {
        assert_eq!(skip_item(input, 0, 0), expected, "{input:02x?}");
    }
    assert_eq!(skip_item(&[0xc0, 0x01], 0, 0), None);
    assert_eq!(skip_item(&[0xf9, 0, 0], 0, 0), None);
    assert_eq!(skip_item(&[0xf6, 0xf5], 1, 0), Some(2));
    assert_eq!(skip_item(&[0x41, 1], 0, 0), Some(2));
    assert_eq!(skip_item(&[0x59, 0xff, 0xff], 0, 0), None);
}

#[test]
fn the_prf_item_is_found_behind_every_head_width() {
    let items: [&[u8]; 4] = [
        &PRF_NULL,
        &PRF_PLACEHOLDER,
        &[0x63, b'a', b'b', b'c'],
        &[0x80],
    ];
    for length in [5, 23, 24, 100, 255, 256, 300, 65_535, 65_536] {
        for item in items {
            let (payload, span) = reply(length, item);
            assert_eq!(prf_span(&payload), Some(span), "{length} {item:02x?}");
        }
    }
}

#[test]
fn the_prf_item_is_found_behind_the_create_reply_transports() {
    let mut payload = vec![0x8a];
    for _ in 0..6 {
        payload.extend(bstr(3));
    }
    payload.extend([0x83, 0x00, 0x01, 0x02, 0xf5]);
    let start = payload.len();
    payload.extend(PRF_NULL);
    payload.push(0xf6);
    assert_eq!(prf_span(&payload), Some(start..start + 1));
}

#[test]
fn a_payload_that_is_not_a_ten_item_reply_has_no_prf_span() {
    let (payload, span) = reply(5, &PRF_NULL);
    assert!(prf_span(&payload).is_some());
    for first in [0x89, 0x8b, 0x4a] {
        assert_eq!(prf_span(&with_first(&payload, first)), None, "{first:#x}");
    }
    assert_eq!(prf_span(&[]), None);
    assert_eq!(prf_span(&[0x8a]), None);
    let (with_map, _) = reply(5, &[0xa0]);
    assert_eq!(prf_span(&with_map), None);
    assert_eq!(
        prf_span(payload.get(..span.start).unwrap_or_default()),
        None
    );
}

#[test]
fn replacing_the_prf_item_changes_only_that_item() {
    let (payload, span) = reply(9, &PRF_NULL);
    let swapped = replace_prf(&payload, &PRF_PLACEHOLDER);
    let expected = [
        payload.get(..span.start).unwrap_or_default(),
        &PRF_PLACEHOLDER,
        payload.get(span.end..).unwrap_or_default(),
    ]
    .concat();
    assert_eq!(swapped, Some(expected));
    assert_eq!(replace_prf(&[0x80], &PRF_NULL), None);
    let (long, _) = reply(300, &PRF_PLACEHOLDER);
    assert_eq!(
        replace_prf(&long, &PRF_NULL).map(|bytes| bytes.len()),
        Some(long.len() - 33)
    );
}
