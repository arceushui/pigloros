//! Raw native wire faults retain ordinary decoding and guarded-work semantics.

use super::{
    encoded, fields, lifecycle, parity, record, replace_first, value, wire_bytes, Fallible, Guard,
    ReadError, Wire,
};
use ciborium::Value;
use pos_core::{KeyRegistryStateV1, KeyRoleV1};

fn unique_start(bytes: &[u8], needle: &[u8]) -> Fallible<usize> {
    assert_eq!(
        bytes
            .windows(needle.len())
            .filter(|part| *part == needle)
            .count(),
        1
    );
    bytes
        .windows(needle.len())
        .position(|part| part == needle)
        .ok_or_else(|| "unique native wire field missing".into())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn nested_string_segments_do_not_inherit_the_container_recursion_limit() -> Fallible<()> {
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    let bytes = encoded(&live)?;
    let mut baseline = Guard::new(1_024);
    assert_eq!(
        KeyRegistryStateV1::from_durable_cbor_with_read_guard(&bytes, &mut baseline)?,
        live
    );
    for (header, needle) in [
        (0x7f, encoded(&"a")?),
        (0x5f, encoded(&Value::Bytes(vec![0x52; 32]))?),
    ] {
        // Target the first owner when identities repeat, or the public key.
        let start = bytes
            .windows(needle.len())
            .position(|part| part == needle)
            .ok_or("native segment field missing")?;
        let mut nested = vec![header; 257];
        nested.extend_from_slice(&needle);
        nested.extend(std::iter::repeat_n(0xff, 257));
        let complete = replace_first(&bytes, &needle, &nested)?;
        // Acceptance is required, not merely agreement between two refusals.
        assert_eq!(parity(&complete)?, live);
        let mut guard = Guard::new(1_024);
        assert_eq!(
            KeyRegistryStateV1::from_durable_cbor_with_read_guard(&complete, &mut guard)?,
            live
        );
        assert_eq!(guard.remaining, baseline.remaining);
        // End the entire carrier before the final break, so later registry
        // fields cannot accidentally supply a missing segment terminator.
        let mut truncated = bytes[..start].to_vec();
        truncated.extend_from_slice(&nested[..nested.len() - 1]);
        assert_eq!(parity(&truncated), Err(ReadError::InvalidSnapshot));
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn native_key_byte_arrays_keep_exact_work_and_reject_invalid_elements() -> Fallible<()> {
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    let bytes = encoded(&live)?;
    let needle = encoded(&Value::Bytes(vec![0x52; 32]))?;
    let start = unique_start(&bytes, &needle)?;
    for (name, mode) in [
        ("definite", Wire::ByteArrays),
        ("indefinite", Wire::IndefiniteByteArrays),
    ] {
        let mut array = Vec::new();
        wire_bytes(&[0x52; 32], mode, &mut array)?;
        let complete = replace_first(&bytes, &needle, &array)?;
        assert_eq!(parity(&complete)?, live, "{name}");
        let mut guard = Guard::new(224); // independent one-live-signing inventory
        assert_eq!(
            KeyRegistryStateV1::from_durable_cbor_with_read_guard(&complete, &mut guard)?,
            live
        );
        assert_eq!(guard.remaining, 0);
        // Two identities cost22, then the private digest costs64. Stop before
        // array bytes0/15/31, or before the fixed copy after32 temporary bytes.
        for limit in [86, 101, 117, 118] {
            let mut refused = Guard::new(limit);
            assert_eq!(
                KeyRegistryStateV1::from_durable_cbor_with_read_guard(&complete, &mut refused),
                Err(ReadError::ReadRefused),
                "{name}, limit{limit}"
            );
            assert_eq!(refused.remaining, 0);
            assert!(refused.failed);
            let observed = refused.events.len();
            assert_eq!(
                KeyRegistryStateV1::from_durable_cbor_with_read_guard(&complete, &mut refused),
                Err(ReadError::ReadRefused)
            );
            assert_eq!(refused.events.len(), observed);
        }
        // Raw CBOR: declare32 bytes, then supply31 valid u8 elements. Ending
        // the whole input here prevents following registry fields hiding EOF.
        let mut prefix = if mode == Wire::ByteArrays {
            vec![0x98, 0x20]
        } else {
            vec![0x9f]
        };
        prefix.extend(std::iter::repeat_n([0x18, 0x52], 31).flatten());
        for tail in [&[][..], &[0x18][..], &[0xc3][..]] {
            let mut truncated = bytes[..start].to_vec();
            truncated.extend_from_slice(&prefix);
            truncated.extend_from_slice(tail);
            assert_eq!(
                parity(&truncated),
                Err(ReadError::InvalidSnapshot),
                "{name}, tail{tail:?}"
            );
        }
        let mut invalid = prefix;
        invalid.extend_from_slice(&[0x19, 0x01, 0x00]); //256 cannot be a u8
        if mode == Wire::IndefiniteByteArrays {
            invalid.push(0xff);
            let mut truncated = bytes[..start].to_vec();
            truncated.extend_from_slice(&array[..array.len() - 1]);
            assert_eq!(parity(&truncated), Err(ReadError::InvalidSnapshot));
        }
        assert_eq!(
            parity(&replace_first(&bytes, &needle, &invalid)?),
            Err(ReadError::InvalidSnapshot)
        );
    }
    Ok(())
}

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn ignored_native_containers_and_bignums_require_their_complete_wire_values() -> Fallible<()> {
    let live = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?
        .swap_remove(1)
        .0;
    let marker = Value::Text("selected-native-wire-fault".to_owned());
    let mut snapshot = value(&live)?;
    fields(record(&mut snapshot)?)?.push((Value::Text("extra".to_owned()), marker.clone()));
    let bytes = encoded(&snapshot)?;
    let needle = encoded(&marker)?;
    let start = unique_start(&bytes, &needle)?;
    // Nested record extras are accepted native fields, unlike root extras.
    // Each malformed value ends at the named gate, before any later fields.
    for (name, complete, truncated) in [
        ("string header", vec![0x7f, 0xff], vec![0x7f]),
        (
            "string chunk",
            vec![0x7f, 0x62, b'a', b'b', 0xff],
            vec![0x7f, 0x62, b'a'],
        ),
        ("array terminator", vec![0x9f, 0xff], vec![0x9f]),
        ("map value", vec![0xa1, 0x00, 0xf6], vec![0xa1, 0x00]),
        ("tag body header", vec![0xc2, 0x41, 0x01], vec![0xc2]),
        (
            "short bignum payload",
            vec![0xc2, 0x41, 0x01],
            vec![0xc2, 0x41],
        ),
    ] {
        let valid = replace_first(&bytes, &needle, &complete)?;
        assert_eq!(parity(&valid)?, live, "{name}");
        let mut guard = Guard::new(224);
        assert_eq!(
            KeyRegistryStateV1::from_durable_cbor_with_read_guard(&valid, &mut guard)?,
            live
        );
        assert_eq!(guard.remaining, 0); // ignored values allocate no carrier
        let mut invalid = bytes[..start].to_vec();
        invalid.extend_from_slice(&truncated);
        assert_eq!(parity(&invalid), Err(ReadError::InvalidSnapshot), "{name}");
    }
    Ok(())
}
