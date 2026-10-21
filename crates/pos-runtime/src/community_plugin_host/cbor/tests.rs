//! R7-P9: one vector per head width the encoder emits, for each major type.

use super::*;

fn encoded(write: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out);
    out
}

#[test]
fn unsigned_integers_use_the_shortest_head() {
    let cases: [(u64, &[u8]); 12] = [
        (0, &[0x00]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65_535, &[0x19, 0xff, 0xff]),
        (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (67_108_864, &[0x1a, 0x04, 0x00, 0x00, 0x00]),
        (4_294_967_295, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
        (
            4_294_967_296,
            &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
        ),
        (
            u64::MAX,
            &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
        (1_000_000_000, &[0x1a, 0x3b, 0x9a, 0xca, 0x00]),
    ];
    for (value, expected) in cases {
        assert_eq!(encoded(|out| unsigned(out, value)), expected, "{value}");
    }
}

#[test]
fn booleans_are_one_byte_without_a_width() {
    assert_eq!(encoded(|out| boolean(out, true)), [0xf5]);
    assert_eq!(encoded(|out| boolean(out, false)), [0xf4]);
}

#[test]
fn text_lengths_use_the_shortest_head() {
    assert_eq!(encoded(|out| text(out, "")), [0x60]);
    assert_eq!(encoded(|out| text(out, "ab")), [0x62, b'a', b'b']);
    let short = "x".repeat(23);
    assert_eq!(encoded(|out| text(out, &short))[..1], [0x77]);
    let long = "x".repeat(24);
    let out = encoded(|out| text(out, &long));
    assert_eq!(out[..2], [0x78, 24]);
    assert_eq!(out.len(), 26);
    let widest_one_byte = "x".repeat(255);
    assert_eq!(
        encoded(|out| text(out, &widest_one_byte))[..2],
        [0x78, 0xff]
    );
    let two_bytes = "x".repeat(256);
    let out = encoded(|out| text(out, &two_bytes));
    assert_eq!(out[..3], [0x79, 0x01, 0x00]);
    assert_eq!(out.len(), 259);
}

#[test]
fn byte_string_lengths_use_the_shortest_head() {
    assert_eq!(encoded(|out| bytes(out, &[])), [0x40]);
    assert_eq!(encoded(|out| bytes(out, &[1, 2])), [0x42, 1, 2]);
    let digest = encoded(|out| bytes(out, &[0x11; 32]));
    assert_eq!(digest[..2], [0x58, 0x20]);
    assert_eq!(digest.len(), 34);
    let short = vec![0; 23];
    assert_eq!(encoded(|out| bytes(out, &short))[..1], [0x57]);
    let widest_one_byte = vec![0; 255];
    assert_eq!(
        encoded(|out| bytes(out, &widest_one_byte))[..2],
        [0x58, 0xff]
    );
    let two_bytes = vec![0; 256];
    let out = encoded(|out| bytes(out, &two_bytes));
    assert_eq!(out[..3], [0x59, 0x01, 0x00]);
    assert_eq!(out.len(), 259);
}

#[test]
fn array_heads_use_the_shortest_head() {
    assert_eq!(encoded(|out| array(out, 0)), [0x80]);
    assert_eq!(encoded(|out| array(out, 23)), [0x97]);
    assert_eq!(encoded(|out| array(out, 24)), [0x98, 24]);
    assert_eq!(encoded(|out| array(out, 255)), [0x98, 0xff]);
    assert_eq!(encoded(|out| array(out, 256)), [0x99, 0x01, 0x00]);
}

#[test]
fn the_wide_heads_of_every_major_type_are_encoded_by_one_routine() {
    let mut out = Vec::new();
    head(&mut out, UNSIGNED, 1 << 32);
    head(&mut out, BYTES, 1 << 32);
    head(&mut out, TEXT, 1 << 32);
    head(&mut out, ARRAY, 1 << 32);
    let wide = [0, 0, 0, 1, 0, 0, 0, 0];
    let expected: Vec<u8> = [0x1b_u8, 0x5b, 0x7b, 0x9b]
        .iter()
        .flat_map(|code| [&[*code][..], &wide[..]].concat())
        .collect();
    assert_eq!(out, expected);
}

#[test]
fn items_compose_into_a_definite_array() {
    let mut out = Vec::new();
    array(&mut out, 3);
    text(&mut out, "a");
    unsigned(&mut out, 1);
    boolean(&mut out, true);
    assert_eq!(out, [0x83, 0x61, b'a', 0x01, 0xf5]);
}
