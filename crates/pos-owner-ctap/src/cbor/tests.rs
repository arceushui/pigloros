use super::{decode, decode_prefix, Value, Writer, MAX_DEPTH};

#[test]
fn the_writer_uses_the_shortest_heads_and_the_reader_reads_them_back() {
    let long = [0x5a; 300];
    let encoded = Writer::default()
        .map(4)
        .unsigned(23)
        .unsigned(24)
        .unsigned(255)
        .unsigned(256)
        .negative(6)
        .bytes(&long)
        .text("id")
        .array(2)
        .boolean(true)
        .boolean(false)
        .finish();
    assert_eq!(encoded[..6], [0xa4, 0x17, 0x18, 0x18, 0x18, 0xff]);
    assert_eq!(encoded[6..10], [0x19, 0x01, 0x00, 0x26]);
    assert_eq!(encoded[10..13], [0x59, 0x01, 0x2c]);
    let value = decode(&encoded);
    let expected = Value::Map(vec![
        (Value::Unsigned(23), Value::Unsigned(24)),
        (Value::Unsigned(255), Value::Unsigned(256)),
        (Value::Negative(6), Value::Bytes(&long)),
        (
            Value::Text("id"),
            Value::Array(vec![Value::Bool(true), Value::Bool(false)]),
        ),
    ]);
    assert_eq!(value, Some(expected));
}

#[test]
fn the_writer_covers_every_argument_width() {
    let encoded = Writer::default()
        .array(3)
        .unsigned(0x1_0000)
        .unsigned(0xffff_ffff)
        .unsigned(0x1_0000_0000)
        .finish();
    assert_eq!(encoded[..6], [0x83, 0x1a, 0x00, 0x01, 0x00, 0x00]);
    assert_eq!(encoded[6..11], [0x1a, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(encoded[11..], [0x1b, 0, 0, 0, 0x01, 0, 0, 0, 0]);
    let values = decode(&encoded).map(|value| {
        value
            .items()
            .iter()
            .filter_map(Value::unsigned)
            .collect::<Vec<_>>()
    });
    assert_eq!(values, Some(vec![0x1_0000, 0xffff_ffff, 0x1_0000_0000]));
}

#[test]
fn the_reader_accepts_every_argument_width_without_requiring_canonical_form() {
    let wide: [&[u8]; 4] = [
        &[0x18, 0x05],
        &[0x19, 0x00, 0x05],
        &[0x1a, 0x00, 0x00, 0x00, 0x05],
        &[0x1b, 0, 0, 0, 0, 0, 0, 0, 0x05],
    ];
    for encoded in wide {
        assert_eq!(decode(encoded), Some(Value::Unsigned(5)), "{encoded:?}");
    }
    assert_eq!(decode(&[0x19, 0x01, 0x02]), Some(Value::Unsigned(258)));
    let wide = [0x1b, 0x01, 0, 0, 0, 0, 0, 0, 0x02];
    assert_eq!(decode(&wide), Some(Value::Unsigned((1 << 56) + 2)));
    assert_eq!(decode(&[0x20]), Some(Value::Negative(0)));
    assert_eq!(decode(&[0xf6]), Some(Value::Null));
    assert_eq!(decode(&[0x62, b'h', b'i']), Some(Value::Text("hi")));
}

#[test]
fn the_reader_refuses_what_ctap2_output_never_contains() {
    let refused: [&[u8]; 14] = [
        &[],
        &[0x1c],
        &[0x5f, 0xff],
        &[0x9f, 0xff],
        &[0xc0, 0x00],
        &[0xf7],
        &[0xf9, 0x00, 0x14],
        &[0x18],
        &[0x42, 0x01],
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        &[0x61, 0xff],
        &[0x81],
        &[0xa1],
        &[0xa1, 0x01],
    ];
    for encoded in refused {
        assert_eq!(decode(encoded), None, "{encoded:?}");
    }
}

#[test]
fn the_reader_refuses_duplicate_keys_in_any_encoding() {
    assert_eq!(decode(&[0xa2, 0x01, 0x01, 0x01, 0x02]), None);
    assert_eq!(decode(&[0xa2, 0x01, 0x00, 0x18, 0x01, 0x00]), None);
    assert!(decode(&[0xa2, 0x01, 0x00, 0x02, 0x00]).is_some());
}

#[test]
fn nesting_is_bounded_for_arrays_and_maps() {
    let mut deepest = vec![0x81; MAX_DEPTH];
    deepest.push(0x00);
    assert!(decode(&deepest).is_some());
    let mut too_deep = vec![0x81; MAX_DEPTH + 1];
    too_deep.push(0x00);
    assert_eq!(decode(&too_deep), None);
    let mut deep_map = vec![0x81; MAX_DEPTH];
    deep_map.extend_from_slice(&[0xa1, 0x00, 0x00]);
    assert_eq!(decode(&deep_map), None);
}

#[test]
fn decode_needs_the_whole_input_and_decode_prefix_reports_its_length() {
    assert_eq!(decode(&[0x01, 0x02]), None);
    assert_eq!(decode_prefix(&[0x01, 0x02]), Some((Value::Unsigned(1), 1)));
}

#[test]
fn the_accessors_answer_only_for_their_own_type() {
    let map = Value::Map(vec![
        (Value::Unsigned(1), Value::Bytes(&[7])),
        (Value::Text("k"), Value::Unsigned(9)),
    ]);
    assert_eq!(map.int(1).and_then(Value::bytes), Some(&[7][..]));
    assert_eq!(map.text_key("k").and_then(Value::unsigned), Some(9));
    assert_eq!(map.int(2), None);
    assert_eq!(map.bytes(), None);
    assert_eq!(map.unsigned(), None);
    assert!(map.items().is_empty());
    assert_eq!(Value::Unsigned(1).int(1), None);
    let array = Value::Array(vec![Value::Null]);
    assert_eq!(array.items(), [Value::Null]);
}
