use super::*;

#[test]
fn decode_reads_lowercase_pairs() {
    assert_eq!(decode(""), Some(Vec::new()));
    assert_eq!(decode("00ff7a"), Some(vec![0x00, 0xff, 0x7a]));
    assert_eq!(decode_array::<2>("0aF0"), None, "uppercase is refused");
}

#[test]
fn decode_refuses_odd_length_and_foreign_characters() {
    for text in ["0", "abc", "0g", "zz", "0 ", "+1", "é1"] {
        assert_eq!(decode(text), None, "{text}");
    }
}

#[test]
fn decode_array_requires_the_exact_length() {
    assert_eq!(decode_array::<2>("0aff"), Some([0x0a, 0xff]));
    assert_eq!(decode_array::<2>("0a"), None);
    assert_eq!(decode_array::<2>("0aff00"), None);
}

#[test]
fn encode_is_lowercase_and_inverts_decode() {
    let bytes = [0x00, 0x0f, 0xa5, 0xff];
    assert_eq!(encode(&bytes), "000fa5ff");
    assert_eq!(decode(&encode(&bytes)), Some(bytes.to_vec()));
    assert_eq!(encode(&[]), "");
}
