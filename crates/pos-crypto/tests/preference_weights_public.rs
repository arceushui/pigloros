//! ADR-097 B4 `persona.preference_weights` plaintext grammar at its public seam.
//!
//! Every vector is literal CBOR written byte by byte, independently of the
//! grammar's encoder.

use pos_crypto::preference_weights::{
    validate_preference_weights, PreferenceWeightV1 as Weight, PreferenceWeightsErrorV1 as Error,
    PreferenceWeightsV1 as Weights, MAX_PREFERENCE_DIMENSIONS, MAX_PREFERENCE_DIMENSION_NAME_BYTES,
    MAX_PREFERENCE_WEIGHTS_PLAINTEXT_BYTES,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HALF_HALF: [u8; 3] = [0xf9, 0x38, 0x00];
const HALF_ONE: [u8; 3] = [0xf9, 0x3c, 0x00];

/// A one-entry map `{"a": [score, confidence]}` of raw float items.
fn single(score: &[u8], confidence: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa1, 0x61, b'a', 0x82];
    bytes.extend_from_slice(score);
    bytes.extend_from_slice(confidence);
    bytes
}

/// A definite text head and body for a name of at most 255 bytes.
fn text(name: &str) -> Vec<u8> {
    let length = u8::try_from(name.len()).unwrap_or(u8::MAX);
    let mut bytes = if length < 24 {
        vec![0x60 + length]
    } else {
        vec![0x78, length]
    };
    bytes.extend_from_slice(name.as_bytes());
    bytes
}

/// A map head for at most 255 entries.
fn map(entries: usize) -> Vec<u8> {
    let count = u8::try_from(entries).unwrap_or(u8::MAX);
    if count < 24 {
        vec![0xa0 + count]
    } else {
        vec![0xb8, count]
    }
}

/// A map of `names`, in the given order, each holding `[0.5, 1.0]`.
fn named(names: &[&str]) -> Vec<u8> {
    let mut bytes = map(names.len());
    for name in names {
        bytes.extend(text(name));
        bytes.push(0x82);
        bytes.extend_from_slice(&HALF_HALF);
        bytes.extend_from_slice(&HALF_ONE);
    }
    bytes
}

fn double(value: f64) -> Vec<u8> {
    let mut bytes = vec![0xfb];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes
}

/// The `index`th of 64 sorted 64-byte names.
fn long_name(index: usize) -> String {
    format!(
        "{}{index:02}",
        "n".repeat(MAX_PREFERENCE_DIMENSION_NAME_BYTES - 2)
    )
}

const fn weight(score: f64, confidence: f64) -> Weight {
    Weight { score, confidence }
}

fn rejected(plaintext: &[u8]) -> Option<Error> {
    let validated = validate_preference_weights(plaintext).err();
    assert_eq!(Weights::decode(plaintext).err(), validated);
    validated
}

#[test]
fn every_float_rule_rejects_its_vector() {
    let weight_error = Some(Error::Weight);
    for (score, confidence) in [
        // Not the shortest precision that holds the value: 0.5 as single and
        // double, 0.0 as single, 2^-24 as single, 0.1f32 and 2^-149 as double.
        (&[0xfa, 0x3f, 0x00, 0x00, 0x00][..], &HALF_ONE[..]),
        (&double(0.5)[..], &HALF_ONE[..]),
        (&HALF_HALF[..], &[0xfa, 0x00, 0x00, 0x00, 0x00][..]),
        (&HALF_HALF[..], &[0xfa, 0x33, 0x80, 0x00, 0x00][..]),
        (&double(f64::from(0.1_f32))[..], &HALF_ONE[..]),
        (&HALF_HALF[..], &double(2_f64.powi(-149))[..]),
        // Negative zero, in either position.
        (&[0xf9, 0x80, 0x00][..], &HALF_ONE[..]),
        (&HALF_HALF[..], &[0xf9, 0x80, 0x00][..]),
        // NaN and the infinities, in half and double precision.
        (&[0xf9, 0x7e, 0x00][..], &HALF_ONE[..]),
        (&double(f64::NAN)[..], &HALF_ONE[..]),
        (&[0xf9, 0x7c, 0x00][..], &HALF_ONE[..]),
        (&[0xf9, 0xfc, 0x00][..], &HALF_ONE[..]),
        (&HALF_HALF[..], &double(f64::INFINITY)[..]),
        // An integer, null, false or a tag where a float belongs.
        (&[0x01][..], &HALF_ONE[..]),
        (&[0x20][..], &HALF_ONE[..]),
        (&HALF_HALF[..], &[0x01][..]),
        (&[0xf6][..], &HALF_ONE[..]),
        (&HALF_HALF[..], &[0xf4][..]),
        (&[0xc1, 0xf9, 0x38, 0x00][..], &HALF_ONE[..]),
        // Out of range: score below -1 or above 1, confidence below 0 or above 1.
        (&[0xf9, 0xbe, 0x00][..], &HALF_ONE[..]),
        (&[0xf9, 0x3e, 0x00][..], &HALF_ONE[..]),
        (&double(1.0 + f64::EPSILON)[..], &HALF_ONE[..]),
        (&[0xfa, 0x49, 0x80, 0x00, 0x00][..], &HALF_ONE[..]),
        (&HALF_HALF[..], &[0xf9, 0xb8, 0x00][..]),
        (&HALF_HALF[..], &[0xf9, 0x3e, 0x00][..]),
        (&HALF_HALF[..], &double(-f64::from_bits(1))[..]),
    ] {
        assert_eq!(rejected(&single(score, confidence)), weight_error);
    }
}

#[test]
fn every_value_shape_rule_rejects_its_vector() {
    for value in [
        // An integer, a float or a map instead of the array.
        &[0x01][..],
        &HALF_HALF[..],
        &[0xa0][..],
        // One or three members, a tagged array, and an indefinite array.
        &[0x81, 0xf9, 0x38, 0x00][..],
        &[0x83, 0xf9, 0x38, 0x00, 0xf9, 0x38, 0x00, 0xf9, 0x38, 0x00][..],
        &[0xc1, 0x82, 0xf9, 0x38, 0x00, 0xf9, 0x3c, 0x00][..],
        &[0x9f, 0xf9, 0x38, 0x00, 0xf9, 0x3c, 0x00, 0xff][..],
        // Truncated before or inside each float.
        &[0x82][..],
        &[0x82, 0xf9, 0x38][..],
        &[0x82, 0xf9, 0x38, 0x00][..],
        &[0x82, 0xf9, 0x38, 0x00, 0xfb, 0x3f][..],
    ] {
        let mut plaintext = vec![0xa1, 0x61, b'a'];
        plaintext.extend_from_slice(value);
        assert_eq!(rejected(&plaintext), Some(Error::Weight));
    }
}

#[test]
fn every_key_rule_rejects_its_vector() {
    let too_long = "a".repeat(MAX_PREFERENCE_DIMENSION_NAME_BYTES + 1);
    for name in ["", too_long.as_str(), "A", "a.b", "a b", "\u{e9}", "a/"] {
        assert_eq!(rejected(&named(&[name])), Some(Error::DimensionName));
    }
    let weight = [0x82, 0xf9, 0x38, 0x00, 0xf9, 0x3c, 0x00];
    for key in [
        // An integer, a byte string, invalid UTF-8, an indefinite text and
        // a non-shortest text head; then a key cut short.
        &[0x01][..],
        &[0x41, b'a'][..],
        &[0x61, 0xff][..],
        &[0x7f, 0x61, b'a', 0xff][..],
        &[0x78, 0x01, b'a'][..],
    ] {
        let mut plaintext = vec![0xa1];
        plaintext.extend_from_slice(key);
        plaintext.extend_from_slice(&weight);
        assert_eq!(rejected(&plaintext), Some(Error::DimensionName));
    }
    assert_eq!(rejected(&[0xa1, 0x62, b'a']), Some(Error::DimensionName));
    assert_eq!(rejected(&[0xa1]), Some(Error::DimensionName));
}

#[test]
fn keys_must_be_unique_and_sorted_by_their_encoding() {
    let key_order = Some(Error::KeyOrder);
    let short = "a".repeat(23);
    let long = "a".repeat(24);
    // Unsorted bytes, unsorted length, a duplicate, and an encoding-order
    // pair across the one-byte to two-byte text head.
    assert_eq!(rejected(&named(&["b", "a"])), key_order);
    assert_eq!(rejected(&named(&["ab", "b"])), key_order);
    assert_eq!(rejected(&named(&["a", "a"])), key_order);
    assert_eq!(rejected(&named(&["a", "b", "b"])), key_order);
    assert_eq!(
        rejected(&named(&[long.as_str(), short.as_str()])),
        key_order
    );
    assert_eq!(validate_preference_weights(&named(&["b", "ab"])), Ok(()));
    assert_eq!(
        validate_preference_weights(&named(&[short.as_str(), long.as_str()])),
        Ok(())
    );
}

#[test]
fn entry_count_and_structure_rules_reject_their_vectors() {
    let mut names: Vec<String> = (0..=MAX_PREFERENCE_DIMENSIONS).map(long_name).collect();
    let over: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_eq!(rejected(&named(&over)), Some(Error::EntryCount));
    assert_eq!(rejected(&[0xa0]), Some(Error::EntryCount));
    names.pop();
    let most: Vec<&str> = names.iter().map(String::as_str).collect();
    assert_eq!(validate_preference_weights(&named(&most)), Ok(()));

    let valid = single(&HALF_HALF, &HALF_ONE);
    assert_eq!(validate_preference_weights(&valid), Ok(()));
    let mut tagged = vec![0xc0];
    tagged.extend_from_slice(&valid);
    let mut trailing = valid.clone();
    trailing.push(0x00);
    let mut indefinite = vec![0xbf];
    indefinite.extend_from_slice(&valid[1..]);
    indefinite.push(0xff);
    let mut non_shortest_head = vec![0xb8, 0x01];
    non_shortest_head.extend_from_slice(&valid[1..]);
    let mut array = vec![0x81];
    array.extend_from_slice(&valid);
    for plaintext in [
        tagged,
        trailing,
        indefinite,
        non_shortest_head,
        array,
        Vec::new(),
        vec![0xb8],
        vec![0x01],
    ] {
        assert_eq!(rejected(&plaintext), Some(Error::Encoding));
    }

    // The 8 KiB bound comes first: one byte over it is too large, and a
    // plaintext of exactly 8 KiB is read and fails only on its trailing bytes.
    let mut exact = valid;
    exact.resize(MAX_PREFERENCE_WEIGHTS_PLAINTEXT_BYTES, 0);
    assert_eq!(MAX_PREFERENCE_WEIGHTS_PLAINTEXT_BYTES, 8_192);
    assert_eq!(rejected(&exact), Some(Error::Encoding));
    exact.push(0);
    assert_eq!(rejected(&exact), Some(Error::TooLarge));
}

#[test]
fn boundary_floats_and_names_are_accepted_bit_for_bit() -> TestResult {
    let all_name_bytes = "abcdefghijklmnopqrstuvwxyz0123456789_-";
    let longest = long_name(0);
    for name in ["a", "-", "_", "9", all_name_bytes, longest.as_str()] {
        assert_eq!(validate_preference_weights(&named(&[name])), Ok(()));
    }
    for (score, confidence, value) in [
        // The domain's ends in half precision.
        (
            &[0xf9, 0xbc, 0x00][..],
            &[0xf9, 0x00, 0x00][..],
            weight(-1.0, 0.0),
        ),
        (&HALF_ONE[..], &HALF_ONE[..], weight(1.0, 1.0)),
        // Half subnormal, normal and eleven significant bits.
        (
            &[0xf9, 0x80, 0x01][..],
            &[0xf9, 0x03, 0xff][..],
            weight(-(2_f64.powi(-24)), 1023.0 * 2_f64.powi(-24)),
        ),
        (
            &[0xf9, 0x04, 0x00][..],
            &[0xf9, 0x38, 0x01][..],
            weight(2_f64.powi(-14), 0.5 + 2_f64.powi(-11)),
        ),
        // Single precision: twelve significant bits, below half range,
        // 0.1f32, the smallest normal and the smallest subnormal.
        (
            &[0xfa, 0x3f, 0x00, 0x10, 0x00][..],
            &[0xfa, 0x33, 0x00, 0x00, 0x00][..],
            weight(0.5 + 2_f64.powi(-12), 2_f64.powi(-25)),
        ),
        (
            &[0xfa, 0x3d, 0xcc, 0xcc, 0xcd][..],
            &[0xfa, 0x00, 0x80, 0x00, 0x00][..],
            weight(f64::from(0.1_f32), 2_f64.powi(-126)),
        ),
        (
            &[0xfa, 0x80, 0x00, 0x00, 0x01][..],
            &[0xfa, 0x00, 0x00, 0x00, 0x01][..],
            weight(-(2_f64.powi(-149)), 2_f64.powi(-149)),
        ),
        // Double precision: 0.1, below single range, and a double subnormal.
        (
            &double(0.1)[..],
            &double(2_f64.powi(-150))[..],
            weight(0.1, 2_f64.powi(-150)),
        ),
        (
            &double(-1.0 + f64::EPSILON / 2.0)[..],
            &double(f64::from_bits(1))[..],
            weight(-1.0 + f64::EPSILON / 2.0, f64::from_bits(1)),
        ),
    ] {
        let plaintext = single(score, confidence);
        let decoded = Weights::decode(&plaintext)?;
        let pairs: Vec<(&str, Weight)> = decoded.dimensions().collect();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "a");
        assert_eq!(pairs[0].1.score.to_bits(), value.score.to_bits());
        assert_eq!(pairs[0].1.confidence.to_bits(), value.confidence.to_bits());
        let typed = Weights::new(vec![("a".to_owned(), value)])?;
        assert_eq!(typed.encode().as_slice(), plaintext.as_slice());
        assert_eq!(typed, decoded);
    }
    Ok(())
}

#[test]
fn encoder_sorts_by_encoding_and_round_trips_byte_exact() -> TestResult {
    let typed = Weights::new(vec![
        ("ab".to_owned(), weight(-0.5, 0.0)),
        ("b".to_owned(), weight(0.1, 0.5)),
        ("aa".to_owned(), weight(0.0, 1.0)),
        ("a".to_owned(), weight(1.0, f64::from(0.1_f32))),
    ])?;
    let mut expected = vec![0xa4];
    for (name, score, confidence) in [
        ("a", &HALF_ONE[..], &[0xfa, 0x3d, 0xcc, 0xcc, 0xcd][..]),
        ("b", &double(0.1)[..], &HALF_HALF[..]),
        ("aa", &[0xf9, 0x00, 0x00][..], &HALF_ONE[..]),
        ("ab", &[0xf9, 0xb8, 0x00][..], &[0xf9, 0x00, 0x00][..]),
    ] {
        expected.extend(text(name));
        expected.push(0x82);
        expected.extend_from_slice(score);
        expected.extend_from_slice(confidence);
    }
    let encoded = typed.encode();
    assert_eq!(encoded.as_slice(), expected.as_slice());
    let decoded = Weights::decode(&encoded)?;
    assert_eq!(decoded, typed);
    assert_eq!(decoded.encode().as_slice(), expected.as_slice());
    let names: Vec<&str> = decoded.dimensions().map(|(name, _)| name).collect();
    assert_eq!(names, ["a", "b", "aa", "ab"]);
    assert_eq!(
        format!("{decoded:?}"),
        "PreferenceWeightsV1 { dimensions: 4, .. }"
    );
    let (_, first) = decoded.dimensions().next().ok_or("expected a dimension")?;
    assert_eq!(format!("{first:?}"), "PreferenceWeightV1(<redacted>)");
    Ok(())
}

#[test]
fn largest_weight_set_is_5442_bytes_and_round_trips() -> TestResult {
    let dimensions: Vec<(String, Weight)> = (0..MAX_PREFERENCE_DIMENSIONS)
        .rev()
        .map(|index| (long_name(index), weight(-0.1, 0.3)))
        .collect();
    let typed = Weights::new(dimensions)?;
    let mut expected = map(MAX_PREFERENCE_DIMENSIONS);
    for index in 0..MAX_PREFERENCE_DIMENSIONS {
        expected.extend(text(&long_name(index)));
        expected.push(0x82);
        expected.extend(double(-0.1));
        expected.extend(double(0.3));
    }
    assert_eq!(expected.len(), 5_442);
    assert_eq!(typed.encode().as_slice(), expected.as_slice());
    assert_eq!(Weights::decode(&expected)?, typed);
    Ok(())
}

#[test]
fn typed_weight_sets_obey_the_same_rules() {
    let valid = weight(0.5, 1.0);
    let entry = |name: &str, weight: Weight| (name.to_owned(), weight);
    let too_many: Vec<(String, Weight)> = (0..=MAX_PREFERENCE_DIMENSIONS)
        .map(|index| (long_name(index), valid))
        .collect();
    let too_long = "a".repeat(MAX_PREFERENCE_DIMENSION_NAME_BYTES + 1);
    for (dimensions, error) in [
        (Vec::new(), Error::EntryCount),
        (too_many, Error::EntryCount),
        (vec![entry("", valid)], Error::DimensionName),
        (vec![entry(&too_long, valid)], Error::DimensionName),
        (vec![entry("Upper", valid)], Error::DimensionName),
        (vec![entry("a", valid), entry("a", valid)], Error::KeyOrder),
        (vec![entry("a", weight(-0.0, 1.0))], Error::Weight),
        (vec![entry("a", weight(0.5, -0.0))], Error::Weight),
        (vec![entry("a", weight(f64::NAN, 1.0))], Error::Weight),
        (vec![entry("a", weight(0.5, f64::INFINITY))], Error::Weight),
        (vec![entry("a", weight(-1.5, 1.0))], Error::Weight),
        (vec![entry("a", weight(0.5, -0.5))], Error::Weight),
    ] {
        assert_eq!(Weights::new(dimensions).err(), Some(error));
    }
}

#[test]
fn rejections_are_payload_free_messages() {
    for (error, message) in [
        (
            Error::TooLarge,
            "preference weights plaintext exceeds 8 KiB",
        ),
        (
            Error::Encoding,
            "preference weights plaintext is not one deterministic CBOR map",
        ),
        (
            Error::EntryCount,
            "preference weights entry count is out of range",
        ),
        (Error::DimensionName, "preference dimension name is invalid"),
        (
            Error::KeyOrder,
            "preference dimension names are not unique and sorted",
        ),
        (Error::Weight, "preference weight is invalid"),
    ] {
        assert_eq!(error.to_string(), message);
    }
}
