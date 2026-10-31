use super::*;

fn number(value: u64) -> JsonV1 {
    JsonIntegerV1::new(value).map_or(JsonV1::Null, JsonV1::Number)
}

#[test]
fn objects_sort_their_keys_and_nest() {
    let inner = JsonV1::object([("z", JsonV1::text("x")), ("y", number(18))]);
    let list = JsonV1::Array(vec![number(0), JsonV1::Bool(false)]);
    let value = JsonV1::object([("b", JsonV1::Bool(true)), ("a", list), ("B", inner)]);
    assert_eq!(
        value.canonical(),
        br#"{"B":{"y":18,"z":"x"},"a":[0,false],"b":true}"#
    );
}

#[test]
fn the_line_ends_with_one_lf_and_empty_containers_are_compact() {
    assert_eq!(JsonV1::Array(Vec::new()).line(), b"[]\n");
    assert_eq!(JsonV1::Object(Vec::new()).line(), b"{}\n");
    assert_eq!(number(JsonIntegerV1::MAX).canonical(), b"9007199254740992");
}

#[test]
fn strings_escape_quote_backslash_and_controls_only() {
    let value = JsonV1::text("a\"b\\c\u{8}\t\n\u{c}\r\u{1}\u{1f} é/");
    assert_eq!(
        value.canonical(),
        "\"a\\\"b\\\\c\\b\\t\\n\\f\\r\\u0001\\u001f é/\"".as_bytes()
    );
}

#[test]
fn keys_sort_by_utf16_code_units_and_null_is_written() {
    // U+1F600 is the surrogate pair D83D DE00, which sorts before U+E000 in UTF-16 although
    // its UTF-8 encoding sorts after it.
    let value = JsonV1::object([
        ("\u{e000}", JsonV1::Null),
        ("\u{1f600}", JsonV1::Bool(true)),
    ]);
    assert_eq!(
        value.canonical(),
        "{\"\u{1f600}\":true,\"\u{e000}\":null}".as_bytes()
    );
}

#[test]
fn the_reader_accepts_exactly_the_canonical_encoding() {
    let canonical = br#"{"a":[null,true,false,7,"x"],"b":{}}"#;
    let parsed = JsonV1::parse_canonical(canonical);
    assert_eq!(
        parsed,
        Some(JsonV1::object([
            (
                "a",
                JsonV1::Array(vec![
                    JsonV1::Null,
                    JsonV1::Bool(true),
                    JsonV1::Bool(false),
                    number(7),
                    JsonV1::text("x"),
                ]),
            ),
            ("b", JsonV1::Object(Vec::new())),
        ]))
    );
    for refused in [
        &br#"{"b":{},"a":[]}"#[..],
        br#"{"a":[], "b":{}}"#,
        br#"{"a":1,"a":2}"#,
        br#"{"a":"\u0041"}"#,
        br#"{"a":-1}"#,
        br#"{"a":1.5}"#,
        br#"{"a":1e2}"#,
        br#"[{"a":-1}]"#,
        br#"{"a""#,
        b"",
    ] {
        assert_eq!(JsonV1::parse_canonical(refused), None);
    }
}

#[test]
fn members_arrays_text_and_booleans_are_read_closed() {
    let object = JsonV1::object([("b", JsonV1::Bool(false)), ("a", JsonV1::text("t"))]);
    assert_eq!(
        object.clone().into_members(["a", "b"]),
        Some([JsonV1::text("t"), JsonV1::Bool(false)])
    );
    assert_eq!(object.clone().into_members(["a"]), None);
    assert_eq!(object.clone().into_members(["a", "c"]), None);
    assert_eq!(object.into_members(["a", "a"]), None);
    assert_eq!(JsonV1::Null.into_members(["a"]), None);
    assert_eq!(
        JsonV1::Array(vec![JsonV1::Null]).into_array(),
        Some(vec![JsonV1::Null])
    );
    assert_eq!(JsonV1::Null.into_array(), None);
    assert_eq!(JsonV1::text("t").into_text(), Some("t".to_owned()));
    assert_eq!(JsonV1::Null.into_text(), None);
    assert_eq!(JsonV1::Bool(true).as_bool(), Some(true));
    assert_eq!(JsonV1::Null.as_bool(), None);
}

#[test]
fn integers_above_two_to_the_53_are_refused_by_the_writer_and_the_reader() {
    assert_eq!(JsonIntegerV1::MAX, 1 << 53);
    assert_eq!(
        JsonIntegerV1::new(JsonIntegerV1::MAX).map(JsonIntegerV1::get),
        Ok(JsonIntegerV1::MAX)
    );
    for above in [JsonIntegerV1::MAX + 1, u64::MAX] {
        assert_eq!(JsonIntegerV1::new(above), Err(JsonIntegerRangeErrorV1));
    }
    assert_eq!(
        JsonIntegerRangeErrorV1.to_string(),
        "JSON integer is above 2^53"
    );
    assert_eq!(
        JsonV1::parse_canonical(b"[9007199254740992]"),
        Some(JsonV1::Array(vec![number(JsonIntegerV1::MAX)]))
    );
    for refused in [&b"[9007199254740993]"[..], b"[18446744073709551615]"] {
        assert_eq!(JsonV1::parse_canonical(refused), None);
    }
}
