use super::*;

#[test]
fn objects_sort_their_keys_bytewise_and_nest() {
    let inner = JsonV1::object([("z", JsonV1::text("x")), ("y", JsonV1::Number(18))]);
    let list = JsonV1::Array(vec![JsonV1::Number(0), JsonV1::Bool(false)]);
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
    assert_eq!(
        JsonV1::Number(u64::MAX).canonical(),
        b"18446744073709551615"
    );
}

#[test]
fn strings_escape_quote_backslash_and_controls_only() {
    let value = JsonV1::text("a\"b\\c\u{8}\t\n\u{c}\r\u{1}\u{1f} é/");
    assert_eq!(
        value.canonical(),
        "\"a\\\"b\\\\c\\b\\t\\n\\f\\r\\u0001\\u001f é/\"".as_bytes()
    );
}
