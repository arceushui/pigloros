use pos_owner_bridge_codec::{
    admit_loopback_http_request, validate_client_data_json, CeremonyKind,
    LoopbackRequestDisposition, OwnerBridgeCodecError,
};

const CHALLENGE: [u8; 32] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

const CREATE_CLIENT_DATA: &[u8] = b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}";
const GET_CLIENT_DATA: &[u8] = b"{\"type\":\"webauthn.get\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}";
const DOCUMENT_REQUEST: &[u8] = b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n";

#[test]
fn public_client_data_accepts_closed_strings_booleans_and_escaped_unknown_fields() {
    let create = b" { \"type\" : \"webauthn.create\" , \"challenge\" : \"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\" , \"origin\" : \"http:\\/\\/localhost:49291\" , \"unknown\" : \"\\uD83D\\uDE00\" , \"feature\" : true , \"crossOrigin\" : false } \n";
    assert_eq!(
        validate_client_data_json(create, CeremonyKind::Create, &CHALLENGE),
        Ok(())
    );
    assert_eq!(
        validate_client_data_json(GET_CLIENT_DATA, CeremonyKind::Get, &CHALLENGE),
        Ok(())
    );
}

#[test]
fn public_client_data_rejects_invalid_envelope_and_required_fields() {
    assert_eq!(
        validate_client_data_json(b"", CeremonyKind::Create, &CHALLENGE),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
    let invalid_inputs: [(&str, &[u8]); 9] = [
        ("invalid utf8", b"\xff"),
        ("array", b"[]"),
        ("empty object", b"{}"),
        (
            "missing type",
            b"{\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "missing challenge",
            b"{\"type\":\"webauthn.create\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "missing origin",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\"}",
        ),
        (
            "type boolean",
            b"{\"type\":false,\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "challenge boolean",
            b"{\"type\":\"webauthn.create\",\"challenge\":false,\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "origin boolean",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":false}",
        ),
    ];
    for (label, input) in invalid_inputs {
        assert_eq!(
            validate_client_data_json(input, CeremonyKind::Create, &CHALLENGE),
            Err(OwnerBridgeCodecError::InvalidPayload),
            "{label}"
        );
    }
    assert_eq!(
        validate_client_data_json(&[b'x'; 4_097], CeremonyKind::Create, &CHALLENGE),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
}

#[test]
fn public_client_data_rejects_closed_value_mismatches_and_duplicates() {
    let invalid_inputs: [(&str, &[u8]); 12] = [
        (
            "wrong ceremony type",
            b"{\"type\":\"webauthn.get\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "wrong challenge",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "escaped challenge",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj\\u0038\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "wrong origin",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"https://localhost:49291\"}",
        ),
        (
            "cross origin true",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"crossOrigin\":true}",
        ),
        (
            "cross origin string",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"crossOrigin\":\"false\"}",
        ),
        (
            "top origin",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"topOrigin\":false}",
        ),
        (
            "token binding",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"tokenBinding\":false}",
        ),
        (
            "duplicate raw key",
            b"{\"type\":\"webauthn.create\",\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "duplicate escaped key",
            b"{\"type\":\"webauthn.create\",\"\\u0074ype\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "unknown number",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":1}",
        ),
        (
            "unknown object",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":{}}",
        ),
    ];
    for (label, input) in invalid_inputs {
        assert_eq!(
            validate_client_data_json(input, CeremonyKind::Create, &CHALLENGE),
            Err(OwnerBridgeCodecError::InvalidPayload),
            "{label}"
        );
    }
}

#[test]
fn public_client_data_rejects_malformed_json_strings_and_trailing_content() {
    let invalid_inputs: [(&str, &[u8]); 9] = [
        (
            "invalid escape",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":\"\\q\"}",
        ),
        (
            "unpaired high surrogate",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":\"\\uD800\"}",
        ),
        (
            "unpaired low surrogate",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":\"\\uDC00\"}",
        ),
        (
            "control character",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":\"\n\"}",
        ),
        (
            "trailing comma",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",}",
        ),
        (
            "invalid member delimiter",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\";}",
        ),
        (
            "trailing bytes",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}x",
        ),
        (
            "unclosed string",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291}",
        ),
        (
            "non boolean literal",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":null}",
        ),
    ];
    for (label, input) in invalid_inputs {
        assert_eq!(
            validate_client_data_json(input, CeremonyKind::Create, &CHALLENGE),
            Err(OwnerBridgeCodecError::InvalidPayload),
            "{label}"
        );
    }
}

#[test]
fn public_client_data_exercises_every_json_escape_and_parser_rejection() {
    const UNKNOWN_VALUE_PREFIX: &[u8] = b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":";
    let escaped_key = r#"x\"\\\/\b\f\n\r\t\u00af\uABCD\uD83D\uDE00é"#;
    let duplicate_escaped_key = [
        br#"{"type":"webauthn.create","challenge":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","origin":"http://localhost:49291",""#,
        escaped_key.as_bytes(),
        br#"":"one",""#,
        escaped_key.as_bytes(),
        br#"":"two"}"#,
    ]
    .concat();
    assert_eq!(
        validate_client_data_json(&duplicate_escaped_key, CeremonyKind::Create, &CHALLENGE),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );

    let mut truncated_escape = Vec::from(UNKNOWN_VALUE_PREFIX);
    truncated_escape.extend_from_slice(b"\"\\");
    let mut truncated_unicode = Vec::from(UNKNOWN_VALUE_PREFIX);
    truncated_unicode.extend_from_slice(br#""\u001"#);
    let invalid_inputs: [(&str, &[u8]); 6] = [
        ("key without a string", b"{true:false}"),
        (
            "member without a colon",
            b"{\"type\" \"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
        ),
        (
            "truncated true literal",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":tru}",
        ),
        (
            "non-hex unicode escape",
            br#"{"type":"webauthn.create","challenge":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","origin":"http://localhost:49291","unknown":"\u00g0"}"#,
        ),
        (
            "high surrogate followed by a non-low surrogate",
            br#"{"type":"webauthn.create","challenge":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","origin":"http://localhost:49291","unknown":"\uD800\u0041"}"#,
        ),
        ("truncated unicode escape", &truncated_unicode),
    ];
    for (label, input) in invalid_inputs {
        assert_eq!(
            validate_client_data_json(input, CeremonyKind::Create, &CHALLENGE),
            Err(OwnerBridgeCodecError::InvalidPayload),
            "{label}"
        );
    }
    assert_eq!(
        validate_client_data_json(&truncated_escape, CeremonyKind::Create, &CHALLENGE),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
}

#[test]
fn public_http_admission_rejects_incomplete_and_wrong_required_requests() {
    let invalid_inputs: [(&str, &[u8]); 11] = [
        ("empty", b""),
        ("partial", b"GET /owner.html HTTP/1.1\r\n"),
        (
            "method",
            b"POST /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "version",
            b"GET /owner.html HTTP/1.0\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "missing host",
            b"GET /owner.html HTTP/1.1\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "wrong host",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "missing destination",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "wrong destination",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "missing mode",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\n\r\n",
        ),
        (
            "wrong mode",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: cors\r\n\r\n",
        ),
        (
            "lowercase host name",
            b"GET /owner.html HTTP/1.1\r\nhost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
    ];
    for (label, input) in invalid_inputs {
        assert_eq!(
            admit_loopback_http_request(input),
            Err(OwnerBridgeCodecError::InvalidHttpRequest),
            "{label}"
        );
    }
}

#[test]
fn public_http_admission_rejects_duplicate_body_and_pipelined_requests() {
    let invalid_inputs: [(&str, &[u8]); 7] = [
        (
            "duplicate host",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "duplicate destination",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "duplicate mode",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "content length",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\ncontent-length: 0\r\n\r\n",
        ),
        (
            "transfer encoding",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nTransfer-Encoding: chunked\r\n\r\n",
        ),
        (
            "pipelining",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\nGET /owner.html HTTP/1.1\r\n\r\n",
        ),
        (
            "malformed header",
            b"GET /owner.html HTTP/1.1\r\nHost localhost:49291\r\n\r\n",
        ),
    ];
    for (label, input) in invalid_inputs {
        assert_eq!(
            admit_loopback_http_request(input),
            Err(OwnerBridgeCodecError::InvalidHttpRequest),
            "{label}"
        );
    }
}

#[test]
fn public_http_admission_rejects_parser_limit_violations() {
    let mut long_request_line = Vec::from(b"GET /".as_slice());
    long_request_line.extend(core::iter::repeat_n(b'x', 251));
    long_request_line.extend_from_slice(
        b" HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
    );
    assert_eq!(
        admit_loopback_http_request(&long_request_line),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );

    let mut long_header_name = Vec::from(DOCUMENT_REQUEST);
    long_header_name.splice(
        long_header_name.len() - 2..long_header_name.len() - 2,
        core::iter::repeat_n(b'n', 33).chain(*b": x\r\n"),
    );
    assert_eq!(
        admit_loopback_http_request(&long_header_name),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );

    let mut long_header_value = Vec::from(DOCUMENT_REQUEST);
    long_header_value.splice(
        long_header_value.len() - 2..long_header_value.len() - 2,
        (*b"X: ")
            .into_iter()
            .chain(core::iter::repeat_n(b'v', 513))
            .chain(*b"\r\n"),
    );
    assert_eq!(
        admit_loopback_http_request(&long_header_value),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );

    let mut too_many_headers = Vec::from(DOCUMENT_REQUEST);
    for _ in 0..22 {
        too_many_headers.splice(
            too_many_headers.len() - 2..too_many_headers.len() - 2,
            b"X: y\r\n".iter().copied(),
        );
    }
    assert_eq!(
        admit_loopback_http_request(&too_many_headers),
        Err(OwnerBridgeCodecError::InvalidHttpRequest)
    );

    let mut oversized_block = Vec::from(DOCUMENT_REQUEST);
    oversized_block.extend(core::iter::repeat_n(b'x', 8_193));
    assert_eq!(
        admit_loopback_http_request(&oversized_block),
        Err(OwnerBridgeCodecError::BoundsExceeded)
    );
}

#[test]
fn public_http_admission_preserves_the_fixed_document_and_not_found_split() {
    assert_eq!(
        admit_loopback_http_request(DOCUMENT_REQUEST),
        Ok(LoopbackRequestDisposition::OwnerDocument)
    );
    assert_eq!(
        admit_loopback_http_request(
            b"GET /other HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nX-Unknown: accepted\r\n\r\n"
        ),
        Ok(LoopbackRequestDisposition::NotFound)
    );
    assert_eq!(
        validate_client_data_json(CREATE_CLIENT_DATA, CeremonyKind::Get, &CHALLENGE),
        Err(OwnerBridgeCodecError::InvalidPayload)
    );
}
