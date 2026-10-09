use pos_owner_bridge_codec::{
    admit_loopback_http_request, validate_client_data_json, CeremonyKind,
    LoopbackRequestDisposition, OwnerBridgeCodecError, VerificationReason as Reason,
    WebAuthnChallenge,
};

const CHALLENGE: WebAuthnChallenge = WebAuthnChallenge::from_bytes([
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
]);

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
        Err(Reason::Malformed)
    );
    let invalid_inputs: [(&str, &[u8], Reason); 9] = [
        ("invalid utf8", b"\xff", Reason::Malformed),
        ("array", b"[]", Reason::Malformed),
        ("empty object", b"{}", Reason::Malformed),
        (
            "missing type",
            b"{\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
            Reason::ClientDataType,
        ),
        (
            "missing challenge",
            b"{\"type\":\"webauthn.create\",\"origin\":\"http://localhost:49291\"}",
            Reason::Challenge,
        ),
        (
            "missing origin",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\"}",
            Reason::Origin,
        ),
        (
            "type boolean",
            b"{\"type\":false,\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
            Reason::ClientDataType,
        ),
        (
            "challenge boolean",
            b"{\"type\":\"webauthn.create\",\"challenge\":false,\"origin\":\"http://localhost:49291\"}",
            Reason::Challenge,
        ),
        (
            "origin boolean",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":false}",
            Reason::Origin,
        ),
    ];
    for (label, input, reason) in invalid_inputs {
        assert_eq!(
            validate_client_data_json(input, CeremonyKind::Create, &CHALLENGE),
            Err(reason),
            "{label}"
        );
    }
    assert_eq!(
        validate_client_data_json(&[b'x'; 4_097], CeremonyKind::Create, &CHALLENGE),
        Err(Reason::Malformed)
    );
}

#[test]
fn public_client_data_rejects_closed_value_mismatches_and_duplicates() {
    let invalid_inputs: [(&str, &[u8], Reason); 12] = [
        (
            "wrong ceremony type",
            b"{\"type\":\"webauthn.get\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
            Reason::ClientDataType,
        ),
        (
            "wrong challenge",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"http://localhost:49291\"}",
            Reason::Challenge,
        ),
        (
            "escaped challenge",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj\\u0038\",\"origin\":\"http://localhost:49291\"}",
            Reason::Challenge,
        ),
        (
            "wrong origin",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"https://localhost:49291\"}",
            Reason::Origin,
        ),
        (
            "cross origin true",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"crossOrigin\":true}",
            Reason::CrossOrigin,
        ),
        (
            "cross origin string",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"crossOrigin\":\"false\"}",
            Reason::CrossOrigin,
        ),
        (
            "top origin",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"topOrigin\":false}",
            Reason::CrossOrigin,
        ),
        (
            "token binding",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"tokenBinding\":false}",
            Reason::CrossOrigin,
        ),
        (
            "duplicate raw key",
            b"{\"type\":\"webauthn.create\",\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
            Reason::Malformed,
        ),
        (
            "duplicate escaped key",
            b"{\"type\":\"webauthn.create\",\"\\u0074ype\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
            Reason::Malformed,
        ),
        (
            "unknown number",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":1}",
            Reason::Malformed,
        ),
        (
            "unknown object",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":{}}",
            Reason::Malformed,
        ),
    ];
    for (label, input, reason) in invalid_inputs {
        assert_eq!(
            validate_client_data_json(input, CeremonyKind::Create, &CHALLENGE),
            Err(reason),
            "{label}"
        );
    }
}

#[test]
fn public_client_data_rejects_malformed_json_strings_and_trailing_content() {
    let invalid_inputs: [(&str, &[u8], Reason); 9] = [
        (
            "invalid escape",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":\"\\q\"}",
            Reason::Malformed,
        ),
        (
            "unpaired high surrogate",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":\"\\uD800\"}",
            Reason::Malformed,
        ),
        (
            "unpaired low surrogate",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":\"\\uDC00\"}",
            Reason::Malformed,
        ),
        (
            "control character",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":\"\n\"}",
            Reason::Malformed,
        ),
        (
            "trailing comma",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",}",
            Reason::Malformed,
        ),
        (
            "invalid member delimiter",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\";}",
            Reason::Malformed,
        ),
        (
            "trailing bytes",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}x",
            Reason::Malformed,
        ),
        (
            "unclosed string",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291}",
            Reason::Malformed,
        ),
        (
            "non boolean literal",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":null}",
            Reason::Malformed,
        ),
    ];
    for (label, input, reason) in invalid_inputs {
        assert_eq!(
            validate_client_data_json(input, CeremonyKind::Create, &CHALLENGE),
            Err(reason),
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
        Err(Reason::Malformed)
    );

    let mut truncated_escape = Vec::from(UNKNOWN_VALUE_PREFIX);
    truncated_escape.extend_from_slice(b"\"\\");
    let mut truncated_unicode = Vec::from(UNKNOWN_VALUE_PREFIX);
    truncated_unicode.extend_from_slice(br#""\u001"#);
    let invalid_inputs: [(&str, &[u8], Reason); 7] = [
        ("key without a string", b"{true:false}", Reason::Malformed),
        (
            "member without a colon",
            b"{\"type\" \"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\"}",
            Reason::Malformed,
        ),
        (
            "truncated true literal",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":tru}",
            Reason::Malformed,
        ),
        (
            "truncated false literal",
            b"{\"type\":\"webauthn.create\",\"challenge\":\"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8\",\"origin\":\"http://localhost:49291\",\"unknown\":fal}",
            Reason::Malformed,
        ),
        (
            "non-hex unicode escape",
            br#"{"type":"webauthn.create","challenge":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","origin":"http://localhost:49291","unknown":"\u00g0"}"#,
            Reason::Malformed,
        ),
        (
            "high surrogate followed by a non-low surrogate",
            br#"{"type":"webauthn.create","challenge":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","origin":"http://localhost:49291","unknown":"\uD800\u0041"}"#,
            Reason::Malformed,
        ),
        (
            "truncated unicode escape",
            &truncated_unicode,
            Reason::Malformed,
        ),
    ];
    for (label, input, reason) in invalid_inputs {
        assert_eq!(
            validate_client_data_json(input, CeremonyKind::Create, &CHALLENGE),
            Err(reason),
            "{label}"
        );
    }
    assert_eq!(
        validate_client_data_json(&truncated_escape, CeremonyKind::Create, &CHALLENGE),
        Err(Reason::Malformed)
    );
}

#[test]
fn public_http_admission_rejects_incomplete_and_wrong_required_requests() {
    let invalid_inputs: [(&str, &[u8]); 10] = [
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
    let invalid_inputs: [(&str, &[u8]); 10] = [
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
            "case-variant duplicate host",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nhost: attacker.example\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "case-variant duplicate destination",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nsec-fetch-dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n",
        ),
        (
            "case-variant duplicate mode",
            b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nsec-fetch-mode: navigate\r\n\r\n",
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
fn public_http_admission_accepts_case_insensitive_required_header_names() {
    assert_eq!(
        admit_loopback_http_request(
            b"GET /owner.html HTTP/1.1\r\nhOsT: localhost:49291\r\nsec-fetch-dest: document\r\nSEC-FETCH-MODE: navigate\r\n\r\n"
        ),
        Ok(LoopbackRequestDisposition::OwnerDocument)
    );
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
        Err(Reason::ClientDataType)
    );
}

const MEMBER_PREFIX: &str = r#"{"type":"webauthn.create","challenge":"ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8","origin":"http://localhost:49291""#;

#[test]
fn public_client_data_enforces_the_exact_size_limit() {
    let mut padded = CREATE_CLIENT_DATA.to_vec();
    padded.resize(4_096, b' ');
    assert_eq!(
        validate_client_data_json(&padded, CeremonyKind::Create, &CHALLENGE),
        Ok(())
    );
    padded.push(b' ');
    assert_eq!(
        validate_client_data_json(&padded, CeremonyKind::Create, &CHALLENGE),
        Err(Reason::Malformed)
    );
}

#[test]
fn public_client_data_unescapes_keys_to_the_scalars_they_name() {
    let equal_pairs = [
        (r"\b", r"\u0008"),
        (r"\f", r"\u000c"),
        (r"\n", r"\u000a"),
        (r"\r", r"\u000d"),
        (r"\t", r"\u0009"),
        (r"\uD83D\uDE00", "\u{1F600}"),
        (r"\u00af", r"\u00AF"),
        (r"\u00af", "\u{af}"),
        (r"\u00AF", "\u{af}"),
    ];
    for (escaped, other) in equal_pairs {
        let input = format!(r#"{MEMBER_PREFIX},"{escaped}":true,"{other}":true}}"#);
        assert_eq!(
            validate_client_data_json(input.as_bytes(), CeremonyKind::Create, &CHALLENGE),
            Err(Reason::Malformed),
            "{escaped}"
        );
    }
    let distinct_keys = [r"\uD83D\uDE00", r"\u00af", r"\u00AF", r"\u0aF0", r"\n"];
    for key in distinct_keys {
        let input = format!(r#"{MEMBER_PREFIX},"{key}":true}}"#);
        assert_eq!(
            validate_client_data_json(input.as_bytes(), CeremonyKind::Create, &CHALLENGE),
            Ok(()),
            "{key}"
        );
    }
}
