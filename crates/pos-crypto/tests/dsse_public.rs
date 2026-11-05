#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use ed25519_dalek::SigningKey;
use pos_crypto::dsse::{
    key_id_v1, pae_v1, DsseEnvelopeV1, DsseParseErrorV1, DsseSignatureErrorV1,
    IN_TOTO_PAYLOAD_TYPE_V1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const BOUND: usize = 4096;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[test]
fn pae_matches_the_dsse_protocol_test_vector() {
    assert_eq!(
        pae_v1("http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    );
    assert_eq!(pae_v1("", b""), b"DSSEv1 0  0 ");
}

#[test]
fn the_key_id_is_the_blake3_digest_of_the_verifying_key() {
    let verifying = key(7).verifying_key();
    assert_eq!(
        key_id_v1(&verifying),
        *blake3::hash(verifying.as_bytes()).as_bytes()
    );
}

#[test]
fn a_signed_envelope_round_trips_canonically_and_verifies() -> TestResult {
    let signer = key(7);
    let envelope = DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, b"{\"a\":1}".to_vec(), &signer);
    let bytes = envelope.to_canonical_json();
    let expected_signature =
        ed25519_dalek::Signer::sign(&signer, &pae_v1(IN_TOTO_PAYLOAD_TYPE_V1, b"{\"a\":1}"))
            .to_bytes();
    let encode = |input: &[u8]| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(input)
    };
    let expected = format!(
        concat!(
            r#"{{"payload":"{}","payloadType":"application/vnd.in-toto+json","#,
            r#""signatures":[{{"keyid":"{}","sig":"{}"}}]}}"#,
        ),
        encode(b"{\"a\":1}"),
        blake3::hash(signer.verifying_key().as_bytes()).to_hex(),
        encode(&expected_signature),
    );
    assert_eq!(String::from_utf8(bytes.clone())?, expected);

    let parsed = DsseEnvelopeV1::from_canonical_json(&bytes, BOUND)?;
    assert_eq!(parsed, envelope);
    assert_eq!(parsed.to_canonical_json(), bytes);
    assert!(parsed.has_payload_type(IN_TOTO_PAYLOAD_TYPE_V1));
    assert!(!parsed.has_payload_type("application/json"));
    assert_eq!(parsed.payload(), b"{\"a\":1}");
    assert_eq!(parsed.key_id(), &key_id_v1(&signer.verifying_key()));
    assert_eq!(parsed.verify(&signer.verifying_key()), Ok(()));
    Ok(())
}

#[test]
fn the_bound_is_checked_before_parsing_and_is_inclusive() {
    let bytes =
        DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, b"x".to_vec(), &key(7)).to_canonical_json();
    assert!(DsseEnvelopeV1::from_canonical_json(&bytes, bytes.len()).is_ok());
    assert_eq!(
        DsseEnvelopeV1::from_canonical_json(&bytes, bytes.len() - 1),
        Err(DsseParseErrorV1::Oversized)
    );
    // Not even JSON: refused by length alone.
    assert_eq!(
        DsseEnvelopeV1::from_canonical_json(&[0xff; 9], 8),
        Err(DsseParseErrorV1::Oversized)
    );
}

#[test]
fn non_canonical_or_non_single_signature_envelopes_are_malformed() -> TestResult {
    let bytes =
        DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, b"x".to_vec(), &key(7)).to_canonical_json();
    let text = String::from_utf8(bytes)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let signature = value["signatures"][0].clone();
    let key_id = signature["keyid"].as_str().ok_or("keyid")?.to_owned();
    let sig = signature["sig"].as_str().ok_or("sig")?.to_owned();
    let refused = [
        text.replace(',', ", "),
        text.replace("\"payload\":\"eA==\"", "\"payload\":\"eA\""),
        text.replace("\"payload\":\"eA==\"", "\"payload\":\"e===\""),
        text.replace("\"payload\":\"eA==\"", "\"payload\":7"),
        text.replace(
            "\"payloadType\":\"application/vnd.in-toto+json\"",
            "\"payloadType\":null",
        ),
        text.replace(&key_id, &key_id.to_uppercase()),
        text.replace(&key_id, &key_id[..62]),
        text.replace(&key_id, "zz"),
        text.replace(&format!("\"keyid\":\"{key_id}\""), "\"keyid\":1"),
        text.replace(&sig, "AAAA"),
        text.replace(&format!("\"sig\":\"{sig}\""), "\"sig\":false"),
        text.replace("\"signatures\":[", "\"signatures\":[{},"),
        text.replace("\"signatures\":[{", "\"signatures\":{\"x\":{")
            .replace("}]}", "}}}"),
        text.replace(&format!("\"keyid\":\"{key_id}\","), ""),
        text.replace("{\"payload\"", "{\"extra\":null,\"payload\""),
        "[]".to_owned(),
        "{".to_owned(),
    ];
    for envelope in refused {
        assert_eq!(
            DsseEnvelopeV1::from_canonical_json(envelope.as_bytes(), BOUND),
            Err(DsseParseErrorV1::Malformed),
            "{envelope}"
        );
    }
    Ok(())
}

#[test]
fn verification_refuses_a_foreign_key_and_a_bad_signature() -> TestResult {
    let signer = key(7);
    let envelope = DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, b"x".to_vec(), &signer);
    assert_eq!(
        envelope.verify(&key(8).verifying_key()),
        Err(DsseSignatureErrorV1::KeyIdMismatch)
    );
    let other =
        DsseEnvelopeV1::sign(IN_TOTO_PAYLOAD_TYPE_V1, b"y".to_vec(), &signer).to_canonical_json();
    let text = String::from_utf8(envelope.to_canonical_json())?;
    let other: serde_json::Value = serde_json::from_slice(&other)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    let swapped = text.replace(
        value["signatures"][0]["sig"].as_str().ok_or("sig")?,
        other["signatures"][0]["sig"].as_str().ok_or("sig")?,
    );
    let forged = DsseEnvelopeV1::from_canonical_json(swapped.as_bytes(), BOUND)?;
    assert_eq!(
        forged.verify(&signer.verifying_key()),
        Err(DsseSignatureErrorV1::InvalidSignature)
    );
    Ok(())
}

#[test]
fn errors_render_their_step() {
    for (message, expected) in [
        (DsseParseErrorV1::Oversized.to_string(), "byte bound"),
        (DsseParseErrorV1::Malformed.to_string(), "canonical"),
        (DsseSignatureErrorV1::KeyIdMismatch.to_string(), "key id"),
        (DsseSignatureErrorV1::InvalidSignature.to_string(), "PAE"),
    ] {
        assert!(message.contains(expected), "{message}");
    }
}
