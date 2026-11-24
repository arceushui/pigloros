//! The V1 reconciliation evidence and its signed SRY1 (ADR-069 R15 §3.1,
//! §4 and invariants 1 and 2).
//!
//! The expected bytes are the R15 §4 vectors, produced by the page's
//! pure-Python script and copied here unchanged.

use std::error::Error;

use ed25519_dalek::SigningKey;
use pos_reference::sandbox_provider_protocol::{
    ReconciliationEvidence, ReconciliationEvidenceFields, RuntimeSigned,
    SandboxProviderProtocolError, SandboxReconcileRequest, SandboxReconcileResponse,
    SandboxReconcileResponseFields, SelfDigested, Sry1, RECONCILIATION_EVIDENCE_V1_BYTES,
    RECONCILIATION_EVIDENCE_V1_DOMAIN,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(DIGITS[usize::from(nibble)]))
        .collect()
}

fn unhex(text: &str) -> TestResult<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&text[index..index + 2], 16)?))
        .collect()
}

/// RCE1-A: attempt `11`×16, AGR1 `22`×32, SPY1 `33`×32, SAU1 `44`×32.
const RCE1_A: ReconciliationEvidenceFields = ReconciliationEvidenceFields {
    attempt_id: [0x11; 16],
    agr1_digest: [0x22; 32],
    terminal_spy1_digest: [0x33; 32],
    final_sau1_digest: [0x44; 32],
};

const RCE1_A_CBOR: &str = "8a5011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f5";
const RCE1_A_DIGEST: &str = "7e02b3d86a17f353121960e9c535b9a7eaf2fa0d48dfe758ece59d73cb38d8cd";
const RCE1_B_CBOR: &str = "8a500102030405060708090a0b0c0d0e0f105820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f5820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f5820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7ff5f5f5f5f5f5";
const RCE1_B_DIGEST: &str = "2c7d64fa64fa5831eaf9c14f5047ebe413bf6a8eccb7a5adc022bbcda74ca204";
const RCE1_A3_DIGEST: &str = "5dbc075a18d5edf9f9c543990cd6ed0ca118b34a71d85621d427d0d08e5b10d1";

/// RCE1-N1 to RCE1-N9 (R15 §4.4), each one change from RCE1-A.
const RCE1_N: [&str; 9] = [
    "8a5011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f4f5f5f5f5f5",
    "8a5011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f4",
    "895011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5",
    "8b5011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f5f5",
    "8a4f111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f5",
    "8a5011111111111111111111111111111111582000000000000000000000000000000000000000000000000000000000000000005820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f5",
    "8a501111111111111111111111111111111159002022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f5",
    "9f5011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f5ff",
    "8a5011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f500",
];

/// SRY1-A (R15 §4.5): RCE1-A signed by the published test seed `07`×32.
const SRY1_A_KEY: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";
const SRY1_A_KEY_ID: &str = "dc29117d8bec78daf7e5cb7bf686432756ab53c9f43962387b48d7bcd7740f27";
const SRY1_A_SELF_DIGEST: &str = "2b0344278110453f0b9fc7b38221c11835cb728e9c9af2794fa91b20b14d010e";
const SRY1_A_SIGNATURE: &str = "a320486af2351b2010643f363fcdaa91bc0d3e80fef567f2290f143b1cbc9804d636ca7b67d87b94cffce7b2ff416eee039e48c8e5bbe3ff0b4afac26c31ac0a";
const SRY1_A_RECORD: &str = "838764535259310150555555555555555555555555555555555011111111111111111111111111111111f558207e02b3d86a17f353121960e9c535b9a7eaf2fa0d48dfe758ece59d73cb38d8cd78406463323931313764386265633738646166376535636237626636383634333237353661623533633966343339363233383762343864376263643737343066323758202b0344278110453f0b9fc7b38221c11835cb728e9c9af2794fa91b20b14d010e5840a320486af2351b2010643f363fcdaa91bc0d3e80fef567f2290f143b1cbc9804d636ca7b67d87b94cffce7b2ff416eee039e48c8e5bbe3ff0b4afac26c31ac0a";

fn digest_under(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(bytes);
    *blake3::hash(&preimage).as_bytes()
}

#[test]
fn the_encoder_reproduces_rce1_a_and_rce1_b() -> TestResult {
    let counting = |start: u8, length: u8| (start..start + length).collect::<Vec<u8>>();
    let rce1_b = ReconciliationEvidenceFields {
        attempt_id: counting(1, 16).as_slice().try_into()?,
        agr1_digest: counting(0x20, 32).as_slice().try_into()?,
        terminal_spy1_digest: counting(0x40, 32).as_slice().try_into()?,
        final_sau1_digest: counting(0x60, 32).as_slice().try_into()?,
    };
    for (fields, cbor, digest) in [
        (RCE1_A, RCE1_A_CBOR, RCE1_A_DIGEST),
        (rce1_b, RCE1_B_CBOR, RCE1_B_DIGEST),
    ] {
        let evidence = ReconciliationEvidence::new(&fields)?;
        assert_eq!(evidence.as_bytes().len(), RECONCILIATION_EVIDENCE_V1_BYTES);
        assert_eq!(hex(evidence.as_bytes()), cbor);
        assert_eq!(hex(&evidence.digest()), digest);
        assert_eq!(
            evidence.digest(),
            digest_under(RECONCILIATION_EVIDENCE_V1_DOMAIN, evidence.as_bytes())
        );
    }
    Ok(())
}

#[test]
fn the_v1_and_v3_domains_separate_and_every_noncanonical_string_digests_apart() -> TestResult {
    let evidence = ReconciliationEvidence::new(&RCE1_A)?;
    assert_eq!(
        hex(&digest_under(
            b"PiglorOS.ReconciliationEvidence.v3\0",
            evidence.as_bytes()
        )),
        RCE1_A3_DIGEST
    );
    assert_ne!(hex(&evidence.digest()), RCE1_A3_DIGEST);
    // No canonical encoding is one of them, and each digests differently.
    for noncanonical in RCE1_N {
        let bytes = unhex(noncanonical)?;
        assert_ne!(bytes.as_slice(), evidence.as_bytes());
        assert_ne!(
            digest_under(RECONCILIATION_EVIDENCE_V1_DOMAIN, &bytes),
            evidence.digest()
        );
    }
    Ok(())
}

#[test]
fn the_encoder_refuses_a_zero_identity_or_digest() {
    for fields in [
        ReconciliationEvidenceFields {
            attempt_id: [0; 16],
            ..RCE1_A
        },
        ReconciliationEvidenceFields {
            agr1_digest: [0; 32],
            ..RCE1_A
        },
        ReconciliationEvidenceFields {
            terminal_spy1_digest: [0; 32],
            ..RCE1_A
        },
        ReconciliationEvidenceFields {
            final_sau1_digest: [0; 32],
            ..RCE1_A
        },
    ] {
        assert_eq!(
            ReconciliationEvidence::new(&fields).err(),
            Some(SandboxProviderProtocolError::FieldOutOfBounds)
        );
    }
}

fn sry1_a_fields() -> TestResult<SandboxReconcileResponseFields> {
    Ok(SandboxReconcileResponseFields {
        request_id: [0x55; 16],
        attempt_id: [0x11; 16],
        reconciliation_evidence_digest: ReconciliationEvidence::new(&RCE1_A)?.digest(),
        runtime_attestation_key_id: SRY1_A_KEY_ID.to_owned(),
    })
}

#[test]
fn the_sry1_producer_reproduces_sry1_a_and_the_decoder_accepts_it() -> TestResult {
    let key = SigningKey::from_bytes(&[0x07; 32]);
    let public = key.verifying_key();
    assert_eq!(hex(public.as_bytes()), SRY1_A_KEY);
    assert_eq!(
        hex(&digest_under(
            b"PiglorOS.RuntimeKeyId.v1\0",
            public.as_bytes()
        )),
        SRY1_A_KEY_ID
    );
    let record: SelfDigested<Sry1> = SandboxReconcileResponse::self_digested(sry1_a_fields()?)?;
    assert_eq!(Sry1::MAGIC, "SRY1");
    assert_eq!(record.key_id(), SRY1_A_KEY_ID);
    assert_eq!(record.body(), &sry1_a_fields()?);
    assert_eq!(hex(&record.digest()), SRY1_A_SELF_DIGEST);
    let signature = ed25519_dalek::Signer::sign(&key, &record.signature_message()).to_bytes();
    assert_eq!(hex(&signature), SRY1_A_SIGNATURE);
    let response = SandboxReconcileResponse::new(record.verify(signature, &public)?, &public)?;
    let encoded = response.to_canonical_cbor()?;
    assert_eq!(hex(&encoded), SRY1_A_RECORD);
    assert_eq!(encoded.len(), 243);
    // The decoder accepts it; the signature check and the request check
    // are separate steps (R15 §3.5 rule 1).
    let decoded = SandboxReconcileResponse::from_canonical_cbor(&encoded)?;
    assert_eq!(decoded, response);
    decoded.verify_signature(&public)?;
    let request = SandboxReconcileRequest::from_canonical_cbor(&srq1()?)?;
    decoded.validate_for_request(&request)?;
    Ok(())
}

/// A canonical SRQ1 for SRY1-A's request and attempt.
fn srq1() -> TestResult<Vec<u8>> {
    use ciborium::value::Value;
    let bytes = |slice: &[u8]| Value::Bytes(slice.to_vec());
    let unsigned = Value::Array(vec![
        Value::Text("SRQ1".to_owned()),
        Value::Integer(1.into()),
        Value::Array(vec![
            bytes(&[0x55; 16]),
            bytes(&[1; 32]),
            Value::Integer(6.into()),
            bytes(&[3; 16]),
        ]),
        bytes(&[0x11; 16]),
        bytes(&[0x22; 32]),
    ]);
    let mut encoded = Vec::new();
    ciborium::into_writer(&unsigned, &mut encoded)?;
    let digest = digest_under(b"PiglorOS.SRQ1.v1\0", &encoded);
    let mut record = Vec::new();
    ciborium::into_writer(&Value::Array(vec![unsigned, bytes(&digest)]), &mut record)?;
    Ok(record)
}

#[test]
fn the_sry1_producer_refuses_zero_fields_and_a_foreign_key() -> TestResult {
    for refused in [
        SandboxReconcileResponseFields {
            request_id: [0; 16],
            ..sry1_a_fields()?
        },
        SandboxReconcileResponseFields {
            attempt_id: [0; 16],
            ..sry1_a_fields()?
        },
        SandboxReconcileResponseFields {
            reconciliation_evidence_digest: [0; 32],
            ..sry1_a_fields()?
        },
        SandboxReconcileResponseFields {
            runtime_attestation_key_id: String::new(),
            ..sry1_a_fields()?
        },
    ] {
        assert_eq!(
            SandboxReconcileResponse::self_digested(refused).err(),
            Some(SandboxProviderProtocolError::FieldOutOfBounds)
        );
    }
    let other = SigningKey::from_bytes(&[9; 32]);
    let record = SandboxReconcileResponse::self_digested(sry1_a_fields()?)?;
    let foreign = ed25519_dalek::Signer::sign(&other, &record.signature_message()).to_bytes();
    let verified = record.verify(foreign, &other.verifying_key())?;
    assert_eq!(
        SandboxReconcileResponse::new(verified, &SigningKey::from_bytes(&[7; 32]).verifying_key())
            .err(),
        Some(SandboxProviderProtocolError::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn a_one_bit_change_or_a_foreign_signature_is_refused() -> TestResult {
    let encoded = unhex(SRY1_A_RECORD)?;
    let public = SigningKey::from_bytes(&[0x07; 32]).verifying_key();
    // A one-bit change of field 5 breaks the self-digest.
    let mut flipped = encoded.clone();
    let field5 = encoded
        .windows(32)
        .position(|window| hex(window) == RCE1_A_DIGEST)
        .ok_or("field 5")?;
    flipped[field5] ^= 1;
    assert_eq!(
        SandboxReconcileResponse::from_canonical_cbor(&flipped).err(),
        Some(SandboxProviderProtocolError::DigestMismatch)
    );
    // A signature under another key fails the separate signature check.
    let decoded = SandboxReconcileResponse::from_canonical_cbor(&encoded)?;
    assert_eq!(
        decoded
            .verify_signature(&SigningKey::from_bytes(&[9; 32]).verifying_key())
            .err(),
        Some(SandboxProviderProtocolError::SignatureInvalid)
    );
    decoded.verify_signature(&public)?;
    Ok(())
}
