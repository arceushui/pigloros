//! The independent `reconciliation-evidence-v1` encoder (ADR-069 R15 §3.1,
//! invariant 1): built over `ciborium`, it must give the R15 §4 vector
//! bytes and digests that the pos-reference encoder gives.

use pos_conformance::{ReconciliationEvidenceV1, SandboxContractErrorV1};

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(DIGITS[usize::from(nibble)]))
        .collect()
}

const RCE1_A: ReconciliationEvidenceV1 = ReconciliationEvidenceV1 {
    attempt_id: [0x11; 16],
    agr1_digest: [0x22; 32],
    terminal_spy1_digest: [0x33; 32],
    final_sau1_digest: [0x44; 32],
};

#[test]
fn the_independent_encoder_reproduces_rce1_a_and_rce1_b() -> Result<(), Box<dyn std::error::Error>>
{
    let counting = |start: u8, length: u8| (start..start + length).collect::<Vec<u8>>();
    let rce1_b = ReconciliationEvidenceV1 {
        attempt_id: counting(1, 16).as_slice().try_into()?,
        agr1_digest: counting(0x20, 32).as_slice().try_into()?,
        terminal_spy1_digest: counting(0x40, 32).as_slice().try_into()?,
        final_sau1_digest: counting(0x60, 32).as_slice().try_into()?,
    };
    for (evidence, cbor, digest) in [
        (
            RCE1_A,
            "8a5011111111111111111111111111111111582022222222222222222222222222222222222222222222222222222222222222225820333333333333333333333333333333333333333333333333333333333333333358204444444444444444444444444444444444444444444444444444444444444444f5f5f5f5f5f5",
            "7e02b3d86a17f353121960e9c535b9a7eaf2fa0d48dfe758ece59d73cb38d8cd",
        ),
        (
            rce1_b,
            "8a500102030405060708090a0b0c0d0e0f105820202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f5820404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f5820606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7ff5f5f5f5f5f5",
            "2c7d64fa64fa5831eaf9c14f5047ebe413bf6a8eccb7a5adc022bbcda74ca204",
        ),
    ] {
        let encoded = evidence.to_canonical_cbor()?;
        assert_eq!(encoded.len(), 126);
        assert_eq!(hex(&encoded), cbor);
        assert_eq!(hex(&evidence.digest()?), digest);
    }
    Ok(())
}

#[test]
fn the_independent_encoder_refuses_a_zero_identity_or_digest() {
    for evidence in [
        ReconciliationEvidenceV1 {
            attempt_id: [0; 16],
            ..RCE1_A
        },
        ReconciliationEvidenceV1 {
            agr1_digest: [0; 32],
            ..RCE1_A
        },
        ReconciliationEvidenceV1 {
            terminal_spy1_digest: [0; 32],
            ..RCE1_A
        },
        ReconciliationEvidenceV1 {
            final_sau1_digest: [0; 32],
            ..RCE1_A
        },
    ] {
        assert_eq!(
            evidence.to_canonical_cbor().err(),
            Some(SandboxContractErrorV1::FieldOutOfBounds)
        );
        assert_eq!(
            evidence.digest().err(),
            Some(SandboxContractErrorV1::FieldOutOfBounds)
        );
    }
}
