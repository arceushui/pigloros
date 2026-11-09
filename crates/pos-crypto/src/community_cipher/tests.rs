//! Narrow primitive/entropy fault injection and independent RFC8452 vectors.

use super::{aes_seal, CommunityArtifactCipherV1 as Cipher, CommunityCipherErrorV1 as Error};
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn aes_schedule_keeps_the_required_zeroize_on_drop_feature() {
    fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    requires_zeroize_on_drop::<aes_gcm_siv::aes::Aes256>();
}

#[test]
fn aes256_matches_rfc8452_appendix_c2_empty_and_eight_byte_vectors() -> TestResult {
    // RFC8452 AppendixC.2: these values are published standard test data.
    let mut key = [0; 32];
    key[0] = 1;
    let mut nonce = [0; 12];
    nonce[0] = 3;
    assert_eq!(
        aes_seal(&key, &nonce, b"", &mut [])?,
        [
            0x07, 0xf5, 0xf4, 0x16, 0x9b, 0xbf, 0x55, 0xa8, 0x40, 0x0c, 0xd4, 0x7e, 0xa6, 0xfd,
            0x40, 0x0f,
        ]
    );
    let mut eight = [0; 8];
    eight[0] = 1;
    let tag = aes_seal(&key, &nonce, b"", &mut eight)?;
    assert_eq!(eight, [0xc2, 0xef, 0x32, 0x8e, 0x5c, 0x71, 0xc8, 0x3b]);
    assert_eq!(
        tag,
        [
            0x84, 0x31, 0x22, 0x13, 0x0f, 0x73, 0x64, 0xb7, 0x61, 0xe0, 0xb9, 0x74, 0x27, 0xe3,
            0xdf, 0x28,
        ]
    );
    Ok(())
}

#[test]
fn partial_nonce_entropy_failure_closes_encryption_and_preserves_old_decryption() -> TestResult {
    let mut cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([1; 32])), 4)?;
    let retained = cipher.seal(b"original", &[2; 32])?;
    let result = cipher.seal_with(
        b"new",
        &[2; 32],
        |bytes| {
            bytes.fill(0x42);
            Err(getrandom::Error::UNSUPPORTED)
        },
        aes_seal,
    );
    assert_eq!(result.err(), Some(Error::EntropyUnavailable));
    assert_eq!(cipher.remaining_encryptions(), 0);
    assert_eq!(
        cipher.seal(b"retry", &[2; 32]).err(),
        Some(Error::EncryptionClosed)
    );
    assert_eq!(
        cipher
            .open(retained.nonce(), retained.ciphertext_and_tag(), &[2; 32])?
            .as_slice(),
        b"original"
    );
    Ok(())
}

#[test]
fn primitive_refusal_closes_remaining_credits_without_returning_a_candidate() -> TestResult {
    let mut cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([3; 32])), 4)?;
    let result = cipher.seal_with(b"candidate", &[4; 32], getrandom::fill, |_, _, _, _| {
        Err(aes_gcm_siv::Error)
    });
    assert_eq!(result.err(), Some(Error::EncryptionFailed));
    assert_eq!(cipher.remaining_encryptions(), 0);
    assert_eq!(
        cipher.seal(b"retry", &[4; 32]).err(),
        Some(Error::EncryptionClosed)
    );
    Ok(())
}
