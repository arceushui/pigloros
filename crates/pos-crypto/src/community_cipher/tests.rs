//! Narrow primitive/entropy fault injection and independent RFC8452 vectors.

#[path = "../../tests/support/community_cipher_vectors.rs"]
mod known_answers;

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
    let [empty, eight, _external] = known_answers::load()?;
    for vector in [empty, eight] {
        let mut bytes = vector.plaintext;
        let tag = aes_seal(&vector.key, &vector.nonce, &vector.aad, &mut bytes)?;
        let (ciphertext, expected_tag) = vector.ciphertext_and_tag.split_at(bytes.len());
        assert_eq!(bytes, ciphertext, "{} ciphertext", vector.id);
        assert_eq!(tag.as_slice(), expected_tag, "{} tag", vector.id);
    }
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
