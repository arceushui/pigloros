//! Unqualified primitive tests; no native vault, owner or authority is implied.

use pos_crypto::community_cipher::{
    CommunityArtifactCipherV1 as Cipher, CommunityCipherErrorV1 as Error,
    MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1 as MAX_PLAINTEXT,
    MAX_COMMUNITY_KEY_ENCRYPTIONS_V1 as MAX_ENCRYPTIONS,
};
use zeroize::Zeroizing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn retained_key_opens_pinned_external_vector_through_the_public_api() -> TestResult {
    // C2SP/wycheproof AES-GCM-SIV tcId139, commit:
    // d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9; published independent test data.
    // https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/aes_gcm_siv_test.json
    let key = [
        0x39, 0x37, 0x98, 0x6a, 0xf8, 0x6d, 0xaf, 0xc1, 0xba, 0x0c, 0x46, 0x72, 0xd8, 0xab, 0xc4,
        0x6c, 0x20, 0x70, 0x62, 0x68, 0x2d, 0x9c, 0x26, 0x4a, 0xb0, 0x6d, 0x6c, 0x58, 0x07, 0x20,
        0x51, 0x30,
    ];
    let nonce = [
        0x8d, 0xf4, 0xb1, 0x5a, 0x88, 0x8c, 0x33, 0x28, 0x6a, 0x7b, 0x76, 0x51,
    ];
    let aad = [
        0xba, 0x44, 0x6f, 0x6f, 0x9a, 0x0c, 0xed, 0x22, 0x45, 0x0f, 0xeb, 0x10, 0x73, 0x7d, 0x90,
        0x07, 0xfd, 0x69, 0xab, 0xc1, 0x9b, 0x1d, 0x4d, 0x90, 0x49, 0xa5, 0x55, 0x1e, 0x86, 0xec,
        0x2b, 0x37,
    ];
    let ciphertext_and_tag = [
        0x97, 0xdb, 0x4d, 0x85, 0x04, 0x42, 0xeb, 0x33, 0xe6, 0x08, 0x9a, 0xf6, 0xf3, 0xca, 0xdf,
        0x7b, 0x3c, 0xcb, 0xb1, 0x25, 0xb2, 0x83, 0x57, 0x54, 0xc1, 0x40, 0x9d, 0x22, 0x7e, 0x37,
        0x4d, 0x0b,
    ];
    let plaintext = [
        0xdc, 0x9e, 0x9e, 0xaf, 0x11, 0xe3, 0x14, 0x18, 0x2d, 0xf6, 0xa4, 0xeb, 0xa1, 0x7a, 0xec,
        0x9c,
    ];
    let cipher = Cipher::from_retained_material(Box::new(Zeroizing::new(key)));
    assert_eq!(
        cipher.open(&nonce, &ciphertext_and_tag, &aad)?.as_slice(),
        plaintext
    );
    let mut changed_aad = aad;
    changed_aad[0] ^= 1;
    assert_eq!(
        cipher.open(&nonce, &ciphertext_and_tag, &changed_aad).err(),
        Some(Error::AuthenticationFailed)
    );
    assert_eq!(cipher.remaining_encryptions(), 0);
    Ok(())
}

#[test]
fn staged_material_preserves_fingerprint_and_has_a_closed_budget_range() -> TestResult {
    for budget in [0, MAX_ENCRYPTIONS + 1, u32::MAX] {
        assert_eq!(
            Cipher::from_staged_material(Box::new(Zeroizing::new([1; 32])), budget).err(),
            Some(Error::InvalidBudget)
        );
    }
    for budget in [1, MAX_ENCRYPTIONS] {
        let cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([1; 32])), budget)?;
        assert_eq!(cipher.remaining_encryptions(), budget);
        let mut preimage = b"pigloros/key-material/v1".to_vec();
        preimage.extend_from_slice(&[1; 32]);
        assert_eq!(
            cipher.material_digest(),
            pos_core::Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
        );
        assert_eq!(
            cipher.material_digest(),
            pos_crypto::key_roles::key_material_digest(&[1; 32])
        );
    }
    Ok(())
}

#[test]
fn primitive_errors_have_static_community_messages_without_nested_payloads() {
    for error in [
        Error::InvalidBudget,
        Error::BoundsExceeded,
        Error::EncryptionClosed,
        Error::EntropyUnavailable,
        Error::EncryptionFailed,
        Error::AuthenticationFailed,
    ] {
        assert!(error.to_string().contains("community"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn empty_partial_block_and_maximum_plaintexts_authenticate_as_private_staging() -> TestResult {
    let mut cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([2; 32])), 8)?;
    for length in [0, 1, 15, 16, 17, 4096, MAX_PLAINTEXT] {
        let plaintext = Zeroizing::new(vec![0x42; length]);
        let sealed = cipher.seal(&plaintext, &[3; 32])?;
        assert_eq!(sealed.ciphertext_and_tag().len(), length + 16);
        let restored = cipher.open(sealed.nonce(), sealed.ciphertext_and_tag(), &[3; 32])?;
        assert_eq!(restored.as_slice(), plaintext.as_slice());
    }
    assert_eq!(cipher.remaining_encryptions(), 1);
    Ok(())
}

#[test]
fn discarded_candidates_burn_credits_and_closing_has_no_reopen_operation() -> TestResult {
    let mut cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([3; 32])), 2)?;
    let first = cipher.seal(b"first", &[4; 32])?;
    assert_eq!(cipher.remaining_encryptions(), 1);
    drop(cipher.seal(b"discarded", &[4; 32])?);
    assert_eq!(cipher.remaining_encryptions(), 0);
    assert_eq!(
        cipher.seal(b"third", &[4; 32]).err(),
        Some(Error::EncryptionClosed)
    );
    assert_eq!(
        cipher
            .open(first.nonce(), first.ciphertext_and_tag(), &[4; 32])?
            .as_slice(),
        b"first"
    );

    let mut fresh = Cipher::from_staged_material(Box::new(Zeroizing::new([4; 32])), 2)?;
    fresh.close_encryption();
    fresh.close_encryption();
    assert_eq!(fresh.remaining_encryptions(), 0);
    assert_eq!(
        fresh.seal(b"closed", &[4; 32]).err(),
        Some(Error::EncryptionClosed)
    );
    Ok(())
}

#[test]
fn retained_material_decrypts_without_reopening_encryption() -> TestResult {
    let mut staged = Cipher::from_staged_material(Box::new(Zeroizing::new([5; 32])), 1)?;
    let sealed = staged.seal(b"retained ciphertext", &[6; 32])?;
    let fingerprint = staged.material_digest();
    drop(staged);
    let mut retained = Cipher::from_retained_material(Box::new(Zeroizing::new([5; 32])));
    assert_eq!(retained.material_digest(), fingerprint);
    assert_eq!(retained.remaining_encryptions(), 0);
    assert_eq!(
        retained.seal(b"replacement", &[6; 32]).err(),
        Some(Error::EncryptionClosed)
    );
    assert_eq!(
        retained
            .open(sealed.nonce(), sealed.ciphertext_and_tag(), &[6; 32])?
            .as_slice(),
        b"retained ciphertext"
    );
    Ok(())
}

#[test]
fn changed_context_nonce_key_ciphertext_or_tag_never_returns_plaintext() -> TestResult {
    let mut cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([6; 32])), 1)?;
    let sealed = cipher.seal(b"protected record", &[7; 32])?;
    for index in 0..32 {
        let mut context = [7; 32];
        context[index] ^= 1;
        assert_eq!(
            cipher
                .open(sealed.nonce(), sealed.ciphertext_and_tag(), &context)
                .err(),
            Some(Error::AuthenticationFailed)
        );
    }
    for index in 0..12 {
        let mut nonce = *sealed.nonce();
        nonce[index] ^= 1;
        assert_eq!(
            cipher
                .open(&nonce, sealed.ciphertext_and_tag(), &[7; 32])
                .err(),
            Some(Error::AuthenticationFailed)
        );
    }
    for index in 0..sealed.ciphertext_and_tag().len() {
        let mut corrupted = sealed.ciphertext_and_tag().to_vec();
        corrupted[index] ^= 1;
        assert_eq!(
            cipher.open(sealed.nonce(), &corrupted, &[7; 32]).err(),
            Some(Error::AuthenticationFailed)
        );
    }
    let wrong = Cipher::from_retained_material(Box::new(Zeroizing::new([7; 32])));
    assert_eq!(
        wrong
            .open(sealed.nonce(), sealed.ciphertext_and_tag(), &[7; 32])
            .err(),
        Some(Error::AuthenticationFailed)
    );
    Ok(())
}

#[test]
fn oversized_plaintext_does_not_consume_a_primitive_credit() -> TestResult {
    let mut cipher = Cipher::from_staged_material(Box::new(Zeroizing::new([8; 32])), 1)?;
    let oversized = Zeroizing::new(vec![0; MAX_PLAINTEXT + 1]);
    assert_eq!(
        cipher.seal(&oversized, &[9; 32]).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(cipher.remaining_encryptions(), 1);
    cipher.seal(b"still available", &[9; 32])?;
    assert_eq!(cipher.remaining_encryptions(), 0);
    for length in [0, 15, MAX_PLAINTEXT + 17] {
        assert_eq!(
            cipher.open(&[0; 12], &vec![0; length], &[9; 32]).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}
