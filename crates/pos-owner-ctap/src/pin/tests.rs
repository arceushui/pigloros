use p256::ecdsa::SigningKey;
use pos_owner_bridge::fake::clock::FakeRandom;
use pos_owner_bridge::{BridgeError, LifecycleCode, SecureRandom, UnavailableCode};
use sha2::{Digest, Sha256};

use super::{agree, authenticate, decrypt, encapsulate, encrypt, ephemeral_key, public_point};
use crate::soft::Drbg;
use crate::vectors::{array32, vector};

const VECTORS: &str = include_str!("../../tests/vectors/protocol2.txt");
const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const RNG: BridgeError = BridgeError::Unavailable(UnavailableCode::RngUnavailable);

fn labelled_key(label: &str) -> Result<SigningKey, p256::ecdsa::Error> {
    SigningKey::from_slice(&Sha256::digest(label.as_bytes()))
}

/// The known-answer platform and authenticator keys, derived from their labels.
fn keys() -> Result<(SigningKey, SigningKey), p256::ecdsa::Error> {
    labelled_key("pos-owner-ctap protocol 2 KAT platform").and_then(|platform| {
        labelled_key("pos-owner-ctap protocol 2 KAT authenticator")
            .map(|authenticator| (platform, authenticator))
    })
}

/// A source whose first `saturated` fills are all ones, which is not a P-256 scalar.
struct Saturated {
    saturated: usize,
    rest: Drbg,
}

impl SecureRandom for Saturated {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), UnavailableCode> {
        if self.saturated > 0 {
            self.saturated -= 1;
            out.fill(0xff);
            return Ok(());
        }
        self.rest.fill(out)
    }
}

#[test]
fn the_shared_secret_matches_the_known_answer_from_both_sides() {
    let checked = keys().map(|(platform, authenticator)| {
        assert_eq!(
            public_point(&platform).x.to_vec(),
            vector(VECTORS, "platform_x")
        );
        assert_eq!(
            public_point(&authenticator).x.to_vec(),
            vector(VECTORS, "authenticator_x")
        );
        for (own, peer) in [(&platform, &authenticator), (&authenticator, &platform)] {
            let secret = agree(own, public_point(peer));
            let halves =
                secret.map(|secret| (secret.hmac_key().to_vec(), secret.aes_key().to_vec()));
            let expected = (
                vector(VECTORS, "shared_hmac_key"),
                vector(VECTORS, "shared_aes_key"),
            );
            assert_eq!(halves, Ok(expected));
        }
    });
    assert!(checked.is_ok());
}

#[test]
fn encrypt_authenticate_and_decrypt_match_the_known_answers() {
    let message = array32(&Sha256::digest(b"pos-owner-ctap protocol 2 KAT plaintext"));
    let blocks = message.as_chunks::<16>().0;
    let checked = keys().map(|(platform, authenticator)| {
        let secret = agree(&platform, public_point(&authenticator));
        let mut random = Drbg::new("pos-owner-ctap protocol 2 KAT iv");
        let sealed = secret.and_then(|secret| {
            encrypt(&secret, blocks, &mut random).map(|encrypted| {
                let tag = authenticate(secret.hmac_key(), &[&encrypted[..16], &encrypted[16..]]);
                assert_eq!(tag.to_vec(), vector(VECTORS, "authenticate"));
                let decrypted = decrypt(&secret, &encrypted);
                assert_eq!(decrypted.as_deref().map(Vec::as_slice), Some(blocks));
                encrypted
            })
        });
        assert_eq!(sealed, Ok(vector(VECTORS, "encrypt")));
    });
    assert!(checked.is_ok());
}

#[test]
fn decrypt_needs_an_iv_and_whole_blocks() {
    let checked = keys().map(|(platform, authenticator)| {
        let secret = agree(&platform, public_point(&authenticator));
        let lengths = secret.and_then(|secret| {
            encrypt(&secret, &[[0; 16]], &mut Drbg::new("decrypt")).map(|encrypted| {
                [15, 31, 16]
                    .map(|length| decrypt(&secret, &encrypted[..length]).map(|blocks| blocks.len()))
            })
        });
        assert_eq!(lengths, Ok([None, None, Some(0)]));
    });
    assert!(checked.is_ok());
}

#[test]
fn encapsulation_agrees_with_the_peer_and_refuses_an_invalid_point() {
    let checked = keys().map(|(_, authenticator)| {
        let peer = public_point(&authenticator);
        let agreed =
            encapsulate(peer, &mut Drbg::new("encapsulate")).and_then(|(platform, secret)| {
                agree(&authenticator, platform).map(|other| {
                    (secret.hmac_key() == other.hmac_key()) && (secret.aes_key() == other.aes_key())
                })
            });
        assert_eq!(agreed, Ok(true));
        let mut invalid = peer;
        invalid.y[31] ^= 1;
        let refused = encapsulate(invalid, &mut Drbg::new("encapsulate"));
        assert_eq!(refused.err(), Some(CLIENT_FAILED));
        assert_eq!(agree(&authenticator, invalid).err(), Some(CLIENT_FAILED));
    });
    assert!(checked.is_ok());
}

#[test]
fn an_invalid_scalar_is_redrawn_a_few_times_then_refused() {
    let rest = Drbg::new("scalar");
    for (saturated, valid) in [(1, true), (3, true), (4, false)] {
        let mut random = Saturated {
            saturated,
            rest: rest.clone(),
        };
        let drawn = ephemeral_key(&mut random);
        assert_eq!(drawn.is_ok(), valid, "{saturated}");
        assert_eq!(drawn.err(), (!valid).then_some(RNG));
    }
}

#[test]
fn a_failing_random_source_is_rng_unavailable() {
    assert_eq!(
        ephemeral_key(&mut FakeRandom::failing_after(1, 0)).err(),
        Some(RNG)
    );
    let checked = keys().map(|(_, authenticator)| {
        let failed = agree(&authenticator, public_point(&authenticator))
            .and_then(|secret| encrypt(&secret, &[[0; 16]], &mut FakeRandom::failing_after(1, 0)));
        assert_eq!(failed, Err(RNG));
        let peer = public_point(&authenticator);
        let refused = encapsulate(peer, &mut FakeRandom::failing_after(1, 0));
        assert_eq!(refused.err(), Some(RNG));
    });
    assert!(checked.is_ok());
}
