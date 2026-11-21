#![cfg(any(test, feature = "test-support"))]
//! ADR-110 §8 E4: `confirm_candidate` returns `Ok` only after an authenticated
//! open, so a wrong PRF, a tampered wrap and a tampered tag each fail.

use pos_core::EntityId;
use pos_crypto::subject_key::{SubjectKeyWrapV1, SubjectPrfOutputV1, SubjectRootKeyV1};
use pos_owner_bridge::fake::clock::FakeRandom;
use pos_owner_bridge::{SecureRandom, UnavailableCode};
use pos_owner_bridge_codec::PrfInput;
use ulid::Ulid;

use super::{confirm, seal, EnrollmentCandidate, Sealing, WRAP};

const PRF: [u8; 32] = [0x40; 32];
const CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];

const fn sealing() -> Sealing<'static> {
    Sealing {
        subject: EntityId::from_ulid(Ulid::from_bytes([0x10; 16])),
        epoch: 3,
        credential_id: &CREDENTIAL_ID,
        prf_input: PrfInput::from_bytes([0x60; 32]),
    }
}

/// A sealed candidate, after checking that it confirms to its own fingerprint.
fn sealed() -> Option<EnrollmentCandidate> {
    seal(&mut FakeRandom::seeded(9), sealing(), &PRF)
        .ok()
        .map(|(candidate, sealed)| {
            assert_eq!(confirm(&candidate, &PRF).ok(), Some(sealed));
            candidate
        })
}

/// The candidate with one byte of its encoded wrap flipped at `offset`.
fn tampered(offset: usize) -> Option<EnrollmentCandidate> {
    sealed()
        .map(|candidate| {
            let mut bytes = candidate.wrap.to_bytes();
            bytes[offset] ^= 1;
            bytes
        })
        .and_then(|bytes| SubjectKeyWrapV1::from_bytes(&bytes).ok())
        .map(|wrap| EnrollmentCandidate {
            root: SubjectRootKeyV1::from_bytes([0; 32]),
            wrap,
        })
}

#[test]
fn the_sealed_wrap_binds_its_inputs_and_opens_under_the_sealing_prf_only() {
    let opened = sealed().map(|candidate| {
        let params = candidate.wrap.params();
        assert_eq!(params.rp_id, "localhost");
        assert_eq!(params.credential_id, CREDENTIAL_ID);
        assert_eq!(params.prf_input, [0x60; 32]);
        assert_eq!(params.epoch, 3);
        assert_eq!(params.subject_id, sealing().subject);
        confirm(&candidate, &[0x41; 32]).err()
    });
    assert_eq!(opened, Some(Some(WRAP)));
}

#[test]
fn a_tampered_tag_or_wrap_field_fails_the_open() {
    let length = sealed()
        .map(|candidate| candidate.wrap.to_bytes().len())
        .unwrap_or_default();
    // The last byte is the tag's. The wrapped root and tag are the final
    // 48-byte string with a 2-byte head, so the byte 50 before the last is
    // the last byte of the 12-byte wrap nonce.
    for offset in [length - 1, length - 51] {
        let opened = tampered(offset).map(|candidate| confirm(&candidate, &PRF).err());
        assert_eq!(opened, Some(Some(WRAP)));
    }
}

/// A source that fills byte `i` of every draw with `i`.
struct Counting;

impl SecureRandom for Counting {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), UnavailableCode> {
        out.iter_mut()
            .zip(0_u8..)
            .for_each(|(byte, value)| *byte = value);
        Ok(())
    }
}

#[test]
fn one_draw_splits_into_root_wrap_salt_subkey_salt_and_nonce_in_order() {
    let drawn: Vec<u8> = (0_u8..108).collect();
    let checked = seal(&mut Counting, sealing(), &PRF)
        .ok()
        .map(|(candidate, _)| {
            let params = candidate.wrap.params();
            assert_eq!(params.wrap_salt.as_slice(), &drawn[32..64]);
            assert_eq!(params.subkey_salt.as_slice(), &drawn[64..96]);
            assert_eq!(params.wrap_nonce.as_slice(), &drawn[96..108]);
            let expected = SubjectRootKeyV1::from_bytes(std::array::from_fn(|index| drawn[index]));
            let opened = candidate
                .wrap
                .open(&SubjectPrfOutputV1::from_bytes(PRF))
                .ok();
            assert_eq!(
                opened.map(|root| root.material_digest()),
                Some(expected.material_digest())
            );
            assert_eq!(candidate.root.material_digest(), expected.material_digest());
        });
    assert!(checked.is_some());
}

#[test]
fn a_randomness_failure_is_a_wrap_failure() {
    assert_eq!(
        seal(&mut FakeRandom::failing_after(9, 0), sealing(), &PRF).err(),
        Some(WRAP)
    );
}
