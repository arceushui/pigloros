//! Reply consumption: decoding failures are classified, and a required PRF that is absent or
//! malformed fails closed as `Unavailable(PrfUnsupported)` (ADR-110 §1 and §7).

use pos_owner_bridge_codec::{
    encode_assertion_reply, encode_attestation_reply, AssertionReplyV1, AttestationReplyV1,
    CeremonyId, CeremonyKind, CoseEs256PublicKey, OwnerBridgeCodecError, OwnerUserHandle,
    PrfResult, TransportCodes, WebAuthnChallenge,
};
use zeroize::Zeroizing;

use super::parse_and_verify;
use crate::ceremony::plan::{CeremonyPlan, StoredGet};
use crate::ceremony::{replace_prf, PRF_NULL};
use crate::fake::clock::FakeClock;
use crate::fake::signer::{FixtureSigner, ReplyShape, FIXTURE_COSE_KEY};
use crate::{BridgeError, MonotonicClock, ProtocolCode, RejectedCode, UnavailableCode};

type TestResult = Result<(), String>;

/// The independently generated `assertion_reply_without_prf` vector of
/// `scripts/owner_bridge_vectors.py`: an assertion reply the way the packaged page encodes an
/// absent PRF result, with CBOR `null` where the closed decoder wants 32 bytes.
const ASSET_SHAPED_WITHOUT_PRF: &str = concat!(
    "8a44574153310150000102030405060708090a0b0c0d0e0f428081427b7d582500",
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021",
    "222324483031323334353637f6f6f6"
);

const CREDENTIAL_ID: [u8; 2] = [0x80, 0x81];

fn codec<T>(result: Result<T, OwnerBridgeCodecError>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

fn bytes(first: u8, count: usize) -> Vec<u8> {
    (0..count)
        .map(|index| first.wrapping_add(u8::try_from(index).unwrap_or(0)))
        .collect()
}

fn array<const N: usize>(first: u8) -> [u8; N] {
    let mut out = [0; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = first.wrapping_add(u8::try_from(index).unwrap_or(0));
    }
    out
}

fn plan(kind: CeremonyKind, stored: bool) -> Result<CeremonyPlan, String> {
    let stored = stored
        .then(|| {
            codec(CoseEs256PublicKey::from_canonical_encoding(
                &FIXTURE_COSE_KEY,
            ))
            .map(|public_key| StoredGet {
                credential_id: CREDENTIAL_ID.to_vec(),
                user_handle: OwnerUserHandle::from_bytes(array(0x40)),
                public_key,
                backup_eligible: false,
                backup_state: false,
                sign_count: 0,
            })
        })
        .transpose()?;
    Ok(CeremonyPlan {
        kind,
        ceremony_id: CeremonyId::from_bytes(array(0)),
        challenge: Zeroizing::new(array(0x20)),
        user_handle: Zeroizing::new(array(0x40)),
        prf_input: Zeroizing::new(array(0x60)),
        stored,
        t0: FakeClock::start().now(),
        generation: 1,
        owner_window: None,
        budget: None,
    })
}

fn assertion_bytes(id: [u8; 16]) -> Result<Vec<u8>, String> {
    let (authenticator_data, signature) = (bytes(0, 0x25), bytes(0x30, 8));
    let reply = codec(AssertionReplyV1::new(
        CeremonyId::from_bytes(id),
        &CREDENTIAL_ID,
        b"{}",
        &authenticator_data,
        &signature,
        None,
        PrfResult::from_bytes(array(0xa0)),
    ))?;
    let mut buffer = vec![0; 1_024];
    let length = codec(encode_assertion_reply(&reply, &mut buffer))?;
    buffer.truncate(length);
    Ok(buffer)
}

fn attestation_bytes() -> Result<Vec<u8>, String> {
    let transports = codec(TransportCodes::new(&[0]))?;
    let reply = codec(AttestationReplyV1::new(
        CeremonyId::from_bytes(array(0)),
        &CREDENTIAL_ID,
        b"{}",
        &[0xa0],
        transports,
        true,
        Some(PrfResult::from_bytes(array(0xa0))),
    ))?;
    let mut buffer = vec![0; 1_024];
    let length = codec(encode_attestation_reply(&reply, &mut buffer))?;
    buffer.truncate(length);
    Ok(buffer)
}

fn without_prf(payload: &[u8]) -> Result<Vec<u8>, String> {
    replace_prf(payload, &PRF_NULL).ok_or_else(|| "the PRF item was not found".to_owned())
}

fn with_prf_item(payload: &[u8], item: &[u8]) -> Result<Vec<u8>, String> {
    replace_prf(payload, item).ok_or_else(|| "the PRF item was not found".to_owned())
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    (0..text.len() / 2)
        .map(|index| {
            let pair = text.get(index * 2..index * 2 + 2).unwrap_or_default();
            u8::from_str_radix(pair, 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn outcome(plan: &CeremonyPlan, payload: &[u8]) -> Option<BridgeError> {
    let mut prf = Zeroizing::new([0_u8; 32]);
    parse_and_verify(plan, payload, &mut prf).err()
}

const PRF_UNSUPPORTED: BridgeError = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);

#[test]
fn a_get_plan_without_a_stored_credential_cannot_verify() -> TestResult {
    let signer = codec(FixtureSigner::new(&CREDENTIAL_ID))?;
    let payload = codec(signer.assertion_payload(
        CeremonyId::from_bytes(array(0)),
        &WebAuthnChallenge::from_bytes(array(0x20)),
        &ReplyShape::honest(1, Some(array(0xa0))),
    ))?;
    assert_eq!(
        outcome(&plan(CeremonyKind::Get, false)?, &payload),
        Some(BridgeError::Rejected(RejectedCode::CredentialMismatch))
    );
    Ok(())
}

#[test]
fn the_rust_codec_and_the_independent_vector_agree_on_the_asset_shaped_reply() -> TestResult {
    let expected = decode_hex(ASSET_SHAPED_WITHOUT_PRF)?;
    let encoded = without_prf(&assertion_bytes(array(0))?)?;
    assert_eq!(encoded, expected);
    Ok(())
}

#[test]
fn an_asset_shaped_reply_with_an_absent_prf_is_prf_unsupported() -> TestResult {
    let payload = decode_hex(ASSET_SHAPED_WITHOUT_PRF)?;
    assert_eq!(
        outcome(&plan(CeremonyKind::Get, true)?, &payload),
        Some(PRF_UNSUPPORTED)
    );
    Ok(())
}

#[test]
fn a_malformed_required_prf_is_prf_unsupported_in_both_kinds() -> TestResult {
    let short: Vec<u8> = [vec![0x58, 0x1f], bytes(1, 31)].concat();
    let long: Vec<u8> = [vec![0x58, 0x21], bytes(1, 33)].concat();
    let items: [&[u8]; 5] = [&short, &long, &[0x63, b'a', b'b', b'c'], &[0x80], &[0xf5]];
    let get = assertion_bytes(array(0))?;
    for item in items {
        let payload = with_prf_item(&get, item)?;
        assert_eq!(
            outcome(&plan(CeremonyKind::Get, true)?, &payload),
            Some(PRF_UNSUPPORTED),
            "get {item:02x?}"
        );
    }
    let create = attestation_bytes()?;
    for item in items {
        let payload = with_prf_item(&create, item)?;
        assert_eq!(
            outcome(&plan(CeremonyKind::Create, false)?, &payload),
            Some(PRF_UNSUPPORTED),
            "create {item:02x?}"
        );
    }
    Ok(())
}

#[test]
fn an_absent_prf_never_hides_another_defect() -> TestResult {
    let get_plan = plan(CeremonyKind::Get, true)?;
    let wrong_id = without_prf(&assertion_bytes(array(1))?)?;
    assert_eq!(
        outcome(&get_plan, &wrong_id),
        Some(BridgeError::Protocol(ProtocolCode::CeremonyIdMismatch))
    );
    let trailing = [decode_hex(ASSET_SHAPED_WITHOUT_PRF)?, vec![0]].concat();
    assert_eq!(
        outcome(&get_plan, &trailing),
        Some(BridgeError::Protocol(ProtocolCode::Malformed))
    );
    let with_map = with_prf_item(&assertion_bytes(array(0))?, &[0xa0])?;
    assert_eq!(
        outcome(&get_plan, &with_map),
        Some(BridgeError::Protocol(ProtocolCode::Malformed))
    );
    for garbage in [&[0xff][..], &[]] {
        assert!(matches!(
            outcome(&get_plan, garbage),
            Some(BridgeError::Protocol(_))
        ));
    }
    Ok(())
}

#[test]
fn a_valid_prf_that_fails_elsewhere_keeps_the_codecs_own_error() -> TestResult {
    let mut payload = assertion_bytes(array(0))?;
    payload.push(0);
    assert_eq!(
        outcome(&plan(CeremonyKind::Get, true)?, &payload),
        Some(BridgeError::Protocol(ProtocolCode::Malformed))
    );
    Ok(())
}
