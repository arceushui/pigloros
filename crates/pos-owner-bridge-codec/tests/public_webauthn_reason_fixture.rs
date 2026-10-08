//! Replays the independently generated per-reason fixture cases.
//!
//! `scripts/owner_bridge_webauthn_fixtures.py` produces every case with its
//! own P-256 arithmetic. Each case differs from the baseline fixture in one
//! verifier fault and names the one `VerificationReason` it must report.

use pos_owner_bridge_codec::{
    decode_assertion_reply, decode_attestation_reply, verify_assertion_reply,
    verify_attestation_reply, AssertionReplyV1, AssertionVerificationContext, AttestationReplyV1,
    CeremonyId, CoseEs256PublicKey, CreateVerificationContext, OwnerBridgeCodecError,
    OwnerUserHandle, PrfResult, StoredCredential, TransportCodes, VerificationReason,
    WebAuthnChallenge,
};

const BASELINE: &str = include_str!("../../../fixtures/owner-bridge/webauthn-es256-v1.fixture");
const REASONS: &str = include_str!("../../../fixtures/owner-bridge/webauthn-reasons-v1.fixture");

/// The number of cases the generator writes today.
const MINIMUM_CASES: usize = 73;

/// A case name that no fixture line uses, so every field keeps its baseline.
const NO_CASE: &str = "baseline";

const ALL_REASONS: [(&str, VerificationReason); 21] = [
    ("CeremonyIdMismatch", VerificationReason::CeremonyIdMismatch),
    ("PrfUnsupported", VerificationReason::PrfUnsupported),
    ("Malformed", VerificationReason::Malformed),
    ("Origin", VerificationReason::Origin),
    ("RpIdHash", VerificationReason::RpIdHash),
    ("ClientDataType", VerificationReason::ClientDataType),
    ("Challenge", VerificationReason::Challenge),
    ("CrossOrigin", VerificationReason::CrossOrigin),
    ("UserPresence", VerificationReason::UserPresence),
    ("UserVerification", VerificationReason::UserVerification),
    ("AttestationFormat", VerificationReason::AttestationFormat),
    ("Algorithm", VerificationReason::Algorithm),
    ("CoseKey", VerificationReason::CoseKey),
    ("Extensions", VerificationReason::Extensions),
    ("Signature", VerificationReason::Signature),
    ("CredentialMismatch", VerificationReason::CredentialMismatch),
    ("UserHandleMismatch", VerificationReason::UserHandleMismatch),
    ("CounterRegression", VerificationReason::CounterRegression),
    ("BackupFlags", VerificationReason::BackupFlags),
    ("PrfMalformed", VerificationReason::PrfMalformed),
    ("PrfAbsent", VerificationReason::PrfAbsent),
];

/// The row of `ALL_REASONS` that must name `reason`.
///
/// The match has no wildcard, so a new variant fails to compile until it is listed here.
const fn position(reason: VerificationReason) -> usize {
    match reason {
        VerificationReason::CeremonyIdMismatch => 0,
        VerificationReason::PrfUnsupported => 1,
        VerificationReason::Malformed => 2,
        VerificationReason::Origin => 3,
        VerificationReason::RpIdHash => 4,
        VerificationReason::ClientDataType => 5,
        VerificationReason::Challenge => 6,
        VerificationReason::CrossOrigin => 7,
        VerificationReason::UserPresence => 8,
        VerificationReason::UserVerification => 9,
        VerificationReason::AttestationFormat => 10,
        VerificationReason::Algorithm => 11,
        VerificationReason::CoseKey => 12,
        VerificationReason::Extensions => 13,
        VerificationReason::Signature => 14,
        VerificationReason::CredentialMismatch => 15,
        VerificationReason::UserHandleMismatch => 16,
        VerificationReason::CounterRegression => 17,
        VerificationReason::BackupFlags => 18,
        VerificationReason::PrfMalformed => 19,
        VerificationReason::PrfAbsent => 20,
    }
}

#[test]
fn every_fixture_case_reports_its_exact_reason() -> Result<(), OwnerBridgeCodecError> {
    let mut replayed = 0;
    for line in REASONS.lines() {
        let Some(case) = line.strip_prefix("case=") else {
            continue;
        };
        replayed += 1;
        let expected = reason_named(case_value(case, "reason")?)?;
        assert_eq!(run_case(case)?, Some(expected), "{case}");
    }
    // A truncated fixture must fail instead of replaying fewer cases.
    assert!(replayed >= MINIMUM_CASES, "{replayed}");
    Ok(())
}

#[test]
fn every_verification_reason_has_a_fixture_case() {
    for (index, (name, reason)) in ALL_REASONS.iter().enumerate() {
        assert_eq!(position(*reason), index);
        assert!(REASONS.lines().any(|line| names_reason(line, name)), "{name}");
    }
}

#[test]
fn the_baseline_replies_still_verify() -> Result<(), OwnerBridgeCodecError> {
    assert_eq!(run_create(NO_CASE)?, None);
    assert_eq!(run_get(NO_CASE)?, None);
    Ok(())
}

fn names_reason(line: &str, name: &str) -> bool {
    line.split_once(".reason=").is_some_and(|(_, value)| value == name)
}

fn run_case(case: &str) -> Result<Option<VerificationReason>, OwnerBridgeCodecError> {
    match case_value(case, "kind")? {
        "create" => run_create(case),
        "get" => run_get(case),
        "decode_attestation" => run_decode(case, true),
        "decode_assertion" => run_decode(case, false),
        _ => Err(OwnerBridgeCodecError::InvalidPayload),
    }
}

fn run_decode(
    case: &str,
    attestation: bool,
) -> Result<Option<VerificationReason>, OwnerBridgeCodecError> {
    let payload = decode_hex(case_value(case, "payload")?)?;
    let failure = if attestation {
        decode_attestation_reply(&payload).err()
    } else {
        decode_assertion_reply(&payload).err()
    };
    match failure {
        None => Ok(None),
        Some(OwnerBridgeCodecError::Verification(reason)) => Ok(Some(reason)),
        Some(error) => Err(error),
    }
}

fn run_create(case: &str) -> Result<Option<VerificationReason>, OwnerBridgeCodecError> {
    let challenge = WebAuthnChallenge::from_bytes(baseline_array("challenge")?);
    let baseline_id = CeremonyId::from_bytes(baseline_array("ceremony_id")?);
    let reply_id = CeremonyId::from_bytes(case_array(case, "reply_ceremony_id", "ceremony_id")?);
    let client_data = case_bytes(case, "client_data_json", "create_client_data_json")?;
    let attestation_object = case_bytes(case, "attestation_object", "attestation_object")?;
    let raw_id = case_bytes(case, "raw_id", "credential_id")?;
    let prf_enabled = case_value_or(case, "prf_enabled", "true") == "true";
    let reply = AttestationReplyV1::new(
        reply_id,
        &raw_id,
        &client_data,
        &attestation_object,
        TransportCodes::new(&[0])?,
        prf_enabled,
        Some(PrfResult::from_bytes(baseline_array("prf_first")?)),
    )?;
    let context = CreateVerificationContext::new(baseline_id, challenge);
    Ok(verify_attestation_reply(&reply, context).err())
}

fn run_get(case: &str) -> Result<Option<VerificationReason>, OwnerBridgeCodecError> {
    let challenge = WebAuthnChallenge::from_bytes(baseline_array("challenge")?);
    let baseline_id = CeremonyId::from_bytes(baseline_array("ceremony_id")?);
    let reply_id = CeremonyId::from_bytes(case_array(case, "reply_ceremony_id", "ceremony_id")?);
    let stored_id = baseline_bytes("credential_id")?;
    let stored_handle = OwnerUserHandle::from_bytes(baseline_array("user_handle")?);
    let client_data = case_bytes(case, "client_data_json", "assertion_client_data_json")?;
    let authenticator_data =
        case_bytes(case, "authenticator_data", "assertion_authenticator_data")?;
    let signature = case_bytes(case, "signature", "assertion_signature_der")?;
    let raw_id = case_bytes(case, "raw_id", "credential_id")?;
    let handle = case_optional_array(case, "user_handle")?;
    let reply_handle = handle.map(OwnerUserHandle::from_bytes);
    let stored_counter = case_value_or(case, "stored_sign_count", "0")
        .parse::<u32>()
        .map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
    let key_bytes = baseline_bytes("public_key_cose")?;
    let public_key = CoseEs256PublicKey::from_canonical_encoding(&key_bytes)?;
    let credential = StoredCredential::new(
        &stored_id,
        stored_handle,
        public_key,
        false,
        false,
        stored_counter,
    )?;
    let reply = AssertionReplyV1::new(
        reply_id,
        &raw_id,
        &client_data,
        &authenticator_data,
        &signature,
        reply_handle,
        PrfResult::from_bytes(baseline_array("prf_first")?),
    )?;
    let context = AssertionVerificationContext::new(baseline_id, challenge, credential);
    Ok(verify_assertion_reply(&reply, context).err())
}

fn reason_named(name: &str) -> Result<VerificationReason, OwnerBridgeCodecError> {
    ALL_REASONS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, reason)| *reason)
        .ok_or(OwnerBridgeCodecError::InvalidPayload)
}

fn lookup(source: &'static str, key: &str) -> Option<&'static str> {
    let prefix = format!("{key}=");
    source.lines().find_map(|line| line.strip_prefix(&prefix))
}

fn case_lookup(case: &str, field: &str) -> Option<&'static str> {
    lookup(REASONS, &format!("{case}.{field}"))
}

fn case_value(case: &str, field: &str) -> Result<&'static str, OwnerBridgeCodecError> {
    case_lookup(case, field).ok_or(OwnerBridgeCodecError::InvalidPayload)
}

fn case_value_or(case: &str, field: &str, default: &'static str) -> &'static str {
    case_lookup(case, field).unwrap_or(default)
}

fn baseline_bytes(name: &str) -> Result<Vec<u8>, OwnerBridgeCodecError> {
    let value = lookup(BASELINE, name).ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    decode_hex(value)
}

fn baseline_array<const N: usize>(name: &str) -> Result<[u8; N], OwnerBridgeCodecError> {
    baseline_bytes(name)?
        .try_into()
        .map_err(|_| OwnerBridgeCodecError::InvalidPayload)
}

fn case_bytes(case: &str, field: &str, baseline: &str) -> Result<Vec<u8>, OwnerBridgeCodecError> {
    case_lookup(case, field).map_or_else(|| baseline_bytes(baseline), decode_hex)
}

fn case_array<const N: usize>(
    case: &str,
    field: &str,
    baseline: &str,
) -> Result<[u8; N], OwnerBridgeCodecError> {
    case_bytes(case, field, baseline)?
        .try_into()
        .map_err(|_| OwnerBridgeCodecError::InvalidPayload)
}

fn case_optional_array<const N: usize>(
    case: &str,
    field: &str,
) -> Result<Option<[u8; N]>, OwnerBridgeCodecError> {
    let Some(value) = case_lookup(case, field) else {
        return Ok(None);
    };
    decode_hex(value)?
        .try_into()
        .map(Some)
        .map_err(|_| OwnerBridgeCodecError::InvalidPayload)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, OwnerBridgeCodecError> {
    let digits = input
        .bytes()
        .map(hex_nibble)
        .collect::<Result<Vec<u8>, OwnerBridgeCodecError>>()?;
    if digits.len() % 2 != 0 {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    Ok(digits
        .chunks_exact(2)
        .map(|pair| pair.iter().fold(0_u8, |byte, digit| (byte << 4) | digit))
        .collect())
}

const fn hex_nibble(value: u8) -> Result<u8, OwnerBridgeCodecError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(OwnerBridgeCodecError::InvalidPayload),
    }
}
