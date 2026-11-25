//! The native client against the software authenticator: LS4 shaping, LS6, LS7 and LP1–LP4.

use hmac::{Hmac, KeyInit, Mac};
use pos_owner_bridge::fake::clock::FakeRandom;
use pos_owner_bridge::{
    BridgeError, MonotonicClock, OwnerAuthenticatorPort, ProtocolCode, ReplyImage, RequestImage,
    UnavailableCode,
};
use pos_owner_bridge_codec::CeremonyKind;
use pos_owner_ctap::{CtapAuthenticator, HidTransport, Notice, TransportError};
use sha2::{Digest, Sha256};

use super::{
    bytes, counting, head, map, ok, text_item, Ceremony, Prompt, Rig, TestResult, CLIENT_FAILED,
    GET_ASSERTION, GET_INFO, KEY_AGREEMENT, MAKE_CREDENTIAL, NO_TERMINAL, PIN, PIN_RETRIES,
    PRF_UNSUPPORTED, TIMEOUT, TOKEN_PIN, TOKEN_UV, UV_RETRIES,
};

const MALFORMED: BridgeError = BridgeError::Protocol(ProtocolCode::Malformed);
const OUT_OF_BOUNDS: BridgeError = BridgeError::Protocol(ProtocolCode::LengthOutOfBounds);
const RNG: BridgeError = BridgeError::Unavailable(UnavailableCode::RngUnavailable);
const KNOWN: [&[u8]; 8] = [
    GET_INFO,
    PIN_RETRIES,
    UV_RETRIES,
    KEY_AGREEMENT,
    TOKEN_UV,
    TOKEN_PIN,
    MAKE_CREDENTIAL,
    GET_ASSERTION,
];

/// `output1 = HMAC-SHA-256(CredRandom, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ prf_input))`, computed
/// here independently of the crate (ADR-110 E20 LP4).
fn webauthn_prf(cred_random: &[u8; 32], prf_input: &[u8; 32]) -> Result<[u8; 32], String> {
    let salt = Sha256::new()
        .chain_update(b"WebAuthn PRF")
        .chain_update([0_u8])
        .chain_update(prf_input)
        .finalize();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(cred_random)
        .map_err(|error| error.to_string())?;
    mac.update(&salt);
    Ok(mac.finalize().into_bytes().into())
}

#[test]
fn a_pin_ceremony_enrolls_and_asserts_with_the_webauthn_prf() -> TestResult {
    let mut rig = Rig::new(false);
    rig.prompt.enter(PIN);
    rig.prompt.enter(PIN);
    let create = Ceremony::drawn("create");
    let enrolled = rig.create(&create)?;
    assert!(enrolled.prf_enabled);
    assert!(!enrolled.create_prf);
    assert_eq!(enrolled.transports, [0]);
    assert_eq!(enrolled.sign_count, 0);
    assert_eq!(rig.commands(&KNOWN), [0, 1, 3, 5, 6]);

    let get = Ceremony::drawn("get");
    let (prf, sign_count) = rig.get(&get, create.user, &enrolled)?;
    assert_eq!(sign_count, 1);
    let cred_random = rig
        .device
        .with_authenticator(|soft| soft.cred_random(&enrolled.credential_id))
        .ok_or("no credential")?;
    assert_eq!(prf, webauthn_prf(&cred_random, get.prf.as_bytes())?);
    assert_eq!(rig.commands(&KNOWN), [0, 1, 3, 5, 6, 0, 1, 3, 5, 7]);
    assert_eq!(rig.prompt.asked(), [8, 8]);
    assert_eq!(rig.prompt.notices(), [Notice::Touch, Notice::Touch]);
    Ok(())
}

#[test]
fn the_same_prf_input_gives_the_same_prf_and_another_input_does_not() -> TestResult {
    let mut rig = Rig::new(true);
    let create = Ceremony::drawn("create");
    let mut enrolled = rig.create(&create)?;
    let first_get = Ceremony::drawn("get");
    let (first, count) = rig.get(&first_get, create.user, &enrolled)?;
    enrolled.sign_count = count;
    let same_input = Ceremony {
        prf: first_get.prf,
        ..Ceremony::drawn("again")
    };
    let (second, count) = rig.get(&same_input, create.user, &enrolled)?;
    assert_eq!(first, second);
    assert_eq!(count, 2);
    enrolled.sign_count = count;
    let (other, _) = rig.get(&Ceremony::drawn("other"), create.user, &enrolled)?;
    assert_ne!(first, other);
    Ok(())
}

#[test]
fn built_in_uv_comes_first_and_needs_no_pin() -> TestResult {
    let mut rig = Rig::new(true);
    rig.create(&Ceremony::drawn("create"))?;
    assert_eq!(rig.commands(&KNOWN), [0, 2, 3, 4, 6]);
    assert!(rig.prompt.asked().is_empty());
    let expected = [Notice::UserVerification { retries: 3 }, Notice::Touch];
    assert_eq!(rig.prompt.notices(), expected);
    Ok(())
}

#[test]
fn uv_without_retries_or_blocked_falls_back_to_the_pin() -> TestResult {
    let mut rig = Rig::new(true);
    rig.device.with_authenticator(|soft| soft.set_uv(0, 0));
    rig.prompt.enter(PIN);
    rig.create(&Ceremony::drawn("create"))?;
    assert_eq!(rig.commands(&KNOWN), [0, 2, 1, 3, 5, 6]);
    assert_eq!(rig.prompt.notices(), [Notice::Touch]);

    let mut rig = Rig::new(true);
    rig.device.override_reply(TOKEN_UV, &[0x3c]);
    rig.prompt.enter(PIN);
    rig.create(&Ceremony::drawn("create"))?;
    assert_eq!(rig.commands(&KNOWN), [0, 2, 3, 4, 1, 3, 5, 6]);
    let expected = [Notice::UserVerification { retries: 3 }, Notice::Touch];
    assert_eq!(rig.prompt.notices(), expected);
    Ok(())
}

#[test]
fn a_rejected_uv_attempt_is_retried_within_the_authenticator_count() -> TestResult {
    let mut rig = Rig::new(true);
    rig.device.with_authenticator(|soft| soft.set_uv(3, 1));
    rig.create(&Ceremony::drawn("create"))?;
    assert_eq!(rig.device.with_authenticator(|soft| soft.uv_retries()), 2);
    assert_eq!(rig.commands(&KNOWN), [0, 2, 3, 4, 2, 3, 4, 6]);
    let expected = [
        Notice::UserVerification { retries: 3 },
        Notice::UserVerification { retries: 2 },
        Notice::Touch,
    ];
    assert_eq!(rig.prompt.notices(), expected);
    assert!(rig.prompt.asked().is_empty());
    Ok(())
}

#[test]
fn uv_attempts_are_capped_at_the_first_retry_count() -> TestResult {
    let mut rig = Rig::new(true);
    let three = ok(&map(&[(head(0, 5), head(0, 3))]));
    for _ in 0..4 {
        rig.device.override_reply(UV_RETRIES, &three);
        rig.device.override_reply(TOKEN_UV, &[0x3f]);
    }
    rig.prompt.enter(PIN);
    rig.create(&Ceremony::drawn("create"))?;
    let expected = [0, 2, 3, 4, 2, 3, 4, 2, 3, 4, 2, 1, 3, 5, 6];
    assert_eq!(rig.commands(&KNOWN), expected);
    assert_eq!(rig.prompt.asked(), [8]);

    // A later answer of zero ends the loop even while attempts from the first answer remain.
    let mut rig = Rig::new(true);
    rig.device.override_reply(UV_RETRIES, &three);
    rig.device.override_reply(TOKEN_UV, &[0x3f]);
    rig.device
        .override_reply(UV_RETRIES, &ok(&map(&[(head(0, 5), head(0, 0))])));
    rig.prompt.enter(PIN);
    rig.create(&Ceremony::drawn("create"))?;
    assert_eq!(rig.commands(&KNOWN), [0, 2, 3, 4, 2, 1, 3, 5, 6]);
    let expected = [Notice::UserVerification { retries: 3 }, Notice::Touch];
    assert_eq!(rig.prompt.notices(), expected);
    assert_eq!(rig.prompt.asked(), [8]);

    let mut rig = Rig::new(true);
    rig.device.override_reply(UV_RETRIES, &three);
    rig.device.override_reply(UV_RETRIES, &[0x01]);
    rig.device.override_reply(TOKEN_UV, &[0x3f]);
    let request = Ceremony::drawn("create").create_request()?;
    assert_eq!(
        rig.perform(&request, CeremonyKind::Create),
        Err(CLIENT_FAILED)
    );
    Ok(())
}

#[test]
fn exhausted_uv_retries_fall_back_to_the_pin() -> TestResult {
    let mut rig = Rig::new(true);
    rig.device.with_authenticator(|soft| soft.set_uv(2, 2));
    rig.prompt.enter(PIN);
    rig.create(&Ceremony::drawn("create"))?;
    assert_eq!(rig.device.with_authenticator(|soft| soft.uv_retries()), 0);
    assert_eq!(rig.commands(&KNOWN), [0, 2, 3, 4, 2, 3, 4, 2, 1, 3, 5, 6]);
    assert_eq!(rig.prompt.asked(), [8]);
    Ok(())
}

#[test]
fn a_pin_entry_that_outlasts_the_deadline_times_out_and_is_never_sent() -> TestResult {
    let request = Ceremony::drawn("create").create_request()?;
    for honours_deadline in [true, false] {
        let mut rig = Rig::new(false);
        rig.prompt
            .enter_after(std::time::Duration::from_mins(3), PIN, honours_deadline);
        assert_eq!(rig.perform(&request, CeremonyKind::Create), Err(TIMEOUT));
        assert_eq!(rig.commands(&KNOWN), [0, 1, 3]);
        assert_eq!(rig.device.cancels(), 0);
    }
    let mut rig = Rig::new(false);
    rig.prompt
        .enter_after(std::time::Duration::from_secs(30), PIN, true);
    rig.create(&Ceremony::drawn("create"))?;
    Ok(())
}

#[test]
fn a_wrong_pin_fails_once_and_is_not_retried() -> TestResult {
    let mut rig = Rig::new(false);
    rig.prompt.enter(b"1357");
    rig.prompt.enter(PIN);
    let request = Ceremony::drawn("create").create_request()?;
    assert_eq!(
        rig.perform(&request, CeremonyKind::Create),
        Err(CLIENT_FAILED)
    );
    assert_eq!(rig.device.with_authenticator(|soft| soft.pin_retries()), 7);
    assert_eq!(rig.commands(&KNOWN), [0, 1, 3, 5]);
    assert_eq!(rig.prompt.asked(), [8]);
    rig.create(&Ceremony::drawn("create"))?;
    assert_eq!(rig.prompt.asked(), [8, 7]);
    Ok(())
}

#[test]
fn a_blocked_pin_is_reported_and_never_retried() -> TestResult {
    let mut rig = Rig::new(false);
    rig.device
        .with_authenticator(|soft| soft.set_pin_retries(0));
    let request = Ceremony::drawn("create").create_request()?;
    assert_eq!(
        rig.perform(&request, CeremonyKind::Create),
        Err(CLIENT_FAILED)
    );
    assert!(rig.prompt.asked().is_empty());
    assert_eq!(rig.prompt.notices(), [Notice::PinBlocked]);

    for status in [0x32, 0x34] {
        let mut rig = Rig::new(false);
        rig.device.override_reply(TOKEN_PIN, &[status]);
        rig.prompt.enter(PIN);
        assert_eq!(
            rig.perform(&request, CeremonyKind::Create),
            Err(CLIENT_FAILED)
        );
        assert_eq!(rig.prompt.notices(), [Notice::PinBlocked]);
    }
    Ok(())
}

#[test]
fn the_pin_is_at_least_four_code_points_of_at_most_63_utf8_bytes() -> TestResult {
    let request = Ceremony::drawn("create").create_request()?;
    for entry in [&b"123"[..], &[0xff, 0xfe, 0xfd, 0xfc], &[b'7'; 64]] {
        let mut rig = Rig::new(false);
        rig.prompt.enter(entry);
        assert_eq!(
            rig.perform(&request, CeremonyKind::Create),
            Err(CLIENT_FAILED)
        );
        assert_eq!(rig.commands(&KNOWN), [0, 1, 3]);
    }
    let longest = [b'7'; 63];
    let multibyte = "ä€𝄞x".as_bytes();
    for pin in [&longest[..], multibyte] {
        let mut rig = Rig::with_pin(false, pin);
        rig.prompt.enter(pin);
        rig.create(&Ceremony::drawn("create"))?;
    }
    Ok(())
}

#[test]
fn the_pin_is_normalized_to_nfc_before_it_is_hashed() -> TestResult {
    let precomposed: String = ['\u{e9}', '1', '2', '3'].iter().collect();
    let decomposed: String = ['e', '\u{301}', '1', '2', '3'].iter().collect();
    assert_ne!(precomposed, decomposed);
    for entered in [&decomposed, &precomposed] {
        let mut rig = Rig::with_pin(false, precomposed.as_bytes());
        rig.prompt.enter(entered.as_bytes());
        rig.create(&Ceremony::drawn("create"))?;
    }
    let combining: String = ['e', '\u{301}', '1', '2'].iter().collect();
    assert_eq!(combining.chars().count(), 4);
    let mut rig = Rig::with_pin(false, combining.as_bytes());
    rig.prompt.enter(combining.as_bytes());
    let request = Ceremony::drawn("create").create_request()?;
    assert_eq!(
        rig.perform(&request, CeremonyKind::Create),
        Err(CLIENT_FAILED)
    );
    assert_eq!(rig.commands(&KNOWN), [0, 1, 3]);
    let expanding: String = std::iter::repeat_n('\u{958}', 21).collect();
    assert_eq!(expanding.len(), 63);
    let mut rig = Rig::new(false);
    rig.prompt.enter(expanding.as_bytes());
    let request = Ceremony::drawn("create").create_request()?;
    assert_eq!(
        rig.perform(&request, CeremonyKind::Create),
        Err(CLIENT_FAILED)
    );
    assert_eq!(rig.commands(&KNOWN), [0, 1, 3]);
    Ok(())
}

#[test]
fn the_prompt_failure_is_the_ceremony_failure() -> TestResult {
    let request = Ceremony::drawn("create").create_request()?;
    let mut rig = Rig::new(false);
    assert_eq!(
        rig.perform(&request, CeremonyKind::Create),
        Err(NO_TERMINAL)
    );
    let mut rig = Rig::new(false);
    rig.prompt.fail(CLIENT_FAILED);
    assert_eq!(
        rig.perform(&request, CeremonyKind::Create),
        Err(CLIENT_FAILED)
    );
    Ok(())
}

/// A `getInfo` body that passes LS6 except for the item `omit`.
fn info_without(omit: usize) -> Vec<u8> {
    let entries = [
        (head(0, 1), [head(4, 1), text_item("FIDO_2_1")].concat()),
        (head(0, 2), [head(4, 1), text_item("hmac-secret")].concat()),
        (
            head(0, 4),
            map(&[
                (text_item("clientPin"), vec![0xf5]),
                (text_item("pinUvAuthToken"), vec![0xf5]),
            ]),
        ),
        (head(0, 6), vec![0x81, 0x02]),
    ];
    let kept: Vec<_> = entries
        .into_iter()
        .enumerate()
        .filter(|(index, _)| *index != omit)
        .map(|(_, entry)| entry)
        .collect();
    map(&kept)
}

#[test]
fn the_capability_check_runs_before_any_credential_is_created() -> TestResult {
    let request = Ceremony::drawn("create").create_request()?;
    let mut rig = Rig::new(false);
    rig.device
        .with_authenticator(|soft| soft.set_info(info_without(4)));
    rig.prompt.enter(PIN);
    rig.create(&Ceremony::drawn("create"))?;
    for omit in 0..4 {
        let mut rig = Rig::new(false);
        rig.device
            .with_authenticator(|soft| soft.set_info(info_without(omit)));
        rig.prompt.enter(PIN);
        assert_eq!(
            rig.perform(&request, CeremonyKind::Create),
            Err(PRF_UNSUPPORTED)
        );
        assert_eq!(rig.commands(&KNOWN), [0]);
        assert!(rig.prompt.asked().is_empty());
    }
    Ok(())
}

/// Authenticator data with `flags`, a counter of 1 and the raw `tail`.
fn get_data(flags: u8, tail: &[u8]) -> Vec<u8> {
    let mut data = counting(32);
    data.push(flags);
    data.extend_from_slice(&[0, 0, 0, 1]);
    data.extend_from_slice(tail);
    data
}

fn assertion_reply(auth_data: Option<Vec<u8>>, signature: Option<Vec<u8>>) -> Vec<u8> {
    let mut entries = Vec::new();
    if let Some(auth_data) = auth_data {
        entries.push((head(0, 2), bytes(&auth_data)));
    }
    if let Some(signature) = signature {
        entries.push((head(0, 3), bytes(&signature)));
    }
    ok(&map(&entries))
}

fn create_reply(auth_data: &[u8]) -> Vec<u8> {
    ok(&map(&[(head(0, 2), bytes(auth_data))]))
}

fn key_agreement_reply(x: Option<usize>, y: Option<usize>) -> Vec<u8> {
    let mut key = Vec::new();
    if let Some(length) = x {
        key.push((head(1, 1), bytes(&counting(length))));
    }
    if let Some(length) = y {
        key.push((head(1, 2), bytes(&counting(length))));
    }
    ok(&map(&[(head(0, 1), map(&key))]))
}

/// `makeCredential` authenticator data whose credential ID is `length` bytes.
fn create_data(flags: u8, length: usize) -> Vec<u8> {
    let mut data = get_data(flags, &[]);
    data.truncate(37);
    data.extend_from_slice(&counting(16));
    data.extend_from_slice(&u16::try_from(length).unwrap_or(0).to_be_bytes());
    data.extend_from_slice(&counting(length));
    data.extend_from_slice(&map(&[(head(0, 1), head(0, 2))]));
    data
}

/// Run one ceremony whose `prefix` request is answered with `reply`, and check its failure.
fn refused(
    uv: bool,
    kind: CeremonyKind,
    prefix: &[u8],
    reply: &[u8],
    expected: BridgeError,
) -> TestResult {
    let ceremony = Ceremony::drawn("malformed");
    let mut rig = Rig::new(uv);
    rig.device.override_reply(prefix, reply);
    rig.prompt.enter(PIN);
    let request = if kind == CeremonyKind::Create {
        ceremony.create_request()?
    } else {
        ceremony.get_request(&counting(8))?
    };
    assert_eq!(
        rig.perform(&request, kind),
        Err(expected),
        "{prefix:?} {reply:?}"
    );
    Ok(())
}

fn create_refused(prefix: &[u8], reply: &[u8]) -> TestResult {
    refused(false, CeremonyKind::Create, prefix, reply, CLIENT_FAILED)
}

#[test]
fn failed_or_malformed_info_retries_and_key_agreement_fail_the_client() -> TestResult {
    for reply in [vec![0x00, 0xa1], vec![0x01], Vec::new()] {
        create_refused(GET_INFO, &reply)?;
    }
    create_refused(PIN_RETRIES, &[0x00, 0xa0])?;
    create_refused(PIN_RETRIES, &[0x31])?;
    refused(
        true,
        CeremonyKind::Create,
        UV_RETRIES,
        &[0x00, 0xa0],
        CLIENT_FAILED,
    )?;
    let key_agreements = [
        vec![0x00, 0xa0],
        vec![0x2e],
        key_agreement_reply(None, Some(32)),
        key_agreement_reply(Some(32), None),
        key_agreement_reply(Some(32), Some(31)),
        key_agreement_reply(Some(32), Some(32)),
    ];
    for reply in key_agreements {
        create_refused(KEY_AGREEMENT, &reply)?;
    }
    refused(
        true,
        CeremonyKind::Create,
        KEY_AGREEMENT,
        &[0x00, 0xa0],
        CLIENT_FAILED,
    )
}

#[test]
fn failed_or_malformed_tokens_fail_the_client() -> TestResult {
    refused(true, CeremonyKind::Create, TOKEN_UV, &[0x27], CLIENT_FAILED)?;
    let one_block = ok(&map(&[(head(0, 2), bytes(&counting(32)))]));
    for reply in [vec![0x31], vec![0x00, 0xff], vec![0x00, 0xa0], one_block] {
        create_refused(TOKEN_PIN, &reply)?;
    }
    Ok(())
}

#[test]
fn failed_or_malformed_credentials_fail_the_client() -> TestResult {
    let no_attested_credential = create_reply(&get_data(0x85, &[]));
    for reply in [
        vec![0x2e],
        vec![0x00, 0xff],
        ok(&map(&[])),
        no_attested_credential,
    ] {
        create_refused(MAKE_CREDENTIAL, &reply)?;
    }
    let long_id = create_reply(&create_data(0x45, 1_025));
    refused(
        false,
        CeremonyKind::Create,
        MAKE_CREDENTIAL,
        &long_id,
        OUT_OF_BOUNDS,
    )
}

#[test]
fn failed_or_malformed_assertions_fail_the_client() -> TestResult {
    let output = map(&[(text_item("hmac-secret"), bytes(&counting(48)))]);
    let failing = [
        vec![0x2e],
        vec![0x00, 0xff],
        assertion_reply(None, Some(counting(70))),
        assertion_reply(Some(get_data(0x85, &output)), None),
    ];
    for reply in failing {
        refused(
            false,
            CeremonyKind::Get,
            GET_ASSERTION,
            &reply,
            CLIENT_FAILED,
        )?;
    }
    let no_output = assertion_reply(Some(get_data(0x05, &[])), Some(counting(70)));
    refused(
        false,
        CeremonyKind::Get,
        GET_ASSERTION,
        &no_output,
        PRF_UNSUPPORTED,
    )?;
    let long_signature = assertion_reply(Some(get_data(0x85, &output)), Some(counting(81)));
    refused(
        false,
        CeremonyKind::Get,
        GET_ASSERTION,
        &long_signature,
        OUT_OF_BOUNDS,
    )
}

#[test]
fn an_assertion_for_an_unknown_credential_fails_the_client() -> TestResult {
    let mut rig = Rig::new(false);
    rig.prompt.enter(PIN);
    let request = Ceremony::drawn("get").get_request(&counting(32))?;
    assert_eq!(rig.perform(&request, CeremonyKind::Get), Err(CLIENT_FAILED));
    Ok(())
}

#[test]
fn every_unanswered_command_ends_at_the_deadline_with_a_cancel() -> TestResult {
    let ceremony = Ceremony::drawn("deadline");
    let cases: [(bool, CeremonyKind, &[u8]); 8] = [
        (false, CeremonyKind::Create, GET_INFO),
        (false, CeremonyKind::Create, PIN_RETRIES),
        (false, CeremonyKind::Create, KEY_AGREEMENT),
        (false, CeremonyKind::Create, TOKEN_PIN),
        (false, CeremonyKind::Create, MAKE_CREDENTIAL),
        (true, CeremonyKind::Create, UV_RETRIES),
        (true, CeremonyKind::Create, TOKEN_UV),
        (true, CeremonyKind::Get, GET_ASSERTION),
    ];
    for (uv, kind, prefix) in cases {
        let mut rig = Rig::new(uv);
        rig.device.drop_reply(prefix);
        rig.prompt.enter(PIN);
        let deadline = rig.deadline();
        let request = if kind == CeremonyKind::Create {
            ceremony.create_request()?
        } else {
            ceremony.get_request(&counting(8))?
        };
        assert_eq!(rig.perform(&request, kind), Err(TIMEOUT), "{prefix:?}");
        assert_eq!(rig.clock.now(), deadline);
        assert_eq!(rig.device.cancels(), 1);
    }
    Ok(())
}

#[test]
fn a_request_image_that_does_not_decode_is_malformed() -> TestResult {
    let mut rig = Rig::new(false);
    assert_eq!(
        rig.perform(&RequestImage::zeroed(), CeremonyKind::Create),
        Err(MALFORMED)
    );
    let mut garbled = Ceremony::drawn("garbled").create_request()?;
    garbled.as_mut_bytes()[64] ^= 0xff;
    assert_eq!(rig.perform(&garbled, CeremonyKind::Create), Err(MALFORMED));
    assert!(rig.device.requests().is_empty());
    Ok(())
}

/// A device that refuses every write.
struct Unplugged;

impl HidTransport for Unplugged {
    fn write_report(&mut self, _report: &[u8; 64]) -> Result<(), TransportError> {
        Err(TransportError)
    }

    fn read_report(
        &mut self,
        _report: &mut [u8; 64],
        _timeout: std::time::Duration,
    ) -> Result<bool, TransportError> {
        Err(TransportError)
    }
}

#[test]
fn an_unplugged_device_or_a_failing_random_source_fails_the_ceremony() -> TestResult {
    let ceremony = Ceremony::drawn("faults");
    let rig = Rig::new(false);
    let mut unplugged = CtapAuthenticator::new(
        Unplugged,
        Prompt::new(rig.clock.clone()),
        FakeRandom::seeded(1),
    );
    let mut reply = ReplyImage::zeroed();
    let request = ceremony.create_request()?;
    let deadline = rig.deadline();
    assert_eq!(
        unplugged.perform(&request, &mut reply, deadline, &rig.clock),
        Err(CLIENT_FAILED)
    );
    let mut buffer = [0; 64];
    assert_eq!(
        Unplugged.read_report(&mut buffer, std::time::Duration::ZERO),
        Err(TransportError)
    );

    for (fills, kind) in [(0, CeremonyKind::Create), (3, CeremonyKind::Get)] {
        let prompt = Prompt::new(rig.clock.clone());
        prompt.enter(PIN);
        let mut port = CtapAuthenticator::new(
            rig.device.clone(),
            prompt,
            FakeRandom::failing_after(2, fills),
        );
        let request = if kind == CeremonyKind::Create {
            ceremony.create_request()?
        } else {
            ceremony.get_request(&counting(8))?
        };
        let mut reply = ReplyImage::zeroed();
        reply.select(kind);
        assert_eq!(
            port.perform(&request, &mut reply, deadline, &rig.clock),
            Err(RNG),
            "{fills}"
        );
    }
    Ok(())
}
