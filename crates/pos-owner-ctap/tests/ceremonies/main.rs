//! P-tier tests of the ADR-110 E20 native CTAP2 client (Redmine #1475): the client against the
//! in-process software authenticator, the fixture's own refusals, and full enrollment and unlock
//! through `OwnerBridge`, the real codec and the shared verifier.

mod bridge;
mod client;
mod soft;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::error::Error;
use std::fmt::Display;
use std::rc::Rc;
use std::time::{Duration, Instant};

use pos_owner_bridge::fake::clock::FakeClock;
use pos_owner_bridge::{
    BridgeError, LifecycleCode, MonotonicClock, OwnerAuthenticatorPort, ReplyImage, RequestImage,
    UnavailableCode,
};
use pos_owner_bridge_codec::{
    decode_assertion_reply, decode_attestation_reply, encode_create_options, encode_get_options,
    verify_assertion_reply, verify_attestation_reply, AssertionVerificationContext, CeremonyId,
    CeremonyKind, CoseEs256PublicKey, CreateOptionsV1, CreateVerificationContext, GetOptionsV1,
    OwnerBridgeControlV1, OwnerUserHandle, PrfInput, StoredCredential, WebAuthnChallenge,
    CONTROL_HEADER_BYTES,
};
use pos_owner_ctap::{
    CtapAuthenticator, Drbg, MemoryHid, Notice, PinBuffer, PinPrompt, SoftAuthenticator,
};

type TestResult = Result<(), Box<dyn Error>>;

/// The PIN every software authenticator is set up with.
const PIN: &[u8] = b"2468";

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const TIMEOUT: BridgeError = BridgeError::Lifecycle(LifecycleCode::InteractionTimeout);
const PRF_UNSUPPORTED: BridgeError = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);
const NO_TERMINAL: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

/// The CBOR request prefixes the in-memory device can intercept.
const GET_INFO: &[u8] = &[0x04];
const PIN_RETRIES: &[u8] = &[0x06, 0xa1, 0x02, 0x01];
const UV_RETRIES: &[u8] = &[0x06, 0xa1, 0x02, 0x07];
const KEY_AGREEMENT: &[u8] = &[0x06, 0xa2, 0x01, 0x02, 0x02, 0x02];
const TOKEN_UV: &[u8] = &[0x06, 0xa5, 0x01, 0x02, 0x02, 0x06];
const TOKEN_PIN: &[u8] = &[0x06, 0xa6, 0x01, 0x02, 0x02, 0x09];
const MAKE_CREDENTIAL: &[u8] = &[0x01];
const GET_ASSERTION: &[u8] = &[0x02];

/// Make a codec or verifier failure usable with `?`.
fn text<T, E: Display>(result: Result<T, E>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

/// One scripted answer to a PIN request.
/// One scripted answer to a PIN request: the time the user takes, then the outcome.
struct Entry {
    delay: Duration,
    outcome: Result<Vec<u8>, BridgeError>,
    honours_deadline: bool,
}

/// A scripted terminal: it answers each PIN request with the next queued entry.
#[derive(Clone)]
struct Prompt {
    clock: FakeClock,
    entries: Rc<RefCell<VecDeque<Entry>>>,
    notices: Rc<RefCell<Vec<Notice>>>,
    asked: Rc<RefCell<Vec<u64>>>,
}

impl Prompt {
    fn new(clock: FakeClock) -> Self {
        Self {
            clock,
            entries: Rc::default(),
            notices: Rc::default(),
            asked: Rc::default(),
        }
    }

    fn push(&self, delay: Duration, outcome: Result<Vec<u8>, BridgeError>, honours_deadline: bool) {
        self.entries.borrow_mut().push_back(Entry {
            delay,
            outcome,
            honours_deadline,
        });
    }

    fn enter(&self, pin: &[u8]) {
        self.push(Duration::ZERO, Ok(pin.to_vec()), true);
    }

    fn fail(&self, error: BridgeError) {
        self.push(Duration::ZERO, Err(error), true);
    }

    /// The user takes `delay`; a prompt that honours the deadline then gives up at it.
    fn enter_after(&self, delay: Duration, pin: &[u8], honours_deadline: bool) {
        self.push(delay, Ok(pin.to_vec()), honours_deadline);
    }

    fn notices(&self) -> Vec<Notice> {
        self.notices.borrow().clone()
    }

    fn asked(&self) -> Vec<u64> {
        self.asked.borrow().clone()
    }
}

impl PinPrompt for Prompt {
    fn read_pin(
        &mut self,
        retries: u64,
        pin: &mut PinBuffer,
        deadline: Instant,
        clock: &dyn MonotonicClock,
    ) -> Result<(), BridgeError> {
        self.asked.borrow_mut().push(retries);
        let entry = self.entries.borrow_mut().pop_front().ok_or(NO_TERMINAL)?;
        self.clock.advance(entry.delay);
        if entry.honours_deadline && clock.now() >= deadline {
            return Err(TIMEOUT);
        }
        entry.outcome.and_then(|bytes| {
            if bytes.iter().all(|byte| pin.push(*byte)) {
                Ok(())
            } else {
                Err(CLIENT_FAILED)
            }
        })
    }

    fn notice(&mut self, notice: Notice) {
        self.notices.borrow_mut().push(notice);
    }
}

/// One ceremony's host-drawn values, derived from a label.
struct Ceremony {
    id: CeremonyId,
    challenge: WebAuthnChallenge,
    user: OwnerUserHandle,
    prf: PrfInput,
}

impl Ceremony {
    fn drawn(label: &str) -> Self {
        let mut drbg = Drbg::new(label);
        let mut id = [0; 16];
        id.copy_from_slice(&drbg.draw()[..16]);
        Self {
            id: CeremonyId::from_bytes(id),
            challenge: WebAuthnChallenge::from_bytes(drbg.draw()),
            user: OwnerUserHandle::from_bytes(drbg.draw()),
            prf: PrfInput::from_bytes(drbg.draw()),
        }
    }

    fn image(
        &self,
        kind: CeremonyKind,
        encode: impl FnOnce(&mut [u8]) -> Result<usize, String>,
    ) -> Result<RequestImage, String> {
        let mut image = RequestImage::zeroed();
        let (header, payload) = image.as_mut_bytes().split_at_mut(CONTROL_HEADER_BYTES);
        let length = encode(payload)?;
        let length = text(u32::try_from(length))?;
        let request = text(OwnerBridgeControlV1::new_request(kind, 1, self.id, length))?;
        header.copy_from_slice(&request.encode());
        Ok(image)
    }

    fn create_request(&self) -> Result<RequestImage, String> {
        let options = CreateOptionsV1::new(self.id, self.challenge, self.user, self.prf);
        self.image(CeremonyKind::Create, |payload| {
            text(encode_create_options(&options, payload))
        })
    }

    fn get_request(&self, credential_id: &[u8]) -> Result<RequestImage, String> {
        let options = text(GetOptionsV1::new(
            self.id,
            self.challenge,
            credential_id,
            self.prf,
        ))?;
        self.image(CeremonyKind::Get, |payload| {
            text(encode_get_options(&options, payload))
        })
    }
}

/// What the shared verifier accepted from a Create reply.
struct Enrolled {
    credential_id: Vec<u8>,
    public_key: CoseEs256PublicKey,
    sign_count: u32,
    prf_enabled: bool,
    create_prf: bool,
    transports: Vec<u8>,
}

/// A client over a software authenticator with the PIN [`PIN`].
struct Rig {
    clock: FakeClock,
    device: MemoryHid,
    prompt: Prompt,
    port: CtapAuthenticator<MemoryHid, Prompt, Drbg>,
}

impl Rig {
    fn new(uv: bool) -> Self {
        Self::with_pin(uv, PIN)
    }

    fn with_pin(uv: bool, pin: &[u8]) -> Self {
        let clock = FakeClock::start();
        let device = MemoryHid::new(SoftAuthenticator::new("p-tier", pin, uv), clock.clone());
        let prompt = Prompt::new(clock.clone());
        let port = CtapAuthenticator::new(device.clone(), prompt.clone(), Drbg::new("client"));
        Self {
            clock,
            device,
            prompt,
            port,
        }
    }

    fn deadline(&self) -> Instant {
        self.clock.now() + Duration::from_mins(2)
    }

    /// Run one ceremony and return the reply payload.
    fn perform(
        &mut self,
        request: &RequestImage,
        kind: CeremonyKind,
    ) -> Result<Vec<u8>, BridgeError> {
        let mut reply = ReplyImage::zeroed();
        reply.select(kind);
        let deadline = self.deadline();
        let length = self
            .port
            .perform(request, &mut reply, deadline, &self.clock)?;
        Ok(reply.as_bytes()[..length].to_vec())
    }

    /// Create a credential and verify it with the shared verifier.
    fn create(&mut self, ceremony: &Ceremony) -> Result<Enrolled, Box<dyn Error>> {
        let payload = self.perform(&ceremony.create_request()?, CeremonyKind::Create)?;
        let reply = text(decode_attestation_reply(&payload))?;
        let context = CreateVerificationContext::new(ceremony.id, ceremony.challenge);
        let verified = text(verify_attestation_reply(&reply, context))?;
        Ok(Enrolled {
            credential_id: verified.credential_id().to_vec(),
            public_key: verified.public_key(),
            sign_count: verified.sign_count(),
            prf_enabled: reply.prf_enabled(),
            create_prf: reply.prf_first().is_some(),
            transports: verified.transports().as_slice().to_vec(),
        })
    }

    /// Assert with `enrolled` and return the verified PRF output and counter.
    fn get(
        &mut self,
        ceremony: &Ceremony,
        user: OwnerUserHandle,
        enrolled: &Enrolled,
    ) -> Result<([u8; 32], u32), Box<dyn Error>> {
        let request = ceremony.get_request(&enrolled.credential_id)?;
        let payload = self.perform(&request, CeremonyKind::Get)?;
        let reply = text(decode_assertion_reply(&payload))?;
        let stored = text(StoredCredential::new(
            &enrolled.credential_id,
            user,
            enrolled.public_key,
            false,
            false,
            enrolled.sign_count,
        ))?;
        let context = AssertionVerificationContext::new(ceremony.id, ceremony.challenge, stored);
        let verified = text(verify_assertion_reply(&reply, context))?;
        Ok((*verified.prf_first().as_bytes(), verified.sign_count()))
    }

    /// The command prefixes of every CBOR request so far, matched against `known`.
    fn commands(&self, known: &[&[u8]]) -> Vec<usize> {
        self.device
            .requests()
            .iter()
            .map(|request| {
                known
                    .iter()
                    .position(|prefix| request.starts_with(prefix))
                    .unwrap_or(usize::MAX)
            })
            .collect()
    }
}

/// The canonical CBOR head of `major` with argument `value` (below 65,536).
fn head(major: u8, value: usize) -> Vec<u8> {
    let major = major << 5;
    let [high, low] = u16::try_from(value).unwrap_or(u16::MAX).to_be_bytes();
    match value {
        0..=23 => vec![major + low],
        24..=0xff => vec![major + 24, low],
        _ => vec![major + 25, high, low],
    }
}

/// A CBOR byte string.
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut encoded = head(2, value.len());
    encoded.extend_from_slice(value);
    encoded
}

/// A CBOR text string.
fn text_item(value: &str) -> Vec<u8> {
    let mut encoded = head(3, value.len());
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

/// A CBOR map of already-encoded keys and values.
fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut encoded = head(5, entries.len());
    for (key, value) in entries {
        encoded.extend_from_slice(key);
        encoded.extend_from_slice(value);
    }
    encoded
}

/// A successful reply carrying `body`.
fn ok(body: &[u8]) -> Vec<u8> {
    let mut reply = vec![0];
    reply.extend_from_slice(body);
    reply
}

/// 32 distinct non-secret bytes for coordinates and padding.
fn counting(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}
