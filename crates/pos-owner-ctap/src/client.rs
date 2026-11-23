//! The native CTAP2 `OwnerAuthenticatorPort` (ADR-110 E20 LS3–LS7, LP1–LP3).
//!
//! One `perform` is one ceremony: a fresh CTAPHID channel, the LS6 capability check, one
//! `pinUvAuthToken` (built-in UV first, the PIN as fallback), and exactly one `makeCredential` or
//! `getAssertion` that spends that token. Nothing PIN-equivalent outlives the call: the PIN, its
//! hash, the ephemeral key, `Z`, the shared secret and the token are all wiped.
//!
//! LS7's "nothing is retried automatically" means nothing beyond the authenticator's own UV
//! retry count (owner decision 2026-11-24): a rejected built-in UV attempt is tried again inside
//! the same operation while `getUVRetries` reports attempts left, within the deadline. The
//! client falls back to the PIN once `getUVRetries` reports 0 or the authenticator answers
//! `CTAP2_ERR_UV_BLOCKED`. A PIN is entered once per CTAP command and never retried.

use std::time::Instant;

use pos_owner_bridge::{
    BridgeError, LifecycleCode, MonotonicClock, OwnerAuthenticatorPort, ProtocolCode, ReplyImage,
    RequestImage, SecureRandom, UnavailableCode,
};
use pos_owner_bridge_codec::{
    decode_create_options, decode_get_options, encode_assertion_reply, encode_attestation_reply,
    AssertionReplyV1, AttestationReplyV1, CeremonyKind, CreateOptionsV1, GetOptionsV1,
    OwnerBridgeControlV1, PrfResult, TransportCodes, CONTROL_HEADER_BYTES,
};
use sha2::digest::Output;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{decode, Value};
use crate::ctap::{
    AssertionRequest, HmacSecretInput, Reply, Session, PERMISSION_GET_ASSERTION,
    PERMISSION_MAKE_CREDENTIAL, STATUS_OK, STATUS_PIN_AUTH_BLOCKED, STATUS_PIN_BLOCKED,
    STATUS_UV_BLOCKED,
};
use crate::hid::{Channel, HidTransport};
use crate::info::Capabilities;
use crate::pin::{self, Point, SharedSecret};
use crate::prompt::{Notice, PinBuffer, PinPrompt};
use crate::webauthn::{client_data_json, created, hmac_secret_output, none_attestation, prf_salt};

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);
const PRF_UNSUPPORTED: BridgeError = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);
const MALFORMED: BridgeError = BridgeError::Protocol(ProtocolCode::Malformed);
const OUT_OF_BOUNDS: BridgeError = BridgeError::Protocol(ProtocolCode::LengthOutOfBounds);

/// The ADR-097 transport code of `usb`, the only transport the native path reports.
const USB: u8 = 0;

/// `CTAP2_ERR_UV_INVALID`.
const STATUS_UV_INVALID: u8 = 0x3f;

/// What one built-in UV attempt produced.
enum UvAttempt {
    Granted(Authorization),
    Rejected,
    Blocked,
}

/// The ceremony a request image asks for.
enum Ceremony<'a> {
    Create(CreateOptionsV1),
    Get(GetOptionsV1<'a>),
}

impl<'a> Ceremony<'a> {
    fn decode(request: &'a RequestImage) -> Result<Self, BridgeError> {
        let bytes = request.as_bytes();
        let (header, payload) = bytes.split_at(CONTROL_HEADER_BYTES.min(bytes.len()));
        let header = OwnerBridgeControlV1::decode(header).or(Err(MALFORMED))?;
        let payload = payload
            .get(..header.payload_len() as usize)
            .unwrap_or_default();
        match header.kind() {
            CeremonyKind::Create => decode_create_options(payload).map(Self::Create),
            CeremonyKind::Get => decode_get_options(payload).map(Self::Get),
        }
        .or(Err(MALFORMED))
    }
}

/// A `pinUvAuthToken` for one command, with the shared secret and platform key it came with.
struct Authorization {
    token: Zeroizing<[u8; 32]>,
    secret: SharedSecret,
    platform: Point,
}

impl Authorization {
    fn from_reply(body: &[u8], secret: SharedSecret, platform: Point) -> Result<Self, BridgeError> {
        let reply = decode(body).ok_or(CLIENT_FAILED)?;
        let encrypted = reply.int(2).and_then(Value::bytes).ok_or(CLIENT_FAILED)?;
        let blocks = pin::decrypt(&secret, encrypted)
            .filter(|blocks| blocks.len() == 2)
            .ok_or(CLIENT_FAILED)?;
        let mut token = Zeroizing::<[u8; 32]>::default();
        token
            .iter_mut()
            .zip(blocks.iter().flatten())
            .for_each(|(to, from)| *to = *from);
        Ok(Self {
            token,
            secret,
            platform,
        })
    }

    /// `pinUvAuthParam = authenticate(pinUvAuthToken, clientDataHash)`.
    fn param(&self, client_data_hash: &[u8; 32]) -> [u8; 32] {
        pin::authenticate(&self.token, &[client_data_hash])
    }
}

/// The native CTAP2 client: one authenticator, one PIN prompt and the randomness for protocol 2.
pub struct CtapAuthenticator<T: HidTransport, P: PinPrompt, R: SecureRandom> {
    transport: T,
    prompt: P,
    random: R,
}

impl<T: HidTransport, P: PinPrompt, R: SecureRandom> CtapAuthenticator<T, P, R> {
    /// A client for the one authenticator behind `transport`.
    #[must_use]
    pub const fn new(transport: T, prompt: P, random: R) -> Self {
        Self {
            transport,
            prompt,
            random,
        }
    }
}

impl<T: HidTransport, P: PinPrompt, R: SecureRandom> OwnerAuthenticatorPort
    for CtapAuthenticator<T, P, R>
{
    fn perform(
        &mut self,
        request: &RequestImage,
        reply: &mut ReplyImage,
        deadline: Instant,
        clock: &dyn MonotonicClock,
    ) -> Result<usize, BridgeError> {
        let ceremony = Ceremony::decode(request)?;
        let mut nonce = <[u8; 8]>::default();
        self.random
            .fill(&mut nonce)
            .map_err(BridgeError::Unavailable)?;
        let channel = Channel::open(&mut self.transport, clock, deadline, nonce)?;
        let mut session = Session::new(channel);
        let capabilities = session.info()?;
        let mut client = Client {
            session,
            capabilities,
            prompt: &mut self.prompt,
            random: &mut self.random,
            deadline,
            clock,
        };
        match ceremony {
            Ceremony::Create(options) => client.create(&options, reply),
            Ceremony::Get(options) => client.get(&options, reply),
        }
    }
}

/// One ceremony in progress.
struct Client<'a> {
    session: Session<'a>,
    capabilities: Capabilities,
    prompt: &'a mut dyn PinPrompt,
    random: &'a mut dyn SecureRandom,
    deadline: Instant,
    clock: &'a dyn MonotonicClock,
}

impl Client<'_> {
    /// A fresh protocol 2 key agreement with the authenticator.
    fn agreement(&mut self) -> Result<(Point, SharedSecret), BridgeError> {
        let peer = self.session.key_agreement()?;
        pin::encapsulate(peer, self.random)
    }

    /// One token for `permission`: built-in UV first, then the PIN (ADR-110 E20 LP1).
    ///
    /// Each rejected UV attempt spends one of the authenticator's UV retries, so the loop ends
    /// when they run out, UV is blocked, or the deadline stops the next command.
    fn authorize(&mut self, permission: usize) -> Result<Authorization, BridgeError> {
        if self.capabilities.uv {
            loop {
                let retries = self.session.uv_retries()?;
                if retries == 0 {
                    break;
                }
                self.prompt.notice(Notice::UserVerification { retries });
                match self.authorize_with_uv(permission)? {
                    UvAttempt::Granted(authorization) => return Ok(authorization),
                    UvAttempt::Blocked => break,
                    UvAttempt::Rejected => {}
                }
            }
        }
        self.authorize_with_pin(permission)
    }

    /// One `getPinUvAuthTokenUsingUvWithPermissions` attempt.
    fn authorize_with_uv(&mut self, permission: usize) -> Result<UvAttempt, BridgeError> {
        let (platform, secret) = self.agreement()?;
        let Reply { status, body } = self.session.token(&platform, None, permission)?;
        match status {
            STATUS_OK => Authorization::from_reply(&body, secret, platform).map(UvAttempt::Granted),
            STATUS_UV_INVALID => Ok(UvAttempt::Rejected),
            STATUS_UV_BLOCKED => Ok(UvAttempt::Blocked),
            _ => Err(CLIENT_FAILED),
        }
    }

    /// `getPinUvAuthTokenUsingPinWithPermissions` with one PIN entry.
    fn authorize_with_pin(&mut self, permission: usize) -> Result<Authorization, BridgeError> {
        let retries = self.session.pin_retries()?;
        if retries == 0 {
            return self.blocked();
        }
        let (platform, secret) = self.agreement()?;
        let pin_hash_enc = self.read_pin(retries, &secret)?;
        let Reply { status, body } =
            self.session
                .token(&platform, Some(pin_hash_enc.as_slice()), permission)?;
        match status {
            STATUS_OK => Authorization::from_reply(&body, secret, platform),
            STATUS_PIN_BLOCKED | STATUS_PIN_AUTH_BLOCKED => self.blocked(),
            _ => Err(CLIENT_FAILED),
        }
    }

    /// Read the PIN and return `pinHashEnc = encrypt(sharedSecret, LEFT(SHA-256(PIN), 16))`.
    fn read_pin(&mut self, retries: u64, secret: &SharedSecret) -> Result<Vec<u8>, BridgeError> {
        let mut entry = PinBuffer::default();
        self.prompt
            .read_pin(retries, &mut entry, self.deadline, self.clock)?;
        let entered = entry.validated().ok_or(CLIENT_FAILED)?;
        let mut digest = Zeroizing::<[u8; 32]>::default();
        Sha256::new()
            .chain_update(entered)
            .finalize_into(Output::<Sha256>::cast_from_core_mut(&mut digest));
        let mut left = Zeroizing::<[u8; 16]>::default();
        left.copy_from_slice(&digest[..16]);
        pin::encrypt(secret, std::slice::from_ref(&*left), self.random)
    }

    /// A blocked PIN is shown to the user and never retried (ADR-110 E20 LS7).
    fn blocked<T>(&mut self) -> Result<T, BridgeError> {
        self.prompt.notice(Notice::PinBlocked);
        Err(CLIENT_FAILED)
    }

    fn create(
        &mut self,
        options: &CreateOptionsV1,
        reply: &mut ReplyImage,
    ) -> Result<usize, BridgeError> {
        let client_data = client_data_json("webauthn.create", options.challenge().as_bytes());
        let hash: [u8; 32] = Sha256::digest(&client_data).into();
        let param = self.authorize(PERMISSION_MAKE_CREDENTIAL)?.param(&hash);
        self.prompt.notice(Notice::Touch);
        let body = self
            .session
            .make_credential(&hash, options.user_handle().as_bytes(), &param)?;
        let response = decode(&body).ok_or(CLIENT_FAILED)?;
        let auth_data = response
            .int(2)
            .and_then(Value::bytes)
            .ok_or(CLIENT_FAILED)?;
        let credential = created(auth_data).ok_or(CLIENT_FAILED)?;
        let attestation = none_attestation(auth_data);
        TransportCodes::new(&[USB])
            .and_then(|transports| {
                AttestationReplyV1::new(
                    options.ceremony_id(),
                    credential.credential_id,
                    &client_data,
                    &attestation,
                    transports,
                    credential.hmac_secret,
                    None,
                )
            })
            .and_then(|attested| encode_attestation_reply(&attested, reply.as_mut_bytes()))
            .or(Err(OUT_OF_BOUNDS))
    }

    fn get(
        &mut self,
        options: &GetOptionsV1<'_>,
        reply: &mut ReplyImage,
    ) -> Result<usize, BridgeError> {
        let client_data = client_data_json("webauthn.get", options.challenge().as_bytes());
        let hash: [u8; 32] = Sha256::digest(&client_data).into();
        let authorization = self.authorize(PERMISSION_GET_ASSERTION)?;
        let param = authorization.param(&hash);
        let salt = Zeroizing::new(prf_salt(options.prf_input().as_bytes()));
        let (first, second) = salt.split_at(16);
        let mut blocks = Zeroizing::<[[u8; 16]; 2]>::default();
        blocks[0].copy_from_slice(first);
        blocks[1].copy_from_slice(second);
        let salt_enc = pin::encrypt(&authorization.secret, blocks.as_slice(), self.random)?;
        let salt_auth = pin::authenticate(authorization.secret.hmac_key(), &[&salt_enc]);
        self.prompt.notice(Notice::Touch);
        let body = self.session.get_assertion(&AssertionRequest {
            client_data_hash: &hash,
            credential_id: options.credential_id(),
            hmac_secret: HmacSecretInput {
                platform: &authorization.platform,
                salt_enc: &salt_enc,
                salt_auth: &salt_auth,
            },
            pin_uv_auth_param: &param,
        })?;
        let response = decode(&body).ok_or(CLIENT_FAILED)?;
        let auth_data = response
            .int(2)
            .and_then(Value::bytes)
            .ok_or(CLIENT_FAILED)?;
        let signature = response
            .int(3)
            .and_then(Value::bytes)
            .ok_or(CLIENT_FAILED)?;
        let allowed = options.credential_id();
        let raw_id = response
            .int(1)
            .and_then(|credential| credential.text_key("id"))
            .and_then(Value::bytes)
            .unwrap_or(allowed);
        let decrypted = hmac_secret_output(auth_data)
            .and_then(|output| pin::decrypt(&authorization.secret, output))
            .ok_or(PRF_UNSUPPORTED)?;
        let mut prf = Zeroizing::<[u8; 32]>::default();
        prf.iter_mut()
            .zip(decrypted.iter().flatten())
            .for_each(|(to, from)| *to = *from);
        AssertionReplyV1::new(
            options.ceremony_id(),
            raw_id,
            &client_data,
            auth_data,
            signature,
            None,
            PrfResult::from_bytes(*prf),
        )
        .and_then(|asserted| encode_assertion_reply(&asserted, reply.as_mut_bytes()))
        .or(Err(OUT_OF_BOUNDS))
    }
}
