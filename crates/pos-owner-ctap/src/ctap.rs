//! CTAP2 commands over one CTAPHID channel (CTAP 2.1 PS §6; ADR-110 E20 LS4, LP1, LP2).
//!
//! Requests are written in CTAP2 canonical CBOR. A reply's status byte is returned to the caller
//! where it chooses the next step (UV fallback, a blocked PIN); every other non-zero status is
//! `Lifecycle(ClientFailed)`.

use pos_owner_bridge::{BridgeError, LifecycleCode};

use crate::cbor::{decode, Value, Writer};
use crate::hid::{Channel, CMD_CBOR, MAX_MESSAGE_BYTES};
use crate::info::{check, Capabilities};
use crate::pin::{Point, PROTOCOL};

/// The only RP ID the owner credential uses.
pub const RP_ID: &str = "localhost";

/// `authenticatorMakeCredential`.
pub const MAKE_CREDENTIAL: u8 = 0x01;
/// `authenticatorGetAssertion`.
pub const GET_ASSERTION: u8 = 0x02;
/// `authenticatorGetInfo`.
pub const GET_INFO: u8 = 0x04;
/// `authenticatorClientPIN`.
pub const CLIENT_PIN: u8 = 0x06;

/// `getPINRetries`.
pub const GET_PIN_RETRIES: u64 = 0x01;
/// `getKeyAgreement`.
pub const GET_KEY_AGREEMENT: u64 = 0x02;
/// `getPinUvAuthTokenUsingUvWithPermissions`.
pub const GET_TOKEN_USING_UV: u64 = 0x06;
/// `getUVRetries`.
pub const GET_UV_RETRIES: u64 = 0x07;
/// `getPinUvAuthTokenUsingPinWithPermissions`.
pub const GET_TOKEN_USING_PIN: u64 = 0x09;

/// The `mc` permission, for one `makeCredential`.
pub const PERMISSION_MAKE_CREDENTIAL: u64 = 0x01;
/// The `ga` permission, for one `getAssertion`.
pub const PERMISSION_GET_ASSERTION: u64 = 0x02;

/// `CTAP2_OK`.
pub const STATUS_OK: u8 = 0x00;
/// `CTAP2_ERR_PIN_BLOCKED`.
pub const STATUS_PIN_BLOCKED: u8 = 0x32;
/// `CTAP2_ERR_PIN_AUTH_BLOCKED`.
pub const STATUS_PIN_AUTH_BLOCKED: u8 = 0x34;
/// `CTAP2_ERR_UV_BLOCKED`.
pub const STATUS_UV_BLOCKED: u8 = 0x3c;

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);

/// Write `point` as a protocol 2 COSE key: EC2, `ECDH-ES+HKDF-256` (-25), P-256.
pub(crate) fn cose_key(writer: &mut Writer, point: &Point) {
    writer
        .map(5)
        .unsigned(1)
        .unsigned(2)
        .unsigned(3)
        .negative(24)
        .negative(0)
        .unsigned(1)
        .negative(1)
        .bytes(&point.x)
        .negative(2)
        .bytes(&point.y);
}

/// Read the point of a COSE key.
pub(crate) fn cose_point(key: &Value<'_>) -> Option<Point> {
    let coordinate = |label| {
        key.get(&Value::Negative(label))
            .and_then(Value::bytes)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
    };
    Some(Point {
        x: coordinate(1)?,
        y: coordinate(2)?,
    })
}

/// A reply status and its CBOR body.
pub struct Reply {
    /// The CTAP2 status byte.
    pub status: u8,
    /// The CBOR body after the status byte.
    pub body: Vec<u8>,
}

impl Reply {
    /// The body of a successful reply.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` for any other status.
    pub fn success(self) -> Result<Vec<u8>, BridgeError> {
        if self.status == STATUS_OK {
            Ok(self.body)
        } else {
            Err(CLIENT_FAILED)
        }
    }
}

/// The `hmac-secret` input of one `getAssertion` (CTAP 2.1 PS §12.5).
pub struct HmacSecretInput<'a> {
    /// The platform key agreement key.
    pub platform: &'a Point,
    /// `encrypt(sharedSecret, salt1)`.
    pub salt_enc: &'a [u8],
    /// `authenticate(sharedSecret, saltEnc)`.
    pub salt_auth: &'a [u8],
}

/// One `getAssertion` request.
pub struct AssertionRequest<'a> {
    /// `SHA-256(clientDataJSON)`.
    pub client_data_hash: &'a [u8; 32],
    /// The one allowed credential.
    pub credential_id: &'a [u8],
    /// The `hmac-secret` input.
    pub hmac_secret: HmacSecretInput<'a>,
    /// `authenticate(pinUvAuthToken, clientDataHash)`.
    pub pin_uv_auth_param: &'a [u8; 32],
}

/// A CTAP2 session on one channel.
pub struct Session<'a> {
    channel: Channel<'a>,
    limit: usize,
}

impl<'a> Session<'a> {
    /// A session on `channel`, limited to 7,609-byte messages until `info` reads `maxMsgSize`.
    #[must_use]
    pub const fn new(channel: Channel<'a>) -> Self {
        Self {
            channel,
            limit: MAX_MESSAGE_BYTES,
        }
    }

    /// Send `command` with the encoded `parameters`.
    ///
    /// # Errors
    ///
    /// Returns the channel failure, or `Lifecycle(ClientFailed)` for an empty reply.
    pub fn command(&mut self, command: u8, parameters: &[u8]) -> Result<Reply, BridgeError> {
        let mut message = Vec::with_capacity(parameters.len() + 1);
        message.push(command);
        message.extend_from_slice(parameters);
        let reply = self.channel.transact(CMD_CBOR, &message, self.limit)?;
        let (status, body) = reply.split_first().ok_or(CLIENT_FAILED)?;
        Ok(Reply {
            status: *status,
            body: body.to_vec(),
        })
    }

    /// `authenticatorGetInfo`, checked against LS6.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable(PrfUnsupported)` for an authenticator that fails the check, and
    /// `Lifecycle(ClientFailed)` for a failed or malformed reply.
    pub fn info(&mut self) -> Result<Capabilities, BridgeError> {
        let body = self.command(GET_INFO, &[])?.success()?;
        let capabilities = decode(&body)
            .ok_or(CLIENT_FAILED)
            .and_then(|info| check(&info))?;
        self.limit = capabilities.max_message;
        Ok(capabilities)
    }

    fn client_pin(&mut self, encoded: &[u8]) -> Result<Reply, BridgeError> {
        self.command(CLIENT_PIN, encoded)
    }

    fn retries(&mut self, sub_command: u64, key: u64) -> Result<u64, BridgeError> {
        let request = Writer::default()
            .map(1)
            .unsigned(2)
            .unsigned(sub_command)
            .finish();
        let body = self.client_pin(&request)?.success()?;
        decode(&body)
            .and_then(|reply| reply.int(key).and_then(Value::unsigned))
            .ok_or(CLIENT_FAILED)
    }

    /// `getPINRetries`.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` for a failed or malformed reply.
    pub fn pin_retries(&mut self) -> Result<u64, BridgeError> {
        self.retries(GET_PIN_RETRIES, 0x03)
    }

    /// `getUVRetries`.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` for a failed or malformed reply.
    pub fn uv_retries(&mut self) -> Result<u64, BridgeError> {
        self.retries(GET_UV_RETRIES, 0x05)
    }

    /// `getKeyAgreement` for protocol 2: the authenticator's key agreement point.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` for a failed or malformed reply.
    pub fn key_agreement(&mut self) -> Result<Point, BridgeError> {
        let request = Writer::default()
            .map(2)
            .unsigned(1)
            .unsigned(PROTOCOL)
            .unsigned(2)
            .unsigned(GET_KEY_AGREEMENT)
            .finish();
        let body = self.client_pin(&request)?.success()?;
        decode(&body)
            .and_then(|reply| reply.int(1).and_then(cose_point))
            .ok_or(CLIENT_FAILED)
    }

    /// Request a `pinUvAuthToken` for `permission` on `localhost`.
    ///
    /// Without `pin_hash_enc` this is `getPinUvAuthTokenUsingUvWithPermissions`; with it,
    /// `getPinUvAuthTokenUsingPinWithPermissions`.
    ///
    /// # Errors
    ///
    /// Returns the channel failure; the status is the caller's to judge.
    pub fn token(
        &mut self,
        platform: &Point,
        pin_hash_enc: Option<&[u8]>,
        permission: u64,
    ) -> Result<Reply, BridgeError> {
        let mut writer = Writer::default();
        let sub_command = pin_hash_enc.map_or(GET_TOKEN_USING_UV, |_| GET_TOKEN_USING_PIN);
        writer
            .map(if pin_hash_enc.is_some() { 6 } else { 5 })
            .unsigned(1)
            .unsigned(PROTOCOL)
            .unsigned(2)
            .unsigned(sub_command)
            .unsigned(3);
        cose_key(&mut writer, platform);
        if let Some(pin_hash_enc) = pin_hash_enc {
            writer.unsigned(6).bytes(pin_hash_enc);
        }
        writer
            .unsigned(9)
            .unsigned(permission)
            .unsigned(10)
            .text(RP_ID);
        self.client_pin(&writer.finish())
    }

    /// `authenticatorMakeCredential` for a non-resident ES256 `hmac-secret` credential.
    ///
    /// The request is shaped as ADR-110 E20 LS4 fixes it.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` for a failed reply.
    pub fn make_credential(
        &mut self,
        client_data_hash: &[u8; 32],
        user_id: &[u8; 32],
        pin_uv_auth_param: &[u8; 32],
    ) -> Result<Vec<u8>, BridgeError> {
        let request = Writer::default()
            .map(8)
            .unsigned(1)
            .bytes(client_data_hash)
            .unsigned(2)
            .map(1)
            .text("id")
            .text(RP_ID)
            .unsigned(3)
            .map(1)
            .text("id")
            .bytes(user_id)
            .unsigned(4)
            .array(1)
            .map(2)
            .text("alg")
            .negative(6)
            .text("type")
            .text("public-key")
            .unsigned(6)
            .map(1)
            .text("hmac-secret")
            .boolean(true)
            .unsigned(7)
            .map(1)
            .text("rk")
            .boolean(false)
            .unsigned(8)
            .bytes(pin_uv_auth_param)
            .unsigned(9)
            .unsigned(PROTOCOL)
            .finish();
        self.command(MAKE_CREDENTIAL, &request)?.success()
    }

    /// `authenticatorGetAssertion` for one credential, with the `hmac-secret` input.
    ///
    /// The request is shaped as ADR-110 E20 LS4 and LP2 fix it.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(ClientFailed)` for a failed reply.
    pub fn get_assertion(
        &mut self,
        request: &AssertionRequest<'_>,
    ) -> Result<Vec<u8>, BridgeError> {
        let mut writer = Writer::default();
        writer
            .map(6)
            .unsigned(1)
            .text(RP_ID)
            .unsigned(2)
            .bytes(request.client_data_hash)
            .unsigned(3)
            .array(1)
            .map(2)
            .text("id")
            .bytes(request.credential_id)
            .text("type")
            .text("public-key")
            .unsigned(4)
            .map(1)
            .text("hmac-secret")
            .map(4)
            .unsigned(1);
        cose_key(&mut writer, request.hmac_secret.platform);
        writer
            .unsigned(2)
            .bytes(request.hmac_secret.salt_enc)
            .unsigned(3)
            .bytes(request.hmac_secret.salt_auth)
            .unsigned(4)
            .unsigned(PROTOCOL)
            .unsigned(6)
            .bytes(request.pin_uv_auth_param)
            .unsigned(7)
            .unsigned(PROTOCOL);
        self.command(GET_ASSERTION, &writer.finish())?.success()
    }
}
