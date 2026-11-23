//! `SoftAuthenticator`: an in-process CTAP 2.1 authenticator for the P-tier tests.
//!
//! It implements the subset the native client uses, honestly: `authenticatorGetInfo`, the
//! protocol 2 `authenticatorClientPIN` subcommands, non-resident ES256 `makeCredential` with
//! `hmac-secret`, and `getAssertion` with the `hmac-secret` output. Each token serves one command
//! (CTAP 2.1 clears its permissions on use). All randomness comes from a deterministic
//! [`Drbg`], so no key, salt or nonce is a literal. It is test support and never deployable.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use pos_owner_bridge::{SecureRandom, UnavailableCode};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbc::CbcBlock;
use crate::cbor::{decode, Value, Writer};
use crate::ctap::{
    cose_key, cose_point, CLIENT_PIN, GET_ASSERTION, GET_INFO, MAKE_CREDENTIAL,
    PERMISSION_GET_ASSERTION, PERMISSION_MAKE_CREDENTIAL, RP_ID, STATUS_OK, STATUS_PIN_BLOCKED,
    STATUS_UV_BLOCKED,
};
use crate::pin::{self, public_point, SharedSecret};

/// `CTAP1_ERR_INVALID_COMMAND`.
pub const STATUS_INVALID_COMMAND: u8 = 0x01;
/// `CTAP1_ERR_INVALID_PARAMETER`.
pub const STATUS_INVALID_PARAMETER: u8 = 0x02;
/// `CTAP2_ERR_NO_CREDENTIALS`.
pub const STATUS_NO_CREDENTIALS: u8 = 0x2e;
/// `CTAP2_ERR_PIN_INVALID`.
pub const STATUS_PIN_INVALID: u8 = 0x31;
/// `CTAP2_ERR_PIN_AUTH_INVALID`.
pub const STATUS_PIN_AUTH_INVALID: u8 = 0x33;
/// `CTAP2_ERR_UV_INVALID`.
pub const STATUS_UV_INVALID: u8 = 0x3f;

const FLAGS_CREATE: u8 = 0xc5;
const FLAGS_GET: u8 = 0x85;

/// A deterministic random source: SHA-256 over a seed and a counter. It never fails.
#[derive(Clone, Debug)]
pub struct Drbg {
    seed: [u8; 32],
    counter: u64,
}

impl Drbg {
    /// A source seeded from `label`.
    #[must_use]
    pub fn new(label: &str) -> Self {
        Self {
            seed: Sha256::digest(label.as_bytes()).into(),
            counter: 0,
        }
    }

    /// The next 32 bytes.
    pub fn draw(&mut self) -> [u8; 32] {
        self.counter += 1;
        Sha256::new()
            .chain_update(self.seed)
            .chain_update(self.counter.to_be_bytes())
            .finalize()
            .into()
    }
}

impl SecureRandom for Drbg {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), UnavailableCode> {
        for chunk in out.chunks_mut(32) {
            let block = self.draw();
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

struct Token {
    value: Zeroizing<[u8; 32]>,
    permissions: u64,
}

struct Credential {
    id: [u8; 32],
    key: SigningKey,
    cred_random: [u8; 32],
}

fn status(code: u8) -> Vec<u8> {
    vec![code]
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut reply = vec![STATUS_OK];
    reply.extend_from_slice(body);
    reply
}

fn two_blocks(bytes: &[u8; 32]) -> [CbcBlock; 2] {
    let mut blocks = [[0; 16]; 2];
    blocks[0].copy_from_slice(&bytes[..16]);
    blocks[1].copy_from_slice(&bytes[16..]);
    blocks
}

fn signature(key: &SigningKey, auth_data: &[u8], client_data_hash: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(&[auth_data, client_data_hash].concat());
    signature.to_der().as_bytes().to_vec()
}

fn rp_id_hash() -> [u8; 32] {
    Sha256::digest(RP_ID.as_bytes()).into()
}

/// The honest `authenticatorGetInfo` body of a CTAP 2.1 key with a PIN set.
fn honest_info(uv: bool, aaguid: &[u8]) -> Vec<u8> {
    Writer::default()
        .map(7)
        .unsigned(1)
        .array(2)
        .text("FIDO_2_0")
        .text("FIDO_2_1")
        .unsigned(2)
        .array(1)
        .text("hmac-secret")
        .unsigned(3)
        .bytes(aaguid)
        .unsigned(4)
        .map(5)
        .text("rk")
        .boolean(true)
        .text("up")
        .boolean(true)
        .text("uv")
        .boolean(uv)
        .text("clientPin")
        .boolean(true)
        .text("pinUvAuthToken")
        .boolean(true)
        .unsigned(5)
        .unsigned(1_200)
        .unsigned(6)
        .array(2)
        .unsigned(2)
        .unsigned(1)
        .unsigned(10)
        .array(1)
        .map(2)
        .text("alg")
        .negative(6)
        .text("type")
        .text("public-key")
        .finish()
}

/// An in-process CTAP 2.1 authenticator.
pub struct SoftAuthenticator {
    drbg: Drbg,
    info: Vec<u8>,
    aaguid: [u8; 16],
    pin_hash: [u8; 16],
    pin_retries: u64,
    uv: bool,
    uv_rejects: u64,
    uv_retries: u64,
    key_agreement: Option<SigningKey>,
    token: Option<Token>,
    credentials: Vec<Credential>,
    counter: u32,
}

impl SoftAuthenticator {
    /// An authenticator with the PIN `pin`, seeded from `label`.
    ///
    /// It has built-in UV when `uv` is set, starts with 8 PIN and 3 UV retries, and accepts every
    /// UV attempt.
    #[must_use]
    pub fn new(label: &str, pin: &[u8], uv: bool) -> Self {
        let mut drbg = Drbg::new(label);
        let mut aaguid = [0; 16];
        aaguid.copy_from_slice(&drbg.draw()[..16]);
        let mut pin_hash = [0; 16];
        pin_hash.copy_from_slice(&Sha256::digest(pin)[..16]);
        let key_agreement = pin::ephemeral_key(&mut drbg).ok();
        Self {
            info: honest_info(uv, &aaguid),
            drbg,
            aaguid,
            pin_hash,
            pin_retries: 8,
            uv,
            uv_rejects: 0,
            uv_retries: 3,
            key_agreement,
            token: None,
            credentials: Vec::new(),
            counter: 0,
        }
    }

    /// Answer `authenticatorGetInfo` with `info` instead of the honest body.
    pub fn set_info(&mut self, info: Vec<u8>) {
        self.info = info;
    }

    /// Set the remaining PIN attempts.
    pub const fn set_pin_retries(&mut self, retries: u64) {
        self.pin_retries = retries;
    }

    /// The remaining PIN attempts.
    #[must_use]
    pub const fn pin_retries(&self) -> u64 {
        self.pin_retries
    }

    /// Set the remaining built-in UV attempts and how many of the next attempts fail.
    pub const fn set_uv(&mut self, retries: u64, rejects: u64) {
        self.uv_retries = retries;
        self.uv_rejects = rejects;
    }

    /// The remaining built-in UV attempts.
    #[must_use]
    pub const fn uv_retries(&self) -> u64 {
        self.uv_retries
    }

    /// The `hmac-secret` key (`CredRandomWithUV`) of the credential `id`.
    #[must_use]
    pub fn cred_random(&self, id: &[u8]) -> Option<[u8; 32]> {
        self.credentials
            .iter()
            .find(|credential| credential.id == id)
            .map(|credential| credential.cred_random)
    }

    /// Process one CTAP2 message: a command byte and its CBOR parameters.
    ///
    /// The reply is a status byte and, on success, the CBOR body. Missing or undecodable
    /// parameters read as absent, so the command fails its own checks.
    pub fn process(&mut self, message: &[u8]) -> Vec<u8> {
        let (command, encoded) = message
            .split_first()
            .map_or((0, &[][..]), |(command, encoded)| (*command, encoded));
        let parameters = decode(encoded).unwrap_or(Value::Null);
        match command {
            GET_INFO => ok(&self.info),
            CLIENT_PIN => self.client_pin(&parameters),
            MAKE_CREDENTIAL => self.make_credential(&parameters),
            GET_ASSERTION => self.get_assertion(&parameters),
            _ => status(STATUS_INVALID_COMMAND),
        }
    }

    fn client_pin(&mut self, parameters: &Value<'_>) -> Vec<u8> {
        match parameters.int(2).and_then(Value::unsigned) {
            Some(0x01) => ok(&Writer::default()
                .map(1)
                .unsigned(3)
                .unsigned(self.pin_retries)
                .finish()),
            Some(0x02) => self.key_agreement_reply(),
            Some(0x06) => self.token_using_uv(parameters),
            Some(0x07) => ok(&Writer::default()
                .map(1)
                .unsigned(5)
                .unsigned(self.uv_retries)
                .finish()),
            Some(0x09) => self.token_using_pin(parameters),
            _ => status(STATUS_INVALID_PARAMETER),
        }
    }

    fn key_agreement_reply(&self) -> Vec<u8> {
        self.key_agreement
            .as_ref()
            .map(|key| {
                let mut writer = Writer::default();
                writer.map(1).unsigned(1);
                cose_key(&mut writer, &public_point(key));
                ok(&writer.finish())
            })
            .unwrap_or_default()
    }

    /// The shared secret with the platform COSE key `key`.
    fn secret(&self, key: Option<&Value<'_>>) -> Option<SharedSecret> {
        key.and_then(cose_point)
            .zip(self.key_agreement.as_ref())
            .and_then(|(point, own)| pin::agree(own, point).ok())
    }

    fn token_using_uv(&mut self, parameters: &Value<'_>) -> Vec<u8> {
        if !self.uv || self.uv_retries == 0 {
            return status(STATUS_UV_BLOCKED);
        }
        if self.uv_rejects > 0 {
            self.uv_rejects -= 1;
            self.uv_retries -= 1;
            return status(STATUS_UV_INVALID);
        }
        self.grant(parameters)
    }

    fn token_using_pin(&mut self, parameters: &Value<'_>) -> Vec<u8> {
        if self.pin_retries == 0 {
            return status(STATUS_PIN_BLOCKED);
        }
        let entered = self.secret(parameters.int(3)).and_then(|secret| {
            parameters
                .int(6)
                .and_then(Value::bytes)
                .and_then(|encrypted| pin::decrypt(&secret, encrypted))
        });
        if entered.is_none_or(|blocks| blocks.as_slice() != [self.pin_hash]) {
            self.pin_retries -= 1;
            self.key_agreement = pin::ephemeral_key(&mut self.drbg).ok();
            return status(STATUS_PIN_INVALID);
        }
        self.grant(parameters)
    }

    /// Issue a fresh token with the requested permissions for `localhost`.
    fn grant(&mut self, parameters: &Value<'_>) -> Vec<u8> {
        let permissions = parameters.int(9).and_then(Value::unsigned).unwrap_or(0);
        let localhost = parameters.int(10) == Some(&Value::Text(RP_ID));
        let token = Zeroizing::new(self.drbg.draw());
        let encrypted = self
            .secret(parameters.int(3))
            .filter(|_| localhost)
            .and_then(|secret| pin::encrypt(&secret, &two_blocks(&token), &mut self.drbg).ok());
        let Some(encrypted) = encrypted else {
            return status(STATUS_INVALID_PARAMETER);
        };
        self.token = Some(Token {
            value: token,
            permissions,
        });
        ok(&Writer::default()
            .map(1)
            .unsigned(2)
            .bytes(&encrypted)
            .finish())
    }

    /// Spend the current token: it must carry `permission` and authenticate
    /// `client_data_hash` as `param`. The token is gone afterwards either way.
    fn spend(
        &mut self,
        param: Option<&Value<'_>>,
        client_data_hash: &[u8],
        permission: u64,
    ) -> bool {
        let wanted = permission;
        let expected = self
            .token
            .take()
            .filter(|token| token.permissions & wanted != 0)
            .map(|token| pin::authenticate(&token.value, &[client_data_hash]));
        expected.is_some_and(|expected| param.and_then(Value::bytes) == Some(&expected[..]))
    }

    fn make_credential(&mut self, parameters: &Value<'_>) -> Vec<u8> {
        let Some(hash) = parameters.int(1).and_then(Value::bytes) else {
            return status(STATUS_INVALID_PARAMETER);
        };
        if !self.spend(parameters.int(8), hash, PERMISSION_MAKE_CREDENTIAL) {
            return status(STATUS_PIN_AUTH_INVALID);
        }
        let scalar = Zeroizing::new(self.drbg.draw());
        SigningKey::from_slice(scalar.as_slice())
            .map(|key| self.attest(key, hash))
            .unwrap_or_default()
    }

    /// Create a credential under `key` and return the `makeCredential` reply.
    fn attest(&mut self, key: SigningKey, hash: &[u8]) -> Vec<u8> {
        let id = self.drbg.draw();
        let cred_random = self.drbg.draw();
        let point = public_point(&key);
        let mut auth_data = rp_id_hash().to_vec();
        auth_data.push(FLAGS_CREATE);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&self.aaguid);
        auth_data.extend_from_slice(&[0, 32]);
        auth_data.extend_from_slice(&id);
        auth_data.extend_from_slice(
            &Writer::default()
                .map(5)
                .unsigned(1)
                .unsigned(2)
                .unsigned(3)
                .negative(6)
                .negative(0)
                .unsigned(1)
                .negative(1)
                .bytes(&point.x)
                .negative(2)
                .bytes(&point.y)
                .map(1)
                .text("hmac-secret")
                .boolean(true)
                .finish(),
        );
        let signed = signature(&key, &auth_data, hash);
        self.credentials.push(Credential {
            id,
            key,
            cred_random,
        });
        ok(&Writer::default()
            .map(3)
            .unsigned(1)
            .text("packed")
            .unsigned(2)
            .bytes(&auth_data)
            .unsigned(3)
            .map(2)
            .text("alg")
            .negative(6)
            .text("sig")
            .bytes(&signed)
            .finish())
    }

    /// The encrypted `output1 = HMAC-SHA-256(CredRandom, salt1)` for the `hmac-secret` input.
    fn hmac_secret(
        &mut self,
        input: Option<&Value<'_>>,
        cred_random: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let secret = input.and_then(|input| self.secret(input.int(1)));
        let salt_enc = input.and_then(|input| input.int(2)).and_then(Value::bytes);
        let salt_auth = input.and_then(|input| input.int(3)).and_then(Value::bytes);
        let expected = secret
            .as_ref()
            .zip(salt_enc)
            .map(|(secret, salt_enc)| pin::authenticate(secret.hmac_key(), &[salt_enc]));
        let authentic = expected.is_some_and(|expected| salt_auth == Some(&expected[..]));
        let output = secret
            .as_ref()
            .zip(salt_enc)
            .filter(|_| authentic)
            .and_then(|(secret, salt_enc)| pin::decrypt(secret, salt_enc))
            .filter(|blocks| blocks.len() == 2)
            .map(|blocks| pin::authenticate(cred_random, &[blocks.as_flattened()]));
        output.zip(secret).and_then(|(output, secret)| {
            pin::encrypt(&secret, &two_blocks(&output), &mut self.drbg).ok()
        })
    }

    fn get_assertion(&mut self, parameters: &Value<'_>) -> Vec<u8> {
        let Some(hash) = parameters.int(2).and_then(Value::bytes) else {
            return status(STATUS_INVALID_PARAMETER);
        };
        if !self.spend(parameters.int(6), hash, PERMISSION_GET_ASSERTION) {
            return status(STATUS_PIN_AUTH_INVALID);
        }
        let wanted = parameters
            .int(3)
            .and_then(|list| list.items().first())
            .and_then(|credential| credential.text_key("id"))
            .and_then(Value::bytes);
        let input = parameters
            .int(4)
            .and_then(|extensions| extensions.text_key("hmac-secret"));
        let found = wanted
            .and_then(|id| {
                self.credentials
                    .iter()
                    .position(|credential| credential.id == id)
            })
            .and_then(|index| {
                let cred_random = self.credentials[index].cred_random;
                self.hmac_secret(input, &cred_random)
                    .map(|output| (index, output))
            });
        let Some((index, output)) = found else {
            return status(STATUS_NO_CREDENTIALS);
        };
        self.counter += 1;
        let mut auth_data = rp_id_hash().to_vec();
        auth_data.push(FLAGS_GET);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(
            &Writer::default()
                .map(1)
                .text("hmac-secret")
                .bytes(&output)
                .finish(),
        );
        let credential = &self.credentials[index];
        let signed = signature(&credential.key, &auth_data, hash);
        ok(&Writer::default()
            .map(3)
            .unsigned(1)
            .map(2)
            .text("id")
            .bytes(&credential.id)
            .text("type")
            .text("public-key")
            .unsigned(2)
            .bytes(&auth_data)
            .unsigned(3)
            .bytes(&signed)
            .finish())
    }
}
