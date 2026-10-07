//! A fixture authenticator: signs synthetic ceremonies with test-only P-256 scalars.
//!
//! The fixture scalar is `d = 1`, whose public key is the P-256 base point. It must never be
//! accepted outside tests.

use std::cell::RefCell;
use std::collections::HashMap;

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use pos_owner_bridge_codec::{
    encode_assertion_reply, encode_attestation_reply, AssertionReplyV1, AttestationReplyV1,
    CeremonyId, OwnerBridgeCodecError, OwnerUserHandle, PrfResult, TransportCodes,
    WebAuthnChallenge,
};
use sha2::{Digest, Sha256};

use crate::ceremony::{replace_prf, PRF_NULL};

/// The test-only scalar `d = 1`.
pub const FIXTURE_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

/// A second scalar whose signatures never verify under the fixture public key.
pub const OTHER_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
];

/// The canonical COSE ES256 encoding of the public key of [`FIXTURE_SCALAR`].
pub const FIXTURE_COSE_KEY: [u8; 77] = [
    0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c,
    0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
    0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x22, 0x58, 0x20, 0x4f, 0xe3, 0x42,
    0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33,
    0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

const ORIGIN: &str = "http://localhost:49291";

type Scalars = ([u8; 32], [u8; 32]);
type KeyPair = (SigningKey, SigningKey);

thread_local! {
    /// Signing is deterministic, so identical ceremonies reuse their signed payload.
    static PAYLOADS: RefCell<HashMap<String, Vec<u8>>> = RefCell::new(HashMap::new());

    /// Deriving a signing key costs a scalar multiplication, so each key pair is built once.
    static KEYS: RefCell<HashMap<Scalars, KeyPair>> = RefCell::new(HashMap::new());
}

fn parse_scalar(bytes: &[u8; 32]) -> Result<SigningKey, OwnerBridgeCodecError> {
    SigningKey::from_slice(bytes).or(Err(OwnerBridgeCodecError::InvalidPayload))
}

fn derive_keys(key: &[u8; 32], other: &[u8; 32]) -> Result<KeyPair, OwnerBridgeCodecError> {
    let keys = (parse_scalar(key)?, parse_scalar(other)?);
    KEYS.with(|cache| cache.borrow_mut().insert((*key, *other), keys.clone()));
    Ok(keys)
}

fn keys_for(key: &[u8; 32], other: &[u8; 32]) -> Result<KeyPair, OwnerBridgeCodecError> {
    let cached = KEYS.with(|cache| cache.borrow().get(&(*key, *other)).cloned());
    cached.map_or_else(|| derive_keys(key, other), Ok)
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn cached(
    key: &str,
    build: impl FnOnce() -> Result<Vec<u8>, OwnerBridgeCodecError>,
) -> Result<Vec<u8>, OwnerBridgeCodecError> {
    let hit = PAYLOADS.with(|cache| cache.borrow().get(key).cloned());
    if let Some(payload) = hit {
        return Ok(payload);
    }
    let payload = build()?;
    PAYLOADS.with(|cache| cache.borrow_mut().insert(key.to_owned(), payload.clone()));
    Ok(payload)
}

/// Encode `bytes` as unpadded base64url.
#[must_use]
pub fn base64url(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = [0_u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let word = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for position in 0..=chunk.len() {
            let index = usize::try_from((word >> (18 - 6 * position)) & 63).unwrap_or(0);
            encoded.push(char::from(BASE64URL.get(index).copied().unwrap_or(b'A')));
        }
    }
    encoded
}

/// The backup flags a fixture authenticator reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backup {
    /// Neither backup-eligible nor backed up.
    None,
    /// Backup-eligible but not backed up.
    Eligible,
    /// Backup-eligible and backed up.
    Synced,
}

/// What a fixture reply says, so tests can make it honest or deviant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplyShape {
    /// The authenticator signature counter.
    pub sign_count: u32,
    /// The PRF `first` result, when the authenticator returns one. A Get reply without one is
    /// encoded the way the packaged page encodes an absent PRF: as CBOR `null`.
    pub prf: Option<[u8; 32]>,
    /// A raw CBOR item that replaces the PRF item of the encoded reply, to model a page that
    /// reports a malformed PRF.
    pub prf_item: Option<Vec<u8>>,
    /// The Create `prf.enabled` flag.
    pub prf_enabled: bool,
    /// The backup flags.
    pub backup: Backup,
    /// The user handle reported in an assertion.
    pub user_handle: Option<OwnerUserHandle>,
    /// A credential ID that replaces the real one in the reply `rawId`.
    pub raw_id: Option<Vec<u8>>,
    /// Sign with a key that does not match the credential.
    pub wrong_key: bool,
}

impl ReplyShape {
    /// An honest reply with `sign_count` and `prf`.
    #[must_use]
    pub const fn honest(sign_count: u32, prf: Option<[u8; 32]>) -> Self {
        Self {
            sign_count,
            prf,
            prf_item: None,
            prf_enabled: true,
            backup: Backup::None,
            user_handle: None,
            raw_id: None,
            wrong_key: false,
        }
    }
}

/// A fixture authenticator holding one credential.
pub struct FixtureSigner {
    key: SigningKey,
    other: SigningKey,
    scalars: Scalars,
    credential_id: Vec<u8>,
}

/// Replace the PRF item of an encoded reply with the raw CBOR `item`, when there is one.
fn patch_prf(encoded: Vec<u8>, item: Option<&[u8]>) -> Vec<u8> {
    item.and_then(|item| replace_prf(&encoded, item))
        .unwrap_or(encoded)
}

/// Append a CBOR byte-string header for a length of at least 24.
fn bstr_header(output: &mut Vec<u8>, length: usize) {
    if length < 256 {
        output.extend_from_slice(&[0x58, u8::try_from(length).unwrap_or(0)]);
    } else {
        let wide = u16::try_from(length).unwrap_or(u16::MAX);
        output.push(0x59);
        output.extend_from_slice(&wide.to_be_bytes());
    }
}

impl FixtureSigner {
    /// Create the authenticator for `credential_id` under the fixture scalar.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPayload` if a scalar is not a valid P-256 scalar.
    pub fn new(credential_id: &[u8]) -> Result<Self, OwnerBridgeCodecError> {
        Self::with_scalars(&FIXTURE_SCALAR, &OTHER_SCALAR, credential_id)
    }

    /// Create an authenticator from explicit scalars.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPayload` if a scalar is not a valid P-256 scalar.
    pub fn with_scalars(
        key: &[u8; 32],
        other: &[u8; 32],
        credential_id: &[u8],
    ) -> Result<Self, OwnerBridgeCodecError> {
        let scalars = (*key, *other);
        let (signing, wrong) = keys_for(key, other)?;
        Ok(Self {
            key: signing,
            other: wrong,
            scalars,
            credential_id: credential_id.to_vec(),
        })
    }

    /// The credential ID this authenticator holds.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    fn rp_id_hash() -> [u8; 32] {
        Sha256::digest(b"localhost").into()
    }

    const fn flags(base: u8, shape: &ReplyShape) -> u8 {
        match shape.backup {
            Backup::None => base,
            Backup::Eligible => base | 0x08,
            Backup::Synced => base | 0x18,
        }
    }

    fn client_data(kind: &str, challenge: &WebAuthnChallenge) -> Vec<u8> {
        let challenge = base64url(challenge.as_bytes());
        format!(
            "{{\"type\":\"{kind}\",\"challenge\":\"{challenge}\",\"origin\":\"{ORIGIN}\",\
             \"crossOrigin\":false}}"
        )
        .into_bytes()
    }

    fn signature(
        &self,
        shape: &ReplyShape,
        authenticator_data: &[u8],
        client_data: &[u8],
    ) -> Vec<u8> {
        let digest = Sha256::digest(client_data);
        let mut message = authenticator_data.to_vec();
        message.extend_from_slice(&digest);
        let key = if shape.wrong_key {
            &self.other
        } else {
            &self.key
        };
        let signature: Signature = key.sign(&message);
        signature.to_der().as_bytes().to_vec()
    }

    fn create_authenticator_data(&self, shape: &ReplyShape) -> Vec<u8> {
        let mut data = Self::rp_id_hash().to_vec();
        data.push(Self::flags(0x45, shape));
        data.extend_from_slice(&shape.sign_count.to_be_bytes());
        data.extend_from_slice(&[0; 16]);
        let id_length = u16::try_from(self.credential_id.len()).unwrap_or(u16::MAX);
        data.extend_from_slice(&id_length.to_be_bytes());
        data.extend_from_slice(&self.credential_id);
        data.extend_from_slice(&FIXTURE_COSE_KEY);
        data
    }

    fn none_attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
        let mut object = vec![0xa3, 0x63];
        object.extend_from_slice(b"fmt");
        object.push(0x64);
        object.extend_from_slice(b"none");
        object.push(0x67);
        object.extend_from_slice(b"attStmt");
        object.push(0xa0);
        object.push(0x68);
        object.extend_from_slice(b"authData");
        bstr_header(&mut object, authenticator_data.len());
        object.extend_from_slice(authenticator_data);
        object
    }

    /// Encode the `AttestationReplyV1` payload of a Create ceremony.
    ///
    /// # Errors
    ///
    /// Returns the codec failure if a field exceeds its closed bound.
    pub fn attestation_payload(
        &self,
        ceremony_id: CeremonyId,
        challenge: &WebAuthnChallenge,
        shape: &ReplyShape,
    ) -> Result<Vec<u8>, OwnerBridgeCodecError> {
        let key = format!(
            "create{ceremony_id:?}{challenge:?}{shape:?}{:?}{:?}",
            self.credential_id, self.scalars
        );
        cached(&key, || {
            self.build_attestation(ceremony_id, challenge, shape)
        })
    }

    fn build_attestation(
        &self,
        ceremony_id: CeremonyId,
        challenge: &WebAuthnChallenge,
        shape: &ReplyShape,
    ) -> Result<Vec<u8>, OwnerBridgeCodecError> {
        let client_data = Self::client_data("webauthn.create", challenge);
        let attestation = Self::none_attestation_object(&self.create_authenticator_data(shape));
        let mut buffer = vec![0_u8; 70_000];
        let length = TransportCodes::new(&[0])
            .and_then(|transports| {
                AttestationReplyV1::new(
                    ceremony_id,
                    &self.credential_id,
                    &client_data,
                    &attestation,
                    transports,
                    shape.prf_enabled,
                    shape.prf.map(PrfResult::from_bytes),
                )
            })
            .and_then(|reply| encode_attestation_reply(&reply, &mut buffer))?;
        buffer.truncate(length);
        Ok(patch_prf(buffer, shape.prf_item.as_deref()))
    }

    /// Encode the `AssertionReplyV1` payload of a Get ceremony.
    ///
    /// # Errors
    ///
    /// Returns the codec failure if a field exceeds its closed bound.
    pub fn assertion_payload(
        &self,
        ceremony_id: CeremonyId,
        challenge: &WebAuthnChallenge,
        shape: &ReplyShape,
    ) -> Result<Vec<u8>, OwnerBridgeCodecError> {
        let key = format!(
            "get{ceremony_id:?}{challenge:?}{shape:?}{:?}{:?}",
            self.credential_id, self.scalars
        );
        cached(&key, || self.build_assertion(ceremony_id, challenge, shape))
    }

    fn build_assertion(
        &self,
        ceremony_id: CeremonyId,
        challenge: &WebAuthnChallenge,
        shape: &ReplyShape,
    ) -> Result<Vec<u8>, OwnerBridgeCodecError> {
        let client_data = Self::client_data("webauthn.get", challenge);
        let mut authenticator_data = Self::rp_id_hash().to_vec();
        authenticator_data.push(Self::flags(0x05, shape));
        authenticator_data.extend_from_slice(&shape.sign_count.to_be_bytes());
        let signature = self.signature(shape, &authenticator_data, &client_data);
        let raw_id = shape.raw_id.as_deref().unwrap_or(&self.credential_id);
        let mut buffer = vec![0_u8; 8_192];
        let placeholder = PrfResult::from_bytes(shape.prf.unwrap_or([0; 32]));
        let length = AssertionReplyV1::new(
            ceremony_id,
            raw_id,
            &client_data,
            &authenticator_data,
            &signature,
            shape.user_handle,
            placeholder,
        )
        .and_then(|reply| encode_assertion_reply(&reply, &mut buffer))?;
        buffer.truncate(length);
        let absent = shape.prf.is_none().then_some(&PRF_NULL[..]);
        Ok(patch_prf(buffer, shape.prf_item.as_deref().or(absent)))
    }
}
