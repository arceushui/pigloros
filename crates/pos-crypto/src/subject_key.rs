//! ADR-091 subject owner and key custody: the `SubjectKeyWrapV1` (SKW1)
//! record, its `WebAuthn`-PRF wrapping key, and the data and consent-bootstrap
//! subkeys (ADR-097 revision 3, section 1).
//!
//! This module is pure cryptography. Randomness, PRF evaluation, durable
//! storage, registry authorization and destruction belong to the trusted
//! owner adapter that calls it.
//!
//! The root, PRF output, wrapping key and subkeys held by this module are
//! wiped on drop. The HKDF pseudorandom key and HMAC state inside
//! `hkdf 0.13.0` are not: that release has no `zeroize` support, and this
//! crate does not clear them.
//!
//! The RP ID grammar reads ADR-091's "strict subset of the `WebAuthn` valid
//! domain string" with the WHATWG host parser's rule: a last label that is
//! all decimal digits, or `0x` followed by hexadecimal digits, is an IPv4
//! number, so the RP ID is an IPv4 literal and is rejected.

use std::fmt;

use pos_core::{EntityId, Hash};
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::key_roles::key_material_digest;
use crate::strict_cbor::{Reader, StrictCborError};
use crate::subject_cbor::{self, ROLE, VERSION};

/// The ASCII prefix of every subject key owner (ADR-091).
pub const SUBJECT_OWNER_PREFIX: &str = "subject:";
/// The exact byte length of a subject key owner: the prefix and 32 hex digits.
pub const SUBJECT_OWNER_BYTES: usize = 40;
/// The longest accepted RP ID, in bytes.
pub const MAX_SUBJECT_RP_ID_BYTES: usize = 253;
/// The longest accepted `WebAuthn` credential ID, in bytes.
pub const MAX_SUBJECT_CREDENTIAL_ID_BYTES: usize = 1024;

const MAGIC: [u8; 4] = *b"SKW1";
const WRAP_LABEL: &[u8] = b"pigloros.subject.wrap.v1\0";
const DATA_LABEL: &[u8] = b"pigloros.subject.data.v1\0";
const BOOTSTRAP_LABEL: &[u8] = b"pigloros.subject.bootstrap.v1\0";
const HEX: &[u8; 16] = b"0123456789abcdef";
/// The error ordinal of the whole SKW1 record and its outer framing.
const DOCUMENT: u8 = 13;

/// A closed `SubjectKeyWrapV1` failure.
///
/// `ordinal` is the SKW1 field (0-12): 0 magic, 2 owner, 3 subject, 4 role,
/// 5 epoch, 6 RP ID, 7 credential ID, 8 PRF input, 9 wrapping salt, 10 subkey
/// salt, 11 wrap nonce and 12 wrapped root. Ordinal 13 is the whole record.
/// No variant carries text, bytes, or key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SubjectKeyWrapErrorV1 {
    /// Truncated, non-shortest, indefinite, or wrongly typed CBOR, a wrong
    /// array cardinality or fixed byte length, or trailing bytes.
    #[error("invalid SKW1 encoding at field {ordinal}")]
    InvalidEncoding {
        /// SKW1 field, or 13 for the record.
        ordinal: u8,
    },
    /// A text or byte string longer than its V1 maximum.
    #[error("SKW1 field {ordinal} exceeds a V1 bound")]
    BoundsExceeded {
        /// SKW1 field.
        ordinal: u8,
    },
    /// A well-typed value outside its allowed value or grammar, including a
    /// wrong magic, a nil subject, an owner that is not the subject's owner,
    /// a role other than `SubjectDataEncryption`, and epoch zero.
    #[error("invalid SKW1 field {ordinal}")]
    InvalidField {
        /// SKW1 field.
        ordinal: u8,
    },
    /// Field 1 names a version other than 1.
    #[error("unsupported SKW1 version")]
    UnsupportedVersion,
    /// AES-256-GCM authentication of the wrapped root failed; no root is
    /// released.
    #[error("SKW1 wrapped root failed authentication")]
    AuthenticationFailed,
    /// HKDF-SHA-256 or AES-256-GCM refused its input lengths. The fixed V1
    /// lengths make this unreachable; it is reported, never replaced by a
    /// zero key or tag.
    #[error("SKW1 key derivation or sealing refused its input")]
    PrimitiveRefused,
}

impl StrictCborError for SubjectKeyWrapErrorV1 {
    fn invalid_encoding(ordinal: u8) -> Self {
        Self::InvalidEncoding { ordinal }
    }

    fn bounds_exceeded(ordinal: u8) -> Self {
        Self::BoundsExceeded { ordinal }
    }
}

/// Derive the dedicated ADR-091 subject key owner: `subject:` followed by the
/// 32 lowercase hexadecimal digits of the subject's 16 ULID bytes.
///
/// # Errors
/// Returns [`SubjectKeyWrapErrorV1::InvalidField`] at ordinal 3 for the nil
/// subject.
pub fn subject_owner_id(subject_id: EntityId) -> Result<String, SubjectKeyWrapErrorV1> {
    let bytes = subject_id.inner().to_bytes();
    if bytes == [0; 16] {
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 3 })
    } else {
        Ok(owner_string(&bytes))
    }
}

/// Parse an exact ADR-091 subject key owner back to its subject.
///
/// The owner must be the 40-byte string `subject:` followed by the 32
/// lowercase hexadecimal digits of a non-nil subject, exactly as
/// [`subject_owner_id`] spells it.
///
/// # Errors
/// Returns [`SubjectKeyWrapErrorV1::InvalidField`] at ordinal 2 for a wrong
/// prefix or length, a non-hexadecimal or uppercase digit, or the nil
/// subject.
pub fn parse_subject_owner_id(owner: &str) -> Result<EntityId, SubjectKeyWrapErrorV1> {
    owner
        .strip_prefix(SUBJECT_OWNER_PREFIX)
        .and_then(|digits| u128::from_str_radix(digits, 16).ok())
        .map(u128::to_be_bytes)
        .filter(|subject| *subject != [0; 16] && owner_string(subject) == owner)
        .map(|subject| EntityId::from_ulid(Ulid::from_bytes(subject)))
        .ok_or(SubjectKeyWrapErrorV1::InvalidField { ordinal: 2 })
}

/// The owner string of non-nil subject bytes.
pub(crate) fn owner_string(subject: &[u8; 16]) -> String {
    let mut owner = String::with_capacity(SUBJECT_OWNER_BYTES);
    owner.push_str(SUBJECT_OWNER_PREFIX);
    for byte in subject {
        owner.push(char::from(HEX[usize::from(byte >> 4)]));
        owner.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    owner
}

/// The 32-byte random subject root key for one subject epoch.
///
/// The bytes are never observable, cloneable, or printed, and they are wiped
/// on drop.
pub struct SubjectRootKeyV1 {
    bytes: Zeroizing<[u8; 32]>,
}

impl SubjectRootKeyV1 {
    /// Take ownership of freshly generated root bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// The ADR-091 registry fingerprint
    /// `BLAKE3("pigloros/key-material/v1" || root32)`.
    #[must_use]
    pub fn material_digest(&self) -> Hash {
        key_material_digest(&self.bytes)
    }
}

impl fmt::Debug for SubjectRootKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubjectRootKeyV1(<redacted>)")
    }
}

/// The 32-byte `WebAuthn` PRF output that keys one wrap.
///
/// The bytes are never observable, cloneable, or printed, and they are wiped
/// on drop.
pub struct SubjectPrfOutputV1 {
    bytes: Zeroizing<[u8; 32]>,
}

impl SubjectPrfOutputV1 {
    /// Take ownership of a verified PRF result.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }
}

impl fmt::Debug for SubjectPrfOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SubjectPrfOutputV1(<redacted>)")
    }
}

/// Which ADR-091 subkey a ciphertext uses (ADR-097 `use` code).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectKeyUseV1 {
    /// `use = 0`: the subject data subkey.
    Data,
    /// `use = 1`: the consent-bootstrap subkey.
    Bootstrap,
}

impl SubjectKeyUseV1 {
    /// The stable wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Bootstrap => 1,
        }
    }

    /// The use for a wire code, or `None` for an unknown code.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Data),
            1 => Some(Self::Bootstrap),
            _ => None,
        }
    }

    const fn label(self) -> &'static [u8] {
        match self {
            Self::Data => DATA_LABEL,
            Self::Bootstrap => BOOTSTRAP_LABEL,
        }
    }
}

/// One derived ADR-091 subkey and the exact identity it serves.
///
/// The key bytes are never observable, cloneable, or printed, and they are
/// wiped on drop. Debug output shows only the identity.
pub struct SubjectSubkeyV1 {
    key: Zeroizing<[u8; 32]>,
    subject_id: EntityId,
    epoch: u64,
    key_use: SubjectKeyUseV1,
}

impl SubjectSubkeyV1 {
    /// The subject this subkey encrypts for.
    #[must_use]
    pub const fn subject_id(&self) -> EntityId {
        self.subject_id
    }

    /// The `SubjectDataEncryption` epoch this subkey belongs to.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether this is the data or the consent-bootstrap subkey.
    #[must_use]
    pub const fn key_use(&self) -> SubjectKeyUseV1 {
        self.key_use
    }

    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

impl fmt::Debug for SubjectSubkeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubjectSubkeyV1")
            .field("subject_id", &self.subject_id)
            .field("epoch", &self.epoch)
            .field("key_use", &self.key_use)
            .finish_non_exhaustive()
    }
}

/// The public inputs of one wrap. The owner adapter generates the PRF input,
/// both salts, and the nonce independently from a CSPRNG for every record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyWrapParamsV1 {
    /// The subject; its owner is derived, never supplied.
    pub subject_id: EntityId,
    /// The positive `SubjectDataEncryption` epoch.
    pub epoch: u64,
    /// The exact registration RP ID in the ADR-091 canonical domain form.
    pub rp_id: String,
    /// The 1-1024-byte `WebAuthn` credential ID.
    pub credential_id: Vec<u8>,
    /// The exact 32-byte PRF evaluation input.
    pub prf_input: [u8; 32],
    /// The wrapping-key HKDF salt.
    pub wrap_salt: [u8; 32],
    /// The data and bootstrap subkey HKDF salt.
    pub subkey_salt: [u8; 32],
    /// The single-use AES-256-GCM nonce for the wrapped root.
    pub wrap_nonce: [u8; 12],
}

/// The ADR-091 `SubjectKeyWrapV1` record: a deterministic-CBOR 13-element
/// array whose last field is the AES-256-GCM-wrapped root and its tag.
///
/// Every field is public data; the record holds no key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectKeyWrapV1 {
    params: SubjectKeyWrapParamsV1,
    wrapped_root: [u8; 48],
}

impl SubjectKeyWrapV1 {
    /// Wrap `root` under the key derived from `prf`.
    ///
    /// # Errors
    /// Returns [`SubjectKeyWrapErrorV1::InvalidField`] for a nil subject
    /// (3), epoch zero (5), an RP ID outside the canonical domain grammar (6),
    /// or an empty credential ID (7), and
    /// [`SubjectKeyWrapErrorV1::BoundsExceeded`] for an RP ID above 253 bytes
    /// (6) or a credential ID above 1024 bytes (7). The unreachable
    /// [`SubjectKeyWrapErrorV1::PrimitiveRefused`] fails closed instead of
    /// producing a zero key or tag.
    pub fn seal(
        params: SubjectKeyWrapParamsV1,
        root: &SubjectRootKeyV1,
        prf: &SubjectPrfOutputV1,
    ) -> Result<Self, SubjectKeyWrapErrorV1> {
        validate(&params)?;
        let mut body = Zeroizing::new(*root.bytes);
        let tag = wrapping_key(&params, prf).and_then(|key| {
            let aad = associated_data(&params);
            subject_cbor::aes_gcm_seal(&key, &params.wrap_nonce, &aad, body.as_mut_slice())
                .ok_or(SubjectKeyWrapErrorV1::PrimitiveRefused)
        });
        tag.map(|tag| {
            let mut wrapped_root = [0; 48];
            wrapped_root[..32].copy_from_slice(body.as_slice());
            wrapped_root[32..].copy_from_slice(&tag);
            Self {
                params,
                wrapped_root,
            }
        })
    }

    /// Authenticate and unwrap the root under the key derived from `prf`.
    ///
    /// # Errors
    /// Returns [`SubjectKeyWrapErrorV1::AuthenticationFailed`] for a wrong
    /// PRF output or any changed field; no root is released.
    pub fn open(
        &self,
        prf: &SubjectPrfOutputV1,
    ) -> Result<SubjectRootKeyV1, SubjectKeyWrapErrorV1> {
        let mut root = Zeroizing::new([0; 32]);
        root.copy_from_slice(&self.wrapped_root[..32]);
        let tag: [u8; 16] = std::array::from_fn(|index| self.wrapped_root[32 + index]);
        wrapping_key(&self.params, prf).and_then(move |key| {
            let aad = associated_data(&self.params);
            if subject_cbor::aes_gcm_open(
                &key,
                &self.params.wrap_nonce,
                &aad,
                root.as_mut_slice(),
                &tag,
            ) {
                Ok(SubjectRootKeyV1 { bytes: root })
            } else {
                Err(SubjectKeyWrapErrorV1::AuthenticationFailed)
            }
        })
    }

    /// Derive the data or consent-bootstrap subkey of this wrap's root.
    ///
    /// The caller passes the root that [`Self::open`] or enrollment produced
    /// for this exact record.
    ///
    /// # Errors
    /// Returns [`SubjectKeyWrapErrorV1::PrimitiveRefused`] if HKDF refuses
    /// the fixed 32-byte output, which it never does.
    pub fn derive_subkey(
        &self,
        root: &SubjectRootKeyV1,
        key_use: SubjectKeyUseV1,
    ) -> Result<SubjectSubkeyV1, SubjectKeyWrapErrorV1> {
        let mut context = Vec::new();
        context.push(0x83);
        write_owner_subject(&self.params, &mut context);
        subject_cbor::unsigned(&mut context, self.params.epoch);
        let salt = &self.params.subkey_salt;
        subject_cbor::hkdf_sha256(&root.bytes, salt, key_use.label(), &context)
            .ok_or(SubjectKeyWrapErrorV1::PrimitiveRefused)
            .map(|key| SubjectSubkeyV1 {
                key,
                subject_id: self.params.subject_id,
                epoch: self.params.epoch,
                key_use,
            })
    }

    /// Decode exactly one canonical SKW1 record.
    ///
    /// # Errors
    /// Returns the [`SubjectKeyWrapErrorV1`] of the first malformed,
    /// noncanonical, unsupported, or invalid field.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SubjectKeyWrapErrorV1> {
        let mut reader = Reader::new(bytes);
        let (subject, epoch) = read_identity(&mut reader)?;
        let params = read_credential(&mut reader, subject, epoch)?;
        reader.at(12);
        let wrapped_root = reader.bytes()?;
        reader.at(DOCUMENT);
        reader.finish()?;
        Ok(Self {
            params,
            wrapped_root,
        })
    }

    /// The canonical 13-element SKW1 encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = associated_data(&self.params);
        output[0] = 0x8d;
        subject_cbor::byte_string(&mut output, &self.wrapped_root);
        output
    }

    /// The AES-GCM associated data: the standalone deterministic-CBOR array
    /// of the 12 fields through `wrap_nonce`.
    #[must_use]
    pub fn associated_data(&self) -> Vec<u8> {
        associated_data(&self.params)
    }

    /// The deterministic-CBOR wrapping-key HKDF context
    /// `[owner, subject, epoch, rp_id, credential_id]`.
    #[must_use]
    pub fn wrap_context(&self) -> Vec<u8> {
        wrap_context(&self.params)
    }

    /// The public wrap inputs.
    #[must_use]
    pub const fn params(&self) -> &SubjectKeyWrapParamsV1 {
        &self.params
    }

    /// The subject's derived owner.
    #[must_use]
    pub fn owner_id(&self) -> String {
        owner_string(&self.params.subject_id.inner().to_bytes())
    }

    /// The 32-byte wrapped root followed by its 16-byte tag.
    #[must_use]
    pub const fn wrapped_root(&self) -> &[u8; 48] {
        &self.wrapped_root
    }
}

/// Fields 0-5: the framing, magic, version, owner, subject, role and epoch,
/// each validated as soon as it is read.
fn read_identity(
    reader: &mut Reader<'_, SubjectKeyWrapErrorV1>,
) -> Result<(EntityId, u64), SubjectKeyWrapErrorV1> {
    reader.at(DOCUMENT);
    reader.fixed_array(13)?;
    reader.at(0);
    if reader.bytes::<4>()? != MAGIC {
        return Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 0 });
    }
    reader.at(1);
    if reader.unsigned()? != VERSION {
        return Err(SubjectKeyWrapErrorV1::UnsupportedVersion);
    }
    reader.at(2);
    let owner = parse_subject_owner_id(reader.text(SUBJECT_OWNER_BYTES)?)?;
    reader.at(3);
    let subject = check_subject(EntityId::from_ulid(Ulid::from_bytes(reader.bytes()?)))?;
    if subject != owner {
        return Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 2 });
    }
    reader.at(4);
    if reader.unsigned()? != u64::from(ROLE) {
        return Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 4 });
    }
    reader.at(5);
    let epoch = check_epoch(reader.unsigned()?)?;
    Ok((subject, epoch))
}

/// Fields 6-11: the RP ID, credential ID, PRF input, salts and nonce.
fn read_credential(
    reader: &mut Reader<'_, SubjectKeyWrapErrorV1>,
    subject_id: EntityId,
    epoch: u64,
) -> Result<SubjectKeyWrapParamsV1, SubjectKeyWrapErrorV1> {
    reader.at(6);
    let rp_id = reader.text(MAX_SUBJECT_RP_ID_BYTES)?.to_owned();
    check_rp_id(&rp_id)?;
    reader.at(7);
    let credential_id = reader
        .byte_string(MAX_SUBJECT_CREDENTIAL_ID_BYTES)?
        .to_vec();
    check_credential_id(&credential_id)?;
    reader.at(8);
    let prf_input = reader.bytes()?;
    reader.at(9);
    let wrap_salt = reader.bytes()?;
    reader.at(10);
    let subkey_salt = reader.bytes()?;
    reader.at(11);
    let wrap_nonce = reader.bytes()?;
    Ok(SubjectKeyWrapParamsV1 {
        subject_id,
        epoch,
        rp_id,
        credential_id,
        prf_input,
        wrap_salt,
        subkey_salt,
        wrap_nonce,
    })
}

fn write_owner_subject(params: &SubjectKeyWrapParamsV1, output: &mut Vec<u8>) {
    let subject = params.subject_id.inner().to_bytes();
    subject_cbor::text(output, &owner_string(&subject));
    subject_cbor::byte_string(output, &subject);
}

fn wrap_context(params: &SubjectKeyWrapParamsV1) -> Vec<u8> {
    let mut context = Vec::new();
    context.push(0x85);
    write_owner_subject(params, &mut context);
    subject_cbor::unsigned(&mut context, params.epoch);
    subject_cbor::text(&mut context, &params.rp_id);
    subject_cbor::byte_string(&mut context, &params.credential_id);
    context
}

fn associated_data(params: &SubjectKeyWrapParamsV1) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(0x8c);
    subject_cbor::byte_string(&mut output, &MAGIC);
    subject_cbor::unsigned(&mut output, VERSION);
    write_owner_subject(params, &mut output);
    subject_cbor::unsigned(&mut output, u64::from(ROLE));
    subject_cbor::unsigned(&mut output, params.epoch);
    subject_cbor::text(&mut output, &params.rp_id);
    subject_cbor::byte_string(&mut output, &params.credential_id);
    subject_cbor::byte_string(&mut output, &params.prf_input);
    subject_cbor::byte_string(&mut output, &params.wrap_salt);
    subject_cbor::byte_string(&mut output, &params.subkey_salt);
    subject_cbor::byte_string(&mut output, &params.wrap_nonce);
    output
}

fn wrapping_key(
    params: &SubjectKeyWrapParamsV1,
    prf: &SubjectPrfOutputV1,
) -> Result<Zeroizing<[u8; 32]>, SubjectKeyWrapErrorV1> {
    let context = wrap_context(params);
    subject_cbor::hkdf_sha256(&prf.bytes, &params.wrap_salt, WRAP_LABEL, &context)
        .ok_or(SubjectKeyWrapErrorV1::PrimitiveRefused)
}

fn validate(params: &SubjectKeyWrapParamsV1) -> Result<(), SubjectKeyWrapErrorV1> {
    check_subject(params.subject_id)?;
    check_epoch(params.epoch)?;
    check_rp_id(&params.rp_id)?;
    check_credential_id(&params.credential_id)
}

fn check_subject(subject: EntityId) -> Result<EntityId, SubjectKeyWrapErrorV1> {
    if subject.inner().to_bytes() == [0; 16] {
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 3 })
    } else {
        Ok(subject)
    }
}

const fn check_epoch(epoch: u64) -> Result<u64, SubjectKeyWrapErrorV1> {
    if epoch == 0 {
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 5 })
    } else {
        Ok(epoch)
    }
}

fn check_rp_id(rp_id: &str) -> Result<(), SubjectKeyWrapErrorV1> {
    if rp_id.len() > MAX_SUBJECT_RP_ID_BYTES {
        Err(SubjectKeyWrapErrorV1::BoundsExceeded { ordinal: 6 })
    } else if is_canonical_rp_id(rp_id) {
        Ok(())
    } else {
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 6 })
    }
}

fn check_credential_id(credential_id: &[u8]) -> Result<(), SubjectKeyWrapErrorV1> {
    if credential_id.len() > MAX_SUBJECT_CREDENTIAL_ID_BYTES {
        Err(SubjectKeyWrapErrorV1::BoundsExceeded { ordinal: 7 })
    } else if credential_id.is_empty() {
        Err(SubjectKeyWrapErrorV1::InvalidField { ordinal: 7 })
    } else {
        Ok(())
    }
}

/// The ADR-091 project canonical RP ID: lower-case ASCII A-label labels of
/// 1-63 bytes from `a`-`z`, `0`-`9` and interior `-`, separated by dots, with
/// no trailing dot. IPv6 literals and Unicode fail the character rule.
///
/// The canonical form is a strict subset of the WHATWG valid domain that
/// `WebAuthn` requires, so a last label that the host parser reads as an IPv4
/// number (all decimal digits, or `0x` followed by hexadecimal digits) makes
/// the string an IPv4 address literal and is rejected.
fn is_canonical_rp_id(rp_id: &str) -> bool {
    let last = rp_id.rsplit_once('.').map_or(rp_id, |(_, last)| last);
    let ipv4_number = last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()));
    rp_id.split('.').all(is_canonical_label) && !ipv4_number
}

fn is_canonical_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}
