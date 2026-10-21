use crate::{OwnerBridgeCodecError, VerificationReason, MAX_AUTHENTICATOR_DATA_BYTES};
use p256::ecdsa::VerifyingKey;

const MIN_AUTHENTICATOR_DATA_BYTES: usize = 37;
const MIN_CREDENTIAL_ID_BYTES: usize = 1;
const MAX_CREDENTIAL_ID_BYTES: usize = 1_024;
const MAX_ATTESTATION_OBJECT_BYTES: usize = 65_536;
const MAX_EXTENSION_MAP_BYTES: usize = 1_024;
const MAX_EXTENSION_MAP_ENTRIES: usize = 16;
const MAX_CBOR_NESTING: usize = 4;

const FLAG_UP: u8 = 1;
const FLAG_UV: u8 = 1 << 2;
const FLAG_BE: u8 = 1 << 3;
const FLAG_BS: u8 = 1 << 4;
/// Authenticator-data flag bits 1 and 5 are reserved and must be zero. The bits are disjoint, and
/// `+` (not `|`) avoids an equivalent `|` to `^` mutant, so do not "fix" it back.
const FLAG_RESERVED_MASK: u8 = (1 << 1) + (1 << 5);
const FLAG_AT: u8 = 1 << 6;
const FLAG_ED: u8 = 1 << 7;

const ATTESTATION_FORMAT_FIELD: u8 = 1;
const ATTESTATION_STATEMENT_FIELD: u8 = 1 << 1;
const ATTESTATION_AUTH_DATA_FIELD: u8 = 1 << 2;
const COSE_KTY_FIELD: u8 = 1;
const COSE_ALGORITHM_FIELD: u8 = 1 << 1;
const COSE_CURVE_FIELD: u8 = 1 << 2;
const COSE_X_FIELD: u8 = 1 << 3;
const COSE_Y_FIELD: u8 = 1 << 4;
const COSE_ES256_ALGORITHM: i64 = -7;

const RP_ID_HASH: [u8; 32] = [
    0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76, 0x60, 0x5b,
    0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63,
];

/// Exact byte size of an ADR-110 canonical COSE ES256 public-key encoding.
pub const CANONICAL_COSE_ES256_KEY_BYTES: usize = 77;

/// A syntactically valid closed COSE ES256 P-256 public key.
///
/// Authenticator-data parsing retains the closed COSE shape before the
/// verifier validates its point. Durable canonical decoding validates both
/// shape and point before a binding reaches an owner adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoseEs256PublicKey {
    x: [u8; 32],
    y: [u8; 32],
}

impl CoseEs256PublicKey {
    /// Return the P-256 affine x-coordinate from the closed COSE key.
    #[must_use]
    pub const fn x(self) -> [u8; 32] {
        self.x
    }

    /// Return the P-256 affine y-coordinate from the closed COSE key.
    #[must_use]
    pub const fn y(self) -> [u8; 32] {
        self.y
    }

    /// Re-encode this key in the fixed canonical COSE map required for a
    /// `SubjectCredentialBindingV1`.
    #[must_use]
    pub fn canonical_encoding(self) -> [u8; CANONICAL_COSE_ES256_KEY_BYTES] {
        let mut output = [0; CANONICAL_COSE_ES256_KEY_BYTES];
        output[..10].copy_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        output[10..42].copy_from_slice(&self.x);
        output[42..45].copy_from_slice(&[0x22, 0x58, 0x20]);
        output[45..].copy_from_slice(&self.y);
        output
    }

    /// Return an uncompressed SEC1 point image for a P-256 verifier.
    #[must_use]
    pub fn uncompressed_sec1_bytes(self) -> [u8; 65] {
        let mut output = [0; 65];
        output[0] = 4;
        output[1..33].copy_from_slice(&self.x);
        output[33..].copy_from_slice(&self.y);
        output
    }

    /// Decode an exact canonical COSE ES256 key stored in a durable binding.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::InvalidPayload`] when `input` is not
    /// the one canonical closed COSE schema or its P-256 point is invalid.
    pub fn from_canonical_encoding(input: &[u8]) -> Result<Self, OwnerBridgeCodecError> {
        let invalid = OwnerBridgeCodecError::InvalidPayload;
        let (key, consumed) = parse_cose_es256_key(input).or(Err(invalid))?;
        if consumed != input.len() || key.canonical_encoding() != input {
            return Err(invalid);
        }
        VerifyingKey::from_sec1_bytes(&key.uncompressed_sec1_bytes()).or(Err(invalid))?;
        Ok(key)
    }
}

/// Validated authenticator data extracted from a Create attestation object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateAuthenticatorData<'a> {
    credential_id: &'a [u8],
    public_key: CoseEs256PublicKey,
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
}

impl<'a> CreateAuthenticatorData<'a> {
    /// Return the credential ID attested inside authenticator data.
    #[must_use]
    pub const fn credential_id(self) -> &'a [u8] {
        self.credential_id
    }

    /// Return the closed ES256 public key extracted from authenticator data.
    #[must_use]
    pub const fn public_key(self) -> CoseEs256PublicKey {
        self.public_key
    }

    /// Return the credential backup-eligibility bit.
    #[must_use]
    pub const fn backup_eligible(self) -> bool {
        self.backup_eligible
    }

    /// Return the credential backup-state bit.
    #[must_use]
    pub const fn backup_state(self) -> bool {
        self.backup_state
    }

    /// Return the authenticator's initial signature counter.
    #[must_use]
    pub const fn sign_count(self) -> u32 {
        self.sign_count
    }
}

/// Validated authenticator data extracted from a Get assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssertionAuthenticatorData {
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
}

impl AssertionAuthenticatorData {
    /// Return the credential backup-eligibility bit.
    #[must_use]
    pub const fn backup_eligible(self) -> bool {
        self.backup_eligible
    }

    /// Return the credential backup-state bit.
    #[must_use]
    pub const fn backup_state(self) -> bool {
        self.backup_state
    }

    /// Return the authenticator's assertion signature counter.
    #[must_use]
    pub const fn sign_count(self) -> u32 {
        self.sign_count
    }
}

/// Parse the closed `none` attestation object and its Create authenticator data.
///
/// # Errors
///
/// Returns a closed [`VerificationReason`]: `AttestationFormat` for a
/// non-`none` or malformed envelope, `CredentialMismatch` for a credential ID
/// that differs from `raw_id`, `RpIdHash`, `UserPresence`, `UserVerification`
/// or `BackupFlags` for the matching authenticator-data check, `Algorithm` or
/// `CoseKey` for the COSE key, `Extensions` for the extension map or trailing
/// bytes, and `Malformed` for other structural failures.
pub fn parse_none_attestation_object<'a>(
    input: &'a [u8],
    raw_id: &[u8],
) -> Result<CreateAuthenticatorData<'a>, VerificationReason> {
    let envelope_fault = VerificationReason::AttestationFormat;
    require_bounded(input, 1, MAX_ATTESTATION_OBJECT_BYTES, envelope_fault)?;
    require_bounded(
        raw_id,
        MIN_CREDENTIAL_ID_BYTES,
        MAX_CREDENTIAL_ID_BYTES,
        VerificationReason::CredentialMismatch,
    )?;
    let auth_data = read_attestation_envelope(input)?;
    let prefix = parse_authenticator_data_prefix(auth_data)?;
    if prefix.flags & FLAG_AT == 0 {
        return Err(VerificationReason::Malformed);
    }
    let (credential_id, cose_offset) = read_attested_credential_id(auth_data, raw_id)?;
    let (public_key, consumed) = parse_cose_es256_key(&auth_data[cose_offset..])?;
    // `parse_cose_es256_key` cannot consume beyond the supplied suffix.
    finish_authenticator_data(
        auth_data,
        cose_offset + consumed,
        prefix.flags & FLAG_ED != 0,
    )?;
    Ok(CreateAuthenticatorData {
        credential_id,
        public_key,
        backup_eligible: prefix.flags & FLAG_BE != 0,
        backup_state: prefix.flags & FLAG_BS != 0,
        sign_count: prefix.sign_count,
    })
}

fn read_attestation_envelope(input: &[u8]) -> Result<&[u8], VerificationReason> {
    let mut reader = AuthenticatorCborReader::new(input, VerificationReason::AttestationFormat);
    let count = reader.map_len()?;
    if count != 3 {
        return Err(reader.fault);
    }

    let mut seen = 0;
    let mut auth_data = input;
    for _ in 0..count {
        let key = reader.map_key()?;
        if key.equals_text(b"fmt") {
            if seen & ATTESTATION_FORMAT_FIELD != 0 || reader.text()? != b"none" {
                return Err(reader.fault);
            }
            seen |= ATTESTATION_FORMAT_FIELD;
        } else if key.equals_text(b"attStmt") {
            if seen & ATTESTATION_STATEMENT_FIELD != 0 || reader.map_len()? != 0 {
                return Err(reader.fault);
            }
            seen |= ATTESTATION_STATEMENT_FIELD;
        } else if key.equals_text(b"authData") {
            if seen & ATTESTATION_AUTH_DATA_FIELD != 0 {
                return Err(reader.fault);
            }
            // The length bound is checked by `parse_authenticator_data_prefix`, which reports an
            // out-of-range authenticator-data length as `Malformed`, not as an envelope fault.
            auth_data = reader.bytes(0, usize::MAX)?;
            seen |= ATTESTATION_AUTH_DATA_FIELD;
        } else {
            return Err(reader.fault);
        }
    }
    reader.finish()?;
    // The three accepted fields have distinct bits, duplicates and unknown
    // fields return above, and the map length is exactly three. Thus every
    // accepted traversal assigned `auth_data` exactly once.
    Ok(auth_data)
}

/// Parse closed Get authenticator data, including any ignored extension map.
///
/// # Errors
///
/// Returns a closed [`VerificationReason`]: `RpIdHash`, `UserPresence`,
/// `UserVerification` or `BackupFlags` for the matching check, `Extensions`
/// for a malformed extension map or trailing bytes, and `Malformed` for a
/// wrong length, reserved flag, or unexpected attested-credential data.
pub fn parse_assertion_authenticator_data(
    input: &[u8],
) -> Result<AssertionAuthenticatorData, VerificationReason> {
    let prefix = parse_authenticator_data_prefix(input)?;
    if prefix.flags & FLAG_AT != 0 {
        return Err(VerificationReason::Malformed);
    }
    finish_authenticator_data(
        input,
        MIN_AUTHENTICATOR_DATA_BYTES,
        prefix.flags & FLAG_ED != 0,
    )?;
    Ok(AssertionAuthenticatorData {
        backup_eligible: prefix.flags & FLAG_BE != 0,
        backup_state: prefix.flags & FLAG_BS != 0,
        sign_count: prefix.sign_count,
    })
}

struct AuthenticatorDataPrefix {
    flags: u8,
    sign_count: u32,
}

fn parse_authenticator_data_prefix(
    input: &[u8],
) -> Result<AuthenticatorDataPrefix, VerificationReason> {
    require_bounded(
        input,
        MIN_AUTHENTICATOR_DATA_BYTES,
        MAX_AUTHENTICATOR_DATA_BYTES,
        VerificationReason::Malformed,
    )?;
    if input[..32] != RP_ID_HASH {
        return Err(VerificationReason::RpIdHash);
    }
    let flags = input[32];
    check_authenticator_flags(flags)?;
    let sign_count = u32::from_be_bytes([input[33], input[34], input[35], input[36]]);
    Ok(AuthenticatorDataPrefix { flags, sign_count })
}

const fn check_authenticator_flags(flags: u8) -> Result<(), VerificationReason> {
    if flags & FLAG_UP == 0 {
        Err(VerificationReason::UserPresence)
    } else if flags & FLAG_UV == 0 {
        Err(VerificationReason::UserVerification)
    } else if flags & FLAG_RESERVED_MASK != 0 {
        Err(VerificationReason::Malformed)
    } else if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        Err(VerificationReason::BackupFlags)
    } else {
        Ok(())
    }
}

/// Check the extension map and that nothing follows the parsed data.
///
/// Trailing bytes after a map-less authenticator-data image are reported as `Extensions`
/// (ADR-110 §7: "`ED = 0` with trailing bytes"), which also covers trailing bytes after the
/// COSE key of a Create reply.
fn finish_authenticator_data(
    input: &[u8],
    mut offset: usize,
    extensions: bool,
) -> Result<(), VerificationReason> {
    let fault = VerificationReason::Extensions;
    if extensions {
        let extension_bytes = &input[offset..];
        require_bounded(extension_bytes, 1, MAX_EXTENSION_MAP_BYTES, fault)?;
        let mut extension_reader = AuthenticatorCborReader::new(extension_bytes, fault);
        extension_reader.validate_extension_map()?;
        extension_reader.finish()?;
        offset = input.len();
    }
    if offset != input.len() {
        return Err(fault);
    }
    Ok(())
}

fn read_attested_credential_id<'a>(
    input: &'a [u8],
    raw_id: &[u8],
) -> Result<(&'a [u8], usize), VerificationReason> {
    const CREDENTIAL_LENGTH_OFFSET: usize = MIN_AUTHENTICATOR_DATA_BYTES + 16;
    const CREDENTIAL_START: usize = CREDENTIAL_LENGTH_OFFSET + 2;

    let malformed = VerificationReason::Malformed;
    let credential_length = input
        .get(CREDENTIAL_LENGTH_OFFSET..CREDENTIAL_START)
        .ok_or(malformed)?;
    let credential_length = usize::from(u16::from_be_bytes([
        credential_length[0],
        credential_length[1],
    ]));
    if !(MIN_CREDENTIAL_ID_BYTES..=MAX_CREDENTIAL_ID_BYTES).contains(&credential_length) {
        return Err(malformed);
    }
    let credential_end = CREDENTIAL_START + credential_length;
    let credential_range = CREDENTIAL_START..credential_end;
    let parsed_credential_id = input.get(credential_range).ok_or(malformed)?;
    if parsed_credential_id != raw_id {
        return Err(VerificationReason::CredentialMismatch);
    }
    Ok((parsed_credential_id, credential_end))
}

fn parse_cose_es256_key(input: &[u8]) -> Result<(CoseEs256PublicKey, usize), VerificationReason> {
    reject_other_cose_algorithm(input)?;
    let mut reader = AuthenticatorCborReader::new(input, VerificationReason::CoseKey);
    if reader.map_len()? != 5 {
        return Err(reader.fault);
    }

    let mut seen = 0;
    let mut x = [0; 32];
    let mut y = [0; 32];
    for _ in 0..5 {
        let key = reader.map_key()?;
        if key.is_unsigned(1) {
            if seen & COSE_KTY_FIELD != 0 || reader.unsigned()? != 2 {
                return Err(reader.fault);
            }
            seen |= COSE_KTY_FIELD;
        } else if key.is_unsigned(3) {
            // `reject_other_cose_algorithm` already proved the first label-3
            // value is -7, so only a duplicate or non-integer value fails here.
            if seen & COSE_ALGORITHM_FIELD != 0 {
                return Err(reader.fault);
            }
            reader.signed()?;
            seen |= COSE_ALGORITHM_FIELD;
        } else if key.is_negative(0) {
            if seen & COSE_CURVE_FIELD != 0 || reader.unsigned()? != 1 {
                return Err(reader.fault);
            }
            seen |= COSE_CURVE_FIELD;
        } else if key.is_negative(1) {
            if seen & COSE_X_FIELD != 0 {
                return Err(reader.fault);
            }
            x = reader.fixed_bytes()?;
            seen |= COSE_X_FIELD;
        } else if key.is_negative(2) {
            if seen & COSE_Y_FIELD != 0 {
                return Err(reader.fault);
            }
            y = reader.fixed_bytes()?;
            seen |= COSE_Y_FIELD;
        } else {
            return Err(reader.fault);
        }
    }
    // Exactly five distinct closed labels are accepted above, and the map
    // length is exactly five, so each field was assigned once.
    Ok((CoseEs256PublicKey { x, y }, reader.offset))
}

/// Report `Algorithm` when the first COSE label `3` holds a non-ES256 value.
///
/// An `EdDSA` or RSA key has a different shape, so this scan runs before the
/// closed-shape parse and lets those keys report the algorithm rather than a
/// generic key failure. A scan that cannot reach an integer label `3` defers
/// to the closed-shape parse, which then rejects the key as `CoseKey`.
fn reject_other_cose_algorithm(input: &[u8]) -> Result<(), VerificationReason> {
    match first_cose_algorithm(input) {
        Some(algorithm) if algorithm != COSE_ES256_ALGORITHM => Err(VerificationReason::Algorithm),
        _ => Ok(()),
    }
}

fn first_cose_algorithm(input: &[u8]) -> Option<i64> {
    let mut reader = AuthenticatorCborReader::new(input, VerificationReason::CoseKey);
    let count = reader.map_len().ok()?;
    for _ in 0..count {
        if reader.map_key().ok()?.is_unsigned(3) {
            return reader.signed().ok();
        }
        reader.validate_value(1).ok()?;
    }
    None
}

#[derive(Clone, Copy)]
enum MapKey<'a> {
    Unsigned(u64),
    Negative(u64),
    Text(&'a [u8]),
}

impl MapKey<'_> {
    fn equals_text(self, expected: &[u8]) -> bool {
        matches!(self, Self::Text(text) if text == expected)
    }

    const fn is_unsigned(self, expected: u64) -> bool {
        matches!(self, Self::Unsigned(value) if value == expected)
    }

    const fn is_negative(self, expected_magnitude: u64) -> bool {
        matches!(self, Self::Negative(value) if value == expected_magnitude)
    }

    fn equals(self, other: Self) -> bool {
        match (self, other) {
            (Self::Unsigned(left), Self::Unsigned(right))
            | (Self::Negative(left), Self::Negative(right)) => left == right,
            (Self::Text(left), Self::Text(right)) => left == right,
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
enum MapKeyPolicy {
    Text,
    TextOrInteger,
}

struct AuthenticatorCborReader<'a> {
    input: &'a [u8],
    offset: usize,
    fault: VerificationReason,
}

impl<'a> AuthenticatorCborReader<'a> {
    const fn new(input: &'a [u8], fault: VerificationReason) -> Self {
        Self {
            input,
            offset: 0,
            fault,
        }
    }

    fn map_len(&mut self) -> Result<usize, VerificationReason> {
        let (major, length) = self.head()?;
        if major != 5 {
            return Err(self.fault);
        }
        self.count(length)
    }

    fn map_key(&mut self) -> Result<MapKey<'a>, VerificationReason> {
        let (major, value) = self.head()?;
        match major {
            0 => Ok(MapKey::Unsigned(value)),
            1 => Ok(MapKey::Negative(value)),
            3 => {
                let text = self.take(self.count(value)?)?;
                core::str::from_utf8(text).map_err(|_| self.fault)?;
                Ok(MapKey::Text(text))
            }
            _ => Err(self.fault),
        }
    }

    fn unsigned(&mut self) -> Result<u64, VerificationReason> {
        let (major, value) = self.head()?;
        if major == 0 {
            Ok(value)
        } else {
            Err(self.fault)
        }
    }

    fn signed(&mut self) -> Result<i64, VerificationReason> {
        let (major, value) = self.head()?;
        match major {
            0 => i64::try_from(value).map_err(|_| self.fault),
            1 => i64::try_from(value)
                .map(|magnitude| -1 - magnitude)
                .map_err(|_| self.fault),
            _ => Err(self.fault),
        }
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], VerificationReason> {
        let bytes = self.bytes(N, N)?;
        let mut output = [0; N];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    fn bytes(&mut self, minimum: usize, maximum: usize) -> Result<&'a [u8], VerificationReason> {
        let (major, length) = self.head()?;
        if major != 2 {
            return Err(self.fault);
        }
        let length = self.count(length)?;
        if length < minimum || length > maximum {
            return Err(self.fault);
        }
        self.take(length)
    }

    fn text(&mut self) -> Result<&'a [u8], VerificationReason> {
        let (major, length) = self.head()?;
        if major != 3 {
            return Err(self.fault);
        }
        let text = self.take(self.count(length)?)?;
        core::str::from_utf8(text).map_err(|_| self.fault)?;
        Ok(text)
    }

    fn validate_extension_map(&mut self) -> Result<(), VerificationReason> {
        let count = self.map_len()?;
        if count > MAX_EXTENSION_MAP_ENTRIES {
            return Err(self.fault);
        }
        self.validate_map_entries(count, 1, MapKeyPolicy::Text)
    }

    fn validate_value(&mut self, depth: usize) -> Result<(), VerificationReason> {
        let (major, value) = self.head()?;
        match major {
            0 | 1 => Ok(()),
            2 => {
                self.take(self.count(value)?)?;
                Ok(())
            }
            3 => {
                let text = self.take(self.count(value)?)?;
                core::str::from_utf8(text).map_err(|_| self.fault)?;
                Ok(())
            }
            4 => {
                if depth > MAX_CBOR_NESTING {
                    return Err(self.fault);
                }
                let count = self.count(value)?;
                for _ in 0..count {
                    self.validate_value(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                if depth > MAX_CBOR_NESTING {
                    return Err(self.fault);
                }
                let count = self.count(value)?;
                self.validate_map_entries(count, depth, MapKeyPolicy::TextOrInteger)
            }
            7 if matches!(value, 20..=22) => Ok(()),
            _ => Err(self.fault),
        }
    }

    fn validate_map_entries(
        &mut self,
        count: usize,
        depth: usize,
        policy: MapKeyPolicy,
    ) -> Result<(), VerificationReason> {
        let map_start = self.offset;
        for _ in 0..count {
            let key_start = self.offset;
            let key = self.map_key()?;
            if matches!(policy, MapKeyPolicy::Text) && !matches!(key, MapKey::Text(_)) {
                return Err(self.fault);
            }
            if duplicate_map_key_before(self.input, map_start, key_start, key) {
                return Err(self.fault);
            }
            self.validate_value(depth + 1)?;
        }
        Ok(())
    }

    const fn finish(&self) -> Result<(), VerificationReason> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(self.fault)
        }
    }

    fn head(&mut self) -> Result<(u8, u64), VerificationReason> {
        let first = self.byte()?;
        let major = first >> 5;
        let additional = first & 31;
        let width = match additional {
            0..=23 => return Ok((major, u64::from(additional))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(self.fault),
        };
        let bytes = self.take(width)?;
        let mut value_bytes = [0; 8];
        value_bytes[8 - width..].copy_from_slice(bytes);
        Ok((major, u64::from_be_bytes(value_bytes)))
    }

    fn count(&self, value: u64) -> Result<usize, VerificationReason> {
        usize::try_from(value)
            .ok()
            .filter(|count| *count <= self.input.len())
            .ok_or(self.fault)
    }

    fn byte(&mut self) -> Result<u8, VerificationReason> {
        let byte = *self.input.get(self.offset).ok_or(self.fault)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], VerificationReason> {
        let end = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or(self.fault)?;
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }
}

fn duplicate_map_key_before<'a>(
    input: &'a [u8],
    map_start: usize,
    current_key_start: usize,
    key: MapKey<'a>,
) -> bool {
    let mut reader = AuthenticatorCborReader::new(input, VerificationReason::Malformed);
    reader.offset = map_start;
    loop {
        if reader.offset == current_key_start {
            return false;
        }
        // Every preceding member completed `map_key`, policy validation, and
        // `validate_value` in the outer traversal before this replay begins. The value is
        // skipped at depth 0 only to advance the offset: it was already checked at its real
        // depth, so the depth limit cannot reject it here.
        let prior_key = reader.map_key().unwrap_or(key);
        if prior_key.equals(key) {
            return true;
        }
        reader.validate_value(0).unwrap_or(());
    }
}

const fn require_bounded(
    input: &[u8],
    minimum: usize,
    maximum: usize,
    fault: VerificationReason,
) -> Result<(), VerificationReason> {
    if input.len() < minimum || input.len() > maximum {
        return Err(fault);
    }
    Ok(())
}
