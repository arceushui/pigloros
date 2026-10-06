use crate::OwnerBridgeCodecError;
use p256::ecdsa::VerifyingKey;

const MIN_AUTHENTICATOR_DATA_BYTES: usize = 37;
const MAX_AUTHENTICATOR_DATA_BYTES: usize = 1_024;
const MIN_CREDENTIAL_ID_BYTES: usize = 1;
const MAX_CREDENTIAL_ID_BYTES: usize = 1_024;
const MAX_ATTESTATION_OBJECT_BYTES: usize = 65_536;
const MAX_EXTENSION_MAP_BYTES: usize = 1_024;
const MAX_EXTENSION_MAP_ENTRIES: usize = 16;
const MAX_CBOR_NESTING: usize = 4;

const FLAG_UP: u8 = 1;
const FLAG_RESERVED_ONE: u8 = 1 << 1;
const FLAG_UV: u8 = 1 << 2;
const FLAG_BE: u8 = 1 << 3;
const FLAG_BS: u8 = 1 << 4;
const FLAG_RESERVED_TWO: u8 = 1 << 5;
const FLAG_AT: u8 = 1 << 6;
const FLAG_ED: u8 = 1 << 7;

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
        let (key, consumed) = parse_cose_es256_key(input)?;
        if consumed != input.len() || key.canonical_encoding() != input {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        VerifyingKey::from_sec1_bytes(&key.uncompressed_sec1_bytes())
            .map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
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
/// Returns a closed [`OwnerBridgeCodecError`] for a non-`none` format, a
/// malformed CBOR object, invalid authenticator flags/RP hash, a credential-ID
/// mismatch, or a COSE key outside the ADR-110 ES256 shape.
pub fn parse_none_attestation_object<'a>(
    input: &'a [u8],
    raw_id: &[u8],
) -> Result<CreateAuthenticatorData<'a>, OwnerBridgeCodecError> {
    require_bounded(input, 1, MAX_ATTESTATION_OBJECT_BYTES)?;
    require_bounded(raw_id, MIN_CREDENTIAL_ID_BYTES, MAX_CREDENTIAL_ID_BYTES)?;

    let mut reader = AuthenticatorCborReader::new(input);
    let count = reader.map_len()?;
    if count != 3 {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }

    let mut fmt_seen = false;
    let mut statement_seen = false;
    let mut auth_data_seen = false;
    let mut auth_data = None;
    for _ in 0..count {
        let key = reader.map_key()?;
        if key.equals_text(b"fmt") {
            if fmt_seen || reader.text()? != b"none" {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            fmt_seen = true;
        } else if key.equals_text(b"attStmt") {
            if statement_seen || reader.map_len()? != 0 {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            statement_seen = true;
        } else if key.equals_text(b"authData") {
            if auth_data_seen {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            auth_data =
                Some(reader.bytes(MIN_AUTHENTICATOR_DATA_BYTES, MAX_AUTHENTICATOR_DATA_BYTES)?);
            auth_data_seen = true;
        } else {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
    }
    reader.finish()?;
    let auth_data = auth_data.ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    if !(fmt_seen && statement_seen) {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }

    let parsed = parse_authenticator_data(auth_data, AuthenticatorDataKind::Create, raw_id)?;
    let (Some(credential_id), Some(public_key)) = (parsed.credential_id, parsed.public_key) else {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    };
    Ok(CreateAuthenticatorData {
        credential_id,
        public_key,
        backup_eligible: parsed.backup_eligible,
        backup_state: parsed.backup_state,
        sign_count: parsed.sign_count,
    })
}

/// Parse closed Get authenticator data, including any ignored extension map.
///
/// # Errors
///
/// Returns a closed [`OwnerBridgeCodecError`] for malformed data, a wrong RP
/// hash, missing user presence/verification, invalid backup flags, unexpected
/// attested-credential data, or malformed extensions.
pub fn parse_assertion_authenticator_data(
    input: &[u8],
) -> Result<AssertionAuthenticatorData, OwnerBridgeCodecError> {
    let parsed = parse_authenticator_data(input, AuthenticatorDataKind::Assertion, &[])?;
    Ok(AssertionAuthenticatorData {
        backup_eligible: parsed.backup_eligible,
        backup_state: parsed.backup_state,
        sign_count: parsed.sign_count,
    })
}

#[derive(Clone, Copy)]
enum AuthenticatorDataKind {
    Create,
    Assertion,
}

struct ParsedAuthenticatorData<'a> {
    credential_id: Option<&'a [u8]>,
    public_key: Option<CoseEs256PublicKey>,
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
}

fn parse_authenticator_data<'a>(
    input: &'a [u8],
    kind: AuthenticatorDataKind,
    raw_id: &[u8],
) -> Result<ParsedAuthenticatorData<'a>, OwnerBridgeCodecError> {
    require_bounded(
        input,
        MIN_AUTHENTICATOR_DATA_BYTES,
        MAX_AUTHENTICATOR_DATA_BYTES,
    )?;
    if input[..32] != RP_ID_HASH {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    let flags = input[32];
    if flags & (FLAG_RESERVED_ONE | FLAG_RESERVED_TWO) != 0
        || flags & (FLAG_UP | FLAG_UV) != (FLAG_UP | FLAG_UV)
        || (flags & FLAG_BS != 0 && flags & FLAG_BE == 0)
    {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    let sign_count = u32::from_be_bytes([input[33], input[34], input[35], input[36]]);
    let backup_eligible = flags & FLAG_BE != 0;
    let backup_state = flags & FLAG_BS != 0;
    let attested_data = flags & FLAG_AT != 0;
    let extensions = flags & FLAG_ED != 0;
    let mut offset = MIN_AUTHENTICATOR_DATA_BYTES;
    let mut credential_id = None;
    let mut public_key = None;

    match kind {
        AuthenticatorDataKind::Create => {
            if !attested_data {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            offset = skip_aaguid_and_read_credential(input, offset, raw_id, &mut credential_id)?;
            let (parsed_key, consumed) = parse_cose_es256_key(&input[offset..])?;
            offset = offset
                .checked_add(consumed)
                .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
            public_key = Some(parsed_key);
        }
        AuthenticatorDataKind::Assertion if attested_data => {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        AuthenticatorDataKind::Assertion => {}
    }

    if extensions {
        let extension_bytes = input
            .get(offset..)
            .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
        require_bounded(extension_bytes, 1, MAX_EXTENSION_MAP_BYTES)?;
        let mut extension_reader = AuthenticatorCborReader::new(extension_bytes);
        extension_reader.validate_extension_map()?;
        extension_reader.finish()?;
        offset = input.len();
    }
    if offset != input.len() {
        return Err(OwnerBridgeCodecError::TrailingBytes);
    }

    Ok(ParsedAuthenticatorData {
        credential_id,
        public_key,
        backup_eligible,
        backup_state,
        sign_count,
    })
}

fn skip_aaguid_and_read_credential<'a>(
    input: &'a [u8],
    offset: usize,
    raw_id: &[u8],
    credential_id: &mut Option<&'a [u8]>,
) -> Result<usize, OwnerBridgeCodecError> {
    let length_offset = offset
        .checked_add(16)
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    let length_end = length_offset
        .checked_add(2)
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    let credential_length = input
        .get(length_offset..length_end)
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    let credential_length = usize::from(u16::from_be_bytes([
        credential_length[0],
        credential_length[1],
    ]));
    if !(MIN_CREDENTIAL_ID_BYTES..=MAX_CREDENTIAL_ID_BYTES).contains(&credential_length) {
        return Err(OwnerBridgeCodecError::BoundsExceeded);
    }
    let credential_start = length_end;
    let credential_end = credential_start
        .checked_add(credential_length)
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    let parsed_credential_id = input
        .get(credential_start..credential_end)
        .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    if parsed_credential_id != raw_id {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    *credential_id = Some(parsed_credential_id);
    Ok(credential_end)
}

fn parse_cose_es256_key(
    input: &[u8],
) -> Result<(CoseEs256PublicKey, usize), OwnerBridgeCodecError> {
    let mut reader = AuthenticatorCborReader::new(input);
    if reader.map_len()? != 5 {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }

    let mut kty_seen = false;
    let mut algorithm_seen = false;
    let mut curve_seen = false;
    let mut x = None;
    let mut y = None;
    for _ in 0..5 {
        let key = reader.map_key()?;
        if key.is_unsigned(1) {
            if kty_seen || reader.unsigned()? != 2 {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            kty_seen = true;
        } else if key.is_unsigned(3) {
            if algorithm_seen || reader.signed()? != -7 {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            algorithm_seen = true;
        } else if key.is_negative(0) {
            if curve_seen || reader.unsigned()? != 1 {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            curve_seen = true;
        } else if key.is_negative(1) {
            if x.is_some() {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            x = Some(reader.fixed_bytes()?);
        } else if key.is_negative(2) {
            if y.is_some() {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            y = Some(reader.fixed_bytes()?);
        } else {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
    }
    if !(kty_seen && algorithm_seen && curve_seen) {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    let x = x.ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    let y = y.ok_or(OwnerBridgeCodecError::InvalidPayload)?;
    Ok((CoseEs256PublicKey { x, y }, reader.offset))
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
}

impl<'a> AuthenticatorCborReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn map_len(&mut self) -> Result<usize, OwnerBridgeCodecError> {
        let (major, length) = self.head()?;
        if major != 5 {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        self.count(length)
    }

    fn map_key(&mut self) -> Result<MapKey<'a>, OwnerBridgeCodecError> {
        let (major, value) = self.head()?;
        match major {
            0 => Ok(MapKey::Unsigned(value)),
            1 => Ok(MapKey::Negative(value)),
            3 => {
                let text = self.take(self.count(value)?)?;
                core::str::from_utf8(text).map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
                Ok(MapKey::Text(text))
            }
            _ => Err(OwnerBridgeCodecError::InvalidPayload),
        }
    }

    fn unsigned(&mut self) -> Result<u64, OwnerBridgeCodecError> {
        let (major, value) = self.head()?;
        if major == 0 {
            Ok(value)
        } else {
            Err(OwnerBridgeCodecError::InvalidPayload)
        }
    }

    fn signed(&mut self) -> Result<i64, OwnerBridgeCodecError> {
        let (major, value) = self.head()?;
        match major {
            0 => i64::try_from(value).map_err(|_| OwnerBridgeCodecError::InvalidPayload),
            1 => i64::try_from(value)
                .map(|magnitude| -1 - magnitude)
                .map_err(|_| OwnerBridgeCodecError::InvalidPayload),
            _ => Err(OwnerBridgeCodecError::InvalidPayload),
        }
    }

    fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], OwnerBridgeCodecError> {
        let bytes = self.bytes(N, N)?;
        let mut output = [0; N];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    fn bytes(&mut self, minimum: usize, maximum: usize) -> Result<&'a [u8], OwnerBridgeCodecError> {
        let (major, length) = self.head()?;
        if major != 2 {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        let length = self.count(length)?;
        if length < minimum || length > maximum {
            return Err(OwnerBridgeCodecError::BoundsExceeded);
        }
        self.take(length)
    }

    fn text(&mut self) -> Result<&'a [u8], OwnerBridgeCodecError> {
        let (major, length) = self.head()?;
        if major != 3 {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        let text = self.take(self.count(length)?)?;
        core::str::from_utf8(text).map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
        Ok(text)
    }

    fn validate_extension_map(&mut self) -> Result<(), OwnerBridgeCodecError> {
        let count = self.map_len()?;
        if count > MAX_EXTENSION_MAP_ENTRIES {
            return Err(OwnerBridgeCodecError::BoundsExceeded);
        }
        self.validate_map_entries(count, 1, MapKeyPolicy::Text)
    }

    fn validate_value(&mut self, depth: usize) -> Result<(), OwnerBridgeCodecError> {
        let (major, value) = self.head()?;
        match major {
            0 | 1 => Ok(()),
            2 => {
                self.take(self.count(value)?)?;
                Ok(())
            }
            3 => {
                let text = self.take(self.count(value)?)?;
                core::str::from_utf8(text).map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
                Ok(())
            }
            4 => {
                if depth > MAX_CBOR_NESTING {
                    return Err(OwnerBridgeCodecError::BoundsExceeded);
                }
                let count = self.count(value)?;
                for _ in 0..count {
                    self.validate_value(depth + 1)?;
                }
                Ok(())
            }
            5 => {
                if depth > MAX_CBOR_NESTING {
                    return Err(OwnerBridgeCodecError::BoundsExceeded);
                }
                let count = self.count(value)?;
                self.validate_map_entries(count, depth, MapKeyPolicy::TextOrInteger)
            }
            7 if matches!(value, 20..=22) => Ok(()),
            _ => Err(OwnerBridgeCodecError::InvalidPayload),
        }
    }

    fn validate_map_entries(
        &mut self,
        count: usize,
        depth: usize,
        policy: MapKeyPolicy,
    ) -> Result<(), OwnerBridgeCodecError> {
        let map_start = self.offset;
        for _ in 0..count {
            let key_start = self.offset;
            let key = self.map_key()?;
            if matches!(policy, MapKeyPolicy::Text) && !matches!(key, MapKey::Text(_)) {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            if duplicate_map_key_before(self.input, map_start, key_start, key, depth, policy)? {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            self.validate_value(depth + 1)?;
        }
        Ok(())
    }

    const fn finish(&self) -> Result<(), OwnerBridgeCodecError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(OwnerBridgeCodecError::TrailingBytes)
        }
    }

    fn head(&mut self) -> Result<(u8, u64), OwnerBridgeCodecError> {
        let first = self.byte()?;
        let major = first >> 5;
        let additional = first & 31;
        let width = match additional {
            0..=23 => return Ok((major, u64::from(additional))),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(OwnerBridgeCodecError::InvalidPayload),
        };
        let bytes = self.take(width)?;
        let mut value_bytes = [0; 8];
        value_bytes[8 - width..].copy_from_slice(bytes);
        Ok((major, u64::from_be_bytes(value_bytes)))
    }

    fn count(&self, value: u64) -> Result<usize, OwnerBridgeCodecError> {
        usize::try_from(value)
            .ok()
            .filter(|count| *count <= self.input.len())
            .ok_or(OwnerBridgeCodecError::BoundsExceeded)
    }

    fn byte(&mut self) -> Result<u8, OwnerBridgeCodecError> {
        let byte = *self
            .input
            .get(self.offset)
            .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], OwnerBridgeCodecError> {
        let end = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or(OwnerBridgeCodecError::InvalidPayload)?;
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }
}

fn duplicate_map_key_before(
    input: &[u8],
    map_start: usize,
    current_key_start: usize,
    key: MapKey<'_>,
    depth: usize,
    policy: MapKeyPolicy,
) -> Result<bool, OwnerBridgeCodecError> {
    let mut reader = AuthenticatorCborReader::new(input);
    reader.offset = map_start;
    loop {
        if reader.offset == current_key_start {
            return Ok(false);
        }
        if reader.offset > current_key_start {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        let prior_key = reader.map_key()?;
        if matches!(policy, MapKeyPolicy::Text) && !matches!(prior_key, MapKey::Text(_)) {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        if prior_key.equals(key) {
            return Ok(true);
        }
        reader.validate_value(depth + 1)?;
    }
}

const fn require_bounded(
    input: &[u8],
    minimum: usize,
    maximum: usize,
) -> Result<(), OwnerBridgeCodecError> {
    if input.len() < minimum || input.len() > maximum {
        return Err(OwnerBridgeCodecError::BoundsExceeded);
    }
    Ok(())
}
