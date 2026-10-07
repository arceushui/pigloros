use crate::{
    cbor::{
        expect_magic, expect_version, read_transports, require_bounded, write_transports,
        CborReader, CborWriter, PROTOCOL_VERSION,
    },
    CeremonyId, OwnerBridgeCodecError, OwnerUserHandle, PrfInput, PrfResult, TransportCodes,
    VerificationReason, WebAuthnChallenge,
};

const CREATE_OPTIONS_MAGIC: [u8; 4] = *b"WCR1";
const GET_OPTIONS_MAGIC: [u8; 4] = *b"WGR1";
const ATTESTATION_REPLY_MAGIC: [u8; 4] = *b"WAR1";
const ASSERTION_REPLY_MAGIC: [u8; 4] = *b"WAS1";
const RP_ID: &str = "localhost";
const RP_NAME: &str = "PiglorOS";
const CREATE_TYPE: i64 = -7;
const CREATE_TYPE_MAGNITUDE: u64 = 6;
const REQUIRED_CODE: u64 = 0;
const MAX_CREDENTIAL_ID_BYTES: usize = 1_024;
const MAX_CLIENT_DATA_BYTES: usize = 4_096;
const MAX_ATTESTATION_OBJECT_BYTES: usize = 65_536;
const MAX_AUTHENTICATOR_DATA_BYTES: usize = 1_024;
const MIN_AUTHENTICATOR_DATA_BYTES: usize = 37;
const MAX_SIGNATURE_BYTES: usize = 80;
const MIN_SIGNATURE_BYTES: usize = 8;
const PRF_ABSENT: OwnerBridgeCodecError =
    OwnerBridgeCodecError::Verification(VerificationReason::PrfAbsent);

/// Host-supplied Create options encoded into a request buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateOptionsV1 {
    ceremony_id: CeremonyId,
    challenge: WebAuthnChallenge,
    user_handle: OwnerUserHandle,
    prf_input: PrfInput,
}

impl CreateOptionsV1 {
    /// Construct closed Create options from their fixed-width host secrets.
    #[must_use]
    pub const fn new(
        ceremony_id: CeremonyId,
        challenge: WebAuthnChallenge,
        user_handle: OwnerUserHandle,
        prf_input: PrfInput,
    ) -> Self {
        Self {
            ceremony_id,
            challenge,
            user_handle,
            prf_input,
        }
    }

    /// Return the exact ceremony identifier.
    #[must_use]
    pub const fn ceremony_id(self) -> CeremonyId {
        self.ceremony_id
    }

    /// Return the exact `WebAuthn` challenge.
    #[must_use]
    pub const fn challenge(self) -> WebAuthnChallenge {
        self.challenge
    }

    /// Return the exact owner user handle.
    #[must_use]
    pub const fn user_handle(self) -> OwnerUserHandle {
        self.user_handle
    }

    /// Return the exact PRF input.
    #[must_use]
    pub const fn prf_input(self) -> PrfInput {
        self.prf_input
    }
}

/// Host-supplied Get options encoded into a request buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetOptionsV1<'a> {
    ceremony_id: CeremonyId,
    challenge: WebAuthnChallenge,
    credential_id: &'a [u8],
    prf_input: PrfInput,
}

impl<'a> GetOptionsV1<'a> {
    /// Construct closed Get options for one exact allowed credential.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::BoundsExceeded`] when `credential_id`
    /// is outside the required 1–1024-byte range.
    pub fn new(
        ceremony_id: CeremonyId,
        challenge: WebAuthnChallenge,
        credential_id: &'a [u8],
        prf_input: PrfInput,
    ) -> Result<Self, OwnerBridgeCodecError> {
        require_bounded(credential_id, 1, MAX_CREDENTIAL_ID_BYTES)?;
        Ok(Self {
            ceremony_id,
            challenge,
            credential_id,
            prf_input,
        })
    }

    /// Return the exact ceremony identifier.
    #[must_use]
    pub const fn ceremony_id(self) -> CeremonyId {
        self.ceremony_id
    }

    /// Return the exact `WebAuthn` challenge.
    #[must_use]
    pub const fn challenge(self) -> WebAuthnChallenge {
        self.challenge
    }

    /// Return the one allowed credential identifier.
    #[must_use]
    pub const fn credential_id(self) -> &'a [u8] {
        self.credential_id
    }

    /// Return the exact PRF input.
    #[must_use]
    pub const fn prf_input(self) -> PrfInput {
        self.prf_input
    }
}

/// Page-supplied Create result before `WebAuthn` verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestationReplyV1<'a> {
    ceremony_id: CeremonyId,
    raw_id: &'a [u8],
    client_data_json: &'a [u8],
    attestation_object: &'a [u8],
    transports: TransportCodes,
    prf_enabled: bool,
    prf_first: Option<PrfResult>,
}

impl<'a> AttestationReplyV1<'a> {
    /// Construct a closed Create result for deterministic transport tests.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::BoundsExceeded`] when any binary field
    /// exceeds the ADR-097 bounds.
    pub fn new(
        ceremony_id: CeremonyId,
        raw_id: &'a [u8],
        client_data_json: &'a [u8],
        attestation_object: &'a [u8],
        transports: TransportCodes,
        prf_enabled: bool,
        prf_first: Option<PrfResult>,
    ) -> Result<Self, OwnerBridgeCodecError> {
        require_bounded(raw_id, 1, MAX_CREDENTIAL_ID_BYTES)?;
        require_bounded(client_data_json, 1, MAX_CLIENT_DATA_BYTES)?;
        require_bounded(attestation_object, 1, MAX_ATTESTATION_OBJECT_BYTES)?;
        Ok(Self {
            ceremony_id,
            raw_id,
            client_data_json,
            attestation_object,
            transports,
            prf_enabled,
            prf_first,
        })
    }

    /// Return the exact ceremony identifier.
    #[must_use]
    pub const fn ceremony_id(self) -> CeremonyId {
        self.ceremony_id
    }

    /// Return the `WebAuthn` raw credential identifier.
    #[must_use]
    pub const fn raw_id(self) -> &'a [u8] {
        self.raw_id
    }

    /// Return the raw, strict-UTF-8 `clientDataJSON` bytes.
    #[must_use]
    pub const fn client_data_json(self) -> &'a [u8] {
        self.client_data_json
    }

    /// Return the raw authenticator attestation object.
    #[must_use]
    pub const fn attestation_object(self) -> &'a [u8] {
        self.attestation_object
    }

    /// Return the bounded transport-code hints.
    #[must_use]
    pub const fn transports(self) -> TransportCodes {
        self.transports
    }

    /// Return whether the page reports PRF support for the new credential.
    #[must_use]
    pub const fn prf_enabled(self) -> bool {
        self.prf_enabled
    }

    /// Return the optional page-supplied Create PRF value.
    #[must_use]
    pub const fn prf_first(self) -> Option<PrfResult> {
        self.prf_first
    }
}

/// Page-supplied Get result before `WebAuthn` verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssertionReplyV1<'a> {
    ceremony_id: CeremonyId,
    raw_id: &'a [u8],
    client_data_json: &'a [u8],
    authenticator_data: &'a [u8],
    signature: &'a [u8],
    user_handle: Option<OwnerUserHandle>,
    prf_first: PrfResult,
}

impl<'a> AssertionReplyV1<'a> {
    /// Construct a closed Get result for deterministic transport tests.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::BoundsExceeded`] when any binary field
    /// exceeds the ADR-097 bounds.
    pub fn new(
        ceremony_id: CeremonyId,
        raw_id: &'a [u8],
        client_data_json: &'a [u8],
        authenticator_data: &'a [u8],
        signature: &'a [u8],
        user_handle: Option<OwnerUserHandle>,
        prf_first: PrfResult,
    ) -> Result<Self, OwnerBridgeCodecError> {
        require_bounded(raw_id, 1, MAX_CREDENTIAL_ID_BYTES)?;
        require_bounded(client_data_json, 1, MAX_CLIENT_DATA_BYTES)?;
        require_bounded(
            authenticator_data,
            MIN_AUTHENTICATOR_DATA_BYTES,
            MAX_AUTHENTICATOR_DATA_BYTES,
        )?;
        require_bounded(signature, MIN_SIGNATURE_BYTES, MAX_SIGNATURE_BYTES)?;
        Ok(Self {
            ceremony_id,
            raw_id,
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
            prf_first,
        })
    }

    /// Return the exact ceremony identifier.
    #[must_use]
    pub const fn ceremony_id(self) -> CeremonyId {
        self.ceremony_id
    }

    /// Return the `WebAuthn` raw credential identifier.
    #[must_use]
    pub const fn raw_id(self) -> &'a [u8] {
        self.raw_id
    }

    /// Return the raw, strict-UTF-8 `clientDataJSON` bytes.
    #[must_use]
    pub const fn client_data_json(self) -> &'a [u8] {
        self.client_data_json
    }

    /// Return the signed authenticator-data bytes.
    #[must_use]
    pub const fn authenticator_data(self) -> &'a [u8] {
        self.authenticator_data
    }

    /// Return the strict-DER signature bytes.
    #[must_use]
    pub const fn signature(self) -> &'a [u8] {
        self.signature
    }

    /// Return the optional exact 32-byte user handle.
    #[must_use]
    pub const fn user_handle(self) -> Option<OwnerUserHandle> {
        self.user_handle
    }

    /// Return the required exact 32-byte Get PRF value.
    #[must_use]
    pub const fn prf_first(self) -> PrfResult {
        self.prf_first
    }
}

/// Encode exact deterministic-CBOR Create options into a caller-owned buffer.
///
/// # Errors
///
/// Returns [`OwnerBridgeCodecError::BufferTooSmall`] when `output` cannot
/// contain the complete 148-byte V1 encoding.
pub fn encode_create_options(
    options: &CreateOptionsV1,
    output: &mut [u8],
) -> Result<usize, OwnerBridgeCodecError> {
    let mut writer = CborWriter::new(output);
    writer.array(11);
    writer.bytes(&CREATE_OPTIONS_MAGIC);
    writer.unsigned(PROTOCOL_VERSION);
    writer.bytes(options.ceremony_id.as_bytes());
    writer.bytes(options.challenge.as_bytes());
    writer.bytes(options.user_handle.as_bytes());
    writer.text(RP_ID);
    writer.text(RP_NAME);
    writer.negative(CREATE_TYPE_MAGNITUDE);
    writer.unsigned(REQUIRED_CODE);
    writer.unsigned(REQUIRED_CODE);
    writer.bytes(options.prf_input.as_bytes());
    writer.finish()
}

/// Decode exact deterministic-CBOR Create options from a request payload.
///
/// # Errors
///
/// Returns a closed [`OwnerBridgeCodecError`] for a wrong schema, noncanonical
/// encoding, or trailing byte.
pub fn decode_create_options(input: &[u8]) -> Result<CreateOptionsV1, OwnerBridgeCodecError> {
    let mut reader = CborReader::new(input);
    reader.fixed_array(11)?;
    expect_magic(&mut reader, CREATE_OPTIONS_MAGIC)?;
    expect_version(&mut reader)?;
    let ceremony_id = CeremonyId::from_bytes(reader.fixed_bytes()?);
    let challenge = WebAuthnChallenge::from_bytes(reader.fixed_bytes()?);
    let user_handle = OwnerUserHandle::from_bytes(reader.fixed_bytes()?);
    reader.exact_text(RP_ID)?;
    reader.exact_text(RP_NAME)?;
    if reader.signed()? != CREATE_TYPE
        || reader.unsigned()? != REQUIRED_CODE
        || reader.unsigned()? != REQUIRED_CODE
    {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    let prf_input = PrfInput::from_bytes(reader.fixed_bytes()?);
    reader.finish()?;
    Ok(CreateOptionsV1::new(
        ceremony_id,
        challenge,
        user_handle,
        prf_input,
    ))
}

/// Encode exact deterministic-CBOR Get options into a caller-owned buffer.
///
/// # Errors
///
/// Returns [`OwnerBridgeCodecError::BufferTooSmall`] when `output` cannot
/// contain the complete bounded V1 encoding.
pub fn encode_get_options(
    options: &GetOptionsV1<'_>,
    output: &mut [u8],
) -> Result<usize, OwnerBridgeCodecError> {
    let mut writer = CborWriter::new(output);
    writer.array(8);
    writer.bytes(&GET_OPTIONS_MAGIC);
    writer.unsigned(PROTOCOL_VERSION);
    writer.bytes(options.ceremony_id.as_bytes());
    writer.bytes(options.challenge.as_bytes());
    writer.text(RP_ID);
    writer.bytes(options.credential_id);
    writer.unsigned(REQUIRED_CODE);
    writer.bytes(options.prf_input.as_bytes());
    writer.finish()
}

/// Decode exact deterministic-CBOR Get options from a request payload.
///
/// # Errors
///
/// Returns a closed [`OwnerBridgeCodecError`] for a wrong schema, noncanonical
/// encoding, or trailing byte.
pub fn decode_get_options(input: &[u8]) -> Result<GetOptionsV1<'_>, OwnerBridgeCodecError> {
    let mut reader = CborReader::new(input);
    reader.fixed_array(8)?;
    expect_magic(&mut reader, GET_OPTIONS_MAGIC)?;
    expect_version(&mut reader)?;
    let ceremony_id = CeremonyId::from_bytes(reader.fixed_bytes()?);
    let challenge = WebAuthnChallenge::from_bytes(reader.fixed_bytes()?);
    reader.exact_text(RP_ID)?;
    let credential_id = reader.bytes(1, MAX_CREDENTIAL_ID_BYTES)?;
    if reader.unsigned()? != REQUIRED_CODE {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    let prf_input = PrfInput::from_bytes(reader.fixed_bytes()?);
    reader.finish()?;
    GetOptionsV1::new(ceremony_id, challenge, credential_id, prf_input)
}

/// Encode exact deterministic-CBOR Attestation reply bytes into a caller-owned buffer.
///
/// # Errors
///
/// Returns [`OwnerBridgeCodecError::BufferTooSmall`] when `output` cannot
/// contain the complete bounded V1 encoding.
pub fn encode_attestation_reply(
    reply: &AttestationReplyV1<'_>,
    output: &mut [u8],
) -> Result<usize, OwnerBridgeCodecError> {
    let mut writer = CborWriter::new(output);
    writer.array(10);
    writer.bytes(&ATTESTATION_REPLY_MAGIC);
    writer.unsigned(PROTOCOL_VERSION);
    writer.bytes(reply.ceremony_id.as_bytes());
    writer.bytes(reply.raw_id);
    writer.bytes(reply.client_data_json);
    writer.bytes(reply.attestation_object);
    write_transports(&mut writer, reply.transports);
    writer.boolean(reply.prf_enabled);
    write_optional_fixed(
        &mut writer,
        reply.prf_first.as_ref().map(PrfResult::as_bytes),
    );
    writer.null();
    writer.finish()
}

/// Decode exact deterministic-CBOR Attestation reply bytes from a page payload.
///
/// # Errors
///
/// Returns a closed [`OwnerBridgeCodecError`] for a wrong schema, noncanonical
/// encoding, or trailing byte.
pub fn decode_attestation_reply(
    input: &[u8],
) -> Result<AttestationReplyV1<'_>, OwnerBridgeCodecError> {
    let mut reader = CborReader::new(input);
    reader.fixed_array(10)?;
    expect_magic(&mut reader, ATTESTATION_REPLY_MAGIC)?;
    expect_version(&mut reader)?;
    let ceremony_id = CeremonyId::from_bytes(reader.fixed_bytes()?);
    let raw_id = reader.bytes(1, MAX_CREDENTIAL_ID_BYTES)?;
    let client_data_json = reader.bytes(1, MAX_CLIENT_DATA_BYTES)?;
    let attestation_object = reader.bytes(1, MAX_ATTESTATION_OBJECT_BYTES)?;
    let transports = read_transports(&mut reader)?;
    let prf_enabled = reader.boolean()?;
    let prf_first = reader
        .optional_fixed_bytes::<32>()
        .map_err(prf_fault)?
        .map(PrfResult::from_bytes);
    reader.null().map_err(prf_fault)?;
    reader.finish()?;
    AttestationReplyV1::new(
        ceremony_id,
        raw_id,
        client_data_json,
        attestation_object,
        transports,
        prf_enabled,
        prf_first,
    )
}

/// Encode exact deterministic-CBOR Assertion reply bytes into a caller-owned buffer.
///
/// # Errors
///
/// Returns [`OwnerBridgeCodecError::BufferTooSmall`] when `output` cannot
/// contain the complete bounded V1 encoding.
pub fn encode_assertion_reply(
    reply: &AssertionReplyV1<'_>,
    output: &mut [u8],
) -> Result<usize, OwnerBridgeCodecError> {
    let mut writer = CborWriter::new(output);
    writer.array(10);
    writer.bytes(&ASSERTION_REPLY_MAGIC);
    writer.unsigned(PROTOCOL_VERSION);
    writer.bytes(reply.ceremony_id.as_bytes());
    writer.bytes(reply.raw_id);
    writer.bytes(reply.client_data_json);
    writer.bytes(reply.authenticator_data);
    writer.bytes(reply.signature);
    write_optional_fixed(
        &mut writer,
        reply.user_handle.as_ref().map(OwnerUserHandle::as_bytes),
    );
    writer.bytes(reply.prf_first.as_bytes());
    writer.null();
    writer.finish()
}

/// Decode exact deterministic-CBOR Assertion reply bytes from a page payload.
///
/// # Errors
///
/// Returns a closed [`OwnerBridgeCodecError`] for a wrong schema, noncanonical
/// encoding, or trailing byte.
pub fn decode_assertion_reply(input: &[u8]) -> Result<AssertionReplyV1<'_>, OwnerBridgeCodecError> {
    let mut reader = CborReader::new(input);
    reader.fixed_array(10)?;
    expect_magic(&mut reader, ASSERTION_REPLY_MAGIC)?;
    expect_version(&mut reader)?;
    let ceremony_id = CeremonyId::from_bytes(reader.fixed_bytes()?);
    let raw_id = reader.bytes(1, MAX_CREDENTIAL_ID_BYTES)?;
    let client_data_json = reader.bytes(1, MAX_CLIENT_DATA_BYTES)?;
    let authenticator_data =
        reader.bytes(MIN_AUTHENTICATOR_DATA_BYTES, MAX_AUTHENTICATOR_DATA_BYTES)?;
    let signature = reader.bytes(MIN_SIGNATURE_BYTES, MAX_SIGNATURE_BYTES)?;
    let user_handle = read_user_handle(&mut reader)?;
    let prf_first = read_required_prf(&mut reader)?;
    reader.finish()?;
    AssertionReplyV1::new(
        ceremony_id,
        raw_id,
        client_data_json,
        authenticator_data,
        signature,
        user_handle,
        prf_first,
    )
}

/// Name the verification reason for a reply field of the wrong shape.
///
/// A wrong type, wrong length, or truncated field becomes `reason`. Every
/// other failure, such as a non-shortest encoding, keeps its own error.
const fn field_fault(
    error: OwnerBridgeCodecError,
    reason: VerificationReason,
) -> OwnerBridgeCodecError {
    match error {
        OwnerBridgeCodecError::InvalidCbor => OwnerBridgeCodecError::Verification(reason),
        other => other,
    }
}

fn read_user_handle(
    reader: &mut CborReader<'_>,
) -> Result<Option<OwnerUserHandle>, OwnerBridgeCodecError> {
    let handle = reader
        .optional_fixed_bytes::<32>()
        .map_err(user_handle_fault)?;
    Ok(handle.map(OwnerUserHandle::from_bytes))
}

/// Read the required Get PRF result and the reserved `second` field.
fn read_required_prf(reader: &mut CborReader<'_>) -> Result<PrfResult, OwnerBridgeCodecError> {
    let first = reader.optional_fixed_bytes::<32>().map_err(prf_fault)?;
    reader.null().map_err(prf_fault)?;
    first.map(PrfResult::from_bytes).ok_or(PRF_ABSENT)
}

const fn prf_fault(error: OwnerBridgeCodecError) -> OwnerBridgeCodecError {
    field_fault(error, VerificationReason::PrfMalformed)
}

const fn user_handle_fault(error: OwnerBridgeCodecError) -> OwnerBridgeCodecError {
    field_fault(error, VerificationReason::UserHandleMismatch)
}

fn write_optional_fixed<const N: usize>(writer: &mut CborWriter<'_>, value: Option<&[u8; N]>) {
    match value {
        Some(value) => writer.bytes(value),
        None => writer.null(),
    }
}
