use p256::ecdsa::VerifyingKey;

use crate::{
    cbor::{CborReader, CborWriter},
    CoseEs256PublicKey, OwnerBridgeCodecError, TransportCodes,
};

const SUBJECT_CREDENTIAL_BINDING_MAGIC: [u8; 4] = *b"SCB1";
const CLEANUP_RECORD_MAGIC: [u8; 4] = *b"PBCR";
const PROTOCOL_VERSION: u64 = 1;
const SUBJECT_DATA_ENCRYPTION_ROLE: u64 = 0;
const ES256_ALGORITHM_CODE: u64 = 0;
const RP_ID: &str = "localhost";
const OWNER_ORIGIN: &str = "http://localhost:49291";
const MAX_CREDENTIAL_ID_BYTES: usize = 1_024;
const MAX_COSE_KEY_BYTES: usize = 256;
const MAX_TRANSPORTS: usize = 6;

/// Maximum deterministic-CBOR bytes admitted for one durable credential binding.
pub const MAX_SUBJECT_CREDENTIAL_BINDING_BYTES: usize = 4_096;

/// Maximum deterministic-CBOR bytes admitted for one owner-bridge cleanup record.
pub const MAX_CLEANUP_RECORD_BYTES: usize = 4_096;

/// Named candidate fields for one durable credential binding.
///
/// This input deliberately carries no validity claim. Pass it to
/// [`SubjectCredentialBindingV1::new`] to enforce the closed ADR-097 schema
/// before any binding reaches durable storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectCredentialBindingInputV1<'a> {
    /// Durable identifier of the owner account.
    pub owner_id: &'a str,
    /// Exact subject identifier whose epoch owns the credential.
    pub subject_id: [u8; 16],
    /// Durable subject-key epoch.
    pub epoch: u64,
    /// Sole credential identifier bound to this epoch.
    pub credential_id: &'a [u8],
    /// Exact owner user handle.
    pub user_handle: [u8; 32],
    /// Candidate closed ES256 credential public key.
    pub public_key: CoseEs256PublicKey,
    /// Credential backup-eligibility flag.
    pub backup_eligible: bool,
    /// Credential backup-state flag.
    pub backup_state: bool,
    /// Last verified authenticator signature counter.
    pub sign_count: u32,
    /// Non-authoritative ordered transport hints.
    pub transports: TransportCodes,
}

/// One exact ADR-097 durable credential binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectCredentialBindingV1<'a> {
    owner_id: &'a str,
    subject_id: [u8; 16],
    epoch: u64,
    credential_id: &'a [u8],
    user_handle: [u8; 32],
    public_key: CoseEs256PublicKey,
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
    transports: TransportCodes,
}

impl<'a> SubjectCredentialBindingV1<'a> {
    /// Construct a binding only from already validated credential material.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::BoundsExceeded`] when one borrowed
    /// field exceeds the durable-record limit, and
    /// [`OwnerBridgeCodecError::InvalidPayload`] for an invalid P-256 point or
    /// impossible backup-flag combination.
    pub fn new(input: SubjectCredentialBindingInputV1<'a>) -> Result<Self, OwnerBridgeCodecError> {
        let SubjectCredentialBindingInputV1 {
            owner_id,
            subject_id,
            epoch,
            credential_id,
            user_handle,
            public_key,
            backup_eligible,
            backup_state,
            sign_count,
            transports,
        } = input;
        require_bounded(owner_id.as_bytes(), 0, MAX_SUBJECT_CREDENTIAL_BINDING_BYTES)?;
        require_bounded(credential_id, 1, MAX_CREDENTIAL_ID_BYTES)?;
        if backup_state && !backup_eligible {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        VerifyingKey::from_sec1_bytes(&public_key.uncompressed_sec1_bytes())
            .map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
        Ok(Self {
            owner_id,
            subject_id,
            epoch,
            credential_id,
            user_handle,
            public_key,
            backup_eligible,
            backup_state,
            sign_count,
            transports,
        })
    }

    /// Return the durable owner identifier.
    #[must_use]
    pub const fn owner_id(self) -> &'a str {
        self.owner_id
    }

    /// Return the exact subject identifier.
    #[must_use]
    pub const fn subject_id(self) -> [u8; 16] {
        self.subject_id
    }

    /// Return the durable subject-key epoch.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    /// Return the sole credential identifier bound to this epoch.
    #[must_use]
    pub const fn credential_id(self) -> &'a [u8] {
        self.credential_id
    }

    /// Return the exact owner user handle.
    #[must_use]
    pub const fn user_handle(self) -> [u8; 32] {
        self.user_handle
    }

    /// Return the validated ES256 credential public key.
    #[must_use]
    pub const fn public_key(self) -> CoseEs256PublicKey {
        self.public_key
    }

    /// Return the immutable credential backup-eligibility flag.
    #[must_use]
    pub const fn backup_eligible(self) -> bool {
        self.backup_eligible
    }

    /// Return the current verified credential backup-state flag.
    #[must_use]
    pub const fn backup_state(self) -> bool {
        self.backup_state
    }

    /// Return the current verified assertion signature counter.
    #[must_use]
    pub const fn sign_count(self) -> u32 {
        self.sign_count
    }

    /// Return the non-authoritative credential transport hints.
    #[must_use]
    pub const fn transports(self) -> TransportCodes {
        self.transports
    }
}

/// One durable record used to complete bridge cleanup after a process restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupRecordV1<'a> {
    ceremony_id: [u8; 16],
    folder_name: &'a str,
    browser_pid: u32,
    creation_filetime: u64,
    image_path_sha256: [u8; 32],
}

impl<'a> CleanupRecordV1<'a> {
    /// Construct the non-secret process identity retained for cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::BoundsExceeded`] when `folder_name`
    /// exceeds the fixed cleanup-record limit.
    pub fn new(
        ceremony_id: [u8; 16],
        folder_name: &'a str,
        browser_pid: u32,
        creation_filetime: u64,
        image_path_sha256: [u8; 32],
    ) -> Result<Self, OwnerBridgeCodecError> {
        require_bounded(folder_name.as_bytes(), 0, MAX_CLEANUP_RECORD_BYTES)?;
        Ok(Self {
            ceremony_id,
            folder_name,
            browser_pid,
            creation_filetime,
            image_path_sha256,
        })
    }

    /// Return the ceremony identifier associated with this process.
    #[must_use]
    pub const fn ceremony_id(self) -> [u8; 16] {
        self.ceremony_id
    }

    /// Return the isolated browser-data folder name.
    #[must_use]
    pub const fn folder_name(self) -> &'a str {
        self.folder_name
    }

    /// Return the browser process identifier.
    #[must_use]
    pub const fn browser_pid(self) -> u32 {
        self.browser_pid
    }

    /// Return the browser process creation `FILETIME`.
    #[must_use]
    pub const fn creation_filetime(self) -> u64 {
        self.creation_filetime
    }

    /// Return the expected SHA-256 of the browser image path.
    #[must_use]
    pub const fn image_path_sha256(self) -> [u8; 32] {
        self.image_path_sha256
    }
}

/// Encode one exact deterministic-CBOR durable credential binding.
///
/// # Errors
///
/// Returns [`OwnerBridgeCodecError::BufferTooSmall`] when `output` cannot
/// contain the record and [`OwnerBridgeCodecError::BoundsExceeded`] when its
/// complete encoding would exceed 4,096 bytes.
pub fn encode_subject_credential_binding(
    binding: &SubjectCredentialBindingV1<'_>,
    output: &mut [u8],
) -> Result<usize, OwnerBridgeCodecError> {
    let mut writer = CborWriter::new(output);
    writer.array(16)?;
    writer.bytes(&SUBJECT_CREDENTIAL_BINDING_MAGIC)?;
    writer.unsigned(PROTOCOL_VERSION)?;
    writer.text(binding.owner_id)?;
    writer.bytes(&binding.subject_id)?;
    writer.unsigned(SUBJECT_DATA_ENCRYPTION_ROLE)?;
    writer.unsigned(binding.epoch)?;
    writer.text(RP_ID)?;
    writer.text(OWNER_ORIGIN)?;
    writer.bytes(binding.credential_id)?;
    writer.bytes(&binding.user_handle)?;
    writer.bytes(&binding.public_key.canonical_encoding())?;
    writer.unsigned(ES256_ALGORITHM_CODE)?;
    writer.boolean(binding.backup_eligible)?;
    writer.boolean(binding.backup_state)?;
    writer.unsigned(u64::from(binding.sign_count))?;
    write_transports(&mut writer, binding.transports)?;
    let length = writer.finish();
    require_length(length, MAX_SUBJECT_CREDENTIAL_BINDING_BYTES)?;
    Ok(length)
}

/// Decode one exact deterministic-CBOR durable credential binding.
///
/// # Errors
///
/// Returns a closed [`OwnerBridgeCodecError`] for a wrong schema, unsupported
/// role or algorithm, malformed credential key, noncanonical encoding, or
/// trailing bytes.
pub fn decode_subject_credential_binding(
    input: &[u8],
) -> Result<SubjectCredentialBindingV1<'_>, OwnerBridgeCodecError> {
    require_length(input.len(), MAX_SUBJECT_CREDENTIAL_BINDING_BYTES)?;
    let mut reader = CborReader::new(input);
    reader.fixed_array(16)?;
    expect_magic(&mut reader, SUBJECT_CREDENTIAL_BINDING_MAGIC)?;
    expect_version(&mut reader)?;
    let owner_id = reader.text(0, MAX_SUBJECT_CREDENTIAL_BINDING_BYTES)?;
    let subject_id = reader.fixed_bytes()?;
    if reader.unsigned()? != SUBJECT_DATA_ENCRYPTION_ROLE {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    let epoch = reader.unsigned()?;
    reader.exact_text(RP_ID)?;
    reader.exact_text(OWNER_ORIGIN)?;
    let credential_id = reader.bytes(1, MAX_CREDENTIAL_ID_BYTES)?;
    let user_handle = reader.fixed_bytes()?;
    let cose_bytes = reader.bytes(1, MAX_COSE_KEY_BYTES)?;
    let public_key = CoseEs256PublicKey::from_canonical_encoding(cose_bytes)?;
    if reader.unsigned()? != ES256_ALGORITHM_CODE {
        return Err(OwnerBridgeCodecError::InvalidPayload);
    }
    let backup_eligible = reader.boolean()?;
    let backup_state = reader.boolean()?;
    let sign_count =
        u32::try_from(reader.unsigned()?).map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
    let transports = read_transports(&mut reader)?;
    reader.finish()?;
    SubjectCredentialBindingV1::new(SubjectCredentialBindingInputV1 {
        owner_id,
        subject_id,
        epoch,
        credential_id,
        user_handle,
        public_key,
        backup_eligible,
        backup_state,
        sign_count,
        transports,
    })
}

/// Encode one exact deterministic-CBOR owner-bridge cleanup record.
///
/// # Errors
///
/// Returns [`OwnerBridgeCodecError::BufferTooSmall`] when `output` cannot
/// contain the record and [`OwnerBridgeCodecError::BoundsExceeded`] when its
/// complete encoding would exceed 4,096 bytes.
pub fn encode_cleanup_record(
    record: &CleanupRecordV1<'_>,
    output: &mut [u8],
) -> Result<usize, OwnerBridgeCodecError> {
    let mut writer = CborWriter::new(output);
    writer.array(7)?;
    writer.bytes(&CLEANUP_RECORD_MAGIC)?;
    writer.unsigned(PROTOCOL_VERSION)?;
    writer.bytes(&record.ceremony_id)?;
    writer.text(record.folder_name)?;
    writer.unsigned(u64::from(record.browser_pid))?;
    writer.unsigned(record.creation_filetime)?;
    writer.bytes(&record.image_path_sha256)?;
    let length = writer.finish();
    require_length(length, MAX_CLEANUP_RECORD_BYTES)?;
    Ok(length)
}

/// Decode one exact deterministic-CBOR owner-bridge cleanup record.
///
/// # Errors
///
/// Returns a closed [`OwnerBridgeCodecError`] for a wrong schema,
/// noncanonical encoding, or trailing bytes.
pub fn decode_cleanup_record(input: &[u8]) -> Result<CleanupRecordV1<'_>, OwnerBridgeCodecError> {
    require_length(input.len(), MAX_CLEANUP_RECORD_BYTES)?;
    let mut reader = CborReader::new(input);
    reader.fixed_array(7)?;
    expect_magic(&mut reader, CLEANUP_RECORD_MAGIC)?;
    expect_version(&mut reader)?;
    let ceremony_id = reader.fixed_bytes()?;
    let folder_name = reader.text(0, MAX_CLEANUP_RECORD_BYTES)?;
    let browser_pid =
        u32::try_from(reader.unsigned()?).map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
    let creation_filetime = reader.unsigned()?;
    let image_path_sha256 = reader.fixed_bytes()?;
    reader.finish()?;
    CleanupRecordV1::new(
        ceremony_id,
        folder_name,
        browser_pid,
        creation_filetime,
        image_path_sha256,
    )
}

fn expect_magic(
    reader: &mut CborReader<'_>,
    expected: [u8; 4],
) -> Result<(), OwnerBridgeCodecError> {
    if reader.fixed_bytes()? == expected {
        Ok(())
    } else {
        Err(OwnerBridgeCodecError::InvalidPayload)
    }
}

fn expect_version(reader: &mut CborReader<'_>) -> Result<(), OwnerBridgeCodecError> {
    if reader.unsigned()? == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(OwnerBridgeCodecError::InvalidPayload)
    }
}

fn read_transports(reader: &mut CborReader<'_>) -> Result<TransportCodes, OwnerBridgeCodecError> {
    let count = reader.array(MAX_TRANSPORTS)?;
    let mut codes = [0; MAX_TRANSPORTS];
    for code in codes.iter_mut().take(count) {
        *code =
            u8::try_from(reader.unsigned()?).map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
    }
    TransportCodes::new(&codes[..count])
}

fn write_transports(
    writer: &mut CborWriter<'_>,
    transports: TransportCodes,
) -> Result<(), OwnerBridgeCodecError> {
    writer.array(
        u64::try_from(transports.as_slice().len())
            .map_err(|_| OwnerBridgeCodecError::BoundsExceeded)?,
    )?;
    for &code in transports.as_slice() {
        writer.unsigned(u64::from(code))?;
    }
    Ok(())
}

const fn require_length(length: usize, maximum: usize) -> Result<(), OwnerBridgeCodecError> {
    if length > maximum {
        return Err(OwnerBridgeCodecError::BoundsExceeded);
    }
    Ok(())
}

const fn require_bounded(
    value: &[u8],
    minimum: usize,
    maximum: usize,
) -> Result<(), OwnerBridgeCodecError> {
    if value.len() < minimum || value.len() > maximum {
        return Err(OwnerBridgeCodecError::BoundsExceeded);
    }
    Ok(())
}
