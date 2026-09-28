//! TEP1 plaintext snapshots and TRX1 HPKE recipient envelopes.
//!
//! This module is deliberately a codec boundary.  It neither authorizes an
//! export nor imports a decrypted candidate into an `EventStore`.

use ciborium::Value;
use hpke::{
    aead::ChaCha20Poly1305,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    setup_receiver, setup_sender_with_rng, Deserializable, OpModeR, OpModeS, Serializable,
};
use pos_core::{
    CanonicalBytes, CorrelationId, EntityId, Event, EventId, Hash, KeyIdentityV1, KeyRoleV1, Kind,
    RecipientKeyDescriptorV1, SchemaVersion, Seq, Signature, Timeline, TimelineExport, TimelineId,
    TimelineMeta, TimelineMode, WallTime,
};
use rand::CryptoRng;
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

const TEP_MAGIC: &[u8; 4] = b"TEP1";
const TRX_MAGIC: &[u8; 4] = b"TRX1";
const VERSION: u64 = 1;
const KEM_ID: u64 = 0x0020;
const KDF_ID: u64 = 0x0001;
const AEAD_ID: u64 = 0x0003;
const CHUNK_BYTES: usize = 65_536;
const TAG_BYTES: usize = 16;
const MAX_PAYLOAD_BYTES: usize = 1 << 30;
const MAX_EVENTS: usize = 1_000_000;
const MAX_EVENT_PAYLOAD_BYTES: usize = 16 << 20;
const MAX_EVENT_TYPE_BYTES: usize = 256;
const MAX_NAME_BYTES: usize = 4096;
const MAX_CHUNKS: usize = 16_384;
const MAX_CHUNKS_U32: u32 = 16_384;
const MAX_PAYLOAD_BYTES_U64: u64 = 1 << 30;
const CHUNK_BYTES_U64: u64 = 65_536;
const MAX_NESTING: usize = 16;
const MAX_ENVELOPE_BYTES: usize = MAX_PAYLOAD_BYTES + MAX_CHUNKS * TAG_BYTES + 1024 * 1024;
const HEADER_DOMAIN: &[u8] = b"pigloros/timeline-recipient-export-header/v1\0";
const PAYLOAD_DOMAIN: &[u8] = b"pigloros/timeline-export-payload/v1\0";

/// Closed failures for the recipient export codec.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecipientExportErrorV1 {
    #[error("recipient export encoding is invalid")]
    InvalidEncoding,
    #[error("recipient export encoding is noncanonical")]
    NonCanonical,
    #[error("recipient export fields are out of bounds")]
    FieldOutOfBounds,
    #[error("recipient export identity does not match")]
    IdentityMismatch,
    #[error("recipient export source does not match")]
    SourceMismatch,
    #[error("recipient export authentication failed")]
    AuthenticationFailed,
    #[error("recipient export encryption setup failed")]
    EncryptionFailed,
}

/// Public routing metadata authenticated by the TRX1 HPKE context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientExportHeaderV1 {
    pub export_id: [u8; 16],
    pub timeline_id: TimelineId,
    pub local_head: Seq,
    pub parent_fork_hash: Option<Hash>,
    pub recipient: RecipientKeyDescriptorV1,
    pub payload_length: u64,
    pub chunk_count: u32,
}

/// An exact TRX1 envelope.  Its bytes are deterministic after HPKE encapsulation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientTimelineExportV1 {
    pub header: RecipientExportHeaderV1,
    pub enc: [u8; 32],
    pub ciphertext_chunks: Vec<Vec<u8>>,
}

impl RecipientTimelineExportV1 {
    /// Decode an exact canonical TRX1 envelope without accessing private material.
    ///
    /// # Errors
    /// Returns an encoding or bounds error for any invalid envelope.
    pub fn decode(encoded: &[u8]) -> Result<Self, RecipientExportErrorV1> {
        validate_envelope_length(encoded.len())?;
        preflight_cbor(
            encoded,
            MAX_CHUNKS + 32,
            MAX_CHUNKS,
            CHUNK_BYTES + TAG_BYTES,
        )?;
        let value: Value =
            ciborium::from_reader(encoded).map_err(|_| RecipientExportErrorV1::InvalidEncoding)?;
        let Value::Array(fields) = value else {
            return Err(RecipientExportErrorV1::InvalidEncoding);
        };
        if fields.len() != 8
            || bytes_of::<4>(&fields[0])? != *TRX_MAGIC
            || unsigned(&fields[1])? != VERSION
            || unsigned(&fields[2])? != KEM_ID
            || unsigned(&fields[3])? != KDF_ID
            || unsigned(&fields[4])? != AEAD_ID
        {
            return Err(RecipientExportErrorV1::InvalidEncoding);
        }
        let header = decode_header(&fields[5])?;
        let enc = bytes_of::<32>(&fields[6])?;
        let Value::Array(chunks) = &fields[7] else {
            return Err(RecipientExportErrorV1::InvalidEncoding);
        };
        if chunks.len() != usize::try_from(header.chunk_count).unwrap_or(usize::MAX) {
            return Err(RecipientExportErrorV1::FieldOutOfBounds);
        }
        let ciphertext_chunks = chunks.iter().map(bytes).collect::<Result<Vec<_>, _>>()?;
        let envelope = Self {
            header,
            enc,
            ciphertext_chunks,
        };
        envelope.validate_shape()?;
        if envelope.encode() != encoded {
            return Err(RecipientExportErrorV1::NonCanonical);
        }
        Ok(envelope)
    }

    /// Return the exact deterministic CBOR envelope bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        array(&mut out, 8);
        byte_string(&mut out, TRX_MAGIC);
        unsigned_to(&mut out, VERSION);
        unsigned_to(&mut out, KEM_ID);
        unsigned_to(&mut out, KDF_ID);
        unsigned_to(&mut out, AEAD_ID);
        encode_header(&mut out, &self.header);
        byte_string(&mut out, &self.enc);
        array(&mut out, self.ciphertext_chunks.len());
        for chunk in &self.ciphertext_chunks {
            byte_string(&mut out, chunk);
        }
        out
    }

    fn validate_shape(&self) -> Result<(), RecipientExportErrorV1> {
        if self.header.export_id == [0; 16]
            || self.header.recipient.identity().role != KeyRoleV1::ExportRecipientEncryption
            || self.header.recipient.identity().epoch == 0
            || !(1..=MAX_CHUNKS).contains(&self.ciphertext_chunks.len())
            || usize::try_from(self.header.chunk_count).ok() != Some(self.ciphertext_chunks.len())
            || self.header.payload_length == 0
            || self.header.payload_length > MAX_PAYLOAD_BYTES_U64
        {
            return Err(RecipientExportErrorV1::FieldOutOfBounds);
        }
        let final_plain_len =
            usize::try_from((self.header.payload_length - 1) % CHUNK_BYTES_U64 + 1)
                .unwrap_or(usize::MAX);
        for (index, chunk) in self.ciphertext_chunks.iter().enumerate() {
            let plain_len = chunk
                .len()
                .checked_sub(TAG_BYTES)
                .ok_or(RecipientExportErrorV1::FieldOutOfBounds)?;
            let is_final = index + 1 == self.ciphertext_chunks.len();
            if (!is_final && plain_len != CHUNK_BYTES) || (is_final && plain_len != final_plain_len)
            {
                return Err(RecipientExportErrorV1::FieldOutOfBounds);
            }
        }
        Ok(())
    }
}

const fn validate_envelope_length(length: usize) -> Result<(), RecipientExportErrorV1> {
    if length > MAX_ENVELOPE_BYTES {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    Ok(())
}

/// Encrypt one complete TEP1 own-segment export into a new TRX1 envelope.
///
/// `export_id` is host supplied so the host can create and reserve it inside
/// its publication transaction. It must be fresh and nonzero.
///
/// # Errors
/// Returns a structural, bounds, identity, or encryption error before
/// constructing a partial envelope.
pub fn encrypt_timeline_export_v1(
    export: &TimelineExport,
    recipient: RecipientKeyDescriptorV1,
    export_id: [u8; 16],
    rng: &mut impl CryptoRng,
) -> Result<RecipientTimelineExportV1, RecipientExportErrorV1> {
    let payload = Zeroizing::new(encode_payload(export)?);
    // `encode_payload` caps these values; the sentinels fail header validation.
    let payload_length = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    let chunk_count = u32::try_from(payload.len().div_ceil(CHUNK_BYTES)).unwrap_or(u32::MAX);
    let header = RecipientExportHeaderV1 {
        export_id,
        timeline_id: export.timeline.id(),
        local_head: export.timeline.head,
        parent_fork_hash: export.parent_fork_hash,
        recipient,
        payload_length,
        chunk_count,
    };
    let mut envelope = RecipientTimelineExportV1 {
        header,
        enc: [0; 32],
        ciphertext_chunks: Vec::new(),
    };
    validate_header(&envelope.header)?;
    let header_digest = digest(HEADER_DOMAIN, &encode_header_bytes(&envelope.header));
    let public_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&recipient.public_key())
        .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
    let (enc, mut context) =
        setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &public_key,
            header_digest.as_bytes(),
            rng,
        )
        .map_err(|_| RecipientExportErrorV1::EncryptionFailed)?;
    envelope.enc.copy_from_slice(enc.to_bytes().as_slice());
    for (index, plaintext) in payload.chunks(CHUNK_BYTES).enumerate() {
        let aad = chunk_aad(
            header_digest,
            u32::try_from(index).map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?,
            index + 1 == usize::try_from(chunk_count).unwrap_or(usize::MAX),
        );
        envelope.ciphertext_chunks.push(
            context
                .seal(plaintext, &aad)
                .map_err(|_| RecipientExportErrorV1::EncryptionFailed)?,
        );
    }
    // Header bounds and fixed HPKE tag width establish the envelope shape.
    Ok(envelope)
}

/// Authenticate and decode TRX1, returning only a structural candidate export.
///
/// # Errors
/// Returns an encoding, identity, or authentication error without exposing
/// plaintext when the envelope cannot be verified.
pub fn decrypt_timeline_export_v1(
    encoded: &[u8],
    expected_export_id: [u8; 16],
    expected_recipient: RecipientKeyDescriptorV1,
    private_key: &[u8; 32],
) -> Result<TimelineExport, RecipientExportErrorV1> {
    let envelope = RecipientTimelineExportV1::decode(encoded)?;
    if envelope.header.export_id != expected_export_id
        || envelope.header.recipient != expected_recipient
    {
        return Err(RecipientExportErrorV1::IdentityMismatch);
    }
    let header_digest = digest(HEADER_DOMAIN, &encode_header_bytes(&envelope.header));
    let private_key = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(private_key)
        .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|_| RecipientExportErrorV1::AuthenticationFailed)?;
    let mut context = setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_key,
        &enc,
        header_digest.as_bytes(),
    )
    .map_err(|_| RecipientExportErrorV1::AuthenticationFailed)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    for (index, ciphertext) in envelope.ciphertext_chunks.iter().enumerate() {
        let aad = chunk_aad(
            header_digest,
            u32::try_from(index).map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?,
            index + 1 == envelope.ciphertext_chunks.len(),
        );
        let chunk = Zeroizing::new(
            context
                .open(ciphertext, &aad)
                .map_err(|_| RecipientExportErrorV1::AuthenticationFailed)?,
        );
        plaintext.extend_from_slice(&chunk);
    }
    let export = decode_payload(&plaintext)?;
    if export.timeline.id() != envelope.header.timeline_id
        || export.timeline.head != envelope.header.local_head
        || export.parent_fork_hash != envelope.header.parent_fork_hash
    {
        return Err(RecipientExportErrorV1::SourceMismatch);
    }
    Ok(export)
}

/// Return the private, local idempotency digest for exact TEP1 bytes.
#[must_use]
pub fn timeline_export_payload_digest_v1(payload: &[u8]) -> Hash {
    digest(PAYLOAD_DOMAIN, payload)
}

fn validate_header(header: &RecipientExportHeaderV1) -> Result<(), RecipientExportErrorV1> {
    if header.export_id == [0; 16]
        || header.recipient.identity().role != KeyRoleV1::ExportRecipientEncryption
        || header.recipient.identity().epoch == 0
        || header.payload_length == 0
        || header.payload_length > MAX_PAYLOAD_BYTES_U64
        || !(1..=MAX_CHUNKS_U32).contains(&header.chunk_count)
        || u64::from(header.chunk_count) != (header.payload_length - 1) / CHUNK_BYTES_U64 + 1
    {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    Ok(())
}

fn encode_payload(export: &TimelineExport) -> Result<Vec<u8>, RecipientExportErrorV1> {
    validate_export(export)?;
    let mut out = Vec::new();
    array(&mut out, 11);
    byte_string(&mut out, TEP_MAGIC);
    unsigned_to(&mut out, VERSION);
    byte_string(&mut out, &export.timeline.id().inner().to_bytes());
    unsigned_to(&mut out, mode_code(export.timeline.mode()));
    optional_text(&mut out, export.timeline.meta.name.as_deref());
    optional_id(
        &mut out,
        export.timeline.meta.owner.map(|id| id.inner().to_bytes()),
    );
    optional_id(
        &mut out,
        export
            .timeline
            .meta
            .fork_point
            .map(|(id, _)| id.inner().to_bytes()),
    );
    optional_unsigned(
        &mut out,
        export.timeline.meta.fork_point.map(|(_, seq)| seq.as_u64()),
    );
    unsigned_to(&mut out, export.timeline.head.as_u64());
    optional_hash(&mut out, export.parent_fork_hash);
    array(&mut out, export.events.len());
    for event in &export.events {
        encode_event(&mut out, event);
    }
    if out.len() > MAX_PAYLOAD_BYTES {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    Ok(out)
}

fn decode_payload(bytes: &[u8]) -> Result<TimelineExport, RecipientExportErrorV1> {
    // The decoded envelope already bounds plaintext length and requires a nonempty payload.
    preflight_cbor(
        bytes,
        MAX_EVENTS.saturating_mul(13).saturating_add(12),
        MAX_EVENTS,
        MAX_EVENT_PAYLOAD_BYTES,
    )?;
    let value: Value =
        ciborium::from_reader(bytes).map_err(|_| RecipientExportErrorV1::InvalidEncoding)?;
    let Value::Array(fields) = value else {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    };
    if fields.len() != 11
        || bytes_of::<4>(&fields[0])? != *TEP_MAGIC
        || unsigned(&fields[1])? != VERSION
    {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    }
    let timeline_id = TimelineId::from_ulid(Ulid::from_bytes(bytes_of::<16>(&fields[2])?));
    let mode = decode_mode(unsigned(&fields[3])?)?;
    let name = optional_text_value(&fields[4])?;
    if name
        .as_ref()
        .is_some_and(|value| value.len() > MAX_NAME_BYTES)
    {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    let owner = optional_id_value(&fields[5])?.map(|id| EntityId::from_ulid(Ulid::from_bytes(id)));
    let parent =
        optional_id_value(&fields[6])?.map(|id| TimelineId::from_ulid(Ulid::from_bytes(id)));
    let fork_seq = optional_unsigned_value(&fields[7])?.map(Seq::from_u64);
    let local_head = Seq::from_u64(unsigned(&fields[8])?);
    let parent_fork_hash = optional_hash_value(&fields[9])?;
    let Value::Array(raw_events) = &fields[10] else {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    };
    let events = raw_events
        .iter()
        .map(decode_event)
        .collect::<Result<Vec<_>, _>>()?;
    let fork_point = match (parent, fork_seq, parent_fork_hash) {
        (None, None, None) => None,
        (Some(parent), Some(seq), Some(_)) => Some((parent, seq)),
        _ => return Err(RecipientExportErrorV1::SourceMismatch),
    };
    let export = TimelineExport {
        timeline: Timeline {
            meta: TimelineMeta {
                id: timeline_id,
                mode,
                name,
                owner,
                fork_point,
            },
            head: local_head,
        },
        events,
        parent_fork_hash,
    };
    validate_export(&export)?;
    if encode_payload(&export)? != bytes {
        return Err(RecipientExportErrorV1::NonCanonical);
    }
    Ok(export)
}

fn validate_export(export: &TimelineExport) -> Result<(), RecipientExportErrorV1> {
    if export.events.len() > MAX_EVENTS
        || export
            .timeline
            .meta
            .name
            .as_ref()
            .is_some_and(|name| name.len() > MAX_NAME_BYTES)
    {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    match (export.timeline.meta.fork_point, export.parent_fork_hash) {
        (None, None) | (Some(_), Some(_)) => {}
        _ => return Err(RecipientExportErrorV1::SourceMismatch),
    }
    for (index, event) in export.events.iter().enumerate() {
        if event.seq.as_u64() != u64::try_from(index + 1).unwrap_or(u64::MAX)
            || event.payload.len() > MAX_EVENT_PAYLOAD_BYTES
            || !(1..=MAX_EVENT_TYPE_BYTES).contains(&event.event_type.as_str().len())
            || event.signature.is_some() != event.signature_identity.is_some()
        {
            return Err(RecipientExportErrorV1::FieldOutOfBounds);
        }
        if *blake3::hash(event.payload.as_slice()).as_bytes() != *event.payload_hash.as_bytes() {
            return Err(RecipientExportErrorV1::SourceMismatch);
        }
        if event.signature_identity.is_some_and(|identity| {
            identity.role != KeyRoleV1::TimelineIntegritySigning || identity.epoch == 0
        }) {
            return Err(RecipientExportErrorV1::IdentityMismatch);
        }
    }
    if export.timeline.head.as_u64() != u64::try_from(export.events.len()).unwrap_or(u64::MAX) {
        return Err(RecipientExportErrorV1::SourceMismatch);
    }
    Ok(())
}

fn encode_header(out: &mut Vec<u8>, header: &RecipientExportHeaderV1) {
    array(out, 10);
    byte_string(out, &header.export_id);
    byte_string(out, &header.timeline_id.inner().to_bytes());
    unsigned_to(out, header.local_head.as_u64());
    optional_hash(out, header.parent_fork_hash);
    text(out, header.recipient.identity().owner_id.as_str());
    unsigned_to(out, u64::from(header.recipient.identity().role.code()));
    unsigned_to(out, header.recipient.identity().epoch);
    byte_string(out, &header.recipient.public_key());
    unsigned_to(out, header.payload_length);
    unsigned_to(out, u64::from(header.chunk_count));
}
fn encode_header_bytes(header: &RecipientExportHeaderV1) -> Vec<u8> {
    let mut out = Vec::new();
    encode_header(&mut out, header);
    out
}
fn decode_header(value: &Value) -> Result<RecipientExportHeaderV1, RecipientExportErrorV1> {
    let Value::Array(fields) = value else {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    };
    if fields.len() != 10 {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    }
    let export_id = bytes_of::<16>(&fields[0])?;
    let timeline_id = TimelineId::from_ulid(Ulid::from_bytes(bytes_of::<16>(&fields[1])?));
    let local_head = Seq::from_u64(unsigned(&fields[2])?);
    let parent_fork_hash = optional_hash_value(&fields[3])?;
    let owner = text_value(&fields[4])?;
    let role = unsigned(&fields[5])?;
    let epoch = unsigned(&fields[6])?;
    let public_key = bytes_of::<32>(&fields[7])?;
    let payload_length = unsigned(&fields[8])?;
    let chunk_count = u32::try_from(unsigned(&fields[9])?)
        .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?;
    let descriptor_bytes = rkp1_bytes(owner, epoch, public_key);
    let recipient = RecipientKeyDescriptorV1::decode(&descriptor_bytes)
        .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
    if role != u64::from(recipient.identity().role.code()) {
        return Err(RecipientExportErrorV1::IdentityMismatch);
    }
    let header = RecipientExportHeaderV1 {
        export_id,
        timeline_id,
        local_head,
        parent_fork_hash,
        recipient,
        payload_length,
        chunk_count,
    };
    validate_header(&header)?;
    Ok(header)
}

fn encode_event(out: &mut Vec<u8>, event: &Event) {
    array(out, 12);
    byte_string(out, &event.id.inner().to_bytes());
    byte_string(out, &event.entity.inner().to_bytes());
    text(out, event.event_type.as_str());
    byte_string(out, event.payload.as_slice());
    unsigned_to(out, event.wall_time.as_micros());
    unsigned_to(out, event.seq.as_u64());
    optional_id(out, event.causation_id.map(|id| id.inner().to_bytes()));
    optional_id(out, event.correlation_id.map(|id| id.inner().to_bytes()));
    unsigned_to(out, u64::from(event.schema_version.as_u32()));
    match event.signature {
        Some(signature) => byte_string(out, signature.as_bytes()),
        None => out.push(0xf6),
    }
    match event.signature_identity {
        Some(identity) => {
            array(out, 3);
            text(out, identity.owner_id.as_str());
            unsigned_to(out, u64::from(identity.role.code()));
            unsigned_to(out, identity.epoch);
        }
        None => out.push(0xf6),
    }
    byte_string(out, event.payload_hash.as_bytes());
}
fn decode_event(value: &Value) -> Result<Event, RecipientExportErrorV1> {
    let Value::Array(fields) = value else {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    };
    if fields.len() != 12 {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    }
    let event_type = text_value(&fields[2])?;
    if !(1..=MAX_EVENT_TYPE_BYTES).contains(&event_type.len()) {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    // The CBOR preflight already caps each byte string at the event payload limit.
    let payload = bytes(&fields[3])?;
    let signature = optional_signature(&fields[9])?;
    let signature_identity = optional_identity(&fields[10])?;
    if signature.is_some() != signature_identity.is_some() {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    let schema = unsigned(&fields[8])?;
    if schema != 1 {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    let event = Event {
        id: EventId::from_ulid(Ulid::from_bytes(bytes_of::<16>(&fields[0])?)),
        entity: EntityId::from_ulid(Ulid::from_bytes(bytes_of::<16>(&fields[1])?)),
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_vec(payload),
        wall_time: WallTime::from_micros(unsigned(&fields[4])?),
        seq: Seq::from_u64(unsigned(&fields[5])?),
        causation_id: optional_id_value(&fields[6])?
            .map(|id| EventId::from_ulid(Ulid::from_bytes(id))),
        correlation_id: optional_id_value(&fields[7])?
            .map(|id| CorrelationId::from_ulid(Ulid::from_bytes(id))),
        schema_version: SchemaVersion::V1,
        signature,
        signature_identity,
        origin: None,
        payload_hash: Hash::from_bytes(bytes_of::<32>(&fields[11])?),
    };
    if *blake3::hash(event.payload.as_slice()).as_bytes() != *event.payload_hash.as_bytes() {
        return Err(RecipientExportErrorV1::SourceMismatch);
    }
    Ok(event)
}

fn optional_identity(value: &Value) -> Result<Option<KeyIdentityV1>, RecipientExportErrorV1> {
    if matches!(value, Value::Null) {
        return Ok(None);
    }
    let Value::Array(fields) = value else {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    };
    if fields.len() != 3 {
        return Err(RecipientExportErrorV1::InvalidEncoding);
    }
    let owner = pos_core::OwnerIdV1::new(text_value(&fields[0])?)
        .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
    let role = KeyRoleV1::from_code(
        u8::try_from(unsigned(&fields[1])?)
            .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?,
    )
    .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
    let epoch = unsigned(&fields[2])?;
    if epoch == 0 || role != KeyRoleV1::TimelineIntegritySigning {
        return Err(RecipientExportErrorV1::IdentityMismatch);
    }
    Ok(Some(KeyIdentityV1::from_parts(owner, role, epoch)))
}
fn optional_signature(value: &Value) -> Result<Option<Signature>, RecipientExportErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        Ok(Some(Signature::from_bytes(bytes_of::<64>(value)?)))
    }
}
const fn mode_code(mode: TimelineMode) -> u64 {
    match mode {
        TimelineMode::Historical => 0,
        TimelineMode::Live => 1,
        TimelineMode::Future => 2,
    }
}
const fn decode_mode(value: u64) -> Result<TimelineMode, RecipientExportErrorV1> {
    match value {
        0 => Ok(TimelineMode::Historical),
        1 => Ok(TimelineMode::Live),
        2 => Ok(TimelineMode::Future),
        _ => Err(RecipientExportErrorV1::FieldOutOfBounds),
    }
}
fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
fn chunk_aad(header_digest: Hash, index: u32, is_final: bool) -> Vec<u8> {
    let mut out = Vec::new();
    array(&mut out, 3);
    byte_string(&mut out, header_digest.as_bytes());
    unsigned_to(&mut out, u64::from(index));
    out.push(if is_final { 0xf5 } else { 0xf4 });
    out
}
fn rkp1_bytes(owner: &str, epoch: u64, public_key: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    array(&mut out, 7);
    byte_string(&mut out, b"RKP1");
    unsigned_to(&mut out, 1);
    text(&mut out, owner);
    unsigned_to(&mut out, 4);
    unsigned_to(&mut out, epoch);
    unsigned_to(&mut out, 0x20);
    byte_string(&mut out, &public_key);
    out
}
fn bytes(value: &Value) -> Result<Vec<u8>, RecipientExportErrorV1> {
    match value {
        Value::Bytes(value) => Ok(value.clone()),
        _ => Err(RecipientExportErrorV1::InvalidEncoding),
    }
}
fn bytes_of<const N: usize>(value: &Value) -> Result<[u8; N], RecipientExportErrorV1> {
    bytes(value)?
        .try_into()
        .map_err(|_| RecipientExportErrorV1::InvalidEncoding)
}
fn text_value(value: &Value) -> Result<&str, RecipientExportErrorV1> {
    match value {
        Value::Text(value) => Ok(value),
        _ => Err(RecipientExportErrorV1::InvalidEncoding),
    }
}
fn optional_text_value(value: &Value) -> Result<Option<String>, RecipientExportErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        Ok(Some(text_value(value)?.to_owned()))
    }
}
fn unsigned(value: &Value) -> Result<u64, RecipientExportErrorV1> {
    match value {
        Value::Integer(value) => {
            u64::try_from(*value).map_err(|_| RecipientExportErrorV1::InvalidEncoding)
        }
        _ => Err(RecipientExportErrorV1::InvalidEncoding),
    }
}
fn optional_unsigned_value(value: &Value) -> Result<Option<u64>, RecipientExportErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        unsigned(value).map(Some)
    }
}
fn optional_id_value(value: &Value) -> Result<Option<[u8; 16]>, RecipientExportErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        bytes_of(value).map(Some)
    }
}
fn optional_hash_value(value: &Value) -> Result<Option<Hash>, RecipientExportErrorV1> {
    if matches!(value, Value::Null) {
        Ok(None)
    } else {
        bytes_of(value).map(Hash::from_bytes).map(Some)
    }
}
fn array(out: &mut Vec<u8>, length: usize) {
    head(out, 4, u64::try_from(length).unwrap_or(u64::MAX));
}
fn byte_string(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 2, u64::try_from(value.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(value);
}
fn text(out: &mut Vec<u8>, value: &str) {
    head(out, 3, u64::try_from(value.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(value.as_bytes());
}
fn optional_text(out: &mut Vec<u8>, value: Option<&str>) {
    if let Some(value) = value {
        text(out, value);
    } else {
        out.push(0xf6);
    }
}
fn optional_id(out: &mut Vec<u8>, value: Option<[u8; 16]>) {
    if let Some(value) = value {
        byte_string(out, &value);
    } else {
        out.push(0xf6);
    }
}
fn optional_unsigned(out: &mut Vec<u8>, value: Option<u64>) {
    if let Some(value) = value {
        unsigned_to(out, value);
    } else {
        out.push(0xf6);
    }
}
fn optional_hash(out: &mut Vec<u8>, value: Option<Hash>) {
    if let Some(value) = value {
        byte_string(out, value.as_bytes());
    } else {
        out.push(0xf6);
    }
}
fn unsigned_to(out: &mut Vec<u8>, value: u64) {
    head(out, 0, value);
}
fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => out.push(tag | bytes[7]),
        24..=0xff => out.extend_from_slice(&[tag | 0x18, bytes[7]]),
        0x100..=0xffff => {
            out.push(tag | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            out.push(tag | 0x1a);
            out.extend_from_slice(&bytes[4..]);
        }
        _ => {
            out.push(tag | 0x1b);
            out.extend_from_slice(&bytes);
        }
    }
}

/// Reject unbounded CBOR before the general-purpose decoder can materialise it.
///
/// The structural decoders below enforce the fixed schemas. This pass only
/// permits the primitive forms used by TEP1/TRX1 and caps depth and items.
fn preflight_cbor(
    bytes: &[u8],
    max_items: usize,
    max_array_items: usize,
    max_string_bytes: usize,
) -> Result<(), RecipientExportErrorV1> {
    let mut position = 0;
    let mut items = 0;
    scan_cbor_item(
        bytes,
        &mut position,
        0,
        &mut items,
        max_items,
        max_array_items,
        max_string_bytes,
    )?;
    if position == bytes.len() {
        Ok(())
    } else {
        Err(RecipientExportErrorV1::InvalidEncoding)
    }
}

fn scan_cbor_item(
    bytes: &[u8],
    position: &mut usize,
    depth: usize,
    items: &mut usize,
    max_items: usize,
    max_array_items: usize,
    max_string_bytes: usize,
) -> Result<(), RecipientExportErrorV1> {
    if depth > MAX_NESTING || *items >= max_items {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    *items += 1;
    let initial = *bytes
        .get(*position)
        .ok_or(RecipientExportErrorV1::InvalidEncoding)?;
    *position += 1;
    let major = initial >> 5;
    let length = scan_argument(bytes, position, initial & 0x1f)?;
    match major {
        0 => Ok(()),
        2 | 3 => {
            if length > u64::try_from(max_string_bytes).unwrap_or(u64::MAX) {
                return Err(RecipientExportErrorV1::FieldOutOfBounds);
            }
            let length = usize::try_from(length).unwrap_or(usize::MAX);
            if length > max_string_bytes {
                return Err(RecipientExportErrorV1::FieldOutOfBounds);
            }
            let remaining = bytes
                .get(*position..)
                .ok_or(RecipientExportErrorV1::InvalidEncoding)?;
            if length > remaining.len() {
                return Err(RecipientExportErrorV1::InvalidEncoding);
            }
            *position += length;
            Ok(())
        }
        4 => {
            if length > u64::try_from(max_array_items).unwrap_or(u64::MAX) {
                return Err(RecipientExportErrorV1::FieldOutOfBounds);
            }
            let length = usize::try_from(length).unwrap_or(usize::MAX);
            if length > max_array_items || length > max_items.saturating_sub(*items) {
                return Err(RecipientExportErrorV1::FieldOutOfBounds);
            }
            for _ in 0..length {
                scan_cbor_item(
                    bytes,
                    position,
                    depth + 1,
                    items,
                    max_items,
                    max_array_items,
                    max_string_bytes,
                )?;
            }
            Ok(())
        }
        7 if matches!(initial, 0xf4..=0xf6) => Ok(()),
        _ => Err(RecipientExportErrorV1::InvalidEncoding),
    }
}

fn scan_argument(
    bytes: &[u8],
    position: &mut usize,
    additional: u8,
) -> Result<u64, RecipientExportErrorV1> {
    #[derive(Clone, Copy)]
    enum Width {
        One,
        Two,
        Four,
        Eight,
    }
    let width = match additional {
        0..=23 => return Ok(u64::from(additional)),
        24 => Width::One,
        25 => Width::Two,
        26 => Width::Four,
        27 => Width::Eight,
        _ => return Err(RecipientExportErrorV1::InvalidEncoding),
    };
    let length = match width {
        Width::One => 1,
        Width::Two => 2,
        Width::Four => 4,
        Width::Eight => 8,
    };
    let slice = bytes
        .get(*position..)
        .and_then(|remaining| remaining.get(..length))
        .ok_or(RecipientExportErrorV1::InvalidEncoding)?;
    *position += length;
    match width {
        Width::One => Ok(u64::from(slice[0])),
        Width::Two => Ok(u64::from(u16::from_be_bytes([slice[0], slice[1]]))),
        Width::Four => Ok(u64::from(u32::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3],
        ]))),
        Width::Eight => Ok(u64::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::recipient_key::derive_recipient_keypair_v1;
    use rand::{rngs::StdRng, SeedableRng};

    fn from_hex(value: &str) -> Result<Vec<u8>, RecipientExportErrorV1> {
        if !value.len().is_multiple_of(2) {
            return Err(RecipientExportErrorV1::InvalidEncoding);
        }
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair)
                    .map_err(|_| RecipientExportErrorV1::InvalidEncoding)?;
                u8::from_str_radix(pair, 16).map_err(|_| RecipientExportErrorV1::InvalidEncoding)
            })
            .collect()
    }

    fn id(value: u128) -> Ulid {
        Ulid::from(value)
    }

    fn recipient() -> Result<(RecipientKeyDescriptorV1, [u8; 32]), RecipientExportErrorV1> {
        let (private, public) = derive_recipient_keypair_v1(&[9; 32])
            .map_err(|_| RecipientExportErrorV1::EncryptionFailed)?;
        let descriptor =
            RecipientKeyDescriptorV1::for_grantee(EntityId::from_ulid(id(1)), 1, public)
                .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
        Ok((descriptor, private))
    }

    fn event(sequence: u64, payload: Vec<u8>) -> Event {
        let payload_hash = Hash::from_bytes(*blake3::hash(&payload).as_bytes());
        Event {
            id: EventId::from_ulid(id(100 + u128::from(sequence))),
            entity: EntityId::from_ulid(id(200)),
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(payload),
            wall_time: WallTime::from_micros(sequence),
            seq: Seq::from_u64(sequence),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash,
        }
    }

    fn export(fork_sequence: Option<u64>, payload: Vec<u8>) -> TimelineExport {
        let events = if payload.is_empty() {
            Vec::new()
        } else {
            vec![event(1, payload)]
        };
        let parent =
            fork_sequence.map(|sequence| (TimelineId::from_ulid(id(2)), Seq::from_u64(sequence)));
        TimelineExport {
            timeline: Timeline {
                meta: TimelineMeta {
                    id: TimelineId::from_ulid(id(3)),
                    mode: TimelineMode::Live,
                    name: Some("candidate".to_owned()),
                    owner: Some(EntityId::from_ulid(id(4))),
                    fork_point: parent,
                },
                head: Seq::from_u64(u64::from(!events.is_empty())),
            },
            events,
            parent_fork_hash: fork_sequence.map(|_| Hash::from_bytes([7; 32])),
        }
    }

    fn round_trip(
        fork_sequence: Option<u64>,
        payload: Vec<u8>,
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let source = export(fork_sequence, payload);
        let mut rng = StdRng::from_seed([6; 32]);
        let envelope = encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng)?;
        let encoded = envelope.encode();
        assert_eq!(RecipientTimelineExportV1::decode(&encoded)?, envelope);
        let decoded = decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private)?;
        assert_eq!(decoded.timeline.meta, source.timeline.meta);
        assert_eq!(decoded.timeline.head, source.timeline.head);
        assert_eq!(decoded.parent_fork_hash, source.parent_fork_hash);
        assert_eq!(decoded.events, source.events);
        Ok(())
    }

    fn rewrite_envelope(
        encoded: &[u8],
        edit: impl FnOnce(&mut Vec<Value>),
    ) -> Result<Vec<u8>, RecipientExportErrorV1> {
        let mut value: Value =
            ciborium::from_reader(encoded).map_err(|_| RecipientExportErrorV1::InvalidEncoding)?;
        let Value::Array(fields) = &mut value else {
            return Err(RecipientExportErrorV1::InvalidEncoding);
        };
        edit(fields);
        let mut result = Vec::new();
        ciborium::into_writer(&value, &mut result)
            .map_err(|_| RecipientExportErrorV1::InvalidEncoding)?;
        Ok(result)
    }

    fn rewrite_payload(
        encoded: &[u8],
        edit: impl FnOnce(&mut Vec<Value>),
    ) -> Result<Vec<u8>, RecipientExportErrorV1> {
        let mut value: Value =
            ciborium::from_reader(encoded).map_err(|_| RecipientExportErrorV1::InvalidEncoding)?;
        let Value::Array(fields) = &mut value else {
            return Err(RecipientExportErrorV1::InvalidEncoding);
        };
        edit(fields);
        let mut result = Vec::new();
        ciborium::into_writer(&value, &mut result)
            .map_err(|_| RecipientExportErrorV1::InvalidEncoding)?;
        Ok(result)
    }

    fn replace_event_field(fields: &mut [Value], index: usize, value: Value) {
        if let Value::Array(events) = &mut fields[10] {
            if let Some(Value::Array(event)) = events.first_mut() {
                event[index] = value;
            }
        }
    }

    fn replace_identity_field(fields: &mut [Value], index: usize, value: Value) {
        if let Value::Array(events) = &mut fields[10] {
            if let Some(Value::Array(event)) = events.first_mut() {
                if let Value::Array(identity) = &mut event[10] {
                    identity[index] = value;
                }
            }
        }
    }

    fn encrypt_payload(
        payload: &[u8],
        recipient: RecipientKeyDescriptorV1,
        export_id: [u8; 16],
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<u8>, RecipientExportErrorV1> {
        let payload_length =
            u64::try_from(payload.len()).map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?;
        let chunk_count = u32::try_from(payload.len().div_ceil(CHUNK_BYTES))
            .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?;
        let header = RecipientExportHeaderV1 {
            export_id,
            timeline_id: TimelineId::from_ulid(id(3)),
            local_head: Seq::from_u64(1),
            parent_fork_hash: None,
            recipient,
            payload_length,
            chunk_count,
        };
        validate_header(&header)?;
        let header_digest = digest(HEADER_DOMAIN, &encode_header_bytes(&header));
        let public_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&recipient.public_key())
            .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
        let (enc, mut context) = setup_sender_with_rng::<
            ChaCha20Poly1305,
            HkdfSha256,
            X25519HkdfSha256,
        >(
            &OpModeS::Base, &public_key, header_digest.as_bytes(), rng
        )
        .map_err(|_| RecipientExportErrorV1::EncryptionFailed)?;
        let ciphertext_chunks = payload
            .chunks(CHUNK_BYTES)
            .enumerate()
            .map(|(index, plaintext)| {
                context
                    .seal(
                        plaintext,
                        &chunk_aad(
                            header_digest,
                            u32::try_from(index)
                                .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?,
                            index + 1
                                == usize::try_from(chunk_count)
                                    .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?,
                        ),
                    )
                    .map_err(|_| RecipientExportErrorV1::EncryptionFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RecipientTimelineExportV1 {
            header,
            enc: enc
                .to_bytes()
                .as_slice()
                .try_into()
                .map_err(|_| RecipientExportErrorV1::EncryptionFailed)?,
            ciphertext_chunks,
        }
        .encode())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn round_trips_root_forks_and_empty_child() -> Result<(), RecipientExportErrorV1> {
        round_trip(None, b"root".to_vec())?;
        round_trip(Some(0), b"fork-at-zero".to_vec())?;
        round_trip(Some(9), b"fork-at-nonzero".to_vec())?;
        round_trip(Some(0), Vec::new())?;
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rfc9180_a2_base_receiver_vector() -> Result<(), RecipientExportErrorV1> {
        // RFC 9180 Appendix A.2.1, sequence numbers 0 and 1 for our fixed suite.
        let private = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&from_hex(
            "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        )?)
        .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
        let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&from_hex(
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        )?)
        .map_err(|_| RecipientExportErrorV1::InvalidEncoding)?;
        let mut receiver = setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &private,
            &enc,
            &from_hex("4f6465206f6e2061204772656369616e2055726e")?,
        )
        .map_err(|_| RecipientExportErrorV1::AuthenticationFailed)?;
        let expected = from_hex("4265617574792069732074727574682c20747275746820626561757479")?;
        for (aad, ciphertext) in [
            (
                "436f756e742d30",
                concat!(
                    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db",
                    "21993c62ce81883d2dd1b51a28"
                ),
            ),
            (
                "436f756e742d31",
                concat!(
                    "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e",
                    "85285337cc95ba5f59992dc98c"
                ),
            ),
        ] {
            let plaintext = receiver
                .open(&from_hex(ciphertext)?, &from_hex(aad)?)
                .map_err(|_| RecipientExportErrorV1::AuthenticationFailed)?;
            assert_eq!(plaintext, expected);
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn pins_tep1_and_trx1_canonical_wire_bytes() -> Result<(), RecipientExportErrorV1> {
        let source = export(None, Vec::new());
        let tep1 = from_hex(
            "8b4454455031015000000000000000000000000000000003016963616e6469646174655000000000000000000000000000000004f6f600f680",
        )?;
        assert_eq!(encode_payload(&source)?, tep1);
        let decoded = decode_payload(&tep1)?;
        assert_eq!(decoded.timeline.meta, source.timeline.meta);
        assert_eq!(decoded.timeline.head, source.timeline.head);
        assert!(decoded.events.is_empty());

        let recipient =
            RecipientKeyDescriptorV1::for_grantee(EntityId::from_ulid(id(1)), 1, [7; 32])
                .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?;
        let envelope = RecipientTimelineExportV1 {
            header: RecipientExportHeaderV1 {
                export_id: [5; 16],
                timeline_id: TimelineId::from_ulid(id(3)),
                local_head: Seq::from_u64(0),
                parent_fork_hash: None,
                recipient,
                payload_length: 1,
                chunk_count: 1,
            },
            enc: [8; 32],
            ciphertext_chunks: vec![vec![9; 17]],
        };
        let trx1 = from_hex(concat!(
            "88445452583101182001038a5005050505050505050505050505050505",
            "500000000000000000000000000000000300f6782a726563697069656e743a",
            "3030303030303030303030303030303030303030303030303030303030303031",
            "040158200707070707070707070707070707070707070707070707070707070707070707",
            "010158200808080808080808080808080808080808080808080808080808080808080808",
            "81510909090909090909090909090909090909"
        ))?;
        assert_eq!(envelope.encode(), trx1);
        assert_eq!(RecipientTimelineExportV1::decode(&trx1)?, envelope);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn uses_ordered_chunks_and_releases_no_plaintext_on_failure(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let overhead = encode_payload(&export(None, vec![3; CHUNK_BYTES]))?.len() - CHUNK_BYTES;
        let source = export(None, vec![3; CHUNK_BYTES * 2 - overhead]);
        let mut rng = StdRng::from_seed([7; 32]);
        let mut envelope = encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng)?;
        assert_eq!(envelope.ciphertext_chunks.len(), 2);
        assert_eq!(envelope.header.payload_length, CHUNK_BYTES_U64 * 2);
        envelope.ciphertext_chunks.swap(0, 1);
        assert!(matches!(
            decrypt_timeline_export_v1(&envelope.encode(), [5; 16], recipient, &private),
            Err(RecipientExportErrorV1::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_wrong_expected_identity_and_noncanonical_envelope(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let mut rng = StdRng::from_seed([8; 32]);
        let encoded = encrypt_timeline_export_v1(
            &export(None, b"root".to_vec()),
            recipient,
            [5; 16],
            &mut rng,
        )?
        .encode();
        assert!(matches!(
            decrypt_timeline_export_v1(&encoded, [4; 16], recipient, &private),
            Err(RecipientExportErrorV1::IdentityMismatch)
        ));
        let mut noncanonical = Vec::with_capacity(encoded.len() + 1);
        noncanonical.extend_from_slice(&[0x98, 8]);
        noncanonical.extend_from_slice(&encoded[1..]);
        assert_eq!(
            RecipientTimelineExportV1::decode(&noncanonical),
            Err(RecipientExportErrorV1::NonCanonical)
        );
        let mut wrong_length = RecipientTimelineExportV1::decode(&encoded)?;
        wrong_length.ciphertext_chunks[0].push(0);
        assert_eq!(
            RecipientTimelineExportV1::decode(&wrong_length.encode()),
            Err(RecipientExportErrorV1::FieldOutOfBounds)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_malformed_public_envelope_fields() -> Result<(), RecipientExportErrorV1> {
        let (recipient, _) = recipient()?;
        let mut rng = StdRng::from_seed([11; 32]);
        let encoded = encrypt_timeline_export_v1(
            &export(None, b"source".to_vec()),
            recipient,
            [5; 16],
            &mut rng,
        )?
        .encode();
        for index in 0..8 {
            let rewritten = rewrite_envelope(&encoded, |fields| fields[index] = Value::Null)?;
            assert!(RecipientTimelineExportV1::decode(&rewritten).is_err());
        }
        for index in [0, 1, 2, 4, 5, 6, 7, 8, 9] {
            let rewritten = rewrite_envelope(&encoded, |fields| {
                if let Value::Array(header) = &mut fields[5] {
                    header[index] = Value::Null;
                }
            })?;
            assert!(RecipientTimelineExportV1::decode(&rewritten).is_err());
        }
        for index in [0, 6, 8, 9] {
            let rewritten = rewrite_envelope(&encoded, |fields| {
                if let Value::Array(header) = &mut fields[5] {
                    header[index] = Value::Integer(0_u64.into());
                }
            })?;
            assert!(RecipientTimelineExportV1::decode(&rewritten).is_err());
        }
        for malformed in [
            vec![],
            vec![0xc0, 0xf6],
            vec![0xbf, 0xff],
            vec![0xf9, 0, 0],
            vec![0x99, 0, 8],
            vec![0x9a, 0, 0, 0, 8],
            vec![0x9b, 0, 0, 0, 0, 0, 0, 0, 8],
        ] {
            assert!(RecipientTimelineExportV1::decode(&malformed).is_err());
        }
        for chunks in [
            vec![],
            vec![Value::Bytes(vec![])],
            vec![Value::Bytes(vec![0; 18])],
        ] {
            let rewritten = rewrite_envelope(&encoded, |fields| {
                fields[7] = Value::Array(chunks);
            })?;
            assert!(RecipientTimelineExportV1::decode(&rewritten).is_err());
        }
        let rewritten = rewrite_envelope(&encoded, |fields| {
            if let Value::Array(header) = &mut fields[5] {
                header[3] = Value::Bytes(vec![7; 31]);
            }
        })?;
        assert!(RecipientTimelineExportV1::decode(&rewritten).is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_inconsistent_source_before_encryption() -> Result<(), RecipientExportErrorV1> {
        let (recipient, _) = recipient()?;
        let mut rng = StdRng::from_seed([9; 32]);
        let mut source = export(None, b"source".to_vec());
        source.events[0].payload_hash = Hash::from_bytes([0; 32]);
        assert!(matches!(
            encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng),
            Err(RecipientExportErrorV1::SourceMismatch)
        ));

        source.events[0].payload_hash = Hash::from_bytes(*blake3::hash(b"source").as_bytes());
        source.events[0].signature = Some(Signature::from_bytes([1; 64]));
        source.events[0].signature_identity = Some(KeyIdentityV1::from_parts(
            pos_core::OwnerIdV1::new("source")
                .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?,
            KeyRoleV1::ExportRecipientEncryption,
            1,
        ));
        assert!(matches!(
            encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng),
            Err(RecipientExportErrorV1::IdentityMismatch)
        ));
        source.events[0].signature_identity = Some(KeyIdentityV1::from_parts(
            pos_core::OwnerIdV1::new("source")
                .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?,
            KeyRoleV1::TimelineIntegritySigning,
            0,
        ));
        assert!(matches!(
            encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng),
            Err(RecipientExportErrorV1::IdentityMismatch)
        ));
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_authenticated_malformed_tep1_at_public_decryption_boundary(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let payload = encode_payload(&export(None, b"source".to_vec()))?;
        let mut rng = StdRng::from_seed([12; 32]);
        for index in [0, 1, 2, 3, 8, 10] {
            let malformed = rewrite_payload(&payload, |fields| fields[index] = Value::Null)?;
            let encoded = encrypt_payload(&malformed, recipient, [5; 16], &mut rng)?;
            assert!(decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private).is_err());
        }
        for index in [4, 5, 6, 7, 9] {
            let malformed = rewrite_payload(&payload, |fields| fields[index] = Value::Bool(true))?;
            let encoded = encrypt_payload(&malformed, recipient, [5; 16], &mut rng)?;
            assert!(decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private).is_err());
        }
        for value in [Value::Integer(3_u64.into()), Value::Text("TEP1".to_owned())] {
            let malformed = rewrite_payload(&payload, |fields| fields[3] = value)?;
            let encoded = encrypt_payload(&malformed, recipient, [5; 16], &mut rng)?;
            assert!(decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private).is_err());
        }
        for index in [0, 1, 2, 3, 4, 5, 8, 11] {
            let malformed = rewrite_payload(&payload, |fields| {
                if let Value::Array(events) = &mut fields[10] {
                    if let Some(Value::Array(event)) = events.first_mut() {
                        event[index] = Value::Null;
                    }
                }
            })?;
            let encoded = encrypt_payload(&malformed, recipient, [5; 16], &mut rng)?;
            assert!(decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private).is_err());
        }
        for index in [6, 7, 9, 10] {
            let malformed = rewrite_payload(&payload, |fields| {
                if let Value::Array(events) = &mut fields[10] {
                    if let Some(Value::Array(event)) = events.first_mut() {
                        event[index] = Value::Bool(true);
                    }
                }
            })?;
            let encoded = encrypt_payload(&malformed, recipient, [5; 16], &mut rng)?;
            assert!(decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private).is_err());
        }
        let malformed = rewrite_payload(&payload, |fields| {
            fields[6] = Value::Bytes(id(2).to_bytes().to_vec());
        })?;
        let encoded = encrypt_payload(&malformed, recipient, [5; 16], &mut rng)?;
        assert!(decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private).is_err());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_structurally_valid_hpke_tampering_at_public_decryption_boundary(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let mut rng = StdRng::from_seed([13; 32]);
        let encoded = encrypt_timeline_export_v1(
            &export(None, b"source".to_vec()),
            recipient,
            [5; 16],
            &mut rng,
        )?
        .encode();
        for edit in [
            |fields: &mut Vec<Value>| fields[6] = Value::Bytes(vec![0; 32]),
            |fields: &mut Vec<Value>| {
                if let Value::Array(header) = &mut fields[5] {
                    header[2] = Value::Integer(2_u64.into());
                }
            },
            |fields: &mut Vec<Value>| {
                if let Value::Array(chunks) = &mut fields[7] {
                    if let Some(Value::Bytes(chunk)) = chunks.first_mut() {
                        chunk[0] ^= 1;
                    }
                }
            },
        ] {
            let tampered = rewrite_envelope(&encoded, edit)?;
            assert!(matches!(
                decrypt_timeline_export_v1(&tampered, [5; 16], recipient, &private),
                Err(RecipientExportErrorV1::AuthenticationFailed)
            ));
        }
        assert!(matches!(
            decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &[8; 32]),
            Err(RecipientExportErrorV1::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn preserves_canonical_metadata_and_signed_event_forms_at_the_public_boundary(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let mut source = export(None, b"source".to_vec());
        source.timeline.meta.mode = TimelineMode::Historical;
        source.timeline.meta.name = None;
        source.timeline.meta.owner = None;
        let event = &mut source.events[0];
        event.wall_time = WallTime::from_micros(0x100);
        event.causation_id = Some(EventId::from_ulid(id(301)));
        event.correlation_id = Some(CorrelationId::from_ulid(id(302)));
        event.signature = Some(Signature::from_bytes([6; 64]));
        event.signature_identity = Some(KeyIdentityV1::from_parts(
            pos_core::OwnerIdV1::new("source")
                .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?,
            KeyRoleV1::TimelineIntegritySigning,
            1,
        ));
        let mut rng = StdRng::from_seed([14; 32]);
        let encoded = encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng)?.encode();
        let decoded = decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private)?;
        assert_eq!(decoded.timeline.meta, source.timeline.meta);
        assert_eq!(decoded.events, source.events);

        source.timeline.meta.mode = TimelineMode::Future;
        source.events[0].wall_time = WallTime::from_micros(0x1_0000_0000);
        let encoded = encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng)?.encode();
        let decoded = decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private)?;
        assert_eq!(decoded.timeline.meta, source.timeline.meta);
        assert_eq!(decoded.events, source.events);
        assert_ne!(
            timeline_export_payload_digest_v1(b"one"),
            timeline_export_payload_digest_v1(b"two")
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_reachable_cbor_preflight_forms_at_the_public_boundary() {
        assert_eq!(
            validate_envelope_length(MAX_ENVELOPE_BYTES + 1),
            Err(RecipientExportErrorV1::FieldOutOfBounds)
        );
        for encoded in [
            vec![0x81, 0xf6, 0xf6],
            vec![0x58, 1],
            vec![0x1c],
            vec![0x18],
        ] {
            assert_eq!(
                RecipientTimelineExportV1::decode(&encoded),
                Err(RecipientExportErrorV1::InvalidEncoding)
            );
        }
        // 65,553 string bytes and 16,385 array items exceed their preflight caps.
        for encoded in [vec![0x5a, 0, 1, 0, 17], vec![0x9a, 0, 0, 0x40, 1]] {
            assert_eq!(
                RecipientTimelineExportV1::decode(&encoded),
                Err(RecipientExportErrorV1::FieldOutOfBounds)
            );
        }
        let mut too_deep = vec![0x81; MAX_NESTING + 2];
        too_deep.push(0xf6);
        assert_eq!(
            RecipientTimelineExportV1::decode(&too_deep),
            Err(RecipientExportErrorV1::FieldOutOfBounds)
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_authenticated_reachable_tep1_schema_variants_at_the_public_boundary(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let payload = encode_payload(&export(None, b"source".to_vec()))?;
        let mut rng = StdRng::from_seed([15; 32]);
        let edits: [fn(&mut Vec<Value>); 8] = [
            |fields: &mut Vec<Value>| fields.truncate(10),
            |fields: &mut Vec<Value>| fields[4] = Value::Text("x".repeat(MAX_NAME_BYTES + 1)),
            |fields: &mut Vec<Value>| fields[10] = Value::Null,
            |fields: &mut Vec<Value>| {
                if let Value::Array(events) = &mut fields[10] {
                    events[0] = Value::Null;
                }
            },
            |fields: &mut Vec<Value>| {
                if let Value::Array(events) = &mut fields[10] {
                    if let Value::Array(event) = &mut events[0] {
                        event.truncate(11);
                    }
                }
            },
            |fields: &mut Vec<Value>| {
                if let Value::Array(events) = &mut fields[10] {
                    if let Value::Array(event) = &mut events[0] {
                        event[2] = Value::Text(String::new());
                    }
                }
            },
            |fields: &mut Vec<Value>| {
                if let Value::Array(events) = &mut fields[10] {
                    if let Value::Array(event) = &mut events[0] {
                        event[8] = Value::Integer(2_u64.into());
                    }
                }
            },
            |fields: &mut Vec<Value>| {
                if let Value::Array(events) = &mut fields[10] {
                    if let Value::Array(event) = &mut events[0] {
                        event[11] = Value::Bytes(vec![0; 32]);
                    }
                }
            },
        ];
        for edit in edits {
            let malformed = rewrite_payload(&payload, edit)?;
            let encoded = encrypt_payload(&malformed, recipient, [5; 16], &mut rng)?;
            assert!(decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private).is_err());
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_invalid_source_shapes_before_encryption() -> Result<(), RecipientExportErrorV1> {
        let (recipient, _) = recipient()?;
        let edits: [fn(&mut TimelineExport); 6] = [
            |source| source.timeline.head = Seq::from_u64(2),
            |source| source.events[0].seq = Seq::from_u64(2),
            |source| source.events[0].event_type = Kind::new(String::new()),
            |source| {
                source.events[0].event_type = Kind::new("x".repeat(MAX_EVENT_TYPE_BYTES + 1));
            },
            |source| source.timeline.meta.name = Some("x".repeat(MAX_NAME_BYTES + 1)),
            |source| source.events[0].signature = Some(Signature::from_bytes([1; 64])),
        ];
        let mut rng = StdRng::from_seed([17; 32]);
        for edit in edits {
            let mut source = export(None, b"source".to_vec());
            edit(&mut source);
            assert!(encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng).is_err());
        }
        let mut source = export(None, b"source".to_vec());
        source.events[0].payload = CanonicalBytes::from_vec(vec![0; MAX_EVENT_PAYLOAD_BYTES + 1]);
        assert_eq!(
            encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng),
            Err(RecipientExportErrorV1::FieldOutOfBounds)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_authenticated_signed_event_and_source_substitution(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let mut source = export(None, b"source".to_vec());
        source.events[0].signature = Some(Signature::from_bytes([1; 64]));
        source.events[0].signature_identity = Some(KeyIdentityV1::from_parts(
            pos_core::OwnerIdV1::new("source")
                .map_err(|_| RecipientExportErrorV1::IdentityMismatch)?,
            KeyRoleV1::TimelineIntegritySigning,
            1,
        ));
        let payload = encode_payload(&source)?;
        let edits: [fn(&mut Vec<Value>); 10] = [
            |fields| fields[2] = Value::Bytes(Ulid::from(4_u128).to_bytes().to_vec()),
            |fields| fields[8] = Value::Integer(2_u64.into()),
            |fields| replace_event_field(fields, 5, Value::Integer(2_u64.into())),
            |fields| replace_event_field(fields, 9, Value::Null),
            |fields| {
                replace_event_field(
                    fields,
                    10,
                    Value::Array(vec![Value::Text("source".to_owned())]),
                );
            },
            |fields| replace_identity_field(fields, 0, Value::Text(String::new())),
            |fields| replace_identity_field(fields, 1, Value::Integer(256_u64.into())),
            |fields| replace_identity_field(fields, 1, Value::Integer(255_u64.into())),
            |fields| replace_identity_field(fields, 2, Value::Integer(0_u64.into())),
            |fields| {
                replace_event_field(fields, 2, Value::Text("x".repeat(MAX_EVENT_TYPE_BYTES + 1)));
            },
        ];
        let mut rng = StdRng::from_seed([18; 32]);
        for edit in edits {
            let malformed = rewrite_payload(&payload, edit)?;
            let encoded = encrypt_payload(&malformed, recipient, [5; 16], &mut rng)?;
            assert!(decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private).is_err());
        }
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_public_header_and_authenticated_payload_disagreements(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let source = export(None, b"source".to_vec());
        let mut rng = StdRng::from_seed([19; 32]);
        let encoded = encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng)?.encode();

        let header_edits: [fn(&mut Vec<Value>); 4] = [
            |fields| {
                if let Value::Array(header) = &mut fields[5] {
                    header.truncate(9);
                }
            },
            |fields| {
                if let Value::Array(header) = &mut fields[5] {
                    header[4] = Value::Text(String::new());
                }
            },
            |fields| {
                if let Value::Array(header) = &mut fields[5] {
                    header[5] = Value::Integer(1_u64.into());
                }
            },
            |fields| {
                if let Value::Array(header) = &mut fields[5] {
                    header[9] = Value::Integer(u64::MAX.into());
                }
            },
        ];
        for edit in header_edits {
            let malformed = rewrite_envelope(&encoded, edit)?;
            assert!(RecipientTimelineExportV1::decode(&malformed).is_err());
        }

        let payload = encode_payload(&source)?;
        let mut noncanonical = Vec::with_capacity(payload.len() + 1);
        noncanonical.extend_from_slice(&[0x98, 11]);
        noncanonical.extend_from_slice(&payload[1..]);
        let encoded = encrypt_payload(&noncanonical, recipient, [5; 16], &mut rng)?;
        assert!(matches!(
            decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private),
            Err(RecipientExportErrorV1::NonCanonical)
        ));

        let mut fork = export(Some(0), b"source".to_vec());
        fork.parent_fork_hash = None;
        assert_eq!(
            encrypt_timeline_export_v1(&fork, recipient, [5; 16], &mut rng),
            Err(RecipientExportErrorV1::SourceMismatch)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn rejects_scalar_and_empty_structural_forms_at_public_boundaries(
    ) -> Result<(), RecipientExportErrorV1> {
        type EnvelopeEdit = fn(&mut Vec<Value>);

        assert_eq!(
            RecipientTimelineExportV1::decode(&[0]),
            Err(RecipientExportErrorV1::InvalidEncoding)
        );
        assert_eq!(
            RecipientTimelineExportV1::decode(&[0x80]),
            Err(RecipientExportErrorV1::InvalidEncoding)
        );

        let (recipient, private) = recipient()?;
        let source = export(None, b"source".to_vec());
        let mut rng = StdRng::from_seed([20; 32]);
        let encoded = encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng)?.encode();
        let edits: [(EnvelopeEdit, RecipientExportErrorV1); 3] = [
            (
                |fields| fields[0] = Value::Bytes(b"TRX0".to_vec()),
                RecipientExportErrorV1::InvalidEncoding,
            ),
            (
                |fields| fields[7] = Value::Array(vec![Value::Null]),
                RecipientExportErrorV1::InvalidEncoding,
            ),
            (
                |fields| {
                    if let Value::Array(header) = &mut fields[5] {
                        header[0] = Value::Bytes(vec![0; 16]);
                    }
                },
                RecipientExportErrorV1::FieldOutOfBounds,
            ),
        ];
        for (edit, expected) in edits {
            let malformed = rewrite_envelope(&encoded, edit)?;
            assert_eq!(RecipientTimelineExportV1::decode(&malformed), Err(expected));
        }

        assert_eq!(
            encrypt_timeline_export_v1(&source, recipient, [0; 16], &mut rng),
            Err(RecipientExportErrorV1::FieldOutOfBounds)
        );

        for payload in [vec![0], vec![0x80]] {
            let encoded = encrypt_payload(&payload, recipient, [5; 16], &mut rng)?;
            assert!(matches!(
                decrypt_timeline_export_v1(&encoded, [5; 16], recipient, &private),
                Err(RecipientExportErrorV1::InvalidEncoding)
            ));
        }
        Ok(())
    }
}
