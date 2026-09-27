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
    pub fn decode(encoded: &[u8]) -> Result<Self, RecipientExportErrorV1> {
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(RecipientExportErrorV1::FieldOutOfBounds);
        }
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
        if chunks.len()
            != usize::try_from(header.chunk_count)
                .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?
        {
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
        let expected_count =
            usize::try_from((self.header.payload_length - 1) / CHUNK_BYTES_U64 + 1)
                .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?;
        if expected_count != self.ciphertext_chunks.len() {
            return Err(RecipientExportErrorV1::FieldOutOfBounds);
        }
        for (index, chunk) in self.ciphertext_chunks.iter().enumerate() {
            let plain_len = chunk
                .len()
                .checked_sub(TAG_BYTES)
                .ok_or(RecipientExportErrorV1::FieldOutOfBounds)?;
            let is_final = index + 1 == self.ciphertext_chunks.len();
            if (!is_final && plain_len != CHUNK_BYTES)
                || (is_final && !(1..=CHUNK_BYTES).contains(&plain_len))
            {
                return Err(RecipientExportErrorV1::FieldOutOfBounds);
            }
        }
        Ok(())
    }
}

/// Encrypt one complete TEP1 own-segment export into a new TRX1 envelope.
///
/// `export_id` is host supplied so the host can create and reserve it inside
/// its publication transaction. It must be fresh and nonzero.
pub fn encrypt_timeline_export_v1(
    export: &TimelineExport,
    recipient: RecipientKeyDescriptorV1,
    export_id: [u8; 16],
    rng: &mut impl CryptoRng,
) -> Result<RecipientTimelineExportV1, RecipientExportErrorV1> {
    let payload = Zeroizing::new(encode_payload(export)?);
    let payload_length =
        u64::try_from(payload.len()).map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?;
    let chunk_count = u32::try_from(payload.len().div_ceil(CHUNK_BYTES))
        .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?;
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
    envelope.validate_shape().or_else(|_| {
        // A newly constructed envelope has no chunks; validate the public header separately.
        validate_header(&envelope.header)
    })?;
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
    envelope.enc = enc
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| RecipientExportErrorV1::EncryptionFailed)?;
    for (index, plaintext) in payload.chunks(CHUNK_BYTES).enumerate() {
        let aad = chunk_aad(
            header_digest,
            u32::try_from(index).map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?,
            index + 1
                == usize::try_from(chunk_count)
                    .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?,
        );
        envelope.ciphertext_chunks.push(
            context
                .seal(plaintext, &aad)
                .map_err(|_| RecipientExportErrorV1::EncryptionFailed)?,
        );
    }
    envelope.validate_shape()?;
    Ok(envelope)
}

/// Authenticate and decode TRX1, returning only a structural candidate export.
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
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        usize::try_from(envelope.header.payload_length)
            .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?,
    ));
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
    if plaintext.len()
        != usize::try_from(envelope.header.payload_length)
            .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?
    {
        return Err(RecipientExportErrorV1::AuthenticationFailed);
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
    if bytes.is_empty() || bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
    preflight_cbor(
        bytes,
        MAX_EVENTS.saturating_mul(13),
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
    if raw_events.len() > MAX_EVENTS {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
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
        (None, None) => {}
        (Some((_, _)), Some(_)) => {}
        _ => return Err(RecipientExportErrorV1::SourceMismatch),
    }
    for (index, event) in export.events.iter().enumerate() {
        if event.seq.as_u64()
            != u64::try_from(index + 1).map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?
            || event.payload.len() > MAX_EVENT_PAYLOAD_BYTES
            || !(1..=MAX_EVENT_TYPE_BYTES).contains(&event.event_type.as_str().len())
            || event.signature.is_some() != event.signature_identity.is_some()
        {
            return Err(RecipientExportErrorV1::FieldOutOfBounds);
        }
    }
    if export.timeline.head.as_u64()
        != u64::try_from(export.events.len())
            .map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?
    {
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
    };
    match event.signature_identity {
        Some(identity) => {
            array(out, 3);
            text(out, identity.owner_id.as_str());
            unsigned_to(out, u64::from(identity.role.code()));
            unsigned_to(out, identity.epoch);
        }
        None => out.push(0xf6),
    };
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
    let payload = bytes(&fields[3])?;
    if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
        return Err(RecipientExportErrorV1::FieldOutOfBounds);
    }
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
fn mode_code(mode: TimelineMode) -> u64 {
    match mode {
        TimelineMode::Historical => 0,
        TimelineMode::Live => 1,
        TimelineMode::Future => 2,
    }
}
fn decode_mode(value: u64) -> Result<TimelineMode, RecipientExportErrorV1> {
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
        24..=0xff => out.extend_from_slice(&[tag | 24, bytes[7]]),
        0x100..=0xffff => {
            out.push(tag | 25);
            out.extend_from_slice(&bytes[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            out.push(tag | 26);
            out.extend_from_slice(&bytes[4..]);
        }
        _ => {
            out.push(tag | 27);
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
            let length =
                usize::try_from(length).map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?;
            if length > max_string_bytes {
                return Err(RecipientExportErrorV1::FieldOutOfBounds);
            }
            let end = position
                .checked_add(length)
                .ok_or(RecipientExportErrorV1::FieldOutOfBounds)?;
            if end > bytes.len() {
                return Err(RecipientExportErrorV1::InvalidEncoding);
            }
            *position = end;
            Ok(())
        }
        4 => {
            let length =
                usize::try_from(length).map_err(|_| RecipientExportErrorV1::FieldOutOfBounds)?;
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
        7 if matches!(initial, 0xf4 | 0xf5 | 0xf6) => Ok(()),
        _ => Err(RecipientExportErrorV1::InvalidEncoding),
    }
}

fn scan_argument(
    bytes: &[u8],
    position: &mut usize,
    additional: u8,
) -> Result<u64, RecipientExportErrorV1> {
    let width = match additional {
        0..=23 => return Ok(u64::from(additional)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(RecipientExportErrorV1::InvalidEncoding),
    };
    let end = position
        .checked_add(width)
        .ok_or(RecipientExportErrorV1::FieldOutOfBounds)?;
    let slice = bytes
        .get(*position..end)
        .ok_or(RecipientExportErrorV1::InvalidEncoding)?;
    *position = end;
    match width {
        1 => Ok(u64::from(slice[0])),
        2 => Ok(u64::from(u16::from_be_bytes([slice[0], slice[1]]))),
        4 => Ok(u64::from(u32::from_be_bytes([
            slice[0], slice[1], slice[2], slice[3],
        ]))),
        8 => Ok(u64::from_be_bytes(
            slice
                .try_into()
                .map_err(|_| RecipientExportErrorV1::InvalidEncoding)?,
        )),
        _ => Err(RecipientExportErrorV1::InvalidEncoding),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::recipient_key::derive_recipient_keypair_v1;
    use rand::{rngs::StdRng, SeedableRng};

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
        Event {
            id: EventId::from_ulid(id(100 + u128::from(sequence))),
            entity: EntityId::from_ulid(id(200)),
            event_type: Kind::new("test.event"),
            payload: CanonicalBytes::from_vec(payload.clone()),
            wall_time: WallTime::from_micros(sequence),
            seq: Seq::from_u64(sequence),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes(*blake3::hash(&payload).as_bytes()),
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
    fn uses_ordered_chunks_and_releases_no_plaintext_on_failure(
    ) -> Result<(), RecipientExportErrorV1> {
        let (recipient, private) = recipient()?;
        let source = export(None, vec![3; CHUNK_BYTES + 1]);
        let mut rng = StdRng::from_seed([7; 32]);
        let mut envelope = encrypt_timeline_export_v1(&source, recipient, [5; 16], &mut rng)?;
        assert_eq!(envelope.ciphertext_chunks.len(), 2);
        envelope.ciphertext_chunks.swap(0, 1);
        assert_eq!(
            decrypt_timeline_export_v1(&envelope.encode(), [5; 16], recipient, &private),
            Err(RecipientExportErrorV1::AuthenticationFailed)
        );
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
        assert_eq!(
            decrypt_timeline_export_v1(&encoded, [4; 16], recipient, &private),
            Err(RecipientExportErrorV1::IdentityMismatch)
        );
        let mut noncanonical = Vec::with_capacity(encoded.len() + 1);
        noncanonical.extend_from_slice(&[0x98, 8]);
        noncanonical.extend_from_slice(&encoded[1..]);
        assert_eq!(
            RecipientTimelineExportV1::decode(&noncanonical),
            Err(RecipientExportErrorV1::NonCanonical)
        );
        Ok(())
    }
}
