//! ADR-097 `SubjectCiphertextV1` (SDC1): one AES-256-GCM subject field bound
//! to its subject key identity, its committed Event, and that Event's
//! canonical clear header (ADR-097 revision 3, section 2).
//!
//! This module is pure cryptography. Reserving the nonce counter durably
//! before encryption, Event schema registration, and the Gateway and store
//! integration belong to the owner adapter and #399's later seams.

use pos_core::{EntityId, EventId, KeyRoleV1, TimelineEventEnvelopeInputV1, TimelineId};
use thiserror::Error;
use ulid::Ulid;
use zeroize::Zeroizing;

use crate::strict_cbor::{Reader, StrictCborError};
use crate::subject_cbor;
use crate::subject_key::{owner_string, SubjectKeyUseV1, SubjectSubkeyV1, SUBJECT_OWNER_BYTES};

/// The largest `SubjectCiphertextV1` encoding, equal to the 256 KiB Event
/// payload bound. A plaintext is therefore also below 256 KiB.
pub const MAX_SUBJECT_CIPHERTEXT_BYTES: usize = 262_144;
/// The largest canonical public header bound into `context_digest`.
pub const MAX_SUBJECT_PUBLIC_HEADER_BYTES: usize = 65_536;
/// The longest `event_type`, in UTF-8 bytes.
pub const MAX_SUBJECT_EVENT_TYPE_BYTES: usize = 256;
/// The longest `field_tag`, in ASCII bytes.
pub const MAX_SUBJECT_FIELD_TAG_BYTES: usize = 128;
/// The project cap on the IV invocation counter; counter zero is never used.
pub const MAX_SUBJECT_NONCE_COUNTER: u64 = 0xffff_ffff;

const MAGIC: [u8; 4] = *b"SDC1";
const CONTEXT_MAGIC: [u8; 4] = *b"SEC1";
const VERSION: u64 = 1;
/// `KeyRoleV1::SubjectDataEncryption`.
const ROLE: u64 = 0;
const CONTEXT_DOMAIN: &[u8] = b"pigloros/subject-context/v1\0";
const TAG_BYTES: usize = 16;
/// The error ordinal of the whole SDC1 encoding and its outer framing.
const DOCUMENT: u8 = 16;

/// A closed `SubjectCiphertextV1` failure.
///
/// `ordinal` is the SDC1 field (0-15): 0 magic, 2 owner, 3 subject, 4 role,
/// 5 epoch, 6 use, 7 origin Timeline, 8 origin logical sequence, 9 Event ID,
/// 10 event type, 11 schema version, 12 field tag, 13 context digest (and the
/// Event context and public header it binds), 14 nonce, and 15 ciphertext.
/// Ordinal 16 is the whole encoding. No variant carries text, bytes,
/// plaintext, or key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SubjectCiphertextErrorV1 {
    /// Truncated, non-shortest, indefinite, or wrongly typed CBOR, a wrong
    /// array cardinality or fixed byte length, or trailing bytes.
    #[error("invalid SDC1 encoding at field {ordinal}")]
    InvalidEncoding {
        /// SDC1 field, or 16 for the encoding.
        ordinal: u8,
    },
    /// A value longer than its V1 bound: the encoding or plaintext above
    /// 256 KiB (16), the public header above 64 KiB (13), the event type
    /// above 256 bytes (10), or the field tag above 128 bytes (12).
    #[error("SDC1 field {ordinal} exceeds a V1 bound")]
    BoundsExceeded {
        /// SDC1 field, or 16 for the encoding.
        ordinal: u8,
    },
    /// A well-typed value outside its allowed value or grammar, including a
    /// wrong magic, a nil identifier, an owner that is not the subject's
    /// owner, a wrong role, epoch or sequence zero, an unknown use, an
    /// empty event type, a field tag that is empty or not ASCII, a context
    /// whose integrity identity is not a positive-epoch
    /// `TimelineIntegritySigning` identity, a nonce or counter outside the
    /// V1 construction, and a ciphertext shorter than its tag.
    #[error("invalid SDC1 field {ordinal}")]
    InvalidField {
        /// SDC1 field.
        ordinal: u8,
    },
    /// Field 1 names a version other than 1.
    #[error("unsupported SDC1 version")]
    UnsupportedVersion,
    /// A ciphertext field differs from the subkey identity (3, 5, 6), the
    /// committed Event (7-11), the requested field tag (12), or the
    /// recomputed context digest (13).
    #[error("SDC1 field {ordinal} differs from its expected context")]
    ContextMismatch {
        /// SDC1 field.
        ordinal: u8,
    },
    /// AES-256-GCM authentication failed; no plaintext is released.
    #[error("SDC1 ciphertext failed authentication")]
    AuthenticationFailed,
}

impl StrictCborError for SubjectCiphertextErrorV1 {
    fn invalid_encoding(ordinal: u8) -> Self {
        Self::InvalidEncoding { ordinal }
    }

    fn bounds_exceeded(ordinal: u8) -> Self {
        Self::BoundsExceeded { ordinal }
    }
}

/// SDC1 fields 3-12, every field that names the key identity, the Event, and
/// the protected field.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Header {
    subject: [u8; 16],
    epoch: u64,
    key_use: SubjectKeyUseV1,
    origin_timeline: [u8; 16],
    origin_logical_seq: u64,
    event_id: [u8; 16],
    event_type: String,
    schema_version: u32,
    field_tag: String,
}

/// One decoded or freshly encrypted `SubjectCiphertextV1`: a deterministic
/// CBOR 16-element array that keeps its exact canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectCiphertextV1 {
    header: Header,
    context_digest: [u8; 32],
    counter: u64,
    ciphertext_and_tag: Vec<u8>,
    bytes: Vec<u8>,
}

impl SubjectCiphertextV1 {
    /// Encrypt one protected field of the finalized Event `event`.
    ///
    /// `counter` must already be durably reserved for `subkey`; the IV is
    /// `0x00000000 || counter_u64_be`. `public_header` is the Event schema's
    /// exact canonical clear header, and `event.entity_id` must be the
    /// subkey's subject.
    ///
    /// # Errors
    /// Returns [`SubjectCiphertextErrorV1::InvalidField`] at 14 for a counter
    /// outside 1 through 2^32 - 1, [`SubjectCiphertextErrorV1::ContextMismatch`]
    /// at 3 for an Event whose entity is not the subkey's subject, the
    /// [`SubjectCiphertextErrorV1`] of an invalid Event context, field tag,
    /// or public header, and [`SubjectCiphertextErrorV1::BoundsExceeded`] at
    /// 16 when the plaintext or the encoding exceeds 256 KiB.
    pub fn encrypt(
        subkey: &SubjectSubkeyV1,
        counter: u64,
        event: &TimelineEventEnvelopeInputV1,
        public_header: &[u8],
        field_tag: &str,
        plaintext: &[u8],
    ) -> Result<Self, SubjectCiphertextErrorV1> {
        if !(1..=MAX_SUBJECT_NONCE_COUNTER).contains(&counter) {
            return Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 14 });
        }
        let header = expected_header(subkey, event, field_tag)?;
        let context_digest = context_digest(event, public_header)?;
        let aad = associated_data(&header, &context_digest, counter);
        let sealed_len = plaintext.len().saturating_add(TAG_BYTES);
        let mut length_head = Vec::new();
        subject_cbor::head(&mut length_head, 2, sealed_len as u64);
        if aad.len() + length_head.len() + sealed_len > MAX_SUBJECT_CIPHERTEXT_BYTES {
            return Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: DOCUMENT });
        }
        let mut ciphertext_and_tag = Vec::with_capacity(sealed_len);
        ciphertext_and_tag.extend_from_slice(plaintext);
        let tag = subject_cbor::aes_gcm_seal(
            subkey.key(),
            &nonce(counter),
            &aad,
            &mut ciphertext_and_tag,
        );
        ciphertext_and_tag.extend_from_slice(&tag);
        let mut bytes = aad;
        bytes[0] = 0x90;
        bytes.extend_from_slice(&length_head);
        bytes.extend_from_slice(&ciphertext_and_tag);
        Ok(Self {
            header,
            context_digest,
            counter,
            ciphertext_and_tag,
            bytes,
        })
    }

    /// Authenticate and decrypt this field of the verified committed Event
    /// `event`.
    ///
    /// Every duplicated field is compared with `subkey`, `event`, and
    /// `field_tag`, and `context_digest` is recomputed from `event` and
    /// `public_header`, before AES-GCM runs.
    ///
    /// # Errors
    /// Returns the [`SubjectCiphertextErrorV1`] of an invalid Event context,
    /// field tag, or public header,
    /// [`SubjectCiphertextErrorV1::ContextMismatch`] at the first field that
    /// differs from its expected value, and
    /// [`SubjectCiphertextErrorV1::AuthenticationFailed`] when the tag does
    /// not verify; no plaintext is released on any error.
    pub fn decrypt(
        &self,
        subkey: &SubjectSubkeyV1,
        event: &TimelineEventEnvelopeInputV1,
        public_header: &[u8],
        field_tag: &str,
    ) -> Result<Zeroizing<Vec<u8>>, SubjectCiphertextErrorV1> {
        let expected = expected_header(subkey, event, field_tag)?;
        if let Some(ordinal) = first_mismatch(&self.header, &expected) {
            return Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal });
        }
        if context_digest(event, public_header)? != self.context_digest {
            return Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal: 13 });
        }
        let split = self.ciphertext_and_tag.len() - TAG_BYTES;
        let mut plaintext = Zeroizing::new(self.ciphertext_and_tag[..split].to_vec());
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(&self.ciphertext_and_tag[split..]);
        if subject_cbor::aes_gcm_open(
            subkey.key(),
            &nonce(self.counter),
            &self.associated_data(),
            plaintext.as_mut_slice(),
            &tag,
        ) {
            Ok(plaintext)
        } else {
            Err(SubjectCiphertextErrorV1::AuthenticationFailed)
        }
    }

    /// Decode exactly one canonical SDC1 encoding of at most 256 KiB.
    ///
    /// # Errors
    /// Returns the [`SubjectCiphertextErrorV1`] of the first oversized,
    /// malformed, noncanonical, unsupported, or invalid field.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SubjectCiphertextErrorV1> {
        if bytes.len() > MAX_SUBJECT_CIPHERTEXT_BYTES {
            return Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: DOCUMENT });
        }
        let mut reader = Reader::new(bytes);
        let (owner, subject, epoch, key_use) = read_identity(&mut reader)?;
        let header = read_event(&mut reader, subject, epoch, key_use)?;
        reader.at(13);
        let context_digest = reader.bytes()?;
        reader.at(14);
        let counter = read_counter(&mut reader)?;
        reader.at(15);
        let ciphertext_and_tag = reader.byte_string(MAX_SUBJECT_CIPHERTEXT_BYTES)?.to_vec();
        reader.at(DOCUMENT);
        reader.finish()?;
        validate_header(&header)?;
        if owner != owner_string(&subject) {
            return Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 2 });
        }
        if ciphertext_and_tag.len() < TAG_BYTES {
            return Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 15 });
        }
        Ok(Self {
            header,
            context_digest,
            counter,
            ciphertext_and_tag,
            bytes: bytes.to_vec(),
        })
    }

    /// The exact canonical 16-element encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The AES-GCM associated data: the standalone deterministic-CBOR array
    /// of the first 15 fields, beginning `0x8f`.
    #[must_use]
    pub fn associated_data(&self) -> Vec<u8> {
        associated_data(&self.header, &self.context_digest, self.counter)
    }

    /// The subject whose subkey encrypted this field.
    #[must_use]
    pub const fn subject_id(&self) -> EntityId {
        EntityId::from_ulid(Ulid::from_bytes(self.header.subject))
    }

    /// The `SubjectDataEncryption` epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.header.epoch
    }

    /// The data or consent-bootstrap subkey use.
    #[must_use]
    pub const fn key_use(&self) -> SubjectKeyUseV1 {
        self.header.key_use
    }

    /// The first-commit origin Timeline.
    #[must_use]
    pub const fn origin_timeline_id(&self) -> TimelineId {
        TimelineId::from_ulid(Ulid::from_bytes(self.header.origin_timeline))
    }

    /// The first-commit origin logical sequence.
    #[must_use]
    pub const fn origin_logical_seq(&self) -> u64 {
        self.header.origin_logical_seq
    }

    /// The Event ID.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        EventId::from_ulid(Ulid::from_bytes(self.header.event_id))
    }

    /// The Event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.header.event_type
    }

    /// The Event schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.header.schema_version
    }

    /// The protected field occurrence.
    #[must_use]
    pub fn field_tag(&self) -> &str {
        &self.header.field_tag
    }

    /// `BLAKE3("pigloros/subject-context/v1\0" || context_bytes)`.
    #[must_use]
    pub const fn context_digest(&self) -> &[u8; 32] {
        &self.context_digest
    }

    /// The IV invocation counter.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// The 96-bit IV `0x00000000 || counter_u64_be`.
    #[must_use]
    pub fn nonce(&self) -> [u8; 12] {
        nonce(self.counter)
    }

    /// The AES-256-GCM ciphertext followed by its 16-byte tag.
    #[must_use]
    pub fn ciphertext_and_tag(&self) -> &[u8] {
        &self.ciphertext_and_tag
    }
}

type Identity<'a> = (&'a str, [u8; 16], u64, SubjectKeyUseV1);

/// Fields 0-6: the framing, magic, version, owner, subject, role, epoch and
/// use.
fn read_identity<'a>(
    reader: &mut Reader<'a, SubjectCiphertextErrorV1>,
) -> Result<Identity<'a>, SubjectCiphertextErrorV1> {
    reader.at(DOCUMENT);
    reader.fixed_array(16)?;
    reader.at(0);
    if reader.bytes::<4>()? != MAGIC {
        return Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 0 });
    }
    reader.at(1);
    if reader.unsigned()? != VERSION {
        return Err(SubjectCiphertextErrorV1::UnsupportedVersion);
    }
    reader.at(2);
    let owner = reader.text(SUBJECT_OWNER_BYTES)?;
    reader.at(3);
    let subject = reader.bytes()?;
    reader.at(4);
    if reader.unsigned()? != ROLE {
        return Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 4 });
    }
    reader.at(5);
    let epoch = reader.unsigned()?;
    reader.at(6);
    let key_use = SubjectKeyUseV1::from_code(reader.unsigned()?)
        .ok_or(SubjectCiphertextErrorV1::InvalidField { ordinal: 6 })?;
    Ok((owner, subject, epoch, key_use))
}

/// Fields 7-12: the Event coordinates and the field tag.
fn read_event(
    reader: &mut Reader<'_, SubjectCiphertextErrorV1>,
    subject: [u8; 16],
    epoch: u64,
    key_use: SubjectKeyUseV1,
) -> Result<Header, SubjectCiphertextErrorV1> {
    reader.at(7);
    let origin_timeline = reader.bytes()?;
    reader.at(8);
    let origin_logical_seq = reader.unsigned()?;
    reader.at(9);
    let event_id = reader.bytes()?;
    reader.at(10);
    let event_type = reader.text(MAX_SUBJECT_EVENT_TYPE_BYTES)?.to_owned();
    reader.at(11);
    let schema_version = u32::try_from(reader.unsigned()?)
        .map_err(|_| SubjectCiphertextErrorV1::InvalidField { ordinal: 11 })?;
    reader.at(12);
    let field_tag = reader.text(MAX_SUBJECT_FIELD_TAG_BYTES)?.to_owned();
    Ok(Header {
        subject,
        epoch,
        key_use,
        origin_timeline,
        origin_logical_seq,
        event_id,
        event_type,
        schema_version,
        field_tag,
    })
}

/// Field 14: a nonce of the V1 form `0x00000000 || counter_u64_be` with a
/// counter from 1 through 2^32 - 1.
fn read_counter(
    reader: &mut Reader<'_, SubjectCiphertextErrorV1>,
) -> Result<u64, SubjectCiphertextErrorV1> {
    let [a, b, c, d, counter @ ..] = reader.bytes::<12>()?;
    let counter = u64::from_be_bytes(counter);
    if [a, b, c, d] == [0; 4] && (1..=MAX_SUBJECT_NONCE_COUNTER).contains(&counter) {
        Ok(counter)
    } else {
        Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 14 })
    }
}

/// The header that `subkey` must produce for `field_tag` of `event`.
fn expected_header(
    subkey: &SubjectSubkeyV1,
    event: &TimelineEventEnvelopeInputV1,
    field_tag: &str,
) -> Result<Header, SubjectCiphertextErrorV1> {
    if event.entity_id != subkey.subject_id() {
        return Err(SubjectCiphertextErrorV1::ContextMismatch { ordinal: 3 });
    }
    let header = Header {
        subject: event.entity_id.inner().to_bytes(),
        epoch: subkey.epoch(),
        key_use: subkey.key_use(),
        origin_timeline: event.origin_timeline_id.inner().to_bytes(),
        origin_logical_seq: event.origin_logical_seq.as_u64(),
        event_id: event.event_id.inner().to_bytes(),
        event_type: event.event_type.as_str().to_owned(),
        schema_version: event.schema_version,
        field_tag: field_tag.to_owned(),
    };
    validate_header(&header).map(|()| header)
}

fn validate_header(header: &Header) -> Result<(), SubjectCiphertextErrorV1> {
    let ordinal = if header.subject == [0; 16] {
        3
    } else if header.epoch == 0 {
        5
    } else if header.origin_timeline == [0; 16] {
        7
    } else if header.origin_logical_seq == 0 {
        8
    } else if header.event_id == [0; 16] {
        9
    } else {
        return validate_names(header);
    };
    Err(SubjectCiphertextErrorV1::InvalidField { ordinal })
}

fn validate_names(header: &Header) -> Result<(), SubjectCiphertextErrorV1> {
    if header.event_type.len() > MAX_SUBJECT_EVENT_TYPE_BYTES {
        Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 10 })
    } else if header.event_type.is_empty() {
        Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 10 })
    } else if header.field_tag.len() > MAX_SUBJECT_FIELD_TAG_BYTES {
        Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 12 })
    } else if header.field_tag.is_empty() || !header.field_tag.is_ascii() {
        Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 12 })
    } else {
        Ok(())
    }
}

/// The first header field, in SDC1 order, that differs from `expected`.
fn first_mismatch(found: &Header, expected: &Header) -> Option<u8> {
    [
        (3, found.subject == expected.subject),
        (5, found.epoch == expected.epoch),
        (6, found.key_use == expected.key_use),
        (7, found.origin_timeline == expected.origin_timeline),
        (8, found.origin_logical_seq == expected.origin_logical_seq),
        (9, found.event_id == expected.event_id),
        (10, found.event_type == expected.event_type),
        (11, found.schema_version == expected.schema_version),
        (12, found.field_tag == expected.field_tag),
    ]
    .into_iter()
    .find_map(|(ordinal, same)| (!same).then_some(ordinal))
}

/// `BLAKE3(domain || context_bytes)` over the 15-element `SEC1` context.
fn context_digest(
    event: &TimelineEventEnvelopeInputV1,
    public_header: &[u8],
) -> Result<[u8; 32], SubjectCiphertextErrorV1> {
    let identity = &event.identity;
    if identity.role != KeyRoleV1::TimelineIntegritySigning || identity.epoch == 0 {
        return Err(SubjectCiphertextErrorV1::InvalidField { ordinal: 13 });
    }
    if public_header.len() > MAX_SUBJECT_PUBLIC_HEADER_BYTES {
        return Err(SubjectCiphertextErrorV1::BoundsExceeded { ordinal: 13 });
    }
    let mut context = Vec::new();
    context.push(0x8f);
    subject_cbor::byte_string(&mut context, &CONTEXT_MAGIC);
    subject_cbor::unsigned(&mut context, VERSION);
    subject_cbor::text(&mut context, identity.owner_id.as_str());
    subject_cbor::byte_string(&mut context, &event.origin_timeline_id.inner().to_bytes());
    subject_cbor::byte_string(&mut context, &event.event_id.inner().to_bytes());
    subject_cbor::unsigned(&mut context, event.origin_logical_seq.as_u64());
    subject_cbor::byte_string(&mut context, &event.entity_id.inner().to_bytes());
    subject_cbor::text(&mut context, event.event_type.as_str());
    subject_cbor::unsigned(&mut context, u64::from(event.schema_version));
    subject_cbor::unsigned(&mut context, event.wall_time.as_micros());
    optional_id(&mut context, event.causation_id.map(|id| id.inner()));
    optional_id(&mut context, event.correlation_id.map(|id| id.inner()));
    subject_cbor::unsigned(&mut context, u64::from(identity.role.code()));
    subject_cbor::unsigned(&mut context, identity.epoch);
    subject_cbor::byte_string(&mut context, public_header);
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTEXT_DOMAIN);
    hasher.update(&context);
    Ok(*hasher.finalize().as_bytes())
}

fn optional_id(output: &mut Vec<u8>, id: Option<Ulid>) {
    let Some(id) = id else {
        output.push(0xf6);
        return;
    };
    subject_cbor::byte_string(output, &id.to_bytes());
}

/// The standalone 15-element AES-GCM associated data.
fn associated_data(header: &Header, context_digest: &[u8; 32], counter: u64) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(0x8f);
    subject_cbor::byte_string(&mut output, &MAGIC);
    subject_cbor::unsigned(&mut output, VERSION);
    subject_cbor::text(&mut output, &owner_string(&header.subject));
    subject_cbor::byte_string(&mut output, &header.subject);
    subject_cbor::unsigned(&mut output, ROLE);
    subject_cbor::unsigned(&mut output, header.epoch);
    subject_cbor::unsigned(&mut output, u64::from(header.key_use.code()));
    subject_cbor::byte_string(&mut output, &header.origin_timeline);
    subject_cbor::unsigned(&mut output, header.origin_logical_seq);
    subject_cbor::byte_string(&mut output, &header.event_id);
    subject_cbor::text(&mut output, &header.event_type);
    subject_cbor::unsigned(&mut output, u64::from(header.schema_version));
    subject_cbor::text(&mut output, &header.field_tag);
    subject_cbor::byte_string(&mut output, context_digest);
    subject_cbor::byte_string(&mut output, &nonce(counter));
    output
}

/// The V1 IV: the zero 32-bit fixed field, then the 64-bit counter, which are
/// exactly the low 96 bits of the counter widened to 128 bits.
fn nonce(counter: u64) -> [u8; 12] {
    let [_, _, _, _, nonce @ ..] = u128::from(counter).to_be_bytes();
    nonce
}
