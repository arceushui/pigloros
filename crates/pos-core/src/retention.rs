//! Immutable ADR-078 retention records. Decoding is structural validation,
//! never consent, inherited-source admission or protected-use authority.

use crate::{Hash, TimelineId};

/// Outer bound for either canonical RTP1 or RLS1 record.
pub const MAX_WORLD_RETENTION_RECORD_BYTES_V1: usize = 512;

const DAY_MICROS: u64 = 86_400_000_000;

/// Closed structural and canonical encoding failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WorldRetentionErrorV1 {
    #[error("invalid retention encoding")]
    InvalidEncoding,
    #[error("noncanonical retention encoding")]
    NonCanonical,
    #[error("unsupported retention value")]
    UnsupportedValue,
    #[error("retention field out of bounds")]
    FieldOutOfBounds,
    #[error("incompatible retention window")]
    InvalidWindow,
    #[error("retention policy identity mismatch")]
    PolicyMismatch,
}

/// Untrusted policy fields; only the immutable validated record has an identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldRetentionPolicyInputV1 {
    pub policy_revision: u32,
    pub purpose: String,
    pub audience_policy_hash: Hash,
    pub minimum_post_admission_days: u16,
    pub maximum_active_days: u16,
    pub maximum_total_days: u16,
}

/// Structurally validated RTP1 policy, without host authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldRetentionPolicyV1(WorldRetentionPolicyInputV1);

impl WorldRetentionPolicyV1 {
    /// Validate the ADR-078 finite policy constraints.
    ///
    /// # Errors
    /// Rejects empty/oversized purpose, zero revision/hash and invalid day bounds.
    pub fn new(input: WorldRetentionPolicyInputV1) -> Result<Self, WorldRetentionErrorV1> {
        if input.policy_revision == 0
            || input.purpose.is_empty()
            || input.purpose.len() > 128
            || input.audience_policy_hash == Hash::zero()
            || input.minimum_post_admission_days < 90
            || input.maximum_active_days == 0
        {
            return Err(WorldRetentionErrorV1::FieldOutOfBounds);
        }
        input
            .minimum_post_admission_days
            .checked_add(input.maximum_active_days)
            .filter(|minimum_total| input.maximum_total_days >= *minimum_total)
            .ok_or(WorldRetentionErrorV1::InvalidWindow)
            .map(|_| Self(input))
    }

    /// Borrow validated fields without allowing mutation of the policy.
    #[must_use]
    pub const fn as_input(&self) -> &WorldRetentionPolicyInputV1 {
        &self.0
    }

    /// Encode the exact ten-field preferred RTP1 representation.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = &self.0;
        let mut out = vec![0x8a, 0x44];
        out.extend_from_slice(b"RTP1");
        out.push(1);
        encode_uint(&mut out, u64::from(input.policy_revision));
        encode_text(&mut out, &input.purpose);
        out.extend_from_slice(&[0x58, 32]);
        out.extend_from_slice(input.audience_policy_hash.as_bytes());
        encode_uint(&mut out, u64::from(input.minimum_post_admission_days));
        encode_uint(&mut out, u64::from(input.maximum_active_days));
        encode_uint(&mut out, u64::from(input.maximum_total_days));
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// Ordinary domain-separated BLAKE3 over the exact canonical policy bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        record_digest(b"pigloros.retention-policy.v1\0", &self.to_canonical_cbor())
    }

    /// Decode the bounded fixed shape before allocating its purpose string.
    ///
    /// # Errors
    /// Rejects malformed, unsupported, incompatible, oversized or noncanonical bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, WorldRetentionErrorV1> {
        let mut reader = Reader::new(bytes)?;
        reader.record_header(10, *b"RTP1")?;
        let input = WorldRetentionPolicyInputV1 {
            policy_revision: reader.uint32()?,
            purpose: reader.text()?,
            audience_policy_hash: Hash::from_bytes(reader.blob()?),
            minimum_post_admission_days: reader.uint16()?,
            maximum_active_days: reader.uint16()?,
            maximum_total_days: reader.uint16()?,
        };
        if reader.head(0)? != 0 || reader.head(0)? != 0 {
            return Err(WorldRetentionErrorV1::UnsupportedValue);
        }
        Self::new(input).and_then(|policy| {
            require_canonical(bytes, &policy.to_canonical_cbor()).map(|()| policy)
        })
    }
}

/// Untrusted concrete lease fields, including its exact referenced policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldRetentionLeaseInputV1 {
    pub timeline_id: TimelineId,
    pub policy_hash: Hash,
    pub started_at_micros: u64,
    pub admission_closes_at_micros: u64,
    pub retention_deadline_micros: u64,
}

/// Structurally validated RLS1 lease; it cannot grant access or renew consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldRetentionLeaseV1(WorldRetentionLeaseInputV1);

impl WorldRetentionLeaseV1 {
    /// Bind the exact policy and validate the actual positive admission window.
    ///
    /// # Errors
    /// Rejects a mismatched policy, reversed/zero window or policy-span violation.
    pub fn new(
        policy: &WorldRetentionPolicyV1,
        input: WorldRetentionLeaseInputV1,
    ) -> Result<Self, WorldRetentionErrorV1> {
        if input.policy_hash != policy.digest() {
            return Err(WorldRetentionErrorV1::PolicyMismatch);
        }
        if input.started_at_micros >= input.admission_closes_at_micros
            || input.admission_closes_at_micros > input.retention_deadline_micros
        {
            return Err(WorldRetentionErrorV1::InvalidWindow);
        }
        let terms = policy.as_input();
        if input.admission_closes_at_micros - input.started_at_micros
            > u64::from(terms.maximum_active_days) * DAY_MICROS
            || input.retention_deadline_micros - input.started_at_micros
                > u64::from(terms.maximum_total_days) * DAY_MICROS
            || input.retention_deadline_micros - input.admission_closes_at_micros
                < u64::from(terms.minimum_post_admission_days) * DAY_MICROS
        {
            return Err(WorldRetentionErrorV1::InvalidWindow);
        }
        Ok(Self(input))
    }

    /// Borrow validated fields without allowing mutation of the lease.
    #[must_use]
    pub const fn as_input(&self) -> &WorldRetentionLeaseInputV1 {
        &self.0
    }

    /// Encode the exact seven-field preferred RLS1 representation.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = &self.0;
        let mut out = vec![0x87, 0x44];
        out.extend_from_slice(b"RLS1");
        out.extend_from_slice(&[1, 0x50]);
        out.extend_from_slice(&input.timeline_id.inner().to_bytes());
        out.extend_from_slice(&[0x58, 32]);
        out.extend_from_slice(input.policy_hash.as_bytes());
        encode_uint(&mut out, input.started_at_micros);
        encode_uint(&mut out, input.admission_closes_at_micros);
        encode_uint(&mut out, input.retention_deadline_micros);
        out
    }

    /// Ordinary domain-separated BLAKE3 over the exact canonical lease bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        record_digest(b"pigloros.retention-lease.v1\0", &self.to_canonical_cbor())
    }

    /// Decode a bounded lease against the exact supplied validated policy.
    ///
    /// # Errors
    /// Rejects malformed, unsupported, mismatched, invalid or noncanonical records.
    pub fn from_canonical_cbor(
        bytes: &[u8],
        policy: &WorldRetentionPolicyV1,
    ) -> Result<Self, WorldRetentionErrorV1> {
        let mut reader = Reader::new(bytes)?;
        reader.record_header(7, *b"RLS1")?;
        let input = WorldRetentionLeaseInputV1 {
            timeline_id: TimelineId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(
                reader.blob()?,
            ))),
            policy_hash: Hash::from_bytes(reader.blob()?),
            started_at_micros: reader.head(0)?,
            admission_closes_at_micros: reader.head(0)?,
            retention_deadline_micros: reader.head(0)?,
        };
        Self::new(policy, input)
            .and_then(|lease| require_canonical(bytes, &lease.to_canonical_cbor()).map(|()| lease))
    }
}

fn require_canonical(bytes: &[u8], encoded: &[u8]) -> Result<(), WorldRetentionErrorV1> {
    if bytes == encoded {
        Ok(())
    } else {
        Err(WorldRetentionErrorV1::NonCanonical)
    }
}

fn record_digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn encode_text(out: &mut Vec<u8>, text: &str) {
    // Validated purpose is at most128 bytes, so its low byte is its full length.
    let length = text.len().to_le_bytes()[0];
    if length <= 23 {
        out.push(0x60 | length);
    } else {
        out.extend_from_slice(&[0x78, length]);
    }
    out.extend_from_slice(text.as_bytes());
}

fn encode_uint(out: &mut Vec<u8>, value: u64) {
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => out.push(bytes[7]),
        24..=255 => out.extend_from_slice(&[0x18, bytes[7]]),
        256..=65_535 => {
            out.push(0x19);
            out.extend_from_slice(&bytes[6..]);
        }
        65_536..=4_294_967_295 => {
            out.push(0x1a);
            out.extend_from_slice(&bytes[4..]);
        }
        _ => {
            out.push(0x1b);
            out.extend_from_slice(&bytes);
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Result<Self, WorldRetentionErrorV1> {
        if bytes.len() > MAX_WORLD_RETENTION_RECORD_BYTES_V1 {
            Err(WorldRetentionErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self { bytes, offset: 0 })
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WorldRetentionErrorV1> {
        // Every requested length is bounded by128, and offset by the512-byte record.
        let end = self.offset + length;
        self.bytes
            .get(self.offset..end)
            .ok_or(WorldRetentionErrorV1::InvalidEncoding)
            .inspect(|_| self.offset = end)
    }

    fn head(&mut self, major: u8) -> Result<u64, WorldRetentionErrorV1> {
        let initial = self.take(1)?[0];
        if initial >> 5 != major {
            return Err(WorldRetentionErrorV1::InvalidEncoding);
        }
        match initial & 31 {
            argument @ 0..=23 => Ok(u64::from(argument)),
            argument @ 24..=27 => self.take(1usize << (argument - 24)).map(|bytes| {
                bytes
                    .iter()
                    .fold(0, |value, byte| (value << 8) | u64::from(*byte))
            }),
            _ => Err(WorldRetentionErrorV1::InvalidEncoding),
        }
    }

    fn record_header(&mut self, count: u64, magic: [u8; 4]) -> Result<(), WorldRetentionErrorV1> {
        if self.head(4)? != count || self.blob::<4>()? != magic {
            return Err(WorldRetentionErrorV1::InvalidEncoding);
        }
        if self.head(0)? != 1 {
            return Err(WorldRetentionErrorV1::UnsupportedValue);
        }
        Ok(())
    }

    fn uint32(&mut self) -> Result<u32, WorldRetentionErrorV1> {
        u32::try_from(self.head(0)?).map_err(|_| WorldRetentionErrorV1::FieldOutOfBounds)
    }

    fn uint16(&mut self) -> Result<u16, WorldRetentionErrorV1> {
        u16::try_from(self.head(0)?).map_err(|_| WorldRetentionErrorV1::FieldOutOfBounds)
    }

    fn blob<const N: usize>(&mut self) -> Result<[u8; N], WorldRetentionErrorV1> {
        // Only fixed native lengths4,16 and32 are instantiated.
        if self.head(2)? != u64::from(N.to_le_bytes()[0]) {
            return Err(WorldRetentionErrorV1::InvalidEncoding);
        }
        self.take(N).map(|bytes| {
            let mut out = [0; N];
            out.copy_from_slice(bytes);
            out
        })
    }

    fn text(&mut self) -> Result<String, WorldRetentionErrorV1> {
        let length = self.head(3)?;
        if length > 128 {
            return Err(WorldRetentionErrorV1::FieldOutOfBounds);
        }
        self.take(usize::from(length.to_le_bytes()[0]))
            .and_then(|bytes| {
                std::str::from_utf8(bytes)
                    .map(str::to_owned)
                    .map_err(|_| WorldRetentionErrorV1::InvalidEncoding)
            })
    }
}
