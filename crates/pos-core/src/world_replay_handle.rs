//! ADR-100 WRH1 structural catalog selector for one exact World cut.
//!
//! A decoded handle is not an owner proof, artifact registration, or release
//! capability. Only the installed cut owner can resolve it against its actual
//! visible receipt, catalog and protected-use fence.

use crate::{encode_hash, encode_head, Hash, TimelineId};
use ulid::Ulid;

/// Maximum accepted preferred-CBOR length of one WRH1 handle.
pub const MAX_WORLD_REPLAY_HANDLE_BYTES_V1: usize = 256;

/// Structural WRH1 errors; none reports owner authority or release state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldReplayHandleErrorV1 {
    /// Wrong CBOR shape, type, field width, magic, version or trailing bytes.
    #[error("invalid WRH1 encoding")]
    InvalidEncoding,
    /// The handle exceeds its fixed admission limit.
    #[error("WRH1 exceeds its byte limit")]
    FieldOutOfBounds,
    /// A cut coordinate or required content digest is zero.
    #[error("invalid WRH1 cut or digest")]
    InvalidHandle,
    /// A field used a nonpreferred CBOR width.
    #[error("noncanonical WRH1 encoding")]
    NonCanonical,
}

/// Exact untrusted fields of a selected local World cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldReplayHandleInputV1 {
    /// ADR-093 owner reference of the actual cut owner.
    pub owner_reference: Hash,
    /// Queried Timeline selected by this cut.
    pub timeline_id: TimelineId,
    /// Positive local cut coordinate.
    pub cut_id: u64,
    /// Native LCQ1 digest selected by the cut.
    pub commit_receipt_digest: Hash,
    /// Native WCR1 digest selected by the cut.
    pub recording_receipt_digest: Hash,
    /// Logical head fixed by the cut, including a valid genesis zero.
    pub logical_head: u64,
    /// Stitched-head hash fixed by the cut.
    pub stitched_head_hash: Hash,
}

/// Preferred-CBOR WRH1 selector, still unauthenticated until owner readback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldReplayHandleV1(WorldReplayHandleInputV1);

impl WorldReplayHandleV1 {
    /// Validate the structural cut coordinate and nonzero digest fields.
    ///
    /// # Errors
    /// Rejects zero cut identity or a zero required digest.
    pub fn new(input: WorldReplayHandleInputV1) -> Result<Self, WorldReplayHandleErrorV1> {
        if input.cut_id == 0
            || input.owner_reference == Hash::zero()
            || input.commit_receipt_digest == Hash::zero()
            || input.recording_receipt_digest == Hash::zero()
            || input.stitched_head_hash == Hash::zero()
        {
            Err(WorldReplayHandleErrorV1::InvalidHandle)
        } else {
            Ok(Self(input))
        }
    }

    /// Borrow exact selector fields without claiming an owner lookup.
    #[must_use]
    pub const fn as_input(&self) -> &WorldReplayHandleInputV1 {
        &self.0
    }

    /// Encode the unique nine-field preferred WRH1 representation.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(162);
        bytes.extend_from_slice(&[0x89, 0x44]);
        bytes.extend_from_slice(b"WRH1");
        bytes.push(1);
        encode_hash(&mut bytes, self.0.owner_reference);
        bytes.push(0x50);
        bytes.extend_from_slice(&u128::from(self.0.timeline_id.inner()).to_be_bytes());
        encode_head(&mut bytes, 0, self.0.cut_id);
        encode_hash(&mut bytes, self.0.commit_receipt_digest);
        encode_hash(&mut bytes, self.0.recording_receipt_digest);
        encode_head(&mut bytes, 0, self.0.logical_head);
        encode_hash(&mut bytes, self.0.stitched_head_hash);
        bytes
    }

    /// Decode one bounded, exact preferred WRH1 selector.
    ///
    /// # Errors
    /// Rejects malformed, oversized, nonpreferred or invalid fields.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, WorldReplayHandleErrorV1> {
        if bytes.len() > MAX_WORLD_REPLAY_HANDLE_BYTES_V1 {
            return Err(WorldReplayHandleErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader {
            cursor: crate::CborCursor::new(bytes),
        };
        reader.handle().and_then(|handle| {
            if !reader.cursor.is_finished() {
                Err(WorldReplayHandleErrorV1::InvalidEncoding)
            } else if handle.to_canonical_cbor() != bytes {
                Err(WorldReplayHandleErrorV1::NonCanonical)
            } else {
                Ok(handle)
            }
        })
    }
}

struct Reader<'a> {
    cursor: crate::CborCursor<'a>,
}

impl Reader<'_> {
    fn handle(&mut self) -> Result<WorldReplayHandleV1, WorldReplayHandleErrorV1> {
        let mut input = WorldReplayHandleInputV1 {
            owner_reference: Hash::zero(),
            timeline_id: TimelineId::from_ulid(Ulid::from(0_u128)),
            cut_id: 0,
            commit_receipt_digest: Hash::zero(),
            recording_receipt_digest: Hash::zero(),
            logical_head: 0,
            stitched_head_hash: Hash::zero(),
        };
        self.fixed(&[0x89, 0x44, b'W', b'R', b'H', b'1', 1])
            .and_then(|()| self.hash().map(|value| input.owner_reference = value))
            .and_then(|()| self.timeline().map(|value| input.timeline_id = value))
            .and_then(|()| self.unsigned().map(|value| input.cut_id = value))
            .and_then(|()| self.hash().map(|value| input.commit_receipt_digest = value))
            .and_then(|()| {
                self.hash()
                    .map(|value| input.recording_receipt_digest = value)
            })
            .and_then(|()| self.unsigned().map(|value| input.logical_head = value))
            .and_then(|()| self.hash().map(|value| input.stitched_head_hash = value))
            .and_then(|()| WorldReplayHandleV1::new(input))
    }

    fn fixed(&mut self, expected: &[u8]) -> Result<(), WorldReplayHandleErrorV1> {
        self.cursor
            .fixed(expected)
            .map_err(|_| WorldReplayHandleErrorV1::InvalidEncoding)
    }

    fn hash(&mut self) -> Result<Hash, WorldReplayHandleErrorV1> {
        self.fixed(&[0x58, 0x20]).and_then(|()| {
            self.take(32).map(|bytes| {
                let mut digest = [0; 32];
                digest.copy_from_slice(bytes);
                Hash::from_bytes(digest)
            })
        })
    }

    fn timeline(&mut self) -> Result<TimelineId, WorldReplayHandleErrorV1> {
        self.fixed(&[0x50]).and_then(|()| {
            self.take(16).map(|bytes| {
                let mut value = [0; 16];
                value.copy_from_slice(bytes);
                TimelineId::from_ulid(Ulid::from(u128::from_be_bytes(value)))
            })
        })
    }

    fn unsigned(&mut self) -> Result<u64, WorldReplayHandleErrorV1> {
        self.cursor
            .byte()
            .and_then(|head| match head {
                0..=23 => Ok(u64::from(head)),
                0x18 => self.cursor.number::<1>(),
                0x19 => self.cursor.number::<2>(),
                0x1a => self.cursor.number::<4>(),
                0x1b => self.cursor.number::<8>(),
                _ => Err(crate::CborReadError::InvalidEncoding),
            })
            .map_err(|_| WorldReplayHandleErrorV1::InvalidEncoding)
    }

    fn take(&mut self, length: usize) -> Result<&[u8], WorldReplayHandleErrorV1> {
        self.cursor
            .take(length)
            .map_err(|_| WorldReplayHandleErrorV1::InvalidEncoding)
    }
}
