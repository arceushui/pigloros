//! Canonical CBOR primitives of the worker IPC envelopes.
//!
//! Reading uses `pos-crypto`'s strict reader, shared with PMF1, PTR1 and
//! PRV1: definite lengths and shortest-form heads only. Writing emits exactly
//! the forms that reader accepts, so a decoded envelope re-encodes to the same
//! bytes.

use pos_crypto::strict_cbor::{Reader, StrictCborError};

use super::WorkerEnvelopeErrorV1;

impl StrictCborError for WorkerEnvelopeErrorV1 {
    fn invalid_encoding(_ordinal: u8) -> Self {
        Self
    }

    fn bounds_exceeded(_ordinal: u8) -> Self {
        Self
    }
}

/// The strict reader over one envelope.
pub(super) type EnvelopeReader<'a> = Reader<'a, WorkerEnvelopeErrorV1>;
/// The result of reading one envelope item.
pub(super) type Decoded<T> = Result<T, WorkerEnvelopeErrorV1>;

/// Reject unless `valid`.
pub(super) const fn require(valid: bool) -> Decoded<()> {
    if valid {
        Ok(())
    } else {
        Err(WorkerEnvelopeErrorV1)
    }
}

/// A `u32` item.
pub(super) fn read_u32(reader: &mut EnvelopeReader<'_>) -> Decoded<u32> {
    u32::try_from(reader.unsigned()?).map_err(|_| WorkerEnvelopeErrorV1)
}

/// A `u16` item.
pub(super) fn read_u16(reader: &mut EnvelopeReader<'_>) -> Decoded<u16> {
    u16::try_from(reader.unsigned()?).map_err(|_| WorkerEnvelopeErrorV1)
}

/// Text of at most `max` bytes, owned.
pub(super) fn read_text(reader: &mut EnvelopeReader<'_>, max: usize) -> Decoded<String> {
    reader.text(max).map(str::to_owned)
}

/// A byte string of at most `max` bytes, owned.
pub(super) fn read_bytes(reader: &mut EnvelopeReader<'_>, max: usize) -> Decoded<Vec<u8>> {
    reader.byte_string(max).map(<[u8]>::to_vec)
}

/// An array of at most `max` items, each read by `item`.
pub(super) fn read_list<T>(
    reader: &mut EnvelopeReader<'_>,
    max: usize,
    mut item: impl FnMut(&mut EnvelopeReader<'_>) -> Decoded<T>,
) -> Decoded<Vec<T>> {
    let count = reader.array(max)?;
    (0..count).map(|_| item(reader)).collect()
}

/// An array of at most `max` digests.
pub(super) fn read_digests(reader: &mut EnvelopeReader<'_>, max: usize) -> Decoded<Vec<[u8; 32]>> {
    read_list(reader, max, EnvelopeReader::bytes)
}

/// The index `code` names in a closed list of `count` entries.
pub(super) fn read_code(reader: &mut EnvelopeReader<'_>, count: usize) -> Decoded<usize> {
    usize::try_from(reader.unsigned()?)
        .ok()
        .filter(|code| *code < count)
        .ok_or(WorkerEnvelopeErrorV1)
}

/// A canonical CBOR writer.
#[derive(Default)]
pub(super) struct Writer {
    pub(super) bytes: Vec<u8>,
}

impl Writer {
    fn head(&mut self, major: u8, value: u64) {
        let tag = major << 5;
        let bytes = value.to_be_bytes();
        let (code, width) = match value {
            0..=23 => {
                self.bytes.push(tag | bytes[7]);
                return;
            }
            24..=0xff => (0x18, 1),
            0x100..=0xffff => (0x19, 2),
            0x1_0000..=0xffff_ffff => (0x1a, 4),
            _ => (0x1b, 8),
        };
        self.bytes.push(tag | code);
        self.bytes.extend_from_slice(&bytes[8 - width..]);
    }

    pub(super) fn unsigned(&mut self, value: u64) -> &mut Self {
        self.head(0, value);
        self
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.head(2, value.len() as u64);
        self.bytes.extend_from_slice(value);
        self
    }

    pub(super) fn text(&mut self, value: &str) -> &mut Self {
        self.head(3, value.len() as u64);
        self.bytes.extend_from_slice(value.as_bytes());
        self
    }

    pub(super) fn array(&mut self, members: usize) -> &mut Self {
        self.head(4, members as u64);
        self
    }

    pub(super) fn boolean(&mut self, value: bool) -> &mut Self {
        self.bytes.push(if value { 0xf5 } else { 0xf4 });
        self
    }

    pub(super) fn null(&mut self) -> &mut Self {
        self.bytes.push(0xf6);
        self
    }

    /// An array of `items`, each written by `item`.
    pub(super) fn list<T>(&mut self, items: &[T], mut item: impl FnMut(&mut Self, &T)) -> &mut Self {
        self.array(items.len());
        for value in items {
            item(self, value);
        }
        self
    }

    pub(super) fn digests(&mut self, digests: &[[u8; 32]]) -> &mut Self {
        self.list(digests, |writer, digest| {
            writer.bytes(digest);
        })
    }
}
