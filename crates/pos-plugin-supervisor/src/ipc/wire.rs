//! Canonical CBOR primitives of the worker IPC envelopes.
//!
//! Reading uses `pos-crypto`'s strict reader, shared with PMF1, PTR1 and
//! PRV1: definite lengths and shortest-form heads only. Writing emits exactly
//! the forms that reader accepts, so a decoded envelope re-encodes to the same
//! bytes.

use pos_crypto::strict_cbor::{Reader, StrictCborError};
use zeroize::Zeroizing;

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
    read_list(reader, max, read_digest)
}

fn read_digest(reader: &mut EnvelopeReader<'_>) -> Decoded<[u8; 32]> {
    reader.bytes()
}

/// The index `code` names in a closed list of `count` entries.
pub(super) fn read_code(reader: &mut EnvelopeReader<'_>, count: usize) -> Decoded<usize> {
    usize::try_from(reader.unsigned()?)
        .ok()
        .filter(|code| *code < count)
        .ok_or(WorkerEnvelopeErrorV1)
}

/// A canonical CBOR writer.
///
/// It stays beside the codec rather than in `pos-crypto`: the existing head
/// writer in `recipient_export` is private to that format. This writer's
/// kill locus is this crate's IPC tests, which assert golden bytes and
/// shortest-form widths.
#[derive(Default)]
pub(super) struct Writer {
    pub(super) bytes: Zeroizing<Vec<u8>>,
    length: usize,
    counting: bool,
}

impl Writer {
    /// Count the immutable envelope before allocating or copying its bytes.
    /// Both passes use the same grammar, and any refused/partial staging is
    /// owned by a zeroizing buffer through its complete lifetime.
    pub(super) fn encode(
        limit: usize,
        write: impl Fn(&mut Self) -> Decoded<()>,
    ) -> Decoded<Zeroizing<Vec<u8>>> {
        let mut counter = Self {
            counting: true,
            ..Self::default()
        };
        write(&mut counter)
            .and_then(|()| require((1..=limit).contains(&counter.length)))
            .and_then(|()| {
                let mut writer = Self {
                    bytes: Zeroizing::new(Vec::with_capacity(counter.length)),
                    ..Self::default()
                };
                write(&mut writer).map(|()| writer.bytes)
            })
    }

    fn push(&mut self, byte: u8) {
        self.length += 1;
        if !self.counting {
            self.bytes.push(byte);
        }
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.length += bytes.len();
        if !self.counting {
            self.bytes.extend_from_slice(bytes);
        }
    }

    fn head(&mut self, major: u8, value: u64) {
        // CBOR's major tag and additional information occupy disjoint bit
        // ranges; addition expresses the canonical initial-byte composition.
        let tag = major << 5;
        let bytes = value.to_be_bytes();
        let (code, width) = match value {
            0..=23 => {
                self.push(tag + bytes[7]);
                return;
            }
            24..=0xff => (0x18, 1),
            0x100..=0xffff => (0x19, 2),
            0x1_0000..=0xffff_ffff => (0x1a, 4),
            _ => (0x1b, 8),
        };
        self.push(tag + code);
        self.extend(&bytes[8 - width..]);
    }

    pub(super) fn unsigned(&mut self, value: u64) -> &mut Self {
        self.head(0, value);
        self
    }

    pub(super) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.head(2, value.len() as u64);
        self.extend(value);
        self
    }

    pub(super) fn text(&mut self, value: &str) -> &mut Self {
        self.head(3, value.len() as u64);
        self.extend(value.as_bytes());
        self
    }

    pub(super) fn array(&mut self, members: usize) -> &mut Self {
        self.head(4, members as u64);
        self
    }

    pub(super) fn boolean(&mut self, value: bool) -> &mut Self {
        self.push(if value { 0xf5 } else { 0xf4 });
        self
    }

    pub(super) fn null(&mut self) -> &mut Self {
        self.push(0xf6);
        self
    }

    /// An array of `items`, each written by `item`.
    pub(super) fn list<T>(
        &mut self,
        items: &[T],
        mut item: impl FnMut(&mut Self, &T),
    ) -> &mut Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_frames_count_exact_bytes_before_writing_without_reallocation() {
        for (size, head) in [
            (0, vec![0x40]),
            (23, vec![0x57]),
            (24, vec![0x58, 24]),
            (255, vec![0x58, 255]),
            (256, vec![0x59, 1, 0]),
            (65_535, vec![0x59, 255, 255]),
            (65_536, vec![0x5a, 0, 1, 0, 0]),
        ] {
            let payload = vec![0x9a; size];
            let mut expected = vec![0x84];
            expected.extend_from_slice(&head);
            expected.extend_from_slice(&payload);
            expected.extend_from_slice(&[0x1b, 255, 255, 255, 255, 255, 255, 255, 255, 0xf5, 0xf6]);
            let encoded = Writer::encode(expected.len(), |writer| {
                let allocation = (!writer.counting).then(|| writer.bytes.as_ptr());
                writer
                    .array(4)
                    .bytes(&payload)
                    .unsigned(u64::MAX)
                    .boolean(true)
                    .null();
                assert_eq!(writer.length, expected.len());
                if let Some(allocation) = allocation {
                    assert_eq!(writer.bytes.as_ptr(), allocation);
                } else {
                    assert!(writer.bytes.is_empty());
                }
                Ok(())
            });
            assert_eq!(
                encoded.as_ref().map(|bytes| bytes.as_slice()),
                Ok(expected.as_slice())
            );
        }
    }

    #[test]
    fn oversized_or_failed_encodings_do_not_escape_owned_staging() {
        let over = Writer::encode(1, |writer| {
            assert!(writer.counting);
            writer.bytes(b"private");
            assert!(writer.bytes.is_empty());
            Ok(())
        });
        assert_eq!(over, Err(WorkerEnvelopeErrorV1));
        assert_eq!(Writer::encode(1, |_| Ok(())), Err(WorkerEnvelopeErrorV1));
        let failed = Writer::encode(64, |writer| {
            writer.bytes(b"private");
            if writer.counting {
                Ok(())
            } else {
                Err(WorkerEnvelopeErrorV1)
            }
        });
        assert_eq!(failed, Err(WorkerEnvelopeErrorV1));
    }
}
