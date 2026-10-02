//! Strict deterministic-CBOR helpers shared by the ADR-105 authority records.
//!
//! These extend the parent ADR-099 reader and encoders, so every ADR-105
//! record keeps exactly the same preferred-serialization profile.

use super::{bytes, hash, text, ForkAttributionCodecErrorV1 as Error, Reader};
use crate::{Hash, KeyRoleV1};

/// The single CBOR `null` byte.
pub(super) const NULL: u8 = 0xf6;

impl<'a> Reader<'a> {
    /// Consume one CBOR `null` when it is the next item.
    pub(super) fn null(&mut self) -> bool {
        if self.bytes.get(self.offset) == Some(&NULL) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    /// Read one `bstr .size (1..maximum)` carrier.
    pub(super) fn record(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        self.bytes(maximum).and_then(nonempty)
    }

    /// Read `null / bstr .size (1..maximum)`.
    pub(super) fn optional_record(&mut self, maximum: usize) -> Result<Option<&'a [u8]>, Error> {
        if self.null() {
            Ok(None)
        } else {
            self.record(maximum).map(Some)
        }
    }

    /// Read one definite array head whose count is at most `maximum`, before
    /// any element is allocated.
    pub(super) fn bounded_len(&mut self, maximum: usize) -> Result<usize, Error> {
        self.array_len().and_then(|count| {
            if count > maximum {
                Err(Error::FieldOutOfBounds)
            } else {
                Ok(count)
            }
        })
    }

    /// Read `[0*maximum_count bstr .size (1..maximum_bytes)]`.
    pub(super) fn records(
        &mut self,
        maximum_count: usize,
        maximum_bytes: usize,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let count = self.bounded_len(maximum_count)?;
        (0..count)
            .map(|_| self.record(maximum_bytes).map(<[u8]>::to_vec))
            .collect()
    }

    /// Read exact UTF-8 text of at most `maximum` bytes. Lower bounds belong
    /// to the owning constructor.
    pub(super) fn bounded_text(&mut self, maximum: usize) -> Result<String, Error> {
        // A length that does not fit `usize` is necessarily over the bound.
        let length = usize::try_from(self.head(3)?).unwrap_or(usize::MAX);
        if length > maximum {
            return Err(Error::FieldOutOfBounds);
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| Error::InvalidEncoding)
    }

    /// Read `null / bstr .size 32`.
    pub(super) fn optional_hash(&mut self) -> Result<Option<Hash>, Error> {
        if self.null() {
            Ok(None)
        } else {
            self.hash().map(Some)
        }
    }

    /// Read one small closed code; a value that does not fit `u8` is malformed.
    pub(super) fn code(&mut self) -> Result<u8, Error> {
        self.uint()
            .and_then(|code| u8::try_from(code).map_err(|_| Error::InvalidEncoding))
    }

    /// Read one closed ADR-065 key-role code.
    pub(super) fn role(&mut self) -> Result<KeyRoleV1, Error> {
        self.code()
            .and_then(|code| KeyRoleV1::from_code(code).map_err(|_| Error::InvalidEncoding))
    }
}

/// Reject an empty `bstr .size (1..N)` carrier.
const fn nonempty(value: &[u8]) -> Result<&[u8], Error> {
    if value.is_empty() {
        Err(Error::FieldOutOfBounds)
    } else {
        Ok(value)
    }
}

/// Encode `null / bstr`.
pub(super) fn encode_optional_record(out: &mut Vec<u8>, value: Option<&[u8]>) {
    if let Some(value) = value {
        bytes(out, value);
    } else {
        out.push(NULL);
    }
}

/// Encode `null / bstr .size N`.
pub(super) fn encode_optional_fixed<const N: usize>(out: &mut Vec<u8>, value: Option<[u8; N]>) {
    if let Some(value) = value {
        bytes(out, &value);
    } else {
        out.push(NULL);
    }
}

/// Encode `null / bstr .size 32`.
pub(super) fn encode_optional_hash(out: &mut Vec<u8>, value: Option<Hash>) {
    if let Some(value) = value {
        hash(out, value);
    } else {
        out.push(NULL);
    }
}

/// Encode `null / tstr`.
pub(super) fn encode_optional_text(out: &mut Vec<u8>, value: Option<&str>) {
    if let Some(value) = value {
        text(out, value);
    } else {
        out.push(NULL);
    }
}
