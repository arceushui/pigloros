//! Shared strict deterministic CBOR reader (ADR-103 profile, ADR-061 PMF1 V1).
//!
//! Every reader accepts only definite-length, shortest-form items. Callers
//! map failures onto their own closed error through `StrictCborError`; a
//! reader reports each failure at the record field ordinal last selected with
//! `Reader::at`, so records without per-field errors simply ignore it.

use std::marker::PhantomData;

/// Maps one reader failure at a record field onto a caller's closed error.
pub trait StrictCborError {
    /// A truncated, non-shortest, indefinite, or wrongly typed item.
    fn invalid_encoding(ordinal: u8) -> Self;
    /// A collection count or text length above its maximum.
    fn bounds_exceeded(ordinal: u8) -> Self;
}

/// A strict reader over one complete canonical record.
pub struct Reader<'a, E> {
    bytes: &'a [u8],
    offset: usize,
    ordinal: u8,
    error: PhantomData<fn() -> E>,
}

impl<'a, E: StrictCborError> Reader<'a, E> {
    /// A reader over `bytes`, reporting failures at ordinal 0.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            ordinal: 0,
            error: PhantomData,
        }
    }

    /// Report later failures at record field `ordinal`.
    pub const fn at(&mut self, ordinal: u8) {
        self.ordinal = ordinal;
    }

    /// The record field ordinal that failures are reported at.
    #[must_use]
    pub const fn ordinal(&self) -> u8 {
        self.ordinal
    }

    /// The number of bytes consumed so far.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// The invalid-encoding error at the current ordinal.
    #[must_use]
    pub fn invalid(&self) -> E {
        E::invalid_encoding(self.ordinal)
    }

    /// The bounds-exceeded error at the current ordinal.
    #[must_use]
    pub fn exceeded(&self) -> E {
        E::bounds_exceeded(self.ordinal)
    }

    fn byte(&mut self) -> Result<u8, E> {
        let Some(&byte) = self.bytes.get(self.offset) else {
            return Err(self.invalid());
        };
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], E> {
        if count > self.bytes.len() - self.offset {
            return Err(self.invalid());
        }
        let end = self.offset + count;
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    /// Read one shortest-form item head as `(major type, argument)`.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for a truncated head, a reserved or
    /// indefinite additional-information value, or an argument that is not in
    /// its shortest form.
    pub fn head(&mut self) -> Result<(u8, u64), E> {
        let first = self.byte()?;
        let small = first & 31;
        let (width, minimum) = match small {
            0..=23 => return Ok((first >> 5, u64::from(small))),
            24 => (1, 24),
            25 => (2, 0x100),
            26 => (4, 0x1_0000),
            27 => (8, 0x1_0000_0000),
            _ => return Err(self.invalid()),
        };
        let mut buffer = [0; 8];
        buffer[8 - width..].copy_from_slice(self.take(width)?);
        let value = u64::from_be_bytes(buffer);
        if value < minimum {
            return Err(self.invalid());
        }
        Ok((first >> 5, value))
    }

    fn bounded(&self, count: u64, max: usize) -> Result<usize, E> {
        usize::try_from(count)
            .ok()
            .filter(|count| *count <= max)
            .ok_or_else(|| self.exceeded())
    }

    /// Read a definite array header whose count is at most `max`.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is not a definite
    /// array, and the bounds error for a count above `max`.
    pub fn array(&mut self, max: usize) -> Result<usize, E> {
        let (major, count) = self.head()?;
        if major != 4 {
            return Err(self.invalid());
        }
        self.bounded(count, max)
    }

    /// Read a definite array header with exactly `members` members.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is not a definite
    /// array of exactly `members` members.
    pub fn fixed_array(&mut self, members: u64) -> Result<(), E> {
        if self.head()? == (4, members) {
            Ok(())
        } else {
            Err(self.invalid())
        }
    }

    /// Read an unsigned integer.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is not an unsigned
    /// integer.
    pub fn unsigned(&mut self) -> Result<u64, E> {
        let (major, value) = self.head()?;
        if major != 0 {
            return Err(self.invalid());
        }
        Ok(value)
    }

    /// Read a signed integer that fits `i64`.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is not an integer
    /// or does not fit `i64`.
    pub fn signed(&mut self) -> Result<i64, E> {
        let (major, value) = self.head()?;
        match major {
            0 => i64::try_from(value).map_err(|_| self.invalid()),
            1 => i64::try_from(value)
                .map(|value| -1 - value)
                .map_err(|_| self.invalid()),
            _ => Err(self.invalid()),
        }
    }

    /// Read valid UTF-8 text of at most `max` bytes.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is not text, a
    /// truncated body or invalid UTF-8, and the bounds error for a length
    /// above `max`.
    pub fn text(&mut self, max: usize) -> Result<&'a str, E> {
        let (major, length) = self.head()?;
        if major != 3 {
            return Err(self.invalid());
        }
        let length = self.bounded(length, max)?;
        std::str::from_utf8(self.take(length)?).map_err(|_| self.invalid())
    }

    /// Read text and report whether it is exactly `expected`.
    ///
    /// A different length is a different value: it is never a bound failure
    /// and the bytes are not read.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is not text, or a
    /// body that is cut short.
    pub fn exact_text(&mut self, expected: &str) -> Result<bool, E> {
        let (major, length) = self.head()?;
        if major != 3 {
            return Err(self.invalid());
        }
        if u64::try_from(expected.len()) != Ok(length) {
            return Ok(false);
        }
        Ok(self.take(expected.len())? == expected.as_bytes())
    }

    /// Read a byte string of at most `max` bytes.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is not a byte
    /// string or a body that is cut short, and the bounds error for a length
    /// above `max`.
    pub fn byte_string(&mut self, max: usize) -> Result<&'a [u8], E> {
        let (major, length) = self.head()?;
        if major != 2 {
            return Err(self.invalid());
        }
        let length = self.bounded(length, max)?;
        self.take(length)
    }

    /// Read a byte string of exactly `N` bytes.
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is not a byte
    /// string of exactly `N` bytes.
    pub fn bytes<const N: usize>(&mut self) -> Result<[u8; N], E> {
        let (major, length) = self.head()?;
        if major != 2 || usize::try_from(length) != Ok(N) {
            return Err(self.invalid());
        }
        let mut value = [0; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    /// Consume a CBOR `null` when it is the next item.
    pub fn null(&mut self) -> bool {
        let null = self.bytes.get(self.offset) == Some(&0xf6);
        self.offset += usize::from(null);
        null
    }

    /// Read CBOR `null` or a byte string of exactly `N` bytes.
    ///
    /// # Errors
    /// As [`Self::bytes`], when the item is not `null`.
    pub fn optional_bytes<const N: usize>(&mut self) -> Result<Option<[u8; N]>, E> {
        if self.null() {
            Ok(None)
        } else {
            self.bytes::<N>().map(Some)
        }
    }

    /// Read CBOR `false` (`0xf4`) or `true` (`0xf5`).
    ///
    /// # Errors
    /// Returns the invalid-encoding error for an item that is neither `false`
    /// nor `true`.
    pub fn boolean(&mut self) -> Result<bool, E> {
        match self.byte()? {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(self.invalid()),
        }
    }

    /// Require that every byte was consumed.
    ///
    /// # Errors
    /// Returns the invalid-encoding error when bytes remain after the last
    /// item.
    pub fn finish(&self) -> Result<(), E> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(self.invalid())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    enum Fault {
        Invalid,
        Exceeded,
    }

    impl StrictCborError for Fault {
        fn invalid_encoding(_ordinal: u8) -> Self {
            Self::Invalid
        }

        fn bounds_exceeded(_ordinal: u8) -> Self {
            Self::Exceeded
        }
    }

    fn reader(bytes: &[u8]) -> Reader<'_, Fault> {
        Reader::new(bytes)
    }

    #[test]
    fn byte_strings_are_read_up_to_their_bound() {
        let mut empty = reader(&[0x40]);
        assert_eq!(empty.byte_string(0), Ok(&[][..]));
        let mut exact = reader(&[0x43, 1, 2, 3]);
        assert_eq!(exact.byte_string(3), Ok(&[1, 2, 3][..]));
        assert_eq!(exact.finish(), Ok(()));
        let mut long = reader(&[0x58, 0x19, 0]);
        assert_eq!(long.byte_string(24), Err(Fault::Exceeded));
        let mut wide = reader(&[0x58, 0x18]);
        assert_eq!(wide.byte_string(23), Err(Fault::Exceeded));
    }

    #[test]
    fn byte_strings_reject_other_items_and_cut_bodies() {
        for (bytes, fault) in [
            (&[0x61, b'a'][..], Fault::Invalid),
            (&[0x81, 0x00], Fault::Invalid),
            (&[0x42, 1], Fault::Invalid),
            (&[0x58, 0x01, 1], Fault::Invalid),
            (&[0x5f, 0xff], Fault::Invalid),
            (&[], Fault::Invalid),
        ] {
            assert_eq!(reader(bytes).byte_string(8), Err(fault), "{bytes:?}");
        }
    }

    #[test]
    fn finish_reports_trailing_bytes() {
        let mut one = reader(&[0x01, 0x02]);
        assert_eq!(one.unsigned(), Ok(1));
        assert_eq!(one.finish(), Err(Fault::Invalid));
        assert_eq!(one.unsigned(), Ok(2));
        assert_eq!(one.finish(), Ok(()));
    }
}
