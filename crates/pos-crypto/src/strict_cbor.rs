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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
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
    /// Returns the caller's error for a truncated, non-canonical, wrongly
    /// typed or out-of-bounds item.
    pub fn finish(&self) -> Result<(), E> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(self.invalid())
        }
    }
}
