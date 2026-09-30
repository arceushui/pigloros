//! Shared bounded cursor mechanics for the crate's structural CBOR codecs.

/// Failure to read a structurally valid CBOR token or byte range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CborReadError {
    InvalidEncoding,
}

/// A small cursor for the bounded definite-length CBOR records owned by `pos-core`.
///
/// Protocol codecs keep their own field bounds, semantic validation, and public
/// errors. This cursor only owns byte movement and basic CBOR head decoding.
pub(crate) struct CborCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CborCursor<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(crate) const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    pub(crate) fn consume_if(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.offset) == Some(&byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], CborReadError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CborReadError::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CborReadError::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }

    pub(crate) fn byte(&mut self) -> Result<u8, CborReadError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn fixed(&mut self, expected: &[u8]) -> Result<(), CborReadError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(CborReadError::InvalidEncoding)
        }
    }

    pub(crate) fn head(&mut self, expected_major: u8) -> Result<u64, CborReadError> {
        let first = self.byte()?;
        if first >> 5 != expected_major {
            return Err(CborReadError::InvalidEncoding);
        }
        match first & 0x1f {
            small @ 0..=23 => Ok(u64::from(small)),
            24 => self.number::<1>(),
            25 => self.number::<2>(),
            26 => self.number::<4>(),
            27 => self.number::<8>(),
            _ => Err(CborReadError::InvalidEncoding),
        }
    }

    pub(crate) fn number<const N: usize>(&mut self) -> Result<u64, CborReadError> {
        self.unsigned_bytes(N)
    }

    pub(crate) fn unsigned_bytes(&mut self, length: usize) -> Result<u64, CborReadError> {
        Ok(self
            .take(length)?
            .iter()
            .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte)))
    }
}
