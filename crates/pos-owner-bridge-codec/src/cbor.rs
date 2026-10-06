use crate::OwnerBridgeCodecError;

/// Minimal deterministic-CBOR reader for the fixed owner-bridge schemas.
pub(crate) struct CborReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> CborReader<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    pub(crate) fn fixed_array(&mut self, expected: u64) -> Result<(), OwnerBridgeCodecError> {
        let (major, count) = self.head()?;
        if major == 4 && count == expected {
            Ok(())
        } else {
            Err(OwnerBridgeCodecError::InvalidCbor)
        }
    }

    pub(crate) fn array(&mut self, maximum: usize) -> Result<usize, OwnerBridgeCodecError> {
        let (major, count) = self.head()?;
        if major != 4 {
            return Err(OwnerBridgeCodecError::InvalidCbor);
        }
        Self::bounded_count(count, maximum)
    }

    pub(crate) fn unsigned(&mut self) -> Result<u64, OwnerBridgeCodecError> {
        let (major, value) = self.head()?;
        if major == 0 {
            Ok(value)
        } else {
            Err(OwnerBridgeCodecError::InvalidCbor)
        }
    }

    pub(crate) fn signed(&mut self) -> Result<i64, OwnerBridgeCodecError> {
        let (major, value) = self.head()?;
        match major {
            0 => i64::try_from(value).map_err(|_| OwnerBridgeCodecError::InvalidCbor),
            1 => i64::try_from(value)
                .map(|magnitude| -1 - magnitude)
                .map_err(|_| OwnerBridgeCodecError::InvalidCbor),
            _ => Err(OwnerBridgeCodecError::InvalidCbor),
        }
    }

    pub(crate) fn fixed_bytes<const N: usize>(&mut self) -> Result<[u8; N], OwnerBridgeCodecError> {
        let (major, length) = self.head()?;
        if major != 2 || usize::try_from(length) != Ok(N) {
            return Err(OwnerBridgeCodecError::InvalidCbor);
        }
        let mut output = [0; N];
        output.copy_from_slice(self.take(N)?);
        Ok(output)
    }

    pub(crate) fn bytes(
        &mut self,
        minimum: usize,
        maximum: usize,
    ) -> Result<&'a [u8], OwnerBridgeCodecError> {
        let (major, length) = self.head()?;
        if major != 2 {
            return Err(OwnerBridgeCodecError::InvalidCbor);
        }
        let length = Self::bounded_count(length, maximum)?;
        if length < minimum {
            return Err(OwnerBridgeCodecError::BoundsExceeded);
        }
        self.take(length)
    }

    pub(crate) fn exact_text(&mut self, expected: &str) -> Result<(), OwnerBridgeCodecError> {
        let (major, length) = self.head()?;
        if major != 3 || usize::try_from(length) != Ok(expected.len()) {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        if self.take(expected.len())? == expected.as_bytes() {
            Ok(())
        } else {
            Err(OwnerBridgeCodecError::InvalidPayload)
        }
    }

    pub(crate) fn text(&mut self, maximum: usize) -> Result<&'a str, OwnerBridgeCodecError> {
        let (major, length) = self.head()?;
        if major != 3 {
            return Err(OwnerBridgeCodecError::InvalidCbor);
        }
        let length = Self::bounded_count(length, maximum)?;
        core::str::from_utf8(self.take(length)?).map_err(|_| OwnerBridgeCodecError::InvalidCbor)
    }

    pub(crate) fn boolean(&mut self) -> Result<bool, OwnerBridgeCodecError> {
        match self.byte()? {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(OwnerBridgeCodecError::InvalidCbor),
        }
    }

    pub(crate) fn null(&mut self) -> Result<(), OwnerBridgeCodecError> {
        if self.byte()? == 0xf6 {
            Ok(())
        } else {
            Err(OwnerBridgeCodecError::InvalidCbor)
        }
    }

    pub(crate) fn optional_fixed_bytes<const N: usize>(
        &mut self,
    ) -> Result<Option<[u8; N]>, OwnerBridgeCodecError> {
        if self.input.get(self.offset) == Some(&0xf6) {
            self.offset += 1;
            Ok(None)
        } else {
            self.fixed_bytes().map(Some)
        }
    }

    pub(crate) const fn finish(&self) -> Result<(), OwnerBridgeCodecError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(OwnerBridgeCodecError::TrailingBytes)
        }
    }

    fn head(&mut self) -> Result<(u8, u64), OwnerBridgeCodecError> {
        let first = self.byte()?;
        let additional = first & 31;
        let major = first >> 5;
        let (width, minimum) = match additional {
            0..=23 => return Ok((major, u64::from(additional))),
            24 => (1, 24),
            25 => (2, 0x100),
            26 => (4, 0x1_0000),
            27 => (8, 0x1_0000_0000),
            _ => return Err(OwnerBridgeCodecError::InvalidCbor),
        };
        let bytes = self.take(width)?;
        let mut value_bytes = [0; 8];
        value_bytes[8 - width..].copy_from_slice(bytes);
        let value = u64::from_be_bytes(value_bytes);
        if value < minimum {
            return Err(OwnerBridgeCodecError::NonCanonicalCbor);
        }
        Ok((major, value))
    }

    fn byte(&mut self) -> Result<u8, OwnerBridgeCodecError> {
        let byte = *self
            .input
            .get(self.offset)
            .ok_or(OwnerBridgeCodecError::InvalidCbor)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], OwnerBridgeCodecError> {
        let end = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or(OwnerBridgeCodecError::InvalidCbor)?;
        let bytes = &self.input[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn bounded_count(count: u64, maximum: usize) -> Result<usize, OwnerBridgeCodecError> {
        usize::try_from(count)
            .ok()
            .filter(|value| *value <= maximum)
            .ok_or(OwnerBridgeCodecError::BoundsExceeded)
    }
}

/// Minimal deterministic-CBOR writer for the fixed owner-bridge schemas.
pub(crate) struct CborWriter<'a> {
    output: &'a mut [u8],
    offset: usize,
}

impl<'a> CborWriter<'a> {
    pub(crate) const fn new(output: &'a mut [u8]) -> Self {
        Self { output, offset: 0 }
    }

    pub(crate) fn array(&mut self, count: u64) -> Result<(), OwnerBridgeCodecError> {
        self.head(4, count)
    }

    pub(crate) fn unsigned(&mut self, value: u64) -> Result<(), OwnerBridgeCodecError> {
        self.head(0, value)
    }

    pub(crate) fn negative(&mut self, magnitude: u64) -> Result<(), OwnerBridgeCodecError> {
        self.head(1, magnitude)
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), OwnerBridgeCodecError> {
        self.head(
            2,
            u64::try_from(value.len()).map_err(|_| OwnerBridgeCodecError::BoundsExceeded)?,
        )?;
        self.write(value)
    }

    pub(crate) fn text(&mut self, value: &str) -> Result<(), OwnerBridgeCodecError> {
        self.head(
            3,
            u64::try_from(value.len()).map_err(|_| OwnerBridgeCodecError::BoundsExceeded)?,
        )?;
        self.write(value.as_bytes())
    }

    pub(crate) fn boolean(&mut self, value: bool) -> Result<(), OwnerBridgeCodecError> {
        self.write(&[if value { 0xf5 } else { 0xf4 }])
    }

    pub(crate) fn null(&mut self) -> Result<(), OwnerBridgeCodecError> {
        self.write(&[0xf6])
    }

    pub(crate) const fn finish(&self) -> usize {
        self.offset
    }

    fn head(&mut self, major: u8, value: u64) -> Result<(), OwnerBridgeCodecError> {
        let prefix = major << 5;
        if value <= 23 {
            let value = u8::try_from(value).map_err(|_| OwnerBridgeCodecError::InvalidPayload)?;
            return self.write(&[prefix | value]);
        }
        if let Ok(value) = u8::try_from(value) {
            return self.write(&[prefix | 0x18, value]);
        }
        if let Ok(value) = u16::try_from(value) {
            self.write(&[prefix | 0x19])?;
            return self.write(&value.to_be_bytes());
        }
        if let Ok(value) = u32::try_from(value) {
            self.write(&[prefix | 0x1a])?;
            return self.write(&value.to_be_bytes());
        }
        self.write(&[prefix | 0x1b])?;
        self.write(&value.to_be_bytes())
    }

    fn write(&mut self, value: &[u8]) -> Result<(), OwnerBridgeCodecError> {
        let end = self
            .offset
            .checked_add(value.len())
            .filter(|end| *end <= self.output.len())
            .ok_or(OwnerBridgeCodecError::BufferTooSmall)?;
        self.output[self.offset..end].copy_from_slice(value);
        self.offset = end;
        Ok(())
    }
}
