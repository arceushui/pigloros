//! Borrowed CBOR cursor for the private registry grammar, not a public codec.

use super::super::{read_guard::ReadContext, KeyRegistryReadErrorV1 as Error};

type Result<T> = std::result::Result<T, Error>;
pub(super) const CHUNK_BYTES: usize = 4_096;

#[derive(Clone, Copy)]
pub(super) enum Header {
    Positive(u64),
    Negative,
    Bytes(Option<usize>),
    Text(Option<usize>),
    Array(Option<usize>),
    Map(Option<usize>),
    Tag(u64),
    Simple(u8),
    Float,
    Break,
}

pub(super) struct Cursor<'input> {
    bytes: &'input [u8],
    buffered: Option<Header>,
    recursion: usize,
}

impl<'input> Cursor<'input> {
    pub(super) const fn new(bytes: &'input [u8]) -> Self {
        Self {
            bytes,
            buffered: None,
            recursion: 256,
        }
    }

    pub(super) fn take(
        &mut self,
        length: usize,
        context: &mut ReadContext<'_>,
    ) -> Result<&'input [u8]> {
        context.step(|_| {
            self.bytes
                .split_at_checked(length)
                .ok_or(Error::InvalidSnapshot)
                .map(|(bytes, remaining)| {
                    self.bytes = remaining;
                    bytes
                })
        })
    }

    pub(super) fn header(&mut self, context: &mut ReadContext<'_>) -> Result<Header> {
        context.step(|context| {
            if let Some(header) = self.buffered.take() {
                return Ok(header);
            }
            let prefix = self.take(1, context)?[0];
            let major = prefix >> 5;
            let minor = prefix & 31;
            if major == 7 {
                return self.simple_header(minor, context);
            }
            let number = match minor {
                0..=23 => Some(u64::from(minor)),
                24 => Some(self.number(1, context)?),
                25 => Some(self.number(2, context)?),
                26 => Some(self.number(4, context)?),
                27 => Some(self.number(8, context)?),
                31 => None,
                _ => return Err(Error::InvalidSnapshot),
            };
            match major {
                0 => number.map(Header::Positive).ok_or(Error::InvalidSnapshot),
                1 => number.map(|_| Header::Negative).ok_or(Error::InvalidSnapshot),
                2..=5 => {
                    let length = number
                        .map(usize::try_from)
                        .transpose()
                        .map_err(|_| Error::InvalidSnapshot)?;
                    Ok(match major {
                        2 => Header::Bytes(length),
                        3 => Header::Text(length),
                        4 => Header::Array(length),
                        _ => Header::Map(length),
                    })
                }
                _ => number.map(Header::Tag).ok_or(Error::InvalidSnapshot),
            }
        })
    }

    fn number(&mut self, length: usize, context: &mut ReadContext<'_>) -> Result<u64> {
        self.take(length, context).map(|bytes| {
            bytes
                .iter()
                .fold(0, |value, byte| (value << 8) | u64::from(*byte))
        })
    }

    fn simple_header(&mut self, minor: u8, context: &mut ReadContext<'_>) -> Result<Header> {
        match minor {
            0..=23 => Ok(Header::Simple(minor)),
            24 => self.take(1, context).map(|bytes| Header::Simple(bytes[0])),
            25 => self.take(2, context).map(|_| Header::Float),
            26 => self.take(4, context).map(|_| Header::Float),
            27 => self.take(8, context).map(|_| Header::Float),
            31 => Ok(Header::Break),
            _ => Err(Error::InvalidSnapshot),
        }
    }

    pub(super) fn peek(&mut self, context: &mut ReadContext<'_>) -> Result<Header> {
        self.header(context).map(|header| {
            self.buffered = Some(header);
            header
        })
    }

    pub(super) fn return_header(&mut self, header: Header) {
        self.buffered = Some(header);
    }

    pub(super) fn untagged(&mut self, context: &mut ReadContext<'_>) -> Result<Header> {
        loop {
            let header = self.header(context)?;
            if !matches!(header, Header::Tag(_)) {
                return Ok(header);
            }
        }
    }

    pub(super) fn nested<T>(
        &mut self,
        context: &mut ReadContext<'_>,
        read: impl FnOnce(&mut Self, &mut ReadContext<'_>) -> Result<T>,
    ) -> Result<T> {
        context.step(|context| {
            let previous = self.recursion;
            self.recursion = previous.checked_sub(1).ok_or(Error::InvalidSnapshot)?;
            let result = read(self, context);
            self.recursion = previous;
            result
        })
    }

    pub(super) fn next(
        &mut self,
        remaining: &mut Option<usize>,
        context: &mut ReadContext<'_>,
    ) -> Result<bool> {
        context.step(|context| match remaining {
            Some(0) => Ok(false),
            Some(count) => {
                *count -= 1;
                Ok(true)
            }
            None => self.header(context).map(|header| {
                if matches!(header, Header::Break) {
                    false
                } else {
                    self.buffered = Some(header);
                    true
                }
            }),
        })
    }

    pub(super) fn identifier(&mut self, context: &mut ReadContext<'_>) -> Result<&'input [u8]> {
        context.step(|context| match self.untagged(context)? {
            Header::Text(Some(length)) if length <= CHUNK_BYTES => {
                let bytes = self.take(length, context)?;
                std::str::from_utf8(bytes)
                    .map(|_| bytes)
                    .map_err(|_| Error::InvalidSnapshot)
            }
            Header::Bytes(Some(length)) if length <= CHUNK_BYTES => self.take(length, context),
            _ => Err(Error::InvalidSnapshot),
        })
    }

    /// Ciborium's string-segment driver also accepts nested indefinite strings;
    /// unlike maps/arrays, those segment headers do not consume recursion depth.
    pub(super) fn segments(
        &mut self,
        length: Option<usize>,
        text: bool,
        context: &mut ReadContext<'_>,
        mut visit: impl FnMut(&[u8], &mut ReadContext<'_>) -> Result<()>,
    ) -> Result<()> {
        if let Some(length) = length {
            let bytes = self.take(length, context)?;
            return chunks(bytes, text, context, visit);
        }
        let mut nesting = 1_usize;
        while nesting != 0 {
            context.step(|context| match self.header(context)? {
                Header::Break => {
                    nesting -= 1;
                    Ok(())
                }
                Header::Text(length) if text => {
                    self.segment(length, &mut nesting, true, context, &mut visit)
                }
                Header::Bytes(length) if !text => {
                    self.segment(length, &mut nesting, false, context, &mut visit)
                }
                _ => Err(Error::InvalidSnapshot),
            })?;
        }
        Ok(())
    }

    fn segment(
        &mut self,
        length: Option<usize>,
        nesting: &mut usize,
        text: bool,
        context: &mut ReadContext<'_>,
        visit: &mut impl FnMut(&[u8], &mut ReadContext<'_>) -> Result<()>,
    ) -> Result<()> {
        if let Some(length) = length {
            chunks(self.take(length, context)?, text, context, visit)
        } else {
            *nesting = nesting.checked_add(1).ok_or(Error::InvalidSnapshot)?;
            Ok(())
        }
    }

    pub(super) fn integer(&mut self, context: &mut ReadContext<'_>) -> Result<u64> {
        loop {
            match self.header(context)? {
                Header::Positive(value) => return Ok(value),
                Header::Tag(2) => {
                    return self.big_integer(context).and_then(|value| {
                        u64::try_from(value).map_err(|_| Error::InvalidSnapshot)
                    });
                }
                Header::Tag(3) => {
                    self.big_integer(context)?;
                    return Err(Error::InvalidSnapshot);
                }
                Header::Tag(_) => (),
                _ => return Err(Error::InvalidSnapshot),
            }
        }
    }

    fn big_integer(&mut self, context: &mut ReadContext<'_>) -> Result<u128> {
        let Header::Bytes(length) = self.header(context)? else {
            return Err(Error::InvalidSnapshot);
        };
        let mut value = 0_u128;
        self.segments(length, false, context, |bytes, context| {
            for byte in bytes {
                context.step(|_| {
                    value = value
                        .checked_mul(256)
                        .and_then(|value| value.checked_add(u128::from(*byte)))
                        .ok_or(Error::InvalidSnapshot)?;
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(value)
    }

    pub(super) fn skip(&mut self, context: &mut ReadContext<'_>) -> Result<()> {
        context.step(|context| match self.header(context)? {
            Header::Positive(_) | Header::Negative | Header::Float | Header::Simple(20..=23) => Ok(()),
            Header::Bytes(length) => self.segments(length, false, context, |_, _| Ok(())),
            Header::Text(length) => self.segments(length, true, context, |bytes, _| {
                std::str::from_utf8(bytes)
                    .map(|_| ())
                    .map_err(|_| Error::InvalidSnapshot)
            }),
            Header::Array(length) => self.nested(context, |cursor, context| {
                cursor.skip_entries(length, false, context)
            }),
            Header::Map(length) => self.nested(context, |cursor, context| {
                cursor.skip_entries(length, true, context)
            }),
            Header::Tag(tag) => self.skip_tag(tag, context),
            _ => Err(Error::InvalidSnapshot),
        })
    }

    fn skip_entries(
        &mut self,
        mut remaining: Option<usize>,
        map: bool,
        context: &mut ReadContext<'_>,
    ) -> Result<()> {
        while self.next(&mut remaining, context)? {
            self.skip(context)?;
            if map {
                self.skip(context)?;
            }
        }
        Ok(())
    }

    fn skip_tag(&mut self, tag: u64, context: &mut ReadContext<'_>) -> Result<()> {
        // IgnoredAny recognizes only short definite bignums as numbers. Other
        // tags (including longer/indefinite bignums) recurse through their body.
        if matches!(tag, 2 | 3)
            && matches!(self.peek(context)?, Header::Bytes(Some(length)) if length <= 16)
        {
            let value = self.big_integer(context)?;
            if tag == 3 && i128::try_from(value).is_err() {
                return Err(Error::InvalidSnapshot);
            }
            Ok(())
        } else {
            self.nested(context, Self::skip)
        }
    }
}

fn chunks(
    mut bytes: &[u8],
    text: bool,
    context: &mut ReadContext<'_>,
    mut visit: impl FnMut(&[u8], &mut ReadContext<'_>) -> Result<()>,
) -> Result<()> {
    context.checkpoint()?;
    while !bytes.is_empty() {
        context.step(|context| {
            let mut length = bytes.len().min(CHUNK_BYTES);
            if text && length < bytes.len() {
                while length != 0 && bytes[length] & 0xc0 == 0x80 {
                    length -= 1;
                }
                if length == 0 {
                    return Err(Error::InvalidSnapshot);
                }
            }
            let (chunk, remaining) = bytes.split_at(length);
            visit(chunk, context)?;
            bytes = remaining;
            Ok(())
        })?;
    }
    context.checkpoint()
}
