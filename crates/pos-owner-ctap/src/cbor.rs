//! Minimal CTAP2 CBOR: a writer for requests and a bounded reader for authenticator output.
//!
//! The writer emits the CTAP2 canonical form for the values this crate sends; callers write map
//! entries in canonical key order. The reader accepts only definite-length items of the major
//! types CTAP2 uses (no tags, no floats), at most [`MAX_DEPTH`] levels deep, and refuses
//! duplicate map keys. It does not require canonical encoding, because CTAP 2.1 does not require
//! it of authenticator output (ADR-110 E20 LT6). Its input is bounded by the CTAPHID message
//! limit.

/// The deepest nesting the reader accepts: the top-level item is at depth zero.
pub(crate) const MAX_DEPTH: usize = 8;

/// One decoded CBOR item that borrows its byte and text strings from the input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Value<'a> {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3.
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Self>),
    /// Major type 5, in input order.
    Map(Vec<(Self, Self)>),
    /// The simple values `false` and `true`.
    Bool(bool),
    /// The simple value `null`.
    Null,
}

impl<'a> Value<'a> {
    /// The value stored under `key` in a map.
    pub(crate) fn get(&self, key: &Self) -> Option<&Self> {
        let Self::Map(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    }

    /// The value stored under the unsigned key `key` in a map.
    pub(crate) fn int(&self, key: u64) -> Option<&Self> {
        self.get(&Self::Unsigned(key))
    }

    /// The value stored under the text key `key` in a map.
    pub(crate) fn text_key(&self, key: &'a str) -> Option<&Self> {
        self.get(&Self::Text(key))
    }

    /// The bytes of a byte string.
    pub(crate) const fn bytes(&self) -> Option<&'a [u8]> {
        if let Self::Bytes(bytes) = self {
            Some(*bytes)
        } else {
            None
        }
    }

    /// The value of an unsigned integer.
    pub(crate) const fn unsigned(&self) -> Option<u64> {
        if let Self::Unsigned(value) = self {
            Some(*value)
        } else {
            None
        }
    }

    /// The items of an array, or none for any other item.
    pub(crate) fn items(&self) -> &[Self] {
        if let Self::Array(items) = self {
            items
        } else {
            &[]
        }
    }
}

/// Decode exactly one item that fills all of `input`.
pub(crate) fn decode(input: &[u8]) -> Option<Value<'_>> {
    decode_prefix(input).and_then(|(value, used)| (used == input.len()).then_some(value))
}

/// Decode the first item of `input` and return it with the number of bytes it used.
pub(crate) fn decode_prefix(input: &[u8]) -> Option<(Value<'_>, usize)> {
    let mut reader = Reader { input, offset: 0 };
    let value = reader.item(0)?;
    Some((value, reader.offset))
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.input.get(self.offset)?;
        self.offset += 1;
        Some(byte)
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(count)?;
        let taken = self.input.get(self.offset..end)?;
        self.offset = end;
        Some(taken)
    }

    fn item(&mut self, depth: usize) -> Option<Value<'a>> {
        let first = self.byte()?;
        let major = first >> 5;
        let argument = match first & 0x1f {
            additional @ 0..=23 => u64::from(additional),
            additional @ 24..=27 => {
                let bytes = self.take(1 << (additional - 24))?;
                let mut word = [0; 8];
                word[8 - bytes.len()..].copy_from_slice(bytes);
                u64::from_be_bytes(word)
            }
            _ => return None,
        };
        match major {
            0 => Some(Value::Unsigned(argument)),
            1 => Some(Value::Negative(argument)),
            2 => self.string(argument).map(Value::Bytes),
            3 => self
                .string(argument)
                .and_then(|text| std::str::from_utf8(text).ok())
                .map(Value::Text),
            4 => self.array(argument, depth),
            5 => self.map(argument, depth),
            7 => simple(first),
            _ => None,
        }
    }

    fn string(&mut self, length: u64) -> Option<&'a [u8]> {
        self.take(usize::try_from(length).unwrap_or(usize::MAX))
    }

    fn array(&mut self, count: u64, depth: usize) -> Option<Value<'a>> {
        let inner = nested(depth)?;
        (0..count)
            .map(|_| self.item(inner))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array)
    }

    fn map(&mut self, count: u64, depth: usize) -> Option<Value<'a>> {
        let inner = nested(depth)?;
        let mut entries: Vec<(Value<'a>, Value<'a>)> = Vec::new();
        for _ in 0..count {
            let key = self.item(inner)?;
            let value = self.item(inner)?;
            if entries.iter().any(|(seen, _)| *seen == key) {
                return None;
            }
            entries.push((key, value));
        }
        Some(Value::Map(entries))
    }
}

/// The depth of the items inside a container at `depth`, if that is still allowed.
const fn nested(depth: usize) -> Option<usize> {
    if depth < MAX_DEPTH {
        Some(depth + 1)
    } else {
        None
    }
}

/// The simple value encoded by the one-byte head `first` of major type 7.
const fn simple(first: u8) -> Option<Value<'static>> {
    match first {
        0xf4 => Some(Value::Bool(false)),
        0xf5 => Some(Value::Bool(true)),
        0xf6 => Some(Value::Null),
        _ => None,
    }
}

/// A CTAP2 canonical CBOR writer.
///
/// Every argument width is supported, so no value is ever clamped.
#[derive(Debug, Default)]
pub(crate) struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// Write a head whose initial byte is `base` (the major type, already in its top three
    /// bits) plus the additional information, then `value`'s argument bytes.
    fn head(&mut self, base: u8, value: u64) {
        let encoded = value.to_be_bytes();
        let (additional, width) = match value {
            0..=23 => (encoded[7], 0),
            24..=0xff => (24, 1),
            0x100..=0xffff => (25, 2),
            0x1_0000..=0xffff_ffff => (26, 4),
            _ => (27, 8),
        };
        // `base` has only its top three bits set and `additional` is below 32, so the sum never
        // carries: it is the two fields side by side.
        self.bytes.push(base.wrapping_add(additional));
        self.bytes.extend_from_slice(&encoded[8 - width..]);
    }

    /// An unsigned integer.
    pub(crate) fn unsigned(&mut self, value: u64) -> &mut Self {
        self.head(0x00, value);
        self
    }

    /// The negative integer `-1 - magnitude`.
    pub(crate) fn negative(&mut self, magnitude: u64) -> &mut Self {
        self.head(0x20, magnitude);
        self
    }

    /// A byte string.
    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.head(0x40, value.len() as u64);
        self.bytes.extend_from_slice(value);
        self
    }

    /// A text string.
    pub(crate) fn text(&mut self, value: &str) -> &mut Self {
        self.head(0x60, value.len() as u64);
        self.bytes.extend_from_slice(value.as_bytes());
        self
    }

    /// The head of an array of `count` items.
    pub(crate) fn array(&mut self, count: usize) -> &mut Self {
        self.head(0x80, count as u64);
        self
    }

    /// The head of a map of `count` entries.
    pub(crate) fn map(&mut self, count: usize) -> &mut Self {
        self.head(0xa0, count as u64);
        self
    }

    /// A boolean.
    pub(crate) fn boolean(&mut self, value: bool) -> &mut Self {
        self.bytes.push(if value { 0xf5 } else { 0xf4 });
        self
    }

    /// The encoded bytes.
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

#[cfg(test)]
mod tests;
