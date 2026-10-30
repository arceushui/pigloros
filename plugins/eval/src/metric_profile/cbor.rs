//! Strict RFC 8949 core-deterministic CBOR for the metric records.
//!
//! [`check_structure`] is the section 4.6 structural pass: it walks the whole input once,
//! keeps nothing, and rejects maps, tags, floats, simple values other than `false`, `true` and
//! `null`, indefinite lengths, non-preferred heads, truncated items, a wrong root or list
//! shape, arrays nested deeper than [`MAX_NESTING_DEPTH`] and trailing bytes, all as
//! `InvalidEncoding` at the coordinate of the defective item. [`Reader`] then reads the
//! fields of an input the structural pass accepted.

use super::{MetricErrorV1, MetricFailureV1, MAX_NESTING_DEPTH};

const ARRAY: u8 = 4;

/// One decoded item head.
#[derive(Clone, Copy)]
struct Head {
    major: u8,
    minor: u8,
    argument: u64,
}

/// The head after the end of the input, read by [`Reader`] only past a validated input.
const END: Head = Head {
    major: 7,
    minor: 31,
    argument: 0,
};

/// Read one well-formed head of preferred width at `position`.
fn head(bytes: &[u8], position: usize) -> Option<(Head, usize)> {
    let initial = *bytes.get(position)?;
    let (major, minor) = (initial >> 5, initial & 0x1f);
    let start = position + 1;
    let (width, floor) = match minor {
        0..=23 => {
            let argument = u64::from(minor);
            return Some((
                Head {
                    major,
                    minor,
                    argument,
                },
                start,
            ));
        }
        24 => (1, 24),
        25 => (2, 0x100),
        26 => (4, 0x1_0000),
        27 => (8, 0x1_0000_0000),
        _ => return None,
    };
    let argument = bytes
        .get(start..start + width)?
        .iter()
        .fold(0_u64, |value, &byte| (value << 8) | u64::from(byte));
    (argument >= floor).then_some((
        Head {
            major,
            minor,
            argument,
        },
        start + width,
    ))
}

/// One segment of a section 4.6 coordinate.
#[derive(Clone, Copy)]
enum Segment {
    Name(&'static str),
    Index(u64),
}

/// A coordinate, rendered only when a failure names it.
#[derive(Clone, Copy)]
pub(super) struct Coordinate<'p> {
    parent: Option<&'p Self>,
    segment: Segment,
}

impl<'p> Coordinate<'p> {
    /// A top-level named coordinate such as `magic` or `records`.
    pub(super) const fn name(name: &'static str) -> Self {
        Self {
            parent: None,
            segment: Segment::Name(name),
        }
    }

    /// The coordinate of item `index` inside this one.
    pub(super) const fn child(&'p self, index: u64) -> Self {
        Self {
            parent: Some(self),
            segment: Segment::Index(index),
        }
    }

    fn render(&self) -> String {
        let mut text = self
            .parent
            .map_or_else(String::new, |parent| parent.render() + "/");
        match self.segment {
            Segment::Name(name) => text.push_str(name),
            Segment::Index(index) => text.push_str(&index.to_string()),
        }
        text
    }

    /// The failure `error` at this coordinate.
    pub(super) fn failure(&self, error: MetricErrorV1) -> MetricFailureV1 {
        MetricFailureV1 {
            error,
            coordinate: self.render(),
        }
    }

    fn invalid(&self) -> MetricFailureV1 {
        self.failure(MetricErrorV1::InvalidEncoding)
    }
}

/// The root shape of a record: named fields, one of which is a list.
pub(super) struct Shape {
    /// The root field names in index order.
    pub(super) fields: &'static [&'static str],
    /// The index of the list field (`records` or `patterns`).
    pub(super) list: usize,
    /// The exact array length of every list element, or `None` when elements are scalars.
    pub(super) element_fields: Option<u64>,
}

/// The section 4.6 structural pass over a whole input.
pub(super) fn check_structure(bytes: &[u8], shape: &Shape) -> Result<(), MetricFailureV1> {
    let root = Coordinate::name("input");
    let mut position = head(bytes, 0)
        .filter(|(head, _)| {
            head.major == ARRAY && usize::try_from(head.argument) == Ok(shape.fields.len())
        })
        .map(|(_, next)| next)
        .ok_or_else(|| root.invalid())?;
    for (index, name) in shape.fields.iter().copied().enumerate() {
        let field = Coordinate::name(name);
        position = if index == shape.list {
            walk_list(bytes, position, &field, shape.element_fields)?
        } else {
            walk_item(bytes, position, &field, 1)?
        };
    }
    if position == bytes.len() {
        Ok(())
    } else {
        Err(Coordinate::name("trailing").invalid())
    }
}

/// Walk the list field: an array of fixed-length arrays (records) or of items (patterns).
fn walk_list(
    bytes: &[u8],
    position: usize,
    at: &Coordinate<'_>,
    element_fields: Option<u64>,
) -> Result<usize, MetricFailureV1> {
    let (list, mut position) = array_head(bytes, position).ok_or_else(|| at.invalid())?;
    for index in 0..list {
        let element = at.child(index);
        position = element_fields.map_or_else(
            || walk_item(bytes, position, &element, 2),
            |fields| walk_element(bytes, position, &element, fields),
        )?;
    }
    Ok(position)
}

/// Walk one record: an array of exactly `fields` items at level 3.
fn walk_element(
    bytes: &[u8],
    position: usize,
    at: &Coordinate<'_>,
    fields: u64,
) -> Result<usize, MetricFailureV1> {
    let mut position = array_head(bytes, position)
        .filter(|(length, _)| *length == fields)
        .map(|(_, next)| next)
        .ok_or_else(|| at.invalid())?;
    for index in 0..fields {
        position = walk_item(bytes, position, &at.child(index), 3)?;
    }
    Ok(position)
}

fn array_head(bytes: &[u8], position: usize) -> Option<(u64, usize)> {
    head(bytes, position)
        .filter(|(head, _)| head.major == ARRAY)
        .map(|(head, next)| (head.argument, next))
}

/// Walk one item whose enclosing array is at nesting `level`.
fn walk_item(
    bytes: &[u8],
    position: usize,
    at: &Coordinate<'_>,
    level: usize,
) -> Result<usize, MetricFailureV1> {
    let (head, next) = head(bytes, position).ok_or_else(|| at.invalid())?;
    match (head.major, head.minor) {
        (0 | 1, _) | (7, 20..=22) => Ok(next),
        (2 | 3, _) => skip(bytes, next, head.argument).ok_or_else(|| at.invalid()),
        (ARRAY, _) if level < MAX_NESTING_DEPTH => {
            let mut position = next;
            for index in 0..head.argument {
                position = walk_item(bytes, position, &at.child(index), level + 1)?;
            }
            Ok(position)
        }
        _ => Err(at.invalid()),
    }
}

fn skip(bytes: &[u8], position: usize, length: u64) -> Option<usize> {
    usize::try_from(length)
        .ok()
        .and_then(|length| position.checked_add(length))
        .filter(|end| *end <= bytes.len())
}

/// One item read from an input the structural pass accepted.
#[derive(Clone, Copy)]
pub(super) enum Item<'a> {
    Unsigned(u64),
    Text(&'a [u8]),
    Bool(bool),
    Null,
    /// Any other well-formed item: a negative integer, byte string or array, read without
    /// its contents.
    Other,
}

/// Reads the fields of an input that [`check_structure`] accepted, in order.
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned at the first root field.
    pub(super) fn fields(bytes: &'a [u8]) -> Self {
        let mut reader = Self { bytes, position: 0 };
        reader.next_head();
        reader
    }

    fn next_head(&mut self) -> Head {
        let end = self.bytes.len();
        let (head, next) = head(self.bytes, self.position).unwrap_or((END, end));
        self.position = next;
        head
    }

    /// The length of the list field the structural pass already checked is an array.
    pub(super) fn list(&mut self) -> u64 {
        self.next_head().argument
    }

    /// Step into one record array the structural pass already checked.
    pub(super) fn element(&mut self) {
        self.next_head();
    }

    /// Read one scalar item. An array is reported as [`Item::Other`] without its contents,
    /// because a field of the wrong type ends decoding.
    pub(super) fn item(&mut self) -> Item<'a> {
        let head = self.next_head();
        match (head.major, head.minor) {
            (0, _) => Item::Unsigned(head.argument),
            (3, _) => Item::Text(self.take(head.argument)),
            (7, 20) => Item::Bool(false),
            (7, 21) => Item::Bool(true),
            (7, 22) => Item::Null,
            _ => Item::Other,
        }
    }

    /// Read one field; a well-formed item of the wrong type is `InvalidEncoding` there (G2).
    pub(super) fn field<T>(
        &mut self,
        at: &Coordinate<'_>,
        typed: fn(Item<'a>) -> Option<T>,
    ) -> Result<T, MetricFailureV1> {
        typed(self.item()).ok_or_else(|| at.failure(MetricErrorV1::InvalidEncoding))
    }

    /// Read a header field that must equal `expected`, or fail with `error` there.
    pub(super) fn header<T: PartialEq>(
        &mut self,
        name: &'static str,
        typed: fn(Item<'a>) -> Option<T>,
        expected: &T,
        error: MetricErrorV1,
    ) -> Result<(), MetricFailureV1> {
        let at = Coordinate::name(name);
        self.field(&at, typed)
            .and_then(|value| require(value == *expected, &at, error))
    }

    fn take(&mut self, length: u64) -> &'a [u8] {
        let last = self.bytes.len();
        let end = skip(self.bytes, self.position, length).unwrap_or(last);
        let taken = self.bytes.get(self.position..end).unwrap_or_default();
        self.position = end;
        taken
    }
}

pub(super) const fn unsigned(item: Item<'_>) -> Option<u64> {
    match item {
        Item::Unsigned(value) => Some(value),
        _ => None,
    }
}

pub(super) const fn text(item: Item<'_>) -> Option<&[u8]> {
    match item {
        Item::Text(bytes) => Some(bytes),
        _ => None,
    }
}

pub(super) const fn boolean(item: Item<'_>) -> Option<bool> {
    match item {
        Item::Bool(value) => Some(value),
        _ => None,
    }
}

/// Require `valid`, or fail with `error` at `at`.
pub(super) fn require(
    valid: bool,
    at: &Coordinate<'_>,
    error: MetricErrorV1,
) -> Result<(), MetricFailureV1> {
    if valid {
        Ok(())
    } else {
        Err(at.failure(error))
    }
}

/// Append one head of preferred width.
pub(super) fn put_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;
    match argument {
        0..=23 => out.push(major | u8::try_from(argument).unwrap_or_default()),
        24..=0xff => {
            out.push(major | 0x18);
            out.push(u8::try_from(argument).unwrap_or_default());
        }
        0x100..=0xffff => {
            out.push(major | 0x19);
            out.extend_from_slice(&u16::try_from(argument).unwrap_or_default().to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 0x1a);
            out.extend_from_slice(&u32::try_from(argument).unwrap_or_default().to_be_bytes());
        }
        _ => {
            out.push(major | 0x1b);
            out.extend_from_slice(&argument.to_be_bytes());
        }
    }
}

/// Append an unsigned integer.
pub(super) fn put_unsigned(out: &mut Vec<u8>, value: u64) {
    put_head(out, 0, value);
}

/// Append a signed integer.
pub(super) fn put_signed(out: &mut Vec<u8>, value: i64) {
    let magnitude = value.unsigned_abs();
    if value < 0 {
        put_head(out, 1, magnitude - 1);
    } else {
        put_head(out, 0, magnitude);
    }
}

/// Append a text string.
pub(super) fn put_text(out: &mut Vec<u8>, text: &str) {
    put_bytes_of(out, 3, text.as_bytes());
}

/// Append a byte string.
pub(super) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_bytes_of(out, 2, bytes);
}

fn put_bytes_of(out: &mut Vec<u8>, major: u8, bytes: &[u8]) {
    put_head(out, major, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    out.extend_from_slice(bytes);
}

/// Append an array head.
pub(super) fn put_array(out: &mut Vec<u8>, length: u64) {
    put_head(out, ARRAY, length);
}

/// Append `false`, `true` or `null`.
pub(super) fn put_simple(out: &mut Vec<u8>, value: Option<bool>) {
    out.push(match value {
        Some(false) => 0xf4,
        Some(true) => 0xf5,
        None => 0xf6,
    });
}
