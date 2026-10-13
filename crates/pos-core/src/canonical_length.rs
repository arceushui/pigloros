//! Private, effect-free native byte emission shared by buffers and length queries.

// Native CBOR argument emission widens slice lengths to u64. All supported
// Rust pointer widths fit that wire argument; this is a build-time invariant,
// not a panic or unchecked narrowing in a length query.
const _: () = assert!(usize::BITS <= u64::BITS);

/// Failure to represent one canonical encoding's length.
///
/// This is an arithmetic result, never a validity or authority decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanonicalLengthErrorV1 {
    /// Checked accumulation cannot fit the target's `usize`.
    #[error("canonical length overflow")]
    LengthOverflow,
}

pub(crate) trait CanonicalEmit {
    fn emit(&self, out: &mut impl CanonicalSink);
}

pub(crate) trait CanonicalSink {
    fn extend_from_slice(&mut self, bytes: &[u8]);

    fn push(&mut self, byte: u8) {
        self.extend_from_slice(&[byte]);
    }

    fn nested_byte_string(&mut self, value: &impl CanonicalEmit);
}

impl CanonicalSink for Vec<u8> {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Self::extend_from_slice(self, bytes);
    }

    fn nested_byte_string(&mut self, value: &impl CanonicalEmit) {
        let mut inner = Self::new();
        value.emit(&mut inner);
        bytes(self, &inner);
    }
}

struct LengthSink {
    length: Option<usize>,
    maximum: usize,
}

impl LengthSink {
    const fn new() -> Self {
        Self { length: Some(0), maximum: usize::MAX }
    }

    fn add(&mut self, amount: usize) {
        self.length = self.length.and_then(|length| {
            length.checked_add(amount).filter(|next| *next <= self.maximum)
        });
    }

    const fn finish(self) -> Result<usize, CanonicalLengthErrorV1> {
        match self.length {
            Some(length) => Ok(length),
            None => Err(CanonicalLengthErrorV1::LengthOverflow),
        }
    }
}

impl CanonicalSink for LengthSink {
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        // Slice lengths already have the target's usize representation; no
        // wire integer is narrowed or interpreted as an allocated payload.
        self.add(bytes.len());
    }

    fn nested_byte_string(&mut self, value: &impl CanonicalEmit) {
        let start = self.length;
        value.emit(self);
        if let Some((end, start)) = self.length.zip(start) {
            // Counting is commutative: count the existing nested emitter first,
            // then its byte-string head. A successful counter is monotone.
            head(self, 2, (end - start) as u64);
        }
    }
}

pub(crate) fn measure(value: &impl CanonicalEmit) -> Result<usize, CanonicalLengthErrorV1> {
    let mut out = LengthSink::new();
    value.emit(&mut out);
    out.finish()
}

pub(crate) fn head(out: &mut impl CanonicalSink, major: u8, value: u64) {
    let tag = major << 5;
    if value < 24 {
        out.push(tag | value.to_be_bytes()[7]);
    } else if let Ok(value) = u8::try_from(value) {
        out.extend_from_slice(&[tag | 0x18, value]);
    } else if let Ok(value) = u16::try_from(value) {
        out.push(tag | 0x19);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        out.push(tag | 0x1a);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(tag | 0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub(crate) fn bytes(out: &mut impl CanonicalSink, value: &[u8]) {
    head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

pub(crate) fn text(out: &mut impl CanonicalSink, value: &str) {
    head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OneByte;

    impl CanonicalEmit for OneByte {
        fn emit(&self, out: &mut impl CanonicalSink) {
            out.push(1);
        }
    }

    #[test]
    fn checked_counter_accepts_exact_maximum_and_permanently_rejects_one_over() {
        let mut out = LengthSink::new();
        out.add(usize::MAX - 1);
        out.push(1);
        assert_eq!(out.finish(), Ok(usize::MAX));
        let mut out = LengthSink::new();
        out.add(usize::MAX);
        out.nested_byte_string(&OneByte);
        out.push(1);
        assert_eq!(out.finish(), Err(CanonicalLengthErrorV1::LengthOverflow));
    }

    #[test]
    fn nested_count_uses_the_same_emitter_without_materializing_a_buffer() {
        let mut bytes = Vec::new();
        bytes.nested_byte_string(&OneByte);
        let mut count = LengthSink::new();
        count.nested_byte_string(&OneByte);
        assert_eq!(bytes, [0x41, 1]);
        assert_eq!(count.finish(), Ok(bytes.len()));
    }

    #[test]
    fn the_actual_counting_primitive_enforces_a_32_bit_target_ceiling() {
        let maximum = u32::MAX as usize;
        let mut count = LengthSink { length: Some(maximum - 1), maximum };
        count.push(1);
        assert_eq!(count.length, Some(maximum));
        count.push(1);
        assert_eq!(count.finish(), Err(CanonicalLengthErrorV1::LengthOverflow));
    }
}
