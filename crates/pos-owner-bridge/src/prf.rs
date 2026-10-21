//! The borrowed PRF view handed to owner ports (ADR-110 §10).

use std::fmt;

use zeroize::Zeroizing;

/// A borrowed view of a PRF result.
///
/// It is neither `Clone` nor `Copy`, its `Debug` is redacted, and it borrows the bridge's
/// preallocated zeroizing slot, which is wiped as soon as the port call returns.
pub struct PrfOutput<'a> {
    slot: &'a Zeroizing<[u8; 32]>,
}

impl<'a> PrfOutput<'a> {
    /// Borrow `slot` for the duration of one port call.
    #[must_use]
    pub const fn new(slot: &'a Zeroizing<[u8; 32]>) -> Self {
        Self { slot }
    }

    /// Borrow the 32 PRF bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.slot
    }
}

impl fmt::Debug for PrfOutput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrfOutput(<redacted>)")
    }
}
