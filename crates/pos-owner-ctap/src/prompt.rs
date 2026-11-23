//! The PIN prompt port and its fixed-size PIN buffer (ADR-110 E20 LP5).
//!
//! The PIN is normalized to Unicode NFC before it is hashed (CTAP 2.1 PS §6.5.1).
//!
//! The Linux implementation reads `/dev/tty` through a file descriptor the owner root passes in
//! (ADR-110 E20 S2). The PIN is read byte by byte into a fixed, zeroized 64-byte buffer and
//! never becomes a `String`, a log line, an argument or an environment value.

use std::time::Instant;

use pos_owner_bridge::{BridgeError, MonotonicClock};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// The most PIN bytes CTAP 2.1 allows.
pub const MAX_PIN_BYTES: usize = 63;

/// The fewest PIN code points CTAP 2.1 allows.
pub const MIN_PIN_CODE_POINTS: usize = 4;

/// A PIN of at most 63 bytes in a zeroized 64-byte buffer.
pub struct PinBuffer {
    bytes: Zeroizing<[u8; MAX_PIN_BYTES + 1]>,
    length: usize,
}

impl Default for PinBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PinBuffer {
    /// An empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes: Zeroizing::new([0; MAX_PIN_BYTES + 1]),
            length: 0,
        }
    }

    /// Append one byte, or return `false` when the buffer is full.
    ///
    /// A full buffer holds 63 bytes and is left unchanged.
    pub fn push(&mut self, byte: u8) -> bool {
        if self.length >= MAX_PIN_BYTES {
            return false;
        }
        self.bytes[self.length] = byte;
        self.length += 1;
        true
    }

    /// The PIN in Unicode NFC (CTAP 2.1 PS §6.5.1), in another zeroized buffer.
    ///
    /// There is none unless the PIN is UTF-8 whose NFC form has at least four code points and
    /// fits in 63 bytes. Each code point passes through a zeroized 4-byte scratch buffer.
    pub(crate) fn normalized(&self) -> Option<Self> {
        let text = std::str::from_utf8(&self.bytes[..self.length]).ok()?;
        let mut nfc = Self::new();
        let mut points = 0;
        let fits = text.nfc().all(|point| {
            points += 1;
            let mut utf8 = Zeroizing::<[u8; 4]>::default();
            point
                .encode_utf8(utf8.as_mut_slice())
                .bytes()
                .all(|byte| nfc.push(byte))
        });
        (fits && points >= MIN_PIN_CODE_POINTS).then_some(nfc)
    }

    /// The bytes of the PIN.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// A fixed message the prompt shows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Notice {
    /// Touch the security key.
    Touch,
    /// Verify on the security key itself, with `retries` attempts left.
    UserVerification {
        /// The authenticator's remaining built-in UV attempts.
        retries: u64,
    },
    /// The PIN is blocked: the key needs its own reset or a power cycle. Nothing is retried.
    PinBlocked,
}

/// The owner's terminal: one PIN entry per CTAP command (ADR-110 E20 LP5, G3).
pub trait PinPrompt {
    /// Read one PIN into `pin`, showing `retries`, the authenticator's remaining PIN attempts.
    ///
    /// The entry shares the ceremony's interaction bound: the prompt waits for input only until
    /// `deadline`, compared against `clock` alone, and then gives up. A PIN typed after the
    /// deadline is never used, because the client sends nothing once the deadline has passed.
    ///
    /// # Errors
    ///
    /// Returns `Lifecycle(InteractionTimeout)` when the deadline passes before the entry is
    /// complete, `Unavailable(InterfaceUnavailable)` when there is no terminal, and
    /// `Lifecycle(ClientFailed)` when the user cancels or the PIN is too long.
    fn read_pin(
        &mut self,
        retries: u64,
        pin: &mut PinBuffer,
        deadline: Instant,
        clock: &dyn MonotonicClock,
    ) -> Result<(), BridgeError>;

    /// Show `notice`.
    fn notice(&mut self, notice: Notice);
}
