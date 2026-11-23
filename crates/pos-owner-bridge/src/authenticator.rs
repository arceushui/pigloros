#![cfg(any(test, feature = "test-support"))]
//! The ADR-110 E20 LS3 direct-ceremony seam.
//!
//! On the Linux profile the owner process is itself the `WebAuthn` client: a native CTAP2 client
//! implements [`OwnerAuthenticatorPort`], and [`DirectHost`] runs each ceremony through
//! [`CeremonyDriver::run_direct`]. There is no surface, listener, generation or cleanup record,
//! and the reply reaches the same `parse_and_verify` path as the buffer protocol.
//!
//! Everything here stays behind `test-support` until the Linux activation (Redmine #1438).

use std::time::Instant;

use crate::ceremony::driver::CeremonyDriver;
use crate::{
    BridgeError, CeremonyHost, CeremonyReply, MonotonicClock, QuarantinePoll, ReplyImage,
    RequestImage,
};

/// A native authenticator client that answers one ceremony request (ADR-110 E20 LS3).
pub trait OwnerAuthenticatorPort {
    /// Answer the ceremony whose request image is `request`.
    ///
    /// `request` is the driver's request image: the 64-byte request control header followed by
    /// the encoded `CreateOptionsV1` or `GetOptionsV1`. The port writes one encoded
    /// `AttestationReplyV1` or `AssertionReplyV1` at the start of `reply` and returns its
    /// length. `deadline` is in the domain of `clock`; the port compares it only against that
    /// clock and cancels the authenticator (`CTAPHID_CANCEL`) by then.
    ///
    /// # Errors
    ///
    /// Returns the ADR-110 E20 LS7 classification of the failure: `Lifecycle(ClientFailed)` for
    /// CTAP and transport errors, `Lifecycle(InteractionTimeout)` at the deadline,
    /// `Unavailable(PrfUnsupported)` for an authenticator that fails the capability check or
    /// returns no usable `hmac-secret` output, and `Unavailable(InterfaceUnavailable)` when no
    /// terminal can take the PIN.
    fn perform(
        &mut self,
        request: &RequestImage,
        reply: &mut ReplyImage,
        deadline: Instant,
        clock: &dyn MonotonicClock,
    ) -> Result<usize, BridgeError>;
}

/// A [`CeremonyHost`] that runs every ceremony through a native authenticator client.
///
/// It never quarantines: the direct path spawns no process and keeps no cleanup record
/// (ADR-110 E20 LS8).
pub struct DirectHost<P: OwnerAuthenticatorPort, C: MonotonicClock> {
    port: P,
    clock: C,
}

impl<P: OwnerAuthenticatorPort, C: MonotonicClock> DirectHost<P, C> {
    /// A host that answers every ceremony with `port`, timed by `clock`.
    #[must_use]
    pub const fn new(port: P, clock: C) -> Self {
        Self { port, clock }
    }
}

impl<P: OwnerAuthenticatorPort, C: MonotonicClock> CeremonyHost for DirectHost<P, C> {
    fn run(&mut self, mut driver: CeremonyDriver) -> CeremonyReply {
        let result = driver.run_direct(&mut self.port, &self.clock);
        CeremonyReply {
            result,
            driver: Some(driver),
        }
    }

    fn poll_quarantine(&mut self) -> QuarantinePoll {
        QuarantinePoll::default()
    }
}
