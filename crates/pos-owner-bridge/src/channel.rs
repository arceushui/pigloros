//! The bounded hand-off between the owner thread and the surface thread (ADR-110 §1a, §6).
//!
//! [`channel`] returns the two halves. The owner thread keeps the [`ChannelHost`], which is a
//! [`CeremonyHost`]: `OwnerBridge::enroll` and `unlock` hand it a driver and block until the
//! surface thread replies. The surface thread keeps the [`SurfaceEndpoint`]: it receives the
//! driver (a `Send` value that carries the preallocated slots, the only way a secret crosses
//! threads), steps it from its timer and event callbacks, and sends the driver back.
//!
//! Both channels hold one message, as the ADR's hand-off does: the owner thread submits one
//! command and blocks on the reply.
//!
//! # Blocking and failure
//!
//! [`ChannelHost::run`](CeremonyHost::run) blocks until the surface thread replies. It has no
//! timeout of its own: the per-phase bounds of ADR-110 §6 (readiness, interaction, release, exit)
//! always end a ceremony, so the surface thread always replies unless it is gone. A surface
//! thread that drops its endpoint after it accepted a driver (a driver still buffered in the
//! capacity-one channel counts as accepted: the owner side cannot tell it was never received) may
//! have a browser still alive, so the ceremony ends fail-closed as `Quarantine(CleanupTimeout)`
//! and the surface stays quarantined; a host must therefore keep the endpoint alive until a
//! quarantine has been polled to completion. A surface thread that is already gone when the driver is handed over fails the
//! ceremony as `Unavailable(InterfaceUnavailable)` and the driver comes back untouched.
//!
//! # Implementing a host on an STA thread
//!
//! The surface thread's message loop calls [`SurfaceEndpoint::try_recv`] from its `WM_TIMER`
//! (never the blocking [`SurfaceEndpoint::recv`]), keeps the driver it received, calls
//! `CeremonyDriver::step` from the timer and from each `WebView2` callback until the step is
//! `Finished` (a `Done` step means it already was), answers with [`SurfaceEndpoint::reply_run`],
//! and keeps a quarantined driver in a
//! [`QuarantineKeeper`](crate::QuarantineKeeper) to answer `PollQuarantine`. The cleanup
//! store and the clock the host passes in `StepEnv` are also used by the owner thread (restart
//! check, enrollment budget), so they need their own interior synchronisation.

use std::sync::mpsc::{sync_channel, Receiver, RecvError, SyncSender, TryRecvError};

use crate::ceremony::driver::CeremonyDriver;
use crate::{BridgeError, CeremonyHost, CeremonyReply, QuarantineCode, UnavailableCode};

const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

/// The surface thread vanished with a driver in hand: its browser may still be alive.
const ABANDONED: BridgeError = BridgeError::Quarantine(QuarantineCode::CleanupTimeout);

/// One command from the owner thread.
pub enum SurfaceRequest {
    /// Run this ceremony to its end and reply with [`SurfaceEndpoint::reply_run`].
    Run(Box<CeremonyDriver>),
    /// Poll the quarantined ceremony and reply with [`SurfaceEndpoint::reply_poll`].
    PollQuarantine,
}

enum Reply {
    Run(CeremonyReply),
    Poll(Option<CeremonyDriver>),
}

/// The owner thread's half: a [`CeremonyHost`] that forwards each command to the surface thread.
pub struct ChannelHost {
    requests: SyncSender<SurfaceRequest>,
    replies: Receiver<Reply>,
}

/// The surface thread's half.
pub struct SurfaceEndpoint {
    requests: Receiver<SurfaceRequest>,
    replies: SyncSender<Reply>,
}

/// Create the two halves of the hand-off.
#[must_use]
pub fn channel() -> (ChannelHost, SurfaceEndpoint) {
    let (requests, incoming) = sync_channel(1);
    let (replies, outgoing) = sync_channel(1);
    (
        ChannelHost {
            requests,
            replies: outgoing,
        },
        SurfaceEndpoint {
            requests: incoming,
            replies,
        },
    )
}

impl CeremonyHost for ChannelHost {
    /// Hand `driver` to the surface thread and block for its reply (see the module documentation).
    /// A surface thread that is gone fails the ceremony with `Unavailable(InterfaceUnavailable)`
    /// and returns the driver; one that vanishes after accepting it ends the ceremony as
    /// `Quarantine(CleanupTimeout)`.
    fn run(&mut self, driver: CeremonyDriver) -> CeremonyReply {
        if let Err(refused) = self.requests.send(SurfaceRequest::Run(Box::new(driver))) {
            let driver = match refused.0 {
                SurfaceRequest::Run(driver) => Some(*driver),
                SurfaceRequest::PollQuarantine => None,
            };
            return CeremonyReply {
                result: Err(UNAVAILABLE),
                driver,
            };
        }
        match self.replies.recv() {
            Ok(Reply::Run(reply)) => reply,
            Ok(Reply::Poll(_)) | Err(RecvError) => CeremonyReply {
                result: Err(ABANDONED),
                driver: None,
            },
        }
    }

    fn poll_quarantine(&mut self) -> Option<CeremonyDriver> {
        self.requests.send(SurfaceRequest::PollQuarantine).ok()?;
        match self.replies.recv() {
            Ok(Reply::Poll(driver)) => driver,
            Ok(Reply::Run(_)) | Err(RecvError) => None,
        }
    }
}

impl SurfaceEndpoint {
    /// Block for the next command; `None` once the owner side is gone.
    #[must_use]
    pub fn recv(&self) -> Option<SurfaceRequest> {
        self.requests.recv().ok()
    }

    /// Take the next command if one is waiting, for a message loop that must not block.
    ///
    /// # Errors
    ///
    /// Returns `Empty` when no command is waiting and `Disconnected` once the owner side is gone.
    pub fn try_recv(&self) -> Result<SurfaceRequest, TryRecvError> {
        self.requests.try_recv()
    }

    /// Answer a `Run` command. Returns `false` when the owner side is gone.
    #[must_use]
    pub fn reply_run(&self, reply: CeremonyReply) -> bool {
        self.replies.send(Reply::Run(reply)).is_ok()
    }

    /// Answer a `PollQuarantine` command. Returns `false` when the owner side is gone.
    #[must_use]
    pub fn reply_poll(&self, driver: Option<CeremonyDriver>) -> bool {
        self.replies.send(Reply::Poll(driver)).is_ok()
    }
}
