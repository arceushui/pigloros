//! The ADR-110 owner bridge: loopback listener, ceremony state machine, owner ports and cleanup.
//!
//! This crate is the portable, `forbid(unsafe_code)` core. A platform adapter implements
//! [`OwnerWebSurface`]; the ADR-091 owner adapter implements the enrollment and unlock ports.
//! Behind the `test-support` feature, `fake` supplies a scripted page, `FakeSurface` and
//! deterministic ports so full flows run without a `WebView`.

pub mod bridge;
pub mod ceremony;
pub mod channel;
pub mod enroll;
pub mod error;
#[cfg(feature = "test-support")]
pub mod fake;
pub mod host;
pub mod listener;
pub mod prf;
pub mod random;
pub mod status;
pub mod surface;
pub mod unlock;

pub use bridge::{BridgeConfig, OwnerBridge, RestartProgress};
pub use enroll::{ConfirmedBinding, EnrollmentContext, EnrollmentPort, RootFingerprint};
pub use error::{
    BridgeError, ErrorClass, LifecycleCode, OwnerError, OwnerErrorKind, ProtocolCode,
    QuarantineCode, RejectedCode, UnavailableCode,
};
pub use host::{
    cleanup_record_bytes, folder_name, CeremonyHost, CeremonyReply, CleanupError, CleanupStore,
    LoopbackPort, ProbeResult, ProcessProbe, QuarantineKeeper, QuarantinePoll, ServedSnapshot,
};
pub use prf::PrfOutput;
pub use random::{MonotonicClock, OsRandom, SecureRandom, SystemClock};
pub use status::BridgeStatus;
pub use surface::{
    NavigationId, OwnerWebSurface, PostGuard, ProcessIdentity, ReplyImage, RequestImage,
    SurfaceError, SurfaceEvent, SurfaceSpec,
};
pub use unlock::{BindingUpdate, UnlockPort};
