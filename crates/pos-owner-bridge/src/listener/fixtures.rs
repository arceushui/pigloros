//! Closed compiled qualification responses (ADR-131). No arbitrary asset input.

use super::{assets::Response, fixture_assets};

/// Sealed qualification assets, available only with `test-support`.
///
/// These do not invoke an authenticator and cannot qualify real PRF results.
/// The production Windows host always uses `ListenerConfig::adr`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureProfile {
    /// Valid receipt and abort through real SDK buffers, pending credentials.
    Pending,
    /// Attempt one popup, which the real handler must mark handled.
    Popup,
    /// Attempt a popup only after the shared protocol receives a valid pair.
    PopupReceipt,
    /// Request notification permission; the real permission handler must deny it.
    Permission,
    /// Attempt the fixed Settings URI for isolated External and composed denial cases.
    External,
    /// Attempt navigation to one fixed disallowed loopback path.
    Navigation,
    /// Serve the owned URL as a fixed attachment, which must be cancelled.
    Download,
    /// Serve one fixed Basic challenge, without supplying credentials.
    Authentication,
    /// After valid receipt, write the SDK request buffer posted `READ_ONLY`.
    /// Adversarial renderer-crash evidence; never a normal G3 delivery case.
    ReadOnlyWrite,
    /// The same event adapter with its write disarmed, as a no-crash control.
    ReadOnlyControl,
    /// Duplicate the first real request event before its matching reply.
    DuplicateRequest,
    /// Deliver a retired reply between a newer request and its matching reply.
    /// Withhold newer replies until that insertion actually occurs.
    InterleavedPair,
    /// Hold real SDK deliveries for 700 ms, crossing the first two retry windows.
    DelayedDelivery,
    /// Fixed public test-key assertion for the native Get plan, resolved after 100 ms.
    /// Exercises successful protocol completion; no real authenticator is used.
    SuccessfulGet,
    /// The same assertion, with a declared 2.5 s page stall after `READY`.
    /// Exercises release expiry and host zeroization of a nonzero reply.
    SuccessfulGetReleaseDelay,
    /// Hold the getter for 1.5 s after the core enters `WRITING`, before encoding.
    /// Adversarial fault scheduling; never part of normal G3 delivery.
    SuccessfulGetWritingDelay,
    /// Retain real SDK events until teardown, exercising all real EMPTY retries.
    /// Adversarial delivery withholding; never a normal G3 delivery case.
    WithheldDelivery,
}

impl FixtureProfile {
    pub(super) const fn response(self) -> &'static Response {
        match self {
            Self::Pending => &fixture_assets::PENDING,
            Self::Popup => &fixture_assets::POPUP,
            Self::PopupReceipt => &fixture_assets::POPUP_RECEIPT,
            Self::Permission => &fixture_assets::PERMISSION,
            Self::External => &fixture_assets::EXTERNAL,
            Self::Navigation => &fixture_assets::NAVIGATION,
            Self::Download => &fixture_assets::DOWNLOAD,
            Self::Authentication => &fixture_assets::AUTHENTICATION,
            Self::ReadOnlyWrite => &fixture_assets::READONLY_WRITE,
            Self::ReadOnlyControl => &fixture_assets::READONLY_CONTROL,
            Self::DuplicateRequest => &fixture_assets::DUPLICATE_REQUEST,
            Self::InterleavedPair => &fixture_assets::INTERLEAVED_PAIR,
            Self::DelayedDelivery => &fixture_assets::DELAYED_DELIVERY,
            Self::SuccessfulGet => &fixture_assets::SUCCESSFUL_GET,
            Self::SuccessfulGetReleaseDelay => &fixture_assets::SUCCESSFUL_GET_RELEASE_DELAY,
            Self::SuccessfulGetWritingDelay => &fixture_assets::SUCCESSFUL_GET_WRITING_DELAY,
            Self::WithheldDelivery => &fixture_assets::WITHHELD_DELIVERY,
        }
    }
}
