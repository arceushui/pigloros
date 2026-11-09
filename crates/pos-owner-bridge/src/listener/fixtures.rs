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
    /// Request geolocation, which the real permission handler must deny.
    Permission,
    /// Attempt one fixed denied URI scheme.
    External,
    /// Attempt navigation to one fixed disallowed loopback path.
    Navigation,
    /// Serve the owned URL as a fixed attachment, which must be cancelled.
    Download,
    /// Serve one fixed Basic challenge, without supplying credentials.
    Authentication,
    /// After valid receipt, write the SDK request buffer posted READ_ONLY.
    /// Adversarial renderer-crash evidence; never a normal G3 delivery case.
    ReadOnlyWrite,
    /// The same event adapter with its write disarmed, as a no-crash control.
    ReadOnlyControl,
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
        }
    }
}
