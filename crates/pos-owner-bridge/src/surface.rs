//! The `OwnerWebSurface` seam (ADR-110 §10): everything a platform adapter supplies.

use std::fmt;

use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, ImagePathSha256, CREATE_REPLY_BUFFER_CAPACITY,
    GET_REPLY_BUFFER_CAPACITY, REQUEST_BUFFER_CAPACITY,
};
use zeroize::Zeroize;

use crate::BridgeError;

/// A surface failure, already classified by the adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SurfaceError {
    error: BridgeError,
}

impl SurfaceError {
    /// Wrap the classified failure `error`.
    #[must_use]
    pub const fn new(error: BridgeError) -> Self {
        Self { error }
    }

    /// Return the classified failure.
    #[must_use]
    pub const fn error(self) -> BridgeError {
        self.error
    }
}

/// What the surface needs to open one fresh ceremony environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceSpec {
    /// The ceremony the environment serves.
    pub ceremony_id: CeremonyId,
    /// The fresh user-data folder name (the lowercase hex ceremony ID).
    pub folder_name: String,
    /// An opaque handle of the owning application window, when one exists.
    pub owner_window: Option<u64>,
}

/// The browser process identity probed right after the controller exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    /// The browser process ID.
    pub browser_pid: u32,
    /// The process creation `FILETIME`.
    pub creation_filetime: u64,
    /// The SHA-256 of the browser image path.
    pub image_path_sha256: ImagePathSha256,
}

/// The identifier of one recorded main-frame navigation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NavigationId(pub u64);

/// The facts the host re-checks immediately before every post.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostGuard {
    /// The current host generation.
    pub generation: u32,
    /// The recorded navigation ID the post must still match.
    pub navigation_id: NavigationId,
    /// The listener's served count, which must be exactly one.
    pub served_count: u32,
}

/// Navigation, process and exit events reported by the surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SurfaceEvent {
    /// `DOMContentLoaded` for the given navigation.
    DomContentLoaded(NavigationId),
    /// A navigation, source or content-loading event after the first navigation.
    NavigationViolation,
    /// A frame was created.
    FrameCreated,
    /// The renderer or browser process failed.
    RendererFailed,
    /// The controller was lost.
    ControllerLost,
    /// The browser process exited.
    BrowserExited {
        /// The exited browser process ID.
        browser_pid: u32,
    },
}

/// The host-written request image, preallocated once.
///
/// It holds the challenge, the user handle and the PRF input, so its `Debug` output shows only
/// its length.
pub struct RequestImage {
    bytes: Box<[u8]>,
}

impl fmt::Debug for RequestImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestImage")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl RequestImage {
    /// Allocate a zeroed request image of the fixed request capacity.
    #[must_use]
    pub fn zeroed() -> Self {
        Self {
            bytes: vec![0; REQUEST_BUFFER_CAPACITY as usize].into_boxed_slice(),
        }
    }

    /// Borrow the image bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrow the image bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Drop for RequestImage {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A preallocated copy target for the reply buffer.
///
/// It holds the reply payload, including the PRF output, so its `Debug` output shows only its
/// active length and whether anything was written to it since its last wipe.
pub struct ReplyImage {
    bytes: Box<[u8]>,
    len: usize,
    dirty: bool,
}

impl fmt::Debug for ReplyImage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplyImage")
            .field("len", &self.len)
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

impl ReplyImage {
    /// Allocate a zeroed image able to hold the largest reply buffer.
    #[must_use]
    pub fn zeroed() -> Self {
        let largest = CREATE_REPLY_BUFFER_CAPACITY as usize;
        Self {
            bytes: vec![0; largest].into_boxed_slice(),
            len: largest,
            dirty: false,
        }
    }

    /// Select the active length for a reply of `kind`.
    pub const fn select(&mut self, kind: CeremonyKind) {
        self.len = match kind {
            CeremonyKind::Create => CREATE_REPLY_BUFFER_CAPACITY as usize,
            CeremonyKind::Get => GET_REPLY_BUFFER_CAPACITY as usize,
        };
    }

    /// Borrow the active bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// Mutably borrow the active bytes. The image counts as written from here on.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.dirty = true;
        let len = self.len;
        self.bytes.get_mut(..len).unwrap_or_default()
    }

    /// Zero every byte of the image; an image nothing wrote to since its last wipe is skipped.
    pub fn wipe(&mut self) {
        if self.dirty {
            self.bytes.zeroize();
            self.dirty = false;
        }
    }
}

impl Drop for ReplyImage {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The platform adapter that owns one `WebView`, its shared buffers and its lifecycle.
///
/// The Windows shim implements this over `WebView2`; `FakeSurface` implements it for tests.
/// The portable bridge only ever calls these methods, in the order the ceremony driver fixes.
pub trait OwnerWebSurface {
    /// Create a fresh folder, environment and controller, with settings readback.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when the surface cannot open.
    fn open(&mut self, spec: &SurfaceSpec) -> Result<ProcessIdentity, SurfaceError>;

    /// Navigate to the owner document and return the recorded navigation ID.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when navigation cannot start.
    fn navigate(&mut self) -> Result<NavigationId, SurfaceError>;

    /// Create both shared buffers and write the request image and reply header.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when a buffer cannot be created.
    fn create_and_write(
        &mut self,
        request: &RequestImage,
        reply_header: &[u8; 64],
    ) -> Result<(), SurfaceError>;

    /// Post the request buffer, then the reply buffer, after re-checking `guard`.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when the guard no longer holds or a post fails.
    fn post(&mut self, guard: &PostGuard) -> Result<(), SurfaceError>;

    /// Load the reply state word with sequentially consistent ordering.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when the word cannot be read.
    fn reply_load_state(&self) -> Result<u32, SurfaceError>;

    /// Compare-exchange the reply state word; `Ok(true)` means the exchange won.
    ///
    /// The host protocol writes the state word only by compare-exchange, never by plain store, so
    /// the seam offers no store.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when the word cannot be accessed.
    fn reply_compare_exchange(&self, current: u32, new: u32) -> Result<bool, SurfaceError>;

    /// Copy the full reply capacity with atomic loads.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when the buffer cannot be read.
    fn reply_copy(&self, out: &mut ReplyImage) -> Result<(), SurfaceError>;

    /// Zero the request mapping and the reply payload area, then close both buffers.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when a buffer cannot be zeroed or closed.
    fn zero_close_buffers(&mut self) -> Result<(), SurfaceError>;

    /// Close the controller while retaining the environment and the exit handler.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when the controller cannot be closed.
    fn close_controller(&mut self) -> Result<(), SurfaceError>;

    /// Take the next navigation, process or exit event, if any.
    fn take_event(&mut self) -> Option<SurfaceEvent>;

    /// After the browser exited: unregister the handler, drop the environment, remove the folder.
    ///
    /// # Errors
    ///
    /// Returns the classified failure when cleanup could not finish.
    fn finish(&mut self) -> Result<(), SurfaceError>;
}
