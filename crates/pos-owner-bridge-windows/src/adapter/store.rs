#![cfg(windows)]
#![forbid(unsafe_code)]

use pos_owner_bridge::{CleanupError, CleanupStore};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod files;
mod io;

#[cfg(test)]
mod tests;

/// A synchronized handle to the same cleanup store used by the surface STA.
///
/// `OwnerBridge` uses a clone for restart admission. A poisoned lock refuses every
/// operation; it never turns an incomplete read into an empty record list.
#[derive(Clone)]
pub struct WindowsCleanupStore(Arc<Mutex<Box<dyn CleanupStore + Send>>>);

impl WindowsCleanupStore {
    /// Open the E17 cleanup store beneath an existing private state root.
    ///
    /// The local fixed NTFS profile uses flushed, exclusive pending files,
    /// no-replace write-through publication and exact readback. Its durability
    /// claim is conditional on the storage assumptions accepted in ADR-110 E17.
    /// Clones share the same scan/write provenance and synchronization.
    ///
    /// # Errors
    ///
    /// Refuses an unprotected root, non-DOS path, reparse ancestry, unsupported
    /// volume or failed native/filesystem admission.
    pub fn open(root: PathBuf) -> Result<Self, CleanupError> {
        files::Files::open(root).map(Self::new)
    }

    pub(super) fn new(store: impl CleanupStore + Send + 'static) -> Self {
        Self(Arc::new(Mutex::new(Box::new(store))))
    }
}

impl CleanupStore for WindowsCleanupStore {
    fn write_record(&mut self, record: &[u8]) -> Result<(), CleanupError> {
        #[cfg(test)]
        let _duration = crate::Native::readiness_span("record-publication");
        let mut store = self.0.lock().map_err(|_| CleanupError)?;
        store.write_record(record)
    }

    fn delete_record(&mut self, record: &[u8]) -> Result<(), CleanupError> {
        self.0
            .lock()
            .map_err(|_| CleanupError)?
            .delete_record(record)
    }

    fn records(&mut self) -> Result<Vec<Vec<u8>>, CleanupError> {
        self.0.lock().map_err(|_| CleanupError)?.records()
    }

    fn folders(&mut self) -> Result<Vec<String>, CleanupError> {
        self.0.lock().map_err(|_| CleanupError)?.folders()
    }

    fn remove_folder(&mut self, folder: &str) -> Result<(), CleanupError> {
        self.0
            .lock()
            .map_err(|_| CleanupError)?
            .remove_folder(folder)
    }
}
