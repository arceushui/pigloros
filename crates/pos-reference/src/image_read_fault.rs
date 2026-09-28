//! Inject one read failure for an exact held inode and offset. Other
//! concurrent selector tests and all production builds are unaffected.

use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt as _;
use std::sync::Mutex;

static FAULTS: Mutex<Vec<(u64, u64, u64)>> = Mutex::new(Vec::new());

pub(super) struct ImageReadFault((u64, u64, u64));

impl ImageReadFault {
    pub(super) fn new(file: &File, offset: u64) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let key = (metadata.dev(), metadata.ino(), offset);
        FAULTS
            .lock()
            .map_err(|_| io::Error::other("image read fault registry poisoned"))?
            .push(key);
        Ok(Self(key))
    }

    pub(super) fn was_triggered(&self) -> io::Result<bool> {
        FAULTS
            .lock()
            .map(|faults| !faults.contains(&self.0))
            .map_err(|_| io::Error::other("image read fault registry poisoned"))
    }
}

impl Drop for ImageReadFault {
    fn drop(&mut self) {
        if let Ok(mut faults) = FAULTS.lock() {
            faults.retain(|key| key != &self.0);
        }
    }
}

pub(super) fn take(file: &File, offset: u64) -> bool {
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    let Ok(mut faults) = FAULTS.lock() else {
        return false;
    };
    let key = (metadata.dev(), metadata.ino(), offset);
    let Some(index) = faults.iter().position(|fault| *fault == key) else {
        return false;
    };
    faults.remove(index);
    true
}
