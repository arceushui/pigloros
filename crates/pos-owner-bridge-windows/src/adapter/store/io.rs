#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use pos_owner_bridge_codec::MAX_CLEANUP_RECORD_BYTES;

/// Private effect seam for interruption and native-failure qualification.
pub(super) trait FileIo: Send {
    fn qualify_path(&self, path: &Path) -> io::Result<()>;
    fn volume(&self, file: &File) -> io::Result<u32>;
    fn open(&self, path: &Path, options: &OpenOptions) -> io::Result<File>;
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()>;
    fn flush(&self, file: &File) -> io::Result<()>;
    fn publish(&self, pending: &Path, committed: &Path) -> io::Result<()>;
    fn read(&self, file: &mut File) -> io::Result<Vec<u8>>;
}

pub(super) struct OsIo;

impl FileIo for OsIo {
    fn qualify_path(&self, path: &Path) -> io::Result<()> {
        crate::Native::cleanup_path_ntfs(path).map_err(|()| failure())
    }
    fn volume(&self, file: &File) -> io::Result<u32> {
        crate::Native::cleanup_file_volume(file).map_err(|()| failure())
    }
    fn open(&self, path: &Path, options: &OpenOptions) -> io::Result<File> {
        options.open(path)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)
    }
    fn flush(&self, file: &File) -> io::Result<()> {
        file.sync_all()
    }
    fn publish(&self, pending: &Path, committed: &Path) -> io::Result<()> {
        crate::Native::publish_cleanup(pending, committed).map_err(|()| failure())
    }
    fn read(&self, file: &mut File) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        file.take((MAX_CLEANUP_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

fn failure() -> io::Error {
    io::Error::other("cleanup storage operation failed")
}
