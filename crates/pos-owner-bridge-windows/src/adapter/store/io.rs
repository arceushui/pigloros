#![cfg(windows)]
#![forbid(unsafe_code)]

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

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
    fn metadata(&self, file: &File) -> io::Result<Metadata>;
    fn inspect(&self, path: &Path) -> io::Result<Metadata>;
    fn entries(&self, path: &Path) -> io::Result<Vec<PathBuf>>;
    fn create_directory(&self, path: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_tree(&self, path: &Path) -> io::Result<()>;
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
    fn metadata(&self, file: &File) -> io::Result<Metadata> {
        file.metadata()
    }
    fn inspect(&self, path: &Path) -> io::Result<Metadata> {
        fs::symlink_metadata(path)
    }
    fn entries(&self, path: &Path) -> io::Result<Vec<PathBuf>> {
        fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect()
    }
    fn create_directory(&self, path: &Path) -> io::Result<()> {
        crate::create_private_directory(path).map_err(io::Error::other)
    }
    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }
    fn remove_tree(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
}

fn failure() -> io::Error {
    io::Error::other("cleanup storage operation failed")
}
