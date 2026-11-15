#![cfg(windows)]
#![forbid(unsafe_code)]

//! Filesystem observations used by runtime admission. The policy consumes the
//! same result values from Windows and from controlled I/O-failure fixtures.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub(super) trait RuntimeIo {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
    fn open(&self, path: &Path, options: &OpenOptions) -> io::Result<File>;
    fn identity(&self, file: &File) -> Result<(u32, u64), ()>;
    fn metadata(&self, path: &Path) -> io::Result<Metadata>;
    fn file_metadata(&self, file: &File) -> io::Result<Metadata>;
    fn entries(&self, path: &Path) -> io::Result<Vec<io::Result<PathBuf>>>;
    fn private_directory(&self, path: &Path, create: bool) -> Result<(), ()>;
    fn read(&self, file: &mut File, buffer: &mut [u8]) -> io::Result<usize>;
    fn read_bounded(&self, file: &mut File, maximum: u64) -> io::Result<Vec<u8>>;
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()>;
}

pub(super) struct OsIo;

impl RuntimeIo for OsIo {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        path.canonicalize()
    }

    fn open(&self, path: &Path, options: &OpenOptions) -> io::Result<File> {
        options.open(path)
    }

    fn identity(&self, file: &File) -> Result<(u32, u64), ()> {
        crate::Native::file_identity(file)
    }

    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        std::fs::symlink_metadata(path)
    }

    fn file_metadata(&self, file: &File) -> io::Result<Metadata> {
        file.metadata()
    }

    fn entries(&self, path: &Path) -> io::Result<Vec<io::Result<PathBuf>>> {
        std::fs::read_dir(path).map(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.path()))
                .collect()
        })
    }

    fn private_directory(&self, path: &Path, create: bool) -> Result<(), ()> {
        if create {
            crate::create_private_directory(path)
        } else {
            crate::verify_private_directory(path)
        }
        .map_err(super::failed)
    }

    fn read(&self, file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
        file.read(buffer)
    }

    fn read_bounded(&self, file: &mut File, maximum: u64) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        file.take(maximum).read_to_end(&mut bytes).map(|_| bytes)
    }

    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)
    }
}
