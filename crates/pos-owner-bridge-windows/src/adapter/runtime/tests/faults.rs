#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::{Cell, RefCell};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use super::super::{verify_with_io, OsIo, RuntimeIo};
use super::{Fixture, TestResult};

#[derive(Clone, Debug)]
struct Operation {
    kind: &'static str,
    path: PathBuf,
}

struct FaultIo {
    fail_at: Option<usize>,
    failed: Cell<bool>,
    calls: RefCell<Vec<Operation>>,
    opened: RefCell<PathBuf>,
}

impl FaultIo {
    fn new(fail_at: Option<usize>) -> Self {
        Self {
            fail_at,
            failed: Cell::new(false),
            calls: RefCell::new(Vec::new()),
            opened: RefCell::new(PathBuf::new()),
        }
    }

    fn observe(&self, kind: &'static str, path: &Path) -> io::Result<()> {
        let mut calls = self.calls.borrow_mut();
        calls.push(Operation {
            kind,
            path: path.to_owned(),
        });
        if self.fail_at == Some(calls.len()) {
            self.failed.set(true);
            Err(io::ErrorKind::PermissionDenied.into())
        } else {
            Ok(())
        }
    }
}

impl RuntimeIo for FaultIo {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        self.observe("canonicalize", path)?;
        OsIo.canonicalize(path)
    }
    fn metadata(&self, path: &Path) -> io::Result<Metadata> {
        self.observe("metadata", path)?;
        OsIo.metadata(path)
    }
    fn file_metadata(&self, file: &File) -> io::Result<Metadata> {
        self.observe("file_metadata", &self.opened.borrow())?;
        OsIo.file_metadata(file)
    }
    fn read(&self, file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
        self.observe("read", &self.opened.borrow())?;
        OsIo.read(file, buffer)
    }
    fn read_bounded(&self, file: &mut File, maximum: u64) -> io::Result<Vec<u8>> {
        self.observe("read_bounded", &self.opened.borrow())?;
        OsIo.read_bounded(file, maximum)
    }
    fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        self.observe("write", &self.opened.borrow())?;
        OsIo.write(file, bytes)
    }

    fn open(&self, path: &Path, options: &OpenOptions) -> io::Result<File> {
        self.observe("open", path)?;
        let result = OsIo.open(path, options);
        if result.is_ok() {
            *self.opened.borrow_mut() = path.to_owned();
        }
        result
    }

    fn identity(&self, file: &File) -> Result<(u32, u64), ()> {
        self.observe("identity", &self.opened.borrow())
            .map_err(super::super::failed)?;
        OsIo.identity(file)
    }

    fn private_directory(&self, path: &Path, create: bool) -> Result<(), ()> {
        self.observe("private_directory", path)
            .map_err(super::super::failed)?;
        OsIo.private_directory(path, create)
    }

    fn entries(&self, path: &Path) -> io::Result<Vec<io::Result<PathBuf>>> {
        self.observe("entries", path)?;
        OsIo.entries(path).map(|entries| {
            entries
                .into_iter()
                .map(|entry| entry.and_then(|path| self.observe("entry", &path).map(|()| path)))
                .collect()
        })
    }
}

fn prepare(f: &Fixture, state: u8, canonical: &[u8]) -> TestResult {
    match std::fs::remove_dir_all(&f.cache) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if state != 0 {
        crate::create_private_directory(&f.cache)?;
        std::fs::write(f.marker(), if state == 1 { canonical } else { b"stale" })?;
    }
    Ok(())
}

pub(super) fn verify(f: &Fixture) -> TestResult {
    assert!(f.verify().is_ok());
    let canonical = std::fs::read(f.marker())?;
    for state in 0..3 {
        prepare(f, state, &canonical)?;
        let baseline = FaultIo::new(None);
        assert!(verify_with_io(&f.runtime, &f.cache, &f.files, &[7; 32], &baseline).is_ok());
        let operations = baseline.calls.borrow().clone();
        let first_hash_read = operations
            .iter()
            .position(|op| op.kind == "read")
            .ok_or("baseline never read a runtime file")?;
        for (index, operation) in operations.iter().enumerate() {
            prepare(f, state, &canonical)?;
            let fault = FaultIo::new(Some(index + 1));
            let result = verify_with_io(&f.runtime, &f.cache, &f.files, &[7; 32], &fault);
            assert!(
                fault.failed.get(),
                "I/O failure was never injected: {operation:?}"
            );
            let cache_read = index < first_hash_read
                && operation.path == f.marker()
                && matches!(operation.kind, "metadata" | "open" | "read_bounded");
            assert_eq!(
                result.is_ok(),
                cache_read,
                "unexpected admission for {operation:?}, state {state}"
            );
            if cache_read {
                // A broken cache is only a hint failure: every actual file must
                // be read and a validated replacement marker must be produced.
                let observed = fault.calls.borrow();
                for file in &f.files {
                    let expected = f.runtime.join(file.path).canonicalize()?;
                    assert!(observed.iter().any(|op| op.kind == "read" && op.path == expected),
                        "cache failure {operation:?}, state {state} did not fully hash {expected:?}");
                }
                assert_eq!(std::fs::read(f.marker())?, canonical);
            }
        }
    }
    Ok(())
}
