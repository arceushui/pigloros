#![cfg(windows)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf, Prefix};

use pos_owner_bridge::{folder_name, CleanupError, CleanupStore};
use pos_owner_bridge_codec::decode_cleanup_record;
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH,
};

use super::io::{FileIo, OsIo};

type Result<T> = std::result::Result<T, CleanupError>;
const REPARSE_POINT: u32 = 0x400;

pub(super) struct Files {
    root: PathBuf,
    records: PathBuf,
    directory: File,
    volume: u32,
    provenance: BTreeMap<Vec<u8>, Vec<PathBuf>>,
    io: Box<dyn FileIo>,
}

impl Files {
    pub(super) fn open(root: PathBuf) -> Result<Self> {
        Self::open_with(root, Box::new(OsIo))
    }

    pub(super) fn open_with(root: PathBuf, io: Box<dyn FileIo>) -> Result<Self> {
        require_dos_path(&root)?;
        crate::verify_private_directory(&root).map_err(|_| CleanupError)?;
        io.qualify_path(&root).map_err(|_| CleanupError)?;
        let records = root.join("records");
        match io.inspect(&records) {
            Ok(_) => crate::verify_private_directory(&records).map_err(|_| CleanupError)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                io.create_directory(&records).map_err(|_| CleanupError)?;
            }
            Err(_) => return Err(CleanupError),
        }
        let directory = io
            .open(
                &records,
                OpenOptions::new()
                    .read(true)
                    .share_mode(3)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0 | FILE_FLAG_OPEN_REPARSE_POINT.0),
            )
            .map_err(|_| CleanupError)?;
        let volume = io.volume(&directory).map_err(|_| CleanupError)?;
        Ok(Self {
            root,
            records,
            directory,
            volume,
            provenance: BTreeMap::new(),
            io,
        })
    }

    fn admit(&self) -> Result<()> {
        crate::verify_private_directory(&self.root).map_err(|_| CleanupError)?;
        crate::verify_private_directory(&self.records).map_err(|_| CleanupError)?;
        self.same_volume(&self.directory)
    }

    fn same_volume(&self, file: &File) -> Result<()> {
        if self.io.volume(file).map_err(|_| CleanupError)? != self.volume {
            return Err(CleanupError);
        }
        Ok(())
    }

    fn read_path(&self, path: &Path) -> Result<(Vec<u8>, u64)> {
        let mut file = self
            .io
            .open(
                path,
                OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0),
            )
            .map_err(|_| CleanupError)?;
        let metadata = self.io.metadata(&file).map_err(|_| CleanupError)?;
        if !metadata.is_file() || metadata.file_attributes() & REPARSE_POINT != 0 {
            return Err(CleanupError);
        }
        self.same_volume(&file)?;
        let bytes = self.io.read(&mut file).map_err(|_| CleanupError)?;
        Ok((bytes, metadata.len()))
    }
}

impl CleanupStore for Files {
    fn write_record(&mut self, bytes: &[u8]) -> Result<()> {
        self.admit()?;
        let record = decode_cleanup_record(bytes).map_err(|_| CleanupError)?;
        let name = folder_name(&record.ceremony_id());
        if record.folder_name() != name {
            return Err(CleanupError);
        }
        let pending = self.records.join(format!("{name}.pending"));
        let committed = self.records.join(format!("{name}.pbcr"));
        let mut file = self
            .io
            .open(
                &pending,
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .share_mode(0)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_WRITE_THROUGH.0),
            )
            .map_err(|_| CleanupError)?;
        self.same_volume(&file)?;
        self.io.write(&mut file, bytes).map_err(|_| CleanupError)?;
        self.io.flush(&file).map_err(|_| CleanupError)?;
        // Rust Drop cannot report a close error. Publication/readback supply
        // the remaining observable gates; neither name is removed on failure.
        drop(file);
        self.io
            .publish(&pending, &committed)
            .map_err(|_| CleanupError)?;
        let (observed, length) = self.read_path(&committed)?;
        if length != bytes.len() as u64 || observed != bytes {
            return Err(CleanupError);
        }
        self.provenance
            .entry(bytes.to_vec())
            .or_default()
            .push(committed);
        Ok(())
    }

    fn records(&mut self) -> Result<Vec<Vec<u8>>> {
        self.admit()?;
        let mut listed = Vec::new();
        let mut provenance: BTreeMap<Vec<u8>, Vec<PathBuf>> = BTreeMap::new();
        for path in self.io.entries(&self.records).map_err(|_| CleanupError)? {
            if !recognized_record(&path)? {
                continue;
            }
            let (bytes, _) = self.read_path(&path)?;
            provenance.entry(bytes.clone()).or_default().push(path);
            listed.push(bytes);
        }
        // A partial/failed scan never replaces the last complete provenance.
        self.provenance = provenance;
        Ok(listed)
    }

    fn delete_record(&mut self, bytes: &[u8]) -> Result<()> {
        self.admit()?;
        let paths = self.provenance.get(bytes).ok_or(CleanupError)?;
        let mut candidates = Vec::new();
        for path in paths {
            match self.io.inspect(path) {
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(_) => return Err(CleanupError),
                Ok(_) => {}
            }
            let (observed, length) = self.read_path(path)?;
            if length != bytes.len() as u64 || observed != bytes {
                return Err(CleanupError);
            }
            candidates.push(path);
        }
        let [path] = candidates.as_slice() else {
            return Err(CleanupError);
        };
        self.io.remove_file(path).map_err(|_| CleanupError)?;
        self.provenance.remove(bytes);
        Ok(())
    }

    fn folders(&mut self) -> Result<Vec<String>> {
        self.admit()?;
        let mut folders = Vec::new();
        for path in self.io.entries(&self.root).map_err(|_| CleanupError)? {
            let Some(name) = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .filter(|name| ceremony_name(name))
            else {
                continue;
            };
            let metadata = self.io.inspect(&path).map_err(|_| CleanupError)?;
            if !metadata.is_dir() || metadata.file_attributes() & REPARSE_POINT != 0 {
                return Err(CleanupError);
            }
            folders.push(name.to_owned());
        }
        Ok(folders)
    }

    fn remove_folder(&mut self, name: &str) -> Result<()> {
        if !ceremony_name(name) {
            return Err(CleanupError);
        }
        self.admit()?;
        let path = self.root.join(name);
        match self.io.inspect(&path) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Ok(metadata)
                if metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT == 0 => {}
            _ => return Err(CleanupError),
        }
        // The fixed root/name were qualified above. The standard library's
        // recursive removal does not follow symbolic links within the tree.
        self.io.remove_tree(&path).map_err(|_| CleanupError)
    }
}

fn ceremony_name(name: &str) -> bool {
    name.len() == 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn recognized_record(path: &Path) -> Result<bool> {
    let Some(extension) = path.extension().and_then(std::ffi::OsStr::to_str) else {
        return Ok(false);
    };
    if !extension.eq_ignore_ascii_case("pending") && !extension.eq_ignore_ascii_case("pbcr") {
        return Ok(false);
    }
    if !matches!(extension, "pending" | "pbcr")
        || !path
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(ceremony_name)
    {
        return Err(CleanupError);
    }
    Ok(true)
}

fn require_dos_path(path: &Path) -> Result<()> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || components.next() != Some(Component::RootDir)
        || components.any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(CleanupError);
    }
    Ok(())
}
