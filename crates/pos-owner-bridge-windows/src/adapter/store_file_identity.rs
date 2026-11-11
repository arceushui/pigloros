#![cfg(windows)]
#![cfg(any(test, feature = "test-support"))]
#![forbid(unsafe_code)]

use std::fs::File;
use std::os::windows::fs::MetadataExt;

use pos_owner_bridge::{BridgeError, UnavailableCode};

/// Observe candidate Windows `[volume_serial, file_index]` metadata.
///
/// This is a handle snapshot, not a store binding or encryption authority.
/// The caller must separately establish the connection-owned `SQLite` main-file
/// handle, its lifetime, and the remaining ADR-097/ADR-132 activation gates.
/// Hard-link aliases of the same file intentionally yield the same identity.
///
/// # Errors
/// Refuses non-regular or reparse files, a non-private owner/DACL, non-NTFS
/// handles, mismatched volume observations or any metadata failure.
pub fn store_file_id(file: &File) -> Result<[u64; 2], BridgeError> {
    candidate(file).map_err(|()| BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable))
}

fn candidate(file: &File) -> Result<[u64; 2], ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
        return Err(());
    }
    crate::Native::require_private_file(file)?;
    let volume = crate::Native::cleanup_file_volume(file)?;
    let (observed_volume, index) = crate::Native::file_identity(file)?;
    if observed_volume != volume {
        return Err(());
    }
    Ok([u64::from(volume), index])
}

#[cfg(test)]
impl crate::Native {
    pub(crate) fn exercise_store_file_identity() -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::{self, OpenOptions};
        use std::os::windows::fs::OpenOptionsExt;
        use std::path::PathBuf;
        use std::process::Command;
        use std::time::{SystemTime, UNIX_EPOCH};
        use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _removed = fs::remove_dir_all(&self.0);
            }
        }
        let path = std::env::temp_dir().join(format!(
            "piglor-store-id-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&path)?;
        let fixture = Fixture(path);
        let private = fixture.0.join("private");
        crate::create_private_directory(&private)
            .map_err(|_| "create private fixture directory")?;
        Self::exercise_default_owner_refusal(&private)?;
        let original = private.join("store.db");
        let file =
            Self::create_private_ledger_file(&original).map_err(|()| "create identity fixture")?;
        Self::diagnose_private_file(&file)?;
        Self::cleanup_file_volume(&file).map_err(|()| "original file NTFS admission")?;
        Self::file_identity(&file).map_err(|()| "original file identity observation")?;
        let identity = store_file_id(&file).map_err(|_| "original candidate identity")?;
        assert_eq!(
            store_file_id(&file.try_clone()?).map_err(|_| "cloned handle identity")?,
            identity
        );
        let alias = private.join("alias.db");
        fs::hard_link(&original, &alias)?;
        assert_eq!(
            store_file_id(&File::open(&alias)?).map_err(|_| "hardlink identity")?,
            identity
        );
        let copied = private.join("copy.db");
        let copied_file =
            Self::create_private_ledger_file(&copied).map_err(|()| "create copy fixture")?;
        drop(copied_file);
        fs::write(&copied, fs::read(&original)?)?;
        assert_ne!(
            store_file_id(&File::open(&copied)?).map_err(|_| "copied file identity")?,
            identity
        );
        let moved = private.join("moved.db");
        fs::rename(&original, &moved)?;
        let replacement = Self::create_private_ledger_file(&original)
            .map_err(|()| "create replacement fixture")?;
        assert_eq!(
            store_file_id(&file).map_err(|_| "moved handle identity")?,
            identity
        );
        assert_ne!(
            store_file_id(&replacement).map_err(|_| "replacement file identity")?,
            identity
        );
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(&private)?;
        assert_eq!(
            store_file_id(&directory),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        drop(directory);
        let device = File::open("NUL")?;
        assert_eq!(
            store_file_id(&device),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        drop(device);
        let result = Command::new("icacls.exe")
            .arg(&moved)
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()?;
        assert!(result.status.success());
        assert_eq!(
            store_file_id(&file),
            Err(BridgeError::Unavailable(
                UnavailableCode::InterfaceUnavailable
            ))
        );
        drop(replacement);
        drop(file);
        Ok(())
    }

    fn exercise_default_owner_refusal(
        private: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write as _;

        let path = private.join("default-owner-fixture.db");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        let wrong_owner = match Self::diagnose_private_file(&file) {
            Ok(()) => false,
            Err(detail) => {
                let actual = detail
                    .split_once("actual=O:")
                    .and_then(|(_, tail)| tail.split_once("D:"))
                    .ok_or("default fixture security observation failed")?
                    .0;
                let expected = detail
                    .split_once("expected=[\"O:")
                    .and_then(|(_, tail)| tail.split_once("D:"))
                    .ok_or("default fixture expected owner unavailable")?
                    .0;
                actual != expected
            }
        };
        if wrong_owner {
            assert!(store_file_id(&file).is_err());
            writeln!(std::io::stderr(), "SNL1_WRONG_OWNER_CASE=qualified")?;
        } else {
            writeln!(std::io::stderr(), "SNL1_WRONG_OWNER_CASE=unqualified")?;
        }
        drop(file);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
