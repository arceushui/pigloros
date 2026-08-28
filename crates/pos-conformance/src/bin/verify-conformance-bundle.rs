#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_conformance::{verify_archive_release_filename, MAX_CONFORMANCE_BUNDLE_BYTES_V1};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const INITIAL_READ_CAPACITY: u64 = 65_536;

fn main() -> Result<(), Box<dyn Error>> {
    run(env::args_os())
}

fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let _program = arguments.next();
    let paths = arguments.collect::<Vec<_>>();
    if paths.is_empty() {
        return Err("usage: verify-conformance-bundle <archive>...".into());
    }
    for path in paths {
        verify_path(Path::new(&path))?;
    }
    Ok(())
}

fn verify_path(path: &Path) -> Result<(), Box<dyn Error>> {
    let (file, declared_len) = open_regular_file(path)?;
    let bytes = read_bounded(file, declared_len, MAX_CONFORMANCE_BUNDLE_BYTES_V1)?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("conformance archive filename is not canonical UTF-8")?;
    verify_archive_release_filename(&bytes, filename).map_err(Into::into)
}

fn open_regular_file(path: &Path) -> Result<(File, u64), Box<dyn Error>> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK.saturating_add(libc::O_NOFOLLOW))
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "conformance bundle path is not a regular file",
            )
            .into());
        }
        Ok((file, metadata.len()))
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "regular-file conformance verification is unsupported on this platform",
        )
        .into())
    }
}

fn read_bounded(
    reader: impl Read,
    declared_len: u64,
    limit: u64,
) -> Result<Vec<u8>, Box<dyn Error>> {
    if declared_len > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "conformance bundle archive exceeds the public size limit",
        )
        .into());
    }
    let initial_capacity =
        usize::try_from(declared_len.min(INITIAL_READ_CAPACITY)).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(initial_capacity);
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "conformance bundle archive exceeds the public size limit",
        )
        .into());
    }
    Ok(bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{read_bounded, run, verify_path};
    use std::ffi::OsString;
    use std::fs;
    use std::io::{self, Cursor, Read};
    #[cfg(unix)]
    use std::process::Command;

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture reader failed"))
        }
    }

    #[test]
    fn verify_path_rejects_a_directory_before_opening_it() -> Result<(), Box<dyn std::error::Error>>
    {
        let path =
            std::env::temp_dir().join(format!("pigloros-directory-cfb1-{}", std::process::id()));
        fs::create_dir(&path)?;
        let result = verify_path(&path);
        fs::remove_dir(&path)?;
        assert!(result.is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn verify_path_rejects_a_fifo_before_opening_it() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!("pigloros-fifo-cfb1-{}", std::process::id()));
        let status = Command::new("mkfifo").arg(&path).status()?;
        assert!(status.success());
        let result = verify_path(&path);
        fs::remove_file(&path)?;
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn bounded_reader_rejects_declared_and_observed_oversize() {
        assert!(read_bounded(Cursor::new([]), 6, 5).is_err());
        assert!(read_bounded(Cursor::new([0_u8; 6]), 5, 5).is_err());
        assert!(read_bounded(Cursor::new([]), 1024 * 1024 * 1024, 1024 * 1024 * 1024).is_ok());
        assert!(read_bounded(Cursor::new([]), 5, 5).is_ok());
        assert!(read_bounded(Cursor::new([0_u8; 5]), 5, 5).is_ok());
        assert!(read_bounded(FailingReader, 0, 5).is_err());
    }

    #[test]
    fn command_rejects_missing_and_invalid_archive_arguments(
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert!(run([OsString::from("verify-conformance-bundle")].into_iter()).is_err());

        let directory = std::env::temp_dir().join(format!(
            "pigloros-invalid-cfb1-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir(&directory)?;
        let path = directory.join(format!("{}.cfb1", "0".repeat(64)));
        fs::write(&path, b"invalid conformance archive")?;
        let result = run([
            OsString::from("verify-conformance-bundle"),
            path.clone().into_os_string(),
        ]
        .into_iter());
        fs::remove_file(path)?;
        fs::remove_dir(directory)?;
        assert!(result.is_err());
        Ok(())
    }
}
