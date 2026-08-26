#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_conformance::{verify_archive_independently, MAX_CONFORMANCE_BUNDLE_BYTES_V1};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    run(env::args_os())
}

fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    run_with_verifier(&mut arguments, verify_path)
}

fn run_with_verifier(
    arguments: &mut impl Iterator<Item = OsString>,
    verify: impl Fn(&Path) -> Result<(), Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let _program = arguments.next();
    let paths = arguments.collect::<Vec<_>>();
    if paths.is_empty() {
        return Err("usage: verify-conformance-bundle <archive>...".into());
    }
    for path in paths {
        verify(Path::new(&path))?;
    }
    Ok(())
}

fn verify_path(path: &Path) -> Result<(), Box<dyn Error>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let bytes = read_bounded(file, metadata.len(), MAX_CONFORMANCE_BUNDLE_BYTES_V1)?;
    verify_archive_independently(&bytes).map_err(Into::into)
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
    let mut bytes = Vec::with_capacity(usize::try_from(declared_len).unwrap_or(0));
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
    use super::{main, read_bounded, run, run_with_verifier, verify_path};
    use std::ffi::OsString;
    use std::fs;
    use std::io::Cursor;

    #[test]
    fn verifier_argument_errors_are_explicit() {
        assert!(run([OsString::from("verify")].into_iter()).is_err());
        let missing =
            std::env::temp_dir().join(format!("pigloros-missing-cfb1-{}", std::process::id()));
        assert!(run([OsString::from("verify"), missing.into_os_string()].into_iter()).is_err());
    }

    #[test]
    fn verifier_main_wires_the_process_arguments() {
        assert!(main().is_err());
    }

    #[test]
    fn verifier_accepts_each_path_when_the_independent_verifier_accepts() {
        let mut arguments = [OsString::from("verify"), OsString::from("archive.cbor")].into_iter();
        assert!(run_with_verifier(&mut arguments, |_| Ok(())).is_ok());
    }

    #[test]
    fn verify_path_rejects_invalid_archive() -> Result<(), Box<dyn std::error::Error>> {
        let path =
            std::env::temp_dir().join(format!("pigloros-invalid-cfb1-{}.cbor", std::process::id()));
        fs::write(&path, [0x9f, 0xff])?;
        let result = verify_path(&path);
        fs::remove_file(&path)?;
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn bounded_reader_rejects_declared_and_observed_oversize() {
        assert!(read_bounded(Cursor::new([]), 6, 5).is_err());
        assert!(read_bounded(Cursor::new([0_u8; 6]), 5, 5).is_err());
        assert!(read_bounded(Cursor::new([]), 5, 5).is_ok());
        assert!(read_bounded(Cursor::new([0_u8; 5]), 5, 5).is_ok());
    }
}
