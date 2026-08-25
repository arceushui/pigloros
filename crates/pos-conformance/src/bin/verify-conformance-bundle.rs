#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_conformance::verify_archive_independently;
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::path::Path;

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
    let bytes = std::fs::read(path)?;
    verify_archive_independently(&bytes).map_err(Into::into)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{run, verify_path};
    use std::ffi::OsString;
    use std::fs;

    #[test]
    fn verifier_argument_errors_are_explicit() {
        assert!(run([OsString::from("verify")].into_iter()).is_err());
        let missing =
            std::env::temp_dir().join(format!("pigloros-missing-cfb1-{}", std::process::id()));
        assert!(run([OsString::from("verify"), missing.into_os_string()].into_iter()).is_err());
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
}
