#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_conformance::verify_archive_independently;
use std::env;
use std::error::Error;
use std::path::Path;

#[cfg_attr(coverage_nightly, coverage(off))]
fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
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
    verify_archive_independently(&bytes)?;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::verify_path;
    use std::fs;

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
