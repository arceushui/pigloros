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
    use tempfile::TempDir;

    #[test]
    fn verify_path_rejects_invalid_archive() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("invalid.cfb1");
        fs::write(&path, [0x9f, 0xff])?;
        assert!(verify_path(&path).is_err());
        Ok(())
    }
}
