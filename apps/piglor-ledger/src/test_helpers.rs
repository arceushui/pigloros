//! Shared test-support utilities exposed as a public module so the binary
//! crate's test code can call them without duplicating the implementations.

use std::path::Path;

/// Return the prediction id (ULID string) of the first `.toml` file found
/// under `<dir>/predictions/`.
///
/// Used in multiple test modules; lives here to avoid the 4-way duplication
/// of the `read_dir().next().…file_stem().to_owned()` chain.
///
/// # Panics
///
/// Panics if the `predictions/` directory is empty or the entry cannot be
/// read — expected only in test fixtures that guarantee a prediction exists.
#[must_use]
pub fn first_prediction_id(dir: &Path) -> String {
    std::fs::read_dir(dir.join("predictions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}
