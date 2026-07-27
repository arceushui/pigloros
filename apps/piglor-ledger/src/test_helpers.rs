//! Shared test utilities used across test modules in this crate.
//!
//! Only compiled in `#[cfg(test)]` — no production code here.

use std::path::Path;

/// Return the prediction id (ULID string) of the first `.toml` file found
/// under `<dir>/predictions/`.
///
/// Used in multiple test modules; lives here to avoid the 4-way duplication
/// of the `read_dir().next().…file_stem().to_owned()` chain.
pub(crate) fn first_prediction_id(dir: &Path) -> String {
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
