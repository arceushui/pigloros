//! Pure checks for the auxiliary members of a fixture provider catalog.
//!
//! This file is self-contained (no `crate::` paths) so that `build.rs` can pull it in with
//! `#[path]` while the library compiles it only under `cfg(test)`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Default maximum number of auxiliary entries per family.
///
/// Pinned to `MAX_AUXILIARY_ARTIFACTS`. ADR-061 revision 8 sets 64 per family; CPF1 also counts
/// the fixed evidence and oracle members in its total of 64 descriptors, so a family with 63 or
/// more auxiliary entries passes the catalog check but fails at materialization. That is a
/// documented known limit (ADR-061 revision 8, decision 7 keeps one composite per family).
pub const DEFAULT_AUXILIARY_CAP: usize = 64;
/// Maximum total bytes of embedded auxiliary members over all layers.
pub const MAX_EMBEDDED_AUXILIARY_BYTES: usize = 4 * 1024 * 1024;
/// The only source directory auxiliary members may live in. The shell validators
/// (`verify-conformance-fixtures.sh`, `generate-conformance-fixture-records.sh`) and the
/// fixture README apply the same `inputs/` rule.
const AUXILIARY_DIRECTORY: &str = "inputs";

/// One `auxiliary` entry of a provider manifest.
pub struct AuxiliaryEntry {
    pub path: String,
    pub media_type: String,
}

/// Reasons an auxiliary catalog is refused.
#[derive(Debug, Eq, PartialEq)]
pub enum AuxiliaryCatalogError {
    TooManyEntries { count: usize, cap: usize },
    UnsafePath(String),
    OutsideInventory(String),
    DuplicatePath(String),
    MissingSource(String),
    InvalidMediaType(String),
    EmbeddedTotalExceeded { max: usize },
}

impl fmt::Display for AuxiliaryCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TooManyEntries { count, cap } => {
                format!("auxiliary catalog has {count} entries, above the cap {cap}")
            }
            Self::UnsafePath(path) => format!("auxiliary path is unsafe or not relative: {path}"),
            Self::OutsideInventory(path) => {
                format!("auxiliary path is outside the inputs directory: {path}")
            }
            Self::DuplicatePath(path) => format!("auxiliary path is declared twice: {path}"),
            Self::MissingSource(path) => {
                format!("auxiliary path is not an inventoried source: {path}")
            }
            Self::InvalidMediaType(value) => format!("auxiliary media type is invalid: {value}"),
            Self::EmbeddedTotalExceeded { max } => {
                format!("embedded auxiliary bytes exceed the {max}-byte limit")
            }
        };
        formatter.write_str(&message)
    }
}

/// Returns whether a media type is lowercase `type/subtype` text of at most 127 bytes.
#[must_use]
pub fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"!#$&^_.+-/".contains(&byte)
        })
        && value.split_once('/').is_some_and(|(kind, subtype)| {
            !kind.is_empty() && !subtype.is_empty() && !subtype.contains('/')
        })
}

fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn in_inventory_directory(path: &str) -> bool {
    path.split_once('/')
        .is_some_and(|(directory, _)| directory == AUXILIARY_DIRECTORY)
}

/// Whether the per-family entry counts of a provider's `auxiliary` object are acceptable: the
/// family keys equal the provider's families, and a `pigloros-json-v1` provider has no entries.
#[must_use]
pub fn declaration_is_valid(
    families: &BTreeSet<String>,
    counts: &BTreeMap<String, usize>,
    json_adapter: bool,
) -> bool {
    counts.keys().eq(families.iter()) && (!json_adapter || counts.values().all(|count| *count == 0))
}

/// Checks the auxiliary entries of one family against the snapshotted source set (the
/// inventory digests are verified afterwards).
///
/// # Errors
///
/// Returns the first fault: too many entries, an unsafe or foreign path, a duplicate, a missing
/// source or an invalid media type.
pub fn validate_auxiliary_catalog(
    sources: &BTreeSet<String>,
    entries: &[AuxiliaryEntry],
    cap: usize,
) -> Result<(), AuxiliaryCatalogError> {
    if entries.len() > cap {
        return Err(AuxiliaryCatalogError::TooManyEntries {
            count: entries.len(),
            cap,
        });
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        if !safe_relative_path(&entry.path) {
            return Err(AuxiliaryCatalogError::UnsafePath(entry.path.clone()));
        }
        if !in_inventory_directory(&entry.path) {
            return Err(AuxiliaryCatalogError::OutsideInventory(entry.path.clone()));
        }
        if !seen.insert(entry.path.as_str()) {
            return Err(AuxiliaryCatalogError::DuplicatePath(entry.path.clone()));
        }
        if !sources.contains(&entry.path) {
            return Err(AuxiliaryCatalogError::MissingSource(entry.path.clone()));
        }
        if !valid_media_type(&entry.media_type) {
            return Err(AuxiliaryCatalogError::InvalidMediaType(
                entry.media_type.clone(),
            ));
        }
    }
    Ok(())
}

/// Accepts embedded auxiliary sizes whose total is at most `max` bytes.
///
/// # Errors
///
/// Returns [`AuxiliaryCatalogError::EmbeddedTotalExceeded`] when the total exceeds `max` or
/// overflows.
pub fn check_embedded_total(sizes: &[usize], max: usize) -> Result<(), AuxiliaryCatalogError> {
    let total = sizes
        .iter()
        .try_fold(0_usize, |total, size| total.checked_add(*size));
    match total {
        Some(total) if total <= max => Ok(()),
        _ => Err(AuxiliaryCatalogError::EmbeddedTotalExceeded { max }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        check_embedded_total, declaration_is_valid, valid_media_type, validate_auxiliary_catalog,
        AuxiliaryCatalogError, AuxiliaryEntry, AUXILIARY_DIRECTORY, DEFAULT_AUXILIARY_CAP,
        MAX_EMBEDDED_AUXILIARY_BYTES,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn entry(path: &str) -> AuxiliaryEntry {
        AuxiliaryEntry {
            path: path.to_owned(),
            media_type: "application/octet-stream".to_owned(),
        }
    }

    fn check(known: &[&str], entries: &[AuxiliaryEntry]) -> Result<(), AuxiliaryCatalogError> {
        let sources: BTreeSet<String> = known.iter().map(|path| (*path).to_owned()).collect();
        validate_auxiliary_catalog(&sources, entries, DEFAULT_AUXILIARY_CAP)
    }

    fn numbered(count: usize) -> (BTreeSet<String>, Vec<AuxiliaryEntry>) {
        let paths = (0..count)
            .map(|index| format!("inputs/plugin-conformance/{index}.pcw2"))
            .collect::<Vec<_>>();
        let entries = paths.iter().map(|path| entry(path)).collect();
        (paths.into_iter().collect(), entries)
    }

    #[test]
    fn sixty_four_entries_are_accepted_and_sixty_five_are_refused() {
        let (sources, entries) = numbered(64);
        let accepted = validate_auxiliary_catalog(&sources, &entries, DEFAULT_AUXILIARY_CAP);
        assert_eq!(accepted, Ok(()));
        let (sources, entries) = numbered(65);
        let refused = validate_auxiliary_catalog(&sources, &entries, DEFAULT_AUXILIARY_CAP);
        assert_eq!(
            refused,
            Err(AuxiliaryCatalogError::TooManyEntries { count: 65, cap: 64 })
        );
    }

    #[test]
    fn an_empty_catalog_is_accepted() {
        assert_eq!(check(&[], &[]), Ok(()));
    }

    #[test]
    fn a_path_outside_the_verified_source_set_is_refused() {
        let missing = "inputs/plugin-conformance/missing.pcw2";
        let known = ["inputs/plugin-conformance/other.pcw2"];
        assert_eq!(
            check(&known, &[entry(missing)]),
            Err(AuxiliaryCatalogError::MissingSource(missing.to_owned()))
        );
    }

    #[test]
    fn traversal_absolute_and_malformed_paths_are_refused() {
        for path in [
            "inputs/../support/LICENSE",
            "/inputs/a.pcw2",
            "inputs//a.pcw2",
            "inputs/./a.pcw2",
            "inputs/a\\b.pcw2",
            "inputs/a\0b.pcw2",
            "",
        ] {
            assert_eq!(
                check(&[path], &[entry(path)]),
                Err(AuxiliaryCatalogError::UnsafePath(path.to_owned()))
            );
        }
    }

    #[test]
    fn a_duplicate_path_is_refused() {
        let path = "inputs/plugin-conformance/a.pcw2";
        assert_eq!(
            check(&[path], &[entry(path), entry(path)]),
            Err(AuxiliaryCatalogError::DuplicatePath(path.to_owned()))
        );
    }

    #[test]
    fn a_path_outside_the_inventoried_directories_is_refused() {
        for path in ["SHA256SUMS", "support/a.pcw2", "published/a.pcw2"] {
            assert_eq!(
                check(&[path], &[entry(path)]),
                Err(AuxiliaryCatalogError::OutsideInventory(path.to_owned()))
            );
        }
    }

    #[test]
    fn the_inputs_directory_is_accepted() {
        let path = format!("{AUXILIARY_DIRECTORY}/a.bin");
        assert_eq!(check(&[path.as_str()], &[entry(&path)]), Ok(()));
    }

    #[test]
    fn an_invalid_media_type_is_refused() {
        let path = "inputs/plugin-conformance/a.pcw2";
        let invalid = AuxiliaryEntry {
            path: path.to_owned(),
            media_type: "Application/Octet-Stream".to_owned(),
        };
        assert_eq!(
            check(&[path], &[invalid]),
            Err(AuxiliaryCatalogError::InvalidMediaType(
                "Application/Octet-Stream".to_owned()
            ))
        );
    }

    #[test]
    fn media_types_are_checked_structurally() {
        assert!(valid_media_type("application/octet-stream"));
        assert!(valid_media_type("application/vnd.pigloros+cbor"));
        let long = format!("a/{}", "b".repeat(126));
        for invalid in ["", "text", "/json", "text/", "a/b/c", "a/B", long.as_str()] {
            assert!(!valid_media_type(invalid), "{invalid}");
        }
    }

    #[test]
    fn the_embedded_total_accepts_exactly_four_mebibytes() {
        let max = MAX_EMBEDDED_AUXILIARY_BYTES;
        let exceeded = Err(AuxiliaryCatalogError::EmbeddedTotalExceeded { max });
        assert_eq!(max, 4 * 1024 * 1024);
        assert_eq!(check_embedded_total(&[], max), Ok(()));
        assert_eq!(check_embedded_total(&[max / 2, max / 2], max), Ok(()));
        assert_eq!(check_embedded_total(&[max / 2, max / 2, 1], max), exceeded);
        assert_eq!(check_embedded_total(&[usize::MAX, 1], max), exceeded);
    }

    fn declaration(families: &[&str], counts: &[(&str, usize)], json: bool) -> bool {
        let families = families.iter().map(|family| (*family).to_owned()).collect();
        let counts = counts
            .iter()
            .map(|(family, count)| ((*family).to_owned(), *count))
            .collect::<BTreeMap<_, _>>();
        declaration_is_valid(&families, &counts, json)
    }

    #[test]
    fn declarations_must_cover_exactly_the_families() {
        assert!(declaration(&["a", "b"], &[("a", 0), ("b", 1)], false));
        assert!(!declaration(&["a", "b"], &[("a", 0)], false));
        assert!(!declaration(&["a"], &[("a", 0), ("c", 0)], false));
        assert!(!declaration(&["a"], &[("b", 0)], false));
    }

    #[test]
    fn json_adapter_declarations_must_be_empty() {
        assert!(declaration(&["a"], &[("a", 0)], true));
        assert!(!declaration(&["a"], &[("a", 1)], true));
    }

    #[test]
    fn error_messages_name_the_fault() {
        let rendered = [
            AuxiliaryCatalogError::TooManyEntries { count: 65, cap: 64 },
            AuxiliaryCatalogError::UnsafePath("p".to_owned()),
            AuxiliaryCatalogError::OutsideInventory("p".to_owned()),
            AuxiliaryCatalogError::DuplicatePath("p".to_owned()),
            AuxiliaryCatalogError::MissingSource("p".to_owned()),
            AuxiliaryCatalogError::InvalidMediaType("m".to_owned()),
            AuxiliaryCatalogError::EmbeddedTotalExceeded { max: 7 },
        ]
        .map(|error| error.to_string());
        assert_eq!(
            rendered,
            [
                "auxiliary catalog has 65 entries, above the cap 64",
                "auxiliary path is unsafe or not relative: p",
                "auxiliary path is outside the inputs directory: p",
                "auxiliary path is declared twice: p",
                "auxiliary path is not an inventoried source: p",
                "auxiliary media type is invalid: m",
                "embedded auxiliary bytes exceed the 7-byte limit",
            ]
        );
    }
}
