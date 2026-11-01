//! In-memory WIT archive and package validation.

#[path = "archive.rs"]
mod archive;

use std::collections::BTreeMap;

use pos_crypto::plugin_execution::COMMUNITY_PLUGIN_WORLD_V1;
use thiserror::Error;
use wit_parser::{Resolve, SourceMap};

const MAX_PACKAGES: usize = 256;

/// A closed WIT content refusal, containing no untrusted source text or paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginWitContentErrorV1 {
    /// The archive, file/package count or path depth exceeds the fixed profile.
    #[error("WIT content exceeds a V1 bound")]
    BoundsExceeded,
    /// The archive or entry uses a format outside the fixed ustar profile.
    #[error("unsupported WIT archive format")]
    UnsupportedFormat,
    /// Framing, paths, UTF-8 or WIT syntax are malformed.
    #[error("malformed WIT content")]
    Malformed,
    /// A package reference cannot resolve, or the required world is absent.
    #[error("WIT package or world reference differs")]
    ReferenceMismatch,
}

/// Validate a bounded ustar WIT archive without extraction or external I/O.
///
/// Every entry is a regular UTF-8 `.wit` file at a sorted safe ASCII path.
/// The fixed maxima are 4 MiB, 256 files, 256 total packages (including inline
/// declarations), and 32 path segments. Numeric header metadata is checked
/// for well-formedness and never applied to the host.
/// Files in one directory form one package group; all groups are resolved
/// together from the supplied bytes. The archive must define the exact
/// [`COMMUNITY_PLUGIN_WORLD_V1`] world. A different world at a compatible-looking
/// version is insufficient.
///
/// This preflight checks neither the Component's executable interface nor
/// other bundle artifacts, and returns no release/admission proof.
///
/// # Errors
/// Returns the closed [`PluginWitContentErrorV1`] for the first archive or
/// package failure. Dependency parser diagnostics are never exposed.
pub fn validate_plugin_wit_v1(archive: &[u8]) -> Result<(), PluginWitContentErrorV1> {
    archive::read(archive).and_then(|files| resolve(&files))
}

fn resolve(files: &[archive::WitFile<'_>]) -> Result<(), PluginWitContentErrorV1> {
    let mut groups = BTreeMap::<&str, SourceMap>::new();
    for file in files {
        let directory = file.path.rsplit_once('/').map_or("", |(parent, _)| parent);
        groups
            .entry(directory)
            .or_default()
            .push_str(&file.path, file.source);
    }
    let mut groups = groups.into_values();
    let mut remaining_packages = MAX_PACKAGES;
    let main = groups
        .next()
        .ok_or(PluginWitContentErrorV1::Malformed)
        .and_then(|map| parse(map, &mut remaining_packages))?;
    let dependencies = groups
        .map(|map| parse(map, &mut remaining_packages))
        .collect::<Result<Vec<_>, _>>()?;
    let mut resolver = Resolve::default();
    resolver
        .push_groups(main, dependencies)
        .map_err(|_| PluginWitContentErrorV1::ReferenceMismatch)
        .and_then(|main| {
            resolver
                .select_world(&[main], Some(COMMUNITY_PLUGIN_WORLD_V1))
                .map_err(|_| PluginWitContentErrorV1::ReferenceMismatch)
        })
        .map(|_| ())
}

fn parse(
    map: SourceMap,
    remaining_packages: &mut usize,
) -> Result<wit_parser::UnresolvedPackageGroup, PluginWitContentErrorV1> {
    if *remaining_packages == 0 {
        return Err(PluginWitContentErrorV1::BoundsExceeded);
    }
    // SourceMap parses one whole group under the archive byte and native
    // syntax-depth limits. It exposes no per-declaration budget callback.
    // Debit the graph budget before retaining that group or parsing another.
    map.parse()
        .map_err(|_| PluginWitContentErrorV1::Malformed)
        .and_then(|group| {
            remaining_packages
                .checked_sub(group.nested.len() + 1)
                .ok_or(PluginWitContentErrorV1::BoundsExceeded)
                .map(|remaining| {
                    *remaining_packages = remaining;
                    group
                })
        })
}
