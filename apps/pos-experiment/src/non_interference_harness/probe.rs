//! The harness probe subject of the fresh-process Local runner (test
//! support).
//!
//! The probe proves the Local runner's process boundary, warm/cold
//! preparation and NIA1 path; it is not a capture adapter of any ADR-059 row
//! (those are slices N1 to N4) and its artifacts are not inventory evidence.
//! It serves only the `NI-EVAL-007` profile (five byte-exact surfaces). Each
//! run writes the unauthorized value to the denied channel file
//! `denied-channel` of its working directory and, unless the permitted input
//! starts with `leak:`, never reads it back. The operational surfaces report
//! whether the run found the cache entry `cache-entry` (a warm, primed
//! directory) or created it (a cold one). A permitted input starting with
//! `net:` records one live network attempt.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use pos_conformance::{
    non_interference_surface_names_v1, NonInterferenceRawCaptureV1, NonInterferenceRawOperationalV1,
};

use super::{
    serve_non_interference_local_subject_v1, NonInterferenceLocalRequestV1,
    NonInterferenceNonExecutedCauseV1,
};

/// The one row the probe serves.
pub const LOCAL_PROBE_FIXTURE_ID_V1: &str = "NI-EVAL-007";
/// The denied channel file of a run's working directory.
pub const LOCAL_PROBE_DENIED_CHANNEL_V1: &str = "denied-channel";
/// The cache entry file of a run's working directory.
pub const LOCAL_PROBE_CACHE_ENTRY_V1: &str = "cache-entry";

/// Run the probe subject for `request` in `directory`.
///
/// # Errors
/// Returns `Unsupported` for any row but `NI-EVAL-007`, and `Unavailable`
/// when the working directory cannot be used.
pub fn local_probe_subject_v1(
    request: &NonInterferenceLocalRequestV1,
    directory: &Path,
) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
    let surfaces = Some(request.fixture_id.as_str())
        .filter(|fixture_id| *fixture_id == LOCAL_PROBE_FIXTURE_ID_V1)
        .and_then(non_interference_surface_names_v1)
        .ok_or(NonInterferenceNonExecutedCauseV1::Unsupported)?;
    let denied = directory.join(LOCAL_PROBE_DENIED_CHANNEL_V1);
    let cache = directory.join(LOCAL_PROBE_CACHE_ENTRY_V1);
    fs::write(&denied, &request.unauthorized_value)?;
    let hit = cache.exists();
    if !hit {
        fs::write(&cache, &request.permitted_input)?;
    }
    let leaked = if request.permitted_input.starts_with(b"leak:") {
        fs::read(&denied)?
    } else {
        Vec::new()
    };
    let cache_class: &[u8] = if hit { b"cache-hit" } else { b"cache-miss" };
    Ok(NonInterferenceRawCaptureV1 {
        surface_names: surfaces.iter().map(|name| (*name).to_owned()).collect(),
        authoritative: surfaces
            .iter()
            .map(|name| {
                let parts: [&[u8]; 3] = [name.as_bytes(), b"\0", &request.permitted_input];
                blake3::hash(&parts.concat()).as_bytes().to_vec()
            })
            .collect(),
        public: surfaces
            .iter()
            .map(|name| {
                [
                    format!("public:{name}:{:?}:", request.variant).as_bytes(),
                    leaked.as_slice(),
                ]
                .concat()
            })
            .collect(),
        operational: surfaces
            .iter()
            .map(|_| NonInterferenceRawOperationalV1::ByteExact(cache_class.to_vec()))
            .collect(),
        unexpected_network_accesses: u32::from(request.permitted_input.starts_with(b"net:")),
        provenance_digest: *blake3::hash(&request.permitted_input).as_bytes(),
    })
}

/// Serve one Local run of the probe in `directory`.
///
/// # Errors
/// Returns the cause of a request, probe or frame failure.
pub fn serve_local_probe_v1<R: Read, W: Write>(
    input: R,
    output: W,
    directory: &Path,
) -> Result<(), NonInterferenceNonExecutedCauseV1> {
    serve_non_interference_local_subject_v1(input, output, |request| {
        local_probe_subject_v1(request, directory)
    })
}
