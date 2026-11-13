//! Compile the public GMD1 declaration
//! (`contracts/gateway/v1/execution-mode-profiles.json`) into canonical GMP1
//! records (ADR-134 §3). `build.rs` runs this; the crate's tests run the same
//! code against every rejection.

use serde::Deserialize;

use super::gmp1::{Gmp1RecordV1, AIR_GAPPED_MODE_PROFILE_ID, LOCAL_MODE_PROFILE_ID};

/// Markers of Draft or repository-test authority that a reviewed
/// declaration never carries.
const FORBIDDEN_MARKERS: [&str; 3] = ["DFA1", "Draft", "repository-test-fixture-only"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclarationV1 {
    magic: String,
    version: u64,
    lifecycle: String,
    authority_kind: String,
    profiles: Vec<DeclaredProfileV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredProfileV1 {
    mode_profile_id: String,
    semantic_version: String,
    mode: String,
    network_allowed: bool,
    ingress: Vec<String>,
    startup_predicates: Vec<String>,
    revocation_freshness: String,
    #[serde(deserialize_with = "Option::deserialize")]
    registration_profile_id: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    previous_mode_profile_digest: Option<String>,
}

const MODES: [(&str, u8); 2] = [("local", 1), ("air-gapped", 2)];
const INGRESS: [(&str, u8); 3] = [
    ("loopback-http", 1),
    ("public-read-only", 2),
    ("fork-admission-socket", 3),
];
const PREDICATES: [(&str, u8); 5] = [
    ("linux", 1),
    ("listeners-within-ingress", 2),
    ("network-features-granted", 3),
    ("no-network-ledger-source", 4),
    ("store-mode-binding", 5),
];
const FRESHNESS: [(&str, u8); 2] = [("current-by-construction", 1), ("observed-persisted", 2)];

/// Compile the declaration into `(mode_profile_id, canonical GMP1 bytes)`
/// for exactly the two reviewed identifiers, in identifier order.
///
/// # Errors
/// Returns a description of the first rejected rule: a Draft or test marker,
/// a malformed or open declaration, a lifecycle other than `Reviewed`, a
/// missing, third or unsorted identifier, or any GMP1 rule.
pub(crate) fn compile_declaration_v1(json: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    FORBIDDEN_MARKERS
        .iter()
        .find(|marker| json.contains(**marker))
        .map_or(Ok(()), |marker| {
            Err(format!("declaration carries {marker}"))
        })
        .and_then(|()| {
            serde_json::from_str::<DeclarationV1>(json).map_err(|error| error.to_string())
        })
        .and_then(|declaration| {
            let header = declaration.magic == "GMD1"
                && declaration.version == 1
                && declaration.lifecycle == "Reviewed"
                && declaration.authority_kind == "gateway-execution-mode-only";
            let identifiers = declaration
                .profiles
                .iter()
                .map(|profile| profile.mode_profile_id.as_str())
                .collect::<Vec<_>>();
            let closed = identifiers == [AIR_GAPPED_MODE_PROFILE_ID, LOCAL_MODE_PROFILE_ID];
            (header && closed)
                .then_some(declaration.profiles)
                .ok_or_else(|| "declaration is not the reviewed GMD1 table".to_owned())
        })
        .and_then(|profiles| profiles.iter().map(compile_profile).collect())
}

fn compile_profile(profile: &DeclaredProfileV1) -> Result<(String, Vec<u8>), String> {
    record(profile)
        .and_then(|record| record.validate().map(|()| record))
        .map(|record| (record.mode_profile_id.clone(), record.encode()))
}

fn record(profile: &DeclaredProfileV1) -> Result<Gmp1RecordV1, String> {
    let mode = tag(&profile.mode, &MODES);
    let ingress = tag_list(&profile.ingress, &INGRESS);
    let startup_predicates = tag_list(&profile.startup_predicates, &PREDICATES);
    let revocation_freshness = tag(&profile.revocation_freshness, &FRESHNESS);
    let previous = profile
        .previous_mode_profile_digest
        .as_deref()
        .map(digest)
        .transpose();
    mode.and_then(|mode| {
        ingress.and_then(|ingress| {
            startup_predicates.and_then(|startup_predicates| {
                revocation_freshness.and_then(|revocation_freshness| {
                    previous.map(|previous_mode_profile_digest| Gmp1RecordV1 {
                        mode_profile_id: profile.mode_profile_id.clone(),
                        semantic_version: profile.semantic_version.clone(),
                        mode,
                        network_allowed: profile.network_allowed,
                        ingress,
                        startup_predicates,
                        revocation_freshness,
                        registration_profile_id: profile.registration_profile_id.clone(),
                        previous_mode_profile_digest,
                    })
                })
            })
        })
    })
}

fn tag(value: &str, table: &[(&str, u8)]) -> Result<u8, String> {
    table
        .iter()
        .find(|(name, _)| *name == value)
        .map(|(_, tag)| *tag)
        .ok_or_else(|| format!("unknown declaration value {value}"))
}

/// Map a strictly ascending, duplicate-free list of names to its tags.
fn tag_list(values: &[String], table: &[(&str, u8)]) -> Result<Vec<u8>, String> {
    values
        .iter()
        .map(|value| tag(value, table))
        .collect::<Result<Vec<_>, _>>()
        .and_then(|tags| {
            tags.windows(2)
                .all(|pair| pair[0] < pair[1])
                .then_some(tags)
                .ok_or_else(|| "declaration tags are not strictly ascending".to_owned())
        })
}

/// Decode 64 lower-case hexadecimal characters.
fn digest(hex: &str) -> Result<[u8; 32], String> {
    let canonical = hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    canonical
        .then(|| {
            std::array::from_fn(|index| {
                u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap_or_default()
            })
        })
        .ok_or_else(|| "previous digest is not 64 lower-case hex characters".to_owned())
}
