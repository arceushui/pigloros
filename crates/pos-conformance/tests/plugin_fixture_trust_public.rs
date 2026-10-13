//! R8-F2a: every generated Plugin release, PTR1, PRV1 and TPS1 of the checked-in `PCW2`
//! composites is accepted by the production verifiers (ADR-061 revision 8 decision 7).
//!
//! The test reads the seven composites and payloads of `fixtures/conformance`, and for every
//! step of every sub-case runs `verify_plugin_trust_v1`, the TPS1 bridge and, for each release,
//! `verify_plugin_release_signature_v1` at the coordinates of the step. A release that a
//! sub-case expects to be an `InvalidManifest` must be refused by the strict PMF1 projection.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::path::PathBuf;

use ciborium::value::Value;
use pos_conformance::{
    authenticate_plugin_tps1_v1, verify_plugin_tps1_policy_v1, PluginTrustPolicyAnchorV1,
    PLUGIN_OPERATOR_ROLE_V1,
};
use pos_crypto::plugin_manifest::verify_plugin_release_signature_v1;
use pos_crypto::plugin_trust::{
    verify_plugin_trust_v1, TrustedPluginRootAnchorV1, ValidatedPluginManifestProjectionV1,
    VerifiedPluginTrustEvidenceV1,
};
use pos_plugin_release::{InMemoryReleaseEntryV1, InMemoryReleaseSourceV1, ReleaseSourceV1};
use serde_json::Value as Json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Pieces = BTreeMap<[u8; 32], Vec<u8>>;

const FAMILIES: [&str; 7] = [
    "positive",
    "denied",
    "malformed",
    "resource-exhaustion",
    "deletion-redaction",
    "downgrade",
    "independent-evaluation",
];

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/conformance")
}

fn digest(text: &str) -> TestResult<[u8; 32]> {
    if text.len() != 64 {
        return Err("a digest is 64 hexadecimal digits".into());
    }
    let bytes = (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(<[u8; 32]>::try_from(bytes).map_err(|_| "not 32 bytes")?)
}

/// The pieces of a composite, each addressed by the BLAKE3 digest of its bytes.
fn pieces_of(composite: &[u8]) -> TestResult<Pieces> {
    let value: Value = ciborium::from_reader(composite)?;
    let Value::Array(items) = value else {
        return Err("the composite is not an array".into());
    };
    let [Value::Text(tag), Value::Integer(_), Value::Array(list)] = items.as_slice() else {
        return Err("the composite has the wrong shape".into());
    };
    assert_eq!(tag, "PCW2");
    let mut pieces = Pieces::new();
    for item in list {
        let Value::Array(pair) = item else {
            return Err("a piece is not a pair".into());
        };
        let [Value::Bytes(named), Value::Bytes(bytes)] = pair.as_slice() else {
            return Err("a piece is not a digest and bytes".into());
        };
        assert_eq!(blake3::hash(bytes).as_bytes().as_slice(), named.as_slice());
        pieces.insert(<[u8; 32]>::try_from(named.as_slice())?, bytes.clone());
    }
    Ok(pieces)
}

fn piece<'a>(pieces: &'a Pieces, text: &Json) -> TestResult<&'a Vec<u8>> {
    let named = digest(text.as_str().ok_or("a piece reference is not text")?)?;
    pieces
        .get(&named)
        .ok_or_else(|| "a digest names no piece".into())
}

/// The trust material of a `material` object, as the adapter builds it from `PCA1`.
struct Material {
    root: TrustedPluginRootAnchorV1,
    policy: PluginTrustPolicyAnchorV1,
    tps1: Vec<u8>,
    ptr1: Vec<Vec<u8>>,
    prv1: Vec<Vec<u8>>,
}

fn records(pieces: &Pieces, list: &Json) -> TestResult<Vec<Vec<u8>>> {
    list.as_array()
        .ok_or("a record list is not an array")?
        .iter()
        .map(|reference| Ok(piece(pieces, reference)?.clone()))
        .collect()
}

fn bytes32(value: &Value) -> TestResult<[u8; 32]> {
    let Value::Bytes(bytes) = value else {
        return Err("not a byte string".into());
    };
    Ok(<[u8; 32]>::try_from(bytes.as_slice())?)
}

fn text(value: &Value) -> TestResult<&str> {
    let Value::Text(text) = value else {
        return Err("not a text".into());
    };
    Ok(text)
}

fn material_of(pieces: &Pieces, object: &Json) -> TestResult<Material> {
    let anchor_bytes = piece(pieces, &object["anchor"])?;
    let value: Value = ciborium::from_reader(anchor_bytes.as_slice())?;
    let Value::Array(items) = value else {
        return Err("the anchor is not an array".into());
    };
    assert_eq!(items.len(), 6);
    assert_eq!(text(&items[0])?, "PCA1");
    let scope = text(&items[2])?;
    let genesis = bytes32(&items[3])?;
    Ok(Material {
        root: TrustedPluginRootAnchorV1::new(scope, genesis)?,
        policy: PluginTrustPolicyAnchorV1::new(
            scope,
            genesis,
            bytes32(&items[4])?,
            PLUGIN_OPERATOR_ROLE_V1,
            bytes32(&items[5])?,
        )?,
        tps1: piece(pieces, &object["tps1"])?.clone(),
        ptr1: records(pieces, &object["ptr1"])?,
        prv1: records(pieces, &object["prv1"])?,
    })
}

/// The evidence of `material` at the coordinates of a step, bridged to its TPS1.
fn verified_evidence(
    material: &Material,
    step: &Json,
) -> TestResult<VerifiedPluginTrustEvidenceV1> {
    let micros = step["instant_micros"].as_u64().ok_or("no instant")?;
    let tick = step["tick"].as_u64().ok_or("no tick")?;
    let utc = i64::try_from(micros / 1_000_000)?;
    let roots: Vec<&[u8]> = material.ptr1.iter().map(Vec::as_slice).collect();
    let revocations: Vec<&[u8]> = material.prv1.iter().map(Vec::as_slice).collect();
    let evidence = verify_plugin_trust_v1(&material.root, &roots, &revocations, utc, tick)?;
    let tps1 = authenticate_plugin_tps1_v1(&material.policy, &material.tps1)?;
    verify_plugin_tps1_policy_v1(&tps1, &evidence, utc, tick)?;
    Ok(evidence)
}

/// Verify the release of a `release` object; `invalid` when the sub-case expects the PMF1 to
/// be refused by the strict projection.
fn verify_release(
    pieces: &Pieces,
    release: &Json,
    evidence: &VerifiedPluginTrustEvidenceV1,
    invalid: bool,
) -> TestResult {
    let manifest = piece(pieces, &release["manifest"])?.clone();
    let blobs = release["blobs"]
        .as_array()
        .ok_or("the blobs are not an array")?
        .iter()
        .map(|reference| Ok(piece(pieces, reference)?.clone()))
        .collect::<TestResult<Vec<_>>>()?;
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest, blobs)?;
    let address = entry.address().clone();
    let source = InMemoryReleaseSourceV1::new(vec![entry])?;
    let bundle = source.read_verified(&address)?;
    let projection = ValidatedPluginManifestProjectionV1::from_verified_bundle(&bundle);
    if invalid {
        assert!(projection.is_err(), "the PMF1 must be refused");
        return Ok(());
    }
    let authorization = evidence.authorize_release(&projection?)?;
    verify_plugin_release_signature_v1(&bundle, &authorization)?;
    Ok(())
}

#[test]
fn generated_releases_and_trust_records_pass_the_production_verifiers() -> TestResult {
    let root = fixture_root();
    let mut releases = 0_usize;
    for family in FAMILIES {
        let inputs = root.join("inputs/plugin-conformance");
        let pieces = pieces_of(&std::fs::read(inputs.join(format!("{family}.pcw2")))?)?;
        let payload: Json =
            serde_json::from_slice(&std::fs::read(inputs.join(format!("{family}.json")))?)?;
        for subcase in payload["subcases"].as_array().ok_or("no sub-cases")? {
            let invalid = subcase["expect"]["error"] == "InvalidManifest";
            let mut last = None;
            for step in subcase["steps"].as_array().ok_or("no steps")? {
                if let Some(object) = step.get("material").filter(|object| !object.is_null()) {
                    last = Some(material_of(&pieces, object)?);
                }
                let Some(material) = &last else { continue };
                if step["step"] == "scan" {
                    continue;
                }
                let evidence = verified_evidence(material, step)?;
                if let Some(release) = step.get("release") {
                    verify_release(&pieces, release, &evidence, invalid)?;
                    releases += 1;
                }
            }
        }
    }
    assert!(releases >= 20, "{releases} releases were verified");
    Ok(())
}
