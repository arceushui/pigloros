//! R8-M1: the in-memory release source at its public seam (ADR-061 revision 8 decision 5).
//!
//! The good closure comes from the sibling builder. The faulty closures are laid out by hand
//! with the same canonical JSON, so each fault reaches the verifier exactly as a payload would
//! deliver it.

use pos_plugin_release::{
    build_oci_closure_v1, BundleAddressV1, InMemoryReleaseEntryV1, InMemoryReleaseErrorV1 as E,
    InMemoryReleaseSourceV1, ReleaseClosureInputV1, ReleaseSourceErrorV1 as S, ReleaseSourceV1,
    VerifiedReleaseBundleV1,
};
use sha2::{Digest as _, Sha256};

type BoxError = Box<dyn std::error::Error>;
type TestResult = Result<(), BoxError>;
type Built = (VerifiedReleaseBundleV1, Vec<u8>, Vec<Vec<u8>>);

const EMPTY_CONFIG: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const PMF1: &str = "application/vnd.pigloros.plugin.manifest.v1+cbor";
const COMPONENT: &str = "application/vnd.pigloros.plugin.component.v1+wasm";
const WIT: &str = "application/vnd.pigloros.plugin.wit.v1+tar";
const PROVENANCE: &str = "application/vnd.in-toto+json";
const SBOM: &str = "application/spdx+json";
const LICENCE: &str = "text/plain; charset=utf-8";

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// One hand-laid layer: its member annotation, media type, bytes and declared size.
struct Layer {
    member: String,
    media_type: &'static str,
    bytes: Vec<u8>,
    size: usize,
}

fn layer(member: &str, media_type: &'static str, bytes: &[u8]) -> Layer {
    Layer {
        member: member.to_owned(),
        media_type,
        bytes: bytes.to_vec(),
        size: bytes.len(),
    }
}

/// The six layers of a valid closure in role order.
fn good_layers() -> Vec<Layer> {
    let licence = b"licence".as_slice();
    let member = format!("licence/{}", &sha256(licence)[7..]);
    vec![
        layer("pmf1", PMF1, b"pmf1"),
        layer("component", COMPONENT, b"component"),
        layer("wit", WIT, b"wit"),
        layer("provenance", PROVENANCE, b"provenance"),
        layer("sbom", SBOM, b"sbom"),
        layer(&member, LICENCE, licence),
    ]
}

fn descriptor(layer: &Layer) -> serde_json::Value {
    serde_json::json!({
        "annotations": {"org.pigloros.plugin.member": layer.member},
        "digest": sha256(&layer.bytes),
        "mediaType": layer.media_type,
        "size": layer.size,
    })
}

/// The canonical manifest of `layers`, as the verifier's own serialization writes it.
fn manifest_of(layers: &[Layer]) -> Vec<u8> {
    let descriptors = layers.iter().map(descriptor).collect::<Vec<_>>();
    serde_json::json!({
        "artifactType": "application/vnd.pigloros.plugin.release.v1",
        "config": {
            "digest": EMPTY_CONFIG,
            "mediaType": "application/vnd.oci.empty.v1+json",
            "size": 2,
        },
        "layers": descriptors,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "schemaVersion": 2,
    })
    .to_string()
    .into_bytes()
}

/// The bytes of every layer, in layer order.
fn bytes_of(layers: &[Layer]) -> Vec<Vec<u8>> {
    layers.iter().map(|layer| layer.bytes.clone()).collect()
}

/// The entry of `layers` with every distinct layer byte string as a blob.
fn entry_of(layers: &[Layer]) -> Result<InMemoryReleaseEntryV1, E> {
    let mut blobs = bytes_of(layers);
    blobs.sort();
    blobs.dedup();
    InMemoryReleaseEntryV1::from_bytes(manifest_of(layers), blobs)
}

/// The error the source gives for the one release of `entry`.
fn read_error(entry: InMemoryReleaseEntryV1) -> Result<Option<S>, BoxError> {
    let address = entry.address().clone();
    let source = InMemoryReleaseSourceV1::new(vec![entry])?;
    Ok(source.read_verified(&address).err())
}

/// A closure from the sibling builder, its manifest, and its blobs without the empty config.
fn built() -> Result<Built, BoxError> {
    let bundle = build_oci_closure_v1(&ReleaseClosureInputV1 {
        pmf1: b"pmf1",
        component: b"component",
        wit: b"wit",
        schemas: vec![b"schema-a".as_slice(), b"schema-b".as_slice()],
        provenance: b"provenance",
        sbom: b"sbom",
        licences: vec![b"licence".as_slice()],
        migration_fixtures: vec![],
    })?;
    let blobs = bundle
        .blobs()
        .iter()
        .filter(|blob| blob.digest() != EMPTY_CONFIG)
        .map(|blob| blob.bytes().to_vec())
        .collect::<Vec<_>>();
    let manifest = bundle.manifest().to_vec();
    Ok((bundle, manifest, blobs))
}

#[test]
fn an_entry_built_from_bytes_reads_back_the_builders_closure() -> TestResult {
    let (bundle, manifest, blobs) = built()?;
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest.clone(), blobs)?;
    // The address is the sha256 of the manifest bytes, computed independently here.
    assert_eq!(entry.address().digest(), sha256(&manifest));
    assert_eq!(entry.address().size(), manifest.len() as u64);
    assert_eq!(entry.address(), bundle.address());
    let source = InMemoryReleaseSourceV1::new(vec![entry.clone()])?;
    let read = source.read_verified(entry.address())?;
    assert_eq!(read, bundle);
    // The empty-config blob was added although the supplied blobs omit it.
    let empty = read
        .blobs()
        .iter()
        .find(|blob| blob.digest() == EMPTY_CONFIG)
        .map(|blob| blob.bytes().to_vec());
    assert_eq!(empty, Some(b"{}".to_vec()));
    // The reading is repeatable: nothing is consumed or cached.
    assert_eq!(source.read_verified(entry.address())?, bundle);
    Ok(())
}

#[test]
fn supplying_the_empty_config_blob_is_the_same_as_omitting_it() -> TestResult {
    let (bundle, manifest, mut blobs) = built()?;
    blobs.push(b"{}".to_vec());
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest, blobs)?;
    let source = InMemoryReleaseSourceV1::new(vec![entry.clone()])?;
    assert_eq!(source.read_verified(entry.address())?, bundle);
    Ok(())
}

#[test]
fn a_manifest_without_an_address_is_rejected() {
    let empty = InMemoryReleaseEntryV1::from_bytes(Vec::new(), vec![]);
    let oversized = InMemoryReleaseEntryV1::from_bytes(vec![b'x'; 64 * 1024 + 1], vec![]);
    assert_eq!(empty.err(), Some(E::InvalidAddress));
    assert_eq!(oversized.err(), Some(E::InvalidAddress));
    // The bound is inclusive: a manifest of exactly 64 KiB has an address, and so has one byte.
    let exact = InMemoryReleaseEntryV1::from_bytes(vec![b'x'; 64 * 1024], vec![]);
    let single = InMemoryReleaseEntryV1::from_bytes(vec![b'x'], vec![]);
    assert!(exact.is_ok());
    assert!(single.is_ok());
}

#[test]
fn construction_rejects_a_duplicate_address_and_an_empty_set() -> TestResult {
    let (_, manifest, blobs) = built()?;
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest, blobs)?;
    let both = vec![entry.clone(), entry.clone()];
    let duplicate = InMemoryReleaseSourceV1::new(both).err();
    let none = InMemoryReleaseSourceV1::new(vec![]).err();
    assert_eq!(duplicate, Some(E::DuplicateAddress));
    assert_eq!(none, Some(E::Empty));
    assert!(InMemoryReleaseSourceV1::new(vec![entry]).is_ok());
    Ok(())
}

#[test]
fn two_distinct_releases_are_held_side_by_side() -> TestResult {
    let (bundle, manifest, blobs) = built()?;
    let first = InMemoryReleaseEntryV1::from_bytes(manifest, blobs)?;
    let other = entry_of(&good_layers())?;
    assert_ne!(first.address(), other.address());
    let source = InMemoryReleaseSourceV1::new(vec![first.clone(), other.clone()])?;
    assert_eq!(source.read_verified(first.address())?, bundle);
    let read = source.read_verified(other.address())?;
    assert_eq!(read.address(), other.address());
    Ok(())
}

#[test]
fn every_fault_inside_the_held_bytes_is_the_verifiers_closed_error_at_every_read() -> TestResult {
    // The good layout is the control of every fault below.
    assert_eq!(read_error(entry_of(&good_layers())?)?, None);

    // A flipped blob byte: the blob is keyed by its own digest, which the manifest does not name.
    // The control with the unflipped blob passes; the flipped one has the same manifest and
    // address but a different blob set, and fails. `DigestMismatch` is unreachable here.
    let mut flipped = good_layers();
    let manifest = manifest_of(&flipped);
    let control = InMemoryReleaseEntryV1::from_bytes(manifest.clone(), bytes_of(&flipped))?;
    flipped[1].bytes[0] ^= 1;
    assert_ne!(flipped[1].bytes, good_layers()[1].bytes);
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest, bytes_of(&flipped))?;
    assert_eq!(entry.address(), control.address());
    assert_eq!(read_error(control)?, None);
    assert_eq!(read_error(entry)?, Some(S::BoundsExceeded));

    // A wrong layer size: the descriptor says one byte more than the blob holds.
    let mut sized = good_layers();
    sized[1].size += 1;
    let entry = entry_of(&sized)?;
    assert_eq!(read_error(entry)?, Some(S::SizeMismatch));

    // A duplicate member: two layers with the same digest.
    let mut duplicate = good_layers();
    duplicate[2] = layer("wit", WIT, b"component");
    let entry = entry_of(&duplicate)?;
    assert_eq!(read_error(entry)?, Some(S::DuplicateMember));

    // A wrong layer media type.
    let mut media = good_layers();
    media[2].media_type = COMPONENT;
    let entry = entry_of(&media)?;
    assert_eq!(read_error(entry)?, Some(S::UnsupportedMediaType));

    // A blob the manifest does not name.
    let layers = good_layers();
    let mut blobs = bytes_of(&layers);
    blobs.push(b"unnamed".to_vec());
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest_of(&layers), blobs)?;
    assert_eq!(read_error(entry)?, Some(S::BoundsExceeded));

    // A missing blob.
    let mut blobs = bytes_of(&layers);
    blobs.pop();
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest_of(&layers), blobs)?;
    assert_eq!(read_error(entry)?, Some(S::BoundsExceeded));
    Ok(())
}

#[test]
fn an_unknown_address_is_not_found() -> TestResult {
    let (_, manifest, blobs) = built()?;
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest, blobs)?;
    let source = InMemoryReleaseSourceV1::new(vec![entry.clone()])?;
    let unknown = BundleAddressV1::new(format!("sha256:{}", "ab".repeat(32)), 100)?;
    assert_eq!(source.read_verified(&unknown).err(), Some(S::NotFound));
    // The right digest with another size is another address.
    let digest = entry.address().digest().to_owned();
    let resized = BundleAddressV1::new(digest, entry.address().size() + 1)?;
    assert_eq!(source.read_verified(&resized).err(), Some(S::NotFound));
    Ok(())
}

#[test]
fn a_clone_serves_the_same_bytes_and_the_types_describe_themselves() -> TestResult {
    let (_, manifest, blobs) = built()?;
    let entry = InMemoryReleaseEntryV1::from_bytes(manifest, blobs)?;
    let source = InMemoryReleaseSourceV1::new(vec![entry.clone()])?;
    let boxed: Box<dyn ReleaseSourceV1> = Box::new(source.clone());
    let first = source.read_verified(entry.address())?;
    let second = boxed.read_verified(entry.address())?;
    assert_eq!(first, second);
    assert!(format!("{source:?}").contains("InMemoryReleaseSourceV1"));
    assert!(format!("{entry:?}").contains("InMemoryReleaseEntryV1"));
    for error in [E::InvalidAddress, E::DuplicateAddress, E::Empty] {
        assert!(!error.to_string().is_empty());
    }
    Ok(())
}
