//! Public-seam tests for `build_oci_closure_v1`, the inverse of
//! `verify_oci_closure_v1`.
//!
//! The golden manifest below was produced by an independent script (Python
//! `hashlib` and `json`, sorted keys, no whitespace), not by this crate.

use std::collections::BTreeMap;

use pos_plugin_release::{
    build_oci_closure_v1, verify_oci_closure_v1, BundleAddressV1, ReleaseClosureInputV1,
    ReleaseSourceErrorV1, VerifiedReleaseBundleV1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The canonical manifest of `golden_input`, from the independent generator, in pieces.
const GOLDEN_MANIFEST_PIECES: &[&str] = &[
    r#"{"artifactType":"application/vnd.pigloros.plugin.release.v1","config":{"digest":"#,
    r#""sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","media"#,
    r#"Type":"application/vnd.oci.empty.v1+json","size":2},"layers":[{"annotations":{"o"#,
    r#"rg.pigloros.plugin.member":"pmf1"},"digest":"sha256:2a18160355b30a36c653d95a29e6"#,
    r#"fc46ac8bacafff1acd226701523ecfb592f3","mediaType":"application/vnd.pigloros.plug"#,
    r#"in.manifest.v1+cbor","size":4},{"annotations":{"org.pigloros.plugin.member":"com"#,
    r#"ponent"},"digest":"sha256:6985ca1f4daa5a584a28eae043a239cb96689af1337ea13afb63e0"#,
    r#"0c2bf512fa","mediaType":"application/vnd.pigloros.plugin.component.v1+wasm","siz"#,
    r#"e":9},{"annotations":{"org.pigloros.plugin.member":"wit"},"digest":"sha256:939df"#,
    r#"4a72606636c5f6a000fff6325ab1ff06e0e68480894e72e0377a05802a7","mediaType":"applic"#,
    r#"ation/vnd.pigloros.plugin.wit.v1+tar","size":3},{"annotations":{"org.pigloros.pl"#,
    r#"ugin.member":"schema/010b0e628c9f63b9811ff16bf2d35d634b6c2ff2b0a457e9c0a73b45486"#,
    r#"01d58"},"digest":"sha256:010b0e628c9f63b9811ff16bf2d35d634b6c2ff2b0a457e9c0a73b4"#,
    r#"548601d58","mediaType":"application/vnd.pigloros.plugin.schema.v1+json","size":8"#,
    r#"},{"annotations":{"org.pigloros.plugin.member":"schema/4485bff988fca40fe77fc06bd"#,
    r#"35986101ef121185f1abc8e46929704250ae739"},"digest":"sha256:4485bff988fca40fe77fc"#,
    r#"06bd35986101ef121185f1abc8e46929704250ae739","mediaType":"application/vnd.piglor"#,
    r#"os.plugin.schema.v1+json","size":8},{"annotations":{"org.pigloros.plugin.member""#,
    r#":"provenance"},"digest":"sha256:96d815328a42cb4ef89d5e0b7a1df6be43b484832c83a7b4"#,
    r#"596d8402c7c0b12b","mediaType":"application/vnd.in-toto+json","size":10},{"annota"#,
    r#"tions":{"org.pigloros.plugin.member":"sbom"},"digest":"sha256:98f3ae1ef67113d814"#,
    r#"0d4f6cb8d2830070e21ea48f091be519659846c771a374","mediaType":"application/spdx+js"#,
    r#"on","size":4},{"annotations":{"org.pigloros.plugin.member":"licence/8178ac72b28d"#,
    r#"77fcb851fcd301583182bd05d9663ed2ec8131e60f057c2795f7"},"digest":"sha256:8178ac72"#,
    r#"b28d77fcb851fcd301583182bd05d9663ed2ec8131e60f057c2795f7","mediaType":"text/plai"#,
    r#"n; charset=utf-8","size":7},{"annotations":{"org.pigloros.plugin.member":"migrat"#,
    r#"ion-fixture/f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d"},""#,
    r#"digest":"sha256:f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d"#,
    r#"","mediaType":"application/vnd.pigloros.plugin.migration-fixture.v1+cbor","size""#,
    r#":7}],"mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2}"#,
];
const GOLDEN_ADDRESS: &str =
    "sha256:b147d65b4129e72b275752c3803848f3fcfbcc9855e0bd4012857b368695275c";
const GOLDEN_SIZE: u64 = 2400;
// Mirrors `MAX_BLOB_BYTES` in `oci.rs`, which is private; the tests below pin the exact
// boundary (one byte over is rejected, 2 x MAX_BLOB breaks the 64 MiB total). They
// allocate roughly 200 MiB at peak.
const MAX_BLOB: usize = 32 * 1024 * 1024;

fn golden_manifest() -> String {
    GOLDEN_MANIFEST_PIECES.concat()
}

fn golden_input<'a>() -> ReleaseClosureInputV1<'a> {
    ReleaseClosureInputV1 {
        pmf1: b"pmf1",
        component: b"component",
        wit: b"wit",
        schemas: vec![b"schema-a", b"schema-b"],
        provenance: b"provenance",
        sbom: b"sbom",
        licences: vec![b"licence"],
        migration_fixtures: vec![b"fixture"],
    }
}

fn blob_map(bundle: &VerifiedReleaseBundleV1) -> BTreeMap<String, Vec<u8>> {
    bundle
        .blobs()
        .iter()
        .map(|blob| (blob.digest().to_owned(), blob.bytes().to_vec()))
        .collect()
}

/// `count` distinct two-byte members from `start`.
fn distinct(start: u16, count: u16) -> Vec<[u8; 2]> {
    (start..start + count).map(u16::to_be_bytes).collect()
}

/// A valid input whose digest-addressed roles are the given members.
fn with_roles<'a>(
    schemas: &'a [[u8; 2]],
    licences: &'a [[u8; 2]],
    fixtures: &'a [[u8; 2]],
) -> ReleaseClosureInputV1<'a> {
    let mut input = golden_input();
    input.schemas = schemas.iter().map(<[u8; 2]>::as_slice).collect();
    input.licences = licences.iter().map(<[u8; 2]>::as_slice).collect();
    input.migration_fixtures = fixtures.iter().map(<[u8; 2]>::as_slice).collect();
    input
}

#[test]
fn builds_the_independent_golden_manifest_byte_for_byte() -> TestResult {
    let bundle = build_oci_closure_v1(&golden_input())?;
    assert_eq!(bundle.manifest(), golden_manifest().into_bytes());
    assert_eq!(bundle.address().digest(), GOLDEN_ADDRESS);
    assert_eq!(bundle.address().size(), GOLDEN_SIZE);
    assert_eq!(bundle.members().len(), 9);
    assert_eq!(bundle.blobs().len(), 10);
    assert_eq!(bundle.pmf1(), b"pmf1");
    let members = bundle
        .members()
        .iter()
        .map(|member| member.member().split('/').next().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(
        members,
        [
            "pmf1",
            "component",
            "wit",
            "schema",
            "schema",
            "provenance",
            "sbom",
            "licence",
            "migration-fixture",
        ]
    );
    Ok(())
}

#[test]
fn a_built_closure_round_trips_through_the_verifier() -> TestResult {
    let built = build_oci_closure_v1(&golden_input())?;
    let verified = verify_oci_closure_v1(
        BundleAddressV1::new(GOLDEN_ADDRESS.to_owned(), GOLDEN_SIZE)?,
        golden_manifest().into_bytes(),
        blob_map(&built),
    )?;
    assert_eq!(verified, built);
    let bytes = verified.member_bytes().collect::<Vec<_>>();
    assert_eq!(
        bytes,
        [
            &b"pmf1"[..],
            b"component",
            b"wit",
            b"schema-a",
            b"schema-b",
            b"provenance",
            b"sbom",
            b"licence",
            b"fixture",
        ]
    );
    Ok(())
}

#[test]
fn member_order_in_the_input_never_changes_the_closure() -> TestResult {
    let mut input = golden_input();
    input.schemas.reverse();
    let bundle = build_oci_closure_v1(&input)?;
    assert_eq!(bundle, build_oci_closure_v1(&golden_input())?);
    let schemas = distinct(0, 5);
    let licences = distinct(100, 7);
    let mut reversed = licences.clone();
    reversed.reverse();
    let forward = build_oci_closure_v1(&with_roles(&schemas, &licences, &[]))?;
    let backward = build_oci_closure_v1(&with_roles(&schemas, &reversed, &[]))?;
    assert_eq!(forward, backward);
    Ok(())
}

#[test]
fn optional_roles_may_be_absent_but_a_licence_may_not() -> TestResult {
    let bundle = build_oci_closure_v1(&with_roles(&[], &distinct(100, 1), &[]))?;
    assert_eq!(bundle.members().len(), 6);
    assert_eq!(counted(0, 0), Err(ReleaseSourceErrorV1::BoundsExceeded));
    Ok(())
}

/// Build a closure with `licences` licence and `fixtures` migration members.
fn counted(licences: u16, fixtures: u16) -> Result<VerifiedReleaseBundleV1, ReleaseSourceErrorV1> {
    let licences = distinct(100, licences);
    let fixtures = distinct(1000, fixtures);
    build_oci_closure_v1(&with_roles(&[], &licences, &fixtures))
}

#[test]
fn role_count_bounds_are_the_verifiers() {
    assert!(counted(32, 0).is_ok());
    assert_eq!(counted(33, 0), Err(ReleaseSourceErrorV1::BoundsExceeded));
    assert!(counted(1, 64).is_ok());
    assert_eq!(counted(1, 65), Err(ReleaseSourceErrorV1::BoundsExceeded));
}

#[test]
fn a_closure_the_verifier_would_reject_is_not_built() {
    let mut empty = golden_input();
    empty.wit = b"";
    assert_eq!(
        build_oci_closure_v1(&empty),
        Err(ReleaseSourceErrorV1::InvalidDescriptor)
    );
    let mut duplicate_in_role = golden_input();
    duplicate_in_role.schemas = vec![b"same", b"same"];
    assert_eq!(
        build_oci_closure_v1(&duplicate_in_role),
        Err(ReleaseSourceErrorV1::DuplicateMember)
    );
    let mut duplicate_across_roles = golden_input();
    duplicate_across_roles.sbom = b"component";
    assert_eq!(
        build_oci_closure_v1(&duplicate_across_roles),
        Err(ReleaseSourceErrorV1::DuplicateMember)
    );
}

#[test]
fn manifest_and_blob_size_bounds_are_enforced() {
    // 300 schema descriptors push the canonical manifest past 64 KiB.
    let schemas = distinct(2000, 300);
    let licences = distinct(100, 1);
    assert_eq!(
        build_oci_closure_v1(&with_roles(&schemas, &licences, &[])),
        Err(ReleaseSourceErrorV1::InvalidAddress)
    );
    let oversized = vec![1_u8; MAX_BLOB + 1];
    let mut input = golden_input();
    input.component = &oversized;
    assert_eq!(
        build_oci_closure_v1(&input),
        Err(ReleaseSourceErrorV1::InvalidDescriptor)
    );
    let component = vec![1_u8; MAX_BLOB];
    let wit = vec![2_u8; MAX_BLOB];
    input.component = &component;
    input.wit = &wit;
    assert_eq!(
        build_oci_closure_v1(&input),
        Err(ReleaseSourceErrorV1::BoundsExceeded)
    );
}
