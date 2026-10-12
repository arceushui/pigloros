//! R8-M2: byte-built trust material and the fixed material source (ADR-061 revision 8
//! decision 5), at the public seam, on the shared signed-release test world.
//!
//! The world's real PTR1, PRV1 and TPS1 bytes feed `from_bytes_v1`, and the real gate consumes
//! the result. The construction checks only anchors and emptiness; the pair of tests on record
//! length shows the gate, not the constructor, refuses a malformed record.
#![cfg(target_os = "linux")]

use pos_conformance::PluginTrustPolicyAnchorV1;
use pos_plugin_publisher::test_support::{
    encoding::{Material, TICK},
    release::Shape,
    world::{wall, World},
    BoxResult,
};
use pos_plugin_release::BundleAddressV1;
use pos_runtime::community_plugin_host::{
    gate_community_release_v1, CommunityPassAuthorizationV1, CommunityPassV1,
    CommunityPluginExpectationV1, CommunityPluginTrustMaterialV1, CommunityTrustAnchorBytesV1,
    CommunityTrustBytesErrorV1 as Bytes, FixedTrustMaterialSourceV1, GatedCommunityReleaseV1,
    PluginTrustMaterialSourceV1, PluginTrustMaterialUnavailableV1,
};
use pos_store::plugin_trust_registry::TrustedUtcSecondV1;

#[path = "common/host_errors.rs"]
pub mod host_errors;

use host_errors::{Error, UNTRUSTED};

type Gate = Result<(GatedCommunityReleaseV1, CommunityPassAuthorizationV1), Error>;
type TestResult = BoxResult<()>;

const PLUGIN_ID: &str = "plugin-a";

fn anchor_bytes(anchor: &PluginTrustPolicyAnchorV1) -> CommunityTrustAnchorBytesV1 {
    CommunityTrustAnchorBytesV1 {
        scope: anchor.scope().to_owned(),
        ptr1_genesis_digest: anchor.ptr1_genesis_digest(),
        operator_key: anchor.operator_key(),
        genesis_tps1_digest: anchor.genesis_tps1_digest(),
    }
}

/// The world's genuine material, the same bytes the gate vectors build with `new`.
fn reference(world: &World, material: &Material) -> CommunityPluginTrustMaterialV1 {
    CommunityPluginTrustMaterialV1::new(
        world.anchor.clone(),
        material.root_anchor().clone(),
        material.tps1.clone(),
        vec![material.ptr1().to_vec()],
        material.prv1_records().to_vec(),
    )
}

/// The same bytes through `from_bytes_v1`, with `roots` replacing the PTR1 history.
fn from_bytes(
    world: &World,
    material: &Material,
    roots: Vec<Vec<u8>>,
) -> Result<CommunityPluginTrustMaterialV1, Bytes> {
    let anchor = anchor_bytes(&world.anchor);
    let tps1 = material.tps1.clone();
    let revocations = material.prv1_records().to_vec();
    CommunityPluginTrustMaterialV1::from_bytes_v1(&anchor, tps1, roots, revocations)
}

/// A world with its first release installed and active, and the address of that release.
fn installed() -> BoxResult<(World, BundleAddressV1)> {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let address = published.address().clone();
    world
        .install(&address, 1)?
        .map_err(|error| format!("install failed: {error}"))?;
    Ok((world, address))
}

fn gate(
    world: &World,
    address: &BundleAddressV1,
    source: &impl PluginTrustMaterialSourceV1,
) -> BoxResult<Gate> {
    let utc = TrustedUtcSecondV1::from_source(&mut wall(50)?)?;
    let pass = CommunityPassV1::open_for_test(utc, TICK);
    let expected = CommunityPluginExpectationV1 {
        plugin_id: PLUGIN_ID.to_owned(),
        release: None,
    };
    Ok(gate_community_release_v1(
        &world.registry,
        &expected,
        &world.store,
        address,
        source,
        &pass,
    ))
}

fn one() -> Vec<Vec<u8>> {
    vec![vec![1]]
}

/// The error of `from_bytes_v1` for the anchor and the two histories, with a fixed TPS1.
fn build(
    anchor: &CommunityTrustAnchorBytesV1,
    roots: Vec<Vec<u8>>,
    revocations: Vec<Vec<u8>>,
) -> Option<Bytes> {
    let built = CommunityPluginTrustMaterialV1::from_bytes_v1(anchor, vec![9], roots, revocations);
    built.err()
}

fn assert_same(left: &CommunityPluginTrustMaterialV1, right: &CommunityPluginTrustMaterialV1) {
    assert_eq!(left.policy_anchor(), right.policy_anchor());
    assert_eq!(left.root_anchor(), right.root_anchor());
    assert_eq!(left.tps1_bytes(), right.tps1_bytes());
    assert_eq!(left.roots(), right.roots());
    assert_eq!(left.revocations(), right.revocations());
}

#[test]
fn from_bytes_builds_the_material_the_gate_accepts() -> TestResult {
    let (world, address) = installed()?;
    let material = world.material()?;
    let built = from_bytes(&world, &material, vec![material.ptr1().to_vec()])?;
    assert_same(&built, &reference(&world, &material));
    let source = FixedTrustMaterialSourceV1::new(built);
    let (gated, _) = gate(&world, &address, &source)??;
    assert_eq!(gated.plugin_id(), PLUGIN_ID);
    Ok(())
}

#[test]
fn a_record_of_any_length_is_accepted_at_construction_and_refused_by_the_gate() -> TestResult {
    let (world, address) = installed()?;
    let material = world.material()?;
    // Pair: the genuine record passes the gate; the same call with a malformed record of any
    // length is built without a pre-check and refused by the gate alone.
    let genuine = from_bytes(&world, &material, vec![material.ptr1().to_vec()])?;
    let source = FixedTrustMaterialSourceV1::new(genuine);
    let accepted = gate(&world, &address, &source)?;
    assert!(accepted.is_ok());
    for length in [0, 1, 1 << 20] {
        let built = from_bytes(&world, &material, vec![vec![0xA5; length]])?;
        let source = FixedTrustMaterialSourceV1::new(built);
        let refused = gate(&world, &address, &source)?;
        assert_eq!(refused.err(), Some(UNTRUSTED), "record length {length}");
    }
    Ok(())
}

#[test]
fn from_bytes_rejects_an_invalid_anchor_and_empty_histories() -> TestResult {
    let (world, _) = installed()?;
    let valid = anchor_bytes(&world.anchor);
    assert_eq!(build(&valid, one(), one()), None);
    // The scope grammar bound is inclusive: 128 characters pass and 129 do not.
    for (scope, expected) in [
        (String::new(), Some(Bytes::Anchor)),
        ("Upper".to_owned(), Some(Bytes::Anchor)),
        ("-lead".to_owned(), Some(Bytes::Anchor)),
        ("a".repeat(129), Some(Bytes::Anchor)),
        ("a".repeat(128), None),
    ] {
        let anchor = CommunityTrustAnchorBytesV1 {
            scope: scope.clone(),
            ..valid.clone()
        };
        let got = build(&anchor, one(), one());
        assert_eq!(got, expected, "scope {scope:?}");
    }
    let mut off_curve = [0; 32];
    off_curve[0] = 2;
    let key = CommunityTrustAnchorBytesV1 {
        operator_key: off_curve,
        ..valid.clone()
    };
    assert_eq!(build(&key, one(), one()), Some(Bytes::Anchor));
    assert_eq!(build(&valid, vec![], one()), Some(Bytes::Empty));
    assert_eq!(build(&valid, one(), vec![]), Some(Bytes::Empty));
    assert_eq!(build(&valid, vec![], vec![]), Some(Bytes::Empty));
    Ok(())
}

#[test]
fn one_record_histories_are_accepted_and_kept_in_order() -> TestResult {
    let (world, _) = installed()?;
    let anchor = anchor_bytes(&world.anchor);
    let built = CommunityPluginTrustMaterialV1::from_bytes_v1(
        &anchor,
        vec![7, 8],
        vec![vec![1], vec![2, 3]],
        vec![vec![4]],
    )?;
    assert_eq!(built.tps1_bytes(), [7, 8]);
    assert_eq!(built.roots(), [vec![1], vec![2, 3]]);
    assert_eq!(built.revocations(), [vec![4]]);
    assert_eq!(built.policy_anchor(), &world.anchor);
    Ok(())
}

#[test]
fn a_clone_of_the_fixed_source_serves_equal_material() -> TestResult {
    let (world, _) = installed()?;
    let material = world.material()?;
    let source = FixedTrustMaterialSourceV1::new(reference(&world, &material));
    let boxed: Box<dyn PluginTrustMaterialSourceV1> = Box::new(source.clone());
    assert_same(&source.material()?, &boxed.material()?);
    assert_same(&source.material()?, &reference(&world, &material));
    assert!(format!("{source:?}").contains("FixedTrustMaterialSourceV1"));
    let unavailable = FixedTrustMaterialSourceV1::unavailable();
    let copy = unavailable.clone();
    let first = unavailable.material().err();
    let second = copy.material().err();
    assert_eq!(first, Some(PluginTrustMaterialUnavailableV1));
    assert_eq!(second, Some(PluginTrustMaterialUnavailableV1));
    Ok(())
}

#[test]
fn the_anchor_bytes_and_errors_compare_clone_and_describe_themselves() -> TestResult {
    let (world, _) = installed()?;
    let anchor = anchor_bytes(&world.anchor);
    let other = CommunityTrustAnchorBytesV1 {
        scope: "other".to_owned(),
        ..anchor.clone()
    };
    assert_eq!(anchor, anchor.clone());
    assert_ne!(anchor, other);
    assert!(format!("{anchor:?}").contains("CommunityTrustAnchorBytesV1"));
    assert!(!Bytes::Anchor.to_string().is_empty());
    assert!(!Bytes::Empty.to_string().is_empty());
    assert_ne!(Bytes::Anchor, Bytes::Empty);
    Ok(())
}
