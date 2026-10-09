//! R7-A1: the activation payload golden vector, and the one-shot source's contract.

use pos_plugin_publisher::test_support::{release::Shape, world::World, BoxResult};

use super::*;

const GOLDEN: &str = "846f706c7567696e2d706f6c6963792d616e6578616d706c652e706c7567696e5820\
                      11111111111111111111111111111111111111111111111111111111111111115820\
                      2222222222222222222222222222222222222222222222222222222222222222";
const GOLDEN_DIGEST: &str = "bef112d44e3c3d728354a491969f1fa20f6ce21c707eb9a67d89b5e333a9faf6";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn activation_payload_matches_the_golden_vector() {
    let payload = activation_payload(
        "plugin-policy-a",
        "example.plugin",
        &[0x11; 32],
        &[0x22; 32],
    );
    assert_eq!(payload.len(), 100);
    assert_eq!(hex(&payload), GOLDEN);
    assert_eq!(hex(blake3::hash(&payload).as_bytes()), GOLDEN_DIGEST);
}

#[test]
fn activation_payload_depends_only_on_its_four_fields() {
    let first = activation_payload("scope", "plugin-a", &[1; 32], &[2; 32]);
    assert_eq!(
        first,
        activation_payload("scope", "plugin-a", &[1; 32], &[2; 32])
    );
    assert_ne!(
        first,
        activation_payload("scope", "plugin-a", &[1; 32], &[3; 32])
    );
}

#[test]
fn the_one_shot_source_yields_its_bundle_once_for_its_own_address_only() -> BoxResult<()> {
    let mut world = World::new()?;
    let published = world.publish(Shape::first())?;
    let address = published.address().clone();
    let bundle = world.store.read_verified(&address)?;
    let other = BundleAddressV1::new(format!("sha256:{}", "ab".repeat(32)), 1)?;
    let once = OneShotSource::new(address.clone(), bundle.clone());
    // Another address is `NotFound` and does not consume the bundle.
    assert_eq!(
        once.read_verified(&other).err(),
        Some(ReleaseSourceErrorV1::NotFound)
    );
    assert_eq!(once.read_verified(&address)?, bundle);
    // The second read of the same address is `NotFound`.
    assert_eq!(
        once.read_verified(&address).err(),
        Some(ReleaseSourceErrorV1::NotFound)
    );
    Ok(())
}
