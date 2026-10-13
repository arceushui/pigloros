//! Factual owner IDs of the registry entries (ADR-064 Revision 3, R3.2.4).

use std::time::Duration;

use pos_core::crypto::Hash;

use super::pass_state_tests::{gated_registry, ids, probe};
use super::test_ext::TestValueExt;
use super::*;

struct LocalPlugin {
    id: PluginId,
    name: &'static str,
}

impl Plugin for LocalPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability::default()
    }
}

fn register_slotted(registry: &mut PluginRegistry, name: &'static str, slot: &str) {
    let plugin = LocalPlugin {
        id: PluginId::new(),
        name,
    };
    let roles = vec![format!("role.{slot}")];
    let slot = ManifestSlotV1::try_new(slot).test_ok();
    registry
        .register_local(&plugin, slot, roles, None, None)
        .test_ok();
}

fn owner_of_slot(registry: &PluginRegistry, slot: &str) -> String {
    let entry = registry
        .plugins
        .values()
        .find(|entry| entry.manifest_slot.as_ref().map(ManifestSlotV1::as_str) == Some(slot));
    entry.test_ok().pass_state.owner_id.as_str().to_owned()
}

/// The slotted preimage of R3.2.4, written out independently of the helper.
fn slotted_vector(slot: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.FactualOwner.v1");
    hasher.update(&[0, 1]);
    hasher.update(&u64::try_from(slot.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(slot.as_bytes());
    format!("plugin:{}", hasher.finalize().to_hex())
}

/// The slotless preimage of R3.2.4, written out independently of the helper.
fn slotless_vector(policy_identity: Hash, name: &str, rank: u32) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.FactualOwner.v1");
    hasher.update(&[0, 2]);
    hasher.update(policy_identity.as_bytes());
    hasher.update(&u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(&rank.to_be_bytes());
    format!("plugin:{}", hasher.finalize().to_hex())
}

/// The entry of the test Driver with this marker.
fn entry_of_marker(registry: &PluginRegistry, marker: u64) -> &PluginEntry {
    let wanted = Duration::from_nanos(marker);
    let entry = registry.plugins.values().find(|entry| {
        entry
            .driver
            .as_ref()
            .is_some_and(|driver| driver.tick_interval() == wanted)
    });
    entry.test_ok()
}

/// The owner ID of the test Driver with this marker.
fn owner_of_marker(registry: &PluginRegistry, marker: u64) -> String {
    entry_of_marker(registry, marker)
        .pass_state
        .owner_id
        .as_str()
        .to_owned()
}

fn policy_identity_of(registry: &PluginRegistry, marker: u64) -> Hash {
    let entry = entry_of_marker(registry, marker);
    let admission = entry.output_admission.as_ref().test_ok();
    admission.closure().test_ok().replay_identity_digest()
}

fn twin_registry(markers: [u64; 2]) -> PluginRegistry {
    let mut registry = gated_registry();
    for marker in markers {
        let (driver, _) = probe("twin", marker, &[]);
        registry.register_test_driver(Box::new(driver));
    }
    registry
}

#[test]
fn a_slotted_owner_id_is_the_pinned_function_of_the_slot() {
    let mut registry = gated_registry();
    register_slotted(&mut registry, "twin", "north");
    assert_eq!(owner_of_slot(&registry, "north"), slotted_vector("north"));
    // The slot text stays out of the recorded ID.
    assert!(!owner_of_slot(&registry, "north").contains("north"));
}

#[test]
fn slotted_twins_differ_by_slot_and_ignore_unrelated_registrations() {
    let mut first = gated_registry();
    register_slotted(&mut first, "twin", "north");
    register_slotted(&mut first, "twin", "south");
    let north = owner_of_slot(&first, "north");
    let south = owner_of_slot(&first, "south");
    assert_ne!(north, south);

    // The same slots in another registry, with an unrelated Plugin inserted
    // between them and the registration order reversed.
    let mut second = gated_registry();
    register_slotted(&mut second, "twin", "south");
    second
        .register_generated(
            &LocalPlugin {
                id: PluginId::new(),
                name: "unrelated",
            },
            None,
            None,
        )
        .test_ok();
    register_slotted(&mut second, "twin", "north");
    assert_eq!(owner_of_slot(&second, "north"), north);
    assert_eq!(owner_of_slot(&second, "south"), south);
}

#[test]
fn a_slotted_owner_id_is_unchanged_by_local_manifest_admission() {
    let mut registry = gated_registry();
    register_slotted(&mut registry, "twin", "north");
    register_slotted(&mut registry, "twin", "south");
    let before = registry.factual_owner_ids();
    let owner = OwnerIdV1::from_static("owner-id-fixture");
    registry
        .admit_local_manifest_registration(owner, 1)
        .test_ok();
    assert_eq!(registry.factual_owner_ids(), before);
}

#[test]
fn slotless_twins_take_ranks_in_registration_order() {
    let first = twin_registry([1, 2]);
    let identity = policy_identity_of(&first, 1);
    assert_eq!(identity, policy_identity_of(&first, 2));
    let (rank_zero, rank_one) = (
        slotless_vector(identity, "twin", 0),
        slotless_vector(identity, "twin", 1),
    );
    assert_eq!(owner_of_marker(&first, 1), rank_zero);
    assert_eq!(owner_of_marker(&first, 2), rank_one);

    // The same order gives the same IDs; the swapped order swaps them.
    let same = twin_registry([1, 2]);
    assert_eq!(owner_of_marker(&same, 1), owner_of_marker(&first, 1));
    assert_eq!(owner_of_marker(&same, 2), owner_of_marker(&first, 2));
    let swapped = twin_registry([2, 1]);
    assert_eq!(owner_of_marker(&swapped, 1), owner_of_marker(&first, 2));
    assert_eq!(owner_of_marker(&swapped, 2), owner_of_marker(&first, 1));
}

#[test]
fn slotted_and_slotless_entries_never_collide() {
    let mut registry = gated_registry();
    register_slotted(&mut registry, "twin", "twin");
    let (driver, _) = probe("twin", 1, &[]);
    registry.register_test_driver(Box::new(driver));
    let slotted = owner_of_slot(&registry, "twin");
    let slotless = owner_of_marker(&registry, 1);
    assert_ne!(slotted, slotless);
    // The domain tag keeps the two preimages apart even for equal text.
    let zero_rank = slotless_vector(Hash::zero(), "twin", 0);
    assert_ne!(slotted_vector("twin"), zero_rank);
}

#[test]
fn a_closureless_driver_takes_the_zero_identity_and_is_listed() {
    let mut registry = gated_registry();
    let (driver, _) = probe("bare", 1, &[]);
    registry.register_driver(Box::new(driver)).test_ok();
    let (twin, _) = probe("bare", 2, &[]);
    registry.register_driver(Box::new(twin)).test_ok();

    let rank_zero = slotless_vector(Hash::zero(), "bare", 0);
    let rank_one = slotless_vector(Hash::zero(), "bare", 1);
    assert_eq!(owner_of_marker(&registry, 1), rank_zero);
    assert_eq!(owner_of_marker(&registry, 2), rank_one);
    let listed = registry.factual_owner_ids();
    assert_eq!(listed.len(), 2);
    for ((listed_id, owner), id) in listed.iter().zip(ids(&registry)) {
        assert_eq!(*listed_id, id);
        assert_eq!(owner, &registry.plugins[&id].pass_state.owner_id);
    }
}
