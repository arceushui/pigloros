//! Public compatibility vectors for ADR-060 complete-inventory generations.

use pos_core::{ErasurePersistenceInventorySnapshotV1, ErasureReferenceV1, TimelineId};

fn reference(value: u8) -> ErasureReferenceV1 {
    ErasureReferenceV1::from_digest([value; 32])
}

#[test]
fn complete_inventory_generation_uses_the_canonical_definite_array_vector(
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = ErasurePersistenceInventorySnapshotV1::new(
        vec![(reference(1), reference(2))],
        vec![TimelineId::from_ulid(ulid::Ulid::nil())],
        1,
    )?;

    assert_eq!(
        snapshot.generation(),
        ErasureReferenceV1::from_digest([
            0x91, 0x49, 0x44, 0xaf, 0x1b, 0x11, 0xed, 0xd5, 0x84, 0x70, 0x28, 0x3a, 0xb7, 0x79,
            0xaa, 0x35, 0x4f, 0xe4, 0xc8, 0xd7, 0x25, 0xe5, 0x33, 0x4f, 0x69, 0x61, 0x32, 0x00,
            0x59, 0x50, 0x4c, 0xe3,
        ])
    );
    Ok(())
}
