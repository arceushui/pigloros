//! Public compatibility vectors for ADR-060 complete-inventory generations.

use pos_core::{
    ErasureErrorV1, ErasurePersistenceInventorySnapshotV1, ErasureReferenceV1, TimelineId,
};

const fn reference(value: u8) -> ErasureReferenceV1 {
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

#[test]
fn empty_complete_inventory_generation_has_a_stable_vector(
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = ErasurePersistenceInventorySnapshotV1::new(Vec::new(), Vec::new(), 1)?;

    assert_eq!(
        snapshot.generation(),
        ErasureReferenceV1::from_digest([
            0x69, 0x90, 0x4b, 0xa9, 0x74, 0x43, 0x0a, 0xf5, 0xc8, 0x16, 0xfb, 0x2d, 0x15, 0xe9,
            0x4b, 0xf5, 0x44, 0x0c, 0x6c, 0x65, 0x06, 0xf8, 0x76, 0x7e, 0xc2, 0x37, 0xfd, 0x6c,
            0xbd, 0xfe, 0xde, 0xd4,
        ])
    );
    Ok(())
}

#[test]
fn complete_inventory_rejects_descending_canonical_members() {
    assert_eq!(
        ErasurePersistenceInventorySnapshotV1::new(
            vec![(reference(2), reference(3)), (reference(1), reference(4))],
            Vec::new(),
            2,
        ),
        Err(ErasureErrorV1::ProvenanceMissing),
    );
    assert_eq!(
        ErasurePersistenceInventorySnapshotV1::new(
            Vec::new(),
            vec![
                TimelineId::from_ulid(ulid::Ulid::from(2_u128)),
                TimelineId::from_ulid(ulid::Ulid::from(1_u128)),
            ],
            1,
        ),
        Err(ErasureErrorV1::ProvenanceMissing),
    );
}
