use pos_core::{
    local_cut_tree_scope_v1, Hash, LocalCutBranchChildV1, LocalCutManifestBindingBranchV1,
    LocalCutManifestBindingPageV1, LocalCutManifestBindingRowV1,
    LocalCutManifestBindingTableV1, LocalCutSealErrorV2, LocalCutSealInputV2, LocalCutSealV2,
    LocalCutTableRefV1, TimelineId, MAX_LOCAL_CUT_SEAL_BYTES_V2,
    MAX_LOCAL_CUT_TABLE_ROWS_V1,
};
use std::fmt::Write as _;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const EXPECTED_LCS2_CBOR_HEX: &str = concat!(
    "96444c43533201582001010101010101010101010101010101010101010101010101010101010101010101000100f6582002020202020202",
    "0202020202020202020202020202020202020202020202020282015820030303030303030303030303030303030303030303030303030303",
    "03030303038201582004040404040404040404040404040404040404040404040404040404040404048200f68200f6820158200505050505",
    "0505050505050505050505050505050505050505050505050505055820060606060606060606060606060606060606060606060606060606",
    "0606060606582007070707070707070707070707070707070707070707070707070707070707078201582008080808080808080808080808",
    "0808080808080808080808080808080808080858200909090909090909090909090909090909090909090909090909090909090909f65820",
    "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a820158200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "0b0b0b0b0b0b0b0b0b0b0b0b",
);
const EXPECTED_LCP1_CBOR_HEX: &str = concat!(
    "86444c435031010e582001010101010101010101010101010101010101010101010101010101010101010081855000000000000000000000",
    "0000000000015820020202020202020202020202020202020202020202020202020202020202020258200303030303030303030303030303",
    "0303030303030303030303030303030303035820040404040404040404040404040404040404040404040404040404040404040458200505",
    "050505050505050505050505050505050505050505050505050505050505",
);
const EXPECTED_LCT1_CBOR_HEX: &str = concat!(
    "88444c435431010e582001010101010101010101010101010101010101010101010101010101010101010100184182830018405820070707",
    "0707070707070707070707070707070707070707070707070707070707831840015820080808080808080808080808080808080808080808",
    "0808080808080808080808",
);

fn hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}")?;
    }
    Ok(text)
}

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn reference(byte: u8) -> Result<LocalCutTableRefV1, LocalCutSealErrorV2> {
    LocalCutTableRefV1::new(1, Some(hash(byte)))
}

fn sample_input() -> Result<LocalCutSealInputV2, LocalCutSealErrorV2> {
    Ok(LocalCutSealInputV2 {
        owner_id: [1; 32],
        cut_id: 1,
        tick: 1,
        membership_epoch: 0,
        configuration_generation: 1,
        schedule_ns: 0,
        previous_visible_receipt_hash: None,
        expected_inventory_generation: hash(2),
        membership_table: reference(3)?,
        composition_table: reference(4)?,
        inbox_table: LocalCutTableRefV1::new(0, None)?,
        invocation_table: LocalCutTableRefV1::new(0, None)?,
        expected_heads_table: reference(5)?,
        ebp_native_hash: hash(6),
        execution_profile_native_hash: hash(7),
        recording_context_table: reference(8)?,
        owner_operational_policy_hash: hash(9),
        explicit_attempt_hash: None,
        ingress_preallocation_native_hash: hash(10),
        manifest_binding_table: reference(11)?,
    })
}

#[test]
fn lcs2_known_digest_and_preferred_roundtrip() -> TestResult {
    let record = LocalCutSealV2::new(sample_input()?)?;
    let bytes = record.to_canonical_cbor();
    assert_eq!(bytes.len(), 404);
    assert_eq!(hex(&bytes)?, EXPECTED_LCS2_CBOR_HEX);
    assert_eq!(&bytes[..7], &[0x96, 0x44, b'L', b'C', b'S', b'2', 1]);
    assert_eq!(LocalCutSealV2::from_canonical_cbor(&bytes)?, record);
    assert_eq!(record.as_input(), &sample_input()?);
    assert_eq!(
        record.digest().as_bytes(),
        &[
            0x44, 0x31, 0x9f, 0x9b, 0x54, 0x45, 0x2c, 0x2a, 0xa8, 0x06, 0xbc, 0x20, 0x51,
            0xa7, 0x89, 0x71, 0xf5, 0xe5, 0xd0, 0x1a, 0xb3, 0xf4, 0x40, 0xc9, 0xdc, 0x86,
            0x6d, 0x12, 0x95, 0xbd, 0xe9, 0x74,
        ]
    );
    Ok(())
}

#[test]
fn lcs2_rejects_unpreferred_and_wrong_wire_shapes() -> TestResult {
    let canonical = LocalCutSealV2::new(sample_input()?)?.to_canonical_cbor();
    let mut old_magic = canonical.clone();
    old_magic[5] = b'1';
    assert_eq!(
        LocalCutSealV2::from_canonical_cbor(&old_magic),
        Err(LocalCutSealErrorV2::InvalidEncoding)
    );
    let mut wrong_count = canonical.clone();
    wrong_count[0] = 0x95;
    assert_eq!(
        LocalCutSealV2::from_canonical_cbor(&wrong_count),
        Err(LocalCutSealErrorV2::InvalidEncoding)
    );
    let mut overlong_version = canonical.clone();
    overlong_version[6] = 0x18;
    overlong_version.insert(7, 1);
    assert_eq!(
        LocalCutSealV2::from_canonical_cbor(&overlong_version),
        Err(LocalCutSealErrorV2::NonCanonical)
    );
    let mut trailing = canonical.clone();
    trailing.push(0xf6);
    assert_eq!(
        LocalCutSealV2::from_canonical_cbor(&trailing),
        Err(LocalCutSealErrorV2::InvalidEncoding)
    );
    let oversized = vec![0; MAX_LOCAL_CUT_SEAL_BYTES_V2 + 1];
    assert_eq!(
        LocalCutSealV2::from_canonical_cbor(&oversized),
        Err(LocalCutSealErrorV2::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn lcs2_structural_bounds_do_not_issue_owner_authority() -> TestResult {
    assert_eq!(
        LocalCutTableRefV1::new(0, Some(hash(1))),
        Err(LocalCutSealErrorV2::InvalidTableReference)
    );
    assert_eq!(
        LocalCutTableRefV1::new(1, None),
        Err(LocalCutSealErrorV2::InvalidTableReference)
    );
    assert_eq!(
        LocalCutTableRefV1::new(1, Some(Hash::zero())),
        Err(LocalCutSealErrorV2::ZeroContentAddress)
    );
    assert_eq!(
        LocalCutTableRefV1::new(MAX_LOCAL_CUT_TABLE_ROWS_V1 + 1, Some(hash(1))),
        Err(LocalCutSealErrorV2::FieldOutOfBounds)
    );
    let mut input = sample_input()?;
    input.cut_id = 0;
    assert_eq!(
        LocalCutSealV2::new(input),
        Err(LocalCutSealErrorV2::FieldOutOfBounds)
    );
    let mut input = sample_input()?;
    input.expected_inventory_generation = Hash::zero();
    assert_eq!(
        LocalCutSealV2::new(input),
        Err(LocalCutSealErrorV2::ZeroContentAddress)
    );
    let mut input = sample_input()?;
    input.inbox_table = LocalCutTableRefV1::new(65_537, Some(hash(12)))?;
    assert_eq!(
        LocalCutSealV2::new(input),
        Err(LocalCutSealErrorV2::FieldOutOfBounds)
    );
    let reference = reference(13)?;
    assert_eq!(reference.row_count(), 1);
    assert_eq!(reference.root_hash(), Some(hash(13)));
    Ok(())
}

fn binding_row(index: u128) -> LocalCutManifestBindingRowV1 {
    LocalCutManifestBindingRowV1 {
        timeline_id: TimelineId::from_ulid(ulid::Ulid::from(index)),
        scope: hash(2),
        wcs_hash: hash(3),
        msr_hash: hash(4),
        msb_hash: hash(5),
    }
}

fn binding_rows(count: u128) -> Vec<LocalCutManifestBindingRowV1> {
    (1..=count).map(binding_row).collect()
}

#[test]
fn kind14_page_and_branch_roundtrip_and_reject_wrong_code() -> TestResult {
    let page = LocalCutManifestBindingPageV1::new(hash(1), 0, vec![binding_row(1)])?;
    let page_bytes = page.to_canonical_cbor();
    assert_eq!(hex(&page_bytes)?, EXPECTED_LCP1_CBOR_HEX);
    assert_eq!(&page_bytes[..8], &[0x86, 0x44, b'L', b'C', b'P', b'1', 1, 14]);
    assert_eq!(LocalCutManifestBindingPageV1::from_canonical_cbor(hash(1), &page_bytes)?, page);
    assert_eq!(page_bytes.len(), 198);
    assert_eq!(
        page.digest().as_bytes(),
        &[
            0xab, 0xcd, 0x6e, 0xc1, 0x5c, 0xf6, 0x26, 0x0e, 0x2d, 0x02, 0x06, 0x38, 0x9c,
            0xb0, 0x9e, 0x8b, 0x57, 0xc1, 0x03, 0x2f, 0x45, 0x1d, 0x44, 0x11, 0x4a, 0x55,
            0x90, 0xc6, 0x4c, 0x9e, 0xd8, 0xce,
        ]
    );
    assert_eq!(page.rows(), &[binding_row(1)]);
    assert_eq!(page.first_ordinal(), 0);

    let branch = LocalCutManifestBindingBranchV1::new(
        hash(1),
        1,
        0,
        vec![
            LocalCutBranchChildV1 {
                first_ordinal: 0,
                row_count: 64,
                node_hash: hash(7),
            },
            LocalCutBranchChildV1 {
                first_ordinal: 64,
                row_count: 1,
                node_hash: hash(8),
            },
        ],
    )?;
    let branch_bytes = branch.to_canonical_cbor();
    assert_eq!(hex(&branch_bytes)?, EXPECTED_LCT1_CBOR_HEX);
    assert_eq!(&branch_bytes[..8], &[0x88, 0x44, b'L', b'C', b'T', b'1', 1, 14]);
    assert_eq!(
        LocalCutManifestBindingBranchV1::from_canonical_cbor(hash(1), &branch_bytes)?,
        branch
    );
    assert_eq!(branch.height(), 1);
    assert_eq!(branch_bytes.len(), 123);
    assert_eq!(
        branch.digest().as_bytes(),
        &[
            0x72, 0x9e, 0x3a, 0x63, 0x9d, 0x43, 0x96, 0x86, 0x8b, 0x66, 0xfe, 0xbc, 0x4a,
            0x1f, 0x16, 0x8d, 0xa2, 0xad, 0xa8, 0x0b, 0x72, 0xcb, 0xec, 0x8b, 0xbd, 0xe5,
            0xc3, 0x4a, 0x23, 0x09, 0xf3, 0x9e,
        ]
    );
    assert_eq!(branch.first_ordinal(), 0);
    assert_eq!(branch.row_count(), 65);
    assert_eq!(branch.children().len(), 2);

    let mut wrong_kind = page_bytes.clone();
    wrong_kind[7] = 13;
    assert_eq!(
        LocalCutManifestBindingPageV1::from_canonical_cbor(hash(1), &wrong_kind),
        Err(LocalCutSealErrorV2::InvalidTableNode)
    );
    let mut wrong_scope = page_bytes.clone();
    wrong_scope[10] = 0;
    assert_eq!(
        LocalCutManifestBindingPageV1::from_canonical_cbor(hash(1), &wrong_scope),
        Err(LocalCutSealErrorV2::InvalidTableNode)
    );
    let mut nonpreferred = page_bytes;
    nonpreferred[6] = 0x18;
    nonpreferred.insert(7, 1);
    assert_eq!(
        LocalCutManifestBindingPageV1::from_canonical_cbor(hash(1), &nonpreferred),
        Err(LocalCutSealErrorV2::NonCanonical)
    );
    let mut wrong_branch_kind = branch_bytes;
    wrong_branch_kind[7] = 13;
    assert_eq!(
        LocalCutManifestBindingBranchV1::from_canonical_cbor(hash(1), &wrong_branch_kind),
        Err(LocalCutSealErrorV2::InvalidTableNode)
    );
    let mut wrong_branch_version = branch.to_canonical_cbor();
    wrong_branch_version[6] = 2;
    assert_eq!(
        LocalCutManifestBindingBranchV1::from_canonical_cbor(hash(1), &wrong_branch_version),
        Err(LocalCutSealErrorV2::UnsupportedVersion)
    );
    let mut trailing = branch.to_canonical_cbor();
    trailing.push(0xf6);
    assert_eq!(
        LocalCutManifestBindingBranchV1::from_canonical_cbor(hash(1), &trailing),
        Err(LocalCutSealErrorV2::InvalidEncoding)
    );
    assert_eq!(
        LocalCutManifestBindingBranchV1::new(
            hash(1),
            1,
            u64::MAX,
            vec![LocalCutBranchChildV1 {
                first_ordinal: u64::MAX,
                row_count: 1,
                node_hash: hash(7),
            }],
        ),
        Err(LocalCutSealErrorV2::FieldOutOfBounds)
    );
    assert_eq!(
        LocalCutManifestBindingBranchV1::new(
            hash(1),
            1,
            0,
            vec![LocalCutBranchChildV1 {
                first_ordinal: 1,
                row_count: 1,
                node_hash: hash(7),
            }],
        ),
        Err(LocalCutSealErrorV2::InvalidTableNode)
    );
    Ok(())
}

#[test]
fn kind14_table_uses_minimal_packed_height_and_complete_nodes() -> TestResult {
    let owner_id = [9; 32];
    let empty = LocalCutManifestBindingTableV1::new(owner_id, 1, Vec::new())?;
    assert_eq!(empty.table_ref(), LocalCutTableRefV1::new(0, None)?);
    assert!(empty.records().is_empty());
    assert_eq!(
        LocalCutManifestBindingTableV1::from_records(
            owner_id,
            1,
            empty.table_ref(),
            empty.records()
        )?,
        empty
    );

    for (count, pages, branches, height) in [
        (1, 1, 0, 0),
        (64, 1, 0, 0),
        (65, 2, 1, 1),
        (15_360, 240, 1, 1),
        (15_361, 241, 3, 2),
    ] {
        let table = LocalCutManifestBindingTableV1::new(owner_id, 1, binding_rows(count))?;
        assert_eq!(table.rows().len(), count as usize);
        assert_eq!(table.tree_scope(), local_cut_tree_scope_v1(owner_id, 1));
        assert_eq!(table.records().len(), pages + branches);
        let root = table.table_ref().root_hash().ok_or("missing table root")?;
        let root_record = table.records().last().ok_or("missing root record")?;
        if height == 0 {
            assert_eq!(
                LocalCutManifestBindingPageV1::from_canonical_cbor(table.tree_scope(), root_record)?
                    .digest(),
                root
            );
        } else {
            let branch = LocalCutManifestBindingBranchV1::from_canonical_cbor(
                table.tree_scope(),
                root_record,
            )?;
            assert_eq!(branch.height(), height);
            assert_eq!(branch.digest(), root);
            if height == 2 {
                let first_branch = LocalCutManifestBindingBranchV1::from_canonical_cbor(
                    table.tree_scope(),
                    &table.records()[pages],
                )?;
                assert_eq!(first_branch.children().len(), 240);
                assert_eq!(first_branch.row_count(), 15_360);
                let last_branch = LocalCutManifestBindingBranchV1::from_canonical_cbor(
                    table.tree_scope(),
                    &table.records()[pages + 1],
                )?;
                assert_eq!(last_branch.children().len(), 1);
                assert_eq!(last_branch.first_ordinal(), 15_360);
            }
        }
        let mut unordered = table.records().to_vec();
        unordered.reverse();
        assert_eq!(
            LocalCutManifestBindingTableV1::from_records(
                owner_id,
                1,
                table.table_ref(),
                &unordered
            )?,
            table
        );
    }
    Ok(())
}

#[test]
fn kind14_table_rejects_duplicate_missing_extra_and_misaddressed_nodes() -> TestResult {
    let owner_id = [9; 32];
    let table = LocalCutManifestBindingTableV1::new(owner_id, 1, binding_rows(65))?;
    let mut duplicate_rows = binding_rows(2);
    duplicate_rows[1] = duplicate_rows[0];
    assert_eq!(
        LocalCutManifestBindingTableV1::new(owner_id, 1, duplicate_rows),
        Err(LocalCutSealErrorV2::RowsNotSorted)
    );
    let mut invalid_row = binding_row(1);
    invalid_row.msb_hash = Hash::zero();
    assert_eq!(
        LocalCutManifestBindingTableV1::new(owner_id, 1, vec![invalid_row]),
        Err(LocalCutSealErrorV2::ZeroContentAddress)
    );
    assert_eq!(
        LocalCutManifestBindingTableV1::new(owner_id, 0, binding_rows(1)),
        Err(LocalCutSealErrorV2::FieldOutOfBounds)
    );
    let mut wrong_scope = table.records().to_vec();
    wrong_scope[0][10] ^= 1;
    assert_eq!(
        LocalCutManifestBindingTableV1::from_records(
            owner_id,
            1,
            table.table_ref(),
            &wrong_scope
        ),
        Err(LocalCutSealErrorV2::InvalidTableNode)
    );
    let mut missing = table.records().to_vec();
    missing.pop();
    assert_eq!(
        LocalCutManifestBindingTableV1::from_records(owner_id, 1, table.table_ref(), &missing),
        Err(LocalCutSealErrorV2::TableMismatch)
    );
    let mut extra = table.records().to_vec();
    extra.push(table.records()[0].clone());
    assert_eq!(
        LocalCutManifestBindingTableV1::from_records(owner_id, 1, table.table_ref(), &extra),
        Err(LocalCutSealErrorV2::TableMismatch)
    );
    assert_eq!(
        LocalCutManifestBindingTableV1::from_records(
            owner_id,
            1,
            LocalCutTableRefV1::new(65, Some(hash(99)))?,
            table.records()
        ),
        Err(LocalCutSealErrorV2::TableMismatch)
    );
    let mut wrong_cut = table.records().to_vec();
    wrong_cut.swap(0, 1);
    assert_eq!(
        LocalCutManifestBindingTableV1::from_records(owner_id, 2, table.table_ref(), &wrong_cut),
        Err(LocalCutSealErrorV2::InvalidTableNode)
    );

    let scope = table.tree_scope();
    let short_page = LocalCutManifestBindingPageV1::new(
        scope,
        0,
        binding_rows(63),
    )?;
    let last_page = LocalCutManifestBindingPageV1::new(
        scope,
        63,
        (64..=65).map(binding_row).collect(),
    )?;
    let unpacked_branch = LocalCutManifestBindingBranchV1::new(
        scope,
        1,
        0,
        vec![
            LocalCutBranchChildV1 {
                first_ordinal: 0,
                row_count: 63,
                node_hash: short_page.digest(),
            },
            LocalCutBranchChildV1 {
                first_ordinal: 63,
                row_count: 2,
                node_hash: last_page.digest(),
            },
        ],
    )?;
    let unpacked_records = vec![
        short_page.to_canonical_cbor(),
        last_page.to_canonical_cbor(),
        unpacked_branch.to_canonical_cbor(),
    ];
    assert_eq!(
        LocalCutManifestBindingTableV1::from_records(
            owner_id,
            1,
            LocalCutTableRefV1::new(65, Some(unpacked_branch.digest()))?,
            &unpacked_records
        ),
        Err(LocalCutSealErrorV2::TableMismatch)
    );
    Ok(())
}
