use std::error::Error;

use pos_core::{
    local_cut_receipt_signature_preimage_v1, Hash, LocalCutCommitErrorV1, LocalCutCommitInputV1,
    LocalCutCommitV1, LocalCutReceiptInputV1, LocalCutReceiptV1, LocalCutTableRefV1,
    MAX_LOCAL_CUT_COMMIT_BYTES_V1, MAX_LOCAL_CUT_RECEIPT_BYTES_V1,
};

type TestResult = Result<(), Box<dyn Error>>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn table(row_count: u64, byte: u8) -> Result<LocalCutTableRefV1, pos_core::LocalCutSealErrorV2> {
    LocalCutTableRefV1::new(row_count, (row_count > 0).then(|| hash(byte)))
}

fn commit_input() -> Result<LocalCutCommitInputV1, pos_core::LocalCutSealErrorV2> {
    Ok(LocalCutCommitInputV1 {
        owner_id: [1; 32],
        cut_id: 2,
        partition_ledger_seq: 3,
        seal_hash: hash(4),
        manifest_hash: hash(5),
        result_heads_table: table(1, 6)?,
        participant_successor_table: table(2, 7)?,
        cpu_completion_table: table(0, 8)?,
        action_disposition_table: table(3, 9)?,
        candidate_bases_table: table(0, 10)?,
        invocation_bridges_table: table(4, 11)?,
        result_inventory_generation: hash(12),
        release_fence_proof_digest: hash(13),
    })
}

fn commit() -> Result<LocalCutCommitV1, Box<dyn Error>> {
    Ok(LocalCutCommitV1::new(commit_input()?)?)
}

fn receipt(commit: &LocalCutCommitV1) -> Result<LocalCutReceiptV1, LocalCutCommitErrorV1> {
    LocalCutReceiptV1::new(LocalCutReceiptInputV1 {
        commit_record_hash: commit.digest(),
        coordinator_key_evidence_hash: hash(14),
        signature: [15; 64],
    })
}

fn first_table_offset(bytes: &[u8]) -> Result<usize, Box<dyn Error>> {
    let prefix = [0x82, 0x01, 0x58, 0x20];
    bytes
        .windows(prefix.len())
        .position(|window| window == prefix)
        .ok_or_else(|| std::io::Error::other("first LCC1 table was not encoded"))
        .map_err(Into::into)
}

#[test]
fn lcc1_and_lcq1_roundtrip_with_stable_structural_digests() -> TestResult {
    let commit = commit()?;
    let commit_bytes = commit.to_canonical_cbor();
    assert_eq!(commit_bytes[..6], [0x8f, 0x44, b'L', b'C', b'C', b'1']);
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&commit_bytes)?,
        commit
    );
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&commit_bytes)?.digest(),
        commit.digest()
    );

    let receipt = receipt(&commit)?;
    let receipt_bytes = receipt.to_canonical_cbor();
    assert_eq!(receipt_bytes[..6], [0x85, 0x44, b'L', b'C', b'Q', b'1']);
    assert_eq!(
        LocalCutReceiptV1::from_canonical_cbor(&receipt_bytes)?,
        receipt
    );
    assert_eq!(
        LocalCutReceiptV1::from_canonical_cbor(&receipt_bytes)?.digest(),
        receipt.digest()
    );
    assert_ne!(commit.digest(), receipt.digest());
    Ok(())
}

#[test]
fn lcq1_signature_preimage_is_exact_and_rejects_absent_addresses() -> TestResult {
    let commit = commit()?;
    let receipt = receipt(&commit)?;
    let mut expected = b"pigloros.local-cut.receipt-signature.v1\0".to_vec();
    expected.extend_from_slice(&[0x82, 0x58, 0x20]);
    expected.extend_from_slice(commit.digest().as_bytes());
    expected.extend_from_slice(&[0x58, 0x20]);
    expected.extend_from_slice(hash(14).as_bytes());

    assert_eq!(receipt.signature_preimage(), expected);
    assert_eq!(
        local_cut_receipt_signature_preimage_v1(commit.digest(), hash(14))?,
        expected
    );
    assert_eq!(
        local_cut_receipt_signature_preimage_v1(Hash::zero(), hash(14)),
        Err(LocalCutCommitErrorV1::InvalidIdentity)
    );
    assert_eq!(
        local_cut_receipt_signature_preimage_v1(commit.digest(), Hash::zero()),
        Err(LocalCutCommitErrorV1::InvalidIdentity)
    );
    Ok(())
}

#[test]
fn constructors_reject_missing_owner_coordinates_and_receipt_addresses() -> TestResult {
    let mut input = commit_input()?;
    input.owner_id = [0; 32];
    assert_eq!(
        LocalCutCommitV1::new(input),
        Err(LocalCutCommitErrorV1::InvalidIdentity)
    );

    let mut input = commit_input()?;
    input.cut_id = 0;
    assert_eq!(
        LocalCutCommitV1::new(input),
        Err(LocalCutCommitErrorV1::InvalidIdentity)
    );

    let mut input = commit_input()?;
    input.partition_ledger_seq = 0;
    assert_eq!(
        LocalCutCommitV1::new(input),
        Err(LocalCutCommitErrorV1::InvalidIdentity)
    );

    let mut input = commit_input()?;
    input.release_fence_proof_digest = Hash::zero();
    assert_eq!(
        LocalCutCommitV1::new(input),
        Err(LocalCutCommitErrorV1::InvalidIdentity)
    );

    assert_eq!(
        LocalCutReceiptV1::new(LocalCutReceiptInputV1 {
            commit_record_hash: Hash::zero(),
            coordinator_key_evidence_hash: hash(14),
            signature: [15; 64],
        }),
        Err(LocalCutCommitErrorV1::InvalidIdentity)
    );
    Ok(())
}

#[test]
fn lcc1_decoder_rejects_invalid_noncanonical_and_invalid_table_forms() -> TestResult {
    let commit = commit()?;
    let canonical = commit.to_canonical_cbor();

    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&[]),
        Err(LocalCutCommitErrorV1::InvalidEncoding)
    );
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&vec![0; MAX_LOCAL_CUT_COMMIT_BYTES_V1 + 1]),
        Err(LocalCutCommitErrorV1::FieldOutOfBounds)
    );

    let mut wrong_magic = canonical.clone();
    wrong_magic[5] = b'X';
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&wrong_magic),
        Err(LocalCutCommitErrorV1::InvalidEncoding)
    );

    let mut wrong_version = canonical.clone();
    wrong_version[6] = 2;
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&wrong_version),
        Err(LocalCutCommitErrorV1::UnsupportedVersion)
    );

    let mut noncanonical = canonical.clone();
    noncanonical.splice(6..7, [0x18, 1]);
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&noncanonical),
        Err(LocalCutCommitErrorV1::NonCanonical)
    );

    let mut missing_coordinate = canonical.clone();
    missing_coordinate[41] = 0;
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&missing_coordinate),
        Err(LocalCutCommitErrorV1::FieldOutOfBounds)
    );

    let table_offset = first_table_offset(&canonical)?;
    let mut null_root_with_rows = canonical.clone();
    null_root_with_rows[table_offset + 1] = 0;
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&null_root_with_rows),
        Err(LocalCutCommitErrorV1::InvalidTableReference)
    );

    let mut zero_root = canonical;
    zero_root[table_offset + 4..table_offset + 36].fill(0);
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&zero_root),
        Err(LocalCutCommitErrorV1::InvalidTableReference)
    );
    Ok(())
}

#[test]
fn lcq1_decoder_rejects_invalid_noncanonical_and_oversized_forms() -> TestResult {
    let receipt = receipt(&commit()?)?;
    let canonical = receipt.to_canonical_cbor();

    assert_eq!(
        LocalCutReceiptV1::from_canonical_cbor(&[]),
        Err(LocalCutCommitErrorV1::InvalidEncoding)
    );
    assert_eq!(
        LocalCutReceiptV1::from_canonical_cbor(&vec![0; MAX_LOCAL_CUT_RECEIPT_BYTES_V1 + 1]),
        Err(LocalCutCommitErrorV1::FieldOutOfBounds)
    );

    let mut wrong_version = canonical.clone();
    wrong_version[6] = 2;
    assert_eq!(
        LocalCutReceiptV1::from_canonical_cbor(&wrong_version),
        Err(LocalCutCommitErrorV1::UnsupportedVersion)
    );

    let mut noncanonical = canonical.clone();
    noncanonical.splice(6..7, [0x18, 1]);
    assert_eq!(
        LocalCutReceiptV1::from_canonical_cbor(&noncanonical),
        Err(LocalCutCommitErrorV1::NonCanonical)
    );

    let mut trailing = canonical;
    trailing.push(0);
    assert_eq!(
        LocalCutReceiptV1::from_canonical_cbor(&trailing),
        Err(LocalCutCommitErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn lcc1_and_lcq1_decoders_reject_every_truncated_prefix() -> TestResult {
    let commit = commit()?;
    let commit_bytes = commit.to_canonical_cbor();
    for end in 0..commit_bytes.len() {
        assert_eq!(
            LocalCutCommitV1::from_canonical_cbor(&commit_bytes[..end]),
            Err(LocalCutCommitErrorV1::InvalidEncoding),
            "LCC1 prefix of {end} bytes"
        );
    }

    let receipt_bytes = receipt(&commit)?.to_canonical_cbor();
    for end in 0..receipt_bytes.len() {
        assert_eq!(
            LocalCutReceiptV1::from_canonical_cbor(&receipt_bytes[..end]),
            Err(LocalCutCommitErrorV1::InvalidEncoding),
            "LCQ1 prefix of {end} bytes"
        );
    }
    Ok(())
}

#[test]
fn lcc1_decoder_rejects_wrong_major_types_and_fixed_lengths() -> TestResult {
    let canonical = commit()?.to_canonical_cbor();
    let table_offset = first_table_offset(&canonical)?;
    let invalid_edits = [
        (1, 0x04),
        (1, 0x43),
        (6, 0x41),
        (7, 0x18),
        (8, 0x1f),
        (41, 0x41),
        (table_offset, 0x02),
        (table_offset + 1, 0x41),
    ];
    for (index, byte) in invalid_edits {
        let mut edited = canonical.clone();
        edited[index] = byte;
        assert_eq!(
            LocalCutCommitV1::from_canonical_cbor(&edited),
            Err(LocalCutCommitErrorV1::InvalidEncoding),
            "LCC1 byte {index} set to {byte:#04x}"
        );
    }

    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&trailing),
        Err(LocalCutCommitErrorV1::InvalidEncoding)
    );

    let mut oversized_rows = canonical;
    oversized_rows.splice(
        table_offset + 1..table_offset + 2,
        [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
    assert_eq!(
        LocalCutCommitV1::from_canonical_cbor(&oversized_rows),
        Err(LocalCutCommitErrorV1::FieldOutOfBounds)
    );
    Ok(())
}
