use ciborium::value::Value;
use pos_core::{
    local_cut_tree_scope_v1, Hash, LocalCutExpectedHeadRowV1, LocalCutHeadsTableV1,
    LocalCutResultHeadRowV1, LocalCutSealErrorV2, LocalCutTableRefV1, TimelineId,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const OWNER: [u8; 32] = [9; 32];
const CUT: u64 = 7;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn timeline(index: u128) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from(index))
}

fn expected_row(index: u128) -> LocalCutExpectedHeadRowV1 {
    LocalCutExpectedHeadRowV1 {
        timeline_id: timeline(index),
        logical_head: 3,
        stitched_chain_hash: hash(1),
        source_timeline_id: timeline(index + 1_000_000),
        source_segment_head: 300,
        source_chain_hash: hash(2),
        logical_prefix: 70_000,
        lineage_proof_hash: None,
        predecessor_wcb_hash: Some(hash(3)),
    }
}

fn result_row(index: u128) -> LocalCutResultHeadRowV1 {
    LocalCutResultHeadRowV1 {
        timeline_id: timeline(index),
        result_logical_head: 4,
        result_stitched_hash: hash(4),
        result_source_segment_head: 301,
        result_source_chain_hash: hash(5),
        successor_wcb_hash: hash(6),
        event_count: u64::MAX,
    }
}

fn expected_rows(count: u128) -> Vec<LocalCutExpectedHeadRowV1> {
    (1..=count).map(expected_row).collect()
}

fn result_rows(count: u128) -> Vec<LocalCutResultHeadRowV1> {
    (1..=count).map(result_row).collect()
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn optional(value: Option<Hash>) -> Value {
    value.map_or(Value::Null, |hash| bytes(hash.as_bytes()))
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

fn expected_value(row: &LocalCutExpectedHeadRowV1) -> Value {
    Value::Array(vec![
        bytes(&row.timeline_id.inner().to_bytes()),
        uint(row.logical_head),
        bytes(row.stitched_chain_hash.as_bytes()),
        bytes(&row.source_timeline_id.inner().to_bytes()),
        uint(row.source_segment_head),
        bytes(row.source_chain_hash.as_bytes()),
        uint(row.logical_prefix),
        optional(row.lineage_proof_hash),
        optional(row.predecessor_wcb_hash),
    ])
}

fn result_value(row: &LocalCutResultHeadRowV1) -> Value {
    Value::Array(vec![
        bytes(&row.timeline_id.inner().to_bytes()),
        uint(row.result_logical_head),
        bytes(row.result_stitched_hash.as_bytes()),
        uint(row.result_source_segment_head),
        bytes(row.result_source_chain_hash.as_bytes()),
        bytes(row.successor_wcb_hash.as_bytes()),
        uint(row.event_count),
    ])
}

fn page_bytes(kind: u64, first_ordinal: u64, rows: Vec<Value>) -> Fallible<Vec<u8>> {
    encode(&Value::Array(vec![
        bytes(b"LCP1"),
        uint(1),
        uint(kind),
        bytes(local_cut_tree_scope_v1(OWNER, CUT).as_bytes()),
        uint(first_ordinal),
        Value::Array(rows),
    ]))
}

fn branch_bytes(kind: u64, height: u64, children: &[(u64, u64, Hash)]) -> Fallible<Vec<u8>> {
    let first_ordinal = children.first().ok_or("branch without children")?.0;
    let row_count = children.iter().map(|child| child.1).sum();
    encode(&Value::Array(vec![
        bytes(b"LCT1"),
        uint(1),
        uint(kind),
        bytes(local_cut_tree_scope_v1(OWNER, CUT).as_bytes()),
        uint(height),
        uint(first_ordinal),
        uint(row_count),
        Value::Array(
            children
                .iter()
                .map(|&(first, count, node)| {
                    Value::Array(vec![uint(first), uint(count), bytes(node.as_bytes())])
                })
                .collect(),
        ),
    ]))
}

fn digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn page_digest(bytes: &[u8]) -> Hash {
    digest(b"pigloros.local-cut.page.v1\0", bytes)
}

fn branch_digest(bytes: &[u8]) -> Hash {
    digest(b"pigloros.local-cut.branch.v1\0", bytes)
}

fn decoded_fields(bytes: &[u8]) -> Fallible<Vec<Value>> {
    let value: Value = ciborium::from_reader(bytes)?;
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err("expected a CBOR array".into()),
    }
}

fn decoded_uint(value: &Value) -> Fallible<u64> {
    match value {
        Value::Integer(integer) => Ok(u64::try_from(*integer)?),
        _ => Err("expected an unsigned integer".into()),
    }
}

#[test]
fn rows_encode_every_field_in_adr082_order() -> TestResult {
    let mut expected = expected_row(1);
    assert_eq!(
        expected.to_canonical_cbor(),
        encode(&expected_value(&expected))?
    );
    expected.lineage_proof_hash = Some(hash(7));
    expected.predecessor_wcb_hash = None;
    expected.logical_head = u64::MAX;
    assert_eq!(
        expected.to_canonical_cbor(),
        encode(&expected_value(&expected))?
    );

    let mut result = result_row(1);
    assert_eq!(result.to_canonical_cbor(), encode(&result_value(&result))?);
    result.event_count = 0;
    result.result_source_segment_head = 65_536;
    assert_eq!(result.to_canonical_cbor(), encode(&result_value(&result))?);
    Ok(())
}

#[test]
fn empty_tables_have_no_root_and_no_records() -> TestResult {
    let expected = LocalCutHeadsTableV1::expected_heads(OWNER, CUT, &[])?;
    assert_eq!(expected.table_ref(), LocalCutTableRefV1::new(0, None)?);
    assert!(expected.records().is_empty());
    let result = LocalCutHeadsTableV1::result_heads(OWNER, CUT, &[])?;
    assert_eq!(result.table_ref(), LocalCutTableRefV1::new(0, None)?);
    assert!(result.records().is_empty());
    Ok(())
}

#[test]
fn one_page_tables_match_independent_lcp1_encodings() -> TestResult {
    let rows = expected_rows(2);
    let table = LocalCutHeadsTableV1::expected_heads(OWNER, CUT, &rows)?;
    let page = page_bytes(4, 0, rows.iter().map(expected_value).collect())?;
    assert_eq!(table.records(), std::slice::from_ref(&page));
    assert_eq!(
        table.table_ref(),
        LocalCutTableRefV1::new(2, Some(page_digest(&page)))?
    );

    let rows = result_rows(64);
    let table = LocalCutHeadsTableV1::result_heads(OWNER, CUT, &rows)?;
    let page = page_bytes(5, 0, rows.iter().map(result_value).collect())?;
    assert_eq!(table.records(), std::slice::from_ref(&page));
    assert_eq!(
        table.table_ref(),
        LocalCutTableRefV1::new(64, Some(page_digest(&page)))?
    );
    Ok(())
}

#[test]
fn two_page_tables_match_independent_lct1_encodings() -> TestResult {
    let rows = expected_rows(65);
    let table = LocalCutHeadsTableV1::expected_heads(OWNER, CUT, &rows)?;
    let first = page_bytes(4, 0, rows[..64].iter().map(expected_value).collect())?;
    let second = page_bytes(4, 64, rows[64..].iter().map(expected_value).collect())?;
    let branch = branch_bytes(
        4,
        1,
        &[(0, 64, page_digest(&first)), (64, 1, page_digest(&second))],
    )?;
    assert_eq!(table.records(), [first, second, branch.clone()]);
    assert_eq!(
        table.table_ref(),
        LocalCutTableRefV1::new(65, Some(branch_digest(&branch)))?
    );

    let rows = result_rows(130);
    let table = LocalCutHeadsTableV1::result_heads(OWNER, CUT, &rows)?;
    let pages = [
        page_bytes(5, 0, rows[..64].iter().map(result_value).collect())?,
        page_bytes(5, 64, rows[64..128].iter().map(result_value).collect())?,
        page_bytes(5, 128, rows[128..].iter().map(result_value).collect())?,
    ];
    let branch = branch_bytes(
        5,
        1,
        &[
            (0, 64, page_digest(&pages[0])),
            (64, 64, page_digest(&pages[1])),
            (128, 2, page_digest(&pages[2])),
        ],
    )?;
    assert_eq!(&table.records()[..3], pages.as_slice());
    assert_eq!(table.records()[3], branch);
    assert_eq!(
        table.table_ref(),
        LocalCutTableRefV1::new(130, Some(branch_digest(&branch)))?
    );
    Ok(())
}

#[test]
fn large_tables_rise_to_a_height_two_root() -> TestResult {
    let rows = expected_rows(15_361);
    let table = LocalCutHeadsTableV1::expected_heads(OWNER, CUT, &rows)?;
    let records = table.records();
    assert_eq!(records.len(), 241 + 2 + 1);
    let first_branch = &records[241];
    let last_branch = &records[242];
    let root = &records[243];
    let first_fields = decoded_fields(first_branch)?;
    assert_eq!(decoded_uint(&first_fields[4])?, 1);
    assert_eq!(decoded_uint(&first_fields[5])?, 0);
    assert_eq!(decoded_uint(&first_fields[6])?, 15_360);
    let Value::Array(first_children) = &first_fields[7] else {
        return Err("missing first branch children".into());
    };
    assert_eq!(first_children.len(), 240);
    let last_fields = decoded_fields(last_branch)?;
    assert_eq!(decoded_uint(&last_fields[5])?, 15_360);
    assert_eq!(decoded_uint(&last_fields[6])?, 1);
    let expected_root = branch_bytes(
        4,
        2,
        &[
            (0, 15_360, branch_digest(first_branch)),
            (15_360, 1, branch_digest(last_branch)),
        ],
    )?;
    assert_eq!(root, &expected_root);
    assert_eq!(
        table.table_ref(),
        LocalCutTableRefV1::new(15_361, Some(branch_digest(root)))?
    );
    Ok(())
}

#[test]
fn tables_reject_duplicate_or_descending_timelines() {
    let duplicate = vec![expected_row(1), expected_row(1)];
    let descending = vec![expected_row(2), expected_row(1)];
    for rows in [duplicate, descending] {
        assert_eq!(
            LocalCutHeadsTableV1::expected_heads(OWNER, CUT, &rows),
            Err(LocalCutSealErrorV2::RowsNotSorted)
        );
    }
    let duplicate = vec![result_row(1), result_row(1)];
    let descending = vec![result_row(2), result_row(1)];
    for rows in [duplicate, descending] {
        assert_eq!(
            LocalCutHeadsTableV1::result_heads(OWNER, CUT, &rows),
            Err(LocalCutSealErrorV2::RowsNotSorted)
        );
    }
}

#[test]
fn rows_round_trip_through_their_canonical_encodings() {
    let mut unchained = expected_row(1);
    unchained.lineage_proof_hash = Some(hash(7));
    unchained.predecessor_wcb_hash = None;
    for row in [expected_row(1), unchained] {
        let bytes = row.to_canonical_cbor();
        assert_eq!(LocalCutExpectedHeadRowV1::from_canonical_cbor(&bytes), Ok(row));
    }
    let row = result_row(1);
    let bytes = row.to_canonical_cbor();
    assert_eq!(LocalCutResultHeadRowV1::from_canonical_cbor(&bytes), Ok(row));
}

#[test]
fn row_decoders_reject_truncated_extended_or_misshapen_rows() {
    let expected = expected_row(1).to_canonical_cbor();
    let result = result_row(1).to_canonical_cbor();
    for length in 0..expected.len() {
        assert_eq!(
            LocalCutExpectedHeadRowV1::from_canonical_cbor(&expected[..length]),
            Err(LocalCutSealErrorV2::InvalidEncoding),
            "{length}"
        );
    }
    for length in 0..result.len() {
        assert_eq!(
            LocalCutResultHeadRowV1::from_canonical_cbor(&result[..length]),
            Err(LocalCutSealErrorV2::InvalidEncoding),
            "{length}"
        );
    }
    let extended = [expected.as_slice(), [0].as_slice()].concat();
    assert_eq!(
        LocalCutExpectedHeadRowV1::from_canonical_cbor(&extended),
        Err(LocalCutSealErrorV2::InvalidEncoding)
    );
    let extended = [result.as_slice(), [0].as_slice()].concat();
    assert_eq!(
        LocalCutResultHeadRowV1::from_canonical_cbor(&extended),
        Err(LocalCutSealErrorV2::InvalidEncoding)
    );
    assert_eq!(
        LocalCutExpectedHeadRowV1::from_canonical_cbor(&result),
        Err(LocalCutSealErrorV2::InvalidEncoding)
    );
    assert_eq!(
        LocalCutResultHeadRowV1::from_canonical_cbor(&expected),
        Err(LocalCutSealErrorV2::InvalidEncoding)
    );
}

#[test]
fn row_decoders_reject_nonpreferred_integer_heads() {
    // The array head and the 17-byte Timeline precede each logical head.
    let expected = expected_row(1).to_canonical_cbor();
    let widened = [&expected[..18], [0x18, 0x03].as_slice(), &expected[19..]].concat();
    assert_eq!(
        LocalCutExpectedHeadRowV1::from_canonical_cbor(&widened),
        Err(LocalCutSealErrorV2::NonCanonical)
    );
    let result = result_row(1).to_canonical_cbor();
    let widened = [&result[..18], [0x18, 0x04].as_slice(), &result[19..]].concat();
    assert_eq!(
        LocalCutResultHeadRowV1::from_canonical_cbor(&widened),
        Err(LocalCutSealErrorV2::NonCanonical)
    );
}
