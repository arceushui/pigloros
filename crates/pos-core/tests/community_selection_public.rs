//! CSI1 selection floors are bounded, strictly ordered control metadata.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityGenerationIdsV1 as Generations, CommunityLifecycleErrorV1 as Error,
    CommunitySelectionInputV1 as Input, CommunitySelectionV1 as Selection,
    CommunityTimelineFloorV1 as Floor, CommunityTimelineFloorsV1 as Floors,
    MAX_COMMUNITY_CLOSED_GENERATIONS_V1, MAX_COMMUNITY_SELECTION_TIMELINES_V1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture array expected".into()),
    }
}

const CLOSED: [[u8; 16]; 2] = [[3; 16], [4; 16]];

const fn floors() -> [Floor<'static>; 2] {
    [
        Floor {
            timeline: timeline(1),
            highest_pass_ordinal: 300,
            active_generation: Some([5; 16]),
            closed_generations: Generations::from_ids(&CLOSED),
            selected_head: Some(hash(6)),
            closed: false,
        },
        Floor {
            timeline: timeline(2),
            highest_pass_ordinal: 0,
            active_generation: None,
            closed_generations: Generations::from_ids(&[]),
            selected_head: None,
            closed: true,
        },
    ]
}

const fn input<'a>(floors: &'a [Floor<'a>]) -> Input<'a> {
    Input {
        store_incarnation: [7; 16],
        installed_catalogue_digest: hash(8),
        native_profile_digest: hash(9),
        highest_native_producer_ordinal: 70_000,
        timeline_floors: Floors::from_floors(floors),
        metadata_not_after_micros: 11,
    }
}

fn row_value(
    timeline: u8,
    ordinal: u64,
    active: Option<[u8; 16]>,
    closed: &[[u8; 16]],
    head: Option<u8>,
    is_closed: bool,
) -> Value {
    Value::Array(vec![
        bytes(&[timeline; 16]),
        uint(ordinal),
        active.map_or(Value::Null, |id| bytes(&id)),
        Value::Array(closed.iter().map(|id| bytes(id.as_slice())).collect()),
        head.map_or(Value::Null, |byte| bytes(&[byte; 32])),
        Value::Bool(is_closed),
    ])
}

fn selection_value(rows: Vec<Value>) -> Value {
    Value::Array(vec![
        bytes(b"CSI1"),
        uint(1),
        bytes(&[7; 16]),
        bytes(&[8; 32]),
        bytes(&[9; 32]),
        uint(70_000),
        Value::Array(rows),
        uint(11),
    ])
}

fn standard_value() -> Value {
    selection_value(vec![
        row_value(1, 300, Some([5; 16]), &CLOSED, Some(6), false),
        row_value(2, 0, None, &[], None, true),
    ])
}

#[test]
fn selection_has_the_exact_wire_and_roundtrips_borrowed_rows() -> TestResult {
    let floors = floors();
    let selection = Selection::new(input(&floors))?;
    let expected = encode(&standard_value())?;
    assert_eq!(&*selection.to_canonical_cbor(), &expected);
    let decoded = Selection::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == input(&floors));
    assert_eq!(&*decoded.to_canonical_cbor(), &expected);
    let rows = decoded.as_input().timeline_floors;
    assert_eq!(rows.len(), 2);
    assert!(!rows.is_empty());
    let first = rows.iter().next().ok_or("row expected")??;
    assert_eq!(first.closed_generations.len(), 2);
    assert!(!first.closed_generations.is_empty());
    assert_eq!(
        first.closed_generations.iter().collect::<Vec<_>>(),
        CLOSED.to_vec()
    );
    assert!(Generations::from_ids(&[]).is_empty());
    assert!(Floors::from_floors(&[]).is_empty());
    assert!(Generations::from_ids(&CLOSED) != Generations::from_ids(&CLOSED[..1]));
    Ok(())
}

#[test]
fn empty_selection_after_bootstrap_roundtrips() -> TestResult {
    let selection = Selection::new(input(&[]))?;
    let expected = encode(&selection_value(vec![]))?;
    assert_eq!(&*selection.to_canonical_cbor(), &expected);
    assert!(Selection::from_canonical_cbor(&expected)?
        .as_input()
        .timeline_floors
        .is_empty());
    Ok(())
}

#[test]
fn record_identities_and_horizon_are_required() -> TestResult {
    for field in 0..3 {
        let mut value = standard_value();
        match field {
            0 => fields(&mut value)?[2] = bytes(&[0; 16]),
            1 => fields(&mut value)?[3] = bytes(&[0; 32]),
            _ => fields(&mut value)?[4] = bytes(&[0; 32]),
        }
        assert_eq!(
            Selection::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut horizon = standard_value();
    fields(&mut horizon)?[7] = uint(0);
    assert_eq!(
        Selection::from_canonical_cbor(&encode(&horizon)?).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn rows_must_be_nonzero_and_strictly_ordered() -> TestResult {
    let cases = [
        vec![row_value(0, 1, None, &[], None, false)],
        vec![
            row_value(2, 1, None, &[], None, false),
            row_value(2, 1, None, &[], None, false),
        ],
        vec![
            row_value(2, 1, None, &[], None, false),
            row_value(1, 1, None, &[], None, false),
        ],
        vec![row_value(1, 1, Some([0; 16]), &[], None, false)],
        vec![row_value(1, 1, None, &[], Some(0), false)],
        vec![row_value(1, 1, None, &[[0; 16]], None, false)],
        vec![row_value(1, 1, None, &[[4; 16], [4; 16]], None, false)],
        vec![row_value(1, 1, None, &[[4; 16], [3; 16]], None, false)],
        vec![row_value(
            1,
            1,
            Some([4; 16]),
            &[[3; 16], [4; 16]],
            None,
            false,
        )],
    ];
    for rows in cases {
        assert_eq!(
            Selection::from_canonical_cbor(&encode(&selection_value(rows))?).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn row_and_generation_counts_are_bounded_at_their_exact_limits() -> TestResult {
    let ids: Vec<[u8; 16]> = (0..=MAX_COMMUNITY_CLOSED_GENERATIONS_V1)
        .map(|index| {
            let mut id = [0; 16];
            id[15] = u8::try_from(index + 1).unwrap_or_default();
            id
        })
        .collect();
    let at_limit = selection_value(vec![row_value(
        1,
        1,
        None,
        &ids[..MAX_COMMUNITY_CLOSED_GENERATIONS_V1],
        None,
        false,
    )]);
    let decoded = encode(&at_limit)?;
    let selection = Selection::from_canonical_cbor(&decoded)?;
    let row = selection
        .as_input()
        .timeline_floors
        .iter()
        .next()
        .ok_or("row expected")??;
    assert_eq!(row.closed_generations.len(), 64);
    assert!(row.closed_generations.iter().eq(ids[..64].iter().copied()));
    let over = selection_value(vec![row_value(1, 1, None, &ids, None, false)]);
    assert_eq!(
        Selection::from_canonical_cbor(&encode(&over)?).err(),
        Some(Error::BoundsExceeded)
    );
    let typed = [Floor {
        timeline: timeline(1),
        highest_pass_ordinal: 1,
        active_generation: None,
        closed_generations: Generations::from_ids(&ids),
        selected_head: None,
        closed: false,
    }];
    assert_eq!(
        Selection::new(input(&typed)).err(),
        Some(Error::BoundsExceeded)
    );

    let rows: Vec<Value> = (1..=MAX_COMMUNITY_SELECTION_TIMELINES_V1 + 1)
        .map(|index| {
            let mut timeline = [0; 16];
            timeline[14..].copy_from_slice(&u16::try_from(index).unwrap_or_default().to_be_bytes());
            let mut row = row_value(1, 1, None, &[], None, false);
            if let Value::Array(fields) = &mut row {
                fields[0] = bytes(&timeline);
            }
            row
        })
        .collect();
    let limit = encode(&selection_value(rows[..256].to_vec()))?;
    assert_eq!(
        Selection::from_canonical_cbor(&limit)?
            .as_input()
            .timeline_floors
            .len(),
        256
    );
    assert_eq!(
        Selection::from_canonical_cbor(&encode(&selection_value(rows))?).err(),
        Some(Error::BoundsExceeded)
    );
    let floors = [floors()[1]; 257];
    assert_eq!(
        Selection::new(input(&floors)).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn selection_framing_is_exact() -> TestResult {
    let mut bad_bool = standard_value();
    if let Value::Array(rows) = &mut fields(&mut bad_bool)?[6] {
        if let Value::Array(row) = &mut rows[1] {
            row[5] = Value::Null;
        }
    }
    let mut bad_generation = standard_value();
    if let Value::Array(rows) = &mut fields(&mut bad_generation)?[6] {
        if let Value::Array(row) = &mut rows[0] {
            row[3] = Value::Array(vec![bytes(&[3; 15]), bytes(&[4; 17])]);
        }
    }
    let mut bad_row = standard_value();
    if let Value::Array(rows) = &mut fields(&mut bad_row)?[6] {
        rows[0] = uint(1);
    }
    for value in [bad_bool, bad_generation, bad_row] {
        assert_eq!(
            Selection::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let mut trailing = encode(&standard_value())?;
    trailing.push(0);
    assert_eq!(
        Selection::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut version = standard_value();
    fields(&mut version)?[1] = uint(2);
    assert_eq!(
        Selection::from_canonical_cbor(&encode(&version)?).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(
        Selection::from_canonical_cbor(&vec![0; 1_048_577]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
