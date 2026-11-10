//! Public-interface tests of the RVA1 run-evidence archive writer (ADR-127,
//! Redmine #1284). The independent pos-reference reader imports every
//! archive the writer produces.

use std::io::{self, Read};

use ciborium::value::Value;
use pos_conformance::run_evidence_archive::{
    run_evidence_event_member_name_v1, run_evidence_event_records_v1, run_evidence_members_v1,
    RunEvidenceArchiveBuilderV1, RunEvidenceArchiveV1, RunEvidenceArchiveWriteErrorV1,
    RunEvidenceMemberV1, RUN_EVIDENCE_ARCHIVE_MARKER_V1, RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1,
    RUN_EVIDENCE_ARCHIVE_TIMELINE_V1, RUN_EVIDENCE_ARCHIVE_VERSION_V1,
};
use pos_core::clock::{Seq, WallTime};
use pos_core::event::{CanonicalBytes, Kind, SchemaVersion};
use pos_core::store::TimelineExport;
use pos_core::timeline::{Timeline, TimelineMeta, TimelineMode};
use pos_core::{CorrelationId, EntityId, Event, EventId, Hash, TimelineId};
use pos_reference::run_evidence_archive::import_run_evidence_archive_v1;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Error = RunEvidenceArchiveWriteErrorV1;

const MAX: usize = RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1;
const MARKER: [u8; 7] = [0x82, 0x64, b'R', b'V', b'A', b'1', 0x01];

fn event(seq: u64, entity: EntityId) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new("t"),
        payload: CanonicalBytes::from_vec(vec![u8::try_from(seq).unwrap_or_default()]),
        wall_time: WallTime::from_micros(seq),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([u8::try_from(seq).unwrap_or_default(); 32]),
    }
}

const fn export(meta: TimelineMeta, events: Vec<Event>) -> TimelineExport {
    let mut timeline = Timeline::new(meta);
    timeline.head = Seq::from_u64(events.len() as u64);
    TimelineExport {
        timeline,
        events,
        parent_fork_hash: None,
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .unwrap_or_default()
}

fn record(seq: u64, entity: u64, cause: Option<u64>, correlation: Option<u64>) -> Value {
    Value::Array(vec![
        uint(seq),
        uint(entity),
        Value::Text("t".to_owned()),
        uint(1),
        cause.map_or(Value::Null, uint),
        correlation.map_or(Value::Null, uint),
        Value::Bytes(vec![u8::try_from(seq).unwrap_or_default()]),
        Value::Bytes(vec![u8::try_from(seq).unwrap_or_default(); 32]),
    ])
}

fn timeline_record(mode: u64, name: Option<&str>, owner: Option<u64>, head: u64) -> Value {
    Value::Array(vec![
        uint(mode),
        name.map_or(Value::Null, |name| Value::Text(name.to_owned())),
        owner.map_or(Value::Null, uint),
        uint(head),
    ])
}

/// An independent canonical ustar encoder of `(name, data)` in the given
/// order (ADR-127 section 1).
fn ustar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, data) in entries {
        let mut header = vec![0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..124].copy_from_slice(b"0000644\x000000000\x000000000\x00");
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..265].copy_from_slice(b"ustar\x0000");
        let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        bytes.extend(header);
        bytes.extend_from_slice(data);
        while !bytes.len().is_multiple_of(512) {
            bytes.push(0);
        }
    }
    bytes.extend([0; 1024]);
    bytes
}

fn build(members: &[(&str, Vec<u8>)]) -> Result<RunEvidenceArchiveV1, Error> {
    let mut builder = RunEvidenceArchiveBuilderV1::new();
    for (name, data) in members {
        builder.insert(name, data.as_slice())?;
    }
    builder.finish()
}

fn members_of(export: &TimelineExport) -> TestResult<Vec<(String, Vec<u8>)>> {
    Ok(run_evidence_members_v1(export)?
        .into_iter()
        .map(|member| (member.name, member.data))
        .collect())
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

#[test]
fn the_projection_is_position_relative_and_byte_exact() -> TestResult {
    let owner = EntityId::new();
    let other = EntityId::new();
    let correlation = CorrelationId::new();
    let mut events = vec![
        event(1, other),
        event(2, owner),
        event(3, other),
        event(4, other),
    ];
    events[1].causation_id = Some(events[0].id);
    events[1].correlation_id = Some(correlation);
    events[2].correlation_id = Some(CorrelationId::new());
    events[3].correlation_id = Some(correlation);
    events[3].causation_id = Some(events[2].id);
    let mut meta = TimelineMeta::root_owned("root", owner);
    meta.mode = TimelineMode::Future;
    let members = run_evidence_members_v1(&export(meta, events))?;
    assert_eq!(
        members,
        vec![
            RunEvidenceMemberV1 {
                name: RUN_EVIDENCE_ARCHIVE_MARKER_V1.to_owned(),
                data: MARKER.to_vec(),
            },
            RunEvidenceMemberV1 {
                name: "events/00000000000000000001.cbor".to_owned(),
                data: cbor(&record(1, 1, None, None)),
            },
            RunEvidenceMemberV1 {
                name: "events/00000000000000000002.cbor".to_owned(),
                data: cbor(&record(2, 0, Some(1), Some(0))),
            },
            RunEvidenceMemberV1 {
                name: "events/00000000000000000003.cbor".to_owned(),
                data: cbor(&record(3, 1, None, Some(1))),
            },
            RunEvidenceMemberV1 {
                name: "events/00000000000000000004.cbor".to_owned(),
                data: cbor(&record(4, 1, Some(3), Some(0))),
            },
            RunEvidenceMemberV1 {
                name: RUN_EVIDENCE_ARCHIVE_TIMELINE_V1.to_owned(),
                data: cbor(&timeline_record(2, Some("root"), Some(0), 4)),
            },
        ]
    );
    assert_eq!(RUN_EVIDENCE_ARCHIVE_VERSION_V1, 1);
    assert_eq!(
        run_evidence_event_member_name_v1(u64::MAX),
        "events/18446744073709551615.cbor"
    );
    // Without an owner the first entity is ordinal 0.
    assert_eq!(
        run_evidence_event_records_v1(&[event(1, other)], None)?,
        vec![cbor(&record(1, 0, None, None))]
    );
    Ok(())
}

#[test]
fn every_integer_head_width_is_the_shortest() -> TestResult {
    let entity = EntityId::new();
    for seq in [
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX,
    ] {
        assert_eq!(
            run_evidence_event_records_v1(&[event(seq, entity)], None)?,
            vec![cbor(&record(seq, 0, None, None))],
            "{seq}"
        );
    }
    Ok(())
}

#[test]
fn the_timeline_record_carries_mode_name_owner_and_head() -> TestResult {
    for (mode, code) in [
        (TimelineMode::Historical, 0),
        (TimelineMode::Live, 1),
        (TimelineMode::Future, 2),
    ] {
        let mut meta = TimelineMeta::root("named");
        meta.mode = mode;
        meta.name = None;
        let members = run_evidence_members_v1(&export(meta, Vec::new()))?;
        assert_eq!(members.len(), 2);
        assert_eq!(members[1].data, cbor(&timeline_record(code, None, None, 0)));
        // Every mode imports.
        let archive = build(
            &members_of(&export(
                TimelineMeta {
                    mode,
                    ..TimelineMeta::root("named")
                },
                vec![event(1, EntityId::new())],
            ))?
            .iter()
            .map(|(name, data)| (name.as_str(), data.clone()))
            .collect::<Vec<_>>(),
        )?;
        import_run_evidence_archive_v1(&archive.bytes, &archive.digest)?;
    }
    Ok(())
}

#[test]
fn the_projection_refuses_forks_gaps_duplicates_and_dangling_causes() {
    let entity = EntityId::new();
    let mut forked = TimelineMeta::root("child");
    forked.fork_point = Some((TimelineId::new(), Seq::from_u64(1)));
    assert_eq!(
        run_evidence_members_v1(&export(forked, vec![event(1, entity)])),
        Err(Error::UnsupportedTimeline)
    );
    let mut ahead = export(TimelineMeta::root("r"), vec![event(1, entity)]);
    ahead.timeline.head = Seq::from_u64(2);
    assert_eq!(
        run_evidence_members_v1(&ahead),
        Err(Error::ClosureIncomplete)
    );
    assert_eq!(
        run_evidence_members_v1(&export(
            TimelineMeta::root("r"),
            vec![event(1, entity), event(3, entity)]
        )),
        Err(Error::ClosureIncomplete)
    );
    let mut duplicate = vec![event(1, entity), event(2, entity)];
    duplicate[1].id = duplicate[0].id;
    assert_eq!(
        run_evidence_members_v1(&export(TimelineMeta::root("r"), duplicate)),
        Err(Error::RecordInvalid)
    );
    for cause in [0, 1, 2] {
        let mut events = vec![event(1, entity), event(2, entity)];
        // 0: outside the stream; 1: itself; 2: a later Event.
        events[1].causation_id = match cause {
            0 => Some(EventId::new()),
            1 => Some(events[1].id),
            _ => None,
        };
        events[0].causation_id = (cause == 2).then_some(events[1].id);
        assert_eq!(
            run_evidence_event_records_v1(&events, None),
            Err(Error::RecordInvalid),
            "{cause}"
        );
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// The members of a small valid export with an owner.
fn sample() -> TestResult<Vec<(String, Vec<u8>)>> {
    let owner = EntityId::new();
    let mut events = vec![event(1, owner), event(2, EntityId::new())];
    events[1].causation_id = Some(events[0].id);
    events[1].correlation_id = Some(CorrelationId::new());
    members_of(&export(TimelineMeta::root_owned("s", owner), events))
}

/// A reader that returns one byte per read.
struct OneByte<'a>(&'a [u8]);

impl Read for OneByte<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match (self.0.split_first(), buffer.first_mut()) {
            (Some((first, rest)), Some(slot)) => {
                *slot = *first;
                self.0 = rest;
                Ok(1)
            }
            _ => Ok(0),
        }
    }
}

struct Failing;

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("unavailable"))
    }
}

#[test]
fn the_archive_is_canonical_and_independent_of_insertion_order_and_chunking() -> TestResult {
    let members = sample()?;
    let expected = ustar(
        &members
            .iter()
            .map(|(name, data)| (name.as_str(), data.as_slice()))
            .collect::<Vec<_>>(),
    );
    let mut reversed = RunEvidenceArchiveBuilderV1::new();
    for (name, data) in members.iter().rev() {
        reversed.insert(name, OneByte(data.as_slice()))?;
    }
    let reversed = reversed.finish()?;
    let sorted = build(
        &members
            .iter()
            .map(|(name, data)| (name.as_str(), data.clone()))
            .collect::<Vec<_>>(),
    )?;
    assert_eq!(sorted.bytes, expected);
    assert_eq!(reversed, sorted);
    assert_eq!(sorted.digest, *blake3::hash(&expected).as_bytes());
    let imported = import_run_evidence_archive_v1(&sorted.bytes, &sorted.digest)?;
    assert_eq!(
        imported
            .members
            .iter()
            .map(|member| (member.name.clone(), member.data.clone()))
            .collect::<Vec<_>>(),
        members
    );
    // The smallest archive: no Event.
    let empty = build(&[
        ("timeline.cbor", cbor(&timeline_record(1, None, None, 0))),
        ("RVA1", MARKER.to_vec()),
    ])?;
    assert_eq!(empty.bytes.len(), 3072);
    import_run_evidence_archive_v1(&empty.bytes, &empty.digest)?;
    Ok(())
}

/// A deterministic generator of small exports: owners, repeated and new
/// entities and correlations, and causes.
fn generated(seed: u64) -> TimelineExport {
    let mut state = seed;
    let mut next = move |bound: u64| {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) % bound
    };
    let entities = [EntityId::new(), EntityId::new(), EntityId::new()];
    let correlations = [CorrelationId::new(), CorrelationId::new()];
    let length = next(6);
    let mut events: Vec<Event> = Vec::new();
    for seq in 1..=length {
        let mut current = event(seq, entities[usize::try_from(next(3)).unwrap_or_default()]);
        current.correlation_id = match next(3) {
            0 => None,
            index => Some(correlations[usize::try_from(index - 1).unwrap_or_default()]),
        };
        current.causation_id = (seq > 1 && next(2) == 0)
            .then(|| events[usize::try_from(next(seq - 1)).unwrap_or_default()].id);
        events.push(current);
    }
    let meta = if next(2) == 0 {
        TimelineMeta::root("g")
    } else {
        TimelineMeta::root_owned("g", entities[0])
    };
    export(meta, events)
}

#[test]
fn every_generated_export_writes_an_archive_that_imports_in_any_order() -> TestResult {
    for seed in 0..24 {
        let members = members_of(&generated(seed))?;
        let one_shot = build(
            &members
                .iter()
                .map(|(name, data)| (name.as_str(), data.clone()))
                .collect::<Vec<_>>(),
        )?;
        let mut reversed = RunEvidenceArchiveBuilderV1::new();
        for (name, data) in members.iter().rev() {
            reversed.insert(name, OneByte(data.as_slice()))?;
        }
        assert_eq!(reversed.finish()?, one_shot, "{seed}");
        let imported = import_run_evidence_archive_v1(&one_shot.bytes, &one_shot.digest)?;
        assert_eq!(imported.members.len(), members.len(), "{seed}");
    }
    // A correlation table that grows: 0, 1, then 0 again.
    let correlations = [CorrelationId::new(), CorrelationId::new()];
    let entity = EntityId::new();
    let mut events = vec![event(1, entity), event(2, entity), event(3, entity)];
    for (current, correlation) in events.iter_mut().zip([0, 1, 0]) {
        current.correlation_id = Some(correlations[correlation]);
    }
    let members = members_of(&export(TimelineMeta::root("c"), events))?;
    let archive = build(
        &members
            .iter()
            .map(|(name, data)| (name.as_str(), data.clone()))
            .collect::<Vec<_>>(),
    )?;
    import_run_evidence_archive_v1(&archive.bytes, &archive.digest)?;
    Ok(())
}

#[test]
fn the_builder_refuses_names_duplicates_and_incomplete_closures() -> TestResult {
    let members = sample()?;
    let with = |extra: &[(&str, Vec<u8>)], skip: &str| {
        let mut set = members
            .iter()
            .filter(|(name, _)| name != skip)
            .map(|(name, data)| (name.as_str(), data.clone()))
            .collect::<Vec<_>>();
        set.extend(extra.iter().cloned());
        build(&set)
    };
    // A name outside the grammar.
    for name in [
        "RVA2",
        "events/1.cbor",
        "events/0000000000000000000a.cbor",
        "events/00000000000000000001.json",
        "../timeline.cbor",
    ] {
        assert_eq!(
            with(&[(name, vec![0])], ""),
            Err(Error::ClosureIncomplete),
            "{name}"
        );
    }
    // A repeated name outside the grammar fails the grammar first.
    for name in ["events/1.cbor", "events/0000000000000000000a.cbor"] {
        assert_eq!(
            with(&[(name, vec![0]), (name, vec![0])], ""),
            Err(Error::ClosureIncomplete),
            "{name}"
        );
    }
    // The grammar is checked before duplicates, in sorted order.
    assert_eq!(
        with(&[("RVA1", MARKER.to_vec()), ("zz", vec![0])], ""),
        Err(Error::DuplicateMember)
    );
    assert_eq!(
        with(&[("RVA1", MARKER.to_vec()), ("A", vec![0])], ""),
        Err(Error::ClosureIncomplete)
    );
    // Missing members.
    for skip in ["RVA1", "timeline.cbor", "events/00000000000000000001.cbor"] {
        assert_eq!(with(&[], skip), Err(Error::ClosureIncomplete), "{skip}");
    }
    assert_eq!(build(&[]), Err(Error::ClosureIncomplete));
    assert_eq!(
        build(&[("RVA1", MARKER.to_vec())]),
        Err(Error::ClosureIncomplete)
    );
    // An I/O failure is operational.
    assert_eq!(
        RunEvidenceArchiveBuilderV1::new().insert("RVA1", Failing),
        Err(Error::SourceUnavailable)
    );
    Ok(())
}

/// The sample with the member `name` replaced by `data`.
fn replaced(name: &str, data: Vec<u8>) -> TestResult<Result<RunEvidenceArchiveV1, Error>> {
    let mut replacement = Some(data);
    let members = sample()?
        .into_iter()
        .map(|(member, original)| {
            let bytes = if member == name {
                replacement.take().unwrap_or_default()
            } else {
                original
            };
            (member, bytes)
        })
        .collect::<Vec<_>>();
    Ok(build(
        &members
            .iter()
            .map(|(member, bytes)| (member.as_str(), bytes.clone()))
            .collect::<Vec<_>>(),
    ))
}

const FIRST: &str = "events/00000000000000000001.cbor";
const SECOND: &str = "events/00000000000000000002.cbor";

/// The first Event record with field `index` replaced by `value`.
fn first_with(index: usize, value: Value) -> (&'static str, Vec<u8>) {
    let mut fields = match record(1, 0, None, None) {
        Value::Array(fields) => fields,
        _ => Vec::new(),
    };
    fields[index] = value;
    (FIRST, cbor(&Value::Array(fields)))
}

/// Records whose encoding or shape the reader refuses.
fn malformed_records() -> Vec<(&'static str, Vec<u8>)> {
    let mut long_head = cbor(&record(1, 0, None, None));
    long_head.splice(1..2, [0x18, 0x01]);
    let mut trailing = cbor(&record(1, 0, None, None));
    trailing.push(0);
    vec![
        (
            "RVA1",
            cbor(&Value::Array(vec![Value::Text("RVA1".to_owned()), uint(2)])),
        ),
        (FIRST, long_head),
        (FIRST, trailing),
        (FIRST, cbor(&Value::Array(vec![uint(1)]))),
        (FIRST, cbor(&uint(1))),
        first_with(0, Value::Integer((-1).into())),
        first_with(2, uint(0)),
        first_with(3, uint(u64::from(u32::MAX) + 1)),
        first_with(4, Value::Array(vec![])),
        first_with(5, Value::Float(0.5)),
        first_with(6, Value::Text("p".to_owned())),
        first_with(7, Value::Bytes(vec![0; 31])),
        (
            "timeline.cbor",
            cbor(&Value::Array(vec![uint(1), uint(0), Value::Null, uint(2)])),
        ),
    ]
}

/// Well-formed records that break a record rule.
fn rule_breaking_records() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (FIRST, cbor(&record(2, 0, None, None))),
        (FIRST, cbor(&record(1, 2, None, None))),
        (FIRST, cbor(&record(1, 0, Some(1), None))),
        (FIRST, cbor(&record(1, 0, None, Some(1)))),
        (SECOND, cbor(&record(2, 0, Some(0), None))),
        (SECOND, cbor(&record(2, 0, Some(2), None))),
        (SECOND, cbor(&record(2, 3, Some(1), None))),
        (SECOND, cbor(&record(2, 1, Some(1), Some(1)))),
        (
            "timeline.cbor",
            cbor(&timeline_record(3, Some("s"), Some(0), 2)),
        ),
        (
            "timeline.cbor",
            cbor(&timeline_record(1, Some("s"), Some(1), 2)),
        ),
        (
            "timeline.cbor",
            cbor(&timeline_record(1, Some("s"), Some(0), 3)),
        ),
    ]
}

#[test]
fn the_builder_refuses_every_record_its_reader_would_refuse() -> TestResult {
    for (index, (name, data)) in malformed_records()
        .into_iter()
        .chain(rule_breaking_records())
        .enumerate()
    {
        assert_eq!(replaced(name, data)?, Err(Error::RecordInvalid), "{index}");
    }
    // The rules' accepting edges: a new correlation and a cause just before
    // the Event; without an owner the first entity is 0.
    for (name, data) in [
        (SECOND, cbor(&record(2, 1, Some(1), Some(0)))),
        (SECOND, cbor(&record(2, 0, Some(1), None))),
    ] {
        let archive = replaced(name, data)??;
        import_run_evidence_archive_v1(&archive.bytes, &archive.digest)?;
    }
    let archive = build(&[
        ("RVA1", MARKER.to_vec()),
        (FIRST, cbor(&record(1, 0, None, Some(0)))),
        ("timeline.cbor", cbor(&timeline_record(1, None, None, 1))),
    ])?;
    import_run_evidence_archive_v1(&archive.bytes, &archive.digest)?;
    Ok(())
}

#[test]
fn the_builder_bounds_the_bytes_it_reads_and_the_archive_it_writes() -> TestResult {
    // Exactly 1 MiB read is within the bound; the invalid name proves the
    // builder went on to validate.
    let mut exact = RunEvidenceArchiveBuilderV1::new();
    exact.insert("bogus", vec![0; MAX].as_slice())?;
    assert_eq!(exact.finish(), Err(Error::ClosureIncomplete));
    let mut over = RunEvidenceArchiveBuilderV1::new();
    over.insert("bogus", vec![0; MAX + 1].as_slice())?;
    assert_eq!(over.finish(), Err(Error::FieldOutOfBounds));
    // The bound is cumulative and sticky.
    let mut cumulative = RunEvidenceArchiveBuilderV1::new();
    cumulative.insert("bogus", vec![0; MAX].as_slice())?;
    // Past the bound one byte more is read, and no further.
    let mut source: &[u8] = &[0; 10];
    cumulative.insert("more", &mut source)?;
    assert_eq!(source.len(), 9);
    cumulative.insert("after", Failing)?;
    assert_eq!(cumulative.finish(), Err(Error::FieldOutOfBounds));
    // An archive of exactly 1 MiB, and one block over.
    let archive = |payload: usize| {
        let event = cbor(&Value::Array(vec![
            uint(1),
            uint(0),
            Value::Text("t".to_owned()),
            uint(1),
            Value::Null,
            Value::Null,
            Value::Bytes(vec![7; payload]),
            Value::Bytes(vec![0; 32]),
        ]));
        build(&[
            ("RVA1", MARKER.to_vec()),
            ("events/00000000000000000001.cbor", event),
            ("timeline.cbor", cbor(&timeline_record(1, None, None, 1))),
        ])
    };
    // Three headers, two one-block members and the end marker leave
    // 1,044,992 bytes for the Event record, which has 47 bytes of fields.
    let exact = archive(1_044_992 - 47)?;
    assert_eq!(exact.bytes.len(), MAX);
    import_run_evidence_archive_v1(&exact.bytes, &exact.digest)?;
    assert_eq!(archive(1_044_992 - 46), Err(Error::FieldOutOfBounds));
    Ok(())
}
