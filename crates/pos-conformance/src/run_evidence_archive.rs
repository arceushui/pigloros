//! The RVA1 run-evidence archive writer (ADR-127, Redmine #1284).
//!
//! An RVA1 archive is a canonical, uncompressed POSIX ustar archive of the
//! position-relative form of one root Timeline export
//! ([`pos_core::store::export_timeline_own`]). Its members, in bytewise name
//! order, are:
//!
//! - `RVA1`: the format marker, the canonical CBOR `["RVA1", 1]`;
//! - `events/<seq>.cbor`: one per Event, `<seq>` as 20 zero-padded decimal
//!   digits, holding `[seq, entity ordinal, event type, schema version,
//!   causation seq or null, correlation ordinal or null, payload, payload
//!   hash]`;
//! - `timeline.cbor`: `[mode code, name or null, owner ordinal or null,
//!   head]`.
//!
//! Every header is a function of the member name and size alone: mode
//! `0644`, owner and group 0, mtime 0, no link, no user or group name, no
//! device numbers and no prefix. The archive ends with exactly two zero
//! blocks and is at most 1 MiB.
//!
//! [`run_evidence_event_records_v1`] is the one definition of the
//! position-relative Event record. The builder sorts its members, so its
//! result never depends on insertion order or read chunking, and it refuses
//! every input whose archive the independent reader
//! (`pos_reference::run_evidence_archive`) would refuse.

use std::io::Read;

use ciborium::value::Value;
use pos_core::{store::TimelineExport, timeline::TimelineMode, CorrelationId, EntityId, Event};
use thiserror::Error;

/// The largest RVA1 archive, in bytes (the #181 surface maximum).
pub const RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1: usize = 1024 * 1024;
/// The name and the magic of the format marker member.
pub const RUN_EVIDENCE_ARCHIVE_MARKER_V1: &str = "RVA1";
/// The name of the Timeline member.
pub const RUN_EVIDENCE_ARCHIVE_TIMELINE_V1: &str = "timeline.cbor";
/// The RVA1 version this writer produces.
pub const RUN_EVIDENCE_ARCHIVE_VERSION_V1: u64 = 1;

const EVENTS_PREFIX: &str = "events/";
const EVENTS_SUFFIX: &str = ".cbor";
const SEQ_DIGITS: usize = 20;
const BLOCK: usize = 512;
const END_MARKER: usize = 2 * BLOCK;
/// The canonical CBOR of `["RVA1", 1]`.
const MARKER_BYTES: [u8; 7] = [0x82, 0x64, b'R', b'V', b'A', b'1', 0x01];
const EVENT_FIELDS: usize = 8;
const TIMELINE_FIELDS: usize = 4;

/// A closed RVA1 writer refusal. It carries no member name, path or byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum RunEvidenceArchiveWriteErrorV1 {
    /// A member source could not be read; the failure is operational.
    #[error("a run-evidence member source is unavailable")]
    SourceUnavailable,
    /// The members or the archive exceed 1 MiB.
    #[error("the run-evidence archive exceeds its bound")]
    FieldOutOfBounds,
    /// Two members share a name.
    #[error("a run-evidence member is duplicated")]
    DuplicateMember,
    /// A member name is outside the grammar, or a required member is
    /// missing.
    #[error("the run-evidence member closure is incomplete")]
    ClosureIncomplete,
    /// A member's record is malformed, non-canonical or breaks a record rule.
    #[error("a run-evidence record is invalid")]
    RecordInvalid,
    /// The export is not of a root Timeline.
    #[error("the run-evidence export is not of a root Timeline")]
    UnsupportedTimeline,
}

type WriteResult<T> = Result<T, RunEvidenceArchiveWriteErrorV1>;

/// One archive member: its name and its exact data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunEvidenceMemberV1 {
    pub name: String,
    pub data: Vec<u8>,
}

/// A finished RVA1 archive: its exact bytes and their BLAKE3 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunEvidenceArchiveV1 {
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
}

/// The name of the Event member at `seq`.
#[must_use]
pub fn run_evidence_event_member_name_v1(seq: u64) -> String {
    format!("{EVENTS_PREFIX}{seq:020}{EVENTS_SUFFIX}")
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn optional_uint(value: Option<u64>) -> Value {
    value.map_or(Value::Null, uint)
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes).map_or(Vec::new(), |()| bytes)
}

/// The first-appearance ordinal of `value` in `seen`.
fn ordinal<T: PartialEq + Copy>(seen: &mut Vec<T>, value: T) -> u64 {
    let position = seen
        .iter()
        .position(|known| *known == value)
        .unwrap_or_else(|| {
            seen.push(value);
            seen.len() - 1
        });
    position as u64
}

/// The position-relative records of an Event stream, one canonical CBOR
/// array per Event, in stream order (ADR-127 section 2):
/// `[seq, entity ordinal, event type, schema version, causation seq or
/// null, correlation ordinal or null, payload, payload hash]`.
///
/// Entities are numbered by first appearance, the Timeline `owner` (when
/// present) first; correlations by first appearance in their own table; a
/// cause by the `seq` of the earlier Event it names. `id`, `wall_time`,
/// `origin`, signatures and signature identities are operational and are
/// not recorded.
///
/// # Errors
/// Returns `RecordInvalid` for a duplicate Event id, or a cause that names
/// no earlier Event of the stream.
pub fn run_evidence_event_records_v1(
    events: &[Event],
    owner: Option<EntityId>,
) -> WriteResult<Vec<Vec<u8>>> {
    let mut entities = owner.into_iter().collect::<Vec<_>>();
    let mut correlations = Vec::<CorrelationId>::new();
    events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let earlier = &events[..index];
            let cause = event.causation_id.map_or(Some(None), |cause| {
                earlier
                    .iter()
                    .find(|candidate| candidate.id == cause)
                    .map(|candidate| Some(candidate.seq.as_u64()))
            });
            cause
                .filter(|_| earlier.iter().all(|candidate| candidate.id != event.id))
                .map(|cause| {
                    encode(&Value::Array(vec![
                        uint(event.seq.as_u64()),
                        uint(ordinal(&mut entities, event.entity)),
                        Value::Text(event.event_type.as_str().to_owned()),
                        uint(u64::from(event.schema_version.as_u32())),
                        optional_uint(cause),
                        optional_uint(
                            event
                                .correlation_id
                                .map(|correlation| ordinal(&mut correlations, correlation)),
                        ),
                        Value::Bytes(event.payload.as_slice().to_vec()),
                        Value::Bytes(event.payload_hash.as_bytes().to_vec()),
                    ]))
                })
                .ok_or(RunEvidenceArchiveWriteErrorV1::RecordInvalid)
        })
        .collect()
}

const fn mode_code(mode: TimelineMode) -> u64 {
    match mode {
        TimelineMode::Historical => 0,
        TimelineMode::Live => 1,
        TimelineMode::Future => 2,
    }
}

/// Project one root Timeline export onto the RVA1 members, the marker first
/// and the Timeline member last.
///
/// # Errors
/// Returns `UnsupportedTimeline` for a forked Timeline, `ClosureIncomplete`
/// when the Event seqs are not exactly `1..=head`, and the errors of
/// [`run_evidence_event_records_v1`].
pub fn run_evidence_members_v1(export: &TimelineExport) -> WriteResult<Vec<RunEvidenceMemberV1>> {
    let meta = &export.timeline.meta;
    let head = export.timeline.head.as_u64();
    if meta.fork_point.is_some() {
        return Err(RunEvidenceArchiveWriteErrorV1::UnsupportedTimeline);
    }
    if export.events.len() as u64 != head
        || export
            .events
            .iter()
            .zip(1_u64..)
            .any(|(event, seq)| event.seq.as_u64() != seq)
    {
        return Err(RunEvidenceArchiveWriteErrorV1::ClosureIncomplete);
    }
    run_evidence_event_records_v1(&export.events, meta.owner).map(|records| {
        let marker = RunEvidenceMemberV1 {
            name: RUN_EVIDENCE_ARCHIVE_MARKER_V1.to_owned(),
            data: MARKER_BYTES.to_vec(),
        };
        let timeline = RunEvidenceMemberV1 {
            name: RUN_EVIDENCE_ARCHIVE_TIMELINE_V1.to_owned(),
            data: encode(&Value::Array(vec![
                uint(mode_code(meta.mode)),
                meta.name.clone().map_or(Value::Null, Value::Text),
                optional_uint(meta.owner.map(|_| 0)),
                uint(head),
            ])),
        };
        std::iter::once(marker)
            .chain(
                records
                    .into_iter()
                    .zip(1_u64..)
                    .map(|(data, seq)| RunEvidenceMemberV1 {
                        name: run_evidence_event_member_name_v1(seq),
                        data,
                    }),
            )
            .chain(std::iter::once(timeline))
            .collect()
    })
}

/// The RVA1 builder: members are inserted in any order with any read
/// chunking, then sorted, validated and encoded by [`Self::finish`].
#[derive(Debug, Default)]
pub struct RunEvidenceArchiveBuilderV1 {
    entries: Vec<(String, Vec<u8>)>,
    total: usize,
    overflow: bool,
}

impl RunEvidenceArchiveBuilderV1 {
    /// An empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Read one member from `source`. The builder keeps a running total of
    /// the bytes read; once it passes 1 MiB, no further byte is read and
    /// [`Self::finish`] reports `FieldOutOfBounds`. A duplicate name is kept
    /// for [`Self::finish`] to report.
    ///
    /// # Errors
    /// Returns `SourceUnavailable` when `source` fails to read.
    pub fn insert(&mut self, name: &str, source: impl Read) -> WriteResult<()> {
        if self.overflow {
            return Ok(());
        }
        let remaining = RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1 - self.total;
        let mut data = Vec::new();
        source
            .take(remaining as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|_| RunEvidenceArchiveWriteErrorV1::SourceUnavailable)
            .map(|read| {
                self.total += read;
                if self.total > RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1 {
                    self.overflow = true;
                } else {
                    self.entries.push((name.to_owned(), data));
                }
            })
    }

    /// Validate the members in sorted order and encode the archive.
    ///
    /// # Errors
    /// Returns, first failure first: `FieldOutOfBounds` after an overflowing
    /// insert; `ClosureIncomplete` for a name outside the grammar and
    /// `DuplicateMember` for a repeated name, in sorted order;
    /// `ClosureIncomplete` for a missing marker, Timeline member or Event;
    /// `RecordInvalid` for a marker other than `["RVA1", 1]` or a malformed,
    /// non-canonical or rule-breaking record; and `FieldOutOfBounds` for an
    /// archive over 1 MiB.
    pub fn finish(mut self) -> WriteResult<RunEvidenceArchiveV1> {
        if self.overflow {
            return Err(RunEvidenceArchiveWriteErrorV1::FieldOutOfBounds);
        }
        self.entries.sort();
        names_valid(&self.entries)
            .and_then(|()| closure_complete(&self.entries))
            .and_then(|()| records_valid(&self.entries))
            .and_then(|()| archive_bytes(&self.entries))
            .map(|bytes| RunEvidenceArchiveV1 {
                digest: *blake3::hash(&bytes).as_bytes(),
                bytes,
            })
    }
}

fn event_digits(name: &str) -> Option<&str> {
    name.strip_prefix(EVENTS_PREFIX)
        .and_then(|rest| rest.strip_suffix(EVENTS_SUFFIX))
        .filter(|digits| digits.len() == SEQ_DIGITS && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn in_grammar(name: &str) -> bool {
    name == RUN_EVIDENCE_ARCHIVE_MARKER_V1
        || name == RUN_EVIDENCE_ARCHIVE_TIMELINE_V1
        || event_digits(name).is_some()
}

fn names_valid(entries: &[(String, Vec<u8>)]) -> WriteResult<()> {
    entries
        .iter()
        .enumerate()
        .try_for_each(|(index, (name, _))| {
            if !in_grammar(name) {
                Err(RunEvidenceArchiveWriteErrorV1::ClosureIncomplete)
            } else if index > 0 && entries[index - 1].0 == *name {
                Err(RunEvidenceArchiveWriteErrorV1::DuplicateMember)
            } else {
                Ok(())
            }
        })
}

/// The sorted, unique, in-grammar names must be the marker, the Events
/// `1..=n` and the Timeline member.
fn closure_complete(entries: &[(String, Vec<u8>)]) -> WriteResult<()> {
    let complete = !entries.is_empty()
        && entries[0].0 == RUN_EVIDENCE_ARCHIVE_MARKER_V1
        && entries[entries.len() - 1].0 == RUN_EVIDENCE_ARCHIVE_TIMELINE_V1
        && entries[1..entries.len() - 1]
            .iter()
            .zip(1_u64..)
            .all(|((name, _), seq)| *name == run_evidence_event_member_name_v1(seq));
    if complete {
        Ok(())
    } else {
        Err(RunEvidenceArchiveWriteErrorV1::ClosureIncomplete)
    }
}

/// One definite-length array of exactly `fields` scalars in canonical CBOR.
fn canonical_fields(data: &[u8], fields: usize) -> Option<Vec<Value>> {
    ciborium::de::from_reader_with_recursion_limit::<Value, _>(data, 1)
        .ok()
        .filter(|value| encode(value) == data)
        .and_then(|value| match value {
            Value::Array(items) if items.len() == fields => Some(items),
            _ => None,
        })
}

fn as_uint(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(integer) => u64::try_from(*integer).ok(),
        _ => None,
    }
}

/// `Some(None)` for null, `Some(Some(n))` for an unsigned integer.
fn as_optional_uint(value: &Value) -> Option<Option<u64>> {
    match value {
        Value::Null => Some(None),
        other => as_uint(other).map(Some),
    }
}

struct EventFields {
    seq: u64,
    entity: u64,
    cause: Option<u64>,
    correlation: Option<u64>,
}

fn event_fields(data: &[u8]) -> Option<EventFields> {
    canonical_fields(data, EVENT_FIELDS).and_then(|items| {
        let typed = matches!(items[2], Value::Text(_))
            && as_uint(&items[3]).is_some_and(|version| u32::try_from(version).is_ok())
            && matches!(items[6], Value::Bytes(_))
            && matches!(&items[7], Value::Bytes(hash) if hash.len() == 32);
        as_uint(&items[0])
            .zip(as_uint(&items[1]))
            .zip(as_optional_uint(&items[4]).zip(as_optional_uint(&items[5])))
            .filter(|_| typed)
            .map(|((seq, entity), (cause, correlation))| EventFields {
                seq,
                entity,
                cause,
                correlation,
            })
    })
}

struct TimelineFields {
    mode: u64,
    owner: Option<u64>,
    head: u64,
}

fn timeline_fields(data: &[u8]) -> Option<TimelineFields> {
    canonical_fields(data, TIMELINE_FIELDS).and_then(|items| {
        let named = matches!(items[1], Value::Null | Value::Text(_));
        as_uint(&items[0])
            .zip(as_optional_uint(&items[2]))
            .zip(as_uint(&items[3]))
            .filter(|_| named)
            .map(|((mode, owner), head)| TimelineFields { mode, owner, head })
    })
}

/// The record rules of ADR-127 section 5 step 8 over the decoded records.
fn rules_hold(timeline: &TimelineFields, events: &[EventFields]) -> bool {
    timeline.mode <= 2
        && timeline.owner.is_none_or(|owner| owner == 0)
        && timeline.head == events.len() as u64
        && events
            .iter()
            .zip(1_u64..)
            .try_fold(
                (u64::from(timeline.owner.is_some()), 0_u64),
                |(entities, correlations), (event, seq)| {
                    (event.seq == seq
                        && event.cause.is_none_or(|cause| cause >= 1 && cause < seq)
                        && event.entity <= entities
                        && event
                            .correlation
                            .is_none_or(|correlation| correlation <= correlations))
                    .then_some((
                        entities + u64::from(event.entity == entities),
                        correlations + u64::from(event.correlation == Some(correlations)),
                    ))
                },
            )
            .is_some()
}

fn records_valid(entries: &[(String, Vec<u8>)]) -> WriteResult<()> {
    let last = entries.len() - 1;
    let valid = entries[0].1 == MARKER_BYTES
        && timeline_fields(&entries[last].1).is_some_and(|timeline| {
            entries[1..last]
                .iter()
                .map(|(_, data)| event_fields(data))
                .collect::<Option<Vec<_>>>()
                .is_some_and(|events| rules_hold(&timeline, &events))
        });
    if valid {
        Ok(())
    } else {
        Err(RunEvidenceArchiveWriteErrorV1::RecordInvalid)
    }
}

/// The canonical 512-byte ustar header of a member (ADR-127 section 1).
fn header(name: &str, size: usize) -> [u8; BLOCK] {
    let mut header = [0_u8; BLOCK];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| u32::from(*byte)).sum::<u32>();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    header
}

fn archive_bytes(entries: &[(String, Vec<u8>)]) -> WriteResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for (name, data) in entries {
        bytes.extend_from_slice(&header(name, data.len()));
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len().next_multiple_of(BLOCK), 0);
    }
    bytes.resize(bytes.len() + END_MARKER, 0);
    if bytes.len() > RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1 {
        Err(RunEvidenceArchiveWriteErrorV1::FieldOutOfBounds)
    } else {
        Ok(bytes)
    }
}
