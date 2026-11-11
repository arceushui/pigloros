//! The independent RVA1 run-evidence archive import (ADR-127 section 5,
//! Redmine #1284).
//!
//! The evaluator imports an RVA1 archive only through
//! [`import_run_evidence_archive_v1`]. It is written from the ADR-127
//! profile and shares no code with the writer in `pos-conformance`, the WIT
//! reader in `pos-plugin-content` or the build-identity reader here.
//!
//! The checks run in one total order and the first failure wins. The digest
//! is compared before any byte is parsed, and the format marker before any
//! later record. Nothing is extracted, and no member name reaches a
//! filesystem API or an error.

use std::cmp::Ordering;

use ciborium::value::Value;

/// The largest RVA1 archive, in bytes (the #181 surface maximum).
pub const RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1: usize = 1_048_576;

const BLOCK: usize = 512;
const END_MARKER: usize = 1024;
/// A marker record, a Timeline record and the end marker.
const MIN_BYTES: usize = 3072;
const NAME_FIELD: usize = 100;
const MARKER: &[u8] = b"RVA1";
const TIMELINE: &[u8] = b"timeline.cbor";
const EVENT_PREFIX: &[u8] = b"events/";
const EVENT_SUFFIX: &[u8] = b".cbor";
const SEQ_DIGITS: usize = 20;
const VERSION: u64 = 1;

/// A closed RVA1 import refusal. It carries no member name, path or byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RunEvidenceArchiveErrorV1 {
    #[error("run-evidence archive exceeds its bound")]
    FieldOutOfBounds,
    #[error("run-evidence archive encoding is invalid")]
    InvalidEncoding,
    #[error("run-evidence archive digest is not the expected one")]
    DigestMismatch,
    #[error("run-evidence archive version is unsupported")]
    UnsupportedVersion,
    #[error("run-evidence archive closure is incomplete")]
    ClosureIncomplete,
    #[error("run-evidence archive member is duplicated")]
    DuplicateMember,
    #[error("run-evidence archive members are not in canonical order")]
    NonCanonicalOrder,
    #[error("run-evidence archive record is invalid")]
    RecordInvalid,
}

type ImportResult<T> = Result<T, RunEvidenceArchiveErrorV1>;

/// One imported member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedRunEvidenceMemberV1 {
    pub name: String,
    pub size: u64,
    pub digest: [u8; 32],
    pub data: Vec<u8>,
}

/// An imported RVA1 archive: its digest and its members in archive order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedRunEvidenceArchiveV1 {
    pub archive_digest: [u8; 32],
    pub members: Vec<ImportedRunEvidenceMemberV1>,
}

/// Import exact RVA1 bytes whose BLAKE3 digest must be `expected_digest`.
///
/// # Errors
/// Returns the first failing check of ADR-127 section 5:
/// `FieldOutOfBounds` over 1 MiB; `InvalidEncoding` for a misaligned or
/// short archive; `DigestMismatch`; per record `InvalidEncoding` (name,
/// size, fit, canonical header, padding), `ClosureIncomplete` (grammar, or a
/// first record other than `RVA1`), `DuplicateMember`, `NonCanonicalOrder`,
/// and for the marker `InvalidEncoding` or `UnsupportedVersion`; then
/// `InvalidEncoding` for the end marker, `ClosureIncomplete` for the member
/// set, `InvalidEncoding` for a record shape and `RecordInvalid` for a record
/// rule.
pub fn import_run_evidence_archive_v1(
    bytes: &[u8],
    expected_digest: &[u8; 32],
) -> ImportResult<ImportedRunEvidenceArchiveV1> {
    if bytes.len() > RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1 {
        return Err(RunEvidenceArchiveErrorV1::FieldOutOfBounds);
    }
    if !bytes.len().is_multiple_of(BLOCK) || bytes.len() < MIN_BYTES {
        return Err(RunEvidenceArchiveErrorV1::InvalidEncoding);
    }
    let archive_digest = *blake3::hash(bytes).as_bytes();
    if archive_digest != *expected_digest {
        return Err(RunEvidenceArchiveErrorV1::DigestMismatch);
    }
    walk(bytes)
        .and_then(|records| member_set(&records).map(|()| records))
        .and_then(|records| decoded(&records).map(|shapes| (records, shapes)))
        .and_then(|(records, (timeline, events))| {
            if rules_hold(&records, &timeline, &events) {
                Ok(records)
            } else {
                Err(RunEvidenceArchiveErrorV1::RecordInvalid)
            }
        })
        .map(|records| ImportedRunEvidenceArchiveV1 {
            archive_digest,
            members: records
                .into_iter()
                .map(|(name, data)| ImportedRunEvidenceMemberV1 {
                    name: String::from_utf8_lossy(name).into_owned(),
                    size: data.len() as u64,
                    digest: *blake3::hash(data).as_bytes(),
                    data: data.to_vec(),
                })
                .collect(),
        })
}

type Record<'a> = (&'a [u8], &'a [u8]);

/// Steps 4 and 5: every record in archive order up to the end marker, then
/// the end marker.
fn walk(bytes: &[u8]) -> ImportResult<Vec<Record<'_>>> {
    let end = bytes.len() - END_MARKER;
    let mut records: Vec<Record<'_>> = Vec::new();
    let mut cursor = 0;
    // A zero block before the end marker fails as a header.
    while cursor < end {
        let block = &bytes[cursor..cursor + BLOCK];
        let start = cursor + BLOCK;
        let record = name_and_size(block)
            .filter(|(_, size)| size.div_ceil(BLOCK) * BLOCK <= end - start)
            .filter(|(name, size)| canonical_header(name, *size) == block)
            .map(|(name, size)| {
                (
                    name,
                    &bytes[start..start + size],
                    size.div_ceil(BLOCK) * BLOCK,
                )
            })
            .filter(|(_, data, padded)| {
                bytes[start + data.len()..start + padded]
                    .iter()
                    .all(|byte| *byte == 0)
            })
            .ok_or(RunEvidenceArchiveErrorV1::InvalidEncoding)
            .and_then(|(name, data, padded)| {
                admitted_name(&records, name)
                    .and_then(|()| {
                        if records.is_empty() {
                            marker(data)
                        } else {
                            Ok(())
                        }
                    })
                    .map(|()| ((name, data), padded))
            });
        let (record, padded) = record?;
        records.push(record);
        cursor = start + padded;
    }
    // Every record ends at or before `end`, so the walk stops exactly there.
    if bytes[end..].iter().all(|byte| *byte == 0) {
        Ok(records)
    } else {
        Err(RunEvidenceArchiveErrorV1::InvalidEncoding)
    }
}

/// Step 4.1: the name up to its NUL (a field without one is invalid) and
/// the size as exactly 11 octal digits.
fn name_and_size(block: &[u8]) -> Option<(&[u8], usize)> {
    let name = block[..NAME_FIELD]
        .iter()
        .position(|byte| *byte == 0)
        .map(|end| &block[..end]);
    let digits = &block[124..135];
    let size = digits
        .iter()
        .all(|digit| (b'0'..=b'7').contains(digit))
        .then(|| {
            digits
                .iter()
                .fold(0_u64, |size, digit| size * 8 + u64::from(digit - b'0'))
        })
        .and_then(|size| usize::try_from(size).ok());
    name.zip(size)
}

/// Step 4.3: the one canonical header of a NUL-free name of 1 to 99 bytes.
fn canonical_header(name: &[u8], size: usize) -> Vec<u8> {
    let mut header = vec![0_u8; BLOCK];
    if name.is_empty() {
        return header;
    }
    header[..name.len()].copy_from_slice(name);
    for (range, field) in [
        (100..108, &b"0000644\0"[..]),
        (108..116, &b"0000000\0"[..]),
        (116..124, &b"0000000\0"[..]),
        (136..148, &b"00000000000\0"[..]),
        (148..156, &b"        "[..]),
        (156..157, &b"0"[..]),
        (257..265, &b"ustar\x0000"[..]),
    ] {
        header[range].copy_from_slice(field);
    }
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    let sum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    header
}

fn event_digits(name: &[u8]) -> Option<&[u8]> {
    name.strip_prefix(EVENT_PREFIX)
        .and_then(|rest| rest.strip_suffix(EVENT_SUFFIX))
        .filter(|digits| digits.len() == SEQ_DIGITS && digits.iter().all(u8::is_ascii_digit))
}

/// Steps 4.5 and 4.6: the grammar, the first record, then the order.
fn admitted_name(records: &[Record<'_>], name: &[u8]) -> ImportResult<()> {
    let in_grammar = name == MARKER || name == TIMELINE || event_digits(name).is_some();
    if !in_grammar || (records.is_empty() && name != MARKER) {
        return Err(RunEvidenceArchiveErrorV1::ClosureIncomplete);
    }
    match records.last().map(|(previous, _)| (*previous).cmp(name)) {
        Some(Ordering::Equal) => Err(RunEvidenceArchiveErrorV1::DuplicateMember),
        Some(Ordering::Greater) => Err(RunEvidenceArchiveErrorV1::NonCanonicalOrder),
        Some(Ordering::Less) | None => Ok(()),
    }
}

/// One canonical CBOR array of exactly `fields` scalars: decoded with a
/// recursion limit of one, then re-encoded and compared.
fn scalars(data: &[u8], fields: usize) -> Option<Vec<Value>> {
    ciborium::de::from_reader_with_recursion_limit::<Value, _>(data, 1)
        .ok()
        .filter(|value| {
            let mut encoded = Vec::new();
            ciborium::into_writer(value, &mut encoded).is_ok() && encoded == data
        })
        .and_then(|value| match value {
            Value::Array(items) if items.len() == fields => Some(items),
            _ => None,
        })
}

/// Step 4.7: the marker is `["RVA1", 1]`. Another magic or a version that is
/// not an unsigned integer is invalid; another unsigned version is
/// unsupported.
fn marker(data: &[u8]) -> ImportResult<()> {
    match scalars(data, 2).as_deref() {
        Some([Value::Text(magic), Value::Integer(version)]) if magic.as_bytes() == MARKER => {
            match u64::try_from(*version) {
                Ok(VERSION) => Ok(()),
                Ok(_) => Err(RunEvidenceArchiveErrorV1::UnsupportedVersion),
                Err(_) => Err(RunEvidenceArchiveErrorV1::InvalidEncoding),
            }
        }
        _ => Err(RunEvidenceArchiveErrorV1::InvalidEncoding),
    }
}

fn seq_name(seq: u64) -> Vec<u8> {
    format!("events/{seq:020}.cbor").into_bytes()
}

/// Step 6: the marker, the Events `1..=n` and the Timeline member.
fn member_set(records: &[Record<'_>]) -> ImportResult<()> {
    // The walk admits at least the marker.
    let complete = records[records.len() - 1].0 == TIMELINE
        && records[1..records.len() - 1]
            .iter()
            .zip(1_u64..)
            .all(|((name, _), seq)| *name == seq_name(seq).as_slice());
    if complete {
        Ok(())
    } else {
        Err(RunEvidenceArchiveErrorV1::ClosureIncomplete)
    }
}

fn unsigned(value: &Value) -> Option<u64> {
    if let Value::Integer(integer) = value {
        u64::try_from(*integer).ok()
    } else {
        None
    }
}

/// A field that is neither null nor an unsigned integer.
struct NotNullable;

fn nullable(value: &Value) -> Result<Option<u64>, NotNullable> {
    if value.is_null() {
        Ok(None)
    } else {
        unsigned(value).map(Some).ok_or(NotNullable)
    }
}

struct TimelineShape {
    mode: u64,
    owner: Option<u64>,
    head: u64,
}

struct EventShape {
    seq: u64,
    entity: u64,
    cause: Option<u64>,
    correlation: Option<u64>,
}

fn timeline_shape(data: &[u8]) -> Option<TimelineShape> {
    scalars(data, 4).and_then(|fields| {
        let mode = unsigned(&fields[0]);
        let named = fields[1].is_null() || fields[1].is_text();
        let owner = nullable(&fields[2]);
        let head = unsigned(&fields[3]);
        match (mode, named, owner, head) {
            (Some(mode), true, Ok(owner), Some(head)) => Some(TimelineShape { mode, owner, head }),
            _ => None,
        }
    })
}

fn event_shape(data: &[u8]) -> Option<EventShape> {
    scalars(data, 8).and_then(|fields| {
        let seq = unsigned(&fields[0]);
        let entity = unsigned(&fields[1]);
        let typed = fields[2].is_text()
            && unsigned(&fields[3]).is_some_and(|version| u32::try_from(version).is_ok())
            && fields[6].is_bytes()
            && fields[7].as_bytes().is_some_and(|hash| hash.len() == 32);
        let cause = nullable(&fields[4]);
        let correlation = nullable(&fields[5]);
        match (seq, entity, typed, cause, correlation) {
            (Some(seq), Some(entity), true, Ok(cause), Ok(correlation)) => Some(EventShape {
                seq,
                entity,
                cause,
                correlation,
            }),
            _ => None,
        }
    })
}

/// Step 7: every record's fixed shape, in archive order.
fn decoded(records: &[Record<'_>]) -> ImportResult<(TimelineShape, Vec<EventShape>)> {
    let last = records.len() - 1;
    records[1..last]
        .iter()
        .map(|(_, data)| event_shape(data))
        .collect::<Option<Vec<_>>>()
        .zip(timeline_shape(records[last].1))
        .map(|(events, timeline)| (timeline, events))
        .ok_or(RunEvidenceArchiveErrorV1::InvalidEncoding)
}

/// Step 8: the record rules, starting from the Timeline record.
fn rules_hold(records: &[Record<'_>], timeline: &TimelineShape, events: &[EventShape]) -> bool {
    let mut entities = u64::from(timeline.owner == Some(0));
    let mut correlations = 0_u64;
    timeline.mode <= 2
        && timeline.owner.is_none_or(|owner| owner == 0)
        && timeline.head == events.len() as u64
        && events.iter().zip(&records[1..]).all(|(event, (name, _))| {
            let named = event_digits(name)
                .is_some_and(|digits| digits == format!("{:020}", event.seq).as_bytes());
            let caused = event
                .cause
                .is_none_or(|cause| (1..event.seq).contains(&cause));
            let entity = event.entity <= entities;
            entities += u64::from(event.entity == entities);
            let correlated = event.correlation.is_none_or(|correlation| {
                let known = correlation <= correlations;
                correlations += u64::from(correlation == correlations);
                known
            });
            named && caused && entity && correlated
        })
}
