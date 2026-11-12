//! Public-interface tests of the independent RVA1 import (ADR-127 section
//! 5, Redmine #1284). Every archive here is built by the test's own encoder,
//! never by the writer in `pos-conformance`.

use ciborium::value::Value;
use pos_reference::run_evidence_archive::{
    import_run_evidence_archive_v1, ImportedRunEvidenceArchiveV1, ImportedRunEvidenceMemberV1,
    RunEvidenceArchiveErrorV1, RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1,
};

type Error = RunEvidenceArchiveErrorV1;

const MARKER: [u8; 7] = [0x82, 0x64, b'R', b'V', b'A', b'1', 0x01];
const FIRST: &str = "events/00000000000000000001.cbor";
const SECOND: &str = "events/00000000000000000002.cbor";

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)
        .map(|()| bytes)
        .unwrap_or_default()
}

fn fields(seq: u64, entity: u64, cause: Option<u64>, correlation: Option<u64>) -> Vec<Value> {
    vec![
        uint(seq),
        uint(entity),
        Value::Text("t".to_owned()),
        uint(1),
        cause.map_or(Value::Null, uint),
        correlation.map_or(Value::Null, uint),
        Value::Bytes(vec![1, 2, 3]),
        Value::Bytes(vec![9; 32]),
    ]
}

fn event(seq: u64, entity: u64, cause: Option<u64>, correlation: Option<u64>) -> Vec<u8> {
    cbor(&Value::Array(fields(seq, entity, cause, correlation)))
}

fn timeline(mode: u64, owner: Option<u64>, head: u64) -> Vec<u8> {
    cbor(&Value::Array(vec![
        uint(mode),
        Value::Text("s".to_owned()),
        owner.map_or(Value::Null, uint),
        uint(head),
    ]))
}

/// The canonical 512-byte header with an mtime of `mtime`.
fn header(name: &[u8], size: usize, mtime: u64) -> Vec<u8> {
    let mut header = vec![0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    header[100..124].copy_from_slice(b"0000644\x000000000\x000000000\x00");
    header[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    header[136..148].copy_from_slice(format!("{mtime:011o}\0").as_bytes());
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..265].copy_from_slice(b"ustar\x0000");
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    header
}

/// A ustar archive of `(name, data)` in the given order.
fn archive(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, data) in entries {
        bytes.extend(header(name.as_bytes(), data.len(), 0));
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.extend([0; 1024]);
    bytes
}

/// A valid archive: an owner (entity 0), a second entity, a cause and a
/// correlation.
fn members() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("RVA1", MARKER.to_vec()),
        (FIRST, event(1, 0, None, Some(0))),
        (SECOND, event(2, 1, Some(1), Some(0))),
        ("timeline.cbor", timeline(2, Some(0), 2)),
    ]
}

fn import(bytes: &[u8]) -> Result<ImportedRunEvidenceArchiveV1, Error> {
    import_run_evidence_archive_v1(bytes, blake3::hash(bytes).as_bytes())
}

/// `members()` with the member `name` replaced by `data`.
fn with(name: &str, data: Vec<u8>) -> Result<ImportedRunEvidenceArchiveV1, Error> {
    let mut replacement = Some(data);
    import(&archive(
        &members()
            .into_iter()
            .map(|(member, original)| {
                let bytes = if member == name {
                    replacement.take().unwrap_or_default()
                } else {
                    original
                };
                (member, bytes)
            })
            .collect::<Vec<_>>(),
    ))
}

#[test]
fn a_canonical_archive_imports_its_members_in_order() {
    let bytes = archive(&members());
    let digest = *blake3::hash(&bytes).as_bytes();
    assert_eq!(
        import_run_evidence_archive_v1(&bytes, &digest),
        Ok(ImportedRunEvidenceArchiveV1 {
            archive_digest: digest,
            members: members()
                .into_iter()
                .map(|(name, data)| ImportedRunEvidenceMemberV1 {
                    name: name.to_owned(),
                    size: data.len() as u64,
                    digest: *blake3::hash(&data).as_bytes(),
                    data,
                })
                .collect(),
        })
    );
    // The smallest archive has no Event; a Timeline without owner starts its
    // entities at 0; every mode code imports.
    let empty = archive(&[
        ("RVA1", MARKER.to_vec()),
        ("timeline.cbor", timeline(0, None, 0)),
    ]);
    assert_eq!(empty.len(), 3072);
    assert!(import(&empty).is_ok());
    for mode in [0, 1, 2] {
        assert!(import(&archive(&[
            ("RVA1", MARKER.to_vec()),
            (FIRST, event(1, 0, None, None)),
            ("timeline.cbor", timeline(mode, None, 1)),
        ]))
        .is_ok());
    }
    assert!(with(
        "timeline.cbor",
        cbor(&Value::Array(vec![uint(1), Value::Null, uint(0), uint(2)]))
    )
    .is_ok());
}

#[test]
fn the_length_alignment_and_digest_come_first() {
    let max = RUN_EVIDENCE_ARCHIVE_MAX_BYTES_V1;
    assert_eq!(max, 1024 * 1024);
    assert_eq!(
        import_run_evidence_archive_v1(&vec![0; max + 512], &[0; 32]),
        Err(Error::FieldOutOfBounds)
    );
    // Exactly 1 MiB passes the bound and reaches the digest.
    assert_eq!(
        import_run_evidence_archive_v1(&vec![0; max], &[0; 32]),
        Err(Error::DigestMismatch)
    );
    for length in [2560, 3073, 3584 + 1] {
        assert_eq!(
            import(&vec![0; length]),
            Err(Error::InvalidEncoding),
            "{length}"
        );
    }
    // A valid archive one byte too long, with a header where the end marker
    // would start: only the alignment check refuses it.
    let mut unaligned = archive(&members());
    let end = unaligned.len() - 1024;
    unaligned[end..end + 512].copy_from_slice(&header(b"x", 0, 0));
    unaligned.push(0);
    assert_eq!(import(&unaligned), Err(Error::InvalidEncoding));
    let bytes = archive(&members());
    let mut wrong = *blake3::hash(&bytes).as_bytes();
    wrong[0] ^= 0xff;
    assert_eq!(
        import_run_evidence_archive_v1(&bytes, &wrong),
        Err(Error::DigestMismatch)
    );
}

/// `members()` encoded, then `edit` applied to the bytes.
fn edited(edit: impl FnOnce(&mut Vec<u8>)) -> Result<ImportedRunEvidenceArchiveV1, Error> {
    let mut bytes = archive(&members());
    edit(&mut bytes);
    import(&bytes)
}

#[test]
fn every_header_byte_is_canonical() {
    // The marker header's mtime, mode, typeflag, magic, a device field, the
    // prefix and the checksum.
    for offset in [136, 100, 156, 257, 329, 345, 148, 500] {
        assert_eq!(
            edited(|bytes| bytes[offset] ^= 0x01),
            Err(Error::InvalidEncoding),
            "{offset}"
        );
    }
    // A name field without a NUL, an empty name, and bytes after the NUL.
    assert_eq!(
        edited(|bytes| bytes[..100].fill(b'a')),
        Err(Error::InvalidEncoding)
    );
    let empty_name = header(b"", 7, 0);
    assert_eq!(
        edited(|bytes| bytes[..512].copy_from_slice(&empty_name)),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(
        edited(|bytes| bytes[50] = b'x'),
        Err(Error::InvalidEncoding)
    );
    // A size digit outside octal, a space, and a size past the end marker.
    assert_eq!(
        edited(|bytes| bytes[134] = b'8'),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(
        edited(|bytes| bytes[124] = b' '),
        Err(Error::InvalidEncoding)
    );
    let oversized = header(b"RVA1", 10 * 512 + 1, 0);
    assert_eq!(
        edited(|bytes| bytes[..512].copy_from_slice(&oversized)),
        Err(Error::InvalidEncoding)
    );
    // The last record's size past the input.
    let past = header(b"timeline.cbor", 2000, 0);
    assert_eq!(
        edited(|bytes| bytes[3072..3584].copy_from_slice(&past)),
        Err(Error::InvalidEncoding)
    );
    // Non-zero padding after the marker data.
    assert_eq!(
        edited(|bytes| bytes[512 + 7] = 1),
        Err(Error::InvalidEncoding)
    );
    // A canonical header with another mtime.
    let mtime = header(b"RVA1", 7, 1);
    assert_eq!(
        edited(|bytes| bytes[..512].copy_from_slice(&mtime)),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn the_end_marker_is_exactly_two_zero_blocks() {
    assert_eq!(
        edited(|bytes| {
            let last = bytes.len() - 1;
            bytes[last] = 1;
        }),
        Err(Error::InvalidEncoding)
    );
    // A third zero block.
    assert_eq!(
        edited(|bytes| bytes.extend([0; 512])),
        Err(Error::InvalidEncoding)
    );
    // A header where the end marker starts.
    assert_eq!(
        edited(|bytes| {
            let end = bytes.len() - 1024;
            bytes[end..end + 512].copy_from_slice(&header(b"x", 0, 0));
        }),
        Err(Error::InvalidEncoding)
    );
    // A non-zero block where the end marker starts.
    assert_eq!(
        edited(|bytes| {
            let end = bytes.len() - 1024;
            bytes[end] = 1;
        }),
        Err(Error::InvalidEncoding)
    );
}

#[test]
fn names_follow_the_grammar_the_marker_and_the_order() {
    let reordered = |entries: &[(&str, Vec<u8>)]| import(&archive(entries));
    let marker = || ("RVA1", MARKER.to_vec());
    let end = || ("timeline.cbor", timeline(1, None, 0));
    for name in [
        "RVA2",
        "events/1.cbor",
        "events/0000000000000000000a.cbor",
        "events/00000000000000000001.json",
        "/timeline.cbor",
        "../x",
    ] {
        assert_eq!(
            reordered(&[marker(), (name, vec![0]), end()]),
            Err(Error::ClosureIncomplete),
            "{name}"
        );
    }
    // A repeated name outside the grammar fails the grammar first.
    for name in ["events/1.cbor", "events/0000000000000000000a.cbor"] {
        assert_eq!(
            reordered(&[marker(), (name, vec![0]), (name, vec![0]), end()]),
            Err(Error::ClosureIncomplete),
            "{name}"
        );
    }
    // The first record must be the marker.
    assert_eq!(
        reordered(&[(FIRST, event(1, 0, None, None)), marker(), end()]),
        Err(Error::ClosureIncomplete)
    );
    assert_eq!(
        reordered(&[marker(), marker(), end()]),
        Err(Error::DuplicateMember)
    );
    assert_eq!(
        reordered(&[marker(), end(), (FIRST, event(1, 0, None, None))]),
        Err(Error::NonCanonicalOrder)
    );
    // The member set: no Timeline, a gap.
    assert_eq!(
        reordered(&[marker(), (FIRST, event(1, 0, None, None))]),
        Err(Error::ClosureIncomplete)
    );
    assert_eq!(
        reordered(&[marker(), (SECOND, event(2, 0, None, None)), end()]),
        Err(Error::ClosureIncomplete)
    );
}

#[test]
fn the_marker_is_checked_before_any_later_record() {
    let text = |magic: &str, version: u64| {
        cbor(&Value::Array(vec![
            Value::Text(magic.to_owned()),
            uint(version),
        ]))
    };
    // A later broken record does not mask the version.
    let broken = |marker: Vec<u8>| {
        import(&archive(&[
            ("RVA1", marker),
            ("events/x", vec![0]),
            ("timeline.cbor", timeline(1, None, 0)),
        ]))
    };
    assert_eq!(broken(text("RVA1", 2)), Err(Error::UnsupportedVersion));
    assert_eq!(broken(text("RVA0", 1)), Err(Error::InvalidEncoding));
    // A version that is not an unsigned integer is invalid, not unsupported.
    for version in [Value::Integer((-1).into()), Value::Text("1".to_owned())] {
        assert_eq!(
            broken(cbor(&Value::Array(vec![
                Value::Text("RVA1".to_owned()),
                version
            ]))),
            Err(Error::InvalidEncoding)
        );
    }
    assert_eq!(broken(cbor(&uint(1))), Err(Error::InvalidEncoding));
    assert_eq!(
        broken(vec![0x82, 0x64, b'R', b'V', b'A', b'1', 0x18, 0x01]),
        Err(Error::InvalidEncoding)
    );
    assert_eq!(broken(MARKER.to_vec()), Err(Error::ClosureIncomplete));
}

#[test]
fn every_record_has_its_fixed_canonical_shape() {
    let shaped = |index: usize, value: Value| {
        let mut record = fields(1, 0, None, Some(0));
        record[index] = value;
        with(FIRST, cbor(&Value::Array(record)))
    };
    for (index, value) in [
        (0, Value::Integer((-1).into())),
        (1, Value::Text("e".to_owned())),
        (2, uint(0)),
        (3, uint(u64::from(u32::MAX) + 1)),
        (4, Value::Bool(true)),
        (5, Value::Array(Vec::new())),
        (6, Value::Text("p".to_owned())),
        (7, Value::Bytes(vec![0; 31])),
        (7, uint(0)),
    ] {
        assert_eq!(shaped(index, value), Err(Error::InvalidEncoding), "{index}");
    }
    assert!(shaped(3, uint(u64::from(u32::MAX))).is_ok());
    let mut trailing = event(1, 0, None, Some(0));
    trailing.push(0xf6);
    let mut long_head = event(1, 0, None, Some(0));
    long_head.splice(1..2, [0x18, 0x01]);
    for data in [
        trailing,
        long_head,
        cbor(&Value::Array(fields(1, 0, None, Some(0))[..7].to_vec())),
        cbor(&Value::Tag(1, Box::new(uint(0)))),
        cbor(&Value::Map(Vec::new())),
    ] {
        assert_eq!(with(FIRST, data), Err(Error::InvalidEncoding));
    }
    for data in [
        cbor(&Value::Array(vec![uint(1), uint(0), Value::Null, uint(2)])),
        cbor(&Value::Array(vec![
            Value::Null,
            Value::Null,
            Value::Null,
            uint(2),
        ])),
        cbor(&Value::Array(vec![
            uint(1),
            Value::Null,
            Value::Text("o".to_owned()),
            uint(2),
        ])),
        cbor(&Value::Array(vec![
            uint(1),
            Value::Null,
            Value::Null,
            Value::Null,
        ])),
        cbor(&Value::Array(vec![uint(1), Value::Null, Value::Null])),
    ] {
        assert_eq!(with("timeline.cbor", data), Err(Error::InvalidEncoding));
    }
}

#[test]
fn the_record_rules_hold() {
    for (name, data) in [
        // The Timeline: a mode code, the owner flag and the head.
        ("timeline.cbor", timeline(3, Some(0), 2)),
        ("timeline.cbor", timeline(1, Some(1), 2)),
        ("timeline.cbor", timeline(1, Some(0), 3)),
        // The inner seq, causes, entity and correlation ordinals.
        (FIRST, event(2, 0, None, Some(0))),
        (FIRST, event(1, 0, Some(0), Some(0))),
        (FIRST, event(1, 0, None, Some(1))),
        (SECOND, event(2, 1, Some(2), Some(0))),
        (SECOND, event(2, 1, Some(0), Some(0))),
        (SECOND, event(2, 2, Some(1), Some(0))),
        (SECOND, event(2, 1, Some(1), Some(2))),
    ] {
        assert_eq!(with(name, data), Err(Error::RecordInvalid), "{name}");
    }
    // Without an owner the first entity must be 0.
    assert_eq!(
        import(&archive(&[
            ("RVA1", MARKER.to_vec()),
            (FIRST, event(1, 1, None, None)),
            ("timeline.cbor", timeline(1, None, 1)),
        ])),
        Err(Error::RecordInvalid)
    );
    // The accepting edges: a new entity, a new correlation, a repeated
    // entity and correlation.
    for (name, data) in [
        (SECOND, event(2, 1, None, Some(1))),
        (SECOND, event(2, 0, Some(1), None)),
        (FIRST, event(1, 1, None, Some(0))),
    ] {
        assert!(with(name, data).is_ok(), "{name}");
    }
}
