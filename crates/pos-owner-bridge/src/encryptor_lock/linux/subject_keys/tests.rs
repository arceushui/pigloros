#![cfg(any(test, feature = "test-support"))]
//! Reserved-name grammar, stage interruption boundaries and the read recheck.

use std::fs;
use std::io;

use rustix::fs::AtFlags;

use super::super::commit::CommitStage;
use super::{
    is_dot, read_regular, SubjectEncryptorLock, SubjectKeyArtifactContent,
    SubjectKeyArtifactKind::{Binding, Wrap},
    SubjectKeyArtifactName,
    SubjectKeyArtifactSlot::{Canonical, Temporary},
    DIRECTORY_NAME,
};
use crate::encryptor_lock_test_support::{write_private, Sandbox};
use crate::{BridgeError, UnavailableCode};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);
const HEX: &str = "0123456789abcdef0123456789abcdef";
const OWNER: &str = "subject:0123456789abcdef0123456789abcdef";
const STAGES: [CommitStage; 5] = [
    CommitStage::Created,
    CommitStage::Written,
    CommitStage::FileSynced,
    CommitStage::Renamed,
    CommitStage::DirectorySynced,
];

fn name(
    kind: super::SubjectKeyArtifactKind,
    epoch: u64,
) -> Result<SubjectKeyArtifactName, &'static str> {
    SubjectKeyArtifactName::new(kind, OWNER, epoch).ok_or("valid fixture name refused")
}

#[test]
fn builders_render_exactly_the_p4_names_and_expose_their_identity() -> TestResult {
    let wrap = name(Wrap, 42)?;
    assert_eq!(wrap.canonical(), format!("wrap.{HEX}.42.skw1"));
    assert_eq!(wrap.temporary(), format!("wrap.{HEX}.42.skw1.tmp"));
    assert_eq!(wrap.kind(), Wrap);
    assert_eq!(wrap.owner_id(), OWNER);
    assert_eq!(wrap.epoch(), 42);
    let binding = name(Binding, 1)?;
    assert_eq!(binding.canonical(), format!("binding.{HEX}.1.scb1"));
    assert_eq!(binding.temporary(), format!("binding.{HEX}.1.scb1.tmp"));
    assert_eq!(binding.kind(), Binding);
    assert_eq!(binding.epoch(), 1);
    assert_eq!(
        name(Wrap, u64::MAX)?.canonical(),
        format!("wrap.{HEX}.18446744073709551615.skw1")
    );
    Ok(())
}

#[test]
fn builders_refuse_owners_outside_the_hex32_grammar_the_nil_owner_and_epoch_zero() {
    let refused = [
        HEX.to_owned(),
        format!("Subject:{HEX}"),
        format!("subject:{}", &HEX[..31]),
        format!("subject:{HEX}0"),
        "subject:0123456789ABCDEF0123456789abcdef".to_owned(),
        "subject:0123456789abcdeg0123456789abcdef".to_owned(),
        "subject:0123456789abcde/0123456789abcdef".to_owned(),
        "subject:0123456789abcde:0123456789abcdef".to_owned(),
        "subject:0123456789abcde`0123456789abcdef".to_owned(),
        "subject:00000000000000000000000000000000".to_owned(),
    ];
    for owner in refused {
        assert_eq!(
            SubjectKeyArtifactName::new(Wrap, &owner, 1),
            None,
            "{owner}"
        );
    }
    assert_eq!(SubjectKeyArtifactName::new(Binding, OWNER, 0), None);
}

#[test]
fn parsing_inverts_rendering_for_both_kinds_and_slots() -> TestResult {
    for kind in [Wrap, Binding] {
        for epoch in [1, 42, u64::MAX] {
            let expected = name(kind, epoch)?;
            assert_eq!(
                SubjectKeyArtifactName::parse(expected.canonical().as_bytes()),
                Some((expected.clone(), Canonical))
            );
            assert_eq!(
                SubjectKeyArtifactName::parse(expected.temporary().as_bytes()),
                Some((expected, Temporary))
            );
        }
    }
    let nil = "binding.00000000000000000000000000000000.1.scb1";
    let (parsed, slot) = SubjectKeyArtifactName::parse(nil.as_bytes()).ok_or("nil name")?;
    assert_eq!(
        (parsed.canonical(), parsed.owner_id(), slot),
        (
            nil.to_owned(),
            "subject:00000000000000000000000000000000".to_owned(),
            Canonical
        )
    );
    Ok(())
}

#[test]
fn parsing_refuses_every_non_canonical_spelling() {
    let refused = [
        String::new(),
        "wrap".to_owned(),
        ".tmp".to_owned(),
        "subject-nonce-ledger.v1".to_owned(),
        format!("wrap.{HEX}.42.scb1"),
        format!("binding.{HEX}.42.skw1"),
        format!("wrap.{HEX}.0.skw1"),
        format!("wrap.{HEX}.042.skw1"),
        format!("wrap.{HEX}.+42.skw1"),
        format!("wrap.{HEX}.-1.skw1"),
        format!("wrap.{HEX}.18446744073709551616.skw1"),
        format!("wrap.{HEX}..skw1"),
        format!("wrap.{HEX}.4.2.skw1"),
        format!("wrap.{HEX}.42 .skw1"),
        format!("wrap.{HEX}.42skw1"),
        format!("wrap{HEX}.42.skw1"),
        format!("xwrap.{HEX}.42.skw1"),
        format!("wrap.{HEX}.42.skw1x"),
        format!("wrap.{HEX}.42.skw1.tmp.tmp"),
        format!("wrap.{HEX}.42.skw1.TMP"),
        format!("wrap.{HEX}.42.skw1tmp"),
        format!("wrap.{}.42.skw1", &HEX[..31]),
        format!("wrap.{HEX}0.42.skw1"),
        "wrap.0123456789ABCDEF0123456789abcdef.42.skw1".to_owned(),
        format!("wrap.subject:{HEX}.42.skw1"),
        format!("WRAP.{HEX}.42.skw1"),
    ];
    for candidate in refused {
        assert_eq!(
            SubjectKeyArtifactName::parse(candidate.as_bytes()),
            None,
            "{candidate}"
        );
    }
    let mut invalid_utf8 = format!("wrap.{HEX}.42.skw1").into_bytes();
    invalid_utf8[5] = 0xff;
    assert_eq!(SubjectKeyArtifactName::parse(&invalid_utf8), None);
}

#[test]
fn only_the_two_dot_entries_are_skipped() {
    assert!(is_dot(c"."));
    assert!(is_dot(c".."));
    assert!(!is_dot(c"..."));
    assert!(!is_dot(c".tmp"));
    assert!(!is_dot(c""));
}

#[test]
fn stage_interruptions_leave_only_states_that_p5_recovers() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let directory = root.0.join("pigloros").join(DIRECTORY_NAME);
    let first = name(Wrap, 1)?;
    let mut observed = Vec::new();
    guard.stage_observing(&first, b"staged", |stage| {
        observed.push(stage);
        Ok(())
    })?;
    assert_eq!(observed, STAGES);
    for (epoch, stop) in (2..).zip(STAGES) {
        let staged = name(Binding, epoch)?;
        let result = guard.stage_observing(&staged, b"binding", |stage| {
            if stage == stop {
                Err(io::ErrorKind::Other.into())
            } else {
                Ok(())
            }
        });
        assert_eq!(result, Err(UNAVAILABLE));
        let canonical = directory.join(staged.canonical());
        if matches!(stop, CommitStage::Renamed | CommitStage::DirectorySynced) {
            // The outcome is unconfirmed; P5 deletes canonical names it staged.
            assert_eq!(fs::read(&canonical)?, b"binding");
        } else {
            assert!(!canonical.exists());
        }
        assert!(!directory.join(staged.temporary()).exists());
    }
    assert_eq!(fs::read(directory.join(first.canonical()))?, b"staged");
    Ok(())
}

#[test]
fn a_regular_entry_replaced_after_listing_is_refused() -> TestResult {
    let root = Sandbox::new()?;
    let guard = SubjectEncryptorLock::acquire(&root.0)?;
    let directory = guard.admit_artifact_directory()?;
    let path = root.0.join("pigloros").join(DIRECTORY_NAME);
    write_private(&path.join("listed"), b"listed")?;
    write_private(&path.join("opened"), b"opened")?;
    let listed = rustix::fs::statat(&directory, "listed", AtFlags::SYMLINK_NOFOLLOW)?;
    assert_eq!(
        read_regular(&directory, c"opened", &listed)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(
        read_regular(&directory, c"listed", &listed)?,
        SubjectKeyArtifactContent::Regular {
            identity: [listed.st_dev, listed.st_ino],
            bytes: b"listed".to_vec(),
        }
    );
    Ok(())
}
