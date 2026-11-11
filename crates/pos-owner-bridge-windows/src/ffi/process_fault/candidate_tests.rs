#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::path::PathBuf;

use pos_owner_bridge::ProcessIdentity;
use pos_owner_bridge_codec::ImagePathSha256;

use super::{
    browser_candidate_from_observations, COREWEBVIEW2_PROCESS_KIND,
    COREWEBVIEW2_PROCESS_KIND_BROWSER, COREWEBVIEW2_PROCESS_KIND_RENDERER,
};

type IdentityObservation = Result<Option<(ProcessIdentity, PathBuf)>, ()>;

fn identity() -> ProcessIdentity {
    ProcessIdentity {
        browser_pid: 11,
        creation_filetime: 27,
        image_path_sha256: ImagePathSha256::from_bytes([3; 32]),
    }
}

fn process_image() -> (ProcessIdentity, PathBuf) {
    (identity(), PathBuf::from("owned-browser"))
}

fn observe(
    first: &[(u32, COREWEBVIEW2_PROCESS_KIND)],
    second: Result<Vec<(u32, COREWEBVIEW2_PROCESS_KIND)>, ()>,
    identities: [IdentityObservation; 2],
) -> (Result<ProcessIdentity, ()>, Vec<&'static str>) {
    let calls = RefCell::new(Vec::new());
    let mut identities = identities.into_iter();
    let result = browser_candidate_from_observations(
        first,
        || {
            calls.borrow_mut().push("snapshot");
            second
        },
        |pid| {
            assert_eq!(pid, 11);
            calls.borrow_mut().push("identity");
            identities.next().unwrap_or(Err(()))
        },
    );
    (result, calls.into_inner())
}

#[test]
fn candidate_requires_two_stable_snapshots_and_identity_reads_in_order() {
    let entries = [
        (11, COREWEBVIEW2_PROCESS_KIND_BROWSER),
        (12, COREWEBVIEW2_PROCESS_KIND_RENDERER),
    ];
    let (result, calls) = observe(
        &entries,
        Ok(entries.to_vec()),
        [Ok(Some(process_image())), Ok(Some(process_image()))],
    );
    assert_eq!(result, Ok(identity()));
    assert_eq!(calls, ["identity", "snapshot", "identity"]);
}

#[test]
fn candidate_refuses_missing_or_ambiguous_initial_browser_before_observation() {
    for first in [
        Vec::new(),
        vec![(12, COREWEBVIEW2_PROCESS_KIND_RENDERER)],
        vec![
            (11, COREWEBVIEW2_PROCESS_KIND_BROWSER),
            (12, COREWEBVIEW2_PROCESS_KIND_BROWSER),
        ],
    ] {
        let (result, calls) = observe(
            &first,
            Err(()),
            [Ok(Some(process_image())), Ok(Some(process_image()))],
        );
        assert_eq!(result, Err(()));
        assert!(calls.is_empty());
    }
}

#[test]
fn candidate_refuses_failed_or_absent_initial_identity_before_second_snapshot() {
    for first_identity in [Err(()), Ok(None)] {
        let (result, calls) = observe(
            &[(11, COREWEBVIEW2_PROCESS_KIND_BROWSER)],
            Err(()),
            [first_identity, Ok(Some(process_image()))],
        );
        assert_eq!(result, Err(()));
        assert_eq!(calls, ["identity"]);
    }
}

#[test]
fn candidate_refuses_incomplete_missing_ambiguous_or_changed_second_browser() {
    for second in [
        Err(()),
        Ok(Vec::new()),
        Ok(vec![(12, COREWEBVIEW2_PROCESS_KIND_RENDERER)]),
        Ok(vec![
            (11, COREWEBVIEW2_PROCESS_KIND_BROWSER),
            (12, COREWEBVIEW2_PROCESS_KIND_BROWSER),
        ]),
        Ok(vec![(12, COREWEBVIEW2_PROCESS_KIND_BROWSER)]),
    ] {
        let (result, calls) = observe(
            &[(11, COREWEBVIEW2_PROCESS_KIND_BROWSER)],
            second,
            [Ok(Some(process_image())), Ok(Some(process_image()))],
        );
        assert_eq!(result, Err(()));
        assert_eq!(calls, ["identity", "snapshot"]);
    }
}

#[test]
fn candidate_refuses_failed_absent_or_changed_second_identity_and_image() {
    let mut changed_pid = identity();
    changed_pid.browser_pid = 12;
    let mut changed_creation = identity();
    changed_creation.creation_filetime += 1;
    let mut changed_hash = identity();
    changed_hash.image_path_sha256 = ImagePathSha256::from_bytes([4; 32]);
    for second_identity in [
        Err(()),
        Ok(None),
        Ok(Some((changed_pid, PathBuf::from("owned-browser")))),
        Ok(Some((changed_creation, PathBuf::from("owned-browser")))),
        Ok(Some((changed_hash, PathBuf::from("owned-browser")))),
        Ok(Some((identity(), PathBuf::from("different-browser")))),
    ] {
        let (result, calls) = observe(
            &[(11, COREWEBVIEW2_PROCESS_KIND_BROWSER)],
            Ok(vec![(11, COREWEBVIEW2_PROCESS_KIND_BROWSER)]),
            [Ok(Some(process_image())), second_identity],
        );
        assert_eq!(result, Err(()));
        assert_eq!(calls, ["identity", "snapshot", "identity"]);
    }
}
