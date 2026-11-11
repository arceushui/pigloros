#![cfg(windows)]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::path::PathBuf;

use pos_owner_bridge::ProcessIdentity;
use pos_owner_bridge_codec::ImagePathSha256;

use super::{
    browser_candidate_from_observations, renderer_presence_from_observations,
    verified_exit_observation, COREWEBVIEW2_PROCESS_KIND, COREWEBVIEW2_PROCESS_KIND_BROWSER,
    COREWEBVIEW2_PROCESS_KIND_RENDERER,
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

type Snapshot = Result<Vec<(u32, COREWEBVIEW2_PROCESS_KIND)>, ()>;

fn modeled_presence(
    snapshots: Vec<Snapshot>,
    identities: Vec<(u32, IdentityObservation)>,
) -> (Result<crate::RendererPresence, ()>, Vec<&'static str>) {
    let calls = RefCell::new(Vec::new());
    let mut snapshots = snapshots.into_iter();
    let mut identities = identities.into_iter();
    let result = renderer_presence_from_observations(
        identity(),
        || {
            calls.borrow_mut().push("snapshot");
            snapshots.next().unwrap_or(Err(()))
        },
        |pid| {
            calls
                .borrow_mut()
                .push(if pid == 11 { "browser" } else { "renderer" });
            let (expected_pid, observed) = identities.next().unwrap_or((0, Err(())));
            assert_eq!(pid, expected_pid);
            observed
        },
    );
    (result, calls.into_inner())
}

fn browser_entry() -> (u32, COREWEBVIEW2_PROCESS_KIND) {
    (11, COREWEBVIEW2_PROCESS_KIND_BROWSER)
}

fn renderer_entry() -> (u32, COREWEBVIEW2_PROCESS_KIND) {
    (12, COREWEBVIEW2_PROCESS_KIND_RENDERER)
}

fn renderer_image() -> (ProcessIdentity, PathBuf) {
    let mut renderer = identity();
    renderer.browser_pid = 12;
    (renderer, PathBuf::from("owned-browser"))
}

#[test]
fn modeled_renderer_presence_rechecks_the_exact_snapshot_and_identities() {
    let browser = process_image();
    let renderer = renderer_image();
    let absent = vec![browser_entry()];
    let (result, calls) = modeled_presence(
        vec![Ok(absent.clone()), Ok(absent)],
        vec![
            (11, Ok(Some(browser.clone()))),
            (11, Ok(Some(browser.clone()))),
        ],
    );
    assert_eq!(result, Ok(crate::RendererPresence::Absent));
    assert_eq!(calls, ["snapshot", "browser", "snapshot", "browser"]);

    let present = vec![browser_entry(), renderer_entry()];
    let (result, calls) = modeled_presence(
        vec![Ok(present.clone()), Ok(present)],
        vec![
            (11, Ok(Some(browser.clone()))),
            (12, Ok(Some(renderer.clone()))),
            (11, Ok(Some(browser))),
            (12, Ok(Some(renderer))),
        ],
    );
    assert_eq!(result, Ok(crate::RendererPresence::Unique));
    assert_eq!(
        calls,
        ["snapshot", "browser", "renderer", "snapshot", "browser", "renderer"]
    );
}

#[test]
fn modeled_renderer_presence_refuses_initial_snapshot_or_browser_failures() {
    for first in [
        Err(()),
        Ok(vec![]),
        Ok(vec![(99, COREWEBVIEW2_PROCESS_KIND_BROWSER)]),
        Ok(vec![
            browser_entry(),
            (99, COREWEBVIEW2_PROCESS_KIND_BROWSER),
        ]),
    ] {
        let (result, calls) = modeled_presence(vec![first], vec![]);
        assert_eq!(result, Err(()));
        assert_eq!(calls, ["snapshot"]);
    }
    let mut changed = identity();
    changed.creation_filetime += 1;
    for observed in [
        Err(()),
        Ok(None),
        Ok(Some((changed, PathBuf::from("owned-browser")))),
    ] {
        let (result, calls) =
            modeled_presence(vec![Ok(vec![browser_entry()])], vec![(11, observed)]);
        assert_eq!(result, Err(()));
        assert_eq!(calls, ["snapshot", "browser"]);
    }
}

#[test]
fn modeled_renderer_presence_refuses_ambiguous_absent_or_foreign_renderer() {
    let browser = process_image();
    let (result, calls) = modeled_presence(
        vec![Ok(vec![
            browser_entry(),
            renderer_entry(),
            (13, COREWEBVIEW2_PROCESS_KIND_RENDERER),
        ])],
        vec![(11, Ok(Some(browser.clone())))],
    );
    assert_eq!(result, Err(()));
    assert_eq!(calls, ["snapshot", "browser"]);
    for observed in [
        Err(()),
        Ok(None),
        Ok(Some((renderer_image().0, PathBuf::from("foreign")))),
    ] {
        let (result, calls) = modeled_presence(
            vec![Ok(vec![browser_entry(), renderer_entry()])],
            vec![(11, Ok(Some(browser.clone()))), (12, observed)],
        );
        assert_eq!(result, Err(()));
        assert_eq!(calls, ["snapshot", "browser", "renderer"]);
    }
}

#[test]
fn modeled_renderer_presence_refuses_changed_second_observations() {
    let browser = process_image();
    let renderer = renderer_image();
    let present = vec![browser_entry(), renderer_entry()];
    for second in [
        Err(()),
        Ok(vec![]),
        Ok(vec![(99, COREWEBVIEW2_PROCESS_KIND_BROWSER)]),
    ] {
        let (result, calls) = modeled_presence(
            vec![Ok(present.clone()), second],
            vec![
                (11, Ok(Some(browser.clone()))),
                (12, Ok(Some(renderer.clone()))),
            ],
        );
        assert_eq!(result, Err(()));
        assert_eq!(calls, ["snapshot", "browser", "renderer", "snapshot"]);
    }
    let mut changed = browser.clone();
    changed.0.creation_filetime += 1;
    for observed in [
        Err(()),
        Ok(None),
        Ok(Some(changed)),
        Ok(Some((browser.0, PathBuf::from("changed-browser")))),
    ] {
        let (result, calls) = modeled_presence(
            vec![Ok(present.clone()), Ok(present.clone())],
            vec![
                (11, Ok(Some(browser.clone()))),
                (12, Ok(Some(renderer.clone()))),
                (11, observed),
            ],
        );
        assert_eq!(result, Err(()));
        assert_eq!(
            calls,
            ["snapshot", "browser", "renderer", "snapshot", "browser"]
        );
    }
    for second in [
        vec![browser_entry()],
        vec![browser_entry(), (13, COREWEBVIEW2_PROCESS_KIND_RENDERER)],
        vec![
            browser_entry(),
            renderer_entry(),
            (13, COREWEBVIEW2_PROCESS_KIND_RENDERER),
        ],
    ] {
        let (result, calls) = modeled_presence(
            vec![Ok(present.clone()), Ok(second)],
            vec![
                (11, Ok(Some(browser.clone()))),
                (12, Ok(Some(renderer.clone()))),
                (11, Ok(Some(browser.clone()))),
            ],
        );
        assert_eq!(result, Err(()));
        assert_eq!(
            calls,
            ["snapshot", "browser", "renderer", "snapshot", "browser"]
        );
    }
    let mut changed_renderer = renderer.clone();
    changed_renderer.0.creation_filetime += 1;
    for observed in [
        Err(()),
        Ok(None),
        Ok(Some(changed_renderer)),
        Ok(Some((renderer.0, PathBuf::from("changed-renderer")))),
    ] {
        let (result, calls) = modeled_presence(
            vec![Ok(present.clone()), Ok(present.clone())],
            vec![
                (11, Ok(Some(browser.clone()))),
                (12, Ok(Some(renderer.clone()))),
                (11, Ok(Some(browser.clone()))),
                (12, observed),
            ],
        );
        assert_eq!(result, Err(()));
        assert_eq!(
            calls,
            ["snapshot", "browser", "renderer", "snapshot", "browser", "renderer"]
        );
    }
}

#[test]
fn modeled_exit_observation_requires_matching_identity_and_image_before_exit_query() {
    let expected = process_image();
    let mut different_identity = expected.0;
    different_identity.creation_filetime += 1;
    for observation in [
        Err(()),
        Ok((expected.0, PathBuf::from("different-browser"))),
        Ok((different_identity, expected.1.clone())),
        Ok((different_identity, PathBuf::from("different-browser"))),
    ] {
        let calls = RefCell::new(Vec::new());
        let result = verified_exit_observation(
            expected.0,
            &expected.1,
            || {
                calls.borrow_mut().push("identity");
                observation
            },
            || {
                calls.borrow_mut().push("exit");
                Ok(Some(0x535))
            },
        );
        assert_eq!(result, Err(()));
        assert_eq!(calls.into_inner(), ["identity"]);
    }
    for exit in [Ok(None), Ok(Some(0x535)), Err(())] {
        let calls = RefCell::new(Vec::new());
        let result = verified_exit_observation(
            expected.0,
            &expected.1,
            || {
                calls.borrow_mut().push("identity");
                Ok(expected.clone())
            },
            || {
                calls.borrow_mut().push("exit");
                exit
            },
        );
        assert_eq!(result, exit);
        assert_eq!(calls.into_inner(), ["identity", "exit"]);
    }
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
