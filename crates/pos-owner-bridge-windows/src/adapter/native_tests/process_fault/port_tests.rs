#![cfg(windows)]
#![forbid(unsafe_code)]

//! Public port calls exercise the harness wrappers with modeled native operations.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::rc::Rc;
use std::task::Poll;
use std::time::{Duration, Instant};

use pos_owner_bridge::{
    cleanup_record_bytes, BridgeError, CleanupStore, NavigationId, OwnerWebSurface, PostGuard,
    ProcessIdentity, ReplyImage, RequestImage, SurfaceError, SurfaceEvent, UnavailableCode,
};
use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, ControlState, ImagePathSha256, OwnerBridgeControlV1,
};

use super::{
    fixed_competing_spec, model_tests::fixture, BeforeRecordStore, ConsumingPort, FixtureRoot,
    SharedSurfacePort, TestResult,
};
use crate::adapter::surface::tests::native::Factory;
use crate::{
    NativeAction, NativeEvent, ProcessFaultPhase, ProcessFaultState, ProcessFaultTarget,
    ProcessFaultTopology,
};

const MODEL_CASE: u8 = 240;
const ERROR: BridgeError = BridgeError::Unavailable(UnavailableCode::InterfaceUnavailable);

fn navigate_port(port: &mut dyn OwnerWebSurface, model: &Factory) -> TestResult {
    let spec = fixed_competing_spec(MODEL_CASE);
    assert!(port.open(&spec).is_pending());
    assert!(port.open(&spec).is_pending());
    assert_eq!(port.open(&spec), Poll::Ready(Ok(identity())));
    model.navigation_succeeds.set(true);
    assert!(port.navigate().is_pending());
    let sink = model.sink.borrow().clone().ok_or("missing modeled sink")?;
    assert_eq!(
        sink.event(NativeEvent::Navigation {
            uri: crate::NativeText::fixture(crate::OWNER_URL),
            id: 7,
            redirected: false,
        }),
        NativeAction::Allow
    );
    let _action = sink.event(NativeEvent::DomLoaded {
        id: 7,
        uri: crate::NativeText::fixture(crate::OWNER_URL),
    });
    assert_eq!(port.navigate(), Poll::Ready(Ok(NavigationId(7))));
    assert_eq!(
        port.take_event(),
        Some(SurfaceEvent::DomContentLoaded(NavigationId(7)))
    );
    // Exercise the real shared listener's served-count prerequisite for posting.
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, 49_291))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n")?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    Ok(())
}

const fn identity() -> ProcessIdentity {
    ProcessIdentity {
        browser_pid: 42,
        creation_filetime: 1,
        image_path_sha256: ImagePathSha256::from_bytes([7; 32]),
    }
}

fn query_failures(port: &dyn OwnerWebSurface, model: &Factory) {
    model.failure.set(Some("load_state"));
    assert_eq!(
        port.reply_load_state().map_err(SurfaceError::error),
        Err(ERROR)
    );
    model.failure.set(Some("compare_exchange"));
    assert_eq!(
        port.reply_compare_exchange(0, 1)
            .map_err(SurfaceError::error),
        Err(ERROR)
    );
    model.failure.set(Some("copy_reply"));
    let mut reply = ReplyImage::zeroed();
    reply.as_mut_bytes().fill(0xa5);
    assert_eq!(
        port.reply_copy(&mut reply).map_err(SurfaceError::error),
        Err(ERROR)
    );
    assert!(reply.as_bytes().iter().all(|byte| *byte == 0xa5));
    model.failure.set(None);
}

fn exercise_port(port: &mut dyn OwnerWebSurface, model: &Factory) -> TestResult {
    navigate_port(port, model)?;
    let id = CeremonyId::from_bytes([MODEL_CASE; 16]);
    let request_header = OwnerBridgeControlV1::new_request(CeremonyKind::Create, 1, id, 1)
        .map_err(|error| error.to_string())?
        .encode();
    let reply_header = OwnerBridgeControlV1::new_reply(CeremonyKind::Create, 1, id)
        .map_err(|error| error.to_string())?
        .encode();
    let mut request = RequestImage::zeroed();
    request.as_mut_bytes()[..64].copy_from_slice(&request_header);
    port.create_and_write(&request, &reply_header)
        .map_err(SurfaceError::error)?;
    port.post(&PostGuard {
        generation: 1,
        navigation_id: NavigationId(7),
        served_count: 1,
    })
    .map_err(SurfaceError::error)?;
    assert_eq!(port.reply_load_state(), Ok(ControlState::Empty as u32));
    assert_eq!(
        port.reply_compare_exchange(ControlState::Empty as u32, ControlState::Received as u32),
        Ok(true)
    );
    assert_eq!(
        port.reply_compare_exchange(ControlState::Empty as u32, ControlState::Ready as u32),
        Ok(false)
    );
    assert_eq!(port.reply_load_state(), Ok(ControlState::Received as u32));
    let mut reply = ReplyImage::zeroed();
    port.reply_copy(&mut reply).map_err(SurfaceError::error)?;
    assert!(reply.as_bytes().iter().all(|byte| *byte == 0x5a));
    query_failures(port, model);
    port.zero_close_buffers().map_err(SurfaceError::error)?;
    port.close_controller().map_err(SurfaceError::error)?;
    let sink = model.sink.borrow().clone().ok_or("missing modeled sink")?;
    let _action = sink.event(NativeEvent::BrowserExited { pid: 42 });
    assert_eq!(
        port.take_event(),
        Some(SurfaceEvent::BrowserExited { browser_pid: 42 })
    );
    port.finish().map_err(SurfaceError::error)?;
    let calls = model.calls.borrow();
    let posts: Vec<_> = calls
        .iter()
        .copied()
        .filter(|call| call.starts_with("post_"))
        .collect();
    assert_eq!(posts, ["post_request", "post_reply"]);
    for expected in [
        "create_window",
        "create_environment",
        "create_controller",
        "navigate",
        "create_buffers",
        "close_buffers",
        "close_controller",
        "unsubscribe_exit",
        "drop_environment",
        "destroy_window",
    ] {
        assert!(
            calls.contains(&expected),
            "missing modeled delegation {expected}"
        );
    }
    Ok(())
}

#[test]
fn consuming_port_delegates_without_intervening_before_the_consuming_exchange() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    {
        let mut port = ConsumingPort {
            inner: RefCell::new(&mut fixture.surface),
            target: ProcessFaultTarget::Browser,
            inject: false,
            deadline: fixture.deadline,
            trace: Rc::clone(&fixture.trace),
            state: ProcessFaultState {
                phase: ProcessFaultPhase::PostedReceipt,
                topology: ProcessFaultTopology::SealedSingleViewFrameFree,
                generation: 1,
                reply_state: ControlState::Received as u32,
                record_count: 1,
                posts: 1,
            },
            handle: RefCell::new(None),
            failure: RefCell::new(None),
            reached: RefCell::new(false),
        };
        exercise_port(&mut port, &model)?;
        assert!(!*port.reached.borrow());
        assert!(port.handle.borrow().is_none());
        assert!(port.failure.borrow().is_none());
        assert!(port.trace.borrow().is_empty());
    }
    assert!(fixture.surface.idle());
    drop(fixture);
    root.remove()
}

#[test]
fn shared_surface_port_preserves_modeled_calls_and_results() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, model) = fixture(&root)?;
    {
        let surface = RefCell::new(&mut fixture.surface);
        let mut port = SharedSurfacePort { inner: &surface };
        exercise_port(&mut port, &model)?;
    }
    assert!(fixture.surface.idle());
    assert!(fixture.trace.borrow().is_empty());
    drop(fixture);
    root.remove()
}

#[test]
fn before_record_store_preserves_durable_results_after_a_failed_observation() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let root = FixtureRoot::new()?;
    let (mut fixture, _model) = fixture(&root)?;
    let id = CeremonyId::from_bytes([MODEL_CASE; 16]);
    let folder = pos_owner_bridge::folder_name(&id);
    let bytes = cleanup_record_bytes(id, &folder, &identity())?;
    crate::create_private_directory(&root.0.join(&folder))?;
    {
        let surface = RefCell::new(&mut fixture.surface);
        let mut port = BeforeRecordStore {
            inner: &mut fixture.store,
            surface: &surface,
            inject: false,
            target: ProcessFaultTarget::Browser,
            presence: None,
            deadline: Instant::now(),
            trace: Rc::clone(&fixture.trace),
            handle: None,
            failure: None,
            reached: false,
            written: false,
            generation: 1,
            posts: 0,
            ceremony_id: id,
        };
        port.write_record(&bytes)?;
        assert!(port.written);
        assert!(!port.reached);
        assert!(port.handle.is_none());
        assert_eq!(port.failure, Some("pre-record fault evidence failed"));
        assert_eq!(port.records()?.as_slice(), std::slice::from_ref(&bytes));
        assert_eq!(port.folders()?.as_slice(), std::slice::from_ref(&folder));
        port.delete_record(&bytes)?;
        assert!(port.records()?.is_empty());
        port.remove_folder(&folder)?;
        assert!(port.folders()?.is_empty());
        assert_eq!(port.write_record(&[]), Err(pos_owner_bridge::CleanupError));
        assert!(!port.written);
        assert_eq!(
            *port.trace.borrow(),
            [crate::ProcessFaultMark::RecordWritten]
        );
    }
    assert!(fixture.surface.idle());
    drop(fixture);
    root.remove()
}

#[test]
fn modeled_pre_record_observation_requires_matching_driver_and_record_identity() -> TestResult {
    let _port = crate::Native::fixed_port_fixture();
    let selected = fixed_competing_spec(MODEL_CASE);
    let other = fixed_competing_spec(MODEL_CASE + 1);
    let ceremony = selected.ceremony_id;
    let folder = selected.folder_name.as_str();
    let other_ceremony = other.ceremony_id;
    let other_folder = other.folder_name.as_str();
    let wrong_pid = ProcessIdentity {
        browser_pid: 43,
        ..identity()
    };
    let wrong_creation = ProcessIdentity {
        creation_filetime: 2,
        ..identity()
    };
    let wrong_image = ProcessIdentity {
        image_path_sha256: ImagePathSha256::from_bytes([8; 32]),
        ..identity()
    };
    let mismatch = Some("pre-record proposed identity or driver state mismatched");
    let cases = [
        (1, 0, ceremony, folder, identity(), None),
        (2, 0, ceremony, folder, identity(), mismatch),
        (1, 1, ceremony, folder, identity(), mismatch),
        (1, 0, other_ceremony, folder, identity(), mismatch),
        (1, 0, ceremony, other_folder, identity(), mismatch),
        (1, 0, ceremony, folder, wrong_pid, mismatch),
        (1, 0, ceremony, folder, wrong_creation, mismatch),
        (1, 0, ceremony, folder, wrong_image, mismatch),
    ];
    for (generation, posts, record_ceremony, record_folder, record_identity, expected) in cases {
        let record = cleanup_record_bytes(record_ceremony, record_folder, &record_identity)?;
        let root = FixtureRoot::new()?;
        let (mut fixture, model) = fixture(&root)?;
        model.preload_owners.set(true);
        assert!(fixture.surface.open(&selected).is_pending());
        assert!(fixture.surface.open(&selected).is_pending());
        assert_eq!(fixture.surface.open(&selected), Poll::Ready(Ok(identity())));
        assert_eq!(fixture.surface.before_record_fault_state(), Ok(identity()));
        assert!(fixture.surface.before_record_owners_retained());
        {
            let surface = RefCell::new(&mut fixture.surface);
            let mut port = BeforeRecordStore {
                inner: &mut fixture.store,
                surface: &surface,
                inject: false,
                target: ProcessFaultTarget::Browser,
                presence: None,
                deadline: fixture.deadline,
                trace: Rc::clone(&fixture.trace),
                handle: None,
                failure: None,
                reached: false,
                written: false,
                generation,
                posts,
                ceremony_id: selected.ceremony_id,
            };
            let error = port.on_write(&record).err().map(|error| error.to_string());
            assert_eq!(error.as_deref(), expected);
            assert_eq!(port.reached, expected.is_none());
            assert!(port.handle.is_none());
            assert!(!port.written);
            assert!(port.failure.is_none());
            assert!(port.records()?.is_empty());
            assert!(surface.borrow_mut().before_record_owners_retained());
            if expected.is_none() {
                assert_eq!(
                    port.trace.borrow().as_slice(),
                    &[crate::ProcessFaultMark::BeforeRecord {
                        generation: 1,
                        record_count: 0
                    }]
                );
                let repeated = port.on_write(&record).err().map(|error| error.to_string());
                assert_eq!(repeated.as_deref(), Some("record write observed twice"));
                assert_eq!(port.trace.borrow().len(), 1);
            } else {
                assert!(port.trace.borrow().is_empty());
            }
        }
        for call in ["navigate", "create_buffers", "post"] {
            assert!(!model.calls.borrow().contains(&call));
        }
        fixture
            .surface
            .close_controller()
            .map_err(SurfaceError::error)?;
        let sink = model.sink.borrow().clone().ok_or("missing modeled sink")?;
        let _action = sink.event(NativeEvent::BrowserExited { pid: 42 });
        fixture.surface.finish().map_err(SurfaceError::error)?;
        assert!(fixture.surface.idle());
        drop(fixture);
        root.remove()?;
    }
    Ok(())
}
