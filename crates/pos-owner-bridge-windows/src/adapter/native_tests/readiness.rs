#![cfg(windows)]
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant};

use pos_owner_bridge::{
    cleanup_record_bytes, folder_name, CleanupStore, LoopbackPort, NavigationId, OwnerWebSurface,
    PostGuard, ProcessIdentity, RequestImage, SurfaceEvent, SurfaceSpec, SystemClock,
};
use pos_owner_bridge_codec::{
    CeremonyId, CeremonyKind, ControlState, GetOptionsV1, OwnerBridgeControlV1, PrfInput,
    WebAuthnChallenge,
};

use super::super::{loopback::SharedLoopback, store::WindowsCleanupStore, surface::Surface};
use super::TestResult;
use crate::{NativeFactory, NativePulse, StaPump};

const WORKERS: usize = 4;
const RUNS_PER_WORKER: usize = 250;

pub(super) fn run(runtime_path: &Path, root: &Path) -> TestResult {
    let loopback = SharedLoopback::start()?;
    let foreground = Arc::new(Mutex::new(()));
    let mut workers = Vec::new();
    for worker in 0..WORKERS {
        let path = runtime_path.to_path_buf();
        let root = root.join(format!("readiness-{worker}"));
        let loopback = loopback.clone();
        let foreground = Arc::clone(&foreground);
        workers.push(thread::spawn(move || {
            run_worker(&path, root, loopback, &foreground, worker)
                .map_err(|error| error.to_string())
        }));
    }
    // Join every STA even if an earlier worker failed. Only the final aggregate
    // decides the fixture result; a dropped JoinHandle must not detach an owner.
    let mut results = Vec::new();
    for worker in workers {
        results.push(worker.join());
    }
    let mut completed = 0;
    let mut reports = Vec::new();
    for (worker, result) in results.into_iter().enumerate() {
        let result = result.map_or_else(
            |_| Err(format!("readiness STA worker {worker} panicked")),
            std::convert::identity,
        );
        writeln!(
            std::io::stderr(),
            "NATIVE_READINESS worker={worker} result={result:?}"
        )?;
        reports.push(result);
    }
    for result in reports {
        completed += result?;
    }
    assert_eq!(completed, 1_000);
    Ok(())
}

fn run_worker(
    runtime_path: &Path,
    root: PathBuf,
    mut loopback: SharedLoopback,
    foreground: &Mutex<()>,
    worker: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    crate::create_private_directory(&root)?;
    let runtime = Arc::new(crate::verify_fixed_runtime(runtime_path, &root)?);
    let factory = Rc::new(crate::Native::owner_factory()?);
    let shared_factory: Rc<dyn NativeFactory> = factory.clone();
    let mut store = WindowsCleanupStore::open(root.clone())?;
    let mut surface = Surface::new(
        shared_factory,
        runtime,
        root,
        Box::new(loopback.clone()),
        Box::new(store.clone()),
        Box::new(SystemClock),
    )
    .map_err(pos_owner_bridge::SurfaceError::error)?;
    for iteration in 0..RUNS_PER_WORKER {
        let number = u64::try_from(worker * RUNS_PER_WORKER + iteration + 1)?;
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&number.to_le_bytes());
        let started = Instant::now();
        run_ceremony(
            &mut surface,
            &mut loopback,
            &mut store,
            foreground,
            CeremonyId::from_bytes(bytes),
        )
        .map_err(|error| format!(
            "native readiness worker {worker} case {number}, {iteration} completed, elapsed={:?}: {error}",
            started.elapsed()
        ))?;
    }
    drop(surface);
    assert!(store.records()?.is_empty());
    assert!(store.folders()?.is_empty());
    drop(store);
    // All sessions and their COM objects have gone before this creating STA.
    let mut factory = Rc::try_unwrap(factory).map_err(|_| "readiness factory still shared")?;
    factory.stop()?;
    Ok(RUNS_PER_WORKER)
}

fn run_ceremony(
    surface: &mut Surface,
    loopback: &mut SharedLoopback,
    store: &mut WindowsCleanupStore,
    foreground: &Mutex<()>,
    id: CeremonyId,
) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(15);
    surface.set_deadline(deadline);
    let spec = SurfaceSpec {
        ceremony_id: id,
        folder_name: folder_name(&id),
        owner_window: None,
    };
    let (identity, visible) = open(surface, &spec, foreground, deadline)?;
    let record = cleanup_record_bytes(id, &spec.folder_name, &identity)?;
    store.write_record(&record)?;
    loopback.probe_ipv6()?;
    loopback.begin_navigation();
    let navigation = navigate(surface, deadline)?;
    await_event(
        surface,
        deadline,
        SurfaceEvent::DomContentLoaded(navigation),
    )?;
    assert_eq!(loopback.served().count, 1);
    assert!(loopback.served().integrity_ok);
    receive(surface, id, navigation, deadline)?;
    assert!(
        Instant::now() < deadline,
        "readiness exceeded the original T0 bound"
    );
    cancel(surface)?;
    surface
        .close_controller()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    // Only showing/navigation/posting need the shared foreground. Environment
    // creation and exact browser-exit cleanup remain concurrent, on separate STAs.
    drop(visible);
    await_event(
        surface,
        Instant::now() + Duration::from_secs(5),
        SurfaceEvent::BrowserExited {
            browser_pid: identity.browser_pid,
        },
    )?;
    surface
        .finish()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    store.delete_record(&record)?;
    assert!(surface.idle());
    Ok(())
}

fn open<'a>(
    surface: &mut Surface,
    spec: &SurfaceSpec,
    foreground: &'a Mutex<()>,
    deadline: Instant,
) -> Result<(ProcessIdentity, MutexGuard<'a, ()>), Box<dyn std::error::Error>> {
    loop {
        let stage = match foreground.try_lock() {
            Ok(visible) => match surface.open(spec) {
                Poll::Ready(result) => {
                    return Ok((
                        result.map_err(pos_owner_bridge::SurfaceError::error)?,
                        visible,
                    ));
                }
                Poll::Pending => {
                    drop(visible);
                    "waiting for native opening completion"
                }
            },
            Err(TryLockError::WouldBlock) => "waiting for the foreground coordination gate",
            Err(TryLockError::Poisoned(_)) => {
                return Err("readiness foreground lock poisoned".into())
            }
        };
        pump(surface, deadline, stage)?;
    }
}

fn navigate(
    surface: &mut Surface,
    deadline: Instant,
) -> Result<NavigationId, Box<dyn std::error::Error>> {
    loop {
        if let Poll::Ready(result) = surface.navigate() {
            return result
                .map_err(pos_owner_bridge::SurfaceError::error)
                .map_err(Into::into);
        }
        pump(surface, deadline, "waiting for the native navigation ID")?;
    }
}

fn await_event(surface: &mut Surface, deadline: Instant, expected: SurfaceEvent) -> TestResult {
    let stage = format!("waiting for {expected:?}");
    loop {
        if let Some(event) = surface.take_event() {
            assert_eq!(event, expected);
            return Ok(());
        }
        pump(surface, deadline, &stage)?;
    }
}

fn pump(surface: &Surface, deadline: Instant, stage: &str) -> TestResult {
    if Instant::now() >= deadline {
        return Err(format!("native readiness fixture deadline expired while {stage}").into());
    }
    if surface.pump()? == NativePulse::Quit {
        return Err(format!("native readiness STA received quit while {stage}").into());
    }
    Ok(())
}

fn receive(
    surface: &mut Surface,
    id: CeremonyId,
    navigation: NavigationId,
    deadline: Instant,
) -> TestResult {
    let options = GetOptionsV1::new(
        id,
        WebAuthnChallenge::from_bytes([2; 32]),
        &[0x80, 0x81],
        PrfInput::from_bytes([3; 32]),
    )
    .map_err(|error| error.to_string())?;
    let mut request = RequestImage::zeroed();
    let length =
        pos_owner_bridge_codec::encode_get_options(&options, &mut request.as_mut_bytes()[64..])
            .map_err(|error| error.to_string())?;
    for (attempt, millis) in [250, 250, 500, 500, 1_000, 1_000, 2_000, 2_000]
        .into_iter()
        .enumerate()
    {
        let generation = u32::try_from(attempt + 1)?;
        let header = OwnerBridgeControlV1::new_request(
            CeremonyKind::Get,
            generation,
            id,
            u32::try_from(length)?,
        )
        .map_err(|error| error.to_string())?
        .encode();
        request.as_mut_bytes()[..64].copy_from_slice(&header);
        let reply = OwnerBridgeControlV1::new_reply(CeremonyKind::Get, generation, id)
            .map_err(|error| error.to_string())?
            .encode();
        surface
            .create_and_write(&request, &reply)
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        surface
            .post(&PostGuard {
                generation,
                navigation_id: navigation,
                served_count: 1,
            })
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        let receipt = (Instant::now() + Duration::from_millis(millis)).min(deadline);
        while surface
            .reply_load_state()
            .map_err(pos_owner_bridge::SurfaceError::error)?
            == ControlState::Empty as u32
            && Instant::now() < receipt
        {
            pump(surface, deadline, "waiting for packaged Get receipt")?;
        }
        if surface
            .reply_load_state()
            .map_err(pos_owner_bridge::SurfaceError::error)?
            != ControlState::Empty as u32
            || !surface
                .reply_compare_exchange(
                    ControlState::Empty as u32,
                    ControlState::ReleaseRequested as u32,
                )
                .map_err(pos_owner_bridge::SurfaceError::error)?
        {
            return Ok(());
        }
        surface
            .zero_close_buffers()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
    }
    Err("packaged page lost all eight readiness pairs".into())
}

fn cancel(surface: &mut Surface) -> TestResult {
    let mut retired = false;
    for _ in 0..8 {
        let state = surface
            .reply_load_state()
            .map_err(pos_owner_bridge::SurfaceError::error)?;
        assert!([1, 2, 6, 7].contains(&state));
        if surface
            .reply_compare_exchange(state, ControlState::ReleaseRequested as u32)
            .map_err(pos_owner_bridge::SurfaceError::error)?
        {
            retired = true;
            break;
        }
    }
    assert!(retired, "native readiness cancellation CAS bound exhausted");
    let deadline = Instant::now() + Duration::from_secs(2);
    while surface
        .reply_load_state()
        .map_err(pos_owner_bridge::SurfaceError::error)?
        != ControlState::Releasing as u32
    {
        pump(surface, deadline, "waiting for Get release acknowledgement")?;
    }
    surface
        .zero_close_buffers()
        .map_err(pos_owner_bridge::SurfaceError::error)?;
    Ok(())
}
