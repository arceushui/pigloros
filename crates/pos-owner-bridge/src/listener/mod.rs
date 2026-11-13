//! The loopback asset listener (ADR-110 §4): exclusive loopback sockets serving one digest-pinned
//! document with bounded concurrency, a first-byte timeout, and a served-exactly-once ledger.
//!
//! # Accepted residual risk
//!
//! At most three connections are served at once and the rest wait in the kernel backlog. A local
//! process that holds three connections open, or keeps reconnecting, can therefore delay the
//! owner page's own request for as long as it does so, until each held connection reaches its
//! first-byte (1 s), header (2 s) or write-idle (30 s) deadline. The ceremony's 15 s readiness
//! bound turns a delay that long into `Lifecycle(ReadinessTimeout)`, which the user may retry.
//! The attack cannot make the host accept a wrong document, because only the pinned bytes are
//! ever served and the served-once ledger counts completed responses; it can only deny service.
//!
//! A response still in flight from the previous navigation can raise the next navigation's
//! served count after the ledger was reset. That fails closed: the ceremony sees a spurious
//! `DuplicateDocumentLoad` and ends, and the host never accepts a wrong document.

// The seam is `bind` (the `LoopbackBinder` a platform shim implements) and the listener below.
mod assets;
pub mod bind;
mod ledger;
mod serve;

#[cfg(feature = "test-support")]
mod fixture_assets;
#[cfg(feature = "test-support")]
mod fixtures;
#[cfg(feature = "test-support")]
pub use fixtures::FixtureProfile;

#[cfg(all(test, feature = "test-support"))]
mod tests;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{BridgeError, LoopbackPort, ServedSnapshot, UnavailableCode};
use bind::{bind_loopback, check_ipv6_absent, Ipv6Mode, LoopbackBinder};
use ledger::ServedLedger;
use serve::{serve_connection, ServeContext};

/// At most this many connections are served at once; the rest wait in the kernel backlog.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 3;

/// How long an accept thread sleeps when it has no free slot or nothing to accept. The sockets
/// are non-blocking so that `shutdown` can stop the threads; a new connection therefore waits a
/// few milliseconds at most, and an idle listener costs a wake-up every 2 ms per socket.
const ACCEPT_POLL: Duration = Duration::from_millis(2);

/// Placeholder for an address that cannot be read back from a bound socket.
const UNBOUND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// The three connection deadlines of ADR-110 §4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerTimeouts {
    /// Close a connection that sends no byte within this time of `accept`.
    pub first_byte: Duration,
    /// Time allowed from the first byte to the complete header block.
    pub header: Duration,
    /// Write idle limit for the response.
    pub idle: Duration,
}

/// The ADR-110 deadlines: 1 s first byte, 2 s header block, 30 s idle.
const ADR_TIMEOUTS: ListenerTimeouts = ListenerTimeouts {
    first_byte: Duration::from_secs(1),
    header: Duration::from_secs(2),
    idle: Duration::from_secs(30),
};

/// Listener tuning. Production code can only build [`ListenerConfig::adr`], the ADR-110 deadlines
/// and the pinned response digest; other values exist for tests behind `test-support`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    timeouts: ListenerTimeouts,
    expected_digest: [u8; 32],
    response: &'static assets::Response,
}

impl ListenerConfig {
    /// The ADR-110 deadlines and the pinned response digest.
    #[must_use]
    pub const fn adr() -> Self {
        Self {
            timeouts: ADR_TIMEOUTS,
            expected_digest: assets::OWNER.digest,
            response: &assets::OWNER,
        }
    }

    /// Other deadlines or another digest, so tests can reach the failure paths quickly.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn new(timeouts: ListenerTimeouts, expected_digest: [u8; 32]) -> Self {
        Self {
            timeouts,
            expected_digest,
            response: &assets::OWNER,
        }
    }

    /// Select immutable qualification bytes, headers and digest together.
    /// This never changes the production host's asset selection.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub const fn fixture(profile: FixtureProfile) -> Self {
        let response = profile.response();
        Self {
            timeouts: ADR_TIMEOUTS,
            expected_digest: response.digest,
            response,
        }
    }

    /// The connection deadlines.
    #[must_use]
    pub const fn timeouts(&self) -> ListenerTimeouts {
        self.timeouts
    }

    /// The digest each completed owner response must match.
    #[must_use]
    pub const fn expected_digest(&self) -> &[u8; 32] {
        &self.expected_digest
    }
}

/// Aggregate diagnostic counters across the shared listener, not per navigation.
#[cfg(feature = "test-support")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerObservation {
    /// Accepted connections.
    pub accepted: usize,
    /// Accepted connections still holding a slot.
    pub handling: usize,
    /// Slots reserved, including transient accept-loop reservations.
    pub reserved: usize,
    /// Connections ending without a complete header.
    pub silent: usize,
    /// Silent reads ended by EOF.
    pub silent_eof: usize,
    /// Silent reads ended by timeout or would-block.
    pub silent_timeout: usize,
    /// Silent reads ended by another I/O failure.
    pub silent_error: usize,
    /// Connections with a complete header.
    pub complete: usize,
    /// Connections whose header filled the buffer.
    pub too_large: usize,
}

#[cfg(feature = "test-support")]
#[derive(Debug, Default)]
struct Observations {
    accepted: AtomicUsize,
    handling: AtomicUsize,
    silent: AtomicUsize,
    silent_eof: AtomicUsize,
    silent_timeout: AtomicUsize,
    silent_error: AtomicUsize,
    complete: AtomicUsize,
    too_large: AtomicUsize,
}

/// State shared by the accept threads.
#[derive(Debug, Default)]
struct Shared {
    stop: AtomicBool,
    active: AtomicUsize,
    #[cfg(feature = "test-support")]
    observations: Arc<Observations>,
}

impl Shared {
    fn try_acquire(&self) -> bool {
        self.active
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                (active < MAX_CONCURRENT_CONNECTIONS).then_some(active + 1)
            })
            .is_ok()
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One of the concurrency slots. Dropping it frees the slot, also when the worker that holds it
/// panics or could not be spawned.
struct SlotGuard {
    shared: Arc<Shared>,
    #[cfg(feature = "test-support")]
    accepted: bool,
}

impl SlotGuard {
    fn acquire(shared: &Arc<Shared>) -> Option<Self> {
        shared.try_acquire().then(|| Self {
            shared: Arc::clone(shared),
            #[cfg(feature = "test-support")]
            accepted: false,
        })
    }

    /// Stop counting an accepted connection as being handled.
    #[cfg(feature = "test-support")]
    fn finish_handling(&self) {
        if self.accepted {
            self.shared
                .observations
                .handling
                .fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        #[cfg(feature = "test-support")]
        self.finish_handling();
        self.shared.release();
    }
}

/// The work of one connection, ready to run on a thread.
type Work = Box<dyn FnOnce() + Send>;

/// Serve `stream` on a thread made by `spawn`. When `spawn` fails (resource exhaustion), the work
/// it was given is dropped, which closes the stream and frees the slot.
fn dispatch(
    stream: TcpStream,
    accepted_at: Instant,
    slot: SlotGuard,
    context: &Arc<ServeContext>,
    spawn: impl FnOnce(Work) -> io::Result<()>,
) {
    let context = Arc::clone(context);
    let work: Work = Box::new(move || {
        let _slot = slot;
        if stream.set_nonblocking(false).is_ok() {
            serve_connection(stream, accepted_at, &context);
        }
    });
    // A failed spawn has already dropped the work, so there is nothing further to do.
    drop(spawn(work));
}

fn spawn_thread(work: Work) -> io::Result<()> {
    thread::Builder::new().spawn(work).map(drop)
}

fn spawn_thread_handle(work: Work) -> io::Result<JoinHandle<()>> {
    thread::Builder::new().spawn(work)
}

/// Put each socket in its accepting mode, then start its accept thread. When a socket cannot be
/// configured or a thread cannot be spawned, the threads already started are stopped and joined,
/// so a listener never runs with only some of its sockets served.
fn start_accept_threads(
    sockets: impl IntoIterator<Item = TcpListener>,
    context: &Arc<ServeContext>,
    shared: &Arc<Shared>,
    configure: impl Fn(&TcpListener) -> io::Result<()>,
    spawn: impl Fn(Work) -> io::Result<JoinHandle<()>>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let mut workers = Vec::new();
    for socket in sockets {
        let (worker_context, worker_shared) = (Arc::clone(context), Arc::clone(shared));
        let started = configure(&socket).and_then(|()| {
            spawn(Box::new(move || {
                accept_loop(&socket, &worker_context, &worker_shared, || {
                    thread::sleep(ACCEPT_POLL);
                });
            }))
        });
        match started {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                shared.stop.store(true, Ordering::SeqCst);
                for worker in workers {
                    // A started accept thread only stops; its join result carries nothing.
                    drop(worker.join());
                }
                return Err(error);
            }
        }
    }
    Ok(workers)
}

fn accept_loop(
    listener: &TcpListener,
    context: &Arc<ServeContext>,
    shared: &Arc<Shared>,
    mut pause: impl FnMut(),
) {
    while !shared.stop.load(Ordering::SeqCst) {
        let Some(slot) = SlotGuard::acquire(shared) else {
            pause();
            continue;
        };
        #[cfg(feature = "test-support")]
        let mut slot = slot;
        let accepted = listener.accept();
        if let Ok((stream, _)) = accepted {
            let accepted_at = Instant::now();
            #[cfg(feature = "test-support")]
            {
                slot.accepted = true;
                shared.observations.accepted.fetch_add(1, Ordering::SeqCst);
                shared.observations.handling.fetch_add(1, Ordering::SeqCst);
            }
            dispatch(stream, accepted_at, slot, context, spawn_thread);
        } else {
            drop(slot);
            pause();
        }
    }
}

/// The running loopback listener. Dropping it stops the accept threads.
pub struct LoopbackListener {
    ledger: Arc<ServedLedger>,
    #[cfg(feature = "test-support")]
    received: Arc<std::sync::atomic::AtomicU64>,
    shared: Arc<Shared>,
    workers: Vec<JoinHandle<()>>,
    v4_addr: SocketAddr,
    v6_addr: Option<SocketAddr>,
    mode: Ipv6Mode,
    binder: Box<dyn LoopbackBinder>,
}

impl LoopbackListener {
    /// Bind the loopback sockets and start serving.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable(PortUnavailable)` or `Unavailable(LoopbackChanged)` as
    /// `bind_loopback` does.
    pub fn start(
        mut binder: Box<dyn LoopbackBinder>,
        config: ListenerConfig,
    ) -> Result<Self, BridgeError> {
        let sockets = bind_loopback(binder.as_mut())?;
        let v4_addr = sockets.v4.local_addr().unwrap_or(UNBOUND);
        let v6_addr = sockets
            .v6
            .as_ref()
            .and_then(|socket| socket.local_addr().ok());
        let ledger = Arc::new(ServedLedger::default());
        #[cfg(feature = "test-support")]
        let received = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let shared = Arc::new(Shared::default());
        let context = Arc::new(ServeContext {
            ledger: Arc::clone(&ledger),
            timeouts: config.timeouts,
            expected_digest: config.expected_digest,
            response: config.response,
            #[cfg(feature = "test-support")]
            received: Arc::clone(&received),
            #[cfg(feature = "test-support")]
            observations: Arc::clone(&shared.observations),
        });
        let accepting = std::iter::once(sockets.v4).chain(sockets.v6);
        let workers = start_accept_threads(
            accepting,
            &context,
            &shared,
            |socket| socket.set_nonblocking(true),
            spawn_thread_handle,
        )
        .map_err(|_| BridgeError::Unavailable(UnavailableCode::PortUnavailable))?;
        Ok(Self {
            ledger,
            #[cfg(feature = "test-support")]
            received,
            shared,
            workers,
            v4_addr,
            v6_addr,
            mode: sockets.mode,
            binder,
        })
    }

    /// The bound IPv4 loopback address.
    #[must_use]
    pub const fn v4_addr(&self) -> SocketAddr {
        self.v4_addr
    }

    /// Count connections that supplied any request byte, including incomplete
    /// requests or responses. Silent speculative preconnects are excluded.
    /// This cumulative test observation is not reset by navigation.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn received_request_count(&self) -> u64 {
        self.received.load(Ordering::SeqCst)
    }

    /// Aggregate test observations; snapshots may race connection transitions.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn observation(&self) -> ListenerObservation {
        let o = &self.shared.observations;
        ListenerObservation {
            accepted: o.accepted.load(Ordering::SeqCst),
            handling: o.handling.load(Ordering::SeqCst),
            reserved: self.shared.active.load(Ordering::SeqCst),
            silent: o.silent.load(Ordering::SeqCst),
            silent_eof: o.silent_eof.load(Ordering::SeqCst),
            silent_timeout: o.silent_timeout.load(Ordering::SeqCst),
            silent_error: o.silent_error.load(Ordering::SeqCst),
            complete: o.complete.load(Ordering::SeqCst),
            too_large: o.too_large.load(Ordering::SeqCst),
        }
    }

    /// The bound IPv6 loopback address, when IPv6 is held.
    #[must_use]
    pub const fn v6_addr(&self) -> Option<SocketAddr> {
        self.v6_addr
    }

    /// Whether IPv6 is held or provably absent.
    #[must_use]
    pub const fn mode(&self) -> Ipv6Mode {
        self.mode
    }

    /// Whether the accept threads still run: `true` from `start` until the first `shutdown`.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        !self.workers.is_empty()
    }

    /// Stop accepting and join the accept threads. Connections already served finish on their own.
    pub fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for worker in self.workers.drain(..) {
            // An accept thread that panicked has no result to report and nothing left to stop.
            drop(worker.join());
        }
    }
}

impl Drop for LoopbackListener {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl LoopbackPort for LoopbackListener {
    fn begin_navigation(&mut self) {
        self.ledger.reset();
    }

    fn served(&self) -> ServedSnapshot {
        self.ledger.snapshot()
    }

    fn probe_ipv6(&mut self) -> Result<(), BridgeError> {
        match self.mode {
            Ipv6Mode::Dual => Ok(()),
            Ipv6Mode::Absent { startup_error } => {
                check_ipv6_absent(self.binder.as_mut(), startup_error)
            }
        }
    }
}
