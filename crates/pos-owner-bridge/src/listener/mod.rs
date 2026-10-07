//! The loopback asset listener (ADR-110 §4): exclusive loopback sockets serving one digest-pinned
//! document with bounded concurrency, a first-byte timeout, and a served-exactly-once ledger.

pub mod assets;
pub mod bind;
pub mod ledger;
pub mod serve;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::{BridgeError, LoopbackPort, ServedSnapshot};
use assets::OWNER_RESPONSE_SHA256;
use bind::{bind_loopback, check_ipv6_absent, Ipv6Mode, LoopbackBinder};
use ledger::ServedLedger;
use serve::{serve_connection, ListenerTimeouts, ServeContext, ADR_TIMEOUTS};

/// At most this many connections are served at once; the rest wait in the kernel backlog.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 3;

const ACCEPT_POLL: Duration = Duration::from_millis(2);

/// Placeholder for an address that cannot be read back from a bound socket.
const UNBOUND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// Listener tuning. [`ListenerConfig::adr`] is the accepted configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    /// The connection deadlines.
    pub timeouts: ListenerTimeouts,
    /// The digest each completed owner response must match.
    pub expected_digest: [u8; 32],
}

impl ListenerConfig {
    /// The ADR-110 deadlines and the pinned response digest.
    #[must_use]
    pub const fn adr() -> Self {
        Self {
            timeouts: ADR_TIMEOUTS,
            expected_digest: OWNER_RESPONSE_SHA256,
        }
    }
}

/// State shared by the accept threads.
#[derive(Debug, Default)]
struct Shared {
    stop: AtomicBool,
    active: AtomicUsize,
}

impl Shared {
    fn try_acquire(&self) -> bool {
        self.active
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                (active < MAX_CONCURRENT_CONNECTIONS).then_some(active + 1)
            })
            .is_ok()
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn accept_loop(listener: &TcpListener, context: &Arc<ServeContext>, shared: &Arc<Shared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        if !shared.try_acquire() {
            thread::sleep(ACCEPT_POLL);
            continue;
        }
        let accepted = listener.accept();
        if let Ok((stream, _)) = accepted {
            let (context, shared) = (Arc::clone(context), Arc::clone(shared));
            thread::spawn(move || {
                stream
                    .set_nonblocking(false)
                    .is_ok()
                    .then(|| serve_connection(stream, &context));
                shared.release();
            });
        } else {
            shared.release();
            thread::sleep(ACCEPT_POLL);
        }
    }
}

/// The running loopback listener. Dropping it stops the accept threads.
pub struct LoopbackListener {
    ledger: Arc<ServedLedger>,
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
    /// [`bind_loopback`] does.
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
        let context = Arc::new(ServeContext {
            ledger: Arc::clone(&ledger),
            timeouts: config.timeouts,
            expected_digest: config.expected_digest,
        });
        let shared = Arc::new(Shared::default());
        let mut workers = Vec::new();
        for socket in std::iter::once(sockets.v4).chain(sockets.v6) {
            let (context, shared) = (Arc::clone(&context), Arc::clone(&shared));
            workers.push(thread::spawn(move || {
                socket
                    .set_nonblocking(true)
                    .is_ok()
                    .then(|| accept_loop(&socket, &context, &shared));
            }));
        }
        Ok(Self {
            ledger,
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

    /// Stop accepting and join the accept threads. Connections already served finish on their own.
    pub fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for worker in self.workers.drain(..) {
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
