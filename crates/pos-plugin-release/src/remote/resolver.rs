//! The bounded, process-shared name resolver of the remote transport.
//!
//! The HTTP client's default resolver spawns a native lookup thread for each
//! timed resolution, and the caller's timeout does not cancel it. This
//! resolver instead owns one worker thread for the whole process. It allows
//! at most one outstanding lookup and keeps no queue: a caller that finds the
//! worker busy fails closed at once. A caller waits at most its remaining
//! deadline; a result that arrives later is discarded. If a native lookup
//! wedges, every later resolution fails closed until it completes or the
//! process restarts. No replacement worker is ever spawned.

use std::net::{SocketAddr, ToSocketAddrs as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

/// The most resolved addresses retained for one connection attempt.
const MAX_ADDRESSES: usize = 16;

type Lookup = fn(&str) -> Vec<SocketAddr>;
type Job = (String, SyncSender<Vec<SocketAddr>>);

/// The single resolver worker and its one-lookup admission flag.
#[derive(Debug)]
struct Worker {
    busy: Arc<AtomicBool>,
    jobs: SyncSender<Job>,
}

impl Worker {
    fn spawn(lookup: Lookup) -> Self {
        let (jobs, queue) = mpsc::sync_channel::<Job>(1);
        let busy = Arc::new(AtomicBool::new(false));
        let worker_busy = Arc::clone(&busy);
        thread::spawn(move || {
            for (host, reply) in queue {
                let addresses = lookup(&host);
                // Admit the next lookup before answering, so a caller that
                // has its answer never finds this completed lookup busy.
                worker_busy.store(false, Ordering::Release);
                // The caller may have stopped waiting: then the late result
                // is dropped here and never reaches a later caller.
                drop(reply.try_send(addresses));
            }
        });
        Self { busy, jobs }
    }

    /// Resolve `host` within `wait`, or fail closed with no address.
    fn resolve(&self, host: String, wait: Duration) -> Vec<SocketAddr> {
        if self.busy.swap(true, Ordering::AcqRel) {
            return Vec::new();
        }
        let (reply, answer) = mpsc::sync_channel(1);
        self.jobs
            .try_send((host, reply))
            .ok()
            .and_then(|()| answer.recv_timeout(wait).ok())
            .unwrap_or_default()
    }
}

fn native_lookup(host: &str) -> Vec<SocketAddr> {
    host.to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default()
}

/// The resolver handle given to the HTTP client. Every handle shares the one
/// process worker, however many sources are built, cloned or dropped.
#[derive(Debug)]
pub(super) struct BoundedResolver {
    worker: &'static Worker,
}

impl BoundedResolver {
    pub(super) fn shared() -> Self {
        static WORKER: OnceLock<Worker> = OnceLock::new();
        Self {
            worker: WORKER.get_or_init(|| Worker::spawn(native_lookup)),
        }
    }
}

impl Resolver for BoundedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        // Requests are HTTPS only, so a URI without a port uses 443.
        let host = format!(
            "{}:{}",
            uri.host().unwrap_or_default(),
            uri.port_u16().unwrap_or(443)
        );
        let mut resolved = self.empty();
        for address in self
            .worker
            .resolve(host, *timeout.after)
            .into_iter()
            .take(MAX_ADDRESSES)
        {
            resolved.push(address);
        }
        if resolved.is_empty() {
            Err(ureq::Error::HostNotFound)
        } else {
            Ok(resolved)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::time::Instant;

    use super::*;

    /// Holding this gate wedges `gated_lookup`, standing in for a native
    /// resolver call that does not return.
    static GATE: Mutex<()> = Mutex::new(());

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn gate() -> MutexGuard<'static, ()> {
        GATE.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One loopback address whose port is the host's numeric suffix, so each
    /// answer names the request it belongs to.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn gated_lookup(host: &str) -> Vec<SocketAddr> {
        drop(gate());
        let port = host
            .rsplit(':')
            .next()
            .and_then(|port| port.parse().ok())
            .unwrap_or(0);
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)]
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn many_lookup(_host: &str) -> Vec<SocketAddr> {
        (1..=20)
            .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
            .collect()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_lookup(_host: &str) -> Vec<SocketAddr> {
        Vec::new()
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn wait(seconds: u64) -> NextTimeout {
        NextTimeout {
            after: ureq::unversioned::transport::time::Duration::Exact(Duration::from_secs(
                seconds,
            )),
            reason: ureq::Timeout::Resolve,
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    /// A resolver over its own worker, held in `cell` for the whole test
    /// process like the production worker (never leaked or respawned).
    fn resolver(cell: &'static OnceLock<Worker>, lookup: Lookup) -> BoundedResolver {
        BoundedResolver {
            worker: cell.get_or_init(|| Worker::spawn(lookup)),
        }
    }

    static GATED_WORKER: OnceLock<Worker> = OnceLock::new();
    static MANY_WORKER: OnceLock<Worker> = OnceLock::new();
    static EMPTY_WORKER: OnceLock<Worker> = OnceLock::new();

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn uri(text: &str) -> Result<Uri, Box<dyn std::error::Error>> {
        Ok(text.parse::<Uri>()?)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn a_wedged_lookup_bounds_the_caller_and_fails_closed_without_a_queue(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resolver = resolver(&GATED_WORKER, gated_lookup);
        let config = Config::default();
        let held = gate();

        let started = Instant::now();
        let wedged = resolver.resolve(&uri("https://wedged.test:1/")?, &config, wait(1));
        let waited = started.elapsed();
        assert!(matches!(wedged, Err(ureq::Error::HostNotFound)));
        assert!(waited >= Duration::from_secs(1) && waited < Duration::from_secs(5));

        // The worker is still busy: the next caller fails at once, not after
        // its own wait, and is not queued behind the wedged lookup.
        let started = Instant::now();
        let refused = resolver.resolve(&uri("https://queued.test:2/")?, &config, wait(30));
        assert!(matches!(refused, Err(ureq::Error::HostNotFound)));
        assert!(started.elapsed() < Duration::from_secs(5));

        drop(held);
        // Once the wedged lookup completes, the same worker serves the next
        // caller with its own answer: the late port-1 result was discarded.
        let mut answer = None;
        let deadline = Instant::now() + Duration::from_secs(10);
        while answer.is_none() && Instant::now() < deadline {
            answer = resolver
                .resolve(&uri("https://next.test:3/")?, &config, wait(1))
                .ok();
            thread::sleep(Duration::from_millis(10));
        }
        let ports = answer
            .ok_or("the worker never recovered")?
            .iter()
            .map(SocketAddr::port)
            .collect::<Vec<_>>();
        assert_eq!(ports, vec![3]);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn a_resolution_keeps_at_most_sixteen_addresses() -> Result<(), Box<dyn std::error::Error>> {
        let resolver = resolver(&MANY_WORKER, many_lookup);
        let addresses =
            resolver.resolve(&uri("https://many.test/")?, &Config::default(), wait(5))?;
        let ports = addresses.iter().map(SocketAddr::port).collect::<Vec<_>>();
        assert_eq!(ports, (1..=16).collect::<Vec<_>>());
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn no_address_is_host_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let resolver = resolver(&EMPTY_WORKER, empty_lookup);
        let addresses = resolver.resolve(&uri("https://none.test/")?, &Config::default(), wait(5));
        assert!(matches!(addresses, Err(ureq::Error::HostNotFound)));
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn every_handle_shares_one_process_worker() {
        let first = BoundedResolver::shared();
        let second = BoundedResolver::shared();
        assert!(std::ptr::eq(first.worker, second.worker));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn the_native_lookup_resolves_a_literal_and_fails_closed_on_a_bad_name() {
        assert_eq!(
            native_lookup("127.0.0.1:443"),
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)]
        );
        assert!(native_lookup("no port").is_empty());
    }

    // Diagnostic branch only: the hosted driver supplies real glibc/NSS DNS
    // through a controlled server in a private network and mount namespace.
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn native_probe_control(
        command: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::UnixStream;

        let mut control = UnixStream::connect(std::env::var("REMOTE_PROBE_CONTROL")?)?;
        control.set_read_timeout(Some(Duration::from_secs(5)))?;
        control.set_write_timeout(Some(Duration::from_secs(5)))?;
        control.write_all(command.as_bytes())?;
        control.shutdown(std::net::Shutdown::Write)?;
        let mut response = String::new();
        control.take(16 * 1024).read_to_string(&mut response)?;
        Ok(serde_json::from_str(&response)?)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn native_probe_thread_count() -> Result<usize, Box<dyn std::error::Error>> {
        Ok(std::fs::read_dir("/proc/self/task")?
            .collect::<Result<Vec<_>, _>>()?
            .len())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn native_system_resolver_resource_probe() -> Result<(), Box<dyn std::error::Error>> {
        let proc_status = std::fs::read_to_string("/proc/self/status")?;
        let effective_uid = proc_status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or("effective UID missing")?;
        assert_eq!(effective_uid, std::env::var("REMOTE_PROBE_UID")?);
        assert_ne!(effective_uid, "0");

        let initial_threads = native_probe_thread_count()?;
        let config = Config::default();
        let (waited, busy_wait, peak_threads) = {
            let first = BoundedResolver::shared();
            let ready = first.resolve(
                &uri("https://ready.remote-probe.invalid:9/")?,
                &config,
                wait(5),
            )?;
            assert_eq!(
                ready.iter().copied().collect::<Vec<_>>(),
                vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 13)), 9)]
            );
            assert_eq!(native_probe_thread_count()?, initial_threads + 1);

            let started = Instant::now();
            let stalled = first.resolve(
                &uri("https://wedged.remote-probe.invalid:1/")?,
                &config,
                wait(1),
            );
            let waited = started.elapsed();
            assert!(matches!(stalled, Err(ureq::Error::HostNotFound)));
            assert!(waited >= Duration::from_secs(1) && waited < Duration::from_secs(5));
            assert_eq!(
                native_probe_control("state")?["hosts"],
                serde_json::json!(["ready.remote-probe.invalid", "wedged.remote-probe.invalid"])
            );

            let busy_started = Instant::now();
            let mut peak_threads = native_probe_thread_count()?;
            for index in 0..100 {
                let handle = BoundedResolver::shared();
                assert!(std::ptr::eq(first.worker, handle.worker));
                let queued = handle.resolve(
                    &uri(&format!("https://queued-{index}.remote-probe.invalid:2/"))?,
                    &config,
                    wait(30),
                );
                assert!(matches!(queued, Err(ureq::Error::HostNotFound)));
                peak_threads = peak_threads.max(native_probe_thread_count()?);
            }
            let busy_wait = busy_started.elapsed();
            assert!(busy_wait < Duration::from_secs(5));
            assert_eq!(peak_threads, initial_threads + 1);
            (waited, busy_wait, peak_threads)
        };
        native_probe_control("release")?;

        let recovered = BoundedResolver::shared();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut answer = None;
        while answer.is_none() && Instant::now() < deadline {
            answer = recovered
                .resolve(
                    &uri("https://next.remote-probe.invalid:3/")?,
                    &config,
                    wait(1),
                )
                .ok();
            thread::yield_now();
        }
        let actual = answer.ok_or("native worker never recovered")?;
        assert_eq!(
            actual.iter().copied().collect::<Vec<_>>(),
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 12)), 3)]
        );
        assert_eq!(native_probe_thread_count()?, initial_threads + 1);
        let state = native_probe_control("state")?;
        assert_eq!(
            state["hosts"],
            serde_json::json!([
                "next.remote-probe.invalid",
                "ready.remote-probe.invalid",
                "wedged.remote-probe.invalid"
            ])
        );
        println!(
            "NATIVE_RESOLVER_PROBE={}",
            serde_json::json!({
                "uid": effective_uid,
                "threads_before_worker": initial_threads,
                "peak_threads_while_busy": peak_threads,
                "threads_after_recovery": native_probe_thread_count()?,
                "caller_wait_ms": waited.as_millis(),
                "busy_callers": 100,
                "busy_wait_ms": busy_wait.as_millis(),
                "dns": state,
                "recovered": actual.iter().map(ToString::to_string).collect::<Vec<_>>(),
            })
        );
        Ok(())
    }
}
