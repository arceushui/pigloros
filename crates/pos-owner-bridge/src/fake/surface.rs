//! `FakeSurface`: an `OwnerWebSurface` over in-memory buffers and a scripted page.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use super::buffers::{offset, Actor, Buffers, LogEntry, Pair};
use super::clock::FakeClock;
use super::host::FakeLoopback;
use crate::{
    BridgeError, LifecycleCode, NavigationId, OwnerWebSurface, PostGuard, ProcessIdentity,
    ProtocolCode, ReplyImage, RequestImage, SurfaceError, SurfaceEvent, SurfaceSpec,
};

/// A host operation a page model may observe or race.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostOp {
    /// The host loads the reply state word.
    Load {
        /// The pair index.
        pair: usize,
    },
    /// The host compare-exchanges the reply state word; `won` is `None` before the exchange.
    Cas {
        /// The pair index.
        pair: usize,
        /// The expected value.
        current: u32,
        /// The new value.
        new: u32,
        /// The outcome, known only after the exchange.
        won: Option<bool>,
    },
    /// The host copies the reply buffer; `count` is 1 for copy A and 2 for copy B.
    Copy {
        /// The pair index.
        pair: usize,
        /// Which copy.
        count: u32,
    },
    /// The host zeroes and closes the pair.
    ZeroClose {
        /// The pair index.
        pair: usize,
    },
}

/// Whether a hook runs before or after the host operation takes effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookPhase {
    /// Before the operation.
    Before,
    /// After the operation.
    After,
}

/// The scripted page behind a [`FakeSurface`].
pub trait PageModel {
    /// The page script starts at `at` (shortly after the document loads).
    fn on_script_start(&mut self, buffers: &mut Buffers, at: Duration);

    /// The host posted `pair` (request, then reply) at `now`.
    fn on_post(&mut self, buffers: &mut Buffers, now: Duration, pair: usize);

    /// Let the page act for every moment up to `now`.
    fn advance(&mut self, buffers: &mut Buffers, now: Duration);

    /// The earliest moment at which the page has something scheduled, if any.
    fn next_activity(&self) -> Option<Duration>;

    /// The host is performing `op`; scripted races may fire here.
    fn on_host_op(&mut self, buffers: &mut Buffers, now: Duration, op: HostOp, phase: HookPhase);
}

/// Failures a test can make individual surface calls return.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SurfaceFaults {
    /// `open` fails.
    pub open: Option<BridgeError>,
    /// `navigate` fails.
    pub navigate: Option<BridgeError>,
    /// `create_and_write` fails.
    pub create: Option<BridgeError>,
    /// `post` fails.
    pub post: Option<BridgeError>,
    /// Every state-word load, exchange, store and copy fails.
    pub state: Option<BridgeError>,
    /// Only compare-exchanges fail.
    pub exchange: Option<BridgeError>,
    /// Only reply copies fail.
    pub copy: Option<BridgeError>,
    /// `zero_close_buffers` fails.
    pub zero_close: bool,
    /// `close_controller` fails.
    pub close_controller: bool,
    /// `finish` fails.
    pub finish: bool,
}

/// How the fake surface behaves.
#[derive(Clone, Copy, Debug)]
pub struct SurfaceConfig {
    /// Time from `navigate` to `DOMContentLoaded`.
    pub load_delay: Duration,
    /// Time from `close_controller` to `BrowserExited`; `None` means the browser never exits.
    pub exit_delay: Option<Duration>,
    /// The browser process identity.
    pub identity: ProcessIdentity,
    /// The served count the listener reports once the document loaded.
    pub served_completions: u32,
    /// The integrity verdict the listener reports once the document loaded.
    pub served_integrity_ok: bool,
    /// Scripted call failures.
    pub faults: SurfaceFaults,
}

impl Default for SurfaceConfig {
    fn default() -> Self {
        Self {
            load_delay: Duration::from_millis(100),
            exit_delay: Some(Duration::from_millis(180)),
            identity: ProcessIdentity {
                browser_pid: 4242,
                creation_filetime: 133_000_000_000_000_000,
                image_path_sha256: pos_owner_bridge_codec::ImagePathSha256::from_bytes([7; 32]),
            },
            served_completions: 1,
            served_integrity_ok: true,
            faults: SurfaceFaults::default(),
        }
    }
}

struct Inner {
    clock: FakeClock,
    loopback: FakeLoopback,
    config: SurfaceConfig,
    buffers: Buffers,
    page: Box<dyn PageModel>,
    navigation: u64,
    current: Option<usize>,
    copies: u32,
    folder: Option<String>,
    finished: u32,
}

const UNEXPECTED: BridgeError = BridgeError::Protocol(ProtocolCode::UnexpectedState);

fn word(bytes: &[u8], at_offset: usize) -> u32 {
    bytes
        .get(at_offset..at_offset + 4)
        .and_then(|chunk| <[u8; 4]>::try_from(chunk).ok())
        .map_or(0, u32::from_le_bytes)
}

impl Inner {
    fn tick(&mut self) -> Duration {
        let now = self.clock.elapsed();
        self.buffers.now = now;
        self.page.advance(&mut self.buffers, now);
        self.buffers.now = now;
        now
    }

    fn next_activity(&self) -> Option<Duration> {
        let scheduled = self.buffers.next_event_time();
        [scheduled, self.page.next_activity()]
            .into_iter()
            .flatten()
            .min()
    }

    fn hook(&mut self, now: Duration, op: HostOp, phase: HookPhase) {
        self.page.on_host_op(&mut self.buffers, now, op, phase);
    }

    fn live_pair(&mut self, what: &'static str) -> Result<usize, SurfaceError> {
        let live = self.current.filter(|&index| {
            self.buffers
                .pairs
                .get(index)
                .is_some_and(|pair| !pair.host_closed)
        });
        live.ok_or_else(|| {
            self.buffers.log.push(LogEntry::Violation(what));
            SurfaceError::new(UNEXPECTED)
        })
    }

    fn fault(fault: Option<BridgeError>) -> Result<(), SurfaceError> {
        fault.map_or(Ok(()), |error| Err(SurfaceError::new(error)))
    }

    fn state_pair(&mut self, what: &'static str) -> Result<(Duration, usize), SurfaceError> {
        let now = self.tick();
        let pair = self.live_pair(what)?;
        Self::fault(self.config.faults.state)?;
        Ok((now, pair))
    }

    fn load_state(&mut self) -> Result<u32, SurfaceError> {
        let (now, pair) = self.state_pair("state load without a live pair")?;
        self.hook(now, HostOp::Load { pair }, HookPhase::Before);
        let value = self.buffers.state_of(pair).unwrap_or(0);
        self.buffers.log.push(LogEntry::HostLoad { pair, value });
        Ok(value)
    }

    fn exchange(&mut self, current: u32, new: u32) -> Result<bool, SurfaceError> {
        let (now, pair) = self.state_pair("exchange without a live pair")?;
        Self::fault(self.config.faults.exchange)?;
        let before = HostOp::Cas {
            pair,
            current,
            new,
            won: None,
        };
        self.hook(now, before, HookPhase::Before);
        let won = self.buffers.cas(Actor::Host, pair, current, new);
        let after = HostOp::Cas {
            pair,
            current,
            new,
            won: Some(won),
        };
        self.hook(now, after, HookPhase::After);
        Ok(won)
    }

    fn store(&mut self, new: u32) -> Result<(), SurfaceError> {
        let (_, pair) = self.state_pair("store without a live pair")?;
        self.buffers.store(Actor::Host, pair, new);
        Ok(())
    }

    fn copy(&mut self, out: &mut ReplyImage) -> Result<(), SurfaceError> {
        let (now, pair) = self.state_pair("copy without a live pair")?;
        Self::fault(self.config.faults.copy)?;
        self.copies += 1;
        let op = HostOp::Copy {
            pair,
            count: self.copies,
        };
        self.hook(now, op, HookPhase::Before);
        let (reply, state) = self
            .buffers
            .pairs
            .get(pair)
            .map_or((Vec::new(), 0), |slot| (slot.reply.clone(), slot.state));
        let count = reply.len().min(out.as_bytes().len());
        let (head, _) = out.as_mut_bytes().split_at_mut(count);
        head.copy_from_slice(reply.get(..count).unwrap_or_default());
        out.as_mut_bytes()
            .get_mut(offset::STATE..offset::STATE + 4)
            .into_iter()
            .for_each(|target| target.copy_from_slice(&state.to_le_bytes()));
        self.buffers.log.push(LogEntry::HostCopy { pair, state });
        self.hook(now, op, HookPhase::After);
        Ok(())
    }

    fn create(
        &mut self,
        request: &RequestImage,
        reply_header: &[u8; 64],
    ) -> Result<(), SurfaceError> {
        self.tick();
        Self::fault(self.config.faults.create)?;
        let overlap = self.current.is_some_and(|index| {
            self.buffers
                .pairs
                .get(index)
                .is_some_and(|pair| !pair.host_closed)
        });
        if overlap {
            self.buffers.log.push(LogEntry::Violation(
                "a pair was created while another is open",
            ));
        }
        let capacity = usize::try_from(word(reply_header, 32)).unwrap_or(0);
        let mut reply = vec![0; capacity];
        for (target, source) in reply.iter_mut().zip(reply_header.iter()) {
            *target = *source;
        }
        let mut ceremony_id = [0; 16];
        let id_bytes = request
            .as_bytes()
            .get(offset::CEREMONY_ID..offset::CEREMONY_ID + 16);
        ceremony_id
            .iter_mut()
            .zip(id_bytes.unwrap_or_default())
            .for_each(|(target, source)| *target = *source);
        let pair = Pair {
            generation: word(request.as_bytes(), offset::GENERATION),
            ceremony_id,
            request: request.as_bytes().to_vec(),
            reply,
            state: 0,
            state_changed_at: self.clock.elapsed(),
            host_closed: false,
            delivered: [false; 2],
            released: [false; 2],
        };
        self.current = Some(self.buffers.add_pair(pair));
        self.copies = 0;
        Ok(())
    }

    fn post(&mut self, guard: &PostGuard) -> Result<(), SurfaceError> {
        let now = self.tick();
        Self::fault(self.config.faults.post)?;
        let pair = self.live_pair("post without a live pair")?;
        let generation = self
            .buffers
            .pairs
            .get(pair)
            .map_or(0, |slot| slot.generation);
        let stale = guard.generation != generation
            || guard.navigation_id != NavigationId(self.navigation)
            || guard.served_count != 1;
        if stale {
            return Err(SurfaceError::new(BridgeError::Lifecycle(
                LifecycleCode::NavigationViolation,
            )));
        }
        self.buffers.log.push(LogEntry::Post {
            pair,
            generation,
            at: now,
        });
        self.page.on_post(&mut self.buffers, now, pair);
        Ok(())
    }

    fn zero_close(&mut self) -> Result<(), SurfaceError> {
        let now = self.tick();
        if self.config.faults.zero_close {
            return Err(SurfaceError::new(UNEXPECTED));
        }
        let pair = self.live_pair("zero and close without a live pair")?;
        self.hook(now, HostOp::ZeroClose { pair }, HookPhase::Before);
        let state = self.buffers.state_of(pair).unwrap_or(0);
        self.buffers
            .pairs
            .get_mut(pair)
            .into_iter()
            .for_each(|slot| {
                slot.request.fill(0);
                slot.host_closed = true;
            });
        self.buffers.zero_reply_payload(pair);
        self.buffers.log.push(LogEntry::ZeroClose {
            pair,
            state,
            at: now,
        });
        Ok(())
    }

    fn close_controller(&mut self) -> Result<(), SurfaceError> {
        let now = self.tick();
        if self.config.faults.close_controller {
            return Err(SurfaceError::new(UNEXPECTED));
        }
        self.buffers.log.push(LogEntry::ControllerClosed);
        if let Some(delay) = self.config.exit_delay {
            let event = SurfaceEvent::BrowserExited {
                browser_pid: self.config.identity.browser_pid,
            };
            self.buffers.schedule(now + delay, event);
        }
        Ok(())
    }
}

/// An `OwnerWebSurface` over in-memory buffers and a scripted [`PageModel`].
pub struct FakeSurface {
    inner: Rc<RefCell<Inner>>,
}

/// A shared view of a [`FakeSurface`] for scripting and inspection after it moved into a bridge.
#[derive(Clone)]
pub struct FakeSurfaceHandle {
    inner: Rc<RefCell<Inner>>,
}

impl FakeSurface {
    /// Create a surface running `page`, reporting served counts through `loopback`.
    #[must_use]
    pub fn new(
        clock: FakeClock,
        loopback: FakeLoopback,
        page: Box<dyn PageModel>,
        config: SurfaceConfig,
    ) -> Self {
        let source_clock = clock.clone();
        let inner = Rc::new(RefCell::new(Inner {
            clock,
            loopback,
            config,
            buffers: Buffers::default(),
            page,
            navigation: 0,
            current: None,
            copies: 0,
            folder: None,
            finished: 0,
        }));
        let watcher = Rc::downgrade(&inner);
        source_clock.set_activity_source(Box::new(move || {
            watcher
                .upgrade()
                .and_then(|surface| surface.borrow().next_activity())
        }));
        Self { inner }
    }

    /// A shared view of this surface.
    #[must_use]
    pub fn handle(&self) -> FakeSurfaceHandle {
        FakeSurfaceHandle {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl FakeSurfaceHandle {
    /// A copy of the operation log.
    #[must_use]
    pub fn log(&self) -> Vec<LogEntry> {
        self.inner.borrow().buffers.log.clone()
    }

    /// The number of pairs created so far.
    #[must_use]
    pub fn pair_count(&self) -> usize {
        self.inner.borrow().buffers.pairs.len()
    }

    /// Run `inspect` over the buffers.
    pub fn with_buffers<T>(&self, inspect: impl FnOnce(&mut Buffers) -> T) -> T {
        inspect(&mut self.inner.borrow_mut().buffers)
    }

    /// Schedule a lifecycle event.
    pub fn schedule(&self, at: Duration, event: SurfaceEvent) {
        self.inner.borrow_mut().buffers.schedule(at, event);
    }

    /// Replace the scripted call failures.
    pub fn set_faults(&self, faults: SurfaceFaults) {
        self.inner.borrow_mut().config.faults = faults;
    }

    /// Replace the listener verdict the next navigation reports.
    pub fn set_served(&self, completions: u32, integrity_ok: bool) {
        let mut inner = self.inner.borrow_mut();
        inner.config.served_completions = completions;
        inner.config.served_integrity_ok = integrity_ok;
    }

    /// The user-data folder of the latest `open`.
    #[must_use]
    pub fn folder(&self) -> Option<String> {
        self.inner.borrow().folder.clone()
    }

    /// Let the page act for every moment up to the current fake time.
    pub fn settle(&self) {
        self.inner.borrow_mut().tick();
    }

    /// How many times `finish` succeeded.
    #[must_use]
    pub fn finished(&self) -> u32 {
        self.inner.borrow().finished
    }
}

impl OwnerWebSurface for FakeSurface {
    fn open(&mut self, spec: &SurfaceSpec) -> Result<ProcessIdentity, SurfaceError> {
        let mut inner = self.inner.borrow_mut();
        inner.tick();
        Inner::fault(inner.config.faults.open)?;
        inner.folder = Some(spec.folder_name.clone());
        let at = inner.clock.elapsed();
        inner.buffers.log.push(LogEntry::Opened { at });
        Ok(inner.config.identity)
    }

    fn navigate(&mut self) -> Result<NavigationId, SurfaceError> {
        let mut inner = self.inner.borrow_mut();
        let now = inner.tick();
        Inner::fault(inner.config.faults.navigate)?;
        inner.navigation += 1;
        let id = NavigationId(inner.navigation);
        let loaded = now + inner.config.load_delay;
        inner
            .buffers
            .schedule(loaded, SurfaceEvent::DomContentLoaded(id));
        let (count, integrity) = (
            inner.config.served_completions,
            inner.config.served_integrity_ok,
        );
        inner.loopback.set_served(count, integrity);
        let Inner { page, buffers, .. } = &mut *inner;
        page.on_script_start(buffers, loaded);
        Ok(id)
    }

    fn create_and_write(
        &mut self,
        request: &RequestImage,
        reply_header: &[u8; 64],
    ) -> Result<(), SurfaceError> {
        self.inner.borrow_mut().create(request, reply_header)
    }

    fn post(&mut self, guard: &PostGuard) -> Result<(), SurfaceError> {
        self.inner.borrow_mut().post(guard)
    }

    fn reply_load_state(&self) -> Result<u32, SurfaceError> {
        self.inner.borrow_mut().load_state()
    }

    fn reply_compare_exchange(&self, current: u32, new: u32) -> Result<bool, SurfaceError> {
        self.inner.borrow_mut().exchange(current, new)
    }

    fn reply_store_state(&self, new: u32) -> Result<(), SurfaceError> {
        self.inner.borrow_mut().store(new)
    }

    fn reply_copy(&self, out: &mut ReplyImage) -> Result<(), SurfaceError> {
        self.inner.borrow_mut().copy(out)
    }

    fn zero_close_buffers(&mut self) -> Result<(), SurfaceError> {
        self.inner.borrow_mut().zero_close()
    }

    fn close_controller(&mut self) -> Result<(), SurfaceError> {
        self.inner.borrow_mut().close_controller()
    }

    fn take_event(&mut self) -> Option<SurfaceEvent> {
        let mut inner = self.inner.borrow_mut();
        let now = inner.tick();
        let event = inner.buffers.take_due(now);
        if matches!(event, Some(SurfaceEvent::BrowserExited { .. })) {
            inner.buffers.log.push(LogEntry::ExitObserved);
        }
        event
    }

    fn finish(&mut self) -> Result<(), SurfaceError> {
        let mut inner = self.inner.borrow_mut();
        inner.tick();
        if inner.config.faults.finish {
            return Err(SurfaceError::new(UNEXPECTED));
        }
        inner.finished += 1;
        inner.buffers.log.push(LogEntry::Finished);
        Ok(())
    }
}
