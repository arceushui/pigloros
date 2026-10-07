//! Shared-buffer pairs and the operation log, as the fake surface and the fake page share them.

use std::time::Duration;

use crate::SurfaceEvent;

/// Reply state values.
pub mod state {
    /// The page has not yet received the pair.
    pub const EMPTY: u32 = 0;
    /// The page is writing its payload.
    pub const WRITING: u32 = 1;
    /// A complete payload is published.
    pub const READY: u32 = 2;
    /// The host owns the published reply.
    pub const CONSUMING: u32 = 3;
    /// The host asked the page to release.
    pub const RELEASE_REQUESTED: u32 = 4;
    /// The page started releasing.
    pub const RELEASING: u32 = 5;
    /// The page failed or was cancelled.
    pub const FAILED: u32 = 6;
    /// The page acknowledged the pair.
    pub const RECEIVED: u32 = 7;
}

/// Byte offsets inside the 64-byte control header.
pub mod offset {
    /// The generation word.
    pub const GENERATION: usize = 12;
    /// The ceremony ID.
    pub const CEREMONY_ID: usize = 16;
    /// The payload length word.
    pub const PAYLOAD_LEN: usize = 36;
    /// The state word.
    pub const STATE: usize = 40;
    /// The first payload byte.
    pub const PAYLOAD: usize = 64;
}

/// Which side of a pair a buffer is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// The host-written read-only request buffer.
    Request,
    /// The page-written reply buffer.
    Reply,
}

impl Role {
    const fn slot(self) -> usize {
        match self {
            Self::Request => 0,
            Self::Reply => 1,
        }
    }
}

/// Who performed a state-word operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Actor {
    /// The owner host.
    Host,
    /// The packaged page.
    Page,
}

/// One entry of the surface and page operation log the oracle checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogEntry {
    /// A pair was created and posted.
    Post {
        /// The pair index.
        pair: usize,
        /// The generation in both headers.
        generation: u32,
        /// When it was posted.
        at: Duration,
    },
    /// The host loaded the state word.
    HostLoad {
        /// The pair index.
        pair: usize,
        /// The value read.
        value: u32,
    },
    /// A compare-exchange by `actor`.
    Cas {
        /// Who exchanged.
        actor: Actor,
        /// The pair index.
        pair: usize,
        /// The expected value.
        current: u32,
        /// The new value.
        new: u32,
        /// Whether it won.
        won: bool,
        /// When.
        at: Duration,
    },
    /// A plain store by `actor`.
    Store {
        /// Who stored.
        actor: Actor,
        /// The pair index.
        pair: usize,
        /// The value stored.
        value: u32,
        /// When.
        at: Duration,
    },
    /// The host copied the reply buffer.
    HostCopy {
        /// The pair index.
        pair: usize,
        /// The state word at the time.
        state: u32,
    },
    /// The host zeroed and closed a pair.
    ZeroClose {
        /// The pair index.
        pair: usize,
        /// The reply state word when zeroed.
        state: u32,
        /// When.
        at: Duration,
    },
    /// The page received a buffer.
    PageReceived {
        /// The pair index.
        pair: usize,
        /// Which buffer.
        role: Role,
    },
    /// A buffer posted before the page listener existed was lost.
    PageLost {
        /// The pair index.
        pair: usize,
        /// Which buffer.
        role: Role,
    },
    /// The page started a `WebAuthn` call for a pair, with the options it decoded.
    PageWebAuthn {
        /// The pair index.
        pair: usize,
        /// The ceremony ID in the request.
        ceremony_id: [u8; 16],
        /// The challenge in the request.
        challenge: [u8; 32],
        /// The PRF input in the request.
        prf_input: [u8; 32],
        /// The user handle in a Create request.
        user_handle: Option<[u8; 32]>,
    },
    /// The page aborted its pending `WebAuthn` call.
    PageAbort {
        /// The pair index.
        pair: usize,
        /// When.
        at: Duration,
    },
    /// The page released a buffer.
    PageReleased {
        /// The pair index.
        pair: usize,
        /// Which buffer.
        role: Role,
        /// When.
        at: Duration,
    },
    /// The page's abort handler ran, with its outcome.
    PageHandler {
        /// The pair index.
        pair: usize,
        /// Whether its compare-exchange threw because the buffer was already detached.
        type_error: bool,
    },
    /// The page deadline fired.
    PageDeadline {
        /// When.
        at: Duration,
    },
    /// A scripted misbehaviour wrote into the read-only request buffer.
    RequestWritten {
        /// The pair index.
        pair: usize,
    },
    /// The surface opened a fresh environment.
    Opened {
        /// When.
        at: Duration,
    },
    /// The surface closed the controller.
    ControllerClosed,
    /// The surface reported the browser exit.
    ExitObserved,
    /// The surface finished cleanup.
    Finished,
    /// A surface call that must never happen, with its description.
    Violation(&'static str),
}

/// A buffer pair: the host-written request and the page-written reply with its state word.
#[derive(Clone, Debug)]
pub struct Pair {
    /// The generation under which the pair was posted.
    pub generation: u32,
    /// The ceremony ID carried by both headers.
    pub ceremony_id: [u8; 16],
    /// The request buffer bytes; the host zeroes them when it closes the pair.
    pub request: Vec<u8>,
    /// The request payload exactly as posted, kept after the host zeroes `request`.
    pub payload: Vec<u8>,
    /// The reply buffer bytes; the live state word is `state`, not these bytes.
    pub reply: Vec<u8>,
    /// The live reply state word.
    pub state: u32,
    /// When `state` last changed.
    pub state_changed_at: Duration,
    /// Whether the host closed the pair.
    pub host_closed: bool,
    /// Whether the page received `[request, reply]`.
    pub delivered: [bool; 2],
    /// Whether the page released `[request, reply]`.
    pub released: [bool; 2],
}

/// The stand-in `pair_at` returns for an index that was never created.
static NO_PAIR: Pair = Pair {
    generation: 0,
    ceremony_id: [0; 16],
    request: Vec::new(),
    payload: Vec::new(),
    reply: Vec::new(),
    state: 0,
    state_changed_at: Duration::ZERO,
    host_closed: true,
    delivered: [false; 2],
    released: [false; 2],
};

/// Every pair ever created, the log, and the scheduled surface events.
#[derive(Debug, Default)]
pub struct Buffers {
    /// Every pair, in creation order.
    pub pairs: Vec<Pair>,
    /// The operation log.
    pub log: Vec<LogEntry>,
    /// The fake time of the call in progress.
    pub now: Duration,
    events: Vec<(Duration, SurfaceEvent)>,
}

impl Buffers {
    /// Add a pair and return its index.
    pub fn add_pair(&mut self, pair: Pair) -> usize {
        self.pairs.push(pair);
        self.pairs.len() - 1
    }

    /// Schedule `event` to surface at `at`.
    pub fn schedule(&mut self, at: Duration, event: SurfaceEvent) {
        self.events.push((at, event));
    }

    /// Take the earliest event due at or before `now`.
    pub fn take_due(&mut self, now: Duration) -> Option<SurfaceEvent> {
        let earliest = self
            .events
            .iter()
            .enumerate()
            .filter(|(_, (at, _))| *at <= now)
            .min_by_key(|(_, (at, _))| *at)
            .map(|(index, _)| index)?;
        Some(self.events.remove(earliest).1)
    }

    /// The earliest scheduled event time, if any.
    #[must_use]
    pub fn next_event_time(&self) -> Option<Duration> {
        self.events.iter().map(|(at, _)| *at).min()
    }

    /// The pair at `index`, or an empty closed pair when there is none.
    #[must_use]
    pub fn pair_at(&self, index: usize) -> &Pair {
        self.pairs.get(index).unwrap_or(&NO_PAIR)
    }

    /// The state word of `pair`, if it exists.
    #[must_use]
    pub fn state_of(&self, pair: usize) -> Option<u32> {
        self.pairs.get(pair).map(|pair| pair.state)
    }

    /// Compare-exchange the state word of `pair` as `actor`; `false` when it lost or is absent.
    pub fn cas(&mut self, actor: Actor, pair: usize, current: u32, new: u32) -> bool {
        let at = self.now;
        let won = match self.pairs.get_mut(pair) {
            Some(slot) if slot.state == current => {
                slot.state = new;
                slot.state_changed_at = at;
                true
            }
            _ => false,
        };
        self.log.push(LogEntry::Cas {
            actor,
            pair,
            current,
            new,
            won,
            at,
        });
        won
    }

    /// Store the state word of `pair` as `actor`.
    pub fn store(&mut self, actor: Actor, pair: usize, value: u32) {
        let at = self.now;
        self.pairs.get_mut(pair).into_iter().for_each(|slot| {
            slot.state = value;
            slot.state_changed_at = at;
        });
        self.log.push(LogEntry::Store {
            actor,
            pair,
            value,
            at,
        });
    }

    /// The document is gone: every buffer the page still holds is released with it.
    pub fn teardown_page(&mut self) {
        for slot in &mut self.pairs {
            for (released, delivered) in slot.released.iter_mut().zip(slot.delivered) {
                *released = *released || delivered;
            }
        }
    }

    /// Mark a buffer as received by the page.
    pub fn deliver(&mut self, pair: usize, role: Role) {
        self.pairs
            .get_mut(pair)
            .into_iter()
            .for_each(|slot| slot.delivered[role.slot()] = true);
        self.log.push(LogEntry::PageReceived { pair, role });
    }

    /// Record that a buffer was lost because the page had no listener yet.
    pub fn lose(&mut self, pair: usize, role: Role) {
        self.log.push(LogEntry::PageLost { pair, role });
    }

    /// The page releases one buffer.
    pub fn release(&mut self, pair: usize, role: Role) {
        let at = self.now;
        self.pairs
            .get_mut(pair)
            .into_iter()
            .for_each(|slot| slot.released[role.slot()] = true);
        self.log.push(LogEntry::PageReleased { pair, role, at });
    }

    /// Write the reply payload and its length word.
    pub fn write_payload(&mut self, pair: usize, payload: &[u8]) {
        let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        self.pairs.get_mut(pair).into_iter().for_each(|slot| {
            slot.reply
                .get_mut(offset::PAYLOAD..offset::PAYLOAD + payload.len())
                .into_iter()
                .for_each(|target| target.copy_from_slice(payload));
            Self::set_word(&mut slot.reply, offset::PAYLOAD_LEN, length);
        });
    }

    /// Overwrite one little-endian word of the reply header or payload.
    pub fn set_reply_word(&mut self, pair: usize, at_offset: usize, value: u32) {
        self.pairs
            .get_mut(pair)
            .into_iter()
            .for_each(|slot| Self::set_word(&mut slot.reply, at_offset, value));
    }

    /// Overwrite one byte of the reply buffer.
    pub fn set_reply_byte(&mut self, pair: usize, at_offset: usize, value: u8) {
        self.pairs
            .get_mut(pair)
            .and_then(|slot| slot.reply.get_mut(at_offset))
            .into_iter()
            .for_each(|byte| *byte = value);
    }

    /// A scripted page writes into the read-only request buffer: the renderer crashes.
    pub fn write_request(&mut self, pair: usize, now: Duration) {
        self.log.push(LogEntry::RequestWritten { pair });
        self.schedule(now, SurfaceEvent::RendererFailed);
    }

    /// Zero the reply payload area, as the page's release sequence does.
    pub fn zero_reply_payload(&mut self, pair: usize) {
        self.pairs
            .get_mut(pair)
            .and_then(|slot| slot.reply.get_mut(offset::PAYLOAD..))
            .into_iter()
            .for_each(|payload| payload.fill(0));
    }

    fn set_word(bytes: &mut [u8], at_offset: usize, value: u32) {
        bytes
            .get_mut(at_offset..at_offset + 4)
            .into_iter()
            .for_each(|word| word.copy_from_slice(&value.to_le_bytes()));
    }
}
