//! Fake listener view, cleanup store and process probe.

use std::cell::RefCell;
use std::rc::Rc;

use pos_owner_bridge_codec::ImagePathSha256;

use crate::{
    BridgeError, CleanupError, CleanupStore, LoopbackPort, ProbeResult, ProcessProbe,
    ServedSnapshot, UnavailableCode,
};

#[derive(Debug)]
struct LoopbackState {
    served: ServedSnapshot,
    fail_probes_from: Option<u32>,
    resets: u32,
    probes: u32,
}

/// A fake loopback listener whose served count and probe verdict the test scripts.
#[derive(Clone, Debug)]
pub struct FakeLoopback {
    state: Rc<RefCell<LoopbackState>>,
}

impl FakeLoopback {
    /// Script the served count and integrity verdict.
    pub fn set_served(&self, count: u32, integrity_ok: bool) {
        self.state.borrow_mut().served = ServedSnapshot {
            count,
            integrity_ok,
        };
    }

    /// Make the IPv6-absence probe fail from its `n`-th run on (1-based); `None` never fails.
    pub fn fail_probes_from(&self, n: Option<u32>) {
        self.state.borrow_mut().fail_probes_from = n;
    }

    /// How many navigations began.
    #[must_use]
    pub fn resets(&self) -> u32 {
        self.state.borrow().resets
    }

    /// How many IPv6 probes ran.
    #[must_use]
    pub fn probes(&self) -> u32 {
        self.state.borrow().probes
    }
}

impl Default for FakeLoopback {
    /// A listener that has served nothing and whose IPv6 probe succeeds.
    fn default() -> Self {
        Self {
            state: Rc::new(RefCell::new(LoopbackState {
                served: ServedSnapshot {
                    count: 0,
                    integrity_ok: true,
                },
                fail_probes_from: None,
                resets: 0,
                probes: 0,
            })),
        }
    }
}

impl LoopbackPort for FakeLoopback {
    fn begin_navigation(&mut self) {
        let mut state = self.state.borrow_mut();
        state.resets += 1;
        state.served = ServedSnapshot {
            count: 0,
            integrity_ok: true,
        };
    }

    fn served(&self) -> ServedSnapshot {
        self.state.borrow().served
    }

    fn probe_ipv6(&mut self) -> Result<(), BridgeError> {
        let mut state = self.state.borrow_mut();
        state.probes += 1;
        if state
            .fail_probes_from
            .is_some_and(|from| state.probes >= from)
        {
            Err(BridgeError::Unavailable(UnavailableCode::LoopbackChanged))
        } else {
            Ok(())
        }
    }
}

/// A cleanup-store operation a test can make fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreOp {
    /// `write_record`.
    Write,
    /// `delete_record`.
    Delete,
    /// `records`.
    List,
    /// `remove_folder`.
    Remove,
}

#[derive(Debug, Default)]
struct StoreState {
    records: Vec<Vec<u8>>,
    removed: Vec<String>,
    failing: Vec<StoreOp>,
}

/// An in-memory cleanup store with scripted failures.
#[derive(Clone, Debug, Default)]
pub struct FakeStore {
    state: Rc<RefCell<StoreState>>,
}

impl FakeStore {
    /// Make exactly the operations in `ops` fail.
    pub fn set_failing(&self, ops: &[StoreOp]) {
        self.state.borrow_mut().failing = ops.to_vec();
    }

    /// Pre-load an encoded record, as left by a crashed run.
    pub fn preload(&self, record: Vec<u8>) {
        self.state.borrow_mut().records.push(record);
    }

    /// The encoded records still stored.
    #[must_use]
    pub fn records_now(&self) -> Vec<Vec<u8>> {
        self.state.borrow().records.clone()
    }

    /// The folder names removed so far.
    #[must_use]
    pub fn removed_folders(&self) -> Vec<String> {
        self.state.borrow().removed.clone()
    }

    fn fails(&self, op: StoreOp) -> bool {
        self.state.borrow().failing.contains(&op)
    }
}

impl CleanupStore for FakeStore {
    fn write_record(&mut self, record: &[u8]) -> Result<(), CleanupError> {
        if self.fails(StoreOp::Write) {
            return Err(CleanupError);
        }
        self.state.borrow_mut().records.push(record.to_vec());
        Ok(())
    }

    fn delete_record(&mut self, record: &[u8]) -> Result<(), CleanupError> {
        if self.fails(StoreOp::Delete) {
            return Err(CleanupError);
        }
        self.state
            .borrow_mut()
            .records
            .retain(|stored| stored != record);
        Ok(())
    }

    fn records(&mut self) -> Result<Vec<Vec<u8>>, CleanupError> {
        if self.fails(StoreOp::List) {
            return Err(CleanupError);
        }
        Ok(self.state.borrow().records.clone())
    }

    fn remove_folder(&mut self, folder_name: &str) -> Result<(), CleanupError> {
        if self.fails(StoreOp::Remove) {
            return Err(CleanupError);
        }
        self.state.borrow_mut().removed.push(folder_name.to_owned());
        Ok(())
    }
}

/// A process probe that replays a script, then repeats its last verdict.
#[derive(Clone, Debug)]
pub struct FakeProbe {
    script: Vec<ProbeResult>,
    calls: usize,
}

impl FakeProbe {
    /// Replay `script`; an empty script always answers `Absent`.
    #[must_use]
    pub const fn new(script: Vec<ProbeResult>) -> Self {
        Self { script, calls: 0 }
    }

    /// How many probes ran.
    #[must_use]
    pub const fn calls(&self) -> usize {
        self.calls
    }
}

impl ProcessProbe for FakeProbe {
    fn probe(
        &mut self,
        _browser_pid: u32,
        _creation_filetime: u64,
        _image_path_sha256: &ImagePathSha256,
    ) -> ProbeResult {
        let index = self.calls.min(self.script.len().saturating_sub(1));
        self.calls += 1;
        self.script
            .get(index)
            .copied()
            .unwrap_or(ProbeResult::Absent)
    }
}
