//! ADR-112 trusted-clock authority adapters.
//!
//! These adapters implement the trusted-host storage and guard ports of
//! `pos_core::trusted_clock`. They report rows and lock state only; every
//! fence decision is made in `pos-core`.
//!
//! No ARD1 artifact catalog exists in these stores yet, so both adapters
//! report zero authoritative catalog entries and the one-time migration may
//! create missing rows. The catalog owner (#432) must report its real count.

use pos_core::trusted_clock::{
    ReleaseGuardPortV1, TrustedClockAcknowledgementRowV1, TrustedClockHighWaterRowV1,
    TrustedClockOverrunLatchRowV1, TrustedClockPortErrorV1, TrustedClockRowsV1,
    TrustedClockStorePortV1,
};
use rand::{rngs::SysRng, TryRng};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

#[cfg(feature = "sqlite")]
mod sqlite;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteTrustedClockAuthorityV1;

fn fresh_clock_domain() -> Result<[u8; 16], TrustedClockPortErrorV1> {
    let mut domain = [0; 16];
    let filled = SysRng.try_fill_bytes(&mut domain);
    filled
        .map(|()| domain)
        .or(Err(TrustedClockPortErrorV1::Storage))
}

#[derive(Debug, Default)]
struct MemoryAuthorityStateV1 {
    rows: TrustedClockRowsV1,
    acknowledgements: Vec<TrustedClockAcknowledgementRowV1>,
    writer_held: bool,
}

#[derive(Debug, Default)]
struct MemoryAuthorityV1 {
    state: Mutex<MemoryAuthorityStateV1>,
    released: Condvar,
}

#[derive(Debug)]
struct MemoryTransactionV1 {
    rows: TrustedClockRowsV1,
    acknowledgements: Vec<TrustedClockAcknowledgementRowV1>,
}

/// One `MemoryStore` trusted-clock authority identity.
///
/// Every handle from [`Self::handle`] shares one authority lock and one set of
/// rows, so reservations and guards on different handles serialize exactly as
/// `SQLite` connections on one file do. Durability is the identity's lifetime.
#[derive(Debug, Default)]
pub struct MemoryTrustedClockAuthorityV1 {
    shared: Arc<MemoryAuthorityV1>,
    transaction: Option<MemoryTransactionV1>,
    holds_writer: bool,
}

fn lock(shared: &MemoryAuthorityV1) -> MutexGuard<'_, MemoryAuthorityStateV1> {
    shared.state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl MemoryTrustedClockAuthorityV1 {
    /// A fresh identity with no rows.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Another handle on the same identity and authority lock.
    #[must_use]
    pub fn handle(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            transaction: None,
            holds_writer: false,
        }
    }

    /// Committed rows.
    #[must_use]
    pub fn rows(&self) -> TrustedClockRowsV1 {
        lock(&self.shared).rows.clone()
    }

    /// Committed acknowledgement rows in append order.
    #[must_use]
    pub fn acknowledgements(&self) -> Vec<TrustedClockAcknowledgementRowV1> {
        lock(&self.shared).acknowledgements.clone()
    }

    fn acquire(&mut self, timeout: Duration) -> Result<(), TrustedClockPortErrorV1> {
        let start = Instant::now();
        let deadline = start.checked_add(timeout).unwrap_or(start);
        let mut state = lock(&self.shared);
        while state.writer_held {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TrustedClockPortErrorV1::Busy);
            }
            let waited = self.shared.released.wait_timeout(state, remaining);
            state = waited.unwrap_or_else(PoisonError::into_inner).0;
        }
        state.writer_held = true;
        drop(state);
        self.holds_writer = true;
        Ok(())
    }

    fn release(&mut self) {
        if self.holds_writer {
            lock(&self.shared).writer_held = false;
            self.shared.released.notify_all();
            self.holds_writer = false;
        }
    }

    fn transaction_mut(&mut self) -> Result<&mut MemoryTransactionV1, TrustedClockPortErrorV1> {
        self.transaction
            .as_mut()
            .ok_or(TrustedClockPortErrorV1::Storage)
    }
}

impl Drop for MemoryTrustedClockAuthorityV1 {
    fn drop(&mut self) {
        self.release();
    }
}

impl TrustedClockStorePortV1 for MemoryTrustedClockAuthorityV1 {
    fn verify_durability_pragmas(&mut self) -> Result<bool, TrustedClockPortErrorV1> {
        Ok(true)
    }

    fn begin_immediate(&mut self, busy_timeout: Duration) -> Result<(), TrustedClockPortErrorV1> {
        self.acquire(busy_timeout)?;
        let rows = self.rows();
        self.transaction = Some(MemoryTransactionV1 {
            rows,
            acknowledgements: Vec::new(),
        });
        Ok(())
    }

    fn authoritative_catalog_entries(&mut self) -> Result<u64, TrustedClockPortErrorV1> {
        Ok(0)
    }

    fn read_rows(&mut self) -> Result<TrustedClockRowsV1, TrustedClockPortErrorV1> {
        self.transaction_mut().map(|tx| tx.rows.clone())
    }

    fn generate_clock_domain(&mut self) -> Result<[u8; 16], TrustedClockPortErrorV1> {
        fresh_clock_domain()
    }

    fn write_high_water(
        &mut self,
        row: &TrustedClockHighWaterRowV1,
    ) -> Result<(), TrustedClockPortErrorV1> {
        let row = row.clone();
        self.transaction_mut()
            .map(|tx| tx.rows.high_water = vec![row])
    }

    fn write_overrun_latch(
        &mut self,
        row: &TrustedClockOverrunLatchRowV1,
    ) -> Result<(), TrustedClockPortErrorV1> {
        let row = *row;
        self.transaction_mut()
            .map(|tx| tx.rows.overrun_latch = vec![row])
    }

    fn append_acknowledgement(
        &mut self,
        row: &TrustedClockAcknowledgementRowV1,
    ) -> Result<(), TrustedClockPortErrorV1> {
        let row = *row;
        self.transaction_mut()
            .map(|tx| tx.acknowledgements.push(row))
    }

    fn commit(&mut self) -> Result<(), TrustedClockPortErrorV1> {
        let transaction = self.transaction_mut()?;
        let rows = std::mem::take(&mut transaction.rows);
        let acknowledgements = std::mem::take(&mut transaction.acknowledgements);
        let mut state = lock(&self.shared);
        state.rows = rows;
        state.acknowledgements.extend(acknowledgements);
        drop(state);
        self.transaction = None;
        self.release();
        Ok(())
    }

    fn rollback(&mut self) {
        self.transaction = None;
        self.release();
    }
}

impl ReleaseGuardPortV1 for MemoryTrustedClockAuthorityV1 {
    fn begin_guard(&mut self, busy_timeout: Duration) -> Result<(), TrustedClockPortErrorV1> {
        self.acquire(busy_timeout)
    }

    fn reread_rows(&mut self) -> Result<TrustedClockRowsV1, TrustedClockPortErrorV1> {
        Ok(self.rows())
    }

    fn rollback_and_release(&mut self) {
        self.transaction = None;
        self.release();
    }
}
