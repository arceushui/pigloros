//! `test-support` in-memory trusted-clock ports with injectable faults.
//!
//! The fixture models one authority identity with a single writer lock.
//! Clones are further handles on the same identity.
#![cfg(any(test, feature = "test-support"))]

use crate::trusted_clock::{
    ReleaseGuardPortV1, TrustedClockAcknowledgementRowV1, TrustedClockHighWaterRowV1,
    TrustedClockOverrunLatchRowV1, TrustedClockPortErrorV1, TrustedClockRowsV1,
    TrustedClockStorePortV1,
};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use TrustedClockFixtureFaultV1 as Fault;

static NEXT_FIXTURE_DOMAIN: AtomicU64 = AtomicU64::new(1);

/// One-shot fixture faults; each fires on the next matching port call.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TrustedClockFixtureFaultV1 {
    DurabilityMismatch,
    DurabilityError,
    BeginBusy,
    BeginStorage,
    CatalogError,
    ReadError,
    ReadBusy,
    ReadCorrupt,
    DomainError,
    WriteHighWater,
    WriteLatch,
    AppendAcknowledgement,
    Commit,
    GuardBusy,
    GuardStorage,
    GuardRead,
    GuardReadBusy,
}

impl TrustedClockFixtureFaultV1 {
    const fn port_error(self) -> TrustedClockPortErrorV1 {
        match self {
            Self::ReadBusy | Self::GuardReadBusy => TrustedClockPortErrorV1::Busy,
            Self::ReadCorrupt => TrustedClockPortErrorV1::Corrupt,
            _ => TrustedClockPortErrorV1::Storage,
        }
    }
}

type FixtureTransactionV1 = (TrustedClockRowsV1, Vec<TrustedClockAcknowledgementRowV1>);

#[derive(Debug, Default)]
struct FixtureStateV1 {
    rows: TrustedClockRowsV1,
    acknowledgements: Vec<TrustedClockAcknowledgementRowV1>,
    transaction: Option<FixtureTransactionV1>,
    writer_held: bool,
    catalog_entries: u64,
    faults: BTreeSet<Fault>,
}

/// One fixture authority identity.
#[derive(Clone, Debug, Default)]
pub struct TrustedClockFixtureV1 {
    state: Rc<RefCell<FixtureStateV1>>,
}

impl TrustedClockFixtureV1 {
    /// A fresh identity with no rows and an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm a one-shot fault.
    pub fn arm(&self, fault: Fault) {
        self.state.borrow_mut().faults.insert(fault);
    }

    /// Set the authoritative catalog entry count.
    pub fn set_catalog_entries(&self, entries: u64) {
        self.state.borrow_mut().catalog_entries = entries;
    }

    /// Committed rows.
    #[must_use]
    pub fn rows(&self) -> TrustedClockRowsV1 {
        self.state.borrow().rows.clone()
    }

    /// Replace the committed rows, as a file swap or corruption would.
    pub fn set_rows(&self, rows: TrustedClockRowsV1) {
        self.state.borrow_mut().rows = rows;
    }

    /// Committed acknowledgement rows in append order.
    #[must_use]
    pub fn acknowledgements(&self) -> Vec<TrustedClockAcknowledgementRowV1> {
        self.state.borrow().acknowledgements.clone()
    }

    /// Whether any handle holds the writer lock.
    #[must_use]
    pub fn writer_held(&self) -> bool {
        self.state.borrow().writer_held
    }

    fn fault(&self, fault: Fault) -> Result<(), TrustedClockPortErrorV1> {
        if self.state.borrow_mut().faults.remove(&fault) {
            Err(fault.port_error())
        } else {
            Ok(())
        }
    }

    fn acquire(&self, busy: Fault) -> Result<(), TrustedClockPortErrorV1> {
        let mut state = self.state.borrow_mut();
        if state.writer_held || state.faults.remove(&busy) {
            return Err(TrustedClockPortErrorV1::Busy);
        }
        state.writer_held = true;
        Ok(())
    }

    fn with_transaction(
        &self,
        apply: impl FnOnce(&mut FixtureTransactionV1),
    ) -> Result<(), TrustedClockPortErrorV1> {
        let mut state = self.state.borrow_mut();
        let transaction = state
            .transaction
            .as_mut()
            .ok_or(TrustedClockPortErrorV1::Storage)?;
        apply(transaction);
        Ok(())
    }
}

impl TrustedClockStorePortV1 for TrustedClockFixtureV1 {
    fn verify_durability_pragmas(&mut self) -> Result<bool, TrustedClockPortErrorV1> {
        self.fault(Fault::DurabilityError)?;
        Ok(self.fault(Fault::DurabilityMismatch).is_ok())
    }

    fn begin_immediate(&mut self, _busy_timeout: Duration) -> Result<(), TrustedClockPortErrorV1> {
        self.fault(Fault::BeginStorage)?;
        self.acquire(Fault::BeginBusy)?;
        let mut state = self.state.borrow_mut();
        let rows = state.rows.clone();
        state.transaction = Some((rows, Vec::new()));
        Ok(())
    }

    fn authoritative_catalog_entries(&mut self) -> Result<u64, TrustedClockPortErrorV1> {
        self.fault(Fault::CatalogError)?;
        Ok(self.state.borrow().catalog_entries)
    }

    fn read_rows(&mut self) -> Result<TrustedClockRowsV1, TrustedClockPortErrorV1> {
        self.fault(Fault::ReadError)?;
        self.fault(Fault::ReadBusy)?;
        self.fault(Fault::ReadCorrupt)?;
        let state = self.state.borrow();
        let rows = state.transaction.as_ref().map_or(&state.rows, |tx| &tx.0);
        Ok(rows.clone())
    }

    fn generate_clock_domain(&mut self) -> Result<[u8; 16], TrustedClockPortErrorV1> {
        self.fault(Fault::DomainError)?;
        let next = NEXT_FIXTURE_DOMAIN.fetch_add(1, Ordering::Relaxed);
        Ok((u128::from(next) | (0xF1 << 120)).to_le_bytes())
    }

    fn write_high_water(
        &mut self,
        row: &TrustedClockHighWaterRowV1,
    ) -> Result<(), TrustedClockPortErrorV1> {
        self.fault(Fault::WriteHighWater)?;
        let row = row.clone();
        self.with_transaction(|tx| tx.0.high_water = vec![row])
    }

    fn write_overrun_latch(
        &mut self,
        row: &TrustedClockOverrunLatchRowV1,
    ) -> Result<(), TrustedClockPortErrorV1> {
        self.fault(Fault::WriteLatch)?;
        let row = *row;
        self.with_transaction(|tx| tx.0.overrun_latch = vec![row])
    }

    fn append_acknowledgement(
        &mut self,
        row: &TrustedClockAcknowledgementRowV1,
    ) -> Result<(), TrustedClockPortErrorV1> {
        self.fault(Fault::AppendAcknowledgement)?;
        let row = *row;
        self.with_transaction(|tx| tx.1.push(row))
    }

    fn commit(&mut self) -> Result<(), TrustedClockPortErrorV1> {
        self.fault(Fault::Commit)?;
        let mut state = self.state.borrow_mut();
        let (rows, acknowledgements) = state
            .transaction
            .take()
            .ok_or(TrustedClockPortErrorV1::Storage)?;
        state.rows = rows;
        state.acknowledgements.extend(acknowledgements);
        state.writer_held = false;
        Ok(())
    }

    fn rollback(&mut self) {
        let mut state = self.state.borrow_mut();
        state.transaction = None;
        state.writer_held = false;
    }
}

impl ReleaseGuardPortV1 for TrustedClockFixtureV1 {
    fn begin_guard(&mut self, _busy_timeout: Duration) -> Result<(), TrustedClockPortErrorV1> {
        self.fault(Fault::GuardStorage)?;
        self.acquire(Fault::GuardBusy)
    }

    fn reread_rows(&mut self) -> Result<TrustedClockRowsV1, TrustedClockPortErrorV1> {
        self.fault(Fault::GuardRead)?;
        self.fault(Fault::GuardReadBusy)?;
        Ok(self.rows())
    }

    fn rollback_and_release(&mut self) {
        self.state.borrow_mut().writer_held = false;
    }
}
