//! ADR-137 N1/N2: the durable reservation reads, validates, advances, replaces
//! and reads back before it returns a counter, and never returns one again.

use pos_core::{Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1};
use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerRowV1, SubjectNonceLedgerV1, SubjectStoreFileIdV1,
    EXHAUSTED_SUBJECT_NONCE_COUNTER,
};

use super::{
    DurableSubjectNonceReservationV1, SubjectNonceLedgerStorageErrorV1, SubjectNonceLedgerStorageV1,
};
use crate::subject_data_consumer::{SubjectDataConsumerErrorV1, SubjectNonceReservationPortV1};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OWNER: &str = "subject:000102030405060708090a0b0c0d0e0f";
const OTHER_OWNER: &str = "subject:ffffffffffffffffffffffffffffffff";
const STORE: SubjectStoreFileIdV1 = SubjectStoreFileIdV1::Linux {
    device: 2,
    inode: 3,
};
const OTHER_STORE: SubjectStoreFileIdV1 = SubjectStoreFileIdV1::Linux {
    device: 2,
    inode: 4,
};
const ONE_MIB: usize = 1024 * 1024;
const REFUSED: SubjectDataConsumerErrorV1 = SubjectDataConsumerErrorV1::NonceReservationRefused;

/// How the fake storage answers a replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Replace {
    /// Store the bytes.
    Store,
    /// Fail without storing anything.
    FailUnchanged,
    /// Store the bytes, then report failure.
    FailAfterStoring,
    /// Report success but store something else.
    StoreOther,
    /// Report success but store more than the documented 1 MiB.
    StoreOversized,
}

struct Storage {
    bytes: Vec<u8>,
    reads: usize,
    replaces: usize,
    fail_read_at: Option<usize>,
    replace: Replace,
}

impl Storage {
    fn new(ledger: &SubjectNonceLedgerV1) -> Self {
        Self::raw(ledger.as_bytes())
    }

    fn raw(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            reads: 0,
            replaces: 0,
            fail_read_at: None,
            replace: Replace::Store,
        }
    }
}

impl SubjectNonceLedgerStorageV1 for Storage {
    fn read_ledger_bytes(&mut self) -> Result<Vec<u8>, SubjectNonceLedgerStorageErrorV1> {
        let call = self.reads;
        self.reads += 1;
        if self.fail_read_at == Some(call) {
            Err(SubjectNonceLedgerStorageErrorV1)
        } else {
            Ok(self.bytes.clone())
        }
    }

    fn replace_ledger_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), SubjectNonceLedgerStorageErrorV1> {
        self.replaces += 1;
        match self.replace {
            Replace::Store => {
                self.bytes = bytes.to_vec();
                Ok(())
            }
            Replace::FailUnchanged => Err(SubjectNonceLedgerStorageErrorV1),
            Replace::FailAfterStoring => {
                self.bytes = bytes.to_vec();
                Err(SubjectNonceLedgerStorageErrorV1)
            }
            Replace::StoreOther => {
                self.bytes = b"other".to_vec();
                Ok(())
            }
            Replace::StoreOversized => {
                self.bytes = vec![0; ONE_MIB + 1];
                Ok(())
            }
        }
    }
}

fn row(
    owner: &str,
    epoch: u64,
    data_next: u64,
    store: SubjectStoreFileIdV1,
) -> SubjectNonceLedgerRowV1 {
    SubjectNonceLedgerRowV1 {
        owner_id: owner.to_owned(),
        epoch,
        root_material_digest: [7; 32],
        store_file_id: store,
        data_next,
        bootstrap_next: 5,
    }
}

fn ledger(
    rows: Vec<SubjectNonceLedgerRowV1>,
) -> Result<SubjectNonceLedgerV1, Box<dyn std::error::Error>> {
    Ok(SubjectNonceLedgerV1::new(rows)?)
}

fn identity(
    owner: &str,
    role: KeyRoleV1,
    epoch: u64,
) -> Result<KeyIdentityV1, Box<dyn std::error::Error>> {
    Ok(KeyIdentityV1::new(OwnerIdV1::new(owner)?, role, epoch))
}

fn data(owner: &str, epoch: u64) -> Result<KeyIdentityV1, Box<dyn std::error::Error>> {
    identity(owner, KeyRoleV1::SubjectDataEncryption, epoch)
}

fn digest() -> Hash {
    Hash::from_bytes([7; 32])
}

fn single(data_next: u64) -> Result<SubjectNonceLedgerV1, Box<dyn std::error::Error>> {
    ledger(vec![row(OWNER, 1, data_next, STORE)])
}

fn new_port(storage: Storage) -> DurableSubjectNonceReservationV1<Storage> {
    DurableSubjectNonceReservationV1::new(storage, STORE)
}

fn stored(
    port: &DurableSubjectNonceReservationV1<Storage>,
) -> Result<SubjectNonceLedgerV1, Box<dyn std::error::Error>> {
    Ok(SubjectNonceLedgerV1::from_bytes(&port.storage.bytes)?)
}

#[test]
fn reservations_return_each_counter_once_and_persist_the_successor() -> TestResult {
    let mut port = new_port(Storage::new(&single(7)?));
    assert_eq!(port.reserve_data_counter(data(OWNER, 1)?, digest()), Ok(7));
    assert_eq!(stored(&port)?.rows().next().map(|r| r.data_next), Some(8));
    assert_eq!(port.reserve_data_counter(data(OWNER, 1)?, digest()), Ok(8));
    assert_eq!(stored(&port)?.rows().next().map(|r| r.data_next), Some(9));
    // Each reservation read the ledger, replaced it, and read it back.
    assert_eq!(port.storage.replaces, 2);
    assert_eq!(port.storage.reads, 4);
    Ok(())
}

#[test]
fn only_the_exact_row_advances_and_everything_else_is_preserved() -> TestResult {
    let ledger = ledger(vec![
        row(OWNER, 1, 3, STORE),
        row(OWNER, 2, 11, STORE),
        row(OTHER_OWNER, 1, 20, STORE),
    ])?;
    let mut port = new_port(Storage::new(&ledger));
    assert_eq!(port.reserve_data_counter(data(OWNER, 2)?, digest()), Ok(11));
    let after = stored(&port)?;
    let counters: Vec<(u64, u64)> = after
        .rows()
        .map(|r| (r.data_next, r.bootstrap_next))
        .collect();
    assert_eq!(counters, vec![(3, 5), (12, 5), (20, 5)]);
    Ok(())
}

#[test]
fn a_non_data_role_is_refused_before_the_ledger_is_read() -> TestResult {
    let mut port = new_port(Storage::new(&single(1)?));
    for role in [
        KeyRoleV1::SubjectAttributionSigning,
        KeyRoleV1::TimelineIntegritySigning,
    ] {
        assert_eq!(
            port.reserve_data_counter(identity(OWNER, role, 1)?, digest()),
            Err(REFUSED)
        );
    }
    assert_eq!((port.storage.reads, port.storage.replaces), (0, 0));
    Ok(())
}

#[test]
fn any_field_mismatch_refuses_without_writing_or_spending() -> TestResult {
    let mut port = new_port(Storage::new(&single(1)?));
    let before = port.storage.bytes.clone();
    assert_eq!(
        port.reserve_data_counter(data(OTHER_OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 2)?, digest()),
        Err(REFUSED)
    );
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, Hash::from_bytes([8; 32])),
        Err(REFUSED)
    );
    assert_eq!((port.storage.replaces, &port.storage.bytes), (0, &before));
    // The exact request still works afterwards.
    assert_eq!(port.reserve_data_counter(data(OWNER, 1)?, digest()), Ok(1));
    Ok(())
}

#[test]
fn a_foreign_store_identity_is_decryption_only_and_never_rewritten() -> TestResult {
    let mut port = DurableSubjectNonceReservationV1::new(
        Storage::new(&ledger(vec![row(OWNER, 1, 4, OTHER_STORE)])?),
        STORE,
    );
    let before = port.storage.bytes.clone();
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!((port.storage.replaces, &port.storage.bytes), (0, &before));
    // A different expected identity of another platform tag never matches.
    let windows = SubjectStoreFileIdV1::Windows {
        volume_serial: 2,
        file_index: 3,
    };
    let mut port = DurableSubjectNonceReservationV1::new(Storage::new(&single(4)?), windows);
    let before = port.storage.bytes.clone();
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!((port.storage.replaces, &port.storage.bytes), (0, &before));
    Ok(())
}

#[test]
fn an_unreadable_or_malformed_ledger_refuses_without_writing() -> TestResult {
    let mut unreadable = Storage::new(&single(1)?);
    unreadable.fail_read_at = Some(0);
    let mut port = new_port(unreadable);
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!(port.storage.replaces, 0);
    // The failed read spent nothing: the next attempt reserves counter 1.
    assert_eq!(port.reserve_data_counter(data(OWNER, 1)?, digest()), Ok(1));

    for bytes in [&b""[..], b"not a ledger", b"\x83DSNL1"] {
        let mut port = new_port(Storage::raw(bytes));
        assert_eq!(
            port.reserve_data_counter(data(OWNER, 1)?, digest()),
            Err(REFUSED)
        );
        assert_eq!(port.storage.replaces, 0);
    }
    let mut empty = new_port(Storage::new(&ledger(Vec::new())?));
    assert_eq!(
        empty.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    Ok(())
}

#[test]
fn an_exhausted_counter_refuses_and_leaves_the_ledger_alone() -> TestResult {
    let mut port = new_port(Storage::new(&single(EXHAUSTED_SUBJECT_NONCE_COUNTER)?));
    let before = port.storage.bytes.clone();
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!((port.storage.replaces, &port.storage.bytes), (0, &before));

    // The last usable counter is returned once, then the ledger is exhausted.
    let mut last = new_port(Storage::new(&single(EXHAUSTED_SUBJECT_NONCE_COUNTER - 1)?));
    assert_eq!(
        last.reserve_data_counter(data(OWNER, 1)?, digest()),
        Ok(EXHAUSTED_SUBJECT_NONCE_COUNTER - 1)
    );
    assert_eq!(
        last.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    Ok(())
}

/// The failed reservation refuses, never restores the old counter, and the next
/// call re-reads the ledger: it returns `next_counter` (the successor row when
/// the replacement landed, the never-returned old counter when it did not).
fn assert_refused_then_reads_afresh(
    storage: Storage,
    stored_data_next: u64,
    next_counter: u64,
) -> TestResult {
    let mut port = new_port(storage);
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!(port.storage.replaces, 1);
    assert_eq!(
        SubjectNonceLedgerV1::from_bytes(&port.storage.bytes)
            .ok()
            .and_then(|l| l.rows().next().map(|r| r.data_next)),
        Some(stored_data_next)
    );
    port.storage.replace = Replace::Store;
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Ok(next_counter)
    );
    assert_eq!(
        stored(&port)?.rows().next().map(|r| r.data_next),
        Some(next_counter + 1)
    );
    Ok(())
}

#[test]
fn a_failed_replacement_leaves_the_old_row_and_the_next_call_reserves_it() -> TestResult {
    let mut failed = Storage::new(&single(2)?);
    failed.replace = Replace::FailUnchanged;
    assert_refused_then_reads_afresh(failed, 2, 2)
}

#[test]
fn an_unconfirmed_replacement_that_landed_makes_the_next_call_return_the_successor() -> TestResult {
    let mut after_storing = Storage::new(&single(2)?);
    after_storing.replace = Replace::FailAfterStoring;
    assert_refused_then_reads_afresh(after_storing, 3, 3)
}

#[test]
fn a_failed_readback_makes_the_next_call_return_the_successor() -> TestResult {
    let mut storage = Storage::new(&single(2)?);
    // Read 0 loads the ledger, read 1 is the readback.
    storage.fail_read_at = Some(1);
    assert_refused_then_reads_afresh(storage, 3, 3)
}

#[test]
fn a_readback_that_differs_from_the_replacement_refuses_and_keeps_refusing() -> TestResult {
    let mut storage = Storage::new(&single(2)?);
    storage.replace = Replace::StoreOther;
    let mut port = new_port(storage);
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!(port.storage.bytes, b"other");
    // The ledger is no longer a valid SNL1: every later call refuses unwritten.
    port.storage.replace = Replace::Store;
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!(
        (port.storage.replaces, &port.storage.bytes),
        (1, &b"other".to_vec())
    );
    Ok(())
}

#[test]
fn an_oversized_readback_is_refused() -> TestResult {
    let mut storage = Storage::new(&single(2)?);
    storage.replace = Replace::StoreOversized;
    let mut port = new_port(storage);
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!(port.storage.bytes.len(), ONE_MIB + 1);
    // An oversized ledger is never decoded, so the next call refuses unwritten.
    assert_eq!(
        port.reserve_data_counter(data(OWNER, 1)?, digest()),
        Err(REFUSED)
    );
    assert_eq!(port.storage.replaces, 1);
    Ok(())
}

#[test]
fn the_failures_carry_fixed_text_only() {
    assert_eq!(
        SubjectNonceLedgerStorageErrorV1.to_string(),
        "subject nonce ledger storage was unavailable"
    );
    assert_eq!(REFUSED.to_string(), "subject nonce reservation was refused");
}
