#![cfg(all(target_os = "linux", any(test, feature = "test-support")))]
//! The ADR-121 owner field-read port over the qualified owner store (#1557).
//!
//! [`OwnerSubjectFieldReaderV1`] implements
//! [`SubjectFieldOwnerReadPortV1`] over a [`QualifiedSqliteStoreV1`]. One call
//! runs, in order, under the store's shared admission and its one guarded
//! `BEGIN IMMEDIATE` (ADR-123 §6):
//!
//! 1. the exact-Timeline ADR-097 B6 fence check
//!    ([`require_no_erasure_fence_rows`]); a row that is present, unreadable
//!    or malformed refuses with `ErasureFenced` before any Event is read or
//!    any key is touched;
//! 2. the latest committed `subject.data.v1` Event of the subject in Timeline
//!    Order, without fallback (ADR-137 A3: one lookup per segment of the
//!    stitched Fork chain, newest segment first, through
//!    `idx_events_entity_type`, never a scan);
//! 3. the key registry, read inside the same transaction, then key
//!    verification, decryption and validation by the consumer's
//!    `deliver_latest`, against that held registry.
//!
//! The outcome is delivered exactly once, adapter staging is wiped, and the
//! transaction is then rolled back explicitly: the read never commits. A
//! panicking callback is caught only to finish the transaction, and the
//! original panic is resumed afterwards.
//!
//! The lookup names `idx_events_entity_type` with `INDEXED BY`, so a store
//! without that index refuses with `ReadUnavailableBeforeDelivery` instead of
//! scanning. This module creates no schema: the qualified constructor never
//! initializes one (ADR-123 §4), and the ADR-137 writable-open slice owns the
//! index definition. Only the exact Timeline's B6 row is consulted: no Fork
//! ancestor or descendant is, so a frozen ancestor segment stays readable.
//!
//! Everything here stays test-support gated until owner activation (#1438).

use std::any::Any;
use std::convert::Infallible;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

use pos_core::clock::Seq;
use pos_core::error::CoreError;
use pos_core::ids::TimelineId;
use pos_core::{
    EntityId, Event, Hash, KeyIdentityV1, KeyRegistryErrorV1,
    KeyRegistryHistoricalDecryptionPortV1, KeyRegistryStateV1,
};
use pos_crypto::subject_data::SUBJECT_DATA_EVENT_TYPE;
use pos_crypto::subject_field_read::{
    SubjectFieldOwnerReadErrorV1, SubjectFieldOwnerReadPortV1, SubjectFieldReadCallbackErrorV1,
    SubjectFieldReadResultV1, SubjectFieldSelectorV1,
};
use rusqlite::{params, OptionalExtension};

use super::erasure_fence_rows::require_no_erasure_fence_rows;
use super::{sqlite_load_key_registry, SqliteStore};
use crate::owner_store_binding::{OwnerStoreBindingErrorV1, QualifiedSqliteStoreV1};
use crate::subject_data_consumer::{
    deliver_latest, SubjectKeyringV1, PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
};

/// The newest `subject.data.v1` Event of one subject within one Fork segment.
///
/// `INDEXED BY` makes a missing `idx_events_entity_type` an error, never a
/// scan. The bound is the segment's logical length: a parent segment ends at
/// its child's Fork point.
const LATEST_IN_SEGMENT_SQL: &str = "SELECT seq FROM events INDEXED BY idx_events_entity_type
     WHERE timeline_id = ?1 AND entity_id = ?2 AND event_type = ?3 AND seq <= ?4
     ORDER BY seq DESC
     LIMIT 1";

/// A caught callback unwind payload, resumed after the transaction finished.
type PanicPayload = Box<dyn Any + Send>;

/// How the in-transaction read ended, before the transaction finished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadEndV1 {
    /// The exact-Timeline B6 check refused: a row was present, unreadable or malformed.
    Fenced,
    /// A non-erasure infrastructure failure came before any outcome existed.
    Unavailable,
    /// One outcome was delivered and the callback returned success.
    Delivered,
    /// One outcome was delivered and the callback returned `Failed`.
    CallbackFailed,
}

/// The ADR-121 owner field-read port of one qualified owner store.
///
/// It borrows the store, so the same store keeps serving its other guarded
/// operations, and one subject's keyring. A keyring reads only its own
/// subject; any other `subject_id` delivers `Integrity`.
#[derive(Debug)]
pub struct OwnerSubjectFieldReaderV1<'bound> {
    store: &'bound mut QualifiedSqliteStoreV1,
    keys: &'bound SubjectKeyringV1,
}

impl<'bound> OwnerSubjectFieldReaderV1<'bound> {
    /// Bind the qualified store and the keyring of the subject it may read.
    #[must_use]
    pub const fn new(
        store: &'bound mut QualifiedSqliteStoreV1,
        keys: &'bound SubjectKeyringV1,
    ) -> Self {
        Self { store, keys }
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only seam: end the guarded transaction early so its finish fails.
    static END_TRANSACTION_EARLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl SubjectFieldOwnerReadPortV1 for OwnerSubjectFieldReaderV1<'_> {
    fn with_subject_field_read(
        &mut self,
        timeline_id: TimelineId,
        subject_id: EntityId,
        field: SubjectFieldSelectorV1,
        deliver: &mut dyn FnMut(
            SubjectFieldReadResultV1,
        ) -> Result<(), SubjectFieldReadCallbackErrorV1>,
    ) -> Result<(), SubjectFieldOwnerReadErrorV1> {
        let keys = self.keys;
        let mut outcome: Result<ReadEndV1, PanicPayload> = Ok(ReadEndV1::Unavailable);
        // The operation always fails on purpose: `guarded` then rolls back, and
        // a read never commits. `Infallible` states that it cannot succeed.
        let finish = self.store.guarded(|binding| {
            outcome = read_in_transaction(
                binding.store(),
                keys,
                (timeline_id, subject_id),
                field,
                deliver,
            );
            #[cfg(test)]
            if END_TRANSACTION_EARLY.with(std::cell::Cell::get) {
                binding.store().conn.execute_batch("COMMIT").unwrap_or(());
            }
            Err::<Infallible, ()>(())
        });
        // The callback's panic is resumed only after the transaction finished
        // (ADR-121 §6); a failed finish stays observable as a quarantine.
        match outcome {
            Ok(end) => outer_result(finish, end),
            Err(payload) => resume_unwind(payload),
        }
    }
}

/// Map the guarded operation's result and how the read ended to ADR-121 §5.
const fn outer_result(
    finish: Result<Result<Infallible, ()>, OwnerStoreBindingErrorV1>,
    end: ReadEndV1,
) -> Result<(), SubjectFieldOwnerReadErrorV1> {
    use SubjectFieldOwnerReadErrorV1 as Refusal;
    match (finish, end) {
        (Err(OwnerStoreBindingErrorV1::Admission(refusal)), _) => Err(refusal),
        (
            Err(OwnerStoreBindingErrorV1::Unavailable | OwnerStoreBindingErrorV1::ModeBinding(_)),
            _,
        )
        | (Ok(_), ReadEndV1::Unavailable) => Err(Refusal::ReadUnavailableBeforeDelivery),
        (Err(OwnerStoreBindingErrorV1::Quarantined), ReadEndV1::Fenced) => {
            Err(Refusal::ErasureFencedTransactionFinishFailed)
        }
        (Err(OwnerStoreBindingErrorV1::Quarantined), ReadEndV1::Unavailable) => {
            Err(Refusal::TransactionFinishFailedBeforeDelivery)
        }
        (
            Err(OwnerStoreBindingErrorV1::Quarantined),
            ReadEndV1::Delivered | ReadEndV1::CallbackFailed,
        ) => Err(Refusal::TransactionFinishFailedAfterDelivery),
        (Ok(_), ReadEndV1::Fenced) => Err(Refusal::ErasureFenced),
        (Ok(_), ReadEndV1::CallbackFailed) => Err(Refusal::CallbackFailed),
        (Ok(_), ReadEndV1::Delivered) => Ok(()),
    }
}

/// The body inside the guarded `BEGIN IMMEDIATE`, in ADR-121 §3 order.
fn read_in_transaction(
    store: &SqliteStore,
    keys: &SubjectKeyringV1,
    (timeline_id, subject_id): (TimelineId, EntityId),
    field: SubjectFieldSelectorV1,
    deliver: &mut dyn FnMut(
        SubjectFieldReadResultV1,
    ) -> Result<(), SubjectFieldReadCallbackErrorV1>,
) -> Result<ReadEndV1, PanicPayload> {
    // The closed selector has exactly one accepted field; a second variant
    // must not compile here until its tag is bound.
    let SubjectFieldSelectorV1::PersonaPreferenceWeights = field;
    let conn = &store.conn;
    require_no_erasure_fence_rows(conn, timeline_id)
        .map_err(|_| ReadEndV1::Fenced)
        .and_then(|()| {
            latest_subject_data(conn, timeline_id, subject_id)
                .and_then(|latest| {
                    sqlite_load_key_registry(conn).map(|registry| (latest, registry))
                })
                .map_err(|_| ReadEndV1::Unavailable)
        })
        .map_or_else(Ok, |(latest, registry)| {
            deliver_once(keys, registry.as_ref(), (subject_id, latest), deliver)
        })
}

/// Deliver the latest Event's outcome once, catching only the callback's unwind.
fn deliver_once(
    keys: &SubjectKeyringV1,
    registry: Option<&KeyRegistryStateV1>,
    (subject_id, latest): (EntityId, Option<Event>),
    deliver: &mut dyn FnMut(
        SubjectFieldReadResultV1,
    ) -> Result<(), SubjectFieldReadCallbackErrorV1>,
) -> Result<ReadEndV1, PanicPayload> {
    let mut held = HeldRegistryV1(registry.cloned());
    catch_unwind(AssertUnwindSafe(|| {
        deliver_latest(
            &mut held,
            keys,
            registry,
            (subject_id, latest.as_ref()),
            PERSONA_PREFERENCE_WEIGHTS_FIELD_TAG,
            deliver,
        )
    }))
    .map(|delivered| match delivered {
        Ok(()) => ReadEndV1::Delivered,
        Err(SubjectFieldReadCallbackErrorV1::Failed) => ReadEndV1::CallbackFailed,
    })
}

/// The key registry as read inside the guarded transaction.
///
/// The transaction holds the `SQLite` write lock, so no rotation or
/// destruction commits while the callback runs. The store's own
/// authorization opens a second transaction, which cannot nest here.
struct HeldRegistryV1(Option<KeyRegistryStateV1>);

impl KeyRegistryHistoricalDecryptionPortV1 for HeldRegistryV1 {
    fn with_decryption_authorization<T, F>(
        &mut self,
        identity: KeyIdentityV1,
        private_material_digest: Hash,
        operation: F,
    ) -> Result<T, KeyRegistryErrorV1>
    where
        F: FnOnce() -> T,
    {
        self.0
            .as_mut()
            .ok_or(KeyRegistryErrorV1::RegistryUnavailable)
            .and_then(|registry| {
                registry.with_decryption_authorization(identity, private_material_digest, operation)
            })
    }
}

/// The latest `subject.data.v1` Event of `subject` in the stitched Timeline.
///
/// Segments are visited newest first and the walk keeps the first hit, which
/// is the latest in Timeline Order. The Event keeps the logical sequence the
/// stitched read would give it.
fn latest_subject_data(
    conn: &rusqlite::Connection,
    timeline: TimelineId,
    subject: EntityId,
) -> Result<Option<Event>, CoreError> {
    SqliteStore::fork_chain_on(conn, timeline).and_then(|chain| {
        (0..chain.len()).rev().try_fold(None, |found, index| {
            found.map_or_else(
                || segment_latest(conn, &chain, index, subject),
                |event| Ok(Some(event)),
            )
        })
    })
}

/// The newest matching Event of one segment, found through the index.
fn segment_latest(
    conn: &rusqlite::Connection,
    chain: &[(TimelineId, Seq)],
    index: usize,
    subject: EntityId,
) -> Result<Option<Event>, CoreError> {
    let (member, prefix) = chain[index];
    SqliteStore::logical_segment_length_on(conn, chain, index, member)
        .and_then(|length| {
            conn.query_row(
                LATEST_IN_SEGMENT_SQL,
                params![
                    member.to_string(),
                    subject.to_string(),
                    SUBJECT_DATA_EVENT_TYPE,
                    i64::try_from(length).unwrap_or(i64::MAX)
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(SqliteStore::into_storage_error)
        })
        .and_then(|local| {
            local
                .map(|local| {
                    let local = Seq::from_u64(u64::try_from(local).unwrap_or(0));
                    SqliteStore::read_own_events_on(conn, member, local, Some(local)).map(
                        |events| {
                            events.into_iter().next().map(|mut event| {
                                event.seq =
                                    Seq::from_u64(prefix.as_u64().saturating_add(local.as_u64()));
                                event
                            })
                        },
                    )
                })
                .transpose()
        })
        .map(Option::flatten)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
