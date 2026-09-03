#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-store` — `EventStore` port adapters and backend factory.
//!
//! # Domain-Driven Design
//!
//! The domain port ([`EventStore`]) is defined in `pos-core`. This crate
//! provides the infrastructure adapters (in-memory, `SQLite`) and a factory
//! ([`open_store`]) so callers hold `Box<dyn EventStore>` and never import
//! a concrete backend type.
//!
//! # Consumer import path
//!
//! Prefer importing export/import helpers from **this crate** together with
//! [`open_store`]:
//!
//! | Intent | Export | Import |
//! |--------|--------|--------|
//! | Independent clone | [`export_timeline`] | [`import_timeline`] |
//! | Identity `CoW` | [`export_timeline_own`] | [`import_timeline_with_id`] |
//! | Verified identity | [`export_timeline_own`] | [`import_timeline_with_verified_signatures`] |
//!
//! Signatures cover the owner/role/epoch domain and **payload bytes only** (not
//! event metadata). See
//! [`import_timeline_with_verified_signatures`].
//!
//! # Backend features
//!
//! | Feature | Default | Dependency |
//! |---------|---------|------------|
//! | `sqlite` | ✅ on | `rusqlite` (WAL; encryption / `SQLCipher` deferred) |
//!
//! Disable `SQLite` entirely: `--no-default-features`
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod memory;
pub mod stitch;

#[cfg(feature = "sqlite")]
pub mod sqlite;

// Re-export the port, its append-deduplication surface, and Wave 6 export/import helpers so
// hosts need one crate.
pub use pos_core::store::{
    append_identity_expires_at, checked_append_identity_expires_at, export_timeline,
    export_timeline_cow, export_timeline_own, export_timeline_raw, import_committed_with_rollback,
    import_timeline, import_timeline_with_id, AppendDedupKey, AppendDedupScope, AppendIdentity,
    AppendIntent, AppendOrDuplicateOutcome, EventStore, PurgeOutcome, SeqRange, TimelineExport,
    APPEND_IDENTITY_RETENTION_MICROS,
};
pub use pos_core::{
    CanonicalBytes, CoreError, CorrelationId, EntityId, ErasureFreezeAuthorizationVerifierV1,
    ErasurePersistencePortV1, Event, EventDraft, EventId, GeographicAdmissionAdmin,
    GeographicAdmissionOutcome, GeographicAdmissionStore, GeographicReplayEvidenceV1,
    GeographicReplayVerifier, Kind, OwnTracksEnrollmentStore, TimelineId,
    ValidatedGeographicAdmissionV1, WallTime,
};

/// Resolve a generic-adapter visibility check without exposing protected Timeline state.
///
/// Both store backends use this concrete seam so that an unavailable presence marker
/// remains a backend error, while an existing marker is indistinguishable from a
/// missing Timeline to ordinary callers.
pub(crate) fn ensure_generic_timeline_visibility(
    geographic_presence: Result<bool, CoreError>,
    timeline: TimelineId,
) -> Result<(), CoreError> {
    generic_timeline_is_visible(geographic_presence).and_then(|visible| {
        if visible {
            Ok(())
        } else {
            Err(CoreError::TimelineNotFound(timeline))
        }
    })
}

/// Convert a backend's protected-evidence marker into its generic visibility.
pub(crate) fn generic_timeline_is_visible(
    geographic_presence: Result<bool, CoreError>,
) -> Result<bool, CoreError> {
    match geographic_presence {
        Ok(false) => Ok(true),
        Ok(true) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Refuse protected drafts before a generic adapter evaluates Timeline visibility.
///
/// This preserves the public boundary's `TimelineNotFound` response and, importantly,
/// avoids querying a possibly unavailable presence marker for an already-forbidden
/// draft.
pub(crate) fn ensure_non_geographic_draft(
    draft: &EventDraft,
    timeline: TimelineId,
) -> Result<(), CoreError> {
    if pos_core::is_geographic_event_type(&draft.event_type)
        || pos_core::is_consent_event_type(&draft.event_type)
    {
        Err(CoreError::TimelineNotFound(timeline))
    } else {
        Ok(())
    }
}

/// Apply [`ensure_non_geographic_draft`] to one batched generic append.
pub(crate) fn ensure_non_geographic_drafts(
    drafts: &[EventDraft],
    timeline: TimelineId,
) -> Result<(), CoreError> {
    match drafts.iter().find(|draft| {
        pos_core::is_geographic_event_type(&draft.event_type)
            || pos_core::is_consent_event_type(&draft.event_type)
    }) {
        Some(_) => Err(CoreError::TimelineNotFound(timeline)),
        None => Ok(()),
    }
}

/// Validate that a batch is restricted to the dedicated V1 consent types.
pub(crate) fn ensure_gateway_consent_types(
    drafts: &[EventDraft],
    timeline: TimelineId,
) -> Result<(), CoreError> {
    if drafts.is_empty()
        || drafts.iter().any(|draft| {
            !matches!(
                draft.event_type.as_str(),
                pos_core::EVENT_TYPE_CONSENT_GRANTED_V1 | pos_core::EVENT_TYPE_CONSENT_REVOKED_V1
            )
        })
    {
        Err(CoreError::TimelineNotFound(timeline))
    } else {
        Ok(())
    }
}

/// Validate the single-revocation batch required by the atomic revocation seam.
pub(crate) fn ensure_gateway_consent_revocation(
    drafts: &[EventDraft],
    timeline: TimelineId,
) -> Result<(), CoreError> {
    if drafts.len() != 1 || drafts[0].event_type.as_str() != pos_core::EVENT_TYPE_CONSENT_REVOKED_V1
    {
        Err(CoreError::TimelineNotFound(timeline))
    } else {
        Ok(())
    }
}

/// Validate the dedicated Gateway-owned V1 consent append seam, including the
/// canonical payload and logical Timeline coordinates.
pub(crate) fn ensure_gateway_consent_drafts(
    drafts: &[EventDraft],
    timeline: TimelineId,
    existing_owner: Option<pos_core::EntityId>,
    expected_first_seq: u64,
) -> Result<pos_core::EntityId, CoreError> {
    ensure_gateway_consent_types(drafts, timeline)?;
    // `ensure_gateway_consent_types` guarantees a non-empty batch, so the
    // first draft supplies a safe initial owner when the Timeline has not
    // recorded one yet. Coordinate validation below rejects any mismatch.
    let owner = existing_owner.unwrap_or(drafts[0].entity);
    for (index, draft) in drafts.iter().enumerate() {
        let expected_seq =
            expected_first_seq.saturating_add(u64::try_from(index).unwrap_or(u64::MAX));
        if draft.event_type.as_str() == pos_core::EVENT_TYPE_CONSENT_GRANTED_V1 {
            let grant = pos_core::ConsentGrantedV1::decode(&draft.payload)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if draft.entity != grant.subject_id || grant.grant_seq != expected_seq {
                return Err(CoreError::Storage(
                    "consent grant coordinate mismatch".to_owned(),
                ));
            }
            if owner != grant.subject_id {
                return Err(CoreError::Storage(
                    "consent Timeline owner mismatch".to_owned(),
                ));
            }
        } else {
            let revocation = pos_core::ConsentRevokedV1::decode(&draft.payload)
                .map_err(|error| CoreError::Storage(error.to_string()))?;
            if draft.entity != revocation.subject_id || revocation.fence_seq != expected_seq {
                return Err(CoreError::Storage(
                    "consent revocation coordinate mismatch".to_owned(),
                ));
            }
            if owner != revocation.subject_id {
                return Err(CoreError::Storage(
                    "consent Timeline owner mismatch".to_owned(),
                ));
            }
        }
    }
    Ok(owner)
}

/// Refuse committed sensitive Events before a generic import or append path can
/// mutate a Timeline. Geographic admission and Gateway-owned consent both use
/// dedicated host seams; generic import and append remain closed.
pub(crate) fn ensure_non_geographic_events(
    events: &[Event],
    timeline: TimelineId,
) -> Result<(), CoreError> {
    match events.iter().find(|event| {
        pos_core::is_geographic_event_type(&event.event_type)
            || pos_core::is_consent_event_type(&event.event_type)
    }) {
        Some(_) => Err(CoreError::TimelineNotFound(timeline)),
        None => Ok(()),
    }
}

/// Compute the next backend-owned Event head and enforce its atomic ceiling.
///
/// Keeping this arithmetic shared gives every adapter identical overflow and
/// limit semantics before it mutates backend state.
pub(crate) fn bounded_owned_head(
    owned_head: u64,
    batch_len: u64,
    max_owned_events: u64,
) -> Result<Option<u64>, CoreError> {
    let next_head = owned_head
        .checked_add(batch_len)
        .ok_or_else(|| CoreError::Storage("bounded append owned Event head overflow".to_owned()))?;
    Ok((next_head <= max_owned_events).then_some(next_head))
}

/// Validate the logical head implied by a fork prefix and backend-owned head.
pub(crate) fn checked_logical_head(logical_prefix: u64, owned_head: u64) -> Result<u64, CoreError> {
    logical_prefix
        .checked_add(owned_head)
        .ok_or_else(|| CoreError::Storage("logical Timeline sequence overflow".to_owned()))
}

/// Convert the optional result of a bounded append helper for an unbounded call.
pub(crate) fn unbounded_append_outcome(
    outcome: Option<AppendOrDuplicateOutcome>,
) -> Result<AppendOrDuplicateOutcome, CoreError> {
    outcome.ok_or_else(|| {
        CoreError::Storage("unbounded append unexpectedly hit an event limit".to_owned())
    })
}

/// Selects which backend [`open_store`] constructs.
///
/// `Memory` is always available. The `Sqlite` variants require the
/// `sqlite` Cargo feature (enabled by default).
#[derive(Clone, Debug)]
pub enum StoreConfig {
    /// Pure in-memory store. Fast, no persistence. Ideal for tests and
    /// short-lived experiments.
    Memory,

    /// `SQLite` WAL store at a filesystem path.
    ///
    /// Requires the `sqlite` feature.
    #[cfg(feature = "sqlite")]
    Sqlite {
        /// Filesystem path to the `.db` file. Created if it does not exist.
        path: String,
    },

    /// `SQLite` store backed by a private in-memory database.
    ///
    /// Behaves identically to [`StoreConfig::Sqlite`] but without touching
    /// the filesystem. Useful for tests that need full `SQLite` semantics.
    ///
    /// Requires the `sqlite` feature.
    #[cfg(feature = "sqlite")]
    SqliteInMemory,
}

/// Construct an event store backend and return it as `Box<dyn EventStore>`.
///
/// This is the single entry point for infrastructure wiring. Callers
/// should never import `MemoryStore` or `SqliteStore` directly.
///
/// # Errors
///
/// Returns [`CoreError::Storage`] if the backend cannot be initialised
/// (e.g. the `SQLite` file path is not writable or schema initialisation fails).
///
/// # Panics
///
/// Panics if in-memory `SQLite` store cannot be opened (should never happen in practice).
///
/// # Examples
///
/// ```rust
/// use pos_core::{
///     clock::Seq,
///     event::{CanonicalBytes, EventDraft, Kind},
///     ids::EntityId,
///     store::SeqRange,
/// };
/// use pos_store::{
///     export_timeline_own, import_timeline_with_id, open_store, StoreConfig,
/// };
///
/// // Parent-then-child CoW sync (identity-preserving).
/// let mut src = open_store(StoreConfig::Memory).unwrap();
/// let root = src.create_timeline("root").unwrap();
/// let entity = EntityId::new();
/// src.append(
///     root.id(),
///     &[EventDraft::new(
///         entity,
///         Kind::new("demo"),
///         CanonicalBytes::from_vec(b"p1".to_vec()),
///     )],
/// )
/// .unwrap();
/// let child = src.fork(root.id(), Seq::from_u64(1), "child").unwrap();
///
/// let mut dst = open_store(StoreConfig::Memory).unwrap();
/// import_timeline_with_id(&mut *dst, export_timeline_own(&*src, root.id()).unwrap()).unwrap();
/// import_timeline_with_id(&mut *dst, export_timeline_own(&*src, child.id()).unwrap()).unwrap();
/// assert_eq!(dst.read(child.id(), SeqRange::all()).unwrap().len(), 1);
/// ```
pub fn open_store(config: StoreConfig) -> Result<Box<dyn EventStore>, CoreError> {
    open_store_with_hasher(config, Box::new(pos_crypto::chain::Blake3Hasher))
}

/// Open an existing `SQLite` store for read-only consumers.
///
/// Unlike [`open_store`], this never creates a database, initializes schema,
/// or returns a writable backend.
///
/// # Errors
/// Returns `CoreError::Storage` if the database cannot be opened or its current
/// schema/invariants are invalid.
#[cfg(feature = "sqlite")]
pub fn open_store_read_only(sqlite_path: &str) -> Result<Box<dyn EventStore>, CoreError> {
    sqlite::SqliteStore::open_read_only(sqlite_path)
        .map(|store| Box::new(store) as Box<dyn EventStore>)
}

/// Open the SQLite-backed local `OwnTracks` enrollment administration capability.
///
/// This deliberately returns only [`OwnTracksEnrollmentStore`], not generic
/// [`EventStore`] or geographic-admission capabilities.
///
/// # Errors
///
/// Returns [`CoreError::Storage`] when the database cannot be opened or its
/// enrollment schema cannot be initialized.
#[cfg(feature = "sqlite")]
pub fn open_owntracks_enrollment_store(
    sqlite_path: &str,
) -> Result<Box<dyn OwnTracksEnrollmentStore>, CoreError> {
    sqlite::SqliteStore::open(sqlite_path).map(|store| Box::new(store) as Box<_>)
}

/// Like [`open_store`] but with a custom [`pos_core::Hasher`] for hash-chain computation.
///
/// # Errors
/// Returns [`CoreError::Storage`] if the backend cannot be initialised.
pub fn open_store_with_hasher(
    config: StoreConfig,
    hasher: Box<dyn pos_core::Hasher>,
) -> Result<Box<dyn EventStore>, CoreError> {
    match config {
        StoreConfig::Memory => Ok(Box::new(memory::MemoryStore::with_hasher(hasher))),
        #[cfg(feature = "sqlite")]
        StoreConfig::Sqlite { path } => {
            let store = sqlite::SqliteStore::open_with_hasher(&path, hasher)?;
            Ok(Box::new(store))
        }
        #[cfg(feature = "sqlite")]
        StoreConfig::SqliteInMemory => {
            let store = sqlite::SqliteStore::open_in_memory_with_hasher(hasher)?;
            Ok(Box::new(store))
        }
    }
}

/// Cryptographically verify signed events in `export`, then identity-import.
///
/// Every event must carry a signature and a `TimelineIntegritySigning`
/// owner/role/epoch identity that is present in the destination registry and whose
/// retained public key matches `public_key`. Verification uses the owner/role/epoch
/// domain and **payload bytes only** (event metadata is not covered). An empty
/// event list is allowed.
///
/// Use this when the export is uniformly signed by one key. For mixed unsigned events
/// or multiple signers, apply the appropriate role-bound verifier per event (or filter)
/// yourself, then call [`import_timeline_with_id`].
///
/// # Errors
/// Returns [`CoreError::SignatureVerificationFailed`] if any event is unsigned or fails
/// verify, or any error from [`import_timeline_with_id`].
pub fn import_timeline_with_verified_signatures(
    store: &mut dyn EventStore,
    export: TimelineExport,
    public_key: &pos_core::PublicKey,
) -> Result<pos_core::Timeline, CoreError> {
    let vk = pos_crypto::signing::verifying_key_from_public_key(public_key)?;
    let registry = if export.events.is_empty() {
        None
    } else {
        Some(store.load_key_registry()?.ok_or_else(|| {
            CoreError::Storage(
                "verified Timeline import requires a persisted key registry".to_owned(),
            )
        })?)
    };
    let mut verified_identity = None;
    for event in &export.events {
        let Some(signature) = &event.signature else {
            return Err(CoreError::SignatureVerificationFailed);
        };
        let Some(identity) = event.signature_identity else {
            return Err(CoreError::SignatureVerificationFailed);
        };
        if identity.role != pos_core::KeyRoleV1::TimelineIntegritySigning {
            return Err(CoreError::SignatureVerificationFailed);
        }
        if verified_identity.is_some_and(|expected| expected != identity) {
            return Err(CoreError::SignatureVerificationFailed);
        }
        let Some(record) = registry
            .as_ref()
            .and_then(|value| value.key_record(identity))
        else {
            return Err(CoreError::SignatureVerificationFailed);
        };
        if record.public_verification_key != Some(*public_key) {
            return Err(CoreError::SignatureVerificationFailed);
        }
        verified_identity = Some(identity);
        pos_crypto::key_roles::verify_for_role(&vk, identity, &event.payload, signature)?;
    }
    import_timeline_with_id(store, export)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected store facade fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing store facade fixture value"))
            })
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful store facade fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bounded_head_helpers_cover_accept_reject_and_overflow() {
        assert_eq!(bounded_owned_head(2, 1, 3).test_ok(), Some(3));
        assert_eq!(bounded_owned_head(2, 2, 3).test_ok(), None);
        assert!(matches!(
            bounded_owned_head(u64::MAX, 1, u64::MAX),
            Err(CoreError::Storage(_))
        ));
        assert_eq!(checked_logical_head(2, 3).test_ok(), 5);
        assert!(matches!(
            checked_logical_head(u64::MAX, 1),
            Err(CoreError::Storage(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_draft_guards_cover_revocation_and_owner_failures() {
        let timeline = pos_core::TimelineId::new();
        let subject = pos_core::EntityId::new();
        let other = pos_core::EntityId::new();
        let grant = pos_core::ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: pos_core::EntityId::new(),
            purpose: "store-guard".to_owned(),
            modalities: pos_core::MODALITY_LOCATION,
            min_geo_resolution: 1,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let grant_draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            grant.encode().test_ok(),
        );
        assert!(ensure_gateway_consent_revocation(&[], timeline).is_err());
        let grant_owner_error = ensure_gateway_consent_drafts(
            std::slice::from_ref(&grant_draft),
            timeline,
            Some(other),
            1,
        )
        .test_err();
        assert!(grant_owner_error.to_string().contains("owner mismatch"));

        let revocation = pos_core::ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: grant.grantee_id,
            grant_seq: grant.grant_seq,
            fence_seq: 1,
        };
        let revocation_draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            revocation.encode().test_ok(),
        );
        let revocation_owner_error = ensure_gateway_consent_drafts(
            std::slice::from_ref(&revocation_draft),
            timeline,
            Some(other),
            1,
        )
        .test_err();
        assert!(revocation_owner_error
            .to_string()
            .contains("owner mismatch"));
    }

    fn assert_consent_store_authority_boundary(store: &mut dyn EventStore) {
        let timeline = store.create_timeline("consent-authority").test_ok();
        let subject = EntityId::new();
        let draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            CanonicalBytes::from_static(b"grant"),
        );
        let authority = pos_core::ConsentAuthority::new();
        let permit = authority.append_permit();
        let missing = store
            .append_consent_bounded(timeline.id(), &[draft], permit, 1)
            .test_err();
        assert!(missing.to_string().contains("not bound"));

        store.bind_consent_authority(permit).test_ok();
        store.bind_consent_authority(permit).test_ok();
        let foreign = pos_core::ConsentAuthority::new().append_permit();
        assert!(store.bind_consent_authority(foreign).is_err());

        let owned = store
            .create_timeline_with_meta(pos_core::timeline::TimelineMeta::root_owned(
                "owned-authority",
                subject,
            ))
            .test_ok();
        let fetched = store.get_timeline(owned.id()).test_ok().test_ok();
        assert_eq!(fetched.meta.owner, Some(subject));
        let child = store
            .fork(owned.id(), pos_core::Seq::ZERO, "owned-child")
            .test_ok();
        assert_eq!(child.meta.owner, Some(subject));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_store_authority_boundary_is_shared_by_backends() {
        let mut memory = open_store(StoreConfig::Memory).test_ok();
        assert_consent_store_authority_boundary(memory.as_mut());
        #[cfg(feature = "sqlite")]
        {
            let mut sqlite = open_store(StoreConfig::SqliteInMemory).test_ok();
            assert_consent_store_authority_boundary(sqlite.as_mut());
        }
    }

    #[test]
    fn unbounded_append_outcome_maps_both_optional_states() {
        assert!(matches!(
            unbounded_append_outcome(Some(AppendOrDuplicateOutcome::Conflict)),
            Ok(AppendOrDuplicateOutcome::Conflict)
        ));
        assert!(unbounded_append_outcome(None).is_err());
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn owntracks_factory_exposes_only_the_narrow_enrollment_capability() {
        let directory = tempfile::tempdir().test_ok();
        let path = directory.path().join("owntracks.db");
        let store = open_owntracks_enrollment_store(path.to_str().test_ok()).test_ok();
        assert_eq!(
            store.owntracks_enrollment_status().test_ok().status(),
            pos_core::OwnTracksEnrollmentStatusV1::Absent
        );
    }

    /// Helper: run a minimal contract against any backend via the port.
    fn contract(store: &mut dyn EventStore) {
        let tl = store.create_timeline("contract-test").test_ok();
        assert_eq!(store.list_timelines().test_ok().len(), 1);
        let events = store.read(tl.id(), SeqRange::all()).test_ok();
        assert!(events.is_empty());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_identity(key: u8, scope: u8) -> AppendIdentity {
        AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([key; 32]),
            AppendDedupScope::from_keyed_hash([scope; 32]),
        )
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_scope_withdrawal(
        store: &mut dyn EventStore,
        timeline: pos_core::TimelineId,
        draft: &EventDraft,
    ) {
        let first = store
            .append_or_duplicate(
                timeline,
                append_identity(3, 4),
                WallTime::from_micros(40),
                draft.clone(),
            )
            .test_ok();
        let _ = appended_event_id(first);
        assert_eq!(
            store
                .remove_append_identities(AppendDedupScope::from_keyed_hash([4; 32]))
                .test_ok(),
            1
        );
        let after_withdrawal = store
            .append_or_duplicate(
                timeline,
                append_identity(3, 4),
                WallTime::from_micros(40),
                draft.clone(),
            )
            .test_ok();
        let _ = appended_event_id(after_withdrawal);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn appended_event_id(outcome: AppendOrDuplicateOutcome) -> EventId {
        match outcome {
            AppendOrDuplicateOutcome::Appended(event) => event.id,
            AppendOrDuplicateOutcome::Duplicate { .. } | AppendOrDuplicateOutcome::Conflict => {
                std::panic::resume_unwind(Box::new("identified append must append an Event"))
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_wall_time_contract(
        store: &mut dyn EventStore,
        timeline: pos_core::TimelineId,
        draft: &EventDraft,
        event_id: EventId,
    ) {
        let duplicate = store
            .append_or_duplicate(
                timeline,
                append_identity(1, 2),
                WallTime::from_micros(21),
                draft.clone(),
            )
            .test_ok();
        assert_eq!(duplicate, AppendOrDuplicateOutcome::Duplicate { event_id });
        let mut retry_without_wall_time = draft.clone();
        retry_without_wall_time.wall_time = None;
        assert_eq!(
            store
                .append_or_duplicate(
                    timeline,
                    append_identity(1, 2),
                    WallTime::from_micros(21),
                    retry_without_wall_time,
                )
                .test_ok(),
            AppendOrDuplicateOutcome::Duplicate { event_id }
        );
        // Generated Event metadata is not part of canonical retry intent. A
        // caller retrying with a different wall-time hint remains a duplicate;
        // identified append owns admission time at the store boundary.
        let mut wall_time_variant = draft.clone();
        wall_time_variant.wall_time = Some(WallTime::from_micros(31));
        assert_eq!(
            store
                .append_or_duplicate(
                    timeline,
                    append_identity(1, 2),
                    WallTime::from_micros(21),
                    wall_time_variant,
                )
                .test_ok(),
            AppendOrDuplicateOutcome::Duplicate { event_id }
        );
    }

    fn assert_timeline_deletion_removes_identities(
        store: &mut dyn EventStore,
        timeline: TimelineId,
        draft: &EventDraft,
    ) {
        store.delete_timeline(timeline).test_ok();
        let replacement = store
            .create_timeline("append-or-duplicate-replacement")
            .test_ok();
        let first_retry = store
            .append_or_duplicate(
                replacement.id(),
                append_identity(1, 2),
                WallTime::from_micros(50),
                draft.clone(),
            )
            .test_ok();
        let _ = appended_event_id(first_retry);
        let second_retry = store
            .append_or_duplicate(
                replacement.id(),
                append_identity(3, 4),
                WallTime::from_micros(50),
                draft.clone(),
            )
            .test_ok();
        let _ = appended_event_id(second_retry);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_contract(store: &mut dyn EventStore) {
        let timeline = store.create_timeline("append-or-duplicate").test_ok();
        let mut draft = EventDraft::new(
            EntityId::new(),
            Kind::new("test.append"),
            CanonicalBytes::from_vec(b"retained-canonical-content".to_vec()),
        )
        .with_wall_time(WallTime::from_micros(30));
        draft.causation_id = Some(EventId::new());
        draft.correlation_id = Some(CorrelationId::new());
        let first = store
            .append_or_duplicate(
                timeline.id(),
                append_identity(1, 2),
                WallTime::from_micros(20),
                draft.clone(),
            )
            .test_ok();
        let event_id = appended_event_id(first);
        let admitted_events = store.read(timeline.id(), SeqRange::all()).test_ok();
        assert_eq!(admitted_events[0].causation_id, draft.causation_id);
        assert_eq!(admitted_events[0].correlation_id, draft.correlation_id);
        assert_wall_time_contract(store, timeline.id(), &draft, event_id);
        let conflict_draft = EventDraft::new(
            draft.entity,
            Kind::new("test.append"),
            CanonicalBytes::from_vec(b"different-retained-canonical-content".to_vec()),
        );
        let conflict = store
            .append_or_duplicate(
                timeline.id(),
                append_identity(1, 2),
                WallTime::from_micros(21),
                conflict_draft,
            )
            .test_ok();
        assert_eq!(conflict, AppendOrDuplicateOutcome::Conflict);
        assert_eq!(
            store.read(timeline.id(), SeqRange::all()).test_ok().len(),
            1
        );

        assert_eq!(
            store
                .purge_expired_append_identities(WallTime::from_micros(
                    20 + APPEND_IDENTITY_RETENTION_MICROS - 1,
                ))
                .test_ok(),
            0
        );
        assert_eq!(
            store
                .purge_expired_append_identities(WallTime::from_micros(
                    20 + APPEND_IDENTITY_RETENTION_MICROS,
                ))
                .test_ok(),
            1
        );
        match store
            .append_or_duplicate(
                timeline.id(),
                append_identity(1, 2),
                WallTime::from_micros(40),
                draft.clone(),
            )
            .test_ok()
        {
            AppendOrDuplicateOutcome::Appended(_) => {}
            AppendOrDuplicateOutcome::Duplicate { .. } | AppendOrDuplicateOutcome::Conflict => {
                std::panic::resume_unwind(Box::new("expired identity must append a new Event"))
            }
        }
        assert_eq!(
            store.read(timeline.id(), SeqRange::all()).test_ok().len(),
            2
        );

        assert_timeline_scoped_and_delayed_expiry(store, timeline.id(), &draft);

        assert_scope_withdrawal(store, timeline.id(), &draft);
        assert_timeline_deletion_removes_identities(store, timeline.id(), &draft);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn assert_timeline_scoped_and_delayed_expiry(
        store: &mut dyn EventStore,
        timeline: pos_core::TimelineId,
        draft: &EventDraft,
    ) {
        let other_timeline = store.create_timeline("append-or-duplicate-other").test_ok();
        // A target Timeline is part of the admission boundary: reusing an
        // opaque key against another Timeline must not disclose the retained
        // Event or return its EventId.
        assert_eq!(
            store
                .append_or_duplicate(
                    other_timeline.id(),
                    append_identity(1, 2),
                    WallTime::from_micros(21),
                    draft.clone(),
                )
                .test_ok(),
            AppendOrDuplicateOutcome::Conflict
        );
        assert!(matches!(
            store.append_or_duplicate(
                pos_core::TimelineId::new(),
                append_identity(1, 2),
                WallTime::from_micros(21),
                draft.clone(),
            ),
            Err(pos_core::CoreError::TimelineNotFound(_))
        ));

        // Admission must replace a logically expired identity even when
        // asynchronous maintenance has not purged it yet.
        let delayed_identity = append_identity(13, 14);
        let delayed_draft = EventDraft::new(
            EntityId::new(),
            Kind::new("test.delayed-expiry"),
            CanonicalBytes::from_vec(b"delayed".to_vec()),
        );
        let delayed_first = store
            .append_or_duplicate(
                timeline,
                delayed_identity,
                WallTime::from_micros(100),
                delayed_draft.clone(),
            )
            .test_ok();
        let _ = appended_event_id(delayed_first);
        assert!(matches!(
            store.append_or_duplicate(
                timeline,
                delayed_identity,
                WallTime::from_micros(100 + APPEND_IDENTITY_RETENTION_MICROS),
                delayed_draft,
            ),
            Ok(AppendOrDuplicateOutcome::Appended(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factory_memory() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        contract(&mut *store);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_contract_memory() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        append_or_duplicate_contract(&mut *store);
    }

    fn bounded_identity_contract(store: &mut dyn EventStore) {
        let timeline = store.create_timeline("bounded-identity").test_ok();
        let entity = EntityId::new();
        let draft = EventDraft::new(
            entity,
            Kind::new("test.bounded"),
            CanonicalBytes::from_vec(b"bounded".to_vec()),
        );
        let identity = append_identity(21, 22);
        let intent = AppendIntent::new(&draft);
        let first = store
            .append_intent_or_duplicate_bounded(timeline.id(), identity, intent.clone(), 1)
            .test_ok()
            .test_ok();
        let event_id = appended_event_id(first);
        assert_eq!(
            store
                .append_intent_or_duplicate_bounded(timeline.id(), identity, intent.clone(), 1)
                .test_ok(),
            Some(AppendOrDuplicateOutcome::Duplicate { event_id })
        );
        assert_eq!(
            store
                .read_event_by_id(timeline.id(), event_id)
                .test_ok()
                .test_ok()
                .id,
            event_id
        );
        assert!(store
            .read_event_by_id(timeline.id(), EventId::new())
            .test_ok()
            .is_none());
        assert!(store
            .append_intent_or_duplicate_bounded(timeline.id(), append_identity(23, 24), intent, 1,)
            .test_ok()
            .is_none());
    }

    #[test]
    fn bounded_identity_contract_memory() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        bounded_identity_contract(&mut *store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factory_sqlite_in_memory() {
        let mut store = open_store(StoreConfig::SqliteInMemory).test_ok();
        contract(&mut *store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_or_duplicate_contract_sqlite() {
        let mut store = open_store(StoreConfig::SqliteInMemory).test_ok();
        append_or_duplicate_contract(&mut *store);
    }

    #[test]
    fn bounded_identity_contract_sqlite() {
        let mut store = open_store(StoreConfig::SqliteInMemory).test_ok();
        bounded_identity_contract(&mut *store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn factory_sqlite_file() {
        let tmp = tempfile::NamedTempFile::new().test_ok();
        let path = tmp.path().to_str().test_ok().to_owned();
        let mut store = open_store(StoreConfig::Sqlite { path }).test_ok();
        contract(&mut *store);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_store_sqlite_rejects_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        let result = open_store(StoreConfig::Sqlite {
            path: dir.path().to_str().test_ok().to_owned(),
        });
        assert!(matches!(result, Err(CoreError::Storage(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_import_roundtrip_memory() {
        let mut src = open_store(StoreConfig::Memory).test_ok();
        let tl = src.create_timeline("source").test_ok();
        let entity = EntityId::new();
        let drafts = vec![
            EventDraft::new(
                entity,
                Kind::new("test.event"),
                CanonicalBytes::from_vec(b"hello".to_vec()),
            ),
            EventDraft::new(
                entity,
                Kind::new("test.event"),
                CanonicalBytes::from_vec(b"world".to_vec()),
            ),
        ];
        src.append(tl.id(), &drafts).test_ok();

        // Export from source
        let export = pos_core::store::export_timeline(src.as_ref(), tl.id()).test_ok();
        assert_eq!(export.events.len(), 2);

        // Import into a fresh store — different backend, same data
        let mut dst = open_store(StoreConfig::Memory).test_ok();
        let imported = pos_core::store::import_timeline(dst.as_mut(), export).test_ok();
        let events = dst.read(imported.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].payload.as_slice(), b"hello");
        assert_eq!(events[1].payload.as_slice(), b"world");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn export_memory_import_sqlite() {
        let mut src = open_store(StoreConfig::Memory).test_ok();
        let tl = src.create_timeline("mem-src").test_ok();
        let entity = EntityId::new();
        src.append(
            tl.id(),
            &[EventDraft::new(
                entity,
                Kind::new("e"),
                CanonicalBytes::from_vec(b"data".to_vec()),
            )],
        )
        .test_ok();

        let export = pos_core::store::export_timeline(src.as_ref(), tl.id()).test_ok();

        let mut dst = open_store(StoreConfig::SqliteInMemory).test_ok();
        let imported = pos_core::store::import_timeline(dst.as_mut(), export).test_ok();
        let events = dst.read(imported.id(), SeqRange::all()).test_ok();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.as_slice(), b"data");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_with_verified_signatures_accepts_valid_and_rejects_bad() {
        use pos_core::{
            clock::{Seq, WallTime},
            event::{Event, SchemaVersion},
            ids::EventId,
            store::TimelineExport,
            timeline::{Timeline, TimelineMeta},
            KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1, KeyRoleV1,
        };
        use pos_crypto::{
            key_roles::{key_material_digest, sign_for_registered_role, SigningKeyMaterial},
            signing::{generate_keypair, public_key_from_verifying_key},
        };

        let (sk, vk) = generate_keypair();
        let signing_material = SigningKeyMaterial::new(sk.clone());
        let pk = public_key_from_verifying_key(&vk);
        let identity = KeyIdentityV1::new("test-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let mut registry = KeyRegistryStateV1::new();
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                key_material_digest(&sk.to_bytes()),
                Some(pk),
            ))
            .test_ok();
        let payload = CanonicalBytes::from_vec(b"signed".to_vec());
        let sig = sign_for_registered_role(&mut registry, &signing_material, identity, &payload)
            .test_ok();
        let entity = EntityId::new();
        let event = Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("t"),
            payload: payload.clone(),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: Some(sig),
            signature_identity: Some(identity),
            payload_hash: pos_crypto::chain::hash_payload(&payload),
        };
        let second_payload = CanonicalBytes::from_vec(b"signed-second".to_vec());
        let second_sig =
            sign_for_registered_role(&mut registry, &signing_material, identity, &second_payload)
                .test_ok();
        let mut second_event = event.clone();
        second_event.id = EventId::new();
        second_event.payload = second_payload.clone();
        second_event.seq = Seq::from_u64(2);
        second_event.signature = Some(second_sig);
        second_event.payload_hash = pos_crypto::chain::hash_payload(&second_payload);
        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("signed")),
            events: vec![event, second_event],
            parent_fork_hash: None,
        };

        let mut ok_store = open_store(StoreConfig::Memory).test_ok();
        ok_store.save_key_registry(&registry).test_ok();
        import_timeline_with_verified_signatures(ok_store.as_mut(), export.clone(), &pk).test_ok();
        assert_verified_import_rejections(&export, &registry, &pk);

        let (_, reject_vk) = generate_keypair();
        let reject_key = public_key_from_verifying_key(&reject_vk);
        let mut bad_store = open_store(StoreConfig::Memory).test_ok();
        bad_store.save_key_registry(&registry).test_ok();
        let err = import_timeline_with_verified_signatures(bad_store.as_mut(), export, &reject_key)
            .test_err();
        assert!(matches!(err, CoreError::SignatureVerificationFailed));
    }

    fn assert_verified_import_rejections(
        export: &pos_core::store::TimelineExport,
        registry: &pos_core::KeyRegistryStateV1,
        public_key: &pos_core::PublicKey,
    ) {
        use pos_core::{KeyIdentityV1, KeyRoleV1};

        let mut missing_registry_store = open_store(StoreConfig::Memory).test_ok();
        let missing_registry = import_timeline_with_verified_signatures(
            missing_registry_store.as_mut(),
            export.clone(),
            public_key,
        )
        .test_err();
        assert!(missing_registry
            .to_string()
            .contains("persisted key registry"));

        let mut missing_identity = export.clone();
        missing_identity.events[0].signature_identity = None;
        let mut missing_identity_store = open_store(StoreConfig::Memory).test_ok();
        missing_identity_store.save_key_registry(registry).test_ok();
        assert!(matches!(
            import_timeline_with_verified_signatures(
                missing_identity_store.as_mut(),
                missing_identity,
                public_key,
            )
            .test_err(),
            CoreError::SignatureVerificationFailed
        ));

        let mut wrong_role = export.clone();
        wrong_role.events[0].signature_identity = Some(KeyIdentityV1::new(
            "test-owner",
            KeyRoleV1::SubjectDataEncryption,
            1,
        ));
        let mut wrong_role_store = open_store(StoreConfig::Memory).test_ok();
        wrong_role_store.save_key_registry(registry).test_ok();
        assert!(matches!(
            import_timeline_with_verified_signatures(
                wrong_role_store.as_mut(),
                wrong_role,
                public_key
            )
            .test_err(),
            CoreError::SignatureVerificationFailed
        ));

        let mut mismatched_identity = export.clone();
        mismatched_identity.events[1].signature_identity = Some(KeyIdentityV1::new(
            "test-owner",
            KeyRoleV1::TimelineIntegritySigning,
            2,
        ));
        let mut mismatched_identity_store = open_store(StoreConfig::Memory).test_ok();
        mismatched_identity_store
            .save_key_registry(registry)
            .test_ok();
        assert!(matches!(
            import_timeline_with_verified_signatures(
                mismatched_identity_store.as_mut(),
                mismatched_identity,
                public_key,
            )
            .test_err(),
            CoreError::SignatureVerificationFailed
        ));

        let mut missing_record = export.clone();
        missing_record.events.truncate(1);
        missing_record.events[0].signature_identity = Some(KeyIdentityV1::new(
            "test-owner",
            KeyRoleV1::TimelineIntegritySigning,
            2,
        ));
        let mut missing_record_store = open_store(StoreConfig::Memory).test_ok();
        missing_record_store.save_key_registry(registry).test_ok();
        assert!(matches!(
            import_timeline_with_verified_signatures(
                missing_record_store.as_mut(),
                missing_record,
                public_key,
            )
            .test_err(),
            CoreError::SignatureVerificationFailed
        ));

        let mut invalid_signature = export.clone();
        invalid_signature.events[0].signature = Some(pos_core::Signature::from_bytes([0; 64]));
        let mut invalid_signature_store = open_store(StoreConfig::Memory).test_ok();
        invalid_signature_store
            .save_key_registry(registry)
            .test_ok();
        assert!(matches!(
            import_timeline_with_verified_signatures(
                invalid_signature_store.as_mut(),
                invalid_signature,
                public_key,
            )
            .test_err(),
            CoreError::SignatureVerificationFailed
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_with_verified_signatures_rejects_invalid_public_key() {
        use pos_core::{
            store::TimelineExport,
            timeline::{Timeline, TimelineMeta},
            PublicKey,
        };
        use pos_crypto::signing::{generate_keypair, public_key_from_verifying_key};

        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("x")),
            events: vec![],
            parent_fork_hash: None,
        };
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let (_, verifying_key) = generate_keypair();
        let valid = public_key_from_verifying_key(&verifying_key);
        import_timeline_with_verified_signatures(store.as_mut(), export.clone(), &valid).test_ok();
        let mut bytes = [0u8; 32];
        bytes[31] = 0xff;
        let bad = PublicKey::from_bytes(bytes);
        let err = import_timeline_with_verified_signatures(store.as_mut(), export, &bad).test_err();
        assert!(matches!(err, CoreError::SignatureVerificationFailed));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn import_with_verified_signatures_rejects_unsigned_event() {
        use pos_core::{
            clock::{Seq, WallTime},
            event::{Event, SchemaVersion},
            ids::EventId,
            store::TimelineExport,
            timeline::{Timeline, TimelineMeta},
            KeyRegistryStateV1,
        };
        use pos_crypto::signing::{generate_keypair, public_key_from_verifying_key};

        let (_, vk) = generate_keypair();
        let pk = public_key_from_verifying_key(&vk);
        let payload = CanonicalBytes::from_vec(b"unsigned".to_vec());
        let export = TimelineExport {
            timeline: Timeline::new(TimelineMeta::root("u")),
            events: vec![Event {
                id: EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new("t"),
                payload: payload.clone(),
                wall_time: WallTime::from_micros(1),
                seq: Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: SchemaVersion::V1,
                signature: None,
                signature_identity: None,
                payload_hash: pos_crypto::chain::hash_payload(&payload),
            }],
            parent_fork_hash: None,
        };
        let mut store = open_store(StoreConfig::Memory).test_ok();
        store
            .save_key_registry(&KeyRegistryStateV1::new())
            .test_ok();
        let err = import_timeline_with_verified_signatures(store.as_mut(), export, &pk).test_err();
        assert!(matches!(err, CoreError::SignatureVerificationFailed));
    }

    #[cfg(feature = "sqlite")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn open_store_sqlite_in_memory_propagates_open_error() {
        sqlite::FAIL_OPEN_IN_MEMORY.with(|f| f.set(true));
        let result = open_store(StoreConfig::SqliteInMemory);
        sqlite::FAIL_OPEN_IN_MEMORY.with(|f| f.set(false));
        assert!(
            matches!(result, Err(CoreError::Storage(_))),
            "expected Storage error from injected open_in_memory failure"
        );
    }

    #[test]
    fn store_owned_clock_drives_canonical_intent_and_bounded_cleanup() {
        let admission = WallTime::from_micros(APPEND_IDENTITY_RETENTION_MICROS + 42);
        let mut store =
            memory::MemoryStore::with_clock(Box::new(pos_core::FixedAdmissionClock(admission)));
        let timeline = store.create_timeline("clock").test_ok();
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("clock.test"),
            CanonicalBytes::from_vec(b"payload".to_vec()),
        );
        let intent = AppendIntent::new(&draft);
        let first = store
            .append_or_duplicate(
                timeline.id(),
                append_identity(9, 9),
                WallTime::from_micros(0),
                draft.clone(),
            )
            .test_ok();
        let event_id = appended_event_id(first);
        let replaced = store
            .append_intent_or_duplicate(timeline.id(), append_identity(9, 9), intent.clone())
            .test_ok();
        let _ = appended_event_id(replaced);
        let second = store
            .append_intent_or_duplicate(timeline.id(), append_identity(8, 8), intent.clone())
            .test_ok();
        let second_event_id = appended_event_id(second);
        let second_event = store.read(timeline.id(), SeqRange::all()).test_ok()[1].clone();
        assert_eq!(second_event.wall_time, admission);
        store
            .append_or_duplicate(
                timeline.id(),
                append_identity(10, 10),
                WallTime::from_micros(0),
                draft,
            )
            .test_ok();
        store
            .append_or_duplicate(
                timeline.id(),
                append_identity(11, 11),
                WallTime::from_micros(1),
                EventDraft::new(
                    EntityId::new(),
                    Kind::new("clock.test.second"),
                    CanonicalBytes::from_vec(b"second".to_vec()),
                ),
            )
            .test_ok();
        assert_eq!(
            store
                .append_intent_or_duplicate(timeline.id(), append_identity(8, 8), intent)
                .test_ok(),
            AppendOrDuplicateOutcome::Duplicate {
                event_id: second_event_id
            }
        );
        let outcome = store
            .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
            .test_ok();
        assert_eq!(outcome.removed, 1);
        assert!(outcome.more_may_remain);
        assert_eq!(
            store
                .purge_expired_append_identities_bounded(std::num::NonZeroUsize::new(1).test_ok())
                .test_ok(),
            PurgeOutcome {
                removed: 1,
                more_may_remain: false
            }
        );
        assert_ne!(event_id, second_event_id);
    }
}

#[cfg(test)]
mod coverage_entrypoints {
    use super::*;

    struct RegistryLoadErrorStore;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl EventStore for RegistryLoadErrorStore {
        fn create_timeline(&mut self, name: &str) -> Result<pos_core::Timeline, CoreError> {
            Ok(pos_core::Timeline::new(pos_core::TimelineMeta::root(name)))
        }

        fn append(
            &mut self,
            _timeline: TimelineId,
            _drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            Ok(Vec::new())
        }

        fn read(
            &self,
            _timeline: TimelineId,
            _range: pos_core::store::SeqRange,
        ) -> Result<Vec<Event>, CoreError> {
            Ok(Vec::new())
        }

        fn fork(
            &mut self,
            _parent: TimelineId,
            _at_seq: pos_core::clock::Seq,
            name: &str,
        ) -> Result<pos_core::Timeline, CoreError> {
            Ok(pos_core::Timeline::new(pos_core::TimelineMeta::root(name)))
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(&self, _id: TimelineId) -> Result<Option<pos_core::Timeline>, CoreError> {
            Ok(None)
        }

        fn load_key_registry(&self) -> Result<Option<pos_core::KeyRegistryStateV1>, CoreError> {
            Err(CoreError::Storage("registry load failed".to_owned()))
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected consent guard fixture error: {error:?}"
            )))
        })
    }

    #[test]
    fn consent_type_boundaries_are_instrumented() {
        let timeline = TimelineId::new();
        assert!(ensure_gateway_consent_types(&[], timeline).is_err());
        let invalid = EventDraft::new(
            EntityId::new(),
            Kind::new("not-consent"),
            CanonicalBytes::from_static(b"invalid"),
        );
        assert!(ensure_gateway_consent_types(&[invalid], timeline).is_err());
    }

    #[test]
    fn consent_draft_type_errors_propagate_through_the_public_guard() {
        let invalid = EventDraft::new(
            EntityId::new(),
            Kind::new("not-consent"),
            CanonicalBytes::from_static(b"invalid"),
        );
        assert!(ensure_gateway_consent_drafts(&[invalid], TimelineId::new(), None, 1,).is_err());
    }

    #[test]
    fn consent_grant_boundaries_are_instrumented() {
        let timeline = TimelineId::new();
        let subject = EntityId::new();
        let grant = pos_core::ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "coverage".to_owned(),
            modalities: pos_core::MODALITY_LOCATION,
            min_geo_resolution: 1,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let grant_draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            ok(grant.encode()),
        );
        assert!(ensure_gateway_consent_drafts(&[grant_draft], timeline, None, 1).is_ok());

        let malformed_grant = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            CanonicalBytes::from_static(b"malformed-grant"),
        );
        assert!(ensure_gateway_consent_drafts(&[malformed_grant], timeline, None, 1).is_err());

        let mut mismatched_grant = EventDraft::new(
            EntityId::new(),
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            ok(grant.encode()),
        );
        mismatched_grant.payload = ok((pos_core::ConsentGrantedV1 {
            grant_seq: 2,
            ..grant.clone()
        })
        .encode());
        assert!(ensure_gateway_consent_drafts(&[mismatched_grant], timeline, None, 1).is_err());
        let owner_mismatch_grant = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            ok(grant.encode()),
        );
        assert!(ensure_gateway_consent_drafts(
            &[owner_mismatch_grant],
            timeline,
            Some(EntityId::new()),
            1,
        )
        .is_err());
    }

    #[test]
    fn consent_revocation_boundaries_are_instrumented() {
        let timeline = TimelineId::new();
        let subject = EntityId::new();
        let revocation = pos_core::ConsentRevokedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: 2,
        };
        let revocation_draft = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            ok(revocation.encode()),
        );
        assert!(
            ensure_gateway_consent_drafts(&[revocation_draft], timeline, Some(subject), 2).is_ok()
        );

        let malformed_revocation = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            CanonicalBytes::from_static(b"malformed-revocation"),
        );
        assert!(
            ensure_gateway_consent_drafts(&[malformed_revocation], timeline, Some(subject), 2)
                .is_err()
        );

        let mismatched_revocation = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            ok((pos_core::ConsentRevokedV1 {
                fence_seq: 3,
                ..revocation
            })
            .encode()),
        );
        assert!(ensure_gateway_consent_drafts(
            &[mismatched_revocation],
            timeline,
            Some(subject),
            2,
        )
        .is_err());
        let owner_mismatch_revocation = EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            ok(revocation.encode()),
        );
        assert!(ensure_gateway_consent_drafts(
            &[owner_mismatch_revocation],
            timeline,
            Some(EntityId::new()),
            2,
        )
        .is_err());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verified_import_requires_a_registry_snapshot() {
        let (_, verifying_key) = pos_crypto::signing::generate_keypair();
        let public_key = pos_crypto::signing::public_key_from_verifying_key(&verifying_key);
        let export = TimelineExport {
            timeline: pos_core::Timeline::new(pos_core::TimelineMeta::root("missing-registry")),
            events: vec![pos_core::Event {
                id: pos_core::EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new("coverage.event"),
                payload: CanonicalBytes::from_static(b"coverage"),
                wall_time: WallTime::from_micros(1),
                seq: pos_core::Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: pos_core::SchemaVersion::V1,
                signature: None,
                signature_identity: None,
                payload_hash: pos_core::Hash::from_bytes([0; 32]),
            }],
            parent_fork_hash: None,
        };
        let mut missing_registry = ok(open_store(StoreConfig::Memory));
        assert!(matches!(
            import_timeline_with_verified_signatures(
                missing_registry.as_mut(),
                export,
                &public_key,
            ),
            Err(CoreError::Storage(_))
        ));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn verified_import_propagates_registry_load_failure() {
        let (_, verifying_key) = pos_crypto::signing::generate_keypair();
        let public_key = pos_crypto::signing::public_key_from_verifying_key(&verifying_key);
        let export = TimelineExport {
            timeline: pos_core::Timeline::new(pos_core::TimelineMeta::root("registry-load-error")),
            events: vec![pos_core::Event {
                id: pos_core::EventId::new(),
                entity: EntityId::new(),
                event_type: Kind::new("coverage.event"),
                payload: CanonicalBytes::from_static(b"coverage"),
                wall_time: WallTime::from_micros(1),
                seq: pos_core::Seq::from_u64(1),
                causation_id: None,
                correlation_id: None,
                schema_version: pos_core::SchemaVersion::V1,
                signature: None,
                signature_identity: None,
                payload_hash: pos_core::Hash::from_bytes([0; 32]),
            }],
            parent_fork_hash: None,
        };
        let mut store = RegistryLoadErrorStore;
        assert!(matches!(
            import_timeline_with_verified_signatures(&mut store, export, &public_key),
            Err(CoreError::Storage(message)) if message == "registry load failed"
        ));
    }
}
