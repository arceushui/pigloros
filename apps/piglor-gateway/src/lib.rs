#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
//! `piglor-gateway` — Wave 6 local-first HTTP/WebSocket gateway (ADR-014 / #69).
//!
//! JSON HTTP envelope; CBOR payloads into [`EventStore`]. No auth in this slice.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

pub mod executor;
mod http;
pub mod ledger_config;
pub mod owntracks;
pub mod owntracks_http;

pub use http::{router, router_for_addr, spectator_router, AppState};
pub use ledger_config::{LedgerConfig, LedgerGateway, LedgerWriteMode};

use pos_core::{
    clock::Seq,
    event::{CanonicalBytes, Event, EventDraft, Kind},
    geo_admission::{
        GeoLocationAdmissionOutcome, GeoLocationAdmissionRequestV1, GeoLocationAdmissionStore,
    },
    ids::{EntityId, EventId, PluginId, TimelineId},
    store::{
        AppendDedupKey, AppendDedupScope, AppendIdentity, AppendIntent, AppendOrDuplicateOutcome,
        EventReadBounds, EventStore, PurgeOutcome, SeqRange,
    },
    timeline::Timeline,
    ActionRejected, Capability, ConsentAuthority, ConsentCapabilityToken, ConsentCodecError,
    ConsentError, ConsentGrantedV1, ConsentRevokedV1, CoreError, Plugin, ProposedAction,
};
use pos_plugin_society::{draft_signal, SocietyDimension, SocietySignal, EVENT_TYPE_SIGNAL};
use pos_plugin_world::{WorldPlugin, EVENT_TYPE_ACTION};
use pos_runtime::PluginRegistry;
use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::broadcast;
use ulid::Ulid;

/// Pre-registered Prediction Ledger entry view (Redmine #58 / OKR KR4.6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerEntryView {
    pub id: String,
    pub scenario: String,
    pub title: String,
    pub predicted_outcome: String,
    pub confidence: f64,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brier_score: Option<f64>,
    pub verification_hash: String,
    pub timestamp: String,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            match self {
                Ok(value) => value,
                Err(error) => {
                    std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
                }
            }
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    trait TestErrorExt<E> {
        fn test_err(self) -> E;
    }

    impl<T, E: std::fmt::Debug> TestErrorExt<E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(_value) => std::panic::resume_unwind(Box::new("expected test error")),
                Err(error) => error,
            }
        }
    }

    use super::{Gateway, OwnTracksOwnerKey};
    use pos_core::{
        geo_admission::{
            GeoLocationAdmissionFenceV1, GeoLocationAdmissionInputV1, GeoLocationAdmissionRequestV1,
        },
        CanonicalBytes, ConsentGrantedV1, EntityId, EventDraft, EventStore, Kind,
        OwnTracksEnrollmentRequestV1, OwnTracksEnrollmentStore, Seq,
    };
    use pos_store::{memory::MemoryStore, open_store, StoreConfig};
    use std::path::Path;

    fn consent_grant(subject_id: EntityId, grant_seq: u64) -> ConsentGrantedV1 {
        ConsentGrantedV1 {
            subject_id,
            grantee_id: EntityId::new(),
            purpose: "coverage-contract".to_owned(),
            modalities: pos_core::MODALITY_LOCATION,
            min_geo_resolution: 1,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq,
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn production_owntracks_constructor_enables_private_ingress() {
        let store = pos_store::sqlite::SqliteStore::open_in_memory().test_ok();
        let gateway = Gateway::new_with_owntracks_ingress(store, &OwnTracksOwnerKey([7; 32]));

        assert!(gateway.owntracks_enabled);
        drop(gateway);
    }

    #[cfg(unix)]
    #[test]
    fn owntracks_owner_key_load_requires_an_existing_private_32_byte_file() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = std::env::temp_dir().join(format!(
            "piglor-gateway-owner-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .test_ok()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).test_ok();
        let path = directory.join("owner.key");
        std::fs::write(&path, [7_u8; 32]).test_ok();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).test_ok();

        assert!(OwnTracksOwnerKey::load(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).test_ok();
        assert!(OwnTracksOwnerKey::load(&path).is_err());
        assert!(OwnTracksOwnerKey::load(&directory.join("missing.key")).is_err());
        assert!(OwnTracksOwnerKey::load(&directory).is_err());

        let short_path = directory.join("short.key");
        std::fs::write(&short_path, [8_u8; 31]).test_ok();
        std::fs::set_permissions(&short_path, std::fs::Permissions::from_mode(0o600)).test_ok();
        assert!(OwnTracksOwnerKey::load(&short_path).is_err());

        let target_path = directory.join("target.key");
        std::fs::write(&target_path, [9_u8; 32]).test_ok();
        std::fs::set_permissions(&target_path, std::fs::Permissions::from_mode(0o600)).test_ok();
        let symlink_path = directory.join("symlink.key");
        symlink(&target_path, &symlink_path).test_ok();
        assert!(OwnTracksOwnerKey::load(&symlink_path).is_err());

        let symlink_directory = directory.join("symlink-directory");
        symlink(&directory, &symlink_directory).test_ok();
        assert!(OwnTracksOwnerKey::load(&symlink_directory.join("owner.key")).is_err());

        let insecure_directory = directory.join("insecure");
        std::fs::create_dir(&insecure_directory).test_ok();
        std::fs::set_permissions(&insecure_directory, std::fs::Permissions::from_mode(0o777))
            .test_ok();
        assert!(OwnTracksOwnerKey::load(&insecure_directory.join("owner.key")).is_err());

        let non_directory = directory.join("not-a-directory");
        std::fs::write(&non_directory, [10_u8; 1]).test_ok();
        assert!(OwnTracksOwnerKey::load(&non_directory.join("owner.key")).is_err());
        assert!(OwnTracksOwnerKey::load(Path::new("/")).is_err());

        let relative_directory = format!(
            ".codex-owntracks-owner-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .test_ok()
                .as_nanos()
        );
        std::fs::create_dir(&relative_directory).test_ok();
        let relative_path = Path::new(&relative_directory).join("owner.key");
        std::fs::write(&relative_path, [11_u8; 32]).test_ok();
        std::fs::set_permissions(&relative_path, std::fs::Permissions::from_mode(0o600)).test_ok();
        assert!(OwnTracksOwnerKey::load(&relative_path).is_ok());
        std::fs::remove_dir_all(relative_directory).test_ok();

        std::fs::remove_dir_all(directory).test_ok();
    }

    #[tokio::test]
    async fn identified_conflict_is_returned() {
        let gateway = Gateway::new(open_store(StoreConfig::Memory).test_ok());
        let timeline = gateway.create_timeline("coverage-conflict").await.test_ok();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        gateway
            .append_identified_action(
                &timeline_id,
                &entity_id,
                "world.action",
                &serde_json::json!({"choice": "left"}),
                "coverage-conflict",
            )
            .await
            .test_ok();
        let _ = gateway
            .append_identified_action(
                &timeline_id,
                &entity_id,
                "world.action",
                &serde_json::json!({"choice": "right"}),
                "coverage-conflict",
            )
            .await
            .test_err();
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fork_action_response_notice_lookup_and_read_share_logical_sequence() {
        let mut store = MemoryStore::new();
        let root = store.create_timeline("logical-root").test_ok();
        let entity = EntityId::new();
        store
            .append(
                root.id(),
                &[
                    EventDraft::new(
                        entity,
                        Kind::new("world.action"),
                        CanonicalBytes::from_static(b"r1"),
                    ),
                    EventDraft::new(
                        entity,
                        Kind::new("world.action"),
                        CanonicalBytes::from_static(b"r2"),
                    ),
                ],
            )
            .test_ok();
        let child = store
            .fork(root.id(), Seq::from_u64(2), "logical-child")
            .test_ok();
        let gateway = Gateway::new(Box::new(store));
        let mut notices = gateway.subscribe();
        let appended = gateway
            .append_action(
                &child.id().to_string(),
                &entity.to_string(),
                "world.action",
                &serde_json::json!({"choice": "child"}),
            )
            .await
            .test_ok();
        assert_eq!(appended.seq, Seq::from_u64(3));
        assert_eq!(notices.recv().await.test_ok().seq, 3);

        let identified = gateway
            .append_identified_action(
                &child.id().to_string(),
                &entity.to_string(),
                "world.action",
                &serde_json::json!({"choice": "identified"}),
                "logical-child-action",
            )
            .await
            .test_ok();
        assert_eq!(identified.event.seq, Seq::from_u64(4));
        assert!(!identified.duplicate);
        assert_eq!(notices.recv().await.test_ok().seq, 4);
        let duplicate = gateway
            .append_identified_action(
                &child.id().to_string(),
                &entity.to_string(),
                "world.action",
                &serde_json::json!({"choice": "identified"}),
                "logical-child-action",
            )
            .await
            .test_ok();
        assert_eq!(duplicate.event.seq, Seq::from_u64(4));
        assert!(duplicate.duplicate);

        let page = gateway
            .read_events_page(&child.id().to_string(), 0, 10)
            .await
            .test_ok();
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.seq.as_u64())
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn privileged_geographic_admission_notifies_only_new_events() {
        let mut store = MemoryStore::default();
        let timeline = store.create_timeline("geo-gateway").test_ok();
        let entity = EntityId::new();
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline.id(),
                entity,
                GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
                [42; 32],
            ))
            .test_ok();
        let gateway = Gateway::new_with_geo_location_admission(store);
        let mut notices = gateway.subscribe();
        let (_, token) = gateway
            .issue_consent_grant(&timeline.id().to_string(), consent_grant(entity, 1))
            .await
            .test_ok();
        let request = || {
            GeoLocationAdmissionRequestV1::from_input(GeoLocationAdmissionInputV1::new(
                timeline.id(),
                entity,
                CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                7,
                ([1; 32], 8, [2; 32]),
                (1, false, 10),
                ([4; 32], [5; 32]),
            ))
        };

        assert!(gateway
            .admit_geo_location_with_consent(request(), &token, 0)
            .await
            .test_ok()
            .is_accepted());
        assert_eq!(notices.recv().await.test_ok().event_type, "geo.location");
        assert!(gateway
            .admit_geo_location_with_consent(request(), &token, 0)
            .await
            .test_ok()
            .is_duplicate());
        assert!(matches!(
            notices.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn owntracks_ingress_rate_limits_after_authentication_and_notifies_only_acceptance() {
        const OWNER_KEY: [u8; 32] = [17; 32];
        const HANDLE: [u8; 32] = [23; 32];
        const SECRET: [u8; 32] = [29; 32];

        let mut store = MemoryStore::default();
        let timeline = store.create_timeline("owntracks-rate-limit").test_ok();
        let entity = EntityId::new();
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(b"pigloros/owntracks/verifier/v1\0");
        material.extend_from_slice(&HANDLE);
        material.extend_from_slice(&SECRET);
        store
            .pair_owntracks_enrollment(OwnTracksEnrollmentRequestV1::new(
                timeline.id(),
                entity,
                GeoLocationAdmissionFenceV1::new(7, ([1; 32], 8, [2; 32]), (1, false, 9)),
                *blake3::keyed_hash(&OWNER_KEY, &material).as_bytes(),
            ))
            .test_ok();
        let gateway = Gateway::new_with_owntracks_ingress_for_test(store, OWNER_KEY);
        gateway
            .issue_consent_grant(&timeline.id().to_string(), consent_grant(entity, 1))
            .await
            .test_ok();
        gateway
            .create_timeline("owntracks-generic-event-store")
            .await
            .test_ok();
        let mut notices = gateway.subscribe();
        let input = || {
            (
                HANDLE,
                SECRET,
                CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
            )
        };

        for _ in 0..5 {
            assert!(!gateway
                .admit_owntracks_ingress(input().0, input().1, input().2)
                .await
                .test_ok()
                .is_rate_limited());
        }
        assert!(gateway
            .admit_owntracks_ingress(input().0, input().1, input().2)
            .await
            .test_ok()
            .is_rate_limited());
        assert_eq!(notices.recv().await.test_ok().event_type, "geo.location");
        assert!(matches!(
            notices.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert!(!gateway
            .admit_owntracks_ingress(input().0, input().1, input().2)
            .await
            .test_ok()
            .is_rate_limited());
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn privileged_geographic_gateway_retains_generic_timeline_commands() {
        let gateway = Gateway::new_with_geo_location_admission(MemoryStore::default());

        let created = gateway
            .create_timeline("privileged-generic-command")
            .await
            .test_ok();

        assert_eq!(
            created.meta.name.as_deref(),
            Some("privileged-generic-command")
        );
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn generic_gateway_cannot_execute_geographic_admission() {
        let gateway = Gateway::new(Box::new(MemoryStore::default()));
        let result = gateway
            .admit_geo_location_from_core(GeoLocationAdmissionRequestV1::from_input(
                GeoLocationAdmissionInputV1::new(
                    pos_core::TimelineId::new(),
                    EntityId::new(),
                    CanonicalBytes::from_static(b"existing-v1-geo-location-payload"),
                    7,
                    ([1; 32], 8, [2; 32]),
                    (1, false, 9),
                    ([4; 32], [5; 32]),
                ),
            ))
            .await;
        assert!(matches!(
            result,
            Err(super::GatewayError::Store(
                pos_core::CoreError::GeographicAdmissionUnavailable
            ))
        ));
        drop(gateway);
    }
}

/// Maximum JSON request body size for HTTP handlers (1 MiB).
pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;

/// Maximum canonical payload accepted for one Gateway-authored Event (256 KiB).
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 256 * 1024;

/// Maximum UTF-8 byte length accepted for imported Event type metadata (64 KiB).
///
/// At JSON's worst-case six-byte escaping expansion this occupies at most
/// 384 KiB. Together with the maximum payload's 512 KiB hex representation
/// and fixed Event fields, it remains below the 1 MiB response envelope.
/// The exact serialized-response check still governs decoded payload expansion.
pub const MAX_EVENT_TYPE_BYTES: usize = 64 * 1024;

/// Maximum number of parent links traversed by one bounded Event poll.
pub const MAX_FORK_DEPTH: usize = 64;

/// Maximum serialized JSON size for one Event polling response (1 MiB).
pub const MAX_EVENTS_RESPONSE_BYTES: usize = 1024 * 1024;

/// Maximum synchronous store time budget for one bounded Event poll (5 seconds).
pub const MAX_EVENTS_READ_TIME_MICROS: u64 = 5_000_000;

/// Maximum number of Timeline events returned by one poll.
pub const MAX_EVENTS_PER_POLL: usize = 100;

/// Maximum number of root Timelines managed by one local Gateway process.
pub const MAX_TIMELINES: usize = 64;

/// Maximum number of owned events atomically accepted for one Timeline.
pub const MAX_EVENTS_PER_TIMELINE: u64 = 10_000;

/// Default broadcast channel capacity for live event fan-out.
pub const EVENT_BUS_CAPACITY: usize = 256;

const CONSENT_LOCK_STRIPES: usize = 64;
const CONSENT_LOCK_STRIPES_U64: u64 = 64;
const CONSENT_DEDUP_CLEANUP_BATCH: NonZeroUsize = match NonZeroUsize::new(256) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const CONSENT_DEDUP_CLEANUP_RETRY_DELAY_MILLIS: u64 = 50;

type ConsentHistoryLocks = Vec<Arc<tokio::sync::Mutex<()>>>;

fn new_consent_history_locks() -> Arc<ConsentHistoryLocks> {
    Arc::new(
        (0..CONSENT_LOCK_STRIPES)
            .map(|_| Arc::new(tokio::sync::Mutex::new(())))
            .collect(),
    )
}

fn new_pending_consent_cleanup() -> Arc<tokio::sync::Mutex<Vec<AppendDedupScope>>> {
    Arc::new(tokio::sync::Mutex::new(Vec::new()))
}

/// Shared Gateway handle (bounded `StoreExecutor` + live Event bus).
///
/// The supported local-first write boundary permits Gateway and experiment-host
/// processes to open one `SQLite` file through [`EventStore`]. Adapter-owned immediate
/// transactions serialize appends and enforce each owned-Event ceiling atomically.
/// Direct SQL mutation that bypasses [`EventStore`] remains outside this contract.
#[derive(Clone)]
pub struct Gateway {
    store: executor::StoreExecutor,
    bus: broadcast::Sender<EventNotice>,
    limits: GatewayLimits,
    owntracks_enabled: bool,
    consent_authority: ConsentAuthority,
    consent_history_locks: Arc<ConsentHistoryLocks>,
    pending_consent_cleanup: Arc<tokio::sync::Mutex<Vec<AppendDedupScope>>>,
    action_registry: Arc<PluginRegistry>,
    action_principal: Option<ActionPrincipal>,
}

/// Authenticated principal configuration for human action submission.
#[derive(Clone)]
pub struct ActionPrincipal {
    entity_id: EntityId,
    capabilities: Vec<Kind>,
}

impl ActionPrincipal {
    /// Create a principal with its already-authenticated entity and capabilities.
    #[must_use]
    pub fn new(entity_id: EntityId, capabilities: impl IntoIterator<Item = Kind>) -> Self {
        Self {
            entity_id,
            capabilities: capabilities.into_iter().collect(),
        }
    }

    fn authorizes(&self, proposal: &ProposedAction) -> Result<(), ActionRejected> {
        if proposal.actor_entity_id != self.entity_id {
            return Err(ActionRejected::InvalidActorEntityId);
        }
        if !self
            .capabilities
            .iter()
            .any(|capability| capability.as_str() == proposal.capability.as_str())
        {
            return Err(ActionRejected::CapabilityNotGranted);
        }
        Ok(())
    }
}

struct GatewayActionPlugin {
    id: PluginId,
}

impl Plugin for GatewayActionPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "gateway-world-actions"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE_ACTION)],
            ..Capability::default()
        }
    }
}

#[cfg(test)]
fn gateway_action_registry() -> Arc<PluginRegistry> {
    gateway_action_registry_with_bodies(std::iter::empty())
}

#[cfg(test)]
fn gateway_action_registry_with_bodies(
    bodies: impl IntoIterator<Item = EntityId>,
) -> Arc<PluginRegistry> {
    gateway_action_registry_with_authority(bodies, None)
}

fn gateway_action_registry_with_authority(
    bodies: impl IntoIterator<Item = EntityId>,
    authority: Option<ConsentAuthority>,
) -> Arc<PluginRegistry> {
    let mut registry = PluginRegistry::new();
    let descriptor = GatewayActionPlugin {
        id: PluginId::new(),
    };
    let registration = registry.register_with_approver(
        &descriptor,
        None,
        None,
        Some(Box::new(WorldPlugin::new().with_bodies(bodies))),
        [Kind::new(EVENT_TYPE_ACTION)],
    );
    if registration.is_err() {
        return Arc::new(PluginRegistry::new());
    }
    if let Some(authority) = authority {
        registry = registry.with_consent_authority(authority);
    }
    Arc::new(registry)
}

/// Resource bounds applied by the local-first Gateway process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GatewayLimits {
    max_timelines: usize,
    max_events_per_timeline: u64,
}

impl GatewayLimits {
    const LOCAL_DEFAULT: Self = Self {
        max_timelines: MAX_TIMELINES,
        max_events_per_timeline: MAX_EVENTS_PER_TIMELINE,
    };
}

/// A bounded page of Timeline Events.
///
/// `next_from_seq` is the inclusive sequence of the first omitted Event, or
/// `None` only when the requested Timeline is exhausted.
#[derive(Debug, PartialEq, Eq)]
pub struct EventPage {
    pub events: Vec<Event>,
    pub next_from_seq: Option<Seq>,
}

/// JSON notice pushed on the event bus / WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventNotice {
    pub timeline_id: String,
    pub event_id: String,
    pub entity_id: String,
    pub event_type: String,
    pub seq: u64,
}

/// Result of an identified Gateway append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifiedAppend {
    pub event: Event,
    pub duplicate: bool,
}

/// API / domain errors for the gateway library.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Malformed ULID path/body field.
    #[error("invalid id: {0}")]
    InvalidId(String),
    /// Unsupported action event type.
    #[error("unsupported action type: {0}")]
    UnsupportedAction(String),
    /// An ingress identity was reused with a different canonical intent.
    #[error("ingress identity conflicts with retained canonical intent")]
    IngressConflict,
    /// Requested poll page is outside the Gateway bounds.
    #[error("event poll limit must be between 1 and {maximum}")]
    InvalidPageLimit { maximum: usize },
    /// This Gateway process has reached its Timeline bound.
    #[error("timeline limit of {maximum} reached")]
    TimelineLimitReached { maximum: usize },
    /// The Timeline has reached its event bound.
    #[error("event limit of {maximum} reached")]
    EventLimitReached { maximum: u64 },
    /// A Gateway-authored Event payload exceeds the retrievable size budget.
    #[error("event payload exceeds maximum of {maximum} bytes")]
    EventPayloadTooLarge { maximum: usize },
    /// Imported Event metadata exceeds the retrievable size budget.
    #[error("event metadata field {field} exceeds maximum of {maximum} bytes")]
    EventMetadataTooLarge { field: &'static str, maximum: usize },
    /// An imported Fork chain exceeds the bounded polling traversal budget.
    #[error("fork depth exceeds maximum of {maximum}")]
    ForkDepthTooLarge { maximum: usize },
    /// Malformed event polling query.
    #[error("invalid events query: {0}")]
    InvalidEventsQuery(String),
    /// A single stored Event cannot fit in a bounded response.
    #[error("event response exceeds maximum of {maximum} bytes")]
    EventResponseTooLarge { maximum: usize },
    /// A bounded Event read exceeded its synchronous store time budget.
    #[error("event read exceeded maximum elapsed time of {maximum_micros} microseconds")]
    EventReadTimeExceeded { maximum_micros: u64 },
    /// The deprecated aggregate-style read would silently truncate Events.
    #[error("compatibility read exceeds its bounded page of {maximum} events")]
    CompatibilityReadTruncated { maximum: usize },
    /// Sensitive and absent resources share one bounded, non-enumerable shape.
    #[error("resource not found")]
    ResourceUnavailable,
    /// The bounded `StoreExecutor` queue cannot accept another command.
    #[error("store executor queue saturated")]
    StoreExecutorSaturated,
    /// The `StoreExecutor` is no longer accepting commands.
    #[error("store executor closed")]
    StoreExecutorClosed,
    /// A store command exceeded its bounded execution deadline.
    #[error("store executor command deadline exceeded")]
    StoreExecutorDeadlineExceeded,
    /// The supervised store worker is unhealthy.
    #[error("store executor unhealthy")]
    StoreExecutorUnhealthy,
    /// Underlying store failure.
    #[error(transparent)]
    Store(#[from] CoreError),
    /// Host consent fence rejected the protected operation.
    #[error(transparent)]
    Consent(#[from] ConsentError),
    /// Ledger domain error.
    #[error(transparent)]
    Ledger(#[from] pos_plugin_ledger::LedgerError),
    /// Ledger prediction write is disabled (feature gate off).
    #[error("ledger write is disabled (set LEDGER_WRITE=1)")]
    LedgerWriteDisabled,
    /// Ledger store is not configured.
    #[error("ledger store not available")]
    LedgerUnavailable,
    /// The existing `OwnTracks` owner-key file failed the activation policy.
    #[error("OwnTracks owner-key file is unavailable")]
    OwnTracksOwnerKeyUnavailable,
    /// Proposed action was rejected by the capability check or approver (ADR-057).
    #[error(transparent)]
    ActionRejected(#[from] ActionRejected),
    /// Human action submission requires an authenticated action principal.
    #[error("human action authorization is unavailable")]
    ActionAuthorizationUnavailable,
    /// Consent payload did not meet its closed V1 contract.
    #[error(transparent)]
    ConsentCodec(#[from] ConsentCodecError),
    /// A host grant must bind the sequence it is about to commit.
    #[error("consent grant sequence does not match the current Timeline position")]
    ConsentGrantSequenceMismatch,
    /// A host revocation must bind the sequence it is about to commit.
    #[error("consent revocation fence does not match the current Timeline position")]
    ConsentRevocationFenceMismatch,
}

/// An existing, owner-only `OwnTracks` activation key loaded from disk.
///
/// The key bytes are intentionally opaque to callers. The only public way to
/// construct this value is [`Self::load`], which rejects missing, unsafe, or
/// malformed owner-key files before the ingress-capable Gateway is created.
#[derive(Clone)]
pub struct OwnTracksOwnerKey([u8; 32]);

impl OwnTracksOwnerKey {
    /// Load an existing owner-only key without creating or rotating it.
    ///
    /// # Errors
    /// Returns a bounded error when the path, permissions, file type, or key
    /// length does not satisfy the local activation policy.
    pub fn load(path: &Path) -> Result<Self, GatewayError> {
        let absolute = absolute_owner_key_path(path)?;
        validate_owner_key_ancestors(&absolute)?;
        let metadata = std::fs::symlink_metadata(&absolute)
            .map_err(|_| GatewayError::OwnTracksOwnerKeyUnavailable)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || owner_key_is_permissive(&metadata)
        {
            return Err(GatewayError::OwnTracksOwnerKeyUnavailable);
        }
        if metadata.len() != 32 {
            return Err(GatewayError::OwnTracksOwnerKeyUnavailable);
        }
        let bytes =
            std::fs::read(absolute).map_err(|_| GatewayError::OwnTracksOwnerKeyUnavailable)?;
        let bytes = bytes
            .try_into()
            .map_err(|_| GatewayError::OwnTracksOwnerKeyUnavailable)?;
        Ok(Self(bytes))
    }
}

#[cfg(unix)]
fn absolute_owner_key_path(path: &Path) -> Result<PathBuf, GatewayError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|_| GatewayError::OwnTracksOwnerKeyUnavailable)
    }
}

#[cfg(not(unix))]
fn absolute_owner_key_path(_path: &Path) -> Result<PathBuf, GatewayError> {
    Err(GatewayError::OwnTracksOwnerKeyUnavailable)
}

#[cfg(unix)]
fn validate_owner_key_ancestors(path: &Path) -> Result<(), GatewayError> {
    use std::os::unix::fs::MetadataExt;

    let parent = path
        .parent()
        .ok_or(GatewayError::OwnTracksOwnerKeyUnavailable)?;
    for (distance, ancestor) in parent.ancestors().enumerate() {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| GatewayError::OwnTracksOwnerKeyUnavailable)?;
        let mode = metadata.mode();
        let writable_by_group_or_other = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (writable_by_group_or_other && (distance == 0 || !sticky))
        {
            return Err(GatewayError::OwnTracksOwnerKeyUnavailable);
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_owner_key_ancestors(_path: &Path) -> Result<(), GatewayError> {
    Err(GatewayError::OwnTracksOwnerKeyUnavailable)
}

#[cfg(unix)]
fn owner_key_is_permissive(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.mode() & 0o077 != 0
}

#[cfg(not(unix))]
const fn owner_key_is_permissive(_metadata: &std::fs::Metadata) -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnTracksIngressResult {
    RateLimited,
    Accepted,
    Duplicate,
    Conflict,
    Unavailable,
}

impl OwnTracksIngressResult {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn is_rate_limited(self) -> bool {
        matches!(self, Self::RateLimited)
    }
}

impl From<executor::StoreExecutorError> for GatewayError {
    fn from(error: executor::StoreExecutorError) -> Self {
        match error {
            executor::StoreExecutorError::Saturated => Self::StoreExecutorSaturated,
            executor::StoreExecutorError::Closed => Self::StoreExecutorClosed,
            executor::StoreExecutorError::DeadlineExceeded => Self::StoreExecutorDeadlineExceeded,
            executor::StoreExecutorError::Unhealthy => Self::StoreExecutorUnhealthy,
            executor::StoreExecutorError::Store(error) => Self::Store(error),
        }
    }
}

fn accepted_event_coordinates(
    outcome: &GeoLocationAdmissionOutcome,
) -> Result<(EventId, Seq), GatewayError> {
    checked_event_coordinates(outcome.event_id(), outcome.event_seq())
}

fn checked_event_coordinates(
    event_id: Option<EventId>,
    seq: Option<Seq>,
) -> Result<(EventId, Seq), GatewayError> {
    let event_id = event_id.ok_or_else(|| {
        GatewayError::Store(CoreError::Storage(
            "accepted geographic admission is missing its Event ID".to_owned(),
        ))
    })?;
    let seq = seq.ok_or_else(|| {
        GatewayError::Store(CoreError::Storage(
            "accepted geographic admission is missing its Event sequence".to_owned(),
        ))
    })?;
    Ok((event_id, seq))
}

impl Gateway {
    async fn enqueue_consent_cleanup(&self, scope: AppendDedupScope) {
        let mut pending = self.pending_consent_cleanup.lock().await;
        if !pending.contains(&scope) {
            pending.push(scope);
        }
    }

    async fn run_pending_consent_cleanup_worker(&self) {
        loop {
            match self.process_pending_consent_cleanup().await {
                Ok(Some(outcome)) if outcome.more_may_remain => {
                    tokio::task::yield_now().await;
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        CONSENT_DEDUP_CLEANUP_RETRY_DELAY_MILLIS,
                    ))
                    .await;
                }
            }
        }
    }

    fn schedule_pending_consent_cleanup(&self) {
        let gateway = self.clone();
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move {
                gateway.run_pending_consent_cleanup_worker().await;
            });
        } else {
            drop(
                std::thread::Builder::new()
                    .name("piglor-consent-cleanup".to_owned())
                    .spawn(move || {
                        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        else {
                            return;
                        };
                        runtime.block_on(gateway.run_pending_consent_cleanup_worker());
                    }),
            );
        }
    }

    #[cfg(test)]
    const fn schedule_startup_consent_cleanup(self) -> Self {
        self
    }

    #[cfg(not(test))]
    fn schedule_startup_consent_cleanup(self) -> Self {
        self.schedule_pending_consent_cleanup();
        self
    }

    /// Run one bounded consent-revocation cleanup pass.
    ///
    /// The Gateway schedules this method after a revocation when a continuation
    /// is required. Hosts may also call it from their maintenance scheduler;
    /// each invocation removes at most the adapter batch limit.
    ///
    /// # Errors
    /// Returns the underlying bounded store error. A failed scope remains
    /// queued for the scheduler's persistent retry loop or a later maintenance
    /// invocation.
    pub async fn process_pending_consent_cleanup(
        &self,
    ) -> Result<Option<PurgeOutcome>, GatewayError> {
        let queued_scope = self.pending_consent_cleanup.lock().await.pop();
        let scope = match queued_scope {
            Some(scope) => Some(scope),
            None => self
                .store
                .pending_append_identity_cleanup()
                .await
                .map_err(GatewayError::from)?,
        };
        let Some(scope) = scope else {
            return Ok(None);
        };
        match self
            .store
            .remove_append_identities_bounded(scope, CONSENT_DEDUP_CLEANUP_BATCH)
            .await
        {
            Ok(outcome) => {
                if outcome.more_may_remain {
                    self.enqueue_consent_cleanup(scope).await;
                }
                Ok(Some(outcome))
            }
            Err(error) => {
                self.enqueue_consent_cleanup(scope).await;
                Err(error.into())
            }
        }
    }

    async fn lock_consent_timeline(
        &self,
        timeline: TimelineId,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let mut hasher = DefaultHasher::new();
        timeline.hash(&mut hasher);
        let stripe =
            usize::try_from(hasher.finish() % CONSENT_LOCK_STRIPES_U64).unwrap_or_default();
        let lock = Arc::clone(&self.consent_history_locks[stripe]);
        lock.lock_owned().await
    }

    async fn restore_consent_history_locked(
        &self,
        timeline: TimelineId,
    ) -> Result<(), GatewayError> {
        let events = self
            .store
            .read(
                timeline,
                SeqRange::from_seq(Seq::from_u64(1)),
                EventReadBounds::new(
                    MAX_EVENT_PAYLOAD_BYTES,
                    MAX_EVENT_TYPE_BYTES,
                    MAX_FORK_DEPTH,
                    usize::try_from(MAX_EVENTS_PER_TIMELINE).unwrap_or(usize::MAX),
                ),
            )
            .await?;
        self.consent_authority
            .restore_from_history(timeline, &events)
            .map_err(GatewayError::ConsentCodec)
    }

    /// Wrap an existing store backend.
    ///
    /// Human action submission is intentionally disabled until the host supplies
    /// both a World body catalogue and an authenticated [`ActionPrincipal`].
    #[must_use]
    pub fn new(store: Box<dyn EventStore>) -> Self {
        let (bus, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        let consent_authority = ConsentAuthority::new();
        Self {
            store: executor::StoreExecutor::new_with_consent_authority(
                store,
                consent_authority.append_permit(),
            ),
            bus,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            action_registry: gateway_action_registry_with_authority(
                std::iter::empty(),
                Some(consent_authority.clone()),
            ),
            consent_authority,
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_principal: None,
        }
        .schedule_startup_consent_cleanup()
    }

    /// Wrap a store and configure the World body catalogue used for actions.
    #[must_use]
    pub fn new_with_world_bodies(
        store: Box<dyn EventStore>,
        bodies: impl IntoIterator<Item = EntityId>,
    ) -> Self {
        let (bus, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        let consent_authority = ConsentAuthority::new();
        Self {
            store: executor::StoreExecutor::new_with_consent_authority(
                store,
                consent_authority.append_permit(),
            ),
            bus,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            action_registry: gateway_action_registry_with_authority(
                bodies,
                Some(consent_authority.clone()),
            ),
            consent_authority,
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_principal: None,
        }
        .schedule_startup_consent_cleanup()
    }

    /// Wrap a store with World bodies and an authenticated action principal.
    #[must_use]
    pub fn new_with_world_bodies_and_principal(
        store: Box<dyn EventStore>,
        bodies: impl IntoIterator<Item = EntityId>,
        principal: ActionPrincipal,
    ) -> Self {
        let (bus, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        let consent_authority = ConsentAuthority::new();
        Self {
            store: executor::StoreExecutor::new_with_consent_authority(
                store,
                consent_authority.append_permit(),
            ),
            bus,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            action_registry: gateway_action_registry_with_authority(
                bodies,
                Some(consent_authority.clone()),
            ),
            consent_authority,
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_principal: Some(principal),
        }
        .schedule_startup_consent_cleanup()
    }

    /// Construct the only Gateway shape that can submit core geographic admission.
    ///
    /// This does not register an HTTP route or widen generic ingress. Callers
    /// must already hold a backend implementing the dedicated core capability.
    #[must_use]
    pub fn new_with_geo_location_admission<S>(store: S) -> Self
    where
        S: EventStore + GeoLocationAdmissionStore + 'static,
    {
        let (bus, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        let consent_authority = ConsentAuthority::new();
        Self {
            store: executor::StoreExecutor::new_with_geo_location_admission(
                store,
                consent_authority.append_permit(),
            ),
            bus,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            action_registry: gateway_action_registry_with_authority(
                std::iter::empty(),
                Some(consent_authority.clone()),
            ),
            consent_authority,
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_principal: None,
        }
        .schedule_startup_consent_cleanup()
    }

    /// Construct the Gateway shape that accepts authenticated local `OwnTracks` ingress.
    ///
    /// This does not register an HTTP route. The private executor performs
    /// authentication, rate limiting, and geographic admission in one queue turn.
    #[must_use]
    pub fn new_with_owntracks_ingress(
        store: pos_store::sqlite::SqliteStore,
        owner_key: &OwnTracksOwnerKey,
    ) -> Self {
        let (bus, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        let consent_authority = ConsentAuthority::new();
        Self {
            store: executor::StoreExecutor::new_with_owntracks_ingress(
                store,
                owner_key.0,
                consent_authority.append_permit(),
            ),
            bus,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: true,
            action_registry: gateway_action_registry_with_authority(
                std::iter::empty(),
                Some(consent_authority.clone()),
            ),
            consent_authority,
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_principal: None,
        }
        .schedule_startup_consent_cleanup()
    }

    #[cfg(test)]
    pub(crate) fn new_with_owntracks_ingress_for_test<S>(store: S, owner_key: [u8; 32]) -> Self
    where
        S: EventStore + GeoLocationAdmissionStore + pos_core::OwnTracksIngressStore + 'static,
    {
        let (bus, _) = broadcast::channel(EVENT_BUS_CAPACITY);
        let consent_authority = ConsentAuthority::new();
        Self {
            store: executor::StoreExecutor::new_with_owntracks_ingress(
                store,
                owner_key,
                consent_authority.append_permit(),
            ),
            bus,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: true,
            action_registry: gateway_action_registry_with_authority(
                std::iter::empty(),
                Some(consent_authority.clone()),
            ),
            consent_authority,
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_principal: None,
        }
        .schedule_startup_consent_cleanup()
    }

    /// Submit one already-authorized core geographic admission request.
    ///
    /// The generic Gateway action and HTTP paths cannot construct this command.
    /// A notice is published only for a definite newly accepted Event.
    ///
    /// # Errors
    /// Returns a bounded executor or store error when admission cannot run.
    ///
    async fn admit_geo_location_from_core(
        &self,
        request: GeoLocationAdmissionRequestV1,
    ) -> Result<GeoLocationAdmissionOutcome, GatewayError> {
        let timeline = request.timeline();
        let entity = request.entity();
        let outcome = self.store.admit_geo_location(request).await?;
        if outcome.is_accepted() {
            let (event_id, seq) = accepted_event_coordinates(&outcome)?;
            self.publish_geographic_notice(timeline, event_id, entity, seq);
        }
        Ok(outcome)
    }

    /// Admit one geographic request after applying the host consent fence.
    ///
    /// The host reads the authoritative logical head while holding the same
    /// per-Timeline lock used by grant and revocation writes. The token is
    /// checked against that head and the grant's ADR-026 geographic floor
    /// before the dedicated geographic store capability is invoked.
    ///
    /// # Errors
    /// Returns [`GatewayError::Consent`] when the capability is stale,
    /// expired, or does not cover the requested resolution.
    pub async fn admit_geo_location_with_consent(
        &self,
        request: GeoLocationAdmissionRequestV1,
        token: &ConsentCapabilityToken,
        now_secs: u64,
    ) -> Result<GeoLocationAdmissionOutcome, GatewayError> {
        let consent_timeline_guard = self.lock_consent_timeline(request.timeline()).await;
        let timeline_head = self
            .store
            .protected_logical_head(request.timeline())
            .await?;
        self.consent_authority.validate_on_timeline(
            request.timeline(),
            token,
            timeline_head.as_u64(),
            now_secs,
        )?;
        token.authorize_event_type(&Kind::new("geo.location"))?;
        token.authorize_geo_resolution(pos_core::GEO_LOCATION_V1_RESOLUTION)?;
        let admission = self.admit_geo_location_from_core(request).await;
        drop(consent_timeline_guard);
        admission
    }

    /// Authenticate, rate-limit, and admit one minimized `OwnTracks` update.
    ///
    /// A notice is published only for a definite newly accepted Event.
    ///
    /// # Errors
    /// Returns a bounded executor or store error when ingress cannot run.
    ///
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn admit_owntracks_ingress(
        &self,
        basic_handle: [u8; 32],
        basic_secret: [u8; 32],
        payload: CanonicalBytes,
    ) -> Result<OwnTracksIngressResult, GatewayError> {
        let prepared = self
            .store
            .prepare_owntracks_ingress(basic_handle, basic_secret, payload)
            .await?;
        let executor::PreparedOwnTracksIngressOutcome::Prepared(prepared) = prepared else {
            return Ok(OwnTracksIngressResult::RateLimited);
        };
        let request = (*prepared).into_admission_request();
        let timeline = request.timeline();
        let entity = request.entity();
        let _consent_timeline_guard = self.lock_consent_timeline(timeline).await;
        let timeline_head = self.store.protected_logical_head(timeline).await?;
        self.consent_authority
            .validate_location_subject_on_timeline(timeline, entity, timeline_head.as_u64(), 0)?;
        let admission = self.store.admit_geo_location(request).await?;
        let result = classify_owntracks_admission(&admission)?;
        if matches!(result, OwnTracksIngressResult::Accepted) {
            let (event_id, seq) = accepted_event_coordinates(&admission)?;
            self.publish_geographic_notice(timeline, event_id, entity, seq);
        }
        Ok(result)
    }

    /// Subscribe to live append notices (WebSocket / tests).
    ///
    /// Slow subscribers can see [`broadcast::error::RecvError::Lagged`]; resync via
    /// the bounded HTTP poll — the store is authoritative.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EventNotice> {
        self.bus.subscribe()
    }

    /// Report whether the supervised `StoreExecutor` is open and ready to accept commands.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.store.is_ready()
    }

    /// Drain queued store commands and join the dedicated worker.
    ///
    /// # Errors
    /// Returns a typed executor lifecycle error when the worker cannot drain,
    /// join, or complete within its bounded shutdown deadline.
    pub async fn shutdown(&self) -> Result<(), GatewayError> {
        self.store.shutdown().await.map_err(Into::into)
    }

    /// Run one bounded deduplication-maintenance pass.
    ///
    /// The server lifecycle supervisor owns scheduling and readiness; this
    /// method only submits a bounded command to the `StoreExecutor`.
    ///
    /// # Errors
    /// Returns [`GatewayError::Store`] when the bounded maintenance pass fails.
    pub async fn purge_expired_ingress_identities(
        &self,
        limit: NonZeroUsize,
    ) -> Result<PurgeOutcome, GatewayError> {
        Ok(self.store.purge(limit).await?)
    }

    /// Create a root Timeline.
    ///
    /// Forks and imported child Timelines do not consume the root-Timeline ceiling.
    ///
    /// # Errors
    /// Returns [`GatewayError::Store`] on backend failure.
    pub async fn create_timeline(&self, name: &str) -> Result<Timeline, GatewayError> {
        let root_count = self.store.root_count(self.limits.max_timelines).await?;
        if root_count >= self.limits.max_timelines {
            return Err(GatewayError::TimelineLimitReached {
                maximum: self.limits.max_timelines,
            });
        }
        Ok(self.store.create(name.to_owned()).await?)
    }

    /// Append one Gateway-owned consent grant and issue its enforcement token.
    ///
    /// No Plugin or HTTP action route can construct this event type.
    ///
    /// # Errors
    /// Returns a closed codec, Timeline, or grant-sequence error.
    pub async fn issue_consent_grant(
        &self,
        timeline_id: &str,
        grant: ConsentGrantedV1,
    ) -> Result<(Event, ConsentCapabilityToken), GatewayError> {
        let timeline = match parse_timeline_id(timeline_id) {
            Ok(timeline) => timeline,
            Err(error) => return Err(error),
        };
        grant.encode()?;
        let _consent_timeline_guard = self.lock_consent_timeline(timeline).await;
        let event = match self
            .store
            .append_consent_grant(
                timeline,
                grant.clone(),
                self.consent_authority.append_permit(),
                self.limits.max_events_per_timeline,
            )
            .await
        {
            Err(executor::StoreExecutorError::Store(CoreError::Storage(message)))
                if message == "consent grant sequence mismatch" =>
            {
                return Err(GatewayError::ConsentGrantSequenceMismatch)
            }
            Err(executor::StoreExecutorError::Store(CoreError::Storage(message)))
                if message == "event limit reached" =>
            {
                return Err(GatewayError::EventLimitReached {
                    maximum: self.limits.max_events_per_timeline,
                })
            }
            Err(error) => return Err(error.into()),
            Ok(event) => event,
        };
        let token = self
            .consent_authority
            .record_grant_on_timeline(timeline, &grant);
        Ok((event, token))
    }

    /// Append one Gateway-owned consent revocation at its durable fence.
    ///
    /// The executor atomically verifies that the supplied fence matches the
    /// logical sequence committed by this revocation.
    ///
    /// # Errors
    /// Returns a closed Timeline, fence, or bounded append error.
    pub async fn issue_consent_revocation(
        &self,
        timeline_id: &str,
        revocation: ConsentRevokedV1,
    ) -> Result<Event, GatewayError> {
        let timeline = match parse_timeline_id(timeline_id) {
            Ok(timeline) => timeline,
            Err(error) => return Err(error),
        };
        revocation.encode()?;
        let _consent_timeline_guard = self.lock_consent_timeline(timeline).await;
        let reservation = match self
            .consent_authority
            .begin_revocation_on_timeline(timeline, &revocation)
        {
            Ok(reservation) => reservation,
            Err(pos_core::ConsentError::NoConsent) => {
                self.restore_consent_history_locked(timeline).await?;
                self.consent_authority
                    .begin_revocation_on_timeline(timeline, &revocation)
                    .map_err(|_| {
                        GatewayError::Store(CoreError::Storage(
                            "consent revocation did not name an active grant".to_owned(),
                        ))
                    })?
            }
            Err(pos_core::ConsentError::Revoked) => {
                return Err(GatewayError::Store(CoreError::Storage(
                    "consent revocation was already fenced".to_owned(),
                )))
            }
            Err(error) => return Err(GatewayError::Store(CoreError::Storage(error.to_string()))),
        };
        let scope = ingress_dedup_scope(revocation.subject_id);
        let event = match self
            .store
            .append_consent_revocation(
                timeline,
                revocation.clone(),
                scope,
                self.consent_authority.append_permit(),
                self.limits.max_events_per_timeline,
                reservation,
            )
            .await
        {
            Err(executor::StoreExecutorError::Store(CoreError::Storage(message)))
                if message == "consent revocation fence mismatch" =>
            {
                return Err(GatewayError::ConsentRevocationFenceMismatch)
            }
            Err(executor::StoreExecutorError::Store(CoreError::Storage(message)))
                if message == "event limit reached" =>
            {
                return Err(GatewayError::EventLimitReached {
                    maximum: self.limits.max_events_per_timeline,
                })
            }
            Ok(event) => event,
            Err(error) => {
                return Err(error.into());
            }
        };
        self.enqueue_consent_cleanup(scope).await;
        #[cfg(not(test))]
        self.schedule_pending_consent_cleanup();
        let cleanup = self
            .store
            .remove_append_identities_bounded(scope, CONSENT_DEDUP_CLEANUP_BATCH)
            .await
            .map_err(GatewayError::from)?;
        if cleanup.more_may_remain {
            self.enqueue_consent_cleanup(scope).await;
        }
        Ok(event)
    }

    /// Poll one bounded page of Timeline events, starting at `from_seq` (inclusive).
    ///
    /// The store is read for `limit + 1` Events. `next_from_seq` is `None` when
    /// exhausted; otherwise it is the inclusive sequence of the first omitted Event.
    ///
    /// # Errors
    /// Returns [`GatewayError::InvalidId`], [`GatewayError::InvalidPageLimit`], or
    /// [`GatewayError::Store`].
    ///
    /// ```no_run
    /// # async fn example(gateway: &piglor_gateway::Gateway, timeline: &str)
    /// # -> Result<(), piglor_gateway::GatewayError> {
    /// let page = gateway.read_events_page(timeline, 0, 100).await?;
    /// let _events = page.events;
    /// let _cursor = page.next_from_seq;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn read_events_page(
        &self,
        timeline_id: &str,
        from_seq: u64,
        limit: usize,
    ) -> Result<EventPage, GatewayError> {
        if limit == 0 || limit > MAX_EVENTS_PER_POLL {
            return Err(GatewayError::InvalidPageLimit {
                maximum: MAX_EVENTS_PER_POLL,
            });
        }
        let id = parse_timeline_id(timeline_id)?;
        let first_seq = from_seq.max(1);
        let last_seq = first_seq.saturating_add(limit as u64);
        let range = SeqRange {
            from: Seq::from_u64(first_seq),
            to: Some(Seq::from_u64(last_seq)),
        };
        let bounds = EventReadBounds::new_with_total_bytes_and_elapsed(
            MAX_EVENT_PAYLOAD_BYTES,
            MAX_EVENT_TYPE_BYTES,
            MAX_FORK_DEPTH,
            limit + 1,
            MAX_EVENTS_RESPONSE_BYTES,
            MAX_EVENTS_READ_TIME_MICROS,
        );
        let mut events = match self.store.read(id, range, bounds).await {
            Ok(events) => events,
            Err(executor::StoreExecutorError::Store(CoreError::PayloadTooLarge { .. })) => {
                return Err(GatewayError::EventPayloadTooLarge {
                    maximum: MAX_EVENT_PAYLOAD_BYTES,
                })
            }
            Err(executor::StoreExecutorError::Store(CoreError::EventMetadataTooLarge {
                field,
                ..
            })) => {
                return Err(GatewayError::EventMetadataTooLarge {
                    field,
                    maximum: MAX_EVENT_TYPE_BYTES,
                })
            }
            Err(executor::StoreExecutorError::Store(CoreError::ForkDepthTooLarge { .. })) => {
                return Err(GatewayError::ForkDepthTooLarge {
                    maximum: MAX_FORK_DEPTH,
                })
            }
            Err(executor::StoreExecutorError::Store(CoreError::ReadBytesTooLarge { .. })) => {
                return Err(GatewayError::EventResponseTooLarge {
                    maximum: MAX_EVENTS_RESPONSE_BYTES,
                })
            }
            Err(
                executor::StoreExecutorError::Store(CoreError::ReadTimeTooLarge { .. })
                | executor::StoreExecutorError::DeadlineExceeded,
            ) => {
                return Err(GatewayError::EventReadTimeExceeded {
                    maximum_micros: MAX_EVENTS_READ_TIME_MICROS,
                })
            }
            Err(error) => return Err(error.into()),
        };
        if events.iter().any(|event| {
            pos_core::is_geographic_event_type(&event.event_type)
                || pos_core::is_consent_event_type(&event.event_type)
        }) {
            return Err(GatewayError::ResourceUnavailable);
        }
        let next_from_seq = events
            .get(limit)
            .map(|event| Seq::from_u64(event_seq(event)));
        events.truncate(limit);
        Ok(EventPage {
            events,
            next_from_seq,
        })
    }

    /// Compatibility shim for Timelines that fit in one bounded page.
    ///
    /// This method no longer aggregates the Timeline to exhaustion. New callers
    /// must use [`Self::read_events_page`] and follow `next_from_seq`.
    ///
    /// # Errors
    /// Returns [`GatewayError::CompatibilityReadTruncated`] when more than one
    /// bounded page is available, in addition to the errors from
    /// [`Self::read_events_page`].
    #[deprecated(
        since = "0.1.0",
        note = "use read_events_page and follow EventPage::next_from_seq"
    )]
    pub async fn read_events_from(
        &self,
        timeline_id: &str,
        from_seq: u64,
    ) -> Result<Vec<Event>, GatewayError> {
        let page = self
            .read_events_page(timeline_id, from_seq, MAX_EVENTS_PER_POLL)
            .await?;
        if page.next_from_seq.is_some() {
            return Err(GatewayError::CompatibilityReadTruncated {
                maximum: MAX_EVENTS_PER_POLL,
            });
        }
        Ok(page.events)
    }

    /// Append one `world.action` draft. `payload` is bounded JSON → CBOR.
    ///
    /// # Errors
    /// Returns store / id / unsupported-type errors.
    #[cfg(test)]
    pub(crate) async fn append_action(
        &self,
        timeline_id: &str,
        entity_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<Event, GatewayError> {
        if event_type != EVENT_TYPE_ACTION {
            return Err(GatewayError::UnsupportedAction(event_type.to_owned()));
        }
        let timeline = parse_timeline_id(timeline_id)?;
        let entity = parse_entity_id(entity_id)?;
        let bytes = json_to_cbor(payload);
        let draft = EventDraft::new(entity, Kind::new(EVENT_TYPE_ACTION), bytes);
        self.append_draft(timeline, draft).await
    }

    /// Submit a proposed action through capability checks and plugin approval (ADR-057).
    ///
    /// # Errors
    /// Returns capability, validation, store, or ID errors.
    pub async fn submit_proposed_action(
        &self,
        timeline_id: &str,
        proposal: ProposedAction,
    ) -> Result<Event, GatewayError> {
        let Some(principal) = self.action_principal.as_ref() else {
            return Err(GatewayError::ActionAuthorizationUnavailable);
        };
        principal.authorizes(&proposal)?;
        let timeline = match parse_timeline_id(timeline_id) {
            Ok(timeline) => timeline,
            Err(error) => return Err(error),
        };
        match self.store.timeline(timeline).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(GatewayError::Store(CoreError::TimelineNotFound(timeline))),
            Err(error) => return Err(error.into()),
        }
        let draft = match self.action_registry.submit_action(&proposal) {
            Ok(draft) => draft,
            Err(error) => return Err(error.into()),
        };
        self.append_draft(timeline, draft).await
    }

    /// Submit a JSON action through the Gateway-owned action registry.
    ///
    /// # Errors
    /// Returns an ID, capability, validation, or store error.
    pub async fn submit_json_action(
        &self,
        timeline_id: &str,
        entity_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
        capability: &str,
    ) -> Result<Event, GatewayError> {
        let entity = match parse_entity_id(entity_id) {
            Ok(entity) => entity,
            Err(error) => return Err(error),
        };
        let proposal = match ProposedAction::try_new(
            Kind::new(event_type),
            entity,
            json_to_cbor(payload),
            Kind::new(capability),
        ) {
            Ok(proposal) => proposal,
            Err(error) => return Err(error.into()),
        };
        self.submit_proposed_action(timeline_id, proposal).await
    }

    /// Submit an identified JSON action through the Gateway-owned action registry.
    ///
    /// # Errors
    /// Returns an ID, capability, validation, conflict, or store error.
    pub async fn submit_identified_json_action(
        &self,
        timeline_id: &str,
        entity_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
        capability: &str,
        ingress_id: &str,
    ) -> Result<IdentifiedAppend, GatewayError> {
        let Some(principal) = self.action_principal.as_ref() else {
            return Err(GatewayError::ActionAuthorizationUnavailable);
        };
        let timeline = match parse_timeline_id(timeline_id) {
            Ok(timeline) => timeline,
            Err(error) => return Err(error),
        };
        match self.store.timeline(timeline).await {
            Ok(Some(_)) => {}
            Ok(None) => return Err(GatewayError::Store(CoreError::TimelineNotFound(timeline))),
            Err(error) => return Err(error.into()),
        }
        let entity = match parse_entity_id(entity_id) {
            Ok(entity) => entity,
            Err(error) => return Err(error),
        };
        let proposal = match ProposedAction::try_new(
            Kind::new(event_type),
            entity,
            json_to_cbor(payload),
            Kind::new(capability),
        ) {
            Ok(proposal) => proposal,
            Err(error) => return Err(error.into()),
        };
        if let Err(error) = principal.authorizes(&proposal) {
            return Err(error.into());
        }
        let draft = match self.action_registry.submit_action(&proposal) {
            Ok(draft) => draft,
            Err(error) => return Err(error.into()),
        };
        drop(proposal);
        self.append_identified_draft(timeline, draft, ingress_id)
            .await
    }

    /// Append an action using an opaque external ingress identity.
    ///
    /// The identity is hashed before it crosses the store boundary. The store
    /// owns admission time and compares only the canonical append intent, so
    /// generated Event metadata cannot turn a retry into a conflict.
    ///
    /// # Errors
    /// Returns an ID, payload, unsupported-action, conflict, or store error.
    #[cfg(test)]
    pub(crate) async fn append_identified_action(
        &self,
        timeline_id: &str,
        entity_id: &str,
        event_type: &str,
        payload: &serde_json::Value,
        ingress_id: &str,
    ) -> Result<IdentifiedAppend, GatewayError> {
        if event_type != EVENT_TYPE_ACTION {
            return Err(GatewayError::UnsupportedAction(event_type.to_owned()));
        }
        let timeline = parse_timeline_id(timeline_id)?;
        let entity = parse_entity_id(entity_id)?;
        let draft = EventDraft::new(entity, Kind::new(EVENT_TYPE_ACTION), json_to_cbor(payload));
        self.append_identified_draft(timeline, draft, ingress_id)
            .await
    }

    async fn append_identified_draft(
        &self,
        timeline: TimelineId,
        draft: EventDraft,
        ingress_id: &str,
    ) -> Result<IdentifiedAppend, GatewayError> {
        if draft.payload.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(GatewayError::EventPayloadTooLarge {
                maximum: MAX_EVENT_PAYLOAD_BYTES,
            });
        }
        if draft_event_response_len(&draft) > MAX_EVENTS_RESPONSE_BYTES {
            return Err(GatewayError::EventResponseTooLarge {
                maximum: MAX_EVENTS_RESPONSE_BYTES,
            });
        }
        let identity = ingress_identity(timeline, draft.entity, ingress_id);
        let outcome = {
            let timeline_meta = self
                .store
                .timeline(timeline)
                .await?
                .ok_or(GatewayError::Store(CoreError::TimelineNotFound(timeline)))?;
            let _ = timeline_meta;
            self.store
                .append_identified(
                    timeline,
                    identity,
                    AppendIntent::new(&draft),
                    self.limits.max_events_per_timeline,
                )
                .await?
                .ok_or(GatewayError::EventLimitReached {
                    maximum: self.limits.max_events_per_timeline,
                })?
        };
        let (event, duplicate) = match outcome {
            AppendOrDuplicateOutcome::Appended(event) => (*event, false),
            AppendOrDuplicateOutcome::Duplicate { event_id } => {
                let event = self.read_event_by_id(timeline, event_id).await?;
                (event, true)
            }
            AppendOrDuplicateOutcome::Conflict => return Err(GatewayError::IngressConflict),
        };
        if duplicate {
            return Ok(IdentifiedAppend { event, duplicate });
        }
        let notice = EventNotice {
            timeline_id: timeline.to_string(),
            event_id: event.id.to_string(),
            entity_id: event.entity.to_string(),
            event_type: event.event_type.as_str().to_owned(),
            seq: event.seq.as_u64(),
        };
        drop(self.bus.send(notice));
        Ok(IdentifiedAppend { event, duplicate })
    }

    /// Append one `society.signal` (fan-out convenience for #71).
    ///
    /// # Errors
    /// Returns store / id errors.
    pub async fn append_signal(
        &self,
        timeline_id: &str,
        entity_id: &str,
        signal: &SocietySignal,
    ) -> Result<Event, GatewayError> {
        let timeline = parse_timeline_id(timeline_id)?;
        let entity = parse_entity_id(entity_id)?;
        let draft = draft_signal(entity, signal);
        debug_assert_eq!(draft.event_type.as_str(), EVENT_TYPE_SIGNAL);
        self.append_draft(timeline, draft).await
    }

    /// The owned-Event ceiling uses this Timeline's store head. Logical Events
    /// inherited by a Fork are readable but do not consume the Fork's ceiling.
    async fn append_draft(
        &self,
        timeline: TimelineId,
        draft: EventDraft,
    ) -> Result<Event, GatewayError> {
        if draft.payload.as_slice().len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(GatewayError::EventPayloadTooLarge {
                maximum: MAX_EVENT_PAYLOAD_BYTES,
            });
        }
        if draft_event_response_len(&draft) > MAX_EVENTS_RESPONSE_BYTES {
            return Err(GatewayError::EventResponseTooLarge {
                maximum: MAX_EVENTS_RESPONSE_BYTES,
            });
        }
        // Fan out only after the committed command returns so subscribers can
        // safely issue a follow-up read.
        let event = {
            let mut committed = match self
                .store
                .append(
                    timeline,
                    vec![draft],
                    Some(self.limits.max_events_per_timeline),
                )
                .await
            {
                Ok(committed) => committed,
                Err(executor::StoreExecutorError::Store(CoreError::Storage(message)))
                    if message == "event limit reached" =>
                {
                    return Err(GatewayError::EventLimitReached {
                        maximum: self.limits.max_events_per_timeline,
                    });
                }
                Err(error) => return Err(error.into()),
            };
            let last_committed = committed.pop();
            match last_committed {
                Some(event) => event,
                None => {
                    return Err(GatewayError::Store(CoreError::Storage(
                        "empty append".to_owned(),
                    )))
                }
            }
        };
        if pos_core::is_consent_event_type(&event.event_type) {
            return Ok(event);
        }
        let notice = EventNotice {
            timeline_id: timeline.to_string(),
            event_id: event.id.to_string(),
            entity_id: event.entity.to_string(),
            event_type: event.event_type.as_str().to_owned(),
            seq: event.seq.as_u64(),
        };
        drop(self.bus.send(notice));
        Ok(event)
    }

    fn publish_geographic_notice(
        &self,
        timeline: TimelineId,
        event_id: pos_core::EventId,
        entity: EntityId,
        seq: Seq,
    ) {
        drop(self.bus.send(EventNotice {
            timeline_id: timeline.to_string(),
            event_id: event_id.to_string(),
            entity_id: entity.to_string(),
            event_type: pos_core::GEOGRAPHIC_EVENT_TYPE.to_owned(),
            seq: seq.as_u64(),
        }));
    }

    async fn read_event_by_id(
        &self,
        timeline: TimelineId,
        event_id: pos_core::ids::EventId,
    ) -> Result<Event, GatewayError> {
        self.store
            .read_one(timeline, event_id)
            .await?
            .ok_or_else(|| {
                GatewayError::Store(CoreError::Storage(
                    "duplicate identity points to a missing Event".to_owned(),
                ))
            })
    }

    #[cfg(test)]
    fn with_bus_capacity(store: Box<dyn EventStore>, capacity: usize) -> Self {
        let consent_authority = ConsentAuthority::new();
        Self {
            store: executor::StoreExecutor::new_with_consent_authority(
                store,
                consent_authority.append_permit(),
            ),
            bus: broadcast::channel(capacity).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority,
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        }
    }

    #[cfg(test)]
    fn with_executor_for_test(store: executor::StoreExecutor) -> Self {
        Self {
            store,
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority: ConsentAuthority::new(),
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        }
    }

    #[cfg(test)]
    fn with_limits(store: Box<dyn EventStore>, limits: GatewayLimits) -> Self {
        let consent_authority = ConsentAuthority::new();
        Self {
            store: executor::StoreExecutor::new_with_consent_authority(
                store,
                consent_authority.append_permit(),
            ),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits,
            owntracks_enabled: false,
            consent_authority,
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        }
    }
}

fn ingress_identity(timeline: TimelineId, entity: EntityId, ingress_id: &str) -> AppendIdentity {
    // Derive each persisted digest in an independent BLAKE3 context.  The
    // Gateway never stores the caller's ingress identifier or its preimage;
    // the context strings provide a stable, domain-separated opaque seam
    // without inventing a process-wide secret or configuration value.
    let mut key = blake3::Hasher::new_derive_key("pigloros ingress dedup key v1");
    key.update(b"timeline:");
    key.update(timeline.to_string().as_bytes());
    key.update(b"\nentity:");
    key.update(entity.to_string().as_bytes());
    key.update(b"\ningress:");
    key.update(ingress_id.as_bytes());
    AppendIdentity::new(
        AppendDedupKey::from_keyed_hash(*key.finalize().as_bytes()),
        ingress_dedup_scope(entity),
    )
}

fn ingress_dedup_scope(entity: EntityId) -> AppendDedupScope {
    let mut scope = blake3::Hasher::new_derive_key("pigloros ingress dedup scope v1");
    scope.update(b"entity:");
    scope.update(entity.to_string().as_bytes());
    AppendDedupScope::from_keyed_hash(*scope.finalize().as_bytes())
}

const fn event_seq(event: &Event) -> u64 {
    event.seq.as_u64()
}

fn parse_timeline_id(s: &str) -> Result<TimelineId, GatewayError> {
    Ulid::from_string(s)
        .map(TimelineId::from_ulid)
        .map_err(|e| GatewayError::InvalidId(e.to_string()))
}

fn parse_entity_id(s: &str) -> Result<EntityId, GatewayError> {
    Ulid::from_string(s)
        .map(EntityId::from_ulid)
        .map_err(|e| GatewayError::InvalidId(e.to_string()))
}

fn json_to_cbor(value: &serde_json::Value) -> CanonicalBytes {
    let mut buf = Vec::new();
    // `Vec<u8>` is an infallible CBOR sink; JSON values have no fallible
    // serializer hooks at this boundary.
    drop(ciborium::into_writer(value, &mut buf));
    CanonicalBytes::from_vec(buf)
}

fn serialized_json_len(value: &serde_json::Value) -> usize {
    let mut bytes = Vec::new();
    // `serde_json::Value` writes into `Vec<u8>` without an I/O failure mode.
    let _result = serde_json::to_writer(&mut bytes, value);
    bytes.len()
}

/// Serialize the exact wire fields derived from a draft, using the longest
/// possible sequence number and fixed-width ULID placeholders.
fn draft_event_response_len(draft: &EventDraft) -> usize {
    let payload = draft.payload.as_slice();
    let view = EventView {
        id: "0".repeat(26),
        entity: draft.entity.to_string(),
        event_type: draft.event_type.as_str().to_owned(),
        seq: u64::MAX,
        payload: decode_cbor_json(payload),
        payload_hex: hex_encode(payload),
    };
    let value = serde_json::json!({
        "events": [view],
        "next_from_seq": u64::MAX,
    });
    serialized_json_len(&value)
}

/// Request body for `POST /v1/timelines`.
#[derive(Debug, Deserialize)]
pub struct CreateTimelineRequest {
    pub name: String,
}

/// Request body for `POST /v1/timelines/:id/actions`.
#[derive(Debug, Deserialize)]
pub struct ActionRequest {
    pub entity_id: String,
    /// Must be `world.action` in the current Gateway foundation.
    #[serde(default = "default_action_type")]
    pub event_type: String,
    pub payload: serde_json::Value,
    /// Capability required to submit the action.
    pub capability: String,
    /// Optional external ingress identity for retry-safe append.
    #[serde(default)]
    pub ingress_id: Option<String>,
}

fn default_action_type() -> String {
    EVENT_TYPE_ACTION.to_owned()
}

/// Request body for `POST /v1/timelines/:id/signals`.
#[derive(Debug, Deserialize)]
pub struct SignalRequest {
    pub entity_id: String,
    pub dimension: SocietyDimension,
    pub value: f64,
    pub subject: Option<String>,
    pub object: Option<String>,
}

impl SignalRequest {
    fn into_signal(self) -> SocietySignal {
        SocietySignal {
            dimension: self.dimension,
            value: self.value,
            subject: self.subject,
            object: self.object,
        }
    }
}

/// Validated query for `GET /v1/timelines/:id/events`.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct EventsQuery {
    pub from_seq: u64,
    pub limit: usize,
}

impl Default for EventsQuery {
    fn default() -> Self {
        Self {
            from_seq: 0,
            limit: MAX_EVENTS_PER_POLL,
        }
    }
}

/// JSON view of a committed event.
///
/// `payload` is the decoded CBOR body when it round-trips as JSON (actions posted
/// via this gateway). `payload_hex` is always the canonical stored bytes (lowercase hex).
#[derive(Debug, Serialize)]
pub struct EventView {
    pub id: String,
    pub entity: String,
    pub event_type: String,
    pub seq: u64,
    /// Decoded JSON when the stored CBOR payload is JSON-compatible; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Canonical CBOR bytes as lowercase hex (for clients that decode CBOR themselves).
    pub payload_hex: String,
}

impl TryFrom<&Event> for EventView {
    type Error = GatewayError;

    fn try_from(event: &Event) -> Result<Self, Self::Error> {
        if pos_core::is_geographic_event_type(&event.event_type)
            || pos_core::is_consent_event_type(&event.event_type)
        {
            return Err(GatewayError::ResourceUnavailable);
        }
        let bytes = event.payload.as_slice();
        Ok(Self {
            id: event.id.to_string(),
            entity: event.entity.to_string(),
            event_type: event.event_type.as_str().to_owned(),
            seq: event.seq.as_u64(),
            payload: decode_cbor_json(bytes),
            payload_hex: hex_encode(bytes),
        })
    }
}

fn classify_owntracks_admission(
    admission: &GeoLocationAdmissionOutcome,
) -> Result<OwnTracksIngressResult, GatewayError> {
    if admission.is_accepted() {
        let _ = accepted_event_coordinates(admission)?;
        Ok(OwnTracksIngressResult::Accepted)
    } else if admission.is_duplicate() {
        Ok(OwnTracksIngressResult::Duplicate)
    } else if admission.is_conflict() {
        Ok(OwnTracksIngressResult::Conflict)
    } else {
        Ok(OwnTracksIngressResult::Unavailable)
    }
}

fn event_view_json(view: &EventView) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert("id".to_owned(), serde_json::Value::String(view.id.clone()));
    object.insert(
        "entity".to_owned(),
        serde_json::Value::String(view.entity.clone()),
    );
    object.insert(
        "event_type".to_owned(),
        serde_json::Value::String(view.event_type.clone()),
    );
    object.insert("seq".to_owned(), serde_json::json!(view.seq));
    if let Some(payload) = &view.payload {
        object.insert("payload".to_owned(), payload.clone());
    }
    object.insert(
        "payload_hex".to_owned(),
        serde_json::Value::String(view.payload_hex.clone()),
    );
    serde_json::Value::Object(object)
}

fn decode_cbor_json(bytes: &[u8]) -> Option<serde_json::Value> {
    ciborium::from_reader(bytes).ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            match self {
                Ok(value) => value,
                Err(error) => {
                    std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
                }
            }
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    trait TestErrorExt<E> {
        fn test_err(self) -> E;
    }

    impl<T, E: std::fmt::Debug> TestErrorExt<E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(_value) => std::panic::resume_unwind(Box::new("expected test error")),
                Err(error) => error,
            }
        }
    }

    use super::*;
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::SchemaVersion,
        geo_admission::GeoLocationAdmissionIntentV1,
        ids::EventId,
        store::{export_timeline_own, import_timeline_with_id},
        timeline::TimelineMeta,
        EVENT_TYPE_CONSENT_GRANTED_V1, EVENT_TYPE_CONSENT_REVOKED_V1,
    };
    use pos_store::{open_store, StoreConfig};
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        time::Duration,
    };
    use tokio::sync::broadcast;

    fn memory_gw() -> Gateway {
        Gateway::new(open_store(StoreConfig::Memory).test_ok())
    }

    fn consent_grant(subject_id: EntityId, grant_seq: u64) -> ConsentGrantedV1 {
        ConsentGrantedV1 {
            subject_id,
            grantee_id: EntityId::new(),
            purpose: "contract-test".to_owned(),
            modalities: pos_core::MODALITY_LOCATION,
            min_geo_resolution: 1,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq,
        }
    }

    #[tokio::test]
    async fn gateway_consent_operations_reject_invalid_timeline_ids() {
        let gateway = memory_gw();
        let grant_error = gateway
            .issue_consent_grant("not-a-timeline", consent_grant(EntityId::new(), 1))
            .await
            .test_err();
        assert!(matches!(grant_error, GatewayError::InvalidId(_)));

        let revocation_error = gateway
            .issue_consent_revocation(
                "not-a-timeline",
                ConsentRevokedV1 {
                    subject_id: EntityId::new(),
                    grantee_id: EntityId::new(),
                    grant_seq: 1,
                    fence_seq: 1,
                },
            )
            .await
            .test_err();
        assert!(matches!(revocation_error, GatewayError::InvalidId(_)));
        drop(gateway);
    }

    #[test]
    fn gateway_action_registry_exposes_the_host_action_schema() {
        let registry = gateway_action_registry();
        assert!(registry.schemas.contains(EVENT_TYPE_ACTION));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn world_body_constructor_without_principal_is_fail_closed() {
        let body = EntityId::new();
        let gateway =
            Gateway::new_with_world_bodies(open_store(StoreConfig::Memory).test_ok(), [body]);
        assert!(gateway.action_principal.is_none());
        assert!(!gateway.owntracks_enabled);
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn action_submission_rejects_unauthorized_inputs_before_store_access() {
        let gateway = memory_gw();
        let proposal = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            EntityId::new(),
            CanonicalBytes::from_static(b"payload"),
            Kind::new("world.action.submit"),
        );
        assert!(matches!(
            gateway
                .submit_proposed_action(&TimelineId::new().to_string(), proposal)
                .await,
            Err(GatewayError::ActionAuthorizationUnavailable)
        ));
        assert!(matches!(
            gateway
                .submit_json_action(
                    &TimelineId::new().to_string(),
                    "not-an-entity",
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({}),
                    "world.action.submit",
                )
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        assert!(matches!(
            gateway
                .submit_identified_json_action(
                    "not-a-timeline",
                    &EntityId::new().to_string(),
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({}),
                    "world.action.submit",
                    "ingress-1",
                )
                .await,
            Err(GatewayError::ActionAuthorizationUnavailable)
        ));
        drop(gateway);
    }

    async fn assert_proposed_action_boundaries(
        gateway: &Gateway,
        valid_timeline: &str,
        proposal: &ProposedAction,
    ) {
        assert!(matches!(
            gateway
                .submit_proposed_action("not-a-timeline", proposal.clone())
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        assert!(matches!(
            gateway
                .submit_proposed_action(&TimelineId::new().to_string(), proposal.clone())
                .await,
            Err(GatewayError::Store(CoreError::TimelineNotFound(_)))
        ));
        assert!(matches!(
            gateway
                .submit_json_action(
                    valid_timeline,
                    &proposal.actor_entity_id.to_string(),
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({"data": "x".repeat(5000)}),
                    "world.action.submit",
                )
                .await,
            Err(GatewayError::ActionRejected(_))
        ));
    }

    async fn assert_identified_action_boundaries(
        gateway: &Gateway,
        valid_timeline: &str,
        actor: EntityId,
    ) {
        assert!(matches!(
            gateway
                .submit_identified_json_action(
                    "not-a-timeline",
                    &actor.to_string(),
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({}),
                    "world.action.submit",
                    "boundary-1",
                )
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        assert!(matches!(
            gateway
                .submit_identified_json_action(
                    &TimelineId::new().to_string(),
                    &actor.to_string(),
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({}),
                    "world.action.submit",
                    "missing-timeline",
                )
                .await,
            Err(GatewayError::Store(CoreError::TimelineNotFound(_)))
        ));
        assert!(matches!(
            gateway
                .submit_identified_json_action(
                    valid_timeline,
                    "not-an-entity",
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({}),
                    "world.action.submit",
                    "boundary-2",
                )
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        let oversized = serde_json::json!({"data": "x".repeat(5000)});
        assert!(matches!(
            gateway
                .submit_identified_json_action(
                    valid_timeline,
                    &actor.to_string(),
                    EVENT_TYPE_ACTION,
                    &oversized,
                    "world.action.submit",
                    "boundary-3",
                )
                .await,
            Err(GatewayError::ActionRejected(_))
        ));
        assert!(matches!(
            gateway
                .submit_identified_json_action(
                    valid_timeline,
                    &EntityId::new().to_string(),
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({}),
                    "world.action.submit",
                    "boundary-4",
                )
                .await,
            Err(GatewayError::ActionRejected(_))
        ));
        assert!(matches!(
            gateway
                .submit_identified_json_action(
                    valid_timeline,
                    &actor.to_string(),
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({}),
                    "world.action.submit",
                    "boundary-5",
                )
                .await,
            Err(GatewayError::ActionRejected(_))
        ));
    }

    fn action_error_gateway(actor: EntityId, body: EntityId) -> Gateway {
        Gateway {
            store: executor::StoreExecutor::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailGetTimeline,
            })),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority: ConsentAuthority::new(),
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry_with_bodies([body]),
            action_principal: Some(ActionPrincipal::new(
                actor,
                [Kind::new("world.action.submit")],
            )),
        }
    }

    #[tokio::test]
    async fn action_submission_covers_id_store_and_approver_boundaries() {
        let actor = EntityId::new();
        let body = EntityId::new();
        let gateway = Gateway::new_with_world_bodies_and_principal(
            open_store(StoreConfig::Memory).test_ok(),
            [body],
            ActionPrincipal::new(actor, [Kind::new("world.action.submit")]),
        );
        let timeline = gateway.create_timeline("action-boundaries").await.test_ok();
        let valid_timeline = timeline.id().to_string();
        let proposal = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            actor,
            CanonicalBytes::from_static(b"payload"),
            Kind::new("world.action.submit"),
        );
        assert_proposed_action_boundaries(&gateway, &valid_timeline, &proposal).await;
        assert_identified_action_boundaries(&gateway, &valid_timeline, actor).await;
        gateway.shutdown().await.test_ok();

        let error_gateway = action_error_gateway(actor, body);
        assert!(matches!(
            error_gateway
                .submit_proposed_action(&valid_timeline, proposal)
                .await,
            Err(GatewayError::Store(_))
        ));
        assert!(matches!(
            error_gateway
                .submit_identified_json_action(
                    &valid_timeline,
                    &actor.to_string(),
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({}),
                    "world.action.submit",
                    "boundary-error",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        error_gateway.shutdown().await.test_ok();
        drop(error_gateway);
        drop(gateway);
    }

    struct TemporarySqliteFile {
        path: String,
    }

    impl TemporarySqliteFile {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "piglor-gateway-{label}-{}-{}.sqlite",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .test_ok()
                    .as_nanos(),
            ));
            Self {
                path: path.to_str().test_ok().to_owned(),
            }
        }
    }

    impl Drop for TemporarySqliteFile {
        fn drop(&mut self) {
            for suffix in ["", "-shm", "-wal"] {
                drop(std::fs::remove_file(format!("{}{suffix}", self.path)));
            }
        }
    }

    #[derive(Clone, Copy)]
    enum ScriptMode {
        FailCreate,
        FailList,
        FailGetTimeline,
        EmptyAppend,
        FailAppend,
        FailConsentRevocationAppend,
        FailRead,
        ReadPayloadTooLarge,
        ReadMetadataTooLarge,
        ReadForkDepthTooLarge,
        ReadBytesTooLarge,
        ReadTimeTooLarge,
        RejectListUse,
        Duplicate,
        DuplicateReadError,
        GeographicRead(&'static str),
        ConsentRead(&'static str),
        MissingTimeline,
    }

    struct ScriptedStore {
        mode: ScriptMode,
    }

    impl EventStore for ScriptedStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            if matches!(self.mode, ScriptMode::FailCreate) {
                return Err(CoreError::Storage("create failed".into()));
            }
            Ok(Timeline::new(TimelineMeta::root(name)))
        }

        fn append(
            &mut self,
            _timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            if matches!(self.mode, ScriptMode::FailAppend) {
                return Err(CoreError::Storage("append failed".into()));
            }
            if matches!(self.mode, ScriptMode::FailConsentRevocationAppend)
                && drafts
                    .iter()
                    .any(|draft| draft.event_type == Kind::new(EVENT_TYPE_CONSENT_REVOKED_V1))
            {
                return Err(CoreError::Storage("revocation append failed".into()));
            }
            if matches!(self.mode, ScriptMode::EmptyAppend) {
                return Ok(Vec::new());
            }
            Ok(drafts
                .iter()
                .enumerate()
                .map(|(i, d)| Event {
                    id: EventId::new(),
                    entity: d.entity,
                    event_type: d.event_type.clone(),
                    payload: d.payload.clone(),
                    wall_time: d.wall_time.unwrap_or_else(WallTime::now),
                    seq: Seq::from_u64(i as u64 + 1),
                    causation_id: d.causation_id,
                    correlation_id: d.correlation_id,
                    schema_version: d.schema_version,
                    signature: None,
                    payload_hash: Hash::from_bytes([0u8; 32]),
                })
                .collect())
        }

        fn append_bounded(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
            _max_owned_events: u64,
        ) -> Result<Option<Vec<Event>>, CoreError> {
            if matches!(self.mode, ScriptMode::FailGetTimeline) {
                return Err(CoreError::Storage("get timeline failed".into()));
            }
            self.append(timeline, drafts).map(Some)
        }

        fn append_consent_bounded(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
            _permit: pos_core::ConsentAppendPermit,
            max_owned_events: u64,
        ) -> Result<Option<Vec<Event>>, CoreError> {
            self.append_bounded(timeline, drafts, max_owned_events)
        }

        fn append_consent_revocation_bounded(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
            permit: pos_core::ConsentAppendPermit,
            max_owned_events: u64,
            _cleanup_scope: AppendDedupScope,
        ) -> Result<Option<Vec<Event>>, CoreError> {
            self.append_consent_bounded(timeline, drafts, permit, max_owned_events)
        }

        fn read(&self, _timeline: TimelineId, _range: SeqRange) -> Result<Vec<Event>, CoreError> {
            if matches!(self.mode, ScriptMode::FailRead) {
                return Err(CoreError::Storage("read failed".into()));
            }
            let bounded_error = match self.mode {
                ScriptMode::ReadPayloadTooLarge => Some(CoreError::PayloadTooLarge { size: 1 }),
                ScriptMode::ReadMetadataTooLarge => Some(CoreError::EventMetadataTooLarge {
                    field: "event_type",
                    size: 1,
                }),
                ScriptMode::ReadForkDepthTooLarge => {
                    Some(CoreError::ForkDepthTooLarge { depth: 1 })
                }
                ScriptMode::ReadBytesTooLarge => Some(CoreError::ReadBytesTooLarge { size: 1 }),
                ScriptMode::ReadTimeTooLarge => {
                    Some(CoreError::ReadTimeTooLarge { elapsed_micros: 1 })
                }
                _ => None,
            };
            if let Some(error) = bounded_error {
                return Err(error);
            }
            if let ScriptMode::GeographicRead(event_type) | ScriptMode::ConsentRead(event_type) =
                self.mode
            {
                let payload = CanonicalBytes::from_vec(b"protected".to_vec());
                return Ok(vec![Event {
                    id: EventId::new(),
                    entity: EntityId::new(),
                    event_type: Kind::new(event_type),
                    payload,
                    wall_time: WallTime::from_micros(1),
                    seq: Seq::from_u64(1),
                    causation_id: None,
                    correlation_id: None,
                    schema_version: SchemaVersion::V1,
                    signature: None,
                    payload_hash: Hash::from_bytes([0; 32]),
                }]);
            }
            Ok(Vec::new())
        }

        fn read_bounded(
            &self,
            timeline: TimelineId,
            range: SeqRange,
            _bounds: EventReadBounds,
        ) -> Result<Vec<Event>, CoreError> {
            self.read(timeline, range)
        }

        fn fork(
            &mut self,
            _parent: TimelineId,
            _at_seq: Seq,
            _name: &str,
        ) -> Result<Timeline, CoreError> {
            Ok(Timeline::new(TimelineMeta::root("fork")))
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            assert!(
                !matches!(self.mode, ScriptMode::RejectListUse),
                "Gateway root quota must not materialise Timeline lists"
            );
            if matches!(self.mode, ScriptMode::FailList) {
                return Err(CoreError::Storage("list failed".into()));
            }
            Ok(Vec::new())
        }

        fn root_timeline_count_bounded(&self, _maximum: usize) -> Result<usize, CoreError> {
            if matches!(self.mode, ScriptMode::FailList) {
                return Err(CoreError::Storage("root count failed".into()));
            }
            Ok(0)
        }

        fn get_timeline(&self, _id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            if matches!(self.mode, ScriptMode::FailGetTimeline) {
                return Err(CoreError::Storage("get timeline failed".into()));
            }
            if matches!(self.mode, ScriptMode::MissingTimeline) {
                return Ok(None);
            }
            Ok(Some(Timeline::new(TimelineMeta::root("scripted"))))
        }

        fn logical_head(&self, _id: TimelineId) -> Result<Seq, CoreError> {
            Ok(Seq::ZERO)
        }

        fn append_intent_or_duplicate_bounded(
            &mut self,
            _timeline: TimelineId,
            _identity: AppendIdentity,
            _intent: AppendIntent,
            _max_owned_events: u64,
        ) -> Result<Option<AppendOrDuplicateOutcome>, CoreError> {
            if matches!(
                self.mode,
                ScriptMode::Duplicate | ScriptMode::DuplicateReadError
            ) {
                return Ok(Some(AppendOrDuplicateOutcome::Duplicate {
                    event_id: EventId::new(),
                }));
            }
            Err(CoreError::Storage("scripted bounded append failed".into()))
        }

        fn read_event_by_id(
            &self,
            _timeline: TimelineId,
            _event_id: EventId,
        ) -> Result<Option<Event>, CoreError> {
            if matches!(self.mode, ScriptMode::DuplicateReadError) {
                return Err(CoreError::Storage("scripted event lookup failed".into()));
            }
            Ok(None)
        }
    }

    struct BlockFirstRootCount {
        inner: Box<dyn EventStore>,
        started: tokio::sync::mpsc::UnboundedSender<()>,
        release: mpsc::Receiver<()>,
        block: AtomicBool,
    }

    impl EventStore for BlockFirstRootCount {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.inner.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.append(timeline, drafts)
        }

        fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
            self.inner.read(timeline, range)
        }

        fn read_bounded(
            &self,
            timeline: TimelineId,
            range: SeqRange,
            bounds: EventReadBounds,
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.read_bounded(timeline, range, bounds)
        }

        fn fork(
            &mut self,
            parent: TimelineId,
            at_seq: Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.inner.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.inner.list_timelines()
        }

        fn root_timeline_count_bounded(&self, maximum: usize) -> Result<usize, CoreError> {
            if self.block.swap(false, Ordering::SeqCst) {
                self.started.send(()).test_ok();
                self.release.recv().test_ok();
            }
            self.inner.root_timeline_count_bounded(maximum)
        }

        fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
            self.inner.get_timeline(id)
        }
    }

    #[tokio::test]
    async fn closed_executor_is_typed_at_gateway_seam() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(9);
        let _ = std::thread::spawn(move || drop(rx.blocking_recv()));
        let gateway =
            Gateway::with_executor_for_test(executor::StoreExecutor::from_sender_for_test(tx));

        assert!(matches!(
            gateway.create_timeline("closed").await,
            Err(GatewayError::StoreExecutorClosed)
        ));
        assert!(matches!(
            gateway
                .issue_consent_grant(
                    &TimelineId::new().to_string(),
                    consent_grant(EntityId::new(), 1)
                )
                .await,
            Err(GatewayError::StoreExecutorClosed)
        ));
        drop(gateway);
    }

    #[tokio::test]
    async fn closed_queue_is_typed_at_gateway_seam() {
        let (tx, rx) = tokio::sync::mpsc::channel(9);
        drop(rx);
        let gateway =
            Gateway::with_executor_for_test(executor::StoreExecutor::from_sender_for_test(tx));

        assert!(matches!(
            gateway.create_timeline("closed-queue").await,
            Err(GatewayError::StoreExecutorClosed)
        ));
        drop(gateway);
    }

    #[tokio::test]
    async fn saturated_gateway_append_is_typed_and_does_not_mutate_or_publish() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("saturation-target").test_ok();
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = mpsc::channel();
        let gateway = Gateway::with_executor_for_test(executor::StoreExecutor::new(Box::new(
            BlockFirstRootCount {
                inner: store,
                started: started_tx,
                release: release_rx,
                block: AtomicBool::new(true),
            },
        )));
        let blocker_gateway = gateway.clone();
        let blocker =
            tokio::spawn(async move { blocker_gateway.store.root_count(MAX_TIMELINES).await });
        tokio::time::timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .test_ok()
            .test_ok();

        let mut queued = Vec::new();
        for _ in 0..executor::QUEUE_CAPACITY {
            let queued_gateway = gateway.clone();
            queued.push(tokio::spawn(async move {
                queued_gateway
                    .purge_expired_ingress_identities(std::num::NonZeroUsize::new(1).test_ok())
                    .await
            }));
            tokio::task::yield_now().await;
        }
        let mut notices = gateway.subscribe();

        let error = gateway
            .append_action(
                &timeline.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"choice": "saturated"}),
            )
            .await
            .test_err();

        assert!(matches!(error, GatewayError::StoreExecutorSaturated));
        release_tx.send(()).test_ok();
        let blocker_result = blocker.await.test_ok();
        assert!(blocker_result.is_ok(), "blocker result: {blocker_result:?}");
        for request in queued {
            assert!(request.await.is_ok());
        }
        assert!(matches!(
            notices.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let page = gateway
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .test_ok();
        assert!(page.events.is_empty());
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn create_timeline_and_append_action_roundtrip() {
        let gw = memory_gw();
        let tl = gw.create_timeline("demo").await.test_ok();
        let entity = EntityId::new().to_string();
        let event = gw
            .append_action(
                &tl.id().to_string(),
                &entity,
                EVENT_TYPE_ACTION,
                &serde_json::json!({"dx": 1.0, "dy": 0.0}),
            )
            .await
            .test_ok();
        assert_eq!(event.event_type.as_str(), EVENT_TYPE_ACTION);
        let page = gw
            .read_events_page(&tl.id().to_string(), 0, MAX_EVENTS_PER_POLL)
            .await
            .test_ok();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].id, event.id);
        assert_eq!(page.next_from_seq, None);
        drop(gw);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_issues_only_canonical_consent_events_at_the_bound_sequence() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("consent-host").await.test_ok();
        let mut notices = gateway.subscribe();
        let grant = consent_grant(EntityId::new(), 1);

        let (grant_event, token) = gateway
            .issue_consent_grant(&timeline.id().to_string(), grant.clone())
            .await
            .test_ok();
        assert_eq!(
            grant_event.event_type.as_str(),
            pos_core::EVENT_TYPE_CONSENT_GRANTED_V1
        );
        assert_eq!(
            ConsentGrantedV1::decode(&grant_event.payload).test_ok(),
            grant
        );
        assert_eq!(token.grant_seq(), 1);
        assert!(matches!(
            notices.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        let revocation = ConsentRevokedV1 {
            subject_id: token.subject_id(),
            grantee_id: token.grantee_id(),
            grant_seq: token.grant_seq(),
            fence_seq: 2,
        };
        let revocation_event = gateway
            .issue_consent_revocation(&timeline.id().to_string(), revocation.clone())
            .await
            .test_ok();
        assert_eq!(
            revocation_event.event_type.as_str(),
            EVENT_TYPE_CONSENT_REVOKED_V1
        );
        assert_eq!(
            ConsentRevokedV1::decode(&revocation_event.payload).test_ok(),
            revocation
        );
        assert!(matches!(
            notices.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        let already_fenced = gateway
            .issue_consent_revocation(&timeline.id().to_string(), revocation)
            .await
            .test_err();
        assert!(matches!(
            already_fenced,
            GatewayError::Store(CoreError::Storage(message))
                if message == "consent revocation was already fenced"
        ));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn consent_revocation_removes_subject_ingress_dedup_identities() {
        let gateway = memory_gw();
        let timeline = gateway
            .create_timeline("consent-dedup-cleanup")
            .await
            .test_ok();
        let subject = EntityId::new();
        let subject_text = subject.to_string();
        let (_grant_event, token) = gateway
            .issue_consent_grant(&timeline.id().to_string(), consent_grant(subject, 1))
            .await
            .test_ok();

        let first = gateway
            .append_identified_action(
                &timeline.id().to_string(),
                &subject_text,
                EVENT_TYPE_ACTION,
                &serde_json::json!({"dx": 1.0}),
                "device-1:42",
            )
            .await
            .test_ok();
        assert!(!first.duplicate);

        for index in 0..CONSENT_DEDUP_CLEANUP_BATCH.get() {
            let result = gateway
                .append_identified_action(
                    &timeline.id().to_string(),
                    &subject_text,
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({"dx": index}),
                    &format!("bulk-device:{index}"),
                )
                .await
                .test_ok();
            assert!(!result.duplicate);
        }

        let fence_seq = gateway
            .store
            .protected_logical_head(timeline.id())
            .await
            .test_ok()
            .as_u64()
            .saturating_add(1);
        gateway
            .issue_consent_revocation(
                &timeline.id().to_string(),
                ConsentRevokedV1 {
                    subject_id: token.subject_id(),
                    grantee_id: token.grantee_id(),
                    grant_seq: token.grant_seq(),
                    fence_seq,
                },
            )
            .await
            .test_ok();

        let mut retried = None;
        for _ in 0..32 {
            let _ = gateway.process_pending_consent_cleanup().await.test_ok();
            let result = gateway
                .append_identified_action(
                    &timeline.id().to_string(),
                    &subject_text,
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({"dx": 1.0}),
                    "device-1:42",
                )
                .await
                .test_ok();
            if !result.duplicate {
                retried = Some(result);
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(retried.is_some());
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn scheduled_consent_cleanup_retries_bounded_store_failures() {
        let gateway = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::FailList,
        }));
        gateway
            .enqueue_consent_cleanup(ingress_dedup_scope(EntityId::new()))
            .await;
        gateway.schedule_pending_consent_cleanup();
        tokio::time::sleep(Duration::from_millis(
            CONSENT_DEDUP_CLEANUP_RETRY_DELAY_MILLIS * 2,
        ))
        .await;
        assert!(gateway.process_pending_consent_cleanup().await.is_err());
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_rejects_a_consent_grant_with_a_stale_sequence_before_append() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("consent-sequence").await.test_ok();
        let error = gateway
            .issue_consent_grant(
                &timeline.id().to_string(),
                consent_grant(EntityId::new(), 0),
            )
            .await
            .test_err();
        assert!(matches!(error, GatewayError::ConsentGrantSequenceMismatch));
        let page = gateway
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .test_ok();
        assert!(page.events.is_empty());
        drop(gateway);
    }

    #[tokio::test]
    async fn gateway_preserves_an_unclassified_consent_grant_append_error() {
        let gateway = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::FailAppend,
        }));
        let timeline = gateway
            .create_timeline("consent-grant-append-error")
            .await
            .test_ok();
        let error = gateway
            .issue_consent_grant(
                &timeline.id().to_string(),
                consent_grant(EntityId::new(), 1),
            )
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::Store(CoreError::Storage(message))
                if message == "append failed"
        ));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_consent_grant_preserves_codec_and_event_ceiling_errors() {
        let gateway = Gateway::with_limits(
            open_store(StoreConfig::Memory).test_ok(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = gateway
            .create_timeline("consent-grant-errors")
            .await
            .test_ok();
        let subject = EntityId::new();
        let mut invalid = consent_grant(EntityId::new(), 1);
        invalid.modalities = 0x10;
        let codec_error = gateway
            .issue_consent_grant(&timeline.id().to_string(), invalid)
            .await
            .test_err();
        assert!(matches!(
            codec_error,
            GatewayError::ConsentCodec(ConsentCodecError::FieldOutOfBounds)
        ));

        gateway
            .issue_consent_grant(&timeline.id().to_string(), consent_grant(subject, 1))
            .await
            .test_ok();
        let ceiling_error = gateway
            .issue_consent_grant(&timeline.id().to_string(), consent_grant(subject, 2))
            .await
            .test_err();
        assert!(matches!(
            ceiling_error,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
        drop(gateway);
    }

    async fn gateway_with_consent_grant() -> (Gateway, Timeline, Event, ConsentCapabilityToken) {
        let gateway = Gateway::with_limits(
            open_store(StoreConfig::Memory).test_ok(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = gateway
            .create_timeline("consent-revocation-test")
            .await
            .test_ok();
        let (grant_event, token) = gateway
            .issue_consent_grant(
                &timeline.id().to_string(),
                consent_grant(EntityId::new(), 1),
            )
            .await
            .test_ok();
        (gateway, timeline, grant_event, token)
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_revocation_rejects_unknown_session_before_append() {
        let gateway = Gateway::with_limits(
            open_store(StoreConfig::Memory).test_ok(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = gateway
            .create_timeline("consent-revocation-unknown")
            .await
            .test_ok();
        let unknown = ConsentRevokedV1 {
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            grant_seq: 1,
            fence_seq: 1,
        };
        let unknown_error = gateway
            .issue_consent_revocation(&timeline.id().to_string(), unknown)
            .await
            .test_err();
        assert!(matches!(
            unknown_error,
            GatewayError::Store(CoreError::Storage(message))
                if message == "consent revocation did not name an active grant"
        ));
        assert!(gateway
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .test_ok()
            .events
            .is_empty());
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_revocation_rejects_stale_fence_before_append() {
        let (gateway, timeline, grant_event, token) = gateway_with_consent_grant().await;
        let fence_error = gateway
            .issue_consent_revocation(
                &timeline.id().to_string(),
                ConsentRevokedV1 {
                    subject_id: token.subject_id(),
                    grantee_id: token.grantee_id(),
                    grant_seq: token.grant_seq(),
                    fence_seq: grant_event.seq.as_u64(),
                },
            )
            .await
            .test_err();
        assert!(matches!(
            fence_error,
            GatewayError::ConsentRevocationFenceMismatch
        ));
        let page_error = gateway
            .read_events_page(&timeline.id().to_string(), 0, 2)
            .await
            .test_err();
        assert!(matches!(page_error, GatewayError::ResourceUnavailable));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_revocation_rejects_event_ceiling_after_fence_validation() {
        let (gateway, timeline, grant_event, token) = gateway_with_consent_grant().await;
        let stale_fence = gateway
            .issue_consent_revocation(
                &timeline.id().to_string(),
                ConsentRevokedV1 {
                    subject_id: token.subject_id(),
                    grantee_id: token.grantee_id(),
                    grant_seq: token.grant_seq(),
                    fence_seq: grant_event.seq.as_u64(),
                },
            )
            .await
            .test_err();
        assert!(matches!(
            stale_fence,
            GatewayError::ConsentRevocationFenceMismatch
        ));
        let ceiling_error = gateway
            .issue_consent_revocation(
                &timeline.id().to_string(),
                ConsentRevokedV1 {
                    subject_id: token.subject_id(),
                    grantee_id: token.grantee_id(),
                    grant_seq: token.grant_seq(),
                    fence_seq: grant_event.seq.as_u64().saturating_add(1),
                },
            )
            .await
            .test_err();
        assert!(matches!(
            ceiling_error,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
        drop(gateway);
    }

    #[tokio::test]
    async fn consent_history_lock_is_shared_by_gateway_clones() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("consent-lock").await.test_ok().id();
        let guard = gateway.lock_consent_timeline(timeline).await;
        let clone = gateway.clone();
        let grant_task = tokio::spawn(async move {
            clone
                .issue_consent_grant(&timeline.to_string(), consent_grant(EntityId::new(), 1))
                .await
        });

        tokio::task::yield_now().await;
        assert!(!grant_task.is_finished());
        drop(guard);
        let (event, _) = grant_task.await.test_ok().test_ok();
        assert_eq!(event.event_type.as_str(), EVENT_TYPE_CONSENT_GRANTED_V1);
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_revocation_preserves_unclassified_append_errors() {
        let gateway = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::FailConsentRevocationAppend,
        }));
        let timeline = gateway
            .create_timeline("consent-revocation-append-error")
            .await
            .test_ok();
        let (_, token) = gateway
            .issue_consent_grant(
                &timeline.id().to_string(),
                consent_grant(EntityId::new(), 1),
            )
            .await
            .test_ok();
        let error = gateway
            .issue_consent_revocation(
                &timeline.id().to_string(),
                ConsentRevokedV1 {
                    subject_id: token.subject_id(),
                    grantee_id: token.grantee_id(),
                    grant_seq: token.grant_seq(),
                    fence_seq: Seq::ZERO.as_u64().saturating_add(1),
                },
            )
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::Store(CoreError::Storage(message))
                if message == "revocation append failed"
        ));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn public_gateway_read_rejects_geographic_events_from_an_adapter() {
        for event_type in [
            pos_core::GEOGRAPHIC_EVENT_TYPE,
            pos_core::GEOGRAPHIC_CELL_EVENT_TYPE,
        ] {
            let gateway = Gateway::new(Box::new(ScriptedStore {
                mode: ScriptMode::GeographicRead(event_type),
            }));
            let error = gateway
                .read_events_page(&TimelineId::new().to_string(), 0, 1)
                .await
                .test_err();
            assert!(matches!(error, GatewayError::ResourceUnavailable));
            drop(gateway);
        }
        let gateway = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::ConsentRead(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
        }));
        let error = gateway
            .read_events_page(&TimelineId::new().to_string(), 0, 1)
            .await
            .test_err();
        assert!(matches!(error, GatewayError::ResourceUnavailable));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_enforces_timeline_and_event_bounds() {
        let timeline_limited = Gateway::with_limits(
            open_store(StoreConfig::Memory).test_ok(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 2,
            },
        );
        timeline_limited.create_timeline("one").await.test_ok();
        let err = timeline_limited.create_timeline("two").await.test_err();
        assert!(matches!(
            err,
            GatewayError::TimelineLimitReached { maximum: 1 }
        ));

        let event_limited = Gateway::with_limits(
            open_store(StoreConfig::Memory).test_ok(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = event_limited.create_timeline("events").await.test_ok();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        event_limited
            .append_action(
                &timeline_id,
                &entity_id,
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_ok();
        let err = event_limited
            .append_action(
                &timeline_id,
                &entity_id,
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_err();
        assert!(matches!(
            err,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
        drop(event_limited);
        drop(timeline_limited);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn root_limit_excludes_forks_and_imported_children() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let root = store.create_timeline("root").test_ok();
        store.fork(root.id(), Seq::ZERO, "fork").test_ok();
        let imported_child = TimelineMeta::forked_from(root.id(), Seq::ZERO, "imported-child");
        store.create_timeline_with_meta(imported_child).test_ok();

        let gateway = Gateway::with_limits(
            store,
            GatewayLimits {
                max_timelines: 2,
                max_events_per_timeline: 1,
            },
        );
        gateway.create_timeline("second-root").await.test_ok();
        let error = gateway.create_timeline("third-root").await.test_err();
        assert!(matches!(
            error,
            GatewayError::TimelineLimitReached { maximum: 2 }
        ));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn create_timeline_uses_bounded_root_count_without_listing() {
        let gateway = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::RejectListUse,
        }));
        gateway.create_timeline("root").await.test_ok();
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn child_event_limit_counts_owned_not_inherited_events() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let root = store.create_timeline("root").test_ok();
        let root_draft = EventDraft::new(
            EntityId::new(),
            Kind::new(EVENT_TYPE_ACTION),
            json_to_cbor(&serde_json::json!({})),
        );
        store.append(root.id(), &[root_draft]).test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        let gateway = Gateway::with_limits(
            store,
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let child_id = child.id().to_string();
        let entity_id = EntityId::new().to_string();
        gateway
            .append_action(
                &child_id,
                &entity_id,
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_ok();
        let error = gateway
            .append_action(
                &child_id,
                &entity_id,
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
        let page = gateway
            .read_events_page(&child_id, 0, MAX_EVENTS_PER_POLL)
            .await
            .test_ok();
        assert_eq!(page.events.len(), 2);
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn identified_retry_wins_over_event_capacity() {
        let gateway = Gateway::with_limits(
            open_store(StoreConfig::Memory).test_ok(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = gateway.create_timeline("dedup-capacity").await.test_ok();
        let entity = EntityId::new();
        let first = gateway
            .append_identified_action(
                &timeline.id().to_string(),
                &entity.to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
                "device-1:capacity",
            )
            .await
            .test_ok();
        let retry = gateway
            .append_identified_action(
                &timeline.id().to_string(),
                &entity.to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
                "device-1:capacity",
            )
            .await
            .test_ok();
        assert!(retry.duplicate);
        assert_eq!(retry.event.id, first.event.id);
        let error = gateway
            .append_identified_action(
                &timeline.id().to_string(),
                &entity.to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 2}),
                "device-1:new",
            )
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn same_ingress_id_is_scoped_to_entity() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("entity-scope").await.test_ok();
        let timeline_id = timeline.id().to_string();
        let first = gateway
            .append_identified_action(
                &timeline_id,
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
                "device-1:shared",
            )
            .await
            .test_ok();
        let second_entity = EntityId::new().to_string();
        let second = gateway
            .append_identified_action(
                &timeline_id,
                &second_entity,
                EVENT_TYPE_ACTION,
                &serde_json::json!({"value": 1}),
                "device-1:shared",
            )
            .await
            .test_ok();
        assert!(!second.duplicate);
        assert_ne!(first.event.id, second.event.id);
        drop(gateway);
    }

    #[tokio::test]
    async fn identified_admission_covers_bounds_and_maintenance() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("identified-bounds").await.test_ok();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        let payload = serde_json::json!({"data": "x".repeat(MAX_EVENT_PAYLOAD_BYTES)});
        assert!(matches!(
            gateway
                .append_identified_action(
                    &timeline_id,
                    &entity_id,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:oversized",
                )
                .await,
            Err(GatewayError::EventPayloadTooLarge { .. })
        ));
        let high_expansion = serde_json::json!({"data": "\0".repeat(160 * 1024)});
        assert!(matches!(
            gateway
                .append_identified_action(
                    &timeline_id,
                    &entity_id,
                    EVENT_TYPE_ACTION,
                    &high_expansion,
                    "device-1:expanded",
                )
                .await,
            Err(GatewayError::EventResponseTooLarge { .. })
        ));
        assert_eq!(
            gateway
                .purge_expired_ingress_identities(NonZeroUsize::new(1).test_ok())
                .await
                .test_ok()
                .removed,
            0
        );
        assert!(matches!(
            gateway
                .append_identified_action(
                    &timeline_id,
                    &entity_id,
                    "other.event",
                    &serde_json::json!({}),
                    "device-1:unsupported",
                )
                .await,
            Err(GatewayError::UnsupportedAction(_))
        ));
        drop(gateway);
    }

    #[tokio::test]
    async fn identified_admission_fails_closed_for_input_and_append_boundaries() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("identified-errors").await.test_ok();
        let valid_timeline = timeline.id().to_string();
        let valid_entity = EntityId::new().to_string();
        let payload = serde_json::json!({});
        assert!(matches!(
            gateway
                .append_identified_action(
                    "bad",
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:bad-timeline",
                )
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        assert!(matches!(
            gateway
                .append_identified_action(
                    &valid_timeline,
                    "bad",
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:bad-entity",
                )
                .await,
            Err(GatewayError::InvalidId(_))
        ));
        let get_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::FailGetTimeline,
        }));
        assert!(matches!(
            get_error
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:get-error",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        let missing_timeline = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::MissingTimeline,
        }));
        assert!(matches!(
            missing_timeline
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:missing-timeline",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        let append_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::RejectListUse,
        }));
        assert!(matches!(
            append_error
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:append-error",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        drop(append_error);
        drop(gateway);
        drop(get_error);
        drop(missing_timeline);
    }

    #[tokio::test]
    async fn identified_admission_fails_closed_for_purge_and_duplicate_boundaries() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("identified-errors").await.test_ok();
        let valid_timeline = timeline.id().to_string();
        let valid_entity = EntityId::new().to_string();
        let payload = serde_json::json!({});
        let purge_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::RejectListUse,
        }));
        assert!(purge_error
            .purge_expired_ingress_identities(NonZeroUsize::new(1).test_ok())
            .await
            .is_err());
        let duplicate_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::Duplicate,
        }));
        assert!(matches!(
            duplicate_error
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:missing-event",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        let duplicate_read_error = Gateway::new(Box::new(ScriptedStore {
            mode: ScriptMode::DuplicateReadError,
        }));
        assert!(matches!(
            duplicate_read_error
                .append_identified_action(
                    &valid_timeline,
                    &valid_entity,
                    EVENT_TYPE_ACTION,
                    &payload,
                    "device-1:read-error",
                )
                .await,
            Err(GatewayError::Store(_))
        ));
        drop(duplicate_error);
        drop(duplicate_read_error);
        drop(gateway);
        drop(purge_error);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn sqlite_gateway_serializes_concurrent_limit_checks_and_appends() {
        let gateway = Gateway::with_limits(
            open_store(StoreConfig::Sqlite {
                path: ":memory:".to_owned(),
            })
            .test_ok(),
            GatewayLimits {
                max_timelines: 1,
                max_events_per_timeline: 1,
            },
        );
        let timeline = gateway.create_timeline("sqlite").await.test_ok();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        let first = gateway.clone();
        let second = gateway.clone();
        let payload_a = serde_json::json!({"writer": "a"});
        let payload_b = serde_json::json!({"writer": "b"});
        let (a, b) = tokio::join!(
            first.append_action(&timeline_id, &entity_id, EVENT_TYPE_ACTION, &payload_a,),
            second.append_action(&timeline_id, &entity_id, EVENT_TYPE_ACTION, &payload_b,)
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        let rejected = if let Err(error) = a {
            error
        } else {
            b.test_err()
        };
        assert!(matches!(
            rejected,
            GatewayError::EventLimitReached { maximum: 1 }
        ));
        let page = gateway
            .read_events_page(&timeline_id, 0, MAX_EVENTS_PER_POLL)
            .await
            .test_ok();
        assert_eq!(page.events.len(), 1);
        drop(first);
        drop(gateway);
        drop(second);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn sqlite_gateways_enforce_one_atomic_event_ceiling() {
        let database = TemporarySqliteFile::new("atomic-ceiling");
        let path = database.path.clone();
        let mut seed = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        let timeline = seed.create_timeline("sqlite").test_ok();
        let entity = EntityId::new();
        let prefill = EventDraft::new(
            entity,
            Kind::new(EVENT_TYPE_ACTION),
            json_to_cbor(&serde_json::json!({"writer": "prefill"})),
        );
        seed.append(
            timeline.id(),
            &vec![prefill; usize::try_from(MAX_EVENTS_PER_TIMELINE - 1).test_ok()],
        )
        .test_ok();
        drop(seed);

        let first = Gateway::new(open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok());
        let second = Gateway::new(open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok());
        let timeline_id = timeline.id().to_string();
        let entity_id = entity.to_string();
        let payload_a = serde_json::json!({"writer": "a"});
        let payload_b = serde_json::json!({"writer": "b"});
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let first_task = {
            let barrier = Arc::clone(&barrier);
            let timeline_id = timeline_id.clone();
            let entity_id = entity_id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                first
                    .append_action(&timeline_id, &entity_id, EVENT_TYPE_ACTION, &payload_a)
                    .await
            })
        };
        let second_task = {
            let barrier = Arc::clone(&barrier);
            let timeline_id = timeline_id.clone();
            let entity_id = entity_id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                second
                    .append_action(&timeline_id, &entity_id, EVENT_TYPE_ACTION, &payload_b)
                    .await
            })
        };
        barrier.wait().await;
        let (a, b) = tokio::join!(first_task, second_task);
        let a = a.test_ok();
        let b = b.test_ok();
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        let rejected = if let Err(error) = a {
            error
        } else {
            b.test_err()
        };
        assert!(matches!(
            rejected,
            GatewayError::EventLimitReached {
                maximum: MAX_EVENTS_PER_TIMELINE
            }
        ));
        let fresh = open_store(StoreConfig::Sqlite { path: path.clone() }).test_ok();
        assert_eq!(
            fresh.get_timeline(timeline.id()).test_ok().test_ok().head,
            Seq::from_u64(MAX_EVENTS_PER_TIMELINE)
        );
        assert_eq!(
            fresh
                .read_own(timeline.id(), SeqRange::all())
                .test_ok()
                .len(),
            usize::try_from(MAX_EVENTS_PER_TIMELINE).test_ok()
        );
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn sqlite_bounded_reads_page_forks_and_reject_external_oversize() {
        let mut store = open_store(StoreConfig::Sqlite {
            path: ":memory:".to_owned(),
        })
        .test_ok();
        let root = store.create_timeline("root").test_ok();
        let small = EventDraft::new(
            EntityId::new(),
            Kind::new(EVENT_TYPE_ACTION),
            json_to_cbor(&serde_json::json!({})),
        );
        store
            .append(root.id(), std::slice::from_ref(&small))
            .test_ok();
        let child = store.fork(root.id(), Seq::from_u64(1), "child").test_ok();
        store
            .append(child.id(), std::slice::from_ref(&small))
            .test_ok();
        let gateway = Gateway::new(store);

        let first = gateway
            .read_events_page(&child.id().to_string(), 1, 1)
            .await
            .test_ok();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].seq.as_u64(), 1);
        assert_eq!(first.next_from_seq, Some(Seq::from_u64(2)));
        let beyond_head = gateway
            .read_events_page(&child.id().to_string(), 3, 1)
            .await
            .test_ok();
        assert!(beyond_head.events.is_empty());

        let mut external = open_store(StoreConfig::Sqlite {
            path: ":memory:".to_owned(),
        })
        .test_ok();
        let timeline = external.create_timeline("external").test_ok();
        let oversized = EventDraft::new(
            EntityId::new(),
            Kind::new("external.event"),
            CanonicalBytes::from_vec(vec![0; MAX_EVENT_PAYLOAD_BYTES + 1]),
        );
        external.append(timeline.id(), &[oversized]).test_ok();
        let error = Gateway::new(external)
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::EventPayloadTooLarge {
                maximum: MAX_EVENT_PAYLOAD_BYTES
            }
        ));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn imported_oversized_event_type_returns_actionable_413_on_bundled_stores() {
        let mut source = open_store(StoreConfig::Memory).test_ok();
        let timeline = source.create_timeline("import-source").test_ok();
        source
            .append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("x".repeat(MAX_EVENT_TYPE_BYTES + 1)),
                    CanonicalBytes::from_static(b"x"),
                )],
            )
            .unwrap_or_else(|error| {
                std::panic::panic_any(format!("source oversized append failed: {error:?}"))
            });
        let export = export_timeline_own(source.as_ref(), timeline.id()).unwrap_or_else(|error| {
            std::panic::panic_any(format!("oversized export failed: {error:?}"))
        });

        let destinations = [
            open_store(StoreConfig::Memory).test_ok(),
            open_store(StoreConfig::Sqlite {
                path: ":memory:".to_owned(),
            })
            .test_ok(),
        ];
        for (destination_index, mut destination) in destinations.into_iter().enumerate() {
            import_timeline_with_id(destination.as_mut(), export.clone()).unwrap_or_else(|error| {
                std::panic::panic_any(format!(
                    "destination {destination_index} oversized import failed: {error:?}"
                ))
            });
            let result = Gateway::new(destination)
                .read_events_page(&timeline.id().to_string(), 0, 1)
                .await;
            let error = match result {
                Ok(_) => std::panic::panic_any(format!(
                    "destination {destination_index} unexpectedly read oversized event"
                )),
                Err(error) => error,
            };
            assert!(
                matches!(
                    error,
                    GatewayError::EventMetadataTooLarge {
                        field: "event_type",
                        maximum: MAX_EVENT_TYPE_BYTES
                    }
                ),
                "destination {destination_index} returned unexpected imported oversized-event error: {error:?}"
            );
        }
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn imported_deep_fork_returns_actionable_413() {
        let mut source = open_store(StoreConfig::Memory).test_ok();
        let root = source.create_timeline("root").test_ok();
        let mut timelines = vec![root];
        for depth in 1..=MAX_FORK_DEPTH + 1 {
            let parent = timelines.last().test_ok();
            let child = source
                .fork(parent.id(), Seq::ZERO, &format!("depth-{depth}"))
                .test_ok();
            timelines.push(child);
        }

        let mut destination = open_store(StoreConfig::Memory).test_ok();
        for timeline in &timelines {
            let export = export_timeline_own(source.as_ref(), timeline.id()).test_ok();
            import_timeline_with_id(destination.as_mut(), export).test_ok();
        }
        let deepest = timelines.last().test_ok();
        let response = GatewayError::ForkDepthTooLarge {
            maximum: MAX_FORK_DEPTH,
        }
        .to_string();
        let error = Gateway::new(destination)
            .read_events_page(&deepest.id().to_string(), 0, 1)
            .await
            .test_err();

        assert_eq!(error.to_string(), response);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn gateway_rejects_payloads_that_cannot_fit_bounded_responses() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("payload").await.test_ok();
        let payload = serde_json::json!({"data": "x".repeat(MAX_EVENT_PAYLOAD_BYTES)});
        let error = gateway
            .append_action(
                &timeline.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &payload,
            )
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::EventPayloadTooLarge {
                maximum: MAX_EVENT_PAYLOAD_BYTES
            }
        ));

        let high_expansion = serde_json::json!({"data": "\0".repeat(160 * 1024)});
        let error = gateway
            .append_action(
                &timeline.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &high_expansion,
            )
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::EventResponseTooLarge {
                maximum: MAX_EVENTS_RESPONSE_BYTES
            }
        ));

        let retrievable = serde_json::json!({"data": "x".repeat(240 * 1024)});
        gateway
            .append_action(
                &timeline.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &retrievable,
            )
            .await
            .test_ok();
        let page = gateway
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .test_ok();
        let response = serde_json::json!({
            "events": page
                .events
                .iter()
                .map(|event| EventView::try_from(event).test_ok())
                .collect::<Vec<_>>(),
            "next_from_seq": page.next_from_seq,
        });
        assert!(serde_json::to_vec(&response).test_ok().len() <= MAX_EVENTS_RESPONSE_BYTES);
        drop(gateway);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn event_type_bound_reserves_space_for_maximum_payload_hex() {
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("\0".repeat(MAX_EVENT_TYPE_BYTES)),
            CanonicalBytes::from_vec(vec![0xff; MAX_EVENT_PAYLOAD_BYTES]),
        );
        assert!(draft_event_response_len(&draft) <= MAX_EVENTS_RESPONSE_BYTES);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn admission_budgets_the_exact_worst_case_cursor_boundary() {
        let entity = EntityId::new();
        let mut boundary = None;
        for length in (MAX_EVENTS_RESPONSE_BYTES / 8 - 128)..=(MAX_EVENTS_RESPONSE_BYTES / 8) {
            let payload = serde_json::json!({"data": "\0".repeat(length)});
            let draft =
                EventDraft::new(entity, Kind::new(EVENT_TYPE_ACTION), json_to_cbor(&payload));
            let view = EventView {
                id: "0".repeat(26),
                entity: entity.to_string(),
                event_type: EVENT_TYPE_ACTION.to_owned(),
                seq: u64::MAX,
                payload: decode_cbor_json(draft.payload.as_slice()),
                payload_hex: hex_encode(draft.payload.as_slice()),
            };
            let null_cursor_len = serde_json::to_vec(&serde_json::json!({
                "events": [view],
                "next_from_seq": null,
            }))
            .test_ok()
            .len();
            let worst_cursor_len = draft_event_response_len(&draft);
            if null_cursor_len <= MAX_EVENTS_RESPONSE_BYTES
                && worst_cursor_len > MAX_EVENTS_RESPONSE_BYTES
            {
                boundary = Some(payload);
                break;
            }
        }
        let payload = boundary.test_ok();
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("cursor-boundary").await.test_ok();
        let error = gateway
            .append_action(
                &timeline.id().to_string(),
                &entity.to_string(),
                EVENT_TYPE_ACTION,
                &payload,
            )
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::EventResponseTooLarge {
                maximum: MAX_EVENTS_RESPONSE_BYTES
            }
        ));
        drop(gateway);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn events_query_remains_deserializable_for_library_callers() {
        let query: EventsQuery =
            serde_json::from_value(serde_json::json!({"from_seq": 7, "limit": 8})).test_ok();
        assert_eq!(
            query,
            EventsQuery {
                from_seq: 7,
                limit: 8
            }
        );
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn event_page_rejects_zero_limit() {
        let gw = memory_gw();
        let timeline = gw.create_timeline("zero").await.test_ok();
        let err = gw
            .read_events_page(&timeline.id().to_string(), 0, 0)
            .await
            .test_err();
        assert!(matches!(
            err,
            GatewayError::InvalidPageLimit {
                maximum: MAX_EVENTS_PER_POLL
            }
        ));
        drop(gw);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn empty_event_page_has_no_cursor() {
        let gw = memory_gw();
        let timeline = gw.create_timeline("empty").await.test_ok();
        let page = gw
            .read_events_page(&timeline.id().to_string(), 0, 1)
            .await
            .test_ok();
        assert!(page.events.is_empty());
        assert_eq!(page.next_from_seq, None);
        drop(gw);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn event_page_cursor_is_first_omitted_sequence_and_none_at_exhaustion() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("cursor").await.test_ok();
        let timeline_id = timeline.id().to_string();
        let entity_id = EntityId::new().to_string();
        for value in 0..2 {
            gateway
                .append_action(
                    &timeline_id,
                    &entity_id,
                    EVENT_TYPE_ACTION,
                    &serde_json::json!({ "value": value }),
                )
                .await
                .test_ok();
        }
        let first = gateway.read_events_page(&timeline_id, 0, 1).await.test_ok();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.next_from_seq, Some(Seq::from_u64(2)));
        let exhausted = gateway.read_events_page(&timeline_id, 2, 1).await.test_ok();
        assert_eq!(exhausted.events.len(), 1);
        assert_eq!(exhausted.next_from_seq, None);
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[allow(deprecated)]
    async fn public_page_api_and_compatibility_shim_remain_bounded() {
        let gateway = memory_gw();
        let timeline = gateway.create_timeline("public-api").await.test_ok();
        let drafts: Vec<_> = (0..=MAX_EVENTS_PER_POLL)
            .map(|_| {
                EventDraft::new(
                    EntityId::new(),
                    Kind::new(EVENT_TYPE_ACTION),
                    json_to_cbor(&serde_json::json!({})),
                )
            })
            .collect();
        {
            gateway
                .store
                .append(timeline.id(), drafts, None)
                .await
                .test_ok();
        }
        let page: EventPage = gateway
            .read_events_page(&timeline.id().to_string(), 0, MAX_EVENTS_PER_POLL)
            .await
            .test_ok();
        assert_eq!(page.events.len(), MAX_EVENTS_PER_POLL);
        assert_eq!(page.next_from_seq, Some(Seq::from_u64(101)));
        let error = gateway
            .read_events_from(&timeline.id().to_string(), 0)
            .await
            .test_err();
        assert!(matches!(
            error,
            GatewayError::CompatibilityReadTruncated {
                maximum: MAX_EVENTS_PER_POLL
            }
        ));
        let final_event = gateway
            .read_events_from(&timeline.id().to_string(), 101)
            .await
            .test_ok();
        assert_eq!(final_event.len(), 1);
        let invalid = gateway.read_events_from("bad", 0).await.test_err();
        assert!(matches!(invalid, GatewayError::InvalidId(_)));
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fork_with_more_than_ten_thousand_logical_events_pages_to_exhaustion() {
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let root = store.create_timeline("root").test_ok();
        let drafts: Vec<_> = (0..MAX_EVENTS_PER_TIMELINE)
            .map(|_| {
                EventDraft::new(
                    EntityId::new(),
                    Kind::new(EVENT_TYPE_ACTION),
                    json_to_cbor(&serde_json::json!({})),
                )
            })
            .collect();
        store.append(root.id(), &drafts).test_ok();
        let child = store
            .fork(root.id(), Seq::from_u64(10_000), "child")
            .test_ok();
        let gateway = Gateway::new(store);
        gateway
            .append_action(
                &child.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_ok();

        let mut from_seq = 0;
        let mut count = 0;
        loop {
            let page = gateway
                .read_events_page(&child.id().to_string(), from_seq, MAX_EVENTS_PER_POLL)
                .await
                .test_ok();
            count += page.events.len();
            match page.next_from_seq {
                Some(next) => from_seq = next.as_u64(),
                None => break,
            }
        }
        assert_eq!(count, 10_001);
        drop(gateway);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn append_action_rejects_other_types() {
        let gw = memory_gw();
        let tl = gw.create_timeline("demo").await.test_ok();
        let err = gw
            .append_action(
                &tl.id().to_string(),
                &EntityId::new().to_string(),
                "world.observation",
                &serde_json::json!({}),
            )
            .await
            .test_err();
        assert!(matches!(err, GatewayError::UnsupportedAction(_)));
        drop(gw);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn append_signal_and_bus_notice() {
        let gw = memory_gw();
        let mut rx = gw.subscribe();
        let tl = gw.create_timeline("society").await.test_ok();
        let signal = SocietySignal {
            dimension: SocietyDimension::Trust,
            value: 0.8,
            subject: None,
            object: None,
        };
        let event = gw
            .append_signal(&tl.id().to_string(), &EntityId::new().to_string(), &signal)
            .await
            .test_ok();
        let notice = rx.try_recv().test_ok();
        assert_eq!(notice.event_id, event.id.to_string());
        assert_eq!(notice.event_type, EVENT_TYPE_SIGNAL);
        drop(gw);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn invalid_ids_error() {
        let gw = memory_gw();
        let err = gw.read_events_page("not-a-ulid", 0, 1).await.test_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        let err = gw
            .append_action(
                "not-a-ulid",
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        let tl = gw.create_timeline("ids").await.test_ok();
        let err = gw
            .append_action(
                &tl.id().to_string(),
                "not-a-ulid",
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        let err = gw
            .append_signal(
                &tl.id().to_string(),
                "not-a-ulid",
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 0.1,
                    subject: None,
                    object: None,
                },
            )
            .await
            .test_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        let err = gw
            .append_signal(
                "not-a-ulid",
                &EntityId::new().to_string(),
                &SocietySignal {
                    dimension: SocietyDimension::Trust,
                    value: 0.1,
                    subject: None,
                    object: None,
                },
            )
            .await
            .test_err();
        assert!(matches!(err, GatewayError::InvalidId(_)));
        drop(gw);
    }

    #[test]
    fn accepted_coordinate_validation_reports_missing_metadata() {
        assert!(matches!(
            checked_event_coordinates(None, Some(Seq::from_u64(1))),
            Err(GatewayError::Store(CoreError::Storage(_)))
        ));
        assert!(matches!(
            checked_event_coordinates(Some(EventId::new()), None),
            Err(GatewayError::Store(CoreError::Storage(_)))
        ));

        let accepted = GeoLocationAdmissionOutcome::accepted(EventId::new(), Seq::from_u64(1));
        assert!(matches!(
            classify_owntracks_admission(&accepted),
            Ok(OwnTracksIngressResult::Accepted)
        ));
        let retained = GeoLocationAdmissionIntentV1::from_owner_keyed_bytes([1; 32]);
        let duplicate = GeoLocationAdmissionOutcome::classify_retained_intent(
            retained,
            retained,
            EventId::new(),
        );
        assert!(matches!(
            classify_owntracks_admission(&duplicate),
            Ok(OwnTracksIngressResult::Duplicate)
        ));
        let conflict = GeoLocationAdmissionOutcome::classify_retained_intent(
            retained,
            GeoLocationAdmissionIntentV1::from_owner_keyed_bytes([2; 32]),
            EventId::new(),
        );
        assert!(matches!(
            classify_owntracks_admission(&conflict),
            Ok(OwnTracksIngressResult::Conflict)
        ));
        assert!(matches!(
            classify_owntracks_admission(&GeoLocationAdmissionOutcome::unavailable()),
            Ok(OwnTracksIngressResult::Unavailable)
        ));
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn store_error_paths_create_and_list() {
        let fail_create = Gateway {
            store: executor::StoreExecutor::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailCreate,
            })),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority: ConsentAuthority::new(),
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        };
        assert!(matches!(
            fail_create.create_timeline("x").await,
            Err(GatewayError::Store(_))
        ));

        let fail_list = Gateway {
            store: executor::StoreExecutor::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailList,
            })),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority: ConsentAuthority::new(),
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        };
        assert!(matches!(
            fail_list.create_timeline("x").await,
            Err(GatewayError::Store(_))
        ));
        drop(fail_create);
        drop(fail_list);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn store_error_paths_append_and_read() {
        let empty_append = Gateway {
            store: executor::StoreExecutor::new(Box::new(ScriptedStore {
                mode: ScriptMode::EmptyAppend,
            })),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority: ConsentAuthority::new(),
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        };
        let tl = empty_append.create_timeline("e").await.test_ok();
        let err = empty_append
            .append_action(
                &tl.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_err();
        assert!(matches!(err, GatewayError::Store(_)));

        let fail_get_timeline = Gateway {
            store: executor::StoreExecutor::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailGetTimeline,
            })),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority: ConsentAuthority::new(),
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        };
        let err = fail_get_timeline
            .append_action(
                &TimelineId::new().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_err();
        assert!(matches!(err, GatewayError::Store(_)));

        let fail_append = Gateway {
            store: executor::StoreExecutor::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailAppend,
            })),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority: ConsentAuthority::new(),
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        };
        let tl = fail_append.create_timeline("a").await.test_ok();
        let err = fail_append
            .append_action(
                &tl.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({}),
            )
            .await
            .test_err();
        assert!(matches!(err, GatewayError::Store(_)));

        let fail_read = Gateway {
            store: executor::StoreExecutor::new(Box::new(ScriptedStore {
                mode: ScriptMode::FailRead,
            })),
            bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
            limits: GatewayLimits::LOCAL_DEFAULT,
            owntracks_enabled: false,
            consent_authority: ConsentAuthority::new(),
            consent_history_locks: new_consent_history_locks(),
            pending_consent_cleanup: new_pending_consent_cleanup(),
            action_registry: gateway_action_registry(),
            action_principal: None,
        };
        let err = fail_read
            .read_events_page(&TimelineId::new().to_string(), 0, 1)
            .await
            .test_err();
        assert!(matches!(err, GatewayError::Store(_)));
        drop(empty_append);
        drop(fail_append);
        drop(fail_get_timeline);
        drop(fail_read);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn read_error_boundaries_map_to_bounded_gateway_errors() {
        let cases = [
            (
                ScriptMode::ReadPayloadTooLarge,
                GatewayError::EventPayloadTooLarge {
                    maximum: MAX_EVENT_PAYLOAD_BYTES,
                },
            ),
            (
                ScriptMode::ReadMetadataTooLarge,
                GatewayError::EventMetadataTooLarge {
                    field: "event_type",
                    maximum: MAX_EVENT_TYPE_BYTES,
                },
            ),
            (
                ScriptMode::ReadForkDepthTooLarge,
                GatewayError::ForkDepthTooLarge {
                    maximum: MAX_FORK_DEPTH,
                },
            ),
            (
                ScriptMode::ReadBytesTooLarge,
                GatewayError::EventResponseTooLarge {
                    maximum: MAX_EVENTS_RESPONSE_BYTES,
                },
            ),
            (
                ScriptMode::ReadTimeTooLarge,
                GatewayError::EventReadTimeExceeded {
                    maximum_micros: MAX_EVENTS_READ_TIME_MICROS,
                },
            ),
        ];
        for (mode, expected) in cases {
            let gateway = Gateway {
                store: executor::StoreExecutor::new(Box::new(ScriptedStore { mode })),
                bus: broadcast::channel(EVENT_BUS_CAPACITY).0,
                limits: GatewayLimits::LOCAL_DEFAULT,
                owntracks_enabled: false,
                consent_authority: ConsentAuthority::new(),
                consent_history_locks: new_consent_history_locks(),
                pending_consent_cleanup: new_pending_consent_cleanup(),
                action_registry: gateway_action_registry(),
                action_principal: None,
            };
            let error = gateway
                .read_events_page(&TimelineId::new().to_string(), 0, 1)
                .await
                .test_err();
            assert_eq!(error.to_string(), expected.to_string());
            drop(gateway);
        }
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn event_view_and_hex() {
        let gw = memory_gw();
        let tl = gw.create_timeline("x").await.test_ok();
        let event = gw
            .append_action(
                &tl.id().to_string(),
                &EntityId::new().to_string(),
                EVENT_TYPE_ACTION,
                &serde_json::json!({"k": "v"}),
            )
            .await
            .test_ok();
        let view = EventView::try_from(&event).test_ok();
        assert_eq!(view.event_type, EVENT_TYPE_ACTION);
        assert!(!view.payload_hex.is_empty());
        assert_eq!(view.payload, Some(serde_json::json!({"k": "v"})));
        assert_eq!(hex_encode(&[0x0a, 0xfb]), "0afb");

        let mut geographic = event;
        geographic.event_type = Kind::new(pos_core::GEOGRAPHIC_EVENT_TYPE);
        let error = EventView::try_from(&geographic).test_err();
        assert!(error.to_string().contains("not found"));
        let mut consent = geographic;
        consent.event_type = Kind::new(EVENT_TYPE_CONSENT_GRANTED_V1);
        assert!(matches!(
            EventView::try_from(&consent),
            Err(GatewayError::ResourceUnavailable)
        ));
        drop(gw);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn decode_cbor_json_roundtrip() {
        let value = serde_json::json!({"n": 1});
        let bytes = json_to_cbor(&value);
        assert_eq!(decode_cbor_json(bytes.as_slice()), Some(value));
        assert!(decode_cbor_json(&[0xff]).is_none());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn signal_request_into_signal() {
        let req = SignalRequest {
            entity_id: EntityId::new().to_string(),
            dimension: SocietyDimension::Opinion,
            value: 0.5,
            subject: Some("a".into()),
            object: None,
        };
        let signal = req.into_signal();
        assert_eq!(signal.dimension, SocietyDimension::Opinion);
        assert!((signal.value - 0.5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn subscribe_lag_signals_resync() {
        use tokio::sync::broadcast::error::TryRecvError;

        let gw = Gateway::with_bus_capacity(open_store(StoreConfig::Memory).test_ok(), 2);
        let mut rx = gw.subscribe();
        let tl = gw.create_timeline("lag").await.test_ok();
        let entity = EntityId::new().to_string();
        let id = tl.id().to_string();
        for _ in 0..3 {
            gw.append_action(&id, &entity, EVENT_TYPE_ACTION, &serde_json::json!({}))
                .await
                .test_ok();
        }
        assert!(matches!(
            rx.try_recv(),
            Ok(_) | Err(TryRecvError::Lagged(_))
        ));
        drop(gw);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn gateway_error_display() {
        let e = GatewayError::UnsupportedAction("x".into());
        assert!(e.to_string().contains("unsupported"));
        let e = GatewayError::InvalidId("bad".into());
        assert!(e.to_string().contains("invalid"));
        let e = GatewayError::InvalidPageLimit {
            maximum: MAX_EVENTS_PER_POLL,
        };
        assert!(e.to_string().contains("between"));
        let e = GatewayError::CompatibilityReadTruncated {
            maximum: MAX_EVENTS_PER_POLL,
        };
        assert!(e.to_string().contains("compatibility"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn executor_lifecycle_errors_map_to_gateway_errors() {
        assert!(matches!(
            GatewayError::from(executor::StoreExecutorError::DeadlineExceeded),
            GatewayError::StoreExecutorDeadlineExceeded
        ));
        assert!(matches!(
            GatewayError::from(executor::StoreExecutorError::Unhealthy),
            GatewayError::StoreExecutorUnhealthy
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ingress_identity_is_domain_separated_and_namespaced() {
        let timeline = TimelineId::new();
        let entity = EntityId::new();
        let same = ingress_identity(timeline, entity, "device-1:42");
        assert_eq!(same, ingress_identity(timeline, entity, "device-1:42"));
        assert_ne!(
            same.dedup_key,
            ingress_identity(timeline, entity, "device-1:43").dedup_key
        );
        assert_ne!(
            same.dedup_key,
            ingress_identity(TimelineId::new(), entity, "device-1:42").dedup_key
        );
        assert_ne!(
            same.scope,
            ingress_identity(timeline, EntityId::new(), "device-1:42").scope
        );
        assert_ne!(same.dedup_key.as_bytes(), same.scope.as_bytes());
    }

    #[tokio::test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn submit_proposed_action_approves_and_rejects() {
        let actor = EntityId::new();
        let body = EntityId::new();
        let gw = Gateway::new_with_world_bodies_and_principal(
            open_store(StoreConfig::Memory).test_ok(),
            [body],
            ActionPrincipal::new(actor, [Kind::new("world.action.submit")]),
        );
        let tl = gw.create_timeline("actions").await.test_ok();
        let action = pos_plugin_world::WorldAction {
            actor_entity_id: actor,
            body_entity_id: body,
            action_kind: "impulse".to_owned(),
            params: vec![1, 2, 3],
            action_scope: 0,
            catalogue_version: 1,
            tick: 1,
        };
        let mut payload = Vec::new();
        ciborium::into_writer(&action, &mut payload).test_ok();

        // Valid proposal
        let valid = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            actor,
            CanonicalBytes::from_vec(payload.clone()),
            Kind::new("world.action.submit"),
        );
        let event = gw
            .submit_proposed_action(&tl.id().to_string(), valid)
            .await
            .test_ok();
        assert_eq!(event.entity, actor);
        assert_eq!(event.event_type.as_str(), EVENT_TYPE_ACTION);

        // Capability mismatch
        let bad_cap = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            actor,
            CanonicalBytes::from_vec(b"ok".to_vec()),
            Kind::new("wrong.capability"),
        );
        let err = gw
            .submit_proposed_action(&tl.id().to_string(), bad_cap)
            .await
            .test_err();
        assert!(err.to_string().contains("capability not granted"));

        // Approver rejection
        let invalid = ProposedAction::new(
            Kind::new(EVENT_TYPE_ACTION),
            actor,
            CanonicalBytes::from_vec(vec![0xff]),
            Kind::new("world.action.submit"),
        );
        let err = gw
            .submit_proposed_action(&tl.id().to_string(), invalid)
            .await
            .test_err();
        assert!(err.to_string().contains("malformed world.action payload"));
        drop(gw);
    }
}

#[cfg(test)]
mod coverage_entrypoints {
    use super::*;

    #[test]
    fn action_registry_entrypoint_builds_the_gateway_registry() {
        assert_eq!(gateway_action_registry().driver_count(), 0);
    }
}
