//! The ELP1 policy compiled into this binary (ADR-136 §4; owner decisions
//! of 2026-11-15 and 2026-11-16 on #1403).
//!
//! Composition requires an installed bundle to name exactly this policy, so
//! a changed constant here is a new `CA(ELP1)` and needs a re-issued bundle.

use pos_core::{
    ArtifactDataClassV1, ErasureArtifactClassV1, ErasureInventoryCategoryV1, ErasureReferenceV1,
    LocalErasureClassificationV1, LocalErasurePolicyV1,
};

use ArtifactDataClassV1::{ConsentedSharedData as Consented, PrivateSubjectData as Private};
use ErasureArtifactClassV1::{
    CalibrationReport, CausalTrace, ConformanceReport, Export, ForkOrSnapshot, ReproManifest,
    TimelineReplay,
};
use ErasureInventoryCategoryV1::{Artifact, Backup, Key, Replica};

/// Automatic retries of a transient owner result.
pub const LOCAL_ERASURE_AUTO_RETRY_MAX_V1: u64 = 3;

/// The lifetime attempt quota of one request.
pub const LOCAL_ERASURE_QUOTA_ATTEMPTS_V1: u64 = 64;

/// Request heads reserved store-wide for administrative resolution and
/// corrected submission.
pub const LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1: u64 = 512;

/// Re-prepares of one lifecycle step before the driver defers it.
pub const LOCAL_ERASURE_MAX_REPREPARE_V1: u64 = 3;

/// One ELP1 classification row: `[artifact_class, data_class, category,
/// ack_class]`.
pub type LocalErasureClassificationRowV1 = (
    ErasureArtifactClassV1,
    ArtifactDataClassV1,
    ErasureInventoryCategoryV1,
    &'static str,
);

/// The ARD1-sourced rows: each of the seven artifact classes, for each of
/// the two destruction-eligible data classes, has its Artifact owner row
/// and its role-7 Key and Backup rows.
const ARD1_ROWS: usize = 7 * 2 * 3;

/// The rows of the other sources: `client-cache-signal` and `local-replica`
/// for both data classes, `timeline-payload` for private data, and
/// `export-recipient` for consented exports.
const SOURCE_ROWS: usize = 2 * 2 + 1 + 1;

/// The number of ELP1 classification rows.
pub const LOCAL_ERASURE_CLASSIFICATION_COUNT_V1: usize = ARD1_ROWS + SOURCE_ROWS;

const _: () = assert!(LOCAL_ERASURE_CLASSIFICATION_COUNT_V1 <= 256);

/// The ELP1 classification permit set, in canonical order (owner decisions
/// D1-a to D5 of 2026-11-16 on #1403).
///
/// A target is an obligation only when its exact row is here. Non-ARD1
/// Timeline obligations carry `TimelineReplay`, `export-recipient` carries
/// `Export`, and a role-7 Key or Backup row carries the class of the
/// artifact that depends on the key.
pub const LOCAL_ERASURE_CLASSIFICATION_V1: [LocalErasureClassificationRowV1;
    LOCAL_ERASURE_CLASSIFICATION_COUNT_V1] = [
    (TimelineReplay, Private, Artifact, "artifact-store"),
    (TimelineReplay, Private, Artifact, "client-cache-signal"),
    (TimelineReplay, Private, Artifact, "timeline-payload"),
    (TimelineReplay, Private, Key, "key-registry"),
    (TimelineReplay, Private, Replica, "local-replica"),
    (TimelineReplay, Private, Backup, "local-backup-inventory"),
    (TimelineReplay, Consented, Artifact, "artifact-store"),
    (TimelineReplay, Consented, Artifact, "client-cache-signal"),
    (TimelineReplay, Consented, Key, "key-registry"),
    (TimelineReplay, Consented, Replica, "local-replica"),
    (TimelineReplay, Consented, Backup, "local-backup-inventory"),
    (ReproManifest, Private, Artifact, "artifact-store"),
    (ReproManifest, Private, Key, "key-registry"),
    (ReproManifest, Private, Backup, "local-backup-inventory"),
    (ReproManifest, Consented, Artifact, "artifact-store"),
    (ReproManifest, Consented, Key, "key-registry"),
    (ReproManifest, Consented, Backup, "local-backup-inventory"),
    (CausalTrace, Private, Artifact, "artifact-store"),
    (CausalTrace, Private, Key, "key-registry"),
    (CausalTrace, Private, Backup, "local-backup-inventory"),
    (CausalTrace, Consented, Artifact, "artifact-store"),
    (CausalTrace, Consented, Key, "key-registry"),
    (CausalTrace, Consented, Backup, "local-backup-inventory"),
    (CalibrationReport, Private, Artifact, "managed-report"),
    (CalibrationReport, Private, Key, "key-registry"),
    (CalibrationReport, Private, Backup, "local-backup-inventory"),
    (CalibrationReport, Consented, Artifact, "managed-report"),
    (CalibrationReport, Consented, Key, "key-registry"),
    (
        CalibrationReport,
        Consented,
        Backup,
        "local-backup-inventory",
    ),
    (Export, Private, Artifact, "artifact-store"),
    (Export, Private, Key, "key-registry"),
    (Export, Private, Backup, "local-backup-inventory"),
    (Export, Consented, Artifact, "artifact-store"),
    (Export, Consented, Artifact, "export-recipient"),
    (Export, Consented, Key, "key-registry"),
    (Export, Consented, Backup, "local-backup-inventory"),
    (ForkOrSnapshot, Private, Artifact, "artifact-store"),
    (ForkOrSnapshot, Private, Key, "key-registry"),
    (ForkOrSnapshot, Private, Backup, "local-backup-inventory"),
    (ForkOrSnapshot, Consented, Artifact, "artifact-store"),
    (ForkOrSnapshot, Consented, Key, "key-registry"),
    (ForkOrSnapshot, Consented, Backup, "local-backup-inventory"),
    (ConformanceReport, Private, Artifact, "managed-report"),
    (ConformanceReport, Private, Key, "key-registry"),
    (ConformanceReport, Private, Backup, "local-backup-inventory"),
    (ConformanceReport, Consented, Artifact, "managed-report"),
    (ConformanceReport, Consented, Key, "key-registry"),
    (
        ConformanceReport,
        Consented,
        Backup,
        "local-backup-inventory",
    ),
];

/// `CA(ELP1)` of [`compiled_local_erasure_policy_v1`], the policy digest an
/// installed bundle must name. A public test recomputes it from the policy.
pub const LOCAL_ERASURE_POLICY_REFERENCE_V1: ErasureReferenceV1 =
    ErasureReferenceV1::from_digest(POLICY_DIGEST);

const POLICY_DIGEST: [u8; 32] = [
    0xe1, 0x2e, 0x33, 0xdf, 0xd3, 0x4d, 0xad, 0xe0, 0xfa, 0xf2, 0xce, 0x53, 0x0a, 0x18, 0x72, 0x26,
    0xea, 0xae, 0x15, 0x4b, 0xf1, 0x95, 0xc3, 0xad, 0x9e, 0x30, 0x40, 0x4f, 0x86, 0xb0, 0xb8, 0x3d,
];

/// The ELP1 this binary serves.
///
/// Every class but the two destruction-eligible ones is always retained
/// (ADR-136 §3), and the classification is
/// [`LOCAL_ERASURE_CLASSIFICATION_V1`].
#[must_use]
pub fn compiled_local_erasure_policy_v1() -> LocalErasurePolicyV1 {
    LocalErasurePolicyV1 {
        retained_classes: vec![
            ArtifactDataClassV1::PublicRecord,
            ArtifactDataClassV1::AggregateData,
            ArtifactDataClassV1::StructuralAuditMetadata,
        ],
        classification: LOCAL_ERASURE_CLASSIFICATION_V1
            .iter()
            .map(|&(artifact_class, data_class, category, ack_class)| {
                LocalErasureClassificationV1 {
                    artifact_class: u64::from(artifact_class),
                    data_class,
                    category: u64::from(category),
                    ack_class: ack_class.to_owned(),
                }
            })
            .collect(),
        auto_retry_max: LOCAL_ERASURE_AUTO_RETRY_MAX_V1,
        quota_attempts: LOCAL_ERASURE_QUOTA_ATTEMPTS_V1,
        store_request_reserve: LOCAL_ERASURE_STORE_REQUEST_RESERVE_V1,
        max_reprepare: LOCAL_ERASURE_MAX_REPREPARE_V1,
    }
}
