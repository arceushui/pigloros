//! Public request, receipt, and failures for recipient-export publication.

use pos_core::{
    ConsentCapabilityToken, ConsentError, CoreError, ErasureReferenceV1, Hash, KeyRegistryErrorV1,
    RecipientKeyDescriptorV1, ReplayClaimEvaluationV1, Seq, TimelineId,
};
use pos_crypto::recipient_export::RecipientExportErrorV1;
use thiserror::Error;

/// One host-authorized request to publish an encrypted Timeline export.
///
/// The caller supplies the opaque host-issued consent capability and the
/// already-evaluated ADR-060 export authority. The `SQLite` host rechecks both
/// while it holds the protected publication boundary.
pub struct RecipientExportRequestV1<'a> {
    /// Exact subject-owned Timeline to export.
    pub timeline_id: TimelineId,
    /// Exact active RKP1 descriptor selected for the consent grantee.
    pub recipient: RecipientKeyDescriptorV1,
    /// Registered ADR-060 export artifact whose claim authorizes this read.
    pub artifact_digest: ErasureReferenceV1,
    /// Current evaluation of the registered export artifact.
    pub evaluation: &'a ReplayClaimEvaluationV1,
    /// Host-issued consent capability for the subject and recipient grantee.
    pub token: &'a ConsentCapabilityToken,
    /// Host-supplied current Unix time used for capability expiry validation.
    pub now_secs: u64,
}

/// Durable catalog metadata for one published encrypted recipient export.
///
/// The ciphertext itself remains in the owner-bound private directory. The
/// catalog row is the sole publication marker and this receipt contains no
/// plaintext or private material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedRecipientExportV1 {
    /// Fresh identifier that names this immutable export object.
    pub export_id: [u8; 16],
    /// Exact recipient descriptor bound to the ciphertext.
    pub recipient: RecipientKeyDescriptorV1,
    /// Source Timeline recorded by the catalog.
    pub timeline_id: TimelineId,
    /// Local Timeline head encoded in the authenticated TRX1 header.
    pub local_head: Seq,
    /// Logical Timeline head observed under the publication gate.
    pub logical_head: Seq,
    /// Number of stored TRX1 ciphertext bytes.
    pub ciphertext_length: u64,
    /// BLAKE3 digest of the complete stored TRX1 ciphertext bytes.
    pub ciphertext_digest: Hash,
}

/// Closed outcomes from durable recipient-export publication and retrieval.
#[derive(Debug, Error)]
pub enum RecipientExportPublicationErrorV1 {
    /// The host-issued consent capability was absent, expired, revoked, or
    /// did not permit export.
    #[error(transparent)]
    Consent(#[from] ConsentError),
    /// The exact recipient identity was not bound to the consent grantee and
    /// private owner directory.
    #[error("recipient export recipient does not match the consent grantee")]
    RecipientMismatch,
    /// The exact active recipient descriptor did not resolve to safe private
    /// material owned by the local adapter.
    #[error("recipient export private material is unavailable")]
    MaterialUnavailable,
    /// The protected Timeline changed after the consent fence was checked.
    #[error("recipient export Timeline changed before publication")]
    SourceChanged,
    /// A fresh random export ID already names an immutable catalog object.
    #[error("recipient export ID collision")]
    IdentifierCollision,
    /// Recovery completed one bounded batch and must be retried before a new
    /// publication can reserve an object name.
    #[error("recipient export recovery requires another pass")]
    RecoveryIncomplete,
    /// The active role-4 registry identity denied publication.
    #[error(transparent)]
    Registry(#[from] KeyRegistryErrorV1),
    /// TEP1/TRX1 serialization, identity binding, or HPKE failed.
    #[error(transparent)]
    Export(#[from] RecipientExportErrorV1),
    /// The immutable ciphertext object or its catalog binding is unavailable.
    #[error("recipient export artifact is unavailable")]
    ArtifactUnavailable,
    /// The `SQLite` adapter, durable directory, erasure fence, or catalog failed.
    #[error(transparent)]
    Store(#[from] CoreError),
}

/// Test-only fault stages for the recipient-export host boundary.
///
/// This type is available only with the nondefault test-support feature. It
/// exists so external acceptance tests can exercise the real publication
/// pipeline without exposing a production fault-control surface.
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientExportPublicationTestFaultV1 {
    /// Advance the source Timeline after the initial head observation.
    SourceHeadChanged,
    /// Revoke the capability after the initial head observation.
    ConsentRevoked,
    /// Block the erasure boundary after the initial head observation.
    ErasureBlocked,
    /// Fail while the encrypted staging object is being written.
    StagingWrite,
    /// Fail the staged ciphertext file sync.
    FileSync,
    /// Fail the final ciphertext directory sync.
    DirectorySync,
    /// Abort the catalog visibility transaction at its commit boundary.
    CatalogCommit,
}

/// Exact publication-boundary observations from the test-support adapter seam.
///
/// The host reader remains the production visibility authority; this fixture
/// exists only to prove interrupted tests leave no partial visible object,
/// that its sole named-object writer receives ciphertext, and that recovery
/// removes non-serving ciphertext objects.
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipientExportPublicationTestArtifactsV1 {
    /// Whether the exact encrypted staging object exists.
    pub staging_ciphertext_exists: bool,
    /// Whether the exact encrypted final object exists.
    pub final_ciphertext_exists: bool,
    /// Whether the sole named-object writer observed bytes that were not a
    /// structurally valid encrypted TRX1 envelope.
    pub named_plaintext_observed: bool,
}
