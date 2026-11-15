//! Gateway-managed user-authored revisions (#304).
//!
//! Preferences and `OptionSpecs` are subject-scoped resources the Gateway
//! stores itself, outside every Timeline. Each resource is a chain of
//! immutable revisions `1, 2, ...`; a new revision names the current head as
//! its parent. One store transaction admits a revision together with its
//! idempotency record and the execution-mode binding it was produced under
//! (ADR-134 §5), so an exact retry returns the original revision and a stale
//! writer commits nothing.
//!
//! The core holds only neutral bytes: the Gateway owns the canonical content
//! encoding and the digest meaning. Erasure physically deletes a revision's
//! row and keeps a payload-free tombstone (kind, resource, revision, subject
//! and digest), so a later read answers `deleted` without reconstructing any
//! protected value. Erasure needs an opaque permit that only the trusted host
//! composition mints through [`GatewayRevisionErasureHostV1`].

use std::num::NonZeroU64;

use crate::{commit_epoch_for_append_v1, EntityId, GatewayModeBindingRecordV1};

/// Largest canonical content of one revision, in bytes.
pub const MAX_GATEWAY_REVISION_CONTENT_BYTES: usize = 65_536;

/// Closed failures of the Gateway revision store port.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GatewayRevisionErrorV1 {
    /// A draft or a persisted revision record is malformed.
    #[error("gateway revision record is invalid")]
    InvalidRecord,
    /// The idempotency key was used before for a different request.
    #[error("gateway revision idempotency key was used for a different request")]
    IdempotencyConflict,
    /// The named parent is not the head of its resource, or a new resource
    /// already exists.
    #[error("gateway revision parent is not the head of its resource")]
    ParentNotHead,
    /// The named parent is unknown, erased or of another subject.
    #[error("gateway revision parent is unavailable")]
    ParentUnavailable,
    /// The writer's execution-mode binding is not the store's.
    #[error("gateway revision writer is not attached to the store's mode binding")]
    ModeBindingStale,
    /// The adapter cannot read or commit the revision.
    #[error("gateway revision store is unavailable")]
    Unavailable,
}

/// The resource family of one revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GatewayRevisionKindV1 {
    /// A Preference revision.
    Preference,
    /// An `OptionSpec` revision.
    OptionSpec,
}

impl GatewayRevisionKindV1 {
    /// The persisted code: 1 Preference, 2 `OptionSpec`.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Preference => 1,
            Self::OptionSpec => 2,
        }
    }

    /// Decode a persisted code.
    ///
    /// # Errors
    /// Returns [`GatewayRevisionErrorV1::InvalidRecord`] for any other code.
    pub const fn from_code(code: u8) -> Result<Self, GatewayRevisionErrorV1> {
        match code {
            1 => Ok(Self::Preference),
            2 => Ok(Self::OptionSpec),
            _ => Err(GatewayRevisionErrorV1::InvalidRecord),
        }
    }
}

/// The identity of one revision: its family, resource and revision number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GatewayRevisionKeyV1 {
    kind: GatewayRevisionKindV1,
    resource_id: [u8; 16],
    revision: NonZeroU64,
}

impl GatewayRevisionKeyV1 {
    /// Revision `revision` of the `kind` resource `resource_id`.
    #[must_use]
    pub const fn new(
        kind: GatewayRevisionKindV1,
        resource_id: [u8; 16],
        revision: NonZeroU64,
    ) -> Self {
        Self {
            kind,
            resource_id,
            revision,
        }
    }

    /// The resource family.
    #[must_use]
    pub const fn kind(&self) -> GatewayRevisionKindV1 {
        self.kind
    }

    /// The 16 resource ID bytes.
    #[must_use]
    pub const fn resource_id(&self) -> [u8; 16] {
        self.resource_id
    }

    /// The revision number.
    #[must_use]
    pub const fn revision(&self) -> NonZeroU64 {
        self.revision
    }
}

/// The payload-free part of a revision that survives its erasure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayRevisionTombstoneV1 {
    key: GatewayRevisionKeyV1,
    subject: EntityId,
    digest: [u8; 32],
}

impl GatewayRevisionTombstoneV1 {
    /// The tombstone of revision `key` of `subject` whose content digest is
    /// `digest`.
    #[must_use]
    pub const fn new(key: GatewayRevisionKeyV1, subject: EntityId, digest: [u8; 32]) -> Self {
        Self {
            key,
            subject,
            digest,
        }
    }

    /// The revision identity.
    #[must_use]
    pub const fn key(&self) -> GatewayRevisionKeyV1 {
        self.key
    }

    /// The subject the revision is scoped to.
    #[must_use]
    pub const fn subject(&self) -> EntityId {
        self.subject
    }

    /// The Gateway's digest of the revision's canonical content.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// One stored revision with its content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRevisionRecordV1 {
    tombstone: GatewayRevisionTombstoneV1,
    principal_id: [u8; 16],
    mode: GatewayModeBindingRecordV1,
    content: Vec<u8>,
}

impl GatewayRevisionRecordV1 {
    /// A stored revision: its tombstone fields, the authoring Principal, the
    /// mode binding it was produced under and its canonical content.
    #[must_use]
    pub const fn new(
        tombstone: GatewayRevisionTombstoneV1,
        principal_id: [u8; 16],
        mode: GatewayModeBindingRecordV1,
        content: Vec<u8>,
    ) -> Self {
        Self {
            tombstone,
            principal_id,
            mode,
            content,
        }
    }

    /// The fields that survive erasure.
    #[must_use]
    pub const fn tombstone(&self) -> &GatewayRevisionTombstoneV1 {
        &self.tombstone
    }

    /// The 16 ID bytes of the Principal that authored the revision.
    #[must_use]
    pub const fn principal_id(&self) -> [u8; 16] {
        self.principal_id
    }

    /// The execution-mode binding recorded by the producing commit.
    #[must_use]
    pub const fn mode(&self) -> &GatewayModeBindingRecordV1 {
        &self.mode
    }

    /// The Gateway's canonical content bytes.
    #[must_use]
    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

/// A stored revision, or the tombstone its erasure left.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayRevisionStateV1 {
    /// The revision and its content.
    Present(GatewayRevisionRecordV1),
    /// The revision was erased; only its tombstone remains.
    Erased(GatewayRevisionTombstoneV1),
}

impl GatewayRevisionStateV1 {
    /// The fields every state carries.
    #[must_use]
    pub const fn tombstone(&self) -> &GatewayRevisionTombstoneV1 {
        match self {
            Self::Present(record) => record.tombstone(),
            Self::Erased(tombstone) => tombstone,
        }
    }
}

/// The idempotency identity of one revision request: the Principal, the
/// family, the digest of the caller's key and the digest of the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayRevisionIdempotencyV1 {
    principal_id: [u8; 16],
    kind: GatewayRevisionKindV1,
    key_digest: [u8; 32],
    request_digest: [u8; 32],
}

impl GatewayRevisionIdempotencyV1 {
    /// The request of `principal_id` for a `kind` revision under the caller
    /// key `key_digest`, whose canonical request is `request_digest`.
    #[must_use]
    pub const fn new(
        principal_id: [u8; 16],
        kind: GatewayRevisionKindV1,
        key_digest: [u8; 32],
        request_digest: [u8; 32],
    ) -> Self {
        Self {
            principal_id,
            kind,
            key_digest,
            request_digest,
        }
    }

    /// The 16 ID bytes of the requesting Principal.
    #[must_use]
    pub const fn principal_id(&self) -> [u8; 16] {
        self.principal_id
    }

    /// The resource family.
    #[must_use]
    pub const fn kind(&self) -> GatewayRevisionKindV1 {
        self.kind
    }

    /// The digest of the caller's idempotency key; the raw key is never
    /// stored.
    #[must_use]
    pub const fn key_digest(&self) -> [u8; 32] {
        self.key_digest
    }

    /// The digest of the canonical request.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }
}

/// One revision the Gateway asks the store to admit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRevisionDraftV1 {
    idempotency: GatewayRevisionIdempotencyV1,
    resource_id: [u8; 16],
    parent: Option<NonZeroU64>,
    subject: EntityId,
    digest: [u8; 32],
    content: Vec<u8>,
}

impl GatewayRevisionDraftV1 {
    /// The next revision of `resource_id` after `parent`, or its first
    /// revision when `parent` is `None`.
    ///
    /// # Errors
    /// Returns [`GatewayRevisionErrorV1::InvalidRecord`] for empty content or
    /// content over [`MAX_GATEWAY_REVISION_CONTENT_BYTES`].
    pub fn try_new(
        idempotency: GatewayRevisionIdempotencyV1,
        resource_id: [u8; 16],
        parent: Option<NonZeroU64>,
        subject: EntityId,
        digest: [u8; 32],
        content: Vec<u8>,
    ) -> Result<Self, GatewayRevisionErrorV1> {
        (1..=MAX_GATEWAY_REVISION_CONTENT_BYTES)
            .contains(&content.len())
            .then(|| Self {
                idempotency,
                resource_id,
                parent,
                subject,
                digest,
                content,
            })
            .ok_or(GatewayRevisionErrorV1::InvalidRecord)
    }

    /// The request's idempotency identity.
    #[must_use]
    pub const fn idempotency(&self) -> &GatewayRevisionIdempotencyV1 {
        &self.idempotency
    }

    /// The 16 resource ID bytes.
    #[must_use]
    pub const fn resource_id(&self) -> [u8; 16] {
        self.resource_id
    }

    /// The parent revision, `None` for a new resource.
    #[must_use]
    pub const fn parent(&self) -> Option<NonZeroU64> {
        self.parent
    }

    /// The revision number the draft becomes: 1 for a new resource, the
    /// parent's successor otherwise.
    #[must_use]
    pub const fn revision(&self) -> NonZeroU64 {
        match self.parent {
            Some(parent) => parent.saturating_add(1),
            None => NonZeroU64::MIN,
        }
    }

    /// The key of the revision the draft becomes.
    #[must_use]
    pub const fn key(&self) -> GatewayRevisionKeyV1 {
        GatewayRevisionKeyV1::new(self.idempotency.kind, self.resource_id, self.revision())
    }

    /// The key of the parent revision, if any.
    #[must_use]
    pub fn parent_key(&self) -> Option<GatewayRevisionKeyV1> {
        self.parent.map(|parent| {
            GatewayRevisionKeyV1::new(self.idempotency.kind, self.resource_id, parent)
        })
    }

    /// The subject the revision is scoped to.
    #[must_use]
    pub const fn subject(&self) -> EntityId {
        self.subject
    }

    /// The record the draft commits as under `mode`.
    #[must_use]
    pub fn to_record(&self, mode: GatewayModeBindingRecordV1) -> GatewayRevisionRecordV1 {
        GatewayRevisionRecordV1::new(
            GatewayRevisionTombstoneV1::new(self.key(), self.subject, self.digest),
            self.idempotency.principal_id,
            mode,
            self.content.clone(),
        )
    }
}

/// The outcome of one admitted revision request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayRevisionCommitV1 {
    /// The request committed this new revision.
    Committed(GatewayRevisionRecordV1),
    /// An exact retry: the state of the revision the original request
    /// committed.
    Replayed(GatewayRevisionStateV1),
}

/// The mode binding a revision commit records: the store's persisted
/// binding, when the writer is attached to its epoch.
///
/// # Errors
/// Returns [`GatewayRevisionErrorV1::ModeBindingStale`] when the writer is
/// unattached or attached to another epoch, or the store is unbound: a
/// revision is never produced outside a bound execution mode.
pub fn gateway_revision_mode_v1(
    persisted: Option<GatewayModeBindingRecordV1>,
    attached: Option<NonZeroU64>,
) -> Result<GatewayModeBindingRecordV1, GatewayRevisionErrorV1> {
    commit_epoch_for_append_v1(
        persisted
            .as_ref()
            .map(GatewayModeBindingRecordV1::binding_epoch),
        attached,
    )
    .ok()
    .flatten()
    .and(persisted)
    .ok_or(GatewayRevisionErrorV1::ModeBindingStale)
}

/// The admission decision of `draft`, given the state of its named parent
/// and the current head of its resource.
///
/// A new resource must have no revision yet. A next revision must name an
/// unerased parent of the same subject that is still the head.
///
/// # Errors
/// Returns [`GatewayRevisionErrorV1::ParentUnavailable`] for an unknown,
/// erased or foreign parent and [`GatewayRevisionErrorV1::ParentNotHead`]
/// when the head moved past the parent or a new resource already exists.
pub fn admit_gateway_revision_v1(
    draft: &GatewayRevisionDraftV1,
    parent: Option<&GatewayRevisionStateV1>,
    head: Option<NonZeroU64>,
) -> Result<(), GatewayRevisionErrorV1> {
    let available = matches!(
        parent,
        Some(GatewayRevisionStateV1::Present(record))
            if record.tombstone().subject() == draft.subject()
    );
    match draft.parent() {
        Some(_) if !available => Err(GatewayRevisionErrorV1::ParentUnavailable),
        parent => (head == parent)
            .then_some(())
            .ok_or(GatewayRevisionErrorV1::ParentNotHead),
    }
}

/// The request digest an idempotency record keeps once its revision is
/// erased: no byte derived from the erased content survives in it.
pub const ERASED_GATEWAY_REVISION_REQUEST_DIGEST: [u8; 32] = [0; 32];

/// The answer to a retry under a recorded idempotency identity, given the
/// state of the revision it committed and the request digest it kept.
///
/// An erased revision answers its tombstone to every retry from its subject
/// under the key, because erasure rewrote the kept digest to
/// [`ERASED_GATEWAY_REVISION_REQUEST_DIGEST`]; a retry from another entity is
/// a conflict, so it never learns of the erasure. A stored revision answers
/// the same request and refuses another.
///
/// # Errors
/// Returns [`GatewayRevisionErrorV1::IdempotencyConflict`] for another
/// request and [`GatewayRevisionErrorV1::InvalidRecord`] when the recorded
/// revision has no state.
pub fn replay_gateway_revision_v1(
    state: Option<GatewayRevisionStateV1>,
    kept_request_digest: [u8; 32],
    draft: &GatewayRevisionDraftV1,
) -> Result<GatewayRevisionCommitV1, GatewayRevisionErrorV1> {
    let conflict = match &state {
        Some(GatewayRevisionStateV1::Present(_)) => {
            kept_request_digest != draft.idempotency().request_digest()
        }
        Some(GatewayRevisionStateV1::Erased(tombstone)) => tombstone.subject() != draft.subject(),
        None => false,
    };
    if conflict {
        Err(GatewayRevisionErrorV1::IdempotencyConflict)
    } else {
        state
            .map(GatewayRevisionCommitV1::Replayed)
            .ok_or(GatewayRevisionErrorV1::InvalidRecord)
    }
}

/// Opaque capability to erase one revision.
#[derive(Debug)]
pub struct GatewayRevisionErasurePermitV1 {
    key: GatewayRevisionKeyV1,
}

impl GatewayRevisionErasurePermitV1 {
    /// The revision the permit erases.
    #[must_use]
    pub const fn key(&self) -> GatewayRevisionKeyV1 {
        self.key
    }
}

/// Host-composition owner of the revision erasure capability.
///
/// Constructing this value declares that the caller is the trusted
/// composition root of the store it erases from. The host must not expose
/// this owner or its permits to Plugin code or to any request path; the
/// subject erasure workflow (#309) is its production caller. This follows
/// the convention of [`crate::GatewayModeBindingHostV1::new`].
#[derive(Debug)]
pub struct GatewayRevisionErasureHostV1 {
    _composition_root: (),
}

impl GatewayRevisionErasureHostV1 {
    /// Declare the trusted composition root.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _composition_root: (),
        }
    }

    /// Authorize erasing revision `key`.
    #[must_use]
    pub const fn authorize_erasure(
        &self,
        key: GatewayRevisionKeyV1,
    ) -> GatewayRevisionErasurePermitV1 {
        GatewayRevisionErasurePermitV1 { key }
    }
}

impl Default for GatewayRevisionErasureHostV1 {
    fn default() -> Self {
        Self::new()
    }
}

/// Store port for Gateway-managed revisions.
///
/// Every commit and erasure is one durable store transaction.
pub trait GatewayRevisionPortV1 {
    /// Admit `draft` in one transaction with its idempotency record and the
    /// mode binding it is produced under.
    ///
    /// A retry under a recorded idempotency identity is answered by
    /// [`replay_gateway_revision_v1`]. Otherwise the draft is admitted by
    /// [`admit_gateway_revision_v1`] under [`gateway_revision_mode_v1`].
    ///
    /// # Errors
    /// Returns [`GatewayRevisionErrorV1::IdempotencyConflict`], the admission
    /// and mode-binding errors, or a closed invalid-record or unavailable
    /// error.
    fn commit_gateway_revision(
        &mut self,
        draft: GatewayRevisionDraftV1,
    ) -> Result<GatewayRevisionCommitV1, GatewayRevisionErrorV1>;

    /// Load the state of revision `key`, if it was ever committed.
    ///
    /// # Errors
    /// Returns a closed invalid-record or unavailable error.
    fn load_gateway_revision(
        &self,
        key: GatewayRevisionKeyV1,
    ) -> Result<Option<GatewayRevisionStateV1>, GatewayRevisionErrorV1>;

    /// Erase the permit's revision: delete its row and content, keep its
    /// tombstone, and rewrite the request digest of its idempotency record to
    /// [`ERASED_GATEWAY_REVISION_REQUEST_DIGEST`] in the same transaction.
    /// Erasing an erased revision returns its tombstone again; an unknown
    /// revision is `None`.
    ///
    /// # Errors
    /// Returns a closed invalid-record or unavailable error.
    fn erase_gateway_revision(
        &mut self,
        permit: GatewayRevisionErasurePermitV1,
    ) -> Result<Option<GatewayRevisionTombstoneV1>, GatewayRevisionErrorV1>;
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::GatewayModeProfileRefV1;

    fn mode(epoch: u64) -> GatewayModeBindingRecordV1 {
        let profile = GatewayModeProfileRefV1::try_new("gateway-mode-local-v1", [3; 32])
            .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
        GatewayModeBindingRecordV1::new(profile, revision(epoch))
    }

    fn revision(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).unwrap_or(NonZeroU64::MIN)
    }

    fn draft(parent: Option<u64>, subject: EntityId) -> GatewayRevisionDraftV1 {
        GatewayRevisionDraftV1::try_new(
            GatewayRevisionIdempotencyV1::new(
                [1; 16],
                GatewayRevisionKindV1::Preference,
                [2; 32],
                [3; 32],
            ),
            [4; 16],
            parent.map(revision),
            subject,
            [5; 32],
            vec![6],
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())))
    }

    #[test]
    fn kind_codes_round_trip_and_reject_unknown_codes() {
        for kind in [
            GatewayRevisionKindV1::Preference,
            GatewayRevisionKindV1::OptionSpec,
        ] {
            assert_eq!(GatewayRevisionKindV1::from_code(kind.code()), Ok(kind));
        }
        assert_eq!(GatewayRevisionKindV1::Preference.code(), 1);
        assert_eq!(GatewayRevisionKindV1::OptionSpec.code(), 2);
        for code in [0, 3, u8::MAX] {
            assert_eq!(
                GatewayRevisionKindV1::from_code(code),
                Err(GatewayRevisionErrorV1::InvalidRecord)
            );
        }
    }

    #[test]
    fn a_draft_bounds_its_content_and_names_its_revision() {
        let subject = EntityId::new();
        let first = draft(None, subject);
        assert_eq!(first.revision(), NonZeroU64::MIN);
        assert_eq!(first.parent_key(), None);
        assert_eq!(first.resource_id(), [4; 16]);
        assert_eq!(first.idempotency().principal_id(), [1; 16]);
        assert_eq!(first.idempotency().key_digest(), [2; 32]);
        assert_eq!(first.idempotency().request_digest(), [3; 32]);
        let next = draft(Some(4), subject);
        assert_eq!(next.revision(), revision(5));
        assert_eq!(next.parent(), Some(revision(4)));
        assert_eq!(
            next.parent_key(),
            Some(GatewayRevisionKeyV1::new(
                GatewayRevisionKindV1::Preference,
                [4; 16],
                revision(4)
            ))
        );
        let record = next.to_record(mode(1));
        assert_eq!(record.tombstone().key().revision(), revision(5));
        assert_eq!(record.tombstone().key().resource_id(), [4; 16]);
        assert_eq!(
            record.tombstone().key().kind(),
            GatewayRevisionKindV1::Preference
        );
        assert_eq!(record.tombstone().subject(), subject);
        assert_eq!(record.tombstone().digest(), [5; 32]);
        assert_eq!(record.principal_id(), [1; 16]);
        assert_eq!(record.mode(), &mode(1));
        assert_eq!(record.content(), [6]);
        let present = GatewayRevisionStateV1::Present(record.clone());
        assert_eq!(present.tombstone(), record.tombstone());
        let erased = GatewayRevisionStateV1::Erased(*record.tombstone());
        assert_eq!(erased.tombstone(), record.tombstone());
        let idempotency = *first.idempotency();
        for content in [Vec::new(), vec![0; MAX_GATEWAY_REVISION_CONTENT_BYTES + 1]] {
            assert_eq!(
                GatewayRevisionDraftV1::try_new(
                    idempotency,
                    [0; 16],
                    None,
                    subject,
                    [0; 32],
                    content
                ),
                Err(GatewayRevisionErrorV1::InvalidRecord)
            );
        }
        assert!(GatewayRevisionDraftV1::try_new(
            idempotency,
            [0; 16],
            None,
            subject,
            [0; 32],
            vec![0; MAX_GATEWAY_REVISION_CONTENT_BYTES],
        )
        .is_ok());
    }

    #[test]
    fn a_revision_records_the_persisted_binding_of_an_attached_writer() {
        assert_eq!(
            gateway_revision_mode_v1(Some(mode(2)), Some(revision(2))),
            Ok(mode(2))
        );
        for (persisted, attached) in [
            (Some(mode(2)), None),
            (Some(mode(2)), Some(revision(1))),
            (None, Some(revision(1))),
            (None, None),
        ] {
            assert_eq!(
                gateway_revision_mode_v1(persisted, attached),
                Err(GatewayRevisionErrorV1::ModeBindingStale)
            );
        }
    }

    #[test]
    fn admission_requires_the_head_as_an_available_parent() {
        let subject = EntityId::new();
        let parent = GatewayRevisionStateV1::Present(draft(None, subject).to_record(mode(1)));
        let foreign =
            GatewayRevisionStateV1::Present(draft(None, EntityId::new()).to_record(mode(1)));
        let erased = GatewayRevisionStateV1::Erased(*parent.tombstone());
        let first = draft(None, subject);
        let next = draft(Some(1), subject);
        let one = Some(NonZeroU64::MIN);
        assert_eq!(admit_gateway_revision_v1(&first, None, None), Ok(()));
        assert_eq!(
            admit_gateway_revision_v1(&first, None, one),
            Err(GatewayRevisionErrorV1::ParentNotHead)
        );
        assert_eq!(admit_gateway_revision_v1(&next, Some(&parent), one), Ok(()));
        assert_eq!(
            admit_gateway_revision_v1(&next, Some(&parent), Some(revision(2))),
            Err(GatewayRevisionErrorV1::ParentNotHead)
        );
        for unavailable in [None, Some(&foreign), Some(&erased)] {
            assert_eq!(
                admit_gateway_revision_v1(&next, unavailable, one),
                Err(GatewayRevisionErrorV1::ParentUnavailable)
            );
        }
    }

    #[test]
    fn a_retry_replays_its_revision_or_the_tombstone_erasure_left() {
        let subject = EntityId::new();
        let draft = draft(None, subject);
        let present = GatewayRevisionStateV1::Present(draft.to_record(mode(1)));
        let erased = GatewayRevisionStateV1::Erased(*present.tombstone());
        let digest = draft.idempotency().request_digest();
        assert_eq!(
            replay_gateway_revision_v1(Some(present.clone()), digest, &draft),
            Ok(GatewayRevisionCommitV1::Replayed(present.clone()))
        );
        assert_eq!(
            replay_gateway_revision_v1(Some(present), [9; 32], &draft),
            Err(GatewayRevisionErrorV1::IdempotencyConflict)
        );
        assert_eq!(
            replay_gateway_revision_v1(
                Some(erased.clone()),
                ERASED_GATEWAY_REVISION_REQUEST_DIGEST,
                &draft
            ),
            Ok(GatewayRevisionCommitV1::Replayed(erased.clone()))
        );
        let foreign = super::GatewayRevisionDraftV1::try_new(
            *draft.idempotency(),
            draft.resource_id(),
            None,
            EntityId::new(),
            [5; 32],
            vec![6],
        )
        .unwrap_or_else(|error| std::panic::resume_unwind(Box::new(error.to_string())));
        assert_eq!(
            replay_gateway_revision_v1(
                Some(erased),
                ERASED_GATEWAY_REVISION_REQUEST_DIGEST,
                &foreign
            ),
            Err(GatewayRevisionErrorV1::IdempotencyConflict)
        );
        assert_eq!(
            replay_gateway_revision_v1(None, digest, &draft),
            Err(GatewayRevisionErrorV1::InvalidRecord)
        );
    }

    #[test]
    fn the_erasure_host_authorizes_exactly_one_revision() {
        let key =
            GatewayRevisionKeyV1::new(GatewayRevisionKindV1::OptionSpec, [9; 16], revision(3));
        assert_eq!(
            GatewayRevisionErasureHostV1::new()
                .authorize_erasure(key)
                .key(),
            key
        );
        assert_eq!(
            GatewayRevisionErasureHostV1::default()
                .authorize_erasure(key)
                .key(),
            key
        );
    }
}
