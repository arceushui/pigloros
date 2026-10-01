//! Store-owned ADR-099 revision 10/11 classifier and append authority boundary.
//!
//! The durable records live in `pos-core`; this module deliberately keeps the
//! live authority capability in `pos-store`, alongside the non-cloneable
//! admission session that establishes its store binding. The session yields
//! its one permit issuer only to the protected composition root that opened
//! it, and every permit dies with that issuer's live scope.

use std::sync::{Arc, Weak};

use pos_core::{
    Event, EventDraft, EventOriginRecordV1, ForkAdmissionRecordV1, ForkAppendOperationV1,
    ForkAppendSourceIdentityV1, ForkClassifierRegistrationV1, ForkClassifierSourceV1,
    ForkClassifierTableV1, ForkEventAppendRequestV1, ForkEventClassifierV1,
    ForkInterventionAdmissionV1, Hash, TimelineId, MAX_FORK_EVENT_REGISTRAR_BYTES_V1,
};

use crate::ForkAdmissionAuthoritySessionV1;

/// Closed outcomes for the local classified-append authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkEventAuthorityErrorV1 {
    /// The host request cannot produce a valid canonical record.
    #[error("invalid Fork Event authority request")]
    InvalidRequest,
    /// The live session or its host-issued source scope is unavailable.
    #[error("Fork Event authority is unauthenticated")]
    Unauthenticated,
    /// The host-resolved source is absent from the child's admitted classifier.
    #[error("Fork Event source is rejected by the admitted classifier")]
    ClassifierRejected,
    /// A stable operation ID was reused with unequal durable inputs.
    #[error("Fork Event authority conflicts with a committed operation")]
    Conflict,
    /// The immutable FAR1/classifier/provenance graph is incomplete or unequal.
    #[error("Fork Event authority is corrupt")]
    CorruptAuthority,
    /// The adapter cannot determine whether its transaction committed.
    #[error("Fork Event authority storage outcome is indeterminate")]
    StorageIndeterminate,
}

/// Committed classifier-registration receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkClassifierRegistrationReceiptV1 {
    /// Admitted child Fork whose table was committed.
    pub child_timeline_id: TimelineId,
    /// Durable FCT1 digest.
    pub classifier_revision_digest: Hash,
    /// Durable FCR1 digest.
    pub registration_digest: Hash,
}

/// Committed classified append receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifiedAppendReceiptV1 {
    /// The committed Event in Timeline Order.
    pub event: Event,
    /// The committed FOP1 evidence.
    pub operation: ForkAppendOperationV1,
}

/// Nonserializable host capability for one immutable FCS1/FCT1 registration.
///
/// Only [`ForkEventPermitIssuerPortV1::issue_classifier_registrar_permit`]
/// creates one, through the live session's one [`ForkEventPermitIssuerV1`],
/// after the protected Gateway composition root selected the FCS1 row from its
/// activation-scoped FCP1 profile. The permit is bound to the store instance,
/// live session, child, FAR1 digest, and selected FCS1; it dies with its
/// issuer, and any other or non-live session refuses it.
pub struct ForkClassifierRegistrarPermitV1 {
    pub(crate) store_id: Hash,
    pub(crate) session_identity: Hash,
    pub(crate) child_timeline_id: TimelineId,
    pub(crate) fork_admission_digest: Hash,
    pub(crate) source: ForkClassifierSourceV1,
    pub(crate) scope: Weak<()>,
}

/// Nonserializable host capability for one classified append source scope.
///
/// Only [`ForkEventPermitIssuerPortV1::issue_append_source_permit`] creates
/// one, after it revalidated the complete FAR1/FCS1/FCT1/FCR1 closure, the
/// profile-selected FCS1, and the issuer's live source scope. Every append
/// and recovery rechecks that scope: deregistering the adapter, dropping the
/// issuer, or opening a new session makes the permit fail closed.
pub struct ForkAppendSourcePermitV1 {
    pub(crate) store_id: Hash,
    pub(crate) session_identity: Hash,
    pub(crate) child_timeline_id: TimelineId,
    pub(crate) fork_admission_digest: Hash,
    pub(crate) classifier_revision_digest: Hash,
    pub(crate) registration_digest: Hash,
    pub(crate) registrar_identifier: String,
    pub(crate) source: ForkAppendSourceIdentityV1,
    pub(crate) scope: Weak<()>,
}

/// The one Fork Event permit issuer and live adapter registry of a session.
///
/// The protected Gateway composition root takes it exactly once from the
/// session it opened with the host signing credential
/// ([`ForkAdmissionAuthoritySessionV1::take_event_permit_issuer`]). The
/// registry is keyed by the host-assigned adapter registration identity,
/// which is the adapter identifier that FEQ1 and FOP1 record; each activation
/// names one exact route/schema pair. Deregistration revokes every permit
/// issued for that adapter. The whole registry dies with the issuer, and any
/// other or non-live session refuses every permit it issued.
///
/// Its only constructor is crate-private, so outside code cannot mint an
/// issuer even with a live session's identity:
///
/// ```compile_fail
/// fn mint(
///     store_id: pos_core::Hash,
///     session: &pos_store::ForkAdmissionAuthoritySessionV1,
/// ) -> pos_store::ForkEventPermitIssuerV1 {
///     pos_store::ForkEventPermitIssuerV1::for_session(store_id, session.identity())
/// }
/// ```
///
/// Permit fields are private, so outside code cannot forge or rescope a
/// permit either:
///
/// ```compile_fail
/// fn forge(
///     permit: pos_store::ForkAppendSourcePermitV1,
///     child: pos_store::TimelineId,
/// ) -> pos_store::ForkAppendSourcePermitV1 {
///     pos_store::ForkAppendSourcePermitV1 {
///         child_timeline_id: child,
///         ..permit
///     }
/// }
/// ```
///
/// Only the owner of the live session can take its single issuer:
///
/// ```
/// fn take(
///     session: &mut pos_store::ForkAdmissionAuthoritySessionV1,
/// ) -> Option<pos_store::ForkEventPermitIssuerV1> {
///     session.take_event_permit_issuer()
/// }
/// # let _ = take;
/// ```
pub struct ForkEventPermitIssuerV1 {
    store_id: Hash,
    session_identity: Hash,
    host_scope: Arc<()>,
    external_scopes: Vec<(ForkAppendSourceIdentityV1, Arc<()>)>,
}

impl ForkEventPermitIssuerV1 {
    /// Bind the one issuer of a newly opened session; see
    /// [`ForkAdmissionAuthoritySessionV1::take_event_permit_issuer`].
    pub(crate) fn for_session(store_id: Hash, session_identity: Hash) -> Self {
        Self {
            store_id,
            session_identity,
            host_scope: Arc::new(()),
            external_scopes: Vec::new(),
        }
    }

    /// Activate one host-assigned adapter registration for an exact
    /// route/schema scope.
    ///
    /// Host-internal sources need no scope, and an adapter identifier outside
    /// the FOP1 bounds is never trusted, so neither is recorded.
    pub fn trust_external_source(&mut self, source: ForkAppendSourceIdentityV1) {
        if matches!(
            &source,
            ForkAppendSourceIdentityV1::ExternalInput { adapter_identifier, .. }
                if !adapter_identifier.is_empty()
                    && adapter_identifier.len() <= MAX_FORK_EVENT_REGISTRAR_BYTES_V1
        ) && self.source_scope(&source).is_none()
        {
            self.external_scopes.push((source, Arc::new(())));
        }
    }

    /// Revoke every live scope of one adapter registration. Permits already
    /// issued for those scopes stop authorizing appends immediately.
    pub fn revoke_external_adapter(&mut self, adapter_identifier: &str) {
        self.external_scopes.retain(|(source, _)| {
            !matches!(source, ForkAppendSourceIdentityV1::ExternalInput { adapter_identifier: candidate, .. } if candidate == adapter_identifier)
        });
    }

    /// Whether this issuer belongs to the given store instance and session.
    pub(crate) fn matches(&self, session: &ForkAdmissionAuthoritySessionV1) -> bool {
        self.store_id == session.store_id() && self.session_identity == session.identity()
    }

    /// The live scope of a host-internal source or active external scope.
    fn source_scope(&self, source: &ForkAppendSourceIdentityV1) -> Option<Weak<()>> {
        match source {
            ForkAppendSourceIdentityV1::HostInternal => Some(Arc::downgrade(&self.host_scope)),
            ForkAppendSourceIdentityV1::ExternalInput { .. } => self
                .external_scopes
                .iter()
                .find(|(candidate, _)| candidate == source)
                .map(|(_, scope)| Arc::downgrade(scope)),
        }
    }

    /// Shared issuance precondition order for both adapters: this issuer
    /// must belong to the presented session, and then that session must be
    /// the store's live session.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` for a foreign issuer, or the store's
    /// live-session error.
    pub(crate) fn authorize(
        &self,
        session: &ForkAdmissionAuthoritySessionV1,
        live_session: impl FnOnce() -> Result<(), ForkEventAuthorityErrorV1>,
    ) -> Result<(), ForkEventAuthorityErrorV1> {
        if self.matches(session) {
            live_session()
        } else {
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        }
    }

    /// The live scope that will bind an append permit for `source`.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` when an external source has no active scope.
    pub(crate) fn live_source_scope(
        &self,
        source: &ForkAppendSourceIdentityV1,
    ) -> Result<Weak<()>, ForkEventAuthorityErrorV1> {
        self.source_scope(source)
            .ok_or(ForkEventAuthorityErrorV1::Unauthenticated)
    }

    /// Build a registrar permit for the validated local FAR1 and selected FCS1.
    ///
    /// # Errors
    ///
    /// Returns `Unauthenticated` when the selected FCS1 names another room
    /// revision descriptor than the admitted FAR1.
    pub(crate) fn registrar_permit(
        &self,
        admission: &ForkAdmissionRecordV1,
        source: ForkClassifierSourceV1,
    ) -> Result<ForkClassifierRegistrarPermitV1, ForkEventAuthorityErrorV1> {
        (admission.input().room_revision_descriptor_hash
            == source.input().room_revision_descriptor_hash)
            .then(|| ForkClassifierRegistrarPermitV1 {
                store_id: self.store_id,
                session_identity: self.session_identity,
                child_timeline_id: admission.input().child_timeline_id,
                fork_admission_digest: admission.digest(),
                source,
                scope: Arc::downgrade(&self.host_scope),
            })
            .ok_or(ForkEventAuthorityErrorV1::Unauthenticated)
    }

    /// Build an append permit from a validated FAR1/FCT1/FCR1 closure.
    ///
    /// The protected composition root's profile-selected FCS1 must be the
    /// durable FCS1: the validated FCT1 binds the durable FCS1 digest, and
    /// equal canonical-byte digests mean equal bytes (ADR-099 r11 section 3).
    ///
    /// # Errors
    ///
    /// Returns `Conflict` when the selected FCS1 is not the durable FCS1, and
    /// `Unauthenticated` when the admitted FCT1 does not classify `source`.
    pub(crate) fn append_permit(
        &self,
        scope: Weak<()>,
        graph: (
            ForkAdmissionRecordV1,
            ForkClassifierTableV1,
            ForkClassifierRegistrationV1,
        ),
        selected: &ForkClassifierSourceV1,
        source: ForkAppendSourceIdentityV1,
    ) -> Result<ForkAppendSourcePermitV1, ForkEventAuthorityErrorV1> {
        let (admission, table, registration) = graph;
        if table.input().source_configuration_revision_digest != selected.digest() {
            return Err(ForkEventAuthorityErrorV1::Conflict);
        }
        ForkEventClassifierV1::from_table(&table)
            .classify_identity(&source)
            .map_err(|_| ForkEventAuthorityErrorV1::Unauthenticated)
            .map(|_| ForkAppendSourcePermitV1 {
                store_id: self.store_id,
                session_identity: self.session_identity,
                child_timeline_id: admission.input().child_timeline_id,
                fork_admission_digest: admission.digest(),
                classifier_revision_digest: table.digest(),
                registration_digest: registration.digest(),
                registrar_identifier: table.input().registrar_identifier.clone(),
                source,
                scope,
            })
    }
}

impl ForkClassifierRegistrarPermitV1 {
    pub(crate) const fn source(&self) -> &ForkClassifierSourceV1 {
        &self.source
    }
    pub(crate) const fn fork_admission_digest(&self) -> Hash {
        self.fork_admission_digest
    }
    /// Whether this permit is still live for this store instance, session,
    /// and child.
    pub(crate) fn authorizes(
        &self,
        session: &ForkAdmissionAuthoritySessionV1,
        child_timeline_id: TimelineId,
    ) -> bool {
        self.store_id == session.store_id()
            && self.session_identity == session.identity()
            && self.child_timeline_id == child_timeline_id
            && self.scope.strong_count() > 0
    }
}

impl ForkAppendSourcePermitV1 {
    pub(crate) const fn source(&self) -> &ForkAppendSourceIdentityV1 {
        &self.source
    }
    pub(crate) const fn child_timeline_id(&self) -> TimelineId {
        self.child_timeline_id
    }
    /// Whether this permit was issued for this store instance and session
    /// and its issuer still holds the exact source scope.
    pub(crate) fn is_live_for(&self, session: &ForkAdmissionAuthoritySessionV1) -> bool {
        self.store_id == session.store_id()
            && self.session_identity == session.identity()
            && self.scope.strong_count() > 0
    }
    /// Whether this permit names exactly the child's durable FAR1, FCT1, FCR1
    /// and registrar.
    pub(crate) fn names_scope(
        &self,
        admission: &ForkAdmissionRecordV1,
        table: &ForkClassifierTableV1,
        registration: &ForkClassifierRegistrationV1,
    ) -> bool {
        self.fork_admission_digest == admission.digest()
            && self.classifier_revision_digest == table.digest()
            && self.registration_digest == registration.digest()
            && self.registrar_identifier == table.input().registrar_identifier
    }
}

/// ADR-099 r11 read-only FCP1 preflight shared by both adapters: every durable
/// FCS1 must equal one activation-profile row byte-for-byte. A durable source
/// for another registrar, or one absent from or unequal to the profile,
/// blocks activation.
///
/// # Errors
///
/// Returns `Conflict` when any durable FCS1 is not a profile row.
pub(crate) fn preflight_classifier_sources<'a>(
    durable: impl IntoIterator<Item = &'a ForkClassifierSourceV1>,
    profile: &[ForkClassifierSourceV1],
) -> Result<(), ForkEventAuthorityErrorV1> {
    durable
        .into_iter()
        .all(|source| profile.contains(source))
        .then_some(())
        .ok_or(ForkEventAuthorityErrorV1::Conflict)
}

/// Return the durable FAR1 only when a registrar permit names its digest.
///
/// # Errors
///
/// Returns `Unauthenticated` when the permit was issued for another FAR1.
pub(crate) fn permitted_fork_admission(
    permitted_admission_digest: Hash,
    admission: ForkAdmissionRecordV1,
) -> Result<ForkAdmissionRecordV1, ForkEventAuthorityErrorV1> {
    (admission.digest() == permitted_admission_digest)
        .then_some(admission)
        .ok_or(ForkEventAuthorityErrorV1::Unauthenticated)
}

/// Store bridge that issues permits only after rereading authority.
pub trait ForkEventPermitIssuerPortV1 {
    /// Read the one validated local FAR1 for protected profile selection.
    ///
    /// # Errors
    ///
    /// Returns an error when local durable admission authority is absent or corrupt.
    fn read_validated_local_fork_admission(
        &self,
        child_timeline_id: TimelineId,
    ) -> Result<ForkAdmissionRecordV1, ForkEventAuthorityErrorV1>;

    /// Read-only ADR-099 r11 preflight of every durable FCS1 against one
    /// activation profile. It writes no authority record.
    ///
    /// # Errors
    ///
    /// Every adapter returns `Conflict` when a durable FCS1 is not exactly
    /// one profile row. Only the `SQLite` adapter, which decodes its rows from
    /// stored bytes, also returns `CorruptAuthority` for a malformed or
    /// mis-keyed durable FCS1 and `StorageIndeterminate` when its rows cannot
    /// be read; the Memory adapter holds typed rows and returns only
    /// `Conflict`.
    fn preflight_fork_classifier_profile(
        &self,
        profile_sources: &[ForkClassifierSourceV1],
    ) -> Result<(), ForkEventAuthorityErrorV1>;

    /// Issue a permit for the admitted child's selected classifier source.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not live, the source does not match
    /// the admitted child, or durable admission authority is unavailable.
    fn issue_classifier_registrar_permit(
        &self,
        issuer: &ForkEventPermitIssuerV1,
        session: &ForkAdmissionAuthoritySessionV1,
        child_timeline_id: TimelineId,
        source: ForkClassifierSourceV1,
    ) -> Result<ForkClassifierRegistrarPermitV1, ForkEventAuthorityErrorV1>;

    /// Issue a source-scoped append permit after checking durable authority.
    ///
    /// `selected_source` is the composition root's activation-profile FCS1
    /// row for the child's durable FAR1 descriptor; it must be the durable
    /// FCS1 before a permit is issued or reissued.
    ///
    /// # Errors
    ///
    /// Returns an error if the session or source scope is unavailable, the
    /// selected FCS1 is not the durable FCS1, or the admitted classifier and
    /// registration graph cannot be verified.
    fn issue_append_source_permit(
        &self,
        issuer: &ForkEventPermitIssuerV1,
        session: &ForkAdmissionAuthoritySessionV1,
        child_timeline_id: TimelineId,
        selected_source: &ForkClassifierSourceV1,
        source: ForkAppendSourceIdentityV1,
    ) -> Result<ForkAppendSourcePermitV1, ForkEventAuthorityErrorV1>;
}

/// Store-owned classifier registration, append, recovery, and suffix-read port.
///
/// Every mutating or recovery call receives the exact live ADR-106 session.
/// A durable session identity alone is never accepted as authority.
pub trait ForkEventProvenanceAuthorityPortV1 {
    /// Register the one immutable classifier for an empty locally admitted Fork.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is not live, the source conflicts with
    /// durable classifier state, or the adapter cannot commit the registration.
    fn register_classifier(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        permit: &ForkClassifierRegistrarPermitV1,
        operation_id: Hash,
        child_timeline_id: TimelineId,
    ) -> Result<ForkClassifierRegistrationReceiptV1, ForkEventAuthorityErrorV1>;

    /// Append one Event with the host-resolved source scope.
    ///
    /// # Errors
    ///
    /// Returns an error when the session, classifier, request, or durable
    /// provenance state is invalid, or the adapter cannot determine the commit outcome.
    fn append_classified(
        &mut self,
        session: &ForkAdmissionAuthoritySessionV1,
        permit: &ForkAppendSourcePermitV1,
        operation_id: Hash,
        draft: EventDraft,
    ) -> Result<ForkClassifiedAppendReceiptV1, ForkEventAuthorityErrorV1>;

    /// Recover a stable append operation after an indeterminate outcome.
    ///
    /// # Errors
    ///
    /// Returns an error when the session, recovery request, or durable
    /// provenance state is invalid.
    fn recover_classified_append(
        &self,
        session: &ForkAdmissionAuthoritySessionV1,
        permit: &ForkAppendSourcePermitV1,
        operation_id: Hash,
        draft: &EventDraft,
    ) -> Result<Option<ForkClassifiedAppendReceiptV1>, ForkEventAuthorityErrorV1>;

    /// Read the validated child suffix provenance in Timeline Order.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored suffix is incomplete or fails provenance validation.
    fn read_fork_event_suffix(
        &self,
        child_timeline_id: TimelineId,
        from_logical_seq: u64,
    ) -> Result<
        Vec<(
            EventOriginRecordV1,
            Option<ForkInterventionAdmissionV1>,
            ForkAppendOperationV1,
        )>,
        ForkEventAuthorityErrorV1,
    >;
}

/// Build the canonical request digest input for a classified append.
///
/// # Errors
///
/// Returns an error when the supplied append fields cannot form a canonical request.
pub(crate) fn fork_append_request(
    operation_id: Hash,
    child_timeline_id: TimelineId,
    source: &ForkAppendSourceIdentityV1,
    draft: &EventDraft,
) -> Result<ForkEventAppendRequestV1, ForkEventAuthorityErrorV1> {
    ForkEventAppendRequestV1::new(ForkEventAppendRequestV1 {
        operation_id,
        child_timeline_id,
        source: source.clone(),
        entity_id: draft.entity,
        event_type: draft.event_type.as_str().to_owned(),
        payload: draft.payload.as_slice().to_vec(),
        causation_id: draft.causation_id,
        correlation_id: draft.correlation_id,
        wall_time_override: draft.wall_time,
    })
    .map_err(|_| ForkEventAuthorityErrorV1::InvalidRequest)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::error::Error;
    #[cfg(feature = "sqlite")]
    use std::path::Path;

    use ciborium::value::Value;
    use pos_core::hasher::Hasher;
    use pos_core::{
        fork_authentication::{
            principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
            ForkAuthenticationPolicyV1,
        },
        CanonicalBytes, EntityId, EventDraft, EventStore, ForkAdmissionHostCommandV1,
        ForkAdmissionOperationResultV1, ForkAdmissionReceiptV1, ForkClassifierSourceInputV1,
        ForkClassifierSourceV1, ForkEventSourceDescriptorV1, ForkExternalInputRouteV1, Hash, Kind,
        PrincipalRefV1, PublicKey, TimelineId, WallTime,
    };
    use pos_crypto::chain::Blake3Hasher;
    use pos_crypto::fork_authentication::{
        verify_authenticated_principal_evidence_v1, ForkAuthenticationAdapterSigningKeyV1,
        ForkHostSigningKeyV1, VerifiedAuthenticatedPrincipalEvidenceV1,
    };
    #[cfg(feature = "sqlite")]
    use rusqlite::{params, Connection};

    use super::*;
    #[cfg(feature = "sqlite")]
    use crate::sqlite::SqliteStore;
    use crate::{
        memory::MemoryStore, ForkAdmissionAuthorityBootstrapPortV1, ForkAdmissionAuthorityPortV1,
    };

    fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes)?;
        Ok(bytes)
    }

    #[cfg(feature = "sqlite")]
    fn replace_cbor_field(
        bytes: &[u8],
        index: usize,
        replacement: Value,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut value: Value = ciborium::from_reader(bytes)?;
        let Value::Array(fields) = &mut value else {
            return Err("durable provenance record must be an array".into());
        };
        let Some(field) = fields.get_mut(index) else {
            return Err("durable provenance record field is missing".into());
        };
        *field = replacement;
        encode(&value)
    }

    fn policy(
        adapter: &ForkAuthenticationAdapterSigningKeyV1,
    ) -> Result<ForkAuthenticationPolicyV1, Box<dyn Error>> {
        Ok(ForkAuthenticationPolicyV1::new(vec![
            ForkAuthenticationAdapterPolicyV1 {
                adapter_id: "fork-event.test".to_owned(),
                verifying_key: adapter.public_key(),
                minimum_assurance: 1,
                registry_bindings: vec![Hash::from_bytes([3; 32])],
            },
        ])?)
    }

    fn open_session<S: ForkAdmissionAuthorityBootstrapPortV1>(
        store: &mut S,
        host: &ForkHostSigningKeyV1,
        policy: &ForkAuthenticationPolicyV1,
    ) -> Result<ForkAdmissionAuthoritySessionV1, Box<dyn Error>> {
        let host_key = PublicKey::from_bytes(host.public_key());
        let initialize = store.begin_fork_admission_initialize(host_key, policy.digest()?)?;
        let initialize_signature = host.sign_initialize(&initialize.to_canonical_cbor()?)?;
        store.finalize_fork_admission_initialize(&initialize, &initialize_signature)?;
        reopen_session(store, host, policy)
    }

    fn reopen_session<S: ForkAdmissionAuthorityBootstrapPortV1>(
        store: &mut S,
        host: &ForkHostSigningKeyV1,
        policy: &ForkAuthenticationPolicyV1,
    ) -> Result<ForkAdmissionAuthoritySessionV1, Box<dyn Error>> {
        let open = store.begin_fork_admission_open(
            PublicKey::from_bytes(host.public_key()),
            policy.digest()?,
        )?;
        let signature = host.sign_open(&open.to_canonical_cbor()?)?;
        Ok(store.finalize_fork_admission_open(&open, &signature)?)
    }

    fn evidence(
        adapter: &ForkAuthenticationAdapterSigningKeyV1,
        policy: &ForkAuthenticationPolicyV1,
    ) -> Result<VerifiedAuthenticatedPrincipalEvidenceV1, Box<dyn Error>> {
        let record = AuthenticatedPrincipalRecordV1 {
            principal: PrincipalRefV1::try_new([4; 16], "test.local")?,
            adapter_id: "fork-event.test".to_owned(),
            assurance: 1,
            issued_at: 0,
            expires_at: u64::MAX,
            registry_binding: Hash::from_bytes([3; 32]),
            operation_nonce: [5; 32],
        };
        Ok(verify_authenticated_principal_evidence_v1(
            policy,
            adapter.sign_authenticated_principal(record)?,
        )?)
    }

    fn command<S: ForkAdmissionAuthorityBootstrapPortV1>(
        store: &S,
        host: &ForkHostSigningKeyV1,
        verified: &VerifiedAuthenticatedPrincipalEvidenceV1,
        session: &ForkAdmissionAuthoritySessionV1,
        operation_id: [u8; 32],
        kind: &str,
        parent: Option<TimelineId>,
    ) -> Result<ForkAdmissionHostCommandV1, Box<dyn Error>> {
        let principal = principal_digest_v1(&verified.evidence().record().principal)?;
        let mut inner = vec![
            Value::Text(kind.to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(
                store
                    .fork_admission_host_record()?
                    .store_id()
                    .as_bytes()
                    .to_vec(),
            ),
            Value::Bytes(session.identity().as_bytes().to_vec()),
            Value::Bytes(operation_id.to_vec()),
            Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
            Value::Bytes(principal.as_bytes().to_vec()),
        ];
        match parent {
            Some(parent) => inner.extend([
                Value::Bytes(parent.inner().to_bytes().to_vec()),
                Value::Integer(0.into()),
                Value::Integer(0.into()),
                Value::Bytes(vec![8; 32]),
                Value::Bytes(vec![9; 32]),
                Value::Integer(1.into()),
                Value::Text("classified-child".to_owned()),
            ]),
            None => inner.push(Value::Text("test-owner".to_owned())),
        }
        let inner = encode(&Value::Array(inner))?;
        let signature = host.sign_command(&inner, verified)?;
        let command = encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(inner),
            Value::Bytes(verified.evidence().to_canonical_cbor()?),
            Value::Bytes(signature.as_bytes().to_vec()),
        ]))?;
        Ok(ForkAdmissionHostCommandV1::from_canonical_cbor(&command)?)
    }

    fn draft(payload: &[u8]) -> EventDraft {
        EventDraft::new(
            EntityId::new(),
            Kind::new("fork.event.test"),
            CanonicalBytes::from_vec(payload.to_vec()),
        )
        .with_wall_time(WallTime::from_micros(10))
    }

    /// An additional issuer for an already opened session.
    ///
    /// Production obtains the one issuer with
    /// `ForkAdmissionAuthoritySessionV1::take_event_permit_issuer`; these
    /// in-crate store tests also need foreign and second issuers.
    fn issuer_for(session: &ForkAdmissionAuthoritySessionV1) -> ForkEventPermitIssuerV1 {
        ForkEventPermitIssuerV1::for_session(session.store_id(), session.identity())
    }

    /// Hand-built registrar permit for one store, child, and FAR1 digest,
    /// live while `issuer` lives.
    ///
    /// Only rejection paths use it; accepted registrations use the issuer.
    fn registrar_permit(
        issuer: &ForkEventPermitIssuerV1,
        store_id: Hash,
        child_timeline_id: TimelineId,
        fork_admission_digest: Hash,
        source: ForkClassifierSourceV1,
    ) -> ForkClassifierRegistrarPermitV1 {
        ForkClassifierRegistrarPermitV1 {
            store_id,
            session_identity: issuer.session_identity,
            child_timeline_id,
            fork_admission_digest,
            source,
            scope: Arc::downgrade(&issuer.host_scope),
        }
    }

    /// Hand-built append permit carrying the fixture's complete authority
    /// scope, live while the fixture issuer lives.
    ///
    /// Rejection tests override one field with struct update syntax; these
    /// defence-in-depth cases are unreachable through the issuer.
    fn append_permit(
        fixture: &LifecycleFixtureV1,
        source: ForkAppendSourceIdentityV1,
    ) -> ForkAppendSourcePermitV1 {
        ForkAppendSourcePermitV1 {
            store_id: fixture.store_id,
            session_identity: fixture.session.identity(),
            child_timeline_id: fixture.fork.child_id,
            fork_admission_digest: fixture.fork.admission_digest,
            classifier_revision_digest: fixture.registration.classifier_revision_digest,
            registration_digest: fixture.registration.registration_digest,
            registrar_identifier: fixture.source.input().registrar_identifier.clone(),
            source,
            scope: Arc::downgrade(&fixture.issuer.host_scope),
        }
    }

    struct LifecycleFixtureV1 {
        session: ForkAdmissionAuthoritySessionV1,
        issuer: ForkEventPermitIssuerV1,
        store_id: Hash,
        fork: ForkAdmissionReceiptV1,
        source: ForkClassifierSourceV1,
        registration: ForkClassifierRegistrationReceiptV1,
        external: ForkEventSourceDescriptorV1,
        external_non_intervention: ForkEventSourceDescriptorV1,
    }

    fn assert_lifecycle<S>(store: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let host_receipt = assert_host_append(store, &fixture)?;
        assert_external_append(store, &fixture, &host_receipt)
    }

    fn assert_generic_fork_append_is_rejected<S>(store: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        assert!(matches!(
            store.append(fixture.fork.child_id, &[draft(b"unclassified-fork-event")]),
            Err(pos_core::CoreError::Storage(message))
                if message == "admitted Fork Events require classified append authority"
        ));
        assert!(store
            .read_fork_event_suffix(fixture.fork.child_id, 1)?
            .is_empty());
        Ok(())
    }

    fn create_lifecycle<S>(store: &mut S) -> Result<LifecycleFixtureV1, Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        // ADR-106 r3: an admitted Fork needs an available bound erasure gate.
        store.bind_erasure_gate(std::sync::Arc::new(
            pos_core::ErasureContainmentGateV1::new_test_open(),
        ))?;
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let mut session = open_session(store, &host, &policy)?;
        let mut issuer = session
            .take_event_permit_issuer()
            .ok_or("a new session yields its issuer once")?;
        assert!(session.take_event_permit_issuer().is_none());
        let verified = evidence(&adapter, &policy)?;
        let principal = command(store, &host, &verified, &session, [43; 32], "POC1", None)?;
        assert!(matches!(
            store.execute_fork_admission_command(&session, &policy, &principal)?,
            ForkAdmissionOperationResultV1::PrincipalOwner(_)
        ));
        let parent = store.create_timeline("classified-parent")?;
        let command = command(
            store,
            &host,
            &verified,
            &session,
            [44; 32],
            "FCC1",
            Some(parent.id()),
        )?;
        let ForkAdmissionOperationResultV1::Fork(fork) =
            store.execute_fork_admission_command(&session, &policy, &command)?
        else {
            return Err("FCC1 did not return a Fork receipt".into());
        };
        let store_id = store.fork_admission_host_record()?.store_id();
        let external =
            ForkEventSourceDescriptorV1::new("gateway.action.v1", Hash::from_bytes([45; 32]))?;
        let external_non_intervention =
            ForkEventSourceDescriptorV1::new("bridge.sample.v1", Hash::from_bytes([59; 32]))?;
        let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: Hash::from_bytes([8; 32]),
            registrar_identifier: "fork-event.test".to_owned(),
            routes: vec![
                ForkExternalInputRouteV1::new(external.clone(), true),
                ForkExternalInputRouteV1::new(external_non_intervention.clone(), false),
            ],
        })?;
        issuer.trust_external_source(ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter".to_owned(),
            source: external.clone(),
        });
        let registration =
            register_classifier(store, &issuer, &session, store_id, &source, fork.child_id)?;
        Ok(LifecycleFixtureV1 {
            session,
            issuer,
            store_id,
            fork,
            source,
            registration,
            external,
            external_non_intervention,
        })
    }

    #[test]
    fn issuer_tracks_external_scopes_by_adapter() -> Result<(), Box<dyn Error>> {
        let mut store = MemoryStore::new();
        let fixture = create_lifecycle(&mut store)?;
        let external = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter".to_owned(),
            source: fixture.external.clone(),
        };
        let retained = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "other.adapter".to_owned(),
            source: fixture.external.clone(),
        };
        let longest = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "a".repeat(MAX_FORK_EVENT_REGISTRAR_BYTES_V1),
            source: fixture.external,
        };

        assert!(fixture
            .issuer
            .source_scope(&ForkAppendSourceIdentityV1::HostInternal)
            .is_some());
        assert!(fixture.issuer.source_scope(&external).is_some());

        let mut issuer = fixture.issuer;
        issuer.trust_external_source(external.clone());
        issuer.trust_external_source(retained.clone());
        issuer.trust_external_source(longest.clone());
        issuer.trust_external_source(ForkAppendSourceIdentityV1::HostInternal);
        assert_eq!(issuer.external_scopes.len(), 3);
        issuer.revoke_external_adapter("gateway.adapter");

        assert!(issuer
            .source_scope(&ForkAppendSourceIdentityV1::HostInternal)
            .is_some());
        assert!(issuer.source_scope(&external).is_none());
        assert!(issuer.source_scope(&retained).is_some());
        assert!(issuer.source_scope(&longest).is_some());
        Ok(())
    }

    fn assert_permit_issuer_rejects_unadmitted_inputs<S>(
        store: &mut S,
    ) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let unknown_source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: Hash::from_bytes([57; 32]),
            registrar_identifier: "unadmitted-registrar".to_owned(),
            routes: vec![ForkExternalInputRouteV1::new(
                fixture.external.clone(),
                true,
            )],
        })?;
        assert_eq!(
            store
                .issue_classifier_registrar_permit(
                    &fixture.issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    unknown_source,
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );

        let registrar = store.issue_classifier_registrar_permit(
            &fixture.issuer,
            &fixture.session,
            fixture.fork.child_id,
            fixture.source.clone(),
        )?;
        let invalid_registrar = ForkClassifierRegistrarPermitV1 {
            fork_admission_digest: Hash::zero(),
            ..registrar
        };
        assert_eq!(
            store
                .register_classifier(
                    &fixture.session,
                    &invalid_registrar,
                    Hash::from_bytes([58; 32]),
                    fixture.fork.child_id,
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );

        assert_eq!(
            store
                .issue_append_source_permit(
                    &fixture.issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    &fixture.source,
                    ForkAppendSourceIdentityV1::ExternalInput {
                        adapter_identifier: "untrusted-adapter".to_owned(),
                        source: fixture.external,
                    }
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        Ok(())
    }

    fn assert_permit_issuer_rejects_missing_admission<S>(
        store: &mut S,
    ) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let unadmitted_child = TimelineId::new();

        assert_eq!(
            store
                .issue_classifier_registrar_permit(
                    &fixture.issuer,
                    &fixture.session,
                    unadmitted_child,
                    fixture.source.clone(),
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        assert_eq!(
            store
                .issue_append_source_permit(
                    &fixture.issuer,
                    &fixture.session,
                    unadmitted_child,
                    &fixture.source,
                    ForkAppendSourceIdentityV1::HostInternal
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    fn assert_permit_issuer_rejects_inactive_or_mismatched_session<S>(
        store: &mut S,
    ) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let current_session = reopen_session(store, &host, &policy)?;
        let current_issuer = issuer_for(&current_session);
        let mismatched_source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: Hash::from_bytes([57; 32]),
            registrar_identifier: fixture.source.input().registrar_identifier.clone(),
            routes: fixture.source.input().routes.clone(),
        })?;

        assert_eq!(
            store
                .issue_classifier_registrar_permit(
                    &fixture.issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    fixture.source.clone(),
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store
                .issue_append_source_permit(
                    &fixture.issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    &fixture.source,
                    ForkAppendSourceIdentityV1::HostInternal
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store
                .issue_classifier_registrar_permit(
                    &current_issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    fixture.source.clone(),
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store
                .issue_classifier_registrar_permit(
                    &current_issuer,
                    &current_session,
                    fixture.fork.child_id,
                    mismatched_source,
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        Ok(())
    }

    fn assert_permit_issuer_rejects_revoked_or_unclassified_external_scope<S>(
        store: &mut S,
    ) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let external = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter".to_owned(),
            source: fixture.external.clone(),
        };
        let unclassified = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter".to_owned(),
            source: ForkEventSourceDescriptorV1::new(
                "gateway.unclassified.v1",
                Hash::from_bytes([61; 32]),
            )?,
        };
        // A malformed adapter scope is never trusted, so it cannot be issued.
        let mut invalid_issuer = issuer_for(&fixture.session);
        for adapter_identifier in [
            String::new(),
            "a".repeat(MAX_FORK_EVENT_REGISTRAR_BYTES_V1 + 1),
        ] {
            let invalid_source = ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier,
                source: fixture.external.clone(),
            };
            invalid_issuer.trust_external_source(invalid_source.clone());
            assert!(invalid_issuer.source_scope(&invalid_source).is_none());
            assert_eq!(
                store
                    .issue_append_source_permit(
                        &invalid_issuer,
                        &fixture.session,
                        fixture.fork.child_id,
                        &fixture.source,
                        invalid_source
                    )
                    .err(),
                Some(ForkEventAuthorityErrorV1::Unauthenticated)
            );
        }
        let mut issuer = fixture.issuer;
        issuer.trust_external_source(unclassified.clone());

        assert_eq!(
            store
                .issue_append_source_permit(
                    &issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    &fixture.source,
                    unclassified
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );

        issuer.revoke_external_adapter("gateway.adapter");
        assert_eq!(
            store
                .issue_append_source_permit(
                    &issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    &fixture.source,
                    external
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert!(store
            .issue_append_source_permit(
                &issuer,
                &fixture.session,
                fixture.fork.child_id,
                &fixture.source,
                ForkAppendSourceIdentityV1::HostInternal
            )
            .is_ok());
        Ok(())
    }

    fn register_classifier<S>(
        store: &mut S,
        issuer: &ForkEventPermitIssuerV1,
        session: &ForkAdmissionAuthoritySessionV1,
        store_id: Hash,
        source: &ForkClassifierSourceV1,
        child_timeline_id: TimelineId,
    ) -> Result<ForkClassifierRegistrationReceiptV1, Box<dyn Error>>
    where
        S: ForkEventProvenanceAuthorityPortV1 + ForkEventPermitIssuerPortV1,
    {
        let registrar = store.issue_classifier_registrar_permit(
            issuer,
            session,
            child_timeline_id,
            source.clone(),
        )?;
        assert_eq!(
            store.register_classifier(
                session,
                &registrar_permit(
                    issuer,
                    Hash::from_bytes([54; 32]),
                    child_timeline_id,
                    registrar.fork_admission_digest(),
                    source.clone(),
                ),
                Hash::from_bytes([46; 32]),
                child_timeline_id,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        // A permit from another session, or whose issuer scope ended, never
        // authorizes registration.
        for stale_registrar in [
            ForkClassifierRegistrarPermitV1 {
                session_identity: Hash::from_bytes([55; 32]),
                ..registrar_permit(
                    issuer,
                    store_id,
                    child_timeline_id,
                    registrar.fork_admission_digest(),
                    source.clone(),
                )
            },
            ForkClassifierRegistrarPermitV1 {
                scope: Weak::new(),
                ..registrar_permit(
                    issuer,
                    store_id,
                    child_timeline_id,
                    registrar.fork_admission_digest(),
                    source.clone(),
                )
            },
        ] {
            assert_eq!(
                store.register_classifier(
                    session,
                    &stale_registrar,
                    Hash::from_bytes([46; 32]),
                    child_timeline_id,
                ),
                Err(ForkEventAuthorityErrorV1::Unauthenticated)
            );
        }
        assert_eq!(
            store.register_classifier(session, &registrar, Hash::zero(), child_timeline_id),
            Err(ForkEventAuthorityErrorV1::InvalidRequest)
        );
        let registration = store.register_classifier(
            session,
            &registrar,
            Hash::from_bytes([46; 32]),
            child_timeline_id,
        )?;
        assert_eq!(
            store.register_classifier(
                session,
                &registrar,
                Hash::from_bytes([46; 32]),
                child_timeline_id,
            )?,
            registration
        );
        Ok(registration)
    }

    fn assert_host_append<S>(
        store: &mut S,
        fixture: &LifecycleFixtureV1,
    ) -> Result<ForkClassifiedAppendReceiptV1, Box<dyn Error>>
    where
        S: ForkEventProvenanceAuthorityPortV1 + ForkEventPermitIssuerPortV1,
    {
        let host_permit = store.issue_append_source_permit(
            &fixture.issuer,
            &fixture.session,
            fixture.fork.child_id,
            &fixture.source,
            ForkAppendSourceIdentityV1::HostInternal,
        )?;
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &ForkAppendSourcePermitV1 {
                    fork_admission_digest: Hash::from_bytes([55; 32]),
                    ..append_permit(fixture, ForkAppendSourceIdentityV1::HostInternal,)
                },
                Hash::from_bytes([47; 32]),
                draft(b"wrong-admission"),
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &ForkAppendSourcePermitV1 {
                    registrar_identifier: "foreign-registrar".to_owned(),
                    ..append_permit(fixture, ForkAppendSourceIdentityV1::HostInternal,)
                },
                Hash::from_bytes([47; 32]),
                draft(b"wrong-registrar"),
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        let host_draft = draft(b"host-internal");
        let receipt = store.append_classified(
            &fixture.session,
            &host_permit,
            Hash::from_bytes([47; 32]),
            host_draft.clone(),
        )?;
        let registrar = store.issue_classifier_registrar_permit(
            &fixture.issuer,
            &fixture.session,
            fixture.fork.child_id,
            fixture.source.clone(),
        )?;
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar,
                Hash::from_bytes([46; 32]),
                fixture.fork.child_id,
            )?,
            fixture.registration
        );
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &host_permit,
                Hash::from_bytes([47; 32]),
                host_draft.clone(),
            )?,
            receipt
        );
        assert_eq!(
            store.recover_classified_append(
                &fixture.session,
                &host_permit,
                Hash::from_bytes([48; 32]),
                &host_draft,
            )?,
            None
        );
        Ok(receipt)
    }

    fn assert_external_append<S>(
        store: &mut S,
        fixture: &LifecycleFixtureV1,
        host_receipt: &ForkClassifiedAppendReceiptV1,
    ) -> Result<(), Box<dyn Error>>
    where
        S: ForkAdmissionAuthorityBootstrapPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let permit = store.issue_append_source_permit(
            &fixture.issuer,
            &fixture.session,
            fixture.fork.child_id,
            &fixture.source,
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: fixture.external.clone(),
            },
        )?;
        let external_draft = draft(b"external-intervention");
        let receipt = store.append_classified(
            &fixture.session,
            &permit,
            Hash::from_bytes([49; 32]),
            external_draft.clone(),
        )?;
        assert_eq!(
            store.recover_classified_append(
                &fixture.session,
                &permit,
                Hash::from_bytes([49; 32]),
                &external_draft,
            )?,
            Some(receipt.clone())
        );
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &permit,
                Hash::from_bytes([49; 32]),
                draft(b"conflict"),
            ),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        assert_eq!(
            store.recover_classified_append(
                &fixture.session,
                &permit,
                Hash::from_bytes([49; 32]),
                &draft(b"conflict"),
            ),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        let suffix = store.read_fork_event_suffix(fixture.fork.child_id, 1)?;
        assert_eq!(suffix.len(), 2);
        assert!(suffix[0].1.is_none());
        assert!(suffix[1].1.is_some());
        assert_eq!(suffix[0].2, host_receipt.operation);
        assert_eq!(suffix[1].2, receipt.operation);
        let bridge_source = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "bridge.adapter".to_owned(),
            source: fixture.external_non_intervention.clone(),
        };
        let mut bridge_issuer = issuer_for(&fixture.session);
        bridge_issuer.trust_external_source(bridge_source.clone());
        let non_intervention_permit = store.issue_append_source_permit(
            &bridge_issuer,
            &fixture.session,
            fixture.fork.child_id,
            &fixture.source,
            bridge_source,
        )?;
        let non_intervention_receipt = store.append_classified(
            &fixture.session,
            &non_intervention_permit,
            Hash::from_bytes([60; 32]),
            draft(b"external-observation"),
        )?;
        let suffix = store.read_fork_event_suffix(fixture.fork.child_id, 1)?;
        assert_eq!(suffix.len(), 3);
        assert!(suffix[2].1.is_none());
        assert_eq!(suffix[2].2, non_intervention_receipt.operation);
        assert_eq!(
            store
                .read_fork_event_suffix(fixture.fork.child_id, receipt.event.seq.as_u64())?
                .len(),
            2
        );
        assert_classifier_registration_is_immutable(store, fixture)?;
        assert_append_scope_is_immutable(store, fixture);
        assert_external_rejections(store, fixture, &permit, &external_draft, receipt)
    }

    fn assert_classifier_registration_is_immutable<S>(
        store: &mut S,
        fixture: &LifecycleFixtureV1,
    ) -> Result<(), Box<dyn Error>>
    where
        S: ForkEventProvenanceAuthorityPortV1 + ForkEventPermitIssuerPortV1,
    {
        let mismatched_admission_source =
            ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
                room_revision_descriptor_hash: Hash::from_bytes([54; 32]),
                registrar_identifier: fixture.source.input().registrar_identifier.clone(),
                routes: fixture.source.input().routes.clone(),
            })?;
        // A permit that does not bind this child and its FAR1 digest does not
        // authenticate the registration, whatever source it carries.
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(
                    &fixture.issuer,
                    fixture.store_id,
                    TimelineId::new(),
                    fixture.fork.admission_digest,
                    mismatched_admission_source.clone(),
                ),
                Hash::from_bytes([56; 32]),
                fixture.fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        // The issuer never selects a source for another room revision.
        assert_eq!(
            store
                .issue_classifier_registrar_permit(
                    &fixture.issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    mismatched_admission_source.clone(),
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        // Defence in depth, unreachable via the issuer: the issuer refuses a
        // source for another room revision (asserted above), so only this
        // hand-built, correctly bound permit can carry one. The store still
        // rechecks the immutable FAR1 descriptor and reports a conflict.
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(
                    &fixture.issuer,
                    fixture.store_id,
                    fixture.fork.child_id,
                    fixture.fork.admission_digest,
                    mismatched_admission_source,
                ),
                Hash::from_bytes([56; 32]),
                fixture.fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        let replacement_source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: fixture.source.input().room_revision_descriptor_hash,
            registrar_identifier: "replacement-registrar.v1".to_owned(),
            routes: vec![ForkExternalInputRouteV1::new(
                fixture.external.clone(),
                false,
            )],
        })?;
        let replacement_registrar = store.issue_classifier_registrar_permit(
            &fixture.issuer,
            &fixture.session,
            fixture.fork.child_id,
            replacement_source,
        )?;
        let original_registrar = store.issue_classifier_registrar_permit(
            &fixture.issuer,
            &fixture.session,
            fixture.fork.child_id,
            fixture.source.clone(),
        )?;
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &replacement_registrar,
                Hash::from_bytes([46; 32]),
                fixture.fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &original_registrar,
                Hash::from_bytes([57; 32]),
                fixture.fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        Ok(())
    }

    fn assert_append_scope_is_immutable<S>(store: &mut S, fixture: &LifecycleFixtureV1)
    where
        S: ForkEventProvenanceAuthorityPortV1,
    {
        let missing_child = ForkAppendSourcePermitV1 {
            child_timeline_id: TimelineId::new(),
            ..append_permit(fixture, ForkAppendSourceIdentityV1::HostInternal)
        };
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &missing_child,
                Hash::from_bytes([58; 32]),
                draft(b"missing-admitted-child"),
            ),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        // A permit issued for another FCR1 no longer names the admitted scope.
        let stale_registration = ForkAppendSourcePermitV1 {
            registration_digest: Hash::from_bytes([89; 32]),
            ..append_permit(fixture, ForkAppendSourceIdentityV1::HostInternal)
        };
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &stale_registration,
                Hash::from_bytes([89; 32]),
                draft(b"stale-registration"),
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
    }

    fn assert_external_rejections<S>(
        store: &mut S,
        fixture: &LifecycleFixtureV1,
        permit: &ForkAppendSourcePermitV1,
        external_draft: &EventDraft,
        receipt: ForkClassifiedAppendReceiptV1,
    ) -> Result<(), Box<dyn Error>>
    where
        S: ForkAdmissionAuthorityBootstrapPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let rejected = append_permit(
            fixture,
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: ForkEventSourceDescriptorV1::new(
                    "gateway.unknown.v1",
                    Hash::from_bytes([50; 32]),
                )?,
            },
        );
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &rejected,
                Hash::from_bytes([51; 32]),
                draft(b"reject"),
            ),
            Err(ForkEventAuthorityErrorV1::ClassifierRejected)
        );
        let foreign_store = ForkAppendSourcePermitV1 {
            store_id: Hash::from_bytes([52; 32]),
            ..append_permit(fixture, ForkAppendSourceIdentityV1::HostInternal)
        };
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &foreign_store,
                Hash::from_bytes([53; 32]),
                draft(b"foreign"),
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_stale_session_and_recovery_rejections(
            store,
            fixture,
            permit,
            external_draft,
            receipt,
            &foreign_store,
        )
    }

    fn assert_stale_session_and_recovery_rejections<S>(
        store: &mut S,
        fixture: &LifecycleFixtureV1,
        permit: &ForkAppendSourcePermitV1,
        external_draft: &EventDraft,
        receipt: ForkClassifiedAppendReceiptV1,
        foreign_store: &ForkAppendSourcePermitV1,
    ) -> Result<(), Box<dyn Error>>
    where
        S: ForkAdmissionAuthorityBootstrapPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let current = reopen_session(store, &host, &policy)?;
        let stale_issuer_result = store.issue_append_source_permit(
            &fixture.issuer,
            &current,
            fixture.fork.child_id,
            &fixture.source,
            ForkAppendSourceIdentityV1::HostInternal,
        );
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(
                    &fixture.issuer,
                    fixture.store_id,
                    fixture.fork.child_id,
                    fixture.fork.admission_digest,
                    fixture.source.clone(),
                ),
                Hash::from_bytes([46; 32]),
                fixture.fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            stale_issuer_result.err(),
            Some(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        let mut current_issuer = issuer_for(&current);
        assert!(store
            .issue_append_source_permit(
                &current_issuer,
                &current,
                fixture.fork.child_id,
                &fixture.source,
                ForkAppendSourceIdentityV1::HostInternal,
            )
            .is_ok());
        assert_eq!(
            store.recover_classified_append(
                &fixture.session,
                permit,
                Hash::from_bytes([49; 32]),
                external_draft,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        // A reopen discards every earlier permit: it stays bound to the old
        // session even when presented with the new live session.
        assert_eq!(
            store.recover_classified_append(
                &current,
                permit,
                Hash::from_bytes([49; 32]),
                external_draft,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store.recover_classified_append(
                &current,
                foreign_store,
                Hash::from_bytes([49; 32]),
                external_draft,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_reissued_permit_recovers(
            store,
            fixture,
            &current,
            &mut current_issuer,
            (permit, external_draft, receipt),
        )
    }

    /// After a reopen, only a permit reissued for the new session and its
    /// renewed adapter scope recovers the same FOP1 operation.
    fn assert_reissued_permit_recovers<S>(
        store: &S,
        fixture: &LifecycleFixtureV1,
        current: &ForkAdmissionAuthoritySessionV1,
        current_issuer: &mut ForkEventPermitIssuerV1,
        (permit, external_draft, receipt): (
            &ForkAppendSourcePermitV1,
            &EventDraft,
            ForkClassifiedAppendReceiptV1,
        ),
    ) -> Result<(), Box<dyn Error>>
    where
        S: ForkEventProvenanceAuthorityPortV1 + ForkEventPermitIssuerPortV1,
    {
        let missing_child = ForkAppendSourcePermitV1 {
            child_timeline_id: TimelineId::new(),
            session_identity: current.identity(),
            scope: Arc::downgrade(&current_issuer.host_scope),
            ..append_permit(fixture, ForkAppendSourceIdentityV1::HostInternal)
        };
        assert_eq!(
            store.recover_classified_append(
                current,
                &missing_child,
                Hash::from_bytes([49; 32]),
                external_draft,
            ),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        // Same-operation recovery needs a permit reissued under the new
        // session for the renewed adapter scope.
        current_issuer.trust_external_source(permit.source().clone());
        let reissued = store.issue_append_source_permit(
            current_issuer,
            current,
            fixture.fork.child_id,
            &fixture.source,
            permit.source().clone(),
        )?;
        assert_eq!(
            store.recover_classified_append(
                current,
                &reissued,
                Hash::from_bytes([49; 32]),
                external_draft,
            )?,
            Some(receipt)
        );
        Ok(())
    }
    /// Payload whose host payload hash is absent under [`ZeroPayloadHashHasher`].
    const ZERO_HASH_PAYLOAD: &[u8] = b"zero-payload-hash";

    /// BLAKE3 hashing, except one sentinel payload whose payload hash is zero.
    struct ZeroPayloadHashHasher;

    impl Hasher for ZeroPayloadHashHasher {
        fn genesis_hash(&self) -> Hash {
            Blake3Hasher.genesis_hash()
        }

        fn hash_payload(&self, payload: &CanonicalBytes) -> Hash {
            if payload.as_slice() == ZERO_HASH_PAYLOAD {
                Hash::zero()
            } else {
                Blake3Hasher.hash_payload(payload)
            }
        }

        fn hash_event(
            &self,
            previous_hash: &Hash,
            event_id_bytes: &[u8],
            payload: &CanonicalBytes,
        ) -> Hash {
            Blake3Hasher.hash_event(previous_hash, event_id_bytes, payload)
        }
    }

    /// A provenance derivation failure leaves neither an Event nor a record.
    fn assert_invalid_payload_hash_append_leaves_no_state<S>(
        store: &mut S,
    ) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let permit = append_permit(&fixture, ForkAppendSourceIdentityV1::HostInternal);
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &permit,
                Hash::from_bytes([64; 32]),
                draft(ZERO_HASH_PAYLOAD),
            ),
            Err(ForkEventAuthorityErrorV1::InvalidRequest)
        );
        assert!(store
            .read_fork_event_suffix(fixture.fork.child_id, 1)?
            .is_empty());
        let receipt = store.append_classified(
            &fixture.session,
            &permit,
            Hash::from_bytes([65; 32]),
            draft(b"after-rejected-provenance"),
        )?;
        assert_eq!(receipt.event.seq.as_u64(), 1);
        Ok(())
    }

    #[test]
    fn memory_classified_append_rejects_invalid_provenance_before_mutation(
    ) -> Result<(), Box<dyn Error>> {
        assert_invalid_payload_hash_append_leaves_no_state(&mut MemoryStore::with_hasher(Box::new(
            ZeroPayloadHashHasher,
        )))
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_append_rolls_back_invalid_provenance() -> Result<(), Box<dyn Error>> {
        assert_invalid_payload_hash_append_leaves_no_state(
            &mut SqliteStore::open_in_memory_with_hasher(Box::new(ZeroPayloadHashHasher))?,
        )
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_append_maps_non_constraint_operation_insert_failure(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("classified-append-insert-fault.sqlite");
        let mut store = sqlite_store_at(&path)?;
        let fixture = create_lifecycle(&mut store)?;
        let permit = append_permit(&fixture, ForkAppendSourceIdentityV1::HostInternal);
        Connection::open(&path)?.execute_batch(
            "CREATE TABLE injected_insert_fault (value INTEGER);
             CREATE TRIGGER inject_fork_append_operation_fault
             BEFORE INSERT ON fork_append_operations
             BEGIN INSERT INTO injected_insert_fault VALUES (1); END;
             DROP TABLE injected_insert_fault;",
        )?;

        assert_eq!(
            store.append_classified(
                &fixture.session,
                &permit,
                Hash::from_bytes([66; 32]),
                draft(b"operation-insert-fault"),
            ),
            Err(ForkEventAuthorityErrorV1::StorageIndeterminate)
        );
        assert!(store
            .read_fork_event_suffix(fixture.fork.child_id, 1)?
            .is_empty());
        Ok(())
    }

    /// Admit one more local child Fork under the fixture's live session.
    fn admit_fork<S>(
        store: &mut S,
        fixture: &LifecycleFixtureV1,
        operation_id: [u8; 32],
        parent_name: &str,
    ) -> Result<ForkAdmissionReceiptV1, Box<dyn Error>>
    where
        S: EventStore + ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
    {
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let verified = evidence(&adapter, &policy)?;
        let parent = store.create_timeline(parent_name)?;
        let command = command(
            store,
            &host,
            &verified,
            &fixture.session,
            operation_id,
            "FCC1",
            Some(parent.id()),
        )?;
        match store.execute_fork_admission_command(&fixture.session, &policy, &command)? {
            ForkAdmissionOperationResultV1::Fork(fork) => Ok(fork),
            ForkAdmissionOperationResultV1::PrincipalOwner(_) => {
                Err("FCC1 did not return a Fork receipt".into())
            }
        }
    }

    /// One FCS1 is shared by every Fork that selects it; a different FCS1
    /// under the same descriptor and registrar is a conflict.
    fn assert_classifier_source_is_shared_across_forks<S>(
        store: &mut S,
    ) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let shared = admit_fork(store, &fixture, [73; 32], "shared-source-parent")?;
        let shared_registrar = store.issue_classifier_registrar_permit(
            &fixture.issuer,
            &fixture.session,
            shared.child_id,
            fixture.source.clone(),
        )?;
        let receipt = store.register_classifier(
            &fixture.session,
            &shared_registrar,
            Hash::from_bytes([74; 32]),
            shared.child_id,
        )?;
        assert_eq!(receipt.child_timeline_id, shared.child_id);
        let conflicting = admit_fork(store, &fixture, [75; 32], "conflicting-source-parent")?;
        let conflicting_source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: fixture.source.input().room_revision_descriptor_hash,
            registrar_identifier: fixture.source.input().registrar_identifier.clone(),
            routes: vec![ForkExternalInputRouteV1::new(
                fixture.external.clone(),
                false,
            )],
        })?;
        let conflicting_registrar = store.issue_classifier_registrar_permit(
            &fixture.issuer,
            &fixture.session,
            conflicting.child_id,
            conflicting_source,
        )?;
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &conflicting_registrar,
                Hash::from_bytes([76; 32]),
                conflicting.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        Ok(())
    }

    /// Invalid requests, unadmitted children, and stale sessions fail closed.
    fn assert_port_request_rejections<S>(store: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let permit_for = |source| append_permit(&fixture, source);
        let host_permit = permit_for(ForkAppendSourceIdentityV1::HostInternal);
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &host_permit,
                Hash::zero(),
                draft(b"zero-operation"),
            ),
            Err(ForkEventAuthorityErrorV1::InvalidRequest)
        );
        let unadmitted_child = TimelineId::new();
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(
                    &fixture.issuer,
                    fixture.store_id,
                    unadmitted_child,
                    fixture.fork.admission_digest,
                    fixture.source.clone(),
                ),
                Hash::from_bytes([70; 32]),
                unadmitted_child,
            ),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        let host_draft = draft(b"host-request");
        store.append_classified(
            &fixture.session,
            &host_permit,
            Hash::from_bytes([71; 32]),
            host_draft.clone(),
        )?;
        let invalid_source = permit_for(ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: String::new(),
            source: fixture.external.clone(),
        });
        assert_eq!(
            store.recover_classified_append(
                &fixture.session,
                &invalid_source,
                Hash::from_bytes([71; 32]),
                &host_draft,
            ),
            Err(ForkEventAuthorityErrorV1::InvalidRequest)
        );
        assert_eq!(
            store.read_fork_event_suffix(TimelineId::new(), 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        reopen_session(store, &host, &policy(&adapter)?)?;
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &host_permit,
                Hash::from_bytes([72; 32]),
                draft(b"stale-session"),
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        Ok(())
    }

    #[test]
    fn memory_classifier_source_is_shared_across_forks() -> Result<(), Box<dyn Error>> {
        assert_classifier_source_is_shared_across_forks(&mut MemoryStore::new())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classifier_source_is_shared_across_forks() -> Result<(), Box<dyn Error>> {
        assert_classifier_source_is_shared_across_forks(&mut SqliteStore::open_in_memory()?)
    }

    #[test]
    fn memory_port_rejects_invalid_requests_and_stale_sessions() -> Result<(), Box<dyn Error>> {
        assert_port_request_rejections(&mut MemoryStore::new())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_port_rejects_invalid_requests_and_stale_sessions() -> Result<(), Box<dyn Error>> {
        assert_port_request_rejections(&mut SqliteStore::open_in_memory()?)
    }

    #[test]
    fn memory_classified_append_port_preserves_provenance_and_authority(
    ) -> Result<(), Box<dyn Error>> {
        assert_lifecycle(&mut MemoryStore::new())
    }

    #[test]
    fn memory_rejects_generic_append_to_admitted_fork() -> Result<(), Box<dyn Error>> {
        assert_generic_fork_append_is_rejected(&mut MemoryStore::new())
    }

    #[test]
    fn memory_permit_issuer_rejects_unadmitted_inputs() -> Result<(), Box<dyn Error>> {
        assert_permit_issuer_rejects_unadmitted_inputs(&mut MemoryStore::new())
    }

    #[test]
    fn memory_permit_issuer_rejects_missing_admission() -> Result<(), Box<dyn Error>> {
        assert_permit_issuer_rejects_missing_admission(&mut MemoryStore::new())
    }

    #[test]
    fn memory_permit_issuer_rejects_each_missing_durable_graph_record() -> Result<(), Box<dyn Error>>
    {
        let mut store = MemoryStore::new();
        let fixture = create_lifecycle(&mut store)?;
        store.test_remove_fork_classifier_table(fixture.fork.child_id);
        assert_eq!(
            store
                .issue_append_source_permit(
                    &fixture.issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    &fixture.source,
                    ForkAppendSourceIdentityV1::HostInternal
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::CorruptAuthority)
        );

        let mut store = MemoryStore::new();
        let fixture = create_lifecycle(&mut store)?;
        store.test_remove_fork_classifier_registration(fixture.fork.child_id);
        assert_eq!(
            store
                .issue_append_source_permit(
                    &fixture.issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    &fixture.source,
                    ForkAppendSourceIdentityV1::HostInternal
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::CorruptAuthority)
        );

        let mut store = MemoryStore::new();
        let fixture = create_lifecycle(&mut store)?;
        store.test_remove_fork_classifier_source(
            fixture.source.input().room_revision_descriptor_hash,
            &fixture.source.input().registrar_identifier,
        );
        assert_eq!(
            store
                .issue_append_source_permit(
                    &fixture.issuer,
                    &fixture.session,
                    fixture.fork.child_id,
                    &fixture.source,
                    ForkAppendSourceIdentityV1::HostInternal
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    #[test]
    fn memory_permit_issuer_rejects_inactive_or_mismatched_session() -> Result<(), Box<dyn Error>> {
        assert_permit_issuer_rejects_inactive_or_mismatched_session(&mut MemoryStore::new())
    }

    #[test]
    fn memory_permit_issuer_rejects_revoked_or_unclassified_external_scope(
    ) -> Result<(), Box<dyn Error>> {
        assert_permit_issuer_rejects_revoked_or_unclassified_external_scope(&mut MemoryStore::new())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_append_port_preserves_provenance_and_authority(
    ) -> Result<(), Box<dyn Error>> {
        assert_lifecycle(&mut SqliteStore::open_in_memory()?)
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_rejects_generic_append_to_admitted_fork() -> Result<(), Box<dyn Error>> {
        assert_generic_fork_append_is_rejected(&mut SqliteStore::open_in_memory()?)
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_permit_issuer_rejects_unadmitted_inputs() -> Result<(), Box<dyn Error>> {
        assert_permit_issuer_rejects_unadmitted_inputs(&mut SqliteStore::open_in_memory()?)
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_permit_issuer_rejects_missing_admission() -> Result<(), Box<dyn Error>> {
        assert_permit_issuer_rejects_missing_admission(&mut SqliteStore::open_in_memory()?)
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_permit_issuer_rejects_each_missing_or_corrupt_durable_graph_record(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        for case in 0..5 {
            let path = directory
                .path()
                .join(format!("issuer-corruption-{case}.sqlite"));
            let mut store = sqlite_store_at(&path)?;
            let fixture = create_lifecycle(&mut store)?;
            let conn = Connection::open(&path)?;
            match case {
                0 => {
                    conn.execute("DELETE FROM fork_classifier_tables", [])?;
                }
                1 => {
                    conn.execute(
                        "UPDATE fork_classifier_tables SET fct1_cbor = ?1 WHERE child_id = ?2",
                        params![vec![0_u8], fixture.fork.child_id.to_string()],
                    )?;
                }
                2 => {
                    conn.execute(
                        "UPDATE fork_classifier_registrations SET fcr1_cbor = ?1 WHERE child_id = ?2",
                        params![vec![0_u8], fixture.fork.child_id.to_string()],
                    )?;
                }
                3 => {
                    conn.execute_batch("DROP TABLE fork_classifier_registrations")?;
                }
                4 => {
                    conn.execute("DELETE FROM fork_classifier_sources", [])?;
                }
                _ => return Err("unexpected durable graph corruption case".into()),
            }
            drop(conn);

            assert_eq!(
                store
                    .issue_append_source_permit(
                        &fixture.issuer,
                        &fixture.session,
                        fixture.fork.child_id,
                        &fixture.source,
                        ForkAppendSourceIdentityV1::HostInternal
                    )
                    .err(),
                Some(ForkEventAuthorityErrorV1::CorruptAuthority)
            );
        }
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_permit_issuer_rejects_inactive_or_mismatched_session() -> Result<(), Box<dyn Error>> {
        assert_permit_issuer_rejects_inactive_or_mismatched_session(
            &mut SqliteStore::open_in_memory()?,
        )
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_permit_issuer_rejects_revoked_or_unclassified_external_scope(
    ) -> Result<(), Box<dyn Error>> {
        assert_permit_issuer_rejects_revoked_or_unclassified_external_scope(
            &mut SqliteStore::open_in_memory()?,
        )
    }

    #[cfg(feature = "sqlite")]
    fn sqlite_store_at(path: &Path) -> Result<SqliteStore, Box<dyn Error>> {
        Ok(SqliteStore::open(
            path.to_str().ok_or("non-UTF-8 temporary path")?,
        )?)
    }

    #[cfg(feature = "sqlite")]
    fn durable_sqlite_fixture(
        path: &Path,
    ) -> Result<(LifecycleFixtureV1, EventDraft), Box<dyn Error>> {
        let mut store = sqlite_store_at(path)?;
        let fixture = create_lifecycle(&mut store)?;
        assert_host_append(&mut store, &fixture)?;
        let permit = store.issue_append_source_permit(
            &fixture.issuer,
            &fixture.session,
            fixture.fork.child_id,
            &fixture.source,
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: fixture.external.clone(),
            },
        )?;
        let external_draft = draft(b"external-intervention");
        store.append_classified(
            &fixture.session,
            &permit,
            Hash::from_bytes([49; 32]),
            external_draft.clone(),
        )?;
        Ok((fixture, external_draft))
    }

    /// Reopen the session and issue the fixture adapter's external permit.
    ///
    /// The caller must keep the returned issuer alive while it uses the
    /// permit: a dropped issuer revokes the permit's live scope, which
    /// ADR-099 r10 checks before it reads any durable recovery evidence.
    #[cfg(feature = "sqlite")]
    fn reopened_external_permit(
        store: &mut SqliteStore,
        fixture: &LifecycleFixtureV1,
    ) -> Result<
        (
            ForkAdmissionAuthoritySessionV1,
            ForkEventPermitIssuerV1,
            ForkAppendSourcePermitV1,
        ),
        Box<dyn Error>,
    > {
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let session = reopen_session(store, &host, &policy)?;
        let mut issuer = issuer_for(&session);
        issuer.trust_external_source(ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter".to_owned(),
            source: fixture.external.clone(),
        });
        let permit = store.issue_append_source_permit(
            &issuer,
            &session,
            fixture.fork.child_id,
            &fixture.source,
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: fixture.external.clone(),
            },
        )?;
        Ok((session, issuer, permit))
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_append_rebuilds_durable_graph_after_reopen() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("classified-append.sqlite");
        let (fixture, external_receipt, external_draft) = {
            let mut store = sqlite_store_at(&path)?;
            let fixture = create_lifecycle(&mut store)?;
            let host_receipt = assert_host_append(&mut store, &fixture)?;
            let external_permit = store.issue_append_source_permit(
                &fixture.issuer,
                &fixture.session,
                fixture.fork.child_id,
                &fixture.source,
                ForkAppendSourceIdentityV1::ExternalInput {
                    adapter_identifier: "gateway.adapter".to_owned(),
                    source: fixture.external.clone(),
                },
            )?;
            let external_draft = draft(b"external-intervention");
            let external_receipt = store.append_classified(
                &fixture.session,
                &external_permit,
                Hash::from_bytes([49; 32]),
                external_draft.clone(),
            )?;
            assert_eq!(
                store
                    .read_fork_event_suffix(fixture.fork.child_id, 1)?
                    .len(),
                2
            );
            assert_eq!(host_receipt.event.seq.as_u64(), 1);
            (fixture, external_receipt, external_draft)
        };

        let mut store = sqlite_store_at(&path)?;
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let session = reopen_session(&mut store, &host, &policy)?;
        let mut issuer = issuer_for(&session);
        issuer.trust_external_source(ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter".to_owned(),
            source: fixture.external.clone(),
        });
        let external_permit = store.issue_append_source_permit(
            &issuer,
            &session,
            fixture.fork.child_id,
            &fixture.source,
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: fixture.external.clone(),
            },
        )?;
        assert_eq!(
            store.recover_classified_append(
                &session,
                &external_permit,
                Hash::from_bytes([49; 32]),
                &external_draft,
            )?,
            Some(external_receipt)
        );
        let host_permit = store.issue_append_source_permit(
            &issuer,
            &session,
            fixture.fork.child_id,
            &fixture.source,
            ForkAppendSourceIdentityV1::HostInternal,
        )?;
        store.append_classified(
            &session,
            &host_permit,
            Hash::from_bytes([56; 32]),
            draft(b"host-after-reopen"),
        )?;
        assert_eq!(
            store
                .read_fork_event_suffix(fixture.fork.child_id, 1)?
                .len(),
            3
        );
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_append_fails_closed_when_each_durable_evidence_row_is_tampered(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        for (index, table, column, expected) in [
            (
                0,
                "fork_classifier_sources",
                "fcs1_cbor",
                ForkEventAuthorityErrorV1::CorruptAuthority,
            ),
            (
                1,
                "fork_classifier_tables",
                "fct1_cbor",
                ForkEventAuthorityErrorV1::CorruptAuthority,
            ),
            (
                2,
                "fork_classifier_registrations",
                "fcr1_cbor",
                ForkEventAuthorityErrorV1::CorruptAuthority,
            ),
            (
                3,
                "fork_append_operations",
                "fop1_cbor",
                ForkEventAuthorityErrorV1::StorageIndeterminate,
            ),
            (
                4,
                "fork_event_origins",
                "eor1_cbor",
                ForkEventAuthorityErrorV1::CorruptAuthority,
            ),
            (
                5,
                "fork_intervention_admissions",
                "fia1_cbor",
                ForkEventAuthorityErrorV1::CorruptAuthority,
            ),
        ] {
            let path = directory.path().join(format!("tampered-{index}.sqlite"));
            let (fixture, external_draft) = durable_sqlite_fixture(&path)?;
            let mut store = sqlite_store_at(&path)?;
            let (session, issuer, permit) = reopened_external_permit(&mut store, &fixture)?;
            let connection = Connection::open(&path)?;
            let operation_id = Hash::from_bytes([49; 32]);
            let changed = if table == "fork_append_operations" {
                connection.execute(
                    &format!("UPDATE {table} SET {column} = ?1 WHERE operation_id = ?2"),
                    params![vec![0_u8], operation_id.as_bytes().as_slice()],
                )?
            } else if table == "fork_event_origins" || table == "fork_intervention_admissions" {
                connection.execute(
                    &format!(
                        "UPDATE {table} SET {column} = ?1 WHERE event_id = (\
                         SELECT event_id FROM fork_append_operations WHERE operation_id = ?2)"
                    ),
                    params![vec![0_u8], operation_id.as_bytes().as_slice()],
                )?
            } else {
                connection.execute(
                    &format!("UPDATE {table} SET {column} = ?1"),
                    params![vec![0_u8]],
                )?
            };
            assert_eq!(changed, 1, "{table}.{column} must target one row");
            assert_eq!(
                store.recover_classified_append(
                    &session,
                    &permit,
                    Hash::from_bytes([49; 32]),
                    &external_draft,
                ),
                Err(expected),
                "{table}.{column} must fail closed"
            );
            drop(issuer);
        }
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_recovery_fails_closed_when_authority_graph_rows_are_missing(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        for (index, table, predicate) in [
            (0, "fork_admissions", "WHERE child_id = ?1"),
            (
                1,
                "fork_admission_operations",
                "WHERE kind = 2 AND child_id = ?1",
            ),
            (2, "fork_classifier_sources", "WHERE ?1 IS NOT NULL"),
            (3, "fork_classifier_tables", "WHERE child_id = ?1"),
            (4, "fork_classifier_registrations", "WHERE child_id = ?1"),
        ] {
            let path = directory
                .path()
                .join(format!("missing-authority-{index}.sqlite"));
            let (fixture, external_draft) = durable_sqlite_fixture(&path)?;
            let mut store = sqlite_store_at(&path)?;
            let (session, issuer, permit) = reopened_external_permit(&mut store, &fixture)?;
            let changed = Connection::open(&path)?.execute(
                &format!("DELETE FROM {table} {predicate}"),
                params![fixture.fork.child_id.to_string()],
            )?;
            assert_eq!(changed, 1, "{table} fixture must be present");

            assert_eq!(
                store.recover_classified_append(
                    &session,
                    &permit,
                    Hash::from_bytes([49; 32]),
                    &external_draft,
                ),
                Err(ForkEventAuthorityErrorV1::CorruptAuthority),
                "missing {table} must make classified recovery unavailable"
            );
            drop(issuer);
        }
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_suffix_fails_closed_when_each_durable_evidence_row_is_tampered(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        for (index, table, column) in [
            (0, "fork_classifier_sources", "fcs1_cbor"),
            (1, "fork_classifier_tables", "fct1_cbor"),
            (2, "fork_classifier_registrations", "fcr1_cbor"),
            (3, "fork_append_operations", "fop1_cbor"),
            (4, "fork_event_origins", "eor1_cbor"),
            (5, "fork_intervention_admissions", "fia1_cbor"),
        ] {
            let path = directory
                .path()
                .join(format!("suffix-tampered-{index}.sqlite"));
            let (fixture, _) = durable_sqlite_fixture(&path)?;
            let connection = Connection::open(&path)?;
            let affected = connection.execute(
                &format!(
                    "UPDATE {table} SET {column} = ?1 WHERE rowid = (SELECT MIN(rowid) FROM {table})"
                ),
                params![vec![0_u8]],
            )?;
            assert_eq!(affected, 1, "{table}.{column} fixture must be present");
            let store = sqlite_store_at(&path)?;
            assert_eq!(
                store.read_fork_event_suffix(fixture.fork.child_id, 1),
                Err(ForkEventAuthorityErrorV1::CorruptAuthority),
                "{table}.{column} must make the suffix unavailable"
            );
        }
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_suffix_rejects_missing_or_orphaned_durable_evidence(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        for (index, table, predicate) in [
            (0, "fork_classifier_sources", ""),
            (1, "fork_classifier_tables", ""),
            (2, "fork_classifier_registrations", ""),
            (
                3,
                "fork_append_operations",
                " WHERE operation_id = ?1",
            ),
            (
                4,
                "fork_event_origins",
                " WHERE event_id = (SELECT event_id FROM fork_append_operations WHERE operation_id = ?1)",
            ),
            (
                5,
                "fork_intervention_admissions",
                " WHERE event_id = (SELECT event_id FROM fork_append_operations WHERE operation_id = ?1)",
            ),
        ] {
            let path = directory.path().join(format!("missing-{index}.sqlite"));
            let (fixture, _) = durable_sqlite_fixture(&path)?;
            let connection = Connection::open(&path)?;
            let changed = if predicate.is_empty() {
                connection.execute(&format!("DELETE FROM {table}"), [])?
            } else {
                let operation_id = Hash::from_bytes([49; 32]);
                connection.execute(
                    &format!("DELETE FROM {table}{predicate}"),
                    params![operation_id.as_bytes().as_slice()],
                )?
            };
            assert_eq!(changed, 1, "{table} fixture must be present");
            let store = sqlite_store_at(&path)?;
            assert_eq!(
                store.read_fork_event_suffix(fixture.fork.child_id, 1),
                Err(ForkEventAuthorityErrorV1::CorruptAuthority),
                "missing {table} must make the suffix unavailable"
            );
        }

        let path = directory.path().join("orphaned-events.sqlite");
        let (fixture, _) = durable_sqlite_fixture(&path)?;
        let store = sqlite_store_at(&path)?;
        let changed = Connection::open(&path)?.execute(
            "DELETE FROM events WHERE timeline_id = ?1",
            params![fixture.fork.child_id.to_string()],
        )?;
        assert_eq!(changed, 2);
        assert_eq!(
            store.read_fork_event_suffix(fixture.fork.child_id, 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_suffix_rejects_orphaned_canonical_provenance() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        for (index, is_origin) in [(0, true), (1, false)] {
            let kind = if is_origin { "origin" } else { "intervention" };
            let path = directory
                .path()
                .join(format!("orphaned-{kind}-{index}.sqlite"));
            let (fixture, _) = durable_sqlite_fixture(&path)?;
            let event_id = pos_core::EventId::new();
            let connection = Connection::open(&path)?;
            if is_origin {
                let origin = EventOriginRecordV1::new(pos_core::EventOriginRecordInputV1 {
                    fork_timeline_id: fixture.fork.child_id,
                    logical_seq: 99,
                    event_id,
                    classification: pos_core::ForkEventClassificationV1::new(
                        pos_core::ForkEventOriginKindV1::HostInternal,
                        false,
                    )?,
                    classifier_revision_digest: fixture.registration.classifier_revision_digest,
                    fork_admission_digest: fixture.fork.admission_digest,
                })?;
                connection.execute(
                    "INSERT INTO fork_event_origins (event_id, eor1_cbor) VALUES (?1, ?2)",
                    params![event_id.to_string(), origin.to_canonical_cbor()],
                )?;
            } else {
                let intervention =
                    ForkInterventionAdmissionV1::new(pos_core::ForkInterventionAdmissionInputV1 {
                        operation_id: Hash::from_bytes([61; 32]),
                        fork_timeline_id: fixture.fork.child_id,
                        logical_seq: 99,
                        event_id,
                        payload_hash: Hash::from_bytes([62; 32]),
                        room_revision_descriptor_hash: fixture
                            .source
                            .input()
                            .room_revision_descriptor_hash,
                        classifier_revision_digest: fixture.registration.classifier_revision_digest,
                        fork_admission_digest: fixture.fork.admission_digest,
                    })?;
                connection.execute(
                    "INSERT INTO fork_intervention_admissions (event_id, fia1_cbor) \
                     VALUES (?1, ?2)",
                    params![event_id.to_string(), intervention.to_canonical_cbor()],
                )?;
            }
            let store = sqlite_store_at(&path)?;
            assert_eq!(
                store.read_fork_event_suffix(fixture.fork.child_id, 1),
                Err(ForkEventAuthorityErrorV1::CorruptAuthority),
                "orphaned canonical {kind} must make the suffix unavailable"
            );
        }
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_suffix_rejects_semantically_inconsistent_evidence(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        for (index, table, column, field, replacement) in [
            (
                0,
                "fork_append_operations",
                "fop1_cbor",
                3,
                Value::Bytes(vec![3; 16]),
            ),
            (
                1,
                "fork_append_operations",
                "fop1_cbor",
                4,
                Value::Integer(3.into()),
            ),
            (
                2,
                "fork_event_origins",
                "eor1_cbor",
                3,
                Value::Integer(3.into()),
            ),
            (
                3,
                "fork_intervention_admissions",
                "fia1_cbor",
                4,
                Value::Integer(3.into()),
            ),
        ] {
            let path = directory
                .path()
                .join(format!("inconsistent-{index}.sqlite"));
            let (fixture, _) = durable_sqlite_fixture(&path)?;
            let connection = Connection::open(&path)?;
            let operation_id = Hash::from_bytes([49; 32]);
            let bytes = if table == "fork_append_operations" {
                connection.query_row(
                    &format!("SELECT {column} FROM {table} WHERE operation_id = ?1"),
                    params![operation_id.as_bytes().as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
            } else {
                connection.query_row(
                    &format!(
                        "SELECT {column} FROM {table} WHERE event_id = (\
                         SELECT event_id FROM fork_append_operations WHERE operation_id = ?1)"
                    ),
                    params![operation_id.as_bytes().as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )?
            };
            let replacement = replace_cbor_field(&bytes, field, replacement)?;
            let changed = if table == "fork_append_operations" {
                connection.execute(
                    &format!("UPDATE {table} SET {column} = ?1 WHERE operation_id = ?2"),
                    params![replacement, operation_id.as_bytes().as_slice()],
                )?
            } else {
                connection.execute(
                    &format!(
                        "UPDATE {table} SET {column} = ?1 WHERE event_id = (\
                         SELECT event_id FROM fork_append_operations WHERE operation_id = ?2)"
                    ),
                    params![replacement, operation_id.as_bytes().as_slice()],
                )?
            };
            assert_eq!(changed, 1, "{table}.{column} fixture must be present");
            let store = sqlite_store_at(&path)?;
            assert_eq!(
                store.read_fork_event_suffix(fixture.fork.child_id, 1),
                Err(ForkEventAuthorityErrorV1::CorruptAuthority),
                "inconsistent {table}.{column} must make the suffix unavailable"
            );
        }
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_recovery_rejects_event_content_that_diverges_from_request(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("recovery-content-mismatch.sqlite");
        let (fixture, external_draft) = durable_sqlite_fixture(&path)?;
        let operation_id = Hash::from_bytes([49; 32]);
        let changed = Connection::open(&path)?.execute(
            "UPDATE events SET payload = ?1 WHERE event_id = (\
             SELECT event_id FROM fork_append_operations WHERE operation_id = ?2)",
            params![
                b"tampered-event-content".to_vec(),
                operation_id.as_bytes().as_slice()
            ],
        )?;
        assert_eq!(changed, 1);
        let mut store = sqlite_store_at(&path)?;
        let (session, issuer, permit) = reopened_external_permit(&mut store, &fixture)?;
        assert_eq!(
            store.recover_classified_append(&session, &permit, operation_id, &external_draft),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        drop(issuer);
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_append_rolls_back_when_provenance_persistence_fails(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("classified-append-rollback.sqlite");
        let mut store = sqlite_store_at(&path)?;
        let fixture = create_lifecycle(&mut store)?;
        let permit = store.issue_append_source_permit(
            &fixture.issuer,
            &fixture.session,
            fixture.fork.child_id,
            &fixture.source,
            ForkAppendSourceIdentityV1::HostInternal,
        )?;
        Connection::open(&path)?.execute_batch(
            "CREATE TRIGGER reject_fork_event_origin
             BEFORE INSERT ON fork_event_origins
             BEGIN SELECT RAISE(ABORT, 'injected provenance failure'); END;",
        )?;

        assert_eq!(
            store.append_classified(
                &fixture.session,
                &permit,
                Hash::from_bytes([61; 32]),
                draft(b"rollback-on-origin-failure"),
            ),
            Err(ForkEventAuthorityErrorV1::StorageIndeterminate)
        );
        assert!(store
            .read_fork_event_suffix(fixture.fork.child_id, 1)?
            .is_empty());
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classifier_registration_rolls_back_when_source_persistence_fails(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory
            .path()
            .join("classifier-registration-rollback.sqlite");
        let mut store = sqlite_store_at(&path)?;
        let fixture = create_lifecycle(&mut store)?;
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let verified = evidence(&adapter, &policy)?;
        let parent = store.create_timeline("classifier-registration-parent")?;
        let command = command(
            &store,
            &host,
            &verified,
            &fixture.session,
            [62; 32],
            "FCC1",
            Some(parent.id()),
        )?;
        let ForkAdmissionOperationResultV1::Fork(fork) =
            store.execute_fork_admission_command(&fixture.session, &policy, &command)?
        else {
            return Err("FCC1 did not return a Fork receipt".into());
        };
        let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: fixture.source.input().room_revision_descriptor_hash,
            registrar_identifier: "registration-failure.test".to_owned(),
            routes: fixture.source.input().routes.clone(),
        })?;
        Connection::open(&path)?.execute_batch(
            "CREATE TRIGGER reject_fork_classifier_source
             BEFORE INSERT ON fork_classifier_sources
             BEGIN SELECT RAISE(ABORT, 'injected classifier source failure'); END;",
        )?;
        let registrar = store.issue_classifier_registrar_permit(
            &fixture.issuer,
            &fixture.session,
            fork.child_id,
            source,
        )?;

        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar,
                Hash::from_bytes([63; 32]),
                fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::StorageIndeterminate)
        );
        assert_eq!(
            Connection::open(&path)?.query_row(
                "SELECT COUNT(*) FROM fork_classifier_tables WHERE child_id = ?1",
                params![fork.child_id.to_string()],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
        Ok(())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_classified_suffix_rejects_operation_with_wrong_logical_sequence(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("classified-suffix-sequence.sqlite");
        let (fixture, _) = durable_sqlite_fixture(&path)?;
        let operation_id = Hash::from_bytes([49; 32]);
        let connection = Connection::open(&path)?;
        let bytes = connection.query_row(
            "SELECT fop1_cbor FROM fork_append_operations WHERE operation_id = ?1",
            params![operation_id.as_bytes().as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let replacement = replace_cbor_field(&bytes, 4, Value::Integer(3.into()))?;
        assert_eq!(
            connection.execute(
                "UPDATE fork_append_operations SET fop1_cbor = ?1 WHERE operation_id = ?2",
                params![replacement, operation_id.as_bytes().as_slice()],
            )?,
            1
        );

        assert_eq!(
            sqlite_store_at(&path)?.read_fork_event_suffix(fixture.fork.child_id, 1),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    /// ADR-099 r10 section 411 and r11 section 3: deregistration revokes an
    /// issued permit, each append and recovery requires the exact current
    /// scope, and every permit ends with its issuer.
    fn assert_live_scope_is_required_at_append<S>(store: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        let mut fixture = create_lifecycle(store)?;
        let child = fixture.fork.child_id;
        let external = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "gateway.adapter".to_owned(),
            source: fixture.external.clone(),
        };
        let permit = store.issue_append_source_permit(
            &fixture.issuer,
            &fixture.session,
            child,
            &fixture.source,
            external.clone(),
        )?;
        let committed_draft = draft(b"before-revocation");
        let committed = store.append_classified(
            &fixture.session,
            &permit,
            Hash::from_bytes([80; 32]),
            committed_draft.clone(),
        )?;

        fixture.issuer.revoke_external_adapter("gateway.adapter");
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &permit,
                Hash::from_bytes([81; 32]),
                draft(b"after-revocation"),
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store.recover_classified_append(
                &fixture.session,
                &permit,
                Hash::from_bytes([80; 32]),
                &committed_draft,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(store.read_fork_event_suffix(child, 1)?.len(), 1);

        // A profile row unequal to the durable FCS1 cannot reissue a permit.
        let unequal = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: fixture.source.input().room_revision_descriptor_hash,
            registrar_identifier: fixture.source.input().registrar_identifier.clone(),
            routes: vec![ForkExternalInputRouteV1::new(
                fixture.external.clone(),
                false,
            )],
        })?;
        assert_eq!(
            store
                .issue_append_source_permit(
                    &fixture.issuer,
                    &fixture.session,
                    child,
                    &unequal,
                    ForkAppendSourceIdentityV1::HostInternal,
                )
                .err(),
            Some(ForkEventAuthorityErrorV1::Conflict)
        );

        // Renewing the adapter scope reissues a permit for exact recovery.
        fixture.issuer.trust_external_source(external.clone());
        let reissued = store.issue_append_source_permit(
            &fixture.issuer,
            &fixture.session,
            child,
            &fixture.source,
            external,
        )?;
        assert_eq!(
            store.recover_classified_append(
                &fixture.session,
                &reissued,
                Hash::from_bytes([80; 32]),
                &committed_draft,
            )?,
            Some(committed)
        );

        assert_permits_end_with_their_issuer(store, fixture, &reissued)
    }

    /// Dropping the issuer ends every permit it issued, including registrar
    /// permits, so no Event or registration can follow.
    fn assert_permits_end_with_their_issuer<S>(
        store: &mut S,
        fixture: LifecycleFixtureV1,
        reissued: &ForkAppendSourcePermitV1,
    ) -> Result<(), Box<dyn Error>>
    where
        S: ForkEventProvenanceAuthorityPortV1 + ForkEventPermitIssuerPortV1,
    {
        let child = fixture.fork.child_id;
        let host = store.issue_append_source_permit(
            &fixture.issuer,
            &fixture.session,
            child,
            &fixture.source,
            ForkAppendSourceIdentityV1::HostInternal,
        )?;
        let registrar = store.issue_classifier_registrar_permit(
            &fixture.issuer,
            &fixture.session,
            child,
            fixture.source.clone(),
        )?;
        let LifecycleFixtureV1 {
            session, issuer, ..
        } = fixture;
        drop(issuer);
        for (permit, operation) in [(&host, 82), (reissued, 83)] {
            assert_eq!(
                store.append_classified(
                    &session,
                    permit,
                    Hash::from_bytes([operation; 32]),
                    draft(b"after-issuer"),
                ),
                Err(ForkEventAuthorityErrorV1::Unauthenticated)
            );
        }
        assert_eq!(
            store.register_classifier(&session, &registrar, Hash::from_bytes([46; 32]), child),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(store.read_fork_event_suffix(child, 1)?.len(), 1);
        Ok(())
    }

    #[test]
    fn memory_append_requires_the_live_issuer_scope() -> Result<(), Box<dyn Error>> {
        assert_live_scope_is_required_at_append(&mut MemoryStore::new())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_append_requires_the_live_issuer_scope() -> Result<(), Box<dyn Error>> {
        assert_live_scope_is_required_at_append(&mut SqliteStore::open_in_memory()?)
    }

    #[test]
    fn a_session_yields_one_issuer_bound_to_it() -> Result<(), Box<dyn Error>> {
        let mut store = MemoryStore::new();
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let mut session = open_session(&mut store, &host, &policy(&adapter)?)?;
        let issuer = session
            .take_event_permit_issuer()
            .ok_or("a new session yields its issuer")?;
        assert!(session.take_event_permit_issuer().is_none());
        assert!(issuer.matches(&session));
        let reopened = reopen_session(&mut store, &host, &policy(&adapter)?)?;
        assert!(!issuer.matches(&reopened));
        Ok(())
    }

    /// ADR-099 r11 migration step 2: the read-only preflight accepts only
    /// durable FCS1 rows that are exact profile rows.
    fn assert_profile_preflight_and_admission_read<S>(store: &mut S) -> Result<(), Box<dyn Error>>
    where
        S: EventStore
            + ForkAdmissionAuthorityBootstrapPortV1
            + ForkAdmissionAuthorityPortV1
            + ForkEventProvenanceAuthorityPortV1
            + ForkEventPermitIssuerPortV1,
    {
        assert_eq!(store.preflight_fork_classifier_profile(&[]), Ok(()));
        let fixture = create_lifecycle(store)?;
        let other = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: Hash::from_bytes([90; 32]),
            registrar_identifier: fixture.source.input().registrar_identifier.clone(),
            routes: Vec::new(),
        })?;
        assert_eq!(
            store.preflight_fork_classifier_profile(&[fixture.source.clone(), other.clone()]),
            Ok(())
        );
        assert_eq!(
            store.preflight_fork_classifier_profile(&[other]),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        assert_eq!(
            store.preflight_fork_classifier_profile(&[]),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        assert_eq!(
            store
                .read_validated_local_fork_admission(fixture.fork.child_id)?
                .digest(),
            fixture.fork.admission_digest
        );
        assert_eq!(
            store
                .read_validated_local_fork_admission(TimelineId::new())
                .err(),
            Some(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    #[test]
    fn memory_profile_preflight_requires_exact_profile_rows() -> Result<(), Box<dyn Error>> {
        assert_profile_preflight_and_admission_read(&mut MemoryStore::new())
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_profile_preflight_requires_exact_profile_rows() -> Result<(), Box<dyn Error>> {
        assert_profile_preflight_and_admission_read(&mut SqliteStore::open_in_memory()?)
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_profile_preflight_fails_closed_on_malformed_durable_sources(
    ) -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        for (case, expected) in [
            ("malformed", ForkEventAuthorityErrorV1::CorruptAuthority),
            ("mis-keyed", ForkEventAuthorityErrorV1::CorruptAuthority),
            (
                "mis-registered",
                ForkEventAuthorityErrorV1::CorruptAuthority,
            ),
            (
                "unreadable",
                ForkEventAuthorityErrorV1::StorageIndeterminate,
            ),
        ] {
            let path = directory.path().join(format!("preflight-{case}.sqlite"));
            let store = {
                let mut store = sqlite_store_at(&path)?;
                let fixture = create_lifecycle(&mut store)?;
                assert_eq!(
                    store.preflight_fork_classifier_profile(std::slice::from_ref(&fixture.source)),
                    Ok(())
                );
                store
            };
            let conn = Connection::open(&path)?;
            match case {
                "malformed" => {
                    conn.execute(
                        "UPDATE fork_classifier_sources SET fcs1_cbor = ?1",
                        params![vec![0_u8]],
                    )?;
                }
                "mis-keyed" => {
                    conn.execute(
                        "UPDATE fork_classifier_sources SET descriptor_hash = ?1",
                        params![vec![91_u8; 32]],
                    )?;
                }
                "mis-registered" => {
                    conn.execute(
                        "UPDATE fork_classifier_sources SET registrar_identifier = ?1",
                        params!["another-registrar"],
                    )?;
                }
                _ => conn.execute_batch("DROP TABLE fork_classifier_sources")?,
            }
            drop(conn);
            assert_eq!(store.preflight_fork_classifier_profile(&[]), Err(expected));
        }
        Ok(())
    }
}
