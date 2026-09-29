//! Store-owned ADR-099 revision 10 classifier and append authority boundary.
//!
//! The durable records live in `pos-core`; this module deliberately keeps the
//! live authority capability in `pos-store`, alongside the non-cloneable
//! admission session that establishes its store binding.

use pos_core::{
    Event, EventDraft, EventOriginRecordV1, ForkAppendOperationV1, ForkAppendSourceIdentityV1,
    ForkClassifierSourceV1, ForkEventAppendRequestV1, ForkInterventionAdmissionV1, Hash,
    TimelineId,
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
/// #468's composition root is the sole future issuer. No public or
/// session-derived constructor exists because an admission session alone does
/// not select a classifier table.
pub struct ForkClassifierRegistrarPermitV1 {
    store_id: Hash,
    registrar_identifier: String,
    source: ForkClassifierSourceV1,
}

/// Nonserializable host capability for one classified append source scope.
///
/// #468's composition root must issue this only after validating live host
/// adapter registration and the complete FAR1/FCS1/FCT1/FCR1 closure.
pub struct ForkAppendSourcePermitV1 {
    store_id: Hash,
    child_timeline_id: TimelineId,
    fork_admission_digest: Hash,
    classifier_revision_digest: Hash,
    registrar_identifier: String,
    source: ForkAppendSourceIdentityV1,
}

impl ForkClassifierRegistrarPermitV1 {
    pub(crate) const fn source(&self) -> &ForkClassifierSourceV1 {
        &self.source
    }
    pub(crate) const fn store_id(&self) -> Hash {
        self.store_id
    }
    pub(crate) fn registrar_identifier(&self) -> &str {
        &self.registrar_identifier
    }
}

impl ForkAppendSourcePermitV1 {
    pub(crate) const fn source(&self) -> &ForkAppendSourceIdentityV1 {
        &self.source
    }
    pub(crate) const fn store_id(&self) -> Hash {
        self.store_id
    }
    pub(crate) const fn child_timeline_id(&self) -> TimelineId {
        self.child_timeline_id
    }
    pub(crate) const fn fork_admission_digest(&self) -> Hash {
        self.fork_admission_digest
    }
    pub(crate) const fn classifier_revision_digest(&self) -> Hash {
        self.classifier_revision_digest
    }
    pub(crate) fn registrar_identifier(&self) -> &str {
        &self.registrar_identifier
    }
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

    fn registrar_permit(
        store_id: Hash,
        source: ForkClassifierSourceV1,
    ) -> ForkClassifierRegistrarPermitV1 {
        ForkClassifierRegistrarPermitV1 {
            store_id,
            registrar_identifier: source.input().registrar_identifier.clone(),
            source,
        }
    }

    fn append_permit(
        store_id: Hash,
        child_timeline_id: TimelineId,
        fork_admission_digest: Hash,
        classifier_revision_digest: Hash,
        registrar_identifier: &str,
        source: ForkAppendSourceIdentityV1,
    ) -> ForkAppendSourcePermitV1 {
        ForkAppendSourcePermitV1 {
            store_id,
            child_timeline_id,
            fork_admission_digest,
            classifier_revision_digest,
            registrar_identifier: registrar_identifier.to_owned(),
            source,
        }
    }

    struct LifecycleFixtureV1 {
        session: ForkAdmissionAuthoritySessionV1,
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
            + ForkEventProvenanceAuthorityPortV1,
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
            + ForkEventProvenanceAuthorityPortV1,
    {
        store.bind_erasure_gate(std::sync::Arc::new(
            pos_core::ErasureContainmentGateV1::new_test_open(),
        ))?;
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
            + ForkEventProvenanceAuthorityPortV1,
    {
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let session = open_session(store, &host, &policy)?;
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
        let registration = register_classifier(store, &session, store_id, &source, fork.child_id)?;
        Ok(LifecycleFixtureV1 {
            session,
            store_id,
            fork,
            source,
            registration,
            external,
            external_non_intervention,
        })
    }

    fn register_classifier<S>(
        store: &mut S,
        session: &ForkAdmissionAuthoritySessionV1,
        store_id: Hash,
        source: &ForkClassifierSourceV1,
        child_timeline_id: TimelineId,
    ) -> Result<ForkClassifierRegistrationReceiptV1, Box<dyn Error>>
    where
        S: ForkEventProvenanceAuthorityPortV1,
    {
        let registrar = registrar_permit(store_id, source.clone());
        assert_eq!(
            store.register_classifier(
                session,
                &registrar_permit(Hash::from_bytes([54; 32]), source.clone()),
                Hash::from_bytes([46; 32]),
                child_timeline_id,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        let mismatched_registrar = ForkClassifierRegistrarPermitV1 {
            store_id,
            registrar_identifier: "foreign-registrar".to_owned(),
            source: source.clone(),
        };
        assert_eq!(
            store.register_classifier(
                session,
                &mismatched_registrar,
                Hash::from_bytes([46; 32]),
                child_timeline_id,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
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
        S: ForkEventProvenanceAuthorityPortV1,
    {
        let host_permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::HostInternal,
        );
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &append_permit(
                    fixture.store_id,
                    fixture.fork.child_id,
                    Hash::from_bytes([55; 32]),
                    fixture.registration.classifier_revision_digest,
                    fixture.source.input().registrar_identifier.as_str(),
                    ForkAppendSourceIdentityV1::HostInternal,
                ),
                Hash::from_bytes([47; 32]),
                draft(b"wrong-admission"),
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &append_permit(
                    fixture.store_id,
                    fixture.fork.child_id,
                    fixture.fork.admission_digest,
                    fixture.registration.classifier_revision_digest,
                    "foreign-registrar",
                    ForkAppendSourceIdentityV1::HostInternal,
                ),
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
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(fixture.store_id, fixture.source.clone()),
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
        S: ForkAdmissionAuthorityBootstrapPortV1 + ForkEventProvenanceAuthorityPortV1,
    {
        let permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: fixture.external.clone(),
            },
        );
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
        let non_intervention_permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "bridge.adapter".to_owned(),
                source: fixture.external_non_intervention.clone(),
            },
        );
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
        assert_classifier_registration_and_append_scope_are_immutable(store, fixture)?;
        assert_external_rejections(store, fixture, &permit, &external_draft, receipt)
    }

    fn assert_classifier_registration_and_append_scope_are_immutable<S>(
        store: &mut S,
        fixture: &LifecycleFixtureV1,
    ) -> Result<(), Box<dyn Error>>
    where
        S: ForkEventProvenanceAuthorityPortV1,
    {
        let mismatched_admission_source =
            ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
                room_revision_descriptor_hash: Hash::from_bytes([54; 32]),
                registrar_identifier: fixture.source.input().registrar_identifier.clone(),
                routes: fixture.source.input().routes.clone(),
            })?;
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(fixture.store_id, mismatched_admission_source),
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
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(fixture.store_id, replacement_source),
                Hash::from_bytes([46; 32]),
                fixture.fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(fixture.store_id, fixture.source.clone()),
                Hash::from_bytes([57; 32]),
                fixture.fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Conflict)
        );
        let missing_child = append_permit(
            fixture.store_id,
            TimelineId::new(),
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::HostInternal,
        );
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &missing_child,
                Hash::from_bytes([58; 32]),
                draft(b"missing-admitted-child"),
            ),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        Ok(())
    }

    fn assert_external_rejections<S>(
        store: &mut S,
        fixture: &LifecycleFixtureV1,
        permit: &ForkAppendSourcePermitV1,
        external_draft: &EventDraft,
        receipt: ForkClassifiedAppendReceiptV1,
    ) -> Result<(), Box<dyn Error>>
    where
        S: ForkAdmissionAuthorityBootstrapPortV1 + ForkEventProvenanceAuthorityPortV1,
    {
        let rejected = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
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
        let foreign_store = append_permit(
            Hash::from_bytes([52; 32]),
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::HostInternal,
        );
        assert_eq!(
            store.append_classified(
                &fixture.session,
                &foreign_store,
                Hash::from_bytes([53; 32]),
                draft(b"foreign"),
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let current = reopen_session(store, &host, &policy)?;
        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(fixture.store_id, fixture.source.clone()),
                Hash::from_bytes([46; 32]),
                fixture.fork.child_id,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store.recover_classified_append(
                &fixture.session,
                permit,
                Hash::from_bytes([49; 32]),
                external_draft,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        assert_eq!(
            store.recover_classified_append(
                &current,
                &foreign_store,
                Hash::from_bytes([49; 32]),
                external_draft,
            ),
            Err(ForkEventAuthorityErrorV1::Unauthenticated)
        );
        let missing_child = append_permit(
            fixture.store_id,
            TimelineId::new(),
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::HostInternal,
        );
        assert_eq!(
            store.recover_classified_append(
                &current,
                &missing_child,
                Hash::from_bytes([49; 32]),
                external_draft,
            ),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
        assert_eq!(
            store.recover_classified_append(
                &current,
                permit,
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
            + ForkEventProvenanceAuthorityPortV1,
    {
        let fixture = create_lifecycle(store)?;
        let permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::HostInternal,
        );
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
        let permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::HostInternal,
        );
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

    #[test]
    fn memory_classified_append_port_preserves_provenance_and_authority(
    ) -> Result<(), Box<dyn Error>> {
        assert_lifecycle(&mut MemoryStore::new())
    }

    #[test]
    fn memory_rejects_generic_append_to_admitted_fork() -> Result<(), Box<dyn Error>> {
        assert_generic_fork_append_is_rejected(&mut MemoryStore::new())
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
        let permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: fixture.external.clone(),
            },
        );
        let external_draft = draft(b"external-intervention");
        store.append_classified(
            &fixture.session,
            &permit,
            Hash::from_bytes([49; 32]),
            external_draft.clone(),
        )?;
        Ok((fixture, external_draft))
    }

    #[cfg(feature = "sqlite")]
    fn reopened_external_permit(
        store: &mut SqliteStore,
        fixture: &LifecycleFixtureV1,
    ) -> Result<(ForkAdmissionAuthoritySessionV1, ForkAppendSourcePermitV1), Box<dyn Error>> {
        let host = ForkHostSigningKeyV1::from_seed([41; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([42; 32])?;
        let policy = policy(&adapter)?;
        let session = reopen_session(store, &host, &policy)?;
        let permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: fixture.external.clone(),
            },
        );
        Ok((session, permit))
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
            let external_permit = append_permit(
                fixture.store_id,
                fixture.fork.child_id,
                fixture.fork.admission_digest,
                fixture.registration.classifier_revision_digest,
                fixture.source.input().registrar_identifier.as_str(),
                ForkAppendSourceIdentityV1::ExternalInput {
                    adapter_identifier: "gateway.adapter".to_owned(),
                    source: fixture.external.clone(),
                },
            );
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
        let external_permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::ExternalInput {
                adapter_identifier: "gateway.adapter".to_owned(),
                source: fixture.external.clone(),
            },
        );
        assert_eq!(
            store.recover_classified_append(
                &session,
                &external_permit,
                Hash::from_bytes([49; 32]),
                &external_draft,
            )?,
            Some(external_receipt)
        );
        let host_permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::HostInternal,
        );
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
            let mut store = sqlite_store_at(&path)?;
            let (session, permit) = reopened_external_permit(&mut store, &fixture)?;
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
            let (session, permit) = reopened_external_permit(&mut store, &fixture)?;
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
        let (session, permit) = reopened_external_permit(&mut store, &fixture)?;
        assert_eq!(
            store.recover_classified_append(&session, &permit, operation_id, &external_draft),
            Err(ForkEventAuthorityErrorV1::CorruptAuthority)
        );
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
        let permit = append_permit(
            fixture.store_id,
            fixture.fork.child_id,
            fixture.fork.admission_digest,
            fixture.registration.classifier_revision_digest,
            fixture.source.input().registrar_identifier.as_str(),
            ForkAppendSourceIdentityV1::HostInternal,
        );
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

        assert_eq!(
            store.register_classifier(
                &fixture.session,
                &registrar_permit(fixture.store_id, source),
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
}
