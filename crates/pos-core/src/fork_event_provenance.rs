//! Local Fork Event-origin and intervention-admission records from ADR-099.
//!
//! These codecs establish neither Fork admission nor append authority. A
//! trusted host must use them with the admitted-Fork append transaction.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    CorrelationId, EntityId, Event, EventDraft, EventId, ForkAdmissionRecordV1, Hash, TimelineId,
    WallTime,
};

/// Maximum accepted `EOR1` bytes.
pub const MAX_EVENT_ORIGIN_RECORD_BYTES_V1: usize = 384;
/// Maximum accepted `FIA1` bytes.
pub const MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1: usize = 512;
/// Maximum UTF-8 bytes in one trusted source route.
pub const MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1: usize = 128;
/// Maximum UTF-8 bytes in one stable host registrar identifier.
pub const MAX_FORK_EVENT_REGISTRAR_BYTES_V1: usize = 64;
/// Maximum external routes retained by one immutable classifier table.
pub const MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1: usize = 1024;
/// Maximum accepted `FCS1` or `FCT1` bytes.
pub const MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1: usize = 196_608;
/// Maximum accepted `FCR1` bytes.
pub const MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1: usize = 192;
/// Maximum accepted `FOP1` bytes.
pub const MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1: usize = 768;
/// Maximum exact payload bytes in a `FEQ1` append request.
pub const MAX_FORK_EVENT_APPEND_PAYLOAD_BYTES_V1: usize = 16_777_216;
/// Maximum UTF-8 bytes in one Event type in a `FEQ1` request.
pub const MAX_FORK_EVENT_TYPE_BYTES_V1: usize = 256;

const EVENT_ORIGIN_DOMAIN: &[u8] = b"pigloros/event-origin/v1";
const INTERVENTION_ADMISSION_DOMAIN: &[u8] = b"pigloros/fork-intervention-admission/v1";
const CLASSIFIER_SOURCE_DOMAIN: &[u8] = b"pigloros/fork-classifier-source/v1";
const CLASSIFIER_TABLE_DOMAIN: &[u8] = b"pigloros/fork-classifier-table/v1";
const CLASSIFIER_REGISTRATION_DOMAIN: &[u8] = b"pigloros/fork-classifier-registration/v1";
const APPEND_REQUEST_DOMAIN: &[u8] = b"pigloros/fork-event-append-request/v1";
const APPEND_OPERATION_DOMAIN: &[u8] = b"pigloros/fork-append-operation/v1";

/// Closed errors for local Fork Event-provenance codecs and classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkEventProvenanceErrorV1 {
    #[error("invalid Fork Event-provenance encoding")]
    InvalidEncoding,
    #[error("noncanonical Fork Event-provenance encoding")]
    NonCanonical,
    #[error("unsupported Fork Event-provenance version")]
    UnsupportedVersion,
    #[error("Fork Event-provenance field is out of bounds")]
    FieldOutOfBounds,
    #[error("Fork Event-provenance origin is unavailable")]
    ImportedAuthorityUnavailable,
    #[error("Fork Event-provenance classification is impossible")]
    ImpossibleClassification,
    #[error("Fork Event source route is not admitted")]
    SourceRejected,
    #[error("Fork Event classifier has duplicate routes")]
    DuplicateSourceRoute,
}

/// Closed storage-boundary failures for classifier registration and classified append.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkEventAuthorityErrorV1 {
    #[error("Fork Event authority request is invalid")]
    InvalidRequest,
    #[error("Fork Event authority permit is unavailable")]
    Unauthenticated,
    #[error("Fork Event authority conflicts with a committed operation")]
    Conflict,
    #[error("Fork Event authority is corrupt")]
    CorruptAuthority,
    #[error("Fork Event authority storage outcome is indeterminate")]
    StorageIndeterminate,
}

/// Opaque binding issued by one trusted classifier composition root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkEventAuthorityBindingV1 {
    host_id: u64,
}

/// Opaque permit to register one trusted host classifier for an admitted Fork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierRegistrationRequestV1 {
    binding: ForkEventAuthorityBindingV1,
    operation_id: Hash,
    admission: ForkAdmissionRecordV1,
    source: ForkClassifierSourceV1,
}

impl ForkClassifierRegistrationRequestV1 {
    #[must_use]
    pub const fn binding(&self) -> ForkEventAuthorityBindingV1 {
        self.binding
    }
    #[must_use]
    pub const fn operation_id(&self) -> Hash {
        self.operation_id
    }
    #[must_use]
    pub const fn admission(&self) -> &ForkAdmissionRecordV1 {
        &self.admission
    }
    #[must_use]
    pub const fn source(&self) -> &ForkClassifierSourceV1 {
        &self.source
    }
}

/// Opaque permit for one host-resolved classified append source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAppendSourcePermitV1 {
    binding: ForkEventAuthorityBindingV1,
    child_timeline_id: TimelineId,
    fork_admission_digest: Hash,
    source: ForkAppendSourceIdentityV1,
}

impl ForkAppendSourcePermitV1 {
    #[must_use]
    pub const fn binding(&self) -> ForkEventAuthorityBindingV1 {
        self.binding
    }
    #[must_use]
    pub const fn child_timeline_id(&self) -> TimelineId {
        self.child_timeline_id
    }
    #[must_use]
    pub const fn fork_admission_digest(&self) -> Hash {
        self.fork_admission_digest
    }
    #[must_use]
    pub const fn source(&self) -> &ForkAppendSourceIdentityV1 {
        &self.source
    }
}

/// Receipt returned only after a complete immutable classifier registration commits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkClassifierRegistrationReceiptV1 {
    pub child_timeline_id: TimelineId,
    pub classifier_revision_digest: Hash,
    pub registration_digest: Hash,
}

/// Receipt returned only after one Event and all provenance rows commit together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifiedAppendReceiptV1 {
    pub event: Event,
    pub operation: ForkAppendOperationV1,
}

/// Host-owned classifier composition root.
#[derive(Debug)]
pub struct ForkEventAuthorityHostV1 {
    binding: ForkEventAuthorityBindingV1,
    registrar_identifier: String,
    routes: Vec<ForkExternalInputRouteV1>,
}

static NEXT_FORK_EVENT_AUTHORITY_HOST_ID: AtomicU64 = AtomicU64::new(1);

impl ForkEventAuthorityHostV1 {
    /// Construct trusted immutable classifier configuration.
    pub fn new(
        registrar_identifier: String,
        mut routes: Vec<ForkExternalInputRouteV1>,
    ) -> Result<Self, ForkEventProvenanceErrorV1> {
        validate_classifier_fields(
            Hash::from_bytes([1; 32]),
            &registrar_identifier,
            &mut routes,
        )?;
        Ok(Self {
            binding: ForkEventAuthorityBindingV1 {
                host_id: NEXT_FORK_EVENT_AUTHORITY_HOST_ID.fetch_add(1, Ordering::Relaxed),
            },
            registrar_identifier,
            routes,
        })
    }

    #[must_use]
    pub const fn binding(&self) -> ForkEventAuthorityBindingV1 {
        self.binding
    }

    /// Permit registration using only a locally admitted Fork record.
    pub fn permit_registration(
        &self,
        operation_id: Hash,
        admission: ForkAdmissionRecordV1,
    ) -> Result<ForkClassifierRegistrationRequestV1, ForkEventProvenanceErrorV1> {
        if operation_id == Hash::zero() {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            registrar_identifier: self.registrar_identifier.clone(),
            routes: self.routes.clone(),
        })?;
        Ok(ForkClassifierRegistrationRequestV1 {
            binding: self.binding,
            operation_id,
            admission,
            source,
        })
    }

    /// Permit a host-internal append after the caller has resolved admitted authority.
    #[must_use]
    pub fn permit_host_internal(
        &self,
        child_timeline_id: TimelineId,
        fork_admission_digest: Hash,
    ) -> ForkAppendSourcePermitV1 {
        ForkAppendSourcePermitV1 {
            binding: self.binding,
            child_timeline_id,
            fork_admission_digest,
            source: ForkAppendSourceIdentityV1::HostInternal,
        }
    }

    /// Permit one configured external route for the exact admitted Fork.
    pub fn permit_external_input(
        &self,
        child_timeline_id: TimelineId,
        fork_admission_digest: Hash,
        adapter_identifier: String,
        source: ForkEventSourceDescriptorV1,
    ) -> Result<ForkAppendSourcePermitV1, ForkEventProvenanceErrorV1> {
        let known = self
            .routes
            .binary_search_by(|route| route.source.cmp(&source))
            .is_ok();
        let source = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier,
            source,
        };
        source.validate()?;
        if !known {
            return Err(ForkEventProvenanceErrorV1::SourceRejected);
        }
        Ok(ForkAppendSourcePermitV1 {
            binding: self.binding,
            child_timeline_id,
            fork_admission_digest,
            source,
        })
    }
}

/// Durable classifier registration, classified append, operation recovery, and suffix-read port.
pub trait ForkEventProvenanceAuthorityPortV1 {
    fn bind_fork_event_authority_host(
        &mut self,
        binding: ForkEventAuthorityBindingV1,
    ) -> Result<(), ForkEventAuthorityErrorV1>;
    fn register_classifier(
        &mut self,
        request: &ForkClassifierRegistrationRequestV1,
    ) -> Result<ForkClassifierRegistrationReceiptV1, ForkEventAuthorityErrorV1>;
    fn append_classified(
        &mut self,
        permit: &ForkAppendSourcePermitV1,
        operation_id: Hash,
        draft: EventDraft,
    ) -> Result<ForkClassifiedAppendReceiptV1, ForkEventAuthorityErrorV1>;
    fn recover_classified_append(
        &self,
        permit: &ForkAppendSourcePermitV1,
        operation_id: Hash,
        draft: &EventDraft,
    ) -> Result<Option<ForkClassifiedAppendReceiptV1>, ForkEventAuthorityErrorV1>;
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

/// The source class selected by the trusted host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkEventOriginKindV1 {
    /// Deterministic host output.
    HostInternal,
    /// A trusted external input route.
    ExternalInput,
}

/// One total classifier result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkEventClassificationV1 {
    origin: ForkEventOriginKindV1,
    intervention: bool,
}

impl ForkEventClassificationV1 {
    /// Construct one valid origin/intervention pair.
    ///
    /// # Errors
    /// Rejects an intervention attributed to host-internal output.
    pub const fn new(
        origin: ForkEventOriginKindV1,
        intervention: bool,
    ) -> Result<Self, ForkEventProvenanceErrorV1> {
        match origin {
            ForkEventOriginKindV1::HostInternal if intervention => {
                return Err(ForkEventProvenanceErrorV1::ImpossibleClassification);
            }
            ForkEventOriginKindV1::HostInternal | ForkEventOriginKindV1::ExternalInput => {}
        }
        Ok(Self {
            origin,
            intervention,
        })
    }

    #[must_use]
    pub const fn origin(self) -> ForkEventOriginKindV1 {
        self.origin
    }

    #[must_use]
    pub const fn intervention(self) -> bool {
        self.intervention
    }
}

/// A host-owned descriptor of one external ingress route and its schema.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ForkEventSourceDescriptorV1 {
    route: String,
    schema_digest: Hash,
}

impl ForkEventSourceDescriptorV1 {
    /// Construct an exact trusted-source descriptor.
    ///
    /// # Errors
    /// Rejects an empty or overlong route and an absent schema digest.
    pub fn new(
        route: impl Into<String>,
        schema_digest: Hash,
    ) -> Result<Self, ForkEventProvenanceErrorV1> {
        let route = route.into();
        if route.is_empty()
            || route.len() > MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1
            || schema_digest == Hash::zero()
        {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        Ok(Self {
            route,
            schema_digest,
        })
    }

    #[must_use]
    pub fn route(&self) -> &str {
        &self.route
    }

    #[must_use]
    pub const fn schema_digest(&self) -> Hash {
        self.schema_digest
    }
}

/// A source descriptor presented to the trusted host append authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkEventSourceV1 {
    /// The trusted host produced this Event internally.
    HostInternal,
    /// The Event entered through this trusted external source descriptor.
    ExternalInput(ForkEventSourceDescriptorV1),
}

/// One route in an admitted room revision's complete external-input table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkExternalInputRouteV1 {
    source: ForkEventSourceDescriptorV1,
    intervention: bool,
}

/// Durable source custody (`FCS1`) selected only by a trusted host registrar.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierSourceInputV1 {
    pub room_revision_descriptor_hash: Hash,
    pub registrar_identifier: String,
    pub routes: Vec<ForkExternalInputRouteV1>,
}

/// Strict canonical `FCS1` bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierSourceV1(ForkClassifierSourceInputV1);

impl ForkClassifierSourceV1 {
    /// Construct complete immutable source custody.
    pub fn new(mut input: ForkClassifierSourceInputV1) -> Result<Self, ForkEventProvenanceErrorV1> {
        validate_classifier_fields(
            input.room_revision_descriptor_hash,
            &input.registrar_identifier,
            &mut input.routes,
        )?;
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkClassifierSourceInputV1 {
        &self.0
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(160 + value.routes.len() * 80);
        array(&mut out, 5);
        text(&mut out, "FCS1");
        uint(&mut out, 1);
        hash(&mut out, value.room_revision_descriptor_hash);
        text(&mut out, &value.registrar_identifier);
        encode_routes(&mut out, &value.routes);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(CLASSIFIER_SOURCE_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical source-custody bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkEventProvenanceErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1)?;
        wire.array(5)?;
        wire.magic(*b"FCS1")?;
        wire.version()?;
        let room_revision_descriptor_hash = wire.hash()?;
        let registrar_identifier = wire.text(MAX_FORK_EVENT_REGISTRAR_BYTES_V1)?;
        let routes = wire.routes()?;
        wire.finish()?;
        let record = Self::new(ForkClassifierSourceInputV1 {
            room_revision_descriptor_hash,
            registrar_identifier,
            routes,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Construction fields for a per-Fork classifier (`FCT1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierTableInputV1 {
    pub child_timeline_id: TimelineId,
    pub fork_admission_digest: Hash,
    pub room_revision_descriptor_hash: Hash,
    pub registrar_identifier: String,
    pub source_configuration_revision_digest: Hash,
    pub routes: Vec<ForkExternalInputRouteV1>,
}

/// Strict canonical admitted per-Fork classifier table (`FCT1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierTableV1(ForkClassifierTableInputV1);

impl ForkClassifierTableV1 {
    /// Construct one immutable classifier table.
    pub fn new(mut input: ForkClassifierTableInputV1) -> Result<Self, ForkEventProvenanceErrorV1> {
        if input.fork_admission_digest == Hash::zero()
            || input.source_configuration_revision_digest == Hash::zero()
        {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        validate_classifier_fields(
            input.room_revision_descriptor_hash,
            &input.registrar_identifier,
            &mut input.routes,
        )?;
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkClassifierTableInputV1 {
        &self.0
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(224 + value.routes.len() * 80);
        array(&mut out, 8);
        text(&mut out, "FCT1");
        uint(&mut out, 1);
        timeline(&mut out, value.child_timeline_id);
        hash(&mut out, value.fork_admission_digest);
        hash(&mut out, value.room_revision_descriptor_hash);
        text(&mut out, &value.registrar_identifier);
        hash(&mut out, value.source_configuration_revision_digest);
        encode_routes(&mut out, &value.routes);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(CLASSIFIER_TABLE_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical table bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkEventProvenanceErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1)?;
        wire.array(8)?;
        wire.magic(*b"FCT1")?;
        wire.version()?;
        let child_timeline_id = wire.timeline()?;
        let fork_admission_digest = wire.hash()?;
        let room_revision_descriptor_hash = wire.hash()?;
        let registrar_identifier = wire.text(MAX_FORK_EVENT_REGISTRAR_BYTES_V1)?;
        let source_configuration_revision_digest = wire.hash()?;
        let routes = wire.routes()?;
        wire.finish()?;
        let record = Self::new(ForkClassifierTableInputV1 {
            child_timeline_id,
            fork_admission_digest,
            room_revision_descriptor_hash,
            registrar_identifier,
            source_configuration_revision_digest,
            routes,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Construction fields for one classifier-registration evidence record (`FCR1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierRegistrationInputV1 {
    pub operation_id: Hash,
    pub child_timeline_id: TimelineId,
    pub fork_admission_digest: Hash,
    pub room_revision_descriptor_hash: Hash,
    pub classifier_revision_digest: Hash,
}

/// Strict canonical immutable classifier-registration evidence (`FCR1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierRegistrationV1(ForkClassifierRegistrationInputV1);

impl ForkClassifierRegistrationV1 {
    /// Construct one registration record.
    pub fn new(
        input: ForkClassifierRegistrationInputV1,
    ) -> Result<Self, ForkEventProvenanceErrorV1> {
        if input.operation_id == Hash::zero()
            || input.fork_admission_digest == Hash::zero()
            || input.room_revision_descriptor_hash == Hash::zero()
            || input.classifier_revision_digest == Hash::zero()
        {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkClassifierRegistrationInputV1 {
        &self.0
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(192);
        array(&mut out, 7);
        text(&mut out, "FCR1");
        uint(&mut out, 1);
        hash(&mut out, value.operation_id);
        timeline(&mut out, value.child_timeline_id);
        hash(&mut out, value.fork_admission_digest);
        hash(&mut out, value.room_revision_descriptor_hash);
        hash(&mut out, value.classifier_revision_digest);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(CLASSIFIER_REGISTRATION_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical registration evidence bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkEventProvenanceErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1)?;
        wire.array(7)?;
        wire.magic(*b"FCR1")?;
        wire.version()?;
        let operation_id = wire.hash()?;
        let child_timeline_id = wire.timeline()?;
        let fork_admission_digest = wire.hash()?;
        let room_revision_descriptor_hash = wire.hash()?;
        let classifier_revision_digest = wire.hash()?;
        wire.finish()?;
        let record = Self::new(ForkClassifierRegistrationInputV1 {
            operation_id,
            child_timeline_id,
            fork_admission_digest,
            room_revision_descriptor_hash,
            classifier_revision_digest,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Host-owned source identity retained by `FEQ1` and `FOP1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkAppendSourceIdentityV1 {
    /// The trusted host produced the Event internally.
    HostInternal,
    /// A trusted registered adapter supplied an exact admitted external route.
    ExternalInput {
        adapter_identifier: String,
        source: ForkEventSourceDescriptorV1,
    },
}

impl ForkAppendSourceIdentityV1 {
    fn validate(&self) -> Result<(), ForkEventProvenanceErrorV1> {
        match self {
            Self::HostInternal => Ok(()),
            Self::ExternalInput {
                adapter_identifier, ..
            } if !adapter_identifier.is_empty()
                && adapter_identifier.len() <= MAX_FORK_EVENT_REGISTRAR_BYTES_V1 =>
            {
                Ok(())
            }
            Self::ExternalInput { .. } => Err(ForkEventProvenanceErrorV1::FieldOutOfBounds),
        }
    }
}

/// Exact deterministic-CBOR hash preimage (`FEQ1`) for one classified append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkEventAppendRequestV1 {
    pub operation_id: Hash,
    pub child_timeline_id: TimelineId,
    pub source: ForkAppendSourceIdentityV1,
    pub entity_id: EntityId,
    pub event_type: String,
    pub payload: Vec<u8>,
    pub causation_id: Option<EventId>,
    pub correlation_id: Option<CorrelationId>,
    pub wall_time_override: Option<WallTime>,
}

impl ForkEventAppendRequestV1 {
    /// Validate and construct an exact append request preimage.
    pub fn new(input: Self) -> Result<Self, ForkEventProvenanceErrorV1> {
        if input.operation_id == Hash::zero()
            || input.event_type.is_empty()
            || input.event_type.len() > MAX_FORK_EVENT_TYPE_BYTES_V1
            || input.payload.len() > MAX_FORK_EVENT_APPEND_PAYLOAD_BYTES_V1
        {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        input.source.validate()?;
        Ok(input)
    }

    /// Encode the exact `FEQ1` canonical bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.event_type.len() + self.payload.len());
        array(&mut out, 12);
        text(&mut out, "FEQ1");
        uint(&mut out, 1);
        hash(&mut out, self.operation_id);
        timeline(&mut out, self.child_timeline_id);
        encode_source(&mut out, &self.source);
        entity(&mut out, self.entity_id);
        text(&mut out, &self.event_type);
        bytes(&mut out, &self.payload);
        optional_event(&mut out, self.causation_id);
        optional_correlation(&mut out, self.correlation_id);
        uint(&mut out, 1);
        optional_wall_time(&mut out, self.wall_time_override);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(APPEND_REQUEST_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical append-request preimage bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkEventProvenanceErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_EVENT_APPEND_PAYLOAD_BYTES_V1 + 784)?;
        wire.array(12)?;
        wire.magic(*b"FEQ1")?;
        wire.version()?;
        let operation_id = wire.hash()?;
        let child_timeline_id = wire.timeline()?;
        let source = wire.source()?;
        let entity_id = wire.entity()?;
        let event_type = wire.text(MAX_FORK_EVENT_TYPE_BYTES_V1)?;
        let payload = wire.bytes(MAX_FORK_EVENT_APPEND_PAYLOAD_BYTES_V1)?;
        let causation_id = wire.optional_event()?;
        let correlation_id = wire.optional_correlation()?;
        wire.version()?;
        let value = Self::new(Self {
            operation_id,
            child_timeline_id,
            source,
            entity_id,
            event_type,
            payload,
            causation_id,
            correlation_id,
            wall_time_override: wire.optional_wall_time()?,
        })?;
        wire.finish()?;
        canonical(bytes_in, &value.to_canonical_cbor())?;
        Ok(value)
    }
}

/// Construction fields for immutable append-operation evidence (`FOP1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAppendOperationInputV1 {
    pub operation_id: Hash,
    pub child_timeline_id: TimelineId,
    pub logical_seq: u64,
    pub event_id: EventId,
    pub request_digest: Hash,
    pub source: ForkAppendSourceIdentityV1,
    pub wall_time: WallTime,
    pub payload_hash: Hash,
    pub classifier_revision_digest: Hash,
    pub fork_admission_digest: Hash,
    pub event_origin_digest: Hash,
    pub intervention_admission_digest: Option<Hash>,
}

/// Strict canonical append-operation evidence (`FOP1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAppendOperationV1(ForkAppendOperationInputV1);

impl ForkAppendOperationV1 {
    /// Construct one committed append-operation record.
    pub fn new(input: ForkAppendOperationInputV1) -> Result<Self, ForkEventProvenanceErrorV1> {
        if input.operation_id == Hash::zero()
            || input.logical_seq == 0
            || input.request_digest == Hash::zero()
            || input.payload_hash == Hash::zero()
            || input.classifier_revision_digest == Hash::zero()
            || input.fork_admission_digest == Hash::zero()
            || input.event_origin_digest == Hash::zero()
            || input.intervention_admission_digest == Some(Hash::zero())
        {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        input.source.validate()?;
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkAppendOperationInputV1 {
        &self.0
    }

    /// Encode exact `FOP1` canonical bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(384);
        array(&mut out, 14);
        text(&mut out, "FOP1");
        uint(&mut out, 1);
        hash(&mut out, value.operation_id);
        timeline(&mut out, value.child_timeline_id);
        uint(&mut out, value.logical_seq);
        event(&mut out, value.event_id);
        hash(&mut out, value.request_digest);
        encode_source(&mut out, &value.source);
        uint(&mut out, value.wall_time.as_micros());
        hash(&mut out, value.payload_hash);
        hash(&mut out, value.classifier_revision_digest);
        hash(&mut out, value.fork_admission_digest);
        hash(&mut out, value.event_origin_digest);
        optional_hash(&mut out, value.intervention_admission_digest);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(APPEND_OPERATION_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical append-operation evidence bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkEventProvenanceErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1)?;
        wire.array(14)?;
        wire.magic(*b"FOP1")?;
        wire.version()?;
        let value = Self::new(ForkAppendOperationInputV1 {
            operation_id: wire.hash()?,
            child_timeline_id: wire.timeline()?,
            logical_seq: wire.uint()?,
            event_id: wire.event()?,
            request_digest: wire.hash()?,
            source: wire.source()?,
            wall_time: WallTime::from_micros(wire.uint()?),
            payload_hash: wire.hash()?,
            classifier_revision_digest: wire.hash()?,
            fork_admission_digest: wire.hash()?,
            event_origin_digest: wire.hash()?,
            intervention_admission_digest: wire.optional_hash()?,
        })?;
        wire.finish()?;
        canonical(bytes_in, &value.to_canonical_cbor())?;
        Ok(value)
    }
}

impl ForkExternalInputRouteV1 {
    #[must_use]
    pub const fn new(source: ForkEventSourceDescriptorV1, intervention: bool) -> Self {
        Self {
            source,
            intervention,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &ForkEventSourceDescriptorV1 {
        &self.source
    }

    #[must_use]
    pub const fn intervention(&self) -> bool {
        self.intervention
    }
}

/// A complete, revision-bound classifier for every host append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkEventClassifierV1 {
    revision_digest: Hash,
    external_routes: Vec<ForkExternalInputRouteV1>,
}

impl ForkEventClassifierV1 {
    /// Construct a classifier from the complete admitted external-input table.
    ///
    /// # Errors
    /// Rejects an absent revision digest or duplicate route/schema descriptors.
    pub fn new(
        revision_digest: Hash,
        mut external_routes: Vec<ForkExternalInputRouteV1>,
    ) -> Result<Self, ForkEventProvenanceErrorV1> {
        if revision_digest == Hash::zero() {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        external_routes.sort_unstable_by(|left, right| left.source.cmp(&right.source));
        if external_routes
            .windows(2)
            .any(|routes| routes[0].source == routes[1].source)
        {
            return Err(ForkEventProvenanceErrorV1::DuplicateSourceRoute);
        }
        Ok(Self {
            revision_digest,
            external_routes,
        })
    }

    #[must_use]
    pub const fn revision_digest(&self) -> Hash {
        self.revision_digest
    }

    /// Classify one source descriptor with no caller-selected result.
    ///
    /// # Errors
    /// Rejects an external route/schema absent from the admitted table.
    pub fn classify(
        &self,
        source: &ForkEventSourceV1,
    ) -> Result<ForkEventClassificationV1, ForkEventProvenanceErrorV1> {
        match source {
            ForkEventSourceV1::HostInternal => {
                ForkEventClassificationV1::new(ForkEventOriginKindV1::HostInternal, false)
            }
            ForkEventSourceV1::ExternalInput(source) => self
                .external_routes
                .binary_search_by(|route| route.source.cmp(source))
                .map_err(|_| ForkEventProvenanceErrorV1::SourceRejected)
                .and_then(|index| {
                    ForkEventClassificationV1::new(
                        ForkEventOriginKindV1::ExternalInput,
                        self.external_routes[index].intervention,
                    )
                }),
        }
    }
}

/// Construction fields for one exact `EOR1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventOriginRecordInputV1 {
    pub fork_timeline_id: TimelineId,
    pub logical_seq: u64,
    pub event_id: EventId,
    pub classification: ForkEventClassificationV1,
    pub classifier_revision_digest: Hash,
    pub fork_admission_digest: Hash,
}

/// Strict local `EOR1` bytes for one admitted child Event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventOriginRecordV1(EventOriginRecordInputV1);

impl EventOriginRecordV1 {
    /// Construct one origin record.
    ///
    /// # Errors
    /// Rejects a zero logical sequence or absent authority digests.
    pub fn new(input: EventOriginRecordInputV1) -> Result<Self, ForkEventProvenanceErrorV1> {
        if input.logical_seq == 0
            || input.classifier_revision_digest == Hash::zero()
            || input.fork_admission_digest == Hash::zero()
        {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &EventOriginRecordInputV1 {
        &self.0
    }

    /// Encode the exact nine-field deterministic-CBOR `EOR1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(160);
        array(&mut out, 9);
        text(&mut out, "EOR1");
        uint(&mut out, 1);
        timeline(&mut out, value.fork_timeline_id);
        uint(&mut out, value.logical_seq);
        event(&mut out, value.event_id);
        uint(
            &mut out,
            u64::from(value.classification.origin() == ForkEventOriginKindV1::ExternalInput),
        );
        uint(&mut out, u64::from(value.classification.intervention()));
        hash(&mut out, value.classifier_revision_digest);
        hash(&mut out, value.fork_admission_digest);
        out
    }

    /// Return the domain-separated digest over complete canonical `EOR1` bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(EVENT_ORIGIN_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode only exact canonical local-origin `EOR1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, noncanonical, or unavailable-origin bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkEventProvenanceErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_EVENT_ORIGIN_RECORD_BYTES_V1)?;
        wire.array(9)?;
        wire.magic(*b"EOR1")?;
        wire.version()?;
        let fork_timeline_id = wire.timeline()?;
        let logical_seq = wire.uint()?;
        let event_id = wire.event()?;
        let origin = wire.origin()?;
        let intervention = wire.bool()?;
        let classifier_revision_digest = wire.hash()?;
        let fork_admission_digest = wire.hash()?;
        wire.finish()?;
        let classification = ForkEventClassificationV1::new(origin, intervention)?;
        let record = Self::new(EventOriginRecordInputV1 {
            fork_timeline_id,
            logical_seq,
            event_id,
            classification,
            classifier_revision_digest,
            fork_admission_digest,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Construction fields for one exact `FIA1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkInterventionAdmissionInputV1 {
    pub operation_id: Hash,
    pub fork_timeline_id: TimelineId,
    pub logical_seq: u64,
    pub event_id: EventId,
    pub payload_hash: Hash,
    pub room_revision_descriptor_hash: Hash,
    pub classifier_revision_digest: Hash,
    pub fork_admission_digest: Hash,
}

/// Strict local `FIA1` bytes for one classified external intervention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkInterventionAdmissionV1(ForkInterventionAdmissionInputV1);

impl ForkInterventionAdmissionV1 {
    /// Construct one intervention admission.
    ///
    /// # Errors
    /// Rejects a zero operation, sequence, or authority field.
    pub fn new(
        input: ForkInterventionAdmissionInputV1,
    ) -> Result<Self, ForkEventProvenanceErrorV1> {
        if input.operation_id == Hash::zero()
            || input.logical_seq == 0
            || input.payload_hash == Hash::zero()
            || input.room_revision_descriptor_hash == Hash::zero()
            || input.classifier_revision_digest == Hash::zero()
            || input.fork_admission_digest == Hash::zero()
        {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkInterventionAdmissionInputV1 {
        &self.0
    }

    /// Encode the exact ten-field deterministic-CBOR `FIA1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(224);
        array(&mut out, 10);
        text(&mut out, "FIA1");
        uint(&mut out, 1);
        hash(&mut out, value.operation_id);
        timeline(&mut out, value.fork_timeline_id);
        uint(&mut out, value.logical_seq);
        event(&mut out, value.event_id);
        hash(&mut out, value.payload_hash);
        hash(&mut out, value.room_revision_descriptor_hash);
        hash(&mut out, value.classifier_revision_digest);
        hash(&mut out, value.fork_admission_digest);
        out
    }

    /// Return the domain-separated digest over complete canonical `FIA1` bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(INTERVENTION_ADMISSION_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode only exact canonical local-origin `FIA1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, or noncanonical bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkEventProvenanceErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1)?;
        wire.array(10)?;
        wire.magic(*b"FIA1")?;
        wire.version()?;
        let operation_id = wire.hash()?;
        let fork_timeline_id = wire.timeline()?;
        let logical_seq = wire.uint()?;
        let event_id = wire.event()?;
        let payload_hash = wire.hash()?;
        let room_revision_descriptor_hash = wire.hash()?;
        let classifier_revision_digest = wire.hash()?;
        let fork_admission_digest = wire.hash()?;
        wire.finish()?;
        let record = Self::new(ForkInterventionAdmissionInputV1 {
            operation_id,
            fork_timeline_id,
            logical_seq,
            event_id,
            payload_hash,
            room_revision_descriptor_hash,
            classifier_revision_digest,
            fork_admission_digest,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

fn domain_digest(domain: &[u8], bytes_in: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes_in);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}
fn text(out: &mut Vec<u8>, value: &str) {
    head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn timeline(out: &mut Vec<u8>, value: TimelineId) {
    bytes(out, &value.inner().to_bytes());
}
fn event(out: &mut Vec<u8>, value: EventId) {
    bytes(out, &value.inner().to_bytes());
}
fn hash(out: &mut Vec<u8>, value: Hash) {
    bytes(out, value.as_bytes());
}
fn array(out: &mut Vec<u8>, value: u64) {
    head(out, 4, value);
}
fn uint(out: &mut Vec<u8>, value: u64) {
    head(out, 0, value);
}
fn head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    if value < 24 {
        out.push(tag | value.to_be_bytes()[7]);
    } else if let Ok(value) = u8::try_from(value) {
        out.extend_from_slice(&[tag | 0x18, value]);
    } else if let Ok(value) = u16::try_from(value) {
        out.push(tag | 0x19);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        out.push(tag | 0x1a);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(tag | 0x1b);
        out.extend_from_slice(&value.to_be_bytes());
    }
}
fn canonical(actual: &[u8], expected: &[u8]) -> Result<(), ForkEventProvenanceErrorV1> {
    if actual == expected {
        Ok(())
    } else {
        Err(ForkEventProvenanceErrorV1::NonCanonical)
    }
}

fn validate_classifier_fields(
    descriptor_hash: Hash,
    registrar_identifier: &str,
    routes: &mut Vec<ForkExternalInputRouteV1>,
) -> Result<(), ForkEventProvenanceErrorV1> {
    if descriptor_hash == Hash::zero()
        || registrar_identifier.is_empty()
        || registrar_identifier.len() > MAX_FORK_EVENT_REGISTRAR_BYTES_V1
        || routes.len() > MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1
    {
        return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
    }
    routes.sort_unstable_by(|left, right| left.source.cmp(&right.source));
    if routes
        .windows(2)
        .any(|pair| pair[0].source == pair[1].source)
    {
        return Err(ForkEventProvenanceErrorV1::DuplicateSourceRoute);
    }
    Ok(())
}

fn encode_routes(out: &mut Vec<u8>, routes: &[ForkExternalInputRouteV1]) {
    array(out, routes.len() as u64);
    for route in routes {
        array(out, 3);
        text(out, route.source.route());
        hash(out, route.source.schema_digest());
        uint(out, u64::from(route.intervention));
    }
}

fn encode_source(out: &mut Vec<u8>, source: &ForkAppendSourceIdentityV1) {
    match source {
        ForkAppendSourceIdentityV1::HostInternal => array(out, 1),
        ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier,
            source,
        } => {
            array(out, 4);
            uint(out, 1);
            text(out, adapter_identifier);
            text(out, source.route());
            hash(out, source.schema_digest());
            return;
        }
    }
    uint(out, 0);
}

fn entity(out: &mut Vec<u8>, value: EntityId) {
    bytes(out, &value.inner().to_bytes());
}
fn optional_event(out: &mut Vec<u8>, value: Option<EventId>) {
    if let Some(value) = value {
        event(out, value);
    } else {
        out.push(0xf6);
    }
}
fn optional_correlation(out: &mut Vec<u8>, value: Option<CorrelationId>) {
    if let Some(value) = value {
        bytes(out, &value.inner().to_bytes());
    } else {
        out.push(0xf6);
    }
}
fn optional_wall_time(out: &mut Vec<u8>, value: Option<WallTime>) {
    if let Some(value) = value {
        uint(out, value.as_micros());
    } else {
        out.push(0xf6);
    }
}
fn optional_hash(out: &mut Vec<u8>, value: Option<Hash>) {
    if let Some(value) = value {
        hash(out, value);
    } else {
        out.push(0xf6);
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, ForkEventProvenanceErrorV1> {
        if bytes.len() > maximum {
            Err(ForkEventProvenanceErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self { bytes, offset: 0 })
        }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ForkEventProvenanceErrorV1> {
        // Every caller requests at most 32 bytes and `Reader::new` bounds the
        // complete input to 512 bytes, so this addition cannot overflow.
        let end = self.offset + length;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ForkEventProvenanceErrorV1::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
    fn head(&mut self, major: u8) -> Result<u64, ForkEventProvenanceErrorV1> {
        let first = self.take(1)?[0];
        if first >> 5 != major {
            return Err(ForkEventProvenanceErrorV1::InvalidEncoding);
        }
        let additional = first & 31;
        let width = match additional {
            0..=23 => return Ok(u64::from(additional)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(ForkEventProvenanceErrorV1::InvalidEncoding),
        };
        let mut value = 0;
        for byte in self.take(width)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }
    fn array(&mut self, expected: u64) -> Result<(), ForkEventProvenanceErrorV1> {
        if self.head(4)? == expected {
            Ok(())
        } else {
            Err(ForkEventProvenanceErrorV1::InvalidEncoding)
        }
    }
    fn uint(&mut self) -> Result<u64, ForkEventProvenanceErrorV1> {
        self.head(0)
    }
    fn text(&mut self, maximum: usize) -> Result<String, ForkEventProvenanceErrorV1> {
        let length = usize::try_from(self.head(3)?)
            .map_err(|_| ForkEventProvenanceErrorV1::FieldOutOfBounds)?;
        if length == 0 || length > maximum {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| ForkEventProvenanceErrorV1::InvalidEncoding)
    }
    fn routes(&mut self) -> Result<Vec<ForkExternalInputRouteV1>, ForkEventProvenanceErrorV1> {
        let count = usize::try_from(self.head(4)?)
            .map_err(|_| ForkEventProvenanceErrorV1::FieldOutOfBounds)?;
        if count > MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1 {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        let mut routes = Vec::with_capacity(count);
        for _ in 0..count {
            self.array(3)?;
            let source = ForkEventSourceDescriptorV1::new(
                self.text(MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1)?,
                self.hash()?,
            )?;
            routes.push(ForkExternalInputRouteV1::new(source, self.bool()?));
        }
        Ok(routes)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ForkEventProvenanceErrorV1> {
        if self.head(2)? != N as u64 {
            return Err(ForkEventProvenanceErrorV1::InvalidEncoding);
        }
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn hash(&mut self) -> Result<Hash, ForkEventProvenanceErrorV1> {
        Ok(Hash::from_bytes(self.fixed()?))
    }
    fn bytes(&mut self, maximum: usize) -> Result<Vec<u8>, ForkEventProvenanceErrorV1> {
        let length = usize::try_from(self.head(2)?)
            .map_err(|_| ForkEventProvenanceErrorV1::FieldOutOfBounds)?;
        if length > maximum {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        Ok(self.take(length)?.to_vec())
    }
    fn timeline(&mut self) -> Result<TimelineId, ForkEventProvenanceErrorV1> {
        Ok(TimelineId::from_ulid(ulid::Ulid::from_bytes(self.fixed()?)))
    }
    fn event(&mut self) -> Result<EventId, ForkEventProvenanceErrorV1> {
        Ok(EventId::from_ulid(ulid::Ulid::from_bytes(self.fixed()?)))
    }
    fn entity(&mut self) -> Result<EntityId, ForkEventProvenanceErrorV1> {
        Ok(EntityId::from_ulid(ulid::Ulid::from_bytes(self.fixed()?)))
    }
    fn null(&mut self) -> Result<bool, ForkEventProvenanceErrorV1> {
        if self.bytes.get(self.offset) == Some(&0xf6) {
            self.offset += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn optional_event(&mut self) -> Result<Option<EventId>, ForkEventProvenanceErrorV1> {
        if self.null()? {
            Ok(None)
        } else {
            self.event().map(Some)
        }
    }
    fn optional_correlation(
        &mut self,
    ) -> Result<Option<CorrelationId>, ForkEventProvenanceErrorV1> {
        if self.null()? {
            Ok(None)
        } else {
            Ok(Some(CorrelationId::from_ulid(ulid::Ulid::from_bytes(
                self.fixed()?,
            ))))
        }
    }
    fn optional_wall_time(&mut self) -> Result<Option<WallTime>, ForkEventProvenanceErrorV1> {
        if self.null()? {
            Ok(None)
        } else {
            self.uint().map(WallTime::from_micros).map(Some)
        }
    }
    fn optional_hash(&mut self) -> Result<Option<Hash>, ForkEventProvenanceErrorV1> {
        if self.null()? {
            Ok(None)
        } else {
            self.hash().map(Some)
        }
    }
    fn source(&mut self) -> Result<ForkAppendSourceIdentityV1, ForkEventProvenanceErrorV1> {
        match self.head(4)? {
            1 => {
                if self.uint()? == 0 {
                    Ok(ForkAppendSourceIdentityV1::HostInternal)
                } else {
                    Err(ForkEventProvenanceErrorV1::InvalidEncoding)
                }
            }
            4 => {
                if self.uint()? != 1 {
                    return Err(ForkEventProvenanceErrorV1::InvalidEncoding);
                }
                let adapter_identifier = self.text(MAX_FORK_EVENT_REGISTRAR_BYTES_V1)?;
                let source = ForkEventSourceDescriptorV1::new(
                    self.text(MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1)?,
                    self.hash()?,
                )?;
                let source = ForkAppendSourceIdentityV1::ExternalInput {
                    adapter_identifier,
                    source,
                };
                source.validate()?;
                Ok(source)
            }
            _ => Err(ForkEventProvenanceErrorV1::InvalidEncoding),
        }
    }
    fn bool(&mut self) -> Result<bool, ForkEventProvenanceErrorV1> {
        match self.uint()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ForkEventProvenanceErrorV1::InvalidEncoding),
        }
    }
    fn origin(&mut self) -> Result<ForkEventOriginKindV1, ForkEventProvenanceErrorV1> {
        match self.uint()? {
            0 => Ok(ForkEventOriginKindV1::HostInternal),
            1 => Ok(ForkEventOriginKindV1::ExternalInput),
            2 => Err(ForkEventProvenanceErrorV1::ImportedAuthorityUnavailable),
            _ => Err(ForkEventProvenanceErrorV1::InvalidEncoding),
        }
    }
    fn magic(&mut self, expected: [u8; 4]) -> Result<(), ForkEventProvenanceErrorV1> {
        if self.head(3)? == 4 && self.take(4)? == expected {
            Ok(())
        } else {
            Err(ForkEventProvenanceErrorV1::InvalidEncoding)
        }
    }
    fn version(&mut self) -> Result<(), ForkEventProvenanceErrorV1> {
        if self.uint()? == 1 {
            Ok(())
        } else {
            Err(ForkEventProvenanceErrorV1::UnsupportedVersion)
        }
    }
    const fn finish(&self) -> Result<(), ForkEventProvenanceErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ForkEventProvenanceErrorV1::InvalidEncoding)
        }
    }
}
