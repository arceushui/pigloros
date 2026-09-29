//! Local Fork Event-origin and intervention-admission records from ADR-099.
//!
//! These codecs establish neither Fork admission nor append authority. A
//! trusted host must use them with the admitted-Fork append transaction.

use crate::{CorrelationId, EntityId, EventId, ForkAdmissionRecordV1, Hash, TimelineId, WallTime};

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
/// Maximum non-payload `FEQ1` bytes; ADR-099 bounds `FEQ1` to 16,778,000 bytes.
const FEQ1_ENVELOPE_BYTES: usize = 784;
/// Maximum accepted `FEQ1` bytes, including its exact payload.
const MAX_FEQ1_BYTES: usize = MAX_FORK_EVENT_APPEND_PAYLOAD_BYTES_V1 + FEQ1_ENVELOPE_BYTES;

/// Initial encoder capacity for fixed `FCS1` fields.
const FCS1_FIXED_CAPACITY: usize = 160;
/// Initial encoder capacity for fixed `FCT1` fields.
const FCT1_FIXED_CAPACITY: usize = 224;
/// Initial encoder capacity reserved for each encoded classifier route.
const ROUTE_CAPACITY: usize = 80;
/// Initial encoder capacity for fixed `FEQ1` fields.
const FEQ1_FIXED_CAPACITY: usize = 256;
/// Initial encoder capacity for one `EOR1` record.
const EOR1_CAPACITY: usize = 160;
/// Initial encoder capacity for one `FIA1` record.
const FIA1_CAPACITY: usize = 224;
/// Initial encoder capacity for one `FOP1` record.
const FOP1_CAPACITY: usize = 384;

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
    /// The bytes are not the expected deterministic-CBOR record shape.
    #[error("invalid Fork Event-provenance encoding")]
    InvalidEncoding,
    /// The bytes decode but differ from their strict canonical re-encoding.
    #[error("noncanonical Fork Event-provenance encoding")]
    NonCanonical,
    /// The record carries a version other than 1.
    #[error("unsupported Fork Event-provenance version")]
    UnsupportedVersion,
    /// A required field is absent, zero, empty, or exceeds its bound.
    #[error("Fork Event-provenance field is out of bounds")]
    FieldOutOfBounds,
    /// The record claims imported origin, which remains unavailable until #447.
    #[error("Fork Event-provenance origin is unavailable")]
    ImportedAuthorityUnavailable,
    /// The origin/intervention pair is `(0,1)`, which ADR-099 rejects.
    #[error("Fork Event-provenance classification is impossible")]
    ImpossibleClassification,
    /// The external route/schema is absent from the admitted classifier table.
    #[error("Fork Event source route is not admitted")]
    SourceRejected,
    /// The classifier table repeats one `(route, schema digest)` pair.
    #[error("Fork Event classifier has duplicate routes")]
    DuplicateSourceRoute,
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
    /// Admitted room revision descriptor hash that keys this source custody.
    pub room_revision_descriptor_hash: Hash,
    /// Stable host registrar identifier that selected the table.
    pub registrar_identifier: String,
    /// Complete external-input route table, canonicalized by construction.
    pub routes: Vec<ForkExternalInputRouteV1>,
}

/// Strict canonical `FCS1` bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierSourceV1(ForkClassifierSourceInputV1);

impl ForkClassifierSourceV1 {
    /// Construct complete immutable source custody.
    ///
    /// # Errors
    /// Returns an error when the descriptor, registrar, or routes are invalid.
    pub fn new(mut input: ForkClassifierSourceInputV1) -> Result<Self, ForkEventProvenanceErrorV1> {
        validate_classifier_fields(
            input.room_revision_descriptor_hash,
            &input.registrar_identifier,
            &mut input.routes,
        )
        .map(|()| Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkClassifierSourceInputV1 {
        &self.0
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(FCS1_FIXED_CAPACITY + value.routes.len() * ROUTE_CAPACITY);
        encode_array(&mut out, 5);
        encode_text(&mut out, "FCS1");
        encode_uint(&mut out, 1);
        encode_hash(&mut out, value.room_revision_descriptor_hash);
        encode_text(&mut out, &value.registrar_identifier);
        encode_routes(&mut out, &value.routes);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(CLASSIFIER_SOURCE_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical source-custody bytes.
    ///
    /// # Errors
    /// Returns an error when bytes are malformed, noncanonical, or out of bounds.
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
        canonical(bytes_in, &record.to_canonical_cbor()).map(|()| record)
    }
}

/// Construction fields for a per-Fork classifier (`FCT1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierTableInputV1 {
    /// Admitted child Fork bound by this table.
    pub child_timeline_id: TimelineId,
    /// Digest of the child's local `FAR1`.
    pub fork_admission_digest: Hash,
    /// Room revision descriptor hash admitted by `FAR1`.
    pub room_revision_descriptor_hash: Hash,
    /// Stable host registrar identifier from the selected `FCS1`.
    pub registrar_identifier: String,
    /// Digest of the selected `FCS1`.
    pub source_configuration_revision_digest: Hash,
    /// Route rows copied byte-for-byte from the selected `FCS1`.
    pub routes: Vec<ForkExternalInputRouteV1>,
}

/// Strict canonical admitted per-Fork classifier table (`FCT1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierTableV1(ForkClassifierTableInputV1);

impl ForkClassifierTableV1 {
    /// Construct one immutable classifier table.
    ///
    /// # Errors
    /// Returns an error when mandatory provenance fields or routes are invalid.
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

    /// Bind one already-validated `FCS1` to its locally admitted child `FAR1`.
    ///
    /// Both records enforce their required nonzero fields and canonical routes,
    /// so the table is infallible. The trusted registrar must still reject an
    /// `FCS1` whose room descriptor differs from the `FAR1` descriptor.
    #[must_use]
    pub fn for_admitted_source(
        admission: &ForkAdmissionRecordV1,
        source: &ForkClassifierSourceV1,
    ) -> Self {
        Self(ForkClassifierTableInputV1 {
            child_timeline_id: admission.input().child_timeline_id,
            fork_admission_digest: admission.digest(),
            room_revision_descriptor_hash: admission.input().room_revision_descriptor_hash,
            registrar_identifier: source.0.registrar_identifier.clone(),
            source_configuration_revision_digest: source.digest(),
            routes: source.0.routes.clone(),
        })
    }

    #[must_use]
    pub const fn input(&self) -> &ForkClassifierTableInputV1 {
        &self.0
    }

    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(FCT1_FIXED_CAPACITY + value.routes.len() * ROUTE_CAPACITY);
        encode_array(&mut out, 8);
        encode_text(&mut out, "FCT1");
        encode_uint(&mut out, 1);
        encode_timeline(&mut out, value.child_timeline_id);
        encode_hash(&mut out, value.fork_admission_digest);
        encode_hash(&mut out, value.room_revision_descriptor_hash);
        encode_text(&mut out, &value.registrar_identifier);
        encode_hash(&mut out, value.source_configuration_revision_digest);
        encode_routes(&mut out, &value.routes);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(CLASSIFIER_TABLE_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical table bytes.
    ///
    /// # Errors
    /// Returns an error when bytes are malformed, noncanonical, or out of bounds.
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
        canonical(bytes_in, &record.to_canonical_cbor()).map(|()| record)
    }
}

/// Construction fields for one classifier-registration evidence record (`FCR1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierRegistrationInputV1 {
    /// Stable registration operation ID.
    pub operation_id: Hash,
    /// Admitted child Fork whose classifier was registered.
    pub child_timeline_id: TimelineId,
    /// Digest of the child's local `FAR1`.
    pub fork_admission_digest: Hash,
    /// Room revision descriptor hash admitted by `FAR1`.
    pub room_revision_descriptor_hash: Hash,
    /// Digest of the registered `FCT1`.
    pub classifier_revision_digest: Hash,
}

/// Strict canonical immutable classifier-registration evidence (`FCR1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifierRegistrationV1(ForkClassifierRegistrationInputV1);

impl ForkClassifierRegistrationV1 {
    /// Construct one registration record.
    ///
    /// # Errors
    /// Returns an error when mandatory registration fields are absent.
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
        let mut out = Vec::with_capacity(MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1);
        encode_array(&mut out, 7);
        encode_text(&mut out, "FCR1");
        encode_uint(&mut out, 1);
        encode_hash(&mut out, value.operation_id);
        encode_timeline(&mut out, value.child_timeline_id);
        encode_hash(&mut out, value.fork_admission_digest);
        encode_hash(&mut out, value.room_revision_descriptor_hash);
        encode_hash(&mut out, value.classifier_revision_digest);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(CLASSIFIER_REGISTRATION_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical registration evidence bytes.
    ///
    /// # Errors
    /// Returns an error when bytes are malformed, noncanonical, or out of bounds.
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
        canonical(bytes_in, &record.to_canonical_cbor()).map(|()| record)
    }
}

/// Host-owned source identity retained by `FEQ1` and `FOP1`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkAppendSourceIdentityV1 {
    /// The trusted host produced the Event internally.
    HostInternal,
    /// A trusted registered adapter supplied an exact admitted external route.
    ExternalInput {
        /// Stable host-registered adapter identifier.
        adapter_identifier: String,
        /// Exact admitted route/schema descriptor.
        source: ForkEventSourceDescriptorV1,
    },
}

impl ForkAppendSourceIdentityV1 {
    const fn validate(&self) -> Result<(), ForkEventProvenanceErrorV1> {
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
    /// Stable append operation ID.
    pub operation_id: Hash,
    /// Admitted child Fork receiving the Event.
    pub child_timeline_id: TimelineId,
    /// Host-resolved source identity.
    pub source: ForkAppendSourceIdentityV1,
    /// Draft Entity ID.
    pub entity_id: EntityId,
    /// Draft Event type.
    pub event_type: String,
    /// Exact draft payload bytes.
    pub payload: Vec<u8>,
    /// Optional draft causation Event ID.
    pub causation_id: Option<EventId>,
    /// Optional draft correlation ID.
    pub correlation_id: Option<CorrelationId>,
    /// Optional caller-supplied wall time.
    pub wall_time_override: Option<WallTime>,
}

impl ForkEventAppendRequestV1 {
    /// Validate and construct an exact append request preimage.
    ///
    /// # Errors
    /// Returns an error when required request fields or source identity are invalid.
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
        let mut out =
            Vec::with_capacity(FEQ1_FIXED_CAPACITY + self.event_type.len() + self.payload.len());
        encode_array(&mut out, 12);
        encode_text(&mut out, "FEQ1");
        encode_uint(&mut out, 1);
        encode_hash(&mut out, self.operation_id);
        encode_timeline(&mut out, self.child_timeline_id);
        encode_source(&mut out, &self.source);
        encode_entity(&mut out, self.entity_id);
        encode_text(&mut out, &self.event_type);
        encode_bytes(&mut out, &self.payload);
        encode_optional_event(&mut out, self.causation_id);
        encode_optional_correlation(&mut out, self.correlation_id);
        encode_uint(&mut out, 1);
        encode_optional_wall_time(&mut out, self.wall_time_override);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(APPEND_REQUEST_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical append-request preimage bytes.
    ///
    /// # Errors
    /// Returns an error when bytes are malformed, noncanonical, or out of bounds.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkEventProvenanceErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FEQ1_BYTES)?;
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
        canonical(bytes_in, &value.to_canonical_cbor()).map(|()| value)
    }
}

/// Construction fields for immutable append-operation evidence (`FOP1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAppendOperationInputV1 {
    /// Stable append operation ID.
    pub operation_id: Hash,
    /// Admitted child Fork that received the Event.
    pub child_timeline_id: TimelineId,
    /// Committed logical Timeline sequence.
    pub logical_seq: u64,
    /// Committed Event ID.
    pub event_id: EventId,
    /// Digest of the exact `FEQ1` request.
    pub request_digest: Hash,
    /// Host-resolved source identity.
    pub source: ForkAppendSourceIdentityV1,
    /// Committed Event wall time.
    pub wall_time: WallTime,
    /// Committed Event payload hash.
    pub payload_hash: Hash,
    /// Digest of the child's `FCT1`.
    pub classifier_revision_digest: Hash,
    /// Digest of the child's local `FAR1`.
    pub fork_admission_digest: Hash,
    /// Digest of the committed `EOR1`.
    pub event_origin_digest: Hash,
    /// Digest of the committed `FIA1`, present exactly for `(1,1)`.
    pub intervention_admission_digest: Option<Hash>,
}

/// Strict canonical append-operation evidence (`FOP1`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAppendOperationV1(ForkAppendOperationInputV1);

impl ForkAppendOperationV1 {
    /// Construct one committed append-operation record.
    ///
    /// # Errors
    /// Returns an error when mandatory operation fields or source identity are invalid.
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
        let mut out = Vec::with_capacity(FOP1_CAPACITY);
        encode_array(&mut out, 14);
        encode_text(&mut out, "FOP1");
        encode_uint(&mut out, 1);
        encode_hash(&mut out, value.operation_id);
        encode_timeline(&mut out, value.child_timeline_id);
        encode_uint(&mut out, value.logical_seq);
        encode_event(&mut out, value.event_id);
        encode_hash(&mut out, value.request_digest);
        encode_source(&mut out, &value.source);
        encode_uint(&mut out, value.wall_time.as_micros());
        encode_hash(&mut out, value.payload_hash);
        encode_hash(&mut out, value.classifier_revision_digest);
        encode_hash(&mut out, value.fork_admission_digest);
        encode_hash(&mut out, value.event_origin_digest);
        encode_optional_hash(&mut out, value.intervention_admission_digest);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(APPEND_OPERATION_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode exact canonical append-operation evidence bytes.
    ///
    /// # Errors
    /// Returns an error when bytes are malformed, noncanonical, or out of bounds.
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
        canonical(bytes_in, &value.to_canonical_cbor()).map(|()| value)
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
        sort_unique_routes(&mut external_routes).map(|()| Self {
            revision_digest,
            external_routes,
        })
    }

    /// Construct the classifier bound by one already-validated `FCT1`.
    ///
    /// `FCT1` construction and decoding already enforce a nonzero digest input
    /// and strictly ordered unique routes, so this cannot fail.
    #[must_use]
    pub fn from_table(table: &ForkClassifierTableV1) -> Self {
        Self {
            revision_digest: table.digest(),
            external_routes: table.0.routes.clone(),
        }
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
            ForkEventSourceV1::HostInternal => self.classify_route(None),
            ForkEventSourceV1::ExternalInput(source) => self.classify_route(Some(source)),
        }
    }

    /// Classify the host-owned source identity retained by `FEQ1` and `FOP1`.
    ///
    /// # Errors
    /// Rejects an external route/schema absent from the admitted table.
    pub fn classify_identity(
        &self,
        source: &ForkAppendSourceIdentityV1,
    ) -> Result<ForkEventClassificationV1, ForkEventProvenanceErrorV1> {
        match source {
            ForkAppendSourceIdentityV1::HostInternal => self.classify_route(None),
            ForkAppendSourceIdentityV1::ExternalInput { source, .. } => {
                self.classify_route(Some(source))
            }
        }
    }

    fn classify_route(
        &self,
        source: Option<&ForkEventSourceDescriptorV1>,
    ) -> Result<ForkEventClassificationV1, ForkEventProvenanceErrorV1> {
        source.map_or(
            Ok(ForkEventClassificationV1 {
                origin: ForkEventOriginKindV1::HostInternal,
                intervention: false,
            }),
            |source| {
                self.external_routes
                    .binary_search_by(|route| route.source.cmp(source))
                    .map(|index| ForkEventClassificationV1 {
                        origin: ForkEventOriginKindV1::ExternalInput,
                        intervention: self.external_routes[index].intervention,
                    })
                    .map_err(|_| ForkEventProvenanceErrorV1::SourceRejected)
            },
        )
    }
}

/// Construction fields for one exact `EOR1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventOriginRecordInputV1 {
    /// Admitted child Fork that owns the Event.
    pub fork_timeline_id: TimelineId,
    /// Committed logical Timeline sequence.
    pub logical_seq: u64,
    /// Committed Event ID.
    pub event_id: EventId,
    /// Total classifier result for the Event source.
    pub classification: ForkEventClassificationV1,
    /// Digest of the child's `FCT1`.
    pub classifier_revision_digest: Hash,
    /// Digest of the child's local `FAR1`.
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
        let mut out = Vec::with_capacity(EOR1_CAPACITY);
        encode_array(&mut out, 9);
        encode_text(&mut out, "EOR1");
        encode_uint(&mut out, 1);
        encode_timeline(&mut out, value.fork_timeline_id);
        encode_uint(&mut out, value.logical_seq);
        encode_event(&mut out, value.event_id);
        uint(
            &mut out,
            u64::from(value.classification.origin() == ForkEventOriginKindV1::ExternalInput),
        );
        encode_uint(&mut out, u64::from(value.classification.intervention()));
        encode_hash(&mut out, value.classifier_revision_digest);
        encode_hash(&mut out, value.fork_admission_digest);
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
        canonical(bytes_in, &record.to_canonical_cbor()).map(|()| record)
    }
}

/// Construction fields for one exact `FIA1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkInterventionAdmissionInputV1 {
    /// Stable append operation ID.
    pub operation_id: Hash,
    /// Admitted child Fork that owns the Event.
    pub fork_timeline_id: TimelineId,
    /// Committed logical Timeline sequence.
    pub logical_seq: u64,
    /// Committed Event ID.
    pub event_id: EventId,
    /// Committed Event payload hash.
    pub payload_hash: Hash,
    /// Room revision descriptor hash admitted by `FAR1`.
    pub room_revision_descriptor_hash: Hash,
    /// Digest of the child's `FCT1`.
    pub classifier_revision_digest: Hash,
    /// Digest of the child's local `FAR1`.
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
        let mut out = Vec::with_capacity(FIA1_CAPACITY);
        encode_array(&mut out, 10);
        encode_text(&mut out, "FIA1");
        encode_uint(&mut out, 1);
        encode_hash(&mut out, value.operation_id);
        encode_timeline(&mut out, value.fork_timeline_id);
        encode_uint(&mut out, value.logical_seq);
        encode_event(&mut out, value.event_id);
        encode_hash(&mut out, value.payload_hash);
        encode_hash(&mut out, value.room_revision_descriptor_hash);
        encode_hash(&mut out, value.classifier_revision_digest);
        encode_hash(&mut out, value.fork_admission_digest);
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

/// Committed Event fields bound into one classified append's provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForkClassifiedEventV1 {
    /// Committed Event ID.
    pub event_id: EventId,
    /// Committed logical Timeline sequence.
    pub logical_seq: u64,
    /// Committed Event wall time.
    pub wall_time: WallTime,
    /// Committed Event payload hash.
    pub payload_hash: Hash,
}

/// Complete `EOR1`, optional `FIA1`, and `FOP1` records for one classified append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkClassifiedProvenanceV1 {
    /// Local origin record.
    pub origin: EventOriginRecordV1,
    /// Intervention admission, present exactly for `(1,1)`.
    pub intervention: Option<ForkInterventionAdmissionV1>,
    /// Append-operation evidence binding the request and both records.
    pub operation: ForkAppendOperationV1,
}

impl ForkClassifiedProvenanceV1 {
    /// Derive every provenance record for one classified Event under `table`.
    ///
    /// `classification` must be the result of classifying `request.source`
    /// with [`ForkEventClassifierV1::from_table`] for the same `table`.
    ///
    /// # Errors
    /// Rejects a request for another child, an absent operation ID, an invalid
    /// source identity, a zero logical sequence, or a zero payload hash.
    pub fn derive(
        request: &ForkEventAppendRequestV1,
        table: &ForkClassifierTableV1,
        classification: ForkEventClassificationV1,
        event: ForkClassifiedEventV1,
    ) -> Result<Self, ForkEventProvenanceErrorV1> {
        let complete = request.child_timeline_id == table.0.child_timeline_id
            && request.operation_id != Hash::zero()
            && event.logical_seq != 0
            && event.payload_hash != Hash::zero();
        request
            .source
            .validate()
            .and_then(|()| {
                complete
                    .then_some(())
                    .ok_or(ForkEventProvenanceErrorV1::FieldOutOfBounds)
            })
            .map(|()| {
                let (origin, intervention) = provenance_records(
                    request.operation_id,
                    request.child_timeline_id,
                    event,
                    classification,
                    table.digest(),
                    table.0.fork_admission_digest,
                    table.0.room_revision_descriptor_hash,
                );
                let operation = ForkAppendOperationV1(ForkAppendOperationInputV1 {
                    operation_id: request.operation_id,
                    child_timeline_id: request.child_timeline_id,
                    logical_seq: event.logical_seq,
                    event_id: event.event_id,
                    request_digest: request.digest(),
                    source: request.source.clone(),
                    wall_time: event.wall_time,
                    payload_hash: event.payload_hash,
                    classifier_revision_digest: table.digest(),
                    fork_admission_digest: table.0.fork_admission_digest,
                    event_origin_digest: origin.digest(),
                    intervention_admission_digest: intervention
                        .as_ref()
                        .map(ForkInterventionAdmissionV1::digest),
                });
                Self {
                    origin,
                    intervention,
                    operation,
                }
            })
    }
}

impl ForkAppendOperationV1 {
    /// Derive the exact `EOR1` and optional `FIA1` this operation binds.
    ///
    /// `table` supplies only the admitted room descriptor; every other field
    /// comes from this validated `FOP1`, so the derivation cannot fail.
    #[must_use]
    pub fn expected_provenance(
        &self,
        table: &ForkClassifierTableV1,
        classification: ForkEventClassificationV1,
    ) -> (EventOriginRecordV1, Option<ForkInterventionAdmissionV1>) {
        let value = &self.0;
        provenance_records(
            value.operation_id,
            value.child_timeline_id,
            ForkClassifiedEventV1 {
                event_id: value.event_id,
                logical_seq: value.logical_seq,
                wall_time: value.wall_time,
                payload_hash: value.payload_hash,
            },
            classification,
            value.classifier_revision_digest,
            value.fork_admission_digest,
            table.0.room_revision_descriptor_hash,
        )
    }
}

/// Build `EOR1` and the `(1,1)`-only `FIA1` from already-validated fields.
fn provenance_records(
    operation_id: Hash,
    child_timeline_id: TimelineId,
    event: ForkClassifiedEventV1,
    classification: ForkEventClassificationV1,
    classifier_revision_digest: Hash,
    fork_admission_digest: Hash,
    room_revision_descriptor_hash: Hash,
) -> (EventOriginRecordV1, Option<ForkInterventionAdmissionV1>) {
    let origin = EventOriginRecordV1(EventOriginRecordInputV1 {
        fork_timeline_id: child_timeline_id,
        logical_seq: event.logical_seq,
        event_id: event.event_id,
        classification,
        classifier_revision_digest,
        fork_admission_digest,
    });
    let intervention = classification.intervention().then(|| {
        ForkInterventionAdmissionV1(ForkInterventionAdmissionInputV1 {
            operation_id,
            fork_timeline_id: child_timeline_id,
            logical_seq: event.logical_seq,
            event_id: event.event_id,
            payload_hash: event.payload_hash,
            room_revision_descriptor_hash,
            classifier_revision_digest,
            fork_admission_digest,
        })
    });
    (origin, intervention)
}

fn domain_digest(domain: &[u8], bytes_in: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes_in);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn encode_bytes(out: &mut Vec<u8>, value: &[u8]) {
    encode_head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}
fn encode_text(out: &mut Vec<u8>, value: &str) {
    encode_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn encode_timeline(out: &mut Vec<u8>, value: TimelineId) {
    encode_bytes(out, &value.inner().to_bytes());
}
fn encode_event(out: &mut Vec<u8>, value: EventId) {
    encode_bytes(out, &value.inner().to_bytes());
}
fn encode_hash(out: &mut Vec<u8>, value: Hash) {
    encode_bytes(out, value.as_bytes());
}
fn encode_array(out: &mut Vec<u8>, value: u64) {
    encode_head(out, 4, value);
}
fn encode_uint(out: &mut Vec<u8>, value: u64) {
    encode_head(out, 0, value);
}
fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
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
    routes: &mut [ForkExternalInputRouteV1],
) -> Result<(), ForkEventProvenanceErrorV1> {
    if descriptor_hash == Hash::zero()
        || registrar_identifier.is_empty()
        || registrar_identifier.len() > MAX_FORK_EVENT_REGISTRAR_BYTES_V1
        || routes.len() > MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1
    {
        return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
    }
    sort_unique_routes(routes)
}

/// Sort routes by `(route, schema digest)` and reject any duplicate pair.
fn sort_unique_routes(
    routes: &mut [ForkExternalInputRouteV1],
) -> Result<(), ForkEventProvenanceErrorV1> {
    routes.sort_unstable_by(|left, right| left.source.cmp(&right.source));
    if routes
        .windows(2)
        .any(|pair| pair[0].source == pair[1].source)
    {
        Err(ForkEventProvenanceErrorV1::DuplicateSourceRoute)
    } else {
        Ok(())
    }
}

fn encode_routes(out: &mut Vec<u8>, routes: &[ForkExternalInputRouteV1]) {
    encode_array(out, routes.len() as u64);
    for route in routes {
        encode_array(out, 3);
        encode_text(out, route.source.route());
        encode_hash(out, route.source.schema_digest());
        encode_uint(out, u64::from(route.intervention));
    }
}

fn encode_source(out: &mut Vec<u8>, source: &ForkAppendSourceIdentityV1) {
    match source {
        ForkAppendSourceIdentityV1::HostInternal => encode_array(out, 1),
        ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier,
            source,
        } => {
            encode_array(out, 4);
            encode_uint(out, 1);
            encode_text(out, adapter_identifier);
            encode_text(out, source.route());
            encode_hash(out, source.schema_digest());
            return;
        }
    }
    encode_uint(out, 0);
}

fn encode_entity(out: &mut Vec<u8>, value: EntityId) {
    encode_bytes(out, &value.inner().to_bytes());
}
fn encode_optional_event(out: &mut Vec<u8>, value: Option<EventId>) {
    if let Some(value) = value {
        encode_event(out, value);
    } else {
        out.push(0xf6);
    }
}
fn encode_optional_correlation(out: &mut Vec<u8>, value: Option<CorrelationId>) {
    if let Some(value) = value {
        encode_bytes(out, &value.inner().to_bytes());
    } else {
        out.push(0xf6);
    }
}
fn encode_optional_wall_time(out: &mut Vec<u8>, value: Option<WallTime>) {
    if let Some(value) = value {
        encode_uint(out, value.as_micros());
    } else {
        out.push(0xf6);
    }
}
fn encode_optional_hash(out: &mut Vec<u8>, value: Option<Hash>) {
    if let Some(value) = value {
        encode_hash(out, value);
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
        let end = self.offset.saturating_add(length);
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
        let length = self.head(3)?;
        if length == 0 || length > maximum as u64 {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        let length = usize::try_from(length).unwrap_or(maximum);
        std::str::from_utf8(self.take(length)?)
            .map(str::to_owned)
            .map_err(|_| ForkEventProvenanceErrorV1::InvalidEncoding)
    }
    fn routes(&mut self) -> Result<Vec<ForkExternalInputRouteV1>, ForkEventProvenanceErrorV1> {
        let count = self.head(4)?;
        if count > MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1 as u64 {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        let count = usize::try_from(count).unwrap_or(MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1);
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
        let length = self.head(2)?;
        if length > maximum as u64 {
            return Err(ForkEventProvenanceErrorV1::FieldOutOfBounds);
        }
        let length = usize::try_from(length).unwrap_or(maximum);
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
    fn null(&mut self) -> bool {
        if self.bytes.get(self.offset) == Some(&0xf6) {
            self.offset += 1;
            true
        } else {
            false
        }
    }
    fn optional_event(&mut self) -> Result<Option<EventId>, ForkEventProvenanceErrorV1> {
        if self.null() {
            Ok(None)
        } else {
            self.event().map(Some)
        }
    }
    fn optional_correlation(
        &mut self,
    ) -> Result<Option<CorrelationId>, ForkEventProvenanceErrorV1> {
        if self.null() {
            Ok(None)
        } else {
            Ok(Some(CorrelationId::from_ulid(ulid::Ulid::from_bytes(
                self.fixed()?,
            ))))
        }
    }
    fn optional_wall_time(&mut self) -> Result<Option<WallTime>, ForkEventProvenanceErrorV1> {
        if self.null() {
            Ok(None)
        } else {
            self.uint().map(WallTime::from_micros).map(Some)
        }
    }
    fn optional_hash(&mut self) -> Result<Option<Hash>, ForkEventProvenanceErrorV1> {
        if self.null() {
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
