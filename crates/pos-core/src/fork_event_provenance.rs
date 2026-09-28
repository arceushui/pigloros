//! Local Fork Event-origin and intervention-admission records from ADR-099.
//!
//! These codecs establish neither Fork admission nor append authority. A
//! trusted host must use them with the admitted-Fork append transaction.

use crate::{EventId, Hash, TimelineId};

/// Maximum accepted `EOR1` bytes.
pub const MAX_EVENT_ORIGIN_RECORD_BYTES_V1: usize = 384;
/// Maximum accepted `FIA1` bytes.
pub const MAX_FORK_INTERVENTION_ADMISSION_BYTES_V1: usize = 512;
/// Maximum UTF-8 bytes in one trusted source route.
pub const MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1: usize = 128;

const EVENT_ORIGIN_DOMAIN: &[u8] = b"pigloros/event-origin/v1";
const INTERVENTION_ADMISSION_DOMAIN: &[u8] = b"pigloros/fork-intervention-admission/v1";

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
    fn timeline(&mut self) -> Result<TimelineId, ForkEventProvenanceErrorV1> {
        Ok(TimelineId::from_ulid(ulid::Ulid::from_bytes(self.fixed()?)))
    }
    fn event(&mut self) -> Result<EventId, ForkEventProvenanceErrorV1> {
        Ok(EventId::from_ulid(ulid::Ulid::from_bytes(self.fixed()?)))
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
