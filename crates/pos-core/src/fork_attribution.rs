//! Portable local-origin Fork attribution records from ADR-099.
//!
//! These codecs establish neither host admission nor publication authority.
//! In particular, a valid `FSM1` is only a mathematical signature until the
//! local publication authority has committed and read it.

use crate::{Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1, Signature, TimelineId};

/// Maximum accepted `FAR1` bytes.
pub const MAX_FORK_ADMISSION_RECORD_BYTES_V1: usize = 768;
/// Maximum accepted `FRM1` bytes.
pub const MAX_FORK_REPRO_MANIFEST_BYTES_V1: usize = 16_384;
/// Maximum accepted `FSM1` bytes.
pub const MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1: usize = 16_640;
/// Maximum intervention coordinates in one `FRM1`.
pub const MAX_FORK_MANIFEST_INTERVENTIONS_V1: usize = 1_024;

const ADMISSION_DOMAIN: &[u8] = b"pigloros/fork-admission/v1";
const RECORD_DOMAIN: &[u8] = b"pigloros/fork-signed-manifest/v1";

/// Closed errors for the portable attribution codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ForkAttributionCodecErrorV1 {
    #[error("invalid Fork attribution encoding")]
    InvalidEncoding,
    #[error("noncanonical Fork attribution encoding")]
    NonCanonical,
    #[error("unsupported Fork attribution version")]
    UnsupportedVersion,
    #[error("Fork attribution field is out of bounds")]
    FieldOutOfBounds,
    #[error("Fork attribution origin is unavailable")]
    ImportedAuthorityUnavailable,
    #[error("Fork attribution fields do not agree")]
    FieldMismatch,
    #[error("Fork intervention coordinates are not strictly increasing")]
    InterventionOrder,
}

/// The only currently usable authority origin.
///
/// The reserved wire code 2 is rejected until #447 installs its authenticated
/// atomic import boundary; it has no public value variant here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkAttributionOriginV1 {
    /// Locally committed authority bytes.
    Local,
}

/// Construction fields for one portable local `FAR1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAdmissionRecordInputV1 {
    pub operation_id: Hash,
    pub principal_owner_binding_digest: Hash,
    pub creator: OwnerIdV1,
    pub parent_timeline_id: TimelineId,
    pub child_timeline_id: TimelineId,
    pub room_revision_descriptor_hash: Hash,
    pub parent_logical_head: u64,
    pub parent_chain_head_hash: Hash,
    pub completed_fold_cursor: u64,
    pub post_fold_tick_boundary: u64,
    pub plugin_composition_hash: Hash,
    pub attribution_required: bool,
    pub origin: ForkAttributionOriginV1,
}

/// Strict portable `FAR1` bytes. This value does not prove host admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAdmissionRecordV1(ForkAdmissionRecordInputV1);

impl ForkAdmissionRecordV1 {
    /// Validate the local structural and duplicated-cut invariants.
    ///
    /// # Errors
    /// Rejects zero required identifiers, duplicate Timeline IDs, or inconsistent cut coordinates.
    pub fn new(input: ForkAdmissionRecordInputV1) -> Result<Self, ForkAttributionCodecErrorV1> {
        if input.operation_id == Hash::zero()
            || input.principal_owner_binding_digest == Hash::zero()
            || input.room_revision_descriptor_hash == Hash::zero()
            || input.plugin_composition_hash == Hash::zero()
            || input.parent_timeline_id == input.child_timeline_id
            || input.completed_fold_cursor != input.parent_logical_head
            || input.post_fold_tick_boundary != input.parent_logical_head
        {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkAdmissionRecordInputV1 {
        &self.0
    }

    /// Encode the exact 15-field deterministic-CBOR `FAR1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(320);
        array(&mut out, 15);
        text(&mut out, "FAR1");
        uint(&mut out, 1);
        hash(&mut out, value.operation_id);
        hash(&mut out, value.principal_owner_binding_digest);
        text(&mut out, value.creator.as_str());
        timeline(&mut out, value.parent_timeline_id);
        timeline(&mut out, value.child_timeline_id);
        hash(&mut out, value.room_revision_descriptor_hash);
        uint(&mut out, value.parent_logical_head);
        hash(&mut out, value.parent_chain_head_hash);
        uint(&mut out, value.completed_fold_cursor);
        uint(&mut out, value.post_fold_tick_boundary);
        hash(&mut out, value.plugin_composition_hash);
        uint(&mut out, u64::from(value.attribution_required));
        array(&mut out, 1);
        uint(&mut out, 1);
        out
    }

    /// Return the domain-separated digest over complete canonical `FAR1` bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(ADMISSION_DOMAIN, &self.to_canonical_cbor())
    }

    /// Decode only exact canonical local-origin `FAR1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, noncanonical, or imported-origin bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_ADMISSION_RECORD_BYTES_V1)?;
        wire.array(15)?;
        wire.magic("FAR1")?;
        wire.version()?;
        let operation_id = wire.hash()?;
        let principal_owner_binding_digest = wire.hash()?;
        let creator = OwnerIdV1::new(wire.text(128)?)
            .map_err(|_| ForkAttributionCodecErrorV1::FieldOutOfBounds)?;
        let parent_timeline_id = wire.timeline()?;
        let child_timeline_id = wire.timeline()?;
        let room_revision_descriptor_hash = wire.hash()?;
        let parent_logical_head = wire.uint()?;
        let parent_chain_head_hash = wire.hash()?;
        let completed_fold_cursor = wire.uint()?;
        let post_fold_tick_boundary = wire.uint()?;
        let plugin_composition_hash = wire.hash()?;
        let attribution_required = wire.bool()?;
        wire.array(1)?;
        let origin = match wire.uint()? {
            1 => ForkAttributionOriginV1::Local,
            2 => return Err(ForkAttributionCodecErrorV1::ImportedAuthorityUnavailable),
            _ => return Err(ForkAttributionCodecErrorV1::InvalidEncoding),
        };
        wire.finish()?;
        let record = Self::new(ForkAdmissionRecordInputV1 {
            operation_id,
            principal_owner_binding_digest,
            creator,
            parent_timeline_id,
            child_timeline_id,
            room_revision_descriptor_hash,
            parent_logical_head,
            parent_chain_head_hash,
            completed_fold_cursor,
            post_fold_tick_boundary,
            plugin_composition_hash,
            attribution_required,
            origin,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Construction fields for one portable `FRM1` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkReproManifestInputV1 {
    pub parent_timeline_id: TimelineId,
    pub fork_timeline_id: TimelineId,
    pub admission_digest: Hash,
    pub room_revision_descriptor_hash: Hash,
    pub parent_logical_head: u64,
    pub parent_chain_head_hash: Hash,
    pub post_fold_tick_boundary: u64,
    pub plugin_composition_hash: Hash,
    pub intervention_sequences: Vec<u64>,
    pub final_fork_logical_head: u64,
    pub final_fork_chain_head_hash: Hash,
}

/// Strict portable `FRM1` bytes, without publication authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkReproManifestV1(ForkReproManifestInputV1);

impl ForkReproManifestV1 {
    /// Construct `FRM1` from the duplicated coordinates in local `FAR1`.
    ///
    /// This constructor establishes only byte agreement with supplied local
    /// admission data. It does not establish that the supplied `FAR1` was
    /// durably committed or authorized for publication.
    ///
    /// # Errors
    ///
    /// Rejects invalid final Fork coordinates or intervention sequences.
    pub fn from_admission(
        admission: &ForkAdmissionRecordV1,
        intervention_sequences: Vec<u64>,
        final_fork_logical_head: u64,
        final_fork_chain_head_hash: Hash,
    ) -> Result<Self, ForkAttributionCodecErrorV1> {
        let record = admission.input();
        Self::new(ForkReproManifestInputV1 {
            parent_timeline_id: record.parent_timeline_id,
            fork_timeline_id: record.child_timeline_id,
            admission_digest: admission.digest(),
            room_revision_descriptor_hash: record.room_revision_descriptor_hash,
            parent_logical_head: record.parent_logical_head,
            parent_chain_head_hash: record.parent_chain_head_hash,
            post_fold_tick_boundary: record.post_fold_tick_boundary,
            plugin_composition_hash: record.plugin_composition_hash,
            intervention_sequences,
            final_fork_logical_head,
            final_fork_chain_head_hash,
        })
    }

    /// Validate exact structural coordinate bounds.
    ///
    /// # Errors
    /// Rejects invalid coordinates or intervention ordering and bounds.
    pub fn new(input: ForkReproManifestInputV1) -> Result<Self, ForkAttributionCodecErrorV1> {
        if input.parent_timeline_id == input.fork_timeline_id
            || input.admission_digest == Hash::zero()
            || input.room_revision_descriptor_hash == Hash::zero()
            || input.plugin_composition_hash == Hash::zero()
            || input.final_fork_logical_head < input.parent_logical_head
            || input.intervention_sequences.len() > MAX_FORK_MANIFEST_INTERVENTIONS_V1
        {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        if input
            .intervention_sequences
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(ForkAttributionCodecErrorV1::InterventionOrder);
        }
        if input.intervention_sequences.iter().any(|sequence| {
            *sequence <= input.parent_logical_head || *sequence > input.final_fork_logical_head
        }) {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkReproManifestInputV1 {
        &self.0
    }

    /// Require every duplicated provenance coordinate to equal local `FAR1`.
    ///
    /// # Errors
    /// Rejects any mismatch between the manifest and admission authority.
    pub fn validate_against_admission(
        &self,
        admission: &ForkAdmissionRecordV1,
    ) -> Result<(), ForkAttributionCodecErrorV1> {
        let manifest = &self.0;
        let record = admission.input();
        if manifest.admission_digest != admission.digest()
            || manifest.parent_timeline_id != record.parent_timeline_id
            || manifest.fork_timeline_id != record.child_timeline_id
            || manifest.room_revision_descriptor_hash != record.room_revision_descriptor_hash
            || manifest.parent_logical_head != record.parent_logical_head
            || manifest.parent_chain_head_hash != record.parent_chain_head_hash
            || manifest.post_fold_tick_boundary != record.post_fold_tick_boundary
            || manifest.plugin_composition_hash != record.plugin_composition_hash
        {
            return Err(ForkAttributionCodecErrorV1::FieldMismatch);
        }
        Ok(())
    }

    /// Encode exact deterministic-CBOR `FRM1` bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(512 + value.intervention_sequences.len() * 9);
        array(&mut out, 13);
        text(&mut out, "FRM1");
        uint(&mut out, 1);
        timeline(&mut out, value.parent_timeline_id);
        timeline(&mut out, value.fork_timeline_id);
        hash(&mut out, value.admission_digest);
        hash(&mut out, value.room_revision_descriptor_hash);
        uint(&mut out, value.parent_logical_head);
        hash(&mut out, value.parent_chain_head_hash);
        uint(&mut out, value.post_fold_tick_boundary);
        hash(&mut out, value.plugin_composition_hash);
        array(&mut out, value.intervention_sequences.len() as u64);
        for sequence in &value.intervention_sequences {
            uint(&mut out, *sequence);
        }
        uint(&mut out, value.final_fork_logical_head);
        hash(&mut out, value.final_fork_chain_head_hash);
        out
    }

    /// Decode exact canonical `FRM1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, or noncanonical manifest bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_REPRO_MANIFEST_BYTES_V1)?;
        wire.array(13)?;
        wire.magic("FRM1")?;
        wire.version()?;
        let parent_timeline_id = wire.timeline()?;
        let fork_timeline_id = wire.timeline()?;
        let admission_digest = wire.hash()?;
        let room_revision_descriptor_hash = wire.hash()?;
        let parent_logical_head = wire.uint()?;
        let parent_chain_head_hash = wire.hash()?;
        let post_fold_tick_boundary = wire.uint()?;
        let plugin_composition_hash = wire.hash()?;
        let count = wire.array_len()?;
        if count > MAX_FORK_MANIFEST_INTERVENTIONS_V1 {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        let mut intervention_sequences = Vec::with_capacity(count);
        for _ in 0..count {
            intervention_sequences.push(wire.uint()?);
        }
        let final_fork_logical_head = wire.uint()?;
        let final_fork_chain_head_hash = wire.hash()?;
        wire.finish()?;
        let record = Self::new(ForkReproManifestInputV1 {
            parent_timeline_id,
            fork_timeline_id,
            admission_digest,
            room_revision_descriptor_hash,
            parent_logical_head,
            parent_chain_head_hash,
            post_fold_tick_boundary,
            plugin_composition_hash,
            intervention_sequences,
            final_fork_logical_head,
            final_fork_chain_head_hash,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Strict portable `FSM1` wrapper. It remains a signature-only value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedForkReproManifestV1 {
    identity: KeyIdentityV1,
    manifest: ForkReproManifestV1,
    signature: Signature,
}

impl SignedForkReproManifestV1 {
    /// Construct a signature-only wrapper bound to supplied local `FAR1`.
    ///
    /// The creator is derived from `FAR1`, and the `FRM1` duplicated fields
    /// must agree with it. This does not treat caller-supplied `FAR1` as
    /// trusted admission or publication authority.
    ///
    /// # Errors
    ///
    /// Rejects a zero epoch or any creator or manifest mismatch.
    pub fn new_from_admission(
        admission: &ForkAdmissionRecordV1,
        epoch: u64,
        manifest: ForkReproManifestV1,
        signature: Signature,
    ) -> Result<Self, ForkAttributionCodecErrorV1> {
        Self::new(
            KeyIdentityV1::from_parts(
                admission.input().creator,
                KeyRoleV1::SubjectAttributionSigning,
                epoch,
            ),
            manifest,
            signature,
        )
        .and_then(|record| {
            record
                .validate_against_admission(admission)
                .map(|()| record)
        })
    }

    /// Require the wrapper creator and manifest fields to agree with local `FAR1`.
    ///
    /// # Errors
    ///
    /// Rejects a different creator or any mismatched duplicated manifest field.
    pub fn validate_against_admission(
        &self,
        admission: &ForkAdmissionRecordV1,
    ) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.identity.owner_id != admission.input().creator {
            return Err(ForkAttributionCodecErrorV1::FieldMismatch);
        }
        self.manifest.validate_against_admission(admission)
    }

    /// Construct a signature-only wrapper for the exact inner canonical bytes.
    ///
    /// # Errors
    /// Rejects an identity without the attribution-signing role or positive epoch.
    pub fn new(
        identity: KeyIdentityV1,
        manifest: ForkReproManifestV1,
        signature: Signature,
    ) -> Result<Self, ForkAttributionCodecErrorV1> {
        if identity.role != KeyRoleV1::SubjectAttributionSigning || identity.epoch == 0 {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        Ok(Self {
            identity,
            manifest,
            signature,
        })
    }
    #[must_use]
    pub const fn identity(&self) -> KeyIdentityV1 {
        self.identity
    }
    #[must_use]
    pub const fn manifest(&self) -> &ForkReproManifestV1 {
        &self.manifest
    }
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.signature
    }
    /// Replace the mathematical signature after the admission-bound fields
    /// have been validated. This does not grant publication authority.
    #[must_use]
    pub const fn with_signature(mut self, signature: Signature) -> Self {
        self.signature = signature;
        self
    }
    /// Return canonical inner `FRM1` bytes used by ADR-065 role signing.
    #[must_use]
    pub fn manifest_bytes(&self) -> Vec<u8> {
        self.manifest.to_canonical_cbor()
    }
    /// Encode exact deterministic-CBOR `FSM1` bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let inner = self.manifest_bytes();
        let mut out = Vec::with_capacity(inner.len() + 192);
        array(&mut out, 7);
        text(&mut out, "FSM1");
        uint(&mut out, 1);
        text(&mut out, self.identity.owner_id.as_str());
        uint(&mut out, u64::from(self.identity.role.code()));
        uint(&mut out, self.identity.epoch);
        bytes(&mut out, &inner);
        bytes(&mut out, self.signature.as_bytes());
        out
    }
    /// Return the ADR-099 record identifier over complete `FSM1` bytes.
    #[must_use]
    pub fn record_id(&self) -> Hash {
        domain_digest(RECORD_DOMAIN, &self.to_canonical_cbor())
    }
    /// Decode exact canonical `FSM1` bytes; this does not verify the signature.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, or noncanonical signed-record bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, ForkAttributionCodecErrorV1> {
        let mut wire = Reader::new(bytes_in, MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1)?;
        wire.array(7)?;
        wire.magic("FSM1")?;
        wire.version()?;
        let owner = OwnerIdV1::new(wire.text(128)?)
            .map_err(|_| ForkAttributionCodecErrorV1::FieldOutOfBounds)?;
        let role = KeyRoleV1::from_code(
            u8::try_from(wire.uint()?).map_err(|_| ForkAttributionCodecErrorV1::InvalidEncoding)?,
        )
        .map_err(|_| ForkAttributionCodecErrorV1::InvalidEncoding)?;
        let epoch = wire.uint()?;
        let inner = wire.bytes(MAX_FORK_REPRO_MANIFEST_BYTES_V1)?;
        let signature = Signature::from_bytes(wire.fixed::<64>()?);
        wire.finish()?;
        let manifest = ForkReproManifestV1::from_canonical_cbor(inner)?;
        let record = Self::new(
            KeyIdentityV1::from_parts(owner, role, epoch),
            manifest,
            signature,
        )?;
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
fn hash(out: &mut Vec<u8>, value: Hash) {
    bytes(out, value.as_bytes());
}
fn timeline(out: &mut Vec<u8>, value: TimelineId) {
    bytes(out, &value.inner().to_bytes());
}
fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}
fn text(out: &mut Vec<u8>, value: &str) {
    head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
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
fn canonical(actual: &[u8], expected: &[u8]) -> Result<(), ForkAttributionCodecErrorV1> {
    if actual == expected {
        Ok(())
    } else {
        Err(ForkAttributionCodecErrorV1::NonCanonical)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, ForkAttributionCodecErrorV1> {
        if bytes.len() > maximum {
            Err(ForkAttributionCodecErrorV1::FieldOutOfBounds)
        } else {
            Ok(Self { bytes, offset: 0 })
        }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ForkAttributionCodecErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ForkAttributionCodecErrorV1::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ForkAttributionCodecErrorV1::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }
    fn head(&mut self, major: u8) -> Result<u64, ForkAttributionCodecErrorV1> {
        let first = self.take(1)?[0];
        if first >> 5 != major {
            return Err(ForkAttributionCodecErrorV1::InvalidEncoding);
        }
        let additional = first & 31;
        let width = match additional {
            0..=23 => return Ok(u64::from(additional)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(ForkAttributionCodecErrorV1::InvalidEncoding),
        };
        let mut value = 0;
        for byte in self.take(width)? {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }
    fn array(&mut self, expected: u64) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.head(4)? == expected {
            Ok(())
        } else {
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        }
    }
    fn array_len(&mut self) -> Result<usize, ForkAttributionCodecErrorV1> {
        usize::try_from(self.head(4)?).map_err(|_| ForkAttributionCodecErrorV1::FieldOutOfBounds)
    }
    fn uint(&mut self) -> Result<u64, ForkAttributionCodecErrorV1> {
        self.head(0)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ForkAttributionCodecErrorV1> {
        if self.head(2)? != N as u64 {
            return Err(ForkAttributionCodecErrorV1::InvalidEncoding);
        }
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], ForkAttributionCodecErrorV1> {
        let length = usize::try_from(self.head(2)?)
            .map_err(|_| ForkAttributionCodecErrorV1::FieldOutOfBounds)?;
        if length > maximum {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        self.take(length)
    }
    fn text(&mut self, maximum: usize) -> Result<&'a str, ForkAttributionCodecErrorV1> {
        let length = usize::try_from(self.head(3)?)
            .map_err(|_| ForkAttributionCodecErrorV1::FieldOutOfBounds)?;
        if length > maximum {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        let value = self.take(length)?;
        if value.is_empty() {
            return Err(ForkAttributionCodecErrorV1::FieldOutOfBounds);
        }
        std::str::from_utf8(value).map_err(|_| ForkAttributionCodecErrorV1::InvalidEncoding)
    }
    fn hash(&mut self) -> Result<Hash, ForkAttributionCodecErrorV1> {
        Ok(Hash::from_bytes(self.fixed()?))
    }
    fn timeline(&mut self) -> Result<TimelineId, ForkAttributionCodecErrorV1> {
        Ok(TimelineId::from_ulid(ulid::Ulid::from_bytes(self.fixed()?)))
    }
    fn bool(&mut self) -> Result<bool, ForkAttributionCodecErrorV1> {
        match self.uint()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ForkAttributionCodecErrorV1::InvalidEncoding),
        }
    }
    fn magic(&mut self, expected: &str) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.text(4)? == expected {
            Ok(())
        } else {
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        }
    }
    fn version(&mut self) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.uint()? == 1 {
            Ok(())
        } else {
            Err(ForkAttributionCodecErrorV1::UnsupportedVersion)
        }
    }
    const fn finish(&self) -> Result<(), ForkAttributionCodecErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ForkAttributionCodecErrorV1::InvalidEncoding)
        }
    }
}
