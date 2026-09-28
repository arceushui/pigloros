//! Structural ARD1 registration bytes. Parsing these bytes never grants use.

use super::{
    ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1,
    ErasureArtifactClassV1,
};
use crate::canonical_cbor_head::encode_head;
use crate::{AdapterAdmissionV1, AdapterTranscriptV1, Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1};
use std::collections::BTreeSet;

/// Maximum canonical size of one ARD1 record.
pub const MAX_ARTIFACT_REGISTRATION_BYTES_V1: usize = 1_048_576;
/// Maximum direct key dependencies in one ARD1 record.
pub const MAX_ARTIFACT_REGISTRATION_KEYS_V1: usize = 2_048;
/// Maximum direct child edges in one ARD1 record.
pub const MAX_ARTIFACT_REGISTRATION_CHILDREN_V1: usize = 2_048;

// Under the direct-list and OwnerIdV1 bounds, even the maximum encoding fits
// the one-MiB record ceiling. The decoder still rejects overlong input first.
const _: () = assert!(
    1 + 5
        + 1
        + 1
        + 34
        + 34
        + 1
        + 1
        + 1
        + 1
        + 5
        + 3
        + (1 + 2 + 128 + 1 + 9 + 34 + 1) * MAX_ARTIFACT_REGISTRATION_KEYS_V1
        + 3
        + (1 + 1 + 34 + 34 + 1) * MAX_ARTIFACT_REGISTRATION_CHILDREN_V1
        <= MAX_ARTIFACT_REGISTRATION_BYTES_V1
);

/// A closed structural failure; it carries no protected artifact data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactRegistrationErrorV1 {
    #[error("invalid ARD1 encoding")]
    InvalidEncoding,
    #[error("unsupported ARD1 version or field code")]
    UnsupportedValue,
    #[error("ARD1 field is outside its accepted bound")]
    FieldOutOfBounds,
    #[error("ARD1 dependency or edge order is invalid")]
    InvalidOrder,
    #[error("ARD1 bytes are not canonical")]
    NonCanonical,
}

/// Failure while deriving the fixed class-1 registration from ADR-101 bytes.
///
/// This is structural extraction only. An installed owner must still verify
/// admission provenance and recorder closure before a store can publish the
/// resulting registration in its authoritative catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AdapterArtifactRegistrationErrorV1 {
    /// MAA1 bytes are malformed, noncanonical, or outside the accepted profile.
    #[error("invalid MAA1 artifact bytes")]
    InvalidAdmission,
    /// MAT1 bytes are malformed, noncanonical, or violate its admitted call contract.
    #[error("invalid MAT1 artifact bytes")]
    InvalidTranscript,
    /// The supplied MAA1 registration is not exactly derived from its retained bytes.
    #[error("MAA1 registration does not match its retained artifact bytes")]
    AdmissionRegistrationMismatch,
}

/// One immutable child registration address and its parent-fixed membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactChildEdgeV1 {
    pub artifact_class: ErasureArtifactClassV1,
    pub artifact_digest: Hash,
    pub registration_address: Hash,
    pub required: bool,
}

/// Untrusted ARD1 fields. A byte owner must derive and compare them at commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRegistrationFieldsV1 {
    pub artifact_class: ErasureArtifactClassV1,
    pub artifact_digest: Hash,
    pub owner_reference: Hash,
    pub data_class: ArtifactDataClassV1,
    pub optionality: ArtifactOptionalityV1,
    pub transition_rule: ArtifactTransitionRuleV1,
    pub required_key_roles: Vec<KeyRoleV1>,
    pub key_dependencies: Vec<ArtifactKeyDependencyV1>,
    pub child_artifacts: Vec<ArtifactChildEdgeV1>,
}

/// Structurally valid canonical ARD1, without catalog or extractor authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRegistrationV1 {
    fields: ArtifactRegistrationFieldsV1,
    canonical_cbor: Vec<u8>,
    address: Hash,
}

impl ArtifactRegistrationV1 {
    /// Validate and encode the exact eleven-field ARD1 array.
    ///
    /// # Errors
    /// Rejects excess cardinality, unsorted or duplicate identities, and a
    /// role array that differs from the exact roles in direct dependencies.
    pub fn new(fields: ArtifactRegistrationFieldsV1) -> Result<Self, ArtifactRegistrationErrorV1> {
        validate_fields(&fields)?;
        let canonical_cbor = encode_registration(&fields);
        let address = domain_hash(b"PiglorOS.ArtifactRegistration.v1\0", &canonical_cbor);
        Ok(Self {
            fields,
            canonical_cbor,
            address,
        })
    }

    /// Parse bounded, preferred definite CBOR and compare exact re-encoding.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, unknown, excessive, and trailing data.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ArtifactRegistrationErrorV1> {
        if bytes.len() > MAX_ARTIFACT_REGISTRATION_BYTES_V1 {
            return Err(ArtifactRegistrationErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        let fields = reader.registration()?;
        if reader.offset != bytes.len() {
            return Err(ArtifactRegistrationErrorV1::InvalidEncoding);
        }
        let registration = Self::new(fields)?;
        if registration.canonical_cbor != bytes {
            return Err(ArtifactRegistrationErrorV1::NonCanonical);
        }
        Ok(registration)
    }

    /// Borrow the untrusted structural fields; only an owner commit may validate them.
    #[must_use]
    pub const fn fields(&self) -> &ArtifactRegistrationFieldsV1 {
        &self.fields
    }

    /// Borrow exact deterministic bytes.
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }

    /// Return the domain-separated address of these exact bytes.
    #[must_use]
    pub const fn address(&self) -> Hash {
        self.address
    }

    /// Hash exact artifact bytes with class and length framing.
    ///
    #[must_use]
    pub fn artifact_digest(artifact_class: ErasureArtifactClassV1, bytes: &[u8]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.ArtifactBytes.v1\0");
        hasher.update(&[artifact_class_byte(artifact_class)]);
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Hash the exact canonical owner ID from the owner's catalog.
    #[must_use]
    pub fn owner_reference(owner_id: &OwnerIdV1) -> Hash {
        let bytes = owner_id.as_str().as_bytes();
        // OwnerIdV1 enforces at most 128 UTF-8 bytes, so the top four bytes
        // of a usize length are zero on every supported target.
        let length = bytes.len().to_be_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PiglorOS.ArtifactOwner.v1\0");
        hasher.update(&length[length.len() - 4..]);
        hasher.update(bytes);
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }
}

/// Derive the fixed ARD1 fields for retained ADR-101 MAA1 bytes.
///
/// MAA1 contains only owner-admitted public configuration. Its class-1
/// registration therefore has no key dependencies or child artifacts. This
/// function validates and re-encodes the exact retained bytes before deriving
/// their digest and owner reference.
///
/// # Errors
/// Returns [`AdapterArtifactRegistrationErrorV1::InvalidAdmission`] when the
/// bytes are not one exact accepted MAA1 record.
pub fn extract_adapter_admission_registration_v1(
    bytes: &[u8],
) -> Result<ArtifactRegistrationV1, AdapterArtifactRegistrationErrorV1> {
    let admission = AdapterAdmissionV1::from_canonical_cbor(bytes)
        .map_err(|_| AdapterArtifactRegistrationErrorV1::InvalidAdmission)?;
    let artifact_digest =
        ArtifactRegistrationV1::artifact_digest(ErasureArtifactClassV1::ReproManifest, bytes);
    ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::ReproManifest,
        artifact_digest,
        owner_reference: admission.as_input().owner_reference,
        data_class: ArtifactDataClassV1::PublicRecord,
        optionality: ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::PreserveExact,
        required_key_roles: Vec::new(),
        key_dependencies: Vec::new(),
        child_artifacts: Vec::new(),
    })
    .map_err(|_| AdapterArtifactRegistrationErrorV1::InvalidAdmission)
}

/// Derive the fixed ARD1 fields for retained ADR-101 MAT1 bytes.
///
/// The one required child is the exact retained MAA1 registration. The
/// transcript is checked against that MAA1 before its registration is derived.
/// This does not certify a closed recorder or authenticated public-record
/// provenance; those are owner-commit preconditions outside this parser.
///
/// # Errors
/// Returns an error when either byte record is invalid, the calls do not match
/// the supplied admission, or the supplied ARD1 is not the exact MAA1-derived
/// registration.
pub fn extract_adapter_transcript_registration_v1(
    transcript_bytes: &[u8],
    admission_bytes: &[u8],
    admission_registration: &ArtifactRegistrationV1,
) -> Result<ArtifactRegistrationV1, AdapterArtifactRegistrationErrorV1> {
    let transcript = AdapterTranscriptV1::from_canonical_cbor(transcript_bytes)
        .map_err(|_| AdapterArtifactRegistrationErrorV1::InvalidTranscript)?;
    let admission = AdapterAdmissionV1::from_canonical_cbor(admission_bytes)
        .map_err(|_| AdapterArtifactRegistrationErrorV1::InvalidAdmission)?;
    let expected_admission = extract_adapter_admission_registration_v1(admission_bytes)?;
    if admission_registration != &expected_admission {
        return Err(AdapterArtifactRegistrationErrorV1::AdmissionRegistrationMismatch);
    }
    transcript
        .compare_call_contracts(&admission)
        .map_err(|_| AdapterArtifactRegistrationErrorV1::InvalidTranscript)?;
    let artifact_digest = ArtifactRegistrationV1::artifact_digest(
        ErasureArtifactClassV1::ReproManifest,
        transcript_bytes,
    );
    ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::ReproManifest,
        artifact_digest,
        owner_reference: transcript.as_input().owner_reference,
        data_class: ArtifactDataClassV1::PublicRecord,
        optionality: ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::PreserveExact,
        required_key_roles: Vec::new(),
        key_dependencies: Vec::new(),
        child_artifacts: vec![ArtifactChildEdgeV1 {
            artifact_class: ErasureArtifactClassV1::ReproManifest,
            artifact_digest: expected_admission.fields().artifact_digest,
            registration_address: expected_admission.address(),
            required: true,
        }],
    })
    .map_err(|_| AdapterArtifactRegistrationErrorV1::InvalidTranscript)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn validate_fields(
    fields: &ArtifactRegistrationFieldsV1,
) -> Result<(), ArtifactRegistrationErrorV1> {
    if fields.key_dependencies.len() > MAX_ARTIFACT_REGISTRATION_KEYS_V1
        || fields.child_artifacts.len() > MAX_ARTIFACT_REGISTRATION_CHILDREN_V1
        || fields.required_key_roles.len() > 5
    {
        return Err(ArtifactRegistrationErrorV1::FieldOutOfBounds);
    }
    if fields
        .required_key_roles
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || fields
            .key_dependencies
            .windows(2)
            .any(|pair| pair[0].identity >= pair[1].identity)
        || fields
            .key_dependencies
            .iter()
            .any(|dependency| dependency.identity.epoch == 0)
    {
        return Err(ArtifactRegistrationErrorV1::InvalidOrder);
    }
    let exact_roles: Vec<_> = fields
        .key_dependencies
        .iter()
        .map(|dependency| dependency.identity.role)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if fields.required_key_roles != exact_roles {
        return Err(ArtifactRegistrationErrorV1::InvalidOrder);
    }
    let mut addresses = BTreeSet::new();
    if fields
        .child_artifacts
        .windows(2)
        .any(|pair| child_sort_key(&pair[0]) >= child_sort_key(&pair[1]))
        || fields
            .child_artifacts
            .iter()
            .any(|child| !addresses.insert(child.registration_address))
    {
        return Err(ArtifactRegistrationErrorV1::InvalidOrder);
    }
    Ok(())
}

const fn child_sort_key(edge: &ArtifactChildEdgeV1) -> (u64, Hash, Hash) {
    (
        edge.artifact_class.code(),
        edge.artifact_digest,
        edge.registration_address,
    )
}

const fn artifact_class_byte(value: ErasureArtifactClassV1) -> u8 {
    match value {
        ErasureArtifactClassV1::TimelineReplay => 0,
        ErasureArtifactClassV1::ReproManifest => 1,
        ErasureArtifactClassV1::CausalTrace => 2,
        ErasureArtifactClassV1::CalibrationReport => 3,
        ErasureArtifactClassV1::Export => 4,
        ErasureArtifactClassV1::ForkOrSnapshot => 5,
        ErasureArtifactClassV1::ConformanceReport => 6,
    }
}

fn encode_registration(fields: &ArtifactRegistrationFieldsV1) -> Vec<u8> {
    let mut out = vec![0x8b, 0x44];
    out.extend_from_slice(b"ARD1");
    out.push(1);
    encode_head(&mut out, 0, fields.artifact_class.code());
    encode_blob(&mut out, fields.artifact_digest.as_bytes());
    encode_blob(&mut out, fields.owner_reference.as_bytes());
    encode_head(&mut out, 0, data_class_code(fields.data_class));
    encode_head(&mut out, 0, optionality_code(fields.optionality));
    encode_head(&mut out, 0, transition_code(fields.transition_rule));
    encode_head(&mut out, 4, fields.required_key_roles.len() as u64);
    for role in &fields.required_key_roles {
        encode_head(&mut out, 0, u64::from(role.code()));
    }
    encode_head(&mut out, 4, fields.key_dependencies.len() as u64);
    for dependency in &fields.key_dependencies {
        out.push(0x85);
        encode_text(&mut out, dependency.identity.owner_id.as_str());
        encode_head(&mut out, 0, u64::from(dependency.identity.role.code()));
        encode_head(&mut out, 0, dependency.identity.epoch);
        encode_blob(&mut out, dependency.material_digest.as_bytes());
        out.push(if dependency.private_material_required {
            0xf5
        } else {
            0xf4
        });
    }
    encode_head(&mut out, 4, fields.child_artifacts.len() as u64);
    for child in &fields.child_artifacts {
        out.push(0x84);
        encode_head(&mut out, 0, child.artifact_class.code());
        encode_blob(&mut out, child.artifact_digest.as_bytes());
        encode_blob(&mut out, child.registration_address.as_bytes());
        out.push(if child.required { 0xf5 } else { 0xf4 });
    }
    out
}

fn encode_text(out: &mut Vec<u8>, text: &str) {
    encode_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

fn encode_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

const fn data_class_code(value: ArtifactDataClassV1) -> u64 {
    match value {
        ArtifactDataClassV1::PrivateSubjectData => 0,
        ArtifactDataClassV1::ConsentedSharedData => 1,
        ArtifactDataClassV1::PublicRecord => 2,
        ArtifactDataClassV1::AggregateData => 3,
        ArtifactDataClassV1::StructuralAuditMetadata => 4,
    }
}

const fn optionality_code(value: ArtifactOptionalityV1) -> u64 {
    match value {
        ArtifactOptionalityV1::Required => 0,
        ArtifactOptionalityV1::Optional => 1,
    }
}

const fn transition_code(value: ArtifactTransitionRuleV1) -> u64 {
    match value {
        ArtifactTransitionRuleV1::PreserveExact => 0,
        ArtifactTransitionRuleV1::RedactViews => 1,
        ArtifactTransitionRuleV1::RetainStructure => 2,
        ArtifactTransitionRuleV1::Remove => 3,
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ArtifactRegistrationErrorV1> {
        // The whole input is at most one MiB; every requested scalar is at
        // most 128 bytes, so this offset addition cannot overflow usize.
        let end = self.offset + length;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ArtifactRegistrationErrorV1::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, ArtifactRegistrationErrorV1> {
        self.take(1).map(|value| value[0])
    }

    fn unsigned_bytes(&mut self, length: usize) -> Result<u64, ArtifactRegistrationErrorV1> {
        self.take(length).map(|bytes| {
            bytes
                .iter()
                .fold(0_u64, |value, byte| (value << 8) | u64::from(*byte))
        })
    }

    fn head(&mut self, major: u8) -> Result<u64, ArtifactRegistrationErrorV1> {
        let first = self.byte()?;
        if first >> 5 != major {
            return Err(ArtifactRegistrationErrorV1::InvalidEncoding);
        }
        let extra = first & 31;
        let value = match extra {
            0..=23 => u64::from(extra),
            24 => u64::from(self.byte()?),
            25 => self.unsigned_bytes(2)?,
            26 => self.unsigned_bytes(4)?,
            27 => self.unsigned_bytes(8)?,
            _ => return Err(ArtifactRegistrationErrorV1::InvalidEncoding),
        };
        Ok(value)
    }

    fn array(&mut self, length: u64) -> Result<(), ArtifactRegistrationErrorV1> {
        if self.head(4)? == length {
            Ok(())
        } else {
            Err(ArtifactRegistrationErrorV1::InvalidEncoding)
        }
    }

    fn bounded_array(&mut self, maximum: usize) -> Result<usize, ArtifactRegistrationErrorV1> {
        let count = self.head(4)?;
        let count =
            usize::try_from(count).map_err(|_| ArtifactRegistrationErrorV1::FieldOutOfBounds)?;
        if count > maximum {
            Err(ArtifactRegistrationErrorV1::FieldOutOfBounds)
        } else {
            Ok(count)
        }
    }

    fn blob(&mut self, length: usize) -> Result<&'a [u8], ArtifactRegistrationErrorV1> {
        if self.head(2)? != length as u64 {
            return Err(ArtifactRegistrationErrorV1::InvalidEncoding);
        }
        self.take(length)
    }

    fn hash(&mut self) -> Result<Hash, ArtifactRegistrationErrorV1> {
        self.blob(32).map(|bytes| {
            let mut digest = [0; 32];
            digest.copy_from_slice(bytes);
            Hash::from_bytes(digest)
        })
    }

    fn owner(&mut self) -> Result<OwnerIdV1, ArtifactRegistrationErrorV1> {
        let length = self.head(3)?;
        if !(1..=128).contains(&length) {
            return Err(ArtifactRegistrationErrorV1::FieldOutOfBounds);
        }
        let length = usize::from(length.to_be_bytes()[7]);
        let text = std::str::from_utf8(self.take(length)?)
            .map_err(|_| ArtifactRegistrationErrorV1::InvalidEncoding)?;
        OwnerIdV1::new(text).map_err(|_| ArtifactRegistrationErrorV1::FieldOutOfBounds)
    }

    fn boolean(&mut self) -> Result<bool, ArtifactRegistrationErrorV1> {
        match self.byte()? {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(ArtifactRegistrationErrorV1::InvalidEncoding),
        }
    }

    fn artifact_class(&mut self) -> Result<ErasureArtifactClassV1, ArtifactRegistrationErrorV1> {
        ErasureArtifactClassV1::from_code(self.head(0)?)
            .map_err(|_| ArtifactRegistrationErrorV1::UnsupportedValue)
    }

    fn role(&mut self) -> Result<KeyRoleV1, ArtifactRegistrationErrorV1> {
        let code = u8::try_from(self.head(0)?)
            .map_err(|_| ArtifactRegistrationErrorV1::UnsupportedValue)?;
        KeyRoleV1::from_code(code).map_err(|_| ArtifactRegistrationErrorV1::UnsupportedValue)
    }

    fn data_class(&mut self) -> Result<ArtifactDataClassV1, ArtifactRegistrationErrorV1> {
        match self.head(0)? {
            0 => Ok(ArtifactDataClassV1::PrivateSubjectData),
            1 => Ok(ArtifactDataClassV1::ConsentedSharedData),
            2 => Ok(ArtifactDataClassV1::PublicRecord),
            3 => Ok(ArtifactDataClassV1::AggregateData),
            4 => Ok(ArtifactDataClassV1::StructuralAuditMetadata),
            _ => Err(ArtifactRegistrationErrorV1::UnsupportedValue),
        }
    }

    fn optionality(&mut self) -> Result<ArtifactOptionalityV1, ArtifactRegistrationErrorV1> {
        match self.head(0)? {
            0 => Ok(ArtifactOptionalityV1::Required),
            1 => Ok(ArtifactOptionalityV1::Optional),
            _ => Err(ArtifactRegistrationErrorV1::UnsupportedValue),
        }
    }

    fn transition_rule(&mut self) -> Result<ArtifactTransitionRuleV1, ArtifactRegistrationErrorV1> {
        match self.head(0)? {
            0 => Ok(ArtifactTransitionRuleV1::PreserveExact),
            1 => Ok(ArtifactTransitionRuleV1::RedactViews),
            2 => Ok(ArtifactTransitionRuleV1::RetainStructure),
            3 => Ok(ArtifactTransitionRuleV1::Remove),
            _ => Err(ArtifactRegistrationErrorV1::UnsupportedValue),
        }
    }

    fn roles(&mut self) -> Result<Vec<KeyRoleV1>, ArtifactRegistrationErrorV1> {
        let count = self.bounded_array(5)?;
        let mut roles = Vec::with_capacity(count);
        for _ in 0..count {
            roles.push(self.role()?);
        }
        Ok(roles)
    }

    fn dependencies(
        &mut self,
    ) -> Result<Vec<ArtifactKeyDependencyV1>, ArtifactRegistrationErrorV1> {
        let count = self.bounded_array(MAX_ARTIFACT_REGISTRATION_KEYS_V1)?;
        let mut dependencies = Vec::with_capacity(count);
        for _ in 0..count {
            self.array(5)?;
            let owner_id = self.owner()?;
            let role = self.role()?;
            let epoch = self.head(0)?;
            let material_digest = self.hash()?;
            let private_material_required = self.boolean()?;
            dependencies.push(ArtifactKeyDependencyV1 {
                identity: KeyIdentityV1::from_parts(owner_id, role, epoch),
                material_digest,
                private_material_required,
            });
        }
        Ok(dependencies)
    }

    fn children(&mut self) -> Result<Vec<ArtifactChildEdgeV1>, ArtifactRegistrationErrorV1> {
        let count = self.bounded_array(MAX_ARTIFACT_REGISTRATION_CHILDREN_V1)?;
        let mut children = Vec::with_capacity(count);
        for _ in 0..count {
            self.array(4)?;
            children.push(ArtifactChildEdgeV1 {
                artifact_class: self.artifact_class()?,
                artifact_digest: self.hash()?,
                registration_address: self.hash()?,
                required: self.boolean()?,
            });
        }
        Ok(children)
    }

    fn registration(
        &mut self,
    ) -> Result<ArtifactRegistrationFieldsV1, ArtifactRegistrationErrorV1> {
        self.array(11)?;
        if self.blob(4)? != b"ARD1" {
            return Err(ArtifactRegistrationErrorV1::InvalidEncoding);
        }
        if self.head(0)? != 1 {
            return Err(ArtifactRegistrationErrorV1::UnsupportedValue);
        }
        let artifact_class = self.artifact_class()?;
        let artifact_digest = self.hash()?;
        let owner_reference = self.hash()?;
        let data_class = self.data_class()?;
        let optionality = self.optionality()?;
        let transition_rule = self.transition_rule()?;
        let required_key_roles = self.roles()?;
        let key_dependencies = self.dependencies()?;
        let child_artifacts = self.children()?;
        Ok(ArtifactRegistrationFieldsV1 {
            artifact_class,
            artifact_digest,
            owner_reference,
            data_class,
            optionality,
            transition_rule,
            required_key_roles,
            key_dependencies,
            child_artifacts,
        })
    }
}
