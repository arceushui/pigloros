//! PMF1 V1 encoding (ADR-061 revision 3).
//!
//! The encoder builds the canonical 25-element array of fields 0-24 from one
//! typed draft, computes the dual-digest `ArtifactDescriptorV1` of every
//! artifact, the unsigned manifest digest (field 25), and the release digest
//! (field 27), and assembles the complete 28-field PMF1 once a signature over
//! the release digest exists. It uses the decoder's digest helpers and role
//! table, and every document it returns has first passed the strict decoder's
//! field, relation, and digest checks, so an encoder/decoder disagreement is a
//! closed [`PluginManifestErrorV1`] and never an accepted release. Closure
//! equality and artifact content are checked later against a verified OCI
//! bundle; no signature is created or verified here.

use pos_core::OwnerIdV1;

use super::{
    check_relations, check_signed_digests, decode, release_digest, role_digest,
    unsigned_manifest_digest, Digest, PluginManifestErrorV1, Role, COMPONENT, LICENCE, MAGIC,
    PROVENANCE, SBOM, SCHEMA, UNSIGNED_HEAD, WIT, WORLD,
};
use crate::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
};

/// Field 26's `algorithm`: pure Ed25519.
const ALGORITHM_ED25519: u64 = 1;
/// Field 26's `role_code`: `PluginReleaseSigning`.
const ROLE_CODE: u64 = 3;
/// Elements of the unsigned array of fields 0-24.
const UNSIGNED_FIELDS: usize = 25;
/// Elements of the complete PMF1 array.
const COMPLETE_FIELDS: usize = 28;
/// Epoch of the throwaway field 26 used only to validate a draft.
const VALIDATION_ONLY_EPOCH: u64 = 1;
/// The PMF1 version written to field 1.
const PMF1_VERSION: u64 = 1;
/// Field 16: PMF1 V1 declares no migration, so it is the empty array.
const NO_MIGRATIONS: usize = 0;
/// The only ABI major a dependency descriptor may name in V1.
const DEPENDENCY_ABI_MAJOR: u64 = 0;
/// Elements of field 26, `[algorithm, role_code, epoch, signature]`.
const SIGNATURE_FIELDS: usize = 4;
/// Elements of an `ArtifactDescriptorV1` and of a `SchemaDescriptorV1`.
const DESCRIPTOR_FIELDS: usize = 4;
/// Upper bound of bytes that fields 25-27 add after the unsigned array: the 34-byte field 25 and
/// field 27, and the field 26 array with its epoch in a 9-byte head.
const SIGNED_TAIL_MAX: usize = 146;

/// The exact bytes of one artifact and the raw SHA-256 of those bytes.
///
/// The ADR-102 closure layer digest is that SHA-256, which `pos-crypto` does
/// not compute, so the caller supplies it. A wrong value cannot produce an
/// accepted release: the decoder proves every descriptor against the verified
/// OCI closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginArtifactInputV1<'a> {
    /// The exact artifact bytes.
    pub bytes: &'a [u8],
    /// The raw SHA-256 of `bytes` (`sha256_32`).
    pub sha256: Digest,
}

/// One `SchemaDescriptorV1` (fields 11-13).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginSchemaInputV1<'a> {
    /// The schema ID.
    pub id: u32,
    /// The schema version, at least 1.
    pub version: u32,
    /// The schema JSON document.
    pub artifact: PluginArtifactInputV1<'a>,
    /// The maximum accepted instance size, 1 to 1,048,576.
    pub max_bytes: u32,
}

/// One `DependencyDescriptorV1` (field 17), fixed to the V1 world and ABI
/// major.
///
/// Members are raw primitives on purpose: the strict decoder, which runs on
/// every draft before it can be signed, is the single validator of their
/// grammar and ranges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginDependencyInputV1 {
    /// The ID-grammar dependency ID.
    pub dependency_id: String,
    /// The dependency's release digest.
    pub release_digest: Digest,
    /// The lowest acceptable dependency ABI minor.
    pub min_minor: u16,
    /// The highest acceptable dependency ABI minor.
    pub max_minor: u16,
    /// Strictly increasing required feature IDs.
    pub required_features: Vec<String>,
    /// Strictly increasing capability IDs.
    pub capability_ids: Vec<String>,
    /// The dependency class in WIT enum order, 0 to 4.
    pub class: u8,
}

/// The typed content of PMF1 fields 2-24.
///
/// Fields 0, 1, 4 and 16 are fixed by V1 and not draft members. Lists other
/// than licences must be given in PMF1 order; licences are sorted by
/// `sha256_32` because that order is derived from the artifact digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginReleaseDraftV1<'a> {
    /// Field 2: the Plugin ID.
    pub plugin_id: String,
    /// Field 3: the release version.
    pub release_version: String,
    /// Fields 5-8: the ABI requirement.
    pub abi: PluginAbiRequirementV1,
    /// Field 9: the Component.
    pub component: PluginArtifactInputV1<'a>,
    /// Field 10: the WIT archive.
    pub wit: PluginArtifactInputV1<'a>,
    /// Field 11: the event schemas.
    pub event_schemas: Vec<PluginSchemaInputV1<'a>>,
    /// Field 12: the state schema.
    pub state_schema: PluginSchemaInputV1<'a>,
    /// Field 13: the optional configuration schema.
    pub configuration_schema: Option<PluginSchemaInputV1<'a>>,
    /// Field 14: the capability descriptors.
    pub capabilities: Vec<PluginCapabilityDescriptorV1>,
    /// Field 15: the deterministic budget.
    pub budget: DeterministicBudgetV1,
    /// Field 17: the dependency descriptors.
    pub dependencies: Vec<PluginDependencyInputV1>,
    /// Field 18: the source provenance.
    pub provenance: PluginArtifactInputV1<'a>,
    /// Field 19: the SBOM.
    pub sbom: PluginArtifactInputV1<'a>,
    /// Field 20: the licence texts.
    pub licences: Vec<PluginArtifactInputV1<'a>>,
    /// Field 21: the publisher owner.
    pub owner: OwnerIdV1,
    /// Field 22: the first valid UTC second.
    pub not_before: i64,
    /// Field 23: the first UTC second at which the release is no longer valid.
    pub not_after: i64,
    /// Field 24: the previous release digest.
    pub previous_release_digest: Option<Digest>,
}

impl PluginReleaseDraftV1<'_> {
    /// Encode fields 0-24 and compute the unsigned manifest and release
    /// digests.
    ///
    /// The returned value's [`UnsignedPluginReleaseV1::release_digest()`] is the
    /// exact 32-byte payload the publisher signs under ADR-065.
    ///
    /// # Errors
    /// Returns the strict decoder's first field, relation, or digest failure
    /// when the draft would not form a valid PMF1, so no invalid draft
    /// reaches signing.
    pub fn unsigned(&self) -> Result<UnsignedPluginReleaseV1, PluginManifestErrorV1> {
        let mut out = Out(Vec::new());
        out.array(UNSIGNED_FIELDS);
        out.text(MAGIC);
        out.unsigned(PMF1_VERSION);
        out.text(&self.plugin_id);
        out.text(&self.release_version);
        out.text(WORLD);
        self.write_abi(&mut out);
        let component = out.artifact(&COMPONENT, &self.component);
        let wit = out.artifact(&WIT, &self.wit);
        self.write_schemas(&mut out);
        self.write_execution_bounds(&mut out);
        self.write_supply_chain(&mut out);
        out.text(self.owner.as_str());
        out.signed(self.not_before);
        out.signed(self.not_after);
        out.optional_digest(self.previous_release_digest.as_ref());
        let manifest_digest = unsigned_manifest_digest(&[out.0.as_slice()]);
        let release = release_digest(&manifest_digest, &component, &wit);
        let unsigned = UnsignedPluginReleaseV1 {
            unsigned: out.0,
            manifest_digest,
            release_digest: release,
            owner: self.owner,
        };
        unsigned.validate()?;
        Ok(unsigned)
    }

    /// Fields 5-8.
    fn write_abi(&self, out: &mut Out) {
        out.unsigned(u64::from(self.abi.major));
        out.unsigned(u64::from(self.abi.min_minor));
        out.unsigned(u64::from(self.abi.max_minor));
        out.texts(&self.abi.required_features);
    }

    /// Fields 11-13.
    fn write_schemas(&self, out: &mut Out) {
        out.array(self.event_schemas.len());
        for schema in &self.event_schemas {
            out.schema(schema);
        }
        out.schema(&self.state_schema);
        let Some(schema) = &self.configuration_schema else {
            out.null();
            return;
        };
        out.schema(schema);
    }

    /// Fields 14-16.
    fn write_execution_bounds(&self, out: &mut Out) {
        out.array(self.capabilities.len());
        for capability in &self.capabilities {
            out.capability(capability);
        }
        out.budget(&self.budget);
        out.array(NO_MIGRATIONS);
    }

    /// Fields 17-20.
    fn write_supply_chain(&self, out: &mut Out) {
        out.array(self.dependencies.len());
        for dependency in &self.dependencies {
            out.dependency(dependency);
        }
        out.artifact(&PROVENANCE, &self.provenance);
        out.artifact(&SBOM, &self.sbom);
        let mut licences = self.licences.iter().collect::<Vec<_>>();
        licences.sort_by_key(|licence| licence.sha256);
        out.array(licences.len());
        for licence in licences {
            out.artifact(&LICENCE, licence);
        }
    }
}

/// Fields 0-24 of a PMF1 with its field 25 and field 27 digests, awaiting a
/// signature over the release digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedPluginReleaseV1 {
    unsigned: Vec<u8>,
    manifest_digest: Digest,
    release_digest: Digest,
    owner: OwnerIdV1,
}

impl UnsignedPluginReleaseV1 {
    /// Field 27: the 32-byte payload the publisher signs.
    #[must_use]
    pub const fn release_digest(&self) -> Digest {
        self.release_digest
    }

    /// Field 25: the unsigned manifest digest, stable across re-signing.
    #[must_use]
    pub const fn unsigned_manifest_digest(&self) -> Digest {
        self.manifest_digest
    }

    /// The publisher owner (field 21) that signs under the registry identity.
    #[must_use]
    pub const fn owner(&self) -> OwnerIdV1 {
        self.owner
    }

    /// The canonical 25-element array of fields 0-24.
    #[must_use]
    pub fn unsigned_bytes(&self) -> &[u8] {
        &self.unsigned
    }

    /// Run the decoder over this document with a throwaway signature.
    ///
    /// Decoding checks structure, relations, and digests only and never a
    /// signature, so any well-formed field 26 stands in for the real one.
    fn validate(&self) -> Result<(), PluginManifestErrorV1> {
        self.with_signature(VALIDATION_ONLY_EPOCH, [0; 64])
            .map(drop)
    }

    /// Assemble the complete 28-field PMF1 with field 26
    /// `[1, 3, epoch, signature]`.
    ///
    /// # Errors
    /// Returns the strict decoder's failure when `epoch` is zero or the
    /// document is otherwise not a valid PMF1.
    pub fn with_signature(
        &self,
        epoch: u64,
        signature: [u8; 64],
    ) -> Result<Vec<u8>, PluginManifestErrorV1> {
        let mut out = Out(Vec::with_capacity(self.unsigned.len() + SIGNED_TAIL_MAX));
        out.array(COMPLETE_FIELDS);
        // Invariant: only `unsigned()` builds this type, and it always begins
        // with the two-byte `UNSIGNED_HEAD` of the 25-element array.
        out.0
            .extend_from_slice(&self.unsigned[UNSIGNED_HEAD.len()..]);
        out.bytes(&self.manifest_digest);
        out.array(SIGNATURE_FIELDS);
        out.unsigned(ALGORITHM_ED25519);
        out.unsigned(ROLE_CODE);
        out.unsigned(epoch);
        out.bytes(&signature);
        out.bytes(&self.release_digest);
        accept(&out.0)?;
        Ok(out.0)
    }
}

/// The decoder's field, relation, and digest checks over one complete PMF1.
fn accept(bytes: &[u8]) -> Result<(), PluginManifestErrorV1> {
    let pmf1 = decode(bytes)?;
    check_relations(&pmf1)?;
    check_signed_digests(bytes, &pmf1)
}

/// A canonical CBOR writer for the PMF1 V1 subset.
///
/// Lengths convert with `as u64`: `usize` is at most 64 bits on every target
/// this repository supports, so the cast never truncates.
struct Out(Vec<u8>);

impl Out {
    /// One shortest-form head.
    fn head(&mut self, major: u8, value: u64) {
        let base = major << 5;
        let bytes = value.to_be_bytes();
        let (code, width) = match value {
            0..=23 => {
                self.0.push(base | bytes[7]);
                return;
            }
            24..=0xff => (24, 1),
            0x100..=0xffff => (25, 2),
            0x1_0000..=0xffff_ffff => (26, 4),
            _ => (27, 8),
        };
        self.0.push(base | code);
        self.0.extend_from_slice(&bytes[8 - width..]);
    }

    fn unsigned(&mut self, value: u64) {
        self.head(0, value);
    }

    fn signed(&mut self, value: i64) {
        if value < 0 {
            self.head(1, value.unsigned_abs() - 1);
        } else {
            self.head(0, value.unsigned_abs());
        }
    }

    fn array(&mut self, count: usize) {
        self.head(4, count as u64);
    }

    fn text(&mut self, value: &str) {
        self.head(3, value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.head(2, value.len() as u64);
        self.0.extend_from_slice(value);
    }

    fn boolean(&mut self, value: bool) {
        self.0.push(if value { 0xf5 } else { 0xf4 });
    }

    fn null(&mut self) {
        self.0.push(0xf6);
    }

    fn optional_digest(&mut self, value: Option<&Digest>) {
        let Some(digest) = value else {
            self.null();
            return;
        };
        self.bytes(digest);
    }

    fn texts(&mut self, values: &[String]) {
        self.array(values.len());
        for value in values {
            self.text(value);
        }
    }

    /// `[media_type, byte_length, blake3_digest32, sha256_32]`; returns the
    /// inner BLAKE3 digest.
    fn artifact(&mut self, role: &Role, input: &PluginArtifactInputV1<'_>) -> Digest {
        let blake3 = role_digest(role.domain, input.bytes);
        self.array(DESCRIPTOR_FIELDS);
        self.text(role.media_type);
        self.unsigned(input.bytes.len() as u64);
        self.bytes(&blake3);
        self.bytes(&input.sha256);
        blake3
    }

    /// `[schema_id, schema_version, artifact, max_bytes]`.
    fn schema(&mut self, schema: &PluginSchemaInputV1<'_>) {
        self.array(DESCRIPTOR_FIELDS);
        self.unsigned(u64::from(schema.id));
        self.unsigned(u64::from(schema.version));
        self.artifact(&SCHEMA, &schema.artifact);
        self.unsigned(u64::from(schema.max_bytes));
    }

    fn capability(&mut self, capability: &PluginCapabilityDescriptorV1) {
        self.array(9);
        self.text(&capability.capability_id);
        self.text(&capability.operation);
        self.text(&capability.resource_pattern);
        self.text(&capability.purpose);
        self.text(&capability.audience);
        self.boolean(capability.required);
        self.unsigned(capability.max_calls);
        self.unsigned(capability.max_request_bytes);
        self.unsigned(capability.max_response_bytes);
    }

    fn budget(&mut self, budget: &DeterministicBudgetV1) {
        self.array(8);
        for member in [
            budget.memory_bytes,
            budget.fuel,
            budget.host_calls,
            budget.event_count,
            budget.event_bytes,
            budget.state_bytes,
            budget.log_calls,
            budget.log_bytes,
        ] {
            self.unsigned(member);
        }
    }

    fn dependency(&mut self, dependency: &PluginDependencyInputV1) {
        self.array(9);
        self.text(&dependency.dependency_id);
        self.bytes(&dependency.release_digest);
        self.text(WORLD);
        self.unsigned(DEPENDENCY_ABI_MAJOR);
        self.unsigned(u64::from(dependency.min_minor));
        self.unsigned(u64::from(dependency.max_minor));
        self.texts(&dependency.required_features);
        self.texts(&dependency.capability_ids);
        self.unsigned(u64::from(dependency.class));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn encoded(write: impl FnOnce(&mut Out)) -> Vec<u8> {
        let mut out = Out(Vec::new());
        write(&mut out);
        out.0
    }

    /// RFC 8949 appendix A heads at every width boundary.
    #[test]
    fn unsigned_heads_are_shortest_form_at_every_width_boundary() {
        let cases: [(u64, &[u8]); 11] = [
            (0, &[0x00]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (255, &[0x18, 0xff]),
            (256, &[0x19, 0x01, 0x00]),
            (65_535, &[0x19, 0xff, 0xff]),
            (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
            (4_294_967_295, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
            (4_294_967_296, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
            (
                u64::MAX,
                &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
            (1_000_000, &[0x1a, 0x00, 0x0f, 0x42, 0x40]),
        ];
        for (value, expected) in cases {
            assert_eq!(encoded(|out| out.unsigned(value)), expected, "{value}");
        }
    }

    #[test]
    fn signed_integers_use_major_one_for_negative_values() {
        let cases: [(i64, &[u8]); 7] = [
            (0, &[0x00]),
            (
                i64::MAX,
                &[0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
            (-1, &[0x20]),
            (-24, &[0x37]),
            (-25, &[0x38, 0x18]),
            (-100, &[0x38, 0x63]),
            (
                i64::MIN,
                &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(encoded(|out| out.signed(value)), expected, "{value}");
        }
    }

    #[test]
    fn text_bytes_booleans_and_null_use_their_major_types() {
        assert_eq!(
            encoded(|out| out.text("PMF1")),
            [0x64, 0x50, 0x4d, 0x46, 0x31]
        );
        assert_eq!(encoded(|out| out.bytes(&[1, 2])), [0x42, 1, 2]);
        assert_eq!(encoded(|out| out.boolean(true)), [0xf5]);
        assert_eq!(encoded(|out| out.boolean(false)), [0xf4]);
        assert_eq!(encoded(Out::null), [0xf6]);
        assert_eq!(encoded(|out| out.array(25)), UNSIGNED_HEAD);
        assert_eq!(encoded(|out| out.array(COMPLETE_FIELDS)), [0x98, 0x1c]);
        assert_eq!(encoded(|out| out.optional_digest(None)), [0xf6]);
        assert_eq!(encoded(|out| out.optional_digest(Some(&[7; 32]))).len(), 34);
    }
}
