//! Bounded, stateless PTR1 and PRV1 verification (ADR-103).

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use pos_core::OwnerIdV1;
use pos_plugin_release::VerifiedReleaseBundleV1;
use thiserror::Error;

use crate::plugin_manifest::{self, PluginManifestErrorV1};
use crate::strict_cbor::StrictCborError;

/// PTR1 and PRV1 report no field ordinal.
type Reader<'a> = crate::strict_cbor::Reader<'a, PluginTrustErrorV1>;

const ROOT_KEY_DOMAIN: &[u8] = b"pigloros/plugin-root-key-id/v1\0";
const ROOT_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-trust-root/v1\0";
const REVOCATION_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-revocation/v1\0";

/// Maximum complete canonical PTR1 or PRV1 record size in bytes.
const MAX_RECORD_BYTES: usize = 1024 * 1024;
/// Maximum UTF-8 bytes in a policy scope, owner, or Plugin ID text field.
const MAX_TEXT_BYTES: usize = 128;
/// Maximum root keys, and therefore root threshold, in one PTR1.
const MAX_ROOT_KEYS: usize = 32;
/// Maximum publisher keys or exact Plugin ID grants in one PTR1.
const MAX_PUBLISHER_ENTRIES: usize = 256;
/// Maximum root-key signatures carried by one PTR1 or PRV1.
const MAX_SIGNATURES: usize = 64;
/// Maximum entries in either cumulative PRV1 revocation collection.
const MAX_REVOCATION_ENTRIES: usize = 4096;
/// V1 lifetime ceiling on complete PTR1 records in one verified history.
const MAX_ROOT_HISTORY: usize = 64;
/// V1 lifetime ceiling on complete PRV1 records in one verified history.
const MAX_REVOCATION_HISTORY: usize = 256;

/// A closed failure from the stateless Plugin trust verifier.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginTrustErrorV1 {
    /// CBOR type, width, canonical form, or record schema is invalid.
    #[error("invalid Plugin trust record encoding")]
    InvalidEncoding,
    /// A record exceeds a V1 per-record bound.
    #[error("Plugin trust record exceeds a V1 bound")]
    BoundsExceeded,
    /// A signature or public key is invalid.
    #[error("invalid Plugin trust record signature")]
    InvalidSignature,
    /// A signature names no root key authorized by the relevant PTR1 record.
    #[error("Plugin trust record signature names an unknown root key")]
    UnknownRootKey,
    /// Too few authorized, distinct root keys signed.
    #[error("Plugin trust root threshold is not met")]
    ThresholdNotMet,
    /// The supplied genesis does not match the operator-pinned anchor.
    #[error("Plugin trust genesis anchor differs")]
    AnchorMismatch,
    /// A chain link or cumulative set is invalid.
    #[error("Plugin trust chain is discontinuous")]
    ChainDiscontinuity,
    /// An authenticated complete-record digest does not match its required link.
    #[error("Plugin trust record digest link differs")]
    DigestMismatch,
    /// Terminal signed metadata is not valid at the supplied UTC second.
    #[error("terminal Plugin trust metadata is expired or not yet valid")]
    Expired,
    /// V1 accepts at most 64 complete PTR1 records.
    #[error("Plugin root history capacity exceeded")]
    RootHistoryCapacityExceeded,
    /// V1 accepts at most 256 complete PRV1 records.
    #[error("Plugin revocation history capacity exceeded")]
    RevocationHistoryCapacityExceeded,
    /// A cumulative revocation set cannot grow beyond 4096 entries.
    #[error("Plugin revocation capacity exhausted")]
    RevocationCapacityExhausted,
    /// The PMF1 projection is not a complete, canonical V1 projection.
    #[error("Plugin manifest projection is incomplete or invalid")]
    IncompleteManifestProjection,
    /// The PMF1 validity interval does not contain the evidence UTC second.
    #[error("Plugin manifest is expired or not yet valid")]
    ManifestExpired,
    /// The terminal PTR1 names no publisher key for the PMF1 owner/role/epoch.
    #[error("Plugin manifest publisher key is unknown")]
    UnknownPublisherKey,
    /// The terminal PTR1 grants the exact PMF1 Plugin ID to no matching owner.
    #[error("Plugin manifest Plugin ID is not granted to its publisher")]
    PluginIdNotGranted,
    /// The resolved publisher key is effectively revoked at the evidence Tick.
    #[error("Plugin manifest publisher key is revoked")]
    PublisherKeyRevoked,
    /// The release digest or a descriptor digest is effectively revoked.
    #[error("Plugin manifest artifact is revoked")]
    ArtifactRevoked,
}

impl StrictCborError for PluginTrustErrorV1 {
    fn invalid_encoding(_ordinal: u8) -> Self {
        Self::InvalidEncoding
    }

    fn bounds_exceeded(_ordinal: u8) -> Self {
        Self::BoundsExceeded
    }
}

/// A caller-pinned genesis digest and exact policy scope. #424 authenticates its source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPluginRootAnchorV1 {
    scope: String,
    genesis_digest: [u8; 32],
}

impl TrustedPluginRootAnchorV1 {
    /// Construct a pin after validating the exact scope grammar.
    ///
    /// # Errors
    /// Returns `InvalidEncoding` for an invalid scope.
    pub fn new(scope: &str, genesis_digest: [u8; 32]) -> Result<Self, PluginTrustErrorV1> {
        validate_plugin_id(scope)?;
        Ok(Self {
            scope: scope.to_owned(),
            genesis_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RootKey {
    id: [u8; 32],
    public: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PublisherKey {
    owner: OwnerIdV1,
    epoch: u64,
    public: [u8; 32],
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Grant {
    plugin_id: String,
    owner: OwnerIdV1,
}

#[derive(Clone, Copy, Debug)]
struct RootSignature {
    id: [u8; 32],
    bytes: [u8; 64],
}

/// One exact canonical PTR1 record. The stateless verifier authenticates its chain.
#[derive(Clone, Debug)]
pub struct PluginTrustRootRecordV1 {
    scope: String,
    version: u64,
    not_before: i64,
    expires: i64,
    previous: Option<[u8; 32]>,
    threshold: usize,
    keys: Vec<RootKey>,
    publishers: Vec<PublisherKey>,
    grants: Vec<Grant>,
    signatures: Vec<RootSignature>,
    message: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RevokedPublisherKey {
    publisher: PublisherKey,
    tick: u64,
    reason: u64,
    replacement: Option<PublisherKey>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RevokedArtifact {
    digest: [u8; 32],
    tick: u64,
    reason: u64,
    replacement: Option<[u8; 32]>,
}

/// One exact canonical PRV1 record. The stateless verifier authenticates its chain.
#[derive(Clone, Debug)]
pub struct PluginRevocationRecordV1 {
    scope: String,
    epoch: u64,
    not_before: i64,
    expires: i64,
    root_digest: [u8; 32],
    previous: Option<[u8; 32]>,
    tick: u64,
    keys: Vec<RevokedPublisherKey>,
    artifacts: Vec<RevokedArtifact>,
    signatures: Vec<RootSignature>,
    message: Vec<u8>,
    digest: [u8; 32],
}

/// Facts authenticated at one explicit UTC second and host Tick.
#[derive(Clone, Debug)]
pub struct VerifiedPluginTrustEvidenceV1 {
    scope: String,
    root_history: Vec<(u64, [u8; 32])>,
    revocation_history: Vec<(u64, [u8; 32])>,
    root_version: u64,
    root_digest: [u8; 32],
    policy_epoch: u64,
    revocation_digest: [u8; 32],
    evaluation_utc_second: i64,
    evaluation_tick: u64,
    root_validity: (i64, i64),
    revocation_validity: (i64, i64),
    root_keys: Vec<RootKey>,
    publishers: Vec<PublisherKey>,
    grants: Vec<Grant>,
    revoked_keys: BTreeSet<PublisherKey>,
    revoked_artifacts: BTreeSet<[u8; 32]>,
    terminal_revoked_key_count: usize,
    terminal_revoked_artifact_count: usize,
}

impl VerifiedPluginTrustEvidenceV1 {
    /// The exact policy scope verified from the pinned genesis.
    #[must_use]
    pub fn policy_scope(&self) -> &str {
        &self.scope
    }

    /// Every authenticated PTR1 version and complete-record digest, from
    /// pinned genesis through the verified terminal root.
    pub fn verified_root_history(&self) -> impl Iterator<Item = (u64, [u8; 32])> + '_ {
        self.root_history.iter().copied()
    }

    /// Every authenticated PRV1 epoch and complete-record digest, from
    /// genesis through the verified terminal revocation record.
    pub fn verified_revocation_history(&self) -> impl Iterator<Item = (u64, [u8; 32])> + '_ {
        self.revocation_history.iter().copied()
    }

    /// Terminal PTR1 version and complete-record digest.
    #[must_use]
    pub const fn terminal_root(&self) -> (u64, [u8; 32]) {
        (self.root_version, self.root_digest)
    }

    /// Terminal PRV1 epoch and complete-record digest.
    #[must_use]
    pub const fn terminal_revocation(&self) -> (u64, [u8; 32]) {
        (self.policy_epoch, self.revocation_digest)
    }

    /// The caller-supplied UTC second and host Tick bound to these facts.
    #[must_use]
    pub const fn evaluation_coordinates(&self) -> (i64, u64) {
        (self.evaluation_utc_second, self.evaluation_tick)
    }

    /// Terminal signed UTC validity intervals.
    #[must_use]
    pub const fn terminal_validity(&self) -> ((i64, i64), (i64, i64)) {
        (self.root_validity, self.revocation_validity)
    }

    /// Root key IDs and public keys in the verified terminal PTR1, ordered by
    /// canonical root key ID.
    pub fn terminal_root_keys(&self) -> impl Iterator<Item = ([u8; 32], [u8; 32])> + '_ {
        self.root_keys.iter().map(|key| (key.id, key.public))
    }

    /// Effective publisher-key denials at the bound Tick.
    pub fn effective_key_revocations(
        &self,
    ) -> impl Iterator<Item = (OwnerIdV1, u64, [u8; 32])> + '_ {
        self.revoked_keys
            .iter()
            .map(|key| (key.owner, key.epoch, key.public))
    }

    /// Effective artifact-digest denials at the bound Tick.
    pub fn effective_artifact_revocations(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.revoked_artifacts.iter().copied()
    }

    /// Resolve one complete PMF1 projection against this terminal evidence.
    ///
    /// ADR-103 makes this the only release query. It succeeds only when the
    /// terminal PTR1 has exactly one publisher key for the PMF1 owner, role 3,
    /// and epoch; exactly one exact Plugin-ID grant to that owner; the PMF1
    /// interval contains the bound UTC second; and neither that key, the
    /// release digest, nor any descriptor digest is effective at the bound
    /// Tick. PTR1 decoding already rejects duplicate publisher identities and
    /// duplicate Plugin IDs, so a single match is the exactly-one match.
    ///
    /// The returned fact resolves the key for #401's PMF1 signature check. It
    /// does not verify that signature, authenticate TPS1, persist a floor,
    /// admit a release, or activate a Plugin.
    ///
    /// # Errors
    /// Returns `RevocationCapacityExhausted` when either terminal cumulative
    /// PRV1 collection is full (including future-effective entries), because
    /// V1 cannot represent another denial;
    /// `IncompleteManifestProjection` (only for a `test-support` fixture
    /// projection), `ManifestExpired`,
    /// `UnknownPublisherKey`, `PluginIdNotGranted`, `PublisherKeyRevoked`, or
    /// `ArtifactRevoked` for the corresponding failed release check.
    pub fn authorize_release(
        &self,
        manifest: &ValidatedPluginManifestProjectionV1,
    ) -> Result<ResolvedPluginTrustAuthorizationV1, PluginTrustErrorV1> {
        if self.terminal_revoked_key_count == MAX_REVOCATION_ENTRIES
            || self.terminal_revoked_artifact_count == MAX_REVOCATION_ENTRIES
        {
            return Err(PluginTrustErrorV1::RevocationCapacityExhausted);
        }
        if !manifest.is_complete() {
            return Err(PluginTrustErrorV1::IncompleteManifestProjection);
        }
        if self.evaluation_utc_second < manifest.not_before
            || self.evaluation_utc_second >= manifest.not_after
        {
            return Err(PluginTrustErrorV1::ManifestExpired);
        }
        let publisher = self
            .publishers
            .iter()
            .find(|key| key.owner == manifest.owner && key.epoch == manifest.epoch)
            .ok_or(PluginTrustErrorV1::UnknownPublisherKey)?;
        if !self
            .grants
            .iter()
            .any(|grant| grant.plugin_id == manifest.plugin_id && grant.owner == manifest.owner)
        {
            return Err(PluginTrustErrorV1::PluginIdNotGranted);
        }
        if self.revoked_keys.contains(publisher) {
            return Err(PluginTrustErrorV1::PublisherKeyRevoked);
        }
        if std::iter::once(&manifest.release_digest)
            .chain(&manifest.descriptor_digests)
            .any(|digest| self.revoked_artifacts.contains(digest))
        {
            return Err(PluginTrustErrorV1::ArtifactRevoked);
        }
        Ok(ResolvedPluginTrustAuthorizationV1 {
            public_key: publisher.public,
            pmf1_digest: manifest.pmf1_digest,
            terminal_root: (self.root_version, self.root_digest),
            terminal_revocation: (self.policy_epoch, self.revocation_digest),
            evaluation_utc_second: self.evaluation_utc_second,
            evaluation_tick: self.evaluation_tick,
        })
    }
}

/// The complete ADR-103 release projection of one canonical PMF1 manifest.
///
/// The only production constructor is [`Self::from_verified_bundle`], which
/// strictly decodes the complete PMF1 V1 member of one verified OCI release
/// closure, proves that closure equal to the PMF1 descriptors, recomputes
/// every inner, manifest, and release digest, and derives the descriptor
/// digest set from the PMF1 structure (ADR-061 revision 3). Its fields are
/// private, so callers cannot supply an arbitrary interval or a partial digest
/// list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPluginManifestProjectionV1 {
    pmf1_digest: [u8; 32],
    plugin_id: String,
    owner: OwnerIdV1,
    role: u64,
    epoch: u64,
    not_before: i64,
    not_after: i64,
    release_digest: [u8; 32],
    descriptor_digests: Vec<[u8; 32]>,
}

impl ValidatedPluginManifestProjectionV1 {
    /// Construct the complete projection from one verified OCI release closure.
    ///
    /// The PMF1 bytes are the closure's `pmf1` member, so a caller supplies no
    /// PMF1 bytes, IDs, or digests. The projection binds the complete-PMF1
    /// BLAKE3 digest, the Plugin ID, the publisher owner, role, and epoch, the
    /// release interval, the release digest, and both digests of every
    /// artifact descriptor plus every dependency release digest. It does not
    /// verify the PMF1 signature or validate artifact content.
    ///
    /// # Errors
    /// Returns the first ADR-061 revision 3 decode, closure, inner-digest, or
    /// manifest/release-digest failure, and no projection.
    pub fn from_verified_bundle(
        bundle: &VerifiedReleaseBundleV1,
    ) -> Result<Self, PluginManifestErrorV1> {
        plugin_manifest::project_verified_bundle(bundle).map(|projection| Self {
            pmf1_digest: projection.pmf1_digest,
            plugin_id: projection.plugin_id,
            owner: projection.owner,
            role: projection.role,
            epoch: projection.epoch,
            not_before: projection.not_before,
            not_after: projection.not_after,
            release_digest: projection.release_digest,
            descriptor_digests: projection.descriptor_digests,
        })
    }

    fn is_complete(&self) -> bool {
        self.role == 3
            && self.epoch != 0
            && self.not_before < self.not_after
            && validate_plugin_id(&self.plugin_id).is_ok()
            && self
                .descriptor_digests
                .iter()
                .zip(self.descriptor_digests.iter().skip(1))
                .all(|(earlier, later)| earlier < later)
    }
}

/// Raw, unchecked projection fields for public-seam test fixtures only.
///
/// This type exists only with the `test-support` feature, which
/// `scripts/check_test_support_features.py` keeps out of deployable dependency
/// graphs. It represents a caller-fabricated projection, so tests can reach
/// the incomplete-projection checks that a projection built by
/// [`ValidatedPluginManifestProjectionV1::from_verified_bundle`] never fails;
/// it is not a PMF1 parser and establishes no release authority.
#[cfg(feature = "test-support")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginManifestProjectionFixtureV1 {
    /// BLAKE3-256 of the complete canonical PMF1 bytes.
    pub pmf1_digest: [u8; 32],
    /// Exact PMF1 field 2 Plugin ID text.
    pub plugin_id: String,
    /// PMF1 publisher owner.
    pub owner: OwnerIdV1,
    /// PMF1 publisher role code; V1 requires 3.
    pub role: u64,
    /// PMF1 publisher key epoch.
    pub epoch: u64,
    /// First UTC second at which the release is valid.
    pub not_before: i64,
    /// First UTC second at which the release is no longer valid.
    pub not_after: i64,
    /// PMF1 release digest.
    pub release_digest: [u8; 32],
    /// Every reachable descriptor digest, strictly sorted.
    pub descriptor_digests: Vec<[u8; 32]>,
}

#[cfg(feature = "test-support")]
impl From<PluginManifestProjectionFixtureV1> for ValidatedPluginManifestProjectionV1 {
    fn from(fixture: PluginManifestProjectionFixtureV1) -> Self {
        Self {
            pmf1_digest: fixture.pmf1_digest,
            plugin_id: fixture.plugin_id,
            owner: fixture.owner,
            role: fixture.role,
            epoch: fixture.epoch,
            not_before: fixture.not_before,
            not_after: fixture.not_after,
            release_digest: fixture.release_digest,
            descriptor_digests: fixture.descriptor_digests,
        }
    }
}

/// The ADR-103 trust-authorization fact for one complete PMF1 projection.
///
/// It binds the resolved publisher key to the complete-PMF1 digest, the
/// terminal PTR1/PRV1 coordinates, and the evaluation UTC second and Tick of
/// the evidence that produced it. It is not a PMF1 signature verification,
/// TPS1 authentication, release admission, or activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedPluginTrustAuthorizationV1 {
    public_key: [u8; 32],
    pmf1_digest: [u8; 32],
    terminal_root: (u64, [u8; 32]),
    terminal_revocation: (u64, [u8; 32]),
    evaluation_utc_second: i64,
    evaluation_tick: u64,
}

impl ResolvedPluginTrustAuthorizationV1 {
    /// The exact terminal PTR1 publisher key #401 uses to verify PMF1.
    #[must_use]
    pub const fn resolved_public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// BLAKE3-256 of the complete canonical PMF1 bytes bound to this fact.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.pmf1_digest
    }

    /// Terminal PTR1 version and complete-record digest of the evidence.
    #[must_use]
    pub const fn terminal_root(&self) -> (u64, [u8; 32]) {
        self.terminal_root
    }

    /// Terminal PRV1 epoch and complete-record digest of the evidence.
    #[must_use]
    pub const fn terminal_revocation(&self) -> (u64, [u8; 32]) {
        self.terminal_revocation
    }

    /// The evidence UTC second and host Tick bound to this fact.
    #[must_use]
    pub const fn evaluation_coordinates(&self) -> (i64, u64) {
        (self.evaluation_utc_second, self.evaluation_tick)
    }
}

fn validate_plugin_id(value: &str) -> Result<(), PluginTrustErrorV1> {
    if plugin_manifest::valid_id_text(value) {
        Ok(())
    } else {
        Err(PluginTrustErrorV1::InvalidEncoding)
    }
}

fn read_owner(reader: &mut Reader<'_>) -> Result<OwnerIdV1, PluginTrustErrorV1> {
    OwnerIdV1::new(reader.text(MAX_TEXT_BYTES)?.to_owned())
        .map_err(|_| PluginTrustErrorV1::InvalidEncoding)
}

fn read_publisher(reader: &mut Reader<'_>) -> Result<PublisherKey, PluginTrustErrorV1> {
    if reader.array(4)? != 4 {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    let owner = read_owner(reader)?;
    if reader.unsigned()? != 3 {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    let epoch = reader.unsigned()?;
    if epoch == 0 {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    let public = reader.bytes()?;
    VerifyingKey::from_bytes(&public).map_err(|_| PluginTrustErrorV1::InvalidEncoding)?;
    Ok(PublisherKey {
        owner,
        epoch,
        public,
    })
}

fn read_optional_publisher(
    reader: &mut Reader<'_>,
) -> Result<Option<PublisherKey>, PluginTrustErrorV1> {
    if reader.null() {
        Ok(None)
    } else {
        read_publisher(reader).map(Some)
    }
}

fn read_signatures(reader: &mut Reader<'_>) -> Result<Vec<RootSignature>, PluginTrustErrorV1> {
    let count = reader.array(MAX_SIGNATURES)?;
    if count == 0 {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    let mut signatures = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        if reader.array(2)? != 2 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let id = reader.bytes()?;
        if previous.is_some_and(|old| old >= id) {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let bytes = reader.bytes()?;
        signatures.push(RootSignature { id, bytes });
        previous = Some(id);
    }
    Ok(signatures)
}

fn read_header(reader: &mut Reader<'_>, magic: &str) -> Result<String, PluginTrustErrorV1> {
    if reader.array(12)? != 12 || reader.text(4)? != magic || reader.unsigned()? != 1 {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    let scope = reader.text(MAX_TEXT_BYTES)?;
    validate_plugin_id(scope)?;
    Ok(scope.to_owned())
}

fn read_interval(reader: &mut Reader<'_>) -> Result<(i64, i64), PluginTrustErrorV1> {
    let not_before = reader.signed()?;
    let expires = reader.signed()?;
    let duration = i128::from(expires) - i128::from(not_before);
    if !(1..=31_622_400).contains(&duration) {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    Ok((not_before, expires))
}

fn signature_message(domain: &[u8], bytes: &[u8], prefix_end: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + prefix_end);
    message.extend_from_slice(domain);
    // All record fields have strict canonical CBOR decoding. Replacing the
    // one-byte 12-element header with the 11-element header yields the exact
    // canonical unsigned prefix without a second serializer.
    message.push(0x8b);
    message.extend_from_slice(&bytes[1..prefix_end]);
    message
}

fn read_root_keys(
    reader: &mut Reader<'_>,
    threshold: usize,
) -> Result<Vec<RootKey>, PluginTrustErrorV1> {
    let key_count = reader.array(MAX_ROOT_KEYS)?;
    if key_count == 0 || threshold == 0 || threshold > key_count {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    let mut keys = Vec::with_capacity(key_count);
    let mut root_publics = BTreeSet::new();
    for _ in 0..key_count {
        if reader.array(2)? != 2 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let id = reader.bytes()?;
        let public = reader.bytes()?;
        VerifyingKey::from_bytes(&public).map_err(|_| PluginTrustErrorV1::InvalidEncoding)?;
        if id != root_key_id(public)
            || keys.last().is_some_and(|old: &RootKey| old.id >= id)
            || !root_publics.insert(public)
        {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        keys.push(RootKey { id, public });
    }
    Ok(keys)
}

fn read_root_threshold(reader: &mut Reader<'_>) -> Result<usize, PluginTrustErrorV1> {
    let threshold = reader.unsigned()?;
    u8::try_from(threshold)
        .map(usize::from)
        .ok()
        .filter(|threshold| (1..=MAX_ROOT_KEYS).contains(threshold))
        .ok_or(PluginTrustErrorV1::InvalidEncoding)
}

fn read_publishers(reader: &mut Reader<'_>) -> Result<Vec<PublisherKey>, PluginTrustErrorV1> {
    let publisher_count = reader.array(MAX_PUBLISHER_ENTRIES)?;
    let mut publishers = Vec::with_capacity(publisher_count);
    let mut publisher_publics = BTreeSet::new();
    let mut publisher_identities = BTreeSet::new();
    for _ in 0..publisher_count {
        let publisher = read_publisher(reader)?;
        if publishers.last().is_some_and(|old| old >= &publisher)
            || !publisher_publics.insert(publisher.public)
            || !publisher_identities.insert((publisher.owner, publisher.epoch))
        {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        publishers.push(publisher);
    }
    Ok(publishers)
}

fn read_grants(
    reader: &mut Reader<'_>,
    publishers: &[PublisherKey],
) -> Result<Vec<Grant>, PluginTrustErrorV1> {
    let grant_count = reader.array(MAX_PUBLISHER_ENTRIES)?;
    let mut grants = Vec::with_capacity(grant_count);
    for _ in 0..grant_count {
        if reader.array(2)? != 2 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let plugin_id = reader.text(MAX_TEXT_BYTES)?;
        validate_plugin_id(plugin_id)?;
        let owner = read_owner(reader)?;
        if grants
            .last()
            .is_some_and(|old: &Grant| old.plugin_id.as_str() >= plugin_id)
            || !publishers.iter().any(|publisher| publisher.owner == owner)
        {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        grants.push(Grant {
            plugin_id: plugin_id.to_owned(),
            owner,
        });
    }
    Ok(grants)
}

impl PluginTrustRootRecordV1 {
    /// Decode one exact, bounded PTR1 record.
    ///
    /// # Errors
    /// Rejects any noncanonical or structurally invalid field.
    pub fn decode(bytes: &[u8]) -> Result<Self, PluginTrustErrorV1> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(PluginTrustErrorV1::BoundsExceeded);
        }
        let mut reader = Reader::new(bytes);
        let scope = read_header(&mut reader, "PTR1")?;
        let version = reader.unsigned()?;
        if version == 0 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let (not_before, expires) = read_interval(&mut reader)?;
        let previous = reader.optional_bytes()?;
        let threshold = read_root_threshold(&mut reader)?;
        let keys = read_root_keys(&mut reader, threshold)?;
        let publishers = read_publishers(&mut reader)?;
        let grants = read_grants(&mut reader, &publishers)?;
        let prefix_end = reader.offset();
        let signatures = read_signatures(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            scope,
            version,
            not_before,
            expires,
            previous,
            threshold,
            keys,
            publishers,
            grants,
            signatures,
            message: signature_message(ROOT_SIGNATURE_DOMAIN, bytes, prefix_end),
            digest: *blake3::hash(bytes).as_bytes(),
        })
    }

    /// BLAKE3-256 of the complete canonical record including signatures.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn root_key_id(public: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROOT_KEY_DOMAIN);
    hasher.update(&public);
    *hasher.finalize().as_bytes()
}

fn read_reason(reader: &mut Reader<'_>) -> Result<u64, PluginTrustErrorV1> {
    let reason = reader.unsigned()?;
    if !(1..=4).contains(&reason) {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    Ok(reason)
}

fn read_revoked_keys(
    reader: &mut Reader<'_>,
    effective_tick: u64,
) -> Result<Vec<RevokedPublisherKey>, PluginTrustErrorV1> {
    let count = reader.array(usize::MAX)?;
    if count > MAX_REVOCATION_ENTRIES {
        return Err(PluginTrustErrorV1::RevocationCapacityExhausted);
    }
    let mut revoked = Vec::with_capacity(count);
    for _ in 0..count {
        if reader.array(7)? != 7 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let owner = read_owner(reader)?;
        if reader.unsigned()? != 3 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let epoch = reader.unsigned()?;
        if epoch == 0 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let public = reader.bytes()?;
        let tick = reader.unsigned()?;
        let reason = read_reason(reader)?;
        let replacement = read_optional_publisher(reader)?;
        let entry = RevokedPublisherKey {
            publisher: PublisherKey {
                owner,
                epoch,
                public,
            },
            tick,
            reason,
            replacement,
        };
        if tick > effective_tick
            || revoked
                .last()
                .is_some_and(|old: &RevokedPublisherKey| old.publisher >= entry.publisher)
        {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        revoked.push(entry);
    }
    Ok(revoked)
}

fn read_revoked_artifacts(
    reader: &mut Reader<'_>,
    effective_tick: u64,
) -> Result<Vec<RevokedArtifact>, PluginTrustErrorV1> {
    let count = reader.array(usize::MAX)?;
    if count > MAX_REVOCATION_ENTRIES {
        return Err(PluginTrustErrorV1::RevocationCapacityExhausted);
    }
    let mut revoked = Vec::with_capacity(count);
    for _ in 0..count {
        if reader.array(4)? != 4 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let digest = reader.bytes()?;
        let tick = reader.unsigned()?;
        let reason = read_reason(reader)?;
        let replacement = reader.optional_bytes()?;
        if tick > effective_tick
            || revoked
                .last()
                .is_some_and(|old: &RevokedArtifact| old.digest >= digest)
        {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        revoked.push(RevokedArtifact {
            digest,
            tick,
            reason,
            replacement,
        });
    }
    Ok(revoked)
}

impl PluginRevocationRecordV1 {
    /// Decode one exact, bounded PRV1 record.
    ///
    /// # Errors
    /// Rejects any noncanonical or structurally invalid field.
    pub fn decode(bytes: &[u8]) -> Result<Self, PluginTrustErrorV1> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(PluginTrustErrorV1::BoundsExceeded);
        }
        let mut reader = Reader::new(bytes);
        let scope = read_header(&mut reader, "PRV1")?;
        let epoch = reader.unsigned()?;
        if epoch == 0 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let (not_before, expires) = read_interval(&mut reader)?;
        let root_digest = reader.bytes()?;
        let previous = reader.optional_bytes()?;
        let tick = reader.unsigned()?;
        let keys = read_revoked_keys(&mut reader, tick)?;
        let artifacts = read_revoked_artifacts(&mut reader, tick)?;
        let prefix_end = reader.offset();
        let signatures = read_signatures(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            scope,
            epoch,
            not_before,
            expires,
            root_digest,
            previous,
            tick,
            keys,
            artifacts,
            signatures,
            message: signature_message(REVOCATION_SIGNATURE_DOMAIN, bytes, prefix_end),
            digest: *blake3::hash(bytes).as_bytes(),
        })
    }

    /// BLAKE3-256 of the complete canonical record including signatures.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn verify_signature_set(
    message: &[u8],
    signatures: &[RootSignature],
    old: Option<(&[RootKey], usize)>,
    current: (&[RootKey], usize),
) -> Result<(), PluginTrustErrorV1> {
    let mut old_count = 0;
    let mut current_count = 0;
    for signature in signatures {
        let old_key = old.and_then(|(keys, _)| keys.iter().find(|key| key.id == signature.id));
        let current_key = current.0.iter().find(|key| key.id == signature.id);
        let public = current_key
            .or(old_key)
            .ok_or(PluginTrustErrorV1::UnknownRootKey)?;
        let verifier = VerifyingKey::from_bytes(&public.public)
            .map_err(|_| PluginTrustErrorV1::InvalidSignature)?;
        verifier
            .verify_strict(message, &Signature::from_bytes(&signature.bytes))
            .map_err(|_| PluginTrustErrorV1::InvalidSignature)?;
        old_count += usize::from(old_key.is_some());
        current_count += usize::from(current_key.is_some());
    }
    if current_count < current.1 || old.is_some_and(|(_, threshold)| old_count < threshold) {
        return Err(PluginTrustErrorV1::ThresholdNotMet);
    }
    Ok(())
}

fn validate_cumulative_keys(
    previous: &[RevokedPublisherKey],
    current: &[RevokedPublisherKey],
    tick: u64,
) -> Result<(), PluginTrustErrorV1> {
    let old: BTreeMap<_, _> = previous
        .iter()
        .map(|entry| (entry.publisher, entry))
        .collect();
    let next: BTreeMap<_, _> = current
        .iter()
        .map(|entry| (entry.publisher, entry))
        .collect();
    for entry in previous {
        if next.get(&entry.publisher).copied() != Some(entry) {
            return Err(PluginTrustErrorV1::ChainDiscontinuity);
        }
    }
    if current
        .iter()
        .any(|entry| !old.contains_key(&entry.publisher) && entry.tick != tick)
    {
        return Err(PluginTrustErrorV1::ChainDiscontinuity);
    }
    Ok(())
}

fn validate_cumulative_artifacts(
    previous: &[RevokedArtifact],
    current: &[RevokedArtifact],
    tick: u64,
) -> Result<(), PluginTrustErrorV1> {
    let old: BTreeMap<_, _> = previous.iter().map(|entry| (entry.digest, entry)).collect();
    let next: BTreeMap<_, _> = current.iter().map(|entry| (entry.digest, entry)).collect();
    for entry in previous {
        if next.get(&entry.digest).copied() != Some(entry) {
            return Err(PluginTrustErrorV1::ChainDiscontinuity);
        }
    }
    if current
        .iter()
        .any(|entry| !old.contains_key(&entry.digest) && entry.tick != tick)
    {
        return Err(PluginTrustErrorV1::ChainDiscontinuity);
    }
    Ok(())
}

fn verify_root_history(
    anchor: &TrustedPluginRootAnchorV1,
    root_bytes: &[&[u8]],
    evaluation_utc_second: i64,
) -> Result<Vec<PluginTrustRootRecordV1>, PluginTrustErrorV1> {
    let roots = root_bytes
        .iter()
        .map(|bytes| PluginTrustRootRecordV1::decode(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let (Some(genesis), Some(terminal)) = (roots.first(), roots.last()) else {
        return Err(PluginTrustErrorV1::ChainDiscontinuity);
    };
    if genesis.digest != anchor.genesis_digest {
        return Err(PluginTrustErrorV1::AnchorMismatch);
    }
    if genesis.scope != anchor.scope || genesis.previous.is_some() {
        return Err(PluginTrustErrorV1::AnchorMismatch);
    }
    let mut root_publics = BTreeSet::new();
    let mut publisher_publics = BTreeSet::new();
    for (index, root) in roots.iter().enumerate() {
        if root.scope != anchor.scope {
            return Err(PluginTrustErrorV1::ChainDiscontinuity);
        }
        root_publics.extend(root.keys.iter().map(|key| key.public));
        publisher_publics.extend(root.publishers.iter().map(|key| key.public));
        let previous = index.checked_sub(1).map(|index| &roots[index]);
        if let Some(previous) = previous {
            if root.previous != Some(previous.digest) {
                return Err(PluginTrustErrorV1::DigestMismatch);
            }
            if root.version
                != previous
                    .version
                    .checked_add(1)
                    .ok_or(PluginTrustErrorV1::ChainDiscontinuity)?
            {
                return Err(PluginTrustErrorV1::ChainDiscontinuity);
            }
        }
        verify_signature_set(
            &root.message,
            &root.signatures,
            previous.map(|prior| (prior.keys.as_slice(), prior.threshold)),
            (&root.keys, root.threshold),
        )?;
    }
    if !root_publics.is_disjoint(&publisher_publics) {
        return Err(PluginTrustErrorV1::ChainDiscontinuity);
    }
    if evaluation_utc_second < terminal.not_before || evaluation_utc_second >= terminal.expires {
        return Err(PluginTrustErrorV1::Expired);
    }
    Ok(roots)
}

fn verify_revocation_history(
    scope: &str,
    roots: &[PluginTrustRootRecordV1],
    revocation_bytes: &[&[u8]],
    evaluation_utc_second: i64,
) -> Result<Vec<PluginRevocationRecordV1>, PluginTrustErrorV1> {
    let revocations = revocation_bytes
        .iter()
        .map(|bytes| PluginRevocationRecordV1::decode(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let mut previous_root_index = 0;
    let known_publishers: BTreeSet<_> = roots
        .iter()
        .flat_map(|root| root.publishers.iter().copied())
        .collect();
    for (index, revocation) in revocations.iter().enumerate() {
        if revocation.scope != scope {
            return Err(PluginTrustErrorV1::ChainDiscontinuity);
        }
        let root_index = roots
            .iter()
            .position(|root| root.digest == revocation.root_digest)
            .ok_or(PluginTrustErrorV1::DigestMismatch)?;
        if root_index < previous_root_index {
            return Err(PluginTrustErrorV1::ChainDiscontinuity);
        }
        previous_root_index = root_index;
        let authority = &roots[root_index];
        verify_signature_set(
            &revocation.message,
            &revocation.signatures,
            None,
            (&authority.keys, authority.threshold),
        )?;
        if revocation
            .keys
            .iter()
            .any(|entry| !known_publishers.contains(&entry.publisher))
        {
            return Err(PluginTrustErrorV1::ChainDiscontinuity);
        }
        if let Some(prior_index) = index.checked_sub(1) {
            let prior = &revocations[prior_index];
            if revocation.previous != Some(prior.digest) {
                return Err(PluginTrustErrorV1::DigestMismatch);
            }
            if revocation.epoch <= prior.epoch || revocation.tick < prior.tick {
                return Err(PluginTrustErrorV1::ChainDiscontinuity);
            }
            validate_cumulative_keys(&prior.keys, &revocation.keys, revocation.tick)?;
            validate_cumulative_artifacts(
                &prior.artifacts,
                &revocation.artifacts,
                revocation.tick,
            )?;
        } else if revocation.previous.is_some() {
            return Err(PluginTrustErrorV1::DigestMismatch);
        } else if revocation
            .keys
            .iter()
            .any(|entry| entry.tick != revocation.tick)
            || revocation
                .artifacts
                .iter()
                .any(|entry| entry.tick != revocation.tick)
        {
            return Err(PluginTrustErrorV1::ChainDiscontinuity);
        }
    }
    let terminal = revocations
        .last()
        .ok_or(PluginTrustErrorV1::ChainDiscontinuity)?;
    let terminal_root = roots.last().ok_or(PluginTrustErrorV1::ChainDiscontinuity)?;
    if terminal.root_digest != terminal_root.digest {
        return Err(PluginTrustErrorV1::DigestMismatch);
    }
    if evaluation_utc_second < terminal.not_before || evaluation_utc_second >= terminal.expires {
        return Err(PluginTrustErrorV1::Expired);
    }
    Ok(revocations)
}

/// Verify complete genesis-anchored PTR1 and PRV1 histories at explicit coordinates.
///
/// # Errors
/// Returns no evidence when any bound, anchor, signature, chain, or expiry check fails.
pub fn verify_plugin_trust_v1(
    anchor: &TrustedPluginRootAnchorV1,
    root_bytes: &[&[u8]],
    revocation_bytes: &[&[u8]],
    evaluation_utc_second: i64,
    evaluation_tick: u64,
) -> Result<VerifiedPluginTrustEvidenceV1, PluginTrustErrorV1> {
    if root_bytes.len() > MAX_ROOT_HISTORY {
        return Err(PluginTrustErrorV1::RootHistoryCapacityExceeded);
    }
    if revocation_bytes.len() > MAX_REVOCATION_HISTORY {
        return Err(PluginTrustErrorV1::RevocationHistoryCapacityExceeded);
    }
    let roots = verify_root_history(anchor, root_bytes, evaluation_utc_second)?;
    let revocations = verify_revocation_history(
        &anchor.scope,
        &roots,
        revocation_bytes,
        evaluation_utc_second,
    )?;
    let terminal_root = roots.last().ok_or(PluginTrustErrorV1::ChainDiscontinuity)?;
    let terminal_revocation = revocations
        .last()
        .ok_or(PluginTrustErrorV1::ChainDiscontinuity)?;
    Ok(VerifiedPluginTrustEvidenceV1 {
        scope: anchor.scope.clone(),
        root_history: roots
            .iter()
            .map(|root| (root.version, root.digest))
            .collect(),
        revocation_history: revocations
            .iter()
            .map(|revocation| (revocation.epoch, revocation.digest))
            .collect(),
        root_version: terminal_root.version,
        root_digest: terminal_root.digest,
        policy_epoch: terminal_revocation.epoch,
        revocation_digest: terminal_revocation.digest,
        evaluation_utc_second,
        evaluation_tick,
        root_validity: (terminal_root.not_before, terminal_root.expires),
        revocation_validity: (terminal_revocation.not_before, terminal_revocation.expires),
        root_keys: terminal_root.keys.clone(),
        publishers: terminal_root.publishers.clone(),
        grants: terminal_root.grants.clone(),
        revoked_keys: terminal_revocation
            .keys
            .iter()
            .filter(|entry| entry.tick <= evaluation_tick)
            .map(|entry| entry.publisher)
            .collect(),
        revoked_artifacts: terminal_revocation
            .artifacts
            .iter()
            .filter(|entry| entry.tick <= evaluation_tick)
            .map(|entry| entry.digest)
            .collect(),
        terminal_revoked_key_count: terminal_revocation.keys.len(),
        terminal_revoked_artifact_count: terminal_revocation.artifacts.len(),
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/plugin_trust_vectors.rs"
    ));
    use ciborium::value::Value;
    use ed25519_dalek::{Signer, SigningKey};

    fn unsigned(value: u64) -> Value {
        Value::Integer(value.into())
    }

    fn signed(value: i64) -> Value {
        Value::Integer(value.into())
    }

    fn bytes<const N: usize>(value: [u8; N]) -> Value {
        Value::Bytes(value.to_vec())
    }

    fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut encoded = Vec::new();
        ciborium::into_writer(value, &mut encoded)?;
        Ok(encoded)
    }

    fn signed_record(
        mut fields: Vec<Value>,
        domain: &[u8],
        signers: &[&SigningKey],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut message = domain.to_vec();
        message.extend_from_slice(&encode(&Value::Array(fields.clone()))?);
        let mut signatures = signers
            .iter()
            .map(|signer| {
                let public = signer.verifying_key().to_bytes();
                let id = root_key_id(public);
                (id, signer.sign(&message).to_bytes())
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(|(id, _)| *id);
        fields.push(Value::Array(
            signatures
                .into_iter()
                .map(|(id, signature)| Value::Array(vec![bytes(id), bytes(signature)]))
                .collect(),
        ));
        encode(&Value::Array(fields))
    }

    fn root(
        signer: &SigningKey,
        publisher: [u8; 32],
        version: u64,
        previous: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        signed_record(
            root_fields(signer, publisher, version, previous),
            ROOT_SIGNATURE_DOMAIN,
            &[signer],
        )
    }

    fn root_fields(
        signer: &SigningKey,
        publisher: [u8; 32],
        version: u64,
        previous: Option<[u8; 32]>,
    ) -> Vec<Value> {
        let public = signer.verifying_key().to_bytes();
        vec![
            Value::Text("PTR1".to_owned()),
            unsigned(1),
            Value::Text("scope".to_owned()),
            unsigned(version),
            signed(0),
            signed(100),
            previous.map_or(Value::Null, bytes),
            unsigned(1),
            Value::Array(vec![Value::Array(vec![
                bytes(root_key_id(public)),
                bytes(public),
            ])]),
            Value::Array(vec![Value::Array(vec![
                Value::Text("publisher".to_owned()),
                unsigned(3),
                unsigned(1),
                bytes(publisher),
            ])]),
            Value::Array(vec![Value::Array(vec![
                Value::Text("plugin-a".to_owned()),
                Value::Text("publisher".to_owned()),
            ])]),
        ]
    }

    fn revocation(
        signer: &SigningKey,
        root_digest: [u8; 32],
        epoch: u64,
        previous: Option<[u8; 32]>,
        revoked_artifacts: Vec<Value>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        signed_record(
            revocation_fields(root_digest, epoch, previous, revoked_artifacts),
            REVOCATION_SIGNATURE_DOMAIN,
            &[signer],
        )
    }

    fn revocation_fields(
        root_digest: [u8; 32],
        epoch: u64,
        previous: Option<[u8; 32]>,
        revoked_artifacts: Vec<Value>,
    ) -> Vec<Value> {
        vec![
            Value::Text("PRV1".to_owned()),
            unsigned(1),
            Value::Text("scope".to_owned()),
            unsigned(epoch),
            signed(0),
            signed(100),
            bytes(root_digest),
            previous.map_or(Value::Null, bytes),
            unsigned(5),
            Value::Array(Vec::new()),
            Value::Array(revoked_artifacts),
        ]
    }

    type TrustFixture = (SigningKey, [u8; 32], Vec<u8>, Vec<u8>);

    fn fixture() -> Result<TrustFixture, Box<dyn std::error::Error>> {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let publisher = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let root = root(&signer, publisher, 1, None)?;
        let revocation = revocation(
            &signer,
            *blake3::hash(&root).as_bytes(),
            1,
            None,
            Vec::new(),
        )?;
        Ok((signer, publisher, root, revocation))
    }

    fn revoked_artifact(digest: [u8; 32], tick: u64) -> Value {
        Value::Array(vec![
            bytes(digest),
            unsigned(tick),
            unsigned(1),
            Value::Null,
        ])
    }

    fn revoked_key(public: [u8; 32], tick: u64) -> Value {
        Value::Array(vec![
            Value::Text("publisher".to_owned()),
            unsigned(3),
            unsigned(1),
            bytes(public),
            unsigned(tick),
            unsigned(1),
            Value::Null,
        ])
    }

    fn rotated_root(
        current: &SigningKey,
        publisher: [u8; 32],
        previous: [u8; 32],
        signers: &[&SigningKey],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let public = current.verifying_key().to_bytes();
        signed_record(
            vec![
                Value::Text("PTR1".to_owned()),
                unsigned(1),
                Value::Text("scope".to_owned()),
                unsigned(2),
                signed(0),
                signed(100),
                bytes(previous),
                unsigned(1),
                Value::Array(vec![Value::Array(vec![
                    bytes(root_key_id(public)),
                    bytes(public),
                ])]),
                Value::Array(vec![Value::Array(vec![
                    Value::Text("publisher".to_owned()),
                    unsigned(3),
                    unsigned(1),
                    bytes(publisher),
                ])]),
                Value::Array(vec![Value::Array(vec![
                    Value::Text("plugin-a".to_owned()),
                    Value::Text("publisher".to_owned()),
                ])]),
            ],
            ROOT_SIGNATURE_DOMAIN,
            signers,
        )
    }

    // Independently generated with hand-written canonical CBOR and Python's
    // `cryptography` Ed25519 implementation. These are fixed external wire
    // fixtures, deliberately not produced by `signed_record` above.
    const GOLDEN_PTR1_PREIMAGE_HEX: &str = "7069676c6f726f732f706c7567696e2d74727573742d726f6f742f7631008b6450545231016d74727573742e6578616d706c65182a201a01e284fff601818258209d7043381b703609599e44f8e8c09abb52faad21b96b60306764dfcb160712935820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787378184697075626c697368657203095820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f081826c616c7068612f706c7567696e697075626c6973686572";
    const GOLDEN_PTR1_DIGEST_HEX: &str =
        "ae7a0ddfc0690d64ec7f2cdb4d34dcd9d21d357a2039a2e23d4e43ce5779c5d3";
    const GOLDEN_PRV1_PREIMAGE_HEX: &str = "7069676c6f726f732f706c7567696e2d7265766f636174696f6e2f7631008b6450525631016d74727573742e6578616d706c6507201a01e284ff5820ae7a0ddfc0690d64ec7f2cdb4d34dcd9d21d357a2039a2e23d4e43ce5779c5d3f60a8187697075626c697368657203095820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f00a01f6818458208fafa054a5f8bebcc9f979e00f851dc064db4a18bece1c8b974f62edfefbd72d0a025820ee791594f8eff6021e834de16a79b82f550aad57c19c98ef24bbab0494c8de6a";
    const GOLDEN_PRV1_DIGEST_HEX: &str =
        "1b1b8f2b1c83bbdd0de33051b5d26c530a77d1d0fc5fb2a170eaf3b8df9395e6";

    #[test]
    fn independent_ptr1_prv1_golden_bytes_verify_and_bind_preimages(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ptr1 = hex_bytes(PTR1_HEX)?;
        let prv1 = hex_bytes(PRV1_HEX)?;
        let expected_ptr1_preimage = hex_bytes(GOLDEN_PTR1_PREIMAGE_HEX)?;
        let expected_prv1_preimage = hex_bytes(GOLDEN_PRV1_PREIMAGE_HEX)?;
        let expected_ptr1_digest: [u8; 32] =
            hex_bytes(GOLDEN_PTR1_DIGEST_HEX)?.as_slice().try_into()?;
        let expected_prv1_digest: [u8; 32] =
            hex_bytes(GOLDEN_PRV1_DIGEST_HEX)?.as_slice().try_into()?;

        let decoded_ptr1 = PluginTrustRootRecordV1::decode(&ptr1)?;
        let decoded_prv1 = PluginRevocationRecordV1::decode(&prv1)?;
        assert_eq!(decoded_ptr1.digest(), expected_ptr1_digest);
        assert_eq!(decoded_prv1.digest(), expected_prv1_digest);
        assert_eq!(decoded_ptr1.message, expected_ptr1_preimage);
        assert_eq!(decoded_prv1.message, expected_prv1_preimage);

        let anchor = TrustedPluginRootAnchorV1::new("trust.example", expected_ptr1_digest)?;
        let evidence = verify_plugin_trust_v1(&anchor, &[&ptr1], &[&prv1], 0, 10)?;
        assert_eq!(evidence.terminal_root(), (42, expected_ptr1_digest));
        assert_eq!(evidence.terminal_revocation(), (7, expected_prv1_digest));
        assert_eq!(
            evidence.effective_key_revocations().collect::<Vec<_>>(),
            vec![(
                OwnerIdV1::new("publisher")?,
                9,
                [
                    0xa0, 0x9a, 0xa5, 0xf4, 0x7a, 0x67, 0x59, 0x80, 0x2f, 0xf9, 0x55, 0xf8, 0xdc,
                    0x2d, 0x2a, 0x14, 0xa5, 0xc9, 0x9d, 0x23, 0xbe, 0x97, 0xf8, 0x64, 0x12, 0x7f,
                    0xf9, 0x38, 0x34, 0x55, 0xa4, 0xf0,
                ],
            )]
        );
        assert_eq!(
            evidence
                .effective_artifact_revocations()
                .collect::<Vec<_>>(),
            vec![[
                0x8f, 0xaf, 0xa0, 0x54, 0xa5, 0xf8, 0xbe, 0xbc, 0xc9, 0xf9, 0x79, 0xe0, 0x0f, 0x85,
                0x1d, 0xc0, 0x64, 0xdb, 0x4a, 0x18, 0xbe, 0xce, 0x1c, 0x8b, 0x97, 0x4f, 0x62, 0xed,
                0xfe, 0xfb, 0xd7, 0x2d,
            ]]
        );
        Ok(())
    }

    #[test]
    fn pinned_genesis_and_empty_revocation_produce_bound_facts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signer, _, root, revocation) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let revocation_digest = *blake3::hash(&revocation).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", root_digest)?;
        let evidence = verify_plugin_trust_v1(&anchor, &[&root], &[&revocation], 50, 4)?;
        assert_eq!(evidence.policy_scope(), "scope");
        assert_eq!(evidence.terminal_root(), (1, root_digest));
        assert_eq!(evidence.terminal_revocation(), (1, revocation_digest));
        assert_eq!(evidence.evaluation_coordinates(), (50, 4));
        assert_eq!(evidence.terminal_validity(), ((0, 100), (0, 100)));
        let root_public = signer.verifying_key().to_bytes();
        assert_eq!(
            evidence.terminal_root_keys().collect::<Vec<_>>(),
            vec![(root_key_id(root_public), root_public)]
        );
        assert_eq!(evidence.effective_key_revocations().count(), 0);
        assert_eq!(evidence.effective_artifact_revocations().count(), 0);
        Ok(())
    }

    #[test]
    fn root_threshold_exceeding_key_count_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, _, _) = fixture()?;
        let mut fields = root_fields(&signer, publisher, 1, None);
        fields[7] = unsigned(2);
        let encoded = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(PluginTrustRootRecordV1::decode(&encoded).is_err());
        Ok(())
    }

    #[test]
    fn malformed_anchor_expiry_and_signature_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_, _, root, revocation) = fixture()?;
        let digest = *blake3::hash(&root).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", digest)?;
        assert_eq!(
            TrustedPluginRootAnchorV1::new("UPPER", digest),
            Err(PluginTrustErrorV1::InvalidEncoding)
        );
        let bad_anchor = TrustedPluginRootAnchorV1::new("scope", [0; 32])?;
        assert!(matches!(
            verify_plugin_trust_v1(&bad_anchor, &[&root], &[&revocation], 50, 0),
            Err(PluginTrustErrorV1::AnchorMismatch)
        ));
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&revocation], 100, 0),
            Err(PluginTrustErrorV1::Expired)
        ));
        let mut tampered = root.clone();
        let last = tampered.last_mut().ok_or("empty root fixture")?;
        *last ^= 1;
        let tampered_anchor =
            TrustedPluginRootAnchorV1::new("scope", *blake3::hash(&tampered).as_bytes())?;
        assert!(matches!(
            verify_plugin_trust_v1(&tampered_anchor, &[&tampered], &[&revocation], 50, 0),
            Err(PluginTrustErrorV1::InvalidSignature)
        ));
        let mut trailing = root;
        trailing.push(0);
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&trailing),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));
        Ok(())
    }

    #[test]
    fn cumulative_revocation_is_set_inclusion_and_tick_bound(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signer, _, root, _) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", root_digest)?;
        let first = revocation(
            &signer,
            root_digest,
            1,
            None,
            vec![revoked_artifact([2; 32], 5)],
        )?;
        let first_digest = *blake3::hash(&first).as_bytes();
        let second = revocation(
            &signer,
            root_digest,
            2,
            Some(first_digest),
            vec![revoked_artifact([1; 32], 5), revoked_artifact([2; 32], 5)],
        )?;
        let before = verify_plugin_trust_v1(&anchor, &[&root], &[&first, &second], 50, 4)?;
        assert_eq!(before.effective_artifact_revocations().count(), 0);
        let effective = verify_plugin_trust_v1(&anchor, &[&root], &[&first, &second], 50, 5)?;
        assert_eq!(
            effective
                .effective_artifact_revocations()
                .collect::<Vec<_>>(),
            vec![[1; 32], [2; 32]]
        );
        let missing_old = revocation(
            &signer,
            root_digest,
            2,
            Some(first_digest),
            vec![revoked_artifact([1; 32], 5)],
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&first, &missing_old], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        let changed_old = revocation(
            &signer,
            root_digest,
            2,
            Some(first_digest),
            vec![revoked_artifact([2; 32], 4)],
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&first, &changed_old], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        let wrong_new_tick = revocation(
            &signer,
            root_digest,
            2,
            Some(first_digest),
            vec![revoked_artifact([1; 32], 4), revoked_artifact([2; 32], 5)],
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&first, &wrong_new_tick], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        Ok(())
    }

    #[test]
    fn cumulative_publisher_revocations_require_retention_and_current_tick(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, root, _) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", root_digest)?;
        let mut first_fields = revocation_fields(root_digest, 1, None, Vec::new());
        first_fields[9] = Value::Array(vec![revoked_key(publisher, 5)]);
        let first = signed_record(first_fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
        let first_digest = *blake3::hash(&first).as_bytes();
        let second_fields = revocation_fields(root_digest, 2, Some(first_digest), Vec::new());
        let missing = signed_record(
            second_fields.clone(),
            REVOCATION_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&first, &missing], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        let mut changed_fields = second_fields;
        changed_fields[9] = Value::Array(vec![revoked_key(publisher, 4)]);
        let changed = signed_record(changed_fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&first, &changed], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));

        let empty_first = revocation(&signer, root_digest, 1, None, Vec::new())?;
        let mut new_fields = revocation_fields(
            root_digest,
            2,
            Some(*blake3::hash(&empty_first).as_bytes()),
            Vec::new(),
        );
        new_fields[9] = Value::Array(vec![revoked_key(publisher, 4)]);
        let wrong_new_tick = signed_record(new_fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&empty_first, &wrong_new_tick], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        Ok(())
    }

    #[test]
    fn malformed_collection_and_capacity_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, _, root, _) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let unsorted = revocation(
            &signer,
            root_digest,
            1,
            None,
            vec![revoked_artifact([2; 32], 5), revoked_artifact([1; 32], 5)],
        )?;
        assert!(matches!(
            PluginRevocationRecordV1::decode(&unsorted),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));
        let over_capacity = (0..=4096_u32)
            .map(|index| {
                let mut digest = [0_u8; 32];
                digest[..4].copy_from_slice(&index.to_be_bytes());
                revoked_artifact(digest, 5)
            })
            .collect();
        let over_capacity = revocation(&signer, root_digest, 1, None, over_capacity)?;
        assert!(matches!(
            PluginRevocationRecordV1::decode(&over_capacity),
            Err(PluginTrustErrorV1::RevocationCapacityExhausted)
        ));
        let mut noncanonical = root;
        assert_eq!(
            &noncanonical[..7],
            &[0x8c, 0x64, b'P', b'T', b'R', b'1', 0x01]
        );
        noncanonical.splice(6..7, [0x18, 0x01]);
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&noncanonical),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));
        Ok(())
    }

    #[test]
    fn revoked_key_fields_and_order_are_strict() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, root, _) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let valid = revoked_key(publisher, 5);
        for (index, replacement) in [
            (0, Value::Text(String::new())),
            (1, unsigned(4)),
            (2, unsigned(0)),
            (4, unsigned(6)),
            (5, unsigned(0)),
            (6, unsigned(0)),
        ] {
            let Value::Array(mut entry) = valid.clone() else {
                return Err("expected array".into());
            };
            entry[index] = replacement;
            let mut fields = revocation_fields(root_digest, 1, None, Vec::new());
            fields[9] = Value::Array(vec![Value::Array(entry)]);
            let encoded = signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
            assert!(matches!(
                PluginRevocationRecordV1::decode(&encoded),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
        }
        for entries in [
            vec![Value::Array(vec![unsigned(1); 6])],
            vec![valid.clone(), valid],
        ] {
            let mut fields = revocation_fields(root_digest, 1, None, Vec::new());
            fields[9] = Value::Array(entries);
            let encoded = signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
            assert!(matches!(
                PluginRevocationRecordV1::decode(&encoded),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
        }
        Ok(())
    }

    #[test]
    fn revoked_artifact_fields_and_order_are_strict() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, _, root, _) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let valid = revoked_artifact([1; 32], 5);
        for (index, replacement) in [
            (0, unsigned(1)),
            (1, unsigned(6)),
            (2, unsigned(5)),
            (3, unsigned(1)),
        ] {
            let Value::Array(mut entry) = valid.clone() else {
                return Err("expected array".into());
            };
            entry[index] = replacement;
            let fields = revocation_fields(root_digest, 1, None, vec![Value::Array(entry)]);
            let encoded = signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
            assert!(matches!(
                PluginRevocationRecordV1::decode(&encoded),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
        }
        for entries in [
            vec![Value::Array(vec![unsigned(1); 3])],
            vec![valid.clone(), valid],
        ] {
            let fields = revocation_fields(root_digest, 1, None, entries);
            let encoded = signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
            assert!(matches!(
                PluginRevocationRecordV1::decode(&encoded),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
        }
        Ok(())
    }

    #[test]
    fn truncated_multi_byte_cbor_lengths_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (_, _, root, _) = fixture()?;
        for length_marker in [0x19, 0x1a, 0x1b] {
            let mut truncated = root[..6].to_vec();
            truncated.push(length_marker);
            assert!(PluginTrustRootRecordV1::decode(&truncated).is_err());
        }
        Ok(())
    }

    #[test]
    fn revocation_member_type_errors_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, root, revocation) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let valid_key = revoked_key(publisher, 5);
        for (index, replacement) in [
            (1, Value::Text("role".to_owned())),
            (2, Value::Text("epoch".to_owned())),
            (3, Value::Text("public".to_owned())),
            (4, Value::Text("tick".to_owned())),
            (5, Value::Text("reason".to_owned())),
        ] {
            let Value::Array(mut entry) = valid_key.clone() else {
                return Err("expected revoked key array".into());
            };
            entry[index] = replacement;
            let mut fields = revocation_fields(root_digest, 1, None, Vec::new());
            fields[9] = Value::Array(vec![Value::Array(entry)]);
            let encoded = signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
            assert!(PluginRevocationRecordV1::decode(&encoded).is_err());
        }

        let mut fields = revocation_fields(root_digest, 1, None, Vec::new());
        fields[9] = Value::Array(vec![unsigned(1)]);
        let invalid_key = signed_record(fields, REVOCATION_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(PluginRevocationRecordV1::decode(&invalid_key).is_err());

        let valid_artifact = revoked_artifact([1; 32], 5);
        let Value::Array(mut artifact) = valid_artifact else {
            return Err("expected revoked artifact array".into());
        };
        artifact[1] = Value::Text("tick".to_owned());
        let invalid_artifact =
            self::revocation(&signer, root_digest, 1, None, vec![Value::Array(artifact)])?;
        assert!(PluginRevocationRecordV1::decode(&invalid_artifact).is_err());

        let invalid_artifact = signed_record(
            revocation_fields(root_digest, 1, None, vec![unsigned(1)]),
            REVOCATION_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        assert!(PluginRevocationRecordV1::decode(&invalid_artifact).is_err());
        let mut trailing = signed_record(
            revocation_fields(root_digest, 1, None, Vec::new()),
            REVOCATION_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        trailing.push(0);
        assert!(PluginRevocationRecordV1::decode(&trailing).is_err());
        assert!(PluginRevocationRecordV1::decode(&revocation).is_ok());
        Ok(())
    }

    #[test]
    fn root_version_increment_overflow_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, _, _) = fixture()?;
        let first = root(&signer, publisher, u64::MAX, None)?;
        let anchor = TrustedPluginRootAnchorV1::new("scope", *blake3::hash(&first).as_bytes())?;
        let second = root(
            &signer,
            publisher,
            1,
            Some(*blake3::hash(&first).as_bytes()),
        )?;
        let revocation = self::revocation(
            &signer,
            *blake3::hash(&second).as_bytes(),
            1,
            None,
            Vec::new(),
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&first, &second], &[&revocation], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        Ok(())
    }

    #[test]
    fn signed_schema_and_type_vectors_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, _, root, revocation) = fixture()?;
        let anchor = TrustedPluginRootAnchorV1::new("scope", *blake3::hash(&root).as_bytes())?;
        let mut roots = Vec::new();
        for (index, value) in [
            (0, Value::Text("PRV1".to_owned())),
            (1, unsigned(2)),
            (2, Value::Text("Scope".to_owned())),
            (3, Value::Text("one".to_owned())),
            (4, Value::Text("zero".to_owned())),
            (6, unsigned(0)),
            (7, Value::Text("one".to_owned())),
            (8, bytes([0_u8; 32])),
            (9, Value::Text("publishers".to_owned())),
            (10, Value::Text("grants".to_owned())),
        ] {
            let mut fields = root_fields(
                &signer,
                SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
                1,
                None,
            );
            fields[index] = value;
            roots.push(signed_record(fields, ROOT_SIGNATURE_DOMAIN, &[&signer])?);
        }
        for malformed in roots {
            assert!(matches!(
                PluginTrustRootRecordV1::decode(&malformed),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
            assert!(verify_plugin_trust_v1(&anchor, &[&malformed], &[&revocation], 50, 5).is_err());
        }

        let root_digest = *blake3::hash(&root).as_bytes();
        let mut revocations = Vec::new();
        for (index, value) in [
            (0, Value::Text("PTR1".to_owned())),
            (1, unsigned(2)),
            (2, Value::Text("Scope".to_owned())),
            (3, unsigned(0)),
            (4, Value::Text("zero".to_owned())),
            (6, Value::Text("digest".to_owned())),
            (7, unsigned(0)),
            (8, Value::Text("tick".to_owned())),
            (9, Value::Text("keys".to_owned())),
            (10, Value::Text("artifacts".to_owned())),
        ] {
            let mut fields = revocation_fields(root_digest, 1, None, Vec::new());
            fields[index] = value;
            revocations.push(signed_record(
                fields,
                REVOCATION_SIGNATURE_DOMAIN,
                &[&signer],
            )?);
        }
        for malformed in revocations {
            assert!(matches!(
                PluginRevocationRecordV1::decode(&malformed),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
            assert!(verify_plugin_trust_v1(&anchor, &[&root], &[&malformed], 50, 5).is_err());
        }
        Ok(())
    }

    #[test]
    fn signed_identity_and_order_vectors_are_checked() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, _, _) = fixture()?;
        let other = SigningKey::from_bytes(&[9; 32]);

        let invalid_public = (1_u8..=255)
            .map(|byte| [byte; 32])
            .find(|public| VerifyingKey::from_bytes(public).is_err())
            .ok_or("expected an invalid Ed25519 public key")?;
        let mut invalid_root_key = root_fields(&signer, publisher, 1, None);
        invalid_root_key[8] = Value::Array(vec![Value::Array(vec![
            bytes(root_key_id(invalid_public)),
            bytes(invalid_public),
        ])]);
        let invalid_root_key = signed_record(invalid_root_key, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&invalid_root_key),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));

        let mut mismatched_key_id = root_fields(&signer, publisher, 1, None);
        mismatched_key_id[8] = Value::Array(vec![Value::Array(vec![
            bytes([0; 32]),
            bytes(signer.verifying_key().to_bytes()),
        ])]);
        let mismatched_key_id =
            signed_record(mismatched_key_id, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&mismatched_key_id),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));

        let mut duplicate_publisher = root_fields(&signer, publisher, 1, None);
        duplicate_publisher[9] = Value::Array(vec![
            Value::Array(vec![
                Value::Text("publisher".to_owned()),
                unsigned(3),
                unsigned(1),
                bytes(publisher),
            ]),
            Value::Array(vec![
                Value::Text("publisher".to_owned()),
                unsigned(3),
                unsigned(1),
                bytes(other.verifying_key().to_bytes()),
            ]),
        ]);
        let duplicate_publisher =
            signed_record(duplicate_publisher, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&duplicate_publisher),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));

        let mut unordered_grants = root_fields(&signer, publisher, 1, None);
        unordered_grants[10] = Value::Array(vec![
            Value::Array(vec![
                Value::Text("plugin-z".to_owned()),
                Value::Text("publisher".to_owned()),
            ]),
            Value::Array(vec![
                Value::Text("plugin-a".to_owned()),
                Value::Text("publisher".to_owned()),
            ]),
        ]);
        let unordered_grants = signed_record(unordered_grants, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&unordered_grants),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));

        let mut ungranted_owner = root_fields(&signer, publisher, 1, None);
        ungranted_owner[10] = Value::Array(vec![Value::Array(vec![
            Value::Text("plugin-a".to_owned()),
            Value::Text("different-owner".to_owned()),
        ])]);
        let ungranted_owner = signed_record(ungranted_owner, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&ungranted_owner),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));
        Ok(())
    }

    #[test]
    fn revoked_publisher_must_name_a_known_key() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, root, _) = fixture()?;
        let other = SigningKey::from_bytes(&[9; 32]);
        let root_digest = *blake3::hash(&root).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", root_digest)?;
        let mut key_revocation_fields = revocation_fields(root_digest, 1, None, Vec::new());
        key_revocation_fields[9] = Value::Array(vec![Value::Array(vec![
            Value::Text("publisher".to_owned()),
            unsigned(3),
            unsigned(1),
            bytes(publisher),
            unsigned(5),
            unsigned(1),
            Value::Array(vec![
                Value::Text("publisher".to_owned()),
                unsigned(3),
                unsigned(1),
                bytes(publisher),
            ]),
        ])]);
        let key_revocation = signed_record(
            key_revocation_fields.clone(),
            REVOCATION_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        let evidence = verify_plugin_trust_v1(&anchor, &[&root], &[&key_revocation], 50, 5)?;
        assert_eq!(
            evidence.effective_key_revocations().collect::<Vec<_>>(),
            vec![(pos_core::OwnerIdV1::new("publisher")?, 1, publisher)]
        );
        key_revocation_fields[9] = Value::Array(vec![Value::Array(vec![
            Value::Text("publisher".to_owned()),
            unsigned(3),
            unsigned(1),
            bytes(other.verifying_key().to_bytes()),
            unsigned(5),
            unsigned(1),
            Value::Null,
        ])]);
        let foreign_key_revocation = signed_record(
            key_revocation_fields,
            REVOCATION_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&foreign_key_revocation], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        Ok(())
    }

    #[test]
    fn root_threshold_and_order_vectors_are_checked() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, _, _) = fixture()?;
        let other = SigningKey::from_bytes(&[9; 32]);
        let mut threshold_root = root_fields(&signer, publisher, 1, None);
        let signer_public = signer.verifying_key().to_bytes();
        let other_public = other.verifying_key().to_bytes();
        let mut keys = [
            (root_key_id(signer_public), signer_public),
            (root_key_id(other_public), other_public),
        ];
        keys.sort_by_key(|(id, _)| *id);
        let mut reversed_root_keys = root_fields(&signer, publisher, 1, None);
        reversed_root_keys[8] = Value::Array(
            keys.iter()
                .rev()
                .map(|(id, public)| Value::Array(vec![bytes(*id), bytes(*public)]))
                .collect(),
        );
        let reversed_root_keys =
            signed_record(reversed_root_keys, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&reversed_root_keys),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));
        threshold_root[7] = unsigned(2);
        threshold_root[8] = Value::Array(
            keys.into_iter()
                .map(|(id, public)| Value::Array(vec![bytes(id), bytes(public)]))
                .collect(),
        );
        let threshold_root =
            signed_record(threshold_root, ROOT_SIGNATURE_DOMAIN, &[&signer, &other])?;
        let threshold_digest = *blake3::hash(&threshold_root).as_bytes();
        let threshold_anchor = TrustedPluginRootAnchorV1::new("scope", threshold_digest)?;
        let threshold_revocation = signed_record(
            revocation_fields(threshold_digest, 1, None, Vec::new()),
            REVOCATION_SIGNATURE_DOMAIN,
            &[&signer, &other],
        )?;
        assert!(verify_plugin_trust_v1(
            &threshold_anchor,
            &[&threshold_root],
            &[&threshold_revocation],
            50,
            5
        )
        .is_ok());
        let under_threshold = signed_record(
            root_fields(&signer, publisher, 1, None)
                .into_iter()
                .enumerate()
                .map(|(index, value)| match index {
                    7 => unsigned(2),
                    8 => Value::Array(
                        keys.iter()
                            .map(|(id, public)| Value::Array(vec![bytes(*id), bytes(*public)]))
                            .collect(),
                    ),
                    _ => value,
                })
                .collect(),
            ROOT_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        let under_threshold_anchor =
            TrustedPluginRootAnchorV1::new("scope", *blake3::hash(&under_threshold).as_bytes())?;
        assert!(matches!(
            verify_plugin_trust_v1(
                &under_threshold_anchor,
                &[&under_threshold],
                &[&threshold_revocation],
                50,
                5
            ),
            Err(PluginTrustErrorV1::ThresholdNotMet)
        ));
        Ok(())
    }

    #[test]
    fn revocation_validity_edges_are_checked() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, _, root, _) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", root_digest)?;
        let mut starting_revocation_fields = revocation_fields(root_digest, 1, None, Vec::new());
        starting_revocation_fields[4] = signed(50);
        let starts_at_fifty = signed_record(
            starting_revocation_fields,
            REVOCATION_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&starts_at_fifty], 49, 5),
            Err(PluginTrustErrorV1::Expired)
        ));
        assert!(verify_plugin_trust_v1(&anchor, &[&root], &[&starts_at_fifty], 50, 5).is_ok());
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&starts_at_fifty], 100, 5),
            Err(PluginTrustErrorV1::Expired)
        ));
        Ok(())
    }

    #[test]
    fn rotation_requires_old_and_new_thresholds_and_revocation_moves_forward(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (old, publisher, genesis, _) = fixture()?;
        let new = SigningKey::from_bytes(&[9; 32]);
        let genesis_digest = *blake3::hash(&genesis).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", genesis_digest)?;
        let rotated = rotated_root(&new, publisher, genesis_digest, &[&old, &new])?;
        let rotated_digest = *blake3::hash(&rotated).as_bytes();
        let first = revocation(&old, genesis_digest, 1, None, Vec::new())?;
        let second = revocation(
            &new,
            rotated_digest,
            2,
            Some(*blake3::hash(&first).as_bytes()),
            Vec::new(),
        )?;
        let evidence =
            verify_plugin_trust_v1(&anchor, &[&genesis, &rotated], &[&first, &second], 50, 5)?;
        assert_eq!(evidence.terminal_root(), (2, rotated_digest));
        for signers in [&[&old][..], &[&new][..]] {
            let invalid = rotated_root(&new, publisher, genesis_digest, signers)?;
            let invalid_revocation = revocation(
                &new,
                *blake3::hash(&invalid).as_bytes(),
                1,
                None,
                Vec::new(),
            )?;
            assert!(matches!(
                verify_plugin_trust_v1(
                    &anchor,
                    &[&genesis, &invalid],
                    &[&invalid_revocation],
                    50,
                    5
                ),
                Err(PluginTrustErrorV1::ThresholdNotMet)
            ));
        }
        let backward = revocation(
            &old,
            genesis_digest,
            3,
            Some(*blake3::hash(&second).as_bytes()),
            Vec::new(),
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(
                &anchor,
                &[&genesis, &rotated],
                &[&first, &second, &backward],
                50,
                5
            ),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        Ok(())
    }

    #[test]
    fn decoder_bounds_and_structural_edges_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, root, revocation) = fixture()?;
        for replacement in [&[0x1a, 0, 0, 0, 1][..], &[0x1b, 0, 0, 0, 0, 0, 0, 0, 1][..]] {
            let mut noncanonical = root.clone();
            noncanonical.splice(6..7, replacement.iter().copied());
            assert!(matches!(
                PluginTrustRootRecordV1::decode(&noncanonical),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
        }
        for record in [&root, &revocation] {
            let oversized = vec![0; 1024 * 1024 + 1];
            let decoded = if record == &root {
                PluginTrustRootRecordV1::decode(&oversized).map(|_| ())
            } else {
                PluginRevocationRecordV1::decode(&oversized).map(|_| ())
            };
            assert_eq!(decoded, Err(PluginTrustErrorV1::BoundsExceeded));
        }
        for (field, entry) in [
            (8, Value::Array(vec![Value::Array(vec![unsigned(1)])])),
            (9, Value::Array(vec![Value::Array(vec![unsigned(1); 3])])),
            (
                10,
                Value::Array(vec![Value::Array(vec![Value::Text("plugin-a".to_owned())])]),
            ),
        ] {
            let mut fields = root_fields(&signer, publisher, 1, None);
            fields[field] = entry;
            let encoded = signed_record(fields, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
            assert!(matches!(
                PluginTrustRootRecordV1::decode(&encoded),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
        }
        Ok(())
    }

    #[test]
    fn signature_and_public_digest_edges_are_checked() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, root, revocation) = fixture()?;
        assert_eq!(
            PluginTrustRootRecordV1::decode(&root)?.digest(),
            *blake3::hash(&root).as_bytes()
        );
        assert_eq!(
            PluginRevocationRecordV1::decode(&revocation)?.digest(),
            *blake3::hash(&revocation).as_bytes()
        );
        for signatures in [
            Vec::new(),
            vec![Value::Array(vec![bytes([0; 32])])],
            vec![
                Value::Array(vec![
                    bytes(root_key_id(signer.verifying_key().to_bytes())),
                    bytes([0; 64]),
                ]),
                Value::Array(vec![
                    bytes(root_key_id(signer.verifying_key().to_bytes())),
                    bytes([1; 64]),
                ]),
            ],
        ] {
            let mut fields = root_fields(&signer, publisher, 1, None);
            fields.push(Value::Array(signatures));
            let encoded = encode(&Value::Array(fields))?;
            assert!(matches!(
                PluginTrustRootRecordV1::decode(&encoded),
                Err(PluginTrustErrorV1::InvalidEncoding)
            ));
        }
        Ok(())
    }

    #[test]
    fn history_discontinuity_edges_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, root, revocation) = fixture()?;
        let digest = *blake3::hash(&root).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", digest)?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[], &[&revocation], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));
        let mut wrong_genesis = root_fields(&signer, publisher, 1, Some([0; 32]));
        wrong_genesis[2] = Value::Text("other".to_owned());
        let wrong_genesis = signed_record(wrong_genesis, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        let wrong_anchor =
            TrustedPluginRootAnchorV1::new("scope", *blake3::hash(&wrong_genesis).as_bytes())?;
        assert!(matches!(
            verify_plugin_trust_v1(&wrong_anchor, &[&wrong_genesis], &[&revocation], 50, 5),
            Err(PluginTrustErrorV1::AnchorMismatch)
        ));
        let mut bad_next = root_fields(&signer, publisher, 3, Some(digest));
        bad_next[2] = Value::Text("other".to_owned());
        let bad_next = signed_record(bad_next, ROOT_SIGNATURE_DOMAIN, &[&signer])?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root, &bad_next], &[&revocation], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));

        let wrong_version = signed_record(
            root_fields(&signer, publisher, 3, Some(digest)),
            ROOT_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root, &wrong_version], &[&revocation], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));

        let wrong_previous = signed_record(
            root_fields(&signer, publisher, 2, Some([0; 32])),
            ROOT_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root, &wrong_previous], &[&revocation], 50, 5),
            Err(PluginTrustErrorV1::DigestMismatch)
        ));

        let alias_public = signer.verifying_key().to_bytes();
        let alias_root = signed_record(
            root_fields(&signer, alias_public, 1, None),
            ROOT_SIGNATURE_DOMAIN,
            &[&signer],
        )?;
        let alias_digest = *blake3::hash(&alias_root).as_bytes();
        let alias_anchor = TrustedPluginRootAnchorV1::new("scope", alias_digest)?;
        let alias_revocation = self::revocation(&signer, alias_digest, 1, None, Vec::new())?;
        assert!(matches!(
            verify_plugin_trust_v1(&alias_anchor, &[&alias_root], &[&alias_revocation], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));

        let bad_initial_previous = self::revocation(&signer, digest, 1, Some([0; 32]), Vec::new())?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&bad_initial_previous], 50, 5),
            Err(PluginTrustErrorV1::DigestMismatch)
        ));

        let unknown_root = self::revocation(&signer, [0; 32], 1, None, Vec::new())?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&unknown_root], 50, 5),
            Err(PluginTrustErrorV1::DigestMismatch)
        ));

        let repeated_epoch = self::revocation(
            &signer,
            digest,
            1,
            Some(*blake3::hash(&revocation).as_bytes()),
            Vec::new(),
        )?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root], &[&revocation, &repeated_epoch], 50, 5),
            Err(PluginTrustErrorV1::ChainDiscontinuity)
        ));

        let new_signer = SigningKey::from_bytes(&[9; 32]);
        let rotated = rotated_root(&new_signer, publisher, digest, &[&signer, &new_signer])?;
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &[&root, &rotated], &[&revocation], 50, 5),
            Err(PluginTrustErrorV1::DigestMismatch)
        ));
        Ok(())
    }

    #[test]
    fn every_truncation_and_selected_single_byte_tamper_fails_closed(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_, _, root, revocation) = fixture()?;
        let anchor = TrustedPluginRootAnchorV1::new("scope", *blake3::hash(&root).as_bytes())?;
        for length in 0..root.len() {
            assert!(PluginTrustRootRecordV1::decode(&root[..length]).is_err());
        }
        for length in 0..revocation.len() {
            assert!(PluginRevocationRecordV1::decode(&revocation[..length]).is_err());
        }
        let replacements = [
            0x00, 0x01, 0x18, 0x19, 0x1a, 0x1b, 0x38, 0x39, 0x3a, 0x3b, 0x58, 0x59, 0x5a, 0x5b,
            0x78, 0x79, 0x7a, 0x7b, 0x98, 0x99, 0x9a, 0x9b, 0x9f, 0xff,
        ];
        for offset in 0..root.len() {
            for replacement in replacements {
                if root[offset] == replacement {
                    continue;
                }
                let mut changed = root.clone();
                changed[offset] = replacement;
                assert!(
                    verify_plugin_trust_v1(&anchor, &[&changed], &[&revocation], 50, 5).is_err(),
                    "PTR1 byte {offset} accepted after replacement {replacement:02x}"
                );
            }
        }
        for offset in 0..revocation.len() {
            for replacement in replacements {
                if revocation[offset] == replacement {
                    continue;
                }
                let mut changed = revocation.clone();
                changed[offset] = replacement;
                assert!(
                    verify_plugin_trust_v1(&anchor, &[&root], &[&changed], 50, 5).is_err(),
                    "PRV1 byte {offset} accepted after replacement {replacement:02x}"
                );
            }
        }
        Ok(())
    }
}
