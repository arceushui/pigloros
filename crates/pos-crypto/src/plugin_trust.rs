//! Bounded, stateless PTR1 and PRV1 verification (ADR-103).

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use pos_core::OwnerIdV1;
use thiserror::Error;

const ROOT_KEY_DOMAIN: &[u8] = b"pigloros/plugin-root-key-id/v1\0";
const ROOT_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-trust-root/v1\0";
const REVOCATION_SIGNATURE_DOMAIN: &[u8] = b"pigloros/plugin-revocation/v1\0";

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
    /// Too few authorized, distinct root keys signed.
    #[error("Plugin trust root threshold is not met")]
    ThresholdNotMet,
    /// The supplied genesis does not match the operator-pinned anchor.
    #[error("Plugin trust genesis anchor differs")]
    AnchorMismatch,
    /// A chain link or cumulative set is invalid.
    #[error("Plugin trust chain is discontinuous")]
    ChainDiscontinuity,
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
    root_version: u64,
    root_digest: [u8; 32],
    policy_epoch: u64,
    revocation_digest: [u8; 32],
    evaluation_utc_second: i64,
    evaluation_tick: u64,
    root_validity: (i64, i64),
    revocation_validity: (i64, i64),
    publishers: Vec<PublisherKey>,
    grants: Vec<Grant>,
    revoked_keys: BTreeSet<PublisherKey>,
    revoked_artifacts: BTreeSet<[u8; 32]>,
}

impl VerifiedPluginTrustEvidenceV1 {
    /// The exact policy scope verified from the pinned genesis.
    #[must_use]
    pub fn policy_scope(&self) -> &str {
        &self.scope
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

    /// Publisher records in the verified terminal PTR1. This is a fact for
    /// #401's complete-PMF1 query, not a release admission decision.
    pub fn publisher_keys(&self) -> impl Iterator<Item = (OwnerIdV1, u64, [u8; 32])> + '_ {
        self.publishers
            .iter()
            .map(|key| (key.owner, key.epoch, key.public))
    }

    /// Exact Plugin ID grants in the verified terminal PTR1.
    pub fn exact_grants(&self) -> impl Iterator<Item = (&str, OwnerIdV1)> + '_ {
        self.grants
            .iter()
            .map(|grant| (grant.plugin_id.as_str(), grant.owner))
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
}

fn validate_plugin_id(value: &str) -> Result<(), PluginTrustErrorV1> {
    let bytes = value.as_bytes();
    if !(1..=128).contains(&bytes.len())
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
    {
        return Err(PluginTrustErrorV1::InvalidEncoding);
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, PluginTrustErrorV1> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(PluginTrustErrorV1::InvalidEncoding)?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], PluginTrustErrorV1> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(PluginTrustErrorV1::InvalidEncoding)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(PluginTrustErrorV1::InvalidEncoding)?;
        self.offset = end;
        Ok(bytes)
    }

    fn head(&mut self) -> Result<(u8, u64), PluginTrustErrorV1> {
        let first = self.byte()?;
        let major = first >> 5;
        let small = first & 31;
        let value = match small {
            0..=23 => u64::from(small),
            24 => {
                let value = u64::from(self.byte()?);
                if value < 24 {
                    return Err(PluginTrustErrorV1::InvalidEncoding);
                }
                value
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(
                    self.take(2)?
                        .try_into()
                        .map_err(|_| PluginTrustErrorV1::InvalidEncoding)?,
                ));
                if value <= u64::from(u8::MAX) {
                    return Err(PluginTrustErrorV1::InvalidEncoding);
                }
                value
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(
                    self.take(4)?
                        .try_into()
                        .map_err(|_| PluginTrustErrorV1::InvalidEncoding)?,
                ));
                if value <= u64::from(u16::MAX) {
                    return Err(PluginTrustErrorV1::InvalidEncoding);
                }
                value
            }
            27 => {
                let value = u64::from_be_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| PluginTrustErrorV1::InvalidEncoding)?,
                );
                if value <= u64::from(u32::MAX) {
                    return Err(PluginTrustErrorV1::InvalidEncoding);
                }
                value
            }
            _ => return Err(PluginTrustErrorV1::InvalidEncoding),
        };
        Ok((major, value))
    }

    fn array(&mut self, max: usize) -> Result<usize, PluginTrustErrorV1> {
        let (major, count) = self.head()?;
        if major != 4 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let count = usize::try_from(count).map_err(|_| PluginTrustErrorV1::BoundsExceeded)?;
        if count > max {
            return Err(PluginTrustErrorV1::BoundsExceeded);
        }
        Ok(count)
    }

    fn unsigned(&mut self) -> Result<u64, PluginTrustErrorV1> {
        let (major, value) = self.head()?;
        if major != 0 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        Ok(value)
    }

    fn signed(&mut self) -> Result<i64, PluginTrustErrorV1> {
        let (major, value) = self.head()?;
        match major {
            0 => i64::try_from(value).map_err(|_| PluginTrustErrorV1::InvalidEncoding),
            1 => i64::try_from(value)
                .map(|value| -1 - value)
                .map_err(|_| PluginTrustErrorV1::InvalidEncoding),
            _ => Err(PluginTrustErrorV1::InvalidEncoding),
        }
    }

    fn text(&mut self, max: usize) -> Result<&'a str, PluginTrustErrorV1> {
        let (major, length) = self.head()?;
        if major != 3 {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        let length = usize::try_from(length).map_err(|_| PluginTrustErrorV1::BoundsExceeded)?;
        if length > max {
            return Err(PluginTrustErrorV1::BoundsExceeded);
        }
        std::str::from_utf8(self.take(length)?).map_err(|_| PluginTrustErrorV1::InvalidEncoding)
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], PluginTrustErrorV1> {
        let (major, length) = self.head()?;
        if major != 2
            || length != u64::try_from(N).map_err(|_| PluginTrustErrorV1::BoundsExceeded)?
        {
            return Err(PluginTrustErrorV1::InvalidEncoding);
        }
        self.take(N)?
            .try_into()
            .map_err(|_| PluginTrustErrorV1::InvalidEncoding)
    }

    fn optional_bytes<const N: usize>(&mut self) -> Result<Option<[u8; N]>, PluginTrustErrorV1> {
        if self.bytes.get(self.offset) == Some(&0xf6) {
            self.offset += 1;
            Ok(None)
        } else {
            self.bytes::<N>().map(Some)
        }
    }

    fn finish(&self) -> Result<(), PluginTrustErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PluginTrustErrorV1::InvalidEncoding)
        }
    }
}

fn read_owner(reader: &mut Reader<'_>) -> Result<OwnerIdV1, PluginTrustErrorV1> {
    OwnerIdV1::new(reader.text(128)?.to_owned()).map_err(|_| PluginTrustErrorV1::InvalidEncoding)
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
    Ok(PublisherKey {
        owner,
        epoch,
        public: reader.bytes()?,
    })
}

fn read_optional_publisher(
    reader: &mut Reader<'_>,
) -> Result<Option<PublisherKey>, PluginTrustErrorV1> {
    if reader.bytes.get(reader.offset) == Some(&0xf6) {
        reader.offset += 1;
        Ok(None)
    } else {
        read_publisher(reader).map(Some)
    }
}

fn read_signatures(reader: &mut Reader<'_>) -> Result<Vec<RootSignature>, PluginTrustErrorV1> {
    let count = reader.array(64)?;
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
    let scope = reader.text(128)?;
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

impl PluginTrustRootRecordV1 {
    /// Decode one exact, bounded PTR1 record.
    ///
    /// # Errors
    /// Rejects any noncanonical or structurally invalid field.
    pub fn decode(bytes: &[u8]) -> Result<Self, PluginTrustErrorV1> {
        if bytes.len() > 1024 * 1024 {
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
        let threshold =
            usize::try_from(reader.unsigned()?).map_err(|_| PluginTrustErrorV1::InvalidEncoding)?;
        let key_count = reader.array(32)?;
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
            if id != root_key_id(public)
                || keys.last().is_some_and(|old: &RootKey| old.id >= id)
                || !root_publics.insert(public)
            {
                return Err(PluginTrustErrorV1::InvalidEncoding);
            }
            keys.push(RootKey { id, public });
        }
        let publisher_count = reader.array(256)?;
        let mut publishers = Vec::with_capacity(publisher_count);
        let mut publisher_publics = BTreeSet::new();
        let mut publisher_identities = BTreeSet::new();
        for _ in 0..publisher_count {
            let publisher = read_publisher(&mut reader)?;
            if publishers.last().is_some_and(|old| old >= &publisher)
                || !publisher_publics.insert(publisher.public)
                || !publisher_identities.insert((publisher.owner, publisher.epoch))
            {
                return Err(PluginTrustErrorV1::InvalidEncoding);
            }
            publishers.push(publisher);
        }
        let grant_count = reader.array(256)?;
        let mut grants = Vec::with_capacity(grant_count);
        for _ in 0..grant_count {
            if reader.array(2)? != 2 {
                return Err(PluginTrustErrorV1::InvalidEncoding);
            }
            let plugin_id = reader.text(128)?;
            validate_plugin_id(plugin_id)?;
            let owner = read_owner(&mut reader)?;
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
        let prefix_end = reader.offset;
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
    if count > 4096 {
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
    if count > 4096 {
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
        if bytes.len() > 1024 * 1024 {
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
        let prefix_end = reader.offset;
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
            .ok_or(PluginTrustErrorV1::InvalidSignature)?;
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
    if root_bytes.len() > 64 {
        return Err(PluginTrustErrorV1::RootHistoryCapacityExceeded);
    }
    if revocation_bytes.len() > 256 {
        return Err(PluginTrustErrorV1::RevocationHistoryCapacityExceeded);
    }
    if root_bytes.is_empty() || revocation_bytes.is_empty() {
        return Err(PluginTrustErrorV1::ChainDiscontinuity);
    }
    let roots = root_bytes
        .iter()
        .map(|bytes| PluginTrustRootRecordV1::decode(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    let genesis = &roots[0];
    if genesis.digest != anchor.genesis_digest
        || genesis.scope != anchor.scope
        || genesis.previous.is_some()
    {
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
            if root.version
                != previous
                    .version
                    .checked_add(1)
                    .ok_or(PluginTrustErrorV1::ChainDiscontinuity)?
                || root.previous != Some(previous.digest)
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
    let terminal_root = roots.last().ok_or(PluginTrustErrorV1::ChainDiscontinuity)?;
    if evaluation_utc_second < terminal_root.not_before
        || evaluation_utc_second >= terminal_root.expires
    {
        return Err(PluginTrustErrorV1::Expired);
    }
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
        if revocation.scope != anchor.scope {
            return Err(PluginTrustErrorV1::ChainDiscontinuity);
        }
        let root_index = roots
            .iter()
            .position(|root| root.digest == revocation.root_digest)
            .ok_or(PluginTrustErrorV1::ChainDiscontinuity)?;
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
            if revocation.previous != Some(prior.digest)
                || revocation.epoch <= prior.epoch
                || revocation.tick < prior.tick
            {
                return Err(PluginTrustErrorV1::ChainDiscontinuity);
            }
            validate_cumulative_keys(&prior.keys, &revocation.keys, revocation.tick)?;
            validate_cumulative_artifacts(
                &prior.artifacts,
                &revocation.artifacts,
                revocation.tick,
            )?;
        } else if revocation.previous.is_some()
            || revocation
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
    let terminal_revocation = revocations
        .last()
        .ok_or(PluginTrustErrorV1::ChainDiscontinuity)?;
    if terminal_revocation.root_digest != terminal_root.digest {
        return Err(PluginTrustErrorV1::ChainDiscontinuity);
    }
    if evaluation_utc_second < terminal_revocation.not_before
        || evaluation_utc_second >= terminal_revocation.expires
    {
        return Err(PluginTrustErrorV1::Expired);
    }
    Ok(VerifiedPluginTrustEvidenceV1 {
        scope: anchor.scope.clone(),
        root_version: terminal_root.version,
        root_digest: terminal_root.digest,
        policy_epoch: terminal_revocation.epoch,
        revocation_digest: terminal_revocation.digest,
        evaluation_utc_second,
        evaluation_tick,
        root_validity: (terminal_root.not_before, terminal_root.expires),
        revocation_validity: (terminal_revocation.not_before, terminal_revocation.expires),
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
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
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

    fn encode(value: Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded)?;
        Ok(encoded)
    }

    fn signed_record(
        mut fields: Vec<Value>,
        domain: &[u8],
        signers: &[&SigningKey],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut message = domain.to_vec();
        message.extend_from_slice(&encode(Value::Array(fields.clone()))?);
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
        encode(Value::Array(fields))
    }

    fn root(
        signer: &SigningKey,
        publisher: [u8; 32],
        version: u64,
        previous: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let public = signer.verifying_key().to_bytes();
        signed_record(
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
            ],
            ROOT_SIGNATURE_DOMAIN,
            &[signer],
        )
    }

    fn revocation(
        signer: &SigningKey,
        root_digest: [u8; 32],
        epoch: u64,
        previous: Option<[u8; 32]>,
        revoked_artifacts: Vec<Value>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        signed_record(
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
            ],
            REVOCATION_SIGNATURE_DOMAIN,
            &[signer],
        )
    }

    fn fixture() -> Result<(SigningKey, [u8; 32], Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
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

    #[test]
    fn pinned_genesis_and_empty_revocation_produce_bound_facts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (_, publisher, root, revocation) = fixture()?;
        let root_digest = *blake3::hash(&root).as_bytes();
        let revocation_digest = *blake3::hash(&revocation).as_bytes();
        let anchor = TrustedPluginRootAnchorV1::new("scope", root_digest)?;
        let evidence = verify_plugin_trust_v1(&anchor, &[&root], &[&revocation], 50, 4)?;
        assert_eq!(evidence.policy_scope(), "scope");
        assert_eq!(evidence.terminal_root(), (1, root_digest));
        assert_eq!(evidence.terminal_revocation(), (1, revocation_digest));
        assert_eq!(evidence.evaluation_coordinates(), (50, 4));
        assert_eq!(evidence.terminal_validity(), ((0, 100), (0, 100)));
        assert_eq!(
            evidence.publisher_keys().collect::<Vec<_>>(),
            vec![(OwnerIdV1::new("publisher")?, 1, publisher)]
        );
        assert_eq!(
            evidence.exact_grants().collect::<Vec<_>>(),
            vec![("plugin-a", OwnerIdV1::new("publisher")?)]
        );
        assert_eq!(evidence.effective_key_revocations().count(), 0);
        assert_eq!(evidence.effective_artifact_revocations().count(), 0);
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
        let mut trailing = root.clone();
        trailing.push(0);
        assert!(matches!(
            PluginTrustRootRecordV1::decode(&trailing),
            Err(PluginTrustErrorV1::InvalidEncoding)
        ));
        Ok(())
    }

    #[test]
    fn full_history_limits_are_lifetime_ceilings() -> Result<(), Box<dyn std::error::Error>> {
        let (signer, publisher, genesis_root, _) = fixture()?;
        let anchor =
            TrustedPluginRootAnchorV1::new("scope", *blake3::hash(&genesis_root).as_bytes())?;
        let mut roots = vec![genesis_root];
        for version in 2..=65 {
            let previous = *blake3::hash(roots.last().ok_or("no PTR1")?).as_bytes();
            roots.push(root(&signer, publisher, version, Some(previous))?);
        }
        let terminal_root = *blake3::hash(roots.get(63).ok_or("no 64th PTR1")?).as_bytes();
        let mut revocations = vec![revocation(&signer, terminal_root, 1, None, Vec::new())?];
        for epoch in 2..=257 {
            let previous = *blake3::hash(revocations.last().ok_or("no PRV1")?).as_bytes();
            revocations.push(revocation(
                &signer,
                terminal_root,
                epoch,
                Some(previous),
                Vec::new(),
            )?);
        }
        let root_refs = roots.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let revocation_refs = revocations.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert!(
            verify_plugin_trust_v1(&anchor, &root_refs[..64], &revocation_refs[..256], 50, 5)
                .is_ok()
        );
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &root_refs[..65], &revocation_refs[..256], 50, 5),
            Err(PluginTrustErrorV1::RootHistoryCapacityExceeded)
        ));
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &root_refs[..64], &revocation_refs[..257], 50, 5),
            Err(PluginTrustErrorV1::RevocationHistoryCapacityExceeded)
        ));
        assert!(matches!(
            verify_plugin_trust_v1(&anchor, &root_refs[1..64], &revocation_refs[..256], 50, 5),
            Err(PluginTrustErrorV1::AnchorMismatch)
        ));
        Ok(())
    }
}
