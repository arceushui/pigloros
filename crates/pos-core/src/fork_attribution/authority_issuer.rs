//! ADR-105 `FAI1` issuer identities and the `FIP1` issuer policy.
//!
//! Both are exact portable values only. Neither installs, pins, or advances
//! local issuer trust; the operator-pinned policy floor is a separate seam.

use std::collections::BTreeSet;

use super::{
    array, authority_wire, bytes, canonical, domain_digest, text, uint,
    ForkAttributionCodecErrorV1 as Error, Reader,
};
use crate::{Hash, PublicKey};

/// Maximum accepted canonical `FAI1` bytes, as carried by `FAE1` field 3 and
/// each `FIP1` entry.
pub const MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1: usize = 512;
/// Maximum exact UTF-8 bytes in an issuer ID or an issuer-policy scope.
pub const MAX_FORK_ATTRIBUTION_ISSUER_ID_BYTES_V1: usize = 128;
/// Maximum accepted canonical `FIP1` bytes.
pub const MAX_FORK_ATTRIBUTION_ISSUER_POLICY_BYTES_V1: usize = 20_480;
/// Maximum issuer identities in one `FIP1`; this is a V1 lifetime ceiling.
pub const MAX_FORK_ATTRIBUTION_ISSUER_POLICY_ENTRIES_V1: usize = 32;

const POLICY_DOMAIN: &[u8] = b"pigloros/fork-attribution-issuer-policy/v1";

/// One exact `FAI1` attribution-import issuer identity.
///
/// The public key is carried exactly; Ed25519 point validity is checked by
/// the `pos-crypto` verification seam, never assumed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionIssuerV1 {
    issuer_id: String,
    epoch: u64,
    public_key: PublicKey,
}

impl ForkAttributionIssuerV1 {
    /// Construct one issuer identity.
    ///
    /// # Errors
    /// Rejects an issuer ID outside 1..=128 exact UTF-8 bytes or a zero epoch.
    pub fn new(
        issuer_id: impl Into<String>,
        epoch: u64,
        public_key: PublicKey,
    ) -> Result<Self, Error> {
        let issuer_id = issuer_id.into();
        if issuer_id.is_empty()
            || issuer_id.len() > MAX_FORK_ATTRIBUTION_ISSUER_ID_BYTES_V1
            || epoch == 0
        {
            return Err(Error::FieldOutOfBounds);
        }
        Ok(Self {
            issuer_id,
            epoch,
            public_key,
        })
    }

    /// Return the exact, unnormalized issuer ID.
    #[must_use]
    pub const fn issuer_id(&self) -> &str {
        self.issuer_id.as_str()
    }

    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Encode the exact five-field deterministic-CBOR `FAI1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(192);
        array(&mut out, 5);
        text(&mut out, "FAI1");
        uint(&mut out, 1);
        text(&mut out, &self.issuer_id);
        uint(&mut out, self.epoch);
        bytes(&mut out, self.public_key.as_bytes());
        out
    }

    /// Decode exact canonical `FAI1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, unsupported-version, or noncanonical bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1)?;
        wire.array(5)?;
        wire.magic("FAI1")?;
        wire.version()?;
        let issuer_id = wire.bounded_text(MAX_FORK_ATTRIBUTION_ISSUER_ID_BYTES_V1)?;
        let epoch = wire.uint()?;
        let public_key = PublicKey::from_bytes(wire.fixed()?);
        wire.finish()?;
        let record = Self::new(issuer_id, epoch, public_key)?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }

    /// The `FIP1` entry order: exact issuer-ID bytes, then numeric epoch.
    const fn order_key(&self) -> (&[u8], u64) {
        (self.issuer_id.as_bytes(), self.epoch)
    }
}

/// Closed `FIP1` issuer states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkAttributionIssuerStateV1 {
    /// May authorize a new absent import operation.
    Active,
    /// May verify only an already committed operation.
    Retired,
    /// Terminal; authorizes no new operation or uncommitted retry.
    Revoked,
}

impl ForkAttributionIssuerStateV1 {
    /// Return the closed wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Retired => 2,
            Self::Revoked => 3,
        }
    }

    /// Decode a closed wire code.
    ///
    /// # Errors
    /// Rejects every code other than 1, 2, or 3.
    pub const fn from_code(code: u64) -> Result<Self, Error> {
        match code {
            1 => Ok(Self::Active),
            2 => Ok(Self::Retired),
            3 => Ok(Self::Revoked),
            _ => Err(Error::InvalidEncoding),
        }
    }
}

/// One `FIP1` entry: an exact issuer identity and its state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionIssuerPolicyEntryV1 {
    pub issuer: ForkAttributionIssuerV1,
    pub state: ForkAttributionIssuerStateV1,
}

/// Construction fields for one `FIP1` issuer policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionIssuerPolicyInputV1 {
    pub scope: String,
    pub generation: u64,
    pub previous_policy_digest: Option<Hash>,
    pub entries: Vec<ForkAttributionIssuerPolicyEntryV1>,
}

/// Strict portable `FIP1` bytes.
///
/// This value validates only its own structure. Continuity with a
/// predecessor, legal state transitions, the operator pin, and the durable
/// floor belong to the policy installation seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkAttributionIssuerPolicyV1(ForkAttributionIssuerPolicyInputV1);

impl ForkAttributionIssuerPolicyV1 {
    /// Validate one structurally complete issuer policy.
    ///
    /// # Errors
    /// Returns `FieldOutOfBounds` for an invalid scope, generation,
    /// predecessor shape, or entry count; `NonCanonical` for entries
    /// that are not strictly increasing by `(issuer_id, epoch)`; and
    /// `FieldMismatch` for a public key named by two entries.
    pub fn new(input: ForkAttributionIssuerPolicyInputV1) -> Result<Self, Error> {
        validate_policy_header(&input)?;
        validate_policy_entries(&input.entries)?;
        Ok(Self(input))
    }

    #[must_use]
    pub const fn input(&self) -> &ForkAttributionIssuerPolicyInputV1 {
        &self.0
    }

    /// Return the state of an exact issuer identity, if the policy names it.
    #[must_use]
    pub fn issuer_state(
        &self,
        issuer: &ForkAttributionIssuerV1,
    ) -> Option<ForkAttributionIssuerStateV1> {
        self.0
            .entries
            .iter()
            .find(|entry| entry.issuer == *issuer)
            .map(|entry| entry.state)
    }

    /// Return the domain-separated digest over complete canonical `FIP1` bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(POLICY_DOMAIN, &self.to_canonical_cbor())
    }

    /// Encode the exact six-field deterministic-CBOR `FIP1` array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let value = &self.0;
        let mut out = Vec::with_capacity(256 + value.entries.len() * 192);
        array(&mut out, 6);
        text(&mut out, "FIP1");
        uint(&mut out, 1);
        text(&mut out, &value.scope);
        uint(&mut out, value.generation);
        authority_wire::optional_hash(&mut out, value.previous_policy_digest);
        array(&mut out, value.entries.len() as u64);
        for entry in &value.entries {
            array(&mut out, 2);
            bytes(&mut out, &entry.issuer.to_canonical_cbor());
            uint(&mut out, u64::from(entry.state.code()));
        }
        out
    }

    /// Decode exact canonical `FIP1` bytes.
    ///
    /// # Errors
    /// Rejects malformed, out-of-bounds, unsupported-version, unordered, or
    /// noncanonical bytes.
    pub fn from_canonical_cbor(bytes_in: &[u8]) -> Result<Self, Error> {
        let mut wire = Reader::new(bytes_in, MAX_FORK_ATTRIBUTION_ISSUER_POLICY_BYTES_V1)?;
        wire.array(6)?;
        wire.magic("FIP1")?;
        wire.version()?;
        let scope = wire.bounded_text(MAX_FORK_ATTRIBUTION_ISSUER_ID_BYTES_V1)?;
        let generation = wire.uint()?;
        let previous_policy_digest = wire.optional_hash()?;
        let count = wire.bounded_len(MAX_FORK_ATTRIBUTION_ISSUER_POLICY_ENTRIES_V1)?;
        let entries = (0..count)
            .map(|_| read_policy_entry(&mut wire))
            .collect::<Result<Vec<_>, _>>()?;
        wire.finish()?;
        let record = Self::new(ForkAttributionIssuerPolicyInputV1 {
            scope,
            generation,
            previous_policy_digest,
            entries,
        })?;
        canonical(bytes_in, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

fn read_policy_entry(wire: &mut Reader<'_>) -> Result<ForkAttributionIssuerPolicyEntryV1, Error> {
    wire.array(2)?;
    let issuer = ForkAttributionIssuerV1::from_canonical_cbor(
        wire.record(MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1)?,
    )?;
    let state = ForkAttributionIssuerStateV1::from_code(wire.uint()?)?;
    Ok(ForkAttributionIssuerPolicyEntryV1 { issuer, state })
}

/// Genesis is generation 1 with no predecessor; every successor names a
/// nonzero predecessor digest.
fn validate_policy_header(input: &ForkAttributionIssuerPolicyInputV1) -> Result<(), Error> {
    let genesis = input.generation == 1;
    if input.scope.is_empty()
        || input.scope.len() > MAX_FORK_ATTRIBUTION_ISSUER_ID_BYTES_V1
        || input.generation == 0
        || genesis != input.previous_policy_digest.is_none()
        || input.previous_policy_digest == Some(Hash::zero())
        || input.entries.is_empty()
        || input.entries.len() > MAX_FORK_ATTRIBUTION_ISSUER_POLICY_ENTRIES_V1
    {
        return Err(Error::FieldOutOfBounds);
    }
    Ok(())
}

fn validate_policy_entries(entries: &[ForkAttributionIssuerPolicyEntryV1]) -> Result<(), Error> {
    if entries
        .windows(2)
        .any(|pair| pair[0].issuer.order_key() >= pair[1].issuer.order_key())
    {
        return Err(Error::NonCanonical);
    }
    let keys = entries
        .iter()
        .map(|entry| *entry.issuer.public_key.as_bytes())
        .collect::<BTreeSet<_>>();
    if keys.len() == entries.len() {
        Ok(())
    } else {
        Err(Error::FieldMismatch)
    }
}
