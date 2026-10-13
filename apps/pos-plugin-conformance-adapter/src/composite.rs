//! The `PCW2` composite and the `PCA1` anchor (ADR-061 revision 8 decision 7).
//!
//! The composite is the one auxiliary member of an attempt that is a deterministic CBOR array
//! `["PCW2", 1, [[digest32, bytes], ...]]` with the pieces sorted by digest. Every CBOR item
//! here is decoded with `ciborium`, re-encoded canonically and compared byte for byte with its
//! input, which also rejects indefinite-length items, non-shortest integers and trailing bytes.
//! A composite fault is a non-executed outcome of the attempt. A digest that names no piece and
//! an undecodable `PCA1` anchor are `payload-invalid`; [`crate::world`] reports them.

use std::collections::BTreeMap;

use ciborium::value::Value;
use pos_reference::evaluator::AttemptArtifact;
use pos_runtime::community_plugin_host::CommunityTrustAnchorBytesV1;

/// The first six bytes of a composite: a three-item array whose first item is the text `PCW2`.
const HEADER: [u8; 6] = [0x83, 0x64, 0x50, 0x43, 0x57, 0x32];

/// A composite fault: the attempt is not executed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PiecesFaultV1 {
    /// No auxiliary member is a composite.
    #[error("the attempt has no composite")]
    Missing,
    /// More than one auxiliary member is a composite.
    #[error("the attempt has more than one composite")]
    Ambiguous,
    /// The composite is not deterministic CBOR of the exact shape, or a piece is wrong.
    #[error("the composite is invalid")]
    Invalid,
}

/// The verified map from BLAKE3 digest to piece bytes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PiecesV1 {
    pieces: BTreeMap<[u8; 32], Vec<u8>>,
}

impl PiecesV1 {
    /// The composite among `auxiliary`: the unique member that starts with the composite header.
    ///
    /// # Errors
    /// Returns [`PiecesFaultV1::Missing`] for zero composites, [`PiecesFaultV1::Ambiguous`] for
    /// more than one, and [`PiecesFaultV1::Invalid`] when the composite violates decision 7:
    /// not canonical CBOR, a wrong shape or version, a piece whose digest is not the BLAKE3 of
    /// its bytes, a duplicate digest, or pieces that are not sorted by digest.
    pub fn find(auxiliary: &[AttemptArtifact]) -> Result<Self, PiecesFaultV1> {
        let mut found = auxiliary
            .iter()
            .filter(|member| member.bytes.starts_with(&HEADER));
        match (found.next(), found.next()) {
            (None, _) => Err(PiecesFaultV1::Missing),
            (Some(_), Some(_)) => Err(PiecesFaultV1::Ambiguous),
            (Some(member), None) => Self::from_bytes(&member.bytes),
        }
    }

    /// The pieces of the composite `bytes`.
    ///
    /// # Errors
    /// Returns [`PiecesFaultV1::Invalid`] as [`Self::find()`] describes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PiecesFaultV1> {
        canonical_value(bytes)
            .and_then(|value| pieces_of(&value))
            .map(|pieces| Self { pieces })
            .ok_or(PiecesFaultV1::Invalid)
    }

    /// The pieces `blobs`, each addressed by its BLAKE3 digest.
    #[must_use]
    pub fn from_blobs(blobs: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let pieces = blobs
            .into_iter()
            .map(|bytes| (*blake3::hash(&bytes).as_bytes(), bytes))
            .collect();
        Self { pieces }
    }

    /// The piece with BLAKE3 digest `digest`.
    #[must_use]
    pub fn get(&self, digest: &[u8; 32]) -> Option<&[u8]> {
        self.pieces.get(digest).map(Vec::as_slice)
    }
}

/// The CBOR value of `bytes`, if re-encoding it canonically gives `bytes` again.
fn canonical_value(bytes: &[u8]) -> Option<Value> {
    ciborium::from_reader::<Value, _>(bytes)
        .ok()
        .and_then(|value| {
            let mut again = Vec::new();
            let written = ciborium::into_writer(&value, &mut again).is_ok();
            (written && again == bytes).then_some(value)
        })
}

/// The unsigned integer of a CBOR integer, if it is one.
fn unsigned(value: &ciborium::value::Integer) -> Option<u64> {
    u64::try_from(i128::from(*value)).ok()
}

/// The 32 bytes of a CBOR byte string.
fn digest_of(bytes: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(bytes).ok()
}

/// The pieces of a composite value: version 1 and pieces in strictly ascending digest order.
fn pieces_of(value: &Value) -> Option<BTreeMap<[u8; 32], Vec<u8>>> {
    match value {
        Value::Array(items) => match items.as_slice() {
            [Value::Text(tag), Value::Integer(version), Value::Array(list)]
                if tag == "PCW2" && unsigned(version) == Some(1) =>
            {
                ordered(list)
            }
            _ => None,
        },
        _ => None,
    }
}

/// The pieces of `list`, which must be strictly ascending by digest.
fn ordered(list: &[Value]) -> Option<BTreeMap<[u8; 32], Vec<u8>>> {
    let mut pieces = BTreeMap::new();
    let mut previous: Option<[u8; 32]> = None;
    for item in list {
        let (digest, bytes) = piece(item)?;
        if previous.is_some_and(|before| before >= digest) {
            return None;
        }
        previous = Some(digest);
        pieces.insert(digest, bytes.clone());
    }
    Some(pieces)
}

/// One `[digest32, bytes]` pair whose digest is the BLAKE3 of its bytes.
fn piece(item: &Value) -> Option<([u8; 32], &Vec<u8>)> {
    match item {
        Value::Array(pair) => match pair.as_slice() {
            [Value::Bytes(digest), Value::Bytes(bytes)] => digest_of(digest)
                .filter(|digest| blake3::hash(bytes).as_bytes() == digest)
                .map(|digest| (digest, bytes)),
            _ => None,
        },
        _ => None,
    }
}

/// The anchor of a `PCA1` piece: `["PCA1", 1, scope, ptr1_genesis_digest, operator_key,
/// genesis_tps1_digest]`, as canonical CBOR.
#[must_use]
pub fn decode_anchor(bytes: &[u8]) -> Option<CommunityTrustAnchorBytesV1> {
    canonical_value(bytes).and_then(|value| anchor_of(&value))
}

fn anchor_of(value: &Value) -> Option<CommunityTrustAnchorBytesV1> {
    match value {
        Value::Array(items) => match items.as_slice() {
            [Value::Text(tag), Value::Integer(version), Value::Text(scope), Value::Bytes(genesis), Value::Bytes(key), Value::Bytes(tps1)]
                if tag == "PCA1" && unsigned(version) == Some(1) =>
            {
                let digests = digest_of(genesis).zip(digest_of(key)).zip(digest_of(tps1));
                digests.map(|((genesis, key), tps1)| CommunityTrustAnchorBytesV1 {
                    scope: scope.clone(),
                    ptr1_genesis_digest: genesis,
                    operator_key: key,
                    genesis_tps1_digest: tps1,
                })
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
