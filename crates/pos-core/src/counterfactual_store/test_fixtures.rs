//! Shared `RCF1`/`SIV1` byte-fixture encoders for counterfactual storage
//! port tests.
//!
//! The port carries both records as exact canonical bytes, so tests of the
//! port, its Memory and `SQLite` adapters, and the coordinator build them
//! with these encoders instead of copying them. The framing constants are
//! written out independently of the port's own verifier so the fixtures stay
//! an independent check of it. Available only with the `test-support`
//! feature.

use crate::Hash;

/// `RCF1` self-digest domain.
pub const FRONTIER_DOMAIN: &[u8] = b"PiglorOS.RecomputationFrontier.v1";
/// `SIV1` self-digest domain.
pub const INVALIDATION_DOMAIN: &[u8] = b"PiglorOS.SuffixInvalidation.v1";
/// `RCF1` text magic and version `1`, as encoded after the array head.
pub const FRONTIER_PREFIX: [u8; 6] = [0x64, b'R', b'C', b'F', b'1', 0x01];
/// `SIV1` text magic and version `1`, as encoded after the array head.
pub const INVALIDATION_PREFIX: [u8; 6] = [0x64, b'S', b'I', b'V', b'1', 0x01];
/// `RCF1` `(record array head, unsigned array head)`.
pub const FRONTIER_HEADS: (u8, u8) = (0x91, 0x90);
/// `SIV1` `(record array head, unsigned array head)`.
pub const INVALIDATION_HEADS: (u8, u8) = (0x92, 0x91);
/// Encoded size of one 32-byte digest field, head included.
pub const DIGEST_FIELD_BYTES: usize = 34;
/// Producer digest every [`node_field`] carries.
pub const NODE_DIGEST: Hash = Hash::from_bytes([21; 32]);

/// Encode one shortest-form CBOR unsigned integer.
#[must_use]
pub fn uint(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => vec![bytes[7]],
        24..=0xff => vec![0x18, bytes[7]],
        0x100..=0xffff => [&[0x19][..], &bytes[6..]].concat(),
        0x1_0000..=0xffff_ffff => [&[0x1a][..], &bytes[4..]].concat(),
        _ => [&[0x1b][..], &bytes[..]].concat(),
    }
}

/// Encode one shortest-form CBOR head of `major` (a CBOR major type, which
/// must be at most 7) with `argument`.
#[must_use]
pub fn head(major: u8, argument: u64) -> Vec<u8> {
    let mut encoded = uint(argument);
    encoded[0] += major << 5;
    encoded
}

/// Encode one CBOR text string.
#[must_use]
pub fn text_field(value: &str) -> Vec<u8> {
    [
        head(3, u64::try_from(value.len()).unwrap_or(u64::MAX)),
        value.as_bytes().to_vec(),
    ]
    .concat()
}

/// Encode one 16-byte identity field.
#[must_use]
pub fn id_field(value: [u8; 16]) -> Vec<u8> {
    [&[0x50][..], &value[..]].concat()
}

/// Encode one 32-byte digest field.
#[must_use]
pub fn hash_field(value: Hash) -> Vec<u8> {
    [&[0x58, 0x20][..], &value.as_bytes()[..]].concat()
}

/// Encode one six-field dependency-node coordinate at `tick` owned by
/// `owner`, with schema 7 and [`NODE_DIGEST`].
#[must_use]
pub fn node_field(tick: u64, owner: &str) -> Vec<u8> {
    [
        vec![0x86],
        uint(tick),
        uint(0),
        text_field(owner),
        uint(0),
        uint(7),
        hash_field(NODE_DIGEST),
    ]
    .concat()
}

/// Encode `SIV1` fields 8 through 14, crossing every CBOR argument width.
#[must_use]
pub fn invalidation_middle() -> Vec<u8> {
    [
        node_field(5, "agent-a"),
        node_field(4_294_967_296, "an-owner-identifier-of-thirty-"),
        vec![0x81, 0x86],
        text_field("event"),
        uint(70_000),
        hash_field(Hash::from_bytes([22; 32])),
        node_field(5, "agent-a"),
        uint(300),
        uint(0),
        vec![0x81],
        hash_field(Hash::from_bytes([23; 32])),
        vec![0x80, 0x80],
        uint(0),
    ]
    .concat()
}

/// Frame the fields after the version as one self-digested record:
/// `heads.0`, `prefix`, `fields`, `padding` zero bytes, then the digest
/// field over `domain`, a zero byte, `heads.1`, and everything after the
/// record array head.
#[must_use]
pub fn frame(
    heads: (u8, u8),
    prefix: [u8; 6],
    domain: &[u8],
    fields: &[u8],
    padding: usize,
) -> Vec<u8> {
    let mut bytes = vec![heads.0];
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(fields);
    bytes.resize(bytes.len() + padding, 0);
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0, heads.1]);
    hasher.update(&bytes[1..]);
    bytes.extend_from_slice(&[0x58, 0x20]);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    bytes
}

/// Frame `RCF1` fields after the version, with `padding` zero bytes.
#[must_use]
pub fn frontier_frame(fields: &[u8], padding: usize) -> Vec<u8> {
    frame(
        FRONTIER_HEADS,
        FRONTIER_PREFIX,
        FRONTIER_DOMAIN,
        fields,
        padding,
    )
}

/// Frame `SIV1` fields after the version, with `padding` zero bytes.
#[must_use]
pub fn invalidation_frame(fields: &[u8], padding: usize) -> Vec<u8> {
    frame(
        INVALIDATION_HEADS,
        INVALIDATION_PREFIX,
        INVALIDATION_DOMAIN,
        fields,
        padding,
    )
}
