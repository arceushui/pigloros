//! ADR-103 revision 3 and 4 Plugin trust bridge: the pure, storage-free checks that
//! turn an operator-signed TPS1 snapshot and #423's verified PTR1/PRV1
//! evidence into one authenticated Plugin trust-policy fact.
//!
//! This module owns no durable state. It never decides when an admission
//! commits, which trusted-UTC source feeds it, or what a denied admission
//! retains; those belong to the registry that calls it.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;
use pos_core::OwnerIdV1;
use pos_crypto::plugin_trust::{
    ResolvedPluginTrustAuthorizationV1, TrustedPluginRootAnchorV1, VerifiedPluginTrustEvidenceV1,
};
use thiserror::Error;

// The TPS1_MAX_* caps live at the crate root because clippy rejects `pub(crate)` items in
// private modules.
use crate::{
    TrustPolicySnapshotV1, TPS1_MAX_REVOKED_ARTIFACTS, TPS1_MAX_REVOKED_KEYS, TPS1_MAX_TRUST_ROOTS,
};

/// The only operator role ADR-103 accepts for the Plugin TPS1 signature.
pub const PLUGIN_OPERATOR_ROLE_V1: &str = "deployment-operator";
/// Reserved TPS1 `trust_roots` key-ID prefix for PTR1 root keys.
pub const PLUGIN_ROOT_KEY_ID_PREFIX_V1: &str = "ptr1-";
/// Reserved TPS1 `revoked_key_ids` prefix for PRV1 publisher-key denials.
pub const PLUGIN_REVOKED_KEY_ID_PREFIX_V1: &str = "pkr1-";
/// Exact length of every `ptr1-` and `pkr1-` TPS1 identifier.
pub const PLUGIN_TPS1_BRIDGE_ID_BYTES_V1: usize = 69;
/// Exact length of an `offline_valid_through` value.
pub const OFFLINE_VALID_THROUGH_BYTES_V1: usize = 20;

const REVOKED_KEY_DOMAIN: &[u8] = b"pigloros/plugin-revoked-key-id/v1\0";
const PUBLISHER_KEY_ROLE: u64 = 3;
const SECONDS_PER_DAY: i64 = 86_400;
const DAYS_FROM_CIVIL_EPOCH_OFFSET: i64 = 719_468;
const DAYS_PER_ERA: i64 = 146_097;

const CBOR_MAJOR_UNSIGNED: u8 = 0;
const CBOR_MAJOR_BYTES: u8 = 2;
const CBOR_MAJOR_TEXT: u8 = 3;
const CBOR_MAJOR_ARRAY: u8 = 4;

/// Closed, secret-free failures of the Plugin TPS1 bridge.
///
/// One enum covers anchor, authentication, policy, genesis and successor failures because
/// the registry wraps it as a single `Bridge(..)` family.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginTrustBridgeErrorV1 {
    /// The anchor scope is not a valid Plugin policy scope.
    #[error("Plugin trust anchor scope is invalid")]
    InvalidAnchorScope,
    /// The anchor operator role is not `deployment-operator`.
    #[error("Plugin trust anchor operator role is invalid")]
    InvalidAnchorRole,
    /// The anchor operator key is not a valid Ed25519 verification key.
    #[error("Plugin trust anchor operator key is invalid")]
    InvalidAnchorOperatorKey,
    /// The bytes are not one exact canonical, structurally valid TPS1.
    #[error("TPS1 snapshot is invalid")]
    InvalidSnapshot,
    /// The pinned operator key does not verify the Plugin signature preimage.
    #[error("TPS1 operator signature is invalid")]
    InvalidOperatorSignature,
    /// TPS1 `policy_id` differs from the anchor scope or the evidence scope.
    #[error("TPS1 policy scope differs")]
    ScopeMismatch,
    /// TPS1 epoch differs from the terminal PRV1 epoch.
    #[error("TPS1 epoch differs from the terminal PRV1 epoch")]
    EpochMismatch,
    /// The evidence was bound to a UTC second other than the trusted second.
    #[error("evidence UTC second differs from the trusted UTC second")]
    EvaluationUtcMismatch,
    /// The evidence was bound to a Tick other than the trusted Tick.
    #[error("evidence Tick differs from the trusted Tick")]
    EvaluationTickMismatch,
    /// `offline_valid_through` is not exact 20-byte real Gregorian UTC text.
    #[error("TPS1 offline_valid_through is not exact UTC text")]
    InvalidUtcFormat,
    /// The trusted UTC second is not strictly before `offline_valid_through`.
    #[error("TPS1 snapshot is expired")]
    Expired,
    /// A terminal PTR1 root key is missing from, or differs in, TPS1.
    #[error("TPS1 trust roots differ from the terminal PTR1 root keys")]
    BridgeRootMismatch,
    /// An effective PRV1 denial is missing from TPS1.
    #[error("TPS1 revocations differ from the effective PRV1 denials")]
    BridgeRevocationMismatch,
    /// TPS1 uses a reserved `ptr1-` or `pkr1-` identifier the evidence does not derive.
    #[error("TPS1 uses a reserved Plugin identifier prefix without matching evidence")]
    ReservedPrefix,
    /// A TPS1 list would exceed the global TPS1 cap.
    #[error("TPS1 global capacity is exceeded")]
    TpsCapExceeded,
    /// The TPS1 is not the anchor's genesis: epoch 1, null predecessor, pinned digest.
    #[error("TPS1 snapshot is not the pinned genesis")]
    InvalidGenesis,
    /// The TPS1 epoch is not strictly greater than the retained epoch.
    #[error("TPS1 snapshot epoch is not newer than the retained snapshot")]
    StaleSnapshot,
    /// The TPS1 does not name the retained snapshot digest as its predecessor.
    #[error("TPS1 snapshot does not continue the retained snapshot")]
    SnapshotDiscontinuity,
    /// TPS1 denies the release's PMF1 digest, release digest, or a descriptor digest.
    #[error("TPS1 denies the release artifact")]
    TpsArtifactDenied,
}

/// Operator-pinned anchor for one exact Plugin policy scope.
///
/// The operator key is neither a PTR1 root key nor a TPS1 `trust_roots`
/// member, and V1 has no in-band operator rotation. Only the private trusted
/// deployment composition boundary should construct this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginTrustPolicyAnchorV1 {
    root_anchor: TrustedPluginRootAnchorV1,
    scope: String,
    operator_key: [u8; 32],
    genesis_tps1_digest: [u8; 32],
}

impl PluginTrustPolicyAnchorV1 {
    /// Pin one scope, its PTR1 genesis digest, the operator key and role, and
    /// the full canonical genesis TPS1 digest.
    ///
    /// # Errors
    /// Returns a closed error for an invalid scope, a role other than
    /// `deployment-operator`, or an operator key that is not a valid Ed25519
    /// verification key.
    pub fn new(
        scope: &str,
        ptr1_genesis_digest: [u8; 32],
        operator_key: [u8; 32],
        operator_role: &str,
        genesis_tps1_digest: [u8; 32],
    ) -> Result<Self, PluginTrustBridgeErrorV1> {
        // The error is closed and secret-free, so the cause is dropped. The scope is stored
        // again below because the pos-crypto anchor exposes no getter.
        let root_anchor = TrustedPluginRootAnchorV1::new(scope, ptr1_genesis_digest)
            .map_err(|_| PluginTrustBridgeErrorV1::InvalidAnchorScope)?;
        if operator_role != PLUGIN_OPERATOR_ROLE_V1 {
            return Err(PluginTrustBridgeErrorV1::InvalidAnchorRole);
        }
        VerifyingKey::from_bytes(&operator_key)
            .map_err(|_| PluginTrustBridgeErrorV1::InvalidAnchorOperatorKey)?;
        Ok(Self {
            root_anchor,
            scope: scope.to_owned(),
            operator_key,
            genesis_tps1_digest,
        })
    }

    /// The exact policy scope, equal to the TPS1 `policy_id`.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The pinned PTR1 genesis anchor for #423's stateless verifier.
    #[must_use]
    pub const fn root_anchor(&self) -> &TrustedPluginRootAnchorV1 {
        &self.root_anchor
    }

    /// The pinned Ed25519 operator verification key.
    #[must_use]
    pub const fn operator_key(&self) -> [u8; 32] {
        self.operator_key
    }

    /// The pinned operator role, always `deployment-operator`.
    #[must_use]
    pub const fn operator_role(&self) -> &'static str {
        PLUGIN_OPERATOR_ROLE_V1
    }

    /// BLAKE3-256 of the complete canonical genesis TPS1 bytes.
    #[must_use]
    pub const fn genesis_tps1_digest(&self) -> [u8; 32] {
        self.genesis_tps1_digest
    }
}

/// One TPS1 whose canonical encoding and operator signature were verified
/// against a [`PluginTrustPolicyAnchorV1`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPluginTps1V1 {
    snapshot: TrustPolicySnapshotV1,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl AuthenticatedPluginTps1V1 {
    /// The decoded snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &TrustPolicySnapshotV1 {
        &self.snapshot
    }

    /// The exact canonical TPS1 bytes that were authenticated.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// BLAKE3-256 of the complete canonical TPS1 bytes, including the signature.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The TPS1 epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.snapshot.epoch
    }

    /// The TPS1 effective Timeline position, kept as an uninterpreted fact.
    #[must_use]
    pub const fn effective_timeline_position(&self) -> u64 {
        self.snapshot.effective_timeline_position
    }
}

/// Decode exact canonical TPS1 bytes and verify the pinned operator signature.
///
/// # Errors
/// Returns `InvalidSnapshot` for any non-canonical or invalid encoding,
/// `ScopeMismatch` when `policy_id` differs from the anchor scope, and
/// `InvalidOperatorSignature` when the pinned key does not verify the preimage.
pub fn authenticate_plugin_tps1_v1(
    anchor: &PluginTrustPolicyAnchorV1,
    tps1_bytes: &[u8],
) -> Result<AuthenticatedPluginTps1V1, PluginTrustBridgeErrorV1> {
    let snapshot = TrustPolicySnapshotV1::from_canonical_cbor(tps1_bytes)
        .map_err(|_| PluginTrustBridgeErrorV1::InvalidSnapshot)?;
    if snapshot.policy_id != anchor.scope {
        return Err(PluginTrustBridgeErrorV1::ScopeMismatch);
    }
    snapshot
        .verify_operator_signature_v1(&anchor.operator_key, PLUGIN_OPERATOR_ROLE_V1)
        .map_err(|_| PluginTrustBridgeErrorV1::InvalidOperatorSignature)?;
    Ok(AuthenticatedPluginTps1V1 {
        snapshot,
        bytes: tps1_bytes.to_vec(),
        digest: *blake3::hash(tps1_bytes).as_bytes(),
    })
}

/// Run the release-independent ADR-103 policy bridge on an authenticated TPS1.
///
/// The TPS1 was already authenticated, so the signature check runs once. The
/// checks run in this order: evidence scope; epoch; evidence UTC binding;
/// evidence Tick binding; expiry; root mapping; revoked-key mapping; and the
/// artifact-denial superset. Release authorization is the caller's own
/// `authorize_release` call.
///
/// # Errors
/// Returns the first failing closed error in the order above.
pub fn verify_plugin_tps1_policy_v1(
    tps1: &AuthenticatedPluginTps1V1,
    evidence: &VerifiedPluginTrustEvidenceV1,
    trusted_utc_second: i64,
    trusted_tick: u64,
) -> Result<(), PluginTrustBridgeErrorV1> {
    let snapshot = tps1.snapshot();
    if snapshot.policy_id != evidence.policy_scope() {
        return Err(PluginTrustBridgeErrorV1::ScopeMismatch);
    }
    if snapshot.epoch != evidence.terminal_revocation().0 {
        return Err(PluginTrustBridgeErrorV1::EpochMismatch);
    }
    let (evidence_utc_second, evidence_tick) = evidence.evaluation_coordinates();
    if evidence_utc_second != trusted_utc_second {
        return Err(PluginTrustBridgeErrorV1::EvaluationUtcMismatch);
    }
    if evidence_tick != trusted_tick {
        return Err(PluginTrustBridgeErrorV1::EvaluationTickMismatch);
    }
    if trusted_utc_second >= parse_offline_valid_through_v1(&snapshot.offline_valid_through)? {
        return Err(PluginTrustBridgeErrorV1::Expired);
    }
    check_root_mapping(snapshot, evidence)?;
    check_revoked_key_mapping(snapshot, evidence)?;
    check_artifact_mapping(snapshot, evidence)
}

/// Reject a release that the authenticated TPS1 itself denies.
///
/// Artifact digests carry no class, so the TPS1 `revoked_artifact_digests`
/// must not contain the PMF1 digest, the release digest, or any descriptor
/// digest that `authorize_release` checked, even when PRV1 lists none of them.
///
/// # Errors
/// Returns `TpsArtifactDenied` when any of those digests is denied.
pub fn check_plugin_tps1_artifact_denial_v1(
    tps1: &AuthenticatedPluginTps1V1,
    authorization: &ResolvedPluginTrustAuthorizationV1,
) -> Result<(), PluginTrustBridgeErrorV1> {
    let listed = |digest: &[u8; 32]| lists_digest(tps1.snapshot(), digest);
    if listed(&authorization.pmf1_digest())
        || listed(&authorization.release_digest())
        || authorization.descriptor_digests().iter().any(listed)
    {
        Err(PluginTrustBridgeErrorV1::TpsArtifactDenied)
    } else {
        Ok(())
    }
}

/// Check that an authenticated TPS1 is the anchor's genesis snapshot.
///
/// The scope is not rechecked here: `authenticate_plugin_tps1_v1`, which the
/// registry must call first, already requires `policy_id` to equal the anchor scope.
///
/// # Errors
/// Returns `InvalidGenesis` unless the epoch is 1, the predecessor is null,
/// and the full-byte digest equals the anchor's genesis TPS1 digest.
pub fn check_plugin_tps1_genesis_v1(
    anchor: &PluginTrustPolicyAnchorV1,
    tps1: &AuthenticatedPluginTps1V1,
) -> Result<(), PluginTrustBridgeErrorV1> {
    if tps1.epoch() == 1
        && tps1.snapshot().previous_snapshot_digest.is_none()
        && tps1.digest() == anchor.genesis_tps1_digest
    {
        Ok(())
    } else {
        Err(PluginTrustBridgeErrorV1::InvalidGenesis)
    }
}

/// Check that an authenticated TPS1 is a valid successor of the retained one.
///
/// The caller handles byte-identical retained bytes before calling this. The
/// epoch must be strictly greater (gaps are allowed) and the predecessor
/// digest must equal the retained full digest.
///
/// The primitive arguments are deliberate: slice 2 is the sole consumer.
///
/// # Errors
/// Returns `StaleSnapshot` for an equal or lower epoch (checked first) and
/// `SnapshotDiscontinuity` for a wrong or null predecessor.
pub fn check_plugin_tps1_successor_v1(
    retained_epoch: u64,
    retained_digest: [u8; 32],
    candidate: &AuthenticatedPluginTps1V1,
) -> Result<(), PluginTrustBridgeErrorV1> {
    if candidate.epoch() <= retained_epoch {
        return Err(PluginTrustBridgeErrorV1::StaleSnapshot);
    }
    if candidate.snapshot().previous_snapshot_digest != Some(retained_digest) {
        return Err(PluginTrustBridgeErrorV1::SnapshotDiscontinuity);
    }
    Ok(())
}

fn check_root_mapping(
    snapshot: &TrustPolicySnapshotV1,
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> Result<(), PluginTrustBridgeErrorV1> {
    let version = evidence.terminal_root().0;
    let expected = evidence
        .terminal_root_keys()
        .map(|(key_id, public_key)| (plugin_root_key_id_v1(key_id), public_key))
        .collect::<Vec<_>>();
    if snapshot
        .trust_roots
        .iter()
        .filter(|root| root.key_id.starts_with(PLUGIN_ROOT_KEY_ID_PREFIX_V1))
        .any(|root| !expected.iter().any(|(id, _)| *id == root.key_id))
    {
        return Err(PluginTrustBridgeErrorV1::ReservedPrefix);
    }
    for (key_id, public_key) in &expected {
        let matched = snapshot.trust_roots.iter().any(|root| {
            root.key_id == *key_id && root.root_version == version && root.public_key == *public_key
        });
        if !matched {
            return Err(PluginTrustBridgeErrorV1::BridgeRootMismatch);
        }
    }
    Ok(())
}

fn check_revoked_key_mapping(
    snapshot: &TrustPolicySnapshotV1,
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> Result<(), PluginTrustBridgeErrorV1> {
    let expected = evidence
        .effective_key_revocations()
        .map(|(owner, epoch, public_key)| plugin_revoked_key_id_v1(&owner, epoch, public_key))
        .collect::<BTreeSet<_>>();
    let actual = snapshot
        .revoked_key_ids
        .iter()
        .map(String::as_str)
        .filter(|key_id| key_id.starts_with(PLUGIN_REVOKED_KEY_ID_PREFIX_V1))
        .collect::<BTreeSet<_>>();
    if actual.iter().any(|key_id| !expected.contains(*key_id)) {
        return Err(PluginTrustBridgeErrorV1::ReservedPrefix);
    }
    if expected
        .iter()
        .any(|key_id| !actual.contains(key_id.as_str()))
    {
        return Err(PluginTrustBridgeErrorV1::BridgeRevocationMismatch);
    }
    Ok(())
}

fn check_artifact_mapping(
    snapshot: &TrustPolicySnapshotV1,
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> Result<(), PluginTrustBridgeErrorV1> {
    if evidence
        .effective_artifact_revocations()
        .all(|digest| lists_digest(snapshot, &digest))
    {
        Ok(())
    } else {
        Err(PluginTrustBridgeErrorV1::BridgeRevocationMismatch)
    }
}

/// Whether the TPS1 `revoked_artifact_digests` contains `digest`.
fn lists_digest(snapshot: &TrustPolicySnapshotV1, digest: &[u8; 32]) -> bool {
    // TPS1 validation keeps this list strictly ordered, so binary search is exact.
    snapshot
        .revoked_artifact_digests
        .binary_search(digest)
        .is_ok()
}

/// The TPS1 `trust_roots` key ID for one PTR1 root key ID.
///
/// It is `ptr1-` plus 64 lowercase hexadecimal digits (69 ASCII bytes).
#[must_use]
pub fn plugin_root_key_id_v1(root_key_id: [u8; 32]) -> String {
    prefixed_hex(PLUGIN_ROOT_KEY_ID_PREFIX_V1, &root_key_id)
}

/// The TPS1 `revoked_key_ids` entry for one PRV1 publisher-key denial.
///
/// It is `pkr1-` plus the lowercase hexadecimal BLAKE3-256 of the
/// domain-separated canonical CBOR array `[owner_text, 3, epoch, public_key]`
/// (69 ASCII bytes).
#[must_use]
pub fn plugin_revoked_key_id_v1(owner: &OwnerIdV1, epoch: u64, public_key: [u8; 32]) -> String {
    let mut preimage = REVOKED_KEY_DOMAIN.to_vec();
    push_cbor_head(&mut preimage, CBOR_MAJOR_ARRAY, 4);
    let owner_text = owner.as_str().as_bytes();
    // `usize` is at most 64 bits on every supported target, so this cast is lossless.
    let owner_length = owner_text.len() as u64;
    push_cbor_head(&mut preimage, CBOR_MAJOR_TEXT, owner_length);
    preimage.extend_from_slice(owner_text);
    push_cbor_head(&mut preimage, CBOR_MAJOR_UNSIGNED, PUBLISHER_KEY_ROLE);
    push_cbor_head(&mut preimage, CBOR_MAJOR_UNSIGNED, epoch);
    push_cbor_head(&mut preimage, CBOR_MAJOR_BYTES, 32);
    preimage.extend_from_slice(&public_key);
    prefixed_hex(
        PLUGIN_REVOKED_KEY_ID_PREFIX_V1,
        blake3::hash(&preimage).as_bytes(),
    )
}

fn prefixed_hex(prefix: &str, bytes: &[u8; 32]) -> String {
    format!("{prefix}{}", crate::hex_digest(bytes))
}

/// Append the shortest deterministic CBOR head for `major` and `value`.
fn push_cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    let bytes = value.to_be_bytes();
    if value < 24 {
        out.push(major | bytes[7]);
    } else if value <= 0xff {
        out.push(major | 0x18);
        out.push(bytes[7]);
    } else if value <= 0xffff {
        out.push(major | 0x19);
        out.extend_from_slice(&bytes[6..]);
    } else if value <= 0xffff_ffff {
        out.push(major | 0x1a);
        out.extend_from_slice(&bytes[4..]);
    } else {
        out.push(major | 0x1b);
        out.extend_from_slice(&bytes);
    }
}

/// Enforce TPS1's global caps on the complete entry totals.
///
/// The three totals are positional because slice 2 is the only consumer and passes them
/// in TPS1 field order (roots, revoked key IDs, revoked artifact digests).
///
/// Totals include Plugin entries plus every retained non-Plugin entry. The
/// bridge reserves no hidden capacity and never drops, compresses, or
/// reorders either class.
///
/// # Errors
/// Returns `TpsCapExceeded` when any total is above 64 roots, 4096 revoked key
/// IDs, or 4096 revoked artifact digests.
pub const fn check_plugin_tps1_global_caps_v1(
    trust_roots: usize,
    revoked_key_ids: usize,
    revoked_artifact_digests: usize,
) -> Result<(), PluginTrustBridgeErrorV1> {
    if trust_roots > TPS1_MAX_TRUST_ROOTS
        || revoked_key_ids > TPS1_MAX_REVOKED_KEYS
        || revoked_artifact_digests > TPS1_MAX_REVOKED_ARTIFACTS
    {
        Err(PluginTrustBridgeErrorV1::TpsCapExceeded)
    } else {
        Ok(())
    }
}

/// Parse a TPS1 `offline_valid_through` value into UTC seconds since the Unix
/// epoch.
///
/// Only exact 20-byte `YYYY-MM-DDTHH:MM:SSZ` is accepted, with a real
/// proleptic-Gregorian date, hour 00-23, minute 00-59, and second 00-59.
/// Offsets, fractions, lowercase designators, and leap seconds reject.
///
/// # Errors
/// Returns `InvalidUtcFormat` for anything else.
pub fn parse_offline_valid_through_v1(value: &str) -> Result<i64, PluginTrustBridgeErrorV1> {
    CivilTime::parse(value.as_bytes())
        .filter(CivilTime::is_valid)
        .map(|time| time.unix_seconds())
        .ok_or(PluginTrustBridgeErrorV1::InvalidUtcFormat)
}

#[derive(Clone, Copy)]
struct CivilTime {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
}

impl CivilTime {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let separators_exact = bytes.len() == OFFLINE_VALID_THROUGH_BYTES_V1
            && [
                (4, b'-'),
                (7, b'-'),
                (10, b'T'),
                (13, b':'),
                (16, b':'),
                (19, b'Z'),
            ]
            .iter()
            .all(|&(index, separator)| bytes[index] == separator);
        if !separators_exact {
            return None;
        }
        Some(Self {
            year: decimal(&bytes[0..4])?,
            month: decimal(&bytes[5..7])?,
            day: decimal(&bytes[8..10])?,
            hour: decimal(&bytes[11..13])?,
            minute: decimal(&bytes[14..16])?,
            second: decimal(&bytes[17..19])?,
        })
    }

    fn is_valid(&self) -> bool {
        (1..=12).contains(&self.month)
            && (1..=days_in_month(self.year, self.month)).contains(&self.day)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
    }

    /// Howard Hinnant's `days_from_civil`, exact for every four-digit year.
    const fn unix_seconds(&self) -> i64 {
        let year = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let era = year.div_euclid(400);
        let year_of_era = year.rem_euclid(400);
        let shifted_month = (self.month + 9) % 12;
        let day_of_year = (153 * shifted_month + 2) / 5 + self.day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * DAYS_PER_ERA + day_of_era - DAYS_FROM_CIVIL_EPOCH_OFFSET;
        days * SECONDS_PER_DAY + self.hour * 3600 + self.minute * 60 + self.second
    }
}

fn decimal(digits: &[u8]) -> Option<i64> {
    digits.iter().try_fold(0_i64, |value, digit| {
        if digit.is_ascii_digit() {
            Some(value * 10 + i64::from(digit - b'0'))
        } else {
            None
        }
    })
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Which independently enforced trust-record floor a failure concerns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginFloorKindV1 {
    /// The PTR1 `(root_version, complete_record_digest)` floor.
    Root,
    /// The PRV1 `(policy_epoch, complete_record_digest)` floor.
    Revocation,
}

impl std::fmt::Display for PluginFloorKindV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Root => "PTR1",
            Self::Revocation => "PRV1",
        })
    }
}

/// Closed failures of the PTR1/PRV1 floor transition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginFloorErrorV1 {
    /// Exactly one of the two floors is present.
    #[error("retained Plugin trust floor state is partial")]
    PartialFloorState,
    /// The candidate coordinate is below the retained floor.
    #[error("{0} candidate is below the retained floor")]
    Rollback(PluginFloorKindV1),
    /// The candidate forks the retained digest at the same or a retained coordinate.
    #[error("{0} candidate forks the retained floor")]
    Fork(PluginFloorKindV1),
    /// The authenticated history lacks, duplicates, or misorders the retained pair
    /// or does not terminate at the candidate.
    #[error("{0} history does not continue the retained floor")]
    Discontinuity(PluginFloorKindV1),
}

/// What committing a successful verification does to one floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginFloorTransitionV1 {
    /// No floor existed: initialize it from the candidate.
    Initialize,
    /// The candidate equals the retained floor exactly.
    Unchanged,
    /// The candidate descends from the retained floor: advance to it.
    Advance,
}

/// Decide one floor transition against the authenticated complete history.
///
/// An absent floor initializes. A lower candidate coordinate is a rollback. An
/// equal coordinate requires the exact retained digest. A greater coordinate
/// requires `history` (strictly ascending by coordinate) to terminate at
/// `candidate` and contain the retained coordinate exactly once with the exact
/// retained digest.
///
/// # Errors
/// Returns the closed rollback, fork, or discontinuity error for `kind`.
pub fn plugin_floor_transition_v1(
    kind: PluginFloorKindV1,
    retained: Option<(u64, [u8; 32])>,
    candidate: (u64, [u8; 32]),
    history: &[(u64, [u8; 32])],
) -> Result<PluginFloorTransitionV1, PluginFloorErrorV1> {
    let Some(retained) = retained else {
        return Ok(PluginFloorTransitionV1::Initialize);
    };
    match candidate.0.cmp(&retained.0) {
        Ordering::Less => Err(PluginFloorErrorV1::Rollback(kind)),
        Ordering::Equal if candidate.1 == retained.1 => Ok(PluginFloorTransitionV1::Unchanged),
        Ordering::Equal => Err(PluginFloorErrorV1::Fork(kind)),
        Ordering::Greater => advance_proof(kind, retained, candidate, history),
    }
}

fn advance_proof(
    kind: PluginFloorKindV1,
    retained: (u64, [u8; 32]),
    candidate: (u64, [u8; 32]),
    history: &[(u64, [u8; 32])],
) -> Result<PluginFloorTransitionV1, PluginFloorErrorV1> {
    let well_formed =
        history.last() == Some(&candidate) && history.windows(2).all(|pair| pair[0].0 < pair[1].0);
    if !well_formed {
        return Err(PluginFloorErrorV1::Discontinuity(kind));
    }
    match history.iter().find(|pair| pair.0 == retained.0) {
        None => Err(PluginFloorErrorV1::Discontinuity(kind)),
        Some(pair) if pair.1 == retained.1 => Ok(PluginFloorTransitionV1::Advance),
        Some(_) => Err(PluginFloorErrorV1::Fork(kind)),
    }
}

/// The only two valid retained trust-record floor shapes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginFloorStateV1 {
    /// Immediately after provisioning: both floors absent.
    Absent,
    /// After a successful admission: both floors present.
    Present {
        /// Retained PTR1 `(root_version, complete_record_digest)`.
        root: (u64, [u8; 32]),
        /// Retained PRV1 `(policy_epoch, complete_record_digest)`.
        revocation: (u64, [u8; 32]),
    },
}

impl PluginFloorStateV1 {
    /// Classify the two retained floors read from durable state.
    ///
    /// # Errors
    /// Returns `PartialFloorState` when exactly one floor is present.
    pub const fn from_retained(
        root: Option<(u64, [u8; 32])>,
        revocation: Option<(u64, [u8; 32])>,
    ) -> Result<Self, PluginFloorErrorV1> {
        match (root, revocation) {
            (None, None) => Ok(Self::Absent),
            (Some(root), Some(revocation)) => Ok(Self::Present { root, revocation }),
            _ => Err(PluginFloorErrorV1::PartialFloorState),
        }
    }
}

/// The two independent floor decisions for one successful verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PluginFloorPlanV1 {
    /// The PTR1 floor decision.
    pub root: PluginFloorTransitionV1,
    /// The PRV1 floor decision.
    pub revocation: PluginFloorTransitionV1,
}

/// Plan both floor transitions from the evidence's authenticated histories.
///
/// Both floors are always evaluated; success of one never compensates for the
/// other's failure, and the PTR1 failure is reported first.
///
/// # Errors
/// Returns the first failing floor's closed error.
pub fn plan_plugin_floor_transition_v1(
    state: &PluginFloorStateV1,
    evidence: &VerifiedPluginTrustEvidenceV1,
) -> Result<PluginFloorPlanV1, PluginFloorErrorV1> {
    let (retained_root, retained_revocation) = match *state {
        PluginFloorStateV1::Absent => (None, None),
        PluginFloorStateV1::Present { root, revocation } => (Some(root), Some(revocation)),
    };
    let root = plugin_floor_transition_v1(
        PluginFloorKindV1::Root,
        retained_root,
        evidence.terminal_root(),
        &evidence.verified_root_history().collect::<Vec<_>>(),
    );
    let revocation = plugin_floor_transition_v1(
        PluginFloorKindV1::Revocation,
        retained_revocation,
        evidence.terminal_revocation(),
        &evidence.verified_revocation_history().collect::<Vec<_>>(),
    );
    Ok(PluginFloorPlanV1 {
        root: root?,
        revocation: revocation?,
    })
}
