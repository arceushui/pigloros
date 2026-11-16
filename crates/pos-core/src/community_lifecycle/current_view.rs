//! ADR-129 §3 CAV1 current-view preimage (revision 6, R6.7).
//!
//! CAV1 is the exact current view a concrete verifier read inside its guard:
//! the frontier and selected head it used, and the scope, authority, Plugin
//! trust, key and clock rows of that read. CAU1's `current_premise_digest`
//! is H(CAV1). Valid bytes do not prove that any row was read from a real
//! store, or that the view is still current: CAV1 is transient by default,
//! and every use builds a fresh view. A decoded CAV1 never replaces those
//! reads.

use super::materialization::CommunityMaterializationReferenceV1;
use super::selected_head::{encode_frontier, read_frontier};
use super::{
    bounded_text, canonical_end, digest, encode_coordinates, fixed_bytes, head_len,
    is_valid_community_id_v1, read_coordinates, read_hash, read_head, read_vec, record_cursor,
    record_prefix, validate_coordinates, validate_horizon, CommunityLifecycleErrorV1 as Error,
    CommunityPassFrontierV1, Result,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, KeyRoleV1, TimelineId};
use zeroize::Zeroizing;

/// Maximum CAV1 scope rows.
pub const MAX_COMMUNITY_VIEW_SCOPE_ROWS_V1: usize = 2048;
/// Maximum CAV1 authority rows.
pub const MAX_COMMUNITY_VIEW_AUTHORITY_ROWS_V1: usize = 2048;
/// Maximum CAV1 Plugin trust rows.
pub const MAX_COMMUNITY_VIEW_TRUST_ROWS_V1: usize = 64;
/// Maximum CAV1 key rows.
pub const MAX_COMMUNITY_VIEW_KEY_ROWS_V1: usize = 4096;
const MAX_VIEW: usize = 2_097_152;
/// Longest scope/Plugin/owner text (R6.7(3)).
const MAX_TEXT: usize = 128;
// Upper bound of a CAV1, a plain literal so no arithmetic mutant survives
// in it: fixed fields, frontier and head under 1024 bytes; 2048 scope rows
// of at most 122 bytes (array head 1, three hashes 102, two nine-byte heads
// and a state); 2048 authority rows of at most 172 (array head 1, T 17, two
// nine-byte heads and four hashes 136); 64 trust rows of at most 390 (array
// head 1, two 130-byte texts, three hashes 102 and three nine-byte heads);
// and 4096 key rows of at most 211 (array head 1, a 130-byte text, role 2,
// a nine-byte epoch, two hashes 68 and a state).
const MAX_ENCODED_BYTES: usize = 1_492_352;
const _: () = assert!(MAX_COMMUNITY_VIEW_SCOPE_ROWS_V1 == 2048);
const _: () = assert!(MAX_COMMUNITY_VIEW_AUTHORITY_ROWS_V1 == 2048);
const _: () = assert!(MAX_COMMUNITY_VIEW_TRUST_ROWS_V1 == 64);
const _: () = assert!(MAX_COMMUNITY_VIEW_KEY_ROWS_V1 == 4096);
const _: () = assert!(MAX_TEXT == 128);
const _: () = assert!(MAX_ENCODED_BYTES < MAX_VIEW);

/// Scope row state; only `Open` admits use.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityScopeStateV1 {
    /// Code 0.
    Open,
    /// Code 1.
    Frozen,
    /// Code 2.
    Closed,
    /// Code 3.
    Unavailable,
}

/// Key row state; only `Available` allows private use.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityKeyStateV1 {
    /// Code 0.
    Available,
    /// Code 1.
    DestructionPending,
    /// Code 2.
    Tombstoned,
    /// Code 3.
    Unavailable,
}

const SCOPE_STATES: [CommunityScopeStateV1; 4] = [
    CommunityScopeStateV1::Open,
    CommunityScopeStateV1::Frozen,
    CommunityScopeStateV1::Closed,
    CommunityScopeStateV1::Unavailable,
];
const KEY_STATES: [CommunityKeyStateV1; 4] = [
    CommunityKeyStateV1::Available,
    CommunityKeyStateV1::DestructionPending,
    CommunityKeyStateV1::Tombstoned,
    CommunityKeyStateV1::Unavailable,
];

/// `[scope_ref, owner_ref, topology_generation, state, lease_digest,
/// not_after]`, strictly ascending by scope then owner.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityScopeViewRowV1 {
    /// Scope reference.
    pub scope_reference: Hash,
    /// Owner reference.
    pub owner_reference: Hash,
    /// Topology generation read.
    pub topology_generation: u64,
    /// Scope state read.
    pub state: CommunityScopeStateV1,
    /// Retention lease digest.
    pub lease_digest: Hash,
    /// Positive scope horizon.
    pub not_after_micros: u64,
}

/// `[authority_T, head_seq, revocation_epoch, registry_digest,
/// capability_policy_revision, consent_policy_revision,
/// grant_and_revocation_binding_digest]`, strictly ascending by T, head and
/// epoch.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityAuthorityViewRowV1 {
    /// Authority Timeline.
    pub authority_timeline: TimelineId,
    /// Persisted authority head read.
    pub head_seq: u64,
    /// Revocation epoch read.
    pub revocation_epoch: u64,
    /// Registry digest.
    pub registry_digest: Hash,
    /// Capability policy revision.
    pub capability_policy_revision: Hash,
    /// Consent policy revision.
    pub consent_policy_revision: Hash,
    /// `H("AuthorityBindings", [grant bindings, revocation digests])`.
    pub binding_digest: Hash,
}

/// `[scope_text, plugin_id_text, TPS1_digest, PTR_floor, PRV_floor,
/// highest_trusted_utc_second, active_PMF1_digest, active_release_digest]`,
/// strictly ascending by scope then Plugin text bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityTrustViewRowV1 {
    /// ADR-103 trust scope, 1..128 bytes of the Plugin ID grammar.
    pub scope: String,
    /// Plugin ID, 1..128 bytes of the Plugin ID grammar.
    pub plugin_id: String,
    /// Trust policy snapshot digest.
    pub policy_digest: Hash,
    /// Trust-policy revision floor.
    pub policy_floor: u64,
    /// Release revision floor.
    pub release_floor: u64,
    /// Highest trusted UTC second.
    pub highest_trusted_utc_second: u64,
    /// Active PMF1 digest.
    pub active_manifest_digest: Hash,
    /// Active release digest.
    pub active_release_digest: Hash,
}

/// `[owner_text, role, epoch, material_fingerprint, state,
/// key_intent_digest]`, strictly ascending by owner text bytes, role and
/// epoch.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityKeyViewRowV1 {
    /// ADR-128 per-operation key owner text.
    pub owner: String,
    /// Key role.
    pub role: KeyRoleV1,
    /// Positive key epoch.
    pub epoch: u64,
    /// Material fingerprint.
    pub material_fingerprint: Hash,
    /// Key state read.
    pub state: CommunityKeyStateV1,
    /// CKP1 key-intent digest.
    pub key_intent_digest: Hash,
}

/// `[overrun_count, latched_bool]`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityClockLatchV1 {
    /// Trusted-clock overrun count.
    pub overrun_count: u64,
    /// Whether the clock is latched.
    pub latched: bool,
}

/// Untrusted CAV1 fields.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityCurrentViewInputV1 {
    /// Nonzero protected store incarnation.
    pub store_incarnation: [u8; 16],
    /// CAU1's Timeline.
    pub timeline: TimelineId,
    /// CAU1's generation.
    pub generation: [u8; 16],
    /// Inventory generation read.
    pub inventory_generation: u64,
    /// The selected head's CSH1 frontier; the parent's for Fork.
    pub frontier: CommunityPassFrontierV1,
    /// CMI1 reference of the selected head read; `None` exactly when the
    /// operation reads no selected head.
    pub selected_head: Option<CommunityMaterializationReferenceV1>,
    /// At most 2048 scope rows.
    pub scope_rows: Vec<CommunityScopeViewRowV1>,
    /// At most 2048 authority rows.
    pub authority_rows: Vec<CommunityAuthorityViewRowV1>,
    /// 1..=64 Plugin trust rows: an empty or partial row set is never a
    /// valid CAV1 (R6.5(4)). Completeness against the roster is the owner's
    /// check.
    pub trust_rows: Vec<CommunityTrustViewRowV1>,
    /// At most 4096 key rows.
    pub key_rows: Vec<CommunityKeyViewRowV1>,
    /// Trusted-clock latch read.
    pub clock_latch: CommunityClockLatchV1,
}

/// Exact thirteen-field CAV1.
#[derive(Clone, Eq, PartialEq)]
pub struct CommunityCurrentViewV1(CommunityCurrentViewInputV1);

impl CommunityCurrentViewV1 {
    /// Validate local identities, row grammar, order and bounds.
    ///
    /// # Errors
    /// Returns `BoundsExceeded` for too many rows of any kind, no trust row
    /// (R6.5(4)), a scope, Plugin or owner text of 0 or more than 128 bytes,
    /// or an invalid scope horizon; `InvalidBinding` for a zero identity,
    /// digest or epoch, a text outside its grammar, unordered or repeated
    /// rows, or a missing selected head with a committed frontier.
    pub fn new(input: CommunityCurrentViewInputV1) -> Result<Self> {
        if input.scope_rows.len() > MAX_COMMUNITY_VIEW_SCOPE_ROWS_V1
            || input.authority_rows.len() > MAX_COMMUNITY_VIEW_AUTHORITY_ROWS_V1
            || !(1..=MAX_COMMUNITY_VIEW_TRUST_ROWS_V1).contains(&input.trust_rows.len())
            || input.key_rows.len() > MAX_COMMUNITY_VIEW_KEY_ROWS_V1
            || input
                .trust_rows
                .iter()
                .flat_map(|row| [&row.scope, &row.plugin_id])
                .chain(input.key_rows.iter().map(|row| &row.owner))
                .any(|text| !(1..=MAX_TEXT).contains(&text.len()))
        {
            return Err(Error::BoundsExceeded);
        }
        if input.store_incarnation == [0; 16]
            || (input.selected_head.is_none() && input.frontier != CommunityPassFrontierV1::Initial)
            || input
                .selected_head
                .is_some_and(|head| head.validate().is_err())
            || !valid_scope_rows(&input.scope_rows)
            || !valid_authority_rows(&input.authority_rows)
            || !valid_trust_rows(&input.trust_rows)
            || !valid_key_rows(&input.key_rows)
        {
            return Err(Error::InvalidBinding);
        }
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| {
                input
                    .scope_rows
                    .iter()
                    .try_for_each(|row| validate_horizon(row.not_after_micros))
            })
            .map(|()| Self(input))
    }

    /// Borrow the exact fields; none of them is a current read.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityCurrentViewInputV1 {
        &self.0
    }

    /// Encode the complete preferred CAV1 into zeroizing storage sized
    /// exactly, so no reallocation leaves an unwiped copy.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(encoded_len(input)));
        record_prefix(&mut out, 13, *b"CAV1");
        encode_bytes(&mut out, &input.store_incarnation, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        encode_head(&mut out, 0, input.inventory_generation);
        encode_frontier(&mut out, input.frontier);
        match input.selected_head {
            None => out.push(0xf6),
            Some(head) => head.encode(&mut out),
        }
        encode_head(&mut out, 4, input.scope_rows.len() as u64);
        for row in &input.scope_rows {
            out.push(0x86);
            encode_hash(&mut out, row.scope_reference);
            encode_hash(&mut out, row.owner_reference);
            encode_head(&mut out, 0, row.topology_generation);
            encode_head(&mut out, 0, scope_code(row.state));
            encode_hash(&mut out, row.lease_digest);
            encode_head(&mut out, 0, row.not_after_micros);
        }
        encode_head(&mut out, 4, input.authority_rows.len() as u64);
        for row in &input.authority_rows {
            out.push(0x87);
            encode_bytes(&mut out, &row.authority_timeline.inner().to_bytes(), 2);
            encode_head(&mut out, 0, row.head_seq);
            encode_head(&mut out, 0, row.revocation_epoch);
            encode_hash(&mut out, row.registry_digest);
            encode_hash(&mut out, row.capability_policy_revision);
            encode_hash(&mut out, row.consent_policy_revision);
            encode_hash(&mut out, row.binding_digest);
        }
        encode_head(&mut out, 4, input.trust_rows.len() as u64);
        for row in &input.trust_rows {
            out.push(0x88);
            encode_bytes(&mut out, row.scope.as_bytes(), 3);
            encode_bytes(&mut out, row.plugin_id.as_bytes(), 3);
            encode_hash(&mut out, row.policy_digest);
            encode_head(&mut out, 0, row.policy_floor);
            encode_head(&mut out, 0, row.release_floor);
            encode_head(&mut out, 0, row.highest_trusted_utc_second);
            encode_hash(&mut out, row.active_manifest_digest);
            encode_hash(&mut out, row.active_release_digest);
        }
        encode_head(&mut out, 4, input.key_rows.len() as u64);
        for row in &input.key_rows {
            out.push(0x86);
            encode_bytes(&mut out, row.owner.as_bytes(), 3);
            encode_head(&mut out, 0, u64::from(row.role.code()));
            encode_head(&mut out, 0, row.epoch);
            encode_hash(&mut out, row.material_fingerprint);
            encode_head(&mut out, 0, key_code(row.state));
            encode_hash(&mut out, row.key_intent_digest);
        }
        out.push(0x82);
        encode_head(&mut out, 0, input.clock_latch.overrun_count);
        out.push(if input.clock_latch.latched {
            0xf5
        } else {
            0xf4
        });
        out
    }

    /// H(CAV1), CAU1's `current_premise_digest`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CAV1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CAV1.
    ///
    /// # Errors
    /// Rejects malformed, nonpreferred, oversized, versioned or trailing
    /// records, unknown state or role codes, and every invalid local binding.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, MAX_VIEW, 13, *b"CAV1").and_then(|mut cursor| {
            read_body(&mut cursor)
                .and_then(|input| canonical_end(&cursor).and_then(|()| Self::new(input)))
        })
    }
}

const fn scope_code(state: CommunityScopeStateV1) -> u64 {
    match state {
        CommunityScopeStateV1::Open => 0,
        CommunityScopeStateV1::Frozen => 1,
        CommunityScopeStateV1::Closed => 2,
        CommunityScopeStateV1::Unavailable => 3,
    }
}

const fn key_code(state: CommunityKeyStateV1) -> u64 {
    match state {
        CommunityKeyStateV1::Available => 0,
        CommunityKeyStateV1::DestructionPending => 1,
        CommunityKeyStateV1::Tombstoned => 2,
        CommunityKeyStateV1::Unavailable => 3,
    }
}

fn valid_scope_rows(rows: &[CommunityScopeViewRowV1]) -> bool {
    rows.iter().all(|row| {
        ![row.scope_reference, row.owner_reference, row.lease_digest].contains(&Hash::zero())
    }) && rows.is_sorted_by(|a, b| {
        (a.scope_reference, a.owner_reference) < (b.scope_reference, b.owner_reference)
    })
}

fn valid_authority_rows(rows: &[CommunityAuthorityViewRowV1]) -> bool {
    rows.iter().all(|row| {
        row.authority_timeline.inner().to_bytes() != [0; 16]
            && ![
                row.registry_digest,
                row.capability_policy_revision,
                row.consent_policy_revision,
                row.binding_digest,
            ]
            .contains(&Hash::zero())
    }) && rows.is_sorted_by(|a, b| {
        (a.authority_timeline, a.head_seq, a.revocation_epoch)
            < (b.authority_timeline, b.head_seq, b.revocation_epoch)
    })
}

fn valid_trust_rows(rows: &[CommunityTrustViewRowV1]) -> bool {
    rows.iter().all(|row| {
        is_valid_community_id_v1(&row.scope)
            && is_valid_community_id_v1(&row.plugin_id)
            && ![
                row.policy_digest,
                row.active_manifest_digest,
                row.active_release_digest,
            ]
            .contains(&Hash::zero())
    }) && rows.is_sorted_by(|a, b| {
        (a.scope.as_bytes(), a.plugin_id.as_bytes()) < (b.scope.as_bytes(), b.plugin_id.as_bytes())
    })
}

fn valid_key_rows(rows: &[CommunityKeyViewRowV1]) -> bool {
    rows.iter().all(|row| {
        is_key_owner_text(&row.owner)
            && row.epoch != 0
            && ![row.material_fingerprint, row.key_intent_digest].contains(&Hash::zero())
    }) && rows.is_sorted_by(|a, b| {
        (a.owner.as_bytes(), a.role.code(), a.epoch) < (b.owner.as_bytes(), b.role.code(), b.epoch)
    })
}

/// The ADR-128 owner grammar
/// `community:<T32>:<G32>:<purpose>:<kind>:<operation>`: nonzero
/// lower-case T and G, purpose `0`..`3`, and a nonzero 16-digit pass ordinal
/// (`p`) or 32-digit initialization (`i`) or control (`c`) identity.
fn is_key_owner_text(owner: &str) -> bool {
    let mut parts = owner.split(':');
    parts.next() == Some("community")
        && parts.next().is_some_and(|t| is_nonzero_hex(t, 32))
        && parts.next().is_some_and(|g| is_nonzero_hex(g, 32))
        && parts
            .next()
            .is_some_and(|purpose| matches!(purpose, "0" | "1" | "2" | "3"))
        && match (parts.next(), parts.next()) {
            (Some("p"), Some(operation)) => is_nonzero_hex(operation, 16),
            (Some("i" | "c"), Some(operation)) => is_nonzero_hex(operation, 32),
            _ => false,
        }
        && parts.next().is_none()
}

fn is_nonzero_hex(text: &str, digits: usize) -> bool {
    text.len() == digits
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && text.bytes().any(|byte| byte != b'0')
}

/// Exact CAV1 length: framing and version (7), incarnation (17), T and G
/// (34), the inventory generation, the frontier, the head ref, the four row
/// arrays and the clock latch.
fn encoded_len(input: &CommunityCurrentViewInputV1) -> usize {
    let frontier = match input.frontier {
        CommunityPassFrontierV1::Initial => 2,
        CommunityPassFrontierV1::Committed(key) => {
            let key_len = Zeroizing::new(key.to_canonical_cbor()).len();
            2 + head_len(key_len as u64) + key_len
        }
    };
    let head = input
        .selected_head
        .map_or(1, |head| 1 + 5 * 34 + head_len(head.artifact_class.code()));
    let scopes: usize = input
        .scope_rows
        .iter()
        .map(|row| {
            1 + 3 * 34
                + head_len(row.topology_generation)
                + head_len(scope_code(row.state))
                + head_len(row.not_after_micros)
        })
        .sum();
    let authorities: usize = input
        .authority_rows
        .iter()
        .map(|row| 1 + 17 + head_len(row.head_seq) + head_len(row.revocation_epoch) + 4 * 34)
        .sum();
    let trust: usize = input
        .trust_rows
        .iter()
        .map(|row| {
            1 + text_len(&row.scope)
                + text_len(&row.plugin_id)
                + 3 * 34
                + head_len(row.policy_floor)
                + head_len(row.release_floor)
                + head_len(row.highest_trusted_utc_second)
        })
        .sum();
    let keys: usize = input
        .key_rows
        .iter()
        .map(|row| {
            1 + text_len(&row.owner)
                + head_len(u64::from(row.role.code()))
                + head_len(row.epoch)
                + 2 * 34
                + head_len(key_code(row.state))
        })
        .sum();
    7 + 17
        + 34
        + head_len(input.inventory_generation)
        + frontier
        + head
        + head_len(input.scope_rows.len() as u64)
        + scopes
        + head_len(input.authority_rows.len() as u64)
        + authorities
        + head_len(input.trust_rows.len() as u64)
        + trust
        + head_len(input.key_rows.len() as u64)
        + keys
        + 1
        + head_len(input.clock_latch.overrun_count)
        + 1
}

const fn text_len(text: &str) -> usize {
    head_len(text.len() as u64) + text.len()
}

fn read_body(cursor: &mut CborCursor<'_>) -> Result<CommunityCurrentViewInputV1> {
    fixed_bytes(cursor).and_then(|store_incarnation| {
        read_coordinates(cursor).and_then(|(timeline, generation)| {
            read_head(cursor, 0).and_then(|inventory_generation| {
                read_frontier(cursor).and_then(|frontier| {
                    read_head_ref(cursor).and_then(|selected_head| {
                        read_rows(cursor).and_then(|rows| {
                            read_latch(cursor).map(|clock_latch| CommunityCurrentViewInputV1 {
                                store_incarnation,
                                timeline,
                                generation,
                                inventory_generation,
                                frontier,
                                selected_head,
                                scope_rows: rows.0,
                                authority_rows: rows.1,
                                trust_rows: rows.2,
                                key_rows: rows.3,
                                clock_latch,
                            })
                        })
                    })
                })
            })
        })
    })
}

type ViewRows = (
    Vec<CommunityScopeViewRowV1>,
    Vec<CommunityAuthorityViewRowV1>,
    Vec<CommunityTrustViewRowV1>,
    Vec<CommunityKeyViewRowV1>,
);

fn read_rows(cursor: &mut CborCursor<'_>) -> Result<ViewRows> {
    read_vec(cursor, MAX_COMMUNITY_VIEW_SCOPE_ROWS_V1, read_scope).and_then(|scopes| {
        read_vec(cursor, MAX_COMMUNITY_VIEW_AUTHORITY_ROWS_V1, read_authority).and_then(
            |authorities| {
                read_vec(cursor, MAX_COMMUNITY_VIEW_TRUST_ROWS_V1, read_trust).and_then(|trust| {
                    read_vec(cursor, MAX_COMMUNITY_VIEW_KEY_ROWS_V1, read_key)
                        .map(|keys| (scopes, authorities, trust, keys))
                })
            },
        )
    })
}

fn read_head_ref(
    cursor: &mut CborCursor<'_>,
) -> Result<Option<CommunityMaterializationReferenceV1>> {
    if cursor.consume_if(0xf6) {
        Ok(None)
    } else {
        CommunityMaterializationReferenceV1::read(cursor).map(Some)
    }
}

/// Read a closed code: an index into `codes`, or `InvalidEncoding`.
fn read_code<T: Copy>(cursor: &mut CborCursor<'_>, codes: &[T]) -> Result<T> {
    read_head(cursor, 0).and_then(|code| {
        usize::try_from(code)
            .ok()
            .and_then(|index| codes.get(index).copied())
            .ok_or(Error::InvalidEncoding)
    })
}

fn read_scope(cursor: &mut CborCursor<'_>) -> Result<CommunityScopeViewRowV1> {
    cursor.fixed(&[0x86]).map_err(Error::from).and_then(|()| {
        read_hash(cursor).and_then(|scope_reference| {
            read_hash(cursor).and_then(|owner_reference| {
                read_head(cursor, 0).and_then(|topology_generation| {
                    read_code(cursor, &SCOPE_STATES).and_then(|state| {
                        read_hash(cursor).and_then(|lease_digest| {
                            read_head(cursor, 0).map(|not_after_micros| CommunityScopeViewRowV1 {
                                scope_reference,
                                owner_reference,
                                topology_generation,
                                state,
                                lease_digest,
                                not_after_micros,
                            })
                        })
                    })
                })
            })
        })
    })
}

fn read_authority(cursor: &mut CborCursor<'_>) -> Result<CommunityAuthorityViewRowV1> {
    cursor.fixed(&[0x87]).map_err(Error::from).and_then(|()| {
        fixed_bytes(cursor).and_then(|timeline: [u8; 16]| {
            read_head(cursor, 0).and_then(|head_seq| {
                read_head(cursor, 0).and_then(|revocation_epoch| {
                    read_hash(cursor).and_then(|registry_digest| {
                        read_hash(cursor).and_then(|capability_policy_revision| {
                            read_hash(cursor).and_then(|consent_policy_revision| {
                                read_hash(cursor).map(|binding_digest| {
                                    CommunityAuthorityViewRowV1 {
                                        authority_timeline: TimelineId::from_ulid(
                                            ulid::Ulid::from_bytes(timeline),
                                        ),
                                        head_seq,
                                        revocation_epoch,
                                        registry_digest,
                                        capability_policy_revision,
                                        consent_policy_revision,
                                        binding_digest,
                                    }
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}

fn read_trust(cursor: &mut CborCursor<'_>) -> Result<CommunityTrustViewRowV1> {
    cursor.fixed(&[0x88]).map_err(Error::from).and_then(|()| {
        bounded_text(cursor, MAX_TEXT).and_then(|scope| {
            bounded_text(cursor, MAX_TEXT).and_then(|plugin_id| {
                read_hash(cursor).and_then(|policy_digest| {
                    read_head(cursor, 0).and_then(|policy_floor| {
                        read_head(cursor, 0).and_then(|release_floor| {
                            read_head(cursor, 0).and_then(|highest_trusted_utc_second| {
                                read_hash(cursor).and_then(|active_manifest_digest| {
                                    read_hash(cursor).map(|active_release_digest| {
                                        CommunityTrustViewRowV1 {
                                            scope: scope.to_owned(),
                                            plugin_id: plugin_id.to_owned(),
                                            policy_digest,
                                            policy_floor,
                                            release_floor,
                                            highest_trusted_utc_second,
                                            active_manifest_digest,
                                            active_release_digest,
                                        }
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}

fn read_key(cursor: &mut CborCursor<'_>) -> Result<CommunityKeyViewRowV1> {
    cursor.fixed(&[0x86]).map_err(Error::from).and_then(|()| {
        bounded_text(cursor, MAX_TEXT).and_then(|owner| {
            read_head(cursor, 0)
                .and_then(|code| {
                    u8::try_from(code)
                        .ok()
                        .and_then(|code| KeyRoleV1::from_code(code).ok())
                        .ok_or(Error::InvalidEncoding)
                })
                .and_then(|role| {
                    read_head(cursor, 0).and_then(|epoch| {
                        read_hash(cursor).and_then(|material_fingerprint| {
                            read_code(cursor, &KEY_STATES).and_then(|state| {
                                read_hash(cursor).map(|key_intent_digest| CommunityKeyViewRowV1 {
                                    owner: owner.to_owned(),
                                    role,
                                    epoch,
                                    material_fingerprint,
                                    state,
                                    key_intent_digest,
                                })
                            })
                        })
                    })
                })
        })
    })
}

fn read_latch(cursor: &mut CborCursor<'_>) -> Result<CommunityClockLatchV1> {
    cursor.fixed(&[0x82]).map_err(Error::from).and_then(|()| {
        read_head(cursor, 0).and_then(|overrun_count| {
            if cursor.consume_if(0xf5) {
                Ok(true)
            } else if cursor.consume_if(0xf4) {
                Ok(false)
            } else {
                Err(Error::InvalidEncoding)
            }
            .map(|latched| CommunityClockLatchV1 {
                overrun_count,
                latched,
            })
        })
    })
}
