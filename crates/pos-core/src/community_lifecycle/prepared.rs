//! Complete CIN1 input preimage, prepared before Reserve without a guest permit.

use super::quarantine_control::{encode_artifact_ref, read_artifact_ref};
use super::{
    bounded_bytes, bounded_text, canonical_end, digest, fixed_bytes, is_valid_community_id_v1,
    read_hash, read_head, record_cursor, record_prefix, ArtifactRefV1,
    CommunityLifecycleErrorV1 as Error, Result, MAX_COMMUNITY_MEMBERS_V1,
    MAX_COMMUNITY_STATE_BYTES_V1,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};
use zeroize::Zeroizing;

/// Maximum complete CIN1 encoding, including both one-MiB private payloads.
pub const MAX_COMMUNITY_PREPARED_INVOCATION_BYTES_V1: usize = 2_101_248;

/// `contract-v1.timeline-position`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimelinePositionV1 {
    /// Timeline ID.
    pub timeline_id: [u8; 16],
    /// Timeline sequence number.
    pub seq: u64,
    /// Tick.
    pub tick: u64,
    /// Scheduler position inside the Tick.
    pub scheduler_position: u32,
}

/// Every actual step invocation and operational option, without owned payload copies.
///
/// These are untrusted data. Artifact resolution, admitted State, fresh invocation
/// allocation, trust, provenance and current-use authority remain owner checks.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityPreparedInvocationInputV1<'a> {
    /// Exact immutable CMB1 identity.
    pub member_binding_digest: Hash,
    /// Fresh nonzero invocation identity, independent of the later pass key.
    pub invocation_id: [u8; 16],
    /// Original WIT coordinate, not a native producer or factual dependency coordinate.
    pub timeline_position: TimelinePositionV1,
    /// Original first guest output ordinal.
    pub output_base_ordinal: u32,
    /// Actual delivered principal artifact.
    pub principal_ref: ArtifactRefV1,
    /// Actual delivered authorization decision artifact.
    pub authorization_ref: ArtifactRefV1,
    /// Actual delivered observation artifact.
    pub observation_snapshot_ref: ArtifactRefV1,
    /// Complete original observation bytes, at most one MiB.
    pub observation_bytes: &'a [u8],
    /// Original prior-State schema digest.
    pub prior_state_schema_digest: [u8; 32],
    /// Complete original prior-State bytes, including empty State.
    pub prior_state_bytes: &'a [u8],
    /// Existing execution-profile identity, not a CNT1 or live-mode substitute.
    pub execution_profile_digest: [u8; 32],
    /// Original trust-policy snapshot identity.
    pub trust_policy_snapshot_digest: [u8; 32],
    /// Original ADR-061 ID, not a diagnostic or free-text label.
    pub deterministic_budget_id: &'a str,
    /// Original deterministic random domain.
    pub deterministic_random_domain: [u8; 32],
    /// Actual pre-Reserve source-closure identity.
    pub provenance_root: [u8; 32],
    /// Original deterministic host Simulation Time.
    pub simulation_time: u64,
    /// Original operational watchdog setting; zero retains its existing meaning.
    pub watchdog_epochs: u32,
}

/// Borrowed CIN1 for the sole supported step export (code0).
///
/// No migration export is admitted. The view cannot allocate an invocation ID,
/// prove source authority, reserve a pass or launch a guest.
pub struct CommunityPreparedInvocationV1<'a>(CommunityPreparedInvocationInputV1<'a>);

impl<'a> CommunityPreparedInvocationV1<'a> {
    /// Validate local bounds and required member/invocation identities.
    ///
    /// # Errors
    /// Rejects zero required identities/digests, payloads over one MiB and an
    /// invalid deterministic budget ID. Existing WIT scalar/ref values are
    /// preserved; actual artifact/schema/digest equality is an owner obligation.
    pub fn new(input: CommunityPreparedInvocationInputV1<'a>) -> Result<Self> {
        if input.member_binding_digest == Hash::zero()
            || input.invocation_id == [0; 16]
            || input.timeline_position.timeline_id == [0; 16]
            || [
                input.principal_ref.digest,
                input.authorization_ref.digest,
                input.observation_snapshot_ref.digest,
                input.prior_state_schema_digest,
                input.execution_profile_digest,
                input.trust_policy_snapshot_digest,
                input.deterministic_random_domain,
                input.provenance_root,
            ]
            .contains(&[0; 32])
        {
            return Err(Error::InvalidBinding);
        }
        if input.observation_bytes.len() > MAX_COMMUNITY_STATE_BYTES_V1
            || input.prior_state_bytes.len() > MAX_COMMUNITY_STATE_BYTES_V1
        {
            return Err(Error::BoundsExceeded);
        }
        if !is_valid_community_id_v1(input.deterministic_budget_id) {
            return Err(Error::InvalidBinding);
        }
        Ok(Self(input))
    }

    /// Borrow exact data. Fresh/current authority is not established by this view.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityPreparedInvocationInputV1<'a> {
        &self.0
    }

    // Fixed fields, maximal integer widths, a 128-byte budget ID and all
    // framing fit in 1024 bytes. Keep the actual reservation request available
    // to check against encoded lengths without assuming allocator behavior.
    const fn staging_capacity(&self) -> usize {
        1024 + self.0.observation_bytes.len() + self.0.prior_state_bytes.len()
    }

    /// Copy private bytes into one fully pre-sized zeroizing CIN1 output buffer.
    /// The installed owner must still inventory the original and encoded copies.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(self.staging_capacity()));
        record_prefix(&mut out, 20, *b"CIN1");
        encode_hash(&mut out, input.member_binding_digest);
        encode_head(&mut out, 0, 0);
        encode_bytes(&mut out, &input.invocation_id, 2);
        let position = input.timeline_position;
        out.push(0x84);
        encode_bytes(&mut out, &position.timeline_id, 2);
        encode_head(&mut out, 0, position.seq);
        encode_head(&mut out, 0, position.tick);
        encode_head(&mut out, 0, u64::from(position.scheduler_position));
        encode_head(&mut out, 0, u64::from(input.output_base_ordinal));
        for reference in [
            input.principal_ref,
            input.authorization_ref,
            input.observation_snapshot_ref,
        ] {
            encode_artifact_ref(&mut out, reference);
        }
        encode_bytes(&mut out, input.observation_bytes, 2);
        encode_bytes(&mut out, &input.prior_state_schema_digest, 2);
        encode_bytes(&mut out, input.prior_state_bytes, 2);
        encode_bytes(&mut out, &input.execution_profile_digest, 2);
        encode_bytes(&mut out, &input.trust_policy_snapshot_digest, 2);
        encode_bytes(&mut out, input.deterministic_budget_id.as_bytes(), 3);
        encode_bytes(&mut out, &input.deterministic_random_domain, 2);
        encode_bytes(&mut out, &input.provenance_root, 2);
        encode_head(&mut out, 0, input.simulation_time);
        encode_head(&mut out, 0, u64::from(input.watchdog_epochs));
        out
    }

    /// Hash exact CIN1 with its accepted domain using a zeroizing hash state.
    /// This protected logical identity does not authorize retaining its preimage.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CIN1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode the complete step input, borrowing observation, State and budget ID.
    ///
    /// # Errors
    /// Rejects unsupported exports/versions, nonpreferred or malformed framing,
    /// overflowing scalars, overlarge fields, invalid bindings and trailing data.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(
            bytes,
            MAX_COMMUNITY_PREPARED_INVOCATION_BYTES_V1,
            20,
            *b"CIN1",
        )
        .and_then(|mut cursor| {
            read_identity(&mut cursor).and_then(|identity| {
                read_payload(&mut cursor).and_then(|payload| {
                    read_environment(&mut cursor).and_then(|environment| {
                        canonical_end(&cursor).and_then(|()| {
                            Self::new(CommunityPreparedInvocationInputV1 {
                                member_binding_digest: identity.member,
                                invocation_id: identity.invocation,
                                timeline_position: identity.position,
                                output_base_ordinal: identity.output_base,
                                principal_ref: identity.references[0],
                                authorization_ref: identity.references[1],
                                observation_snapshot_ref: identity.references[2],
                                observation_bytes: payload.observation,
                                prior_state_schema_digest: payload.schema,
                                prior_state_bytes: payload.state,
                                execution_profile_digest: environment.profile,
                                trust_policy_snapshot_digest: environment.trust,
                                deterministic_budget_id: environment.budget,
                                deterministic_random_domain: environment.random,
                                provenance_root: environment.provenance,
                                simulation_time: environment.simulation_time,
                                watchdog_epochs: environment.watchdog,
                            })
                        })
                    })
                })
            })
        })
    }
}

const _: () =
    assert!(2 * MAX_COMMUNITY_STATE_BYTES_V1 + 1024 <= MAX_COMMUNITY_PREPARED_INVOCATION_BYTES_V1);

/// Complete due-input preimage, in strict member-digest order, before Reserve.
///
/// The set borrows actual complete CIN1 views; hashes are derived from those
/// views, never accepted as a substitute for retaining the original preimages.
/// An empty data set does not authorize a normal pass or a progress control.
pub struct CommunityPreparedInputSetV1<'a> {
    members: &'a [CommunityPreparedInvocationV1<'a>],
}

impl<'a> CommunityPreparedInputSetV1<'a> {
    /// Check the bounded roster, member order and globally distinct invocation IDs.
    ///
    /// # Errors
    /// Rejects more than64 members, duplicate/unordered member identities or any
    /// repeated invocation ID, before a reservation/guest permit can be requested.
    /// The qualified owner still compares the actual complete due roster.
    pub fn new(members: &'a [CommunityPreparedInvocationV1<'a>]) -> Result<Self> {
        if members.len() > MAX_COMMUNITY_MEMBERS_V1 {
            return Err(Error::BoundsExceeded);
        }
        for (index, member) in members.iter().enumerate() {
            let input = member.as_input();
            if index > 0
                && members[index - 1].as_input().member_binding_digest
                    >= input.member_binding_digest
                || members[..index]
                    .iter()
                    .any(|prior| prior.as_input().invocation_id == input.invocation_id)
            {
                return Err(Error::InvalidBinding);
            }
        }
        Ok(Self { members })
    }

    /// Borrow the complete prepared roster without cloning any private preimage.
    #[must_use]
    pub const fn members(&self) -> &'a [CommunityPreparedInvocationV1<'a>] {
        self.members
    }

    /// Encode the exact definite array of `[member_digest, CIN1_digest]` pairs.
    /// Deriving the private CIN1 hashes belongs before any database writer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(9 + self.members.len() * 69));
        encode_head(&mut out, 4, self.members.len() as u64);
        for member in self.members {
            out.push(0x82);
            encode_hash(&mut out, member.as_input().member_binding_digest);
            encode_hash(&mut out, member.digest());
        }
        out
    }

    /// Exact CRI1 prepared-input-set identity, with no future pass/result/receipt.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(
            b"PiglorOS.Community.PreparedInputSet.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Compare canonical stored pairs against actual independently retained CIN1.
    ///
    /// # Errors
    /// Rejects malformed/substituted/partial/reordered pairs or an oversized
    /// array. Equality does not authenticate sources, freshness or completeness
    /// against the installed schedule; those remain qualified-owner checks.
    pub fn validate_canonical_cbor(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 9 + MAX_COMMUNITY_MEMBERS_V1 * 69 {
            return Err(Error::BoundsExceeded);
        }
        if bytes == self.to_canonical_cbor().as_slice() {
            Ok(())
        } else {
            Err(Error::InvalidBinding)
        }
    }
}

struct Identity {
    member: Hash,
    invocation: [u8; 16],
    position: TimelinePositionV1,
    output_base: u32,
    references: [ArtifactRefV1; 3],
}

fn read_identity(cursor: &mut CborCursor<'_>) -> Result<Identity> {
    read_hash(cursor).and_then(|member| {
        read_head(cursor, 0).and_then(|export| {
            if export != 0 {
                return Err(Error::InvalidBinding);
            }
            fixed_bytes(cursor).and_then(|invocation| {
                read_position(cursor).and_then(|position| {
                    read_u32(cursor).and_then(|output_base| {
                        read_artifact_ref(cursor).and_then(|principal| {
                            read_artifact_ref(cursor).and_then(|authorization| {
                                read_artifact_ref(cursor).map(|observation| Identity {
                                    member,
                                    invocation,
                                    position,
                                    output_base,
                                    references: [principal, authorization, observation],
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}

fn read_position(cursor: &mut CborCursor<'_>) -> Result<TimelinePositionV1> {
    cursor.fixed(&[0x84]).map_err(Error::from).and_then(|()| {
        fixed_bytes(cursor).and_then(|timeline_id| {
            read_head(cursor, 0).and_then(|seq| {
                read_head(cursor, 0).and_then(|tick| {
                    read_u32(cursor).map(|scheduler_position| TimelinePositionV1 {
                        timeline_id,
                        seq,
                        tick,
                        scheduler_position,
                    })
                })
            })
        })
    })
}

fn read_u32(cursor: &mut CborCursor<'_>) -> Result<u32> {
    read_head(cursor, 0).and_then(|value| u32::try_from(value).map_err(|_| Error::BoundsExceeded))
}

struct Payload<'a> {
    observation: &'a [u8],
    schema: [u8; 32],
    state: &'a [u8],
}

fn read_payload<'a>(cursor: &mut CborCursor<'a>) -> Result<Payload<'a>> {
    bounded_bytes(cursor, MAX_COMMUNITY_STATE_BYTES_V1).and_then(|observation| {
        fixed_bytes(cursor).and_then(|schema| {
            bounded_bytes(cursor, MAX_COMMUNITY_STATE_BYTES_V1).map(|state| Payload {
                observation,
                schema,
                state,
            })
        })
    })
}

struct Environment<'a> {
    profile: [u8; 32],
    trust: [u8; 32],
    budget: &'a str,
    random: [u8; 32],
    provenance: [u8; 32],
    simulation_time: u64,
    watchdog: u32,
}

fn read_environment<'a>(cursor: &mut CborCursor<'a>) -> Result<Environment<'a>> {
    fixed_bytes(cursor).and_then(|profile| {
        fixed_bytes(cursor).and_then(|trust| {
            bounded_text(cursor, 128).and_then(|budget| {
                fixed_bytes(cursor).and_then(|random| {
                    fixed_bytes(cursor).and_then(|provenance| {
                        read_head(cursor, 0).and_then(|simulation_time| {
                            read_u32(cursor).map(|watchdog| Environment {
                                profile,
                                trust,
                                budget,
                                random,
                                provenance,
                                simulation_time,
                                watchdog,
                            })
                        })
                    })
                })
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_covers_encoded_inputs_without_exceeding_the_record_budget() -> Result<()> {
        let payload = Zeroizing::new(vec![7; MAX_COMMUNITY_STATE_BYTES_V1]);
        let budget = "b".repeat(128);
        let reference = ArtifactRefV1 {
            schema_id: u32::MAX,
            byte_length: u64::MAX,
            digest: [1; 32],
        };
        [
            0,
            23,
            24,
            255,
            256,
            8192,
            65_535,
            65_536,
            MAX_COMMUNITY_STATE_BYTES_V1,
        ]
        .into_iter()
        .try_for_each(|length| {
            [(length, 0), (0, length), (length, length)]
                .into_iter()
                .try_for_each(|(observation, state)| {
                    let input = CommunityPreparedInvocationInputV1 {
                        member_binding_digest: Hash::from_bytes([1; 32]),
                        invocation_id: [2; 16],
                        timeline_position: TimelinePositionV1 {
                            timeline_id: [3; 16],
                            seq: u64::MAX,
                            tick: u64::MAX,
                            scheduler_position: u32::MAX,
                        },
                        output_base_ordinal: u32::MAX,
                        principal_ref: reference,
                        authorization_ref: reference,
                        observation_snapshot_ref: reference,
                        observation_bytes: &payload[..observation],
                        prior_state_schema_digest: [4; 32],
                        prior_state_bytes: &payload[..state],
                        execution_profile_digest: [5; 32],
                        trust_policy_snapshot_digest: [6; 32],
                        deterministic_budget_id: &budget,
                        deterministic_random_domain: [7; 32],
                        provenance_root: [8; 32],
                        simulation_time: u64::MAX,
                        watchdog_epochs: u32::MAX,
                    };
                    CommunityPreparedInvocationV1::new(input).and_then(|record| {
                        let encoded = record.to_canonical_cbor();
                        assert!(encoded.len() <= record.staging_capacity());
                        assert!(
                            record.staging_capacity() <= MAX_COMMUNITY_PREPARED_INVOCATION_BYTES_V1
                        );
                        CommunityPreparedInvocationV1::from_canonical_cbor(&encoded)
                            .map(|decoded| assert!(*decoded.as_input() == input))
                    })
                })
        })
    }
}
