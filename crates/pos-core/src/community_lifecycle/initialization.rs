//! CGI1/CIS1 initialization data; neither record admits a generation or a guest.

use super::quarantine_control::{encode_artifact_ref, read_artifact_ref};
use super::{
    canonical_end, digest, encode_coordinates, encode_optional_hash, fixed_bytes, read_coordinates,
    read_hash, read_hashes, read_head, read_optional_hash, record_cursor, record_prefix,
    validate_coordinates, validate_horizon, ArtifactRefV1, CommunityDigestListV1,
    CommunityLifecycleErrorV1 as Error, Result, MAX_COMMUNITY_MEMBERS_V1,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash, Seq, TimelineId};
use zeroize::Zeroizing;

// The complete scalar/source framing is below 1 KiB; 64 fixed-width member
// digests fit without reallocating the secret encoder's original allocation.
const _: () = assert!(1024 + MAX_COMMUNITY_MEMBERS_V1 * 34 <= 4096);

/// Independently admitted source selected by the original CGI1 request.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityInitializationSourceV1 {
    /// Code 0: the exact initializer artifact, not permission from its digest.
    Initializer(ArtifactRefV1),
    /// Code 1: exact prior CSH1; its complete retained ancestry remains required.
    PriorState(Hash),
    /// Code 2: ordinary Fork; an Event cut alone does not identify State.
    Fork {
        /// Original parent Timeline.
        timeline: TimelineId,
        /// Factual parent cut, which may be zero.
        cut: Seq,
        /// Exact complete parent CSH1, including State-only progress.
        selected_head_digest: Hash,
        /// Original nonzero Fork operation identity.
        operation_id: [u8; 16],
    },
}

/// Untrusted CGI1 fields, preserving the installed roster's original order.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityInitializationRequestInputV1<'a> {
    /// Stable nonzero initialization/transition identity, never a `PassKey`.
    pub operation_id: [u8; 16],
    /// Target Timeline.
    pub timeline: TimelineId,
    /// Fresh target generation identity.
    pub generation: [u8; 16],
    /// Expected previous generation, absent only with its head.
    pub expected_prior_generation: Option<[u8; 16]>,
    /// Complete expected prior selection, absent only with its generation.
    pub expected_prior_head_digest: Option<Hash>,
    /// Exact complete CDP1 profile identity.
    pub profile_digest: Hash,
    /// Complete unique CMB1 identities in admitted roster order.
    pub member_binding_digests: CommunityDigestListV1<'a>,
    /// Original admitted source selection.
    pub initial_source: CommunityInitializationSourceV1,
    /// Actual authenticated-principal record reference, not authentication.
    pub principal_ref: ArtifactRefV1,
    /// Original authorization record reference, not current authority.
    pub authorization_ref: ArtifactRefV1,
    /// Fixed positive original horizon, never renewed by discovery.
    pub evidence_not_after_micros: u64,
}

/// Exact thirteen-field CGI1. Valid bytes cannot initialize or replace State.
pub struct CommunityInitializationRequestV1<'a>(CommunityInitializationRequestInputV1<'a>);

impl<'a> CommunityInitializationRequestV1<'a> {
    /// Validate bounded identities, paired predecessor and unique roster fields.
    ///
    /// # Errors
    /// Rejects zero bindings, an incomplete predecessor pair, an empty/oversized
    /// or repeated roster, malformed source identity and invalid finite horizon.
    /// Actual current source, roster completeness and CAS remain owner checks.
    pub fn new(input: CommunityInitializationRequestInputV1<'a>) -> Result<Self> {
        validate_coordinates(input.timeline, input.generation)
            .and_then(|()| validate_request_bindings(&input))
            .and_then(|()| validate_source(input.initial_source))
            .and_then(|()| validate_roster(input.member_binding_digests))
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow exact fields without authenticating their sources.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityInitializationRequestInputV1<'a> {
        &self.0
    }

    /// Encode the complete preferred CGI1 into bounded zeroizing storage.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        // At most 64 fixed-width digests plus bounded scalar/source fields.
        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        record_prefix(&mut out, 13, *b"CGI1");
        encode_bytes(&mut out, &input.operation_id, 2);
        encode_coordinates(&mut out, input.timeline, input.generation);
        match input.expected_prior_generation {
            Some(generation) => encode_bytes(&mut out, &generation, 2),
            None => out.push(0xf6),
        }
        encode_optional_hash(&mut out, input.expected_prior_head_digest);
        encode_hash(&mut out, input.profile_digest);
        encode_head(&mut out, 4, input.member_binding_digests.len() as u64);
        for member in input.member_binding_digests.iter() {
            encode_hash(&mut out, member);
        }
        encode_source(&mut out, input.initial_source);
        encode_artifact_ref(&mut out, input.principal_ref);
        encode_artifact_ref(&mut out, input.authorization_ref);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Protected CGI1 identity; it allocates neither a generation nor a permit.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CGI1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode a complete preferred request, borrowing its bounded roster range.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/oversized or unsupported records
    /// and invalid local fields. Decoding is not original-outcome discovery.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, 65_536, 13, *b"CGI1").and_then(|mut cursor| {
            read_request(&mut cursor)
                .and_then(Self::new)
                .and_then(|record| canonical_end(&cursor).map(|()| record))
        })
    }
}

/// Exact non-guest CIS1 producer fields, including its initializer source.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityInitializationProducerInputV1 {
    /// Original CGI1 identity.
    pub generation_request_digest: Hash,
    /// Exact immutable CMB1 identity.
    pub member_binding_digest: Hash,
    /// Original admitted initializer/transition source artifact.
    pub initializer_ref: ArtifactRefV1,
    /// Exact CSC1 content identity.
    pub state_content_digest: Hash,
    /// Independently derived complete CSB1 scope binding.
    pub scope_binding_digest: Hash,
    /// Finite original evidence horizon.
    pub evidence_not_after_micros: u64,
}

/// Eight-field CIS1 data; initialization never fabricates a guest invocation.
pub struct CommunityInitializationProducerV1(CommunityInitializationProducerInputV1);

impl CommunityInitializationProducerV1 {
    /// Check local identities and the finite original horizon.
    ///
    /// # Errors
    /// Rejects zero required links or an invalid horizon. Source, scope and
    /// current authority still require the installed qualified owner's checks.
    pub fn new(input: CommunityInitializationProducerInputV1) -> Result<Self> {
        if [
            input.generation_request_digest,
            input.member_binding_digest,
            input.state_content_digest,
            input.scope_binding_digest,
            Hash::from_bytes(input.initializer_ref.digest),
        ]
        .contains(&Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        validate_horizon(input.evidence_not_after_micros).map(|()| Self(input))
    }

    /// Borrow retained data, without granting protected use of its State.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityInitializationProducerInputV1 {
        &self.0
    }

    /// Encode the exact bounded CIS1 in a zeroizing allocation.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024));
        record_prefix(&mut out, 8, *b"CIS1");
        encode_hash(&mut out, input.generation_request_digest);
        encode_hash(&mut out, input.member_binding_digest);
        encode_artifact_ref(&mut out, input.initializer_ref);
        encode_hash(&mut out, input.state_content_digest);
        encode_hash(&mut out, input.scope_binding_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Exact CIS1 identity, separate from invocation or measurement evidence.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CIS1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode one complete preferred CIS1, without admitting its source.
    ///
    /// # Errors
    /// Rejects framing, version, trailing bytes, limits and invalid field links.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        record_cursor(bytes, 1024, 8, *b"CIS1").and_then(|mut cursor| {
            read_hashes(&mut cursor).and_then(
                |[generation_request_digest, member_binding_digest]| {
                    read_artifact_ref(&mut cursor).and_then(|initializer_ref| {
                        read_hashes(&mut cursor).and_then(
                            |[state_content_digest, scope_binding_digest]| {
                                read_head(&mut cursor, 0).and_then(|evidence_not_after_micros| {
                                    Self::new(CommunityInitializationProducerInputV1 {
                                        generation_request_digest,
                                        member_binding_digest,
                                        initializer_ref,
                                        state_content_digest,
                                        scope_binding_digest,
                                        evidence_not_after_micros,
                                    })
                                    .and_then(|record| canonical_end(&cursor).map(|()| record))
                                })
                            },
                        )
                    })
                },
            )
        })
    }
}

fn validate_request_bindings(input: &CommunityInitializationRequestInputV1<'_>) -> Result<()> {
    if input.operation_id == [0; 16]
        || input.profile_digest == Hash::zero()
        || input.expected_prior_generation == Some([0; 16])
        || input.expected_prior_head_digest == Some(Hash::zero())
        || input.expected_prior_generation.is_some() != input.expected_prior_head_digest.is_some()
        || [input.principal_ref, input.authorization_ref]
            .iter()
            .any(|reference| reference.digest == [0; 32])
    {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

fn validate_roster(members: CommunityDigestListV1<'_>) -> Result<()> {
    if members.is_empty() || members.len() > MAX_COMMUNITY_MEMBERS_V1 {
        Err(Error::BoundsExceeded)
    } else if members.iter().enumerate().any(|(index, member)| {
        member == Hash::zero() || members.iter().take(index).any(|prior| prior == member)
    }) {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

fn validate_source(source: CommunityInitializationSourceV1) -> Result<()> {
    let valid = match source {
        CommunityInitializationSourceV1::Initializer(reference) => reference.digest != [0; 32],
        CommunityInitializationSourceV1::PriorState(head) => head != Hash::zero(),
        CommunityInitializationSourceV1::Fork {
            timeline,
            selected_head_digest,
            operation_id,
            ..
        } => {
            timeline.inner().to_bytes() != [0; 16]
                && selected_head_digest != Hash::zero()
                && operation_id != [0; 16]
        }
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidBinding)
    }
}

fn encode_source(out: &mut Vec<u8>, source: CommunityInitializationSourceV1) {
    match source {
        CommunityInitializationSourceV1::Initializer(reference) => {
            out.extend_from_slice(&[0x82, 0]);
            encode_artifact_ref(out, reference);
        }
        CommunityInitializationSourceV1::PriorState(head) => {
            out.extend_from_slice(&[0x82, 1]);
            encode_hash(out, head);
        }
        CommunityInitializationSourceV1::Fork {
            timeline,
            cut,
            selected_head_digest,
            operation_id,
        } => {
            out.extend_from_slice(&[0x85, 2]);
            encode_bytes(out, &timeline.inner().to_bytes(), 2);
            encode_head(out, 0, cut.as_u64());
            encode_hash(out, selected_head_digest);
            encode_bytes(out, &operation_id, 2);
        }
    }
}

fn read_source(cursor: &mut CborCursor<'_>) -> Result<CommunityInitializationSourceV1> {
    read_head(cursor, 4).and_then(|fields| {
        read_head(cursor, 0).and_then(|tag| match (fields, tag) {
            (2, 0) => read_artifact_ref(cursor).map(CommunityInitializationSourceV1::Initializer),
            (2, 1) => read_hash(cursor).map(CommunityInitializationSourceV1::PriorState),
            (5, 2) => fixed_bytes(cursor).and_then(|timeline| {
                read_head(cursor, 0).and_then(|cut| {
                    read_hash(cursor).and_then(|selected_head_digest| {
                        fixed_bytes(cursor).map(|operation_id| {
                            CommunityInitializationSourceV1::Fork {
                                timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes(timeline)),
                                cut: Seq::from_u64(cut),
                                selected_head_digest,
                                operation_id,
                            }
                        })
                    })
                })
            }),
            _ => Err(Error::InvalidEncoding),
        })
    })
}

fn read_prior_generation(cursor: &mut CborCursor<'_>) -> Result<Option<[u8; 16]>> {
    if cursor.consume_if(0xf6) {
        Ok(None)
    } else {
        fixed_bytes(cursor).map(Some)
    }
}

struct PriorSelection {
    generation: Option<[u8; 16]>,
    head: Option<Hash>,
    profile: Hash,
}

fn read_selection(cursor: &mut CborCursor<'_>) -> Result<PriorSelection> {
    read_prior_generation(cursor).and_then(|generation| {
        read_optional_hash(cursor).and_then(|head| {
            read_hash(cursor).map(|profile| PriorSelection {
                generation,
                head,
                profile,
            })
        })
    })
}

struct InitializationSources {
    source: CommunityInitializationSourceV1,
    principal: ArtifactRefV1,
    authorization: ArtifactRefV1,
    horizon: u64,
}

fn read_sources(cursor: &mut CborCursor<'_>) -> Result<InitializationSources> {
    read_source(cursor).and_then(|source| {
        read_artifact_ref(cursor).and_then(|principal| {
            read_artifact_ref(cursor).and_then(|authorization| {
                read_head(cursor, 0).map(|horizon| InitializationSources {
                    source,
                    principal,
                    authorization,
                    horizon,
                })
            })
        })
    })
}

fn read_request<'a>(
    cursor: &mut CborCursor<'a>,
) -> Result<CommunityInitializationRequestInputV1<'a>> {
    let coordinates = fixed_bytes(cursor).and_then(|operation| {
        read_coordinates(cursor).map(|(timeline, generation)| (operation, timeline, generation))
    });
    coordinates.and_then(|(operation_id, timeline, generation)| {
        read_selection(cursor).and_then(|prior| {
            super::seal::read_list(cursor).and_then(|member_binding_digests| {
                read_sources(cursor).map(|sources| CommunityInitializationRequestInputV1 {
                    operation_id,
                    timeline,
                    generation,
                    expected_prior_generation: prior.generation,
                    expected_prior_head_digest: prior.head,
                    profile_digest: prior.profile,
                    member_binding_digests,
                    initial_source: sources.source,
                    principal_ref: sources.principal,
                    authorization_ref: sources.authorization,
                    evidence_not_after_micros: sources.horizon,
                })
            })
        })
    })
}
