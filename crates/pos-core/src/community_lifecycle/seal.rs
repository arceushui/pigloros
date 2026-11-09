//! CPS1 complete candidate data. Neither decoding nor a digest can Seal a pass.

use super::{
    canonical_end, encode_optional_hash, read_hash, read_hashes, read_head, read_optional_hash,
    read_pass_key, record_cursor, record_prefix, validate_horizon,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1, Result, MAX_COMMUNITY_MEMBERS_V1,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};
use zeroize::Zeroizing;

/// Borrowed digest list, ordered by the owning roster rather than digest value.
#[derive(Clone, Copy)]
pub struct CommunityDigestListV1<'a>(DigestRows<'a>);

#[derive(Clone, Copy)]
enum DigestRows<'a> {
    Typed(&'a [Hash]),
    Canonical(&'a [u8]),
}

impl<'a> CommunityDigestListV1<'a> {
    /// Borrow untrusted identities. Record construction validates its bounds.
    #[must_use]
    pub const fn from_digests(digests: &'a [Hash]) -> Self {
        Self(DigestRows::Typed(digests))
    }

    /// Number of logical identities in this list.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            DigestRows::Typed(rows) => rows.len(),
            DigestRows::Canonical(bytes) => bytes.len() / 34,
        }
    }

    /// Whether the list contains no identities.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate validated fixed-width digests without cloning a heap buffer.
    pub fn iter(&self) -> impl Iterator<Item = Hash> + '_ {
        (0..self.len()).map(|index| match self.0 {
            DigestRows::Typed(rows) => rows[index],
            DigestRows::Canonical(bytes) => {
                let mut digest = [0; 32];
                digest.copy_from_slice(&bytes[index * 34 + 2..(index + 1) * 34]);
                Hash::from_bytes(digest)
            }
        })
    }

    /// Exact decoded wire range, for the qualified owner's copy inventory.
    #[must_use]
    pub const fn as_canonical_rows(&self) -> Option<&'a [u8]> {
        match self.0 {
            DigestRows::Typed(_) => None,
            DigestRows::Canonical(bytes) => Some(bytes),
        }
    }
}

impl PartialEq for CommunityDigestListV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityDigestListV1<'_> {}

/// Untrusted exact candidate links; the owner verifies the complete actual set.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunitySealedResultInputV1<'a> {
    /// Original reserved CPK1.
    pub pass_key: CommunityPassKeyV1,
    /// Exact original CPR1, not a newly created reservation.
    pub reservation_digest: Hash,
    /// Required CPI1 invocation producers, never CIV1 measurement identities.
    pub invocation_step_digests: CommunityDigestListV1<'a>,
    /// Existing complete Event-draft vector identity, including the empty vector.
    pub event_draft_vector_digest: Hash,
    /// Exact CED1 retaining the draft preimage fragments.
    pub event_draft_manifest_digest: Hash,
    /// Complete new CSR1 identities in the admitted member order.
    pub new_revision_digests: CommunityDigestListV1<'a>,
    /// Complete new CMS1 identities, not only their State revisions.
    pub new_member_progress_digests: CommunityDigestListV1<'a>,
    /// Complete candidate CSH1, including unchanged/not-due members.
    pub candidate_head_digest: Hash,
    /// Required native/factual dependency bundle.
    pub dependency_bundle_digest: Hash,
    /// Present only if validated presentation items were retained.
    pub annotation_manifest_digest: Option<Hash>,
    /// Mandatory complete CRR1 for every successful original Seal.
    pub replay_recording_digest: Hash,
    /// Original fixed admitted horizon, never extended by discovery.
    pub evidence_not_after_micros: u64,
}

/// Historical CPS1 candidate data. It cannot execute, Seal or reconcile a pass.
pub struct CommunitySealedResultV1<'a>(CommunitySealedResultInputV1<'a>);

impl<'a> CommunitySealedResultV1<'a> {
    /// Validate local links and all three 64-entry list bounds.
    ///
    /// # Errors
    /// Rejects zero required/present optional links, oversized lists or an
    /// invalid horizon. Completeness, roster order and candidate equality require
    /// actual owner verification; wire construction grants no publication right.
    pub fn new(input: CommunitySealedResultInputV1<'a>) -> Result<Self> {
        if [
            input.reservation_digest,
            input.event_draft_vector_digest,
            input.event_draft_manifest_digest,
            input.candidate_head_digest,
            input.dependency_bundle_digest,
            input.replay_recording_digest,
        ]
        .contains(&Hash::zero())
            || input.annotation_manifest_digest == Some(Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        [
            input.invocation_step_digests,
            input.new_revision_digests,
            input.new_member_progress_digests,
        ]
        .iter()
        .try_for_each(|list| validate_list(*list))
        .and_then(|()| validate_horizon(input.evidence_not_after_micros))
        .map(|()| Self(input))
    }

    /// Borrow exact candidate data without authenticating any linked artifact.
    #[must_use]
    pub const fn as_input(&self) -> &CommunitySealedResultInputV1<'a> {
        &self.0
    }

    /// Encode exact 14-field CPS1 in a fully reserved zeroizing buffer.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(65_536));
        record_prefix(&mut out, 14, *b"CPS1");
        let pass_key = Zeroizing::new(input.pass_key.to_canonical_cbor());
        encode_bytes(&mut out, &pass_key, 2);
        encode_hash(&mut out, input.reservation_digest);
        encode_list(&mut out, input.invocation_step_digests);
        encode_hash(&mut out, input.event_draft_vector_digest);
        encode_hash(&mut out, input.event_draft_manifest_digest);
        encode_list(&mut out, input.new_revision_digests);
        encode_list(&mut out, input.new_member_progress_digests);
        encode_hash(&mut out, input.candidate_head_digest);
        encode_hash(&mut out, input.dependency_bundle_digest);
        encode_optional_hash(&mut out, input.annotation_manifest_digest);
        encode_hash(&mut out, input.replay_recording_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Protected CPS1 identity, independent of the later CPC1 terminal receipt.
    #[must_use]
    pub fn digest(&self) -> Hash {
        super::digest(b"PiglorOS.Community.CPS1.v1\0", &self.to_canonical_cbor())
    }

    /// Parse preferred CPS1 while borrowing all digest lists from the input.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/versioned/oversized records or
    /// locally invalid links, including an absent Replay recording root.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, 65_536, 14, *b"CPS1").and_then(|mut cursor| {
            read_pass_key(&mut cursor).and_then(|pass_key| {
                read_hash(&mut cursor).and_then(|reservation_digest| {
                    read_candidate(&mut cursor).and_then(|candidate| {
                        read_tail(&mut cursor).and_then(|tail| {
                            canonical_end(&cursor).and_then(|()| {
                                Self::new(CommunitySealedResultInputV1 {
                                    pass_key,
                                    reservation_digest,
                                    invocation_step_digests: candidate.invocations,
                                    event_draft_vector_digest: candidate.drafts[0],
                                    event_draft_manifest_digest: candidate.drafts[1],
                                    new_revision_digests: candidate.revisions,
                                    new_member_progress_digests: candidate.progress,
                                    candidate_head_digest: tail.head,
                                    dependency_bundle_digest: tail.dependencies,
                                    annotation_manifest_digest: tail.annotations,
                                    replay_recording_digest: tail.recording,
                                    evidence_not_after_micros: tail.horizon,
                                })
                            })
                        })
                    })
                })
            })
        })
    }
}

fn validate_list(list: CommunityDigestListV1<'_>) -> Result<()> {
    if list.len() > MAX_COMMUNITY_MEMBERS_V1 {
        Err(Error::BoundsExceeded)
    } else if list.iter().any(|hash| hash == Hash::zero()) {
        Err(Error::InvalidBinding)
    } else {
        Ok(())
    }
}

fn encode_list(out: &mut Vec<u8>, list: CommunityDigestListV1<'_>) {
    encode_head(out, 4, list.len() as u64);
    for hash in list.iter() {
        encode_hash(out, hash);
    }
}

pub(super) fn read_list<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityDigestListV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        if count > MAX_COMMUNITY_MEMBERS_V1 {
            return Err(Error::BoundsExceeded);
        }
        cursor
            .take(count * 34)
            .map_err(Error::from)
            .and_then(|bytes| {
                if bytes.chunks_exact(34).any(|row| row[..2] != [0x58, 0x20]) {
                    Err(Error::InvalidEncoding)
                } else {
                    Ok(CommunityDigestListV1(DigestRows::Canonical(bytes)))
                }
            })
    })
}

struct CandidateLists<'a> {
    invocations: CommunityDigestListV1<'a>,
    drafts: [Hash; 2],
    revisions: CommunityDigestListV1<'a>,
    progress: CommunityDigestListV1<'a>,
}

fn read_candidate<'a>(cursor: &mut CborCursor<'a>) -> Result<CandidateLists<'a>> {
    read_list(cursor).and_then(|invocations| {
        read_hashes(cursor).and_then(|drafts| {
            read_list(cursor).and_then(|revisions| {
                read_list(cursor).map(|progress| CandidateLists {
                    invocations,
                    drafts,
                    revisions,
                    progress,
                })
            })
        })
    })
}

struct CandidateTail {
    head: Hash,
    dependencies: Hash,
    annotations: Option<Hash>,
    recording: Hash,
    horizon: u64,
}

fn read_tail(cursor: &mut CborCursor<'_>) -> Result<CandidateTail> {
    read_hashes(cursor).and_then(|[head, dependencies]| {
        read_optional_hash(cursor).and_then(|annotations| {
            read_hash(cursor).and_then(|recording| {
                read_head(cursor, 0).map(|horizon| CandidateTail {
                    head,
                    dependencies,
                    annotations,
                    recording,
                    horizon,
                })
            })
        })
    })
}
