//! Stable quarantine identities and retained ledger data, never reset authority.

use super::{
    bounded_bytes, bounded_text, canonical_end, digest, encode_implementation_key, fixed_bytes,
    read_hash, read_head, read_implementation_key, read_optional_hash, record_cursor,
    record_prefix, validate_horizon, CommunityLifecycleErrorV1 as Error, Result,
};
use crate::{
    encode_bytes, encode_hash, encode_head, CborCursor, Hash, ImplementationKeyV1, TimelineId,
};
use zeroize::Zeroizing;

/// CQK1 stable identity. It deliberately contains no run-local ID or generation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityQuarantineKeyV1<'a> {
    timeline: TimelineId,
    stable_entry: &'a str,
    implementation: &'a ImplementationKeyV1,
}

impl<'a> CommunityQuarantineKeyV1<'a> {
    /// Validate the exact ADR-088 stable entry and a retained implementation key.
    ///
    /// # Errors
    /// Rejects a zero Timeline/release or an invalid 1..64-byte stable slot.
    /// Installation/composition and current release trust remain owner checks.
    pub fn new(
        timeline: TimelineId,
        stable_entry: &'a str,
        implementation: &'a ImplementationKeyV1,
    ) -> Result<Self> {
        if timeline.inner().to_bytes() == [0; 16]
            || implementation.release_digest() == Hash::zero()
            || !crate::manifest_plugin_roster::valid_slot(stable_entry)
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(Self {
                timeline,
                stable_entry,
                implementation,
            })
        }
    }

    /// Execution Timeline; no implicit cross-Timeline blacklist is selected.
    #[must_use]
    pub const fn timeline(&self) -> TimelineId {
        self.timeline
    }

    /// Byte-identical admitted World entry, never a guest-supplied replacement.
    #[must_use]
    pub const fn stable_entry(&self) -> &'a str {
        self.stable_entry
    }

    /// Exact implementation identity, including host version and release digest.
    #[must_use]
    pub const fn implementation(&self) -> &'a ImplementationKeyV1 {
        self.implementation
    }

    /// Encode exact five-field CQK1 without cloning its potentially personal texts.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(512));
        record_prefix(&mut out, 5, *b"CQK1");
        encode_bytes(&mut out, &self.timeline.inner().to_bytes(), 2);
        encode_bytes(&mut out, self.stable_entry.as_bytes(), 3);
        encode_implementation_key(&mut out, self.implementation);
        out
    }

    /// Stable protected CQK1 identity; it grants no lookup/reset permission.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CQK1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode exact CQK1 against the independently retained actual implementation.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/versioned/oversized bytes,
    /// invalid coordinates/slot or any nested implementation substitution.
    /// No unregistered implementation is reconstructed from wire strings.
    pub fn from_canonical_cbor(
        bytes: &'a [u8],
        implementation: &'a ImplementationKeyV1,
    ) -> Result<Self> {
        record_cursor(bytes, 512, 5, *b"CQK1").and_then(|mut cursor| {
            fixed_bytes(&mut cursor).and_then(|timeline| {
                bounded_text(&mut cursor, 64).and_then(|entry| {
                    read_implementation_key(&mut cursor, implementation).and_then(|()| {
                        Self::new(
                            TimelineId::from_ulid(ulid::Ulid::from_bytes(timeline)),
                            entry,
                            implementation,
                        )
                        .and_then(|key| canonical_end(&cursor).map(|()| key))
                    })
                })
            })
        })
    }
}

/// Existing failure mapping, with no severity/chronological ordering invented.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityQuarantineReasonV1 {
    /// Code0; only an actual host trap failure may set this reason.
    Trapped,
    /// Code1; only actual deterministic resource failures may set it.
    ResourceExhausted,
    /// Code2; only an actual revoked-release failure may set it.
    Revoked,
    /// Code3; only an actual worker crash may set it, never a watchdog timeout.
    Unavailable,
}

impl CommunityQuarantineReasonV1 {
    const ALL: [Self; 4] = [
        Self::Trapped,
        Self::ResourceExhausted,
        Self::Revoked,
        Self::Unavailable,
    ];

    /// Fixed retained reason code, independent of Rust discriminants.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Trapped => 0,
            Self::ResourceExhausted => 1,
            Self::Revoked => 2,
            Self::Unavailable => 3,
        }
    }
}

/// Untrusted reason plus its exact earlier CFO1 evidence identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityQuarantineReasonEvidenceV1 {
    /// Closed reason; a code alone never proves the corresponding failure.
    pub reason: CommunityQuarantineReasonV1,
    /// Exact CFO1, not the later CQC1/CQR1/CQO1/CAB1 referencing it.
    pub failure_evidence_digest: Hash,
}

/// Borrowed reason set; empty means a reset result only after actual admission.
#[derive(Clone, Copy)]
pub struct CommunityQuarantineReasonsV1<'a>(ReasonRows<'a>);

#[derive(Clone, Copy)]
enum ReasonRows<'a> {
    Typed(&'a [CommunityQuarantineReasonEvidenceV1]),
    Canonical(&'a [u8]),
}

impl<'a> CommunityQuarantineReasonsV1<'a> {
    /// Borrow caller data, with bounds/order checked by ledger construction.
    #[must_use]
    pub const fn from_reasons(reasons: &'a [CommunityQuarantineReasonEvidenceV1]) -> Self {
        Self(ReasonRows::Typed(reasons))
    }

    /// Number of active reasons, at most4 in an accepted ledger.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.0 {
            ReasonRows::Typed(rows) => rows.len(),
            ReasonRows::Canonical(bytes) => bytes.len() / 36,
        }
    }

    /// Whether the retained selected revision has no active reasons.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate fixed-width reason/evidence pairs without allocating.
    pub fn iter(&self) -> impl Iterator<Item = CommunityQuarantineReasonEvidenceV1> + '_ {
        (0..self.len()).map(|index| match self.0 {
            ReasonRows::Typed(rows) => rows[index],
            ReasonRows::Canonical(bytes) => {
                let row = &bytes[index * 36..(index + 1) * 36];
                let mut evidence = [0; 32];
                evidence.copy_from_slice(&row[4..]);
                CommunityQuarantineReasonEvidenceV1 {
                    reason: CommunityQuarantineReasonV1::ALL[usize::from(row[1])],
                    failure_evidence_digest: Hash::from_bytes(evidence),
                }
            }
        })
    }

    /// Exact original decoded rows for registered private-range accounting.
    #[must_use]
    pub const fn as_canonical_rows(&self) -> Option<&'a [u8]> {
        match self.0 {
            ReasonRows::Typed(_) => None,
            ReasonRows::Canonical(bytes) => Some(bytes),
        }
    }
}

impl PartialEq for CommunityQuarantineReasonsV1<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for CommunityQuarantineReasonsV1<'_> {}

/// Untrusted retained CQR1 fields, without selected-index or reset authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityQuarantineRevisionInputV1<'a> {
    /// Exact stable Timeline/entry/implementation identity.
    pub key: CommunityQuarantineKeyV1<'a>,
    /// Positive per-key ledger ordinal, compared to the actual predecessor.
    pub ledger_ordinal: u64,
    /// Original predecessor when present; absence cannot clear a live ledger.
    pub predecessor_ledger_digest: Option<Hash>,
    /// Complete active set, strictly ordered by reason code with no duplicates.
    pub active_reasons: CommunityQuarantineReasonsV1<'a>,
    /// Earlier exact CQC1, never the later CQO1/CAB1.
    pub control_request_digest: Hash,
    /// Original admitted horizon, bounded by every required failure dependency.
    pub evidence_not_after_micros: u64,
}

/// Historical CQR1 data. Missing/expired evidence is never an availability grant.
pub struct CommunityQuarantineRevisionV1<'a>(CommunityQuarantineRevisionInputV1<'a>);

impl<'a> CommunityQuarantineRevisionV1<'a> {
    /// Check local identities, positive ordinal, fixed horizon and closed set.
    ///
    /// # Errors
    /// Rejects zero links/ordinal, invalid horizon or excess/unsorted/duplicate
    /// reasons. Actual failure mapping, source horizon and authenticated control
    /// admission/predecessor comparison remain qualified owner requirements.
    pub fn new(input: CommunityQuarantineRevisionInputV1<'a>) -> Result<Self> {
        if input.ledger_ordinal == 0
            || input.control_request_digest == Hash::zero()
            || input.predecessor_ledger_digest == Some(Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        validate_reasons(input.active_reasons)
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow retained facts; an empty set alone does not authorize execution.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityQuarantineRevisionInputV1<'a> {
        &self.0
    }

    /// Encode exact eight-field CQR1 in pre-sized private staging.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        record_prefix(&mut out, 8, *b"CQR1");
        let key = input.key.to_canonical_cbor();
        encode_bytes(&mut out, &key, 2);
        encode_head(&mut out, 0, input.ledger_ordinal);
        super::encode_optional_hash(&mut out, input.predecessor_ledger_digest);
        encode_reasons(&mut out, input.active_reasons);
        encode_hash(&mut out, input.control_request_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Protected immutable revision identity, not its current selected status.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CQR1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode exact retained data against the actual admitted implementation.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/versioned/oversized data, nested
    /// key mismatch and invalid local ordinal/set/evidence/horizon values.
    pub fn from_canonical_cbor(
        bytes: &'a [u8],
        implementation: &'a ImplementationKeyV1,
    ) -> Result<Self> {
        record_cursor(bytes, 4096, 8, *b"CQR1").and_then(|mut cursor| {
            bounded_bytes(&mut cursor, 512)
                .and_then(|bytes| {
                    CommunityQuarantineKeyV1::from_canonical_cbor(bytes, implementation)
                })
                .and_then(|key| {
                    read_revision(&mut cursor, key)
                        .and_then(Self::new)
                        .and_then(|record| canonical_end(&cursor).map(|()| record))
                })
        })
    }
}

pub(super) fn validate_reasons(reasons: CommunityQuarantineReasonsV1<'_>) -> Result<()> {
    if reasons.len() > 4 {
        return Err(Error::BoundsExceeded);
    }
    let mut prior = None;
    reasons.iter().try_for_each(|entry| {
        let code = entry.reason.code();
        if entry.failure_evidence_digest == Hash::zero()
            || prior.is_some_and(|previous| previous >= code)
        {
            return Err(Error::InvalidBinding);
        }
        prior = Some(code);
        Ok(())
    })
}

pub(super) fn encode_reasons(out: &mut Vec<u8>, reasons: CommunityQuarantineReasonsV1<'_>) {
    encode_head(out, 4, reasons.len() as u64);
    for entry in reasons.iter() {
        out.extend_from_slice(&[0x82, entry.reason.code()]);
        encode_hash(out, entry.failure_evidence_digest);
    }
}

pub(super) fn read_reasons<'a>(
    cursor: &mut CborCursor<'a>,
) -> Result<CommunityQuarantineReasonsV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        if count > 4 {
            return Err(Error::BoundsExceeded);
        }
        cursor
            .take(count * 36)
            .map_err(Error::from)
            .and_then(|bytes| {
                if bytes
                    .chunks_exact(36)
                    .any(|row| row[0] != 0x82 || row[1] > 3 || row[2..4] != [0x58, 0x20])
                {
                    Err(Error::InvalidEncoding)
                } else {
                    Ok(CommunityQuarantineReasonsV1(ReasonRows::Canonical(bytes)))
                }
            })
    })
}

fn read_revision<'a>(
    cursor: &mut CborCursor<'a>,
    key: CommunityQuarantineKeyV1<'a>,
) -> Result<CommunityQuarantineRevisionInputV1<'a>> {
    read_head(cursor, 0).and_then(|ledger_ordinal| {
        read_optional_hash(cursor).and_then(|predecessor_ledger_digest| {
            read_reasons(cursor).and_then(|active_reasons| {
                read_hash(cursor).and_then(|control_request_digest| {
                    read_head(cursor, 0).map(|evidence_not_after_micros| {
                        CommunityQuarantineRevisionInputV1 {
                            key,
                            ledger_ordinal,
                            predecessor_ledger_digest,
                            active_reasons,
                            control_request_digest,
                            evidence_not_after_micros,
                        }
                    })
                })
            })
        })
    })
}
