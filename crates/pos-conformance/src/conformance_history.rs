//! The per-profile CHS1 conformance history of ADR-062 Revision 8 section 5.3 (slice G4, #1239).
//!
//! A CHS1 record is the exact deterministic-CBOR array
//!
//! ```text
//! [ "CHS1", 1, profile_digest, [[previous_digest, record_kind, record_digest], ...],
//!   record_digest ]
//! ```
//!
//! The first entry links to the CPF1 profile digest and every later entry to the entry digest of
//! the entry before it, so a broken, reordered or rewritten link is refused. A valid CPF1
//! always decodes as Draft: the lifecycle lives only here, replayed from the governance records
//! the entries name (wiki `ADR-062_R8_Promotion_Gate` sections 2 to 5).

use crate::{
    ConformanceArtifactKindV1, ConformanceConflictResolutionV1, ConformanceConflictV1,
    ConformanceCorrectionV1, ConformanceGovernanceErrorV1 as Error,
    ConformanceHistoryRecordKindV1 as Kind, ConformanceImpactAnalysisV1, ConformancePromotionV1,
    ConformanceRetentionV1, ConformanceWaiverV1, ConformanceWithdrawalV1, GovernanceEncoder,
    GovernanceRecordV1, ProfileLifecycleV1,
};
use ciborium::value::Value;

/// Magic of the CHS1 conformance history record.
pub const CONFORMANCE_HISTORY_MAGIC_V1: &str = "CHS1";
const ENTRY_DOMAIN: &[u8] = b"PiglorOS.ConformanceHistoryEntry.v1";
const SNAPSHOT_DOMAIN: &[u8] = b"PiglorOS.ConformanceWaiverConflictSnapshot.v1";

/// One link of a CHS1 history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceHistoryEntryV1 {
    /// The profile digest for the first entry, else the entry digest of the entry before it.
    pub previous_digest: [u8; 32],
    pub record_kind: Kind,
    pub record_digest: [u8; 32],
}

impl ConformanceHistoryEntryV1 {
    /// BLAKE3(`PiglorOS.ConformanceHistoryEntry.v1` || 0x00 || canonical
    /// `[previous_digest, record_kind, record_digest]`).
    #[must_use]
    pub fn entry_digest(&self) -> [u8; 32] {
        let mut encoder = GovernanceEncoder::array(3);
        encoder.bytes(&self.previous_digest);
        encoder.uint(self.record_kind.wire_code());
        encoder.bytes(&self.record_digest);
        crate::domain_digest(ENTRY_DOMAIN, &encoder.out)
    }
}

/// One CHS1 per-profile conformance history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceHistoryV1 {
    pub profile_digest: [u8; 32],
    pub entries: Vec<ConformanceHistoryEntryV1>,
    pub record_digest: [u8; 32],
}

/// The state a valid history replays to: its lifecycle and the waivers and conflicts it holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceHistoryStateV1 {
    lifecycle: ProfileLifecycleV1,
    waivers: Vec<ConformanceWaiverV1>,
    conflicts: Vec<ConformanceConflictV1>,
}

impl ConformanceHistoryV1 {
    /// The empty history of a profile: a Draft profile with no record.
    #[must_use]
    pub fn new(profile_digest: [u8; 32]) -> Self {
        Self::sealed(profile_digest, Vec::new())
    }

    fn sealed(profile_digest: [u8; 32], entries: Vec<ConformanceHistoryEntryV1>) -> Self {
        let mut history = Self {
            profile_digest,
            entries,
            record_digest: [0; 32],
        };
        history.record_digest = history.computed_record_digest();
        history
    }

    /// This history with one more entry, naming `record_digest` of `record_kind`, linked to
    /// the head. Nothing already in the history changes.
    ///
    /// # Errors
    /// Returns the validation error of the extended history, such as `FieldOutOfBounds` past
    /// 4,096 entries.
    pub fn append(&self, record_kind: Kind, record_digest: [u8; 32]) -> Result<Self, Error> {
        let mut entries = self.entries.clone();
        entries.push(ConformanceHistoryEntryV1 {
            previous_digest: self.head_digest(),
            record_kind,
            record_digest,
        });
        let history = Self::sealed(self.profile_digest, entries);
        history.validate().map(|()| history)
    }

    /// The last entry digest, or the profile digest of an empty history.
    #[must_use]
    pub fn head_digest(&self) -> [u8; 32] {
        self.entries
            .last()
            .map_or(self.profile_digest, ConformanceHistoryEntryV1::entry_digest)
    }

    /// The record digest recomputed over fields 0 through 3.
    #[must_use]
    pub fn computed_record_digest(&self) -> [u8; 32] {
        crate::governance_record_digest(self)
    }

    /// Validate the bound, every link and the record digest.
    ///
    /// # Errors
    /// Returns the closed error of the first violation.
    pub fn validate(&self) -> Result<(), Error> {
        crate::governance_validate(self)
    }

    /// Encode the history as its canonical CHS1 bytes.
    ///
    /// # Errors
    /// Returns the validation error when the history is invalid.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, Error> {
        crate::governance_encode(self)
    }

    /// Decode and validate exact canonical CHS1 bytes.
    ///
    /// # Errors
    /// Returns the closed error for oversized, malformed, non-canonical or invalid records.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, Error> {
        crate::governance_decode(bytes)
    }

    /// Refuse a history that does not extend the caller-pinned head: the profile digest or
    /// the digest of an entry the host already accepted. Each entry digest commits every
    /// entry before it, so a history holding the pinned head keeps the pinned history as an
    /// exact prefix.
    ///
    /// # Errors
    /// Returns the validation error, or `HistoryNotAppendOnly`.
    pub fn extends(&self, pinned_head: &[u8; 32]) -> Result<(), Error> {
        self.validate().and_then(|()| {
            if self.profile_digest == *pinned_head
                || self
                    .entries
                    .iter()
                    .any(|entry| entry.entry_digest() == *pinned_head)
            {
                Ok(())
            } else {
                Err(Error::HistoryNotAppendOnly)
            }
        })
    }

    /// Replay the history over the exact bytes of the record each entry names, in entry order.
    ///
    /// Each record is decoded with its kind's strict decoder and must have the entry's record
    /// digest; a CWV1, CCF1 or CPR1 must name this profile. A CPR1 moves the lifecycle from its
    /// `from_lifecycle`, which must be the current one; a CRT1 of kind `ConformanceProfile`
    /// must name this profile and retires a Candidate or Stable profile.
    ///
    /// # Errors
    /// Returns the validation error, a record decode error, `HistoryRecordMismatch`,
    /// `ProfileMismatch` or `InvalidLifecycleTransition`.
    pub fn replay(&self, records: &[&[u8]]) -> Result<ConformanceHistoryStateV1, Error> {
        self.validate()?;
        if records.len() != self.entries.len() {
            return Err(Error::HistoryRecordMismatch);
        }
        let mut state = ConformanceHistoryStateV1 {
            lifecycle: ProfileLifecycleV1::Draft,
            waivers: Vec::new(),
            conflicts: Vec::new(),
        };
        for (entry, bytes) in self.entries.iter().zip(records) {
            let (record_digest, profile_digest) = state.apply(entry.record_kind, bytes)?;
            if record_digest != entry.record_digest {
                return Err(Error::HistoryRecordMismatch);
            }
            if profile_digest.is_some_and(|digest| digest != self.profile_digest) {
                return Err(Error::ProfileMismatch);
            }
        }
        Ok(state)
    }
}

impl ConformanceHistoryStateV1 {
    /// The replayed lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> ProfileLifecycleV1 {
        self.lifecycle
    }

    /// The CWV1 waivers of the history, in entry order.
    #[must_use]
    pub fn waivers(&self) -> &[ConformanceWaiverV1] {
        &self.waivers
    }

    /// The CCF1 conflicts of the history, in entry order.
    #[must_use]
    pub fn conflicts(&self) -> &[ConformanceConflictV1] {
        &self.conflicts
    }

    /// Whether the history holds an Open CCF1 conflict.
    #[must_use]
    pub fn has_open_conflict(&self) -> bool {
        self.conflicts
            .iter()
            .any(|conflict| conflict.resolution == ConformanceConflictResolutionV1::Open)
    }

    /// BLAKE3(`PiglorOS.ConformanceWaiverConflictSnapshot.v1` || 0x00 || canonical
    /// `[[CWV1 record digests ascending], [CCF1 record digests ascending]]`): the CPR1
    /// `waiver_conflict_snapshot_digest` of exactly the waivers and conflicts of the history.
    ///
    /// The same record digest may appear more than once: the history deliberately allows a
    /// record to be appended again, and the snapshot keeps every occurrence in sorted order.
    #[must_use]
    pub fn waiver_conflict_snapshot_digest(&self) -> [u8; 32] {
        let ascending = |mut digests: Vec<[u8; 32]>| {
            digests.sort_unstable();
            digests
        };
        let mut encoder = GovernanceEncoder::array(2);
        encoder.digests(&ascending(
            self.waivers
                .iter()
                .map(|waiver| waiver.record_digest)
                .collect(),
        ));
        encoder.digests(&ascending(
            self.conflicts
                .iter()
                .map(|conflict| conflict.record_digest)
                .collect(),
        ));
        crate::domain_digest(SNAPSHOT_DOMAIN, &encoder.out)
    }

    /// Decode one record of `kind`, apply its lifecycle effect and keep its waiver or
    /// conflict; returns its record digest and the profile digest it names, if any.
    fn apply(&mut self, kind: Kind, bytes: &[u8]) -> Result<([u8; 32], Option<[u8; 32]>), Error> {
        match kind {
            Kind::Waiver => ConformanceWaiverV1::from_canonical_cbor(bytes).map(|waiver| {
                let named = (waiver.record_digest, Some(waiver.profile_digest));
                self.waivers.push(waiver);
                named
            }),
            Kind::Conflict => ConformanceConflictV1::from_canonical_cbor(bytes).map(|conflict| {
                let named = (conflict.record_digest, Some(conflict.profile_digest));
                self.conflicts.push(conflict);
                named
            }),
            Kind::Correction => ConformanceCorrectionV1::from_canonical_cbor(bytes)
                .map(|record| (record.record_digest, None)),
            Kind::ImpactAnalysis => ConformanceImpactAnalysisV1::from_canonical_cbor(bytes)
                .map(|record| (record.record_digest, None)),
            Kind::Withdrawal => ConformanceWithdrawalV1::from_canonical_cbor(bytes)
                .map(|record| (record.record_digest, None)),
            Kind::Retention => {
                let record = ConformanceRetentionV1::from_canonical_cbor(bytes)?;
                if record.retired_artifact_kind != ConformanceArtifactKindV1::ConformanceProfile {
                    return Ok((record.record_digest, None));
                }
                self.lifecycle = match self.lifecycle {
                    ProfileLifecycleV1::Candidate | ProfileLifecycleV1::Stable => {
                        ProfileLifecycleV1::Retired
                    }
                    _ => return Err(Error::InvalidLifecycleTransition),
                };
                Ok((record.record_digest, Some(record.retired_artifact_digest)))
            }
            Kind::Promotion => {
                let record = ConformancePromotionV1::from_canonical_cbor(bytes)?;
                if record.from_lifecycle != self.lifecycle {
                    return Err(Error::InvalidLifecycleTransition);
                }
                self.lifecycle = record.to_lifecycle;
                Ok((record.record_digest, Some(record.profile_digest)))
            }
        }
    }
}

impl GovernanceRecordV1 for ConformanceHistoryV1 {
    const MAGIC: &'static str = CONFORMANCE_HISTORY_MAGIC_V1;
    const DOMAIN: &'static [u8] = b"PiglorOS.ConformanceHistory.v1";
    const BODY_FIELDS: u64 = 2;

    fn encode_body(&self, encoder: &mut GovernanceEncoder) {
        encoder.bytes(&self.profile_digest);
        encoder.open_array(self.entries.len());
        for entry in &self.entries {
            encoder.open_array(3);
            encoder.bytes(&entry.previous_digest);
            encoder.uint(entry.record_kind.wire_code());
            encoder.bytes(&entry.record_digest);
        }
    }

    fn decode_body(body: Vec<Value>, record_digest: [u8; 32]) -> Result<Self, Error> {
        let [profile, entries] = crate::governance_fields::<2>(body)?;
        Ok(Self {
            profile_digest: crate::governance_fixed(profile)?,
            entries: crate::governance_array(entries)?
                .into_iter()
                .map(decode_entry)
                .collect::<Result<_, _>>()?,
            record_digest,
        })
    }

    fn stored_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    /// Only the bound and the links are checked. Duplicate record digests are deliberately
    /// allowed; a replay applies every occurrence, so a repeated CPR1 is still refused as a
    /// lifecycle step.
    fn check(&self) -> Result<(), Error> {
        if self.entries.len() > crate::MAX_CONFORMANCE_GOVERNANCE_LIST_ITEMS_V1 {
            return Err(Error::FieldOutOfBounds);
        }
        let mut previous = self.profile_digest;
        for entry in &self.entries {
            if entry.previous_digest != previous {
                return Err(Error::BrokenHistoryLink);
            }
            previous = entry.entry_digest();
        }
        Ok(())
    }
}

fn decode_entry(value: Value) -> Result<ConformanceHistoryEntryV1, Error> {
    let [previous, kind, record] = crate::governance_fields::<3>(crate::governance_array(value)?)?;
    Ok(ConformanceHistoryEntryV1 {
        previous_digest: crate::governance_fixed(previous)?,
        record_kind: crate::governance_code(&kind, Kind::from_wire_code)?,
        record_digest: crate::governance_fixed(record)?,
    })
}
