//! Payload codecs of the two reserved ADR-119 Event types.

use super::{
    check_entry_key, check_text, require, strictly_sorted, write_optional_hash, write_text,
    DomainFallbackPolicyV1, FallbackActivationOriginV1, FallbackActivationOriginV1 as Origin,
    FallbackRecordErrorV1, FallbackSkipReasonV1, FallbackSkipReasonV1 as Reason,
    FallbackTriggerCodeV1, FallbackTriggerCodeV1 as Trigger, Field, ImplementationKeyV1, Outcome,
    Reader, MAX_FALLBACK_ENTRIES_V1, MAX_FALLBACK_EVENT_PAYLOAD_BYTES_V1, MAX_FALLBACK_SKIPPED_V1,
    SCOPE_MAX,
};
use crate::{encode_bytes, encode_hash, encode_head, Hash};

const PAYLOAD_MAX: usize = MAX_FALLBACK_EVENT_PAYLOAD_BYTES_V1;
const REBASED_MAX: usize = MAX_FALLBACK_ENTRIES_V1;
const SKIPPED_MAX: usize = MAX_FALLBACK_SKIPPED_V1;

/// One `rebased` pair of the declaration payload, `[entry_key, imk1_digest]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackRebasedEntryV1 {
    entry_key: String,
    implementation_digest: Hash,
}

impl FallbackRebasedEntryV1 {
    /// Validate one re-based entry and the IMK1 digest it freezes or promotes.
    ///
    /// # Errors
    /// Returns `InvalidField(EntryKey)` for an invalid entry key.
    pub fn new(
        entry_key: String,
        implementation_digest: Hash,
    ) -> Result<Self, FallbackRecordErrorV1> {
        check_entry_key(&entry_key)?;
        Ok(Self {
            entry_key,
            implementation_digest,
        })
    }

    /// Return the entry key.
    #[must_use]
    pub fn entry_key(&self) -> &str {
        &self.entry_key
    }

    /// Return the `imk1_digest` of the entry's new primary.
    #[must_use]
    pub const fn implementation_digest(&self) -> Hash {
        self.implementation_digest
    }
}

/// The `pigloros.composition.fallback-declared` v1 payload.
///
/// `[scope, policy_digest, previous_policy_digest_or_null, rebased]`, with at
/// most 32 `rebased` pairs strictly sorted by entry key. A withdrawal carries
/// the digest of its 0-entry DFP1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackDeclaredPayloadV1 {
    scope: String,
    policy_digest: Hash,
    previous_policy_digest: Option<Hash>,
    rebased: Vec<FallbackRebasedEntryV1>,
}

impl FallbackDeclaredPayloadV1 {
    /// Validate one declaration payload.
    ///
    /// # Errors
    /// Returns `InvalidField(Scope)` for an empty or over-long scope, and
    /// `InvalidField(Rebased)` for more than 32 pairs or pairs not strictly
    /// sorted by entry key.
    pub fn new(
        scope: String,
        policy_digest: Hash,
        previous_policy_digest: Option<Hash>,
        rebased: Vec<FallbackRebasedEntryV1>,
    ) -> Result<Self, FallbackRecordErrorV1> {
        check_text(&scope, SCOPE_MAX, Field::Scope)?;
        require(valid_rebased(&rebased), Field::Rebased)?;
        Ok(Self {
            scope,
            policy_digest,
            previous_policy_digest,
            rebased,
        })
    }

    /// Build the declaration payload of one validated policy.
    ///
    /// # Errors
    /// Returns `InvalidField(Rebased)` as [`Self::new`] does.
    pub fn for_policy(
        policy: &DomainFallbackPolicyV1,
        rebased: Vec<FallbackRebasedEntryV1>,
    ) -> Result<Self, FallbackRecordErrorV1> {
        let scope = policy.scope().to_owned();
        let previous = policy.previous_policy_digest();
        Self::new(scope, policy.policy_digest(), previous, rebased)
    }

    /// Return the composition scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Return the declared DFP1 `policy_digest`.
    #[must_use]
    pub const fn policy_digest(&self) -> Hash {
        self.policy_digest
    }

    /// Return the declared policy's `previous_policy_digest`.
    #[must_use]
    pub const fn previous_policy_digest(&self) -> Option<Hash> {
        self.previous_policy_digest
    }

    /// Return the re-based entries in ascending entry-key order.
    #[must_use]
    pub fn rebased(&self) -> &[FallbackRebasedEntryV1] {
        &self.rebased
    }

    /// Encode the unique preferred CBOR payload.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(0x84);
        write_text(&mut out, &self.scope);
        encode_hash(&mut out, self.policy_digest);
        write_optional_hash(&mut out, self.previous_policy_digest);
        encode_head(&mut out, 4, self.rebased.len() as u64);
        for pair in &self.rebased {
            out.push(0x82);
            write_text(&mut out, &pair.entry_key);
            encode_hash(&mut out, pair.implementation_digest);
        }
        out
    }

    /// Decode a bounded preferred payload and recheck its canonical form.
    ///
    /// # Errors
    /// Rejects oversized, malformed, out-of-bounds, nonpreferred or trailing data.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FallbackRecordErrorV1> {
        let mut reader = Reader::open(bytes, PAYLOAD_MAX)?;
        let payload = read_declared(&mut reader)?;
        reader.finish(bytes, &payload.to_canonical_cbor())?;
        Ok(payload)
    }
}

/// One `skipped` pair of the activation payload, `[imk1_digest, reason_u8]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackSkippedCandidateV1 {
    /// The `imk1_digest` of the skipped candidate.
    pub implementation_digest: Hash,
    /// Why the candidate was skipped.
    pub reason: FallbackSkipReasonV1,
}

/// The activation payload `trigger_basis`: a u16 cause code and a u8 origin.
///
/// The cause code is the host's closed failure cause; this record carries it
/// opaquely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FallbackTriggerBasisV1 {
    /// The host's cause code.
    pub cause: u16,
    /// Whether the host or an owner started the activation.
    pub origin: FallbackActivationOriginV1,
}

/// Unvalidated fields of one `pigloros.composition.fallback-activated` v1 payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackActivatedInputV1 {
    pub scope: String,
    pub policy_digest: Hash,
    pub entry_key: String,
    pub closing_tenure_ordinal: u64,
    pub from: ImplementationKeyV1,
    pub to: ImplementationKeyV1,
    pub skipped: Vec<FallbackSkippedCandidateV1>,
    pub trigger_code: FallbackTriggerCodeV1,
    pub trigger_basis: FallbackTriggerBasisV1,
    pub activation_ordinal: u64,
}

/// The `pigloros.composition.fallback-activated` v1 payload.
///
/// `[scope, policy_digest, entry_key, closing_tenure_ordinal,`
/// `from_imk1_bytes, to_imk1_bytes, skipped, trigger_code, trigger_basis,`
/// `activation_ordinal]`.
/// It carries no UTC and no Tick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackActivatedPayloadV1(FallbackActivatedInputV1);

impl FallbackActivatedPayloadV1 {
    /// Validate one activation payload.
    ///
    /// # Errors
    /// Returns `InvalidField` for an invalid scope (`Scope`) or entry key
    /// (`EntryKey`), more than two skipped candidates (`Skipped`), or `from`
    /// and `to` naming one `plugin_id_text` (`Implementation`).
    pub fn new(input: FallbackActivatedInputV1) -> Result<Self, FallbackRecordErrorV1> {
        check_text(&input.scope, SCOPE_MAX, Field::Scope)?;
        check_entry_key(&input.entry_key)?;
        require(input.skipped.len() <= SKIPPED_MAX, Field::Skipped)?;
        let switched = input.from.plugin_id() != input.to.plugin_id();
        require(switched, Field::Implementation)?;
        Ok(Self(input))
    }

    /// Borrow the validated fields.
    #[must_use]
    pub const fn as_input(&self) -> &FallbackActivatedInputV1 {
        &self.0
    }

    /// Return the ordinal of the tenure that opens, `closing_tenure_ordinal + 1`.
    ///
    /// Returns `None` when the closing ordinal is `u64::MAX`.
    #[must_use]
    pub const fn opening_tenure_ordinal(&self) -> Option<u64> {
        self.0.closing_tenure_ordinal.checked_add(1)
    }

    /// Encode the unique preferred CBOR payload.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let input = &self.0;
        let mut out = Vec::with_capacity(1_024);
        out.push(0x8a);
        write_text(&mut out, &input.scope);
        encode_hash(&mut out, input.policy_digest);
        write_text(&mut out, &input.entry_key);
        encode_head(&mut out, 0, input.closing_tenure_ordinal);
        encode_bytes(&mut out, &input.from.to_canonical_cbor(), 2);
        encode_bytes(&mut out, &input.to.to_canonical_cbor(), 2);
        encode_head(&mut out, 4, input.skipped.len() as u64);
        for skipped in &input.skipped {
            out.push(0x82);
            encode_hash(&mut out, skipped.implementation_digest);
            encode_head(&mut out, 0, u64::from(skipped.reason.code()));
        }
        encode_head(&mut out, 0, u64::from(input.trigger_code.code()));
        let [high, low] = input.trigger_basis.cause.to_be_bytes();
        let origin = input.trigger_basis.origin.code();
        out.extend_from_slice(&[0x43, high, low, origin]);
        encode_head(&mut out, 0, input.activation_ordinal);
        out
    }

    /// Decode a bounded preferred payload and recheck its canonical form.
    ///
    /// # Errors
    /// Rejects oversized, malformed, out-of-bounds, nonpreferred or trailing data.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FallbackRecordErrorV1> {
        let mut reader = Reader::open(bytes, PAYLOAD_MAX)?;
        let payload = read_activated(&mut reader)?;
        reader.finish(bytes, &payload.to_canonical_cbor())?;
        Ok(payload)
    }
}

fn valid_rebased(rebased: &[FallbackRebasedEntryV1]) -> bool {
    let keys: Vec<&str> = rebased
        .iter()
        .map(FallbackRebasedEntryV1::entry_key)
        .collect();
    rebased.len() <= REBASED_MAX && strictly_sorted(&keys)
}

fn read_head(reader: &mut Reader<'_>, header: u8) -> Outcome<(String, Hash)> {
    reader.fixed(&[header])?;
    let scope = reader.text()?;
    Ok((scope, reader.hash()?))
}

fn read_declared(reader: &mut Reader<'_>) -> Outcome<FallbackDeclaredPayloadV1> {
    let (scope, policy_digest) = read_head(reader, 0x84)?;
    let previous = reader.optional_hash()?;
    let rebased = reader.list(REBASED_MAX, Field::Rebased, read_rebased)?;
    FallbackDeclaredPayloadV1::new(scope, policy_digest, previous, rebased)
}

fn read_rebased(reader: &mut Reader<'_>) -> Outcome<FallbackRebasedEntryV1> {
    reader.fixed(&[0x82])?;
    let entry_key = reader.text()?;
    let implementation_digest = reader.hash()?;
    FallbackRebasedEntryV1::new(entry_key, implementation_digest)
}

type Transition = (ImplementationKeyV1, ImplementationKeyV1, Vec<FallbackSkippedCandidateV1>);
type TriggerFields = (FallbackTriggerCodeV1, FallbackTriggerBasisV1, u64);

fn read_activated(reader: &mut Reader<'_>) -> Outcome<FallbackActivatedPayloadV1> {
    let (scope, policy_digest) = read_head(reader, 0x8a)?;
    let entry_key = reader.text()?;
    let closing_tenure_ordinal = reader.unsigned()?;
    read_activated_tail(reader).and_then(|((from, to, skipped), trigger)| {
        FallbackActivatedPayloadV1::new(FallbackActivatedInputV1 {
            scope,
            policy_digest,
            entry_key,
            closing_tenure_ordinal,
            from,
            to,
            skipped,
            trigger_code: trigger.0,
            trigger_basis: trigger.1,
            activation_ordinal: trigger.2,
        })
    })
}

fn read_activated_tail(reader: &mut Reader<'_>) -> Outcome<(Transition, TriggerFields)> {
    let from = read_implementation_bytes(reader)?;
    let to = read_implementation_bytes(reader)?;
    let skipped = reader.list(SKIPPED_MAX, Field::Skipped, read_skipped)?;
    Ok(((from, to, skipped), read_trigger(reader)?))
}

fn read_implementation_bytes(reader: &mut Reader<'_>) -> Outcome<ImplementationKeyV1> {
    let bytes = reader.blob(2)?;
    ImplementationKeyV1::from_canonical_cbor(bytes)
}

fn read_skipped(reader: &mut Reader<'_>) -> Outcome<FallbackSkippedCandidateV1> {
    reader.fixed(&[0x82])?;
    let implementation_digest = reader.hash()?;
    let reason = reader.lookup(Reason::from_code, Field::SkipReason)?;
    Ok(FallbackSkippedCandidateV1 {
        implementation_digest,
        reason,
    })
}

fn read_trigger(reader: &mut Reader<'_>) -> Outcome<TriggerFields> {
    let code = reader.lookup(Trigger::from_code, Field::TriggerCode)?;
    let basis = read_basis(reader)?;
    Ok((code, basis, reader.unsigned()?))
}

fn read_basis(reader: &mut Reader<'_>) -> Outcome<FallbackTriggerBasisV1> {
    reader.fixed(&[0x43])?;
    let bytes = reader.take(3)?;
    let origin = Origin::from_code(bytes[2]).ok_or(Field::TriggerOrigin);
    Ok(FallbackTriggerBasisV1 {
        cause: u16::from_be_bytes([bytes[0], bytes[1]]),
        origin: origin.map_err(FallbackRecordErrorV1::InvalidField)?,
    })
}
