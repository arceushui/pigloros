//! DFP1, the domain fallback policy, and its entries.

use super::{
    all_unique, check_entry_key, check_text, count_within, domain_digest, read_pin, require,
    strictly_sorted, write_optional_hash, write_text, CompositionPinV1, FallbackActivationModeV1,
    FallbackActivationModeV1 as Mode, FallbackRecordErrorV1, FallbackTriggerCodeV1,
    FallbackTriggerCodeV1 as Trigger, Field, Outcome, Reader, FALLBACK_POLICY_DIGEST_DOMAIN_V1,
    MAX_FALLBACK_CANDIDATES_V1, MAX_FALLBACK_ENTRIES_V1, MAX_FALLBACK_ENTRY_BYTES_V1,
    MAX_FALLBACK_POLICY_BYTES_V1, SCOPE_MAX,
};
use crate::{encode_hash, encode_head, Hash};

const DFP1_HEADER: [u8; 7] = [0x86, 0x44, b'D', b'F', b'P', b'1', 0x01];
const CANDIDATES_MAX: usize = MAX_FALLBACK_CANDIDATES_V1;
const ENTRIES_MAX: usize = MAX_FALLBACK_ENTRIES_V1;
const TRIGGERS_MAX: usize = FallbackTriggerCodeV1::ALL.len();

/// One DFP1 entry.
///
/// `[entry_key, primary_ppn1, candidates, triggers, activation_mode]`, with 1
/// or 2 candidates and a strictly ascending, non-empty trigger list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackEntryV1 {
    entry_key: String,
    primary: CompositionPinV1,
    candidates: Vec<CompositionPinV1>,
    triggers: Vec<FallbackTriggerCodeV1>,
    activation_mode: FallbackActivationModeV1,
}

impl FallbackEntryV1 {
    /// Validate one entry.
    ///
    /// # Errors
    /// Returns `InvalidField` for an invalid entry key (`EntryKey`), a
    /// candidate count outside 1 to 2 (`Candidates`), an empty or unsorted
    /// trigger list (`Triggers`), or a repeated `plugin_id_text` among the
    /// primary and its candidates (`Distinctness`).
    pub fn new(
        entry_key: String,
        primary: CompositionPinV1,
        candidates: Vec<CompositionPinV1>,
        triggers: Vec<FallbackTriggerCodeV1>,
        activation_mode: FallbackActivationModeV1,
    ) -> Result<Self, FallbackRecordErrorV1> {
        check_entry_key(&entry_key)?;
        let chain = count_within(candidates.len(), 1, CANDIDATES_MAX);
        require(chain, Field::Candidates)?;
        require(valid_triggers(&triggers), Field::Triggers)?;
        let entry = Self {
            entry_key,
            primary,
            candidates,
            triggers,
            activation_mode,
        };
        require(all_unique(&entry.plugin_ids()), Field::Distinctness)?;
        Ok(entry)
    }

    /// Return the entry key, the ADR-088 stable slot.
    #[must_use]
    pub fn entry_key(&self) -> &str {
        &self.entry_key
    }

    /// Return the primary pin.
    #[must_use]
    pub const fn primary(&self) -> &CompositionPinV1 {
        &self.primary
    }

    /// Return the candidate pins in chain order.
    #[must_use]
    pub fn candidates(&self) -> &[CompositionPinV1] {
        &self.candidates
    }

    /// Return the trigger codes in ascending order.
    #[must_use]
    pub fn triggers(&self) -> &[FallbackTriggerCodeV1] {
        &self.triggers
    }

    /// Return the activation mode.
    #[must_use]
    pub const fn activation_mode(&self) -> FallbackActivationModeV1 {
        self.activation_mode
    }

    /// Encode the unique preferred CBOR form of this entry.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_FALLBACK_ENTRY_BYTES_V1);
        self.write(&mut out);
        out
    }

    fn plugin_ids(&self) -> Vec<&str> {
        std::iter::once(&self.primary)
            .chain(&self.candidates)
            .map(CompositionPinV1::plugin_id)
            .collect()
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(0x85);
        write_text(out, &self.entry_key);
        self.primary.write(out);
        encode_head(out, 4, self.candidates.len() as u64);
        for candidate in &self.candidates {
            candidate.write(out);
        }
        encode_head(out, 4, self.triggers.len() as u64);
        for trigger in &self.triggers {
            encode_head(out, 0, u64::from(trigger.code()));
        }
        encode_head(out, 0, u64::from(self.activation_mode.code()));
    }
}

/// DFP1 (`DomainFallbackPolicyV1`), one owner-declared fallback policy.
///
/// `[h'44465031', 1, scope, entries, previous_policy_digest, policy_digest]`.
/// Zero entries is a withdrawal. `policy_digest` is BLAKE3 over the DFP1
/// domain and the five-element array of fields 0 to 4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainFallbackPolicyV1 {
    scope: String,
    entries: Vec<FallbackEntryV1>,
    previous_policy_digest: Option<Hash>,
    policy_digest: Hash,
}

impl DomainFallbackPolicyV1 {
    /// Validate one policy and compute its `policy_digest`.
    ///
    /// `previous_policy_digest` is `None` only for the first policy of a
    /// Timeline lineage; the store port enforces that rule.
    ///
    /// # Errors
    /// Returns `InvalidField` for an empty or over-long scope (`Scope`), more
    /// than 32 entries or entries not strictly sorted by entry key (`Entries`),
    /// or a `plugin_id_text` repeated across the policy (`Distinctness`).
    pub fn new(
        scope: String,
        entries: Vec<FallbackEntryV1>,
        previous_policy_digest: Option<Hash>,
    ) -> Result<Self, FallbackRecordErrorV1> {
        check_text(&scope, SCOPE_MAX, Field::Scope)?;
        require(valid_entries(&entries), Field::Entries)?;
        require(distinct_plugins(&entries), Field::Distinctness)?;
        let mut policy = Self {
            scope,
            entries,
            previous_policy_digest,
            policy_digest: Hash::zero(),
        };
        let preimage = policy.fields(0x85);
        policy.policy_digest = domain_digest(FALLBACK_POLICY_DIGEST_DOMAIN_V1, &preimage);
        Ok(policy)
    }

    /// Return the composition scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Return the entries in ascending entry-key order.
    #[must_use]
    pub fn entries(&self) -> &[FallbackEntryV1] {
        &self.entries
    }

    /// Return the predecessor's digest, or `None` for a first policy.
    #[must_use]
    pub const fn previous_policy_digest(&self) -> Option<Hash> {
        self.previous_policy_digest
    }

    /// Return `policy_digest`.
    #[must_use]
    pub const fn policy_digest(&self) -> Hash {
        self.policy_digest
    }

    /// Return whether this policy withdraws its predecessor (zero entries).
    #[must_use]
    pub const fn is_withdrawal(&self) -> bool {
        self.entries.is_empty()
    }

    /// Encode the unique preferred six-field DFP1 CBOR record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = self.fields(0x86);
        encode_hash(&mut out, self.policy_digest);
        out
    }

    /// Decode bounded preferred DFP1 bytes and recheck digest and canonical form.
    ///
    /// The byte bound is checked before anything is decoded.
    ///
    /// # Errors
    /// Rejects oversized, malformed, out-of-bounds, nonpreferred or trailing
    /// data, and returns `PolicyDigestMismatch` for a wrong `policy_digest`.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FallbackRecordErrorV1> {
        let mut reader = Reader::open(bytes, MAX_FALLBACK_POLICY_BYTES_V1)?;
        let policy = read_policy(&mut reader)?;
        reader.finish(bytes, &policy.to_canonical_cbor())?;
        Ok(policy)
    }

    fn fields(&self, array_header: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.push(array_header);
        out.extend_from_slice(&DFP1_HEADER[1..]);
        write_text(&mut out, &self.scope);
        encode_head(&mut out, 4, self.entries.len() as u64);
        for entry in &self.entries {
            entry.write(&mut out);
        }
        write_optional_hash(&mut out, self.previous_policy_digest);
        out
    }
}

fn valid_triggers(triggers: &[FallbackTriggerCodeV1]) -> bool {
    let codes: Vec<u8> = triggers.iter().copied().map(Trigger::code).collect();
    !codes.is_empty() && codes.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_entries(entries: &[FallbackEntryV1]) -> bool {
    let keys: Vec<&str> = entries.iter().map(FallbackEntryV1::entry_key).collect();
    entries.len() <= MAX_FALLBACK_ENTRIES_V1 && strictly_sorted(&keys)
}

fn distinct_plugins(entries: &[FallbackEntryV1]) -> bool {
    let ids: Vec<&str> = entries
        .iter()
        .flat_map(FallbackEntryV1::plugin_ids)
        .collect();
    all_unique(&ids)
}

fn read_policy(reader: &mut Reader<'_>) -> Outcome<DomainFallbackPolicyV1> {
    reader.fixed(&DFP1_HEADER)?;
    let scope = reader.text()?;
    let entries = reader.list(ENTRIES_MAX, Field::Entries, read_entry)?;
    let previous = reader.optional_hash()?;
    DomainFallbackPolicyV1::new(scope, entries, previous)
        .and_then(|policy| check_policy_digest(reader, policy))
}

fn check_policy_digest(
    reader: &mut Reader<'_>,
    policy: DomainFallbackPolicyV1,
) -> Outcome<DomainFallbackPolicyV1> {
    if reader.hash()? == policy.policy_digest {
        Ok(policy)
    } else {
        Err(FallbackRecordErrorV1::PolicyDigestMismatch)
    }
}

fn read_entry(reader: &mut Reader<'_>) -> Outcome<FallbackEntryV1> {
    reader.fixed(&[0x85])?;
    let entry_key = reader.text()?;
    let primary = read_pin(reader)?;
    let candidates = reader.list(CANDIDATES_MAX, Field::Candidates, read_pin)?;
    read_entry_tail(reader, entry_key, primary, candidates)
}

fn read_entry_tail(
    reader: &mut Reader<'_>,
    entry_key: String,
    primary: CompositionPinV1,
    candidates: Vec<CompositionPinV1>,
) -> Outcome<FallbackEntryV1> {
    let triggers = reader.list(TRIGGERS_MAX, Field::Triggers, read_trigger)?;
    let mode = reader.lookup(Mode::from_code, Field::ActivationMode)?;
    FallbackEntryV1::new(entry_key, primary, candidates, triggers, mode)
}

fn read_trigger(reader: &mut Reader<'_>) -> Outcome<FallbackTriggerCodeV1> {
    reader.lookup(Trigger::from_code, Field::Triggers)
}
