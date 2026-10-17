//! ADR-119 explicit domain fallback records and Event payload codecs.
//!
//! This module holds the canonical, deterministic-CBOR records of ADR-119
//! section 4.1 and the declaration and activation Event payloads of section
//! 4.3: IMK1 (implementation key), PPN1 (pin), DFP1 (domain fallback policy),
//! `pigloros.composition.fallback-declared` and
//! `pigloros.composition.fallback-activated`. It validates structure and bounds
//! only. It authorizes, admits, declares and activates nothing.
//!
//! V1 covers community entries only. A native implementation key is future
//! work (ADR-119 section 4.8) and has no variant here.

use self::FallbackFieldV1 as Field;
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, CborReadError, Hash};
use std::collections::BTreeSet;

mod payload;
mod policy;

pub use payload::{
    FallbackActivatedInputV1, FallbackActivatedPayloadV1, FallbackDeclaredPayloadV1,
    FallbackRebasedEntryV1, FallbackSkippedCandidateV1, FallbackTriggerBasisV1,
};
pub use policy::{DomainFallbackPolicyV1, FallbackEntryV1};

/// Reserved Event type of the ADR-119 declaration Event, schema version 1.
pub const COMPOSITION_FALLBACK_DECLARED_EVENT_TYPE_V1: &str =
    "pigloros.composition.fallback-declared";
/// Reserved Event type of the ADR-119 activation Event, schema version 1.
pub const COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1: &str =
    "pigloros.composition.fallback-activated";

/// BLAKE3 domain of `imk1_digest`, including its terminating zero byte.
pub const IMPLEMENTATION_KEY_DIGEST_DOMAIN_V1: &[u8] =
    b"PiglorOS.Composition.ImplementationKey.v1\0";
/// BLAKE3 domain of the PPN1 `pin_digest`, including its terminating zero byte.
pub const COMPOSITION_PIN_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.Composition.Pin.v1\0";
/// BLAKE3 domain of the DFP1 `policy_digest`, including its terminating zero byte.
pub const FALLBACK_POLICY_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.Composition.FallbackPolicy.v1\0";

/// Maximum UTF-8 byte length of an IMK1 `plugin_id_text`.
pub const MAX_FALLBACK_PLUGIN_ID_BYTES_V1: usize = 128;
/// Maximum UTF-8 byte length of an IMK1 `version_text`.
pub const MAX_FALLBACK_VERSION_BYTES_V1: usize = 64;
/// Maximum UTF-8 byte length of one PPN1 role.
pub const MAX_FALLBACK_ROLE_BYTES_V1: usize = 64;
/// Maximum number of roles in one PPN1.
pub const MAX_FALLBACK_ROLES_V1: usize = 16;
/// Maximum byte length of an entry key (an ADR-088 stable slot).
pub const MAX_FALLBACK_ENTRY_KEY_BYTES_V1: usize = 64;
/// Maximum UTF-8 byte length of a composition scope.
pub const MAX_FALLBACK_SCOPE_BYTES_V1: usize = 128;
/// Maximum number of candidates of one entry (the V1 chain length).
pub const MAX_FALLBACK_CANDIDATES_V1: usize = 2;
/// Maximum number of entries in one DFP1.
pub const MAX_FALLBACK_ENTRIES_V1: usize = 32;
/// Maximum number of skipped candidates in one activation payload.
pub const MAX_FALLBACK_SKIPPED_V1: usize = 2;
/// Maximum canonical size of one IMK1.
pub const MAX_IMPLEMENTATION_KEY_BYTES_V1: usize = 237;
/// Maximum canonical size of one PPN1.
pub const MAX_COMPOSITION_PIN_BYTES_V1: usize = 1_301;
/// Maximum canonical size of one `FallbackEntryV1`.
pub const MAX_FALLBACK_ENTRY_BYTES_V1: usize = 3_978;
/// Size bound checked before a DFP1 is decoded.
pub const MAX_FALLBACK_POLICY_BYTES_V1: usize = 135_168;
/// Size bound of one declaration or activation Event payload (EBP1).
pub const MAX_FALLBACK_EVENT_PAYLOAD_BYTES_V1: usize = 4_096;

const PLUGIN_ID_MAX: usize = MAX_FALLBACK_PLUGIN_ID_BYTES_V1;
const VERSION_MAX: usize = MAX_FALLBACK_VERSION_BYTES_V1;
const ROLE_MAX: usize = MAX_FALLBACK_ROLE_BYTES_V1;
const ROLES_MAX: usize = MAX_FALLBACK_ROLES_V1;
const ENTRY_KEY_MAX: usize = MAX_FALLBACK_ENTRY_KEY_BYTES_V1;
const SCOPE_MAX: usize = MAX_FALLBACK_SCOPE_BYTES_V1;

type Outcome<T> = Result<T, FallbackRecordErrorV1>;

const IMK1_HEADER: [u8; 7] = [0x85, 0x44, b'I', b'M', b'K', b'1', 0x01];
const PPN1_HEADER: [u8; 7] = [0x84, 0x44, b'P', b'P', b'N', b'1', 0x01];

/// The record field an ADR-119 record refuses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackFieldV1 {
    /// The IMK1 `plugin_id_text`.
    PluginId,
    /// The IMK1 `version_text`, or a registered version that differs from it.
    Version,
    /// A registered pin `configuration_digest` that differs from the release digest.
    ConfigurationDigest,
    /// The PPN1 roles: count, length or uniqueness.
    Roles,
    /// An entry key.
    EntryKey,
    /// The candidate list of one entry.
    Candidates,
    /// The trigger list of one entry.
    Triggers,
    /// The activation mode of one entry.
    ActivationMode,
    /// Two implementations of one policy share a `plugin_id_text`.
    Distinctness,
    /// The composition scope.
    Scope,
    /// The DFP1 entry list: count or order.
    Entries,
    /// The declaration payload `rebased` list: count or order.
    Rebased,
    /// The activation payload `skipped` list.
    Skipped,
    /// A skipped candidate's reason code.
    SkipReason,
    /// The activation payload `trigger_code`.
    TriggerCode,
    /// The origin byte of the activation payload `trigger_basis`.
    TriggerOrigin,
    /// The activation `from` and `to` implementations name one Plugin.
    Implementation,
}

/// Closed failures of the ADR-119 record codecs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FallbackRecordErrorV1 {
    /// Wrong CBOR shape, field type, magic or version, or truncated input.
    #[error("invalid ADR-119 record encoding")]
    InvalidEncoding,
    /// A nonpreferred CBOR width, or trailing bytes.
    #[error("noncanonical ADR-119 record encoding")]
    NonCanonical,
    /// The input exceeds the record's byte bound.
    #[error("ADR-119 record exceeds its byte bound")]
    TooLarge,
    /// A field is outside its bound or breaks a record rule.
    #[error("invalid ADR-119 record field {0:?}")]
    InvalidField(FallbackFieldV1),
    /// The DFP1 `policy_digest` is not the digest of fields 0 to 4.
    #[error("DFP1 policy digest does not match its fields")]
    PolicyDigestMismatch,
}

/// The trigger codes of ADR-119 section 4.2.
///
/// Which codes a host treats as eligible is a runtime decision; this type only
/// names the closed V1 code set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FallbackTriggerCodeV1 {
    /// Code 1: `MissingImplementation` during restart composition.
    MissingImplementation = 1,
    /// Code 2: `ComponentTrap`.
    ComponentTrap = 2,
    /// Code 3: an authoritative fuel, memory, host-call or output limit.
    ResourceLimit = 3,
    /// Code 4: `ArtifactRevoked`.
    ArtifactRevoked = 4,
    /// Code 5: `WorkerCrashed`.
    WorkerCrashed = 5,
}

impl FallbackTriggerCodeV1 {
    /// Every V1 trigger code, in ascending code order.
    pub const ALL: [Self; 5] = [
        Self::MissingImplementation,
        Self::ComponentTrap,
        Self::ResourceLimit,
        Self::ArtifactRevoked,
        Self::WorkerCrashed,
    ];

    /// Return the wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return the trigger with this wire code, if V1 defines one.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.code() == code)
    }
}

/// The DFP1 `activation_mode` of one entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FallbackActivationModeV1 {
    /// The host activates the next candidate on an eligible trigger.
    Automatic = 0,
    /// Only an owner action activates a candidate.
    Manual = 1,
}

impl FallbackActivationModeV1 {
    /// Every V1 activation mode, in ascending code order.
    pub const ALL: [Self; 2] = [Self::Automatic, Self::Manual];

    /// Return the wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return the mode with this wire code, if V1 defines one.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.code() == code)
    }
}

/// Who started one activation, the origin byte of `trigger_basis`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FallbackActivationOriginV1 {
    /// The host's automatic mode.
    Automatic = 0,
    /// An owner action (`composition.fallback.activate`).
    Owner = 1,
}

impl FallbackActivationOriginV1 {
    /// Every V1 origin, in ascending code order.
    pub const ALL: [Self; 2] = [Self::Automatic, Self::Owner];

    /// Return the wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return the origin with this wire code, if V1 defines one.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.code() == code)
    }
}

/// Why the CBT skipped one candidate, the `reason_u8` of `skipped`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FallbackSkipReasonV1 {
    /// `evaluate_current_release` refused the release (revoked or untrusted).
    ReleaseNotCurrent = 1,
    /// Re-verification of the section 4.1 facts failed.
    FactsMismatch = 2,
    /// The release source is missing or unreadable (`SourceUnavailable`).
    SourceUnavailable = 3,
    /// The candidate's member, handle or worker could not be built.
    MemberBuildFailed = 4,
    /// The dry-run `prepare` refused the candidate.
    PrepareRefused = 5,
    /// `validate_swap` refused the candidate, including its prefix read.
    SwapRefused = 6,
}

impl FallbackSkipReasonV1 {
    /// Every V1 skip reason, in ascending code order.
    pub const ALL: [Self; 6] = [
        Self::ReleaseNotCurrent,
        Self::FactsMismatch,
        Self::SourceUnavailable,
        Self::MemberBuildFailed,
        Self::PrepareRefused,
        Self::SwapRefused,
    ];

    /// Return the wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return the reason with this wire code, if V1 defines one.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.code() == code)
    }
}

/// IMK1, the cross-run identity of one community implementation.
///
/// `[h'494d4b31', 1, plugin_id_text, version_text, release_digest]`. The
/// version is a host-supplied label; the release digest binds the release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImplementationKeyV1 {
    plugin_id: String,
    version: String,
    release_digest: Hash,
}

impl ImplementationKeyV1 {
    /// Validate one implementation key.
    ///
    /// # Errors
    /// Returns `InvalidField(PluginId)` or `InvalidField(Version)` when a text
    /// field is empty or over its byte bound.
    pub fn new(
        plugin_id: String,
        version: String,
        release_digest: Hash,
    ) -> Result<Self, FallbackRecordErrorV1> {
        check_text(&plugin_id, PLUGIN_ID_MAX, Field::PluginId)?;
        check_text(&version, VERSION_MAX, Field::Version)?;
        Ok(Self {
            plugin_id,
            version,
            release_digest,
        })
    }

    /// Return the PMF1 Plugin ID text.
    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    /// Return the host-supplied version label.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Return the admitted release digest.
    #[must_use]
    pub const fn release_digest(&self) -> Hash {
        self.release_digest
    }

    /// Encode the unique preferred IMK1 CBOR record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_IMPLEMENTATION_KEY_BYTES_V1);
        self.write(&mut out);
        out
    }

    /// Return `imk1_digest`, BLAKE3 over the IMK1 domain and the record.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let bytes = self.to_canonical_cbor();
        domain_digest(IMPLEMENTATION_KEY_DIGEST_DOMAIN_V1, &bytes)
    }

    /// Decode bounded preferred IMK1 bytes and recheck their canonical form.
    ///
    /// # Errors
    /// Rejects oversized, malformed, out-of-bounds, nonpreferred or trailing data.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FallbackRecordErrorV1> {
        let mut reader = Reader::open(bytes, MAX_IMPLEMENTATION_KEY_BYTES_V1)?;
        let key = read_implementation(&mut reader)?;
        reader.finish(bytes, &key.to_canonical_cbor())?;
        Ok(key)
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&IMK1_HEADER);
        write_text(out, &self.plugin_id);
        write_text(out, &self.version);
        encode_hash(out, self.release_digest);
    }
}

/// PPN1, the pin of one community implementation.
///
/// `[h'50504e31', 1, imk1, roles]` with 1 to 16 unique roles of 1 to 64 bytes.
/// Building a pin is the fallible step of PPN1 encoding: a `PluginPinV1` whose
/// roles exceed these bounds has no PPN1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositionPinV1 {
    implementation: ImplementationKeyV1,
    roles: Vec<String>,
}

impl CompositionPinV1 {
    /// Validate one pin. Role order is kept as given.
    ///
    /// # Errors
    /// Returns `InvalidField(Roles)` for no roles, more than 16, an empty or
    /// over-long role, or a repeated role.
    pub fn new(
        implementation: ImplementationKeyV1,
        roles: Vec<String>,
    ) -> Result<Self, FallbackRecordErrorV1> {
        require(valid_roles(&roles), Field::Roles)?;
        Ok(Self {
            implementation,
            roles,
        })
    }

    /// Return the pinned implementation key.
    #[must_use]
    pub const fn implementation(&self) -> &ImplementationKeyV1 {
        &self.implementation
    }

    /// Return the roles in their authoritative order.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Encode the unique preferred PPN1 CBOR record.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_COMPOSITION_PIN_BYTES_V1);
        self.write(&mut out);
        out
    }

    /// Return `pin_digest`, BLAKE3 over the PPN1 domain and the record.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let bytes = self.to_canonical_cbor();
        domain_digest(COMPOSITION_PIN_DIGEST_DOMAIN_V1, &bytes)
    }

    /// Decode bounded preferred PPN1 bytes and recheck their canonical form.
    ///
    /// # Errors
    /// Rejects oversized, malformed, out-of-bounds, nonpreferred or trailing data.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, FallbackRecordErrorV1> {
        let mut reader = Reader::open(bytes, MAX_COMPOSITION_PIN_BYTES_V1)?;
        let pin = read_pin(&mut reader)?;
        reader.finish(bytes, &pin.to_canonical_cbor())?;
        Ok(pin)
    }

    fn plugin_id(&self) -> &str {
        self.implementation.plugin_id()
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&PPN1_HEADER);
        self.implementation.write(out);
        encode_head(out, 4, self.roles.len() as u64);
        for role in &self.roles {
            write_text(out, role);
        }
    }
}

/// The bounded reader shared by every ADR-119 decoder.
struct Reader<'a> {
    cursor: CborCursor<'a>,
}

impl<'a> Reader<'a> {
    const fn open(bytes: &'a [u8], maximum: usize) -> Outcome<Self> {
        if bytes.len() > maximum {
            return Err(FallbackRecordErrorV1::TooLarge);
        }
        Ok(Self {
            cursor: CborCursor::new(bytes),
        })
    }

    fn finish(&self, bytes: &[u8], encoded: &[u8]) -> Outcome<()> {
        if self.cursor.is_finished() && encoded == bytes {
            Ok(())
        } else {
            Err(FallbackRecordErrorV1::NonCanonical)
        }
    }

    fn fixed(&mut self, expected: &[u8]) -> Outcome<()> {
        self.cursor.fixed(expected).map_err(encoding)
    }

    fn unsigned(&mut self) -> Outcome<u64> {
        self.cursor.head(0).map_err(encoding)
    }

    fn take(&mut self, length: usize) -> Outcome<&'a [u8]> {
        self.cursor.take(length).map_err(encoding)
    }

    fn lookup<T>(&mut self, decode: fn(u8) -> Option<T>, field: FallbackFieldV1) -> Outcome<T> {
        self.unsigned()
            .map(|value| u8::try_from(value).unwrap_or(u8::MAX))
            .and_then(|code| decode(code).ok_or(invalid(field)))
    }

    fn count(&mut self, maximum: usize, field: FallbackFieldV1) -> Outcome<usize> {
        let length = to_length(self.cursor.head(4).map_err(encoding)?);
        require(length <= maximum, field)?;
        Ok(length)
    }

    fn blob(&mut self, major: u8) -> Outcome<&'a [u8]> {
        let length = to_length(self.cursor.head(major).map_err(encoding)?);
        self.cursor.take(length).map_err(encoding)
    }

    fn text(&mut self) -> Outcome<String> {
        let bytes = self.blob(3)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .or(Err(FallbackRecordErrorV1::InvalidEncoding))
    }

    fn hash(&mut self) -> Outcome<Hash> {
        self.fixed(&[0x58, 0x20])?;
        self.cursor.take(32).map(hash_from_slice).map_err(encoding)
    }

    fn optional_hash(&mut self) -> Outcome<Option<Hash>> {
        if self.cursor.consume_if(0xf6) {
            Ok(None)
        } else {
            self.hash().map(Some)
        }
    }

    fn list<T>(
        &mut self,
        maximum: usize,
        field: FallbackFieldV1,
        item: fn(&mut Self) -> Outcome<T>,
    ) -> Outcome<Vec<T>> {
        self.count(maximum, field)
            .and_then(|count| (0..count).map(|_| item(self)).collect())
    }
}

fn read_implementation(reader: &mut Reader<'_>) -> Outcome<ImplementationKeyV1> {
    reader.fixed(&IMK1_HEADER)?;
    let plugin_id = reader.text()?;
    let version = reader.text()?;
    let release_digest = reader.hash()?;
    ImplementationKeyV1::new(plugin_id, version, release_digest)
}

fn read_pin(reader: &mut Reader<'_>) -> Outcome<CompositionPinV1> {
    reader.fixed(&PPN1_HEADER)?;
    let implementation = read_implementation(reader)?;
    let roles = reader.list(ROLES_MAX, Field::Roles, Reader::text)?;
    CompositionPinV1::new(implementation, roles)
}

const fn encoding(_: CborReadError) -> FallbackRecordErrorV1 {
    FallbackRecordErrorV1::InvalidEncoding
}

const fn invalid(field: FallbackFieldV1) -> FallbackRecordErrorV1 {
    FallbackRecordErrorV1::InvalidField(field)
}

const fn require(condition: bool, field: FallbackFieldV1) -> Outcome<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(field))
    }
}

const fn text_within(text: &str, maximum: usize) -> bool {
    !text.is_empty() && text.len() <= maximum
}

const fn check_text(text: &str, maximum: usize, field: FallbackFieldV1) -> Outcome<()> {
    require(text_within(text, maximum), field)
}

fn valid_roles(roles: &[String]) -> bool {
    let names: Vec<&str> = roles.iter().map(String::as_str).collect();
    count_within(names.len(), 1, ROLES_MAX)
        && all_unique(&names)
        && names.iter().all(|role| text_within(role, ROLE_MAX))
}

fn check_entry_key(key: &str) -> Outcome<()> {
    let valid = text_within(key, ENTRY_KEY_MAX) && key.bytes().all(is_slot_byte);
    require(valid, Field::EntryKey)
}

fn count_within(count: usize, minimum: usize, maximum: usize) -> bool {
    (minimum..=maximum).contains(&count)
}

const fn is_slot_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn to_length(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn all_unique(items: &[&str]) -> bool {
    let mut seen = BTreeSet::new();
    items.iter().all(|item| seen.insert(*item))
}

fn strictly_sorted(items: &[&str]) -> bool {
    items.windows(2).all(|pair| pair[0] < pair[1])
}

fn write_text(out: &mut Vec<u8>, text: &str) {
    encode_bytes(out, text.as_bytes(), 3);
}

fn write_optional_hash(out: &mut Vec<u8>, hash: Option<Hash>) {
    match hash {
        Some(hash) => encode_hash(out, hash),
        None => out.push(0xf6),
    }
}

fn hash_from_slice(slice: &[u8]) -> Hash {
    Hash::from_bytes(<[u8; 32]>::try_from(slice).unwrap_or([0; 32]))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}
