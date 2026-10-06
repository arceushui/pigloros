//! Canonical ADR-088 MPR1 Plugin roster codec, without any owner authority.
//!
//! A decoded roster is only a structurally valid, canonical value. It cannot
//! show that an actual owner admitted these Plugins, that the closure bytes
//! are retained, or that a cut selected this roster.
//!
//! # Stable slots
//!
//! A stable slot is the opaque, host-authored name of one Plugin position in
//! the composition. It is 1-64 ASCII bytes drawn from `A-Z a-z 0-9 . _ -`.
//! The host chooses it, so it stays the same when fresh runs allocate fresh
//! `PluginId`s. It must hold no participant, secret or other private text:
//! it is stored and compared in the clear. Slots are unique and rows are
//! ordered by their raw bytes.
//!
//! # Not a cross-run key
//!
//! MPR1 is a canonical per-run encoding, not a cross-run equality key: fresh
//! `PluginId`s, EOP1 digests and closure bytes may differ between runs that
//! still match under the typed slot-aligned comparison. Neither MPR1 byte
//! equality nor a hash over these bytes is the cross-run matching rule.
//!
//! # Example
//!
//! Two Plugins may share a display name; their `PluginId`s, digests and
//! closures stay distinct. `ManifestPluginRosterV1::new` accepts entries in
//! any order and sorts them by slot.
//!
//! ```text
//! let id = |byte| PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]));
//! let first = ManifestPluginEntryV1::new(
//!     "sensor.b", id(2), "Sensor", "1.0.0", Hash::from_bytes([2; 32]), vec![2],
//! )?;
//! let second = ManifestPluginEntryV1::new(
//!     "sensor.a", id(1), "Sensor", "1.0.0", Hash::from_bytes([1; 32]), vec![1],
//! )?;
//! let roster = ManifestPluginRosterV1::new(vec![first, second])?;
//! let bytes = roster.to_canonical_cbor();
//! assert_eq!(ManifestPluginRosterV1::from_canonical_cbor(&bytes)?, roster);
//! ```

use std::{collections::HashSet, fmt, sync::Arc};

use crate::{
    retention::MAX_WORLD_RETENTION_RECORD_BYTES_V1, Hash, PluginId, MAX_MANIFEST_OWNER_PLUGINS_V1,
};

/// Maximum entries in one MPR1 roster.
pub const MAX_MANIFEST_PLUGIN_ROSTER_ENTRIES_V1: usize = MAX_MANIFEST_OWNER_PLUGINS_V1;
/// Fixed upper bound on one roster's checked maximum encoded size, 1 GiB.
///
/// The cap is the checked sum of each entry's worst-case encoded size, so a
/// roster of 256 maximum-size closures (about 1.28 GiB) cannot be represented
/// by design; roughly 200 maximum-size entries fit. Decoding rejects any input
/// longer than this before parsing or copying anything.
pub const MAX_MANIFEST_PLUGIN_ROSTER_BYTES_V1: usize = 1 << 30;
/// Native OPC1 maximum for one retained closure envelope.
///
/// This mirrors `pos_runtime::MAX_OUTPUT_POLICY_CLOSURE_BYTES_V1`, which
/// `pos-core` cannot import; `pos-runtime` asserts equality at compile time.
pub const MAX_MANIFEST_PLUGIN_CLOSURE_BYTES_V1: usize =
    2 * 65_536 + 2 * (2 * 1_048_576) + 1_048_576 + MAX_WORLD_RETENTION_RECORD_BYTES_V1 + 4 + 6 * 8;

// Rendered rule for `ClosureBytes`; the public tests pin it to the constant.
const CLOSURE_RULE: &str = "closure_bytes must be at most 5374516 bytes (the native OPC1 maximum)";
const INVALID: ManifestPluginRosterErrorV1 = ManifestPluginRosterErrorV1::InvalidEncoding;
const MAGIC: &[u8; 4] = b"MPR1";
const MAX_SLOT_BYTES: usize = 64;
const MAX_NAME_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 64;
// Array head, magic string and entry-count head, each at its widest.
const ROSTER_FRAMING_MAX_BYTES: usize = 1 + 5 + 9;
// Array head, four variable heads at their widest, 16-byte id, 32-byte digest.
// The cap uses this widest-head framing, so a canonical roster within about
// 256 x 30 bytes of the cap can be rejected.
const ENTRY_FRAMING_MAX_BYTES: usize = 1 + 4 * 9 + 17 + 34;

/// An entry field whose bound an error refers to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestPluginFieldV1 {
    /// The mandatory display name.
    PluginName,
    /// The exact registered version.
    PluginVersion,
    /// The EOP1 digest.
    Eop1Digest,
    /// The retained OPC1 closure bytes.
    ClosureBytes,
}

impl fmt::Display for ManifestPluginFieldV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PluginName => formatter.write_str("plugin_name must be 1-128 UTF-8 bytes"),
            Self::PluginVersion => formatter.write_str("plugin_version must be 1-64 UTF-8 bytes"),
            Self::Eop1Digest => formatter.write_str("eop1_digest must not be all zero"),
            Self::ClosureBytes => formatter.write_str(CLOSURE_RULE),
        }
    }
}

/// Closed structural errors; none grants or denies native owner authority.
///
/// Messages say what to change. Variants carry at most a stable slot, never
/// closure bytes or other entry contents.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManifestPluginRosterErrorV1 {
    /// The bytes are not one well-formed definite CBOR MPR1 roster shape.
    #[error(
        "invalid MPR1 encoding: expected one definite-length CBOR roster \
         [h'4d505231', [entry, ...]] of six-field entries with no tags, maps, floats or \
         trailing bytes"
    )]
    InvalidEncoding,
    /// The bytes decode to a valid roster but are not its exact preferred form.
    #[error(
        "noncanonical MPR1 encoding: use shortest-form integers and lengths, or re-encode \
         with to_canonical_cbor"
    )]
    NonCanonical,
    /// The roster has more than 256 entries or exceeds the fixed 1 GiB cap.
    #[error("MPR1 roster too large: use at most 256 entries and at most 1073741824 bytes")]
    RosterTooLarge,
    /// Two entries carry the same stable slot.
    #[error("duplicate slot `{slot}`: give every entry a unique stable slot")]
    DuplicateSlot {
        /// The repeated slot.
        slot: String,
    },
    /// Two entries carry the same `PluginId`; `slot` is the later entry in slot order.
    #[error("duplicate PluginId at slot `{slot}`: give every entry a distinct PluginId")]
    DuplicatePluginId {
        /// The slot of the second entry using the repeated `PluginId`.
        slot: String,
    },
    /// A stable slot is not 1-64 ASCII bytes of `A-Za-z0-9._-`.
    ///
    /// When decoding an over-long slot, `slot` holds only its first 64 bytes.
    #[error(
        "invalid slot `{}`: use 1-64 ASCII bytes from A-Z a-z 0-9 . _ - (no spaces or other \
         characters)",
        .slot.escape_debug()
    )]
    InvalidSlot {
        /// The offending slot text, at most 64 bytes.
        slot: String,
    },
    /// A name, version, digest or closure length is outside its bound.
    #[error("slot `{}`: {field}", .slot.escape_debug())]
    InvalidField {
        /// The slot of the offending entry.
        slot: String,
        /// The field and the rule it broke.
        field: ManifestPluginFieldV1,
    },
    /// Decoded entries are not strictly ordered by raw stable-slot bytes.
    #[error(
        "slot `{slot}` is out of order: MPR1 requires strictly ascending raw-byte slot order \
         (ManifestPluginRosterV1::new sorts for you)"
    )]
    UnsortedSlots {
        /// The first slot that sorts before its predecessor.
        slot: String,
    },
    /// The leading magic is not exactly `MPR1`.
    #[error("unsupported MPR1 magic: the roster must start with the 4-byte string MPR1")]
    UnsupportedMagic,
}

impl ManifestPluginRosterErrorV1 {
    fn duplicate_slot(entry: &ManifestPluginEntryV1) -> Self {
        Self::DuplicateSlot {
            slot: entry.stable_slot.clone(),
        }
    }

    fn duplicate_id(entry: &ManifestPluginEntryV1) -> Self {
        Self::DuplicatePluginId {
            slot: entry.stable_slot.clone(),
        }
    }

    fn unsorted(entry: &ManifestPluginEntryV1) -> Self {
        Self::UnsortedSlots {
            slot: entry.stable_slot.clone(),
        }
    }

    fn invalid_field(slot: &str, field: ManifestPluginFieldV1) -> Self {
        Self::InvalidField {
            slot: slot.to_owned(),
            field,
        }
    }
}

/// Add `addition` bytes to a running roster-size tally, checked against 1 GiB.
///
/// # Errors
/// Returns `RosterTooLarge` on `usize` overflow or when the new total
/// exceeds `MAX_MANIFEST_PLUGIN_ROSTER_BYTES_V1`.
pub const fn checked_manifest_plugin_roster_size_v1(
    current: usize,
    addition: usize,
) -> Result<usize, ManifestPluginRosterErrorV1> {
    match current.checked_add(addition) {
        Some(total) if total <= MAX_MANIFEST_PLUGIN_ROSTER_BYTES_V1 => Ok(total),
        _ => Err(ManifestPluginRosterErrorV1::RosterTooLarge),
    }
}

/// One validated MPR1 row for one admitted Plugin.
///
/// It has no `Serialize`/`Deserialize` impl: the only decoder is
/// [`ManifestPluginRosterV1::from_canonical_cbor`]. `Debug` redacts closure
/// bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ManifestPluginEntryV1 {
    stable_slot: String,
    plugin_id: PluginId,
    plugin_name: String,
    plugin_version: String,
    eop1_digest: Hash,
    closure_bytes: Arc<[u8]>,
}

impl fmt::Debug for ManifestPluginEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManifestPluginEntryV1")
            .field("stable_slot", &self.stable_slot)
            .field("plugin_id", &self.plugin_id)
            .field("plugin_name", &self.plugin_name)
            .field("plugin_version", &self.plugin_version)
            .field("eop1_digest", &self.eop1_digest)
            .field("closure_len", &self.closure_bytes.len())
            .finish()
    }
}

impl ManifestPluginEntryV1 {
    /// Validate and build one entry; roster-wide rules apply in the roster.
    ///
    /// The slot is 1-64 ASCII bytes from `A-Za-z0-9._-`, the name is 1-128
    /// bytes, the version is 1-64 bytes, the EOP1 digest is nonzero and the
    /// closure is at most `MAX_MANIFEST_PLUGIN_CLOSURE_BYTES_V1` bytes. Text
    /// and closure arguments accept anything convertible, such as `&str` and
    /// `Vec<u8>`.
    ///
    /// # Errors
    /// `InvalidSlot` for a bad slot; `InvalidField` names the slot and the
    /// name, version, digest or closure bound that failed.
    pub fn new(
        stable_slot: impl Into<String>,
        plugin_id: PluginId,
        plugin_name: impl Into<String>,
        plugin_version: impl Into<String>,
        eop1_digest: Hash,
        closure_bytes: impl Into<Arc<[u8]>>,
    ) -> Result<Self, ManifestPluginRosterErrorV1> {
        let stable_slot = stable_slot.into();
        let plugin_name = plugin_name.into();
        let plugin_version = plugin_version.into();
        let closure_bytes = closure_bytes.into();
        if !valid_slot(&stable_slot) {
            return Err(ManifestPluginRosterErrorV1::InvalidSlot { slot: stable_slot });
        }
        let field = if !(1..=MAX_NAME_BYTES).contains(&plugin_name.len()) {
            Some(ManifestPluginFieldV1::PluginName)
        } else if !(1..=MAX_VERSION_BYTES).contains(&plugin_version.len()) {
            Some(ManifestPluginFieldV1::PluginVersion)
        } else if eop1_digest == Hash::zero() {
            Some(ManifestPluginFieldV1::Eop1Digest)
        } else if closure_bytes.len() > MAX_MANIFEST_PLUGIN_CLOSURE_BYTES_V1 {
            Some(ManifestPluginFieldV1::ClosureBytes)
        } else {
            None
        };
        if let Some(field) = field {
            let error = ManifestPluginRosterErrorV1::invalid_field(&stable_slot, field);
            return Err(error);
        }
        Ok(Self {
            stable_slot,
            plugin_id,
            plugin_name,
            plugin_version,
            eop1_digest,
            closure_bytes,
        })
    }

    /// Opaque stable slot, unique within the roster.
    #[must_use]
    pub const fn stable_slot(&self) -> &str {
        self.stable_slot.as_str()
    }

    /// Run-local Plugin identity, unique within the roster.
    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    /// Display name; duplicates across entries are permitted.
    #[must_use]
    pub const fn plugin_name(&self) -> &str {
        self.plugin_name.as_str()
    }

    /// Exact registered Plugin version.
    #[must_use]
    pub const fn plugin_version(&self) -> &str {
        self.plugin_version.as_str()
    }

    /// ADR-077 digest of this Plugin's exact EOP1; not a cross-run key.
    #[must_use]
    pub const fn eop1_digest(&self) -> Hash {
        self.eop1_digest
    }

    /// Exact retained OPC1 envelope bytes, unverified by this crate.
    ///
    /// An empty closure is allowed: the ADR gives only an upper bound.
    #[must_use]
    pub fn closure_bytes(&self) -> &[u8] {
        &self.closure_bytes
    }

    fn maximum_encoded_len(&self) -> usize {
        ENTRY_FRAMING_MAX_BYTES
            + self.stable_slot.len()
            + self.plugin_name.len()
            + self.plugin_version.len()
            + self.closure_bytes.len()
    }

    fn write_cbor(&self, out: &mut Vec<u8>) {
        encode_head(out, 4, 6);
        encode_text(out, &self.stable_slot);
        encode_bytes(out, &self.plugin_id.inner().to_bytes());
        encode_text(out, &self.plugin_name);
        encode_text(out, &self.plugin_version);
        encode_bytes(out, self.eop1_digest.as_bytes());
        encode_bytes(out, &self.closure_bytes);
    }
}

/// Immutable validated MPR1 roster; it carries no owner authority.
///
/// Its bytes and hash are a per-run encoding, not a cross-run equality key.
/// It has no `Serialize`/`Deserialize` impl, so only the canonical decoder
/// can produce one from untrusted bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestPluginRosterV1 {
    entries: Vec<ManifestPluginEntryV1>,
}

impl ManifestPluginRosterV1 {
    /// The roster with no entries, valid only when no Plugin was admitted.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Build a roster from entries in any order, sorting them by raw slot bytes.
    ///
    /// Only the canonical decoder requires the input to arrive sorted.
    ///
    /// # Errors
    /// `RosterTooLarge` above 256 entries or the 1 GiB cap; `DuplicateSlot`
    /// or `DuplicatePluginId` name the repeated slot.
    pub fn new(
        mut entries: Vec<ManifestPluginEntryV1>,
    ) -> Result<Self, ManifestPluginRosterErrorV1> {
        if entries.len() > MAX_MANIFEST_PLUGIN_ROSTER_ENTRIES_V1 {
            return Err(ManifestPluginRosterErrorV1::RosterTooLarge);
        }
        entries.sort_by(|left, right| left.stable_slot.cmp(&right.stable_slot));
        check_unique_slots(&entries)?;
        check_unique_ids(&entries)?;
        check_size_cap(&entries)?;
        Ok(Self { entries })
    }

    /// Entries in strict raw stable-slot order.
    #[must_use]
    pub const fn entries(&self) -> &[ManifestPluginEntryV1] {
        self.entries.as_slice()
    }

    /// Encode exact preferred `[h'4d505231', [0*256 entry]]` MPR1 bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_head(&mut out, 4, 2);
        encode_bytes(&mut out, MAGIC);
        encode_head(&mut out, 4, self.entries.len() as u64);
        for entry in &self.entries {
            entry.write_cbor(&mut out);
        }
        out
    }

    /// Decode one complete preferred MPR1 record; the decoder stays strict.
    ///
    /// Unlike [`Self::new`], the input must already be in strict slot order.
    /// Input longer than the 1 GiB cap is rejected before anything is parsed
    /// or copied. Declared entry counts and closure lengths are bounded before
    /// any entry is copied or any slice is taken. The decoded roster is
    /// re-encoded and compared byte for byte with the input.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, oversized, duplicate, unsorted or
    /// out-of-bounds inputs with the matching closed error.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ManifestPluginRosterErrorV1> {
        checked_manifest_plugin_roster_size_v1(0, bytes.len())?;
        let mut wire = Wire::new(bytes);
        wire.array(2)?;
        wire.magic()?;
        let count = wire.entry_count()?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(wire.entry()?);
        }
        wire.finish()?;
        check_decoded_order(&entries)?;
        let roster = Self::new(entries)?;
        check_canonical(bytes, &roster.to_canonical_cbor())?;
        Ok(roster)
    }
}

fn valid_slot(slot: &str) -> bool {
    (1..=MAX_SLOT_BYTES).contains(&slot.len())
        && slot
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

// The second entry of the first adjacent pair whose slots satisfy `violates`.
fn first_violation(
    entries: &[ManifestPluginEntryV1],
    violates: impl Fn(&str, &str) -> bool,
) -> Option<&ManifestPluginEntryV1> {
    entries
        .windows(2)
        .find(|pair| violates(&pair[0].stable_slot, &pair[1].stable_slot))
        .map(|pair| &pair[1])
}

fn check_decoded_order(
    entries: &[ManifestPluginEntryV1],
) -> Result<(), ManifestPluginRosterErrorV1> {
    first_violation(entries, |left, right| left > right).map_or(Ok(()), |entry| {
        Err(ManifestPluginRosterErrorV1::unsorted(entry))
    })
}

fn check_unique_slots(
    entries: &[ManifestPluginEntryV1],
) -> Result<(), ManifestPluginRosterErrorV1> {
    first_violation(entries, |left, right| left == right).map_or(Ok(()), |entry| {
        Err(ManifestPluginRosterErrorV1::duplicate_slot(entry))
    })
}

fn check_unique_ids(entries: &[ManifestPluginEntryV1]) -> Result<(), ManifestPluginRosterErrorV1> {
    let mut seen = HashSet::with_capacity(entries.len());
    for entry in entries {
        if !seen.insert(entry.plugin_id) {
            return Err(ManifestPluginRosterErrorV1::duplicate_id(entry));
        }
    }
    Ok(())
}

fn check_size_cap(entries: &[ManifestPluginEntryV1]) -> Result<(), ManifestPluginRosterErrorV1> {
    let mut total = ROSTER_FRAMING_MAX_BYTES;
    for entry in entries {
        total = checked_manifest_plugin_roster_size_v1(total, entry.maximum_encoded_len())?;
    }
    Ok(())
}

fn bounded(declared: u64, bounds: (usize, usize)) -> Option<usize> {
    usize::try_from(declared)
        .ok()
        .filter(|length| (bounds.0..=bounds.1).contains(length))
}

fn check_canonical(bytes: &[u8], canonical: &[u8]) -> Result<(), ManifestPluginRosterErrorV1> {
    if bytes == canonical {
        Ok(())
    } else {
        Err(ManifestPluginRosterErrorV1::NonCanonical)
    }
}

fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let tag = major << 5;
    match value {
        0..=23 => out.push(tag | bytes[7]),
        24..=255 => out.extend_from_slice(&[tag | 0x18, bytes[7]]),
        256..=65_535 => {
            out.push(tag | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
        // Lengths and counts are bounded below 2^32 by the codec limits.
        _ => {
            out.push(tag | 0x1a);
            out.extend_from_slice(&bytes[4..]);
        }
    }
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn encode_text(out: &mut Vec<u8>, text: &str) {
    encode_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

// Borrow and bound-check every declared length before slicing or copying.
struct Wire<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Wire<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, ManifestPluginRosterErrorV1> {
        let byte = self.bytes.get(self.offset).copied().ok_or(INVALID)?;
        self.offset += 1;
        Ok(byte)
    }

    // Accept any definite head width; the final re-encode compare rejects
    // non-preferred forms. Indefinite and reserved additional info reject.
    fn head(&mut self, major: u8) -> Result<u64, ManifestPluginRosterErrorV1> {
        let first = self.byte()?;
        if first >> 5 != major {
            return Err(INVALID);
        }
        let additional = first & 0x1f;
        if additional < 24 {
            return Ok(u64::from(additional));
        }
        let width = match additional {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(INVALID),
        };
        let mut value = 0_u64;
        for _ in 0..width {
            value = (value << 8) | u64::from(self.byte()?);
        }
        Ok(value)
    }

    fn array(&mut self, expected: u64) -> Result<(), ManifestPluginRosterErrorV1> {
        if self.head(4)? == expected {
            Ok(())
        } else {
            Err(INVALID)
        }
    }

    fn length(
        &mut self,
        major: u8,
        bounds: (usize, usize),
    ) -> Result<Option<usize>, ManifestPluginRosterErrorV1> {
        Ok(bounded(self.head(major)?, bounds))
    }

    fn slice(&mut self, length: usize) -> Result<&'a [u8], ManifestPluginRosterErrorV1> {
        if length > self.bytes.len() - self.offset {
            return Err(INVALID);
        }
        let start = self.offset;
        self.offset += length;
        Ok(&self.bytes[start..self.offset])
    }

    fn utf8(&mut self, length: usize) -> Result<&'a str, ManifestPluginRosterErrorV1> {
        std::str::from_utf8(self.slice(length)?).map_err(|_| INVALID)
    }

    fn magic(&mut self) -> Result<(), ManifestPluginRosterErrorV1> {
        let error = ManifestPluginRosterErrorV1::UnsupportedMagic;
        let Some(length) = self.length(2, (MAGIC.len(), MAGIC.len()))? else {
            return Err(error);
        };
        if self.slice(length)? == MAGIC {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn entry_count(&mut self) -> Result<usize, ManifestPluginRosterErrorV1> {
        self.length(4, (0, MAX_MANIFEST_PLUGIN_ROSTER_ENTRIES_V1))?
            .ok_or(ManifestPluginRosterErrorV1::RosterTooLarge)
    }

    // An out-of-bounds slot length is reported with at most its first 64 bytes.
    fn slot(&mut self) -> Result<String, ManifestPluginRosterErrorV1> {
        let declared = self.head(3)?;
        let Some(length) = bounded(declared, (1, MAX_SLOT_BYTES)) else {
            let rest = &self.bytes[self.offset..];
            let shown = usize::try_from(declared)
                .unwrap_or(usize::MAX)
                .min(MAX_SLOT_BYTES)
                .min(rest.len());
            let slot = String::from_utf8_lossy(&rest[..shown]).into_owned();
            return Err(ManifestPluginRosterErrorV1::InvalidSlot { slot });
        };
        self.utf8(length).map(str::to_owned)
    }

    fn field_text(
        &mut self,
        maximum: usize,
        slot: &str,
        field: ManifestPluginFieldV1,
    ) -> Result<&'a str, ManifestPluginRosterErrorV1> {
        let Some(length) = self.length(3, (1, maximum))? else {
            return Err(ManifestPluginRosterErrorV1::invalid_field(slot, field));
        };
        self.utf8(length)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ManifestPluginRosterErrorV1> {
        let Some(length) = self.length(2, (N, N))? else {
            return Err(INVALID);
        };
        let mut out = [0; N];
        out.copy_from_slice(self.slice(length)?);
        Ok(out)
    }

    fn closure(&mut self, slot: &str) -> Result<&'a [u8], ManifestPluginRosterErrorV1> {
        let field = ManifestPluginFieldV1::ClosureBytes;
        let Some(length) = self.length(2, (0, MAX_MANIFEST_PLUGIN_CLOSURE_BYTES_V1))? else {
            return Err(ManifestPluginRosterErrorV1::invalid_field(slot, field));
        };
        self.slice(length)
    }

    fn entry(&mut self) -> Result<ManifestPluginEntryV1, ManifestPluginRosterErrorV1> {
        self.array(6)?;
        let stable_slot = self.slot()?;
        let plugin_id = self.fixed::<16>()?;
        let name_field = ManifestPluginFieldV1::PluginName;
        let plugin_name = self.field_text(MAX_NAME_BYTES, &stable_slot, name_field)?;
        let version_field = ManifestPluginFieldV1::PluginVersion;
        let plugin_version = self.field_text(MAX_VERSION_BYTES, &stable_slot, version_field)?;
        let eop1_digest = self.fixed::<32>()?;
        let closure = self.closure(&stable_slot)?;
        ManifestPluginEntryV1::new(
            stable_slot,
            PluginId::from_ulid(ulid::Ulid::from_bytes(plugin_id)),
            plugin_name,
            plugin_version,
            Hash::from_bytes(eop1_digest),
            closure,
        )
    }

    const fn finish(&self) -> Result<(), ManifestPluginRosterErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(INVALID)
        }
    }
}
