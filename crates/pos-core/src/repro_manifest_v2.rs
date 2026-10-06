//! Version-2 `ReproManifest` shape with strict JSON and CBOR codecs (ADR-088 Revision 3).
//!
//! A version-2 manifest names every admitted Plugin once, in a canonical MPR1 roster, instead of
//! five name-keyed maps. Two Plugins may share a display name; their `PluginId`s, EOP1 digests and
//! closures stay separate rows.
//!
//! A decoded manifest is only a structurally valid value. It mints no Replay capability: the
//! installed host still checks native bytes, owner roots, consent, leases and erasure fences. The
//! type has no `Serialize` or `Deserialize` impl, so the two decoders here are the only way to
//! build one from untrusted bytes.
//!
//! # Example
//!
//! ```
//! # use pos_core::{
//! #     Hash, ManifestPluginEntryV1, ManifestPluginRosterV1, PluginId, ReproManifestV2,
//! #     TimelineId, WallTime,
//! # };
//! # type Outcome<T> = Result<T, Box<dyn std::error::Error>>;
//! # fn entry(slot: &str, byte: u8) -> Outcome<ManifestPluginEntryV1> {
//! #     let id = PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]));
//! #     let digest = Hash::from_bytes([byte; 32]);
//! #     Ok(ManifestPluginEntryV1::new(slot, id, "Sensor", "1.0.0", digest, vec![byte])?)
//! # }
//! # fn main() -> Outcome<()> {
//! let roster = ManifestPluginRosterV1::new(vec![entry("sensor.b", 2)?, entry("sensor.a", 1)?])?;
//! let timeline_id = TimelineId::from_ulid(ulid::Ulid::from_bytes([7; 16]));
//! let manifest = ReproManifestV2::new(
//!     timeline_id,
//!     Hash::from_bytes([9; 32]),
//!     WallTime::from_micros(1_000_000),
//!     roster,
//!     Vec::new(),
//!     Some("run-1".to_owned()),
//! )?;
//! let json = manifest.to_json()?;
//! assert_eq!(ReproManifestV2::from_json(json.as_bytes())?, manifest);
//! let cbor = manifest.to_cbor()?;
//! assert_eq!(ReproManifestV2::from_cbor(&cbor)?, manifest);
//! # Ok(())
//! # }
//! ```
//!
//! # JSON layout
//!
//! One object with `manifest_format_version` (integer 2), `timeline_id`, `head_hash`,
//! `created_at` (microseconds), `adapter_records`, an optional `label`,
//! `manifest_plugin_roster_version` (integer 1) and `manifest_plugin_entries`. The entries are
//! ordered by `stable_slot` and carry `stable_slot`, `plugin_id`, `plugin_name`,
//! `plugin_version`, `eop1_digest` and `closure_bytes`. Ids and digests are fixed-width lowercase
//! hex; closure bytes are RFC 4648 section 4 base64 with required padding. Member order carries
//! no meaning.
//!
//! # CBOR layout
//!
//! One definite-length map with text keys in canonical RFC 8949 order (shorter key first, then
//! bytewise), the shortest integer heads, and no tags, floats or indefinite items. The decoder
//! re-encodes and compares, so exactly one byte string exists per manifest.
//!
//! | key | value |
//! | --- | --- |
//! | `label` | text, omitted when absent |
//! | `head_hash` | 32-byte string |
//! | `created_at` | unsigned integer, microseconds |
//! | `timeline_id` | 16-byte string |
//! | `adapter_records` | array of maps keyed `plugin_id`, `wall_time`, `call_index`, `input_hash`, `output_hash` |
//! | `manifest_plugin_roster` | byte string holding the exact canonical MPR1 bytes |
//! | `manifest_format_version` | unsigned integer 2 |
//!
//! # Bounds
//!
//! Whole JSON and CBOR inputs are at most 1.5 GiB, an MPR1 roster at most 1 GiB, `adapter_records`
//! at most 1,048,576 and a label at most 256 UTF-8 bytes.
//!
//! The whole-input length is checked before any parsing, and an `adapter_records` array stops
//! at its cap while it streams, so an oversized array is never built. The remaining limits (label,
//! roster bytes and JSON roster entries) are checked after the generic document tree exists: the
//! decoder holds each such string or byte string once, moved rather than copied, and the 1.5 GiB
//! input cap is what bounds that memory.
//!
//! A document that is well-formed JSON or CBOR is classified before its shape is checked: null,
//! boolean, float and negative values are kept as opaque values, so an old document (which
//! serializes an absent `label` as null) reports `UnsupportedManifestVersion` or
//! `AmbiguousLegacyManifest`. Such a value in a version-2 field fails that field with
//! `InvalidField`; `InvalidEncoding` is kept for bytes that are not one well-formed document
//! with a map on top.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Value};
use std::fmt;
use ulid::Ulid;

use crate::{
    clock::WallTime,
    crypto::Hash,
    ids::{PluginId, TimelineId},
    manifest::AdapterRecord,
    manifest_plugin_roster::{
        ManifestPluginEntryV1, ManifestPluginRosterErrorV1, ManifestPluginRosterV1,
        MAX_MANIFEST_PLUGIN_ROSTER_ENTRIES_V1,
    },
    repro_manifest_root::MAX_REPRO_MANIFEST_LABEL_BYTES_V1,
};

/// Largest accepted whole JSON or CBOR manifest input, 1.5 GiB.
pub const MAX_REPRO_MANIFEST_V2_INPUT_BYTES: usize = 1_610_612_736;
/// Most `adapter_records` one version-2 manifest may carry.
pub const MAX_REPRO_MANIFEST_V2_ADAPTER_RECORDS: usize = 1_048_576;

const FORMAT_VERSION: u64 = 2;
const VERSION: &str = "manifest_format_version";
const TIMELINE: &str = "timeline_id";
const HEAD: &str = "head_hash";
const CREATED: &str = "created_at";
const RECORDS: &str = "adapter_records";
const LABEL: &str = "label";
const ROSTER_VERSION: &str = "manifest_plugin_roster_version";
const ENTRIES: &str = "manifest_plugin_entries";
const ROSTER: &str = "manifest_plugin_roster";
const JSON_FIELDS: [&str; 8] = [
    VERSION,
    TIMELINE,
    HEAD,
    CREATED,
    RECORDS,
    LABEL,
    ROSTER_VERSION,
    ENTRIES,
];
const CBOR_FIELDS: [&str; 7] = [VERSION, TIMELINE, HEAD, CREATED, RECORDS, LABEL, ROSTER];
// Positions in `JSON_FIELDS` and `CBOR_FIELDS`; the two lists agree up to `AT_LABEL`.
const AT_TIMELINE: usize = 1;
const AT_HEAD: usize = 2;
const AT_CREATED: usize = 3;
const AT_RECORDS: usize = 4;
const AT_LABEL: usize = 5;
const AT_ROSTER_VERSION: usize = 6;
const AT_ENTRIES: usize = 7;
const AT_ROSTER: usize = 6;
const ROSTER_FIELDS: [&str; 3] = [ROSTER_VERSION, ENTRIES, ROSTER];
const LEGACY_FIELDS: [&str; 5] = [
    "plugin_versions",
    "output_policy_digests",
    "replay_policy_identities",
    "replay_policy_closures",
    "replay_policy_closure_identities",
];
const ENTRY_FIELDS: [&str; 6] = [
    "stable_slot",
    "plugin_id",
    "plugin_name",
    "plugin_version",
    "eop1_digest",
    "closure_bytes",
];
// Positions in `ENTRY_FIELDS` and `RECORD_FIELDS`.
const ENTRY_SLOT: usize = 0;
const ENTRY_ID: usize = 1;
const ENTRY_NAME: usize = 2;
const ENTRY_VERSION: usize = 3;
const ENTRY_DIGEST: usize = 4;
const ENTRY_CLOSURE: usize = 5;
const RECORD_ID: usize = 0;
const RECORD_CALL: usize = 1;
const RECORD_INPUT: usize = 2;
const RECORD_OUTPUT: usize = 3;
const RECORD_WALL: usize = 4;
const RECORD_FIELDS: [&str; 5] = [
    "plugin_id",
    "call_index",
    "input_hash",
    "output_hash",
    "wall_time",
];
const ID_RULE: &str = "must be 16 bytes: 32 lowercase hex digits in JSON, 16 bytes in CBOR";
const HASH_RULE: &str = "must be 32 bytes: 64 lowercase hex digits in JSON, 32 bytes in CBOR";
const BASE64_RULE: &str = "must be RFC 4648 base64 with padding, zero pad bits and no spaces";
const CBOR_RULE: &str = "must use the documented deterministic layout";
const ROSTER_RULE: &str = "must be a byte string of canonical MPR1 bytes";
const OBJECT_RULE: &str = "must be a map (a JSON object)";
const TOO_MANY_MARKER: &str = "manifest array exceeds the element cap";
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Closed, matchable errors; none echoes closure bytes and each says what to change.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReproManifestV2Error {
    /// The document is not a version-2 manifest, for example an old name-keyed one.
    #[error(
        "unsupported manifest_format_version ({}): this reader accepts only the integer 2; \
         write the manifest again with a version-2 writer, because older documents cannot be \
         upgraded",
        .found.map_or_else(|| "missing or not an unsigned integer".to_owned(), |v| v.to_string())
    )]
    UnsupportedManifestVersion {
        /// The unsigned integer found, or `None` when it is missing or not one.
        found: Option<u64>,
    },
    /// Old name-keyed policy maps and the version-2 roster appear in one document.
    #[error(
        "ambiguous manifest: `{field}` mixes the version-1 name-keyed policy maps with the \
         version-2 roster; remove plugin_versions, output_policy_digests, \
         replay_policy_identities, replay_policy_closures and \
         replay_policy_closure_identities (even when empty) and keep only the roster"
    )]
    AmbiguousLegacyManifest {
        /// The first conflicting field found.
        field: &'static str,
    },
    /// The bytes are not one well-formed document of the named transport.
    #[error(
        "malformed {transport} manifest: expect exactly one well-formed {transport} document \
         whose top level is a map, with no trailing bytes"
    )]
    InvalidEncoding {
        /// `JSON` or `CBOR`.
        transport: &'static str,
    },
    /// An `adapter_records` list holds more elements than allowed.
    #[error("{field} has more than {max} elements: keep at most {max}")]
    TooManyElements {
        /// The offending field, or `an array` when found while streaming; `max` is its limit.
        field: &'static str,
        /// The limit.
        max: usize,
    },
    /// The whole input is larger than the cap.
    #[error("manifest is larger than {max} bytes: record fewer adapter_records or Plugins")]
    InputTooLarge {
        /// The cap in bytes.
        max: usize,
    },
    /// A map key appears twice.
    #[error(
        "duplicate key `{}`: keep each key once and remove the repeat",
        .key.escape_debug()
    )]
    DuplicateKey {
        /// The repeated key, cut to 64 characters.
        key: String,
    },
    /// A field that version 2 does not define.
    #[error(
        "unknown field `{}`: remove it; version 2 defines no such field",
        .field.escape_debug()
    )]
    UnknownField {
        /// The field name, cut to 64 characters.
        field: String,
    },
    /// A roster field of the other transport.
    #[error(
        "`{field}` does not belong in a {transport} manifest: use manifest_plugin_entries in \
         JSON and manifest_plugin_roster in CBOR"
    )]
    WrongTransportField {
        /// The foreign field.
        field: &'static str,
        /// `JSON` or `CBOR`.
        transport: &'static str,
    },
    /// A required field is absent.
    #[error("missing required field `{field}`: add it")]
    MissingField {
        /// The absent field.
        field: &'static str,
    },
    /// A field has the wrong type, width or value.
    #[error("invalid `{field}`: it {rule}")]
    InvalidField {
        /// The offending field.
        field: &'static str,
        /// The rule it broke.
        rule: &'static str,
    },
    /// A value is valid but not in its single canonical spelling.
    #[error("noncanonical `{field}`: it {rule}")]
    NonCanonical {
        /// The offending field, or `manifest` for a whole CBOR document.
        field: &'static str,
        /// The rule it broke.
        rule: &'static str,
    },
    /// The label is longer than 256 UTF-8 bytes.
    #[error("label is {len} bytes: shorten it to at most 256 UTF-8 bytes")]
    LabelTooLong {
        /// The label length in bytes.
        len: usize,
    },
    /// The MPR1 roster itself is invalid.
    #[error(transparent)]
    Roster(#[from] ManifestPluginRosterErrorV1),
}

/// Check a whole JSON or CBOR input length against the 1.5 GiB cap.
///
/// # Errors
/// `InputTooLarge` when `len` exceeds `MAX_REPRO_MANIFEST_V2_INPUT_BYTES`.
pub const fn checked_repro_manifest_v2_input_len(
    len: usize,
) -> Result<usize, ReproManifestV2Error> {
    if len > MAX_REPRO_MANIFEST_V2_INPUT_BYTES {
        Err(ReproManifestV2Error::InputTooLarge {
            max: MAX_REPRO_MANIFEST_V2_INPUT_BYTES,
        })
    } else {
        Ok(len)
    }
}

/// Immutable validated version-2 manifest; it carries no Replay capability.
///
/// Build it with [`Self::new`], which validates everything before returning, and read it back
/// with the getters. There is no builder that overwrites an earlier value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReproManifestV2 {
    timeline_id: TimelineId,
    head_hash: Hash,
    created_at: WallTime,
    plugin_roster: ManifestPluginRosterV1,
    adapter_records: Vec<AdapterRecord>,
    label: Option<String>,
}

impl ReproManifestV2 {
    /// Validate and build one manifest.
    ///
    /// # Errors
    /// `TooManyElements` above 1,048,576 `adapter_records`; `LabelTooLong` above 256 bytes.
    pub fn new(
        timeline_id: TimelineId,
        head_hash: Hash,
        created_at: WallTime,
        plugin_roster: ManifestPluginRosterV1,
        adapter_records: Vec<AdapterRecord>,
        label: Option<String>,
    ) -> Result<Self, ReproManifestV2Error> {
        if adapter_records.len() > MAX_REPRO_MANIFEST_V2_ADAPTER_RECORDS {
            return Err(too_many(RECORDS));
        }
        let len = label.as_deref().map_or(0, str::len);
        if len > MAX_REPRO_MANIFEST_LABEL_BYTES_V1 {
            return Err(ReproManifestV2Error::LabelTooLong { len });
        }
        Ok(Self {
            timeline_id,
            head_hash,
            created_at,
            plugin_roster,
            adapter_records,
            label,
        })
    }

    /// The Timeline this manifest describes.
    #[must_use]
    pub const fn timeline_id(&self) -> TimelineId {
        self.timeline_id
    }

    /// The head hash of that Timeline.
    #[must_use]
    pub const fn head_hash(&self) -> Hash {
        self.head_hash
    }

    /// Creation time.
    #[must_use]
    pub const fn created_at(&self) -> WallTime {
        self.created_at
    }

    /// The canonical MPR1 Plugin roster.
    #[must_use]
    pub const fn plugin_roster(&self) -> &ManifestPluginRosterV1 {
        &self.plugin_roster
    }

    /// Recorded adapter calls.
    #[must_use]
    pub const fn adapter_records(&self) -> &[AdapterRecord] {
        self.adapter_records.as_slice()
    }

    /// Optional human-readable label.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Encode compact JSON.
    ///
    /// Key order follows `serde_json`'s default sorted map; a golden test pins it.
    ///
    /// # Errors
    /// `InputTooLarge` when the text would exceed the 1.5 GiB cap. A manifest holds at most a
    /// 1 GiB roster and about 168 MB of records, so a value built through [`Self::new`] stays
    /// far below the cap and this is a defensive bound, not a reachable path.
    pub fn to_json(&self) -> Result<String, ReproManifestV2Error> {
        let roster = &self.plugin_roster;
        let entries: Vec<Value> = roster.entries().iter().map(entry_json).collect();
        let records: Vec<Value> = self.adapter_records.iter().map(record_json).collect();
        let mut document = json!({
            VERSION: FORMAT_VERSION,
            ROSTER_VERSION: 1,
            ENTRIES: entries,
            TIMELINE: hex_encode(&self.timeline_id.inner().to_bytes()),
            HEAD: hex_encode(self.head_hash.as_bytes()),
            CREATED: self.created_at.as_micros(),
            RECORDS: records,
        });
        if let Some(label) = &self.label {
            document[LABEL] = label.as_str().into();
        }
        let text = document.to_string();
        let len = text.len();
        checked_repro_manifest_v2_input_len(len).map(|_| text)
    }

    /// Decode strict JSON.
    ///
    /// # Errors
    /// Rejects oversized, malformed, duplicate-key, unknown-field, old, mixed, wrong-transport,
    /// noncanonical or out-of-bounds input with the matching closed error.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ReproManifestV2Error> {
        checked_repro_manifest_v2_input_len(bytes.len())?;
        let raw: Raw =
            serde_json::from_slice(bytes).map_err(|error| stream_error(Transport::Json, &error))?;
        decode(raw, Transport::Json)
    }

    /// Encode the deterministic CBOR layout described in the module docs.
    ///
    /// # Errors
    /// `InputTooLarge` when the bytes would exceed the 1.5 GiB cap. As with JSON, that is a
    /// defensive bound: the roster is at most 1 GiB and the records about 168 MB.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ReproManifestV2Error> {
        let out = self.encode_cbor();
        let len = out.len();
        checked_repro_manifest_v2_input_len(len).map(|_| out)
    }

    fn encode_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_head(&mut out, 5, 6 + u64::from(self.label.is_some()));
        if let Some(label) = &self.label {
            put_text(&mut out, LABEL);
            put_text(&mut out, label);
        }
        put_text(&mut out, HEAD);
        put_bytes(&mut out, self.head_hash.as_bytes());
        put_text(&mut out, CREATED);
        put_head(&mut out, 0, self.created_at.as_micros());
        put_text(&mut out, TIMELINE);
        put_bytes(&mut out, &self.timeline_id.inner().to_bytes());
        put_text(&mut out, RECORDS);
        put_head(&mut out, 4, self.adapter_records.len() as u64);
        for record in &self.adapter_records {
            put_record(&mut out, record);
        }
        put_text(&mut out, ROSTER);
        put_bytes(&mut out, &self.plugin_roster.to_canonical_cbor());
        put_text(&mut out, VERSION);
        put_head(&mut out, 0, FORMAT_VERSION);
        out
    }

    /// Decode strict CBOR; the input must be the exact deterministic encoding.
    ///
    /// # Errors
    /// Rejects oversized, malformed, duplicate-key, unknown-field, old, mixed, wrong-transport,
    /// noncanonical or out-of-bounds input with the matching closed error.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ReproManifestV2Error> {
        checked_repro_manifest_v2_input_len(bytes.len())?;
        let mut rest = bytes;
        let raw: Raw = ciborium::from_reader(&mut rest)
            .map_err(|error| stream_error(Transport::Cbor, &error))?;
        if !rest.is_empty() {
            return Err(malformed(Transport::Cbor));
        }
        let manifest = decode(raw, Transport::Cbor)?;
        if manifest.encode_cbor() != bytes {
            return Err(non_canonical("manifest", CBOR_RULE));
        }
        Ok(manifest)
    }
}

const fn too_many(field: &'static str) -> ReproManifestV2Error {
    ReproManifestV2Error::TooManyElements {
        field,
        max: MAX_REPRO_MANIFEST_V2_ADAPTER_RECORDS,
    }
}

const fn invalid(field: &'static str, rule: &'static str) -> ReproManifestV2Error {
    ReproManifestV2Error::InvalidField { field, rule }
}

const fn non_canonical(field: &'static str, rule: &'static str) -> ReproManifestV2Error {
    ReproManifestV2Error::NonCanonical { field, rule }
}

const fn malformed(transport: Transport) -> ReproManifestV2Error {
    ReproManifestV2Error::InvalidEncoding {
        transport: transport.name(),
    }
}

fn bounded_text(value: &str) -> String {
    value.chars().take(64).collect()
}

fn unknown_field(key: &str) -> ReproManifestV2Error {
    ReproManifestV2Error::UnknownField {
        field: bounded_text(key),
    }
}

fn duplicate_key(key: &str) -> ReproManifestV2Error {
    ReproManifestV2Error::DuplicateKey {
        key: bounded_text(key),
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Json,
    Cbor,
}

impl Transport {
    const fn name(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Cbor => "CBOR",
        }
    }

    const fn allowed(self) -> &'static [&'static str] {
        match self {
            Self::Json => &JSON_FIELDS,
            Self::Cbor => &CBOR_FIELDS,
        }
    }

    const fn foreign(self) -> &'static [&'static str] {
        match self {
            Self::Json => &[ROSTER],
            Self::Cbor => &[ROSTER_VERSION, ENTRIES],
        }
    }
}

// A generic document tree. Maps keep every pair, so duplicate keys survive until they are checked.
enum Raw {
    Uint(u64),
    // Null, boolean, float or negative integer: well-formed, but never a valid field value.
    Other,
    Text(String),
    Bytes(Vec<u8>),
    Array(Vec<Self>),
    Map(Vec<(String, Self)>),
}

impl<'de> Deserialize<'de> for Raw {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(RawVisitor)
    }
}

struct RawVisitor;

impl<'de> Visitor<'de> for RawVisitor {
    type Value = Raw;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON or CBOR value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Raw, E> {
        Ok(Raw::Other)
    }

    fn visit_none<E: de::Error>(self) -> Result<Raw, E> {
        Ok(Raw::Other)
    }

    fn visit_bool<E: de::Error>(self, _value: bool) -> Result<Raw, E> {
        Ok(Raw::Other)
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<Raw, E> {
        Ok(Raw::Other)
    }

    fn visit_i64<E: de::Error>(self, _value: i64) -> Result<Raw, E> {
        Ok(Raw::Other)
    }

    fn visit_i128<E: de::Error>(self, _value: i128) -> Result<Raw, E> {
        Ok(Raw::Other)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Raw, E> {
        Ok(Raw::Uint(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Raw, E> {
        Ok(Raw::Text(value.to_owned()))
    }

    // Long strings arrive owned from the CBOR decoder; move them instead of copying.
    fn visit_string<E: de::Error>(self, value: String) -> Result<Raw, E> {
        Ok(Raw::Text(value))
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Raw, E> {
        Ok(Raw::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Raw, E> {
        Ok(Raw::Bytes(value))
    }

    // Stop at the cap while streaming, so a huge array is never built.
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Raw, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Raw>()? {
            if items.len() == MAX_REPRO_MANIFEST_V2_ADAPTER_RECORDS {
                return Err(de::Error::custom(TOO_MANY_MARKER));
            }
            items.push(item);
        }
        Ok(Raw::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Raw, A::Error> {
        let mut pairs = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            pairs.push((key, map.next_value::<Raw>()?));
        }
        Ok(Raw::Map(pairs))
    }
}

fn stream_error(transport: Transport, error: &impl fmt::Display) -> ReproManifestV2Error {
    // The visitor reports the cap through `Error::custom`, which only carries text; the marker has
    // no numbers, so it cannot drift from the cap constants.
    if error.to_string().contains(TOO_MANY_MARKER) {
        too_many("an array")
    } else {
        malformed(transport)
    }
}

fn decode(raw: Raw, transport: Transport) -> Result<ReproManifestV2, ReproManifestV2Error> {
    let Raw::Map(pairs) = raw else {
        return Err(malformed(transport));
    };
    gate(&pairs, transport)?;
    let fields = object(&pairs, transport.allowed())?;
    let (timeline_id, head_hash, created_at) = decode_head(&fields, transport)?;
    let adapter_records = decode_records(required(fields[AT_RECORDS], RECORDS)?, transport)?;
    let label = fields[AT_LABEL]
        .map(|raw| text(raw, LABEL).map(str::to_owned))
        .transpose()?;
    let plugin_roster = match transport {
        Transport::Json => json_roster(fields[AT_ROSTER_VERSION], fields[AT_ENTRIES])?,
        Transport::Cbor => cbor_roster(fields[AT_ROSTER])?,
    };
    ReproManifestV2::new(
        timeline_id,
        head_hash,
        created_at,
        plugin_roster,
        adapter_records,
        label,
    )
}

// Decide old, mixed and wrong-transport documents before any shape or value check.
fn gate(pairs: &[(String, Raw)], transport: Transport) -> Result<(), ReproManifestV2Error> {
    let has = |name: &str| pairs.iter().any(|(key, _)| key.as_str() == name);
    let found = match pairs.iter().find(|(key, _)| key.as_str() == VERSION) {
        Some((_, Raw::Uint(version))) => Some(*version),
        _ => None,
    };
    let is_v2 = found == Some(FORMAT_VERSION);
    let legacy = LEGACY_FIELDS.iter().copied().find(|name| has(name));
    let modern = ROSTER_FIELDS.iter().copied().find(|name| has(name));
    let mixed = if is_v2 { legacy } else { legacy.and(modern) };
    if let Some(field) = mixed {
        return Err(ReproManifestV2Error::AmbiguousLegacyManifest { field });
    }
    if !is_v2 {
        return Err(ReproManifestV2Error::UnsupportedManifestVersion { found });
    }
    foreign_check(pairs, transport)
}

fn foreign_name(key: &str, transport: Transport) -> Option<&'static str> {
    let names = transport.foreign();
    names.iter().copied().find(|name| *name == key)
}

fn foreign_check(
    pairs: &[(String, Raw)],
    transport: Transport,
) -> Result<(), ReproManifestV2Error> {
    let found = pairs
        .iter()
        .find_map(|(key, _)| foreign_name(key, transport));
    found.map_or(Ok(()), |field| {
        Err(ReproManifestV2Error::WrongTransportField {
            field,
            transport: transport.name(),
        })
    })
}

// Positions follow `fields`; absent entries are `None`. Unknown and repeated keys reject.
fn object<'a>(
    pairs: &'a [(String, Raw)],
    fields: &[&'static str],
) -> Result<Vec<Option<&'a Raw>>, ReproManifestV2Error> {
    let mut values = vec![None; fields.len()];
    for (key, value) in pairs {
        let Some(index) = fields.iter().position(|field| *field == key.as_str()) else {
            return Err(unknown_field(key));
        };
        if values[index].replace(value).is_some() {
            return Err(duplicate_key(key));
        }
    }
    Ok(values)
}

fn full_object<'a>(
    raw: &'a Raw,
    fields: &[&'static str],
    owner: &'static str,
) -> Result<Vec<&'a Raw>, ReproManifestV2Error> {
    let Raw::Map(pairs) = raw else {
        return Err(invalid(owner, OBJECT_RULE));
    };
    object(pairs, fields)?
        .into_iter()
        .zip(fields)
        .map(|(value, field)| required(value, field))
        .collect()
}

fn required<'a>(
    value: Option<&'a Raw>,
    field: &'static str,
) -> Result<&'a Raw, ReproManifestV2Error> {
    value.ok_or(ReproManifestV2Error::MissingField { field })
}

fn text<'a>(raw: &'a Raw, field: &'static str) -> Result<&'a str, ReproManifestV2Error> {
    match raw {
        Raw::Text(value) => Ok(value),
        _ => Err(invalid(field, "must be text")),
    }
}

const fn unsigned(raw: &Raw, field: &'static str) -> Result<u64, ReproManifestV2Error> {
    match raw {
        Raw::Uint(value) => Ok(*value),
        _ => Err(invalid(field, "must be an unsigned integer")),
    }
}

// Fixed-width id or digest: lowercase hex text in JSON, an exact byte string in CBOR.
fn fixed<const N: usize>(
    raw: &Raw,
    field: &'static str,
    transport: Transport,
    rule: &'static str,
) -> Result<[u8; N], ReproManifestV2Error> {
    let exact = match (raw, transport) {
        (Raw::Text(value), Transport::Json) => return hex_decode(value, field, rule),
        (Raw::Bytes(value), Transport::Cbor) => <[u8; N]>::try_from(value.as_slice()).ok(),
        _ => None,
    };
    let error = invalid(field, rule);
    exact.ok_or(error)
}

fn decode_head(
    fields: &[Option<&Raw>],
    transport: Transport,
) -> Result<(TimelineId, Hash, WallTime), ReproManifestV2Error> {
    let timeline = required(fields[AT_TIMELINE], TIMELINE)?;
    let timeline = fixed::<16>(timeline, TIMELINE, transport, ID_RULE)?;
    let head = required(fields[AT_HEAD], HEAD)?;
    let head = fixed::<32>(head, HEAD, transport, HASH_RULE)?;
    let created = unsigned(required(fields[AT_CREATED], CREATED)?, CREATED)?;
    Ok((
        TimelineId::from_ulid(Ulid::from_bytes(timeline)),
        Hash::from_bytes(head),
        WallTime::from_micros(created),
    ))
}

fn decode_records(
    raw: &Raw,
    transport: Transport,
) -> Result<Vec<AdapterRecord>, ReproManifestV2Error> {
    let Raw::Array(items) = raw else {
        return Err(invalid(RECORDS, "must be an array of adapter records"));
    };
    items
        .iter()
        .map(|item| decode_record(item, transport))
        .collect()
}

fn decode_record(raw: &Raw, transport: Transport) -> Result<AdapterRecord, ReproManifestV2Error> {
    let fields = full_object(raw, &RECORD_FIELDS, RECORDS)?;
    let plugin_id = fixed::<16>(fields[RECORD_ID], "plugin_id", transport, ID_RULE)?;
    let input_hash = fixed::<32>(fields[RECORD_INPUT], "input_hash", transport, HASH_RULE)?;
    let output_hash = fixed::<32>(fields[RECORD_OUTPUT], "output_hash", transport, HASH_RULE)?;
    Ok(AdapterRecord {
        plugin_id: PluginId::from_ulid(Ulid::from_bytes(plugin_id)),
        call_index: unsigned(fields[RECORD_CALL], "call_index")?,
        input_hash: Hash::from_bytes(input_hash),
        output_hash: Hash::from_bytes(output_hash),
        wall_time: WallTime::from_micros(unsigned(fields[RECORD_WALL], "wall_time")?),
    })
}

fn cbor_roster(raw: Option<&Raw>) -> Result<ManifestPluginRosterV1, ReproManifestV2Error> {
    match required(raw, ROSTER)? {
        Raw::Bytes(bytes) => Ok(ManifestPluginRosterV1::from_canonical_cbor(bytes)?),
        _ => Err(invalid(ROSTER, ROSTER_RULE)),
    }
}

fn json_roster(
    version: Option<&Raw>,
    entries: Option<&Raw>,
) -> Result<ManifestPluginRosterV1, ReproManifestV2Error> {
    if !matches!(required(version, ROSTER_VERSION)?, Raw::Uint(1)) {
        return Err(invalid(ROSTER_VERSION, "must be the integer 1"));
    }
    let Raw::Array(items) = required(entries, ENTRIES)? else {
        return Err(invalid(ENTRIES, "must be an array of roster entries"));
    };
    if items.len() > MAX_MANIFEST_PLUGIN_ROSTER_ENTRIES_V1 {
        return Err(ManifestPluginRosterErrorV1::RosterTooLarge.into());
    }
    let parsed = items.iter().map(json_entry);
    let rows = parsed.collect::<Result<Vec<_>, _>>()?;
    let slots: Vec<String> = rows.iter().map(slot_text).collect();
    let roster = ManifestPluginRosterV1::new(rows)?;
    check_slot_order(&roster, &slots)?;
    Ok(roster)
}

fn slot_text(entry: &ManifestPluginEntryV1) -> String {
    entry.stable_slot().to_owned()
}

// `ManifestPluginRosterV1::new` sorts, but a JSON document must already arrive sorted.
fn check_slot_order(
    roster: &ManifestPluginRosterV1,
    slots: &[String],
) -> Result<(), ReproManifestV2Error> {
    let moved = roster
        .entries()
        .iter()
        .zip(slots)
        .find(|(entry, slot)| entry.stable_slot() != slot.as_str());
    moved.map_or(Ok(()), |(entry, _)| {
        let slot = entry.stable_slot().to_owned();
        Err(ManifestPluginRosterErrorV1::UnsortedSlots { slot }.into())
    })
}

fn json_entry(raw: &Raw) -> Result<ManifestPluginEntryV1, ReproManifestV2Error> {
    let fields = full_object(raw, &ENTRY_FIELDS, ENTRIES)?;
    let id = fixed::<16>(fields[ENTRY_ID], "plugin_id", Transport::Json, ID_RULE)?;
    let digest = fixed::<32>(
        fields[ENTRY_DIGEST],
        "eop1_digest",
        Transport::Json,
        HASH_RULE,
    )?;
    Ok(ManifestPluginEntryV1::new(
        text(fields[ENTRY_SLOT], "stable_slot")?,
        PluginId::from_ulid(Ulid::from_bytes(id)),
        text(fields[ENTRY_NAME], "plugin_name")?,
        text(fields[ENTRY_VERSION], "plugin_version")?,
        Hash::from_bytes(digest),
        closure_bytes(fields[ENTRY_CLOSURE])?,
    )?)
}

fn closure_bytes(raw: &Raw) -> Result<Vec<u8>, ReproManifestV2Error> {
    let encoded = text(raw, "closure_bytes")?;
    let decoded = base64_decode(encoded);
    let canonical = decoded.filter(|bytes| base64_encode(bytes) == encoded);
    let error = non_canonical("closure_bytes", BASE64_RULE);
    canonical.ok_or(error)
}

fn entry_json(entry: &ManifestPluginEntryV1) -> Value {
    json!({
        "stable_slot": entry.stable_slot(),
        "plugin_id": hex_encode(&entry.plugin_id().inner().to_bytes()),
        "plugin_name": entry.plugin_name(),
        "plugin_version": entry.plugin_version(),
        "eop1_digest": hex_encode(entry.eop1_digest().as_bytes()),
        "closure_bytes": base64_encode(entry.closure_bytes()),
    })
}

fn record_json(record: &AdapterRecord) -> Value {
    json!({
        "plugin_id": hex_encode(&record.plugin_id.inner().to_bytes()),
        "call_index": record.call_index,
        "input_hash": hex_encode(record.input_hash.as_bytes()),
        "output_hash": hex_encode(record.output_hash.as_bytes()),
        "wall_time": record.wall_time.as_micros(),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        out.push(char::from(HEX[usize::from(*byte >> 4)]));
        out.push(char::from(HEX[usize::from(*byte & 15)]));
    }
    out
}

const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

fn hex_decode<const N: usize>(
    encoded: &str,
    field: &'static str,
    rule: &'static str,
) -> Result<[u8; N], ReproManifestV2Error> {
    if encoded.len() != 2 * N {
        return Err(invalid(field, rule));
    }
    let mut out = [0_u8; N];
    for (byte, pair) in out.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let Some((high, low)) = nibble(pair[0]).zip(nibble(pair[1])) else {
            return Err(non_canonical(field, rule));
        };
        *byte = (high << 4) | low;
    }
    Ok(out)
}

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut padded = [0_u8; 4];
        padded[1..=chunk.len()].copy_from_slice(chunk);
        let word = u32::from_be_bytes(padded);
        for index in 0..4_usize {
            if index <= chunk.len() {
                let six = (word >> (18 - 6 * index)).to_le_bytes()[0] & 63;
                out.push(char::from(B64[usize::from(six)]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn sextet(digit: u8) -> Option<u32> {
    match digit {
        b'A'..=b'Z' => Some(u32::from(digit - b'A')),
        b'a'..=b'z' => Some(u32::from(digit - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(digit - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

// Lenient decode; the caller re-encodes and compares, which rejects bad padding and pad bits.
fn base64_decode(encoded: &str) -> Option<Vec<u8>> {
    let symbols = encoded.trim_end_matches('=').as_bytes();
    let mut out = Vec::new();
    for chunk in symbols.chunks(4) {
        let mut word = 0_u32;
        for index in 0..4 {
            word = (word << 6) | chunk.get(index).map_or(Some(0), |symbol| sextet(*symbol))?;
        }
        let kept = chunk.len() * 6 / 8;
        if kept == 0 {
            return None;
        }
        out.extend_from_slice(&word.to_be_bytes()[1..=kept]);
    }
    Some(out)
}

fn put_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let tag = major << 5;
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => out.push(tag | bytes[7]),
        24..=255 => out.extend_from_slice(&[tag | 0x18, bytes[7]]),
        256..=65_535 => {
            out.push(tag | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
        65_536..=4_294_967_295 => {
            out.push(tag | 0x1a);
            out.extend_from_slice(&bytes[4..]);
        }
        _ => {
            out.push(tag | 0x1b);
            out.extend_from_slice(&bytes);
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn put_text(out: &mut Vec<u8>, value: &str) {
    put_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

// Keys in canonical order: shorter first, then bytewise.
fn put_record(out: &mut Vec<u8>, record: &AdapterRecord) {
    put_head(out, 5, 5);
    put_text(out, "plugin_id");
    put_bytes(out, &record.plugin_id.inner().to_bytes());
    put_text(out, "wall_time");
    put_head(out, 0, record.wall_time.as_micros());
    put_text(out, "call_index");
    put_head(out, 0, record.call_index);
    put_text(out, "input_hash");
    put_bytes(out, record.input_hash.as_bytes());
    put_text(out, "output_hash");
    put_bytes(out, record.output_hash.as_bytes());
}
