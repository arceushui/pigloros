//! The payload grammar (ADR-061 revision 8 decision 8), parsed strictly with `serde_json`.
//!
//! Unknown keys, missing keys, a value of the wrong type, a hex value of the wrong length or
//! case, a number that is not an integer from 0 to 9,007,199,254,740,991 and a text with a
//! control or non-ASCII character are all `payload-invalid`. A conditional key is required
//! exactly when its condition holds. Digest references are resolved against the composite by
//! [`crate::world`], not here.

use std::collections::BTreeSet;

use pos_reference::evaluator_domain::FixtureFamily;
use serde::de::{self, Deserializer};
use serde::Deserialize;

use crate::hex;
use crate::{CONTRACT_VERSION, PROVIDER_ID, SCHEMA_ID};

/// The most sub-cases a payload carries.
pub const MAX_SUBCASES: usize = 64;

/// The largest `u64` the grammar accepts: 2^53 - 1.
pub const MAX_JSON_U64: u64 = 9_007_199_254_740_991;

/// The sub-case that carries the nested document and expects `malformed`.
const MALFORMED_SUBCASE: &str = "mal.6";

/// A payload that is not valid for the grammar: it is the case result `payload-invalid`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("the payload violates the Plugin conformance case grammar")]
pub struct InvalidCaseV1;

/// The payload name of `family`.
#[must_use]
pub const fn family_text(family: FixtureFamily) -> &'static str {
    match family {
        FixtureFamily::Positive => "positive",
        FixtureFamily::Denied => "denied",
        FixtureFamily::Malformed => "malformed",
        FixtureFamily::ResourceExhaustion => "resource-exhaustion",
        FixtureFamily::DeletionRedaction => "deletion-redaction",
        FixtureFamily::Downgrade => "downgrade",
        FixtureFamily::IndependentEvaluation => "independent-evaluation",
    }
}

/// `text`: printable ASCII, no control character.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Text(String);

impl Text {
    /// The text.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
            Ok(Self(text))
        } else {
            Err(de::Error::custom("text is not printable ASCII"))
        }
    }
}

/// `u64`: a JSON integer from 0 to 2^53 - 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonU64(pub u64);

impl<'de> Deserialize<'de> for JsonU64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        if value <= MAX_JSON_U64 {
            Ok(Self(value))
        } else {
            Err(de::Error::custom("integer above 2^53 - 1"))
        }
    }
}

/// `hex32`: 64 lowercase hexadecimal characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hex32(pub [u8; 32]);

impl<'de> Deserialize<'de> for Hex32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode_array::<32>(&text);
        bytes
            .map(Self)
            .ok_or_else(|| de::Error::custom("not hex32"))
    }
}

/// `hex16`: 32 lowercase hexadecimal characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hex16(pub [u8; 16]);

impl<'de> Deserialize<'de> for Hex16 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex::decode_array::<16>(&text);
        bytes
            .map(Self)
            .ok_or_else(|| de::Error::custom("not hex16"))
    }
}

/// `hexb`: lowercase hexadecimal of any even length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HexBytes(pub Vec<u8>);

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text)
            .map(Self)
            .ok_or_else(|| de::Error::custom("not hexb"))
    }
}

/// A key that may be `null`, but must be present.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// A conditional key: absent is `None`, and a present value must be a `T` (`null` is not).
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// `release`: the OCI manifest piece and the layer pieces.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseV1 {
    pub manifest: Hex32,
    pub blobs: Vec<Hex32>,
}

/// `material`: the anchor piece, the TPS1 piece and the PTR1 and PRV1 pieces, oldest first.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MaterialV1 {
    pub anchor: Hex32,
    pub tps1: Hex32,
    pub ptr1: Vec<Hex32>,
    pub prv1: Vec<Hex32>,
}

/// `{schema, bytes}`: a Plugin state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StateV1 {
    pub schema: Hex32,
    pub bytes: HexBytes,
}

/// Step `install`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstallV1 {
    pub release: ReleaseV1,
    #[serde(deserialize_with = "nullable")]
    pub material: Option<MaterialV1>,
    pub instant_micros: JsonU64,
    pub tick: JsonU64,
}

/// Step `bind`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BindV1 {
    pub release: ReleaseV1,
    #[serde(deserialize_with = "nullable")]
    pub material: Option<MaterialV1>,
    pub plugin_id: Text,
    pub instant_micros: JsonU64,
    pub tick: JsonU64,
    pub initial_state: StateV1,
    pub event_type: Text,
}

/// Step `refresh`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RefreshV1 {
    #[serde(deserialize_with = "nullable")]
    pub material: Option<MaterialV1>,
    pub instant_micros: JsonU64,
    pub tick: JsonU64,
}

/// The text `absent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsentTextV1;

impl<'de> Deserialize<'de> for AbsentTextV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == "absent" {
            Ok(Self)
        } else {
            Err(de::Error::custom("not the text absent"))
        }
    }
}

/// The `at` of a member: nothing, or another release.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum AtV1 {
    Absent(AbsentTextV1),
    Release(ReleaseV1),
}

/// A member of a `pass`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemberV1 {
    pub plugin_id: Text,
    #[serde(default, deserialize_with = "present")]
    pub at: Option<AtV1>,
}

/// Step `pass`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PassV1 {
    pub members: Vec<MemberV1>,
    pub instant_micros: JsonU64,
    pub tick: JsonU64,
    pub invocation_id: Hex16,
    pub random_domain: Hex32,
    pub timeline_seq: JsonU64,
    pub observation: HexBytes,
    pub simulation_time: JsonU64,
}

/// A place a `scan` searches.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "lowercase")]
pub enum ScanSource {
    /// The committed Event payload bytes.
    Events,
    /// The Driver's committed state bytes.
    State,
    /// The outcome record's canonical bytes.
    Outcome,
}

/// The metadata a deletion case expects to survive.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RetainedV1 {
    pub plugin_id: Text,
    pub invocation_id_hex: Text,
}

/// Step `scan`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScanV1 {
    pub marker: Text,
    #[serde(rename = "in")]
    pub sources: Vec<ScanSource>,
    pub retained: RetainedV1,
}

/// One step of a sub-case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "step", rename_all = "lowercase")]
pub enum StepV1 {
    Install(InstallV1),
    Bind(BindV1),
    Refresh(RefreshV1),
    Pass(PassV1),
    Scan(ScanV1),
}

/// Expect `committed`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommittedV1 {
    pub output_digest: Hex32,
}

/// Expect `refused`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RefusedV1 {
    pub error: Text,
    pub class: Text,
    #[serde(default, deserialize_with = "present")]
    pub basis: Option<Text>,
    #[serde(default, deserialize_with = "present")]
    pub index: Option<JsonU64>,
}

/// Expect `failed`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FailedV1 {
    pub error: Text,
    pub class: Text,
}

/// Expect `malformed`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MalformedV1 {}

/// Expect `absent`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AbsentV1 {
    pub marker: Text,
    pub retained: RetainedV1,
}

/// `compute` `blake3_of`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Blake3OfV1 {
    pub input: Text,
}

/// The field of a `release_identity` compute.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IdentityFieldV1 {
    /// The unkeyed BLAKE3-256 of the complete canonical PMF1 bytes.
    Pmf1,
    /// The PMF1 release digest.
    Release,
}

/// `compute` `release_identity`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentityV1 {
    pub field: IdentityFieldV1,
}

/// `compute` `output_digest`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OutputDigestV1 {
    pub pass_index: JsonU64,
}

/// The pinned runtime of a `profile_digest` compute.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeV1 {
    pub version: Text,
    pub features: Vec<Text>,
    pub engine: (JsonU64, bool, bool),
    pub traps: Vec<(Text, Text)>,
}

/// `compute` `profile_digest`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProfileDigestV1 {
    pub ceilings: [JsonU64; 5],
    pub runtime: RuntimeV1,
}

/// What an `ind.*` sub-case computes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "what", rename_all = "snake_case")]
pub enum ComputeV1 {
    Blake3Of(Blake3OfV1),
    ReleaseIdentity(ReleaseIdentityV1),
    OutputDigest(OutputDigestV1),
    ProfileDigest(ProfileDigestV1),
}

/// Expect `digest`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DigestV1 {
    pub compute: ComputeV1,
    pub value: Hex32,
}

/// What a sub-case expects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ExpectV1 {
    Committed(CommittedV1),
    Refused(RefusedV1),
    Failed(FailedV1),
    Malformed(MalformedV1),
    Absent(AbsentV1),
    Digest(DigestV1),
}

impl ExpectV1 {
    /// Whether the conditional keys of the expectation are present exactly when required:
    /// `basis` for `ArtifactTrustDenied` and `ArtifactRevoked`, `index` for `CapabilityDenied`
    /// and `MissingFeature`.
    fn is_valid(&self) -> bool {
        match self {
            Self::Refused(refused) => {
                let name = refused.error.as_str();
                let basis = matches!(name, "ArtifactTrustDenied" | "ArtifactRevoked");
                let index = matches!(name, "CapabilityDenied" | "MissingFeature");
                refused.basis.is_some() == basis && refused.index.is_some() == index
            }
            Self::Committed(_)
            | Self::Failed(_)
            | Self::Malformed(_)
            | Self::Absent(_)
            | Self::Digest(_) => true,
        }
    }
}

/// One sub-case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SubCaseV1 {
    pub id: Text,
    pub steps: Vec<StepV1>,
    pub expect: ExpectV1,
    #[serde(default, deserialize_with = "present")]
    pub nested: Option<Hex32>,
}

impl SubCaseV1 {
    /// The sub-case document `bytes`, as the adapter's own decoder reads a nested piece.
    ///
    /// # Errors
    /// Returns [`InvalidCaseV1`] for a document that is not JSON, violates the grammar, or
    /// carries a `nested` key of its own.
    pub fn parse_document(bytes: &[u8]) -> Result<Self, InvalidCaseV1> {
        let parsed = serde_json::from_slice::<Self>(bytes).or(Err(InvalidCaseV1));
        parsed.and_then(|subcase| {
            let valid = subcase.nested.is_none() && subcase.is_wellformed();
            valid.then_some(subcase).ok_or(InvalidCaseV1)
        })
    }

    /// The scan steps of the sub-case.
    fn scans(&self) -> impl Iterator<Item = &ScanV1> {
        self.steps.iter().filter_map(|step| match step {
            StepV1::Scan(scan) => Some(scan),
            StepV1::Install(_) | StepV1::Bind(_) | StepV1::Refresh(_) | StepV1::Pass(_) => None,
        })
    }

    /// Whether an `absent` expectation has exactly one `scan` step with its marker and metadata.
    fn scans_agree(&self) -> bool {
        let ExpectV1::Absent(absent) = &self.expect else {
            return true;
        };
        let mut scans = self.scans();
        let (first, second) = (scans.next(), scans.next());
        match (first, second) {
            (Some(scan), None) => scan.marker == absent.marker && scan.retained == absent.retained,
            _ => false,
        }
    }

    /// The grammar rules that need no context.
    fn is_wellformed(&self) -> bool {
        self.expect.is_valid() && self.scans_agree()
    }

    /// The rules of a sub-case of a payload: `nested` and the `malformed` expectation belong
    /// to `mal.6` only.
    fn is_valid(&self) -> bool {
        let malformed = self.id.as_str() == MALFORMED_SUBCASE;
        let expects = matches!(self.expect, ExpectV1::Malformed(_));
        malformed == self.nested.is_some() && malformed == expects && self.is_wellformed()
    }
}

/// The `provider` header of a `downgrade` payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderV1 {
    pub provider_id: Text,
    pub contract_version: Text,
    pub abi_major: JsonU64,
    pub abi_minor: JsonU64,
    pub from_abi_minor: JsonU64,
}

impl ProviderV1 {
    /// Whether the header equals the adapter's constants and the materializer's transition.
    fn is_valid(&self) -> bool {
        self.provider_id.as_str() == PROVIDER_ID
            && self.contract_version.as_str() == CONTRACT_VERSION
            && self.abi_major.0 == 0
            && self.abi_minor.0 == 0
            && self.from_abi_minor.0 == 1
    }
}

/// The case payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaseV1 {
    pub schema: Text,
    pub family: Text,
    pub subcases: Vec<SubCaseV1>,
    #[serde(default, deserialize_with = "present")]
    pub provider: Option<ProviderV1>,
}

impl CaseV1 {
    /// Parse and check the payload `bytes` of a case of `family`.
    ///
    /// # Errors
    /// Returns [`InvalidCaseV1`] for JSON that violates the grammar, a schema string other
    /// than the pinned one, a `family` that differs from the attempt's, no sub-cases, more than
    /// 64 sub-cases, a repeated sub-case id, or a `provider` header that is missing, unexpected
    /// or not the transition.
    pub fn parse(bytes: &[u8], family: FixtureFamily) -> Result<Self, InvalidCaseV1> {
        let parsed = serde_json::from_slice::<Self>(bytes).or(Err(InvalidCaseV1));
        parsed.and_then(|case| case.checked(family))
    }

    /// Whether no two sub-cases share an ID.
    fn ids_are_unique(&self) -> bool {
        let ids: BTreeSet<&str> = self.subcases.iter().map(|s| s.id.as_str()).collect();
        ids.len() == self.subcases.len()
    }

    fn checked(self, family: FixtureFamily) -> Result<Self, InvalidCaseV1> {
        let provider = match (family, &self.provider) {
            (FixtureFamily::Downgrade, Some(header)) => header.is_valid(),
            (FixtureFamily::Downgrade, None) | (_, Some(_)) => false,
            (_, None) => true,
        };
        let valid = self.schema.as_str() == SCHEMA_ID
            && self.family.as_str() == family_text(family)
            && !self.subcases.is_empty()
            && self.subcases.len() <= MAX_SUBCASES
            && self.ids_are_unique()
            && provider
            && self.subcases.iter().all(SubCaseV1::is_valid);
        valid.then_some(self).ok_or(InvalidCaseV1)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
