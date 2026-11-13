//! The GMP1 canonical record of one Gateway execution-mode profile
//! (ADR-134 §2). `build.rs` and the crate share this module: the build
//! validates and encodes the reviewed declaration, and the crate validates
//! and re-encodes the compiled bytes it decodes.

use ciborium::Value;

/// The record magic, distinct from EPF1's `EPF1`.
pub(crate) const GMP1_MAGIC: &str = "GMP1";
/// The one record version.
pub(crate) const GMP1_VERSION: u8 = 1;
/// The one platform value: Linux.
pub(crate) const GMP1_PLATFORM_LINUX: u8 = 1;
/// The Local profile identifier.
pub(crate) const LOCAL_MODE_PROFILE_ID: &str = "gateway-mode-local-v1";
/// The Air-Gapped profile identifier.
pub(crate) const AIR_GAPPED_MODE_PROFILE_ID: &str = "gateway-mode-air-gapped-v1";
/// Startup predicates both modes require: linux, listeners-within-ingress,
/// network-features-granted, no-network-ledger-source, store-mode-binding.
pub(crate) const STARTUP_PREDICATES: [u8; 5] = [1, 2, 3, 4, 5];

/// The reviewed meaning of one identifier: fields 2 and 4 to 9. Changing it
/// needs an ADR-134 amendment.
struct ReviewedMeaningV1 {
    id: &'static str,
    mode: u8,
    network_allowed: bool,
    ingress: &'static [u8],
    revocation_freshness: u8,
    registration_profile_id: Option<&'static str>,
}

const REVIEWED_MEANINGS: [ReviewedMeaningV1; 2] = [
    ReviewedMeaningV1 {
        id: AIR_GAPPED_MODE_PROFILE_ID,
        mode: 2,
        network_allowed: false,
        ingress: &[1, 3],
        revocation_freshness: 1,
        registration_profile_id: None,
    },
    ReviewedMeaningV1 {
        id: LOCAL_MODE_PROFILE_ID,
        mode: 1,
        network_allowed: true,
        ingress: &[1, 2, 3],
        revocation_freshness: 2,
        registration_profile_id: Some("live-local-v1"),
    },
];

/// The fields of one GMP1 record other than its constant magic, version and
/// platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Gmp1RecordV1 {
    pub(crate) mode_profile_id: String,
    pub(crate) semantic_version: String,
    pub(crate) mode: u8,
    pub(crate) network_allowed: bool,
    pub(crate) ingress: Vec<u8>,
    pub(crate) startup_predicates: Vec<u8>,
    pub(crate) revocation_freshness: u8,
    pub(crate) registration_profile_id: Option<String>,
    pub(crate) previous_mode_profile_digest: Option<[u8; 32]>,
}

impl Gmp1RecordV1 {
    /// Check every ADR-134 §2 rule: a reviewed identifier whose fields match
    /// its reviewed meaning, and a `SemVer` 2.0.0 core version.
    ///
    /// # Errors
    /// Returns a description of the first broken rule.
    pub(crate) fn validate(&self) -> Result<(), String> {
        REVIEWED_MEANINGS
            .iter()
            .find(|meaning| meaning.id == self.mode_profile_id)
            .ok_or_else(|| format!("unknown mode profile id {}", self.mode_profile_id))
            .and_then(|meaning| {
                let matches = meaning.mode == self.mode
                    && meaning.network_allowed == self.network_allowed
                    && meaning.ingress == self.ingress.as_slice()
                    && STARTUP_PREDICATES.as_slice() == self.startup_predicates.as_slice()
                    && meaning.revocation_freshness == self.revocation_freshness
                    && meaning.registration_profile_id == self.registration_profile_id.as_deref();
                matches.then_some(()).ok_or_else(|| {
                    format!(
                        "{} does not match its reviewed meaning",
                        self.mode_profile_id
                    )
                })
            })
            .and_then(|()| {
                is_semantic_version(&self.semantic_version)
                    .then_some(())
                    .ok_or_else(|| format!("invalid semantic version {}", self.semantic_version))
            })
    }

    /// The exact canonical GMP1 bytes: a definite-length 12-field array with
    /// shortest-form integers. Serializing a float-free, map-free value into
    /// memory cannot fail, and every consumer compares the bytes it relies
    /// on, so a partial write could never be accepted.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let value = Value::Array(vec![
            Value::Text(GMP1_MAGIC.to_owned()),
            Value::Integer(GMP1_VERSION.into()),
            Value::Text(self.mode_profile_id.clone()),
            Value::Text(self.semantic_version.clone()),
            Value::Integer(self.mode.into()),
            Value::Bool(self.network_allowed),
            tags(&self.ingress),
            tags(&self.startup_predicates),
            Value::Integer(self.revocation_freshness.into()),
            self.registration_profile_id
                .clone()
                .map_or(Value::Null, Value::Text),
            Value::Integer(GMP1_PLATFORM_LINUX.into()),
            self.previous_mode_profile_digest
                .map_or(Value::Null, |digest| Value::Bytes(digest.to_vec())),
        ]);
        let mut bytes = Vec::new();
        drop(ciborium::ser::into_writer(&value, &mut bytes));
        bytes
    }
}

fn tags(values: &[u8]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::Integer((*value).into()))
            .collect(),
    )
}

/// `SemVer` 2.0.0 core of 5 to 29 bytes: three dot-separated numbers of at
/// most nine digits with no leading zero.
fn is_semantic_version(version: &str) -> bool {
    let parts = version.split('.').collect::<Vec<_>>();
    (5..=29).contains(&version.len())
        && parts.len() == 3
        && parts.iter().all(|part| {
            (1..=9).contains(&part.len())
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
        })
}
