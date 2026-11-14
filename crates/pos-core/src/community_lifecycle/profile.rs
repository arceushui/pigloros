//! CDP1 identity binds the complete selected lifecycle policy before CMB1/COB1.

use super::quarantine_control::encode_artifact_ref;
use super::{
    digest, encode_implementation_key, record_prefix, validate_horizon, ArtifactRefV1,
    CommunityLifecycleErrorV1 as Error, Result, MAX_COMMUNITY_MEMBERS_V1,
};
use crate::{encode_bytes, encode_hash, encode_head, Hash, ImplementationKeyV1};
use zeroize::Zeroizing;

const MAX_RECORD: usize = 1_048_576;
const RECOVERY_WINDOW: u64 = 86_400_000_000;
const OWNER: [u64; 4] = [1, 0, 65_536, 65_536];
const GRAPH: [u64; 10] = [
    1,
    4096,
    8192,
    4096,
    4096,
    67_108_864,
    268_435_456,
    67_108_864,
    2048,
    2048,
];
const LIMITS: [u64; 15] = [
    64,
    256,
    8192,
    4096,
    65_536,
    262_144,
    134_217_728,
    1_000_000,
    4_000_000,
    4_000_000,
    4_194_304,
    3_145_728,
    3836,
    16_384,
    65_536,
];
const WORKER: [u64; 10] = [
    30_000_000,
    27_000_000,
    24_000_000,
    250_000,
    64,
    1,
    1_073_741_824,
    16_384,
    1,
    0,
];
const ANNOTATION: [u64; 5] = [1_128_333_313, 1024, 1_048_576, 4096, 86_400_000_000];
const REPLAY: [u64; 3] = [1, 1, 0];
const _: () = assert!(1024 + MAX_COMMUNITY_MEMBERS_V1 * 512 < MAX_RECORD);
const _: () = assert!(1 + 66 + 3 + crate::MAX_IMPLEMENTATION_KEY_BYTES_V1 + 3 * 34 + 49 <= 512);

/// Retention backend named by the profile, not a deployment qualification.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityDurableBackendV1 {
    /// Code0; retained Memory, without process-restart persistence.
    RetainedMemory,
    /// Code1; the selected qualified `SQLite` process-restart composition.
    SqliteProcessRestart,
}

impl CommunityDurableBackendV1 {
    const fn code(self) -> u64 {
        match self {
            Self::RetainedMemory => 0,
            Self::SqliteProcessRestart => 1,
        }
    }
}

/// Immutable roster-policy row. It excludes future CMB1 and COB1 addresses.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityProfileMemberV1<'a> {
    stable_entry: &'a str,
    implementation: &'a ImplementationKeyV1,
    pmf1_digest: Hash,
    state_schema_digest: Hash,
    negotiated_tuple_digest: Hash,
    initializer: ArtifactRefV1,
}

impl<'a> CommunityProfileMemberV1<'a> {
    /// Bind the exact retained implementation and required initializer identity.
    ///
    /// # Errors
    /// Rejects invalid stable entry or zero release/required digests. Equality
    /// with actual admitted PMF1/schema/CNT1/initializer remains an owner check.
    pub fn new(
        stable_entry: &'a str,
        implementation: &'a ImplementationKeyV1,
        pmf1_digest: Hash,
        state_schema_digest: Hash,
        negotiated_tuple_digest: Hash,
        initializer: ArtifactRefV1,
    ) -> Result<Self> {
        if !crate::manifest_plugin_roster::valid_slot(stable_entry)
            || [
                implementation.release_digest(),
                pmf1_digest,
                state_schema_digest,
                negotiated_tuple_digest,
                Hash::from_bytes(initializer.digest),
            ]
            .contains(&Hash::zero())
        {
            Err(Error::InvalidBinding)
        } else {
            Ok(Self {
                stable_entry,
                implementation,
                pmf1_digest,
                state_schema_digest,
                negotiated_tuple_digest,
                initializer,
            })
        }
    }

    /// Original stable World entry, defining the strict roster order.
    #[must_use]
    pub const fn stable_entry(&self) -> &'a str {
        self.stable_entry
    }

    /// Exact independently retained IMK1, without cloned personal text fields.
    #[must_use]
    pub const fn implementation(&self) -> &'a ImplementationKeyV1 {
        self.implementation
    }

    /// PMF1, State schema and complete CNT1 identities, in their wire order.
    #[must_use]
    pub const fn digests(&self) -> [Hash; 3] {
        [
            self.pmf1_digest,
            self.state_schema_digest,
            self.negotiated_tuple_digest,
        ]
    }

    /// Exact initializer ref; this data value cannot admit its source.
    #[must_use]
    pub const fn initializer(&self) -> ArtifactRefV1 {
        self.initializer
    }
}

/// Exact finite original policy dates, never a sliding lease extension.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityProfileRetentionV1 {
    /// Original generation absolute trusted deadline, positive and <=`i64::MAX`.
    pub generation_not_after_micros: u64,
    /// Original recovery interval,1..24hours, not an absolute timestamp.
    pub recovery_window_micros: u64,
    /// Independently admitted quarantine absolute deadline.
    pub quarantine_not_after_micros: u64,
    /// Independently admitted native metadata absolute deadline.
    pub metadata_not_after_micros: u64,
}

/// Inputs for the exact ADR-129 initial selected policy, with all values encoded.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityDurableProfileInputV1<'a> {
    /// Explicit retained backend; no default inferred on restart.
    pub backend: CommunityDurableBackendV1,
    /// Existing complete execution-profile digest, distinct from CDP1/CNT1.
    pub execution_profile_digest: Hash,
    /// Complete roster in strict stable-entry byte order,1..64 members.
    pub roster: &'a [CommunityProfileMemberV1<'a>],
    /// Actual independently installed source/extractor catalogue.
    pub source_catalogue_digest: Hash,
    /// Actual independently installed authority catalogue.
    pub authority_catalogue_digest: Hash,
    /// Exact original finite retention policy.
    pub retention: CommunityProfileRetentionV1,
}

/// Complete CDP1 data for the accepted initial profile; not an installation permit.
///
/// The selected owner/graph/capacity/worker/annotation/Replay values are literal
/// record inputs, never omitted environment defaults. A deployment with lower
/// limits must provide a separately qualified explicit policy; this constructor
/// supports exactly the accepted initial values and never substitutes a limit.
pub struct CommunityDurableProfileV1<'a>(CommunityDurableProfileInputV1<'a>);

impl<'a> CommunityDurableProfileV1<'a> {
    /// Check complete bounded roster order, identities and finite retention.
    ///
    /// # Errors
    /// Rejects absent/oversized/unordered/duplicate entries, zero catalogue or
    /// execution identities and invalid dates/window. Actual source authority,
    /// lease horizons, worst-case graph fit and worker qualification remain
    /// independent installation checks, not conclusions of this constructor.
    pub fn new(input: CommunityDurableProfileInputV1<'a>) -> Result<Self> {
        if input.roster.len() > MAX_COMMUNITY_MEMBERS_V1 {
            return Err(Error::BoundsExceeded);
        }
        if input.roster.is_empty()
            || [
                input.execution_profile_digest,
                input.source_catalogue_digest,
                input.authority_catalogue_digest,
            ]
            .contains(&Hash::zero())
            || input
                .roster
                .windows(2)
                .any(|pair| pair[0].stable_entry.as_bytes() >= pair[1].stable_entry.as_bytes())
        {
            return Err(Error::InvalidBinding);
        }
        let retention = input.retention;
        if retention.recovery_window_micros == 0
            || retention.recovery_window_micros > RECOVERY_WINDOW
        {
            return Err(Error::BoundsExceeded);
        }
        [
            retention.generation_not_after_micros,
            retention.quarantine_not_after_micros,
            retention.metadata_not_after_micros,
        ]
        .into_iter()
        .try_for_each(validate_horizon)
        .map(|()| Self(input))
    }

    /// Borrow complete recorded data without choosing a current replacement.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityDurableProfileInputV1<'a> {
        &self.0
    }

    /// Encode all14 fields, including all seven explicit canonical policy bstrs.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(1024 + input.roster.len() * 512));
        record_prefix(&mut out, 14, *b"CDP1");
        encode_head(&mut out, 0, input.backend.code());
        encode_hash(&mut out, input.execution_profile_digest);
        encode_head(&mut out, 4, input.roster.len() as u64);
        for member in input.roster {
            out.push(0x86);
            encode_bytes(&mut out, member.stable_entry.as_bytes(), 3);
            encode_implementation_key(&mut out, member.implementation);
            for hash in member.digests() {
                encode_hash(&mut out, hash);
            }
            encode_artifact_ref(&mut out, member.initializer);
        }
        encode_policy(&mut out, &OWNER);
        encode_hash(&mut out, input.source_catalogue_digest);
        encode_hash(&mut out, input.authority_catalogue_digest);
        encode_policy(&mut out, &GRAPH);
        encode_policy(&mut out, &LIMITS);
        let retention = input.retention;
        encode_policy(
            &mut out,
            &[
                retention.generation_not_after_micros,
                retention.recovery_window_micros,
                retention.quarantine_not_after_micros,
                retention.metadata_not_after_micros,
            ],
        );
        encode_policy(&mut out, &WORKER);
        encode_policy(&mut out, &ANNOTATION);
        encode_policy(&mut out, &REPLAY);
        out
    }

    /// Exact CDP1 logical identity, including backend, modes through CNT1 and policy.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CDP1.v1\0", &self.to_canonical_cbor())
    }

    /// Compare retained bytes against the exact independently reconstructed profile.
    ///
    /// # Errors
    /// Rejects an oversized, partial, nonpreferred, versioned, unknown or
    /// substituted policy/roster. Expected data must come from retained original
    /// policy, admitted roster and catalogues, never the current host defaults.
    pub fn validate_canonical_cbor(
        bytes: &[u8],
        expected: CommunityDurableProfileInputV1<'a>,
    ) -> Result<Self> {
        if bytes.len() > MAX_RECORD {
            return Err(Error::BoundsExceeded);
        }
        Self::new(expected).and_then(|record| {
            if bytes == record.to_canonical_cbor().as_slice() {
                Ok(record)
            } else {
                Err(Error::InvalidBinding)
            }
        })
    }
}

fn encode_policy(out: &mut Vec<u8>, values: &[u64]) {
    let mut bytes = Zeroizing::new(Vec::with_capacity(9 + values.len() * 9));
    encode_head(&mut bytes, 4, values.len() as u64);
    for value in values {
        encode_head(&mut bytes, 0, *value);
    }
    encode_bytes(out, &bytes, 2);
}
