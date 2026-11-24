//! CDP1 identity binds the complete selected lifecycle policy before CMB1/COB1.

use super::quarantine_control::encode_artifact_ref;
use super::{
    digest, encode_implementation_key, record_prefix, validate_horizon, ArtifactRefV1,
    CommunityLifecycleErrorV1 as Error, Result, MAX_COMMUNITY_MEMBERS_V1,
};
use crate::{encode_bytes, encode_hash, encode_head, Hash, ImplementationKeyV1};
use zeroize::Zeroizing;

/// Reference schema ID of the code-0 initializer set `L` (R6.4, P6).
pub const COMMUNITY_INITIALIZER_SET_SCHEMA_V1: u32 = 0x4341_0004;
const MAX_RECORD: usize = 1_048_576;
// The largest `L`, a plain literal: array head 1 and 64 refs of at most 49
// bytes (array head 1, schema ID 5, length head 9 and digest 34).
const MAX_SET_BYTES: usize = 3_137;
const _: () = assert!(MAX_COMMUNITY_MEMBERS_V1 == 64);
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
/// The CDP1 `limits_bytes` shared per-record maxima `[nodes, edges, bytes]`
/// that every operation's CBQ1 quote must fit (ADR-129 §2, §5).
pub const COMMUNITY_SHARED_RECORD_LIMITS_V1: [u64; 3] = [LIMITS[4], LIMITS[5], LIMITS[6]];

/// The CDP1 `owner_policy_bytes` maximum store keys, compared with the
/// domain's live key count (ADR-129 §2; revision 11, R11.1(6)).
pub const COMMUNITY_MAXIMUM_STORE_KEYS_V1: u64 = OWNER[2];

/// The CDP1 `limits_bytes` roster maximum (ADR-129 revision 13, R13.3):
/// a CDP1 with more roster rows is refused at installation.
pub const COMMUNITY_MAXIMUM_ROSTER_V1: usize = 3;

/// `R_other`, the erasure targets left to writers that do not check the
/// budget (ADR-129 revision 13, R13.1(6)).
pub const COMMUNITY_ERASURE_RESERVE_V1: u64 = 128;

/// The community line `4,096 - R_other`: no community operation takes an
/// actor's `targets(A)` above it (R13.1(3)).
pub const COMMUNITY_ERASURE_TARGET_LINE_V1: u64 =
    crate::ERASURE_MAX_TARGETS as u64 - COMMUNITY_ERASURE_RESERVE_V1;

/// The ADR-136 view-list bound: a Timeline's `rows(U)` of any class stay at
/// most 4,096 (R13.1(1), (3)).
pub const COMMUNITY_ERASURE_ROW_LIMIT_V1: u64 = crate::ERASURE_MAX_OBLIGATIONS_PER_CATEGORY as u64;

/// `F_q` per roster member: four quarantine reasons, one CFO1 row each, at
/// two targets per row (R13.1(5)).
pub const COMMUNITY_QUARANTINE_RESERVE_PER_MEMBER_V1: u64 = 8;

// R13.3 minimum-lifetime floor: the minimum required pass, repeated 64
// times from the initialization base with every member due and no new
// Event, fits at the roster maximum the 4,096-registration and 8,192-edge
// closure bounds (5n + 2 + 7n x 64 and 6n + 1 + 11n x 64) and the erasure
// budget with its reserves: 2 + 10n + 6 + 8n + 64 x (18n + 6) + 2(n + 1),
// that is 394 + 1,172n, at most 4,096 - 128. The sums depend on n alone, so
// no installable CDP1 can fail them.
const _: () = assert!(5 * LIMITS[0] + 2 + 7 * LIMITS[0] * 64 <= GRAPH[1]);
const _: () = assert!(6 * LIMITS[0] + 1 + 11 * LIMITS[0] * 64 <= GRAPH[2]);
const _: () = assert!(394 + 1172 * LIMITS[0] <= COMMUNITY_ERASURE_TARGET_LINE_V1);
// R11.1(5): no V1 key reaches the per-key encryption maximum. The pass
// ExecutionState cohort holds at most n x (7 + 2 x 16) + 2 records plus the
// Measurement CPN1s, and a CES1 cohort at most 4,096 records, two credits
// each.
const _: () = assert!(2 * (LIMITS[0] * (7 + 2 * 16 + 1) + 2) <= OWNER[3]);
const _: () = assert!(2 * LIMITS[3] <= OWNER[3]);

/// The CDP1 `limits_bytes` cumulative recorded-set maxima `[nodes, edges,
/// declared_inputs]` (ADR-129 §2; revision 10, R10.4(1)).
pub const COMMUNITY_CUMULATIVE_RECORD_LIMITS_V1: [u64; 3] = [LIMITS[7], LIMITS[8], LIMITS[9]];

/// The CDP1 `limits_bytes` cap on retained detailed pass outcomes per
/// generation (ADR-129 §2; revision 10, R10.4(4)).
pub const COMMUNITY_RETAINED_PASS_OUTCOMES_V1: u64 = LIMITS[1];

/// The CDP1 `limits_bytes` cap on retained control/protection operations
/// per generation (ADR-129 §2; revision 10, R10.4(4)).
pub const COMMUNITY_CONTROL_OPERATIONS_V1: u64 = LIMITS[2];

/// The CDP1 `limits_bytes` deterministic fold budget, 12 s in microseconds
/// (ADR-129 revision 9, R9.7(a)): the 16th entry.
pub const COMMUNITY_FOLD_BUDGET_MICROS_V1: u64 = LIMITS[15];

/// The CDP1 `worker_policy_bytes` decision deadline, 27 s in microseconds,
/// measured from guard start (ADR-129 §2; revisions 8 and 10).
pub const COMMUNITY_DECISION_DEADLINE_MICROS_V1: u64 = WORKER[1];

const LIMITS: [u64; 16] = [
    COMMUNITY_MAXIMUM_ROSTER_V1 as u64,
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
    12_000_000,
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
// Installation requires the fold budget below the worker result deadline.
const _: () = assert!(LIMITS[15] < WORKER[2]);
const ANNOTATION: [u64; 5] = [1_128_333_313, 1024, 1_048_576, 4096, 86_400_000_000];
const REPLAY: [u64; 3] = [1, 1, 0];
const _: () = assert!(1024 + MAX_COMMUNITY_MEMBERS_V1 * 512 < MAX_RECORD);
// A roster row: array head, stable entry, IMK1 bstr, three digests, the
// initializer ref and the widest cadence interval (revision 10, R10.1).
const _: () = assert!(1 + 66 + 3 + crate::MAX_IMPLEMENTATION_KEY_BYTES_V1 + 3 * 34 + 49 + 9 <= 512);

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
    cadence_interval_ns: u64,
}

impl<'a> CommunityProfileMemberV1<'a> {
    /// Bind the exact retained implementation, required initializer identity
    /// and cadence interval.
    ///
    /// `cadence_interval_ns` is the member's only cadence interval, in
    /// Simulation Time nanoseconds (revision 10, R10.1).
    ///
    /// # Errors
    /// Rejects invalid stable entry, zero release/required digests and a zero
    /// cadence interval. Equality with actual admitted PMF1/schema/CNT1/
    /// initializer remains an owner check.
    pub fn new(
        stable_entry: &'a str,
        implementation: &'a ImplementationKeyV1,
        pmf1_digest: Hash,
        state_schema_digest: Hash,
        negotiated_tuple_digest: Hash,
        initializer: ArtifactRefV1,
        cadence_interval_ns: u64,
    ) -> Result<Self> {
        let identities = [
            implementation.release_digest(),
            pmf1_digest,
            state_schema_digest,
            negotiated_tuple_digest,
            Hash::from_bytes(initializer.digest),
        ];
        if valid_row(stable_entry, &identities, cadence_interval_ns) {
            Ok(Self {
                stable_entry,
                implementation,
                pmf1_digest,
                state_schema_digest,
                negotiated_tuple_digest,
                initializer,
                cadence_interval_ns,
            })
        } else {
            Err(Error::InvalidBinding)
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

    /// The member's cadence interval in Simulation Time nanoseconds, at
    /// least 1 (revision 10, R10.1).
    #[must_use]
    pub const fn cadence_interval_ns(&self) -> u64 {
        self.cadence_interval_ns
    }
}

/// A roster row's local invariants: an ADR-088 stable entry, nonzero
/// identities and a cadence interval of at least 1 (revision 10, R10.1).
fn valid_row(stable_entry: &str, identities: &[Hash], cadence_interval_ns: u64) -> bool {
    cadence_interval_ns != 0
        && crate::manifest_plugin_roster::valid_slot(stable_entry)
        && !identities.contains(&Hash::zero())
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
    /// The installed recording owner's admitted absolute horizon for the
    /// purpose-2 `ReplayRecording` evidence (revision 10, R10.4(3)).
    pub recording_not_after_micros: u64,
}

impl CommunityProfileRetentionV1 {
    /// The first four `retention_bytes` entries: the `RetentionPolicy`
    /// lease preimage, which excludes the recording horizon (R10.4(3)).
    const fn lease_entries(self) -> [u64; 4] {
        [
            self.generation_not_after_micros,
            self.recovery_window_micros,
            self.quarantine_not_after_micros,
            self.metadata_not_after_micros,
        ]
    }
}

/// Inputs for the exact ADR-129 initial selected policy, with all values encoded.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityDurableProfileInputV1<'a> {
    /// Explicit retained backend; no default inferred on restart.
    pub backend: CommunityDurableBackendV1,
    /// Existing complete execution-profile digest, distinct from CDP1/CNT1.
    pub execution_profile_digest: Hash,
    /// Complete roster in strict stable-entry byte order, 1..=9 members.
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
        if input.roster.len() > COMMUNITY_MAXIMUM_ROSTER_V1 {
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
            retention.recording_not_after_micros,
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
            out.push(0x87);
            encode_bytes(&mut out, member.stable_entry.as_bytes(), 3);
            encode_implementation_key(&mut out, member.implementation);
            for hash in member.digests() {
                encode_hash(&mut out, hash);
            }
            encode_artifact_ref(&mut out, member.initializer);
            encode_head(&mut out, 0, member.cadence_interval_ns);
        }
        encode_policy(&mut out, &OWNER);
        encode_hash(&mut out, input.source_catalogue_digest);
        encode_hash(&mut out, input.authority_catalogue_digest);
        encode_policy(&mut out, &GRAPH);
        encode_policy(&mut out, &LIMITS);
        let retention = input.retention;
        let [generation, recovery, quarantine, metadata] = retention.lease_entries();
        encode_policy(
            &mut out,
            &[
                generation,
                recovery,
                quarantine,
                metadata,
                retention.recording_not_after_micros,
            ],
        );
        encode_policy(&mut out, &WORKER);
        encode_policy(&mut out, &ANNOTATION);
        encode_policy(&mut out, &REPLAY);
        out
    }

    /// `H("RetentionPolicy", retention_bytes)`: the generation's CDP1
    /// retention-policy digest over the canonical array of the first four
    /// `retention_bytes` entries. It is the lease reference of a native
    /// Event's whole-Timeline scope row (owner 2026-11-21 (#560), item (c)),
    /// so it never depends on the recording horizon (revision 10, R10.4(3)).
    #[must_use]
    pub fn retention_policy_digest(&self) -> Hash {
        let mut bytes = Vec::with_capacity(37);
        encode_head(&mut bytes, 4, 4);
        for value in self.0.retention.lease_entries() {
            encode_head(&mut bytes, 0, value);
        }
        digest(b"PiglorOS.Community.RetentionPolicy.v1\0", &bytes)
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

/// The code-0 CGI1 `admitted_initializer_ref` of a roster (R6.1(7), P6).
///
/// It is `[0x4341_0004, len(L), H("InitializerSet", L)]`, where `L` is the
/// preferred array of the roster rows' `initializer_artifact_ref`s in roster
/// order.
///
/// The ref commits to the installed roster only; it admits no initializer
/// and resolves no State.
#[must_use]
pub fn community_initializer_set_ref_v1(profile: &CommunityDurableProfileV1<'_>) -> ArtifactRefV1 {
    let roster = profile.as_input().roster;
    let mut set = Vec::with_capacity(MAX_SET_BYTES);
    encode_head(&mut set, 4, roster.len() as u64);
    for member in roster {
        encode_artifact_ref(&mut set, member.initializer);
    }
    ArtifactRefV1 {
        schema_id: COMMUNITY_INITIALIZER_SET_SCHEMA_V1,
        byte_length: set.len() as u64,
        digest: *digest(b"PiglorOS.Community.InitializerSet.v1\0", &set).as_bytes(),
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
