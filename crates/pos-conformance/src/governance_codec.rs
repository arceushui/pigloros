// Shared codec of the ADR-062 Revision 8 governance records (slice G3, #1238), included at the
// crate root so the record modules share it. Wire layouts, codes and digest rules are fixed by
// the wiki note `ADR-062_R8_Governance_Records` (2026-11-06). Every record is the exact
// deterministic-CBOR array `[magic, 1, fields..., record_digest]`, where `record_digest` is
// BLAKE3 over the record's domain, one NUL byte and the canonical array of every earlier field.

/// Largest encoded governance record (1 MiB, inclusive).
pub const MAX_CONFORMANCE_GOVERNANCE_RECORD_BYTES_V1: usize = 1024 * 1024;
/// Most approver ids in one governance record.
pub const MAX_CONFORMANCE_GOVERNANCE_APPROVERS_V1: usize = 32;
/// Most items in any governance record list.
pub const MAX_CONFORMANCE_GOVERNANCE_LIST_ITEMS_V1: usize = 4096;

/// The deepest item admitted by `preflight_array_cbor`, which counts the record array as depth
/// 0 and every item inside an array as one deeper: list items and tuple fields such as a CPR1
/// identity at 2, and the scalars of a CIA1 `[report_digest, effect]` entry at 3. Any item may
/// sit at depth 3, including an empty array, so the wiki's "two arrays deep" (a list and its
/// entry arrays below the record) is only an upper bound here; the per-record decoders refuse
/// any array whose shape is not the exact record layout.
const GOVERNANCE_MAX_NESTING_DEPTH: u8 = 3;
const GOVERNANCE_MAX_IDENTIFIER_BYTES: usize = 128;

/// Closed errors of the governance record codecs and validators.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConformanceGovernanceErrorV1 {
    /// The bytes are malformed, not canonical, trailing, or use a forbidden CBOR item.
    #[error("invalid governance record encoding")]
    InvalidEncoding,
    /// The magic or record version is not the expected record version 1.
    #[error("unsupported governance record version")]
    UnsupportedSchemaVersion,
    /// A value, code or the encoded record is outside its bound.
    #[error("governance record field is out of bounds")]
    FieldOutOfBounds,
    /// A list is not strictly ascending.
    #[error("governance record list is not canonical")]
    NonCanonicalOrder,
    /// The stored record digest is not the recomputed one.
    #[error("governance record digest does not recompute")]
    RecordDigestMismatch,
    /// A waiver expires at or before its issue epoch.
    #[error("waiver expiry is not after its issue epoch")]
    ExpiryNotAfterIssue,
    /// A conflict resolution and its resolving profile digest disagree.
    #[error("conflict resolution is invalid")]
    InvalidResolution,
    /// A correction's replacement digest equals its old digest.
    #[error("correction does not change the artifact digest")]
    CorrectionWithoutChange,
    /// A withdrawal source does not match its reason code.
    #[error("withdrawal source does not match its reason")]
    InvalidWithdrawalSource,
    /// A stored retention bound is not the recomputed one.
    #[error("retention bound does not recompute")]
    RetentionBoundMismatch,
    /// A promotion is not a single forward step to Candidate or Stable.
    #[error("promotion lifecycle transition is invalid")]
    InvalidLifecycleTransition,
    /// The waiver names another profile.
    #[error("waiver names another profile")]
    ProfileMismatch,
    /// The profile has no fixture for the waived case, claim layer and mode.
    #[error("waived case is not in the profile")]
    CaseNotInProfile,
    /// The epoch is outside the waiver's issue and expiry epochs.
    #[error("waiver is not in force at this epoch")]
    WaiverNotInForce,
    /// A waiver on a mandatory case is only a Candidate exception.
    #[error("waiver on a mandatory case outside Candidate")]
    MandatoryWaiverOutsideCandidate,
    /// An open conflict keeps the profile Candidate.
    #[error("open conflict refuses Stable")]
    OpenConflict,
    /// The impact analysis and the correction do not name each other.
    #[error("impact analysis does not bind the correction")]
    CorrectionMismatch,
    /// A report naming the corrected digest is missing from the impact analysis.
    #[error("impact analysis is missing an affected report")]
    AffectedReportMissing,
    /// The withdrawn report bytes are not a valid CNR1 report.
    #[error("withdrawn report is unreadable")]
    ReportUnreadable,
    /// The report is not the withdrawn report.
    #[error("report is not the withdrawn report")]
    ReportMismatch,
    /// Removal of a retired artifact before both retention bounds are met.
    #[error("retired artifact removal is too early")]
    RemovalTooEarly,
}

macro_rules! governance_code_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$variant_meta:meta])* $variant:ident = $code:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* $variant),+
        }

        impl $name {
            /// Decode a closed wire code.
            #[must_use]
            pub const fn from_wire_code(code: u64) -> Option<Self> {
                match code {
                    $($code => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// The closed wire code.
            #[must_use]
            pub const fn wire_code(self) -> u64 {
                match self {
                    $(Self::$variant => $code,)+
                }
            }
        }
    };
}

governance_code_enum! {
    /// The kind of a corrected (CCR1) or retired (CRT1) conformance artifact.
    ConformanceArtifactKindV1 {
        NormativeSpec = 0,
        ConformanceProfile = 1,
        FixtureBundle = 2,
        Fixture = 3,
        ExpectedResult = 4,
        EvaluatorProtocol = 5,
        EvaluatorBinary = 6,
        Report = 7,
    }
}

governance_code_enum! {
    /// The closed reason of a CWV1 waiver.
    ConformanceWaiverReasonV1 {
        FixtureDefect = 0,
        ExpectedResultDefect = 1,
        NormativeAmbiguity = 2,
        EnvironmentUnavailable = 3,
        KnownImplementationFailure = 4,
    }
}

governance_code_enum! {
    /// The kind of a CCF1 conflict.
    ConformanceConflictKindV1 {
        ConflictOfInterest = 0,
        ImplementationDisagreement = 1,
        SharedCode = 2,
    }
}

governance_code_enum! {
    /// The resolution state of a CCF1 conflict.
    ConformanceConflictResolutionV1 {
        Open = 0,
        ResolvedByNewProfileDigest = 1,
    }
}

governance_code_enum! {
    /// The closed reason of a CCR1 correction.
    ConformanceCorrectionReasonV1 {
        FixtureDefect = 0,
        ExpectedResultDefect = 1,
        NormativeAmbiguity = 2,
        SecurityDefect = 3,
        ProvenanceDefect = 4,
    }
}

governance_code_enum! {
    /// The effect of a correction on one affected report in a CIA1 impact analysis.
    ConformanceImpactEffectV1 {
        Withdrawn = 0,
        Unaffected = 1,
        RerunRequired = 2,
    }
}

governance_code_enum! {
    /// The closed reason of a CWD1 withdrawal.
    ConformanceWithdrawalReasonV1 {
        Corrected = 0,
        ConflictResolved = 1,
        KeyRevoked = 2,
        EvidenceInvalid = 3,
        SubmitterRequest = 4,
    }
}

governance_code_enum! {
    /// The record kind a CWD1 withdrawal source digest names.
    ConformanceWithdrawalSourceKindV1 {
        Correction = 0,
        Conflict = 1,
    }
}

/// One governance record kind: its magic, digest domain and the fields between the version
/// and the record digest.
pub(crate) trait GovernanceRecordV1: Sized {
    const MAGIC: &'static str;
    const DOMAIN: &'static [u8];
    const BODY_FIELDS: u64;

    fn encode_body(&self, encoder: &mut GovernanceEncoder);
    fn decode_body(
        body: Vec<Value>,
        record_digest: [u8; 32],
    ) -> Result<Self, ConformanceGovernanceErrorV1>;
    fn stored_record_digest(&self) -> [u8; 32];
    /// Every rule of the record except its digest.
    fn check(&self) -> Result<(), ConformanceGovernanceErrorV1>;
}

/// An infallible shortest-form encoder of definite-length CBOR.
pub(crate) struct GovernanceEncoder {
    pub(crate) out: Vec<u8>,
}

impl GovernanceEncoder {
    pub(crate) fn array(len: u64) -> Self {
        let mut encoder = Self { out: Vec::new() };
        encoder.head(4, len);
        encoder
    }

    fn head(&mut self, major: u8, value: u64) {
        let be = value.to_be_bytes();
        let (additional, width) = match value {
            0..=23 => (be[7], 0),
            24..=0xff => (24, 1),
            0x100..=0xffff => (25, 2),
            0x1_0000..=0xffff_ffff => (26, 4),
            _ => (27, 8),
        };
        self.out.push((major << 5) + additional);
        self.out.extend_from_slice(&be[8 - width..]);
    }

    pub(crate) fn uint(&mut self, value: u64) {
        self.head(0, value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.head(2, value.len() as u64);
        self.out.extend_from_slice(value);
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.head(3, value.len() as u64);
        self.out.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn open_array(&mut self, len: usize) {
        self.head(4, len as u64);
    }

    /// `null`, or the item `encode` writes for the value.
    pub(crate) fn optional<T>(&mut self, value: Option<T>, encode: impl FnOnce(&mut Self, T)) {
        self.out.extend(value.map_or_else(
            || vec![0xf6],
            |value| {
                let mut item = Self { out: Vec::new() };
                encode(&mut item, value);
                item.out
            },
        ));
    }

    pub(crate) fn digests(&mut self, values: &[[u8; 32]]) {
        self.open_array(values.len());
        for value in values {
            self.bytes(value);
        }
    }

    pub(crate) fn texts(&mut self, values: &[String]) {
        self.open_array(values.len());
        for value in values {
            self.text(value);
        }
    }
}

fn governance_unsealed<R: GovernanceRecordV1>(record: &R, fields: u64) -> GovernanceEncoder {
    let mut encoder = GovernanceEncoder::array(fields);
    encoder.text(R::MAGIC);
    encoder.uint(1);
    record.encode_body(&mut encoder);
    encoder
}

/// The record digest recomputed over every field before it.
pub(crate) fn governance_record_digest<R: GovernanceRecordV1>(record: &R) -> [u8; 32] {
    domain_digest(
        R::DOMAIN,
        &governance_unsealed(record, R::BODY_FIELDS + 2).out,
    )
}

/// Validate every record rule, then the stored record digest.
pub(crate) fn governance_validate<R: GovernanceRecordV1>(
    record: &R,
) -> Result<(), ConformanceGovernanceErrorV1> {
    record.check().and_then(|()| {
        if governance_record_digest(record) == record.stored_record_digest() {
            Ok(())
        } else {
            Err(ConformanceGovernanceErrorV1::RecordDigestMismatch)
        }
    })
}

/// Encode a valid record as its canonical bytes.
pub(crate) fn governance_encode<R: GovernanceRecordV1>(
    record: &R,
) -> Result<Vec<u8>, ConformanceGovernanceErrorV1> {
    governance_validate(record).map(|()| {
        let mut encoder = governance_unsealed(record, R::BODY_FIELDS + 3);
        encoder.bytes(&record.stored_record_digest());
        encoder.out
    })
}

/// Decode and validate exact canonical record bytes.
pub(crate) fn governance_decode<R: GovernanceRecordV1>(
    bytes: &[u8],
) -> Result<R, ConformanceGovernanceErrorV1> {
    if bytes.len() > MAX_CONFORMANCE_GOVERNANCE_RECORD_BYTES_V1 {
        return Err(ConformanceGovernanceErrorV1::FieldOutOfBounds);
    }
    preflight_array_cbor(
        bytes,
        GOVERNANCE_MAX_NESTING_DEPTH,
        MAX_CONFORMANCE_GOVERNANCE_LIST_ITEMS_V1 as u64,
        true,
    )
    .map_err(governance_preflight_error)?;
    let value: Value = ciborium::from_reader(Cursor::new(bytes))
        .map_err(|_| ConformanceGovernanceErrorV1::InvalidEncoding)?;
    let mut fields = governance_array(value)?.into_iter();
    let (Some(magic), Some(version)) = (fields.next(), fields.next()) else {
        return Err(ConformanceGovernanceErrorV1::InvalidEncoding);
    };
    let mut body: Vec<Value> = fields.collect();
    let record_digest = body
        .pop()
        .ok_or(ConformanceGovernanceErrorV1::InvalidEncoding)
        .and_then(governance_fixed)?;
    if governance_text(magic)? != R::MAGIC || governance_uint(&version)? != 1 {
        return Err(ConformanceGovernanceErrorV1::UnsupportedSchemaVersion);
    }
    let record = R::decode_body(body, record_digest)?;
    if governance_encode(&record)? == bytes {
        Ok(record)
    } else {
        Err(ConformanceGovernanceErrorV1::InvalidEncoding)
    }
}

const fn governance_preflight_error(error: CborPreflightError) -> ConformanceGovernanceErrorV1 {
    match error {
        CborPreflightError::InvalidEncoding => ConformanceGovernanceErrorV1::InvalidEncoding,
        CborPreflightError::FieldOutOfBounds => ConformanceGovernanceErrorV1::FieldOutOfBounds,
    }
}

/// The exact number of body fields, or `InvalidEncoding`.
pub(crate) fn governance_fields<const N: usize>(
    body: Vec<Value>,
) -> Result<[Value; N], ConformanceGovernanceErrorV1> {
    body.try_into()
        .map_err(|_| ConformanceGovernanceErrorV1::InvalidEncoding)
}

pub(crate) fn governance_array(value: Value) -> Result<Vec<Value>, ConformanceGovernanceErrorV1> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(ConformanceGovernanceErrorV1::InvalidEncoding),
    }
}

pub(crate) fn governance_text(value: Value) -> Result<String, ConformanceGovernanceErrorV1> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(ConformanceGovernanceErrorV1::InvalidEncoding),
    }
}

pub(crate) fn governance_uint(value: &Value) -> Result<u64, ConformanceGovernanceErrorV1> {
    match value {
        Value::Integer(integer) => {
            u64::try_from(*integer).map_err(|_| ConformanceGovernanceErrorV1::InvalidEncoding)
        }
        _ => Err(ConformanceGovernanceErrorV1::InvalidEncoding),
    }
}

pub(crate) fn governance_bytes(value: Value) -> Result<Vec<u8>, ConformanceGovernanceErrorV1> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(ConformanceGovernanceErrorV1::InvalidEncoding),
    }
}

pub(crate) fn governance_fixed<const N: usize>(
    value: Value,
) -> Result<[u8; N], ConformanceGovernanceErrorV1> {
    governance_bytes(value).and_then(|bytes| {
        bytes
            .try_into()
            .map_err(|_| ConformanceGovernanceErrorV1::InvalidEncoding)
    })
}

/// `null`, or the value decoded by `decode`.
pub(crate) fn governance_optional<T>(
    value: Value,
    decode: impl FnOnce(Value) -> Result<T, ConformanceGovernanceErrorV1>,
) -> Result<Option<T>, ConformanceGovernanceErrorV1> {
    match value {
        Value::Null => Ok(None),
        value => decode(value).map(Some),
    }
}

pub(crate) fn governance_digests(
    value: Value,
) -> Result<Vec<[u8; 32]>, ConformanceGovernanceErrorV1> {
    governance_array(value)?
        .into_iter()
        .map(governance_fixed)
        .collect()
}

pub(crate) fn governance_texts(value: Value) -> Result<Vec<String>, ConformanceGovernanceErrorV1> {
    governance_array(value)?
        .into_iter()
        .map(governance_text)
        .collect()
}

/// A closed code; an unknown code is `FieldOutOfBounds`.
pub(crate) fn governance_code<T>(
    value: &Value,
    from_wire_code: impl FnOnce(u64) -> Option<T>,
) -> Result<T, ConformanceGovernanceErrorV1> {
    governance_uint(value)
        .and_then(|code| from_wire_code(code).ok_or(ConformanceGovernanceErrorV1::FieldOutOfBounds))
}

pub(crate) fn governance_mode(code: u64) -> Option<ExecutionModeV1> {
    u8::try_from(code)
        .ok()
        .and_then(ExecutionModeV1::from_wire_code)
}

pub(crate) fn governance_claim_layer(code: u64) -> Option<ClaimLayerV1> {
    u8::try_from(code)
        .ok()
        .and_then(ClaimLayerV1::from_wire_code)
}

/// A CNR1-style UTF-8 id: 1-128 bytes and not blank.
pub(crate) fn governance_utf8_id(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= GOVERNANCE_MAX_IDENTIFIER_BYTES
}

pub(crate) fn governance_identifier(value: &str) -> bool {
    identifier(value, GOVERNANCE_MAX_IDENTIFIER_BYTES)
}

/// A nonzero epoch, or `FieldOutOfBounds`.
pub(crate) const fn governance_epoch(epoch: u64) -> Result<(), ConformanceGovernanceErrorV1> {
    if epoch == 0 {
        Err(ConformanceGovernanceErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

/// 1-32 identifiers in strictly ascending order.
pub(crate) fn governance_approvers(
    approvers: &[String],
) -> Result<(), ConformanceGovernanceErrorV1> {
    if approvers.is_empty()
        || approvers.len() > MAX_CONFORMANCE_GOVERNANCE_APPROVERS_V1
        || !approvers.iter().all(|id| governance_identifier(id))
    {
        Err(ConformanceGovernanceErrorV1::FieldOutOfBounds)
    } else if strictly_ordered(approvers) {
        Ok(())
    } else {
        Err(ConformanceGovernanceErrorV1::NonCanonicalOrder)
    }
}
