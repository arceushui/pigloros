//! The metric-conformance case payload of provider contract 2.0.0 and its `MCS1` composite.
//!
//! The payload is RFC 8785 JSON (`pigloros.metric-conformance.case.v2`, profile section 5):
//! `{"schema", "family", "algorithm", "subcases": [...]}` with one to sixty-four sub-cases. Each
//! sub-case names its member by record kind, BLAKE3 digest and length (or `null`), its
//! expectation and, for the gate families, its stimulus. The members are the entries of the
//! family's `MCS1` composite, `["MCS1", 1, [[digest32, member], ...]]`, each addressed by the
//! BLAKE3 of its bytes in strictly increasing digest order.

use std::collections::BTreeMap;

use ciborium::value::Value;
use pos_plugin_eval::{METRIC_ALGORITHM_ID, METRIC_ALGORITHM_MAJOR};
use pos_reference::evaluator::AttemptArtifact;
use serde::de::IgnoredAny;
use serde::Deserialize;

use super::{CONTRACT_VERSION, PROVIDER_ID, SCHEMA_ID};

/// The magic of the member composite.
const COMPOSITE_MAGIC: &str = "MCS1";
/// The largest number of sub-cases one payload holds.
const MAX_SUBCASES: usize = 64;
/// The largest member ceiling an oversized-member stimulus may select: the #222 transport's
/// compiled member ceiling, 64 MiB.
const MAX_MEMBER_CEILING: u64 = 64 * 1024 * 1024;

/// The members of a composite, by the lowercase hexadecimal BLAKE3 of their bytes.
pub(super) type MembersV1 = BTreeMap<String, Vec<u8>>;

/// The record kind a result expectation names.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
pub(super) enum OutputRecordV1 {
    /// An `MTR1` metric result.
    #[serde(rename = "MTR1")]
    Metric,
    /// An `MQR1` quantization result.
    #[serde(rename = "MQR1")]
    Quantization,
}

impl OutputRecordV1 {
    /// The record name.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Metric => "MTR1",
            Self::Quantization => "MQR1",
        }
    }
}

/// What a sub-case comes to, compared between the expectation and the subject's observation.
#[derive(Eq, PartialEq)]
pub(super) enum OutcomeV1 {
    /// A result record with the lowercase hexadecimal BLAKE3 of its bytes.
    Result {
        record: OutputRecordV1,
        digest: String,
    },
    /// A closed `MetricErrorV1` with its wire code, name and first coordinate.
    MetricError {
        code: u8,
        error: String,
        coordinate: String,
    },
    /// The requested capability or network use is denied.
    Denied,
    /// The #222 transport rejected the member with the named error.
    TransportRejection(String),
    /// The requested execution steps exceed the attempt's budget.
    ResourceLimit,
    /// The presented provider contract is not the one the subject reads.
    IncompatibleContract,
    /// Nothing was refused and the sub-case carries no input.
    NoInput,
    /// A sub-case the subject does not decide, with its expectation kind.
    EvaluatorOwned(&'static str),
}

/// The stimulus gate a sub-case passes before its input is computed.
pub(super) enum GateV1 {
    /// The subject requests a capability.
    Capability(String),
    /// The subject attempts network use.
    Network,
    /// The subject requests this many execution steps.
    Steps(u64),
    /// The provider contract presented to the subject is its own.
    Contract { own: bool },
}

/// The input of a sub-case the subject computes.
pub(super) enum InputV1 {
    /// An `MTI1` member.
    Metric(Vec<u8>),
    /// An `MTQ1` member.
    Quantization(Vec<u8>),
    /// A zero-filled `MTI1` member of `length` bytes sent through the #222 transport under the
    /// member ceiling `ceiling`.
    Oversized { length: usize, ceiling: u64 },
}

/// What the subject does for a sub-case.
pub(super) enum StepV1 {
    /// The sub-case is decided by the evaluator or the generator, not by the subject.
    EvaluatorOwned(&'static str),
    /// The subject passes the gate, then computes the input.
    Subject {
        gate: Option<GateV1>,
        input: Option<InputV1>,
    },
}

/// One validated sub-case.
pub(super) struct SubCaseV1 {
    pub(super) id: String,
    pub(super) expect: OutcomeV1,
    pub(super) step: StepV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadText {
    schema: String,
    family: String,
    algorithm: AlgorithmText,
    subcases: Vec<SubCaseText>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AlgorithmText {
    id: String,
    major: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubCaseText {
    id: String,
    #[serde(rename = "title")]
    _title: String,
    member: Option<MemberText>,
    expect: ExpectText,
    stimulus: Option<StimulusText>,
}

#[derive(Clone, Copy, Deserialize)]
enum RecordText {
    #[serde(rename = "MTI1")]
    Input,
    #[serde(rename = "MTQ1")]
    Quantization,
    #[serde(rename = "MTR1")]
    Result,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberText {
    record: RecordText,
    blake3: String,
    bytes: u64,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum ExpectText {
    Result {
        record: OutputRecordV1,
        blake3: String,
        #[serde(rename = "pins")]
        _pins: Option<IgnoredAny>,
        #[serde(rename = "absent_marker")]
        _absent_marker: Option<String>,
    },
    MetricError {
        code: u8,
        error: String,
        first_coordinate: String,
    },
    Denied {
        #[serde(rename = "code_id")]
        _code_id: String,
        #[serde(rename = "output")]
        _output: (),
    },
    TransportRejection {
        error: String,
    },
    ResourceLimit {
        #[serde(rename = "code_id")]
        _code_id: String,
    },
    IncompatibleContract {
        #[serde(rename = "code_id")]
        _code_id: String,
    },
    ResultRejected {
        #[serde(rename = "code")]
        _code: u8,
        #[serde(rename = "error")]
        _error: String,
        #[serde(rename = "first_coordinate")]
        _first_coordinate: String,
    },
    GeneratorCheck {},
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractText {
    provider_id: String,
    contract_version: String,
}

impl ContractText {
    /// Whether this is the provider contract the subject reads.
    fn is_own(&self) -> bool {
        self.provider_id == PROVIDER_ID && self.contract_version == CONTRACT_VERSION
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum StimulusText {
    CapabilityRequest {
        capability: String,
    },
    NetworkRequest {
        #[serde(rename = "execution_profile")]
        _execution_profile: String,
    },
    OversizedMember {
        bytes: u64,
        ceiling_bytes: u64,
        #[serde(rename = "fill")]
        _fill: String,
        #[serde(rename = "record")]
        _record: String,
    },
    ExecutionSteps {
        requested: u64,
        #[serde(rename = "maximum")]
        _maximum: u64,
    },
    ProviderContract {
        presented: ContractText,
        required: ContractText,
        allow_fallback: bool,
    },
    Recompute {
        #[serde(rename = "families")]
        _families: Vec<String>,
    },
    GeneratorCheck {
        #[serde(rename = "command")]
        _command: String,
    },
}

/// The members of one `MCS1` composite, or `None` when `bytes` is not one.
fn composite_members(bytes: &[u8]) -> Option<MembersV1> {
    let Ok(Value::Array(fields)) = ciborium::from_reader::<Value, _>(bytes) else {
        return None;
    };
    let [Value::Text(magic), Value::Integer(version), Value::Array(entries)] = fields.as_slice()
    else {
        return None;
    };
    if magic != COMPOSITE_MAGIC || u64::try_from(*version) != Ok(1) {
        return None;
    }
    let mut members = MembersV1::new();
    for entry in entries {
        let Value::Array(pair) = entry else {
            return None;
        };
        let [Value::Bytes(digest), Value::Bytes(member)] = pair.as_slice() else {
            return None;
        };
        let address = blake3::hash(member);
        let key = address.to_hex().to_string();
        // Lowercase hexadecimal orders like the digest bytes.
        let increasing = members
            .last_key_value()
            .is_none_or(|(previous, _)| previous < &key);
        if digest.as_slice() != address.as_bytes() || !increasing {
            return None;
        }
        members.insert(key, member.clone());
    }
    Some(members)
}

/// The members of the first auxiliary member that is an `MCS1` composite.
pub(super) fn find_composite(auxiliary: &[AttemptArtifact]) -> Option<MembersV1> {
    auxiliary
        .iter()
        .find_map(|artifact| composite_members(&artifact.bytes))
}

impl MemberText {
    /// The record kind and bytes of the composite member this names: its digest, its length.
    fn resolve(&self, members: &MembersV1) -> Option<(RecordText, Vec<u8>)> {
        members
            .get(&self.blake3)
            .filter(|bytes| u64::try_from(bytes.len()) == Ok(self.bytes))
            .map(|bytes| (self.record, bytes.clone()))
    }
}

impl ExpectText {
    /// The outcome the sub-case expects.
    fn outcome(self) -> OutcomeV1 {
        match self {
            Self::Result { record, blake3, .. } => OutcomeV1::Result {
                record,
                digest: blake3,
            },
            Self::MetricError {
                code,
                error,
                first_coordinate,
            } => OutcomeV1::MetricError {
                code,
                error,
                coordinate: first_coordinate,
            },
            Self::Denied { .. } => OutcomeV1::Denied,
            Self::TransportRejection { error } => OutcomeV1::TransportRejection(error),
            Self::ResourceLimit { .. } => OutcomeV1::ResourceLimit,
            Self::IncompatibleContract { .. } => OutcomeV1::IncompatibleContract,
            Self::ResultRejected { .. } => OutcomeV1::EvaluatorOwned("result-rejected"),
            Self::GeneratorCheck {} => OutcomeV1::EvaluatorOwned("generator-check"),
        }
    }
}

/// The step of a sub-case the subject decides, from its stimulus and resolved member. An
/// `MTR1` member is never an input of the subject.
fn subject_step(
    stimulus: Option<StimulusText>,
    member: Option<(RecordText, Vec<u8>)>,
) -> Option<StepV1> {
    let input = match member {
        None => None,
        Some((RecordText::Input, bytes)) => Some(InputV1::Metric(bytes)),
        Some((RecordText::Quantization, bytes)) => Some(InputV1::Quantization(bytes)),
        Some((RecordText::Result, _)) => return None,
    };
    let (gate, input) = match stimulus {
        None | Some(StimulusText::Recompute { .. } | StimulusText::GeneratorCheck { .. }) => {
            (None, input)
        }
        Some(StimulusText::CapabilityRequest { capability }) => {
            (Some(GateV1::Capability(capability)), input)
        }
        Some(StimulusText::NetworkRequest { .. }) => (Some(GateV1::Network), input),
        Some(StimulusText::ExecutionSteps { requested, .. }) => {
            (Some(GateV1::Steps(requested)), input)
        }
        Some(StimulusText::ProviderContract {
            presented,
            required,
            allow_fallback,
        }) => {
            if !required.is_own() || allow_fallback {
                return None;
            }
            let own = presented.is_own();
            (Some(GateV1::Contract { own }), input)
        }
        Some(StimulusText::OversizedMember {
            bytes,
            ceiling_bytes,
            ..
        }) => {
            // A member one byte over the ceiling is refused exactly as a longer one is, so the
            // stimulus never allocates more than one byte beyond the ceiling.
            let length = (ceiling_bytes <= MAX_MEMBER_CEILING)
                .then_some(bytes.min(ceiling_bytes.saturating_add(1)))
                .and_then(|length| usize::try_from(length).ok())?;
            let oversized = InputV1::Oversized {
                length,
                ceiling: ceiling_bytes,
            };
            (None, Some(oversized))
        }
    };
    Some(StepV1::Subject { gate, input })
}

impl SubCaseText {
    /// The validated sub-case, or `None` when it violates the grammar.
    fn resolve(self, members: &MembersV1) -> Option<SubCaseV1> {
        let expect = self.expect.outcome();
        let member = self
            .member
            .as_ref()
            .map_or(Some(None), |member| member.resolve(members).map(Some))?;
        let step = match expect {
            OutcomeV1::EvaluatorOwned(kind) => Some(StepV1::EvaluatorOwned(kind)),
            OutcomeV1::Result { .. }
            | OutcomeV1::MetricError { .. }
            | OutcomeV1::Denied
            | OutcomeV1::TransportRejection(_)
            | OutcomeV1::ResourceLimit
            | OutcomeV1::IncompatibleContract
            | OutcomeV1::NoInput => subject_step(self.stimulus, member),
        }?;
        Some(SubCaseV1 {
            id: self.id,
            expect,
            step,
        })
    }
}

/// The sub-cases of a payload of `family` whose members are `members`, or `None` when the
/// payload violates the grammar or names a member the composite lacks.
pub(super) fn parse(bytes: &[u8], family: &str, members: &MembersV1) -> Option<Vec<SubCaseV1>> {
    serde_json::from_slice::<PayloadText>(bytes)
        .ok()
        .filter(|payload| {
            payload.schema == SCHEMA_ID
                && payload.family == family
                && payload.algorithm.id == METRIC_ALGORITHM_ID
                && payload.algorithm.major == METRIC_ALGORITHM_MAJOR
                && (1..=MAX_SUBCASES).contains(&payload.subcases.len())
        })
        .and_then(|payload| {
            payload
                .subcases
                .into_iter()
                .map(|subcase| subcase.resolve(members))
                .collect()
        })
}
