//! Shared `RCF1`/`SIV1` byte-fixture encoders and dependency record builders
//! for counterfactual storage port tests.
//!
//! The port carries both records as exact canonical bytes, so tests of the
//! port, its Memory and `SQLite` adapters, and the coordinator build them
//! with these encoders instead of copying them. The framing constants are
//! written out independently of the port's own verifier so the fixtures stay
//! an independent check of it.
//!
//! The dependency record contract, its Memory and `SQLite` adapters, and the
//! factual dependency contract share the test result helpers, the coordinate,
//! node, edge, and record builders, and the paged-read helpers below. The
//! `IDP1` edge bytes are likewise written out independently of the contract.
//! Available only with the `test-support` feature.

use crate::{
    CanonicalBytes, CounterfactualFactsV1, CounterfactualStoreErrorV1, DependencyEdgeRecordV1,
    DependencyNodeCoordinateV1, DependencyNodeRecordV1, DependencyPageCursorV1,
    DependencyPageRequestV1, DependencyPageV1, DependencyPagedRowV1, DependencyReadScopeV1,
    EntityId, EventDraft, ForkGenerationV1, Hash, Kind, RecordedDependencyClassV1,
    RecordedNodeOriginV1, Seq, TickDependencyRecordV1, TimelineId,
};

/// `RCF1` self-digest domain.
pub const FRONTIER_DOMAIN: &[u8] = b"PiglorOS.RecomputationFrontier.v1";
/// `SIV1` self-digest domain.
pub const INVALIDATION_DOMAIN: &[u8] = b"PiglorOS.SuffixInvalidation.v1";
/// `RCF1` text magic and version `1`, as encoded after the array head.
pub const FRONTIER_PREFIX: [u8; 6] = [0x64, b'R', b'C', b'F', b'1', 0x01];
/// `SIV1` text magic and version `1`, as encoded after the array head.
pub const INVALIDATION_PREFIX: [u8; 6] = [0x64, b'S', b'I', b'V', b'1', 0x01];
/// `RCF1` `(record array head, unsigned array head)`.
pub const FRONTIER_HEADS: (u8, u8) = (0x91, 0x90);
/// `SIV1` `(record array head, unsigned array head)`.
pub const INVALIDATION_HEADS: (u8, u8) = (0x92, 0x91);
/// Encoded size of one 32-byte digest field, head included.
pub const DIGEST_FIELD_BYTES: usize = 34;
/// Producer digest every [`node_field`] carries.
pub const NODE_DIGEST: Hash = Hash::from_bytes([21; 32]);

/// Encode one shortest-form CBOR unsigned integer.
#[must_use]
pub fn uint(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => vec![bytes[7]],
        24..=0xff => vec![0x18, bytes[7]],
        0x100..=0xffff => [&[0x19][..], &bytes[6..]].concat(),
        0x1_0000..=0xffff_ffff => [&[0x1a][..], &bytes[4..]].concat(),
        _ => [&[0x1b][..], &bytes[..]].concat(),
    }
}

/// Encode one shortest-form CBOR head of `major` (a CBOR major type, which
/// must be at most 7) with `argument`.
#[must_use]
pub fn head(major: u8, argument: u64) -> Vec<u8> {
    let mut encoded = uint(argument);
    encoded[0] += major << 5;
    encoded
}

/// Encode one CBOR text string.
#[must_use]
pub fn text_field(value: &str) -> Vec<u8> {
    [
        head(3, u64::try_from(value.len()).unwrap_or(u64::MAX)),
        value.as_bytes().to_vec(),
    ]
    .concat()
}

/// Encode one 16-byte identity field.
#[must_use]
pub fn id_field(value: [u8; 16]) -> Vec<u8> {
    [&[0x50][..], &value[..]].concat()
}

/// Encode one 32-byte digest field.
#[must_use]
pub fn hash_field(value: Hash) -> Vec<u8> {
    [&[0x58, 0x20][..], &value.as_bytes()[..]].concat()
}

/// Encode one six-field dependency-node coordinate at `tick` owned by
/// `owner`, with schema 7 and [`NODE_DIGEST`].
#[must_use]
pub fn node_field(tick: u64, owner: &str) -> Vec<u8> {
    [
        vec![0x86],
        uint(tick),
        uint(0),
        text_field(owner),
        uint(0),
        uint(7),
        hash_field(NODE_DIGEST),
    ]
    .concat()
}

/// Encode `SIV1` fields 8 through 14, crossing every CBOR argument width.
#[must_use]
pub fn invalidation_middle() -> Vec<u8> {
    [
        node_field(5, "agent-a"),
        node_field(4_294_967_296, "an-owner-identifier-of-thirty-"),
        vec![0x81, 0x86],
        text_field("event"),
        uint(70_000),
        hash_field(Hash::from_bytes([22; 32])),
        node_field(5, "agent-a"),
        uint(300),
        uint(0),
        vec![0x81],
        hash_field(Hash::from_bytes([23; 32])),
        vec![0x80, 0x80],
        uint(0),
    ]
    .concat()
}

/// Frame the fields after the version as one self-digested record.
///
/// The record is `heads.0`, `prefix`, `fields`, `padding` zero bytes, then the digest
/// field over `domain`, a zero byte, `heads.1`, and everything after the
/// record array head.
#[must_use]
pub fn frame(
    heads: (u8, u8),
    prefix: [u8; 6],
    domain: &[u8],
    fields: &[u8],
    padding: usize,
) -> Vec<u8> {
    let mut bytes = vec![heads.0];
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(fields);
    bytes.resize(bytes.len() + padding, 0);
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0, heads.1]);
    hasher.update(&bytes[1..]);
    bytes.extend_from_slice(&[0x58, 0x20]);
    bytes.extend_from_slice(hasher.finalize().as_bytes());
    bytes
}

/// Frame `RCF1` fields after the version, with `padding` zero bytes.
#[must_use]
pub fn frontier_frame(fields: &[u8], padding: usize) -> Vec<u8> {
    frame(
        FRONTIER_HEADS,
        FRONTIER_PREFIX,
        FRONTIER_DOMAIN,
        fields,
        padding,
    )
}

/// Frame `SIV1` fields after the version, with `padding` zero bytes.
#[must_use]
pub fn invalidation_frame(fields: &[u8], padding: usize) -> Vec<u8> {
    frame(
        INVALIDATION_HEADS,
        INVALIDATION_PREFIX,
        INVALIDATION_DOMAIN,
        fields,
        padding,
    )
}

/// One committed factual Tick a store test seeds without a pipeline commit.
///
/// The record is the Tick's committed record; `first_seq` and `last_seq`
/// bound the contiguous Events it owns, and each `event_nodes` entry binds
/// one of those Events to the Event-backed node that stands for it.
///
/// `seed_factual_prefix` seeds it into the Memory and `SQLite` adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeededFactualTickV1 {
    /// The Tick's committed record.
    pub record: TickDependencyRecordV1,
    /// The first `seq` the Tick owns.
    pub first_seq: Seq,
    /// The last `seq` the Tick owns.
    pub last_seq: Seq,
    /// The `(seq, node artifact digest)` binding of each Event-backed node.
    pub event_nodes: Vec<(Seq, Hash)>,
}

/// A result of the counterfactual storage port.
type StoreResult<T> = Result<T, CounterfactualStoreErrorV1>;

/// `IDP1` array head, text magic, and version `1`, as an edge starts.
pub const EDGE_HEAD: [u8; 7] = [0x89, 0x64, b'I', b'D', b'P', b'1', 0x01];
/// Provenance digest every [`class_row`] carries.
pub const PROVENANCE_DIGEST: Hash = Hash::from_bytes([99; 32]);

/// Unwrap `result`, unwinding with its error when it failed.
///
/// The unwind carries `unexpected test error: {error:?}` and does not run the
/// panic hook. Tests call it as a statement to assert that a write succeeded,
/// so it is not `#[must_use]`.
#[allow(clippy::must_use_candidate)]
pub fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

/// Unwrap the error of `result`, unwinding with its value when it succeeded.
///
/// The unwind carries `unexpected success: {value:?}` and does not run the
/// panic hook.
#[must_use]
pub fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    result.map_or_else(
        |error| error,
        |value| std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
    )
}

/// The digest whose 32 bytes are all `value`.
#[must_use]
pub const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

/// The digest whose last eight bytes hold `index`, big-endian.
#[must_use]
pub fn indexed_hash(index: usize) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&ok(u64::try_from(index)).to_be_bytes());
    Hash::from_bytes(bytes)
}

/// The published counterfactual facts every dependency test command binds.
#[must_use]
pub const fn facts() -> CounterfactualFactsV1 {
    CounterfactualFactsV1 {
        plan_digest: hash(5),
        dependency_graph_digest: hash(3),
        trust_epoch: 6,
        revocation_epoch: 7,
        erasure_epoch: 8,
    }
}

/// One `counterfactual.tick` draft for a fresh entity, with payload `value`.
#[must_use]
pub fn draft(value: u8) -> EventDraft {
    typed_draft("counterfactual.tick", value)
}

/// One draft of `kind` for a fresh entity, with payload `value`.
#[must_use]
pub fn typed_draft(kind: &str, value: u8) -> EventDraft {
    EventDraft::new(
        EntityId::new(),
        Kind::new(kind),
        CanonicalBytes::from_vec(vec![value]),
    )
}

/// The schema-7 coordinate at `tick`, scheduler position 0, of `owner`'s
/// output `ordinal` with `digest`.
#[must_use]
pub fn coord_at(tick: u64, owner: &str, ordinal: u32, digest: Hash) -> DependencyNodeCoordinateV1 {
    ok(DependencyNodeCoordinateV1::try_new(
        tick,
        0,
        owner.to_owned(),
        ordinal,
        7,
        digest,
    ))
}

/// The [`coord_at`] coordinate of `owner`'s output 0, with digest
/// [`hash`]`(digest)`.
#[must_use]
pub fn coord(tick: u64, owner: &str, digest: u8) -> DependencyNodeCoordinateV1 {
    coord_at(tick, owner, 0, hash(digest))
}

/// The node at `coordinate` of `class` and `origin` declaring `inputs`.
///
/// The node carries [`PROVENANCE_DIGEST`].
#[must_use]
pub fn class_row(
    coordinate: DependencyNodeCoordinateV1,
    class: RecordedDependencyClassV1,
    origin: RecordedNodeOriginV1,
    inputs: Vec<Hash>,
) -> DependencyNodeRecordV1 {
    ok(DependencyNodeRecordV1::try_new(
        coordinate,
        class,
        origin,
        inputs,
        PROVENANCE_DIGEST,
    ))
}

/// The endogenous-recomputed [`class_row`] node at `coordinate`.
#[must_use]
pub fn node_row(
    coordinate: DependencyNodeCoordinateV1,
    origin: RecordedNodeOriginV1,
    inputs: Vec<Hash>,
) -> DependencyNodeRecordV1 {
    let class = RecordedDependencyClassV1::EndogenousRecomputed;
    class_row(coordinate, class, origin, inputs)
}

/// The provisional [`node_row`] node at `coordinate`.
#[must_use]
pub fn provisional_row(
    coordinate: DependencyNodeCoordinateV1,
    inputs: Vec<Hash>,
) -> DependencyNodeRecordV1 {
    node_row(coordinate, RecordedNodeOriginV1::Provisional, inputs)
}

/// Encode the six-field node array of `node`.
#[must_use]
pub fn node_bytes(node: &DependencyNodeCoordinateV1) -> Vec<u8> {
    [
        vec![0x86],
        uint(node.tick()),
        uint(u64::from(node.scheduler_position())),
        text_field(node.owner_id()),
        uint(u64::from(node.output_ordinal())),
        uint(u64::from(node.schema_id())),
        hash_field(node.artifact_digest()),
    ]
    .concat()
}

/// Encode the five `IDP1` fields after the source node, with `rule` as the
/// rule ID.
#[must_use]
pub fn edge_tail_with_rule(rule: &str) -> Vec<u8> {
    [
        uint(2),
        vec![0x82],
        uint(3),
        uint(5),
        hash_field(hash(0x33)),
        vec![0x82],
        text_field(rule),
        uint(1),
        hash_field(hash(0x44)),
    ]
    .concat()
}

/// Encode the five `IDP1` fields after the source node, with the
/// `adr064.classification` rule ID.
#[must_use]
pub fn edge_tail() -> Vec<u8> {
    edge_tail_with_rule("adr064.classification")
}

/// Encode the `IDP1` edge from `consumer` to `source`.
#[must_use]
pub fn edge_bytes(
    consumer: &DependencyNodeCoordinateV1,
    source: &DependencyNodeCoordinateV1,
) -> Vec<u8> {
    [
        EDGE_HEAD.to_vec(),
        node_bytes(consumer),
        node_bytes(source),
        edge_tail(),
    ]
    .concat()
}

/// The verified [`edge_bytes`] edge from `consumer` to `source`.
#[must_use]
pub fn edge_row(
    consumer: &DependencyNodeCoordinateV1,
    source: &DependencyNodeCoordinateV1,
) -> DependencyEdgeRecordV1 {
    ok(DependencyEdgeRecordV1::try_from_canonical(
        edge_bytes(consumer, source),
        consumer.clone(),
        source.artifact_digest(),
    ))
}

/// The provisional record of `nodes` and `edges` at `tick`.
#[must_use]
pub fn record_of(
    tick: u64,
    nodes: Vec<DependencyNodeRecordV1>,
    edges: Vec<DependencyEdgeRecordV1>,
) -> TickDependencyRecordV1 {
    ok(TickDependencyRecordV1::try_new(
        tick,
        RecordedNodeOriginV1::Provisional,
        nodes,
        edges,
    ))
}

/// The read scope of `fork`'s `generation`.
#[must_use]
pub const fn fork_scope(fork: TimelineId, generation: u64) -> DependencyReadScopeV1 {
    DependencyReadScopeV1::ForkGeneration(ForkGenerationV1 { fork, generation })
}

/// The read scope of `timeline`'s factual prefix through `through_tick`.
#[must_use]
pub const fn prefix_scope(timeline: TimelineId, through_tick: u64) -> DependencyReadScopeV1 {
    DependencyReadScopeV1::ParentPrefix {
        timeline,
        through_tick,
    }
}

/// The page request of `scope` after `after`, of at most `limit` rows.
#[must_use]
pub fn request(
    scope: DependencyReadScopeV1,
    after: Option<DependencyPageCursorV1>,
    limit: usize,
) -> DependencyPageRequestV1 {
    ok(DependencyPageRequestV1::try_new(scope, after, limit))
}

/// Read every page of `scope`, `limit` rows at a time, through `read`.
///
/// # Errors
/// Returns the first error `read` returns.
pub fn collect_rows<T: DependencyPagedRowV1 + Clone>(
    scope: DependencyReadScopeV1,
    limit: usize,
    read: impl Fn(&DependencyPageRequestV1) -> StoreResult<DependencyPageV1<T>>,
) -> StoreResult<Vec<T>> {
    let mut rows = Vec::new();
    let mut after = None;
    loop {
        let page = read(&request(scope, after, limit))?;
        rows.extend_from_slice(page.items());
        after = page.next().cloned();
        if after.is_none() {
            return Ok(rows);
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        collect_rows, err, ok, prefix_scope, CounterfactualStoreErrorV1, DependencyNodeRecordV1,
        DependencyPageRequestV1, DependencyPageV1, StoreResult, TimelineId,
    };

    type NodeRow = DependencyNodeRecordV1;

    fn unwound_message<T>(outcome: std::thread::Result<T>) -> Option<String> {
        let payload = outcome.err()?;
        payload.downcast_ref::<String>().cloned()
    }

    #[test]
    fn ok_and_err_unwind_with_the_unexpected_outcome() {
        assert_eq!(ok::<u8, &str>(Ok(1)), 1);
        assert_eq!(err::<u8, &str>(Err("refused")), "refused");
        let failed = std::panic::catch_unwind(|| ok::<u8, _>(Err("refused")));
        assert_eq!(
            unwound_message(failed).as_deref(),
            Some("unexpected test error: \"refused\"")
        );
        let succeeded = std::panic::catch_unwind(|| err::<u8, &str>(Ok(1)));
        assert_eq!(
            unwound_message(succeeded).as_deref(),
            Some("unexpected success: 1")
        );
    }

    const fn refuse(_: &DependencyPageRequestV1) -> StoreResult<DependencyPageV1<NodeRow>> {
        Err(CounterfactualStoreErrorV1::CorruptState)
    }

    #[test]
    fn collect_rows_returns_the_first_read_error() {
        let scope = prefix_scope(TimelineId::new(), 1);
        assert_eq!(
            collect_rows(scope, 1, refuse).err(),
            Some(CounterfactualStoreErrorV1::CorruptState)
        );
    }
}
