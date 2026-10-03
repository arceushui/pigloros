//! Public-interface contract tests for the ADR-064 counterfactual storage port.

use std::collections::BTreeMap;

use pos_core::{
    CanonicalBytes, CounterfactualBasisV1, CounterfactualInvalidationCommandV1,
    CounterfactualInvalidationInputV1, CounterfactualInvalidationOutcomeV1,
    CounterfactualStoreErrorV1, CounterfactualStorePortV1, EntityId, EventDraft, ForkGenerationV1,
    Hash, InvalidationConflictV1, Kind, PipelineDraftBatchV1, RecomputationFrontierBytesV1, Seq,
    StoredCounterfactualArtifactV1, SuffixInvalidationBytesV1, TimelineId,
    MAX_COUNTERFACTUAL_EVICTIONS_V1, MAX_COUNTERFACTUAL_FRONTIER_BYTES_V1,
    MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1, MAX_COUNTERFACTUAL_INVALID_ARTIFACTS_V1,
};
use ulid::Ulid;

type StoreError = CounterfactualStoreErrorV1;

const FRONTIER_DOMAIN: &[u8] = b"PiglorOS.RecomputationFrontier.v1";
const INVALIDATION_DOMAIN: &[u8] = b"PiglorOS.SuffixInvalidation.v1";
const FRONTIER_PREFIX: [u8; 6] = [0x64, b'R', b'C', b'F', b'1', 0x01];
const INVALIDATION_PREFIX: [u8; 6] = [0x64, b'S', b'I', b'V', b'1', 0x01];
const FRONTIER_HEADER_BYTES: usize = 17 + 3 * 34;
const DIGEST_FIELD_BYTES: usize = 34;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
    })
}

fn err<T: std::fmt::Debug, E>(result: Result<T, E>) -> E {
    match result {
        Ok(value) => std::panic::resume_unwind(Box::new(format!("unexpected success: {value:?}"))),
        Err(error) => error,
    }
}

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn indexed_hash(index: usize) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&ok(u64::try_from(index)).to_be_bytes());
    Hash::from_bytes(bytes)
}

fn fork() -> TimelineId {
    TimelineId::from_ulid(Ulid::from(0x0123_4567_89ab_cdef_u128))
}

/// Encode one shortest-form CBOR unsigned integer.
fn uint(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => vec![bytes[7]],
        24..=0xff => vec![0x18, bytes[7]],
        0x100..=0xffff => [&[0x19][..], &bytes[6..]].concat(),
        0x1_0000..=0xffff_ffff => [&[0x1a][..], &bytes[4..]].concat(),
        _ => [&[0x1b][..], &bytes[..]].concat(),
    }
}

/// Encode one shortest-form CBOR head of `major` with `argument`.
fn head(major: u8, argument: u64) -> Vec<u8> {
    let mut encoded = uint(argument);
    encoded[0] |= major << 5;
    encoded
}

fn text_field(value: &str) -> Vec<u8> {
    [
        head(3, ok(u64::try_from(value.len()))),
        value.as_bytes().to_vec(),
    ]
    .concat()
}

/// Encode one six-field dependency-node coordinate.
fn node_field(tick: u64, owner: &str) -> Vec<u8> {
    [
        vec![0x86],
        uint(tick),
        uint(0),
        text_field(owner),
        uint(0),
        uint(7),
        hash_field(hash(21)),
    ]
    .concat()
}

/// Encode `SIV1` fields 8 through 14, crossing every CBOR argument width.
fn invalidation_middle() -> Vec<u8> {
    [
        node_field(5, "agent-a"),
        node_field(4_294_967_296, "an-owner-identifier-of-thirty-"),
        vec![0x81, 0x86],
        text_field("event"),
        uint(70_000),
        hash_field(hash(22)),
        node_field(5, "agent-a"),
        uint(300),
        uint(0),
        vec![0x81],
        hash_field(hash(23)),
        vec![0x80, 0x80],
        uint(0),
    ]
    .concat()
}

fn id_field(value: [u8; 16]) -> Vec<u8> {
    [&[0x50][..], &value[..]].concat()
}

fn hash_field(value: Hash) -> Vec<u8> {
    [&[0x58, 0x20][..], &value.as_bytes()[..]].concat()
}

/// Frame fields after the version as one self-digested record.
fn frame(
    heads: (u8, u8),
    prefix: [u8; 6],
    domain: &[u8],
    fields: &[u8],
    padding: usize,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(7 + fields.len() + padding + DIGEST_FIELD_BYTES);
    bytes.push(heads.0);
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

fn frontier_fields(plan: Hash, graph: Hash) -> Vec<u8> {
    [
        id_field([1; 16]),
        hash_field(plan),
        hash_field(hash(2)),
        hash_field(graph),
        vec![0x01],
    ]
    .concat()
}

fn frontier_bytes(plan: Hash, graph: Hash) -> Vec<u8> {
    frame(
        (0x91, 0x90),
        FRONTIER_PREFIX,
        FRONTIER_DOMAIN,
        &frontier_fields(plan, graph),
        0,
    )
}

fn frontier(plan: Hash) -> RecomputationFrontierBytesV1 {
    ok(RecomputationFrontierBytesV1::try_from_canonical(
        frontier_bytes(plan, hash(3)),
    ))
}

fn trailing_digest(bytes: &[u8]) -> Hash {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&bytes[bytes.len() - 32..]);
    Hash::from_bytes(digest)
}

struct InvalidationFields {
    plan: Hash,
    fork_id: [u8; 16],
    prior: Vec<u8>,
    new: Vec<u8>,
    frontier_digest: Hash,
    middle: Vec<u8>,
    commit_head: u8,
    commit_timeline: [u8; 16],
    commit_seq: u64,
    commit_tick: u64,
}

impl InvalidationFields {
    fn valid(frontier: &RecomputationFrontierBytesV1, prior: u64) -> Self {
        Self {
            plan: frontier.plan_digest(),
            fork_id: fork().inner().to_bytes(),
            prior: uint(prior),
            new: uint(prior + 1),
            frontier_digest: frontier.digest(),
            middle: invalidation_middle(),
            commit_head: 0x83,
            commit_timeline: fork().inner().to_bytes(),
            commit_seq: 41,
            commit_tick: 17,
        }
    }

    fn encode(&self) -> Vec<u8> {
        [
            id_field([4; 16]),
            hash_field(self.plan),
            id_field(self.fork_id),
            self.prior.clone(),
            self.new.clone(),
            hash_field(self.frontier_digest),
            self.middle.clone(),
            vec![self.commit_head],
            id_field(self.commit_timeline),
            uint(self.commit_seq),
            uint(self.commit_tick),
        ]
        .concat()
    }

    fn bytes(&self) -> Vec<u8> {
        invalidation_frame(&self.encode(), 0)
    }

    fn parse(&self) -> Result<SuffixInvalidationBytesV1, StoreError> {
        SuffixInvalidationBytesV1::try_from_canonical(self.bytes())
    }
}

fn invalidation_frame(fields: &[u8], padding: usize) -> Vec<u8> {
    frame(
        (0x92, 0x91),
        INVALIDATION_PREFIX,
        INVALIDATION_DOMAIN,
        fields,
        padding,
    )
}

fn drafts() -> PipelineDraftBatchV1 {
    ok(PipelineDraftBatchV1::try_new(vec![EventDraft::new(
        EntityId::from_ulid(Ulid::from(9_u128)),
        Kind::new("counterfactual.tick"),
        CanonicalBytes::from_vec(vec![7]),
    )]))
}

fn input() -> CounterfactualInvalidationInputV1 {
    let frontier = frontier(hash(5));
    let invalidation = ok(InvalidationFields::valid(&frontier, 3).parse());
    CounterfactualInvalidationInputV1 {
        fork: fork(),
        fork_logical_head: Seq::from_u64(41),
        trust_epoch: 6,
        revocation_epoch: 7,
        erasure_epoch: 8,
        frontier,
        invalidation,
        invalid_artifacts: vec![hash(10), hash(11)],
        evictions: vec![hash(12), hash(13)],
        first_tick: 17,
        first_tick_drafts: drafts(),
    }
}

fn command() -> CounterfactualInvalidationCommandV1 {
    ok(CounterfactualInvalidationCommandV1::try_new(input()))
}

#[test]
fn frontier_bytes_expose_verified_digests() {
    let bytes = frontier_bytes(hash(5), hash(6));
    let frontier = ok(RecomputationFrontierBytesV1::try_from_canonical(
        bytes.clone(),
    ));
    assert_eq!(frontier.as_bytes(), bytes.as_slice());
    assert_eq!(frontier.digest(), trailing_digest(&bytes));
    assert_eq!(frontier.plan_digest(), hash(5));
    assert_eq!(frontier.dependency_graph_digest(), hash(6));
}

#[test]
fn frontier_size_bound_is_checked_first() {
    let fields = frontier_fields(hash(5), hash(6));
    let padding = MAX_COUNTERFACTUAL_FRONTIER_BYTES_V1 - 7 - fields.len() - DIGEST_FIELD_BYTES;
    let at_limit = frame(
        (0x91, 0x90),
        FRONTIER_PREFIX,
        FRONTIER_DOMAIN,
        &fields,
        padding,
    );
    assert_eq!(at_limit.len(), MAX_COUNTERFACTUAL_FRONTIER_BYTES_V1);
    let frontier = ok(RecomputationFrontierBytesV1::try_from_canonical(at_limit));
    assert_eq!(frontier.plan_digest(), hash(5));
    drop(frontier);
    let over_limit = frame(
        (0x91, 0x90),
        FRONTIER_PREFIX,
        FRONTIER_DOMAIN,
        &fields,
        padding + 1,
    );
    assert_eq!(
        err(RecomputationFrontierBytesV1::try_from_canonical(over_limit)),
        StoreError::FieldOutOfBounds
    );
}

#[test]
fn invalidation_size_bound_is_checked_first() {
    let frontier = frontier(hash(5));
    let fields = InvalidationFields::valid(&frontier, 3).encode();
    let padding = MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1 - 7 - fields.len() - DIGEST_FIELD_BYTES;
    let at_limit = invalidation_frame(&fields, padding);
    assert_eq!(at_limit.len(), MAX_COUNTERFACTUAL_INVALIDATION_BYTES_V1);
    let invalidation = ok(SuffixInvalidationBytesV1::try_from_canonical(at_limit));
    assert_eq!(invalidation.prior_generation(), 3);
    drop(invalidation);
    assert_eq!(
        err(SuffixInvalidationBytesV1::try_from_canonical(
            invalidation_frame(&fields, padding + 1)
        )),
        StoreError::FieldOutOfBounds
    );
}

#[test]
fn frontier_framing_failures_are_closed() {
    let fields = frontier_fields(hash(5), hash(6));
    let parse = |bytes: Vec<u8>| err(RecomputationFrontierBytesV1::try_from_canonical(bytes));
    let valid = frontier_bytes(hash(5), hash(6));

    assert_eq!(parse(vec![0x58; 33]), StoreError::InvalidEncoding);
    assert_eq!(
        parse(valid[valid.len() - 34..].to_vec()),
        StoreError::InvalidEncoding
    );
    let wrong_head = frame((0x92, 0x90), FRONTIER_PREFIX, FRONTIER_DOMAIN, &fields, 0);
    assert_eq!(parse(wrong_head), StoreError::InvalidEncoding);
    let invalidation_magic = frame(
        (0x91, 0x90),
        INVALIDATION_PREFIX,
        FRONTIER_DOMAIN,
        &fields,
        0,
    );
    assert_eq!(parse(invalidation_magic), StoreError::UnsupportedVersion);
    let mut version_two = FRONTIER_PREFIX;
    version_two[5] = 0x02;
    let version_two = frame((0x91, 0x90), version_two, FRONTIER_DOMAIN, &fields, 0);
    assert_eq!(parse(version_two), StoreError::UnsupportedVersion);
    assert_eq!(parse(valid[..6].to_vec()), StoreError::InvalidEncoding);

    let mut wrong_digest_head = valid.clone();
    let at = wrong_digest_head.len() - 33;
    wrong_digest_head[at] = 0x1f;
    assert_eq!(parse(wrong_digest_head), StoreError::InvalidEncoding);

    let mut flipped_digest = valid.clone();
    let last = flipped_digest.len() - 1;
    flipped_digest[last] ^= 1;
    assert_eq!(parse(flipped_digest), StoreError::DigestMismatch);

    let mut flipped_field = valid;
    flipped_field[30] ^= 1;
    assert_eq!(parse(flipped_field), StoreError::DigestMismatch);

    let wrong_domain = frame(
        (0x91, 0x90),
        FRONTIER_PREFIX,
        INVALIDATION_DOMAIN,
        &fields,
        0,
    );
    assert_eq!(parse(wrong_domain), StoreError::DigestMismatch);
    let signed_head = frame((0x91, 0x91), FRONTIER_PREFIX, FRONTIER_DOMAIN, &fields, 0);
    assert_eq!(parse(signed_head), StoreError::DigestMismatch);
}

#[test]
fn frontier_header_truncation_and_field_heads_are_rejected() {
    let fields = frontier_fields(hash(5), hash(6));
    for length in 0..FRONTIER_HEADER_BYTES {
        let bytes = frame(
            (0x91, 0x90),
            FRONTIER_PREFIX,
            FRONTIER_DOMAIN,
            &fields[..length],
            0,
        );
        assert_eq!(
            err(RecomputationFrontierBytesV1::try_from_canonical(bytes)),
            StoreError::InvalidEncoding,
            "truncated at {length}"
        );
    }
    let exact = frame(
        (0x91, 0x90),
        FRONTIER_PREFIX,
        FRONTIER_DOMAIN,
        &fields[..FRONTIER_HEADER_BYTES],
        0,
    );
    let frontier = ok(RecomputationFrontierBytesV1::try_from_canonical(exact));
    assert_eq!(frontier.dependency_graph_digest(), hash(6));
    for (offset, value) in [(0, 0x4f), (17, 0x57), (18, 0x1f)] {
        let mut wrong = fields.clone();
        wrong[offset] = value;
        let bytes = frame((0x91, 0x90), FRONTIER_PREFIX, FRONTIER_DOMAIN, &wrong, 0);
        assert_eq!(
            err(RecomputationFrontierBytesV1::try_from_canonical(bytes)),
            StoreError::InvalidEncoding
        );
    }
}

#[test]
fn invalidation_bytes_expose_verified_header() {
    let frontier = frontier(hash(5));
    let fields = InvalidationFields::valid(&frontier, 3);
    let bytes = fields.bytes();
    let invalidation = ok(fields.parse());
    assert_eq!(invalidation.as_bytes(), bytes.as_slice());
    assert_eq!(invalidation.digest(), trailing_digest(&bytes));
    assert_eq!(invalidation.plan_digest(), hash(5));
    assert_eq!(invalidation.fork_id(), fork().inner().to_bytes());
    assert_eq!(invalidation.prior_generation(), 3);
    assert_eq!(invalidation.new_generation(), 4);
    assert_eq!(invalidation.frontier_digest(), frontier.digest());
    assert_eq!(invalidation.commit_timeline_id(), fork().inner().to_bytes());
    assert_eq!(invalidation.commit_seq(), 41);
    assert_eq!(invalidation.commit_tick(), 17);
}

#[test]
fn invalidation_walks_middle_fields_structurally() {
    let frontier = frontier(hash(5));
    let first_node = node_field(5, "agent-a").len();
    let rest = invalidation_middle()[first_node..].to_vec();
    let with_field_eight = |item: &[u8]| {
        let mut fields = InvalidationFields::valid(&frontier, 3);
        fields.middle = [item, rest.as_slice()].concat();
        fields.parse()
    };
    let invalidation = ok(with_field_eight(&[0x81, 0x81, 0x81, 0x00][..]));
    assert_eq!(invalidation.commit_tick(), 17);
    for item in [
        &[0x81, 0x81, 0x81, 0x81, 0x00][..],
        &[0x1c][..],
        &[0x20][..],
        &[0xa0][..],
        &[0xf6][..],
        &[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
    ] {
        assert_eq!(
            err(with_field_eight(item)),
            StoreError::InvalidEncoding,
            "field 8 {item:02x?}"
        );
    }
    let mut fields = InvalidationFields::valid(&frontier, 3);
    fields.commit_head = 0x82;
    assert_eq!(err(fields.parse()), StoreError::InvalidEncoding);
}

#[test]
fn invalidation_generations_cross_every_integer_width() {
    let frontier = frontier(hash(5));
    for prior in [
        0,
        22,
        23,
        255,
        65_535,
        4_294_967_295,
        4_294_967_296,
        u64::MAX - 1,
    ] {
        let invalidation = ok(InvalidationFields::valid(&frontier, prior).parse());
        assert_eq!(invalidation.prior_generation(), prior);
        assert_eq!(invalidation.new_generation(), prior + 1);
    }
}

#[test]
fn invalidation_rejects_non_shortest_or_non_integer_generations() {
    let frontier = frontier(hash(5));
    for (prior, encoded) in [
        (23, vec![0x18, 23]),
        (255, vec![0x19, 0, 0xff]),
        (65_535, vec![0x1a, 0, 0, 0xff, 0xff]),
        (
            4_294_967_295,
            vec![0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        ),
        (0, vec![0x1c]),
        (0, vec![0x20]),
    ] {
        let mut fields = InvalidationFields::valid(&frontier, prior);
        fields.prior = encoded;
        assert_eq!(err(fields.parse()), StoreError::InvalidEncoding);
    }
    let mut fields = InvalidationFields::valid(&frontier, 3);
    fields.new = vec![0x18, 4];
    assert_eq!(err(fields.parse()), StoreError::InvalidEncoding);
}

#[test]
fn invalidation_new_generation_must_be_prior_plus_one() {
    let frontier = frontier(hash(5));
    for (prior, new) in [(5, 7), (5, 5), (5, 4), (u64::MAX, 0)] {
        let mut fields = InvalidationFields::valid(&frontier, 0);
        fields.prior = uint(prior);
        fields.new = uint(new);
        assert_eq!(err(fields.parse()), StoreError::PriorGenerationMismatch);
    }
}

#[test]
fn invalidation_header_truncation_and_framing_are_rejected() {
    let frontier = frontier(hash(5));
    let fields = InvalidationFields::valid(&frontier, 300);
    let encoded = fields.encode();
    let header_bytes = encoded.len();
    for length in 0..header_bytes {
        assert_eq!(
            err(SuffixInvalidationBytesV1::try_from_canonical(
                invalidation_frame(&encoded[..length], 0)
            )),
            StoreError::InvalidEncoding,
            "truncated at {length}"
        );
    }
    ok(SuffixInvalidationBytesV1::try_from_canonical(
        invalidation_frame(&encoded[..header_bytes], 0),
    ));
    let mut wrong_fork_head = encoded.clone();
    wrong_fork_head[51] = 0x4f;
    assert_eq!(
        err(SuffixInvalidationBytesV1::try_from_canonical(
            invalidation_frame(&wrong_fork_head, 0)
        )),
        StoreError::InvalidEncoding
    );
    let frontier_framed = frame((0x91, 0x90), FRONTIER_PREFIX, FRONTIER_DOMAIN, &encoded, 0);
    assert_eq!(
        err(SuffixInvalidationBytesV1::try_from_canonical(
            frontier_framed
        )),
        StoreError::InvalidEncoding
    );
    let mut flipped = fields.bytes();
    flipped[40] ^= 1;
    assert_eq!(
        err(SuffixInvalidationBytesV1::try_from_canonical(flipped)),
        StoreError::DigestMismatch
    );
}

#[test]
fn command_binds_every_transaction_part() {
    let input = input();
    let command = command();
    assert_eq!(command.fork(), fork());
    assert_eq!(
        command.expected_basis(),
        CounterfactualBasisV1 {
            fork_logical_head: Seq::from_u64(41),
            plan_digest: hash(5),
            dependency_graph_digest: hash(3),
            generation: 3,
            trust_epoch: 6,
            revocation_epoch: 7,
            erasure_epoch: 8,
        }
    );
    assert_eq!(
        command.new_generation(),
        ForkGenerationV1 {
            fork: fork(),
            generation: 4,
        }
    );
    assert_eq!(command.frontier(), &input.frontier);
    assert_eq!(command.invalidation(), &input.invalidation);
    assert_eq!(command.invalid_artifacts(), &[hash(10), hash(11)]);
    assert_eq!(command.evictions(), &[hash(12), hash(13)]);
    assert_eq!(command.first_tick(), 17);
    assert_eq!(command.first_tick_drafts(), &drafts());

    let receipt = ok(command.committed_receipt(Seq::from_u64(42)));
    assert_eq!(receipt.generation(), command.new_generation());
    assert_eq!(receipt.frontier_digest(), input.frontier.digest());
    assert_eq!(receipt.invalidation_digest(), input.invalidation.digest());
    assert_eq!(receipt.first_tick(), 17);
    assert_eq!(receipt.first_tick_head(), Seq::from_u64(42));
}

#[test]
fn command_rejects_disagreeing_bindings() {
    let mut other_fork = input();
    other_fork.fork = TimelineId::from_ulid(Ulid::from(77_u128));
    assert_eq!(
        err(CounterfactualInvalidationCommandV1::try_new(other_fork)),
        StoreError::BindingMismatch
    );

    let mut other_plan = input();
    other_plan.frontier = frontier(hash(6));
    let mut fields = InvalidationFields::valid(&other_plan.frontier, 3);
    fields.plan = hash(5);
    other_plan.invalidation = ok(fields.parse());
    assert_eq!(
        err(CounterfactualInvalidationCommandV1::try_new(other_plan)),
        StoreError::BindingMismatch
    );

    let mut other_frontier = input();
    let mut fields = InvalidationFields::valid(&other_frontier.frontier, 3);
    fields.frontier_digest = hash(9);
    other_frontier.invalidation = ok(fields.parse());
    assert_eq!(
        err(CounterfactualInvalidationCommandV1::try_new(other_frontier)),
        StoreError::BindingMismatch
    );
}

#[test]
fn command_binds_the_tick_boundary_commit_coordinate() {
    let coordinate_changes: [fn(&mut InvalidationFields); 3] = [
        |fields| fields.commit_timeline = [0x77; 16],
        |fields| fields.commit_seq = 42,
        |fields| fields.commit_tick = 16,
    ];
    for change in coordinate_changes {
        let mut moved = input();
        let mut fields = InvalidationFields::valid(&moved.frontier, 3);
        change(&mut fields);
        moved.invalidation = ok(fields.parse());
        assert_eq!(
            err(CounterfactualInvalidationCommandV1::try_new(moved)),
            StoreError::BindingMismatch
        );
    }
    let input_changes: [fn(&mut CounterfactualInvalidationInputV1); 2] = [
        |input| input.fork_logical_head = Seq::from_u64(40),
        |input| input.first_tick = 18,
    ];
    for change in input_changes {
        let mut moved = input();
        change(&mut moved);
        assert_eq!(
            err(CounterfactualInvalidationCommandV1::try_new(moved)),
            StoreError::BindingMismatch
        );
    }
}

#[test]
fn command_never_quarantines_its_own_records() {
    let input = input();
    let own = [input.frontier.digest(), input.invalidation.digest()];
    for digest in own {
        assert_eq!(
            with_sets(vec![digest], Vec::new()),
            Err(StoreError::BindingMismatch)
        );
        assert_eq!(
            with_sets(Vec::new(), vec![digest]),
            Err(StoreError::BindingMismatch)
        );
    }
}

#[test]
fn receipt_requires_the_fork_head_to_advance() {
    let command = command();
    for head in [0, 40, 41] {
        assert_eq!(
            command.committed_receipt(Seq::from_u64(head)),
            Err(StoreError::CorruptState)
        );
    }
    assert_eq!(
        ok(command.committed_receipt(Seq::from_u64(u64::MAX))).first_tick_head(),
        Seq::from_u64(u64::MAX)
    );
}

fn with_sets(invalid_artifacts: Vec<Hash>, evictions: Vec<Hash>) -> Result<(), StoreError> {
    let mut input = input();
    input.invalid_artifacts = invalid_artifacts;
    input.evictions = evictions;
    CounterfactualInvalidationCommandV1::try_new(input).map(drop)
}

fn ascending(count: usize) -> Vec<Hash> {
    (0..count).map(indexed_hash).collect()
}

#[test]
fn digest_sets_are_bounded_at_their_limits() {
    ok(with_sets(Vec::new(), Vec::new()));
    let over_index = ascending(MAX_COUNTERFACTUAL_INVALID_ARTIFACTS_V1 + 1);
    ok(with_sets(
        over_index[..MAX_COUNTERFACTUAL_INVALID_ARTIFACTS_V1].to_vec(),
        Vec::new(),
    ));
    assert_eq!(
        with_sets(over_index, Vec::new()),
        Err(StoreError::FieldOutOfBounds)
    );
    let over_evictions = ascending(MAX_COUNTERFACTUAL_EVICTIONS_V1 + 1);
    ok(with_sets(
        Vec::new(),
        over_evictions[..MAX_COUNTERFACTUAL_EVICTIONS_V1].to_vec(),
    ));
    assert_eq!(
        with_sets(Vec::new(), over_evictions),
        Err(StoreError::FieldOutOfBounds)
    );
}

#[test]
fn digest_sets_must_be_strictly_ascending() {
    let unordered = vec![hash(2), hash(1)];
    let duplicate = vec![hash(1), hash(1)];
    assert_eq!(
        with_sets(unordered.clone(), Vec::new()),
        Err(StoreError::NonCanonicalOrder)
    );
    assert_eq!(
        with_sets(duplicate.clone(), Vec::new()),
        Err(StoreError::DuplicateIdentity)
    );
    assert_eq!(
        with_sets(Vec::new(), unordered),
        Err(StoreError::NonCanonicalOrder)
    );
    assert_eq!(
        with_sets(Vec::new(), duplicate),
        Err(StoreError::DuplicateIdentity)
    );
}

#[test]
fn basis_reports_the_first_conflict_in_canonical_order() {
    let expected = command().expected_basis();
    assert_eq!(expected.first_conflict(&expected), None);
    let cases: [(fn(&mut CounterfactualBasisV1), InvalidationConflictV1); 7] = [
        (
            |basis| basis.fork_logical_head = Seq::from_u64(42),
            InvalidationConflictV1::LogicalHead,
        ),
        (
            |basis| basis.plan_digest = hash(99),
            InvalidationConflictV1::PlanDigest,
        ),
        (
            |basis| basis.dependency_graph_digest = hash(99),
            InvalidationConflictV1::DependencyGraphDigest,
        ),
        (
            |basis| basis.generation = 4,
            InvalidationConflictV1::PriorGeneration,
        ),
        (
            |basis| basis.trust_epoch = 9,
            InvalidationConflictV1::TrustEpoch,
        ),
        (
            |basis| basis.revocation_epoch = 9,
            InvalidationConflictV1::RevocationEpoch,
        ),
        (
            |basis| basis.erasure_epoch = 9,
            InvalidationConflictV1::ErasureEpoch,
        ),
    ];
    for (change, conflict) in cases {
        let mut persisted = expected;
        change(&mut persisted);
        assert_eq!(expected.first_conflict(&persisted), Some(conflict));
    }
    let mut persisted = expected;
    persisted.erasure_epoch = 9;
    persisted.plan_digest = hash(99);
    assert_eq!(
        expected.first_conflict(&persisted),
        Some(InvalidationConflictV1::PlanDigest)
    );
}

#[test]
fn reads_require_the_current_generation_and_hide_quarantined_bytes() {
    let at = ForkGenerationV1 {
        fork: fork(),
        generation: 4,
    };
    for current in [3, 5] {
        assert_eq!(
            at.resolve_read(
                current,
                StoredCounterfactualArtifactV1::Authoritative(vec![1])
            ),
            Err(StoreError::MixedForkGeneration)
        );
    }
    assert_eq!(
        at.resolve_read(4, StoredCounterfactualArtifactV1::Absent),
        Ok(None)
    );
    assert_eq!(
        at.resolve_read(4, StoredCounterfactualArtifactV1::Quarantined),
        Err(StoreError::InvalidArtifactReuse)
    );
    assert_eq!(
        at.resolve_read(4, StoredCounterfactualArtifactV1::Authoritative(vec![1, 2])),
        Ok(Some(vec![1, 2]))
    );
}

#[test]
fn errors_have_distinct_safe_messages() {
    let errors = [
        StoreError::InvalidEncoding,
        StoreError::UnsupportedVersion,
        StoreError::FieldOutOfBounds,
        StoreError::NonCanonicalOrder,
        StoreError::DuplicateIdentity,
        StoreError::DigestMismatch,
        StoreError::PriorGenerationMismatch,
        StoreError::BindingMismatch,
        StoreError::MixedForkGeneration,
        StoreError::InvalidArtifactReuse,
        StoreError::ForkNotFound,
        StoreError::CorruptState,
        StoreError::StorageFailure,
    ];
    let messages: std::collections::BTreeSet<String> =
        errors.iter().map(ToString::to_string).collect();
    assert_eq!(messages.len(), errors.len());
}

/// Minimal fake showing the port is implementable without backend types.
struct FakeStore {
    basis: CounterfactualBasisV1,
    artifacts: BTreeMap<Hash, Vec<u8>>,
    quarantined: Vec<Hash>,
}

impl CounterfactualStorePortV1 for FakeStore {
    fn commit_counterfactual_invalidation(
        &mut self,
        command: &CounterfactualInvalidationCommandV1,
    ) -> Result<CounterfactualInvalidationOutcomeV1, StoreError> {
        if let Some(conflict) = command.expected_basis().first_conflict(&self.basis) {
            return Ok(CounterfactualInvalidationOutcomeV1::InvalidationConflict(
                conflict,
            ));
        }
        self.basis.generation = command.new_generation().generation;
        self.quarantined
            .extend_from_slice(command.invalid_artifacts());
        command
            .committed_receipt(Seq::from_u64(42))
            .map(CounterfactualInvalidationOutcomeV1::Committed)
    }

    fn current_fork_generation(&self, fork: TimelineId) -> Result<ForkGenerationV1, StoreError> {
        Ok(ForkGenerationV1 {
            fork,
            generation: self.basis.generation,
        })
    }

    fn read_generation_artifact(
        &self,
        at: ForkGenerationV1,
        artifact_digest: Hash,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let stored = if self.quarantined.contains(&artifact_digest) {
            StoredCounterfactualArtifactV1::Quarantined
        } else {
            self.artifacts
                .get(&artifact_digest)
                .map_or(StoredCounterfactualArtifactV1::Absent, |bytes| {
                    StoredCounterfactualArtifactV1::Authoritative(bytes.clone())
                })
        };
        at.resolve_read(self.basis.generation, stored)
    }
}

#[test]
fn port_commits_whole_generation_or_reports_conflict() {
    let command = command();
    let mut stale = command.expected_basis();
    stale.trust_epoch = 99;
    let mut store = FakeStore {
        basis: stale,
        artifacts: BTreeMap::from([(hash(10), vec![1]), (hash(20), vec![2])]),
        quarantined: Vec::new(),
    };
    let prior = ok(store.current_fork_generation(fork()));
    assert_eq!(
        ok(store.commit_counterfactual_invalidation(&command)),
        CounterfactualInvalidationOutcomeV1::InvalidationConflict(
            InvalidationConflictV1::TrustEpoch
        )
    );
    assert_eq!(ok(store.current_fork_generation(fork())), prior);
    assert_eq!(
        ok(store.read_generation_artifact(prior, hash(10))),
        Some(vec![1])
    );

    store.basis = command.expected_basis();
    assert_eq!(
        ok(store.commit_counterfactual_invalidation(&command)),
        CounterfactualInvalidationOutcomeV1::Committed(ok(
            command.committed_receipt(Seq::from_u64(42))
        ))
    );
    let current = ok(store.current_fork_generation(fork()));
    assert_eq!(current, command.new_generation());
    assert_eq!(
        store.read_generation_artifact(current, hash(10)),
        Err(StoreError::InvalidArtifactReuse)
    );
    assert_eq!(
        store.read_generation_artifact(prior, hash(20)),
        Err(StoreError::MixedForkGeneration)
    );
    assert_eq!(
        ok(store.read_generation_artifact(current, hash(20))),
        Some(vec![2])
    );
    assert_eq!(ok(store.read_generation_artifact(current, hash(30))), None);
}
