"""The G-FORK non-interference oracle (ADR-062 Revision 8 slice N4, #1232).

The owner note `ADR-062_R8_NonInterference_Fork` has this oracle derive the expected NIA1
`result_digest` of every executed case of NI-FORK-008 (modes L, R and F) independently
(ADR-062 Revision 8, Q3 (a)). It uses no Rust, no cargo and no binary of the repository, and
implementation output is never an oracle. It rebuilds, byte for byte, the seven ADR-064 Fork
artifacts that `pos_experiment::fork_artifacts::run_fork_v1` exports for the subject of
`apps/pos-experiment/src/non_interference_harness/g_fork.rs`, from the documented contracts:
- the subject fixture: the permitted input decides only the Intervention's value digest; the
  unauthorized value reaches the factual Timeline after the cut alone, so nothing here reads it;
- the factual Tick 1 of the history (three generated Drivers committed through scheduled
  admission) and its recorded dependency rows, which the Fork reads through the cut;
- the host-declared provisional graph of Ticks 2 and 3 (the records form);
- `INT1`, `CFP1` (with the EPF1 and TPS1 of the DFA1 fixture), `RCF1`, `SIV1`, both `RCP1`
  and the `CFR1`.
The nine surfaces then follow `g_fork_capture_v1`, and the digests the #181 capture profile and
the harness result domain (`non_interference_fixtures.py`). The only repository file read at run
time is the DFA1 fixture `fixtures/conformance/support/draft-execution-authority.json`.

`scripts/generate_non_interference_fixtures.py` plugs this oracle into the evidence binder.
"""

from __future__ import annotations

import json
import sys
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from non_interference_fixtures import (  # noqa: E402
    ROOT,
    b3,
    cbor,
    decode,
    domain_digest,
    golden,
    result_digest,
)

FORK_ROW = "NI-FORK-008"
ROWS = (FORK_ROW,)

# `non_interference_surface_names_v1("NI-FORK-008")`, every one ByteExact (code 5).
SURFACES = {
    FORK_ROW: (
        ("Fork parent/cut", 5),
        ("CounterfactualPlan", 5),
        ("RecomputationFrontier", 5),
        ("SuffixInvalidation", 5),
        ("snapshots", 5),
        ("checkpoints", 5),
        ("result", 5),
        ("ReproManifest", 5),
        ("exports", 5),
    ),
}

DFA1 = ROOT / "fixtures/conformance/support/draft-execution-authority.json"

# The exports-surface kind codes of `kind_code` in g_fork.rs (the export order).
KIND_CODES = {
    "Intervention": 0,
    "CounterfactualPlan": 1,
    "RecomputationFrontier": 2,
    "SuffixInvalidation": 3,
    "Checkpoint": 4,
    "Result": 5,
}

# Dependency classes (`DependencyClassV1` / `RecordedDependencyClassV1`, one code table).
EXOGENOUS, INTERVENTION, ENDOGENOUS, FIXED, PRESENTATION = 0, 1, 2, 3, 4


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def prefixed(value: bytes) -> bytes:
    """A big-endian `u64` length prefix and the bytes (`update_prefixed`)."""
    return u64(len(value)) + value


def framed(value: bytes) -> bytes:
    """A little-endian `u64` length frame and the bytes (pos-runtime `hash_framed`)."""
    return len(value).to_bytes(8, "little") + value


# --- The subject (g_fork.rs `g_fork_subject_fixture_v1`, fork_artifacts.rs) ---

FACTUAL_TIMELINE = b"pigloros.factual"  # FACTUAL_TIMELINE_ID_V1
FORK_TIMELINE = b"pigloros.fork.v1"  # FORK_TIMELINE_ID_V1
CUT_TICK = 1  # G_FORK_CUT_TICK_V1
HORIZON_SPAN = 1  # G_FORK_HORIZON_SPAN_V1
PLAN_ID = bytes([0x46] * 16)
ROOM_ID = "room.g-fork"
ROOM_DIGEST = bytes([0x47] * 32)
PARENT_CUT_DIGEST = bytes([0x48] * 32)
PLUGIN_COMPOSITION_DIGEST = bytes([0x4C] * 32)
SCHEDULER_DIGEST = bytes([0x4D] * 32)
NUMERIC_PROFILE_DIGEST = bytes([0x4E] * 32)
BUDGET_DIGEST = bytes([0x4F] * 32)
FAILURE_POLICY_DIGEST = bytes([0x50] * 32)
REPLAY_CLAIM_EXACT = 0  # `replay_claim_code(ReplayClaimV1::Exact)`
REVOCATION_EPOCH = 7
ERASURE_EPOCH = 8
FRONTIER_ID = bytes([0x51] * 16)
INVALIDATION_ID = bytes([0x52] * 16)
PROVENANCE = bytes([0x53] * 32)
RESULT_ID = bytes([0x54] * 16)
EVALUATOR_IDENTITY = bytes([0x55] * 32)
EXECUTION_PROFILE_ID = "deterministic-local-v1"

# g_fork.rs `intervention`.
INTERVENTION_ID = bytes([0x49] * 16)
CONSENT_DECISION_DIGEST = bytes([0x4A] * 32)
INTERVENTION_PROVENANCE = bytes([0x4B] * 32)


def permitted_input(variant: str) -> bytes:
    """`g_fork_permitted_input_v1`."""
    return f"g-fork permitted input v1/{FORK_ROW}/{variant}".encode()


# --- The history (fork_artifacts/history.rs) ---

INPUT_EVENT_TYPE = "agent.forkrun.input"
INPUT_ENTITY = 0x20
INPUT_PAYLOAD = b"input"  # the one external input before Tick 1
DRIVER_ENTITY = 0x07
FACTUAL_PAYLOAD = b"factual"  # every Driver payload through the cut
RECORDS_FORM_ENTITY = 0x09  # records_form.rs `staged_drafts`
PASS_DOMAIN = b"PiglorOS.ForkArtifactsFactualPass.v1\0"
LEAD_EVENT_TYPE = "agent.forkrun.alpha"
# `DRIVERS`: (Plugin and Driver name, owned Event type), in schedule order.
DRIVERS = (
    ("alpha", LEAD_EVENT_TYPE),
    ("beta", "agent.forkrun.beta"),
    ("gamma", "agent.forkrun.gamma"),
)
PLUGIN_VERSION = "0.1.0"  # the default `Plugin::version`


# --- Draft digests (pos-core pipeline.rs) ---


def draft(entity: int, event_type: str, payload: bytes) -> bytes:
    """One `EventDraft::new` as `digest_intent` encodes it: no causation, no correlation,
    schema version 1, no wall time."""
    kind = event_type.encode()
    no_causation_no_correlation, schema_v1, no_wall_time = b"\0\0", u32(1), b"\0"
    head = entity.to_bytes(16, "big") + prefixed(kind) + prefixed(payload)
    return head + no_causation_no_correlation + schema_v1 + no_wall_time


def draft_vector_digest(drafts: list[bytes]) -> bytes:
    """`pipeline_draft_vector_digest_v1`."""
    return b3(b"PiglorOS.PipelineDraftBatch.v1\0" + u64(len(drafts)) + b"".join(drafts))


def driver_drafts() -> list[bytes]:
    """The staged drafts of factual Tick 1, in schedule order."""
    return [draft(DRIVER_ENTITY, event_type, FACTUAL_PAYLOAD) for _, event_type in DRIVERS]


def records_form_drafts(tick: int) -> list[bytes]:
    """records_form.rs `staged_drafts`: one draft per lane, payload the Tick big-endian."""
    return [draft(RECORDS_FORM_ENTITY, event_type, u64(tick)) for _, event_type in DRIVERS]


# --- Owner ids and replay identities (pos-runtime registry, output_admission.rs) ---

# reviewed_policy.rs `REVIEWED_RETENTION_POLICY_RTP1`.
RTP1 = bytes.fromhex(
    "8a44525450310101" "6f776f726c642d7265706c61792d7631"
    "5820b8999e89305c44dda75e999082b9a016b63f86f47f28dd1a25437a70dd7ed276185a181e18780000"
)
# registry.rs `generated_budget_input`: (level, max_events, max_bytes, max_cpu_us).
GENERATED_FIDELITY = (
    (0, 1_000, 64 << 20, 500_000),
    (1, 1_000, 64 << 20, 250_000),
    (2, 1_000, 16 << 20, 50_000),
)
GENERATED_CPU_RESERVATION = (10, 10, 10)
GENERATED_MAX_EVENT_BYTES = 4_096
GENERATED_MAX_PASS_WALL_US = 1_000
OUTPUT_DECLARATION_MAX_BYTES = 4_096


def le32(value: int) -> bytes:
    return value.to_bytes(4, "little")


@lru_cache(maxsize=None)
def policy_identity(name: str, event_type: str) -> bytes:
    """`OutputPolicyClosureV1::replay_identity_digest` of a `register_generated` Plugin:
    the generated implementation artifact, the CFG1 configuration with no details, the
    reviewed RTP1, one Authoritative L0 declaration and the generated EBP1 budget, whose
    execution-profile hash is the BLAKE3 digest of the empty (Generated) EPF1 member."""
    version = PLUGIN_VERSION.encode()
    implementation = (
        b"pigloros.generated-implementation.v1\0"
        + framed(name.encode())
        + framed(version)
        + framed(event_type.encode())
    )
    no_details = framed(b"")
    configuration = b"CFG1" + framed(name.encode()) + framed(version)
    configuration += framed(event_type.encode()) + no_details
    value = b"pigloros.output-policy-replay-identity.v1\0" + framed(version)
    value += domain_digest(b"pigloros.implementation-artifact.v1", implementation)
    value += domain_digest(b"pigloros.base-configuration.v1", configuration)
    value += domain_digest(b"pigloros.retention-policy.v1", RTP1)
    value += le32(1)  # policy_revision
    # The declaration: event type, Authoritative (0), L0 (0), max bytes, no stride, no group.
    value += framed(event_type.encode()) + b"\0\0" + le32(OUTPUT_DECLARATION_MAX_BYTES)
    value += le32(0) + le32(0)
    # The budget: revision 1, Interactive (0), cut family 0, max Event bytes, fidelities.
    value += le32(1) + b"\0" + b"\0" + le32(GENERATED_MAX_EVENT_BYTES)
    for level, events, max_bytes, cpu in GENERATED_FIDELITY:
        value += bytes([level]) + le32(events) + max_bytes.to_bytes(8, "little")
        value += le32(cpu) + le32(0)
    value += b"".join(le32(reservation) for reservation in GENERATED_CPU_RESERVATION)
    value += b"\0" + b3(b"") + GENERATED_MAX_PASS_WALL_US.to_bytes(8, "little")
    for member in (implementation, configuration, b"", RTP1):
        value += framed(member)
    return b3(value)


def owner_id(name: str, identity: bytes) -> str:
    """`factual_owner_id` of a slotless entry of rank 0 (owner_id.rs)."""
    preimage = bytes([2]) + identity + prefixed(name.encode()) + u32(0)
    return "plugin:" + domain_digest(b"PiglorOS.FactualOwner.v1", preimage).hex()


@lru_cache(maxsize=None)
def lanes() -> tuple[tuple[str, str, int, bytes], ...]:
    """Every Driver as (owner id, Event type, scheduler position, policy identity)."""
    found = []
    for position, (name, event_type) in enumerate(DRIVERS, start=1):
        identity = policy_identity(name, event_type)
        found.append((owner_id(name, identity), event_type, position, identity))
    return tuple(found)


# --- Factual Tick 1 (pos-core factual_dependency.rs, registry/factual_dependencies.rs) ---

STEP_SCHEMA, SNAPSHOT_SCHEMA, FOLD_SCHEMA = 1, 2, 5
# FactualRuleV1: (rule id, class), in declaration order.
FACTUAL_RULES = (
    ("pos.factual.driver-output", ENDOGENOUS),
    ("pos.factual.driver-output.ephemeral", PRESENTATION),
    ("pos.factual.driver-step", ENDOGENOUS),
    ("pos.factual.observation-snapshot", ENDOGENOUS),
    ("pos.factual.verified-prefix", ENDOGENOUS),
    ("pos.factual.consumed-history", ENDOGENOUS),
    ("pos.factual.external-ingress", EXOGENOUS),
    ("pos.factual.fold-checkpoint", ENDOGENOUS),
    ("pos.factual.fold-history", ENDOGENOUS),
)
RULE_CLASS = dict(FACTUAL_RULES)
SCHEDULED_AI_DRIVER = 2  # `ingress_tag`


def event_schema_id(event_type: str) -> int:
    """`factual_event_schema_id`."""
    digest = domain_digest(b"PiglorOS.FactualEventSchema.v1", event_type.encode())
    return max(1, int.from_bytes(digest[:4], "big"))


def artifact_digest(timeline: bytes, key: tuple[int, int, str, int, int], content: bytes) -> bytes:
    """`factual_artifact_digest` of the node at `(tick, position, owner, ordinal, schema)`."""
    tick, position, owner, ordinal, schema = key
    preimage = timeline + u64(tick) + u32(position) + prefixed(owner.encode())
    preimage += u32(ordinal) + u32(schema)
    return domain_digest(b"PiglorOS.FactualDependencyNode.v1", preimage + content)


def output_content_digest(one_draft: bytes) -> bytes:
    """`factual_output_content_digest`: the draft vector digest of the one draft."""
    return draft_vector_digest([one_draft])


def classification_bundle_bytes() -> bytes:
    """`factual_classification_bundle_bytes`: `[rule_id, 1, class]` sorted by rule id."""
    return cbor([[rule, 1, code] for rule, code in sorted(FACTUAL_RULES)])


@lru_cache(maxsize=None)
def classification_bundle_digest() -> bytes:
    bundle = classification_bundle_bytes()
    return domain_digest(b"PiglorOS.DependencyClassificationBundle.v1", bundle)


def authority_grant() -> bytes:
    """scheduled_admission_host/local.rs: the grant id `keyed(b"grant", &[])`."""
    return b3(b"PiglorOS.LocalScheduledAdmission.v1\0" + b"grant" + b"\0")


def pass_attempt(tick: int) -> bytes:
    """history.rs `admission`: the attempt digest of the pass of `tick`."""
    return b3(PASS_DOMAIN + FACTUAL_TIMELINE + u64(tick))


@lru_cache(maxsize=None)
def pass_validation(tick: int) -> bytes:
    """history.rs `admission`: the provider-validation (evidence) digest."""
    return b3(PASS_DOMAIN + pass_attempt(tick) + draft_vector_digest(driver_drafts()))


def provenance_digest(tick: int, owner: str, identity: bytes, rule: str) -> bytes:
    """`factual_provenance_digest` of a node of the scheduled pass of `tick`."""
    preimage = (
        FACTUAL_TIMELINE
        + pass_attempt(tick)[:16]
        + bytes([SCHEDULED_AI_DRIVER])
        + pass_validation(tick)
        + authority_grant()
        + prefixed(owner.encode())
        + identity
        + prefixed(rule.encode())
        + u32(1)
    )
    return domain_digest(b"PiglorOS.FactualNodeProvenance.v1", preimage)


def node_value(node: tuple) -> list:
    """`node_value` / `push_node`: `[tick, position, owner, ordinal, schema, digest]`."""
    return list(node)


def edge_bytes(
    consumer: tuple,
    source: tuple,
    source_class: int,
    authorization: bytes,
    rule: str,
    provenance: bytes,
) -> bytes:
    """One IDP1 edge (`edge_bytes` in factual_dependency.rs, `encode_dependency` in
    counterfactual/dependency.rs): the exact Tick range `[source.tick, consumer.tick]`."""
    return cbor(
        [
            "IDP1",
            1,
            node_value(consumer),
            node_value(source),
            source_class,
            [source[0], consumer[0]],
            authorization,
            [rule, 1],
            provenance,
        ]
    )


def graph_node(node: tuple, cls: int, origin: str, inputs: list[bytes], provenance: bytes) -> dict:
    """A `DependencyGraphNodeV1`; the input digests are sorted and distinct."""
    return {
        "node": node,
        "class": cls,
        "origin": origin,
        "inputs": sorted(set(inputs)),
        "provenance": provenance,
    }


def graph_edge(consumer: tuple, source: tuple, source_class: int, *binding: object) -> dict:
    """One `InputDependencyV1`; `binding` is (authorization, rule id, provenance)."""
    return {
        "consumer": consumer,
        "source": source,
        "bytes": edge_bytes(consumer, source, source_class, *binding),
    }


def edge_order(edge: dict) -> tuple:
    """`edge_order_key`: the consumer coordinate key, then the source digest."""
    return edge["consumer"][:4] + (edge["source"][5],)


@lru_cache(maxsize=None)
def factual_tick() -> tuple[tuple[dict, ...], tuple[dict, ...], dict]:
    """The recorded rows of factual Tick 1 (`assemble_factual_tick` of the scheduled pass):
    its nodes in canonical order, its edges, and the Tick's step and output nodes by owner.

    The pass observes through `seq` 1 (the input Event). No Driver subscribes, so a step node
    consumes only the observation snapshot, which binds an empty state set. The fold window
    `(0, 1]` holds the input Event, so the Tick records its ingress node and one fold
    checkpoint chunk behind the snapshot node."""
    tick, observed_through = 1, 1
    input_payload_hash = b3(INPUT_PAYLOAD)
    no_states = u64(0)
    snapshot = b3(
        b"PiglorOS.ScheduledObservationSnapshot.v1\0"
        + FACTUAL_TIMELINE
        + u64(observed_through)
        + no_states
    )
    fold = domain_digest(
        b"PiglorOS.FactualFoldCheckpoint.v1",
        bytes(32) + u64(1) + u64(observed_through) + u64(1) + u64(1) + input_payload_hash,
    )
    zero = bytes(32)
    # specs: (key, content, rule, policy identity, source keys)
    ingress_key = (tick, 0, "host.ingress", 0, event_schema_id(INPUT_EVENT_TYPE))
    fold_key = (tick, 0, "host.lineage", 0, FOLD_SCHEMA)
    snapshot_key = (tick, 0, "host.observation", 0, SNAPSHOT_SCHEMA)
    specs = [
        (snapshot_key, snapshot, "pos.factual.observation-snapshot", zero, [fold_key]),
        (ingress_key, b3(input_payload_hash + u64(1)), "pos.factual.external-ingress", zero, []),
        (fold_key, fold, "pos.factual.fold-checkpoint", zero, [ingress_key]),
    ]
    for lane, one_draft in zip(lanes(), driver_drafts(), strict=True):
        owner, event_type, position, identity = lane
        step_key = (tick, position, owner, 0, STEP_SCHEMA)
        content = b3(identity + draft_vector_digest([one_draft]))  # `factual_step_content_digest`
        specs.append((step_key, content, "pos.factual.driver-step", identity, [snapshot_key]))
        output_key = (tick, position, owner, 1, event_schema_id(event_type))
        content = output_content_digest(one_draft)
        specs.append((output_key, content, "pos.factual.driver-output", identity, [step_key]))
    nodes = {
        key: key + (artifact_digest(FACTUAL_TIMELINE, key, content),)
        for key, content, *_ in specs
    }
    rules = {key: rule for key, _, rule, *_ in specs}
    rows, edges, chains = [], [], {}
    for key, _, rule, identity, sources in sorted(specs, key=lambda spec: spec[0][:4]):
        node = nodes[key]
        provenance = provenance_digest(tick, key[2], identity, rule)
        resolved = sorted((nodes[source] for source in sources), key=lambda source: source[5])
        inputs = [source[5] for source in resolved]
        rows.append(graph_node(node, RULE_CLASS[rule], "committed", inputs, provenance))
        for source in resolved:
            source_class = RULE_CLASS[rules[source[:5]]]
            binding = (authority_grant(), rule, provenance)
            edges.append(graph_edge(node, source, source_class, *binding))
        if key[1] > 0:
            chains.setdefault(key[2], {})["step" if key[3] == 0 else "output"] = node
    return tuple(rows), tuple(edges), chains


# --- EPF1 and TPS1 (bundle_contract.rs, execution_profile.rs, trust_policy_snapshot.rs) ---

REPRODUCIBILITY_CODES = {
    "RecordedReplay": 0,
    "ProfileRecomputation": 1,
    "CrossProfileConformance": 2,
    "LiveUnverified": 3,
}
FIXTURE_AUTHORITY_SEED = bytes([7] * 32)  # DRAFT_FIXTURE_AUTHORITY_SIGNING_BYTES


@lru_cache(maxsize=None)
def authority() -> dict:
    return json.loads(DFA1.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def execution_profile_bytes(profile_id: str = EXECUTION_PROFILE_ID) -> bytes:
    """`canonical_execution_profile_bytes_v1` of the DFA1 profile: 16 unsigned fields and the
    `PiglorOS.ExecutionProfile.v1\\0` digest. The profile carries no previous digest."""
    profile = next(p for p in authority()["execution_profiles"] if p["profile_id"] == profile_id)
    fields = [
        "EPF1",
        1,
        profile["profile_id"],
        profile["semantic_version"],
        [REPRODUCIBILITY_CODES[name] for name in profile["reproducibility_classes"]],
        profile["architecture_rules"],
        profile["numeric_rules"],
        profile["scheduler_driver_order"],
        profile["tick_policy"],
        profile["schemas_and_upcasters"],
        profile["artifact_rules"],
        [profile["network_allowed"], profile["capability_ids"]],
        profile["deterministic_budgets"],
        profile["allowed_operational_differences"],
        [profile["minimum_evaluator_version"], profile["maximum_evaluator_version"]],
        profile["previous_profile_digest"],
    ]
    digest = b3(b"PiglorOS.ExecutionProfile.v1\0" + cbor(fields))
    return cbor(fields + [digest])


@lru_cache(maxsize=None)
def trust_policy_bytes() -> bytes:
    """`draft_trust_policy_snapshot_bytes_v1`: the DFA1 policy, its unsigned 11 fields signed
    with the fixture authority key."""
    dfa = authority()
    fields = [
        "TPS1",
        1,
        dfa["trust_policy_id"],
        dfa["trust_policy_epoch"],
        dfa["effective_timeline_position"],
        [
            [r["key_id"], r["root_version"], r["algorithm"], bytes.fromhex(r["public_key_hex"])]
            for r in dfa["trust_roots"]
        ],
        dfa["revoked_key_ids"],
        [bytes.fromhex(digest) for digest in dfa["revoked_artifact_digests"]],
        [[m["artifact_kind"], m["semantic_version"]] for m in dfa["minimum_versions"]],
        dfa["offline_valid_through"],
        dfa["previous_trust_policy_snapshot_digest"],
    ]
    return cbor(fields + [golden.ed25519_sign(FIXTURE_AUTHORITY_SEED, cbor(fields))])


@lru_cache(maxsize=None)
def profile_ref() -> list:
    """`PlanExecutionProfileRefV1`: `[profile_id, semantic_version, profile_digest]`."""
    fields = decode(execution_profile_bytes())[0]
    return [fields[2], fields[3], fields[16]]


@lru_cache(maxsize=None)
def trust_ref() -> list:
    """`PlanTrustPolicyRefV1`: `[policy_id, epoch, BLAKE3 of the complete TPS1]`."""
    fields = decode(trust_policy_bytes())[0]
    return [fields[2], fields[3], b3(trust_policy_bytes())]


# --- INT1 and CFP1 (counterfactual/intervention.rs, counterfactual/plan.rs) ---


def intervention_bytes(variant: str) -> bytes:
    """`encode_intervention` of g_fork.rs `intervention`: AssignValue (0) of the lead output
    `body.velocity` at the first recomputation Tick."""
    return cbor(
        [
            "INT1",
            1,
            INTERVENTION_ID,
            event_schema_id(LEAD_EVENT_TYPE),
            "body",
            "velocity",
            0,
            b3(permitted_input(variant)),
            CUT_TICK + 1,
            0,
            "principal:operator",
            "intervene",
            3,
            CONSENT_DECISION_DIGEST,
            "g-fork what if",
            INTERVENTION_PROVENANCE,
        ]
    )


def intervention_digest(variant: str) -> bytes:
    return domain_digest(b"PiglorOS.Intervention.v1", intervention_bytes(variant))


def cut() -> tuple[int, int]:
    """The factual head at the cut: Tick 1 ends at `seq` 4 (the input Event, then one Event
    per Driver)."""
    return CUT_TICK, 1 + len(DRIVERS)


def plan_fields(variant: str) -> list:
    """`body_fields` of fork_artifacts.rs `plan`: CFP1 fields 0 through 24."""
    cut_tick, cut_seq = cut()
    first_tick = cut_tick + 1
    return [
        "CFP1",
        1,
        PLAN_ID,
        ROOM_ID,
        ROOM_DIGEST,
        FACTUAL_TIMELINE,
        cut_seq,
        cut_tick,
        PARENT_CUT_DIGEST,
        first_tick,
        first_tick + HORIZON_SPAN,
        [intervention_bytes(variant)],
        [],
        [],
        classification_bundle_digest(),
        0,  # UnknownEdgePolicyV1::Reject
        profile_ref(),
        trust_ref(),
        PLUGIN_COMPOSITION_DIGEST,
        SCHEDULER_DIGEST,
        NUMERIC_PROFILE_DIGEST,
        BUDGET_DIGEST,
        FAILURE_POLICY_DIGEST,
        REPLAY_CLAIM_EXACT,
        None,
    ]


@lru_cache(maxsize=None)
def plan_digest(variant: str) -> bytes:
    return domain_digest(b"PiglorOS.CounterfactualPlan.v1", cbor(plan_fields(variant)))


def plan_bytes(variant: str) -> bytes:
    return cbor(plan_fields(variant) + [plan_digest(variant)])


# --- The provisional graph (fork_artifacts/records_form.rs `provisional_graph`) ---


@lru_cache(maxsize=None)
def provisional_graph(variant: str) -> tuple[list[dict], list[dict]]:
    """The Intervention root and, per lane and Tick 2 and 3, a step and an output node. A step
    node consumes the lane's previous step node, the cut Tick's Event nodes (Tick 2 only) and
    every output node of the previous Tick; an output node its step node and, for the lead lane
    at Tick 2, the root. Both nodes of a lane stand for its staged draft."""
    _, _, chains = factual_tick()
    first_tick = CUT_TICK + 1
    grant = authority_grant()
    schema = event_schema_id(LEAD_EVENT_TYPE)
    root = (first_tick, 0, "intervention", 0, schema, intervention_digest(variant))
    nodes = [graph_node(root, INTERVENTION, "provisional", [], INTERVENTION_PROVENANCE)]
    edges: list[dict] = []
    classes = {root: INTERVENTION}

    def endogenous(key: tuple, one_draft: bytes, inputs: list[tuple]) -> tuple:
        node = key + (artifact_digest(FORK_TIMELINE, key, output_content_digest(one_draft)),)
        unique = {source[5]: source for source in inputs}
        for digest in sorted(unique):
            source = unique[digest]
            source_class = classes.get(source, ENDOGENOUS)
            authorization = CONSENT_DECISION_DIGEST if source_class == INTERVENTION else grant
            edges.append(
                graph_edge(node, source, source_class, authorization, "classify.v1", PROVENANCE)
            )
        nodes.append(graph_node(node, ENDOGENOUS, "provisional", list(unique), PROVENANCE))
        return node

    steps = [chains[owner]["step"] for owner, *_ in lanes()]
    outputs: list[tuple] = []
    forwarded = [chains[owner]["output"] for owner, *_ in lanes()]
    for tick in range(first_tick, first_tick + HORIZON_SPAN + 1):
        given = forwarded if tick == first_tick else []
        new_steps, new_outputs = [], []
        for index, ((owner, event_type, position, _), previous, one_draft) in enumerate(
            zip(lanes(), steps, records_form_drafts(tick), strict=True)
        ):
            step_key = (tick, position, owner, 0, STEP_SCHEMA)
            step = endogenous(step_key, one_draft, [previous, *given, *outputs])
            seed = [root] if index == 0 and tick == first_tick else []
            output_key = (tick, position, owner, 1, event_schema_id(event_type))
            output = endogenous(output_key, one_draft, [step, *seed])
            new_steps.append(step)
            new_outputs.append(output)
        steps, outputs = new_steps, new_outputs
    nodes.sort(key=lambda node: node["node"][:4])
    edges.sort(key=edge_order)
    return nodes, edges


# --- The dependency graph and RCF1 (pos-time counterfactual/frontier.rs) ---


def graph(variant: str) -> tuple[list[dict], list[dict]]:
    """`PrefixSeededFrontierSourceV1::read_graph`: the recorded prefix through the cut, then
    the provisional graph."""
    prefix_nodes, prefix_edges, _ = factual_tick()
    nodes, edges = provisional_graph(variant)
    return [*prefix_nodes, *nodes], [*prefix_edges, *edges]


@lru_cache(maxsize=None)
def dependency_graph_digest(variant: str) -> bytes:
    """`dependency_graph_digest_v1`."""
    nodes, edges = graph(variant)
    value = plan_digest(variant) + u64(len(nodes))
    for node in nodes:
        tick, position, owner, ordinal, schema, digest = node["node"]
        value += u64(tick) + u32(position) + prefixed(owner.encode()) + u32(ordinal) + u32(schema)
        value += digest + bytes([node["class"]])
        value += u64(len(node["inputs"])) + b"".join(node["inputs"]) + node["provenance"]
    value += u64(len(edges))
    for edge in edges:
        value += domain_digest(b"PiglorOS.InputDependency.v1", edge["bytes"])
    return domain_digest(b"PiglorOS.CounterfactualDependencyGraph.v1", value)


@lru_cache(maxsize=None)
def affected_nodes(variant: str) -> list[dict]:
    """`affected_nodes`: every `EndogenousRecomputed` node reachable from the Intervention
    seeds, the seeds included, in `DependencyNodeV1` order."""
    nodes, edges = graph(variant)
    by_digest = {node["node"][5]: node for node in nodes}
    consumers: dict[bytes, list[dict]] = {}
    for edge in edges:
        consumers.setdefault(edge["source"][5], []).append(by_digest[edge["consumer"][5]])
    visited = {node["node"]: node for node in nodes if node["class"] == INTERVENTION}
    layer = list(visited.values())
    while layer:
        found = {
            consumer["node"]: consumer
            for node in layer
            for consumer in consumers.get(node["node"][5], [])
            if consumer["class"] == ENDOGENOUS and consumer["node"] not in visited
        }
        visited.update(found)
        layer = list(found.values())
    return [visited[key] for key in sorted(visited)]


def owner_frontiers(affected: list[dict]) -> list:
    """`owner_frontiers`: each owner's first affected node and its affected causes."""
    digests = {node["node"][5] for node in affected}
    seen, frontiers = set(), []
    for node in affected:
        tick, position, owner, ordinal, _, digest = node["node"]
        if owner in seen:
            continue
        seen.add(owner)
        causes = [cause for cause in node["inputs"] if cause in digests]
        frontiers.append([owner, tick, position, ordinal, causes or [digest]])
    return frontiers


def frontier_fields(variant: str) -> list:
    """`frontier_fields` of `derive_recomputation_frontier_v1` over the complete graph."""
    nodes, _ = graph(variant)
    affected = affected_nodes(variant)
    earliest = affected[0]["node"]
    return [
        "RCF1",
        1,
        FRONTIER_ID,
        plan_digest(variant),
        PARENT_CUT_DIGEST,
        dependency_graph_digest(variant),
        [node_value(node["node"]) for node in nodes if node["class"] == INTERVENTION],
        [node_value(node["node"]) for node in affected],
        owner_frontiers(affected),
        earliest[0],
        earliest[1],
        0,  # Reject: the graph is complete
        [],
        CUT_TICK + 1 + HORIZON_SPAN,
        classification_bundle_digest(),
        PROVENANCE,
    ]


@lru_cache(maxsize=None)
def frontier_digest(variant: str) -> bytes:
    return domain_digest(b"PiglorOS.RecomputationFrontier.v1", cbor(frontier_fields(variant)))


def frontier_bytes(variant: str) -> bytes:
    return cbor(frontier_fields(variant) + [frontier_digest(variant)])


# --- SIV1 (pos-runtime counterfactual/coordinator.rs `invalidation_parts`) ---


def invalidation_fields(variant: str) -> list:
    """The first generation (prior 0, new 1) of the fresh Fork, reason `NewIntervention`. The
    invalid artifacts are every provisional endogenous node at or after the global frontier;
    the commit coordinate is the Fork's logical head, its cut `seq`, at the frontier Tick."""
    nodes, _ = graph(variant)
    affected = affected_nodes(variant)
    frontier = frontier_fields(variant)
    global_frontier = (frontier[9], frontier[10])
    producers = sorted(
        node["node"]
        for node in nodes
        if node["origin"] == "provisional"
        and node["class"] == ENDOGENOUS
        and node["node"][:2] >= global_frontier
    )
    span = sorted({node["node"] for node in affected} | set(producers))
    return [
        "SIV1",
        1,
        INVALIDATION_ID,
        plan_digest(variant),
        FORK_TIMELINE,
        0,
        1,
        frontier_digest(variant),
        node_value(span[0]),
        node_value(span[-1]),
        [["EndogenousRecomputed", p[4], p[5], node_value(p), 0, 0] for p in producers],
        [],
        [],
        [],
        0,
        [FORK_TIMELINE, cut()[1], frontier[9]],
        PROVENANCE,
    ]


@lru_cache(maxsize=None)
def invalidation_digest(variant: str) -> bytes:
    return domain_digest(b"PiglorOS.SuffixInvalidation.v1", cbor(invalidation_fields(variant)))


def invalidation_bytes(variant: str) -> bytes:
    return cbor(invalidation_fields(variant) + [invalidation_digest(variant)])


# --- RCP1 and CFR1 (pos-runtime counterfactual/suffix.rs) ---


def chain_state(previous: bytes, tick: int, drafts: list[bytes]) -> bytes:
    """`chain_state` under the receipt's epochs: trust 1 (the TPS1 epoch), revocation and
    erasure of the fixture."""
    trust_epoch = authority()["trust_policy_epoch"]
    return b3(
        b"PiglorOS.CounterfactualSuffixState.v1\0"
        + previous
        + u64(trust_epoch)
        + u64(REVOCATION_EPOCH)
        + u64(ERASURE_EPOCH)
        + u64(tick)
        + draft_vector_digest(drafts)
    )


def checkpoint_fields(variant: str, tick: int, seq: int, state: bytes) -> list:
    """`unsealed_checkpoint`: no Plugin or Projection state, the one chained state, the cursor
    after the (empty) frozen closure and the SIV1 provenance root."""
    states = [["counterfactual.suffix", state]]
    cursor = [0, None]
    return ["RCP1", 1, plan_digest(variant), tick, seq, 0, [], [], states, cursor, PROVENANCE]


@lru_cache(maxsize=None)
def checkpoints(variant: str) -> list[tuple[int, bytes, bytes, bytes]]:
    """One `(tick, state, digest, RCP1)` per recomputed Tick. Tick 2 is committed by the
    admission right after the cut `seq`; every later Tick appends its drafts and then its
    checkpoint Event, and the `RCP1` `seq` is the Tick's last recomputed Event."""
    state, head = invalidation_digest(variant), cut()[1]
    first_tick = CUT_TICK + 1
    out = []
    for tick in range(first_tick, first_tick + HORIZON_SPAN + 1):
        drafts = records_form_drafts(tick)
        state = chain_state(state, tick, drafts)
        seq = head + len(drafts)
        fields = checkpoint_fields(variant, tick, seq, state)
        digest = domain_digest(b"PiglorOS.RecomputeCheckpoint.v1", cbor(fields))
        out.append((tick, state, digest, cbor(fields + [digest])))
        head = seq if tick == first_tick else seq + 1
    return out


def result_fields(variant: str) -> list:
    """`finish` of a completed suffix: generation 1, every checkpoint ref, the final state as
    suffix digest and the RCF1 digest as dependency root."""
    made = checkpoints(variant)
    first_tick = CUT_TICK + 1
    horizon = first_tick + HORIZON_SPAN
    return [
        "CFR1",
        1,
        RESULT_ID,
        plan_digest(variant),
        FORK_TIMELINE,
        1,
        first_tick,
        horizon,
        horizon,
        [[tick, 1, digest] for tick, _, digest, _ in made],
        0,  # Completed
        None,
        made[-1][1],
        frontier_digest(variant),
        PROVENANCE,
        REPLAY_CLAIM_EXACT,
        profile_ref()[2],
        trust_ref()[2],
        EVALUATOR_IDENTITY,
    ]


def result_bytes(variant: str) -> bytes:
    fields = result_fields(variant)
    return cbor(fields + [domain_digest(b"PiglorOS.CounterfactualResult.v1", cbor(fields))])


# --- The export and its surfaces (fork_artifacts.rs `export`, g_fork.rs `g_fork_capture_v1`) ---


@lru_cache(maxsize=None)
def artifacts(variant: str) -> list[tuple[str, bytes]]:
    """The seven exported artifacts, in export order."""
    return [
        ("Intervention", intervention_bytes(variant)),
        ("CounterfactualPlan", plan_bytes(variant)),
        ("RecomputationFrontier", frontier_bytes(variant)),
        ("SuffixInvalidation", invalidation_bytes(variant)),
        *(("Checkpoint", made[3]) for made in checkpoints(variant)),
        ("Result", result_bytes(variant)),
    ]


def surfaces(variant: str) -> tuple[list[bytes], list[bytes]]:
    """The nine authoritative and public records of `g_fork_capture_v1`. Every artifact sits at
    the WorldCut `[parent Timeline id, parent cut seq, parent cut Tick]`, its artifact ordinal
    its export position."""
    exported = artifacts(variant)
    cut_tick, cut_seq = cut()
    coordinate = [FACTUAL_TIMELINE, cut_seq, cut_tick]

    def kind(name: str) -> tuple[bytes, bytes]:
        chosen = [(ordinal, data) for ordinal, (k, data) in enumerate(exported) if k == name]
        return (
            cbor([data for _, data in chosen]),
            cbor([[ordinal, len(data), b3(data)] for ordinal, data in chosen]),
        )

    empty = cbor([])
    numbered = list(enumerate(exported))
    stream = cbor([[KIND_CODES[k], *coordinate, ordinal, data] for ordinal, (k, data) in numbered])
    listed = cbor(
        [[KIND_CODES[k], ordinal, len(data), b3(data)] for ordinal, (k, data) in numbered]
    )
    plan, frontier, invalidation, checkpoint, result = (
        kind(name)
        for name in (
            "CounterfactualPlan",
            "RecomputationFrontier",
            "SuffixInvalidation",
            "Checkpoint",
            "Result",
        )
    )
    parent_cut = cbor([FACTUAL_TIMELINE, cut_seq, cut_tick, PARENT_CUT_DIGEST])
    records = (parent_cut, cbor(coordinate)), plan, frontier, invalidation
    records += (empty, empty), checkpoint, result, (empty, empty), (stream, listed)
    return [record[0] for record in records], [record[1] for record in records]


def expected_result_digest(row: str, variant: str) -> bytes:
    if row != FORK_ROW:
        raise SystemExit(f"{row} is not a G-FORK row")
    authoritative, public = surfaces(variant)
    return result_digest(row, SURFACES[row], authoritative, public)


# --- Self-test ---


def self_test() -> None:
    # INT1: array(16), text "INT1", 1, bstr(16) of 0x49.
    if intervention_bytes("success")[:24] != bytes.fromhex("9064494e54310150") + bytes([0x49] * 16):
        raise SystemExit("the INT1 header is wrong")
    # The lead schema id is the first four bytes of its domain digest, nonzero.
    schema = event_schema_id(LEAD_EVENT_TYPE)
    lead = domain_digest(b"PiglorOS.FactualEventSchema.v1", LEAD_EVENT_TYPE.encode())
    expected = int.from_bytes(lead[:4], "big")
    if schema != max(1, expected) or decode(intervention_bytes("denial"))[0][3] != schema:
        raise SystemExit("the Intervention target schema id is wrong")
    # The fixture authority key signs TPS1: its public key is the DFA1 trust root.
    tps = decode(trust_policy_bytes())[0]
    key = tps[5][0][3]
    if key != golden.ed25519_public(FIXTURE_AUTHORITY_SEED) or key.hex() != authority()[
        "fixture_authority_public_key_hex"
    ]:
        raise SystemExit("the TPS1 trust root is not the DFA1 fixture authority key")
    # The classification bundle: nine `[rule, 1, class]`, external ingress ExogenousFrozen.
    bundle = decode(classification_bundle_bytes())[0]
    ingress = ["pos.factual.external-ingress", 1, EXOGENOUS]
    if len(bundle) != 9 or ingress not in bundle or bundle != sorted(bundle):
        raise SystemExit("the classification bundle is wrong")
    # Owner ids are `plugin:` and 64 lowercase hex digits, one per Driver.
    owners = [owner for owner, *_ in lanes()]
    if len(set(owners)) != 3 or any(len(o) != 71 or not o.startswith("plugin:") for o in owners):
        raise SystemExit("the factual owner ids are wrong")
    # Tick 1 records the snapshot, ingress, fold and a step and output node per Driver.
    rows, edges, _ = factual_tick()
    hosts = [row["node"][2] for row in rows[:3]]
    expected_hosts = ["host.ingress", "host.lineage", "host.observation"]
    if (len(rows), len(edges)) != (9, 8) or hosts != expected_hosts:
        raise SystemExit("the factual Tick 1 record is wrong")
    # The export: seven artifacts, the plan at the cut seq 4 of Tick 1.
    exported = artifacts("success")
    if [k for k, _ in exported] != list(KIND_CODES)[:5] + ["Checkpoint", "Result"]:
        raise SystemExit("the export order is wrong")
    if decode(exported[1][1])[0][6:8] != [4, 1]:
        raise SystemExit("the plan does not cut the factual Timeline at seq 4, Tick 1")
    # Only the permitted input moves the result.
    variants = ("success", "denial", "warm_cache", "cold_cache")
    if len({expected_result_digest(FORK_ROW, variant) for variant in variants}) != 4:
        raise SystemExit("the variants do not have four distinct result digests")
