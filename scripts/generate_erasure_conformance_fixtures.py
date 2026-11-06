#!/usr/bin/env python3
"""Generate and check the ADR-060 erasure conformance cases (ADR-062 Revision 8 slice N5, #1233).

The owner note `ADR-062_R8_Erasure_Cases` (decision 3) makes this script the independent oracle of
the erasure cases. It uses no Rust, no cargo and no binary of the repository (ADR-062 Revision 8,
Q3 (a)); implementation output is never an oracle.

It is the only writer of:

- `fixtures/conformance/erasure/cases.json`: the case definitions (digests, targets, obligations,
  acknowledgements in arrival order, artifact transition rules and states, rejoin proofs) and the
  expected projection of every case, derived here from the ADR-060 rules: the lifecycle sequence,
  the terminal state, the canonical acknowledgement order, the pending and failed owners, the
  per-row from/to ReplayClaim of each ERC1 inventory row, the aggregate ReplayClaim and each
  rejoin outcome;
- `fixtures/conformance/erasure/requests/*.erq1`: the exact ERQ1 bytes of every request,
  including the corrected request of the policy-conflict case, whose provenance is the
  ErasureCorrectionProvenanceV1 content address derived here from the rejected ERS1 chain.

`executions.json` and `records/` are the recorded artifacts of one run of
`apps/pos-experiment/tests/erasure_conformance.rs` (decision 2). `--check` decodes every recorded
ERS1, ERC1 and ERRJ1 and requires:

- every file name under `records/` to be the BLAKE3 of its bytes;
- every digest (ERS1 state digest, ERC1 receipt digest, ERRJ1 content digest) to recompute;
- each ERS1 chain to link oldest to newest with permitted lifecycle edges and a ReplayClaim that
  never strengthens, and its pre-freeze states (Submitted, Authorized, Rejected) and the
  destruction-dispatch states to equal the bytes derived here;
- each ERC1 to bind its terminal ERS1, the frozen targets, the canonical acknowledgements, the
  derived owners and the expected rows, and each row and the aggregate never to upgrade;
- each ERRJ1 to bind its receipt and to carry the expected outcome;
- no file of the erasure fixtures to contain the erased canary bytes.

Usage:
    python3 scripts/generate_erasure_conformance_fixtures.py          # write cases and requests
    python3 scripts/generate_erasure_conformance_fixtures.py --check  # self-test and verify
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import generate_metric_conformance_fixtures as metric  # noqa: E402
import generate_pmf1_golden_vectors as golden  # noqa: E402

ERASURE = ROOT / "fixtures/conformance/erasure"
CASES = ERASURE / "cases.json"
EXECUTIONS = ERASURE / "executions.json"

# The erased subject payload of `erasure_conformance.rs`. It must never appear in a fixture.
CANARY = b"pigloros-erasure-canary:subject-payload-v1"

VERSION = 1
ZERO = bytes(32)

CLAIMS = (
    "Exact",
    "ExactAuthoritativeWithRedactedViews",
    "StructuralOnly",
    "UnverifiableArtifactsMissing",
    "IncompatibleProfile",
)
LIFECYCLES = (
    "Submitted",
    "Authorized",
    "AccessFrozen",
    "DestructionDispatched",
    "AwaitingAcknowledgements",
    "Complete",
    "PartialFailure",
    "Rejected",
)
# ErasureLifecycleV1::permits: the single permitted forward edges.
PERMITTED = {
    "Submitted": {"Authorized", "Rejected"},
    "Authorized": {"AccessFrozen", "Rejected"},
    "AccessFrozen": {"DestructionDispatched"},
    "DestructionDispatched": {"AwaitingAcknowledgements"},
    "AwaitingAcknowledgements": {"Complete", "PartialFailure"},
    "Complete": set(),
    "PartialFailure": {"Complete", "PartialFailure"},
    "Rejected": set(),
}
CLASSES = (
    "TimelineReplay",
    "ReproManifest",
    "CausalTrace",
    "CalibrationReport",
    "Export",
    "ForkOrSnapshot",
    "ConformanceReport",
)
KEY_ROLES = ("DataEncryption", "Signing", "BackupEnvelope", "ReplicaTransport")
CATEGORIES = ("Artifact", "Key", "Replica", "Backup")
OUTCOMES = ("Acknowledged", "Negative", "Stale")
RULES = ("PreserveExact", "RedactViews", "RetainStructure", "Remove")
STATES = (
    "Retained",
    "TransitionApplied",
    "MissingParentCut",
    "MissingFrozenInput",
    "MissingKey",
    "MissingSchema",
    "MissingPlugin",
    "MissingModel",
    "MissingRuntime",
    "MissingRequiredOutput",
    "Erased",
    "Invalidated",
)
DISPOSITIONS = ("Tombstoned", "Unrecoverable")

FREEZE_POSITION = 10
REQUEST_POSITION = 9
HORIZON_POSITION = 20
# (admitted, deadline, issue) of attempt 0 and of the retry.
ATTEMPT_POSITIONS = ((11, 20, 20), (21, 30, 30))


# --- Primitives ---


def b3(data: bytes) -> bytes:
    return golden.blake3(data)


def domain_digest(domain: str, data: bytes) -> bytes:
    """`domain_digest` of `pos-core` erasure evidence: BLAKE3(domain || 0x00 || bytes)."""
    return b3(domain.encode("ascii") + b"\0" + data)


def ref(label: str) -> bytes:
    """A deterministic fixture digest; it never carries payload bytes."""
    return b3(b"pigloros.fixture.erasure-conformance/" + label.encode("utf-8"))


def enc(value: object) -> bytes:
    return metric.enc(value)


def claim_rank(claim: str) -> int:
    return CLAIMS.index(claim)


def weakened_to(current: str, candidate: str) -> str:
    """ErasureReplayClaimV1::weakened_to: a claim never strengthens."""
    return candidate if claim_rank(current) <= claim_rank(candidate) else current


# --- Independent derivation of the ADR-060 records ---


def target_key(target: dict) -> tuple:
    """The ADR-060 canonical target order `(class, digest, role, key, replica_set, replica_id)`."""
    return (
        CLASSES.index(target["artifact_class"]),
        bytes.fromhex(target["artifact_digest"]),
        KEY_ROLES.index(target["key_role"]),
        bytes.fromhex(target["key_digest"]),
        bytes.fromhex(target["replica_set"]),
        bytes.fromhex(target["replica_id"]),
    )


def target_value(target: dict) -> list:
    return [
        CLASSES.index(target["artifact_class"]),
        bytes.fromhex(target["artifact_digest"]),
        KEY_ROLES.index(target["key_role"]),
        bytes.fromhex(target["key_digest"]),
        bytes.fromhex(target["replica_set"]),
        bytes.fromhex(target["replica_id"]),
    ]


def command_identity(request: bytes, target: dict) -> bytes:
    """`destruction_command_reference`: the stable `(ERQ1, target)` command identity."""
    return b3(
        b"pigloros/erasure-destruction-command/v1"
        + request
        + CLASSES.index(target["artifact_class"]).to_bytes(8, "big")
        + bytes.fromhex(target["artifact_digest"])
        + KEY_ROLES.index(target["key_role"]).to_bytes(8, "big")
        + bytes.fromhex(target["key_digest"])
        + bytes.fromhex(target["replica_set"])
        + bytes.fromhex(target["replica_id"])
    )


def obligation_reference(request: bytes, obligation: dict, targets: list[dict]) -> bytes:
    target = targets[obligation["target"]]
    record = [
        "ERO1",
        VERSION,
        CATEGORIES.index(obligation["category"]),
        target_value(target),
        bytes.fromhex(obligation["owner"]),
        command_identity(request, target),
    ]
    return domain_digest("ERO1", enc(record))


def request_bytes(fields: dict) -> bytes:
    """Exact-length deterministic ERQ1 (12 elements, ADR-060)."""
    return enc(
        [
            "ERQ1",
            VERSION,
            fields["request"],
            fields["subject"],
            0,  # ErasureScopeV1::PrivateSubjectData
            sorted(fields["selectors"]),
            fields["requester"],
            fields["authorization"],
            fields["policy"],
            REQUEST_POSITION,
            HORIZON_POSITION,
            fields["provenance"],
        ]
    )


def state_core(state: dict) -> list:
    return [
        "ERS1",
        VERSION,
        state["request"],
        LIFECYCLES.index(state["lifecycle"]),
        state["freeze_position"],
        state["coordinator"],
        sorted(state["pending_owners"]),
        sorted(state["failed_owners"]),
        CLAIMS.index(state["replay_claim"]),
        state["previous_state"],
        state["provenance"],
    ]


def state_bytes(state: dict) -> tuple[bytes, bytes]:
    """Exact ERS1 (12 elements) and its state digest over the 11-element core."""
    core = state_core(state)
    digest = domain_digest("ERS1", enc(core))
    return enc(core + [digest]), digest


def pre_freeze_states(request: bytes, provenance: bytes, coordinator: bytes, steps) -> list:
    """The exact Submitted root and its pre-freeze successors `[(lifecycle, provenance)]`."""
    states = []
    previous = None
    for lifecycle, step_provenance in [("Submitted", provenance), *steps]:
        data, digest = state_bytes(
            {
                "request": request,
                "lifecycle": lifecycle,
                "freeze_position": FREEZE_POSITION if lifecycle == "AccessFrozen" else None,
                "coordinator": coordinator,
                "pending_owners": [],
                "failed_owners": [],
                "replay_claim": "Exact",
                "previous_state": previous,
                "provenance": step_provenance,
            }
        )
        states.append((data, digest))
        previous = digest
    return states


def rejection_reference(request: bytes, provenance: bytes) -> bytes:
    """ErasureAuthorizationRejectionV1 (ERAJ1) content address."""
    return domain_digest("ERAJ1", enc(["ERAJ1", VERSION, request, provenance]))


def correction_reference(
    request: bytes, rejected_state: bytes, reason: bytes, authorization: bytes
) -> bytes:
    """ErasureCorrectionProvenanceV1 (ERCP1) content address."""
    return domain_digest(
        "ERCP1", enc(["ERCP1", VERSION, request, rejected_state, reason, authorization])
    )


def retry_admission_reference(
    request: bytes,
    ordinal: int,
    source_receipt: bytes | None,
    unresolved: list[tuple[bytes, bytes]],
    attempt: dict,
    common: dict,
) -> bytes:
    """ErasureRetryAdmissionV1 (ERRA1) content address; obligations sorted bytewise."""
    pairs = sorted(unresolved)
    admitted, deadline, _issue = ATTEMPT_POSITIONS[ordinal]
    record = [
        "ERRA1",
        VERSION,
        request,
        ordinal,
        source_receipt,
        [obligation for obligation, _ in pairs],
        [command for _, command in pairs],
        common["policy"],
        common["trust"],
        admitted,
        deadline,
        bytes.fromhex(attempt["authorization_provenance"]),
    ]
    return domain_digest("ERRA1", enc(record))


def disposition(rule: str) -> str:
    return {
        "PreserveExact": "Exact",
        "RedactViews": "ExactAuthoritativeWithRedactedViews",
        "RetainStructure": "StructuralOnly",
        "Remove": "UnverifiableArtifactsMissing",
    }[rule]


def evaluate_row(current: str, rule: str, state: str) -> str:
    """ReplayClaimEvaluatorV1 for one required artifact (ADR-060 per-artifact transitions)."""
    if state == "Retained":
        candidate = current
    elif state == "TransitionApplied":
        candidate = disposition(rule)
    else:
        candidate = "UnverifiableArtifactsMissing"
    return weakened_to(current, candidate)


# --- Case catalogue ---


def digest_hex(label: str) -> str:
    return ref(label).hex()


def make_target(case: str, label: str, artifact_class: str, key_role: str) -> dict:
    return {
        "artifact_class": artifact_class,
        "artifact_digest": digest_hex(f"{case}/{label}/artifact"),
        "key_role": key_role,
        "key_digest": digest_hex(f"{case}/{label}/key"),
        "replica_set": digest_hex(f"{case}/replica-set"),
        "replica_id": digest_hex(f"{case}/replica"),
    }


def make_obligation(case: str, target: int, label: str, category: str) -> dict:
    return {
        "category": category,
        "target": target,
        "owner": digest_hex(f"{case}/{label}/{category.lower()}-owner"),
    }


def make_ack(case: str, attempt: int, obligation: int, outcome: str) -> dict:
    return {
        "obligation": obligation,
        "outcome": outcome,
        "evidence": digest_hex(f"{case}/attempt-{attempt}/ack-{obligation}-{outcome.lower()}"),
    }


def make_row(case: str, attempt: int, obligation: int, rule: str, state: str, disclosure=None):
    prefix = f"{case}/attempt-{attempt}/row-{obligation}"
    return {
        "obligation": obligation,
        "rule": rule,
        "state": state,
        "reason": digest_hex(f"{prefix}/reason"),
        "acknowledgements": digest_hex(f"{prefix}/acknowledgements"),
        "provenance": digest_hex(f"{prefix}/provenance"),
        "retained_disclosure": disclosure or digest_hex(f"{prefix}/retained-disclosure"),
    }


def make_attempt(case: str, attempt: int, acks: list[dict], rows: list[dict]) -> dict:
    return {
        "authorization_provenance": digest_hex(f"{case}/attempt-{attempt}/authorization"),
        "signature": digest_hex(f"{case}/attempt-{attempt}/signature"),
        "acknowledgements": acks,
        "rows": rows,
    }


def make_rejoin(case: str, label: str, attempt: int, entries, trusted: bool = True) -> dict:
    return {
        "attempt": attempt,
        "inventory_generation": digest_hex(f"{case}/{label}/inventory-generation"),
        "attestation": REJOIN_ATTESTATION.hex() if trusted else digest_hex(f"{case}/{label}/forged"),
        "entries": [
            {
                "obligation": obligation,
                "disposition": disposition_name,
                "evidence": digest_hex(f"{case}/{label}/entry-{obligation}"),
            }
            for obligation, disposition_name in entries
        ],
    }


REJOIN_ATTESTATION = ref("rejoin-attestation")


def base_case(case_id: str, title: str, targets: list[dict]) -> dict:
    return {
        "case_id": case_id,
        "title": title,
        "request": f"requests/{case_id}.erq1",
        "policy_conflict": None,
        "authorization_provenance": digest_hex(f"{case_id}/authorization-provenance"),
        "freeze_provenance": digest_hex(f"{case_id}/freeze-provenance"),
        "targets": sorted(targets, key=target_key),
        "obligations": [],
        "attempts": [],
        "rejoins": [],
    }


def case_complete() -> dict:
    name = "complete-all-categories"
    case = base_case(
        name,
        "Complete over the artifact, key, replica and backup obligations of one target; "
        "acknowledgements arrive out of canonical order with an exact duplicate; replica and "
        "backup rejoin (not distributed).",
        [make_target(name, "subject", "TimelineReplay", "DataEncryption")],
    )
    case["obligations"] = [make_obligation(name, 0, "subject", c) for c in CATEGORIES]
    acks = [make_ack(name, 0, index, "Acknowledged") for index in (3, 2, 1, 0)]
    acks.insert(2, dict(acks[1]))
    case["attempts"] = [
        make_attempt(
            name,
            0,
            acks,
            [
                make_row(name, 0, 0, "RedactViews", "TransitionApplied"),
                make_row(name, 0, 1, "RedactViews", "TransitionApplied"),
                make_row(name, 0, 2, "RetainStructure", "TransitionApplied"),
                make_row(name, 0, 3, "RetainStructure", "TransitionApplied"),
            ],
        )
    ]
    case["rejoins"] = [
        make_rejoin(name, "rejoin-complete", 0, [(2, "Tombstoned"), (3, "Unrecoverable")]),
        make_rejoin(name, "rejoin-without-backup", 0, [(2, "Tombstoned")]),
        make_rejoin(
            name, "rejoin-forged", 0, [(2, "Tombstoned"), (3, "Tombstoned")], trusted=False
        ),
    ]
    return case


def case_retry() -> dict:
    name = "partial-failure-then-retry"
    case = base_case(
        name,
        "A negative key acknowledgement gives PartialFailure; the retry closes it to Complete "
        "and a PreserveExact rule cannot restore the redacted claim.",
        [make_target(name, "subject", "ReproManifest", "Signing")],
    )
    case["obligations"] = [
        make_obligation(name, 0, "subject", "Artifact"),
        make_obligation(name, 0, "subject", "Key"),
    ]
    case["attempts"] = [
        make_attempt(
            name,
            0,
            [make_ack(name, 0, 1, "Negative"), make_ack(name, 0, 0, "Acknowledged")],
            [
                make_row(name, 0, 0, "RedactViews", "TransitionApplied"),
                make_row(name, 0, 1, "RetainStructure", "Retained"),
            ],
        ),
        make_attempt(
            name,
            1,
            [make_ack(name, 1, 1, "Acknowledged")],
            [
                make_row(name, 1, 0, "PreserveExact", "TransitionApplied"),
                make_row(name, 1, 1, "RetainStructure", "TransitionApplied"),
            ],
        ),
    ]
    case["rejoins"] = [make_rejoin(name, "rejoin-partial", 0, [])]
    return case


def case_stale_missing() -> dict:
    name = "partial-failure-stale-and-missing"
    case = base_case(
        name,
        "A stale artifact acknowledgement and a missing replica acknowledgement leave the attempt "
        "PartialFailure at its deadline; a rejoin against it is refused.",
        [make_target(name, "subject", "CausalTrace", "BackupEnvelope")],
    )
    case["obligations"] = [
        make_obligation(name, 0, "subject", "Artifact"),
        make_obligation(name, 0, "subject", "Replica"),
        make_obligation(name, 0, "subject", "Backup"),
    ]
    case["attempts"] = [
        make_attempt(
            name,
            0,
            [make_ack(name, 0, 2, "Acknowledged"), make_ack(name, 0, 0, "Stale")],
            [
                make_row(name, 0, 0, "Remove", "Retained"),
                make_row(name, 0, 1, "Remove", "Retained"),
                make_row(name, 0, 2, "RetainStructure", "TransitionApplied"),
            ],
        )
    ]
    case["rejoins"] = [
        make_rejoin(name, "rejoin-pending", 0, [(1, "Tombstoned"), (2, "Tombstoned")])
    ]
    return case


def case_policy_conflict() -> dict:
    name = "policy-conflict-corrected"
    case = base_case(
        name,
        "The authority refuses authorization with PolicyConflict; the request is Rejected and a "
        "corrected ERQ1 bound to its ErasureCorrectionProvenanceV1 completes.",
        [make_target(name, "subject", "CalibrationReport", "DataEncryption")],
    )
    case["policy_conflict"] = {
        "rejection_provenance": digest_hex(f"{name}/rejection-provenance"),
        "correction_reason": digest_hex(f"{name}/correction-reason"),
        "correction_authorization": digest_hex(f"{name}/correction-authorization"),
        "request": f"requests/{name}.corrected.erq1",
    }
    case["obligations"] = [make_obligation(name, 0, "subject", "Artifact")]
    case["attempts"] = [
        make_attempt(
            name,
            0,
            [make_ack(name, 0, 0, "Acknowledged")],
            [make_row(name, 0, 0, "RedactViews", "TransitionApplied")],
        )
    ]
    return case


def case_legal_hold() -> dict:
    name = "legal-hold"
    case = base_case(
        name,
        "The pinned policy holds one artifact: its key, replica and backup obligations are "
        "Inapplicable, it keeps Exact with a retained-disclosure digest, and the request "
        "completes on the remaining obligations.",
        [
            make_target(name, "erased", "Export", "DataEncryption"),
            make_target(name, "held", "ForkOrSnapshot", "DataEncryption"),
        ],
    )
    labels = {target["artifact_digest"]: index for index, target in enumerate(case["targets"])}
    erased = labels[digest_hex(f"{name}/erased/artifact")]
    held = labels[digest_hex(f"{name}/held/artifact")]
    case["obligations"] = [
        make_obligation(name, erased, "erased", "Artifact"),
        make_obligation(name, erased, "erased", "Key"),
        make_obligation(name, held, "held", "Artifact"),
    ]
    case["attempts"] = [
        make_attempt(
            name,
            0,
            [make_ack(name, 0, index, "Acknowledged") for index in (2, 0, 1)],
            [
                make_row(name, 0, 0, "Remove", "TransitionApplied"),
                make_row(name, 0, 1, "Remove", "TransitionApplied"),
                make_row(
                    name, 0, 2, "PreserveExact", "Retained", digest_hex(f"{name}/hold-disclosure")
                ),
            ],
        )
    ]
    return case


def case_transitions() -> dict:
    name = "transitions-every-class"
    # (state, rule): every artifact state and transition rule, cycled over every class and role.
    plan = [
        ("Retained", "PreserveExact"),
        ("TransitionApplied", "PreserveExact"),
        ("TransitionApplied", "RedactViews"),
        ("TransitionApplied", "RetainStructure"),
        ("TransitionApplied", "Remove"),
        ("MissingParentCut", "RetainStructure"),
        ("MissingFrozenInput", "RedactViews"),
        ("MissingKey", "PreserveExact"),
        ("MissingSchema", "RedactViews"),
        ("MissingPlugin", "RetainStructure"),
        ("MissingModel", "PreserveExact"),
        ("MissingRuntime", "RedactViews"),
        ("MissingRequiredOutput", "RetainStructure"),
        ("Erased", "Remove"),
        ("Invalidated", "PreserveExact"),
    ]
    targets = [
        make_target(name, f"member-{index:02}", CLASSES[index % 7], KEY_ROLES[index % 4])
        for index in range(len(plan))
    ]
    case = base_case(
        name,
        "Every artifact class, transition rule and artifact state through ReplayClaimEvaluatorV1.",
        targets,
    )
    index_of = {target["artifact_digest"]: i for i, target in enumerate(case["targets"])}
    member_targets = [index_of[digest_hex(f"{name}/member-{i:02}/artifact")] for i in range(len(plan))]
    case["obligations"] = [
        make_obligation(name, member_targets[i], f"member-{i:02}", "Artifact")
        for i in range(len(plan))
    ]
    case["attempts"] = [
        make_attempt(
            name,
            0,
            [make_ack(name, 0, i, "Acknowledged") for i in range(len(plan))],
            [make_row(name, 0, i, rule, state) for i, (state, rule) in enumerate(plan)],
        )
    ]
    return case


COMMON = {
    "coordinator": ref("coordinator"),
    "policy": ref("policy"),
    "trust": ref("trust"),
    "scope_member": ref("scope-member"),
    "lineage_rule": ref("lineage-rule"),
    "quota_reservation": ref("quota-reservation"),
    "rejoin_attestation": REJOIN_ATTESTATION,
}


def request_fields(case_id: str, request_label: str, provenance: bytes) -> dict:
    return {
        "request": ref(f"{case_id}/{request_label}"),
        "subject": ref(f"{case_id}/subject"),
        "selectors": [ref(f"{case_id}/selector")],
        "requester": ref(f"{case_id}/requester"),
        "authorization": ref(f"{case_id}/authorization"),
        "policy": COMMON["policy"],
        "provenance": provenance,
    }


def original_request(case: dict) -> dict:
    return request_fields(case["case_id"], "request", ref(f"{case['case_id']}/request-provenance"))


def corrected_request(case: dict) -> tuple[dict, list]:
    """The corrected ERQ1 and the exact rejected chain it is bound to."""
    original = original_request(case)
    conflict = case["policy_conflict"]
    rejected = pre_freeze_states(
        original["request"],
        original["provenance"],
        COMMON["coordinator"],
        [
            (
                "Rejected",
                rejection_reference(
                    original["request"], bytes.fromhex(conflict["rejection_provenance"])
                ),
            )
        ],
    )
    correction = correction_reference(
        original["request"],
        rejected[-1][1],
        bytes.fromhex(conflict["correction_reason"]),
        bytes.fromhex(conflict["correction_authorization"]),
    )
    return request_fields(case["case_id"], "corrected-request", correction), rejected


def cases() -> list[dict]:
    return [
        case_complete(),
        case_retry(),
        case_stale_missing(),
        case_policy_conflict(),
        case_legal_hold(),
        case_transitions(),
    ]


# --- Expected projection ---


def expected_attempts(case: dict, request: bytes) -> list[dict]:
    """Per attempt: lifecycle, canonical acknowledgements, owners, rows and aggregate claim."""
    targets = case["targets"]
    obligations = case["obligations"]
    references = [obligation_reference(request, o, targets) for o in obligations]
    effective: dict[int, dict] = {}
    previous_rows: dict[int, str] = {}
    receipts = []
    for attempt in case["attempts"]:
        for ack in attempt["acknowledgements"]:
            effective[ack["obligation"]] = ack
        positive = {index for index, ack in effective.items() if ack["outcome"] == "Acknowledged"}
        complete = positive == set(range(len(obligations)))
        acknowledgements = sorted(
            effective.values(),
            key=lambda ack: (
                target_key(targets[obligations[ack["obligation"]]["target"]]),
                references[ack["obligation"]],
                bytes.fromhex(obligations[ack["obligation"]]["owner"]),
                bytes.fromhex(ack["evidence"]),
                OUTCOMES.index(ack["outcome"]),
            ),
        )
        failed = sorted(
            {
                obligations[ack["obligation"]]["owner"]
                for ack in effective.values()
                if ack["outcome"] != "Acknowledged"
            }
        )
        pending = sorted(
            {
                obligations[index]["owner"]
                for index in range(len(obligations))
                if index not in positive
            }
            - set(failed)
        )
        rows = []
        for row in attempt["rows"]:
            current = previous_rows.get(row["obligation"], "Exact")
            rows.append(
                {
                    "obligation": row["obligation"],
                    "from": current,
                    "to": evaluate_row(current, row["rule"], row["state"]),
                }
            )
        rows.sort(
            key=lambda row: (
                CATEGORIES.index(obligations[row["obligation"]]["category"]),
                target_key(targets[obligations[row["obligation"]]["target"]]),
            )
        )
        aggregate = "Exact"
        for row in rows:
            aggregate = weakened_to(aggregate, row["to"])
        receipts.append(
            {
                "lifecycle": "Complete" if complete else "PartialFailure",
                "replay_claim": aggregate,
                "acknowledgements": [
                    {"obligation": ack["obligation"], "outcome": ack["outcome"]}
                    for ack in acknowledgements
                ],
                "pending_owners": pending,
                "failed_owners": failed,
                "rows": rows,
            }
        )
        previous_rows = {row["obligation"]: row["to"] for row in rows}
        effective = {index: ack for index, ack in effective.items() if index in positive}
    return receipts


def expected_rejoin(case: dict, rejoin: dict, receipts: list[dict]) -> str:
    """ErasureRejoinProofV1::admit under the fixture attestation verifier."""
    receipt = receipts[rejoin["attempt"]]
    obligations = case["obligations"]
    backups = [i for i in range(len(obligations)) if obligations[i]["category"] == "Backup"]
    if receipt["lifecycle"] != "Complete":
        return "BackupDeletionPending" if backups else "BackupInventoryIncomplete"
    expected = sorted(
        i for i in range(len(obligations)) if obligations[i]["category"] in ("Replica", "Backup")
    )
    found = sorted(entry["obligation"] for entry in rejoin["entries"])
    if not expected or found != expected:
        return "BackupInventoryIncomplete"
    if rejoin["attestation"] != REJOIN_ATTESTATION.hex():
        return "Unauthorized"
    return "Admitted"


def expected_history(case: dict, refusal: str | None, request: bytes) -> dict:
    receipts = expected_attempts(case, request)
    lifecycles = [
        "Submitted",
        "Authorized",
        "AccessFrozen",
        "DestructionDispatched",
        "AwaitingAcknowledgements",
    ] + [receipt["lifecycle"] for receipt in receipts]
    claims = ["Exact"] * 5 + [receipt["replay_claim"] for receipt in receipts]
    return {
        "authorization_refusal": refusal,
        "lifecycles": lifecycles,
        "replay_claims": claims,
        "receipts": receipts,
    }


def expected_case(case: dict) -> dict:
    histories = []
    if case["policy_conflict"] is None:
        final = original_request(case)
    else:
        histories.append(
            {
                "authorization_refusal": "Conflict",
                "lifecycles": ["Submitted", "Rejected"],
                "replay_claims": ["Exact", "Exact"],
                "receipts": [],
            }
        )
        final, _ = corrected_request(case)
    histories.append(expected_history(case, None, final["request"]))
    receipts = histories[-1]["receipts"]
    return {
        "histories": histories,
        "rejoins": [expected_rejoin(case, rejoin, receipts) for rejoin in case["rejoins"]],
    }


def catalogue() -> dict:
    entries = []
    for case in cases():
        entries.append({**case, "expected": expected_case(case)})
    return {
        "schema": "pigloros.erasure-conformance.cases.v1",
        "adr": "ADR-060; ADR-062 Revision 8 note ADR-062_R8_Erasure_Cases (#1233)",
        "authority_kind": "repository-test-fixture-only",
        "evidence": "engineering-evidence",
        "distribution": "not-distributed",
        "execution": "local-in-process",
        **{key: value.hex() for key, value in COMMON.items()},
        "cases": entries,
    }


def outputs() -> dict[Path, bytes]:
    wanted = {CASES: (json.dumps(catalogue(), indent=2, sort_keys=True) + "\n").encode("utf-8")}
    for case in cases():
        wanted[ERASURE / case["request"]] = request_bytes(original_request(case))
        if case["policy_conflict"] is not None:
            corrected, _ = corrected_request(case)
            wanted[ERASURE / case["policy_conflict"]["request"]] = request_bytes(corrected)
    return wanted


# --- Recorded-artifact check ---


def decode(data: bytes, pos: int = 0) -> tuple[object, int]:
    """Decode the definite-length CBOR of the erasure records (no maps, no floats, no tags)."""
    initial = data[pos]
    major, info = initial >> 5, initial & 31
    pos += 1
    if initial == 0xF6:
        return None, pos
    if info < 24:
        argument = info
    elif info <= 27:
        width = 1 << (info - 24)
        argument = int.from_bytes(data[pos : pos + width], "big")
        pos += width
    else:
        raise ValueError("indefinite or reserved CBOR item")
    if major == 0:
        return argument, pos
    if major == 2:
        return bytes(data[pos : pos + argument]), pos + argument
    if major == 3:
        return data[pos : pos + argument].decode("utf-8"), pos + argument
    if major == 4:
        items = []
        for _ in range(argument):
            item, pos = decode(data, pos)
            items.append(item)
        return items, pos
    raise ValueError(f"unexpected CBOR major type {major}")


def decode_exact(data: bytes, tag: str, length: int) -> list:
    value, end = decode(data)
    if end != len(data) or not isinstance(value, list) or len(value) != length:
        raise SystemExit(f"{tag}: not one exact {length}-element array")
    if value[0] != tag or value[1] != VERSION or enc(value) != data:
        raise SystemExit(f"{tag}: wrong header or non-canonical encoding")
    return value


def fail(message: str) -> None:
    raise SystemExit(f"erasure conformance check failed: {message}")


def record_bytes(path: str) -> bytes:
    if not path.startswith("records/"):
        fail(f"{path} is not under records/")
    data = (ERASURE / path).read_bytes()
    if Path(path).stem != b3(data).hex():
        fail(f"{path} is not named by its BLAKE3")
    return data


def check_states(paths: list[str], request: bytes, expected: dict) -> list[dict]:
    states = []
    previous = None
    for path in paths:
        value = decode_exact(record_bytes(path), "ERS1", 12)
        if domain_digest("ERS1", enc(value[:11])) != value[11]:
            fail(f"{path}: state digest does not recompute")
        state = {
            "request": value[2],
            "lifecycle": LIFECYCLES[value[3]],
            "freeze_position": value[4],
            "coordinator": value[5],
            "pending_owners": [owner.hex() for owner in value[6]],
            "failed_owners": [owner.hex() for owner in value[7]],
            "replay_claim": CLAIMS[value[8]],
            "previous_state": value[9],
            "provenance": value[10],
            "digest": value[11],
            "bytes": record_bytes(path),
        }
        if state["request"] != request or state["coordinator"] != COMMON["coordinator"]:
            fail(f"{path}: wrong request or coordinator")
        if previous is None:
            if state["previous_state"] is not None:
                fail(f"{path}: the root state names a predecessor")
        else:
            if state["previous_state"] != previous["digest"]:
                fail(f"{path}: broken predecessor link")
            if state["lifecycle"] not in PERMITTED[previous["lifecycle"]]:
                fail(f"{path}: backward or skipped lifecycle edge")
            if claim_rank(state["replay_claim"]) < claim_rank(previous["replay_claim"]):
                fail(f"{path}: the ReplayClaim was upgraded")
        states.append(state)
        previous = state
    if [s["lifecycle"] for s in states] != expected["lifecycles"]:
        fail(f"lifecycles {[s['lifecycle'] for s in states]} != {expected['lifecycles']}")
    if [s["replay_claim"] for s in states] != expected["replay_claims"]:
        fail("ERS1 ReplayClaims differ from the expected projection")
    return states


def check_receipt(path: str, case: dict, request: bytes, state: dict, expected: dict, ordinal: int):
    data = record_bytes(path)
    value = decode_exact(data, "ERC1", 19)
    core = value[:16] + value[17:]
    if domain_digest("ERC1", enc(core)) != value[16]:
        fail(f"{path}: receipt digest does not recompute")
    targets = case["targets"]
    obligations = case["obligations"]
    references = [obligation_reference(request, o, targets) for o in obligations]
    if value[2] != request or value[3] != state["digest"] or value[18] != COMMON["coordinator"]:
        fail(f"{path}: not bound to its request, terminal ERS1 and coordinator")
    if LIFECYCLES[value[4]] != expected["lifecycle"] or value[5] != FREEZE_POSITION:
        fail(f"{path}: wrong lifecycle or freeze position")
    if value[6] != [target_value(t) for t in targets]:
        fail(f"{path}: frozen targets differ from the canonical target closure")
    acknowledgements = []
    for ack in value[7]:
        index = references.index(ack[0])
        if ack[1] != target_value(targets[obligations[index]["target"]]):
            fail(f"{path}: acknowledgement target mismatch")
        if ack[2] != bytes.fromhex(obligations[index]["owner"]):
            fail(f"{path}: acknowledgement owner mismatch")
        acknowledgements.append({"obligation": index, "outcome": OUTCOMES[ack[4]]})
    if acknowledgements != expected["acknowledgements"]:
        fail(f"{path}: acknowledgements are not in the expected canonical order")
    if [o.hex() for o in value[8]] != expected["pending_owners"]:
        fail(f"{path}: pending owners differ")
    if [o.hex() for o in value[9]] != expected["failed_owners"]:
        fail(f"{path}: failed owners differ")
    if state["pending_owners"] != expected["pending_owners"]:
        fail(f"{path}: terminal ERS1 pending owners differ")
    if state["failed_owners"] != expected["failed_owners"]:
        fail(f"{path}: terminal ERS1 failed owners differ")
    rows = []
    for category_index, inventory in enumerate(value[10]):
        for row in inventory:
            if row[0] != category_index:
                fail(f"{path}: row in the wrong inventory")
            index = next(
                i
                for i, o in enumerate(obligations)
                if CATEGORIES.index(o["category"]) == row[0]
                and target_value(targets[o["target"]]) == row[1]
            )
            transition = row[2]
            if claim_rank(CLAIMS[transition[1]]) < claim_rank(CLAIMS[transition[0]]):
                fail(f"{path}: an inventory row upgrades its ReplayClaim")
            if transition[3] != bytes.fromhex(obligations[index]["owner"]):
                fail(f"{path}: row owner differs from the obligation owner")
            row_input = next(r for r in case["attempts"][ordinal]["rows"] if r["obligation"] == index)
            if row[3] != bytes.fromhex(row_input["retained_disclosure"]):
                fail(f"{path}: retained disclosure differs")
            rows.append(
                {"obligation": index, "from": CLAIMS[transition[0]], "to": CLAIMS[transition[1]]}
            )
    if rows != expected["rows"]:
        fail(f"{path}: rows {rows} != {expected['rows']}")
    if CLAIMS[value[11]] != expected["replay_claim"] or state["replay_claim"] != expected["replay_claim"]:
        fail(f"{path}: aggregate ReplayClaim differs")
    if value[12] != COMMON["policy"] or value[13] != COMMON["trust"]:
        fail(f"{path}: wrong policy or trust")
    if value[15] != ATTEMPT_POSITIONS[ordinal][2]:
        fail(f"{path}: wrong issue position")
    if value[17] != bytes.fromhex(case["attempts"][ordinal]["signature"]):
        fail(f"{path}: wrong signature commitment")
    return value[16]


def check_history(case: dict, history: dict, expected: dict, request_label: str) -> list:
    data = (ERASURE / history["request"]).read_bytes()
    request_value = decode_exact(data, "ERQ1", 12)
    request = request_value[2]
    if history["authorization_refusal"] != expected["authorization_refusal"]:
        fail(f"{case['case_id']}: authorization refusal differs")
    states = check_states(history["states"], request, expected)
    root = states[0]
    if root["provenance"] != request_value[11]:
        fail(f"{case['case_id']}: Submitted provenance is not the ERQ1 provenance")
    if request_label == "rejected":
        exact = pre_freeze_states(
            request,
            request_value[11],
            COMMON["coordinator"],
            [
                (
                    "Rejected",
                    rejection_reference(
                        request, bytes.fromhex(case["policy_conflict"]["rejection_provenance"])
                    ),
                )
            ],
        )
        if [s["bytes"] for s in states] != [d for d, _ in exact]:
            fail(f"{case['case_id']}: the rejected chain differs from its derivation")
        if history["receipts"]:
            fail(f"{case['case_id']}: a rejected request has a receipt")
        return []
    exact = pre_freeze_states(
        request,
        request_value[11],
        COMMON["coordinator"],
        [("Authorized", bytes.fromhex(case["authorization_provenance"]))],
    )
    if [s["bytes"] for s in states[:2]] != [d for d, _ in exact]:
        fail(f"{case['case_id']}: Submitted/Authorized differ from their derivation")
    if states[2]["freeze_position"] != FREEZE_POSITION:
        fail(f"{case['case_id']}: wrong freeze position")
    if len(history["receipts"]) != len(case["attempts"]):
        fail(f"{case['case_id']}: one ERC1 per attempt is required")
    receipts = []
    terminal_states = states[5:]
    previous_receipt = None
    obligations = case["obligations"]
    references = [obligation_reference(request, o, case["targets"]) for o in obligations]
    acknowledged: set[int] = set()
    for ordinal, path in enumerate(history["receipts"]):
        unresolved = [
            (references[i], command_identity(request, case["targets"][obligations[i]["target"]]))
            for i in range(len(obligations))
            if i not in acknowledged
        ]
        admission = retry_admission_reference(
            request, ordinal, previous_receipt, unresolved, case["attempts"][ordinal], COMMON
        )
        if ordinal == 0 and (
            states[3]["provenance"] != admission or states[4]["provenance"] != admission
        ):
            fail(f"{case['case_id']}: dispatch states are not bound to the ERRA1 admission")
        expected_receipt = expected["receipts"][ordinal]
        digest = check_receipt(
            path, case, request, terminal_states[ordinal], expected_receipt, ordinal
        )
        acknowledged |= {
            a["obligation"]
            for a in expected_receipt["acknowledgements"]
            if a["outcome"] == "Acknowledged"
        }
        receipts.append(digest)
        previous_receipt = digest
    return receipts


def check_rejoin(case: dict, rejoin: dict, record: dict, receipts: list, request: bytes, outcome):
    value = decode_exact(record_bytes(record["proof"]), "ERRJ1", 10)
    if domain_digest("ERRJ1", enc(value[:9])) != value[9]:
        fail(f"{record['proof']}: proof digest does not recompute")
    if value[2] != request or value[3] != receipts[rejoin["attempt"]]:
        fail(f"{record['proof']}: proof is not bound to its request and receipt")
    if value[8] != bytes.fromhex(rejoin["attestation"]):
        fail(f"{record['proof']}: wrong attestation")
    if len(value[7]) != len(rejoin["entries"]):
        fail(f"{record['proof']}: wrong entry count")
    if record["outcome"] != outcome:
        fail(f"{record['proof']}: outcome {record['outcome']} != {outcome}")


def check_executions() -> None:
    catalogue_value = json.loads(CASES.read_text(encoding="utf-8"))
    executions = json.loads(EXECUTIONS.read_text(encoding="utf-8"))
    if executions["schema"] != "pigloros.erasure-conformance.executions.v1":
        fail("unknown executions schema")
    by_id = {case["case_id"]: case for case in catalogue_value["cases"]}
    if [case["case_id"] for case in executions["cases"]] != list(by_id):
        fail("executions.json does not cover every case in order")
    referenced = set()
    for execution in executions["cases"]:
        case = by_id[execution["case_id"]]
        expected = case["expected"]
        if len(execution["histories"]) != len(expected["histories"]):
            fail(f"{case['case_id']}: wrong number of request histories")
        receipts: list = []
        request = b""
        for index, (history, expected_history_value) in enumerate(
            zip(execution["histories"], expected["histories"])
        ):
            rejected = case["policy_conflict"] is not None and index == 0
            receipts = check_history(
                case, history, expected_history_value, "rejected" if rejected else "final"
            )
            request = decode_exact((ERASURE / history["request"]).read_bytes(), "ERQ1", 12)[2]
            referenced.update(history["states"])
            referenced.update(history["receipts"])
        if len(execution["rejoins"]) != len(case["rejoins"]):
            fail(f"{case['case_id']}: wrong number of rejoin proofs")
        for rejoin, record, outcome in zip(case["rejoins"], execution["rejoins"], expected["rejoins"]):
            check_rejoin(case, rejoin, record, receipts, request, outcome)
            referenced.add(record["proof"])
    on_disk = {
        f"records/{path.name}" for path in (ERASURE / "records").iterdir() if path.is_file()
    }
    if on_disk != referenced:
        fail("records/ holds files that executions.json does not reference, or misses some")


def check_no_canary() -> None:
    for path in sorted(ERASURE.rglob("*")):
        if path.is_file() and CANARY in path.read_bytes():
            fail(f"{path} contains erased canary bytes")


def self_test() -> None:
    metric.check_blake3_vectors()
    # The weakening rule is one-way.
    for current in CLAIMS:
        for candidate in CLAIMS:
            result = weakened_to(current, candidate)
            if claim_rank(result) < claim_rank(current):
                fail("weakened_to strengthened a claim")
    # The ERQ1 decoder reads back what the encoder writes.
    for case in cases():
        data = request_bytes(original_request(case))
        if decode_exact(data, "ERQ1", 12)[2] != ref(f"{case['case_id']}/request"):
            fail("ERQ1 self-test")
    # Every enum variant the Rust case model mirrors is exercised by some case.
    used_states = {r["state"] for c in cases() for a in c["attempts"] for r in a["rows"]}
    used_rules = {r["rule"] for c in cases() for a in c["attempts"] for r in a["rows"]}
    used_outcomes = {k["outcome"] for c in cases() for a in c["attempts"] for k in a["acknowledgements"]}
    used_categories = {o["category"] for c in cases() for o in c["obligations"]}
    used_classes = {t["artifact_class"] for c in cases() for t in c["targets"]}
    used_roles = {t["key_role"] for c in cases() for t in c["targets"]}
    used_dispositions = {
        e["disposition"] for c in cases() for j in c["rejoins"] for e in j["entries"]
    }
    for used, every in (
        (used_states, STATES),
        (used_rules, RULES),
        (used_outcomes, OUTCOMES),
        (used_categories, CATEGORIES),
        (used_classes, CLASSES),
        (used_roles, KEY_ROLES),
        (used_dispositions, DISPOSITIONS),
    ):
        if used != set(every):
            fail(f"the cases do not exercise {sorted(set(every) - used)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="self-test and verify every output")
    arguments = parser.parse_args()
    self_test()
    wanted = outputs()
    if not arguments.check:
        for path, data in wanted.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return 0
    stale = [path for path, data in wanted.items() if not path.exists() or path.read_bytes() != data]
    for path in stale:
        print(f"{path} is stale; rerun the generator", file=sys.stderr)
    if stale:
        return 1
    check_executions()
    check_no_canary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
