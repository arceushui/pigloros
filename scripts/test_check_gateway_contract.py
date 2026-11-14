#!/usr/bin/env python3
"""Rejection tests of `check_gateway_contract.py`: drift in each input fails (#1312-#1314)."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_gateway_contract as checker  # noqa: E402

DOCUMENT = checker.load(checker.OPENAPI)
REGISTRY = checker.load(checker.PROBLEM_TYPES)


def contract(document: dict | None = None, registry: dict | None = None) -> checker.Contract:
    return checker.Contract(
        copy.deepcopy(DOCUMENT if document is None else document),
        copy.deepcopy(REGISTRY if registry is None else registry),
    )


PROBLEM_CODES = [entry["code"] for entry in REGISTRY["problem_types"]]


def with_problem_code(code: str) -> tuple[dict, dict]:
    """The description and registry with one more problem type, as a later v1 revision adds it."""
    document, registry = copy.deepcopy(DOCUMENT), copy.deepcopy(REGISTRY)
    registry["problem_types"].append({
        "code": code,
        "type": checker.PROBLEM_TYPE_PREFIX + code,
        "title": "Quota exhausted",
        "statuses": [429],
        "description": "A new problem type of a later v1 revision.",
    })
    document["components"]["schemas"]["Problem"]["properties"]["code"]["enum"].append(code)
    return document, registry


def problem_code(baseline: dict) -> dict:
    return baseline["components"]["schemas"]["Problem"]["properties"]["code"]


UNROUTED_PATHS = Path(__file__).resolve().parent / "data/gateway_unrouted_paths.json"
TIMELINES = "/v1/timelines"
EVENTS = "/v1/timelines/{timeline_id}/events"
PREVIEWS = "/v1/decision-previews"


def example(name: str) -> dict:
    return checker.load(checker.EXAMPLES / f"{name}.json")  # type: ignore[return-value]


def problem(status: int, code: str, instance: str = TIMELINES) -> dict:
    title = {entry["code"]: entry["title"] for entry in REGISTRY["problem_types"]}[code]
    return {
        "type": checker.PROBLEM_TYPE_PREFIX + code,
        "title": title,
        "status": status,
        "detail": "detail",
        "instance": instance,
        "code": code,
        "schema_id": "urn:pigloros:gateway:v1:schema:problem",
        "retryable": False,
    }


class CheckGatewayContractTest(unittest.TestCase):
    def operation(self, subject: checker.Contract, method: str, path: str) -> dict:
        return subject.operation_for(method, path)[1]

    def test_the_checked_in_contract_passes(self) -> None:
        subject = contract()
        checker.check_description(subject)
        checker.check_registry(subject)
        self.assertGreater(checker.check_examples(subject), 0)
        self.assertGreater(checker.check_fixtures(subject), 0)

    def test_a_reordered_registry_is_drift(self) -> None:
        registry = copy.deepcopy(REGISTRY)
        registry["problem_types"].reverse()
        with self.assertRaises(checker.ContractError):
            checker.check_registry(contract(registry=registry))

    def test_a_wrong_problem_type_urn_is_drift(self) -> None:
        registry = copy.deepcopy(REGISTRY)
        registry["problem_types"][0]["type"] = "about:blank"
        with self.assertRaises(checker.ContractError):
            checker.check_registry(contract(registry=registry))

    def test_a_failure_answered_as_plain_json_is_drift(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        responses = document["paths"]["/v1/timelines"]["post"]["responses"]
        responses["429"] = {
            "description": "plain",
            "content": {"application/json": {"schema": {"type": "object"}}},
        }
        with self.assertRaises(checker.ContractError):
            checker.check_description(contract(document=document))

    def test_a_duplicate_operation_id_is_drift(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["paths"]["/v1/ledger"]["get"]["operationId"] = "getHealth"
        with self.assertRaises(checker.ContractError):
            checker.check_description(contract(document=document))

    def test_an_unresolved_reference_is_drift(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["EventPage"]["properties"]["events"]["items"] = {
            "$ref": "urn:pigloros:gateway:v1:schema:missing"
        }
        with self.assertRaises(checker.ContractError):
            checker.check_description(contract(document=document))

    def test_a_problem_with_an_unregistered_status_is_rejected(self) -> None:
        subject = contract()
        operation = self.operation(subject, "POST", "/v1/timelines")
        self.assertEqual(
            subject.response_errors(
                operation, 429, problem(429, "resource-limit-exceeded"), TIMELINES
            ),
            [],
        )
        self.assertTrue(
            subject.response_errors(operation, 418, problem(418, "unauthorized"), TIMELINES)
        )

    def test_a_problem_whose_status_differs_from_the_http_status_is_rejected(self) -> None:
        subject = contract()
        operation = self.operation(subject, "POST", "/v1/timelines")
        self.assertTrue(
            subject.response_errors(
                operation, 429, problem(413, "resource-limit-exceeded"), TIMELINES
            )
        )

    def test_an_undocumented_member_in_a_served_response_is_rejected(self) -> None:
        subject = contract()
        operation = self.operation(subject, "GET", "/health")
        self.assertEqual(subject.response_errors(operation, 200, {"ok": True}, "/health"), [])
        extra = {"ok": True, "extra": 1}
        self.assertTrue(subject.response_errors(operation, 200, extra, "/health"))

    def test_an_old_error_envelope_is_rejected(self) -> None:
        subject = contract()
        operation = self.operation(subject, "POST", "/v1/timelines")
        self.assertTrue(subject.response_errors(operation, 429, {"error": "limit"}, TIMELINES))

    def test_a_problem_naming_a_concrete_path_is_rejected(self) -> None:
        subject = contract()
        concrete = f"/v1/timelines/{checker.SAMPLE_ULID}/events"
        template, operation = subject.operation_for("GET", concrete)
        self.assertEqual(template, EVENTS)
        invalid = problem(400, "invalid-request", concrete)
        self.assertTrue(subject.response_errors(operation, 400, invalid, template, concrete))
        valid = problem(400, "invalid-request", EVENTS)
        self.assertEqual(subject.response_errors(operation, 400, valid, template, concrete), [])

    def test_only_an_unrouted_not_found_names_its_request_path(self) -> None:
        subject = contract()
        concrete = f"/v1/timelines/{checker.SAMPLE_ULID}/events"
        template, operation = subject.operation_for("GET", concrete)
        unrouted = problem(404, "not-found-or-unavailable", concrete)
        self.assertEqual(subject.response_errors(operation, 404, unrouted, template, concrete), [])
        elsewhere = problem(404, "not-found-or-unavailable", "/v1/timelines/other/events")
        self.assertTrue(subject.response_errors(operation, 404, elsewhere, template, concrete))

    def test_an_unknown_path_names_no_operation(self) -> None:
        with self.assertRaises(checker.ContractError):
            contract().operation_for("GET", "/v1/unknown")

    def test_a_missing_idempotency_key_makes_an_action_request_invalid(self) -> None:
        subject = contract()
        operation = self.operation(subject, "POST", f"/v1/timelines/{checker.SAMPLE_ULID}/actions")
        self.assertTrue(checker.parameter_errors(operation, subject, "header", {}))
        self.assertEqual(
            checker.parameter_errors(operation, subject, "header", {"Idempotency-Key": "k-1"}), []
        )

    def test_an_unknown_query_is_invalid(self) -> None:
        subject = contract()
        operation = self.operation(subject, "GET", f"/v1/timelines/{checker.SAMPLE_ULID}/events")
        self.assertTrue(checker.parameter_errors(operation, subject, "query", {"page": 1}))

    def test_the_checked_in_contract_has_draft_families_and_limits(self) -> None:
        subject = contract()
        drafts = [
            op for op in subject.operations().values() if op["x-pigloros-status"] == "draft"
        ]
        self.assertGreater(len(drafts), 0)
        self.assertGreater(len(checker.check_limits(subject)), 0)

    def test_a_served_exchange_cannot_reach_a_draft_operation(self) -> None:
        with self.assertRaisesRegex(checker.ContractError, "Draft operation getSession"):
            contract().operation_for("GET", "/v1/session")
        exchange = {
            "router": "loopback",
            "method": "GET",
            "path": "/v1/session",
            "expect": {"status": 401, "body": {"json": problem(401, "unauthenticated")}},
        }
        payload = {"subcases": [{"id": "draft.1", "exchanges": [exchange]}]}
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "draft.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(checker.ContractError, "Draft operation"):
                checker.check_fixtures(contract(), Path(directory))

    def test_a_draft_operation_without_an_example_is_rejected(self) -> None:
        examples = [
            (name, item)
            for name, item in checker.load_examples()
            if item["operation_id"] != "getErasure"
        ]
        with self.assertRaisesRegex(checker.ContractError, "getErasure has no golden example"):
            checker.check_examples(contract(), examples)

    def test_a_draft_family_without_a_fail_closed_example_is_rejected(self) -> None:
        examples = [
            (name, item)
            for name, item in checker.load_examples()
            if item["operation_id"] != "getSession" or item["response"]["status"] < 400
        ]
        with self.assertRaisesRegex(checker.ContractError, "family session"):
            checker.check_examples(contract(), examples)

    def test_a_draft_mutation_without_an_idempotency_key_is_rejected(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["paths"][PREVIEWS]["post"]["parameters"] = []
        with self.assertRaisesRegex(checker.ContractError, "requires Idempotency-Key"):
            checker.check_description(contract(document=document))

    def test_an_admission_that_does_not_answer_the_receipt_is_rejected(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        answer = document["paths"][PREVIEWS]["post"]["responses"]["202"]["content"]
        answer["application/json"]["schema"] = {"$ref": "#/components/schemas/DecisionPreview"}
        with self.assertRaisesRegex(checker.ContractError, "admission receipt"):
            checker.check_description(contract(document=document))

    def test_a_draft_operation_must_be_structurally_draft(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        del document["paths"]["/v1/session"]["get"]["x-pigloros-owner"]
        with self.assertRaisesRegex(checker.ContractError, "owner ticket"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        document["paths"]["/v1/session"]["get"]["description"] = "Read the session."
        with self.assertRaisesRegex(checker.ContractError, "does not start with Draft"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        document["paths"]["/v1/session"]["get"]["tags"] = []
        with self.assertRaisesRegex(checker.ContractError, "one family tag"):
            checker.check_description(contract(document=document))

    def test_a_served_operation_has_no_draft_owner(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["paths"]["/health"]["get"]["x-pigloros-owner"] = "#302"
        with self.assertRaisesRegex(checker.ContractError, "no Draft owner"):
            checker.check_description(contract(document=document))

    def test_a_draft_read_answers_an_enveloped_resource(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        answer = document["paths"]["/v1/session"]["get"]["responses"]["200"]["content"]
        answer["application/json"]["schema"] = {
            "$ref": "#/components/schemas/CommittedEventReceipt"
        }
        with self.assertRaisesRegex(checker.ContractError, "enveloped resource"):
            checker.check_description(contract(document=document))

    def test_a_served_operation_reaching_a_draft_schema_is_rejected(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        answer = document["paths"]["/health"]["get"]["responses"]["200"]["content"]
        answer["application/json"]["schema"] = {"$ref": "#/components/schemas/Session"}
        with self.assertRaisesRegex(checker.ContractError, "served operations reach the Draft"):
            checker.check_description(contract(document=document))

    def test_a_draft_operation_reaching_an_unmarked_schema_is_rejected(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        del document["components"]["schemas"]["Session"]["x-pigloros-maturity"]
        with self.assertRaisesRegex(checker.ContractError, "neither Draft nor served"):
            checker.check_description(contract(document=document))

    def test_a_limit_must_equal_its_schema_bound(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        plugins = document["components"]["schemas"]["ScenarioRoomInput"]["properties"]["plugins"]
        plugins["maxItems"] = 33
        with self.assertRaisesRegex(checker.ContractError, "does not equal 32"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        document["x-pigloros-limits"]["room_plugins"]["value"] = 0
        with self.assertRaisesRegex(checker.ContractError, "positive integer"):
            checker.check_description(contract(document=document))

    def test_a_limit_must_name_its_enforcement(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        limits = document["x-pigloros-limits"]
        limits["request_body_bytes"]["enforced_by"]["runtime"]["status"] = 418
        with self.assertRaisesRegex(checker.ContractError, "not registered"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        rules = document["x-pigloros-limits"]["room_rules"]["enforced_by"]["schema"]
        rules.append("/components/schemas/Missing/maxItems")
        with self.assertRaisesRegex(checker.ContractError, "does not resolve"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        document["x-pigloros-limits"]["room_rules"]["enforced_by"] = {}
        with self.assertRaisesRegex(checker.ContractError, "neither schema nor runtime"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        del document["x-pigloros-limits"]
        with self.assertRaisesRegex(checker.ContractError, "no x-pigloros-limits"):
            checker.check_description(contract(document=document))

    def test_every_draft_array_bound_is_a_stated_limit(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["x-pigloros-limits"]["room_rules"]["enforced_by"]["schema"].pop()
        with self.assertRaisesRegex(checker.ContractError, "is not a stated limit"):
            checker.check_description(contract(document=document))

    def test_every_draft_array_string_and_map_is_bounded(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        schemas = document["components"]["schemas"]
        del schemas["Erasure"]["properties"]["retained_classes"]["maxItems"]
        with self.assertRaisesRegex(checker.ContractError, "unbounded array"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        schemas = document["components"]["schemas"]
        del schemas["ResourceEnvelope"]["properties"]["schema_id"]["maxLength"]
        with self.assertRaisesRegex(checker.ContractError, "unbounded string"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        schemas = document["components"]["schemas"]
        del schemas["AdmissionReceipt"]["properties"]["bound_inputs"]["maxProperties"]
        del document["x-pigloros-limits"]["admission_bound_inputs"]
        with self.assertRaisesRegex(checker.ContractError, "unbounded map"):
            checker.check_description(contract(document=document))

    def test_local_mode_never_claims_an_air_gapped_profile(self) -> None:
        subject = contract()
        schema = {"$ref": "urn:pigloros:gateway:v1:schema:execution-profile"}
        air = {
            "mode": "air-gapped",
            "profile_id": "deterministic-air-gapped-v1",
            "profile_digest": "0" * 64,
            "network": "absent",
        }
        self.assertEqual(subject.schema_errors(air, schema), [])
        self.assertTrue(subject.schema_errors({**air, "network": "denied"}, schema))
        self.assertTrue(subject.schema_errors({**air, "mode": "local"}, schema))

    def test_a_resource_has_exactly_one_ordinal_and_no_unknown_member(self) -> None:
        subject = contract()
        session = example("draft-session-local")["response"]["body"]
        schema = {"$ref": "#/components/schemas/Session"}
        self.assertEqual(subject.schema_errors(session, schema), [])
        self.assertTrue(subject.schema_errors({**session, "revision": 1}, schema))
        self.assertTrue(subject.schema_errors({**session, "extra": 1}, schema))
        withheld = {"state": "available", "withheld": [{"member": "/x", "reason": "deleted"}]}
        self.assertTrue(subject.schema_errors({**session, "availability": withheld}, schema))

    def test_an_admission_receipt_never_claims_a_commit(self) -> None:
        subject = contract()
        receipt = example("draft-decision-preview-admitted")["response"]["body"]
        schema = {"$ref": "#/components/schemas/AdmissionReceipt"}
        self.assertEqual(subject.schema_errors(receipt, schema), [])
        self.assertTrue(subject.schema_errors({**receipt, "state": "committed"}, schema))
        self.assertTrue(subject.schema_errors({**receipt, "seq": 1}, schema))

    def test_an_incomplete_fork_exposes_no_suffix(self) -> None:
        subject = contract()
        ensemble = example("draft-ensemble-incomplete")["response"]["body"]
        schema = {"$ref": "#/components/schemas/Ensemble"}
        self.assertEqual(subject.schema_errors(ensemble, schema), [])
        partial = copy.deepcopy(ensemble)
        partial["forks"][1]["suffix_digest"] = "0" * 64
        self.assertTrue(subject.schema_errors(partial, schema))

    def test_a_preview_names_a_commit_exactly_after_committing(self) -> None:
        subject = contract()
        schema = {"$ref": "#/components/schemas/DecisionPreview"}
        committed = example("draft-decision-preview-committed")["response"]["body"]
        admitted = example("draft-decision-preview-admitted-not-committed")["response"]["body"]
        self.assertEqual(subject.schema_errors(committed, schema), [])
        self.assertEqual(subject.schema_errors(admitted, schema), [])
        for state in ("admitted", "failed"):
            self.assertTrue(subject.schema_errors({**committed, "state": state}, schema))
        for state in ("committed", "projected", "complete", "exported", "degraded"):
            self.assertTrue(subject.schema_errors({**admitted, "state": state}, schema))

    def test_a_degraded_resource_never_claims_exact(self) -> None:
        subject = contract()
        for name, schema_name in (
            ("draft-ensemble-complete", "Ensemble"),
            ("draft-replay-degraded", "Replay"),
            ("draft-export-exported", "Export"),
        ):
            body = example(name)["response"]["body"]
            schema = {"$ref": f"#/components/schemas/{schema_name}"}
            degraded = {**body, "state": "degraded"}
            redacted = {**degraded, "replay_claim": "exact-authoritative-with-redacted-views"}
            self.assertEqual(subject.schema_errors(redacted, schema), [])
            self.assertTrue(subject.schema_errors({**degraded, "replay_claim": "exact"}, schema))

    def test_a_replay_without_full_evidence_is_never_verified_exact(self) -> None:
        subject = contract()
        schema = {"$ref": "#/components/schemas/Replay"}
        replay = example("draft-replay-degraded")["response"]["body"]
        self.assertEqual(subject.schema_errors(replay, schema), [])
        for claim in ("structural-only", "unverifiable-artifacts-missing", "incompatible-profile"):
            self.assertTrue(subject.schema_errors({**replay, "replay_claim": claim}, schema))
            weaker = {**replay, "replay_claim": claim, "verification_outcome": "diverged"}
            self.assertEqual(subject.schema_errors(weaker, schema), [])

    def test_a_complete_ensemble_has_only_complete_forks(self) -> None:
        subject = contract()
        schema = {"$ref": "#/components/schemas/Ensemble"}
        incomplete = example("draft-ensemble-incomplete")["response"]["body"]
        self.assertTrue(subject.schema_errors({**incomplete, "state": "complete"}, schema))
        unnamed = copy.deepcopy(incomplete)
        unnamed["forks"][1]["failure_code"] = None
        self.assertTrue(subject.schema_errors(unnamed, schema))
        forking = copy.deepcopy(incomplete)
        forking["forks"][1]["state"] = "forking"
        self.assertTrue(subject.schema_errors(forking, schema))
        forking["forks"][1]["failure_code"] = None
        self.assertEqual(subject.schema_errors({**forking, "state": "forking"}, schema), [])

    def test_fork_ordinals_are_contiguous_in_examples(self) -> None:
        examples = checker.load_examples()
        for _, item in examples:
            if item["operation_id"] == "getEnsemble":
                item["response"]["body"]["forks"][1]["ordinal"] = 0
        with self.assertRaisesRegex(checker.ContractError, "ordinals"):
            checker.check_examples(contract(), examples)

    def test_an_exported_export_names_its_repro_manifest(self) -> None:
        subject = contract()
        schema = {"$ref": "#/components/schemas/Export"}
        exported = example("draft-export-exported")["response"]["body"]
        self.assertEqual(subject.schema_errors(exported, schema), [])
        self.assertTrue(subject.schema_errors({**exported, "repro_manifest": None}, schema))
        admitted = {**exported, "state": "admitted", "repro_manifest": None}
        self.assertEqual(subject.schema_errors(admitted, schema), [])

    def test_an_identifier_is_ascii_so_its_length_is_its_byte_length(self) -> None:
        subject = contract()
        schema = {"$ref": "urn:pigloros:gateway:v1:schema:domain-key"}
        self.assertEqual(subject.schema_errors("cafe", schema), [])
        self.assertTrue(subject.schema_errors("café", schema))
        enforced = DOCUMENT["x-pigloros-limits"]["label_bytes"]["enforced_by"]
        self.assertEqual(enforced, {"runtime": {"code": "invalid-request", "status": 400}})

    def test_draft_values_are_bounded_integers(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        envelope = document["components"]["schemas"]["ResourceEnvelope"]["properties"]
        del envelope["generation"]["maximum"]
        with self.assertRaisesRegex(checker.ContractError, "unbounded integer"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        document["components"]["parameters"]["Revision"]["schema"].pop("maximum")
        with self.assertRaisesRegex(checker.ContractError, "unbounded integer"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        request = document["components"]["schemas"]["CreatePreferenceRequest"]["properties"]
        request["weights"]["items"]["properties"]["weight_micro"]["type"] = "number"
        with self.assertRaisesRegex(checker.ContractError, "JSON number"):
            checker.check_description(contract(document=document))
        subject = contract()
        body = example("draft-preference-create")["request"]["body"]
        schema = {"$ref": "#/components/schemas/CreatePreferenceRequest"}
        self.assertEqual(subject.schema_errors(body, schema), [])
        fractional = {"weights": [{"dimension": "nature", "weight_micro": 0.5}]}
        self.assertTrue(subject.schema_errors(fractional, schema))
        operation = DOCUMENT["paths"][
            "/v1/preferences/{preference_id}/revisions/{revision}"
        ]["get"]
        path = {"preference_id": checker.SAMPLE_ULID, "revision": 2**53}
        self.assertTrue(checker.parameter_errors(operation, subject, "path", path))
        self.assertEqual(
            checker.parameter_errors(operation, subject, "path", {**path, "revision": 1}), []
        )

    def test_a_draft_creation_answers_a_closed_or_enveloped_body(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        answer = document["paths"]["/v1/preferences"]["post"]["responses"]["201"]["content"]
        answer["application/json"]["schema"] = {"$ref": "#/components/schemas/ActionRequest"}
        with self.assertRaisesRegex(checker.ContractError, "closed or enveloped"):
            checker.check_description(contract(document=document))

    def test_path_parameters_of_an_example_are_validated(self) -> None:
        subject = contract()
        operation = self.operation(subject, "GET", "/v1/timelines/x/events")
        path = {"timeline_id": checker.SAMPLE_ULID}
        self.assertEqual(checker.parameter_errors(operation, subject, "path", path), [])
        self.assertTrue(checker.parameter_errors(operation, subject, "path", {}))
        self.assertTrue(
            checker.parameter_errors(operation, subject, "path", {**path, "revision": 1})
        )

    def test_an_unrouted_request_answers_by_its_api_major(self) -> None:
        # The same table drives the Gateway fallback test in apps/piglor-gateway/src/problem.rs.
        cases = checker.load(UNROUTED_PATHS)["cases"]
        self.assertEqual(
            {case["code"] for case in cases}, {"unsupported-version", "not-found-or-unavailable"}
        )
        for case in cases:
            self.assertEqual(
                checker.unrouted_problem(case["path"]), (case["code"], case["status"]), case
            )

    def test_an_unrouted_example_must_answer_its_negotiation_problem(self) -> None:
        subject = contract()
        operations = checker.operations_by_id(subject)
        major = example("unsupported-version-api-major")
        checker.check_example(subject, operations, "major", major)
        as_not_found = copy.deepcopy(major)
        as_not_found["response"]["status"] = 404
        as_not_found["response"]["body"].update(
            status=404,
            code="not-found-or-unavailable",
            type=checker.PROBLEM_TYPE_PREFIX + "not-found-or-unavailable",
            title="Not found or unavailable",
        )
        with self.assertRaisesRegex(checker.ContractError, "answers 400 unsupported-version"):
            checker.check_example(subject, operations, "major", as_not_found)
        templated = copy.deepcopy(major)
        templated["response"]["body"]["instance"] = "/v1/timelines"
        with self.assertRaisesRegex(checker.ContractError, "is not the route"):
            checker.check_example(subject, operations, "major", templated)
        routed = copy.deepcopy(major)
        routed["request"]["target"] = "/v1/session"
        with self.assertRaisesRegex(checker.ContractError, "is routed"):
            checker.check_example(subject, operations, "routed", routed)
        valid = {**major, "request_valid": True}
        with self.assertRaisesRegex(checker.ContractError, "never valid"):
            checker.check_example(subject, operations, "valid", valid)
        unnamed = copy.deepcopy(major)
        del unnamed["request"]["method"]
        with self.assertRaisesRegex(checker.ContractError, "names its method and query-free"):
            checker.check_example(subject, operations, "unnamed", unnamed)

    def test_a_served_exchange_under_another_major_is_an_unsupported_version(self) -> None:
        subject = contract()
        operation = self.operation(subject, "POST", "/v1/timelines")
        body = problem(400, "unsupported-version", "/v2/timelines")
        self.assertEqual(subject.problem_errors(400, body, TIMELINES, "/v2/timelines"), [])
        self.assertTrue(
            subject.response_errors(operation, 400, body, TIMELINES, "/v1/timelines/x")
        )

    def test_the_checked_in_contract_is_compatible_with_its_frozen_baseline(self) -> None:
        self.assertGreater(checker.check_compatibility(contract()), 0)
        baseline = checker.load(checker.BASELINE)
        self.assertEqual(baseline["window"]["supported_through"], "Wave 10")
        frozen = {name for name, _ in checker.load_examples(checker.FROZEN_EXAMPLES)}
        self.assertIn("unsupported-version-api-major.json", frozen)
        self.assertIn("compatible-unknown-optional-member-ignored.json", frozen)

    def assert_breaking(self, document: dict, message: str) -> None:
        with self.assertRaisesRegex(checker.ContractError, message):
            checker.check_compatibility(contract(document=document))

    def assert_compatible(self, document: dict) -> None:
        self.assertGreater(checker.check_compatibility(contract(document=document)), 0)

    def test_an_added_optional_member_stays_in_v1(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        schemas = document["components"]["schemas"]
        schemas["EventView"]["properties"]["fork_generation"] = {"type": "integer", "minimum": 0}
        schemas["CreateTimelineRequest"]["properties"]["label"] = {"type": "string"}
        self.assert_compatible(document)

    def test_an_added_required_member_is_breaking(self) -> None:
        for name in ("EventView", "CreateTimelineRequest"):
            document = copy.deepcopy(DOCUMENT)
            schema = document["components"]["schemas"][name]
            schema["properties"]["label"] = {"type": "string"}
            schema["required"].append("label")
            self.assert_breaking(document, "added member label is required")

    def test_a_removed_member_is_breaking(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        created = document["components"]["schemas"]["TimelineCreated"]
        del created["properties"]["head"]
        created["required"].remove("head")
        self.assert_breaking(document, "frozen member head was removed")
        document = copy.deepcopy(DOCUMENT)
        del document["components"]["schemas"]["SignalRequest"]["properties"]["subject"]
        self.assert_breaking(document, "frozen member subject was removed")

    def test_requiredness_changes_by_direction(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["SignalRequest"]["required"].append("subject")
        self.assert_breaking(document, "request member subject became required")
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["TimelineCreated"]["required"].remove("head")
        self.assert_breaking(document, "response member head is no longer guaranteed")
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["SignalRequest"]["required"].remove("value")
        self.assert_compatible(document)

    def test_values_may_widen_only_in_requests(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        dimension = document["components"]["schemas"]["SignalRequest"]["properties"]["dimension"]
        dimension["enum"].remove("economy")
        self.assert_breaking(document, "request enumeration was narrowed")
        document = copy.deepcopy(DOCUMENT)
        dimension = document["components"]["schemas"]["SignalRequest"]["properties"]["dimension"]
        dimension["enum"].append("mobility")
        self.assert_compatible(document)
        # A frozen fail-closed fixture pins a rejection: world.action.v2 stays unsupported in v1.
        document = copy.deepcopy(DOCUMENT)
        event_type = document["components"]["schemas"]["ActionRequest"]["properties"]["event_type"]
        del event_type["const"]
        event_type["enum"] = ["world.action.v1", "world.action.v2"]
        self.assert_breaking(document, "unknown-required-schema-event-type.json: request validity")
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["HealthOk"]["properties"]["ok"] = {"type": "boolean"}
        self.assert_breaking(document, "response enumeration was widened")
        document = copy.deepcopy(DOCUMENT)
        seq = document["components"]["schemas"]["EventView"]["properties"]["seq"]
        seq["type"] = ["integer", "null"]
        self.assert_breaking(document, "response type was widened")
        document = copy.deepcopy(DOCUMENT)
        name = document["components"]["schemas"]["CreateTimelineRequest"]["properties"]["name"]
        name["type"] = "integer"
        self.assert_breaking(document, "request type was narrowed")

    def test_bounds_may_loosen_only_in_requests(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["IdempotencyKey"]["maxLength"] = 64
        self.assert_breaking(document, "request bound maxLength was tightened")
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["EventPage"]["properties"]["events"]["maxItems"] = 200
        self.assert_breaking(document, "response bound maxItems was loosened")
        document = copy.deepcopy(DOCUMENT)
        del document["components"]["schemas"]["TimelineCreated"]["properties"]["head"]["minimum"]
        self.assert_breaking(document, "response bound minimum was loosened")
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["CreateTimelineRequest"]["properties"]["name"][
            "maxLength"
        ] = 64
        self.assert_breaking(document, "request bound maxLength was tightened")
        document = copy.deepcopy(DOCUMENT)
        listing = document["paths"][EVENTS]["get"]["parameters"]
        listing[1]["schema"]["minimum"] = -1
        self.assert_compatible(document)
        # A frozen fail-closed fixture pins a rejection: a page limit over 100 stays invalid.
        document = copy.deepcopy(DOCUMENT)
        document["paths"][EVENTS]["get"]["parameters"][2]["schema"]["maximum"] = 200
        self.assert_breaking(document, "malformed-page-limit.json: request validity")

    def test_unknown_member_handling_and_identity_are_frozen(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["CreateTimelineRequest"]["additionalProperties"] = False
        self.assert_breaking(document, "handling of unknown members changed")
        document = copy.deepcopy(DOCUMENT)
        del document["components"]["schemas"]["EventView"]["additionalProperties"]
        self.assert_breaking(document, "handling of unknown members changed")
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["Ulid"]["pattern"] = "^[0-9A-Z]{26}$"
        self.assert_breaking(document, "pattern of a frozen schema changed")
        document = copy.deepcopy(DOCUMENT)
        page = document["components"]["schemas"]["EventPage"]["properties"]["events"]
        page["items"] = {"$ref": "urn:pigloros:gateway:v1:schema:ulid"}
        self.assert_breaking(document, "schema:event became urn:pigloros:gateway:v1:schema:ulid")
        document = copy.deepcopy(DOCUMENT)
        page = document["components"]["schemas"]["EventPage"]["properties"]["events"]
        page["items"] = copy.deepcopy(document["components"]["schemas"]["EventView"])
        self.assert_breaking(document, "inlined or added")
        document = copy.deepcopy(DOCUMENT)
        cursor = document["components"]["schemas"]["EventPage"]["properties"]["next_cursor"]
        cursor["oneOf"].append({"type": "integer"})
        self.assert_breaking(document, "oneOf of a frozen schema changed shape")

    def test_a_frozen_operation_keeps_its_interface(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        del document["paths"]["/v1/bridges/owntracks"]
        self.assert_breaking(document, "frozen operation was removed")
        document = copy.deepcopy(DOCUMENT)
        document["paths"][TIMELINES]["post"]["x-pigloros-status"] = "draft"
        self.assert_breaking(document, "no longer served")
        document = copy.deepcopy(DOCUMENT)
        document["paths"][TIMELINES]["post"]["operationId"] = "makeTimeline"
        self.assert_breaking(document, "operationId of a frozen operation changed")
        document = copy.deepcopy(DOCUMENT)
        document["paths"]["/health"]["get"]["x-pigloros-listeners"] = ["loopback"]
        self.assert_breaking(document, "frozen listener")
        document = copy.deepcopy(DOCUMENT)
        document["paths"][TIMELINES]["post"]["security"] = [{"ownTracksBasic": []}]
        self.assert_breaking(document, "security requirement")
        document = copy.deepcopy(DOCUMENT)
        del document["paths"][TIMELINES]["post"]["responses"]["429"]
        self.assert_breaking(document, "frozen response 429 was removed")
        document = copy.deepcopy(DOCUMENT)
        content = document["paths"][TIMELINES]["post"]["responses"]["201"]["content"]
        content["application/problem+json"] = content.pop("application/json")
        self.assert_breaking(document, "media type application/json was removed")

    def test_a_frozen_operation_keeps_its_parameters_and_body(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["paths"][EVENTS]["get"]["parameters"][2]["required"] = True
        self.assert_breaking(document, "optional parameter became required")
        document = copy.deepcopy(DOCUMENT)
        del document["paths"][EVENTS]["get"]["parameters"][3]
        self.assert_breaking(document, "frozen parameter was removed")
        document = copy.deepcopy(DOCUMENT)
        document["paths"][EVENTS]["get"]["parameters"].append(
            {"name": "fork", "in": "query", "required": True, "schema": {"type": "string"}}
        )
        self.assert_breaking(document, "query parameter fork: a new required one")
        document = copy.deepcopy(DOCUMENT)
        document["paths"][EVENTS]["get"]["parameters"].append(
            {"name": "fork", "in": "query", "required": False, "schema": {"type": "string"}}
        )
        self.assert_compatible(document)
        document = copy.deepcopy(DOCUMENT)
        del document["paths"][TIMELINES]["post"]["requestBody"]
        self.assert_breaking(document, "frozen request body was removed")
        document = copy.deepcopy(DOCUMENT)
        document["paths"]["/health"]["get"]["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": {"type": "object"}}},
        }
        self.assert_breaking(document, "new required request body")

    def test_the_frozen_problem_registry_and_window_are_kept(self) -> None:
        registry = copy.deepcopy(REGISTRY)
        registry["problem_types"][1]["title"] = "Version unsupported"
        with self.assertRaisesRegex(checker.ContractError, "removed or renamed"):
            checker.check_compatibility(contract(registry=registry))
        registry = copy.deepcopy(REGISTRY)
        registry["problem_types"][0]["statuses"].remove(405)
        with self.assertRaisesRegex(checker.ContractError, "frozen status"):
            checker.check_compatibility(contract(registry=registry))
        baseline = checker.load(checker.BASELINE)
        baseline["window"] = {**baseline["window"], "supported_through": "Wave 9"}
        with self.assertRaisesRegex(checker.ContractError, "does not declare the window"):
            checker.check_compatibility(contract(), baseline=baseline)

    def test_a_new_problem_code_stays_in_v1_and_freezes(self) -> None:
        document, registry = with_problem_code("quota-exhausted")
        current = contract(document=document, registry=registry)
        checker.check_registry(current)
        self.assertGreater(checker.check_compatibility(current), 0)
        baseline = checker.load(checker.BASELINE)
        frozen = checker.freeze(current, baseline)
        self.assertEqual(frozen["problem_types"][-1]["code"], "quota-exhausted")
        codes = frozen["components"]["schemas"]["Problem"]["properties"]["code"]["enum"]
        self.assertEqual(codes, PROBLEM_CODES + ["quota-exhausted"])
        checker.check_appended(baseline, frozen)
        self.assertGreater(checker.check_compatibility(current, baseline=frozen), 0)
        self.assertEqual(checker.freeze(current, frozen), frozen)
        self.assertEqual(checker.freeze(current, None), frozen)
        # Once frozen, the new code is as permanent as the others.
        with self.assertRaisesRegex(checker.ContractError, "quota-exhausted was removed"):
            checker.check_compatibility(contract(), baseline=frozen)

    def test_a_frozen_problem_code_is_never_removed_or_changed(self) -> None:
        for change in ("remove", "rename", "drop-enum"):
            document = copy.deepcopy(DOCUMENT)
            registry = copy.deepcopy(REGISTRY)
            code = document["components"]["schemas"]["Problem"]["properties"]["code"]
            if change == "drop-enum":
                code["type"] = "string"
                del code["enum"]
            else:
                code["enum"].remove("revoked")
            if change == "rename":
                code["enum"].append("withdrawn")
            # The registry keeps the frozen entry, so only the enumeration rule can reject it.
            with self.assertRaisesRegex(checker.ContractError, "frozen problem code was removed"):
                checker.check_compatibility(contract(document=document, registry=registry))
        document, registry = with_problem_code("revoked-v2")
        registry["problem_types"] = [
            entry for entry in registry["problem_types"] if entry["code"] != "revoked"
        ]
        document["components"]["schemas"]["Problem"]["properties"]["code"]["enum"].remove("revoked")
        with self.assertRaisesRegex(checker.ContractError, "revoked was removed or renamed"):
            checker.check_compatibility(contract(document=document, registry=registry))

    def test_a_new_problem_code_is_appended_never_inserted_or_reordered(self) -> None:
        def inserted(codes: list) -> None:
            codes.insert(3, codes.pop())

        def reordered(codes: list) -> None:
            codes[0], codes[1] = codes[1], codes[0]

        for move in (inserted, reordered):
            document, registry = with_problem_code("quota-exhausted")
            move(document["components"]["schemas"]["Problem"]["properties"]["code"]["enum"])
            # The registry keeps the frozen order, so only the enumeration rule can reject it.
            with self.assertRaisesRegex(checker.ContractError, "code was removed or moved"):
                checker.check_compatibility(contract(document=document, registry=registry))
            move(registry["problem_types"])
            current = contract(document=document, registry=registry)
            checker.check_registry(current)
            with self.assertRaisesRegex(checker.ContractError, "problem type was moved"):
                checker.check_compatibility(current)

    def test_only_the_problem_code_enumeration_may_widen_in_a_response(self) -> None:
        document, registry = with_problem_code("quota-exhausted")
        code = document["components"]["schemas"]["Problem"]["properties"]["code"]
        code["pattern"] = "^[a-z-]+$"
        with self.assertRaisesRegex(checker.ContractError, "pattern of a frozen schema changed"):
            checker.check_compatibility(contract(document=document, registry=registry))
        document = copy.deepcopy(DOCUMENT)
        schema_id = document["components"]["schemas"]["Problem"]["properties"]["schema_id"]
        schema_id["enum"] = [schema_id.pop("const"), "urn:pigloros:gateway:v1:schema:other"]
        self.assert_breaking(document, "schema_id: a response enumeration was widened")
        document = copy.deepcopy(DOCUMENT)
        document["components"]["schemas"]["HealthOk"]["properties"]["ok"] = {"type": "boolean"}
        self.assert_breaking(document, "response enumeration was widened")

    def test_old_supported_fixtures_stay_executable(self) -> None:
        frozen = checker.load_examples(checker.FROZEN_EXAMPLES)
        broken = copy.deepcopy(frozen)
        for _, item in broken:
            if item["operation_id"] == "createTimeline" and item["request_valid"]:
                item["response"]["body"]["head"] = -1
        with self.assertRaisesRegex(checker.ContractError, "response invalid"):
            checker.check_compatibility(contract(), frozen=broken)
        drafted = frozen + [("draft.json", example("draft-session-local"))]
        with self.assertRaisesRegex(checker.ContractError, "no served operation"):
            checker.check_compatibility(contract(), frozen=drafted)
        with self.assertRaisesRegex(checker.ContractError, "no frozen compatibility examples"):
            checker.check_compatibility(contract(), frozen=[])

    def test_a_promoted_operation_must_be_frozen_and_freezing_only_appends(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        session = document["paths"]["/v1/session"]["get"]
        session["x-pigloros-status"] = "served"
        self.assert_breaking(document, "GET /v1/session: a served operation is not frozen")
        promoted = contract(document=document)
        baseline = checker.load(checker.BASELINE)
        frozen = checker.freeze(promoted, baseline)
        self.assertEqual(frozen["paths"]["/v1/session"]["get"]["operationId"], "getSession")
        self.assertIn("Session", frozen["components"]["schemas"])
        self.assertIn("ResourceEnvelope", frozen["components"]["schemas"])
        for path in baseline["paths"]:
            self.assertEqual(frozen["paths"][path], baseline["paths"][path])
        checker.check_appended(baseline, frozen)
        self.assertGreater(checker.check_compatibility(promoted, baseline=frozen), 0)
        self.assertEqual(checker.freeze(contract(), None), baseline)
        self.assertEqual(checker.freeze(contract(), baseline), baseline)

    def test_freezing_merges_optional_additions_into_frozen_entries(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        schemas = document["components"]["schemas"]
        digest = {"$ref": "urn:pigloros:gateway:v1:schema:digest"}
        schemas["EventView"]["properties"]["fork"] = digest
        listing = document["paths"][EVENTS]["get"]
        listing["parameters"].append(
            {"name": "fork", "in": "query", "required": False, "schema": {"type": "string"}}
        )
        listing["responses"]["504"] = copy.deepcopy(
            document["paths"][TIMELINES]["post"]["responses"]["429"]
        )
        created = document["paths"][TIMELINES]["post"]["responses"]["201"]
        created["headers"] = {"Location": {"schema": {"type": "string"}}}
        current = contract(document=document)
        baseline = checker.load(checker.BASELINE)
        frozen = checker.freeze(current, baseline)
        event_view = frozen["components"]["schemas"]["EventView"]
        self.assertIn("fork", event_view["properties"])
        frozen_view = baseline["components"]["schemas"]["EventView"]
        self.assertEqual(event_view["required"], frozen_view["required"])
        self.assertIn("Digest", frozen["components"]["schemas"])
        frozen_listing = frozen["paths"][EVENTS]["get"]
        self.assertEqual(frozen_listing["parameters"][-1]["name"], "fork")
        self.assertIn("504", frozen_listing["responses"])
        self.assertIn("Location", frozen["paths"][TIMELINES]["post"]["responses"]["201"]["headers"])
        checker.check_appended(baseline, frozen)
        self.assertEqual(checker.freeze(current, frozen), frozen)
        self.assertGreater(checker.check_compatibility(current, baseline=frozen), 0)
        # A later removal of a merged member is now breaking.
        del document["components"]["schemas"]["EventView"]["properties"]["fork"]
        with self.assertRaisesRegex(checker.ContractError, "frozen member fork was removed"):
            checker.check_compatibility(contract(document=document), baseline=frozen)

    def test_freezing_never_records_a_breaking_change(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        schemas = document["components"]["schemas"]
        schemas["TimelineCreated"]["properties"]["label"] = {"type": "string"}
        schemas["TimelineCreated"]["required"].append("label")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "baseline.json"
            target.write_text(checker.BASELINE.read_text(encoding="utf-8"), encoding="utf-8")
            with self.assertRaisesRegex(checker.ContractError, "added member label is required"):
                checker.write_baseline(contract(document=document), target)
            self.assertEqual(checker.load(target), checker.load(checker.BASELINE))

    def test_the_baseline_may_only_gain_entries(self) -> None:
        baseline = checker.load(checker.BASELINE)
        checker.check_appended(baseline, copy.deepcopy(baseline))
        cases = []
        grown = copy.deepcopy(baseline)
        grown["components"]["schemas"]["EventView"]["properties"]["fork"] = {"type": "string"}
        grown["paths"][EVENTS]["get"]["parameters"].append({"name": "x", "in": "query"})
        grown["paths"][EVENTS]["put"] = {"operationId": "x"}
        grown["components"]["schemas"]["Extra"] = {"type": "string"}
        grown["problem_types"].append({"code": "x"})
        grown["x-pigloros-limits"]["extra"] = {"value": 1}
        problem_code(grown)["enum"].append("x")
        checker.check_appended(baseline, grown)
        widened = copy.deepcopy(baseline)
        widened["components"]["schemas"]["SignalRequest"]["properties"]["dimension"][
            "enum"
        ].append("mobility")
        cases.append((widened, "dimension/enum: a frozen list was changed"))
        shrunk = copy.deepcopy(baseline)
        problem_code(shrunk)["enum"].pop()
        cases.append((shrunk, "code/enum: a frozen list was changed"))
        shuffled = copy.deepcopy(baseline)
        problem_code(shuffled)["enum"].insert(0, "x")
        cases.append((shuffled, "code/enum/0: a frozen value changed"))
        loosened = copy.deepcopy(baseline)
        loosened["components"]["schemas"]["IdempotencyKey"]["maxLength"] = 64
        cases.append((loosened, "a frozen value changed"))
        removed = copy.deepcopy(baseline)
        del removed["components"]["schemas"]["TimelineCreated"]["properties"]["head"]
        cases.append((removed, "a frozen entry was removed"))
        required = copy.deepcopy(baseline)
        required["components"]["schemas"]["SignalRequest"]["required"].append("subject")
        cases.append((required, "a frozen list was changed"))
        added = copy.deepcopy(baseline)
        added["components"]["schemas"]["CreateTimelineRequest"]["properties"]["name"][
            "maxLength"
        ] = 8
        cases.append((added, "maxLength was added to a frozen entry"))
        window = copy.deepcopy(baseline)
        window["window"]["supported_through"] = "Wave 9"
        cases.append((window, "a frozen value changed"))
        limit = copy.deepcopy(baseline)
        limit["x-pigloros-limits"]["request_body_bytes"]["value"] = 1
        cases.append((limit, "a frozen value changed"))
        reordered = copy.deepcopy(baseline)
        reordered["problem_types"].reverse()
        cases.append((reordered, "a frozen value changed"))
        dropped = copy.deepcopy(baseline)
        dropped["paths"][EVENTS]["get"]["parameters"].pop()
        cases.append((dropped, "a frozen list was changed"))
        for changed, message in cases:
            with self.assertRaisesRegex(checker.ContractError, message):
                checker.check_appended(baseline, changed)

    def git(self, root: Path, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t", *arguments],
            check=True,
            capture_output=True,
        )

    def test_the_compatibility_directory_is_append_only_against_the_merge_base(self) -> None:
        relative = checker.COMPATIBILITY.relative_to(checker.ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.git(root, "init", "-q", "-b", "main")
            target = root / relative
            (target / "examples").mkdir(parents=True)
            baseline = checker.load(checker.BASELINE)
            (target / "baseline.json").write_text(json.dumps(baseline), encoding="utf-8")
            (target / "examples" / "a.json").write_text("{}\n", encoding="utf-8")
            self.git(root, "add", ".")
            self.git(root, "commit", "-q", "-m", "baseline")
            self.git(root, "checkout", "-q", "-b", "change")
            grown = copy.deepcopy(baseline)
            grown["components"]["schemas"]["EventView"]["properties"]["fork"] = {"type": "string"}
            (target / "baseline.json").write_text(json.dumps(grown), encoding="utf-8")
            (target / "examples" / "b.json").write_text("{}\n", encoding="utf-8")
            self.assertEqual(checker.check_append_only("main", root), 2)
            document, registry = with_problem_code("quota-exhausted")
            coded = checker.freeze(contract(document=document, registry=registry), grown)
            (target / "baseline.json").write_text(json.dumps(coded), encoding="utf-8")
            self.assertEqual(checker.check_append_only("main", root), 2)
            loosened = copy.deepcopy(baseline)
            loosened["components"]["schemas"]["IdempotencyKey"]["maxLength"] = 256
            (target / "baseline.json").write_text(json.dumps(loosened), encoding="utf-8")
            with self.assertRaisesRegex(checker.ContractError, "a frozen value changed"):
                checker.check_append_only("main", root)
            (target / "baseline.json").write_text(json.dumps(grown), encoding="utf-8")
            (target / "examples" / "a.json").write_text("[]\n", encoding="utf-8")
            with self.assertRaisesRegex(checker.ContractError, "a.json: a frozen file was changed"):
                checker.check_append_only("main", root)
            (target / "examples" / "a.json").unlink()
            with self.assertRaisesRegex(checker.ContractError, "a.json: a frozen file was removed"):
                checker.check_append_only("main", root)
            with self.assertRaisesRegex(checker.ContractError, "git merge-base"):
                checker.check_append_only("no-such-ref", root)

    def test_freezing_examples_copies_only_served_and_unrouted_ones(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "frozen"
            copied = checker.freeze_examples(contract(), checker.EXAMPLES, target)
            self.assertIn("unsupported-version-api-major.json", copied)
            self.assertIn("positive-create-timeline.json", copied)
            self.assertFalse(any(name.startswith("draft-") for name in copied))
            self.assertEqual(checker.freeze_examples(contract(), checker.EXAMPLES, target), [])
            baseline = Path(directory) / "baseline.json"
            checker.write_baseline(contract(), baseline)
            self.assertEqual(checker.load(baseline), checker.load(checker.BASELINE))

    def test_the_command_line_takes_freeze_or_append_only(self) -> None:
        self.assertEqual(checker.main(["--write"]), 2)
        self.assertEqual(checker.main(["--append-only"]), 2)
        self.assertEqual(checker.main([]), 0)
        self.assertEqual(checker.main(["--append-only", "no-such-ref"]), 1)

    def test_a_frozen_response_header_stays_guaranteed(self) -> None:
        owntracks = "/v1/bridges/owntracks"
        document = copy.deepcopy(DOCUMENT)
        del document["paths"][owntracks]["post"]["responses"]["429"]["headers"]["Retry-After"]
        self.assert_breaking(document, "header Retry-After: a frozen response header was removed")
        document = copy.deepcopy(DOCUMENT)
        headers = document["paths"][owntracks]["post"]["responses"]["429"]["headers"]
        headers["Retry-After"]["schema"]["minimum"] = 0
        self.assert_breaking(document, "response bound minimum was loosened")
        document = copy.deepcopy(DOCUMENT)
        headers = document["paths"][owntracks]["post"]["responses"]["429"]["headers"]
        headers["retry-after"] = headers.pop("Retry-After")
        self.assert_compatible(document)
        baseline = checker.load(checker.BASELINE)
        frozen = baseline["paths"][owntracks]["post"]["responses"]["429"]["headers"]
        frozen["Retry-After"]["required"] = True
        with self.assertRaisesRegex(checker.ContractError, "required response header"):
            checker.check_compatibility(contract(), baseline=baseline)
        frozen["Retry-After"] = {"content": {}}
        with self.assertRaisesRegex(checker.ContractError, "declares no schema"):
            checker.check_compatibility(contract(), baseline=baseline)

    def test_served_limits_move_only_in_their_direction(self) -> None:
        limits = DOCUMENT["x-pigloros-limits"]
        self.assertEqual(limits["request_body_bytes"]["direction"], "request")
        self.assertEqual(limits["response_body_bytes"]["direction"], "response")
        self.assertEqual(limits["page_items"]["direction"], "both")
        for name, value, message in (
            ("request_body_bytes", 2097152, None),
            ("request_body_bytes", 1024, "request limit moved against its direction"),
            ("response_body_bytes", 1024, None),
            ("response_body_bytes", 2097152, "response limit moved against its direction"),
            ("fork_depth", 32, "request limit moved against its direction"),
        ):
            document = copy.deepcopy(DOCUMENT)
            document["x-pigloros-limits"][name]["value"] = value
            if message is None:
                self.assert_compatible(document)
            else:
                self.assert_breaking(document, message)
        baseline = checker.load(checker.BASELINE)
        frozen = baseline["x-pigloros-limits"]
        self.assertNotIn("room_plugins", frozen)
        current = copy.deepcopy(DOCUMENT["x-pigloros-limits"])
        prefixes = checker.served_pointer_prefixes(contract())
        checker.check_frozen_limits(frozen, current, prefixes)
        for name, member, value, message in (
            ("page_items", "value", 50, "both limit moved against its direction"),
            ("fork_depth", "unit", "links", "frozen unit changed"),
            ("root_timelines", "surface", "draft", "was removed"),
            ("root_timelines", "enforced_by", {"runtime": {"code": "x", "status": 1}},
             "enforcement changed"),
            ("idempotency_key_length", "enforced_by", {"schema": []}, "keyword was dropped"),
        ):
            changed = copy.deepcopy(current)
            changed[name][member] = value
            with self.assertRaisesRegex(checker.ContractError, message):
                checker.check_frozen_limits(frozen, changed, prefixes)
        removed = copy.deepcopy(current)
        del removed["events_per_timeline"]
        with self.assertRaisesRegex(checker.ContractError, "events_per_timeline was removed"):
            checker.check_frozen_limits(frozen, removed, prefixes)
        # A Draft keyword of a shared limit is not frozen.
        draft = copy.deepcopy(current)
        draft["page_items"]["enforced_by"]["schema"] = [
            path for path in draft["page_items"]["enforced_by"]["schema"] if "Export" not in path
        ]
        checker.check_frozen_limits(frozen, draft, prefixes)

    def test_a_limit_declares_its_surface_and_direction(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["x-pigloros-limits"]["idempotency_key_length"]["surface"] = "draft"
        with self.assertRaisesRegex(checker.ContractError, "surface is not the surface"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        document["x-pigloros-limits"]["room_rules"]["surface"] = "served"
        with self.assertRaisesRegex(checker.ContractError, "surface is not the surface"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        document["x-pigloros-limits"]["room_rules"]["direction"] = "sideways"
        with self.assertRaisesRegex(checker.ContractError, "unknown surface or direction"):
            checker.check_description(contract(document=document))

    def test_a_frozen_security_scheme_is_kept(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["components"]["securitySchemes"]["ownTracksBasic"]["scheme"] = "bearer"
        self.assert_breaking(document, "security scheme ownTracksBasic")
        schemes = checker.load(checker.BASELINE)["components"]["securitySchemes"]
        self.assertIn("ownTracksBasic", schemes)

    def test_parameters_are_declared_per_operation_with_a_schema(self) -> None:
        document = copy.deepcopy(DOCUMENT)
        document["paths"][EVENTS]["parameters"] = []
        with self.assertRaisesRegex(checker.ContractError, "not the path"):
            checker.check_description(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        parameter = document["paths"][EVENTS]["get"]["parameters"][1]
        parameter["content"] = {"application/json": {"schema": parameter.pop("schema")}}
        with self.assertRaisesRegex(checker.ContractError, "declares a schema, not content"):
            checker.check_description(contract(document=document))
        with self.assertRaisesRegex(checker.ContractError, "declares no schema"):
            checker.check_compatibility(contract(document=document))
        document = copy.deepcopy(DOCUMENT)
        document["components"]["parameters"]["TimelineId"]["content"] = {}
        with self.assertRaisesRegex(checker.ContractError, "declares a schema, not content"):
            checker.check_description(contract(document=document))

    def test_the_normalization_is_undone_with_valid_samples(self) -> None:
        restored = checker.restore(
            {"id": "<ulid>", "next_cursor": "<cursor>", "detail": "<message>",
             "instance": "/v1/timelines/<ulid>/events"}
        )
        self.assertEqual(restored["id"], checker.SAMPLE_ULID)
        self.assertEqual(restored["next_cursor"], checker.SAMPLE_CURSOR)
        self.assertEqual(restored["instance"], f"/v1/timelines/{checker.SAMPLE_ULID}/events")


if __name__ == "__main__":
    unittest.main()
