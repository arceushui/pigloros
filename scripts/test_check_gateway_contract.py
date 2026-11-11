#!/usr/bin/env python3
"""Rejection tests of `check_gateway_contract.py`: drift in each input fails (#1312, #1313)."""

from __future__ import annotations

import copy
import json
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
            if item["request"].get("path", {}).get("ensemble_id"):
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
