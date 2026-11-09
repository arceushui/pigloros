#!/usr/bin/env python3
"""Rejection tests of `check_gateway_contract.py`: drift in each checked input fails (#1312)."""

from __future__ import annotations

import copy
import sys
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
