#!/usr/bin/env python3
"""Check the Gateway v1 contract against its examples and the served-response fixtures (#1312).

The canonical contract is `contracts/gateway/v1/openapi.json` (OpenAPI 3.1.1, JSON Schema
2020-12 dialect) with its RFC 9457 problem-type registry `problem-types.json`. This check fails
when the description, the registry, the golden examples or the gateway-client-conformance
fixtures disagree:

1. the description is OpenAPI 3.1.1 with the 2020-12 dialect, every component schema is a valid
   2020-12 schema with a unique `urn:pigloros:gateway:v1:schema:` identifier, every reference
   resolves, every operation has a unique `operationId`, a `x-pigloros-status` and only JSON or
   problem+json content, and every 4xx/5xx answer is a problem;
2. the registry codes, types and titles are unique, follow the URN rule and equal the `code`
   enumeration of the `Problem` schema in order;
3. every golden example under `contracts/gateway/v1/examples/` names a served operation, its
   request is valid exactly when the example says so, and its response is valid for its status;
4. every expected exchange of `fixtures/conformance/inputs/gateway-client-conformance/` is a
   JSON response valid for its operation and status. Those fixtures are executed against the
   served routers by `apps/pos-gateway-conformance-adapter`, so a served response that drifts
   from the description fails one of the two checks.

Every problem body must use a status its registry entry permits.

Requires the hash-pinned `jsonschema` of `requirements-pinned-dependencies.txt`.

Usage:
    python3 scripts/check_gateway_contract.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError:  # pragma: no cover - environment guard
    sys.exit(
        "jsonschema is required; install requirements-pinned-dependencies.txt with "
        "--require-hashes"
    )

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "contracts/gateway/v1"
OPENAPI = CONTRACT / "openapi.json"
PROBLEM_TYPES = CONTRACT / "problem-types.json"
EXAMPLES = CONTRACT / "examples"
FIXTURE_INPUTS = ROOT / "fixtures/conformance/inputs/gateway-client-conformance"

SCHEMA_ID_PREFIX = "urn:pigloros:gateway:v1:schema:"
PROBLEM_TYPE_PREFIX = "urn:pigloros:gateway:v1:problem:"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
MEDIA_TYPES = {"application/json", "application/problem+json"}
METHODS = ("get", "put", "post", "delete", "patch")
STATUSES = {"served", "draft"}

# Values the conformance normalization replaces, restored to valid samples before validation.
SAMPLE_ULID = "01JC0GATEWAYF1XTVRESAMP1E0"
SAMPLE_CURSOR = f"v1.{'0' * 64}.{SAMPLE_ULID}.1"
PLACEHOLDERS = {"<ulid>": SAMPLE_ULID, "<cursor>": SAMPLE_CURSOR, "<message>": "message"}


class ContractError(Exception):
    """One violation of the contract checks."""


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class Contract:
    """The parsed description, its schema registry and its served operations."""

    def __init__(self, document: dict, problem_types: dict) -> None:
        self.document = document
        self.problem_types = problem_types
        self.schemas: dict[str, dict] = document["components"]["schemas"]
        self.registry = Registry().with_resources(
            (schema["$id"], Resource(contents=schema, specification=DRAFT202012))
            for schema in self.schemas.values()
        )
        self.statuses = {
            entry["code"]: set(entry["statuses"]) for entry in problem_types["problem_types"]
        }
        self.titles = {entry["code"]: entry["title"] for entry in problem_types["problem_types"]}

    def resolve(self, value: dict) -> dict:
        """Follow one document-relative `#/components/...` reference."""
        if "$ref" not in value:
            return value
        target: object = self.document
        for part in value["$ref"].removeprefix("#/").split("/"):
            if not isinstance(target, dict) or part not in target:
                raise ContractError(f"unresolved reference {value['$ref']}")
            target = target[part]
        return self.resolve(target)  # type: ignore[arg-type]

    def schema_errors(self, value: object, schema: dict) -> list[str]:
        if "$ref" in schema and schema["$ref"].startswith("#/components/schemas/"):
            schema = self.resolve(schema)
        validator = Draft202012Validator(schema, registry=self.registry)
        return [
            f"{'/'.join(map(str, error.absolute_path)) or '$'}: {error.message}"
            for error in validator.iter_errors(value)
        ]

    def operations(self) -> dict[tuple[str, str], dict]:
        found: dict[tuple[str, str], dict] = {}
        for path, item in self.document["paths"].items():
            for method in METHODS:
                if method in item:
                    found[(method.upper(), path)] = item[method]
        return found

    def operation_for(self, method: str, path: str) -> tuple[str, dict]:
        """The served operation whose path template matches a concrete request path."""
        base = path.split("?", 1)[0]
        for (op_method, template), operation in self.operations().items():
            pattern = "^" + re.sub(r"\\\{[a-z_]+\\\}", "[^/]+", re.escape(template)) + "$"
            if op_method == method and re.fullmatch(pattern, base):
                return template, operation
        raise ContractError(f"{method} {base} names no operation of the contract")

    def response_errors(
        self, operation: dict, status: int, body: object, template: str, path: str = ""
    ) -> list[str]:
        """Check a response; a problem names the route template, or its request path if unrouted."""
        responses = operation["responses"]
        response = self.resolve(responses.get(str(status), responses.get("default", {})))
        content = response.get("content")
        if not content:
            return [f"status {status} has no response content"]
        media = "application/problem+json" if status >= 400 else "application/json"
        if media not in content:
            return [f"status {status} does not answer {media}"]
        errors = self.schema_errors(body, content[media]["schema"])
        if not errors and media == "application/problem+json":
            errors = self.problem_errors(status, body, template, path)  # type: ignore[arg-type]
        return errors

    def problem_errors(self, status: int, body: dict, template: str, path: str) -> list[str]:
        code = body["code"]
        errors = []
        unrouted = code == "not-found-or-unavailable" and body["instance"] == path
        if body["instance"] != template and not unrouted:
            errors.append(f"problem instance {body['instance']} is not the route {template}")
        if body["status"] != status:
            errors.append(f"problem status {body['status']} is not the HTTP status {status}")
        if status not in self.statuses[code]:
            errors.append(f"status {status} is not registered for {code}")
        if body["type"] != PROBLEM_TYPE_PREFIX + code or body["title"] != self.titles[code]:
            errors.append(f"type or title of {code} differs from the registry")
        return errors


def check_description(contract: Contract) -> None:
    document = contract.document
    if document.get("openapi") != "3.1.1" or document.get("jsonSchemaDialect") != DIALECT:
        raise ContractError("the description is not OpenAPI 3.1.1 with the 2020-12 dialect")
    seen_ids: set[str] = set()
    for name, schema in contract.schemas.items():
        Draft202012Validator.check_schema(schema)
        schema_id = schema.get("$id", "")
        if not schema_id.startswith(SCHEMA_ID_PREFIX) or schema_id in seen_ids:
            raise ContractError(f"schema {name} has no unique {SCHEMA_ID_PREFIX} identifier")
        seen_ids.add(schema_id)
    check_references(document, contract, seen_ids)
    operation_ids: set[str] = set()
    for (method, path), operation in contract.operations().items():
        where = f"{method} {path}"
        operation_id = operation.get("operationId")
        if not operation_id or operation_id in operation_ids:
            raise ContractError(f"{where}: missing or duplicate operationId")
        operation_ids.add(operation_id)
        if operation.get("x-pigloros-status") not in STATUSES:
            raise ContractError(f"{where}: x-pigloros-status is not one of {sorted(STATUSES)}")
        check_responses(contract, where, operation)


def check_references(value: object, contract: Contract, schema_ids: set[str]) -> None:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            if reference.startswith("#/"):
                contract.resolve({"$ref": reference})
            elif reference not in schema_ids:
                raise ContractError(f"unresolved reference {reference}")
        for item in value.values():
            check_references(item, contract, schema_ids)
    elif isinstance(value, list):
        for item in value:
            check_references(item, contract, schema_ids)


def check_responses(contract: Contract, where: str, operation: dict) -> None:
    if "default" not in operation["responses"]:
        raise ContractError(f"{where}: no default problem response")
    for status, response in operation["responses"].items():
        content = contract.resolve(response).get("content", {})
        if set(content) - MEDIA_TYPES:
            raise ContractError(f"{where} {status}: unsupported media type")
        failure = status == "default" or int(status) >= 400
        if failure and set(content) != {"application/problem+json"}:
            raise ContractError(f"{where} {status}: a failure must be a problem body")


def check_registry(contract: Contract) -> None:
    entries = contract.problem_types["problem_types"]
    codes = [entry["code"] for entry in entries]
    if len(set(codes)) != len(codes):
        raise ContractError("duplicate problem code")
    for entry in entries:
        if entry["type"] != PROBLEM_TYPE_PREFIX + entry["code"]:
            raise ContractError(f"{entry['code']}: type is not {PROBLEM_TYPE_PREFIX}<code>")
        if not entry["statuses"] or any(not 400 <= status <= 599 for status in entry["statuses"]):
            raise ContractError(f"{entry['code']}: statuses must be 4xx or 5xx")
    if contract.schemas["Problem"]["properties"]["code"]["enum"] != codes:
        raise ContractError("the Problem code enumeration is not the registry in order")


def parameter_errors(operation: dict, contract: Contract, location: str, values: dict) -> list[str]:
    """Violations of the declared `header` or `query` parameters; unknown queries are invalid."""
    errors = []
    fold = str.lower if location == "header" else str
    given = {fold(name): value for name, value in values.items()}
    declared = set()
    for parameter in operation.get("parameters", []):
        parameter = contract.resolve(parameter)
        if parameter["in"] != location:
            continue
        name = fold(parameter["name"])
        declared.add(name)
        if name not in given:
            if parameter.get("required"):
                errors.append(f"missing {location} {parameter['name']}")
            continue
        errors.extend(contract.schema_errors(given[name], parameter["schema"]))
    if location == "query":
        errors.extend(f"unknown query {name}" for name in sorted(set(given) - declared))
    return errors


def check_examples(contract: Contract) -> int:
    operations = {
        op["operationId"]: (template, op) for (_, template), op in contract.operations().items()
    }
    count = 0
    for path in sorted(EXAMPLES.glob("*.json")):
        example = load(path)
        if example["operation_id"] not in operations:
            raise ContractError(f"{path.name}: unknown operation {example['operation_id']}")
        template, operation = operations[example["operation_id"]]
        request = example["request"]
        errors = parameter_errors(operation, contract, "header", request.get("headers", {}))
        errors += parameter_errors(operation, contract, "query", request.get("query", {}))
        if "body" in request:
            body_schema = contract.resolve(operation["requestBody"])["content"]["application/json"]
            errors.extend(contract.schema_errors(request["body"], body_schema["schema"]))
        if (not errors) != example["request_valid"]:
            raise ContractError(f"{path.name}: request validity is not {example['request_valid']}")
        response = example["response"]
        errors = contract.response_errors(
            operation, response["status"], response["body"], template
        )
        if errors:
            raise ContractError(f"{path.name}: response invalid: {errors[:3]}")
        count += 1
    if count == 0:
        raise ContractError("no golden examples")
    return count


def restore(value: object, key: str | None = None) -> object:
    """Undo the conformance normalization with valid sample values."""
    if isinstance(value, dict):
        return {name: restore(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [restore(item) for item in value]
    if isinstance(value, str):
        if key == "instance":
            return value.replace("<ulid>", SAMPLE_ULID)
        return PLACEHOLDERS.get(value, value)
    return value


def check_fixtures(contract: Contract) -> int:
    count = 0
    for path in sorted(FIXTURE_INPUTS.glob("*.json")):
        payload = load(path)
        for subcase in payload["subcases"]:
            for index, exchange in enumerate(subcase["exchanges"], start=1):
                where = f"{path.name} {subcase['id']} exchange {index}"
                expect = exchange["expect"]
                if "refused" in expect:
                    continue
                if not isinstance(expect["body"], dict):
                    raise ContractError(f"{where}: every contract response is JSON")
                concrete = exchange["path"].replace("{timeline}", SAMPLE_ULID)
                template, operation = contract.operation_for(exchange["method"], concrete)
                body = restore(expect["body"]["json"])
                errors = contract.response_errors(
                    operation, expect["status"], body, template, concrete.split("?", 1)[0]
                )
                if errors:
                    raise ContractError(f"{where}: {errors[:3]}")
                count += 1
    if count == 0:
        raise ContractError("no gateway-client-conformance exchanges")
    return count


def main() -> int:
    try:
        contract = Contract(load(OPENAPI), load(PROBLEM_TYPES))  # type: ignore[arg-type]
        check_description(contract)
        check_registry(contract)
        examples = check_examples(contract)
        exchanges = check_fixtures(contract)
    except ContractError as error:
        print(f"gateway contract check failed: {error}", file=sys.stderr)
        return 1
    print(f"Gateway v1 contract OK: {examples} examples, {exchanges} served exchanges.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
