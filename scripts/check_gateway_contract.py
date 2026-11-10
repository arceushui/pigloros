#!/usr/bin/env python3
"""Check the Gateway v1 contract, its examples and the served-response fixtures (#1312, #1313).

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
3. every golden example under `contracts/gateway/v1/examples/` names an operation, its request
   (headers, query and path) is valid exactly when the example says so, and its response is
   valid for its status;
4. every expected exchange of `fixtures/conformance/inputs/gateway-client-conformance/` is a
   JSON response valid for its served operation and status. Those fixtures are executed against
   the served routers by `apps/pos-gateway-conformance-adapter`, so a served response that
   drifts from the description fails one of the two checks. An exchange that reaches a Draft
   operation fails: a Draft operation is never mistaken for a served one;
5. a Draft operation (`x-pigloros-status: draft`) names its owning ticket in
   `x-pigloros-owner` and in its description, has exactly one family tag and at least one
   golden example, and every Draft family has a positive and a fail-closed example. A Draft
   mutation requires `Idempotency-Key`, a Draft read answers a resource that composes the
   resource envelope, and every `202` answers the admission receipt;
6. every schema a Draft operation reaches is `x-pigloros-maturity: draft` or shared with a
   served operation, and no served operation reaches a Draft schema. Every array, string and
   map of a Draft schema is bounded;
7. every `x-pigloros-limits` entry has a value, unit, scope, origin and source, and is enforced
   either by the schema keywords it names (each equal to its value) or by a registered
   problem. Every array bound of a Draft schema is a stated limit unless it is the size of its
   own unique enumeration.

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
MUTATIONS = {"POST", "PUT", "PATCH", "DELETE"}
DRAFT_OWNER = re.compile(r"^#30[2-9]$")
ENVELOPE_ID = SCHEMA_ID_PREFIX + "resource-envelope"
ADMISSION_ID = SCHEMA_ID_PREFIX + "admission-receipt"
LIMIT_MEMBERS = {"value", "unit", "scope", "origin", "source", "enforced_by"}
LIMIT_SCOPES = {"structural", "per-input", "per-phase", "operation-wide", "per-principal"}
LIMIT_ORIGINS = {"code", "adr", "new"}
LIMIT_KEYWORDS = {"maxItems", "maxLength", "maximum", "maxProperties"}

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
        self.names = {schema["$id"]: name for name, schema in self.schemas.items()}
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
                if operation["x-pigloros-status"] != "served":
                    raise ContractError(
                        f"{method} {base} is the Draft operation {operation['operationId']}; "
                        "a served exchange cannot exercise it"
                    )
                return template, operation
        raise ContractError(f"{method} {base} names no operation of the contract")

    def schema_name(self, reference: str) -> str:
        return reference.rsplit("/", 1)[1] if reference.startswith("#/") else self.names[reference]

    def reachable(self, value: object) -> set[str]:
        """The component schemas a description fragment reaches through its references."""
        found: set[str] = set()
        stack = [value]
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(item)
                continue
            if not isinstance(item, dict):
                continue
            stack.extend(item.values())
            reference = item.get("$ref")
            if not isinstance(reference, str):
                continue
            if reference.startswith("#/") and not reference.startswith("#/components/schemas/"):
                stack.append(self.resolve({"$ref": reference}))
                continue
            name = self.schema_name(reference)
            if name not in found:
                found.add(name)
                stack.append(self.schemas[name])
        return found

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
        check_operation_status(contract, method, where, operation)
    check_maturity(contract)
    check_bounded(contract, check_limits(contract))


def check_operation_status(contract: Contract, method: str, where: str, operation: dict) -> None:
    """A Draft operation is structurally Draft; every admission answers the admission receipt."""
    for status, response in operation["responses"].items():
        if status == "202" and response_schema_id(contract, response) != ADMISSION_ID:
            raise ContractError(f"{where} 202: an admission answers the admission receipt")
    owner = operation.get("x-pigloros-owner")
    if operation["x-pigloros-status"] == "served":
        if owner is not None:
            raise ContractError(f"{where}: a served operation has no Draft owner")
        return
    if not isinstance(owner, str) or not DRAFT_OWNER.match(owner):
        raise ContractError(f"{where}: a Draft operation names its owner ticket #302-#309")
    if not operation.get("description", "").startswith(f"Draft ({owner}): "):
        raise ContractError(f"{where}: the description does not start with Draft ({owner})")
    tags = operation.get("tags")
    if not isinstance(tags, list) or len(tags) != 1:
        raise ContractError(f"{where}: a Draft operation has exactly one family tag")
    parameters = [contract.resolve(parameter) for parameter in operation.get("parameters", [])]
    if method in MUTATIONS and not any(
        parameter["in"] == "header"
        and parameter["name"].lower() == "idempotency-key"
        and parameter.get("required") is True
        for parameter in parameters
    ):
        raise ContractError(f"{where}: a Draft mutation requires Idempotency-Key")
    if method == "GET":
        schema_id = response_schema_id(contract, operation["responses"].get("200", {}))
        schema = contract.schemas[contract.names[schema_id]] if schema_id else {}
        if (
            {"$ref": ENVELOPE_ID} not in schema.get("allOf", [])
            or schema.get("unevaluatedProperties") is not False
            or schema["properties"].get("schema_id", {}).get("const") != schema_id
        ):
            raise ContractError(f"{where} 200: a Draft read answers a closed enveloped resource")


def response_schema_id(contract: Contract, response: dict) -> str | None:
    """The `$id` of the referenced JSON schema a response answers, if any."""
    content = contract.resolve(response).get("content", {}).get("application/json", {})
    reference = content.get("schema", {}).get("$ref")
    if not isinstance(reference, str):
        return None
    return contract.schemas[contract.schema_name(reference)]["$id"]


def check_maturity(contract: Contract) -> None:
    """Draft operations reach Draft or shared served schemas; served ones reach no Draft schema."""
    served: set[str] = set()
    drafts: list[tuple[str, set[str]]] = []
    for operation in contract.operations().values():
        reached = contract.reachable(operation)
        if operation["x-pigloros-status"] == "served":
            served |= reached
        else:
            drafts.append((operation["operationId"], reached))
    for name in sorted(served):
        if contract.schemas[name].get("x-pigloros-maturity") == "draft":
            raise ContractError(f"served operations reach the Draft schema {name}")
    for operation_id, reached in drafts:
        for name in sorted(reached - served):
            if contract.schemas[name].get("x-pigloros-maturity") != "draft":
                raise ContractError(f"{operation_id} reaches {name}, neither Draft nor served")


def pointer(document: object, path: str) -> object:
    """Resolve an RFC 6901 JSON Pointer."""
    target = document
    for part in path.removeprefix("/").split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(target, list) and part.isdigit() and int(part) < len(target):
            target = target[int(part)]
        elif isinstance(target, dict) and part in target:
            target = target[part]
        else:
            raise ContractError(f"limit pointer {path} does not resolve")
    return target


def check_limits(contract: Contract) -> set[str]:
    """Every stated limit is enforced; returns the schema keyword pointers that enforce one."""
    limits = contract.document.get("x-pigloros-limits")
    if not isinstance(limits, dict) or not limits:
        raise ContractError("the contract states no x-pigloros-limits")
    pointers: set[str] = set()
    for name, limit in limits.items():
        if not isinstance(limit, dict) or set(limit) != LIMIT_MEMBERS:
            raise ContractError(f"limit {name} does not have exactly {sorted(LIMIT_MEMBERS)}")
        value = limit["value"]
        if type(value) is not int or value < 1:
            raise ContractError(f"limit {name} has no positive integer value")
        if limit["scope"] not in LIMIT_SCOPES or limit["origin"] not in LIMIT_ORIGINS:
            raise ContractError(f"limit {name} has an unknown scope or origin")
        if not limit["unit"] or not limit["source"]:
            raise ContractError(f"limit {name} has no unit or source")
        enforced = limit["enforced_by"]
        if set(enforced) == {"schema"} and enforced["schema"]:
            for path in enforced["schema"]:
                if path.rsplit("/", 1)[-1] not in LIMIT_KEYWORDS or path in pointers:
                    raise ContractError(f"limit {name}: {path} is not a unique bound keyword")
                if pointer(contract.document, path) != value:
                    raise ContractError(f"limit {name}: {path} does not equal {value}")
                pointers.add(path)
        elif set(enforced) == {"runtime"}:
            problem = enforced["runtime"]
            if problem.get("status") not in contract.statuses.get(problem.get("code"), set()):
                raise ContractError(f"limit {name}: its runtime problem is not registered")
        else:
            raise ContractError(f"limit {name} is enforced by neither schema nor runtime")
    return pointers


def check_bounded(contract: Contract, limit_pointers: set[str]) -> None:
    """Every array, string and map of a Draft schema is bounded; array bounds are limits."""
    for name, schema in contract.schemas.items():
        if schema.get("x-pigloros-maturity") == "draft":
            check_bounded_node(schema, f"/components/schemas/{name}", limit_pointers)


def check_bounded_node(node: object, path: str, limit_pointers: set[str]) -> None:
    if isinstance(node, list):
        for index, item in enumerate(node):
            check_bounded_node(item, f"{path}/{index}", limit_pointers)
        return
    if not isinstance(node, dict):
        return
    kinds = node.get("type")
    kinds = set(kinds) if isinstance(kinds, list) else {kinds}
    if "array" in kinds or "items" in node or "prefixItems" in node:
        if "maxItems" not in node:
            raise ContractError(f"{path}: an unbounded array")
        items = node.get("items")
        enumerated = (
            node.get("uniqueItems") is True
            and isinstance(items, dict)
            and node["maxItems"] == len(items.get("enum", []))
        )
        if f"{path}/maxItems" not in limit_pointers and not enumerated:
            raise ContractError(f"{path}/maxItems is not a stated limit")
    if "string" in kinds and not {"const", "enum", "maxLength"} & set(node):
        raise ContractError(f"{path}: an unbounded string")
    if isinstance(node.get("additionalProperties"), dict) and "maxProperties" not in node:
        raise ContractError(f"{path}: an unbounded map")
    for key, value in node.items():
        if key not in ("enum", "const"):
            check_bounded_node(value, f"{path}/{key.replace('~', '~0').replace('/', '~1')}",
                               limit_pointers)


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
    """Violations of the declared `header`, `query` or `path` parameters.

    Unknown query and path parameters are invalid; undeclared headers are ignored.
    """
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
    if location != "header":
        errors.extend(f"unknown {location} {name}" for name in sorted(set(given) - declared))
    return errors


def load_examples(directory: Path = EXAMPLES) -> list[tuple[str, dict]]:
    paths = sorted(directory.glob("*.json"))
    return [(path.name, load(path)) for path in paths]  # type: ignore[misc]


def check_examples(contract: Contract, examples: list[tuple[str, dict]] | None = None) -> int:
    """Validate the golden examples; the only check a Draft operation has."""
    examples = load_examples() if examples is None else examples
    operations = {
        op["operationId"]: (template, op) for (_, template), op in contract.operations().items()
    }
    statuses: dict[str, list[int]] = {}
    for name, example in examples:
        if example["operation_id"] not in operations:
            raise ContractError(f"{name}: unknown operation {example['operation_id']}")
        template, operation = operations[example["operation_id"]]
        request = example["request"]
        errors = parameter_errors(operation, contract, "header", request.get("headers", {}))
        errors += parameter_errors(operation, contract, "query", request.get("query", {}))
        if "path" in request:
            errors += parameter_errors(operation, contract, "path", request["path"])
        if "body" in request:
            body_schema = contract.resolve(operation["requestBody"])["content"]["application/json"]
            errors.extend(contract.schema_errors(request["body"], body_schema["schema"]))
        if (not errors) != example["request_valid"]:
            raise ContractError(f"{name}: request validity is not {example['request_valid']}")
        response = example["response"]
        errors = contract.response_errors(
            operation, response["status"], response["body"], template
        )
        if errors:
            raise ContractError(f"{name}: response invalid: {errors[:3]}")
        statuses.setdefault(example["operation_id"], []).append(response["status"])
    if not examples:
        raise ContractError("no golden examples")
    check_draft_examples(operations, statuses)
    return len(examples)


def check_draft_examples(operations: dict, statuses: dict[str, list[int]]) -> None:
    """Every Draft operation has an example; every Draft family a positive and a fail-closed one."""
    families: dict[str, list[int]] = {}
    for operation_id, (_, operation) in operations.items():
        if operation["x-pigloros-status"] != "draft":
            continue
        if operation_id not in statuses:
            raise ContractError(f"the Draft operation {operation_id} has no golden example")
        families.setdefault(operation["tags"][0], []).extend(statuses[operation_id])
    for family, seen in sorted(families.items()):
        if not any(status < 300 for status in seen) or not any(status >= 400 for status in seen):
            raise ContractError(
                f"the Draft family {family} lacks a positive or a fail-closed example"
            )


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


def check_fixtures(contract: Contract, inputs: Path = FIXTURE_INPUTS) -> int:
    count = 0
    for path in sorted(inputs.glob("*.json")):
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
    drafts = sum(op["x-pigloros-status"] == "draft" for op in contract.operations().values())
    limits = len(contract.document["x-pigloros-limits"])
    print(
        f"Gateway v1 contract OK: {examples} examples, {exchanges} served exchanges, "
        f"{drafts} Draft operations, {limits} limits."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
