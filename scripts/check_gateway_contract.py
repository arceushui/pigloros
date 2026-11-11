#!/usr/bin/env python3
"""Check the Gateway v1 contract, its examples, served fixtures and compatibility (#1312-#1314).

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
3. every golden example under `contracts/gateway/v1/examples/` names an operation (or an
   unrouted request, see 8), its request
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
   own unique enumeration;
8. a request no route serves answers its request path as `instance`: a path under another API
   major (`/v2/...`) is `400 unsupported-version`, every other one `404
   not-found-or-unavailable`. A golden example with a null `operation_id` names such a request
   by its `method` and query-free request `target`;
9. the contract stays compatible with its frozen v1 baseline
   `contracts/gateway/v1/compatibility/baseline.json` for the declared window: every frozen
   served operation, parameter, response and problem type still exists; a request accepts
   everything it accepted (no new required member or parameter, no narrowed type, enumeration
   or bound); a response guarantees everything it guaranteed (no removed or no longer required
   member, no widened type, enumeration or bound); an added member is optional; schema
   identities and the declared handling of unknown members are unchanged; and every frozen
   example under `compatibility/examples/` is still valid. Every served operation is frozen.

Every problem body must use a status its registry entry permits.

`--freeze` appends every served operation, component, problem type and example the baseline
does not hold yet (a Draft operation promoted to served); it never rewrites a frozen entry.

Requires the hash-pinned `jsonschema` of `requirements-pinned-dependencies.txt`.

Usage:
    python3 scripts/check_gateway_contract.py
    python3 scripts/check_gateway_contract.py --freeze
"""

from __future__ import annotations

import copy
import json
import re
import shutil
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
COMPATIBILITY = CONTRACT / "compatibility"
BASELINE = COMPATIBILITY / "baseline.json"
FROZEN_EXAMPLES = COMPATIBILITY / "examples"

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
SERVED_API_MAJOR = "1"
API_MAJOR = re.compile(r"^/v([0-9]+)(?:/|$)")
# The compatibility window of the frozen v1 baseline (Wave 9 specification section 11).
WINDOW = {
    "opens": "Wave 9 acceptance",
    "supported_through": "Wave 10",
    "source": "Wave 9 acceptance specification section 11; Redmine #301 and #1314",
}

# Values the conformance normalization replaces, restored to valid samples before validation.
SAMPLE_ULID = "01JC0GATEWAYF1XTVRESAMP1E0"
SAMPLE_CURSOR = f"v1.{'0' * 64}.{SAMPLE_ULID}.1"
PLACEHOLDERS = {"<ulid>": SAMPLE_ULID, "<cursor>": SAMPLE_CURSOR, "<message>": "message"}


class ContractError(Exception):
    """One violation of the contract checks."""


def template_pattern(template: str) -> str:
    """The regular expression of the concrete paths an OpenAPI path template matches."""
    return "^" + re.sub(r"\\\{[a-z_]+\\\}", "[^/]+", re.escape(template)) + "$"


def unrouted_problem(path: str) -> tuple[str, int]:
    """The problem code and status of a request no route serves.

    A path under another API major fails closed as `unsupported-version` so that a client can
    tell an unsupported version from a missing resource; any other path is
    `not-found-or-unavailable`, which never reveals whether a resource exists.
    """
    major = API_MAJOR.match(path)
    if major and major.group(1) != SERVED_API_MAJOR:
        return "unsupported-version", 400
    return "not-found-or-unavailable", 404


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
        # The first template in document order that matches wins; no two templates overlap.
        for (op_method, template), operation in self.operations().items():
            if op_method == method and re.fullmatch(template_pattern(template), base):
                if operation["x-pigloros-status"] != "served":
                    raise ContractError(
                        f"{method} {base} is the Draft operation {operation['operationId']}; "
                        "a served exchange cannot exercise it"
                    )
                return template, operation
        raise ContractError(f"{method} {base} names no operation of the contract")

    def schema_name(self, reference: str) -> str:
        return reference.rsplit("/", 1)[1] if reference.startswith("#/") else self.names[reference]

    def target(self, reference: str) -> dict:
        """The component schema a `#/components/schemas/` or `$id` reference names."""
        if reference.startswith("#/components/schemas/"):
            name = reference.removeprefix("#/components/schemas/")
        else:
            name = self.names.get(reference, "")
        if name not in self.schemas:
            raise ContractError(f"unresolved schema reference {reference}")
        return self.schemas[name]

    def components(self, value: object) -> set[tuple[str, str]]:
        """The `(kind, name)` components a description fragment reaches through references."""
        found: set[tuple[str, str]] = set()
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
            if reference.startswith("#/components/"):
                kind, name = reference.removeprefix("#/components/").split("/", 1)
            else:
                kind, name = "schemas", self.names[reference]
            if (kind, name) not in found:
                found.add((kind, name))
                stack.append(self.document["components"][kind][name])
        return found

    def reachable(self, value: object) -> set[str]:
        """The component schemas a description fragment reaches through its references."""
        return {name for kind, name in self.components(value) if kind == "schemas"}

    def routed(self, path: str) -> bool:
        """Whether any operation template, served or Draft, matches a concrete request path."""
        return any(
            re.fullmatch(template_pattern(template), path) for template in self.document["paths"]
        )

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
        unrouted = body["instance"] == path and (code, status) == unrouted_problem(path)
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
    for status in ("200", "201"):
        if status not in operation["responses"]:
            continue
        schema_id = response_schema_id(contract, operation["responses"][status])
        schema = contract.schemas[contract.names[schema_id]] if schema_id else {}
        enveloped = (
            {"$ref": ENVELOPE_ID} in schema.get("allOf", [])
            and schema.get("unevaluatedProperties") is False
            and schema["properties"].get("schema_id", {}).get("const") == schema_id
        )
        if method == "GET" and not enveloped:
            raise ContractError(f"{where} 200: a Draft read answers a closed enveloped resource")
        if not enveloped and schema.get("additionalProperties") is not False:
            raise ContractError(f"{where} {status}: a Draft answer is closed or enveloped")


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
    """Every array, string, integer and map of a Draft schema or Draft parameter is bounded.

    Array bounds are stated limits, and a Draft schema has no JSON `number`: values that must
    replay deterministically are integers (micro-units where fractional).
    """
    for name, schema in contract.schemas.items():
        if schema.get("x-pigloros-maturity") == "draft":
            check_bounded_node(schema, f"/components/schemas/{name}", limit_pointers)
    for (method, template), operation in contract.operations().items():
        if operation["x-pigloros-status"] != "draft":
            continue
        for index, parameter in enumerate(operation.get("parameters", [])):
            where = f"{method} {template} parameter {index}"
            check_bounded_node(contract.resolve(parameter)["schema"], where, limit_pointers)


def check_bounded_node(node: object, path: str, limit_pointers: set[str]) -> None:
    if isinstance(node, list):
        for index, item in enumerate(node):
            check_bounded_node(item, f"{path}/{index}", limit_pointers)
        return
    if not isinstance(node, dict):
        return
    kinds = node.get("type")
    kinds = set(kinds) if isinstance(kinds, list) else {kinds}
    if "number" in kinds:
        raise ContractError(f"{path}: a Draft value is a JSON number, not an integer")
    if "integer" in kinds and not {"const", "enum", "maximum"} & set(node):
        raise ContractError(f"{path}: an unbounded integer")
    # Every Draft array declares `type: array`; an untyped `items` only refines one in a branch.
    if "array" in kinds:
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
    operations = operations_by_id(contract)
    statuses: dict[str, list[int]] = {}
    for name, example in examples:
        check_example(contract, operations, name, example)
        if example["operation_id"] is not None:
            statuses.setdefault(example["operation_id"], []).append(example["response"]["status"])
    if not examples:
        raise ContractError("no golden examples")
    check_draft_examples(operations, statuses)
    return len(examples)


def operations_by_id(contract: Contract) -> dict[str, tuple[str, dict]]:
    return {
        op["operationId"]: (template, op) for (_, template), op in contract.operations().items()
    }


def check_example(
    contract: Contract, operations: dict[str, tuple[str, dict]], name: str, example: dict
) -> None:
    """One golden example: an exchange of a named operation, or an unrouted request."""
    if example["operation_id"] is None:
        check_unrouted_example(contract, name, example)
        return
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
    errors = contract.response_errors(operation, response["status"], response["body"], template)
    errors += fork_ordinal_errors(response["body"])
    if errors:
        raise ContractError(f"{name}: response invalid: {errors[:3]}")


def check_unrouted_example(contract: Contract, name: str, example: dict) -> None:
    """A request no operation template matches answers the problem `unrouted_problem` names."""
    request = example["request"]
    method, path = request.get("method"), request.get("target")
    if method not in MUTATIONS | {"GET"} or not isinstance(path, str) or "?" in path:
        raise ContractError(f"{name}: an unrouted example names its method and query-free target")
    if contract.routed(path):
        raise ContractError(f"{name}: {path} is routed; name its operation")
    if example["request_valid"] is not False:
        raise ContractError(f"{name}: an unrouted request is never valid")
    response = example["response"]
    status, body = response["status"], response["body"]
    errors = contract.schema_errors(body, {"$ref": "#/components/schemas/Problem"})
    expected = unrouted_problem(path)
    if not errors and (body["code"], status) != expected:
        errors = [f"{path} answers {expected[1]} {expected[0]}"]
    if not errors:
        errors = contract.problem_errors(status, body, path, path)
    if errors:
        raise ContractError(f"{name}: response invalid: {errors[:3]}")


def fork_ordinal_errors(body: object) -> list[str]:
    """Ensemble Forks carry unique ordinals contiguous from 0 in array order.

    JSON Schema cannot state uniqueness of one member, so the examples enforce it.
    """
    forks = body.get("forks") if isinstance(body, dict) else None
    if not isinstance(forks, list) or not all(isinstance(fork, dict) for fork in forks):
        return []
    ordinals = [fork.get("ordinal") for fork in forks]
    if "ordinal" not in forks[0] or ordinals == list(range(len(forks))):
        return []
    return [f"forks: ordinals {ordinals} are not 0..{len(forks) - 1} in order"]


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


LOWER_BOUNDS = ("minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties")
UPPER_BOUNDS = ("maximum", "exclusiveMaximum", "maxLength", "maxItems", "maxProperties")
# Keywords that never change what a schema accepts.
ANNOTATIONS = {"description", "title", "examples", "$comment", "deprecated"}
# Keywords compared by a directional rule; every other keyword must stay identical.
DIRECTIONAL = {
    "$ref", "type", "enum", "const", "properties", "required", "items", "prefixItems",
    "allOf", "anyOf", "oneOf", "additionalProperties", "unevaluatedProperties",
    *LOWER_BOUNDS, *UPPER_BOUNDS,
}
REQUEST, RESPONSE = "request", "response"


def covered(kinds: frozenset[str], by: frozenset[str]) -> bool:
    """Whether every JSON type of `kinds` is accepted by `by` (an integer is a number)."""
    return all(kind in by or (kind == "integer" and "number" in by) for kind in kinds)


def accepted_types(node: dict) -> frozenset[str] | None:
    kinds = node.get("type")
    if kinds is None:
        return None
    return frozenset(kinds if isinstance(kinds, list) else [kinds])


def accepted_values(node: dict) -> frozenset[str] | None:
    if "const" in node:
        return frozenset([json.dumps(node["const"], sort_keys=True)])
    if "enum" in node:
        return frozenset(json.dumps(value, sort_keys=True) for value in node["enum"])
    return None


def widens(base: frozenset[str] | None, current: frozenset[str] | None, types: bool) -> bool:
    """Whether `current` accepts a value `base` rejected (None accepts every value)."""
    if base is None:
        return False
    if current is None:
        return True
    return not (covered(current, base) if types else current <= base)


class Compatibility:
    """Compares the current contract with its frozen baseline, direction by direction.

    A request schema must keep accepting every value it accepted; a response schema must keep
    guaranteeing every property it guaranteed. A schema reached from both directions therefore
    keeps its constraints exactly. Members may be added only as optional members.
    """

    def __init__(self, baseline: Contract, current: Contract) -> None:
        self.baseline = baseline
        self.current = current
        self.seen: set[tuple[str, str]] = set()

    def operation(self, where: str, base: dict, current: dict) -> None:
        if current["x-pigloros-status"] != "served":
            raise ContractError(f"{where}: a frozen served operation is no longer served")
        if current["operationId"] != base["operationId"]:
            raise ContractError(f"{where}: the operationId of a frozen operation changed")
        listeners = set(current.get("x-pigloros-listeners", []))
        if not set(base.get("x-pigloros-listeners", [])) <= listeners:
            raise ContractError(f"{where}: a frozen listener no longer serves the operation")
        if current.get("security") != base.get("security"):
            raise ContractError(f"{where}: the security requirement of a frozen operation changed")
        self.parameters(where, base, current)
        self.request_body(where, base, current)
        for status, response in base["responses"].items():
            if status not in current["responses"]:
                raise ContractError(f"{where}: the frozen response {status} was removed")
            self.content(
                f"{where} {status}",
                self.baseline.resolve(response),
                self.current.resolve(current["responses"][status]),
                RESPONSE,
            )

    def parameters(self, where: str, base: dict, current: dict) -> None:
        def keyed(contract: Contract, operation: dict) -> dict[tuple[str, str], dict]:
            """Parameters by location and name; header names are case-insensitive."""
            found = {}
            for parameter in map(contract.resolve, operation.get("parameters", [])):
                name = parameter["name"]
                fold = parameter["in"] == "header"
                found[(parameter["in"], name.lower() if fold else name)] = parameter
            return found

        before, after = keyed(self.baseline, base), keyed(self.current, current)
        for key, parameter in before.items():
            label = f"{where} {key[0]} parameter {key[1]}"
            if key not in after:
                raise ContractError(f"{label}: a frozen parameter was removed")
            if after[key].get("required", False) and not parameter.get("required", False):
                raise ContractError(f"{label}: an optional parameter became required")
            self.schema(label, parameter["schema"], after[key]["schema"], REQUEST)
        for location, name in sorted(set(after) - set(before)):
            if after[(location, name)].get("required", False):
                raise ContractError(f"{where} {location} parameter {name}: a new required one")

    def request_body(self, where: str, base: dict, current: dict) -> None:
        before = self.baseline.resolve(base["requestBody"]) if "requestBody" in base else None
        after = self.current.resolve(current["requestBody"]) if "requestBody" in current else None
        if before is None:
            if after is not None and after.get("required", False):
                raise ContractError(f"{where}: a new required request body")
            return
        if after is None:
            raise ContractError(f"{where}: the frozen request body was removed")
        if after.get("required", False) and not before.get("required", False):
            raise ContractError(f"{where}: an optional request body became required")
        self.content(f"{where} request", before, after, REQUEST)

    def content(self, where: str, base: dict, current: dict, direction: str) -> None:
        for media, entry in base.get("content", {}).items():
            if media not in current.get("content", {}):
                raise ContractError(f"{where}: the frozen media type {media} was removed")
            self.schema(f"{where} {media}", entry["schema"], current["content"][media]["schema"],
                        direction)

    def schema(self, where: str, base: object, current: object, direction: str) -> None:
        if not isinstance(base, dict) or not isinstance(current, dict):
            if base != current:
                raise ContractError(f"{where}: a boolean schema changed")
            return
        if "$ref" in base or "$ref" in current:
            self.reference(where, base, current, direction)
        for keyword in sorted((set(base) | set(current)) - DIRECTIONAL - ANNOTATIONS):
            if base.get(keyword) != current.get(keyword):
                raise ContractError(f"{where}: {keyword} of a frozen schema changed")
        self.values(where, base, current, direction)
        self.bounds(where, base, current, direction)
        self.members(where, base, current, direction)
        for keyword in ("additionalProperties", "unevaluatedProperties"):
            before, after = base.get(keyword), current.get(keyword)
            if isinstance(before, dict) and isinstance(after, dict):
                self.schema(f"{where}/{keyword}", before, after, direction)
            elif before != after:
                raise ContractError(f"{where}: the declared handling of unknown members changed")
        for keyword in ("items", "prefixItems", "allOf", "anyOf", "oneOf"):
            before, after = base.get(keyword), current.get(keyword)
            if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
                for index, (item, other) in enumerate(zip(before, after)):
                    self.schema(f"{where}/{keyword}/{index}", item, other, direction)
            elif isinstance(before, dict) and isinstance(after, dict):
                self.schema(f"{where}/{keyword}", before, after, direction)
            elif before != after:
                raise ContractError(f"{where}: {keyword} of a frozen schema changed shape")

    def reference(self, where: str, base: dict, current: dict, direction: str) -> None:
        if "$ref" not in base or "$ref" not in current:
            raise ContractError(f"{where}: a frozen schema reference was inlined or added")
        before = self.baseline.target(base["$ref"])
        after = self.current.target(current["$ref"])
        if before["$id"] != after["$id"]:
            raise ContractError(f"{where}: {before['$id']} became {after['$id']}")
        if (before["$id"], direction) not in self.seen:
            self.seen.add((before["$id"], direction))
            self.schema(f"{where} -> {before['$id']}", before, after, direction)

    def values(self, where: str, base: dict, current: dict, direction: str) -> None:
        for types, before, after in (
            (True, accepted_types(base), accepted_types(current)),
            (False, accepted_values(base), accepted_values(current)),
        ):
            what = "type" if types else "enumeration"
            if direction == REQUEST and widens(after, before, types):
                raise ContractError(f"{where}: a request {what} was narrowed")
            if direction == RESPONSE and widens(before, after, types):
                raise ContractError(f"{where}: a response {what} was widened")

    def bounds(self, where: str, base: dict, current: dict, direction: str) -> None:
        for keywords, sign in ((LOWER_BOUNDS, 1), (UPPER_BOUNDS, -1)):
            for keyword in keywords:
                before, after = base.get(keyword), current.get(keyword)
                tightened = after is not None and (before is None or sign * (after - before) > 0)
                loosened = before is not None and (after is None or sign * (after - before) < 0)
                if direction == REQUEST and tightened:
                    raise ContractError(f"{where}: the request bound {keyword} was tightened")
                if direction == RESPONSE and loosened:
                    raise ContractError(f"{where}: the response bound {keyword} was loosened")

    def members(self, where: str, base: dict, current: dict, direction: str) -> None:
        before, after = base.get("properties", {}), current.get("properties", {})
        required_before = set(base.get("required", []))
        required_after = set(current.get("required", []))
        for name, schema in before.items():
            if name not in after:
                raise ContractError(f"{where}: the frozen member {name} was removed")
            self.schema(f"{where}/{name}", schema, after[name], direction)
        added = sorted((set(after) & required_after) - set(before))
        if added:
            raise ContractError(f"{where}: the added member {added[0]} is required")
        if direction == REQUEST and required_after - required_before:
            name = sorted(required_after - required_before)[0]
            raise ContractError(f"{where}: the request member {name} became required")
        if direction == RESPONSE and required_before - required_after:
            name = sorted(required_before - required_after)[0]
            raise ContractError(f"{where}: the response member {name} is no longer guaranteed")


def check_window(baseline: dict) -> None:
    if baseline.get("window") != WINDOW:
        raise ContractError(f"the compatibility baseline does not declare the window {WINDOW}")


def check_compatibility(
    contract: Contract,
    baseline: dict | None = None,
    frozen: list[tuple[str, dict]] | None = None,
) -> int:
    """The current contract keeps every frozen v1 promise; returns the frozen examples checked."""
    if baseline is None:
        if not BASELINE.exists():
            raise ContractError(f"no compatibility baseline {BASELINE.name}; run with --freeze")
        baseline = load(BASELINE)  # type: ignore[assignment]
    frozen = load_examples(FROZEN_EXAMPLES) if frozen is None else frozen
    check_window(baseline)  # type: ignore[arg-type]
    base = Contract(baseline, contract.problem_types)  # type: ignore[arg-type]
    check_references(baseline, base, set(base.names))
    current_types = {entry["code"]: entry for entry in contract.problem_types["problem_types"]}
    for entry in baseline["problem_types"]:  # type: ignore[index]
        now = current_types.get(entry["code"])
        if now is None or (now["type"], now["title"]) != (entry["type"], entry["title"]):
            raise ContractError(f"the frozen problem type {entry['code']} was removed or renamed")
        if not set(entry["statuses"]) <= set(now["statuses"]):
            raise ContractError(f"a frozen status of the problem type {entry['code']} was removed")
    current = contract.operations()
    comparison = Compatibility(base, contract)
    for (method, path), operation in base.operations().items():
        where = f"{method} {path}"
        if (method, path) not in current:
            raise ContractError(f"{where}: a frozen operation was removed")
        comparison.operation(where, operation, current[(method, path)])
    for (method, path), operation in current.items():
        if operation["x-pigloros-status"] == "served" and (method, path) not in base.operations():
            raise ContractError(
                f"{method} {path}: a served operation is not frozen; run with --freeze"
            )
    operations = operations_by_id(contract)
    served = {
        operation_id
        for operation_id, (_, operation) in operations.items()
        if operation["x-pigloros-status"] == "served"
    }
    for name, example in frozen:
        if example["operation_id"] not in served | {None}:
            raise ContractError(f"{name}: a frozen example exercises no served operation")
        check_example(contract, operations, name, example)
    if not frozen:
        raise ContractError("no frozen compatibility examples")
    return len(frozen)


def freeze(contract: Contract, baseline: dict | None) -> dict:
    """Append every served operation, component and problem type the baseline lacks.

    A frozen entry is never rewritten: promotion adds to the window, it never moves it.
    """
    frozen = copy.deepcopy(baseline) if baseline is not None else {
        "$comment": (
            "Not a schema: the frozen v1 baseline of the Gateway contract (#1314). Every served "
            "operation, the components it reaches and the problem registry as published. "
            "scripts/check_gateway_contract.py fails when the current contract breaks one of "
            "them; --freeze only appends."
        ),
        "contract": "urn:pigloros:gateway:v1",
        "window": WINDOW,
        "paths": {},
        "components": {"schemas": {}, "parameters": {}, "responses": {}},
        "problem_types": [],
    }
    for (method, path), operation in contract.operations().items():
        item = frozen["paths"].setdefault(path, {})
        if operation["x-pigloros-status"] != "served" or method.lower() in item:
            if not item:
                del frozen["paths"][path]
            continue
        item[method.lower()] = copy.deepcopy(operation)
        for kind, name in sorted(contract.components(operation)):
            section = frozen["components"].setdefault(kind, {})
            if name not in section:
                section[name] = copy.deepcopy(contract.document["components"][kind][name])
    codes = {entry["code"] for entry in frozen["problem_types"]}
    for entry in contract.problem_types["problem_types"]:
        if entry["code"] not in codes:
            frozen["problem_types"].append(
                {key: copy.deepcopy(entry[key]) for key in ("code", "type", "title", "statuses")}
            )
    return frozen


def freeze_examples(contract: Contract, source: Path = EXAMPLES,
                    target: Path = FROZEN_EXAMPLES) -> list[str]:
    """Copy each golden example of a served operation or unrouted request not yet frozen."""
    operations = operations_by_id(contract)
    target.mkdir(parents=True, exist_ok=True)
    copied = []
    for name, example in load_examples(source):
        operation_id = example["operation_id"]
        served = operation_id is None or (
            operations[operation_id][1]["x-pigloros-status"] == "served"
        )
        if served and not (target / name).exists():
            shutil.copyfile(source / name, target / name)
            copied.append(name)
    return copied


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


def write_baseline(contract: Contract, path: Path = BASELINE) -> None:
    """Append the served contract the baseline at `path` does not hold yet."""
    baseline = load(path) if path.exists() else None
    frozen = freeze(contract, baseline)  # type: ignore[arg-type]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(frozen, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in ([], ["--freeze"]):
        print("usage: check_gateway_contract.py [--freeze]", file=sys.stderr)
        return 2
    try:
        contract = Contract(load(OPENAPI), load(PROBLEM_TYPES))  # type: ignore[arg-type]
        check_description(contract)
        check_registry(contract)
        examples = check_examples(contract)
        exchanges = check_fixtures(contract)
        if arguments:
            write_baseline(contract)
            freeze_examples(contract)
        frozen = check_compatibility(contract)
    except ContractError as error:
        print(f"gateway contract check failed: {error}", file=sys.stderr)
        return 1
    drafts = sum(op["x-pigloros-status"] == "draft" for op in contract.operations().values())
    limits = len(contract.document["x-pigloros-limits"])
    print(
        f"Gateway v1 contract OK: {examples} examples, {exchanges} served exchanges, "
        f"{drafts} Draft operations, {limits} limits, {frozen} frozen v1 examples."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
