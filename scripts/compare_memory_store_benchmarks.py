#!/usr/bin/env python3
"""Validate advisory MemoryStore benchmark evidence and compare trusted baselines.

The workflow uses this dependency-free tool in two modes:

* ``write-manifest`` validates the current raw CSV and records its provenance.
* ``compare`` validates the current evidence, selects the newest compatible
  trusted ``main`` artifact, and emits an advisory GitHub summary/annotation.

Only malformed current evidence fails the workflow. Historical evidence that is
missing, stale, incompatible, or unverifiable becomes an explicit successful
``comparison unavailable`` result instead.
"""

from __future__ import annotations

import argparse
import csv
import datetime as datetime
import io
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any


ARTIFACT_NAME = "memory-store-benchmark-baseline-v1"
BENCHMARK_COMMAND = "cargo bench --locked -p pos-store --bench memory_erasure"
CSV_HEADER = ("scenario", "cardinality", "sample", "elapsed_nanos")
DEFAULT_BRANCH = "main"
FRESHNESS_LIMIT = datetime.timedelta(days=14)
MANIFEST_FILE = "memory-erasure-benchmark-manifest.json"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 1_000_000
MAX_ARCHIVE_MEMBERS = 32
SAMPLE_COUNT = 10
SCHEMA_VERSION = 1
WORKFLOW_PATH = ".github/workflows/memory-store-benchmark.yml"


@dataclass(frozen=True, order=True)
class ScenarioKey:
    """One benchmark scenario/cardinality pair from the raw CSV contract."""

    scenario: str
    cardinality: int


EXPECTED_INVENTORY = (
    ScenarioKey("acknowledgement-admission", 0),
    ScenarioKey("acknowledgement-admission", 8),
    ScenarioKey("acknowledgement-admission", 32),
    ScenarioKey("acknowledgement-admission", 63),
    ScenarioKey("manifest-cas", 0),
    ScenarioKey("manifest-cas", 32),
    ScenarioKey("manifest-cas", 128),
    ScenarioKey("manifest-cas", 512),
    ScenarioKey("recovery-error-append", 0),
    ScenarioKey("recovery-error-append", 8),
    ScenarioKey("recovery-error-append", 24),
    ScenarioKey("recovery-error-read", 1),
    ScenarioKey("recovery-error-read", 9),
    ScenarioKey("recovery-error-read", 25),
)
EXPECTED_KEYS = frozenset(EXPECTED_INVENTORY)
REQUIRED_MANIFEST_FIELDS = frozenset(
    {
        "architecture",
        "benchmark_command",
        "created_at",
        "event",
        "head_branch",
        "head_repository_id",
        "head_sha",
        "repository",
        "repository_id",
        "run_attempt",
        "runner_fingerprint",
        "runner_image",
        "sample_count",
        "scenario_inventory",
        "schema_version",
        "toolchain",
        "workflow_id",
        "workflow_path",
        "workflow_run_id",
    }
)
TRUSTED_EVENTS = frozenset({"push", "schedule"})


class EvidenceError(ValueError):
    """A CSV or manifest cannot establish the required evidence contract."""


class CandidateRejected(ValueError):
    """One historical artifact cannot serve as a trusted baseline."""


class ApiError(RuntimeError):
    """GitHub Actions evidence could not be retrieved or verified."""


@dataclass(frozen=True)
class BenchmarkDataset:
    """Parsed raw samples, indexed by their exact scenario/cardinality key."""

    samples_by_key: Mapping[ScenarioKey, tuple[int, ...]]

    def statistics(self, key: ScenarioKey) -> "BenchmarkStatistics":
        values = self.samples_by_key[key]
        return BenchmarkStatistics(median_ns=values[len(values) // 2], p95_ns=values[-1])


@dataclass(frozen=True)
class BenchmarkStatistics:
    """The upper median and p95 used by the existing ten-sample harness."""

    median_ns: int
    p95_ns: int


@dataclass(frozen=True)
class ComparisonRow:
    """One displayable PR-versus-baseline scenario comparison."""

    key: ScenarioKey
    baseline: BenchmarkStatistics
    current: BenchmarkStatistics
    warning: bool


@dataclass(frozen=True)
class ExpectedIdentity:
    """Repository-owned workflow identity a baseline must prove."""

    repository: str
    repository_id: int
    workflow_id: int
    workflow_path: str
    default_branch: str = DEFAULT_BRANCH


@dataclass(frozen=True)
class SelectedBaseline:
    """Validated baseline content plus immutable artifact/run references."""

    artifact_id: int
    artifact_created_at: datetime.datetime
    dataset: BenchmarkDataset
    manifest: Mapping[str, Any]


def require_positive_int(value: Any, field: str, error_type: type[ValueError]) -> int:
    """Return a positive JSON integer, rejecting bools and coercion surprises."""

    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise error_type(f"{field} must be a positive integer")
    return value


def require_nonempty_string(value: Any, field: str, error_type: type[ValueError]) -> str:
    """Return a nonblank JSON string without silently coercing values."""

    if not isinstance(value, str) or not value.strip():
        raise error_type(f"{field} must be a non-empty string")
    return value


def parse_timestamp(value: Any, field: str, error_type: type[ValueError]) -> datetime.datetime:
    """Parse an ISO-8601 UTC timestamp into an aware datetime."""

    text = require_nonempty_string(value, field, error_type)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.datetime.fromisoformat(normalized)
    except ValueError as error:
        raise error_type(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise error_type(f"{field} must include a timezone")
    return parsed.astimezone(datetime.timezone.utc)


def utc_now() -> datetime.datetime:
    """Return an aware UTC timestamp in one injectable place for tests."""

    return datetime.datetime.now(datetime.timezone.utc)


def inventory_as_json() -> list[dict[str, Any]]:
    """Return the canonical manifest representation of the V1 inventory."""

    return [
        {"scenario": key.scenario, "cardinality": key.cardinality}
        for key in EXPECTED_INVENTORY
    ]


def parse_ascii_nonnegative_integer(value: str, field: str, line: int) -> int:
    """Parse strict decimal CSV data without accepting signs, spaces, or floats."""

    if not re.fullmatch(r"[0-9]+", value):
        raise EvidenceError(f"CSV line {line}: {field} must be an unsigned decimal integer")
    return int(value)


def parse_benchmark_csv(text: str) -> BenchmarkDataset:
    """Parse the fixed V1 raw-CSV contract emitted by ``memory_erasure``."""

    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        header = next(reader)
    except StopIteration as error:
        raise EvidenceError("CSV is empty") from error
    if tuple(header) != CSV_HEADER:
        raise EvidenceError(
            "CSV header must be exactly " + ",".join(CSV_HEADER)
        )

    values_by_key: dict[ScenarioKey, list[int]] = defaultdict(list)
    seen_samples: set[tuple[ScenarioKey, int]] = set()
    for line_number, row in enumerate(reader, start=2):
        if len(row) != len(CSV_HEADER):
            raise EvidenceError(
                f"CSV line {line_number}: expected {len(CSV_HEADER)} columns, got {len(row)}"
            )
        scenario, raw_cardinality, raw_sample, raw_elapsed = row
        cardinality = parse_ascii_nonnegative_integer(
            raw_cardinality, "cardinality", line_number
        )
        sample = parse_ascii_nonnegative_integer(raw_sample, "sample", line_number)
        elapsed_nanos = parse_ascii_nonnegative_integer(
            raw_elapsed, "elapsed_nanos", line_number
        )
        key = ScenarioKey(scenario=scenario, cardinality=cardinality)
        if key not in EXPECTED_KEYS:
            raise EvidenceError(
                f"CSV line {line_number}: unexpected scenario/cardinality "
                f"{scenario!r}/{cardinality}"
            )
        if sample >= SAMPLE_COUNT:
            raise EvidenceError(
                f"CSV line {line_number}: sample must be below {SAMPLE_COUNT}"
            )
        identity = (key, sample)
        if identity in seen_samples:
            raise EvidenceError(
                f"CSV line {line_number}: duplicate sample {sample} for "
                f"{scenario!r}/{cardinality}"
            )
        seen_samples.add(identity)
        values_by_key[key].append(elapsed_nanos)

    actual_keys = frozenset(values_by_key)
    if actual_keys != EXPECTED_KEYS:
        missing = sorted(EXPECTED_KEYS - actual_keys)
        extra = sorted(actual_keys - EXPECTED_KEYS)
        pieces: list[str] = []
        if missing:
            pieces.append(
                "missing "
                + ", ".join(f"{key.scenario}/{key.cardinality}" for key in missing)
            )
        if extra:
            pieces.append(
                "unexpected "
                + ", ".join(f"{key.scenario}/{key.cardinality}" for key in extra)
            )
        raise EvidenceError("CSV scenario inventory mismatch: " + "; ".join(pieces))

    normalized: dict[ScenarioKey, tuple[int, ...]] = {}
    for key in EXPECTED_INVENTORY:
        values = values_by_key[key]
        if len(values) != SAMPLE_COUNT:
            raise EvidenceError(
                f"CSV {key.scenario}/{key.cardinality} must contain exactly "
                f"{SAMPLE_COUNT} samples"
            )
        sample_indexes = {
            sample
            for candidate_key, sample in seen_samples
            if candidate_key == key
        }
        if sample_indexes != set(range(SAMPLE_COUNT)):
            raise EvidenceError(
                f"CSV {key.scenario}/{key.cardinality} must contain each sample index "
                f"from 0 through {SAMPLE_COUNT - 1} exactly once"
            )
        normalized[key] = tuple(sorted(values))
    return BenchmarkDataset(samples_by_key=normalized)


def load_csv(path: pathlib.Path) -> BenchmarkDataset:
    """Read and parse a UTF-8 raw benchmark CSV file."""

    try:
        return parse_benchmark_csv(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise EvidenceError(f"cannot read CSV {path}: {error}") from error


def parse_inventory(value: Any, error_type: type[ValueError]) -> tuple[ScenarioKey, ...]:
    """Validate the manifest's exact, ordered scenario/cardinality inventory."""

    if not isinstance(value, list):
        raise error_type("scenario_inventory must be a list")
    parsed: list[ScenarioKey] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != {"scenario", "cardinality"}:
            raise error_type(
                f"scenario_inventory[{index}] must contain only scenario and cardinality"
            )
        scenario = require_nonempty_string(item["scenario"], "scenario", error_type)
        cardinality = require_positive_or_zero_int(item["cardinality"], "cardinality", error_type)
        parsed.append(ScenarioKey(scenario=scenario, cardinality=cardinality))
    return tuple(parsed)


def require_positive_or_zero_int(value: Any, field: str, error_type: type[ValueError]) -> int:
    """Return a nonnegative JSON integer while rejecting bools."""

    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise error_type(f"{field} must be a non-negative integer")
    return value


def load_manifest_text(text: str, label: str) -> Mapping[str, Any]:
    """Decode a manifest and reject schema drift rather than guessing compatibility."""

    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as error:
        raise EvidenceError(f"{label} manifest is not valid JSON") from error
    if not isinstance(manifest, dict) or set(manifest) != REQUIRED_MANIFEST_FIELDS:
        missing = sorted(REQUIRED_MANIFEST_FIELDS - set(manifest) if isinstance(manifest, dict) else REQUIRED_MANIFEST_FIELDS)
        extra = sorted(set(manifest) - REQUIRED_MANIFEST_FIELDS) if isinstance(manifest, dict) else []
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise EvidenceError(
            f"{label} manifest has an incompatible schema" + (": " + "; ".join(detail) if detail else "")
        )
    return manifest


def load_manifest(path: pathlib.Path, label: str) -> Mapping[str, Any]:
    """Read and decode a UTF-8 manifest file."""

    try:
        return load_manifest_text(path.read_text(encoding="utf-8"), label)
    except OSError as error:
        raise EvidenceError(f"cannot read {label} manifest {path}: {error}") from error


def validate_manifest(
    manifest: Mapping[str, Any], dataset: BenchmarkDataset, label: str
) -> datetime.datetime:
    """Validate static V1 metadata and its agreement with the parsed CSV."""

    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceError(f"{label} manifest schema_version must be {SCHEMA_VERSION}")
    if manifest.get("benchmark_command") != BENCHMARK_COMMAND:
        raise EvidenceError(f"{label} manifest benchmark_command is not the approved command")
    if manifest.get("sample_count") != SAMPLE_COUNT:
        raise EvidenceError(f"{label} manifest sample_count must be {SAMPLE_COUNT}")
    if parse_inventory(manifest.get("scenario_inventory"), EvidenceError) != EXPECTED_INVENTORY:
        raise EvidenceError(f"{label} manifest scenario_inventory does not match V1")

    for field in (
        "architecture",
        "event",
        "head_branch",
        "head_sha",
        "repository",
        "runner_fingerprint",
        "runner_image",
        "toolchain",
        "workflow_path",
    ):
        require_nonempty_string(manifest.get(field), f"{label} manifest {field}", EvidenceError)
    for field in (
        "head_repository_id",
        "repository_id",
        "run_attempt",
        "workflow_id",
        "workflow_run_id",
    ):
        require_positive_int(manifest.get(field), f"{label} manifest {field}", EvidenceError)

    expected_fingerprint = f"{manifest['runner_image']}|{manifest['architecture']}"
    if manifest["runner_fingerprint"] != expected_fingerprint:
        raise EvidenceError(
            f"{label} manifest runner_fingerprint must bind runner_image and architecture"
        )
    if frozenset(dataset.samples_by_key) != EXPECTED_KEYS:
        raise EvidenceError(f"{label} CSV scenario inventory does not match V1")
    return parse_timestamp(manifest.get("created_at"), f"{label} manifest created_at", EvidenceError)


def make_manifest(
    dataset: BenchmarkDataset,
    *,
    architecture: str,
    event: str,
    head_branch: str,
    head_repository_id: int,
    head_sha: str,
    repository: str,
    repository_id: int,
    run_attempt: int,
    runner_image: str,
    toolchain: str,
    workflow_id: int,
    workflow_path: str,
    workflow_run_id: int,
    created_at: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Create a canonical manifest from validated current CSV and runner facts."""

    if frozenset(dataset.samples_by_key) != EXPECTED_KEYS:
        raise EvidenceError("current CSV scenario inventory does not match V1")
    timestamp = (created_at or utc_now()).astimezone(datetime.timezone.utc)
    return {
        "architecture": architecture,
        "benchmark_command": BENCHMARK_COMMAND,
        "created_at": timestamp.isoformat().replace("+00:00", "Z"),
        "event": event,
        "head_branch": head_branch,
        "head_repository_id": head_repository_id,
        "head_sha": head_sha,
        "repository": repository,
        "repository_id": repository_id,
        "run_attempt": run_attempt,
        "runner_fingerprint": f"{runner_image}|{architecture}",
        "runner_image": runner_image,
        "sample_count": SAMPLE_COUNT,
        "scenario_inventory": inventory_as_json(),
        "schema_version": SCHEMA_VERSION,
        "toolchain": toolchain,
        "workflow_id": workflow_id,
        "workflow_path": workflow_path,
        "workflow_run_id": workflow_run_id,
    }


def write_manifest(arguments: argparse.Namespace) -> int:
    """Validate current data before writing a manifest for artifact upload."""

    dataset = load_csv(arguments.csv)
    manifest = make_manifest(
        dataset,
        architecture=arguments.architecture,
        event=arguments.event,
        head_branch=arguments.head_branch,
        head_repository_id=arguments.head_repository_id,
        head_sha=arguments.head_sha,
        repository=arguments.repository,
        repository_id=arguments.repository_id,
        run_attempt=arguments.run_attempt,
        runner_image=arguments.runner_image,
        toolchain=arguments.toolchain,
        workflow_id=arguments.workflow_id,
        workflow_path=arguments.workflow_path,
        workflow_run_id=arguments.workflow_run_id,
    )
    validate_manifest(manifest, dataset, "current")
    try:
        arguments.output.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as error:
        raise EvidenceError(f"cannot write manifest {arguments.output}: {error}") from error
    print(f"Validated current benchmark evidence and wrote {arguments.output}.")
    return 0


def compare_datasets(
    baseline: BenchmarkDataset, current: BenchmarkDataset
) -> tuple[ComparisonRow, ...]:
    """Compare matching datasets using overflow-safe integer threshold arithmetic."""

    if frozenset(baseline.samples_by_key) != frozenset(current.samples_by_key):
        raise CandidateRejected("baseline CSV inventory differs from current CSV inventory")
    rows: list[ComparisonRow] = []
    for key in EXPECTED_INVENTORY:
        baseline_stats = baseline.statistics(key)
        current_stats = current.statistics(key)
        if baseline_stats.median_ns == 0:
            raise CandidateRejected(
                f"baseline median is zero for {key.scenario}/{key.cardinality}"
            )
        rows.append(
            ComparisonRow(
                key=key,
                baseline=baseline_stats,
                current=current_stats,
                warning=current_stats.median_ns * 10 > baseline_stats.median_ns * 11,
            )
        )
    return tuple(rows)


def percentage_delta(baseline: int, current: int) -> str:
    """Render a rounded percentage without floating-point overflow or drift."""

    if baseline == 0:
        return "unavailable"
    difference = current - baseline
    sign = "+" if difference >= 0 else "-"
    hundredths = (abs(difference) * 10_000 + (baseline // 2)) // baseline
    whole, fractional = divmod(hundredths, 100)
    return f"{sign}{whole}.{fractional:02d}%"


def render_comparison_summary(
    baseline: SelectedBaseline, rows: Sequence[ComparisonRow]
) -> str:
    """Render every scenario delta into a GitHub job-summary table."""

    manifest = baseline.manifest
    lines = [
        "## Advisory MemoryStore performance comparison",
        "",
        "Trusted baseline: "
        f"`{manifest['head_sha']}` from artifact `{baseline.artifact_id}` "
        f"created {baseline.artifact_created_at.isoformat()}.",
        "",
        "| Scenario | Cardinality | Main median | PR median | Delta | Main p95 | PR p95 | Result |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        result = "warning (>10% slower)" if row.warning else "advisory"
        lines.append(
            "| "
            f"{row.key.scenario} | {row.key.cardinality} | {row.baseline.median_ns} ns | "
            f"{row.current.median_ns} ns | "
            f"{percentage_delta(row.baseline.median_ns, row.current.median_ns)} | "
            f"{row.baseline.p95_ns} ns | {row.current.p95_ns} ns | {result} |"
        )
    return "\n".join(lines) + "\n"


def render_unavailable_summary(reason: str) -> str:
    """Render a successful, explicit absence of comparable historical evidence."""

    return (
        "## Advisory MemoryStore performance comparison\n\n"
        f"Comparison unavailable: {reason}. This advisory result does not affect merge eligibility.\n"
    )


def append_summary(path: pathlib.Path, text: str) -> None:
    """Append markdown to GitHub's supplied job-summary file."""

    try:
        with path.open("a", encoding="utf-8") as output:
            output.write(text)
    except OSError as error:
        raise EvidenceError(f"cannot write job summary {path}: {error}") from error


def warning_annotation(row: ComparisonRow, baseline_sha: str) -> str:
    """Return one supported, static-shape GitHub warning command."""

    delta = percentage_delta(row.baseline.median_ns, row.current.median_ns)
    return (
        "::warning title=MemoryStore benchmark regression::"
        f"{row.key.scenario} cardinality={row.key.cardinality}: PR median "
        f"{row.current.median_ns} ns is {delta} versus trusted main baseline "
        f"{row.baseline.median_ns} ns ({baseline_sha})."
    )


def require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    """Require a JSON object for nested GitHub REST response data."""

    if not isinstance(value, dict):
        raise CandidateRejected(f"{field} must be an object")
    return value


def validate_artifact_metadata(
    artifact: Mapping[str, Any], identity: ExpectedIdentity, now: datetime.datetime
) -> tuple[int, datetime.datetime, Mapping[str, Any]]:
    """Validate immutable artifact-list provenance before any archive download."""

    if artifact.get("name") != ARTIFACT_NAME:
        raise CandidateRejected("artifact has the wrong baseline name")
    artifact_id = require_positive_int(artifact.get("id"), "artifact id", CandidateRejected)
    archive_size = require_positive_int(
        artifact.get("size_in_bytes"), "artifact size_in_bytes", CandidateRejected
    )
    if archive_size > MAX_ARCHIVE_BYTES:
        raise CandidateRejected("artifact exceeds the maximum archive size")
    if artifact.get("expired") is not False:
        raise CandidateRejected("artifact is expired")
    created_at = parse_timestamp(artifact.get("created_at"), "artifact created_at", CandidateRejected)
    expires_at = parse_timestamp(artifact.get("expires_at"), "artifact expires_at", CandidateRejected)
    if expires_at <= now:
        raise CandidateRejected("artifact has reached its expiration timestamp")
    if created_at < now - FRESHNESS_LIMIT:
        raise CandidateRejected("artifact exceeds the 14-day freshness limit")
    workflow_run = require_mapping(artifact.get("workflow_run"), "artifact workflow_run")
    if require_positive_int(
        workflow_run.get("repository_id"), "artifact workflow_run repository_id", CandidateRejected
    ) != identity.repository_id:
        raise CandidateRejected("artifact belongs to a foreign repository")
    if require_positive_int(
        workflow_run.get("head_repository_id"),
        "artifact workflow_run head_repository_id",
        CandidateRejected,
    ) != identity.repository_id:
        raise CandidateRejected("artifact head repository is not repository-owned")
    if workflow_run.get("head_branch") != identity.default_branch:
        raise CandidateRejected("artifact did not run from main")
    require_nonempty_string(
        workflow_run.get("head_sha"), "artifact workflow_run head_sha", CandidateRejected
    )
    require_positive_int(workflow_run.get("id"), "artifact workflow_run id", CandidateRejected)
    require_nonempty_string(
        artifact.get("archive_download_url"), "artifact archive_download_url", CandidateRejected
    )
    return artifact_id, created_at, workflow_run


def validate_workflow_run(
    run: Mapping[str, Any],
    artifact_run: Mapping[str, Any],
    identity: ExpectedIdentity,
) -> None:
    """Require the run API to agree with artifact metadata and trusted policy."""

    run_id = require_positive_int(run.get("id"), "workflow run id", CandidateRejected)
    if run_id != artifact_run["id"]:
        raise CandidateRejected("workflow run ID disagrees with artifact metadata")
    if run.get("event") not in TRUSTED_EVENTS:
        raise CandidateRejected("workflow run event is not trusted")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise CandidateRejected("workflow run did not complete successfully")
    if require_positive_int(run.get("workflow_id"), "workflow run workflow_id", CandidateRejected) != identity.workflow_id:
        raise CandidateRejected("workflow run has the wrong workflow ID")
    if run.get("path") != identity.workflow_path:
        raise CandidateRejected("workflow run has the wrong workflow path")
    repository = require_mapping(run.get("repository"), "workflow run repository")
    head_repository = require_mapping(run.get("head_repository"), "workflow run head_repository")
    if require_positive_int(repository.get("id"), "workflow run repository id", CandidateRejected) != identity.repository_id:
        raise CandidateRejected("workflow run belongs to a foreign repository")
    if require_positive_int(
        head_repository.get("id"), "workflow run head_repository id", CandidateRejected
    ) != identity.repository_id:
        raise CandidateRejected("workflow run head repository is not repository-owned")
    if run.get("head_branch") != identity.default_branch:
        raise CandidateRejected("workflow run did not execute on main")
    if run.get("head_branch") != artifact_run["head_branch"]:
        raise CandidateRejected("workflow run branch disagrees with artifact metadata")
    if run.get("head_sha") != artifact_run["head_sha"]:
        raise CandidateRejected("workflow run SHA disagrees with artifact metadata")
    require_positive_int(run.get("run_attempt"), "workflow run run_attempt", CandidateRejected)


def read_named_archive_members(archive: bytes) -> tuple[str, str]:
    """Read only the two expected files directly from an archive, never extract it."""

    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            members = zipped.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise CandidateRejected("archive has too many members")
            matches: dict[str, zipfile.ZipInfo] = {}
            for member in members:
                name = pathlib.PurePosixPath(member.filename).name
                if name not in {MANIFEST_FILE, "memory-erasure-benchmark.csv"}:
                    continue
                if member.is_dir() or member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise CandidateRejected(f"archive member {name!r} is not an acceptable file")
                if name in matches:
                    raise CandidateRejected(f"archive contains duplicate {name!r} files")
                matches[name] = member
            expected_names = {MANIFEST_FILE, "memory-erasure-benchmark.csv"}
            if set(matches) != expected_names:
                raise CandidateRejected("archive lacks the required CSV or manifest")
            manifest_text = zipped.read(matches[MANIFEST_FILE]).decode("utf-8")
            csv_text = zipped.read(matches["memory-erasure-benchmark.csv"]).decode("utf-8")
            return manifest_text, csv_text
    except CandidateRejected:
        raise
    except Exception as error:
        # Archive bytes are historical evidence: no malformed ZIP/decompression
        # failure may turn the advisory PR comparison into a failed job.
        raise CandidateRejected(f"cannot read baseline artifact archive: {error}") from error


def validate_baseline_manifest(
    manifest: Mapping[str, Any],
    dataset: BenchmarkDataset,
    artifact_run: Mapping[str, Any],
    run: Mapping[str, Any],
    current_manifest: Mapping[str, Any],
    identity: ExpectedIdentity,
    now: datetime.datetime,
) -> None:
    """Bind archive content to both REST records and the current compatible run."""

    created_at = validate_manifest(manifest, dataset, "baseline")
    if created_at < now - FRESHNESS_LIMIT:
        raise CandidateRejected("baseline manifest exceeds the 14-day freshness limit")
    expected_values = {
        "repository": identity.repository,
        "repository_id": identity.repository_id,
        "head_repository_id": identity.repository_id,
        "head_branch": identity.default_branch,
        "head_sha": artifact_run["head_sha"],
        "workflow_id": identity.workflow_id,
        "workflow_path": identity.workflow_path,
        "workflow_run_id": artifact_run["id"],
        "run_attempt": run["run_attempt"],
        "event": run["event"],
    }
    for field, expected in expected_values.items():
        if manifest.get(field) != expected:
            raise CandidateRejected(f"baseline manifest {field} disagrees with trusted metadata")
    for field in (
        "benchmark_command",
        "sample_count",
        "scenario_inventory",
        "schema_version",
        "toolchain",
        "runner_image",
        "architecture",
        "runner_fingerprint",
    ):
        if manifest.get(field) != current_manifest.get(field):
            raise CandidateRejected(f"baseline manifest {field} is incompatible with current evidence")


def candidate_sort_key(artifact: Mapping[str, Any]) -> tuple[int, datetime.datetime, int]:
    """Sort deterministically by newest valid timestamp then highest artifact ID."""

    try:
        created_at = parse_timestamp(artifact.get("created_at"), "artifact created_at", CandidateRejected)
        artifact_id = require_positive_int(artifact.get("id"), "artifact id", CandidateRejected)
    except CandidateRejected:
        return (0, datetime.datetime.min.replace(tzinfo=datetime.timezone.utc), 0)
    return (1, created_at, artifact_id)


def select_newest_baseline(
    artifacts: Iterable[Mapping[str, Any]],
    *,
    fetch_run: Callable[[int], Mapping[str, Any]],
    fetch_archive: Callable[[Mapping[str, Any]], bytes],
    current_manifest: Mapping[str, Any],
    identity: ExpectedIdentity,
    now: datetime.datetime,
) -> tuple[SelectedBaseline | None, tuple[str, ...]]:
    """Return the newest valid baseline and deterministic rejection diagnostics."""

    rejections: list[str] = []
    for artifact in sorted(artifacts, key=candidate_sort_key, reverse=True):
        artifact_id = artifact.get("id", "unknown")
        try:
            selected_id, created_at, artifact_run = validate_artifact_metadata(
                artifact, identity, now
            )
            run = fetch_run(artifact_run["id"])
            validate_workflow_run(run, artifact_run, identity)
            manifest_text, csv_text = read_named_archive_members(fetch_archive(artifact))
            manifest = load_manifest_text(manifest_text, "baseline")
            dataset = parse_benchmark_csv(csv_text)
            validate_baseline_manifest(
                manifest,
                dataset,
                artifact_run,
                run,
                current_manifest,
                identity,
                now,
            )
            compare_datasets(dataset, dataset)
        except (ApiError, CandidateRejected, EvidenceError) as error:
            rejections.append(f"artifact {artifact_id}: {error}")
            continue
        return (
            SelectedBaseline(
                artifact_id=selected_id,
                artifact_created_at=created_at,
                dataset=dataset,
                manifest=manifest,
            ),
            tuple(rejections),
        )
    return None, tuple(rejections)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Make the authenticated artifact API redirect explicit and token-safe."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def read_bounded_archive_response(response: Any) -> bytes:
    """Read a historical artifact with a hard size limit, even without a header."""

    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        if not re.fullmatch(r"[0-9]+", content_length):
            raise ApiError("artifact response has an invalid Content-Length")
        if int(content_length) > MAX_ARCHIVE_BYTES:
            raise ApiError("artifact response exceeds the maximum archive size")

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, MAX_ARCHIVE_BYTES - total + 1))
        if not chunk:
            return b"".join(chunks)
        if not isinstance(chunk, bytes):
            raise ApiError("artifact response did not return bytes")
        total += len(chunk)
        if total > MAX_ARCHIVE_BYTES:
            raise ApiError("artifact response exceeds the maximum archive size")
        chunks.append(chunk)


class GitHubActionsClient:
    """Small standard-library GitHub Actions REST client for one workflow job."""

    def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise ApiError("GITHUB_TOKEN is required to read Actions evidence")
        parsed = urllib.parse.urlparse(api_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ApiError("api_url must be an HTTPS origin")
        self._api_url = api_url.rstrip("/")
        self._api_origin = (parsed.scheme, parsed.netloc)
        self._token = token

    def _api_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "pigloros-benchmark-comparator",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _assert_api_origin(self, url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if (parsed.scheme, parsed.netloc) != self._api_origin:
            raise ApiError("GitHub API pagination escaped the configured API origin")

    def _json_response(self, url: str) -> tuple[Mapping[str, Any], str | None]:
        self._assert_api_origin(url)
        request = urllib.request.Request(url, headers=self._api_headers())
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = json.load(response)
                link = response.headers.get("Link")
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as error:
            raise ApiError(f"cannot retrieve GitHub Actions data: {error}") from error
        if not isinstance(body, dict):
            raise ApiError("GitHub Actions API returned a non-object response")
        return body, link

    def _next_link(self, link_header: str | None) -> str | None:
        if not link_header:
            return None
        for target, relation in re.findall(r'<([^>]+)>;\s*rel="([^"]+)"', link_header):
            if relation == "next":
                self._assert_api_origin(target)
                return target
        return None

    def list_baseline_artifacts(self, repository: str) -> list[Mapping[str, Any]]:
        """Follow all filtered pages so a newer invalid artifact cannot hide an older valid one."""

        repository_path = urllib.parse.quote(repository, safe="/")
        query = urllib.parse.urlencode({"name": ARTIFACT_NAME, "per_page": 100})
        url = f"{self._api_url}/repos/{repository_path}/actions/artifacts?{query}"
        artifacts: list[Mapping[str, Any]] = []
        while url:
            payload, link_header = self._json_response(url)
            page = payload.get("artifacts")
            if not isinstance(page, list) or not all(isinstance(item, dict) for item in page):
                raise ApiError("artifact list response has an invalid artifacts array")
            artifacts.extend(page)
            url = self._next_link(link_header)
        return artifacts

    def get_run(self, repository: str, run_id: int) -> Mapping[str, Any]:
        """Retrieve the independent workflow-run evidence record for a candidate."""

        repository_path = urllib.parse.quote(repository, safe="/")
        payload, _ = self._json_response(
            f"{self._api_url}/repos/{repository_path}/actions/runs/{run_id}"
        )
        return payload

    def download_archive(self, artifact: Mapping[str, Any]) -> bytes:
        """Download an artifact without forwarding the API token to its signed redirect URL."""

        url = require_nonempty_string(
            artifact.get("archive_download_url"), "artifact archive_download_url", CandidateRejected
        )
        self._assert_api_origin(url)
        request = urllib.request.Request(url, headers=self._api_headers())
        opener = urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(request, timeout=30) as response:
                return read_bounded_archive_response(response)
        except urllib.error.HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                raise ApiError(f"cannot start artifact download: {error}") from error
            location = error.headers.get("Location")
        if not location:
            raise ApiError("artifact download redirect did not include a location")
        destination = urllib.parse.urlparse(location)
        if destination.scheme != "https" or not destination.netloc:
            raise ApiError("artifact download redirect was not HTTPS")
        anonymous_request = urllib.request.Request(
            location,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "pigloros-benchmark-comparator",
            },
        )
        try:
            with urllib.request.urlopen(anonymous_request, timeout=30) as response:
                return read_bounded_archive_response(response)
        except (urllib.error.URLError, urllib.error.HTTPError) as error:
            raise ApiError(f"cannot download artifact archive: {error}") from error


def validate_current_identity(
    manifest: Mapping[str, Any], identity: ExpectedIdentity
) -> None:
    """Ensure the PR's own manifest belongs to this workflow and repository."""

    if manifest.get("repository") != identity.repository:
        raise EvidenceError("current manifest repository does not match this workflow")
    if manifest.get("repository_id") != identity.repository_id:
        raise EvidenceError("current manifest repository_id does not match this workflow")
    if manifest.get("workflow_id") != identity.workflow_id:
        raise EvidenceError("current manifest workflow_id does not match this workflow")
    if manifest.get("workflow_path") != identity.workflow_path:
        raise EvidenceError("current manifest workflow_path does not match this workflow")
    if manifest.get("event") != "pull_request":
        raise EvidenceError("comparison is only valid for a pull_request current manifest")


def compare(arguments: argparse.Namespace) -> int:
    """Select a trusted baseline, then render a non-gating comparison result."""

    current_dataset = load_csv(arguments.csv)
    current_manifest = load_manifest(arguments.manifest, "current")
    validate_manifest(current_manifest, current_dataset, "current")
    identity = ExpectedIdentity(
        repository=arguments.repository,
        repository_id=arguments.repository_id,
        workflow_id=arguments.workflow_id,
        workflow_path=arguments.workflow_path,
        default_branch=arguments.default_branch,
    )
    validate_current_identity(current_manifest, identity)
    now = utc_now()
    client = GitHubActionsClient(arguments.token, arguments.api_url)
    try:
        artifacts = client.list_baseline_artifacts(identity.repository)
        baseline, rejections = select_newest_baseline(
            artifacts,
            fetch_run=lambda run_id: client.get_run(identity.repository, run_id),
            fetch_archive=client.download_archive,
            current_manifest=current_manifest,
            identity=identity,
            now=now,
        )
    except ApiError as error:
        baseline = None
        rejections = (str(error),)

    if baseline is None:
        if rejections:
            reason = f"no compatible trusted baseline ({len(rejections)} candidate(s) rejected)"
        else:
            reason = "no trusted main baseline artifact exists yet"
        append_summary(arguments.summary, render_unavailable_summary(reason))
        print(f"::notice title=MemoryStore benchmark comparison::{reason}.")
        return 0

    try:
        rows = compare_datasets(baseline.dataset, current_dataset)
    except CandidateRejected as error:
        reason = f"selected baseline could not be compared: {error}"
        append_summary(arguments.summary, render_unavailable_summary(reason))
        print(f"::notice title=MemoryStore benchmark comparison::{reason}.")
        return 0

    append_summary(arguments.summary, render_comparison_summary(baseline, rows))
    for row in rows:
        if row.warning:
            print(warning_annotation(row, str(baseline.manifest["head_sha"])))
    print("Advisory MemoryStore benchmark comparison completed.")
    return 0


def positive_cli_integer(value: str) -> int:
    """Argparse adapter for metadata IDs that must remain positive integers."""

    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"expected integer, got {value!r}") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    """Build the narrow command-line interface used by the workflow."""

    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    write = subcommands.add_parser("write-manifest", help="validate current CSV and write metadata")
    write.add_argument("--csv", type=pathlib.Path, required=True)
    write.add_argument("--output", type=pathlib.Path, required=True)
    write.add_argument("--architecture", required=True)
    write.add_argument("--event", required=True)
    write.add_argument("--head-branch", required=True)
    write.add_argument("--head-repository-id", type=positive_cli_integer, required=True)
    write.add_argument("--head-sha", required=True)
    write.add_argument("--repository", required=True)
    write.add_argument("--repository-id", type=positive_cli_integer, required=True)
    write.add_argument("--run-attempt", type=positive_cli_integer, required=True)
    write.add_argument("--runner-image", required=True)
    write.add_argument("--toolchain", required=True)
    write.add_argument("--workflow-id", type=positive_cli_integer, required=True)
    write.add_argument("--workflow-path", default=WORKFLOW_PATH)
    write.add_argument("--workflow-run-id", type=positive_cli_integer, required=True)
    write.set_defaults(handler=write_manifest)

    comparison = subcommands.add_parser("compare", help="compare a PR CSV with trusted main evidence")
    comparison.add_argument("--csv", type=pathlib.Path, required=True)
    comparison.add_argument("--manifest", type=pathlib.Path, required=True)
    comparison.add_argument("--summary", type=pathlib.Path, required=True)
    comparison.add_argument("--token", required=True)
    comparison.add_argument("--repository", required=True)
    comparison.add_argument("--repository-id", type=positive_cli_integer, required=True)
    comparison.add_argument("--workflow-id", type=positive_cli_integer, required=True)
    comparison.add_argument("--workflow-path", default=WORKFLOW_PATH)
    comparison.add_argument("--default-branch", default=DEFAULT_BRANCH)
    comparison.add_argument("--api-url", default="https://api.github.com")
    comparison.set_defaults(handler=compare)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the selected operation and turn current-evidence errors into failures."""

    arguments = build_parser().parse_args(argv)
    try:
        return arguments.handler(arguments)
    except EvidenceError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
