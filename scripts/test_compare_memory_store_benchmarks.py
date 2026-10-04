#!/usr/bin/env python3
"""Deterministic contract tests for advisory MemoryStore benchmark comparison."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
import zipfile
from collections.abc import Callable
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "compare_memory_store_benchmarks.py"
SPEC = importlib.util.spec_from_file_location("compare_memory_store_benchmarks", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
COMPARATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMPARATOR
SPEC.loader.exec_module(COMPARATOR)


NOW = COMPARATOR.datetime.datetime(2026, 10, 4, 0, 0, tzinfo=COMPARATOR.datetime.timezone.utc)
IDENTITY = COMPARATOR.ExpectedIdentity(
    repository="arceushui/pigloros",
    repository_id=1_301_576_583,
    workflow_id=350_682_006,
    workflow_path=COMPARATOR.WORKFLOW_PATH,
)


def csv_text(
    values_by_key: dict[Any, list[int]] | None = None,
    *,
    alter_row: Callable[[list[str], Any, int], None] | None = None,
) -> str:
    """Build a complete V1 raw CSV, optionally mutating a copied row."""

    rows = [list(COMPARATOR.CSV_HEADER)]
    values_by_key = values_by_key or {}
    for key_index, key in enumerate(COMPARATOR.EXPECTED_INVENTORY):
        values = values_by_key.get(
            key,
            [1_000 + (key_index * 100) + sample for sample in range(COMPARATOR.SAMPLE_COUNT)],
        )
        if len(values) != COMPARATOR.SAMPLE_COUNT:
            raise ValueError("fixture must contain exactly ten values per key")
        for sample, value in enumerate(values):
            row = [key.scenario, str(key.cardinality), str(sample), str(value)]
            if alter_row is not None:
                alter_row(row, key, sample)
            rows.append(row)
    return "\n".join(",".join(row) for row in rows) + "\n"


def dataset(
    values_by_key: dict[Any, list[int]] | None = None,
) -> Any:
    """Parse one deterministic complete fixture into the public dataset seam."""

    return COMPARATOR.parse_benchmark_csv(csv_text(values_by_key))


def manifest(
    data: Any,
    *,
    event: str = "pull_request",
    head_branch: str = "feature/benchmark",
    head_sha: str = "f" * 40,
    run_attempt: int = 1,
    workflow_run_id: int = 101,
    toolchain: str = "rustc 1.97.1",
    runner_image: str = "ubuntu-24.04-20261001",
    architecture: str = "x86_64",
    created_at: Any = NOW,
) -> dict[str, Any]:
    """Create a fully valid manifest, with controlled provenance variations."""

    return COMPARATOR.make_manifest(
        data,
        architecture=architecture,
        event=event,
        head_branch=head_branch,
        head_repository_id=IDENTITY.repository_id,
        head_sha=head_sha,
        repository=IDENTITY.repository,
        repository_id=IDENTITY.repository_id,
        run_attempt=run_attempt,
        runner_image=runner_image,
        toolchain=toolchain,
        workflow_id=IDENTITY.workflow_id,
        workflow_path=IDENTITY.workflow_path,
        workflow_run_id=workflow_run_id,
        created_at=created_at,
    )


def artifact(
    artifact_id: int,
    *,
    run_id: int,
    sha: str,
    created_at: Any = NOW,
    expires_at: Any = NOW + COMPARATOR.datetime.timedelta(days=90),
    head_branch: str = "main",
    repository_id: int = IDENTITY.repository_id,
    head_repository_id: int = IDENTITY.repository_id,
    expired: bool = False,
) -> dict[str, Any]:
    """Build the relevant GitHub artifact-list response shape."""

    def iso(value: Any) -> str:
        return value.isoformat().replace("+00:00", "Z")

    return {
        "id": artifact_id,
        "name": COMPARATOR.ARTIFACT_NAME,
        "expired": expired,
        "created_at": iso(created_at),
        "expires_at": iso(expires_at),
        "archive_download_url": f"https://api.github.com/artifacts/{artifact_id}/zip",
        "workflow_run": {
            "id": run_id,
            "repository_id": repository_id,
            "head_repository_id": head_repository_id,
            "head_branch": head_branch,
            "head_sha": sha,
        },
    }


def workflow_run(
    run_id: int,
    *,
    sha: str,
    event: str = "push",
    status: str = "completed",
    conclusion: str = "success",
    workflow_id: int = IDENTITY.workflow_id,
    path: str = IDENTITY.workflow_path,
    head_branch: str = "main",
    run_attempt: int = 1,
    repository_id: int = IDENTITY.repository_id,
    head_repository_id: int = IDENTITY.repository_id,
) -> dict[str, Any]:
    """Build the independent GitHub workflow-run response shape."""

    return {
        "id": run_id,
        "event": event,
        "status": status,
        "conclusion": conclusion,
        "workflow_id": workflow_id,
        "path": path,
        "head_branch": head_branch,
        "head_sha": sha,
        "run_attempt": run_attempt,
        "repository": {"id": repository_id},
        "head_repository": {"id": head_repository_id},
    }


def archive_bytes(manifest_data: dict[str, Any], data: Any) -> bytes:
    """Build the minimal trusted artifact ZIP without extracting to disk."""

    csv_contents = csv_text(
        {
            key: list(data.samples_by_key[key])
            for key in COMPARATOR.EXPECTED_INVENTORY
        }
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as zipped:
        zipped.writestr(f"artifacts/{COMPARATOR.MANIFEST_FILE}", json.dumps(manifest_data))
        zipped.writestr("artifacts/memory-erasure-benchmark.csv", csv_contents)
    return output.getvalue()


class BenchmarkCsvTests(unittest.TestCase):
    """Tests for the strict current-output parser and deterministic statistics."""

    def test_valid_csv_uses_upper_median_and_p95(self) -> None:
        values = [8, 1, 7, 2, 6, 3, 5, 4, 10, 9]
        key = COMPARATOR.EXPECTED_INVENTORY[0]
        parsed = dataset({key: values})

        self.assertEqual(parsed.statistics(key).median_ns, 6)
        self.assertEqual(parsed.statistics(key).p95_ns, 10)

    def test_rejects_wrong_header(self) -> None:
        broken = csv_text().replace(
            "scenario,cardinality,sample,elapsed_nanos",
            "scenario,cardinality,sample,elapsed",
            1,
        )

        with self.assertRaisesRegex(COMPARATOR.EvidenceError, "header"):
            COMPARATOR.parse_benchmark_csv(broken)

    def test_rejects_malformed_duplicate_and_missing_rows(self) -> None:
        with self.subTest("empty"):
            with self.assertRaisesRegex(COMPARATOR.EvidenceError, "empty"):
                COMPARATOR.parse_benchmark_csv("")

        with self.subTest("malformed integer"):
            broken = csv_text(
                alter_row=lambda row, _key, sample: row.__setitem__(3, "1.2")
                if sample == 0
                else None
            )
            with self.assertRaisesRegex(COMPARATOR.EvidenceError, "unsigned decimal"):
                COMPARATOR.parse_benchmark_csv(broken)

        with self.subTest("duplicate sample"):
            broken = csv_text(
                alter_row=lambda row, _key, sample: row.__setitem__(2, "0")
                if sample == 1
                else None
            )
            with self.assertRaisesRegex(COMPARATOR.EvidenceError, "duplicate sample"):
                COMPARATOR.parse_benchmark_csv(broken)

        with self.subTest("missing scenario"):
            lines = csv_text().splitlines()
            missing = COMPARATOR.EXPECTED_INVENTORY[-1]
            kept = [
                line
                for line in lines
                if not line.startswith(f"{missing.scenario},{missing.cardinality},")
            ]
            with self.assertRaisesRegex(COMPARATOR.EvidenceError, "inventory mismatch"):
                COMPARATOR.parse_benchmark_csv("\n".join(kept) + "\n")

        with self.subTest("missing sample index"):
            lines = csv_text().splitlines()
            missing = COMPARATOR.EXPECTED_INVENTORY[0]
            kept = [
                line
                for line in lines
                if line != f"{missing.scenario},{missing.cardinality},9,1009"
            ]
            with self.assertRaisesRegex(COMPARATOR.EvidenceError, "exactly 10 samples"):
                COMPARATOR.parse_benchmark_csv("\n".join(kept) + "\n")

    def test_rejects_added_scenario(self) -> None:
        broken = csv_text() + "unexpected,1,0,3\n"

        with self.assertRaisesRegex(COMPARATOR.EvidenceError, "unexpected scenario"):
            COMPARATOR.parse_benchmark_csv(broken)


class ComparisonArithmeticTests(unittest.TestCase):
    """Tests for exact warning boundaries and diagnostic percentage output."""

    def uniform_dataset(self, value: int) -> Any:
        return dataset(
            {
                key: [value] * COMPARATOR.SAMPLE_COUNT
                for key in COMPARATOR.EXPECTED_INVENTORY
            }
        )

    def test_exactly_ten_percent_does_not_warn_but_just_over_does(self) -> None:
        baseline = self.uniform_dataset(100)
        exact = self.uniform_dataset(110)
        over = self.uniform_dataset(111)

        self.assertFalse(any(row.warning for row in COMPARATOR.compare_datasets(baseline, exact)))
        self.assertTrue(all(row.warning for row in COMPARATOR.compare_datasets(baseline, over)))

    def test_speedup_and_large_integer_arithmetic_remain_advisory(self) -> None:
        baseline = self.uniform_dataset(10**100)
        speedup = self.uniform_dataset(10**99)
        regression = self.uniform_dataset((10**100 * 11) // 10 + 1)

        self.assertFalse(any(row.warning for row in COMPARATOR.compare_datasets(baseline, speedup)))
        self.assertTrue(all(row.warning for row in COMPARATOR.compare_datasets(baseline, regression)))
        self.assertEqual(COMPARATOR.percentage_delta(100, 90), "-10.00%")
        self.assertEqual(COMPARATOR.percentage_delta(100, 110), "+10.00%")

    def test_zero_baseline_is_not_a_percentage_claim(self) -> None:
        zero = self.uniform_dataset(0)
        current = self.uniform_dataset(1)

        with self.assertRaisesRegex(COMPARATOR.CandidateRejected, "zero"):
            COMPARATOR.compare_datasets(zero, current)
        self.assertEqual(COMPARATOR.percentage_delta(0, 1), "unavailable")


class ManifestTests(unittest.TestCase):
    """Tests for versioned evidence manifest creation and validation."""

    def test_manifest_binds_inventory_runner_and_metadata(self) -> None:
        data = dataset()
        evidence = manifest(data)

        created_at = COMPARATOR.validate_manifest(evidence, data, "current")

        self.assertEqual(created_at, NOW)
        self.assertEqual(evidence["scenario_inventory"], COMPARATOR.inventory_as_json())
        self.assertEqual(evidence["runner_fingerprint"], "ubuntu-24.04-20261001|x86_64")

    def test_manifest_rejects_schema_and_fingerprint_drift(self) -> None:
        data = dataset()
        schema_drift = manifest(data)
        schema_drift["schema_version"] = 2
        with self.assertRaisesRegex(COMPARATOR.EvidenceError, "schema_version"):
            COMPARATOR.validate_manifest(schema_drift, data, "current")

        fingerprint_drift = manifest(data)
        fingerprint_drift["runner_fingerprint"] = "other"
        with self.assertRaisesRegex(COMPARATOR.EvidenceError, "runner_fingerprint"):
            COMPARATOR.validate_manifest(fingerprint_drift, data, "current")

    def test_manifest_parser_rejects_unknown_fields(self) -> None:
        data = manifest(dataset())
        data["future"] = True

        with self.assertRaisesRegex(COMPARATOR.EvidenceError, "incompatible schema"):
            COMPARATOR.load_manifest_text(json.dumps(data), "baseline")

    def test_write_manifest_cli_rejects_bad_current_csv_before_artifact_upload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = pathlib.Path(directory)
            raw_csv = temp / "benchmark.csv"
            raw_csv.write_text("wrong\n", encoding="utf-8")
            output = temp / "manifest.json"
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = COMPARATOR.main(
                    [
                        "write-manifest",
                        "--csv",
                        str(raw_csv),
                        "--output",
                        str(output),
                        "--architecture",
                        "x86_64",
                        "--event",
                        "pull_request",
                        "--head-branch",
                        "feature",
                        "--head-repository-id",
                        str(IDENTITY.repository_id),
                        "--head-sha",
                        "f" * 40,
                        "--repository",
                        IDENTITY.repository,
                        "--repository-id",
                        str(IDENTITY.repository_id),
                        "--run-attempt",
                        "1",
                        "--runner-image",
                        "ubuntu",
                        "--toolchain",
                        "rustc",
                        "--workflow-id",
                        str(IDENTITY.workflow_id),
                        "--workflow-run-id",
                        "1",
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertFalse(output.exists())


class BaselineSelectionTests(unittest.TestCase):
    """Tests for trust boundary validation and newest-valid deterministic selection."""

    def setUp(self) -> None:
        self.current_data = dataset()
        self.current_manifest = manifest(self.current_data)
        self.baseline_data = dataset()

    def valid_candidate(
        self,
        artifact_id: int,
        *,
        run_id: int,
        sha: str,
        created_at: Any = NOW,
    ) -> tuple[dict[str, Any], dict[str, Any], bytes]:
        baseline_manifest = manifest(
            self.baseline_data,
            event="push",
            head_branch="main",
            head_sha=sha,
            workflow_run_id=run_id,
            created_at=created_at,
        )
        return (
            artifact(artifact_id, run_id=run_id, sha=sha, created_at=created_at),
            workflow_run(run_id, sha=sha),
            archive_bytes(baseline_manifest, self.baseline_data),
        )

    def select(
        self,
        artifacts: list[dict[str, Any]],
        runs: dict[int, dict[str, Any]],
        archives: dict[int, bytes],
    ) -> tuple[Any, tuple[str, ...]]:
        return COMPARATOR.select_newest_baseline(
            artifacts,
            fetch_run=lambda run_id: runs[run_id],
            fetch_archive=lambda candidate: archives[candidate["id"]],
            current_manifest=self.current_manifest,
            identity=IDENTITY,
            now=NOW,
        )

    def test_chooses_newest_valid_candidate_after_rejecting_newer_untrusted_run(self) -> None:
        newest, newest_run, newest_archive = self.valid_candidate(
            20, run_id=200, sha="2" * 40, created_at=NOW
        )
        newest_run["event"] = "pull_request"
        older, older_run, older_archive = self.valid_candidate(
            10,
            run_id=100,
            sha="1" * 40,
            created_at=NOW - COMPARATOR.datetime.timedelta(hours=1),
        )

        selected, rejections = self.select(
            [older, newest],
            {100: older_run, 200: newest_run},
            {10: older_archive, 20: newest_archive},
        )

        self.assertIsNotNone(selected)
        self.assertEqual(selected.artifact_id, 10)
        self.assertEqual(len(rejections), 1)
        self.assertIn("event is not trusted", rejections[0])

    def test_rejects_stale_expired_foreign_and_wrong_workflow_candidates(self) -> None:
        stale, stale_run, stale_archive = self.valid_candidate(
            1,
            run_id=101,
            sha="1" * 40,
            created_at=NOW - COMPARATOR.FRESHNESS_LIMIT - COMPARATOR.datetime.timedelta(seconds=1),
        )
        expired, expired_run, expired_archive = self.valid_candidate(2, run_id=102, sha="2" * 40)
        expired["expired"] = True
        foreign, foreign_run, foreign_archive = self.valid_candidate(3, run_id=103, sha="3" * 40)
        foreign["workflow_run"]["head_repository_id"] = 99
        wrong_workflow, wrong_workflow_run, wrong_workflow_archive = self.valid_candidate(
            4, run_id=104, sha="4" * 40
        )
        wrong_workflow_run["workflow_id"] = 1

        selected, rejections = self.select(
            [stale, expired, foreign, wrong_workflow],
            {101: stale_run, 102: expired_run, 103: foreign_run, 104: wrong_workflow_run},
            {1: stale_archive, 2: expired_archive, 3: foreign_archive, 4: wrong_workflow_archive},
        )

        self.assertIsNone(selected)
        self.assertEqual(len(rejections), 4)
        self.assertTrue(any("freshness" in reason for reason in rejections))
        self.assertTrue(any("expired" in reason for reason in rejections))
        self.assertTrue(any("head repository" in reason for reason in rejections))
        self.assertTrue(any("workflow ID" in reason for reason in rejections))

    def test_rejects_manifest_run_attempt_and_runner_mismatches(self) -> None:
        bad_attempt, attempt_run, attempt_archive = self.valid_candidate(1, run_id=101, sha="1" * 40)
        bad_runner, runner_run, runner_archive = self.valid_candidate(2, run_id=102, sha="2" * 40)

        with zipfile.ZipFile(io.BytesIO(attempt_archive)) as zipped:
            attempt_manifest = json.loads(zipped.read(f"artifacts/{COMPARATOR.MANIFEST_FILE}"))
        attempt_manifest["run_attempt"] = 2
        attempt_archive = archive_bytes(attempt_manifest, self.baseline_data)

        with zipfile.ZipFile(io.BytesIO(runner_archive)) as zipped:
            runner_manifest = json.loads(zipped.read(f"artifacts/{COMPARATOR.MANIFEST_FILE}"))
        runner_manifest["runner_image"] = "different-runner"
        runner_manifest["runner_fingerprint"] = "different-runner|x86_64"
        runner_archive = archive_bytes(runner_manifest, self.baseline_data)

        selected, rejections = self.select(
            [bad_attempt, bad_runner],
            {101: attempt_run, 102: runner_run},
            {1: attempt_archive, 2: runner_archive},
        )

        self.assertIsNone(selected)
        self.assertTrue(any("run_attempt" in reason for reason in rejections))
        self.assertTrue(any("runner_image" in reason for reason in rejections))

    def test_rejects_all_remaining_run_and_manifest_provenance_failures(self) -> None:
        cases = {
            "non-main": lambda candidate, run, evidence: candidate["workflow_run"].update(
                {"head_branch": "topic"}
            ),
            "manual-dispatch": lambda candidate, run, evidence: run.update(
                {"event": "workflow_dispatch"}
            ),
            "incomplete": lambda candidate, run, evidence: run.update({"status": "in_progress"}),
            "unsuccessful": lambda candidate, run, evidence: run.update({"conclusion": "failure"}),
            "wrong-workflow-path": lambda candidate, run, evidence: run.update(
                {"path": ".github/workflows/other.yml"}
            ),
            "schema-mismatch": lambda candidate, run, evidence: evidence.update(
                {"schema_version": 2}
            ),
            "toolchain-mismatch": lambda candidate, run, evidence: evidence.update(
                {"toolchain": "different rustc"}
            ),
            "manifest-run-mismatch": lambda candidate, run, evidence: evidence.update(
                {"head_sha": "e" * 40}
            ),
        }
        expected_fragments = {
            "non-main": "did not run from main",
            "manual-dispatch": "event is not trusted",
            "incomplete": "did not complete successfully",
            "unsuccessful": "did not complete successfully",
            "wrong-workflow-path": "wrong workflow path",
            "schema-mismatch": "schema_version",
            "toolchain-mismatch": "toolchain",
            "manifest-run-mismatch": "head_sha",
        }

        for name, mutate in cases.items():
            with self.subTest(name=name):
                candidate, run, _archive = self.valid_candidate(1, run_id=101, sha="1" * 40)
                evidence = manifest(
                    self.baseline_data,
                    event="push",
                    head_branch="main",
                    head_sha="1" * 40,
                    workflow_run_id=101,
                )
                mutate(candidate, run, evidence)
                selected, rejections = self.select(
                    [candidate], {101: run}, {1: archive_bytes(evidence, self.baseline_data)}
                )

                self.assertIsNone(selected)
                self.assertIn(expected_fragments[name], rejections[0])

    def test_rejects_duplicate_archive_members(self) -> None:
        candidate, run, archive = self.valid_candidate(1, run_id=101, sha="1" * 40)
        duplicated = io.BytesIO()
        with zipfile.ZipFile(duplicated, "w") as zipped:
            with zipfile.ZipFile(io.BytesIO(archive)) as source:
                zipped.writestr(
                    f"first/{COMPARATOR.MANIFEST_FILE}",
                    source.read(f"artifacts/{COMPARATOR.MANIFEST_FILE}"),
                )
                zipped.writestr(
                    f"second/{COMPARATOR.MANIFEST_FILE}",
                    source.read(f"artifacts/{COMPARATOR.MANIFEST_FILE}"),
                )
                zipped.writestr(
                    "artifacts/memory-erasure-benchmark.csv",
                    source.read("artifacts/memory-erasure-benchmark.csv"),
                )

        selected, rejections = self.select(
            [candidate], {101: run}, {1: duplicated.getvalue()}
        )

        self.assertIsNone(selected)
        self.assertIn("duplicate", rejections[0])


class SummaryTests(unittest.TestCase):
    """Tests for job-summary completeness and supported warning shape."""

    def test_summary_contains_every_delta_and_warning_annotation(self) -> None:
        baseline_data = dataset(
            {
                key: [100] * COMPARATOR.SAMPLE_COUNT
                for key in COMPARATOR.EXPECTED_INVENTORY
            }
        )
        current_data = dataset(
            {
                key: [111 if index == 0 else 90] * COMPARATOR.SAMPLE_COUNT
                for index, key in enumerate(COMPARATOR.EXPECTED_INVENTORY)
            }
        )
        baseline_manifest = manifest(
            baseline_data,
            event="push",
            head_branch="main",
            head_sha="a" * 40,
            workflow_run_id=300,
        )
        selected = COMPARATOR.SelectedBaseline(
            artifact_id=400,
            artifact_created_at=NOW,
            dataset=baseline_data,
            manifest=baseline_manifest,
        )
        rows = COMPARATOR.compare_datasets(baseline_data, current_data)
        summary = COMPARATOR.render_comparison_summary(selected, rows)

        for key in COMPARATOR.EXPECTED_INVENTORY:
            self.assertIn(f"| {key.scenario} | {key.cardinality} |", summary)
        self.assertEqual(sum("warning (>10% slower)" in line for line in summary.splitlines()), 1)
        warning = COMPARATOR.warning_annotation(rows[0], "a" * 40)
        self.assertTrue(warning.startswith("::warning title=MemoryStore benchmark regression::"))
        self.assertIn("+11.00%", warning)

    def test_unavailable_summary_is_explicit_and_non_gating(self) -> None:
        summary = COMPARATOR.render_unavailable_summary("no valid artifact")

        self.assertIn("Comparison unavailable", summary)
        self.assertIn("does not affect merge eligibility", summary)


if __name__ == "__main__":
    unittest.main()
