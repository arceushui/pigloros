# Performance-regression warnings — research for Redmine #297

Canonical decision record: [ADR-070 — Advisory Performance Regression Evidence](https://redmine.piglor.com/projects/pigloros/wiki/ADR-070_Advisory_Performance_Regression_Evidence). This document remains the supporting research evidence; the Redmine ADR owns the decision and lifecycle.

## Recommendation

**Preserve the current dependency-free `memory_erasure` harness and add a small deterministic CSV comparator. Do not introduce Criterion or Gungraun for #297.**

The actual harness at [`memory_erasure.rs`](../../crates/pos-store/benches/memory_erasure.rs) intentionally uses only `std`: it runs ten raw `Instant` samples by default for each scenario/cardinality, writes `scenario,cardinality,sample,elapsed_nanos` CSV, and prints the median and p95. Its manifest has `harness = false` and no benchmark-framework dependency ([`pos-store/Cargo.toml`](../../crates/pos-store/Cargo.toml)). #297 should preserve this observable contract and compare the raw CSV with a reviewed, dependency-free comparator (for example, a Python-standard-library script with fixture tests).

Use the **latest successful `main` benchmark artifact** as the advisory baseline. The artifact must contain the unmodified CSV, stdout summary, a schema version, benchmark command, toolchain, runner fingerprint, commit SHA, and timestamps. A PR runs the same harness, selects a validated baseline, and emits a GitHub `::warning` annotation plus job summary; it exits successfully. This has a clear provenance boundary: artifacts are workflow outputs, whereas GitHub positions caches as reusable dependencies rather than workflow outputs. ([GitHub: artifacts vs. cache](https://docs.github.com/en/actions/concepts/workflows-and-actions/dependency-caching#artifacts-versus-dependency-caching), [GitHub warning annotations](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#setting-a-warning-message))

`latest successful main` means the newest non-expired artifact whose API metadata and embedded manifest show a repository-owned `main` run, known main SHA, successful benchmark job, and matching schema/fingerprint—not merely the newest similarly named upload. GitHub's artifact API exposes expiration plus workflow-run branch/SHA/repository metadata. ([GitHub artifact API](https://docs.github.com/en/rest/actions/artifacts))

## Why not a new benchmark framework

| Option | Fit for the current harness | Decision for #297 |
|---|---|---|
| Existing raw-CSV harness + deterministic comparator | Retains the measured end-to-end MemoryStore path, benchmark cardinalities, CSV evidence, and zero new Rust dependencies | **Adopt.** |
| Criterion.rs | Offers bootstrap estimates and comparison reports, but requires a new dev dependency and a different benchmark/output contract. Its own documentation says hosted CI virtualization is noisy enough that results should not be relied on. | **Do not add.** It does not solve GitHub-hosted noise and would add migration work without making an advisory 10-sample signal more trustworthy. |
| Gungraun (formerly iai-callgrind) | Measures deterministic instruction/cache behaviour under Valgrind tools such as Callgrind rather than the harness's wall-clock `Instant` durations; it needs Valgrind and its runner binary, so answers a different question with a distinct toolchain | **Do not add.** Consider separately only if the project deliberately wants instruction-count regression policy. ([Gungraun changelog](https://github.com/gungraun/gungraun/blob/main/CHANGELOG.md)) |
| Dedicated historical service / fixed self-hosted runner | Can improve long-term hardware consistency | Defer: it adds operational ownership, and GitHub warns that public forks can run dangerous code on self-hosted runners. ([GitHub runner-group security](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access)) |

Criterion remains useful background for a later, deliberate redesign: it uses bootstrap confidence intervals and comparison testing, but cautions that VM load can create apparent changes even when source did not change. That cautions against treating a framework addition as a noise cure. ([Criterion analysis](https://bheisler.github.io/criterion.rs/book/analysis.html), [Criterion CI FAQ](https://bheisler.github.io/criterion.rs/book/faq.html))

## Threshold and comparison policy

Retain the ticket's **10% advisory median threshold**. Replace the earlier 5% + 95%-CI suggestion: it is inappropriate as the initial policy for this harness.

- There are only ten samples for a scenario/cardinality. A bootstrap confidence interval can be calculated from them, but it cannot manufacture stability or reliable power from ten noisy hosted-runner observations.
- The harness's p95 at ten samples is its largest sorted observation (`ceil(10 × .95) - 1 = 9`): publish it for diagnosis, but do not use it to trigger warnings.
- A 5% trigger on GitHub-hosted wall-clock time is especially prone to false positives. Criterion documents VM/background-load variation; systems-benchmarking research likewise requires accounting for uncertainty and setup bias. ([Criterion CI FAQ](https://bheisler.github.io/criterion.rs/book/faq.html), [Kalibera & Jones, 2013](https://kar.kent.ac.uk/33611/), [Mytkowicz et al., 2009](https://sape.inf.usi.ch/publications/asplos09.html))

For each exact `(scenario, cardinality)` pair, the comparator sorts its ten integer-nanosecond values and computes the same upper median as the harness (`values[5]`). Use exact integer cross-multiplication—`pr_median_ns * 10 > baseline_median_ns * 11`—rather than floating-point arithmetic; equality at exactly 10% does not warn. A zero baseline is comparison-unavailable, not a percentage claim. The job summary always shows baseline/PR median, relative change when defined, baseline/PR p95, raw-sample count, baseline SHA/age, and runner fingerprint. This preserves the ticket's requested PR-median comparison without pretending that p95 or a ten-sample CI is a merge-quality statistic.

## Baseline, expiry, and security policy

1. A trusted `push` to `main` uploads a per-run artifact after the harness succeeds, retaining it for 90 days initially. Artifacts can set retention individually; deletion, expiry, or workflow-run deletion makes them unavailable. ([GitHub artifact retention](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/remove-workflow-artifacts), [official upload action](https://github.com/actions/upload-artifact))
2. A PR lists artifacts with only `actions: read`, selects newest valid creation time then artifact ID, validates API metadata and manifest, and rejects expired, foreign, non-`main`, stale (start with 14 days), schema-mismatched, or runner-fingerprint-mismatched results.
3. No valid baseline, added/removed scenario, or incompatible CSV is **comparison unavailable**, not a failure. Upload the PR evidence for review, but never promote PR data to a trusted baseline; only a fresh successful `main` run may do that.
4. Use ordinary `pull_request` with minimal `actions: read`/`contents: read` permissions. Fork PR tokens are normally read-only and have no secrets; do not use `pull_request_target`, and never pass a PR artifact to a trusted follow-up workflow. ([GitHub token permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions-for-the-github_token), [runner compromise guidance](https://docs.github.com/en/actions/concepts/security/compromised-runners))
5. Do not use an Actions cache as fallback. Cache readers restore contents as-is; forks can read default-branch caches, and GitHub documents cache-poisoning controls. ([GitHub cache security](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#cache-access-for-low-trust-workflow-triggers))

`main` publication races and concurrent PRs are acceptable for an advisory signal: select only completed validated artifacts and record the chosen SHA. A later PR may use a newer `main` baseline. If serializing the publisher, remember Actions concurrency constrains execution but does not guarantee start-order determinism. ([GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency))

The warning job must always finish successfully. Do not configure it as a required status in this phase; required checks block merges when they do not finish `successful`, `skipped`, or `neutral`, whereas annotations alone are advisory. ([GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging))

## Deterministic comparator tests

Test the parser, selector, and arithmetic with fixture CSV—not timing tests. Cover: exact header and ten distinct sample indices per pair; median/p95 agreement with the harness; equality at 10% (no warning) and just above it (warning); zero baselines and integer-overflow-safe ratio arithmetic; speedups; empty/duplicate/malformed rows; changed scenario/cardinality inventory; and rejected expired, foreign, non-main, stale, schema/fingerprint-mismatched, or PR-origin baselines. Also prove deterministic newest-artifact selection and that no PR candidate can overwrite or satisfy the trusted-baseline predicate.

## Phased rollout

1. **Observe now:** preserve the current command and ten-sample CSV; publish a 90-day trusted `main` artifact; use a 14-day freshness limit and the 10% median-only advisory warning.
2. **Calibrate for 4–8 weeks:** triage every warning; record baseline age, runner drift, and confirmation by a repeat run. Do not lower the threshold merely because a framework can calculate a CI.
3. **Reconsider only with evidence:** a 5% threshold, Criterion, or Gungraun needs a separately documented measurement goal, stable comparable environment, sufficient repetitions, and evidence that the current 10% warnings miss material regressions. A dedicated private runner remains the stronger route for a future hard wall-clock gate.
4. **Promote selectively:** add a separate required check only after stable hardware identity, an owner and triage/SLO, enough observations, low unexplained-warning rate, a reviewed threshold, and deterministic missing-baseline behaviour. Prefer an exact-PR-base or merge-queue baseline for that hard gate; keep hosted latest-`main` results advisory.

This preserves the harness intentionally built for the MemoryStore persistence path, gives #297 an auditable and maintainable signal, and avoids a new dependency whose statistical machinery cannot remove hosted-runner noise.
