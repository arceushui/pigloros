---
name: rust-quality-gates
description: Validate PiglorOS Rust changes against formatting, tests, Clippy, and 99% line and region coverage. Use for Rust implementation or coverage closure; use ci-verification for hosted workflow behavior and failures.
---

# Rust Quality Gates

Internal PiglorOS workflow. Before editing Rust, read
[code-edit lessons](references/code-edits.md). Before instrumentation or a
coverage claim, read [coverage lessons](references/coverage.md).

Use the exact local commands and thresholds in [AGENTS.md](../../../AGENTS.md)
and [test policy](../../../docs/test-policy.md), including ignored tests. Respect
explicit local resource limits before starting Cargo or hooks; retain the same
thresholds when authorized hosted checks supply unavailable local evidence.

Before broad verification, budget retained normal, instrumented, and feature
build graphs, including the backing volume for a virtual disk. Bound build/test
concurrency, serialize coverage writers, and account for Cargo locks before
scheduling checks. Propagate no-build constraints to hooks, scripts, and reviewers;
use authorized hosted evidence without weakening required gates.

Tests must reach the public seam and cover new behavior. Remove unreachable new
code instead of exempting it. Preserve error semantics and typed assertions when
addressing LLVM region gaps; inspect mapped source before changing syntax.

Re-run applicable gates after a code change, including review fixes. Inspect each
exit code before committing or performing dependent mutations. A compiler failure
or missing artifact is missing evidence, never a coverage percentage.

## Pre-flight

- [ ] Changed Rust paths, public exports, feature configurations, and tests agree.
- [ ] Format, tests, lint, and coverage evidence identify the tested revision.
- [ ] Line and region floors remain 99%; changed mapped behavior is exercised.
- [ ] No production coverage exemption, lint suppression, or weakened error API.
- [ ] Claims name their file/behavior scope and any pending hosted evidence.
