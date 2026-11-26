---
name: rust-quality-gates
description: Verify PiglorOS Rust changes through hosted formatting, tests, Clippy, and 99% line and region coverage. Use for Rust implementation or coverage closure; use ci-verification for workflow diagnosis.
---

# Rust Quality Gates

Internal PiglorOS workflow. Before editing Rust, read
[code-edit lessons](references/code-edits.md). Before instrumentation or a
coverage claim, read [coverage lessons](references/coverage.md).

Follow the evidence mode in the reviewed checkout's [AGENTS.md](../../../AGENTS.md)
and [test policy](../../../docs/test-policy.md). PiglorOS uses hosted CI for
Cargo build, test, lint, coverage, and mutation evidence. Push the authorized
branch, then inspect the jobs and logs for its exact head. Manual local Cargo
is limited to `cargo generate-lockfile`; keep the versioned Git hooks, including
their configured format and Clippy checks. A user restriction that also covers
hooks must be resolved without bypassing them or claiming unexecuted checks.

Keep ignored tests and the 99% line and region floors in scope. Budget retained
normal, instrumented, and feature build graphs on the authorized runner, including
its backing volume. Bound build/test concurrency, serialize coverage writers,
and account for Cargo locks. Propagate execution constraints to scripts and
reviewers; resource pressure never permits weakening a gate.

Tests must reach the public seam and cover new behavior. Remove unreachable new
code instead of exempting it. Preserve error semantics and typed assertions when
addressing LLVM region gaps; inspect mapped source before changing syntax.

Use fresh hosted results after a code change, including review fixes. Inspect
permitted local checks and hook exit codes before dependent mutations; inspect
hosted results before declaring verification complete. A compiler failure or
missing artifact is missing evidence, never a coverage percentage.

## Pre-flight

- [ ] Changed Rust paths, public exports, feature configurations, and tests agree.
- [ ] Format, tests, lint, and coverage evidence identify the tested revision.
- [ ] Line and region floors remain 99%; changed mapped behavior is exercised.
- [ ] No production coverage exemption, lint suppression, or weakened error API.
- [ ] Claims name their file/behavior scope and any pending hosted evidence.
