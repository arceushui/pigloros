---
name: ci-verification
description: Verify PiglorOS hosted gates, investigate GitHub Actions failures, and change workflow scheduling or evidence production without weakening checks. Use for CI, mutation, sanitizer, cache, or workflow work; use rust-quality-gates for local Rust validation.
---

# CI Verification

Internal PiglorOS workflow. Read [hosted-gate lessons](references/hosted-gates.md)
before interpreting a hosted failure or editing a workflow. Read the current
workflow and its policy-test owners rather than inferring them from job names.

## Establish the evidence

Pin the PR head, run, job, trigger, and required status. Read the complete job
inventory, including all pages, and inspect authoritative logs before classifying
a failure. Distinguish check-run conclusions from status-context states, pending
dependencies from missing checks, and merge-ref evidence from head execution.

Read completed job logs while sibling jobs run; run completion and retry
eligibility are separate facts. Verify cancellation reached a terminal state
and inspect downstream fan-out before retrying a closed queue run. Retrieve raw
logs without truncation; an analyzer's successful execution does not mean its
findings are clean.

Classify compile/lint, behavior, coverage, mutation, metadata/transport, and
contract-review failures separately. Use `diagnosing-bugs` when a reproducible
bug investigation is needed; keep mechanical fixes narrow.

## Change the workflow

Map triggers, permissions, inputs, steps, artifacts, shard membership, and
aggregate checks. Preserve scope, pins, failure behavior, and branch protection.
Use existing policy tests for small invariants and adversarial fixtures for
evidence-producing execution graphs. Measure the actual bottleneck before tuning
caches, concurrency, or timeouts.

Before an Actions dependency bump, inventory exact-pin policy consumers and
reviewed evidence producers; update constrained pins only with their owning
contract. Verify parser/runtime versions, language edition, byte encoding, and
the final consumer's regex dialect. A wrapper's parser is not necessarily the
parser that executes the policy.

Profile only complete workloads: identify selected tests versus child-harness
summaries, verify the execution frontier, preserve raw samples, and compare
semantically identical cfg variants. An early-failing run cannot size the full
suite. Ensure diagnostic argument forwarding reaches the intended executable.

For mutation evidence, establish a passing unmutated baseline under the same
toolchain, features, and arguments, then classify every shard. For coverage,
inspect exact-head artifacts and changed mapped source. Validate workflow changes
in hosted PR execution; post-merge checks apply when merge is authorized.

## Pre-flight

- [ ] Requiredness, complete job inventory, revision, and raw logs are known.
- [ ] Tests, features, ignored tests, shard fan-in, and trust boundaries survive.
- [ ] Measurements support performance claims; timeouts do not hide defects.
- [ ] Hosted results and pending checks are reported separately from source review.
- [ ] No new merge permission is inferred from green checks.
