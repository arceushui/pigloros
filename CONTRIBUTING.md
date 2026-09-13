# Contributing to PiglorOS

Thank you for contributing. PiglorOS is a Rust workspace with a deliberately
strict, hosted CI process. Keep changes focused, preserve the project
vocabulary in [`CONTEXT.md`](CONTEXT.md), and use the repository's existing
tools and policy checks before adding new automation.

The shortest path from a fresh checkout to a reviewable pull request is:

```mermaid
flowchart LR
    A["Read README and CONTEXT"] --> B["Create a task worktree"]
    B --> C["Enable versioned hooks"]
    C --> D["Make a focused change"]
    D --> E["Run the applicable existing checks"]
    E --> F["Commit and push"]
    F --> G["Open or update the pull request"]
    G --> H["Resolve required CI gates"]
```

## Start with the repository guidance

Read these files before making a change:

- [`README.md`](README.md) — project overview, workspace layout, and common commands.
- [`CONTEXT.md`](CONTEXT.md) — domain vocabulary and current product boundaries.
- [`AGENTS.md`](AGENTS.md) — worktree, tracker, coverage, and quality-gate rules.
- [`docs/test-policy.md`](docs/test-policy.md) — test, coverage, and change-risk policy.

Keep current contributor instructions in Git. Dated plans, execution notes,
and architectural decisions belong in the linked Redmine or Notion records,
not in a second copy of this guide.

## Set up an isolated worktree

The project uses one worktree per task. Do not make task changes directly on
`main`.

```bash
git fetch origin main
git worktree add ../pigloros-<task-name> -b <branch-name> origin/main
cd ../pigloros-<task-name>

# Enable the versioned pre-commit hook once per clone.
git config core.hooksPath .githooks

rustup show active-toolchain
```

The toolchain is pinned in `rust-toolchain.toml` and currently requires Rust
1.97.1 with rustfmt, clippy, and llvm-tools-preview. Keep secrets outside
version control; for example, verify private files with:

```bash
git check-ignore -- .secrets/ledger.key
```

The local hook is an early feedback mechanism. It does not replace the
hosted required checks.

## Make a focused change

Before editing, classify the change and identify its public seam. New crates,
plugins, binaries, durable public APIs, storage or security boundaries,
protocols, and coordinate models require an accepted ADR before implementation.
Tests should exercise public interfaces rather than implementation details.

Use the existing repository commands and policy tools. A one-off script that
duplicates a tool's coverage, lint, or policy behavior is not a substitute for
the configured gate.

The normal local entry point is:

```bash
./scripts/ci.sh
```

For a pull request, the coverage diff can be evaluated against the exact base
commit:

```bash
DIFF_COVERAGE_BASE=<pull-request-base-sha> ./scripts/ci.sh
```

The individual commands are also useful while iterating:

```bash
cargo fmt --all -- --check
cargo test --workspace --all-features --locked -- --include-ignored
cargo clippy --workspace --all-features --all-targets --locked -- \
  -D warnings -W clippy::pedantic
RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --all-features --locked \
  --summary-only --fail-under-lines 99 --fail-under-regions 99 \
  -- --include-ignored
```

See [`docs/test-policy.md`](docs/test-policy.md) for the rules behind these
commands. In particular, ignored tests must run, `coverage(off)` is test-only,
rustdoc `ignore` fences are not allowed, and production code must not be
exempted merely to satisfy coverage.

## How CI chooses its scope

The main CI workflow runs for pull requests, pushes to `main`, and manual
dispatches. Pull requests first run `ci_change_scope`. The trusted base
revision provides `.github/rust-scope.yml`, which keeps the decision about
whether a change affects Rust code out of the pull request's untrusted edits.

```mermaid
flowchart TD
    T["Pull request, main push, or manual run"] --> S["ci_change_scope"]
    S --> Q{"Rust-affecting path?"}
    Q -->|"yes"| R["Run the complete Rust blocking path"]
    Q -->|"no"| D["Skip Rust jobs successfully"]
    D --> L["Keep scope, Trunk, and CodeQL policy checks visible"]
    R --> G["ci-gate validates every blocking result"]
    L --> G
```

The documentation-only allowlist currently covers Markdown, MDX, AsciiDoc,
reStructuredText, `.agents/**`, and `docs/**`. Rust source, Cargo manifests,
the lockfile, toolchain files, scripts, workflows, fixtures, and unknown paths
are treated conservatively as Rust-affecting. A policy or workflow change
should therefore be expected to run the full gate set.

```mermaid
stateDiagram-v2
    [*] --> Unknown
    Unknown --> FullSuite: "Rust, Cargo, script, workflow, fixture, or unknown path"
    Unknown --> DocsOnly: "Every path is in the documentation allowlist"
    DocsOnly --> ScopeGate: "Scope job succeeds"
    FullSuite --> RustGates: "Scope job marks rust=true"
    ScopeGate --> [*]
    RustGates --> [*]: "ci-gate and required checks pass"
```

## Required CI sequence

For a Rust-affecting pull request, the first four high-signal quality gates
start in parallel after scope detection. `cargo-crap` waits for coverage, the
remaining Rust-dependent checks wait for that quality set, and ASan is last.
This keeps the gates independent while still preventing expensive downstream
work after a required prerequisite fails.

```mermaid
flowchart TD
    S["Rust scope"] --> F["fmt"]
    S --> T["test"]
    S --> C["clippy"]
    S --> V["coverage report"]
    V --> N["covgate: changed production Rust first"]
    N --> W["workspace floor: 99% lines and 99% regions"]
    W --> CR["cargo-crap"]
```

The gates mean:

1. `fmt` runs `cargo fmt --all -- --check`.
2. `test` checks the workspace with default features disabled and all
   features enabled, then runs all tests with `--include-ignored`. The test
   gate is workspace-wide; Cargo has no built-in changed-test selector.
3. `clippy` runs all targets with warnings denied and the repository's
   pedantic policy.
4. `coverage` performs one complete `cargo llvm-cov` run. `covgate` checks
   changed production Rust code first from that report, then the same report
   is checked against the full workspace 99% line and 99% region floor. The
   resulting LCOV is uploaded for the next gate.
5. `cargo-crap` consumes that LCOV and a trusted baseline. Existing function
   scores may not regress, and new functions must score at most 30.

This ordering makes independent failures visible together while preserving the
full workspace evidence. It does not lower any threshold or remove any test.

After `cargo-crap`, the remaining blocking checks can run:

```mermaid
flowchart TD
    CR["cargo-crap passed"] --> D["rustdoc"]
    CR --> E["reference evaluator release"]
    CR --> CF["conformance fixture validation"]
    CF --> CB["conformance bundle materialization"]
    CR --> P["platform checks"]
    CR --> A["cargo-audit"]
    CR --> Y["cargo-deny"]
    CR --> H["cargo-shear"]
    CR --> U["cargo-geiger"]
    CR --> X["Docker build and smoke test"]
    CR --> W["WASM and browser parity"]
    D --> AS["ASan shards"]
    E --> AS
    CB --> AS
    P --> AS
    A --> AS
    Y --> AS
    H --> AS
    U --> AS
    X --> AS
    W --> AS
    AS --> AG["asan-gate"]
```

ASan is intentionally the final expensive gate in `ci.yml`. It uses four
parallel shards after every blocking prerequisite succeeds, then `asan-gate`
requires all shards to pass. The sharding changes wall-clock time, not test
scope: all features, test targets, sanitizer instrumentation, and leak checks
remain required.

The `ci-gate` job is the single blocking fan-in for the main CI workflow.
Individual jobs are implementation details; branch protection should require
the aggregate check.

```mermaid
flowchart TD
    B1["fmt"] --> G["ci-gate"]
    B2["test"] --> G
    B3["clippy"] --> G
    B4["coverage"] --> G
    B5["cargo-crap"] --> G
    B6["security and dependency checks"] --> G
    B7["conformance checks"] --> G
    B8["Docker and WASM checks"] --> G
    B9["asan-gate"] --> G
    G --> M{"All required results are success?"}
    M -->|"yes"| P["CI may be merged when other repository rules pass"]
    M -->|"no"| F["Pull request remains blocked"]
```

`pinned-dependencies`, `modules-structure`, and `depgraph` are informational
reports in the main workflow. They are useful review artifacts but are not
substitutes for the blocking `ci-gate` result.

## Mutation testing is a separate expensive gate

The `mutation.yml` workflow is diff-scoped. It first classifies whether the
pull request contains mutation-relevant paths. Relevant changes get a complete
workspace test baseline, followed by eight changed-line mutation shards. The
separate `diff mutation testing` fan-in validates the baseline and every shard.

```mermaid
flowchart TD
    C["Classify changed paths"] --> R{"Mutation-relevant?"}
    R -->|"no"| S["Skip baseline and shards"]
    S --> G0["diff mutation testing: successful no-op"]
    R -->|"yes"| B["Full workspace baseline with ignored tests"]
    B --> M1["Mutation shard 1"]
    B --> M2["Mutation shard 2"]
    B --> M3["Mutation shard 3"]
    B --> M4["Mutation shards 4 through 8"]
    M1 --> G["diff mutation testing"]
    M2 --> G
    M3 --> G
    M4 --> G
    B --> G
    G --> O["Required mutation result"]
```

Mutation testing is not a replacement for coverage. A passing baseline proves
that the unmutated workspace is healthy; the shards then test whether changed
logic is observable through the existing test seams. Inspect the uploaded
shard report when a mutant survives or a watchdog times out.

## Other workflows

The repository also has separate workflows for concerns that should not make
every pull request wait for a full stable-CI run:

```mermaid
flowchart LR
    PR["Pull request"] --> TC["Trunk Check"]
    PR --> CQ["CodeQL when Rust scope applies"]
    PR --> FU["Targeted fuzzing when fuzz scope applies"]
    PR --> MU["Diff mutation testing"]
    MAIN["main or schedule"] --> TS["ThreadSanitizer"]
    MAIN --> FU
    MANUAL["Manual dispatch"] --> DP["Deploy after explicit environment choice"]
```

Trunk Check uses diff mode for pull requests and all-repository mode on the
scheduled and main-branch runs. CodeQL, fuzzing, ThreadSanitizer, and deploy
have their own triggers and policies; inspect their workflow files when a
change touches those boundaries.

## Pull request checklist

```mermaid
sequenceDiagram
    participant C as Contributor
    participant R as Repository
    participant A as GitHub Actions
    participant V as Reviewer

    C->>R: Push focused branch
    R->>A: Start scoped workflows
    A-->>C: Report gate results and artifacts
    C->>R: Push fixes if a gate fails
    R->>A: Cancel superseded run and start the new head
    A-->>V: Publish required aggregate checks
    V->>R: Review diff and evidence
    R-->>C: Merge only after required checks pass
```

Before requesting review, confirm:

- the change is on a task worktree and the branch is based on current `main`;
- the diff is focused and does not include secrets, generated noise, or
  unrelated formatting;
- public terminology matches [`CONTEXT.md`](CONTEXT.md);
- tests use public seams and ignored tests are not used to hide failures;
- documentation-only changes stay within the documentation scope when that is
  intentional;
- Rust-affecting changes include the relevant test, coverage, and policy
  evidence; and
- the pull request description explains any hosted-only or resource-dependent
  validation and links to the relevant artifacts.

When a hosted gate fails, fix the earliest meaningful failure first. Read the
job log and uploaded artifact before changing timeouts, shard counts, or
thresholds. A retry is useful for a known transient runner failure; it is not
evidence that a product or policy failure is resolved.

```mermaid
flowchart TD
    F["Required check fails"] --> E["Read the exact job log and artifact"]
    E --> K{"Failure class?"}
    K -->|"format or lint"| L["Run the pinned formatter or lint command"]
    K -->|"test"| T["Reproduce the affected workspace test with ignored tests included"]
    K -->|"coverage"| C["Inspect changed-code misses, then workspace summary"]
    K -->|"cargo-crap"| Q["Compare the trusted baseline and current LCOV"]
    K -->|"mutation or ASan"| X["Inspect shard output and sanitizer diagnostics"]
    K -->|"runner or transport"| R["Confirm external failure before retrying"]
    L --> P["Push the smallest corrective change"]
    T --> P
    C --> P
    Q --> P
    X --> P
    R --> P
    P --> A["Wait for the new head's checks"]
```

For the complete policy, including coverage attribution, trusted cargo-crap
baselines, hardware-dependent startup, and ASan scope, see
[`docs/test-policy.md`](docs/test-policy.md).
