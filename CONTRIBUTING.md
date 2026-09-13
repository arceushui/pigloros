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

CI is deliberately staged. A broken pull request receives useful feedback
before it can occupy the expensive runners, and the main staged workflow uses
no more than eight heavy runners at once.

```mermaid
flowchart TD
    S["ci_change_scope"] --> P["Fast preflight"]
    P --> C["Core: four parallel jobs"]
    C --> R["cargo-crap"]
    R --> N["Normal checks: at most eight runners"]
    N --> M["Mutation: at most eight shards"]
    M --> A["ASan: five shards"]
    A --> G["ci-gate"]
    P -. "failure" .-> X["Stop downstream work"]
    C -. "failure" .-> X
    N -. "failure" .-> X
    M -. "failure" .-> X
```

### Stage 1: fast preflight

Pull requests run Trunk in its native diff mode before Cargo-heavy work. The
same stage validates pinned workflow dependencies and the Linux/non-Linux
conformance boundaries.

```mermaid
flowchart LR
    S["Trusted scope"] --> T["Trunk changed-file check"]
    S --> P["Pinned workflow policy"]
    S --> F["Conformance fixtures"]
    S --> N["Non-Linux boundary"]
    T --> G["preflight-gate"]
    P --> G
    F --> G
    N --> G
```

The standalone `trunk-check.yml` workflow performs the full-repository Trunk
audit on `main` and on schedule. It does not duplicate the pull-request diff
check.

### Stage 2: core quality gates

After preflight, the four core jobs start together:

```mermaid
flowchart TD
    P["preflight-gate"] --> F["fmt"]
    P --> T["full workspace test"]
    P --> C["clippy"]
    P --> V["one coverage execution"]
    F --> G["core-gate"]
    T --> G
    C --> G
    V --> G
```

The core checks and their immediate cargo-crap consumer mean:

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

There is no custom changed-test mapper. Cargo and nextest do not provide a
reliable affected-test mapping for this workspace, so the complete test suite
runs once. Coverage still checks changed production code first without a
second instrumented execution:

```mermaid
flowchart LR
    R["One llvm-cov report"] --> D["Changed production Rust: 99/99"]
    D --> W["Workspace: 99/99"]
    W --> L["Export LCOV"]
    L --> C["cargo-crap"]
```

### Stage 3: normal checks

`cargo-crap` starts only after every core job passes. Its success releases the
normal checks. Audit, deny, and shear share one runner; browser parity replaces
the completed WASM packaging job rather than adding another concurrent runner.
CodeQL is called from this stage instead of starting independently on every PR.

```mermaid
flowchart TD
    CR["cargo-crap"] --> D["rustdoc"]
    CR --> E["reference evaluator"]
    CR --> B["conformance bundles"]
    CR --> P["audit → deny → shear"]
    CR --> U["cargo-geiger"]
    CR --> X["Docker"]
    CR --> W["WASM package"]
    CR --> Q["CodeQL"]
    W --> BP["browser parity"]
    D --> G["standard-gate"]
    E --> G
    B --> G
    P --> G
    U --> G
    X --> G
    Q --> G
    BP --> G
```

`modules-structure` and `depgraph` are reporting-only jobs. They run after a
successful normal stage on `main`, not on pull requests.

### Stages 4 and 5: mutation, then ASan

Mutation and ASan cannot begin until every cheaper blocking gate passes.
Mutation is changed-line scoped and uses at most eight shards. It skips its own
workspace baseline because the identical stable full-workspace test command has
already passed in the core stage.

```mermaid
flowchart TD
    G["standard-gate"] --> R{"Mutation-relevant PR?"}
    R -->|"no"| S["Successful skip"]
    R -->|"yes"| M["Eight changed-line shards"]
    M --> MG["diff mutation testing"]
    S --> A["ASan"]
    MG --> A
```

ASan remains final. The previously dominant `bundle_contract_public` target is
split through nextest's native `slice:1/2` partitioning; the other test groups
remain unchanged.

```mermaid
flowchart LR
    M["Mutation passed or skipped"] --> P1["bundle-public 1/2"]
    M --> P2["bundle-public 2/2"]
    M --> C["bundle coverage"]
    M --> O["moat proof"]
    M --> R["remainder"]
    P1 --> G["asan-gate"]
    P2 --> G
    C --> G
    O --> G
    R --> G
```

All features, ignored tests, sanitizer instrumentation, leak detection, and the
negative leak control remain required. Partitioning changes wall-clock time,
not scope.

The `ci-gate` job is the single blocking fan-in for the main CI workflow.
Individual jobs are implementation details; branch protection should require
the aggregate check.

```mermaid
flowchart TD
    B1["preflight-gate"] --> G["ci-gate"]
    B2["core-gate"] --> G
    B3["standard-gate"] --> G
    B4["diff mutation testing"] --> G
    B5["asan-gate"] --> G
    G --> M{"All required results are success?"}
    M -->|"yes"| P["CI may be merged when other repository rules pass"]
    M -->|"no"| F["Pull request remains blocked"]
```

## Other workflows

The repository also has separate workflows for concerns that should not make
every pull request wait for a full stable-CI run:

```mermaid
flowchart LR
    PR["Pull request"] --> CI["Staged CI: Trunk, CodeQL, mutation, ASan"]
    PR --> FU["Targeted fuzzing when fuzz scope applies"]
    MAIN["main"] --> TC["Full Trunk audit"]
    MAIN --> RP["Module and dependency reports"]
    PERIODIC["main or schedule"] --> TS["ThreadSanitizer"]
    PERIODIC --> FU
    MANUAL["Manual dispatch"] --> DP["Deploy after explicit environment choice"]
```

Fuzzing, ThreadSanitizer, and deploy retain their own triggers and policies;
inspect their workflow files when a change touches those boundaries.

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
