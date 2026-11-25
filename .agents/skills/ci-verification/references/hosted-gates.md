# CI / GitHub Actions

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Every test type must run in CI — no local-only tests.** GitHub Actions (`.github/workflows/ci.yml`) is the single source of truth for what passes. When adding any test — unit test, integration test (`tests/` directory), doctest, or `#[ignore]`d test — verify that the `test` job's `cargo nextest run --workspace --all-features --locked --run-ignored all` (or, for doctests, its `cargo test --doc -- --include-ignored` step) actually executes it. `--run-ignored all` / `--include-ignored` is mandatory so `#[ignore]` cannot silently skip. If you write an integration test that lives in `tests/`, it MUST be picked up by the workspace test job; if it isn't, the test is dead and the CI green light is a lie. Before claiming a ticket is done, name the CI job/steps that run your new test.

- **GitHub Actions workflow `name:` must be lowercase-with-hyphens.** All workflow YAML files under `.github/workflows/` must use the same naming convention: lowercase words separated by hyphens (e.g. `name: ci`, `name: cargo-deny`, `name: deploy`, `name: trunk-check`). No PascalCase (`Deploy`, `Trunk Check`), no ALLCAPS. This keeps the Actions sidebar predictable and sortable.

- **Treat hosted CI as an independent environment probe.** Permission, non-root process identity, ordering, cache, target, and runner behavior can differ from a root local checkout. Overlap independent review with hosted latency, but do not substitute either evidence stream for the other.

- **Profile sanitizer work at executable and fixture boundaries.** Cargo build-job limits and per-process test threads do not parallelize separate test executables. Measure each executable before tuning the job, then place a dominant target in an explicit shard and balance for the slowest shard. Inside a hot mutation loop, decode stable fixture structure once and mutate/restore only the field under test instead of rebuilding equivalent state for every case.

- **Remove accidental serialization only after isolating test state.** A process-wide mutex can dominate an instrumented test suite even when tests do not share a resource. Give each test collision-proof temporary state using the label, process ID, timestamp, and an atomic sequence; retain serialization only for a genuine process-global or external resource.

- **Treat coverage summaries as evidence, not intent.** Adding tests or seeing a smaller diff does not prove a per-file region target was met. Download and inspect the hosted coverage artifact for the exact final PR head, including every requested file, before reporting coverage complete.

- **Separate status evidence from diagnostic evidence.** Batch or reduce GitHub polling; if REST quota is exhausted, use an exact-head GraphQL check rollup to preserve status, but do not change code or classify a failure until the authoritative hosted job log is available.

- **Keep sharded required gates disjoint and fail closed.** Lock the exact target inventory and shard partition in an executable policy test, retain all features and test targets, and expose one stable aggregate check that runs with `always()` and succeeds only when every shard succeeds. Update the live branch rules to require that aggregate rather than an individual shard; a workflow fan-in does not protect merges unless branch policy requires its exact status.

- **Validate workflow changes through a canary pull request.** Inspect every hosted job, fix failures in the isolated worktree, require a clean ruleset, merge, and verify the post-merge `main` workflows.

- **Compile documentation explicitly with rustdoc warnings denied.** Compiler, test, and Clippy success do not validate rustdoc links.

- **Use explicit sanitizer-compatible fuzz targets.** Include every manifest that can affect an isolated workspace in path filters, and keep path-filtered fuzz or mutation checks advisory unless an always-emitted aggregator represents skipped work safely.

- **Make informational jobs cancellation-safe.** Avoid `always()` steps that hold replacement runs in a concurrency group. Do not confuse scheduled or manual ThreadSanitizer with a universal pull-request gate.

- **Keep ADR version scope separate from implementation scope.** The current product implementation is V1, but an ADR may legitimately document future V2/V3 evolution. Track whether a decision applies now or is deferred independently from its version label; do not rewrite valid future-version design as current behavior.

- **Triage hosted failures before editing.** Classify each failure as compile/lint, behavior, coverage, mutation, metadata/transport, or independent contract review. Fix mechanical failures narrowly, keep coverage and semantic changes separate, and stop implementation when a new architectural blocker requires an ADR or boundary decision.

- **Validate mutation in the correct order.** The unmutated baseline must compile and pass before shard output is meaningful; every shard must be classified. For a survivor, trace reachability and public observability first, remove equivalent or unreachable checks when the stronger invariant already implies them, and add a focused boundary test only for independent behavior.

- **Diagnose mutation timeouts by phase and test frontier.** Inspect the scenario outcome and log before changing code or timeout policy. A cold `cargo test --no-run` timeout needs a separate build allowance; a Test-phase timeout needs the last running tests traced to shared setup and checked for pathological cost at domain maxima. Do not hide either defect by enlarging one global timeout.

- **Design tests at public seams and account for coverage shape.** A test should fail at the authority or adapter boundary it claims to protect, not through an obsolete incidental mismatch. Equivalent Rust syntax can produce different LLVM regions; choose clear constructs, avoid untestable branches, and keep test-only instrumentation within test scope.

- **Synchronize on semantic prerequisites, not progress proxies.** Poll for the exact file, directory, child state, or other observable condition an operation needs, with child-exit detection and a bounded deadline. Arbitrary file counts and sleeps become flaky under sanitizer overhead and concurrent subprocess contention.

- **Treat repository policy as stronger than tool suggestions.** Compiler help text, formatter output, and a single lint message are local hints. Check the configured Trunk/Clippy policy and existing conventions before applying a suggestion; intentional must-use drops, combinator changes, and suppressions must satisfy the repository contract.

- **Keep workflow changes minimal and executable.** Remove whitespace-only churn, use the repository’s naming conventions, and verify folded shell commands, quoting, environment transport, path filters, timeouts, cancellation behavior, and aggregators on the actual runner. Performance improvements should be measured; do not hide architectural debt with larger timeouts.

- **Check formatting on the changed files themselves.** `cargo fmt --all` covers Cargo's discovered target graph, which can omit a changed Rust fixture or integration target that repository-wide Trunk checks format directly. Run the repository formatter and the pinned rustfmt check on every changed Rust file before pushing; keep the hosted formatter authoritative.

- **Distinguish formatter findings from formatter execution failures.** A whole-repository Trunk rustfmt batch can reach its 1,200-second limit with no stdout, stderr, or formatting finding even when the dedicated `fmt` gate passes on the same commit. Treat that as a tool-execution failure, not evidence that source needs reformatting: re-run the exact failed job once on a fresh runner before editing; if it times out again, isolate or split its file batch and inspect the tool/cache state instead of making speculative source changes.

- **Keep required workflows alive while scoping expensive gates.** Use a pinned path-filter action with its filter configuration loaded from the pull request’s trusted base revision and a conservative documentation-only allowlist to drive job-level `needs`/`if` conditions; keep required workflow triggers broad because top-level path filters can leave checks pending. Ensure unknown, deleted, renamed, generated, and policy inputs run the full suite, and keep pushes, schedules, and manual runs full.

- **Give every fixture one owner and lifecycle.** Shipped conformance fixtures, test-only fixtures, public authority bytes, and mutation reports have different audiences and validity. Keep them separate, bind reports to the commit that produced them, and remove embedded sample data when its product owner is removed.

- **Optimize expensive validation from measurements.** For mutation, formatting, sanitizer, and coverage jobs, measure per-case cost, shard balance, artifact size, and runner limits before changing parallelism or timeout. Preserve the gate’s scope and failure semantics; a longer timeout is not a performance fix.

- **Classify a failed signal before editing.** Check requiredness, trigger, and data source first: a policy gate driven by immutable metadata needs a maintainer decision or base policy change, not a speculative patch. An absent downstream status is not drift until its `needs` chain is terminal.

- **Normalize heterogeneous check results.** Normalize check-run (`status`/`conclusion`) and status-context (`state`) rollup entries by type before reporting readiness.

- **Probe tool availability before composing a verification command.** Use `command -v` for non-Cargo validators and state the fallback evidence upfront; preserve unsupported-local-tool errors as pending hosted checks and never bypass pins.

- **State the CI performance objective, then model the schedule.** Name whether green latency, time to first useful failure, or total runner minutes is primary; simulate the critical path under the runner budget and report green-path savings separately from failed-PR cost. Classify each dependency as data, validation, or scheduling, and do not overlap work in a way that delays or hides the first useful failure; keep independent sibling results. Order bounded matrices so the predicted tail starts first and only work that cannot overtake it is delayed, and validate with hosted timestamps.

- **Audit cache scope and capacity before tuning compilation.** Check cache size, quota, eviction risk, and hit/miss evidence before recommending compiler, runner, or test-partition changes; a fast cache mechanism still yields cold builds when entries are unusable or evicted.

- **Verify cache policy by its side effect.** Pair an executable configuration contract with a post-run cache-inventory assertion for the relevant branch or merge-ref namespace, recording expected present and absent identities with the run URL.

- **Extend the nearest contract test for small workflow invariants.** Add a direct assertion to the existing test that owns the workflow; reserve a new checker for independently reusable or complex contracts.

- **Do not invent publication gates from supplemental diagnostics.** For each hold, cite the exact owner and normative condition, and separate source correctness, publication authority, diagnostic risk, and final-delivery requirements. When publication is authorized, predecessor required runs are terminal, and every blocking check is preserved, run primary draft CI in parallel with supplemental experiments, adjudicate prior review advice explicitly, and never call unfinished validation successful.

- **A mutation result needs a working unmutated baseline.** Inspect scenario logs to separate compile, harness-startup, test, and assertion failures; require a passing unmutated run with the same toolchain, features, and arguments, make fan-in depend on it, and check baseline timeout semantics in the pinned tool source.

- **Shorten concurrency waits only when waiting cannot change the outcome.** Trace lock ownership and release first, keep the real write and exact refusal, and prove a subsequent success through the same competitor after release.

- **Keep fault-position sweeps oracle-independent.** Validate an independent positive operation under unchanged limits, require every injected position to refuse and the full valid prefix to succeed, and measure sweep runtime (replaying each prefix can be quadratic). Treat a source-supported diagnosis as unproven until hosted evidence confirms it.
