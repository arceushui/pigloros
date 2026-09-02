---
name: lessons-learned
description: Anti-patterns and mistakes to avoid when working on this project. Read before starting any implementation.
disable-model-invocation: true
---

# Lessons Learned

This is an internal PiglorOS skill and the canonical source of durable project lessons. Add guidance to the relevant section below; keep raw task-observation history and dated execution records outside Git. This file is a cross-cutting checklist: use the owning specialist skill (`code-review`, `diagnosing-bugs`, `technical-documentation-pipeline`, or `worktree-status`) for full procedures.

## Commits and worktrees

- **Never `git add -A`.** It stages everything including skills files with pre-existing yamllint issues, stray config files (`opencode.json`, `skills-lock.json`). Stage only the files you changed: `git add path/to/changed/file.rs`.

- **Worktree changes can be lost.** When a worktree is force-removed, uncommitted changes in it are gone. Commit from the worktree before removing it. Push from the worktree, then merge into main from the main checkout.

- **`git reset` can lose your staging.** If you `git reset HEAD .agents/` then `git add specific files`, make sure the files you're adding are the ones with actual changes. If a file was already committed, `git add` won't re-stage it.

- **Define completion by the requested end state.** A local green run is not delivery by itself. Verify the committed worktree, pushed branch, pull-request gates, merged target branch, post-merge workflows, tracker or release state, and external records that the task requires.

- **Reconcile project records before reporting status.** Compare the repository, Redmine, Notion, GitHub, roadmap, worktrees, and product acceptance. If they disagree, name stale or conflicting labels, distinguish the current Wave from its milestone design, and never infer the project stage from one source.

- **Stage only task files and re-check mutation boundaries.** Before cleanup, rebasing, or an external write, confirm live ownership, current state, and exact targets immediately before the mutation; never delete an active worktree or overwrite a shared record from a stale inventory.

- **Reconcile a shared PR immediately before pushing.** Concurrent workers can land equivalent or overlapping fixes while a rebase or hook is running. Fetch the PR branch, compare the merge base and commits, rebase onto its current tip, and drop patches already present. Never force-push a shared branch to replace a concurrent update.

## Code edits

- **Use the repository edit tool for multi-line changes.** `sed` and inline rewrite scripts can corrupt source when a pattern or snapshot is stale. Prefer `apply_patch`, keep the change narrow, and inspect the diff immediately.

- **Restore a corrupted file from a known baseline before repairing it.** Preserve any intended changes first, then use a file-scoped restore and reapply the change with the edit tool. Never repair a damaged file by guessing at the original text.

- **Removing an implementation does not remove its product claim.** After deleting code, search the README, examples, roadmap pages, and external documentation for stale promises and update or remove them.

- **Don't ship placeholder code.** `crps = brier_score` with a "placeholder for future" comment is speculative generality. Either implement it properly from a spec requirement, or don't add the field. Defer unsupported contracts explicitly.

- **Never add `#[allow(clippy::*)]` to suppress lints.** If clippy flags a pattern (e.g. `clippy::question_mark`, `clippy::match_like_matches_macro`), fix the code to match the idiomatic pattern instead of silencing the lint. Suppressing lints hides real design problems and is harder to maintain. For `needless_pass_by_value` on `fn store_err(e: E)`: use `impl From<E> for MyError` instead — it eliminates the fn entirely, works as a `map_err` function item, and keeps the port definition clean.

- **Respect domain boundaries in imports.** Port definitions (e.g. `store.rs` / `LedgerStore`) must not import adapter-specific types from other crates. If an adapter needs a `From<E>` impl, put it in the adapter file (e.g. `event_store.rs`), not in the port. If a type feels missing from the port, consider whether it's a genuine port concept or an adapter detail.

## Coverage

- **`?` operator creates uncoverable LLVM sub-regions.** Replace `?` in production hot paths with `.map()`, `.and_then()`, or `.ok().flatten()` combinators — they propagate errors without creating sub-region artifacts that LLVM can't track. Similarly, `matches!()` in assertions creates macro-internal sub-regions; use `.to_string().contains()` for type-safe pattern checks in test contracts. CI requires 99% line and region coverage; the 1% tolerance is only for source-unmappable regions after a fresh non-root run.

- **Coverage rule: delete, don't exempt.** If new code can't be covered by a test, remove the code — don't use `coverage(off)` on production code. Treat the coverage threshold as a design constraint.

- **Run every applicable quality gate after each code change.** Include review fixes and restart gates from the new commit. Run the documented local format, test, lint, and coverage checks; only when the documented coverage instrumentation exhausts local memory may the unchanged hosted coverage gate serve as the fallback, with thresholds intact and logs inspected.

- **Choose Rust constructs deliberately when coverage evidence matters.** Equivalent macros and control-flow forms can create different LLVM regions; prefer the idiomatic form that keeps behavior clear and measurable.

- **Do not trade error semantics for coverage.** Converting a fallible public or codec API into an unconditional abort merely to remove a coverage region weakens diagnostics and changes the contract. Preserve the `Result` boundary, then cover its success and error behavior through the public seam.

## Redmine

- **Must invoke `start-work` skill when beginning work on any Redmine ticket.** This sets the ticket to In Progress and records all work as journal notes. Never start work without it.

- **ADR wiki pages use Markdown, not Textile, and MUST have `ADR` as their parent page.** See the `adr-wiki` skill for full rules for hierarchy, formatting, and API usage.

- **Follow the configured ADR transition flow.** Keep ADRs in `Proposed → Under Review → Accepted / Rejected` as configured; if a transition is unavailable, record the blocker rather than changing trackers or statuses to bypass it.

- **Advance tracker artifacts only through their configured lifecycle.** A commit, an Accepted ADR, or a passing CI run does not by itself resolve an implementation ticket. For the configured Redmine flow, Feature/Bug/Task completion uses Resolved (status 3), ADR completion uses Proposed → Under Review → Accepted (status 9), and Closed (status 5) is reserved for rejected or superseded work. Keep ADR acceptance, implementation authorization, evidence readiness, and product acceptance separate.

- **Keep authority states separate.** ADR status, implementation authorization, ticket status, evidence readiness, and product acceptance are different facts. An Accepted ADR records a decision; it does not start implementation.

- **Preserve the project hierarchy.** Keep Wave, milestone design, ADR, implementation ticket, and subtask distinct. Use Redmine parent/child for decomposition and blocker relations for execution order between otherwise independent tickets; do not encode the same relation twice.

## Design and contracts

- **Leave-one-out for per-entity baselines.** When computing entity-specific metrics, exclude the current observation from the historical baseline. Otherwise single-observation entities get perfect scores.

- **Prefer iterators over owned collections in API.** `fn plugin_names() -> impl Iterator<Item = &str>` is consistent. `fn plugin_versions() -> HashMap<String, String>` is not.

- **State acceptance criteria separately from evidence.** Every claim needs an audience, public boundary, pass/fail condition, named module or schema owner, authoritative artifact, evaluator, maturity, and remaining gate.

- **Metadata does not prove behavior.** Fixture IDs, digests, and screenshots are references, not conformance. Mandatory cases must execute through the public boundary, and equality claims must bind to independently produced outputs.

- **Keep evidence roles distinct.** Record host evidence, evaluator validation, independent reproduction, and authorship or organizational independence as separate fields.

- **Use the smallest deterministic fixture that proves the claim.** Do not strengthen domain semantics merely because a fixture makes a stronger statement convenient.

- **Separate computational Replay from empirical validity.** Keep Replay, world-model evidence, Persona calibration, Society Signal, route-level security enforcement, and future architecture distinct; a deterministic fixture or descriptor must not claim validity outside its declared role.

- **Audit contract changes as graph changes.** When an enum, trait, schema, or public constructor changes, search every exhaustive match, adapter, composition root, test seam, fixture, migration, and downstream consumer before pushing; hosted compile failures often reveal fan-out missed at the declaration site.

- **Keep authority independent from its consumer.** A caller must not mint, grant, or self-validate the authority it presents. Bind opaque capabilities and permits at the trusted composition boundary, reject foreign or unbound values, and retain only the lifecycle operations authorized by the port.

- **Pair privacy-preserving reads with host-owned continuation seams.** If a generic API intentionally hides protected data, model the authenticated head, replay, retry, or revocation seam explicitly and exercise it with fixtures that satisfy every consent and capability precondition.

- **Make unsupported evidence structurally incomplete.** Unavailable authority bytes, signatures, or external attestations stay Draft or pending; they must not look like Candidate or materialized evidence through placeholder paths, digests, or metadata.

- **Keep cryptographic integrity and trust authorization distinct.** A valid signature does not establish that the signer is trusted for the requested lifecycle transition. Require both checks at the promotion boundary, and bind recursive containers through explicit layered commitments.

- **Treat V1 contract evolution as replacement-first when compatibility is out of scope.** Replace obsolete interfaces directly, remove stale compatibility shims and claims, and update migrations, fixtures, and public tests to the one normative contract rather than preserving an unused legacy path.

- **Treat conformance metadata as executable input.** A changed matrix, fixture, profile, byte count, digest, checksum, or workflow key requires recomputation and static verification of every dependent field before publication. Paired execution modes share authoritative content but may differ in transport paths; compare by case, layer, and content identity.

## Code review

- **Always request independent code review after completing code changes, before starting new work.** Use the `code-review` skill with a fixed point, review Standards and Spec fit separately, address findings in a separate round, and re-review the resulting exact head. A conflict-free PR or passing subset of checks is not merge readiness.

- **Review the complete PR diff after rebases.** A review of only the newest commit can miss regressions introduced by earlier commits or by conflict resolution. Compare the final PR head with the latest `main`, and record the exact reviewed head.

- **Pin one review baseline before delegation.** Fetch the remote base and record its exact commit, feature head, merge-base, changed-file list, and full commit list; give every reviewer the same `base...HEAD` range. A rebase invalidates the old source-review evidence and requires a new explicitly pinned baseline.

- **Disposition the complete finding set.** Preserve Standards and Spec as separate axes, and show every item as accepted, rejected, or deferred with current evidence, ownership, merge impact, and the concrete reason. Previous findings are leads rather than evidence; verify them against current lines, omit stale defects, and explain whether a disagreement comes from a code misread, an over-literal rule, or valid debt outside the ticket.

- **Separate ownership from correctness.** Defer a missing capability when an adjacent ticket owns it, but still flag provisional behavior that implements that capability incorrectly. Ticket boundaries prevent scope creep; they do not make incorrect behavior safe to merge as an accidental contract.

- **Bound and retrieve delegated review reports deliberately.** Require concise structured output, retrieve large independent reports one at a time, and adjudicate only after all axes complete. Combining unbounded reports in one response can truncate evidence and hide findings.

- **Do not infer specification compliance from green gates.** CI, coverage, mutation, lint, and security analysis can all pass while an acceptance criterion or ADR invariant remains unimplemented. Report source-review readiness and hosted-gate readiness as separate facts.

- **Give Spec reviewers the complete acceptance record.** Requirements alone are insufficient when delivery evidence lives in issue journals, PR descriptions, hosted reports, or recorded measurements. Supply those authoritative artifacts with the fixed review baseline, and require the reviewer to distinguish missing implementation from missing external evidence before assigning severity.

## CI / GitHub Actions

- **Every test type must run in CI — no local-only tests.** GitHub Actions (`.github/workflows/ci.yml`) is the single source of truth for what passes. When adding any test — unit test, integration test (`tests/` directory), doctest, or `#[ignore]`d test — verify that `cargo test --workspace --locked -- --include-ignored` in the `test` job actually executes it. The `--include-ignored` flag is mandatory so `#[ignore]` cannot silently skip. If you write an integration test that lives in `tests/`, it MUST be picked up by the workspace test job; if it isn't, the test is dead and the CI green light is a lie. Before claiming a ticket is done, name the CI job/steps that run your new test.

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

## Documentation boundaries

- **Keep Git docs contributor-facing and canonical.** Put current usage, contribution, policy, and durable contract guidance in Git; search for an existing source before creating another guide. Put dated execution logs, plans, and decision history in Redmine or Notion; link to the canonical external record rather than copying it into a dated Markdown file.

- **Treat external documentation as structured data.** Mermaid code is literal: do not apply rich-text escaping inside code fences, use `<br>` for label breaks, and quote labels containing special characters. In Notion tables, use native Markdown links or plain text, not raw HTML anchors or block-level markup in cells. Treat diagrams, rich text, table cells, and page tags as separate serialization layers.

- **Verify external writes by reading back canonical content.** A child-page creation can append a structural `<page>` block to its parent; fetch the live parent, place the block at the intended index, and fetch parent and child after the write. Verify schemas, links, hierarchy, authority markers, vocabulary, maturity claims, and migrated record counts rather than trusting a success summary.

- **Make documentation claims reviewable before making them attractive.** Lead product pages with user value and a concrete first action; give architecture pages a current system map and next seam; give validation pages a claim contract before technical detail. Use examples that clarify without narrowing the product, and mark current state, maturity, and source of truth structurally.

- **Keep hierarchy and current truth explicit.** A parent page must explain why its child is the next useful drill-down. Living overviews and technical hubs state the current product or domain contract; dated plans, review transcripts, competitor investigations, and execution logs belong in linked history or dedicated pages.

- **Tie strategy and research to release evidence.** Preserve dated first-party evidence and historical investigation separately from the current landscape, then map each objective, differentiator, and scenario to a named milestone and user-visible acceptance gate. Traceability should clarify the product journey rather than make the reader reconstruct it from tickets.

- **Make external records durable and auditable.** When comments or delegated edits are part of the handoff, consolidate them into ordered page content with session/job ownership, verify the migrated count and canonical text, and state any API limitation that prevents source cleanup. Never trust a mutation success summary without a read-back.

## Execution modes and terminology

- **Keep execution modes separate.** Local/Connected, Air-Gapped, Deterministic, and Live Exploration describe different combinations of deployment locality, network permission, and reproducibility.

- **Use the project glossary exactly.** **Timeline**, **Fork**, **PersonaModel**, **Society Signal**, **Brier Score**, and **Calibration Report** carry defined meanings and should not be replaced by looser synonyms.

## Safe records

- **Make append-only logs collision-aware.** Read the live file, assert the next number is unused, append, then verify count, uniqueness, and survival.

## Pre-flight verification

Before delivery, re-read this file and check every applicable rule against the diff, commands, records, and handoff. For a skill update, confirm that the new guidance is a synthesis rather than a transcript, that no contradictory rule remains, and that each new read-only or explicitly authorized embedded command has been executed once against real data with plausible output; validate mutating or destructive examples by syntax and exact-target inspection without executing them unless the task authorizes that mutation. For implementation work, execute each read-only or explicitly authorized embedded command once against real data and inspect its output before relying on it. Do not report completion until the required local, hosted, and external-record checks are evidenced.
