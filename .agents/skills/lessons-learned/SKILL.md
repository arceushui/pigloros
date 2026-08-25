---
name: lessons-learned
description: Anti-patterns and mistakes to avoid when working on this project. Read before starting any implementation.
disable-model-invocation: true
---

# Lessons Learned

This is an internal PiglorOS skill and the canonical source of durable project lessons. Add guidance to the relevant section below; keep raw task-observation history and dated execution records outside Git.

## Commits and worktrees

1. **Never `git add -A`.** It stages everything including skills files with pre-existing yamllint issues, stray config files (`opencode.json`, `skills-lock.json`). Stage only the files you changed: `git add path/to/changed/file.rs`.

2. **Worktree changes can be lost.** When a worktree is force-removed, uncommitted changes in it are gone. Commit from the worktree before removing it. Push from the worktree, then merge into main from the main checkout.

3. **`git reset` can lose your staging.** If you `git reset HEAD .agents/` then `git add specific files`, make sure the files you're adding are the ones with actual changes. If a file was already committed, `git add` won't re-stage it.

4. **Define completion by the requested end state.** A local green run is not delivery by itself. Verify the committed worktree, pushed branch, pull-request gates, merged target branch, post-merge workflows, tracker or release state, and external records that the task requires.

5. **Reconcile project records before reporting status.** Compare the repository, Redmine, Notion, GitHub, roadmap, worktrees, and product acceptance. If they disagree, name stale or conflicting labels, distinguish the current Wave from its milestone design, and never infer the project stage from one source.

6. **Stage only task files and re-check mutation boundaries.** Before cleanup, rebasing, or an external write, confirm live ownership, current state, and exact targets immediately before the mutation; never delete an active worktree or overwrite a shared record from a stale inventory.

## Code edits

7. **Use the repository edit tool for multi-line changes.** `sed` and inline rewrite scripts can corrupt source when a pattern or snapshot is stale. Prefer `apply_patch`, keep the change narrow, and inspect the diff immediately.

8. **Restore a corrupted file from a known baseline before repairing it.** Preserve any intended changes first, then use a file-scoped restore and reapply the change with the edit tool. Never repair a damaged file by guessing at the original text.

9. **Removing an implementation does not remove its product claim.** After deleting code, search the README, examples, roadmap pages, and external documentation for stale promises and update or remove them.

10. **Don't ship placeholder code.** `crps = brier_score` with a "placeholder for future" comment is speculative generality. Either implement it properly from a spec requirement, or don't add the field. Defer unsupported contracts explicitly.

11. **Never add `#[allow(clippy::*)]` to suppress lints.** If clippy flags a pattern (e.g. `clippy::question_mark`, `clippy::match_like_matches_macro`), fix the code to match the idiomatic pattern instead of silencing the lint. Suppressing lints hides real design problems and is harder to maintain. For `needless_pass_by_value` on `fn store_err(e: E)`: use `impl From<E> for MyError` instead — it eliminates the fn entirely, works as a `map_err` function item, and keeps the port definition clean.

12. **Respect domain boundaries in imports.** Port definitions (e.g. `store.rs` / `LedgerStore`) must not import adapter-specific types from other crates. If an adapter needs a `From<E>` impl, put it in the adapter file (e.g. `event_store.rs`), not in the port. If a type feels missing from the port, consider whether it's a genuine port concept or an adapter detail.

## Coverage

13. **`?` operator creates uncoverable LLVM sub-regions.** Replace `?` in production hot paths with `.map()`, `.and_then()`, or `.ok().flatten()` combinators — they propagate errors without creating sub-region artifacts that LLVM can't track. Similarly, `matches!()` in assertions creates macro-internal sub-regions; use `.to_string().contains()` for type-safe pattern checks in test contracts. CI requires 99% line and region coverage; the 1% tolerance is only for source-unmappable regions after a fresh non-root run.

14. **Coverage rule: delete, don't exempt.** If new code can't be covered by a test, remove the code — don't use `coverage(off)` on production code. Treat the coverage threshold as a design constraint.

15. **Run every applicable quality gate after each code change.** Include review fixes and restart gates from the new commit. Run the documented local checks when resources permit; when local Cargo execution is explicitly constrained, use the unchanged hosted gates and inspect their logs without lowering thresholds.

16. **Choose Rust constructs deliberately when coverage evidence matters.** Equivalent macros and control-flow forms can create different LLVM regions; prefer the idiomatic form that keeps behavior clear and measurable.

## Redmine

17. **Must invoke `start-work` skill when beginning work on any Redmine ticket.** This sets the ticket to In Progress and records all work as journal notes. Never start work without it.

18. **ADR wiki pages use Markdown, not Textile, and MUST have `ADR` as their parent page.** See the `adr-wiki` skill for full rules for hierarchy, formatting, and API usage.

19. **Follow the configured ADR transition flow.** Keep ADRs in `Proposed → Under Review → Accepted / Rejected` as configured; if a transition is unavailable, record the blocker rather than changing trackers or statuses to bypass it.

20. **Advance tracker artifacts only through their configured lifecycle.** A commit, an Accepted ADR, or a passing CI run does not by itself resolve an implementation ticket. For the configured Redmine flow, Feature/Bug/Task completion uses Resolved (status 3), ADR completion uses Proposed → Under Review → Accepted (status 9), and Closed (status 5) is reserved for rejected or superseded work. Keep ADR acceptance, implementation authorization, evidence readiness, and product acceptance separate.

21. **Keep authority states separate.** ADR status, implementation authorization, ticket status, evidence readiness, and product acceptance are different facts. An Accepted ADR records a decision; it does not start implementation.

22. **Preserve the project hierarchy.** Keep Wave, milestone design, ADR, implementation ticket, and subtask distinct. Use Redmine parent/child for decomposition and blocker relations for execution order between otherwise independent tickets; do not encode the same relation twice.

## Design and contracts

23. **Leave-one-out for per-entity baselines.** When computing entity-specific metrics, exclude the current observation from the historical baseline. Otherwise single-observation entities get perfect scores.

24. **Prefer iterators over owned collections in API.** `fn plugin_names() -> impl Iterator<Item = &str>` is consistent. `fn plugin_versions() -> HashMap<String, String>` is not.

25. **State acceptance criteria separately from evidence.** Every claim needs an audience, public boundary, pass/fail condition, named module or schema owner, authoritative artifact, evaluator, maturity, and remaining gate.

26. **Metadata does not prove behavior.** Fixture IDs, digests, and screenshots are references, not conformance. Mandatory cases must execute through the public boundary, and equality claims must bind to independently produced outputs.

27. **Keep evidence roles distinct.** Record host evidence, evaluator validation, independent reproduction, and authorship or organizational independence as separate fields.

28. **Use the smallest deterministic fixture that proves the claim.** Do not strengthen domain semantics merely because a fixture makes a stronger statement convenient.

29. **Separate computational Replay from empirical validity.** Keep Replay, world-model evidence, Persona calibration, Society Signal, route-level security enforcement, and future architecture distinct; a deterministic fixture or descriptor must not claim validity outside its declared role.

- **Audit contract changes as graph changes.** When an enum, trait, schema, or public constructor changes, search every exhaustive match, adapter, composition root, test seam, fixture, migration, and downstream consumer before pushing; hosted compile failures often reveal fan-out missed at the declaration site.

- **Keep authority independent from its consumer.** A caller must not mint, grant, or self-validate the authority it presents. Bind opaque capabilities and permits at the trusted composition boundary, reject foreign or unbound values, and retain only the lifecycle operations authorized by the port.

- **Pair privacy-preserving reads with host-owned continuation seams.** If a generic API intentionally hides protected data, model the authenticated head, replay, retry, or revocation seam explicitly and exercise it with fixtures that satisfy every consent and capability precondition.

- **Make unsupported evidence structurally incomplete.** Unavailable authority bytes, signatures, or external attestations stay Draft or pending; they must not look like Candidate or materialized evidence through placeholder paths, digests, or metadata.

- **Keep cryptographic integrity and trust authorization distinct.** A valid signature does not establish that the signer is trusted for the requested lifecycle transition. Require both checks at the promotion boundary, and bind recursive containers through explicit layered commitments.

- **Treat V1 contract evolution as replacement-first when compatibility is out of scope.** Replace obsolete interfaces directly, remove stale compatibility shims and claims, and update migrations, fixtures, and public tests to the one normative contract rather than preserving an unused legacy path.

- **Treat conformance metadata as executable input.** A changed matrix, fixture, profile, byte count, digest, checksum, or workflow key requires recomputation and static verification of every dependent field before publication. Paired execution modes share authoritative content but may differ in transport paths; compare by case, layer, and content identity.

## Code review

30. **Always request independent code review after completing code changes, before starting new work.** Use the `code-review` skill with a fixed point, review Standards and Spec fit separately, address findings in a separate round, and re-review the resulting exact head. A conflict-free PR or passing subset of checks is not merge readiness.

## CI / GitHub Actions

31. **Every test type must run in CI — no local-only tests.** GitHub Actions (`.github/workflows/ci.yml`) is the single source of truth for what passes. When adding any test — unit test, integration test (`tests/` directory), doctest, or `#[ignore]`d test — verify that `cargo test --workspace --locked -- --include-ignored` in the `test` job actually executes it. The `--include-ignored` flag is mandatory so `#[ignore]` cannot silently skip. If you write an integration test that lives in `tests/`, it MUST be picked up by the workspace test job; if it isn't, the test is dead and the CI green light is a lie. Before claiming a ticket is done, name the CI job/steps that run your new test.

32. **GitHub Actions workflow `name:` must be lowercase-with-hyphens.** All workflow YAML files under `.github/workflows/` must use the same naming convention: lowercase words separated by hyphens (e.g. `name: ci`, `name: cargo-deny`, `name: deploy`, `name: trunk-check`). No PascalCase (`Deploy`, `Trunk Check`), no ALLCAPS. This keeps the Actions sidebar predictable and sortable.

33. **Treat hosted CI as an independent environment probe.** Permission, non-root process identity, ordering, cache, target, and runner behavior can differ from a root local checkout. Overlap independent review with hosted latency, but do not substitute either evidence stream for the other.

34. **Validate workflow changes through a canary pull request.** Inspect every hosted job, fix failures in the isolated worktree, require a clean ruleset, merge, and verify the post-merge `main` workflows.

35. **Compile documentation explicitly with rustdoc warnings denied.** Compiler, test, and Clippy success do not validate rustdoc links.

36. **Use explicit sanitizer-compatible fuzz targets.** Include every manifest that can affect an isolated workspace in path filters, and keep path-filtered fuzz or mutation checks advisory unless an always-emitted aggregator represents skipped work safely.

37. **Make informational jobs cancellation-safe.** Avoid `always()` steps that hold replacement runs in a concurrency group. Do not confuse scheduled or manual ThreadSanitizer with a universal pull-request gate.

38. **Keep ADR version scope separate from implementation scope.** The current product implementation is V1, but an ADR may legitimately document future V2/V3 evolution. Track whether a decision applies now or is deferred independently from its version label; do not rewrite valid future-version design as current behavior.

- **Triage hosted failures before editing.** Classify each failure as compile/lint, behavior, coverage, mutation, metadata/transport, or independent contract review. Fix mechanical failures narrowly, keep coverage and semantic changes separate, and stop implementation when a new architectural blocker requires an ADR or boundary decision.

- **Validate mutation in the correct order.** The unmutated baseline must compile and pass before shard output is meaningful; every shard must be classified. For a survivor, trace reachability and public observability first, remove equivalent or unreachable checks when the stronger invariant already implies them, and add a focused boundary test only for independent behavior.

- **Design tests at public seams and account for coverage shape.** A test should fail at the authority or adapter boundary it claims to protect, not through an obsolete incidental mismatch. Equivalent Rust syntax can produce different LLVM regions; choose clear constructs, avoid untestable branches, and keep test-only instrumentation within test scope.

- **Treat repository policy as stronger than tool suggestions.** Compiler help text, formatter output, and a single lint message are local hints. Check the configured Trunk/Clippy policy and existing conventions before applying a suggestion; intentional must-use drops, combinator changes, and suppressions must satisfy the repository contract.

- **Keep workflow changes minimal and executable.** Remove whitespace-only churn, use the repository’s naming conventions, and verify folded shell commands, quoting, environment transport, path filters, timeouts, cancellation behavior, and aggregators on the actual runner. Performance improvements should be measured; do not hide architectural debt with larger timeouts.

- **Give every fixture one owner and lifecycle.** Shipped conformance fixtures, test-only fixtures, public authority bytes, and mutation reports have different audiences and validity. Keep them separate, bind reports to the commit that produced them, and remove embedded sample data when its product owner is removed.

- **Optimize expensive validation from measurements.** For mutation, formatting, sanitizer, and coverage jobs, measure per-case cost, shard balance, artifact size, and runner limits before changing parallelism or timeout. Preserve the gate’s scope and failure semantics; a longer timeout is not a performance fix.

## Documentation boundaries

39. **Keep Git docs contributor-facing and canonical.** Put current usage, contribution, policy, and durable contract guidance in Git; search for an existing source before creating another guide. Put dated execution logs, plans, and decision history in Redmine or Notion; link to the canonical external record rather than copying it into a dated Markdown file.

40. **Treat external documentation as structured data.** Mermaid code is literal: do not apply rich-text escaping inside code fences, use `<br>` for label breaks, and quote labels containing special characters. In Notion tables, use native Markdown links or plain text, not raw HTML anchors or block-level markup in cells. Treat diagrams, rich text, table cells, and page tags as separate serialization layers.

41. **Verify external writes by reading back canonical content.** A child-page creation can append a structural `<page>` block to its parent; fetch the live parent, place the block at the intended index, and fetch parent and child after the write. Verify schemas, links, hierarchy, authority markers, vocabulary, maturity claims, and migrated record counts rather than trusting a success summary.

- **Make documentation claims reviewable before making them attractive.** Lead product pages with user value and a concrete first action; give architecture pages a current system map and next seam; give validation pages a claim contract before technical detail. Use examples that clarify without narrowing the product, and mark current state, maturity, and source of truth structurally.

- **Keep hierarchy and current truth explicit.** A parent page must explain why its child is the next useful drill-down. Living overviews and technical hubs state the current product or domain contract; dated plans, review transcripts, competitor investigations, and execution logs belong in linked history or dedicated pages.

- **Tie strategy and research to release evidence.** Preserve dated first-party evidence and historical investigation separately from the current landscape, then map each objective, differentiator, and scenario to a named milestone and user-visible acceptance gate. Traceability should clarify the product journey rather than make the reader reconstruct it from tickets.

- **Make external records durable and auditable.** When comments or delegated edits are part of the handoff, consolidate them into ordered page content with session/job ownership, verify the migrated count and canonical text, and state any API limitation that prevents source cleanup. Never trust a mutation success summary without a read-back.

## Execution modes and terminology

42. **Keep execution modes separate.** Local/Connected, Air-Gapped, Deterministic, and Live Exploration describe different combinations of deployment locality, network permission, and reproducibility.

43. **Use the project glossary exactly.** **Timeline**, **Fork**, **PersonaModel**, **Society Signal**, **Brier Score**, and **Calibration Report** carry defined meanings and should not be replaced by looser synonyms.

## Safe records

44. **Make append-only logs collision-aware.** Read the live file, assert the next number is unused, append, then verify count, uniqueness, and survival.

## Pre-flight verification

Before delivery, re-read this file and check every applicable rule against the diff, commands, records, and handoff. For a skill update, confirm that the new guidance is a synthesis rather than a transcript, that no contradictory rule remains, and that every new embedded command has been executed once against real data with plausible output. For implementation work, execute each read-only or explicitly authorized embedded command once against real data and inspect its output before relying on it; for mutating or destructive examples, validate the syntax and exact target without running them unless the task authorizes that mutation. Do not report completion until the required local or hosted, review, and external-record checks are evidenced.
