---
name: lessons-learned
description: Anti-patterns and mistakes to avoid when working on this project. Read before starting any implementation.
disable-model-invocation: true
---

# Lessons Learned

This tracked file is the canonical source of project lessons. Add durable guidance to the relevant section below; keep raw task-observation history as an audit record rather than creating a second lessons document.

## Commits and worktrees

1. **Never `git add -A`.** It stages everything including skills files with pre-existing yamllint issues, stray config files (`opencode.json`, `skills-lock.json`). Stage only the files you changed: `git add path/to/changed/file.rs`.

2. **Worktree changes can be lost.** When a worktree is force-removed, uncommitted changes in it are gone. Commit from the worktree before removing it. Push from the worktree, then merge into main from the main checkout.

3. **`git reset` can lose your staging.** If you `git reset HEAD .agents/` then `git add specific files`, make sure the files you're adding are the ones with actual changes. If a file was already committed, `git add` won't re-stage it.

4. **Define completion by the requested end state.** A local green run is not delivery by itself. Verify the committed worktree, pushed branch, pull-request gates, merged target branch, post-merge workflows, and tracker or release state that the task requires.

5. **Reconcile project records before reporting status.** Compare the repository, Redmine, Notion, GitHub, roadmap, and worktrees. If they disagree, name the conflict instead of silently choosing one source.

6. **Stage only task files and re-check mutation boundaries.** Before cleanup or an external write, confirm ownership, current state, and exact targets immediately before the mutation.

## Code edits

7. **Never use sed for multi-line code changes.** sed corrupts source files when the pattern doesn't match exactly. Python inline scripts are safer for batch operations. For single-file edits, always use the edit tool.

8. **Use restore when sed corrupts a file.** `git checkout -- path/to/file.rs` restores to HEAD. Don't try to manually fix sed corruption.

9. **Removing an implementation does not remove its product claim.** After deleting code, search the README, examples, roadmap pages, and external documentation for stale promises and update or remove them.

10. **Don't ship placeholder code.** `crps = brier_score` with a "placeholder for future" comment is speculative generality. Either implement it properly from a spec requirement, or don't add the field. Defer unsupported contracts explicitly.

11. **Never add `#[allow(clippy::*)]` to suppress lints.** If clippy flags a pattern (e.g. `clippy::question_mark`, `clippy::match_like_matches_macro`), fix the code to match the idiomatic pattern instead of silencing the lint. Suppressing lints hides real design problems and is harder to maintain. For `needless_pass_by_value` on `fn store_err(e: E)`: use `impl From<E> for MyError` instead — it eliminates the fn entirely, works as a `map_err` function item, and keeps the port definition clean.

12. **Respect domain boundaries in imports.** Port definitions (e.g. `store.rs` / `LedgerStore`) must not import adapter-specific types from other crates. If an adapter needs a `From<E>` impl, put it in the adapter file (e.g. `event_store.rs`), not in the port. If a type feels missing from the port, consider whether it's a genuine port concept or an adapter detail.

## Coverage

13. **`?` operator creates uncoverable LLVM sub-regions.** Replace `?` in production hot paths with `.map()`, `.and_then()`, or `.ok().flatten()` combinators — they propagate errors without creating sub-region artifacts that LLVM can't track. Similarly, `matches!()` in assertions creates macro-internal sub-regions; use `.to_string().contains()` for type-safe pattern checks in test contracts. CI requires 99% line and region coverage; the 1% tolerance is only for source-unmappable LLVM regions after a fresh non-root run.

14. **Coverage rule: delete, don't exempt.** If new code can't be covered by a test, remove the code — don't use `coverage(off)` on production code.

15. **Run all quality gates after EVERY change.** Including after code review fixes. `cargo test`, `cargo clippy`, `cargo llvm-cov`. No exceptions.

16. **Treat coverage thresholds as design constraints.** Remove dead or uncoverable production branches instead of exempting them; keep `coverage(off)` test-only.

17. **Choose Rust constructs deliberately when coverage evidence matters.** Equivalent macros and control-flow forms can create different LLVM regions; prefer the idiomatic form that keeps behavior clear and measurable.

## Redmine

18. **Must invoke `start-work` skill when beginning work on any Redmine ticket.** This sets the ticket to In Progress and records all work as journal notes. Never start work without it.

19. **ADR wiki pages use Markdown, not Textile, and MUST have `ADR` as their parent page.** See the `adr-wiki` skill for full rules on hierarchy, formatting, and API usage.

20. **ADR tracker workflow is broken.** No allowed transitions from "Proposed" status. ADR issues can't be closed via API or UI. To close an ADR via API: switch it to Feature tracker (tracker_id=2), then close (status_id=5).

21. **Close completed issues after every commit.** Use the correct status:
    - **Feature / Bug / Task** → `Resolved` (status_id=3), NOT Closed
    - **ADR** → `Accepted` (status_id=9), flow: Proposed→Under Review→Accepted
    - Only use Closed (status_id=5) for rejected or superseded issues

22. **Keep authority states separate.** ADR status, implementation authorization, ticket status, evidence readiness, and product acceptance are different facts. An Accepted ADR records a decision; it does not start implementation.

23. **Preserve the project hierarchy.** Keep Wave, milestone design, ADR, implementation ticket, and subtask distinct. Use Redmine parent/child for decomposition and blocker relations for execution order between independent tickets.

## Redmine ADR workflow setup (one-time admin fix)

The ADR tracker (id=5) has zero allowed transitions from its default status "Proposed" (id=7). Until this is fixed, ADRs cannot be accepted/closed. Here's the fix:

1. Go to your Redmine instance: `https://redmine.piglor.com`
2. Navigate to **Administration** → **Workflow** → **Status transitions**
3. Select **Tracker: ADR** and **Role: Manager** (and Developer)
4. Click **Edit**
5. For row "Proposed" (status 7), check these columns:
   - **Under Review** (status 8)
   - **Accepted** (status 9)
   - **Rejected** (status 6)
6. For row "Under Review" (status 8), check:
   - **Accepted** (status 9)
   - **Rejected** (status 6)
7. Click **Save**
8. Repeat for Developer role (role_id=4) if developers should manage ADRs

After this, ADRs can follow the flow: `Proposed → Under Review → Accepted / Rejected`. The API will also work for these transitions.

## Design and contracts

24. **Leave-one-out for per-entity baselines.** When computing entity-specific metrics, exclude the current observation from the historical baseline. Otherwise single-observation entities get perfect scores.

25. **Prefer iterators over owned collections in API.** `fn plugin_names() -> impl Iterator<Item = &str>` is consistent. `fn plugin_versions() -> HashMap<String, String>` is not.

26. **State acceptance criteria separately from evidence.** Every claim needs an audience, boundary, pass/fail condition, authoritative artifact, schema owner, evaluator, maturity, and remaining gate.

27. **Metadata does not prove behavior.** Fixture IDs, digests, and screenshots are references, not conformance. Mandatory cases must execute through the public boundary, and equality claims must bind to independently produced outputs.

28. **Keep evidence roles distinct.** Record host evidence, evaluator validation, independent reproduction, and authorship or organizational independence as separate fields.

29. **Use the smallest deterministic fixture that proves the claim.** Do not strengthen domain semantics merely because a fixture makes a stronger statement convenient.

30. **Separate computational Replay from empirical validity.** Keep Replay, world-model evidence, Persona calibration, and route-level security enforcement distinct from future architecture.

## Code review

31. **Always request code review after completing code changes, before starting new work.** Use the `code-review` skill with the appropriate fixed point (e.g. `main..HEAD` or a prior commit). Address all findings as a separate round of fixes, then let the reviewer confirm before moving to the next task. Do not start new tickets until the current review cycle is closed.

## CI / GitHub Actions

32. **Every test type must run in CI — no local-only tests.** GitHub Actions (`.github/workflows/ci.yml`) is the single source of truth for what passes. When adding any test — unit test, integration test (`tests/` directory), doctest, or `#[ignore]`d test — verify that `cargo test --workspace --locked -- --include-ignored` in the `test` job actually executes it. The `--include-ignored` flag is mandatory so `#[ignore]` cannot silently skip. If you write an integration test that lives in `tests/`, it MUST be picked up by the workspace test job; if it isn't, the test is dead and the CI green light is a lie. Before claiming a ticket is done, name the CI job/steps that run your new test.

33. **GitHub Actions workflow `name:` must be lowercase-with-hyphens.** All workflow YAML files under `.github/workflows/` must use the same naming convention: lowercase words separated by hyphens (e.g. `name: ci`, `name: cargo-deny`, `name: deploy`, `name: trunk-check`). No PascalCase (`Deploy`, `Trunk Check`), no ALLCAPS. This keeps the Actions sidebar predictable and sortable.

34. **Treat hosted CI as an independent environment probe.** Permission, process identity, ordering, cache, target, and runner behavior can differ from a root local checkout.

35. **Validate workflow changes through a canary pull request.** Inspect every hosted job, fix failures in the isolated worktree, require a clean ruleset, merge, and verify the post-merge `main` workflows.

36. **Compile documentation explicitly with rustdoc warnings denied.** Compiler, test, and Clippy success do not validate rustdoc links.

37. **Use explicit sanitizer-compatible fuzz targets.** Include every manifest that can affect an isolated workspace in path filters, and keep path-filtered fuzz or mutation checks advisory unless an always-emitted aggregator represents skipped work safely.

38. **Make informational jobs cancellation-safe.** Avoid `always()` steps that hold replacement runs in a concurrency group. Do not confuse scheduled or manual ThreadSanitizer with a universal pull-request gate.

39. **Keep ADR version scope separate from implementation scope.** The current product implementation is V1, but an ADR may legitimately document future V2/V3 evolution. Track whether a decision applies now or is deferred independently from its version label; do not rewrite valid future-version design as current behavior.

## Product and documentation

40. **Map objectives and competitor insight to proof.** Name the primary Wave, supporting Wave, user-visible acceptance gate, and evidence for each claim. Strategy is not operational until it points to proof.

41. **Keep overview pages about current product truth.** Lead with user value; put exclusions, review transcripts, and execution detail in their proper pages. Separate current landscape pages from dated updates and evidence reports, and label evidence, inference, roadmap implication, and “not evidenced” claims.

42. **Use one dominant reading path.** Show the current position and next step; use diagrams for sequence and transformation, tables for exact mappings, and child pages when deeper detail is useful.

43. **Keep examples broad enough for the product.** Examples should clarify without accidentally narrowing a general product to one market. First-impression reviews should distinguish intrigue, comprehension, operational clarity, willingness to try, and willingness to trust.

44. **Treat external documentation as a schema.** Mermaid code is literal: do not apply rich-text escaping inside code fences, use `<br>` for label breaks, and quote labels containing special characters. In Notion tables, use native Markdown links or plain text, not raw HTML anchors or block-level markup in cells.

45. **Verify external writes by reading back canonical content.** A child-page creation can append a structural `<page>` block to its parent; fetch the live parent, place the block at the intended index, and fetch parent and child after the write. Verify schemas, links, hierarchy, authority markers, vocabulary, and maturity claims rather than trusting a success summary.

## Execution modes and terminology

46. **Keep execution modes separate.** Local/Connected, Air-Gapped, Deterministic, and Live Exploration describe different combinations of deployment locality, network permission, and reproducibility.

47. **Use the project glossary exactly.** **Timeline**, **Fork**, **PersonaModel**, **Society Signal**, **Brier Score**, and **Calibration Report** carry defined meanings and should not be replaced by looser synonyms.

## Safe records and handoff

48. **Make append-only logs collision-aware.** Read the live file, assert the next number is unused, append, then verify count, uniqueness, and survival.

49. **Make handoff evidence-based.** Review the diff, run required gates, request independent review for code changes, verify hosted and post-merge state, read back external records, confirm clean worktrees, and report advisory risks honestly.
