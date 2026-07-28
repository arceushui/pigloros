# Skill Observation Log

Observations captured during task-oriented work.

**Status key:** OPEN = not yet actioned | ACTIONED (YYYY-MM-DD) = skill
updated/created | DECLINED (YYYY-MM-DD) = user decided not to pursue —
resolved statuses always carry their resolution date

---

## 2026-07-27

### Observation 1: LLVM coverage region artifacts require code restructuring, not more tests

**Status:** OPEN
**Date:** 2026-07-27
**Session context:** #110 piglor-ledger CLI — achieving 100% region coverage after code review
**Skill:** lessons-learned (anti-patterns)
**Type:** open-source
**Phase/Area:** Coverage / Rust testing

**Issue:** `cargo llvm-cov --fail-under-regions 100` catches coverage gaps that `--fail-under-lines 100` misses. These are not missing tests — the code path is exercised — but LLVM sub-region artifacts from:
- Method chains crossing line boundaries (each intermediate `.method()` creates a zero-count region)
- `match` arms where the compiler splits a single arm into multiple basic blocks (2 regions per arm)
- `?` on intermediate results in multi-line expressions within a function body

In this session, the HTML report showed zero actual uncovered lines, but the region counter still reported 5-7 uncovered. Adding error-path tests did not fix it — the code paths were already covered. The fix was **restructuring**:
1. `bytes.as_slice().try_into()` → `[u8; 32]::try_from(bytes.as_slice())` (single-expression binding)
2. `match` on optional `wallet.toml` → `if let` with early `return None` and separate `then_wallet_toml = None` branch

**Suggested improvement:** Add a section to `lessons-learned` SKILL.md documenting this pattern: "When region coverage < 100% but lines show 100% and all error paths are tested, restructure code to eliminate intermediate temporaries and multi-region match arms. Adding more tests won't help."

**Principle:** LLVM region coverage counts basic blocks, not code paths. Method chains and match expressions create zero-count basic blocks that tests physically execute but the coverage instrumenter sees as dead. Fix these with code structure changes, not with more tests.

### Observation 2: Rust CI audit job catches unused deps and broken doc links pre-merge

**Status:** OPEN
**Date:** 2026-07-27
**Session context:** #110 — CI hardening after code review, fixing 18 pre-existing broken doc links across workspace
**Skill:** New skill candidate: rust-ci-hardening
**Type:** open-source
**Phase/Area:** CI / Rust tooling

**Issue:** Two CI gaps discovered during code review hardening: (a) `cargo doc --document-private-items` was not run in CI, allowing broken intra-doc links (`[Type]`, `[function]`) to accumulate across crates; (b) unused dependencies went undetected. Adding `cargo machete` and `cargo doc -D warnings --document-private-items` to a new `audit` job caught both. Fixing the doc links required removing unresolvable `[Type]` references and using `[]()` form for functions with ambiguous module paths — 18 fixes across 6 crates.

**Suggested improvement:** Create a reusable CI audit job recipe for Rust workspaces: `cargo machete` (unused deps) + `cargo doc -D warnings --document-private-items` (broken doc links) + `cargo clippy` (already standard). Add `--locked` and `set -euo pipefail` to coverage jobs. Document the doc-link fix patterns (remove unresolvable `[Type]`, use `[]()` fallback for ambiguous paths).

**Principle:** A Rust CI audit job with `cargo machete` + `cargo doc -D warnings` catches bit-rot that clippy and fmt don't. Broken doc links are the canary — they mean `rustdoc` can't resolve the symbol, which means neither can rust-analyzer, so developers working on the crate see red squiggles.

### Observation 3: Redmine wiki pages accept Markdown, not Textile

**Status:** OPEN
**Date:** 2026-07-27
**Session context:** setup-matt-pocock-skills — moving ADRs from git repo to Redmine wiki
**Skill:** adr-wiki, setup-matt-pocock-skills (issue-tracker docs)
**Type:** open-source
**Phase/Area:** Documentation / Redmine API

**Issue:** Both `.agents/issue-tracker.md` and `docs/agents/issue-tracker.md` documented the ADR wiki creation API endpoint but omitted the content format. When attempting to publish ADR content, the default assumption was Textile (Redmine's legacy wiki format), but this Redmine instance accepts Markdown. Textile-formatted content was rejected with "Text field cannot be blank" (actually a format mismatch).

**Suggested improvement:** Update both issue-tracker files to explicitly state that Redmine wiki pages accept Markdown. Include a sample payload showing `"text": "<markdown content>"`.

**Principle:** Wiki format (Textile vs Markdown) is per-instance Redmine configuration. Documenting the assumed format saves wasted API calls. When API creates return 4xx with cryptic messages, format mismatch should be the first hypothesis.
