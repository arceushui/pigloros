# Coverage

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Diagnose LLVM regions before changing Rust syntax.** Error propagation and macros can produce residual LLVM regions; inspect the actual mapped spans and counters before choosing an equivalent idiomatic form. Preserve `Result` semantics and typed assertions; do not blanket-replace `?` or convert typed values to strings just to raise coverage. CI requires 99% line and region coverage; the 1% tolerance is only for source-unmappable regions after a fresh non-root run.

- **Coverage rule: delete, don't exempt.** If new code can't be covered by a test, remove the code — don't use `coverage(off)` on production code. Treat the coverage threshold as a design constraint.

- **Close coverage gaps in material semantic batches.** Use the exact hosted artifact to group missed changed regions by file and behavior, then add public-boundary tests or remove unreachable branches in one coherent batch. Report per-file before/after counts; crossing the aggregate threshold alone does not prove changed code is adequately exercised.

- **Run every applicable quality gate after each code change.** Include review fixes and restart gates from the new commit. Run the documented local format, test, lint, and coverage checks. When instrumentation exhausts local memory or a stated local resource constraint prohibits a run, use the unchanged hosted gate for that evidence, preserve thresholds, and inspect its logs. Report unavailable evidence explicitly; do not start a prohibited build to demonstrate the constraint.

- **Choose Rust constructs deliberately when coverage evidence matters.** Equivalent macros and control-flow forms can create different LLVM regions; prefer the idiomatic form that keeps behavior clear and measurable.

- **Treat coverage and complexity as coupled constraints.** Helper extraction, error propagation, and decoder flattening can improve one metric while adding uncovered residual regions or pathological formatter work. Accept the refactor only when control flow remains linearly auditable and both machine-readable reports improve without weakened semantics.

- **Do not trade error semantics for coverage.** Converting a fallible public or codec API into an unconditional abort merely to remove a coverage region weakens diagnostics and changes the contract. Preserve the `Result` boundary, then cover its success and error behavior through the public seam.

- **Normalize before declaring a region missed.** Group identical source spans and region kinds across instantiations; a span is missed only if no contributing counter covers it. Cross-check against the report's authoritative file and changed-code summaries.

- **Mirror the enforced selector and map moved code.** Reproduce both the metric parser and the gate's changed-line selector (command, base, hunk alignment, path filter) before crediting gains. For relocated code, map old to new owner families first and report numerator, denominator, and missed-count changes separately; coordinate-only subtraction is not evidence.

- **Audit standalone test crates per hosted build mode.** Each independently compiled test crate carries its own root attributes; compile success in one mode proves nothing about the instrumented build. A missing coverage artifact after a compile failure is not a coverage percentage.

- **Scope every coverage closure statement.** Keep the complete changed-source inventory, give each closure claim an explicit file and behavior scope, and audit all changed mapped entries and non-instrumented files before promoting component closure to PR closure. For target-dependent impossibility, keep the real narrower-target check, make the target invariant explicit, and obtain cross-target evidence instead of manufacturing a native failure.

## Source and target identity

- Inspect raw function/region mappings for every changed test or source file even
  when a summary omits it. Empty matches are unknown evidence. Preserve byte
  count, digest, producer-log completeness, and exact checkout identity before
  interpreting missing source or tests from a rendered view.
- Join target-specific counters only through identity-bound observations from the
  required targets. Missing execution is not covered execution. Place safe policy
  decisions under their own coverage floor rather than hiding them beside a
  target-specific unsafe adapter. Audit every source-analysis consumer's test/cfg
  classification after moving helpers.
- Once coverage is complete, more tests cannot offset an existing function's
  increased complexity. Simplify the real control flow against the trusted
  baseline; do not rename or relocate a function to evade its regression identity.
- Audit the consuming target's edition, formatter configuration, and lexical lint
  context when moving Rust witnesses. Equivalent runtime code may acquire new
  lint obligations in a different scope.
