# Code review

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Use independent review within the authorized workflow.** Use the `code-review` skill when review is explicitly requested, with a fixed point and separate Standards and Spec axes. Address findings in a separate round and re-review the resulting exact head. Independent review is required before merge under the repository merge policy; implementation completion alone does not authorize spawning reviewers. A conflict-free PR or passing subset of checks is not merge readiness.

- **Review the complete PR diff after a head change.** A review of only the
  newest commit can miss regressions from earlier commits or conflict resolution.
  Pin the current PR base and final head, review their full merge-base diff, and
  record both identities.

- **Pin one review baseline before delegation.** Fetch the remote base and
  record its commit, feature head, merge-base, files, and complete commit list.
  Give every reviewer the same `base...HEAD` range. Any changed head invalidates
  the old source-review evidence and requires a newly pinned snapshot.

- **Disposition the complete finding set.** Preserve Standards and Spec as separate axes, and show every item as accepted, rejected, or deferred with current evidence, ownership, merge impact, and the concrete reason. Previous findings are leads rather than evidence; verify them against current lines, omit stale defects, and explain whether a disagreement comes from a code misread, an over-literal rule, or valid debt outside the ticket.

- **Separate ownership from correctness.** Defer a missing capability when an adjacent ticket owns it, but still flag provisional behavior that implements that capability incorrectly. Ticket boundaries prevent scope creep; they do not make incorrect behavior safe to merge as an accidental contract.

- **Bound and retrieve delegated review reports deliberately.** Require concise structured output, retrieve large independent reports one at a time, and adjudicate only after all axes complete. Combining unbounded reports in one response can truncate evidence and hide findings.

- **Do not infer specification compliance from green gates.** CI, coverage, mutation, lint, and security analysis can all pass while an acceptance criterion or ADR invariant remains unimplemented. Report source-review readiness and hosted-gate readiness as separate facts.

- **Give Spec reviewers the complete acceptance record.** Requirements alone are insufficient when delivery evidence lives in issue journals, PR descriptions, hosted reports, or recorded measurements. Supply those authoritative artifacts with the fixed review baseline, and require the reviewer to distinguish missing implementation from missing external evidence before assigning severity.

- **Bind blocking findings to immutable evidence.** Record the exact commit or revision and a directly inspectable source quote before escalating a finding; label everything else an unverified question. For ADRs, preserve the exact accepted revision as the normative source and use the newer page only to establish the acceptance decision.

- **Treat reviewable delivery scope as its own gate.** Before detailed source review, map the issue, approved prerequisites, seams, tests, and maintenance work to diff groups; when separately testable seams are bundled, propose dependency-ordered slices or request a scope exception. Never defer mandatory tests, claim unverified compilation, or add temporary authority bypasses to make a slice fit.

- **Enumerate every new reference in a hosted-only review.** Derive from the diff all new imports and qualified paths (including `crate::` and `super::`) and attach defining module, visibility or re-export, cfg availability, constructor visibility and parameter types, nested `Result` layers, and an already-compiled caller to each.

- **Check full trait obligations before hosted-only compilation.** For new trait implementations, inspect the full declaration, supertraits, auto-trait needs of each field, associated types, and feature graph. Formatting is never compiler evidence; keep compilation explicitly unverified until hosted CI confirms.

- **Verify exact-boundary and fault-injection claims.** An exact-limit claim needs a fixture whose tested quantity equals the limit, distinct from within-limit and one-over cases.

- **Make fault fixtures reach the boundary they claim to test.** A fault fixture proves only the boundary it reaches: trace it through earlier schema and admission checks and assert the fault was actually injected. Never weaken production constraints to inject the fault: use an isolated minimal owner-test schema that omits only the constraint preventing it, keep normal fixtures intact, and require hosted execution before treating the assertion as evidence.

- **Make temporal fixtures distinguish preserved state from a reset.** A temporal fixture must produce different outcomes for a preserved epoch versus a reset.

- **Audit the whole protected operation and the real read plan.** For resource and deadline claims, start at the protected entry point and inventory prefixes, helpers, suffixes, and every early return; preflight checks must mirror the executed lookups and scans. Include zero-work and zero-requirement success routes, test that unrelated indexed data cannot consume the operation's quota, prefer source-coupled encoding length over a second production wire-size model, and demand distinct architecture authority when a faithful fix expands a public seam.

- **Verify allocation inventories against the exact source.** Cite the exact pinned allocator expressions and reachable variants, not serializer conventions.

- **Refresh cumulative oracles when a phase becomes contextual.** Give exact and one-over integration oracles fresh values from independently encoded inputs and the actual repeated operations; never calibrate from measured usage.

- **Credit evidence at its real scope.** Before calling behavior absent, check existing public component witnesses and distinguish source presence, historical execution, final-head execution, and enclosing-consumer integration. Compare test scope across runners by test identity, not summary totals; demand a normative basis before requiring a Cartesian cross-product.

- **Preserve typed-reader compatibility.** A replacement reader must keep the pinned implementation's actual dispatch and stream-consumption contract; stricter acceptance requires an explicit compatibility decision and differential witnesses for previously accepted forms. Keep source hypotheses separate from executed parity.

- **Reuse an existing equivalent dependency seam before expanding a public interface.** Inspect the pinned dependency's implementation and default-feature APIs, verify semantic equivalence from primary sources and an independent public oracle, and classify the reuse against the accepted decision. Do not substitute a prehash or feature-gated primitive merely because it avoids allocation.

- **Review evidence-producing workflows as a full execution graph.** Triggers, permissions, environment, job set, controls, ordered steps, and the producer command must be parsed and tested as an allowlist, with adversarial mutations for fabrication, reordering, skipping, non-blocking execution, and permission escalation.

- **Separate raw evidence identity from parsed views.** Keep job and commit identity, byte count, and digest of raw hosted evidence; treat an empty matcher as unknown, not as proof of absence.

- **Bind each evidence class to its exact tree.** Record the review base, head, comparator baseline, checkout, and merge parents separately for each evidence class, and recompute statistics against the chosen baseline. Merge-ref results are integration evidence, not head execution.

- **Propagate task constraints to every reviewer.** A user-set constraint such as hosted-only validation must appear in the coordinator checklist and each delegated prompt unchanged.
