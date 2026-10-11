# CI core-cache policy

The `test`, `clippy`, and `coverage` jobs restore their Rust caches on every
eligible run, but write them only from `main`:

```yaml
save-if: ${{ github.ref == 'refs/heads/main' }}
```

This is the runtime mechanism, not a convention enforced by a wrapper. The
pinned `Swatinem/rust-cache` action documents `save-if: false` as
restore-only, and its save implementation writes only when the resolved input
is `true`. GitHub Actions permits `github`-context expressions in a step's
`with` values; a pull-request run's `github.ref` is its merge reference rather
than `refs/heads/main`.

The compact executable contract in
[`scripts/test_ci_workflow_policy.py`](../../scripts/test_ci_workflow_policy.py)
protects the `pull_request` and `main` push triggers, the core jobs'
main-push reachability, the unconditional scope and preflight prerequisites,
the three cache identities, the pinned action revision, and the main-only
write condition. The contract requires the unfiltered `pull_request` trigger
and the sole `main` push branch, avoiding ordered branch-exclusion patterns
that can superficially contain `main` while suppressing its event. It also
requires each cache step to run on pull requests, so a step-level condition
cannot turn a restore into a silent skip. Adversarial mutations prove those
trigger, prerequisite, reachability, and restore-path protections fail closed.
It reuses the existing pinned-PyYAML policy-test harness. It deliberately
replaces a standalone checker and its self-test: direct assertions are enough
for this small, repository-specific workflow invariant.

Shell `grep` is not used because it cannot reliably associate YAML fields with
the intended job. Adding `yq` would introduce a second parser/tool dependency
solely for this assertion. The other Python policy scripts remain appropriate
where they validate larger structured contracts (for example, ASan and
`cargo-crap`) or generate/verify structured evidence; they should not be
rewritten merely to eliminate Python.

## Sources

- [Pinned rust-cache action metadata](https://github.com/Swatinem/rust-cache/blob/f0d9c3887740aee45f6153b24b3a6b815192ec16/action.yml)
- [Pinned rust-cache save implementation](https://raw.githubusercontent.com/Swatinem/rust-cache/f0d9c3887740aee45f6153b24b3a6b815192ec16/src/save.ts)
- [GitHub Actions contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts)
- [GitHub cache access restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#restrictions-for-accessing-a-cache)
