# Next CI latency improvement after PRs #483 and #484

Research snapshot: 2026-10-12. PR #484 is merged at `c38d010`; PR #483 is
queued at `0dd7033`. All Cargo evidence in this report comes from GitHub-hosted
runs. No Cargo command was run locally.

## Recommendation

Start the existing full `cargo-geiger` job after `preflight-gate`, in parallel
with `fmt`, `clippy`, `test`, and `coverage`, but keep it mandatory in
`standard-gate`. Also make the eight-heavy-runner ceiling structural: make the
post-core release wait for the independently-started `ledger-windows` job
before it fans out the remaining seven standard jobs.

This changes scheduling, not coverage. Across seven successful hosted runs,
Geiger delayed the standard gate by a median **11m15s** (range **4m36s–17m15s**).
Moving it earlier should remove nearly all of that delay while preserving every
current check. It does not reduce Geiger's runner minutes; its trade-off is
spending those minutes on a pull request that later fails a core gate.

After that low-risk change, run a hosted A/B experiment replacing only the
normal test-execution step with the already-pinned `cargo-nextest`, followed by
a separate doctest step. The current test job is the longest core gate, but
reducing it alone has limited end-to-end value because coverage then becomes
the core critical path.

## Evidence

The current graph deliberately runs cheap policy checks first, then four core
jobs, then `cargo-crap`, up to eight standard jobs, mutation, and ASan. The
full Geiger audit is in the standard fan-out even though it is a prerequisite
of `standard-gate`. Its repository script invokes Geiger sequentially for all
33 workspace package manifests because Geiger cleans its shared target data.

Seven recent successful hosted runs show:

| Gate | Median | Observed range | Critical-path interpretation |
|---|---:|---:|---|
| `fmt` | 8m19s | 4m27s–8m22s | Not core-critical; PR diff rustfmt already returns in about 20–30s |
| `clippy` | 3m07s | 1m39s–4m22s | Fast core feedback |
| `test` | 18m25s | 14m06s–18m49s | Usually the core critical path |
| `coverage` | 15m45s | 10m33s–15m57s | Becomes critical if test is shortened |
| `cargo-geiger` | 27m41s | 17m15s–29m18s | Slowest standard job |
| delay attributable to Geiger | **11m15s** | **4m36s–17m15s** | Direct scheduling opportunity |

The sample is runs
[`38106211848`](https://github.com/arceushui/pigloros/actions/runs/38106211848),
[`38117824524`](https://github.com/arceushui/pigloros/actions/runs/38117824524),
[`38123617316`](https://github.com/arceushui/pigloros/actions/runs/38123617316),
[`38129035993`](https://github.com/arceushui/pigloros/actions/runs/38129035993),
[`38152253181`](https://github.com/arceushui/pigloros/actions/runs/38152253181),
[`38152298412`](https://github.com/arceushui/pigloros/actions/runs/38152298412), and
[`38195167875`](https://github.com/arceushui/pigloros/actions/runs/38195167875).
For each run, “delay attributable to Geiger” is the Geiger completion time
minus the latest completion time of the other standard-gate prerequisites.

The first post-#484 main
[`38200354565`](https://github.com/arceushui/pigloros/actions/runs/38200354565)
was still active at the snapshot. Its core gates took 3m59s (`clippy`), 4m46s
(`fmt`), 15m55s (`coverage`), and 18m43s (`test`). Every other standard job was
finished by 04:08:25 UTC while Geiger was still running, independently
confirming the bottleneck. PR #483's Trunk test
[`38202129670`](https://github.com/arceushui/pigloros/actions/runs/38202129670)
was also active; its restore-only cache policy had already produced a 1m20s
`clippy` result.

PR #484's final PR run and Trunk merge run completed in 77m56s and 78m23s.
Their two ASan remainder shards were 37m03s/38m19s and 26m07s/37m07s,
respectively. That supports treating the remainder split as complete rather
than immediately repartitioning ASan again.

In the active main test job, the full `cargo test` step took about 16m05s.
Compilation finished after about 4m15s, while the 246 emitted test summaries
reported 562.93 seconds of execution in aggregate. Cargo runs distinct test
executables serially; this is a plausible nextest opportunity, not proof of a
specific speed-up.

## Ranked options

| Rank | Change | Expected effect | Risk and cost |
|---:|---|---|---|
| 1 | Start full Geiger with the core jobs; retain it in `standard-gate` | Median wall reduction about **11m**, observed opportunity **5–17m** | Low correctness risk; runner-minutes unchanged; failed-core PRs may spend Geiger minutes unnecessarily |
| 2 | Hosted A/B of nextest for the normal test step, plus separate doctests | Estimated **4–6m** off the test job and runner cost; only **0–3m** end-to-end until coverage is faster | Medium compatibility risk: exact ignored-test, doctest, retry, process, and test-count equivalence must be proved |
| 3 | After equivalence evidence, make full Geiger main/scheduled-only; keep compiler and manifest-policy enforcement blocking PRs | Removes **17–29 runner-minutes** per PR and the same critical delay as rank 1 | Medium governance risk: changes when the independent audit runs |
| 4 | Coverage sharding or compiler-cache service | Unknown until profiled | High complexity and cache/concurrency risk; not justified by present evidence |

### Why Geiger can move without weakening the gate

The proposed first change does not remove or narrow Geiger. It only starts it
earlier and keeps `standard-gate` dependent on its result.

There is also a defensible later case for reducing Geiger frequency. The root
workspace sets `unsafe_code = "forbid"`; policy checks require every non-shim
member to inherit that lint, reject overrides, and pin the Windows owner-bridge
shim exception and source inventory. Rust documents that `unsafe_code` catches
unsafe blocks and unsafe constructs, while `forbid` cannot be lowered by a
nested lint level. The current Geiger script then discards dependency findings
and asserts zero unsafe only for each workspace package. This is substantial
overlap, but the schedule/frequency decision should be made explicitly rather
than silently replacing the independent audit.

Geiger's `--forbid-only` mode is not a drop-in acceleration: upstream describes
it as checking entry points for forbid flags, whereas the repository policy
checker verifies workspace lint inheritance and the exact shim exception.
Upstream also rejects a virtual workspace manifest, explaining the per-package
loop. If Geiger remains blocking, pin `cargo-geiger@0.13.0` and disable installer
fallback so the executed audit cannot float independently of review.

### Hosted nextest experiment contract

The repository already pins and uses `cargo-nextest` 0.9.146 in ASan, so this
experiment introduces no new tool. A candidate must preserve the current
semantics, not merely produce a green run:

1. Run all workspace/all-feature tests with the lockfile, no user config, no
   default filter, and ignored tests included.
2. Run `cargo test --workspace --all-features --doc --locked` separately,
   because nextest does not execute doctests.
3. Compare discovered and executed test inventories with the existing hosted
   job; exercise ignored, process-sensitive, and failure-reporting cases.
4. Measure at least one warm-cache and one cold-cache hosted run before adopting
   it. Keep `test` as an early core job.

Nextest runs individual tests in parallel and defaults its thread count to the
available CPUs. A rough two-vCPU lower bound from the measured 562.93 seconds of
aggregate execution is 4m41s before scheduling and process overhead. Therefore
4–6 minutes is a planning estimate, not a promised result.

## Runner ceiling and failure feedback

With Geiger moved forward, the core phase uses five heavy runners. The existing
Windows job can overlap it, for six. After core and `cargo-crap`, the remaining
standard fan-out has seven jobs: rustdoc, reference evaluator, bundle
materialization, dependency policy, Docker, world-client WASM, and CodeQL.
Browser parity replaces the completed WASM runner rather than adding another.

To make the fixed limit provable instead of timing-dependent, the post-core
release should also depend on `ledger-windows`; in observed runs it finishes
well before core, so this should not delay normal execution. The worst standard
overlap is then seven jobs plus an unfinished Geiger: exactly **eight**. Add a
workflow-policy test for this graph invariant and for Geiger remaining a
required `standard-gate` dependency.

The fast-feedback order remains intact:

- PR diff formatting/policy checks remain preflight and return first.
- Full `fmt`, `clippy`, `test`, and `coverage` still start immediately after
  preflight.
- Geiger consumes one additional runner but does not gate those four jobs.
- Mutation and ASan still wait for the complete standard gate.

## Cache conclusion

At the snapshot, the repository held 64 GitHub caches totalling 10,643,180,858
bytes, about **99.1%** of GitHub's default 10 GiB repository limit. The main
`test`, `coverage`, and `clippy` caches alone occupied about 3.20 GB. GitHub
evicts least-recently-used caches over the limit and documents cache thrashing
as a consequence; pull-request caches are scoped to their merge ref.

PR #483's restore-only-on-PR policy addresses that exact failure mode while
retaining base-branch restores. Do not add a nextest, coverage-shard, or
compiler-cache namespace yet. Let #483 land, observe main cache residency and
PR restore hits, then make any further cache change against measured misses.

## Primary sources

- [Rust `unsafe_code` lint](https://doc.rust-lang.org/stable/nightly-rustc/rustc_lint/builtin/static.UNSAFE_CODE.html),
  [Rust `forbid` attribute](https://doc.rust-lang.org/stable/std/attribute.forbid.html), and
  [Cargo workspace lint inheritance](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-lints-table)
- [Cargo test execution model](https://doc.rust-lang.org/cargo/commands/cargo-test.html)
- [nextest execution](https://nexte.st/docs/running/) and
  [doctest limitation](https://nexte.st/docs/listing/)
- [`cargo-nextest` 0.9.146 manifest](https://raw.githubusercontent.com/nextest-rs/nextest/cargo-nextest-0.9.146/Cargo.toml)
  and [release](https://github.com/nextest-rs/nextest/releases/tag/cargo-nextest-0.9.146)
- [`cargo-geiger` purpose](https://github.com/geiger-rs/cargo-geiger),
  [0.13.0 CLI semantics](https://raw.githubusercontent.com/geiger-rs/cargo-geiger/cargo-geiger-0.13.0/cargo-geiger/src/args.rs), and
  [virtual-manifest handling](https://raw.githubusercontent.com/geiger-rs/cargo-geiger/cargo-geiger-0.13.0/cargo-geiger/src/main.rs)
- [GitHub Actions cache limits, scope, and eviction](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [Pinned `rust-cache` key and `save-if` behavior](https://raw.githubusercontent.com/Swatinem/rust-cache/f0d9c3887740aee45f6153b24b3a6b815192ec16/README.md)

## Validation boundary

This is a research-only change. Validation was limited to repository policy and
workflow inspection, GitHub-hosted run/job/log evidence, cache metadata, source
review, and `git diff --check`. No workflow, script, Rust source, issue, or pull
request was changed, and no Cargo command was run locally.
