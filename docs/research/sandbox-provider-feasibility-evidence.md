# Sandbox Provider feasibility evidence

Status: completed throwaway prototype for Redmine #211  
Decision governed by: [ADR-069](https://redmine.piglor.com/projects/pigloros/wiki/ADR-069_Linux_public_adapter_process_sandbox)  
Prototype branch: `codex/ticket-211-sandbox-provider-prototype-v2`  
Evidence commit: `e5a191a2d370e71551059a69630975644ce6588f`  
Hosted run: [34022822716](https://github.com/arceushui/pigloros/actions/runs/34022822716)  
Recorded: 2026-09-06

## Conclusion

The pure-Rust typed control-plane approach is feasible for systemd transient units, route netlink, direct nftables transactions, cgroup-v2 controls, broker-death cleanup, restart reconciliation, and concurrent attempts. Every measured latency is comfortably below the ADR-069 threshold on both hosted architectures.

ADR-069 is **not ready for acceptance** from this evidence. GitHub-hosted Ubuntu 26.04 supplied systemd 259 rather than the required systemd-260 baseline, rejected creation of a user namespace and therefore the complete required namespace set, and lacked dm-verity capability plus an admitted signed SIM1/keyring/image. The runner labels are floating rather than digest-pinned, and network isolation is enforced by the privileged probe entering a fresh network namespace rather than by independent VM-level egress policy. Production implementation remains blocked.

## Evidence environment

| Architecture | Runner image | Kernel | systemd | Result |
|---|---|---|---|---|
| x86_64 | `ubuntu26` `20260831.124.1` | `7.0.0-1012-azure` | `259 (259.5-0ubuntu3.4)` | Workflow passed |
| aarch64 | `ubuntu26-arm64` `20260831.111.1` | `7.0.0-1012-azure` | `259 (259.5-0ubuntu3.4)` | Workflow passed |

The workflow grants only `contents: read`, disables checkout credential persistence, references no secrets or caches, pins every action by commit SHA, and runs the privileged executable after it unshares its network namespace. These controls establish a fresh secretless hosted job and process-level no-host-network execution. They do not establish a digest-pinned VM or independently enforced no-egress infrastructure.

## Primitive results

| Requirement | Evidence | Conclusion |
|---|---|---|
| Typed systemd D-Bus | Generated `zbus_systemd` calls create, bind, stop, kill, query, and reconcile transient units without `systemd-run` | Feasible on systemd 259; systemd 260 still requires validation |
| Route netlink | `rtnetlink` creates, reads back, and deletes uniquely named dummy links | Feasible on both architectures and under eight concurrent attempts |
| Atomic nftables policy | One typed NFNL batch creates an owned `inet` table, output base chain with default-drop policy, and one exact allow rule for IPv4 TCP `127.0.0.1:443`; table, chain, rule, expressions, and ownership data are read back before table deletion | Feasible on both architectures and under eight concurrent attempts |
| Namespace handles | Parent retains descriptors across child exit and compares namespace inode identity | Mount, PID, IPC, UTS, and network pass individually; user namespace and therefore the complete set are unsupported on both hosted runners |
| cgroup v2 limits | systemd applies `MemoryMax=128 MiB`, `CPUQuotaPerSecUSec=500000`, `TasksMax=16`, and `IOWeight=100`; the probe reads effective `memory.max`, `cpu.max`, `pids.max`, and `io.weight` before cleanup | Feasible on both architectures |
| dm-verity | Capability probe checks `/sys/module/dm_verity` and `/dev/mapper/control` and refuses unsigned/path-based substitution | Unsupported: host capability absent and no admitted SIM1, keyring, or image was available |
| Broker death | Attempt scope is bound to the broker scope; worker and descendant termination plus both-unit disappearance are verified | 46.188 ms x86_64; 38.431 ms aarch64 |
| Restart reconciliation | A later controller invocation discovers and stops an injected orphan scope, then verifies worker, descendant, and unit absence | 51.752 ms x86_64; 43.607 ms aarch64 |
| Eight concurrent attempts | Unique systemd, link, and nftables identities are exercised concurrently | Passed on both architectures |

## Performance distributions

Each architecture recorded 30 normal launches/cleanups, 30 cancellation launches/cleanups, 30 forced launches/cleanups, and 30 complete primitive lifecycles. p95 is the 29th value of each sorted 30-sample set.

| Architecture | Mode | Launch p95 | Cleanup p95 | ADR threshold | Result |
|---|---|---:|---:|---:|---|
| x86_64 | Normal | 14.170 ms | 51.984 ms | 2 s / 2 s | Pass |
| x86_64 | Cancellation | 12.329 ms | 52.929 ms | 2 s / 2 s | Pass |
| x86_64 | Forced | 12.383 ms | 104.347 ms | 2 s / 5 s | Pass |
| aarch64 | Normal | 22.206 ms | 51.755 ms | 2 s / 2 s | Pass |
| aarch64 | Cancellation | 22.604 ms | 52.982 ms | 2 s / 2 s | Pass |
| aarch64 | Forced | 22.503 ms | 105.137 ms | 2 s / 5 s | Pass |

The complete primitive lifecycle p95 was 36.291 ms on x86_64 and 39.048 ms on aarch64. Restart reconciliation remained far below the 10-second ADR threshold.

## DependencyEvidence

The isolated prototype has its own committed `Cargo.lock` with SHA-256 `d40dd79bcaaea4b4b4dd8b5b047fa88fe2a00923b68d316bdd17d16aedd0ba11`. The graph contains 100 packages. The complete edge graph and package identity/licence/MSRV records are preserved under [`evidence/sandbox-provider-211`](evidence/sandbox-provider-211/).

Exact direct dependencies:

| Crate | Version | Role |
|---|---:|---|
| `futures-util` | 0.3.34 | Typed asynchronous stream handling |
| `zbus_systemd` | 0.26100.0 | Generated systemd interfaces |
| `zbus` | 5.19.0 | D-Bus transport and values |
| `rtnetlink` | 0.23.0 | Route-netlink operations |
| `netlink-packet-route` | 0.33.0 | Typed route messages |
| `netlink-packet-netfilter` | 0.4.0 | Typed nftables messages and expressions |
| `netlink-packet-core` | 0.9.0 | Netlink envelopes |
| `netlink-sys` | 0.9.0 | Direct netfilter socket |
| `nix` | 0.31.3 | Namespace syscalls with only `sched` enabled |
| `tokio` | 1.53.1 | Bounded async runtime with `macros`, `rt-multi-thread`, and `time` |

The prototype declares Rust 1.87. Hosted `cargo +1.87.0 check --locked` passed on both architectures, and the highest transitive declared MSRV is 1.87.0. The evidence compiler was Rust 1.97.1. `cargo deny --locked check` concluded `advisories ok, bans ok, licenses ok, sources ok`; no package lacks a declared licence. All observed SPDX expressions are combinations of MIT, Apache-2.0, BSD-2-Clause, Unicode-3.0, LLVM exception, LGPL-2.1-or-later, or Unlicense covered by repository policy.

The final prototype source digest is `c1376622d2698e0396822f6f9176fe11140260be007f58ad3ecaf7282ac6f7c1` for `src/main.rs`. The prototype is explicitly throwaway and must not be copied into production code.

## Remaining ADR-069 gates

1. Run the same evidence on digest-pinned x86_64 and aarch64 disposable VMs with Linux 6.12 and systemd 260, with independently enforced no-egress policy during privileged execution.
2. Enable and prove the complete mount/PID/IPC/UTS/user/network namespace set. The hosted runner's user-namespace rejection is a hard blocker, not an optional fallback.
3. Supply an admitted signed SIM1 image, verification keyring, immutable image handles, and dm-verity-capable host; prove activation and exact mounted identity. No unsigned compatibility path is allowed.
4. Compare the same minimal attempt against youki `libcontainer`/`libcgroups`, including code surface, native dependencies, exact policy read-back, launch/cleanup latency, and lifecycle recovery. The existing [open-source landscape](sandbox-provider-open-source-landscape.md) is a design comparison, not this missing execution benchmark.
5. Extend the prototype policy to the complete ADR filesystem, seccomp, capability, endpoint-proxy, bounded capture/replay, revocation, and provenance contract. The current exact allow rule proves nftables mechanics only.

## Preserved raw evidence

The repository preserves both architecture host identities, initial results, cgroup read-back, eight-attempt summaries, all 90 cleanup samples, all 30 lifecycle samples, p95 summaries, broker-death and restart-reconciliation traces, the complete dependency graph/package list, source digest, compiler identity, and cargo-deny conclusion in [`docs/research/evidence/sandbox-provider-211`](evidence/sandbox-provider-211/). The GitHub run remains the authoritative execution record for commit `e5a191a2`.
