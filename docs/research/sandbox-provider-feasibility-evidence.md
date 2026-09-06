# Sandbox Provider feasibility evidence

Status: completed throwaway prototype for Redmine #211  
Decision governed by: [ADR-069](https://redmine.piglor.com/projects/pigloros/wiki/ADR-069_Linux_public_adapter_process_sandbox)  
Prototype branch: `codex/ticket-211-sandbox-provider-prototype-v2`  
Initial evidence commit: `e5a191a2d370e71551059a69630975644ce6588f`

Pinned-host evidence commits: `c10c59705320f215d1b21900ee6a52b9ed838e8c`, strengthened by `8d613baad514d53c4ac984627e8dd42d1d1abdf0`

Hosted runs: [initial 34022822716](https://github.com/arceushui/pigloros/actions/runs/34022822716), [pinned host 34036714171](https://github.com/arceushui/pigloros/actions/runs/34036714171), [strengthened pinned host 34037903952](https://github.com/arceushui/pigloros/actions/runs/34037903952)
Recorded: 2026-09-06

## Conclusion

The pure-Rust typed control-plane approach is feasible for systemd transient units, route netlink, direct nftables transactions, cgroup-v2 controls, broker-death cleanup, restart reconciliation, and concurrent attempts. Every measured latency is comfortably below the ADR-069 threshold on both hosted architectures.

The pinned NixOS supplement closes only part of the host-baseline gap in the initial run. On both architectures it boots a disposable VM from exact nixpkgs revision `6713828a351efa628b025a1adf7f43cbf8597513` (`sha256-Fd3OB8J9JhgliQwOKcqx4M672CInxi1I5VnwsaXeSQo=`), verifies Linux 6.12.108 and systemd 260.2, behaviorally proves QEMU-enforced no-egress, creates all six namespaces together and enters each retained descriptor separately, observes dm-verity capability, records 30-sample distributions, emits raw non-default cgroup values, and exercises `cgroup.kill` on a root-managed transient child cgroup.

ADR-069 is still **not ready for acceptance**. The evidence does not activate an admitted signed SIM1 image, prove the exact transient `Type=exec` security-property matrix and SCS1 readback, force every required limit outcome, emit complete HCP1/PCR1 records, or verify the full cleanup surface. Production implementation remains blocked.

## Evidence environment

| Architecture | Runner image | Kernel | systemd | Result |
|---|---|---|---|---|
| x86_64 | `ubuntu26` `20260831.124.1` | `7.0.0-1012-azure` | `259 (259.5-0ubuntu3.4)` | Workflow passed |
| aarch64 | `ubuntu26-arm64` `20260831.111.1` | `7.0.0-1012-azure` | `259 (259.5-0ubuntu3.4)` | Workflow passed |

The pinned supplement adds these guest environments:

| Architecture | Guest source | Kernel | systemd | VM acceleration | Result |
|---|---|---|---|---|---|
| x86_64 | exact nixpkgs revision and 4,609-entry build-derivation requisite closure | `6.12.108` | `260 (260.2)` | KVM | Workflow passed |
| aarch64 | exact nixpkgs revision and 3,834-entry build-derivation requisite closure | `6.12.108` | `260 (260.2)` | same-architecture TCG | Workflow passed |

The workflow grants only `contents: read`, disables checkout credential persistence, references no secrets or caches, and pins every action by commit SHA. The initial jobs establish a fresh secretless hosted job and process-level no-host-network execution. The supplemental NixOS VMs additionally set QEMU `restrict=on`; a verified HTTP endpoint on the VM host is unreachable from each guest, behaviorally proving the independent VM egress boundary rather than inferring it from guest route shape.

## Primitive results

| Requirement | Evidence | Conclusion |
|---|---|---|
| Typed systemd D-Bus | Generated `zbus_systemd` calls create, bind, stop, kill, query, and reconcile transient units without `systemd-run` | Feasible on systemd 259 and pinned systemd 260.2; exact `Type=exec` policy remains unproved |
| Route netlink | `rtnetlink` creates, reads back, and deletes uniquely named dummy links | Feasible on both architectures and under eight concurrent attempts |
| Atomic nftables policy | One typed NFNL batch creates an owned `inet` table, output base chain with default-drop policy, and one exact allow rule for IPv4 TCP `127.0.0.1:443`; table, chain, rule, expressions, and ownership data are read back before table deletion | Feasible on both architectures and under eight concurrent attempts |
| Namespace handles | Parent retains descriptors across child exit and compares namespace inode identity | All six are created together in both pinned guests, but fresh helpers enter each retained descriptor separately; all-six entry in one process remains unproved |
| cgroup v2 limits | systemd applies `MemoryMax=128 MiB`, `MemorySwapMax=0`, `CPUQuotaPerSecUSec=500000`, `TasksMax=16`, and non-default `IOWeight=200`; the probe emits and matches raw `memory.max`, `memory.swap.max`, `cpu.max`, `pids.max`, and `io.weight`, writes `1` to `cgroup.kill`, reaps the worker, and proves unit removal | Feasible on both pinned architectures; cgroup delegation and D-Bus delegation readback remain unproved |
| dm-verity | Capability probe checks `/sys/module/dm_verity` and `/dev/mapper/control` and refuses unsigned/path-based substitution | Host mechanism present in both pinned guests; signed SIM1 activation remains unproved |
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

The strengthened pinned-host run repeated the same sample counts on Linux 6.12.108 and systemd 260.2:

| Architecture | Mode | Launch p95 | Cleanup p95 | Result |
|---|---|---:|---:|---|
| x86_64 | Normal | 34.618 ms | 85.331 ms | Pass |
| x86_64 | Cancellation | 38.683 ms | 89.188 ms | Pass |
| x86_64 | Forced | 38.792 ms | 195.521 ms | Pass |
| aarch64 TCG | Normal | 206.262 ms | 1,008.718 ms | Pass |
| aarch64 TCG | Cancellation | 197.715 ms | 1,097.645 ms | Pass |
| aarch64 TCG | Forced | 226.071 ms | 1,135.263 ms | Pass |

Pinned complete-lifecycle p95 was 43.254 ms on x86_64 and 325.807 ms on aarch64 TCG. Every result remains below the ADR thresholds.

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

The pinned-host prototype source digest is `3d6d449d798183994b94c9555cd78b54c8e4f3f505240eb46b8484c186c75a09` for `src/main.rs`. The prototype is explicitly throwaway and must not be copied into production code.

## Remaining ADR-069 gates

1. Supply an admitted signed SIM1 image, verification keyring, immutable image handles, and dm-verity-capable host; prove activation and exact mounted identity. No unsigned compatibility path is allowed.
2. Prove a transient `Type=exec` service with every section 6 security property and the selected SCS1 requested/effective syscall arrays read back exactly.
3. Force and observe the mandatory memory, task, CPU-watchdog, file, and output outcomes rather than relying only on configured-limit readback.
4. Enter all six retained namespace descriptors in one process and use a delegated cgroup with exact D-Bus delegation readback.
5. Emit complete HCP1/PCR1 evidence and verify cleanup of every owned cgroup, namespace, nftables, veth, mount, and tmpfs resource.
6. Extend the prototype policy to the complete ADR filesystem, endpoint-proxy, bounded capture/replay, revocation, and provenance contract. The current exact allow rule proves nftables mechanics only.

## Preserved raw evidence

The repository preserves both architecture host identities, initial results, cgroup read-back, eight-attempt summaries, all 90 cleanup samples, all 30 lifecycle samples, p95 summaries, broker-death and restart-reconciliation traces, the complete dependency graph/package list, source digest, compiler identity, and cargo-deny conclusion in [`docs/research/evidence/sandbox-provider-211`](evidence/sandbox-provider-211/). Run 34037903952 additionally preserves the exact flake identity, full VM transcript, pinned-host distributions, and sorted build-derivation requisite closure for each architecture. The strengthened durable Redmine archives are [x86_64](https://redmine.piglor.com/attachments/download/10/ticket-211-pinned-host-x86_64-run-34037903952.zip), SHA-256 `26398d82d4afa0e625862c99580acdd4a559a7a94158fc6c0df8496e1d96e917`, and [aarch64](https://redmine.piglor.com/attachments/download/11/ticket-211-pinned-host-aarch64-run-34037903952.zip), SHA-256 `76f55fd8ec1727e58b8ae340d8772bc1fe7282c0626d46a1e688e5d163ffed40`. The earlier attachments 8/9 remain historical evidence of the incomplete output-path recording and are superseded by attachments 10/11.
