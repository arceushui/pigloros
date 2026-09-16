# systemd v260.2 limit semantics for the #214 provider

**Scope.** This is bounded source research, not a #214 implementation, host
probe, or conformance claim. It uses the pinned systemd tag `v260.2` and Linux
`v6.12` documentation. “Requested state” below means the transient-unit D-Bus
property was accepted and stored by systemd. It does **not** establish that a
future provider has started a unit, read the live cgroup/kernel state, or
produced the ADR-069-required ELM1/SAU1/SPR1 evidence.

## Decision-relevant conclusion

The initial provider can use the selected maintained, generated
`zbus_systemd 0.26100.0` systemd1 binding with `zbus 5.19.0`; this research
does not recommend a bespoke D-Bus proxy, a new runtime, or a workaround for
an incompatible zero. The binding's documentation calls its service modules
auto-generated and exposes the `systemd1` module behind its feature; it uses
zbus without default features and documents selectable async executors.
([binding docs](https://docs.rs/zbus_systemd/0.26100.0/zbus_systemd/),
[zbus runtime docs](https://docs.rs/zbus/5.19.0/zbus/)). Its published
MIT/Apache-2.0 licensing fits `deny.toml`'s allow-list. The dependency is not
currently present in `Cargo.toml`/`Cargo.lock`, so any future manifest change
still needs the repository's normal dependency review, locked resolution,
feature selection, and hosted/privileged evidence; this note authorizes none
of those changes.

The exact v260.2 D-Bus rules make a generic “zero means unlimited” encoder
wrong:

| ELM1 value / target | v260.2 requested-state result | Kernel/live meaning that still needs read-back |
|---|---|---|
| `0 MemoryBytes` → `MemoryMax` | **Rejected**: its D-Bus setter has minimum 1. | Therefore a literal zero ceiling cannot be represented by this property alone; do not silently send infinity/default. |
| `0 SwapBytes` → `MemorySwapMax` | **Accepted**: its setter has minimum 0. | systemd writes `0` to `memory.swap.max`; Linux says reaching it prevents anonymous memory being swapped out. |
| `0 Tasks` → `TasksMax` | **Rejected**: setter requires at least 1. | Do not silently turn it into unlimited/default. |
| `0 CpuQuotaPerMillion` → `CPUQuotaPerSecUSec` | **Rejected** with D-Bus `InvalidArgs`. | Finite nonzero quotas are rounded by systemd's `cpu.max` writer; see below. |
| `0 WatchdogMilliseconds` → `RuntimeMaxUSec` | **Accepted as literal 0**, not normalized to infinity by this setter. | A running service timer is armed for the resulting runtime deadline; this is not evidence that an attempt was stopped or that its cgroup was cleaned. |
| `u64::MAX` cgroup memory/swap/tasks / CPU / runtime | systemd's sentinels map this to unlimited for these controls: memory writes `max`, TasksMax writes `max`, and CPU uses `max <period>`; service default/runtime sentinel is `USEC_INFINITY`. | Read back exact D-Bus and kernel values. `u64::MAX` must never arise from a finite ELM1 arithmetic overflow. |
| `0 WorkBytes` → tmpfs `size=0` | Not a systemd D-Bus property. | Linux v6.12 states `size=0` means blocks are not limited: it is **unlimited**, the opposite of ELM1 zero. |
| `0 OpenFiles` / `0 FileBytes` → rlimits | Accepted as a literal rlimit value. First hard-property write initializes *both* soft and hard; later `Limit…Soft` changes only soft. | Applied during exec through `setrlimit_closest_all`; a malformed `soft > hard` pair is not a usable applied limit, and live process rlimit plus terminal evidence remain required. |

The bold requested-state facts are source facts. Whether the provider should
reject zero ELM1 before `StartTransientUnit`, produce a policy-specific
unavailable result, or employ a separately accepted mechanism is an **inference
for the #214 design/review**, not a behavior established here. No custom
zero-WorkBytes workaround is proposed.

## Primary-source trace

### D-Bus setter acceptance and sentinels

- `MemoryMax` uses `BUS_DEFINE_SET_CGROUP_LIMIT(..., minimum=1)`, while
  `MemorySwapMax` uses the same helper with `minimum=0`. The helper stores the
  unsigned `t` unchanged and recognizes `CGROUP_LIMIT_MAX`; that constant is
  `UINT64_MAX`. [v260.2 `dbus-cgroup.c`](https://github.com/systemd/systemd/blob/v260.2/src/core/dbus-cgroup.c#L831-L919)
  [v260.2 constant](https://github.com/systemd/systemd/blob/v260.2/src/basic/cgroup-util.h#L74-L79)
- `TasksMax` reads `t`, rejects `v < 1`, and treats `CGROUP_LIMIT_MAX` as
  `infinity`. [v260.2 setter](https://github.com/systemd/systemd/blob/v260.2/src/core/dbus-cgroup.c#L952-L985)
- `CPUQuotaPerSecUSec` reads `t`, rejects `u64 <= 0`, and maps
  `USEC_INFINITY` to an empty `CPUQuota=` setting. Thus zero is not an
  admissible D-Bus value and `UINT64_MAX` is its systemd unlimited sentinel.
  [v260.2 setter](https://github.com/systemd/systemd/blob/v260.2/src/core/dbus-cgroup.c#L1140-L1166)
- `RuntimeMaxUSec` delegates to `bus_set_transient_usec`, not the `_fix_0`
  variant. The shared helper stores zero unchanged; only `_fix_0` rewrites zero
  to `USEC_INFINITY`. `Service` initializes `runtime_max_usec` to infinity and
  arms its running timer from that value, so the source supports “zero is a
  literal immediate deadline”, not “zero disables it.”
  [service property](https://github.com/systemd/systemd/blob/v260.2/src/core/dbus-service.c#L636-L638)
  [generic setter](https://github.com/systemd/systemd/blob/v260.2/src/core/dbus-util.c#L122-L158)
  [service default/timer](https://github.com/systemd/systemd/blob/v260.2/src/core/service.c#L177-L190)
  [timer arm](https://github.com/systemd/systemd/blob/v260.2/src/core/service.c#L2438-L2448)

### Translation to cgroup v2, including CPU rounding

- Finite memory/swap values are written as their decimal number; the
  `UINT64_MAX` sentinel is written as `max`. The application site is exactly
  `memory.max` and `memory.swap.max`. [v260.2 writer](https://github.com/systemd/systemd/blob/v260.2/src/core/cgroup.c#L1243-L1250)
  [v260.2 application](https://github.com/systemd/systemd/blob/v260.2/src/core/cgroup.c#L1486-L1502)
- A finite CPU quota is translated to `cpu.max` as
  `max(quota × period / 1_000_000, 1_000)` microseconds; the period is adjusted
  into `[1 ms, 1 s]`. Infinity is written as `max <period>`. Consequently,
  equality of the requested `CPUQuotaPerSecUSec` with an ELM1 ceiling is not
  equality of a tiny kernel quota: any finite requested quota that would
  calculate below 1 ms becomes 1 ms. This is a source fact; mapping an ELM1
  CPU unit to systemd microseconds is a provider-design inference and must not
  claim deterministic fuel equivalence.
  [v260.2 clamp](https://github.com/systemd/systemd/blob/v260.2/src/core/cgroup.c#L1030-L1061)
  [v260.2 writer](https://github.com/systemd/systemd/blob/v260.2/src/core/cgroup.c#L1092-L1108)
  [v260.2 manual](https://github.com/systemd/systemd/blob/v260.2/man/systemd.resource-control.xml#L254-L268)
- Linux 6.12 defines `memory.max` as a hard memory limit (with documented
  temporary overage cases), `memory.swap.max` as the hard swap limit,
  `pids.max` as a hard task limit, and `cpu.max`'s `max` token as no CPU
  bandwidth limit. [memory](https://github.com/torvalds/linux/blob/v6.12/Documentation/admin-guide/cgroup-v2.rst#L1296-L1311)
  [swap](https://github.com/torvalds/linux/blob/v6.12/Documentation/admin-guide/cgroup-v2.rst#L1716-L1722)
  [pids](https://github.com/torvalds/linux/blob/v6.12/Documentation/admin-guide/cgroup-v2.rst#L2247-L2255)
  [CPU](https://github.com/torvalds/linux/blob/v6.12/Documentation/admin-guide/cgroup-v2.rst#L1134-L1144)
- Linux 6.12 explicitly says `size=0` (or `nr_blocks=0`) leaves tmpfs blocks
  unlimited. [tmpfs documentation](https://github.com/torvalds/linux/blob/v6.12/Documentation/filesystems/tmpfs.rst#L89-L98)

### `LimitNOFILE` and `LimitFSIZE`: pair semantics and application

The Exec D-Bus setter recognizes `Limit*`/`Limit*Soft`, maps wire
`UINT64_MAX` to `RLIM_INFINITY`, and otherwise checks the u64-to-`rlim_t`
conversion. If there is no existing limit it sets **both** `rlim_cur` and
`rlim_max`; on an existing limit the non-Soft field updates hard and Soft
updates only soft. [v260.2 setter](https://github.com/systemd/systemd/blob/v260.2/src/core/dbus-execute.c#L3993-L4060)

For a unit-file colon form, systemd's rlimit parser rejects `soft > hard`; its
manual documents a single value as equal soft/hard and `infinity` as no limit.
The individual transient D-Bus setter shown above does not itself make that
pair validation, so a producer must send a consistent pair in an order that
does not transiently violate it.
[parser](https://github.com/systemd/systemd/blob/v260.2/src/basic/rlimit-util.c#L250-L288)
[manual](https://github.com/systemd/systemd/blob/v260.2/man/systemd.exec.xml#L1029-L1106)
At execution setup, systemd calls `setrlimit_closest_all`; the helper first
tries the requested pair and, only on `EPERM`, may lower both ends to the
current hard ceiling. Therefore requested D-Bus read-back alone is not proof
of the child process's applied rlimit. [exec path](https://github.com/systemd/systemd/blob/v260.2/src/core/exec-invoke.c#L5934-L5945)
[fallback behavior](https://github.com/systemd/systemd/blob/v260.2/src/basic/rlimit-util.c#L15-L77)

## Overflow and boundary rules (recommendations, not source facts)

1. Treat each ELM1 number as an unsigned literal ceiling. Decode and use
   `SelectorGrantCommitment::effective_limits()`, never raw selected arrays.
2. Do not encode a literal finite `u64::MAX` ELM1 ceiling as a backend infinity
   sentinel merely because the wire type is also unsigned. Sentinel collisions
   require explicit representability handling, just like zero; the ELM1 format
   supplies no implicit unlimited authority.
   For positive milliseconds supplied to a `…USec` D-Bus property, use checked
   `ms × 1_000`; reject an arithmetic overflow and reject a result equal to the
   reserved `u64::MAX` unlimited sentinel. Do not saturate: saturation would
   change a finite ceiling into unlimited. A checked conversion also must occur
   before constructing a D-Bus `t` value.
3. Preflight a representability matrix before the D-Bus call. The source
   establishes that zero MemoryBytes, Tasks, and CPU quota cannot be requested
   through the named property, while zero WorkBytes would become unlimited
   tmpfs. It does **not** establish which #214 terminal category should result;
   leave that choice to the accepted provider design.
4. For CPU, retain both requested `CPUQuotaPerSecUSec` and live `cpu.max` in
   the required evidence. Refuse to claim that a rounded `cpu.max` is an exact
   ELM1 ceiling or a deterministic CPU/fuel bound. The source writer also
   multiplies quota by the adjusted period before division; representability
   analysis must cover that intermediate arithmetic, not only the millisecond
   conversion. A property read-back does not verify that multiplication or a
   successful kernel write.
5. Ensure both rlimit ends are consistent with the selected ceiling and read
   them from the launched process before relying on it. The setter's initial
   hard-property write can set both ends; that does not establish that every
   future context begins with an unset limit. This note does not authorize
   additional `Limit…Soft` properties beyond the accepted unit configuration.
   Do not treat property ordering or systemd's EPERM “closest” fallback as
   authenticated authority.

## Existing repository seams and harness constraints

The present selector already derives the immutable authoritative ELM1 vector:
`derive_effective_limits` requires all 17 ordered IDs, takes
`min(broker, policy, applicable attempt)` and rejects effective watchdog zero
or `ConcurrentAttempts > 256`; `attempt_limit` has additional operands only
for IDs 0, 4, 8, and 9, returning `u64::MAX` for other IDs. That latter value
means “no same-unit attempt operand,” **not** backend unlimited authority.
`SelectorGrantCommitment::effective_limits()` exposes the retained derived
vector. [admission derivation](../../crates/pos-reference/src/sandbox_provider_protocol/admission.rs)

ADR-069 section 8 is explicit: every ID `0..16` is mandatory, unsigned zero is
a literal zero-capacity/deny-all ceiling, effective watchdog zero closes
admission, and concurrent attempts may not exceed 256. Its selected owners
also distinguish requested configuration from the required cgroup/process/
mount read-backs. The table above follows that separation and does not treat a
D-Bus success reply as kernel evidence. The normative input is
[Accepted ADR-069 revision 84, section 8](https://redmine.piglor.com/projects/pigloros/wiki/ADR-069_Linux_public_adapter_process_sandbox?version=84),
not this research note or an ephemeral local copy.

Repository inspection found no production privileged systemd provider runtime
harness. `scripts/run-isolated-test.sh` is a constrained Docker test wrapper
(network disabled, capabilities dropped, fixed container limits) and does not
exercise a host systemd transient unit. Existing materialization and conformance
scripts are fixture-oriented. Thus no repository executable currently produces
the live runtime/kernel evidence this research distinguishes above.

## Unresolved evidence / non-claims

- No actual systemd v260.2 + Linux 6.12 host was started, no D-Bus request was
  sent, and no cgroup, mountinfo, statfs, process rlimit, systemd result, or
  cleanup read-back was produced.
- The binding release was inspected as the selected generated-client surface;
  its exact resolved transitive graph, MSRV against this repository's pinned
  Rust 1.97.1, advisories, and enabled runtime feature set need locked build
  evidence before a dependency change. In particular, zbus documents both
  runtime-agnostic behavior and executor/thread trade-offs; choose deliberately
  rather than accidentally enabling defaults.
- Systemd's behavior proves neither a safe mapping for every literal-zero ELM1
  control nor a substitute mechanism. Such a mapping would be architecture and
  admission policy, outside this research and requiring accepted design work.
- No statement here satisfies #214 or claims a completed provider,
  conformance run, or production capability.
