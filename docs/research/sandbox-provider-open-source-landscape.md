# Open-source landscape for the ADR-069 Sandbox Provider Plugin

Status: research input for Redmine #191  
Checked: 2026-09-03  
Source policy: primary sources only—upstream repositories, project documentation, specifications, and release notes.

## Executive recommendation

No assessed project satisfies the approved ADR-069 requirements without substantial PiglorOS-specific orchestration. The missing whole is not Linux isolation itself; it is the combination of:

- an interchangeable, out-of-process `describe` / `execute` / `cancel` / `reconcile` provider contract;
- exact signed capability admission and immutable provider identity;
- LPS1 policy translation without backend-specific fields or silent fallback;
- signed image admission plus dm-verity activation checks;
- broker-mediated Local networking with bounded capture, digest, and replay evidence;
- fail-closed resource-limit precedence, revocation, cleanup, reconciliation, audit, and provenance.

The best initial implementation is therefore a small PiglorOS-owned **systemd Sandbox Provider Adapter**. Prototype [`zbus_systemd`](https://github.com/lucab/zbus_systemd) generated interfaces over [`zbus`](https://github.com/z-galaxy/zbus) for typed systemd D-Bus calls, [`rtnetlink`](https://github.com/rust-netlink/rtnetlink) plus [`netlink-packet-route`](https://github.com/rust-netlink/netlink-packet-route) for route/link operations, and direct nftables netlink with [`netlink-packet-netfilter`](https://github.com/rust-netlink/netlink-packet-netfilter). Keep the portable provider protocol, admission, transcript, revocation, and evidence logic in PiglorOS.

Use youki's `libcontainer`/`libcgroups` as a prototype comparator or a source of implementation patterns, not automatically as the first provider's control plane. Keep Firecracker or libkrun as candidates for a later VM-backed provider. Use runc, bubblewrap, and Kata Containers primarily as mature design references.

## Evaluation baseline

The comparison uses the canonical [ADR-069](https://redmine.piglor.com/projects/pigloros/wiki/ADR-069_Linux_public_adapter_process_sandbox), with the trust and protocol constraints inherited from [ADR-061](https://redmine.piglor.com/projects/pigloros/wiki/ADR-061_Sandboxed_Community_Plugin_Runtime_and_Decentralized_Artifact_Trust), [ADR-062](https://redmine.piglor.com/projects/pigloros/wiki/ADR-062_Independent_Evaluator_and_Conformance_Governance), and [ADR-068](https://redmine.piglor.com/projects/pigloros/wiki/ADR-068_Plugin-Owned_Extensible_Conformance_Fixture_Contracts). It also applies the approved #191 direction that the sandbox implementation is an interchangeable, locally admitted provider plugin rather than a hard-coded systemd implementation.

The resulting evaluation criteria are:

1. A root-owned broker admits an exact provider identity, version, capability manifest, executable path, binary digest, and test evidence. There is no central allow-list and no capability fallback.
2. The provider is out of process and exposes bounded `describe`, `execute`, `cancel`, and `reconcile` operations. Provider-specific details do not leak into LPS1.
3. The initial provider supports Linux 6.12+, cgroup v2, systemd 260+, namespaces, direct nftables/netlink control, tmpfs-only writable work space, and signed dm-verity-backed images.
4. Air-Gapped means no network namespace reachability. Local networking is only through broker-mediated exact TCP endpoints, with bounded capture, digest, and replay evidence.
5. Resource exhaustion, broker/provider death, cancellation, revocation, and cleanup are fail-closed operational outcomes. A resource-limit event overrides and discards otherwise valid adapter output.
6. The adapter wire protocol remains bounded, stdout-only for protocol output, and resistant to a malicious signed adapter. There is no direct-launch or legacy fallback.
7. The implementation works on x86_64 and aarch64, supports capability probes and an inert startup self-test, and records complete provider and sandbox provenance.

## Snapshot

| Project | Language and license | Current release or maintenance evidence | Privilege/rootless model | Coverage of sandbox concerns | Rust/native-dependency profile | ADR-069 role |
|---|---|---|---|---|---|---|
| youki | Rust; Apache-2.0 | [`v0.7.0`, 2026-07-25](https://github.com/youki-dev/youki/releases/tag/v0.7.0); active upstream | Rootful and user-namespace rootless; rootless cgroup v2 depends on delegation | Strong namespaces, mounts, seccomp, cgroups, OCI lifecycle; network and image trust remain external | Rust code at the control layer; default features use native/system components including libseccomp, libsystemd, libbpf/clang toolchains | Possible container-mechanics backend, but not a complete provider |
| Firecracker | Rust; Apache-2.0 | [`v1.16.1`, 2026-07-02](https://github.com/firecracker-microvm/firecracker/releases/tag/v1.16.1) | `/dev/kvm`; production jailer starts privileged and drops to a dedicated identity | Strong VM boundary, jailer, seccomp, cgroup/namespace setup, lifecycle API; host supplies network, image, and higher-level policy | Mostly Rust, with KVM/kernel ABI and low-level unsafe boundaries; requires kernel/guest artifacts | Future VM-backed provider substrate; substantial orchestration required |
| rust-vmm | Rust; Apache-2.0/BSD-3-Clause per crate | Active [monorepo](https://github.com/rust-vmm/rust-vmm); latest checked commit [`ffb0b5053186`, 2026-08-27](https://github.com/rust-vmm/rust-vmm/commit/ffb0b5053186313e2bf56e48b1565abf0f79ff2d) | Determined by the VMM assembled from the crates | Low-level KVM, virtio, memory, seccomp, and device primitives; no complete sandbox lifecycle | Rust-first but necessarily wraps ioctls, memory maps, and kernel ABIs; crate-specific native requirements | Reusable primitives only; building a provider directly would be a major VMM project |
| libkrun | Rust core with C API; Apache-2.0 | [`v1.19.4`, 2026-07-03](https://github.com/libkrun/libkrun/releases/tag/v1.19.4) | Can run as a user with KVM/HVF access; guest and VMM retain the same host security context | Embedded microVM execution, rootfs and several network modes; host must supply isolation, cgroups, trust, and lifecycle | Rust internals exposed as a native dynamic-library C ABI; KVM/HVF and firmware/runtime artifacts | Attractive future VM primitive, not a provider by itself |
| zbus | Rust; MIT | [`zbus-5.19.0`, 2026-08-09](https://github.com/z-galaxy/zbus/releases/tag/zbus-5.19.0) | Client privilege is determined by D-Bus policy; the ADR broker remains privileged | Typed D-Bus transport only; no sandbox mechanics | Rust implementation with no mandatory C D-Bus library | Recommended systemd-control primitive |
| zbus_systemd | Rust; MIT OR Apache-2.0 | [`v0.26100.0`, 2026-06-26](https://github.com/lucab/zbus_systemd/releases/tag/v0.26100.0) | Same D-Bus authorization model as zbus | Generated typed systemd interfaces including `StartTransientUnit`; no sandbox policy | Pure Rust over zbus; MSRV 1.87; generated from systemd 261 interfaces | Preferred prototype binding, subject to systemd-260 capability probing |
| systemd transient units | C; LGPL-2.1-or-later | [`v261.2`, 2026-07-23](https://github.com/systemd/systemd/releases/tag/v261.2); ADR minimum is 260 | PID 1 owns host cgroups; callers require system-bus authorization | Strong transient lifecycle, cgroup/resource policy, process restrictions, root-image integration; not network evidence or Piglor trust | Native host service; Rust talks to it through zbus | Recommended initial provider substrate, not the provider contract |
| rtnetlink | Rust; MIT | [`v0.23.0`, 2026-08-18](https://github.com/rust-netlink/rtnetlink/releases/tag/v0.23.0) | Host network changes need root/CAP_NET_ADMIN; rootless is namespace/delegation-limited | High-level links, addresses, routes, neighbours, and namespace helpers | Rust/netlink stack with `nix`/`libc`, no external C netlink library; namespace helper contains OS-level unsafe/fork logic | Recommended route/link primitive, with a custom FD-safe namespace lifecycle |
| netlink-packet-route | Rust; MIT | [`v0.33.0`, 2026-08-18](https://github.com/rust-netlink/netlink-packet-route/releases/tag/v0.33.0) | Same kernel capability model as route netlink | Typed route-netlink packet model only | Rust packet types; no external C library | Reusable primitive beneath rtnetlink |
| nftables-rs | Rust; MIT OR Apache-2.0 | [`v0.6.3`, 2025-08-15](https://github.com/nftables-rs/nftables-rs/releases/tag/v0.6.3); repository remained active after the release | `nft` operations need CAP_NET_ADMIN in the relevant namespace | Good nftables JSON data model; helper executes the external `nft` program | Rust types, but the execution helper has a native executable dependency | Type/reference value only; its command helper is unsuitable for ADR-069 |
| netlink-packet-netfilter | Rust; MIT | [`v0.4.0`, 2026-08-22](https://github.com/rust-netlink/netlink-packet-netfilter/releases/tag/v0.4.0) | Netfilter netlink needs CAP_NET_ADMIN in the relevant namespace | Low-level tables, chains, rules, sets, and expression packet types; no policy/lifecycle layer | Rust packet types using libc/zerocopy; no external C netfilter library declared | Preferred direct-netlink prototype primitive |
| bubblewrap | C; LGPL-2.0-or-later | [`v0.12.0`, 2026-08-26](https://github.com/containers/bubblewrap/releases/tag/v0.12.0) | Rootless user namespaces; current design removed setuid mode | Excellent empty-by-default mount namespace, PID namespace/reaping, seccomp, optional empty network namespace; no cgroup manager | Native C executable and Linux syscall dependencies | Reference implementation and possible low-level helper, not a complete provider |
| runc | Go; Apache-2.0 | [`v1.5.1`, 2026-07-14](https://github.com/opencontainers/runc/releases/tag/v1.5.1) | Rootful or user-namespace rootless; rootless cgroup v2 relies on delegation/systemd | Mature OCI namespaces, mounts, capabilities, seccomp, cgroups, and lifecycle; image/network/supervision external | Go runtime; seccomp builds can use native libseccomp/cgo | Mature lifecycle reference; a strict wrapper would still be substantial |
| Kata Containers | Mixed Rust, Go, and C ecosystem; Apache-2.0 | [`4.1.0`, 2026-08-21](https://github.com/kata-containers/kata-containers/releases/tag/4.1.0) | Hardware virtualization; documented rootless mode only makes the VMM unprivileged while other components remain privileged | Broad VM sandbox, guest agent, pluggable hypervisor/network/storage, host and guest cgroups | Large native stack: KVM and selectable VMM, guest kernel/image, containerd shim, and filesystem/network helpers | Best plugin/resource-lifecycle architecture reference; too broad for the initial provider |

## Detailed assessment

### youki

youki is a Rust implementation of an OCI runtime with `create`, `start`, `state`, `kill`, and `delete` lifecycle operations and documented rootless support ([README](https://github.com/youki-dev/youki/blob/v0.7.0/README.md)). Its `libcontainer` crate contains namespace, mount, capability, seccomp, process, and root-filesystem mechanics; its `libcgroups` crate exposes cgroup v1/v2 and systemd managers ([`libcontainer` manifest](https://github.com/youki-dev/youki/blob/v0.7.0/crates/libcontainer/Cargo.toml), [`libcgroups` manifest](https://github.com/youki-dev/youki/blob/v0.7.0/crates/libcgroups/Cargo.toml), [`libcgroups` documentation](https://youki-dev.github.io/youki/user/libcgroups.html)). Release 0.7.0 specifically records rootless cgroup-v2 and systemd D-Bus improvements ([release notes](https://github.com/youki-dev/youki/releases/tag/v0.7.0)).

**Privilege and scope.** Rootless mode uses user namespaces; useful cgroup-v2 control still depends on host delegation. youki covers most namespace, mount, seccomp, capability, cgroup, and process lifecycle mechanics. OCI networking is intentionally external to the runtime, and OCI image distribution/signature/dm-verity admission is outside its scope.

**Safety and dependencies.** The code is Rust, but isolation necessarily crosses unsafe syscall and kernel-ABI boundaries. Default features include systemd, cgroup v1/v2, and libseccomp; the documented build environment includes native `libsystemd`, `libseccomp`, `libelf`, `libbpf`, `clang`, and related packages. This is materially larger than adopting a pure Rust data-model crate.

**Fit.** youki could sit behind a Sandbox Provider Adapter, but it is not one. An OCI bundle is also broader than LPS1: it permits mounts, hooks, environment, paths, and capabilities that the Piglor broker must never accept unchecked. PiglorOS would still own provider admission, a restrictive LPS1-to-runtime translation, signed dm-verity image activation, Local capture/replay, revocation, result precedence, audit, and provenance.

**Ideas to borrow.** Reuse or imitate the explicit OCI lifecycle state machine, cgroup-manager abstraction, rootless-v2 capability checks, path-hardening work, and runtime conformance tests. Prototype `libcontainer`/`libcgroups` against direct systemd orchestration before accepting their native dependency and policy surface.

### Firecracker and rust-vmm

Firecracker runs one KVM microVM per VMM process and supplies an API socket, a jailer, seccomp filters, and x86_64/aarch64 support ([README](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/README.md), [design](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/design.md)). Production guidance requires the jailer and treats guest kernel/rootfs, TAP networking, rate limiting, and host setup as operator responsibilities ([production host setup](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/prod-host-setup.md)).

Firecracker offers a stronger isolation boundary than a native process, but it does not eliminate the provider. PiglorOS would need to provide a guest boot/image pipeline, immutable image admission, a guest-side adapter transport, host systemd/cgroup ownership, TAP or proxy network capture/replay, cancellation, reconciliation, trust-epoch revocation, and complete evidence. The latest v1.16.1 notes also reverted `O_NOFOLLOW` use for jailer cgroup and network-namespace paths, so ADR-069 cannot inherit those pathname semantics; immutable file descriptors/inodes and post-activation verification remain required ([v1.16.1 notes](https://github.com/firecracker-microvm/firecracker/releases/tag/v1.16.1)).

rust-vmm is the lower-level ecosystem from which a custom VMM can be assembled. Its charter emphasizes reusable, testable virtualization components rather than a single runtime ([community overview](https://github.com/rust-vmm/community/blob/main/README.md)). The official `vmm-reference` explicitly describes itself as experimental and not production-ready ([README](https://github.com/rust-vmm/vmm-reference/blob/main/README.md)); `seccompiler` is a useful Rust seccomp-BPF primitive with x86_64/aarch64 support ([repository](https://github.com/rust-vmm/seccompiler)).

**Fit.** Firecracker is a credible later VM-backed provider substrate. rust-vmm crates are primitives only, and a custom rust-vmm provider would amount to building and securing a VMM product. Neither is the shortest route to the approved native systemd provider.

**Ideas to borrow.** One isolated process/VM per attempt, a narrowly scoped control socket, split jailer/VMM responsibilities, per-thread seccomp, explicit supported-host policy, reproducible guest artifacts, and dedicated production-host validation. Do not inherit pathname-based trust or assume VM isolation supplies policy admission.

### libkrun

libkrun embeds a KVM/HVF microVM behind a compact C API and implements most internals in Rust ([README](https://github.com/libkrun/libkrun/blob/v1.19.4/README.md), [public header](https://github.com/libkrun/libkrun/blob/v1.19.4/include/libkrun.h)). It is easier to embed than a full container stack and supports root-path, executable, argv/environment, and network configuration.

Its own security documentation calls the result only partially isolated: the guest and VMM run under the same host security context, and the host must isolate the VMM. The virtio-fs mode does not itself prevent access outside the selected directory on the same filesystem. Its default transparent socket impersonation can proxy INET/INET6—and, in some configurations, UNIX sockets—so it must be explicitly disabled for ADR-069 Air-Gapped mode ([security and networking notes](https://github.com/libkrun/libkrun/blob/v1.19.4/README.md)).

**Privilege and dependencies.** On Linux it needs usable `/dev/kvm`; privilege depends on device access and the chosen host networking/filesystem setup. The Rust implementation is delivered through a native dynamic-library C ABI and also needs firmware/guest runtime artifacts. It does not supply Piglor cgroup/systemd lifecycle, trust, revocation, audit, or provider protocol.

**Fit and ideas.** libkrun is an attractive future VM provider primitive, especially if startup measurements beat Firecracker. Borrow its small configuration-context API and embedded guest-init model. A Piglor prototype should use a block/root-image path rather than broad virtio-fs sharing, disable transparent networking by default, and still run the VMM in a broker-owned transient cgroup.

### systemd over zbus

zbus provides high- and low-level Rust D-Bus APIs without a mandatory C D-Bus library, and its macro can generate typed proxies ([README](https://github.com/z-galaxy/zbus/blob/zbus-5.19.0/README.md), [`proxy` macro](https://docs.rs/zbus_macros/5.19.0/zbus_macros/attr.proxy.html)). systemd's D-Bus manager supports `StartTransientUnit` and exposes transient-unit properties for cgroup accounting and process controls ([systemd control-group interface](https://systemd.io/CONTROL_GROUP_INTERFACE/), [v260 manager interface](https://github.com/systemd/systemd/blob/v260.2/man/org.freedesktop.systemd1.xml)). `systemd-run` itself is only a command-line wrapper over this D-Bus control plane ([systemd architecture](https://systemd.io/ARCHITECTURE/)).

**Privilege and scope.** zbus does not confer privilege; authorization comes from the system bus and systemd policy. In ADR-069 the root-owned broker/provider is the authorized caller. systemd supplies transient service lifecycle, cgroup-v2 placement, resource controls, namespaces/process restrictions, root-image options, accounting, and cleanup notifications. It does not supply LPS1 translation, provider admission, nftables topology, TCP transcript capture/replay, dm-verity trust policy, trust-epoch revocation, or Piglor evidence.

**Safety and dependencies.** zbus is the smallest Rust-native control-plane candidate and avoids linking `libdbus` or `libsystemd`. D-Bus is still an external privileged service boundary. Generated types should be pinned to the minimum supported systemd API, and the provider should reject unknown or unavailable required properties rather than probe-and-weaken.

**Fit and ideas.** This is the recommended substrate for the initial provider. Generate a narrow proxy from the official systemd XML; maintain an explicit property allow-list; verify applied properties through read-back; subscribe to unit/job state changes; and implement an inert startup self-test. Keep peer authentication for the separate Piglor provider socket at the kernel credential layer rather than assuming best-effort D-Bus credential fields are sufficient.

[`zbus_systemd` v0.26100.0](https://github.com/lucab/zbus_systemd/tree/v0.26100.0) already generates pure-Rust zbus interfaces from systemd 261, including the exact typed `StartTransientUnit(name, mode, properties, aux)` call. Its manifest declares MIT OR Apache-2.0, Rust 1.87, and zbus 5.3. It can remove locally maintained proxy boilerplate, but its generated version must not be mistaken for runtime capability: the provider still probes every required property against the supported systemd-260 baseline and fails closed when absent.

### rtnetlink and netlink-packet-route

rtnetlink is the high-level Rust API for creating and changing links, addresses, routes, neighbours, and related route-netlink objects ([README](https://github.com/rust-netlink/rtnetlink/blob/v0.23.0/README.md), [examples](https://github.com/rust-netlink/rtnetlink/tree/v0.23.0/examples)). `netlink-packet-route` supplies the typed protocol messages and recommends rtnetlink for normal high-level use ([README](https://github.com/rust-netlink/netlink-packet-route/blob/v0.33.0/README.md)).

**Privilege and scope.** Host topology changes require root or `CAP_NET_ADMIN`; rootless operation is limited to capabilities delegated into a user/network namespace. These crates cover link/veth, address, route, neighbour, rule, traffic-control, and namespace-ID messages. They do not create Piglor network policy, nftables rules, endpoint proxies, transcript capture, lifecycle ownership, or reconciliation by themselves.

**Safety and dependencies.** The stack is Rust and has no mandatory external C netlink library, though it uses `nix`/`libc` at the syscall boundary. The current high-level namespace helper creates `/run/netns` paths and contains `fork`/mount lifecycle logic ([namespace helper source](https://github.com/rust-netlink/rtnetlink/blob/v0.23.0/src/ns.rs)); that path-oriented helper should not be adopted unchanged for ADR-069's TOCTOU-resistant handle requirements.

**Fit and ideas.** Use rtnetlink's typed link/address/route builders and `netlink-packet-route` packet types. Implement namespace creation and ownership around immutable file descriptors, exact object names/IDs, kernel acknowledgements, post-apply read-back, idempotent deletion, and reconcile-by-provider-attempt identity.

### nftables-rs and netlink-packet-netfilter

`nftables-rs` models the nftables JSON API, but its execution helper launches the external `nft` executable through `std::process::Command` ([README](https://github.com/nftables-rs/nftables-rs/blob/v0.6.3/README.md), [helper source](https://github.com/nftables-rs/nftables-rs/blob/v0.6.3/src/helper.rs)). That introduces executable lookup/versioning and a second parser/control path, contrary to ADR-069's typed direct-control and no command fallback requirements. Its Rust data model and tests can still inform a readable policy representation.

`netlink-packet-netfilter` instead supplies Rust packet types for nftables tables, chains, rules, sets, set elements, and expressions such as comparison, bitwise, lookup, metadata, payload, and immediate values ([manifest](https://github.com/rust-netlink/netlink-packet-netfilter/blob/v0.4.0/Cargo.toml), [nftables source tree](https://github.com/rust-netlink/netlink-packet-netfilter/tree/v0.4.0/src/nftables)). It is intentionally low-level; the kernel's nftables netlink specification remains the protocol authority ([Linux nftables netlink specification](https://docs.kernel.org/networking/netlink_spec/nftables.html)).

**Privilege and scope.** Netfilter changes require `CAP_NET_ADMIN` in the applicable user/network namespace. The packet crate supplies encoding/decoding, not transactions, atomic batches, policy compilation, error interpretation, ownership, read-back, cleanup, or capture/replay.

**Safety and dependencies.** Both are Rust libraries. `netlink-packet-netfilter` declares Rust packet/zero-copy and libc dependencies rather than `libnftnl`/`libmnl`; this reduces native linkage but does not reduce the need to validate every encoded kernel operation and acknowledgement.

**Fit and ideas.** Prototype `netlink-packet-netfilter` as the direct nftables primitive. The prototype must demonstrate atomic table installation, exact family/hook/priority semantics, strict ACK/error handling, complete read-back comparison, per-attempt ownership, bounded counters, and idempotent cleanup on Linux 6.12. If it cannot do that without a large bespoke protocol layer, evaluate a native `libnftnl` binding explicitly rather than falling back to the `nft` command.

### bubblewrap

bubblewrap builds a sandbox from an empty mount namespace using explicit bind mounts, read-only mounts, namespaces, seccomp, capability removal, environment clearing, and a PID-1 reaper. It supports rootless user namespaces and has removed its former setuid mode ([README](https://github.com/containers/bubblewrap/blob/v0.12.0/README.md), [implementation](https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c)). Its documentation is explicit that bubblewrap is not a complete policy sandbox: security depends on the arguments chosen by the policy-owning caller.

**Scope.** It is particularly strong as a filesystem/mount and process-namespace reference. It can create an isolated network namespace, but it does not implement ADR-069's exact Local endpoint proxy/capture/replay, cgroup-v2 resource ownership, image signature/dm-verity admission, provider lifecycle, or provenance. Its native CLI is also not the required typed provider protocol.

**Ideas to borrow.** Start with no filesystem view and add only required mounts; clear environment by default; use a PID-1 reaper and parent-death coupling; make loopback opt-in; keep policy out of the low-level mechanism; and pass already-open file descriptors instead of re-resolving paths. Bubblewrap's addition of `--ro-bind-fd` was explicitly intended to avoid a bind-mount TOCTOU class ([v0.10.0 release notes](https://github.com/containers/bubblewrap/releases/tag/v0.10.0)).

### runc

runc is the reference-style low-level OCI runtime, implementing namespace, rootfs/mount, capability, seccomp, cgroup, process, and `create`/`start`/`delete` lifecycle mechanics ([README](https://github.com/opencontainers/runc/blob/v1.5.1/README.md), [`libcontainer` specification](https://github.com/opencontainers/runc/blob/v1.5.1/libcontainer/SPEC.md)). It supports rootless user namespaces; rootless cgroup v2 requires delegation, and its documentation recommends the systemd cgroup driver ([cgroup-v2 guide](https://github.com/opencontainers/runc/blob/v1.5.1/docs/cgroup-v2.md)). The OCI Linux specification usefully catalogues the namespace, mount, capability, seccomp, and cgroup configuration surface ([OCI runtime spec](https://github.com/opencontainers/runtime-spec/blob/v1.2.1/config-linux.md)).

**Safety and dependencies.** It is a Go executable. Seccomp support commonly brings cgo/libseccomp, and the runtime necessarily contains low-level Linux syscall code. That is a different implementation and supply-chain stack from PiglorOS's Rust workspace.

**Fit.** runc is highly mature container machinery, but image distribution/trust, networking, and supervision are intentionally external. A Piglor adapter would have to generate a tightly restricted OCI config and still implement every admission, network-evidence, revocation, outcome, and provenance requirement. This is substantial orchestration and exposes a broad configuration format that Piglor does not need.

**Ideas to borrow.** A small lifecycle state machine; parent-death and cgroup kill semantics; rootfs/path hardening; feature discovery separated from execution; and adversarial runtime-spec conformance tests. Do not expose raw OCI JSON as the provider or LPS1 API.

### Kata Containers

Kata Containers runs containers in lightweight VMs and has a production Rust runtime shim with pluggable hypervisor, network, storage, and resource managers ([project README](https://github.com/kata-containers/kata-containers/blob/4.1.0/README.md), [runtime-rs README](https://github.com/kata-containers/kata-containers/blob/4.1.0/src/runtime-rs/README.md)). Its 4.x architecture explicitly separates resource managers and their dependency-ordered lifecycle ([architecture](https://github.com/kata-containers/kata-containers/blob/4.1.0/docs/design/architecture_4.0/architecture.md)). It also distinguishes host VMM cgroups from guest workload cgroups ([host-cgroups design](https://github.com/kata-containers/kata-containers/blob/4.1.0/docs/design/host-cgroups.md)).

**Privilege and dependencies.** Kata requires hardware virtualization and a large host/guest stack. Its documented rootless VMM mode only removes privilege from the VMM; the shim and filesystem daemon remain privileged ([rootless VMM guide](https://github.com/kata-containers/kata-containers/blob/4.1.0/docs/how-to/how-to-run-rootless-vmm.md)). The default Rust runtime still integrates containerd, a VMM, guest kernel/image and agent, and network/filesystem helpers ([installation guide](https://github.com/kata-containers/kata-containers/blob/4.1.0/docs/installation.md)).

**Fit.** Kata is the strongest architecture reference for interchangeable sandbox backends, but adopting it does not provide the Piglor provider contract, LPS1 semantics, local signed admission, exact transcript, trust-epoch revocation, or canonical evidence. Its containerd/CRI and multi-resource model is much broader than ADR-069's single public-adapter attempt.

**Ideas to borrow.** Separate portable sandbox intent from backend resource managers; represent resource dependencies explicitly; make prepare/start/stop/cleanup idempotent; distinguish host and guest limits; version the guest-agent/control protocol; and test the same behavioral contract across hypervisors. These patterns map well to interchangeable Piglor providers even if no Kata code is linked.

## Requirement-gap comparison

Legend: **Yes** means the upstream project owns the concern; **Partial** means it provides mechanics but not ADR semantics; **No** means PiglorOS must implement it.

| Candidate as backend | Isolation FS/process | Network mechanics | cgroup/resource lifecycle | Provider ABI and admission | Signed dm-verity image policy | Exact Local capture/replay | Revocation/audit/provenance | Complete without substantial orchestration? |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| systemd + zbus + direct netlink | Partial | Partial | Yes | No | Partial | No | No | **No** |
| youki | Yes | Partial | Yes | No | No | No | No | **No** |
| Firecracker | Yes | Partial | Partial | No | No | No | No | **No** |
| libkrun | Partial | Partial | No | No | No | No | No | **No** |
| runc | Yes | Partial | Yes | No | No | No | No | **No** |
| Kata Containers | Yes | Yes | Yes | No | No | No | No | **No** |
| bubblewrap | Yes | Partial | No | No | No | No | No | **No** |

Kata has the broadest generic sandbox orchestration, while youki/runc have the broadest native-container mechanics. Neither breadth addresses the requirements unique to PiglorOS. Conversely, systemd plus direct netlink is not the most self-contained generic sandbox, but it is the narrowest substrate that matches ADR-069's approved initial Linux architecture and leaves the portable provider seam under PiglorOS control.

## Concrete implementation direction

### Initial production provider

Build one PiglorOS-owned `systemd` provider process behind the approved provider socket:

1. **Portable front door:** implement bounded canonical requests for `describe`, `execute`, `cancel`, and `reconcile`. Return portable capabilities and operational outcomes; never return systemd property names in LPS1.
2. **Admission before contact:** resolve the root-owned registry entry, verify the exact provider executable by immutable handle and digest, verify its signed capability manifest and trust epoch, then authenticate the connected process with kernel peer credentials.
3. **Lifecycle:** use generated zbus proxies and `StartTransientUnit`; pin an allow-list of required properties; fail if any required property is unavailable; read the properties back; and bind unit lifetime to provider/broker death.
4. **Filesystem:** activate the already admitted signed dm-verity image through immutable handles; create only `/work` as writable tmpfs with `noexec,nosuid,nodev`; mask other writable locations; verify the mounted identity after activation.
5. **Network:** use rtnetlink packet builders for namespace/veth/address/route setup. Use a direct nftables netlink prototype for deny-by-default rules and ownership. Local mode reaches only broker-owned endpoint proxies; Air-Gapped creates no reachable interface. Capture and digest the exact bounded byte stream at the broker boundary.
6. **Terminal precedence:** broker-observed resource limits, revocation, provider/broker death, timeout, or cleanup failure override/discard adapter output. Make cancellation and reconcile idempotent.
7. **Evidence:** bind provider ID/version, signed manifest digest, executable digest, capability-probe result, inert self-test result, image and verity identities, effective LPS1 digest, systemd unit identity, network ruleset identity, capture digest, trust epoch, and cleanup result.

### Prototype gates before dependency commitment

- Compare direct systemd orchestration with a youki `libcontainer`/`libcgroups` implementation of the same minimal attempt. Measure code surface, native dependencies, startup/cleanup latency, and ability to prove exact applied policy.
- Prove direct nftables netlink atomic install, read-back, counters, and cleanup on Linux 6.12 for both x86_64 and aarch64. Do not accept `nft` command execution as fallback.
- Exercise adversarial paths: provider death between prepare/start, broker death, symlink/path replacement, namespace-handle reuse, partial netlink ACK, stale transient units/rules, revocation during execution, output racing a resource limit, and repeated reconcile.
- Benchmark Firecracker and libkrun only as future providers against the same portable contract; do not add VM-specific fields to LPS1.

## Conclusion

There is no drop-in open-source Sandbox Provider Adapter for ADR-069. The recommended architecture is a PiglorOS-owned interchangeable provider layer over well-scoped upstream primitives:

- **Prototype for adoption:** zbus_systemd generated interfaces over zbus for systemd D-Bus; adopt rtnetlink/netlink-packet-route for route netlink.
- **Prototype before adopting:** netlink-packet-netfilter for direct nftables; youki `libcontainer`/`libcgroups` as a native-container backend comparator.
- **Evaluate later as alternate providers:** Firecracker first for a strong, explicit microVM boundary; libkrun when embedded startup simplicity is more important and its host-isolation caveats are addressed.
- **Borrow designs, not control planes:** bubblewrap's empty mount view and FD-based path handling, runc's lifecycle/conformance discipline, and Kata's pluggable resource-manager architecture.
- **Reject as the ADR control path:** external `nft` command execution, raw OCI configuration as public policy, transparent libkrun networking defaults, and any provider that weakens a requested capability when its backend cannot implement it exactly.

This preserves the approved open-source extensibility goal: users may install and locally trust interchangeable providers, while every provider must prove the same exact capability and conformance contract rather than inherit trust from its upstream project name.
