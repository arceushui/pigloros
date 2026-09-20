# ADR-084 Podman feasibility prototype

**Throwaway prototype — never production code.**

This branch and its pull request are pre-acceptance evidence only. They are not
an implementation of ticket #214, must not be merged as production code, and
must not be copied into the eventual provider.

Question: on standard GitHub-hosted Ubuntu 24.04 x86_64 and arm64 runners,
can the distribution Podman + crun path preserve EAI1/EAO1 on stdin/stdout,
carry a launcher-only release socket, keep adapter bytes blocked until release,
and expose stable process/cgroup evidence while leaving the adapter with no
non-stdio descriptor?

The prototype also emits ADR-085 canonical vectors, independently verifies the
OCI manifest/config/layer/DiffID/ChainID closure, removes and rootlessly imports
the saved OCI archive, and records runtime, namespace, mount, cgroup,
descriptor, environment, and negative-probe evidence. For ADR-084 revision 27,
it partitions the signed SCS1 into requested `R`, effective audit `E`, and
readback-only PNR `D`; materializes an exact-`R` libseccomp interface and exact
`E` audit profile; compiles numeric `R` with pinned libseccomp 2.6.1; and uses an
independent symbolic verifier over the exported BPF's complete 32-bit syscall
domain, including the x86_64 x32-kill range and tracer-skip sentinel. It
also includes four signed-rootfs evidence helpers that are deliberately absent
from OIS1's admitted launcher and adapter executable fields. Two observe the
foreign-ABI and x86_64 boundary outcomes from a bounded parent; one is a
minimal, deadline-free cache-bypass witness; and one executes the closed native
syscall-number matrix, with `sync` closed to successful return or the unchanged
100 ms bound because completion depends on hosted filesystem state. Raw
`rt_sigreturn` and x86_64 `uretprobe` are likewise closed to their documented
signal or that unchanged bound: neither has a normal zero-argument userspace
call contract, and a timeout is terminated and retained rather than relaxed.
The
prototype intentionally lives only on the throwaway
evidence branch.

The normal attempt and cancellation attempt now cross stdin as canonical,
length-prefixed CBOR EAI1 streams with authenticated BLAKE3 transcripts. The
normal adapter result crosses stdout as a canonical EAO1 stream. The provider
driver independently decodes the frames, verifies canonical encoding, member
digests, and both transcripts; the adapter accepts only the two generated
throwaway vectors, so this remains a byte-preservation proof rather than a
production transport implementation.

The EAI1 fixture's authenticated memory and storage ceilings equal the runtime
controls: 64 MiB `memory.max`, zero swap, and one 64 KiB `/work` tmpfs. Every
launch requires `/work` to be exactly `rw,nosuid,nodev,noexec` with the retained
mountinfo size while the image root remains read-only. Forced terminal outcomes
begin with a canonical MEMORY attempt: only after ReleaseV2, the adapter faults
memory beyond `memory.max`; the provider retains the before/after
`memory.events.local` counters and Podman `OOMKilled` state and selects ADR-069
terminal code 3 `OomKilled`. The other forced outcomes and their precedence
remain an open evidence slice.

A canonical TASKS attempt forces `pids.max=16`; its retained local `max` event
selects terminal code 5 `TaskLimit`. A separate canonical CPU attempt crosses
the 0.5-CPU quota and retains an `nr_throttled` delta without selecting a
terminal, because CPU throttling is telemetry only.

Every launch also retains the exact `RLIMIT_NOFILE=64:64` and
`RLIMIT_FSIZE=32768:32768` process readback. NOFILE remains safety evidence only.
A canonical FILE attempt crosses the file-size limit inside `/work`. It runs
without the ptrace install observer so the observer cannot suppress or alter a
signal, while retaining the exact runtime BPF annotation/profile tuple already
captured byte-for-byte by the global proof. Both hosted architectures enforce
the limit but return `EFBIG` and exit 71 without SIGXFSZ. ADR-069 therefore
selects fallback code 8 `ProcessCrash`, not code 7 `FileOrOutputLimit`; this is
a manifest-bound incompatibility finding, not a successful prerequisite.

A canonical WATCHDOG attempt remains alive until the provider's exact one-second
monotonic deadline, then receives provider-owned TERM and bounded SIGKILL
escalation. The
retained release/start/deadline/termination/finish times, process result, and
empty post-exit cgroup select terminal code 6 `Watchdog`.

A canonical WORK attempt writes only 16 KiB files, each below the independently
read-back 32 KiB `RLIMIT_FSIZE`, until the sole 64 KiB `/work` tmpfs returns
`ENOSPC`. The provider records mountinfo and statfs before release, retains an
open directory descriptor to that same mount across process death, and records
the exhausted statfs again after forced termination. This separates WorkBytes
evidence from the candidate's unresolved FileBytes/SIGXFSZ incompatibility.

The launcher barrier itself uses canonical LPV2, ReadyV2, and signed ReleaseV2
records rather than literal readiness/release tokens. Before invoking Podman,
the driver durably records an attempt-bound monotonic launch anchor and passes a
bounded provider-private canonical context over the inherited `SOCK_SEQPACKET`
channel. The static launcher hashes the held launcher and adapter descriptors
with the ADR-085 executable domain, records `statx` mount/inode identities and
its current mount namespace in ReadyV2, and remains blocked. Only after the
driver validates ReadyV2 and the live runtime observations does it build, sign,
and independently verify the exact ReleaseV2 bytes. The launcher then validates
canonical encoding, self-digest, attempt/nonce/Ready binding, anchor ordering,
and expiry; freshly rechecks both descriptors and the mount namespace; closes
control; and calls `execveat` on the held adapter descriptor. A missing packet
has a separate 30-second bound. The launcher uses the official BLAKE3 C
implementation pinned by Git commit and built only in the hosted workflow; as
the accepted ADR requires, it has no Ed25519 public key and does not repeat the
provider's durable signature-policy decision.

The hosted runtime matrix also replaces a verified base release with narrowly
scoped conformance injections and proves that the still-blocked launcher emits
no adapter bytes. It covers a non-minimal record head, trailing data, wrong
self-digest, wrong attempt, nonce, and ReadyV2 binding, invalid anchor order,
expiry, and malformed UTF-8 in the opaque runtime-key field. Separate attempts
prove immediate live revocation when the authenticated provider closes the
connected socket and the unchanged 30-second missing-release timeout. These
injections deliberately bypass the provider's successful base-record
verification and are labelled as such in retained evidence.

An eight-process lifecycle case uses distinct provider processes and containers.
Each attempt reaches its own identity-bound `Observed` state and writes a gate
record while its launcher remains blocked. Only after all eight records exist
does the coordinator open the release gate. The retained report requires eight
unique attempt IDs, container IDs, launcher PIDs, and cgroup paths, and proves
the earliest ReleaseV2 occurs after the latest `Observed` timestamp.

The seccomp supervisor also stops the admitted-flags syscall before kernel
continuation when the mapped install buffer differs from the provider-exported
BPF. A valid-base64, one-byte mutation is exercised through real crun and must
terminate under `PTRACE_O_EXITKILL` without an installed-byte artifact.

Isolated pinned-Podman `CONTAINERS_CONF` cases also inject configured defaults.
A benign `fixture.configured-default` reaches the real five-member effective
runtime map, where the provider kills the still-blocked attempt without sending
release. A separate `org.systemd.property.DeviceAllow` default is interpreted
and rejected by crun before launcher start. These distinguish provider map
closure and runtime-native rejection from the in-memory mutation matrix.

The canonical ADRs remain Proposed. A green workflow proves only the bounded
claims named by its retained artifacts; the complete ADR acceptance matrix,
production provider, native source coverage, a general-purpose transport codec,
complete lifecycle/crash matrix, and ticket rewrites remain separate.

The command below is documentation for the remote workflow. Do not run it in a
developer worktree; the evidence is produced only by the dedicated GitHub
Actions x86_64 and arm64 jobs.

```bash
bash prototypes/adr084-podman-feasibility/run.sh
```

The command writes only beneath `artifacts/adr084-podman-feasibility/` and the
rootless Podman storage owned by the current user. It does not run Cargo.
