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

The prototype emits a partial x86_64 ADR-085 vector set, independently verifies
the OCI manifest/config/layer/DiffID/ChainID closure, removes and rootlessly
imports the saved OCI archive, and records runtime, namespace, mount, cgroup,
descriptor, environment, and negative-probe evidence. Both hosted jobs validate
that same x86_64 vector fixture; this is not native per-architecture vector
evidence, does not cover the complete ADR-085 rejection matrix, and does not
materialize PCF1/PCR1 authority closure. For ADR-084 revision 27,
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
The separate seccomp boundary helper gives each synchronized child one second
to be scheduled after the parent releases it. A timeout still fails the probe;
the allowance does not replace or relax the required SIGSYS and sentinel errno
outcomes. This avoids treating ordinary hosted-runner scheduling jitter as a
seccomp result.
The prototype intentionally lives only on the throwaway evidence branch.

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
terminal code 3 `OomKilled`.

The memory attempt keeps a minimal adapter parent alive while its allocating
child crosses `memory.max`. This prevents rootless Podman from deleting the
empty cgroup before the provider can collect `memory.events.local`; the provider
kills the retained parent only after the child SIGKILL marker and authoritative
`oom_kill` delta are both observed. Exit 137 by itself is still rejected.
The same still-live cgroup retains the before/after `memory.swap.events`
counters under `memory.swap.max=0`; a missing `max` delta is reported as a
separate SwapBytes candidate incompatibility rather than inferred from OOM.

A separate canonical MEMORY_LIMIT attempt tests whether the provider can select
code 4 `MemoryLimit` without relabelling an OOM. The adapter first evicts and
then reads a 48 MiB clean file from the signed throwaway rootfs, first-charging
its reclaimable page cache to the attempt cgroup. It then faults a 48 MiB
retained anonymous arena. The provider selects code 4 only if the
local `max` counter advances, both `oom` and `oom_kill` remain unchanged, and
the adapter emits its survival marker while it is still running. The signed
observation and cleanup proof are retained. If the hosted kernel or admitted
seccomp policy cannot produce all of those facts, the report records a
candidate incompatibility and no code 4 outcome.

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

The provider also reserves the complete canonical EAI1 byte descriptor against
an exact InputBytes ceiling before launch, retains the terminal counter snapshot
before ReleaseV2, and rejects a one-byte-larger declaration without launching.
A separate normal adapter is bounded by a four-byte OutputBytes ceiling. The
provider accepts only the length prefix, observes the next overflow byte before
one complete EAO1 frame, discards all adapter output, withholds a Completed
descriptor, and selects terminal code 7 `FileOrOutputLimit`.

The concurrency, queue, peer-rate, and transfer-deadline artifact is explicitly
a model-only transition oracle. It signs deterministic semaphore/FIFO,
token-bucket, and partial-transfer state transitions, but it does not exercise a
provider admission socket, kernel peer credentials, concurrent clients, or a
real partial byte stream. It therefore cannot be used as forced provider-control
evidence; that #379 prerequisite remains open.

A separate closed precedence matrix evaluates all 2,048 subsets of the eleven
ADR-069 terminal observations plus the empty Completed case. It retains every
input subset and selected code, binds the complete matrix with a BLAKE3 digest,
and signs and verifies the summary. This proves selection order only; it does
not relabel an outcome whose authoritative runtime signal was not forced.

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

This is a held-descriptor barrier experiment, not an authority-complete
ReleaseV2 implementation. The driver does not admit and verify the governing
AGR2 and ELM2 objects or derive RBS2 from that closure, and its live negative
packets are sent after a valid base packet was verified rather than rejected by
the provider before send. Those gaps are acceptance blockers retained in the
final verdict.

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

A separate provider-death matrix uses an inert static lifecycle probe in its own
explicitly throwaway fixture image, leaving the admitted ADR-085 image and its
exact mounted-root manifest unchanged. The probe forks one descendant and then
blocks. The matrix deliberately SIGKILLs the provider process immediately before
and after split Podman create, start, identity capture, stop, kill, remove, and
journal-fsync boundaries. Restart recovery trusts labels only for discovery:
before acting it requires the exact provider, attempt, creation nonce, image,
container, creation-time, and live PID/start-time identities from the
hash-chained fsynced journal. After-create, after-start, and
before-identity-capture lack that complete durable identity, so recovery refuses
to touch the candidate; only the separate conformance harness cleans it up. The
remaining actionable cases terminate descendants, remove the exact container,
verify the retained cgroup is empty or absent, verify the merged root is no
longer mounted, and replay reconciliation without another action. Live cleanup
fails closed unless durable cgroup and merged-root identities are available;
live inspection may confirm those paths but cannot supply a missing journaled
value. Never-created and durably-never-started cases are labelled separately. A
continuously running lookalike sentinel proves unrelated state is not touched.
Separate ambiguity and identity-reuse mutations, including missing and
mismatched cgroup and merged-root paths, require operator-visible refusal and
leave every candidate unchanged. Because Podman 4.9.3 does not offer
`--preserve-fds` on `create`, this split lifecycle matrix does not claim the
authenticated launcher barrier; Ready, Observe, and Release crash boundaries
remain a separate barrier-stage experiment.

That complementary barrier experiment forks a provider for each side of Ready,
Observe, and Release. Every provider persists a BLAKE3-linked, fsynced closed-
state journal while traversing the unchanged authenticated ReadyV2/ReleaseV2
path, then receives SIGKILL at the selected stage. Restart discovery requires
the exact provider, attempt, nonce, image, container, creation, and live PID/start
identity before touching the candidate. The five pre-release cases must contain
no adapter descendant marker. The post-release case closes stdin, requires the
real HOLDING descendant marker, then kills the provider. All six select terminal
code 0 `BrokerDied`, remove the exact container and cgroup descendants, and bind
their journal tips into a signed cross-case summary.

The terminal matrix also retains three otherwise easy-to-conflate provider
outcomes. The existing real cancellation path now signs code 1 `Cancelled` only
after its descendant-bearing cgroup is empty. A conformance-owned temporary
resource is deliberately retained beyond a monotonic cleanup deadline to force
code 2 `CleanupFailed`, then removed by the harness after the observation is
durable. For code 9 `IpcFailure`, a released HOLD attempt remains alive while
the provider closes its own stdout transport endpoint and observes `EBADF` on
the real pipe before any process-crash observation; cleanup follows terminal
selection and cannot retroactively relabel the outcome.

The ADR-079 slice is likewise throwaway evidence, not coverage of production
provider code. Two Rust 1.97.1 static-musl objects are built once per native
architecture under pinned cargo-llvm-cov 0.9.0 instrumentation and LLVM counter
relocation. Compile-time `%m%c` profile names avoid `LLVM_PROFILE_FILE`. The
instrumented launcher clears its environment, verifies its closed descriptor
set and mapped profile, and executes the held adapter descriptor with an
explicit empty `envp`.

The candidate is nevertheless incompatible on both hosted architectures. The
LLVM continuous-profile runtime recreates
`__LLVM_PROFILE_RT_INIT_ONCE=__LLVM_PROFILE_RT_INIT_ONCE` before adapter `main`,
so the adapter cannot satisfy the normative empty-environment scan. The failed
clean attempt retains distinct launcher and adapter raw profiles and a
machine-readable incompatibility report. In accordance with ADR-079's stop
rule, the fixture does not continue to forced-kill or report-composition claims
after that mandatory criterion fails. Clearing the runtime entry inside the
adapter would be an instrumentation-specific bypass, not evidence that the
accepted production boundary is preserved.

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

In GitHub Actions the command writes beneath
`artifacts/adr084-podman-feasibility/`, runner-temporary build directories, the
coverage fixture's Cargo target directory, and rootless Podman storage. Its
ADR-079 subprobe invokes pinned Cargo/cargo-llvm-cov remotely. Nothing in this
README authorizes running it in a developer worktree. The uploaded bundle
retains the exact production and derived SCS1 inputs, validates the closed SPDX
2.3 document shape and source-epoch timestamp independently of its generator,
versions the Tool creator with the exact Git commit, gives each
run-attempt/architecture document a unique namespace, and uses
extraction-portable relative paths in `SHA256SUMS`. The SPDX checker does not
claim to recompute the generator's logical-path inventory.
