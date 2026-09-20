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
100 ms bound because completion depends on hosted filesystem state. The
prototype intentionally lives only on the throwaway
evidence branch.

The normal attempt and cancellation attempt now cross stdin as canonical,
length-prefixed CBOR EAI1 streams with authenticated BLAKE3 transcripts. The
normal adapter result crosses stdout as a canonical EAO1 stream. The provider
driver independently decodes the frames, verifies canonical encoding, member
digests, and both transcripts; the adapter accepts only the two generated
throwaway vectors, so this remains a byte-preservation proof rather than a
production transport implementation.

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
