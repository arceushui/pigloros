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
syscall-number matrix. The prototype intentionally lives only on the throwaway
evidence branch.

The canonical ADRs remain Proposed. A green workflow proves only the bounded
claims named by its retained artifacts; the complete ADR acceptance matrix,
production provider, native source coverage, canonical EAI1/EAO1 framing,
installed-BPF capture, complete lifecycle/crash matrix, and ticket rewrites
remain separate.

The command below is documentation for the remote workflow. Do not run it in a
developer worktree; the evidence is produced only by the dedicated GitHub
Actions x86_64 and arm64 jobs.

```bash
bash prototypes/adr084-podman-feasibility/run.sh
```

The command writes only beneath `artifacts/adr084-podman-feasibility/` and the
rootless Podman storage owned by the current user. It does not run Cargo.
