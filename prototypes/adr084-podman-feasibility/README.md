# ADR-084 Podman feasibility prototype

**Throwaway prototype — never production code.**

Question: on standard GitHub-hosted Ubuntu 24.04 x86_64 and arm64 runners,
can the distribution Podman + crun path preserve EAI1/EAO1 on stdin/stdout,
carry a launcher-only release socket, keep adapter bytes blocked until release,
and expose stable process/cgroup evidence while leaving the adapter with no
non-stdio descriptor?

The prototype also emits ADR-085 canonical vectors, independently verifies the
OCI manifest/config/layer/DiffID/ChainID closure, removes and rootlessly imports
the saved OCI archive, and records runtime, namespace, mount, cgroup,
descriptor, environment, and negative-probe evidence. It intentionally lives
only on the throwaway evidence branch.

The command below is documentation for the remote workflow. Do not run it in a
developer worktree; the evidence is produced only by the dedicated GitHub
Actions x86_64 and arm64 jobs.

```bash
bash prototypes/adr084-podman-feasibility/run.sh
```

The command writes only beneath `artifacts/adr084-podman-feasibility/` and the
rootless Podman storage owned by the current user. It does not run Cargo.
