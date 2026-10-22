# systemd Sandbox Provider components

This package holds the systemd-specific implementation of Accepted ADR-069 and
ADR-072. It is separate from the reference evaluator and provider-neutral wire
contracts. Redmine #214 tracks the delivered component foundation. Complete
daemon/runtime delivery remains tracked by epic #287 tickets #437–#444.

`SystemCallFilter` compiles a canonical selected SCS1 into the exact `(bas)`
requested property, checks the selected digest and architecture, and compares
typed readback with the separate complete expected array without normalization.
The selected digest and architecture must come from authenticated admission;
this component neither grants admission nor establishes kernel enforcement.

Public integration tests use both checked-in production architecture records
and the selected zbus closure's zvariant 5.15.0 serializer. Workspace GitHub
test, coverage and mutation gates execute those tests; lint checks their code.
No daemon, test launcher, host group expansion, direct process fallback or
runtime admission shortcut is supplied by this slice.

`SystemdTransientUnitTransport` consumes that closed property bundle and calls
the generated systemd `StartTransientUnit` proxy with the fixed `fail` job mode
and no auxiliary units. It enables manager signals once per connection and
subscribes to `JobRemoved` before submission, accepts only the matching unit/job
pair with result `done`, resolves the unit object, and reads every requested
property through the generated typed service proxy.
The existing request verifier rejects any unequal complete readback. The
effective `RootImagePolicy` is recorded separately because it is manager-owned
state, not requested configuration or signature-admission evidence. The typed
result proves requested-state verification only. The separate `stop_job` and
`force_kill` operations command only the deterministic attempt unit through
typed systemd D-Bus. Stop uses `replace` mode so a queued start job cannot
block cleanup; start retains `fail` mode. A completed stop job or acknowledged
SIGKILL is not proof that the unit or cgroup is absent. The separate cgroup
observer can verify process emptiness, but not complete cleanup. Later slices
own bounded orchestration, launcher readiness/release, and full lifecycle
cleanup.

`SystemdServiceLimits` accepts the complete ordered, already authorized ELM1
limit set and compiles IDs 0–6 into the seven exact systemd service properties:
`MemoryMax`, `MemorySwapMax`, `TasksMax`, `CPUQuotaPerSecUSec`,
`RuntimeMaxUSec`, `LimitNOFILE`, and `LimitFSIZE`. The watchdog value is
converted from milliseconds to microseconds with overflow rejection. Values
that pinned systemd cannot represent as exact finite ceilings fail before
submission; the generated service proxy then reads back each typed `t` value.
This is requested-state verification, not ELM1 authentication or proof that the
kernel enforced the effective limit. Provider admission remains in #437–#438;
kernel limit reads and signed limit evidence remain in #443.

`MountfsdImageActivator` is the private ADR-087 `ImageActivator` transport
(#439). It connects only to `/run/systemd/io.systemd.MountFileSystem`,
requires a root peer, and performs one `MountImage` call per connection: the
held image descriptor travels as index 0 with the fixed read-only,
non-interactive `root=signed+erofs:=absent` request, and the reply must return
exactly one root mount descriptor in the same transaction. zlink 0.7.1 frames
the call, but this crate supplies the socket. Every receive requests
`MSG_CMSG_CLOEXEC`, verifies `FD_CLOEXEC`, rejects ancillary truncation,
credentials and descriptors in more than one read, and bounds the reply to one
NUL-terminated message. The captured bytes are then parsed under a closed
systemd v260.2 schema. Under ported v260.2 `image_policy_equivalent()` rules,
the effective image policy must be equivalent to the request or, because
v260.2 intersects it with a default that carries no filesystem flags, to the
request with only its filesystem flags removed (accepted ADR-087 Part
A.1 effective-policy amendment). EROFS stays enforced by the SIM1 precheck, the
reply's `fileSystemType` and kernel readback. Every rejection closes all
received descriptors. The result is a quarantined root mount, not proof of the
image, the mount or its dm-verity identity.

`ActivationImage`'s only constructor is
`ActivationImage::from_admission(&HeldImageAdmission)`. It duplicates exactly
the held image that #438 admitted, close-on-exec, and takes the root partition
and architecture from the same SIM1, so no caller can activate an unadmitted
descriptor.

`activate_admitted_root(&HeldImageAdmission, &PreparedAttemptDirectory)` (#440)
composes the attempt:

- It requires the kernel command line to carry the one plain
  `systemd.allow_userspace_verity=0` word (ADR-087 Part C.3); otherwise it
  returns host feature unavailable before mountfsd is called.
- It bounds the connection and the `MountImage` call to 60 s each.
- It attaches the sealed root mount by descriptor onto the held attempt root
  and makes it private.
- It reads the mount back by descriptor: path, mountinfo, EROFS and
  read-only, the dm-verity device and its loop partitions, and the loop
  backing identity. It then re-admits the held image.
- Any failure after attachment detaches the mount.

The live dm-verity table is #444 evidence, not a runtime check. Lifecycle
cleanup (#442) and packaged-build conformance (#444) remain separate.

`/work`, the sole writable mount, is requested as
`TemporaryFileSystem=/work:size=<ELM1 WorkBytes>,nosuid,nodev,noexec` and read
back as a typed `a(ss)` value. A zero ceiling requests no mount at all, because
tmpfs reads `size=0` as unbounded. The image must provide the `/work`
directory, and #444 records the effective mount.

`execute` (#441) composes one reserved, admitted attempt from its rechecked
root to its end. `AdmittedAttempt::from_entry` takes the facts of an
`AdmittedEntry` only together with the directory prepared for that attempt and
image. The attempt's planned mode must equal the admitted launch policy's. The
verified root is rechecked last, immediately before `StartTransientUnit`, and
must be the attempt's own root. After the typed unit is started and verified,
its cgroup is bound and an `ActiveAttempt` is recorded; the launcher barrier
(`LaunchBarrier`) then releases the adapter exactly once. Any failure after
the unit was submitted kills it. The unit host, the barrier and the Local
network are ports, so the composition is exercised without systemd.

- Local: the FD 3 socket pair is created with the attempt, and
  `piglor-host-service-v1` precedes `piglor-release-v1`. `ActiveAttempt` is the
  only source of `BoundLocalProxy`, the `LocalProxyBinding` that `serve_proxy`
  in `pos-reference` requires. It checks the grant's attempt, SIM1, authority
  heads and epochs against the rechecked admission, the namespace's attempt and
  the channel's attempt. The proxy serves on a blocking thread that the attempt
  watchdog closes. The namespace, veth pair and nftables rules belong to a
  separate ticket; `FailClosedLocalNetwork` establishes none and refuses every
  connection.
- Replay: every captured exchange is resolved from the durable capture store
  before launch; a missing or mismatched capture is unavailable and nothing
  starts.
- Air-Gapped and Fork carry no network authority and no live descriptor.

The result carries the ordered NXT1 transcript digests for SPR1 and the proxy
termination for the SAU1 terminal classification; signing and classification
are #443, and unmounting and removing the attempt are #442.

The provider never creates a local process: `connect_system` accepts only a
Unix-socket system-bus address (zbus's `unixexec` and `ibus` transports would
start one), and
`provider_process_creation_public` checks the provider's production sources
and manifests, because zbus receives system-bus descriptors without
`MSG_CMSG_CLOEXEC`.

## Launcher mode and release barrier (#441)

The package now builds one binary, `pos-sandboxd`, whose mode is chosen by
argv. The only mode is `launch-barrier <lpv1-hex>`: the ADR-069 Sandbox Release
Launcher, started by the provider as the transient unit's main process. It
adopts the descriptors systemd passes (`sd-listen-fds`), validates their names,
types, count, order and the absence of any other open descriptor, accepts the
release channel only from a root `SO_PEERCRED` peer, opens and hashes the
adapter beneath the activated root, sends one `ReadyV1` with
`SCM_CREDENTIALS`, waits for one `ReleaseV1` (attempt, nonce, `ReadyV1` digest
and monotonic deadline), closes the release channel and replaces its process
image with the held adapter descriptor through `nix`'s safe `execveat`
wrapper (`src/launcher/exec.rs`, the only file allowed to name it). Any other
outcome, including EOF, ends the process without running adapter bytes.

The launcher code path never calls admission or the verifier (a hosted source
test enforces it). CI builds the binary for `x86_64` and `aarch64`
`unknown-linux-musl` and requires no `PT_INTERP` and no dynamic section.
ADR-087 A.3 governs the daemon mode; the launcher's final exec creates no
process.

`release_after_ready` is the provider half: it accepts one `ReadyV1` only from
the unit's `MainPID` (kernel `SCM_CREDENTIALS`) with every binding equal to
held or observed evidence, rechecks current authority through the
`ReleaseRecheck` port, and sends one `ReleaseV1` signed through `ReleaseSigner`.
