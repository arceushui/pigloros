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
and the selected zbus 6.0.0 wire serializer. Workspace GitHub
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
observer can verify process emptiness, but not complete cleanup. The bounded
`execute` orchestration and launcher readiness/release barrier are implemented
below; full lifecycle cleanup remains #442.

`wait_for_attempt_unit_absence` queries the exact attempt name with typed
`GetUnit` until systemd reports `org.freedesktop.systemd1.NoSuchUnit`, under
one caller-supplied absolute deadline. A loaded object, including an inactive
or failed unit, keeps waiting; all other errors reject. The sealed result is
only a point-in-time manager observation. It does not fence later starts or
prove process/resource absence, authorize unmount or intent deletion, or reopen
admission. Complete lifecycle ownership and cleanup remain #442.

`stop_attempt_unit` joins the retained cgroup's bounded stop/grace/escalation
with exact-name unit removal. After kernel process emptiness, it resets only
that unit's failed state so systemd can collect it, waits for fresh `GetUnit`
absence, and rechecks the retained cgroup identity and emptiness. The process
shutdown budget must leave time before one absolute final deadline. Reset
acknowledgement, including `NoSuchUnit`, cannot substitute for the fresh query.
The lifecycle controller retains exclusive ownership and captures terminal
systemd state before teardown, since unloading discards that state. The sealed
joint observation proves neither a later-start fence nor complete resource
cleanup; mount/device/directory/intent cleanup and restart reconciliation remain
#442.

`PreparedAttemptDirectory::remove_unmounted` consumes the held directory
ownership, rechecks its durable identity record and empty unmounted tree, then
removes only its exact root and attempt directories through held parent
descriptors. Each parent is synchronized after removal. Unexpected attempt
children reject before either directory is removed. The lifecycle controller
retains exclusive ownership and stops the unit and unmounts the root first.
The durable intent remains unchanged for later full reconciliation. Read-only
recovery inventory recognizes the root-removed/attempt-present crash frontier,
while every surviving directory must match its recorded identity. This stage
does not prove other resource absence or reopen admission; full cleanup remains
#442.

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
the unit was submitted kills it, every start and bind is bounded by the
attempt watchdog, every termination call by a fixed 1 to 10 s bound, and
dropping the execution future after the submission spawns a best-effort kill
of the unit. A Local admission, namespace or channel of another
attempt, request, authority block, head, epoch or launch policy, or one that
plans an endpoint the launch policy does not allow, is refused before anything
is submitted. A proxy protocol failure kills the unit at once and the evidence
is kept; after a watchdog expiry the unit is killed while the proxy thread is
still being joined. The Local
network port owns its namespace by RAII: the execute path drops it on every
path that does not serve it. The unit host, the barrier and the Local network
are ports, so the composition is exercised without systemd.

- Local: the FD 3 socket pair is created with the attempt, and
  `piglor-host-service-v1` precedes `piglor-release-v1`. `CheckedLocal` is the
  only source of `BoundLocalProxy`, the `LocalProxyBinding` that `serve_proxy`
  in `pos-reference` requires; `ActiveAttempt` witnesses that the unit was
  started. `AdmittedAttempt::check_local` checks the grant's attempt, request,
  full authority block, heads and epochs, expected launch policy digest and
  planned endpoints against the admitted attempt and its launch policy, and
  the namespace's and the channel's attempt; the token carries the attempt it
  checked. The proxy serves on a blocking thread that the attempt watchdog
  closes. The namespace, veth pair and nftables rules belong to a
  separate ticket; `FailClosedLocalNetwork` establishes none and refuses every
  connection.
- Replay: every captured exchange is resolved from the durable capture store
  before launch; a missing or mismatched capture is unavailable and nothing
  starts.
- Air-Gapped and Fork carry no network authority and no live descriptor.

The result carries the ordered NXT1 transcript digests for SPR1 and the proxy
termination for the SAU1 terminal classification; signing and classification
are #443, and unmounting and removing the attempt are #442. A watchdog that
closed the channel is reported by `ServedProxy::watchdog_expired`, not by the
termination, which reads a closed channel as a clean close.

`ExecStart=` is requested as `a(sasb)`: the bind-mounted launcher at
`/.pigloros/release-launcher`, `launch-barrier` and one lowercase-hexadecimal
LPV1 argument, and read back as path, argument vector and ignore-failure flag.
`ProviderReleaseBarrier` is the production `LaunchBarrier`. Its `prepare`
operation checks the complete admitted attempt before handing over a descriptor,
and release checks the active attempt against that same record again.
The root recheck also returns the complete admitted context in its opaque
`CheckedRoot` proof. Both prelaunch execution and the final release check
reject a proof from another context, including a changed authority for the
same attempt ID.
Execution derives its syscall filter from the exact admitted SCS1; an execute
job cannot supply another independently validated allow-list.
The attempt also retains the SPM1-selected runtime key ID and authenticated
verifying key. The production barrier requires that ID from its signer and
verifies the produced signature under the admitted key before sending any
release; a safe but incorrect key file cannot authorize execution.
`AdmittedAttempt` derives the launcher source, byte length, BLAKE3 digest and
device/inode from the authenticated SIC1 role-11 provider executable. Neither
the execute job nor barrier evidence can supply a separate path or digest.
Before the start the barrier
builds the LPV1 parameters (attempt, a nonce from `fresh_nonce`, SIM1, adapter
path and arguments, the expected FDL1 digest of the mode) and the
`SOCK_SEQPACKET` release channel. After the start it reads the unit's current
`MainPID` and `InvocationID` from the manager, observes `/proc/<MainPID>/exe`
itself through a held descriptor, checks its device/inode and length against
admitted evidence, and independently hashes those exact bytes. It bounds the
`ReadyV1` receive and the `ReleaseV1` send with socket timeouts recomputed from
the original attempt deadline. The signed absolute deadline is conservatively
translated by sampling `CLOCK_MONOTONIC` before the remaining `Instant` duration.
The original deadline is checked after the final identity recheck and after
sending the release. The blocking
receive, the recheck and the signed `ReleaseV1` send run under
`tokio::task::block_in_place`, so the barrier needs a multi-thread Tokio
runtime; a current-thread runtime or none is refused with
`BarrierError::RuntimeFlavor`, already when the launcher command is requested,
before any unit starts (a test fixes this requirement). The receive and the
`ReleaseV1` send are bounded by socket timeouts, because an outer deadline
cannot preempt a blocking call. After `ReadyV1` verifies, the last-moment
recheck reads `MainPID`, `InvocationID` and the launcher executable again and
refuses the release if any changed (`BarrierError::Refused` carries the typed
`RecheckRefusal`); a barrier releases at most once.
`AuthorityCheck` is the last-moment recheck: the caller's
`|| root.recheck(&directory, &entry)`, the cancellation flag the attempt
lifecycle sets, and the observed readback-set digest behind `ObservedReadback`.

Not composed here, and stated so that nothing is assumed: the observed
readback-set digest itself (#443 owns the kernel observations and their
digest, and the provider must supply an `ObservedReadback` before it can
release), the adapter's mount and inode identity (the composition root
supplies it in `BarrierEvidence`), the setting of the cancellation flag
(#442), adapter stdin and stdout transport, and the real Local namespace.
`AdmittedAttempt::check_local` binds an admission against the launch-policy
view and the authority heads the attempt was admitted with; that the recheck
closure belongs to the same admitted entry is the caller's contract
(`VerifiedRootMount::recheck` enforces it for its own entry). Authorization of
a Replay exchange set is the caller's: the report that supplies it is not
verified here. `tokio` gains its `rt` and `rt-multi-thread` features.

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
