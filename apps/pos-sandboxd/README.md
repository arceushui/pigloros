# systemd Sandbox Provider components

This package holds the systemd-specific implementation of Accepted ADR-069 and
ADR-072. It is separate from the reference evaluator and provider-neutral wire
contracts. Complete daemon/runtime delivery remains tracked by Redmine #214.

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
kernel enforced the effective limit. Provider admission, kernel limit reads,
and signed limit evidence remain separate #214 work.
