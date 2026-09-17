# Native profiling probe preflight

Owner: Redmine #371 under #214. Authority: approved ADR-079 revision 1
(Accepted publication revision 3), with Accepted ADR-069 revision 84 and
ADR-072 revision 2. Production conformance orchestration remains owned by #216.

The adjacent JSON fixes the initial probe ceilings and extraction policy to
address the independent Sol review's LOW execution clarification. These are
research-run safety ceilings, not measured resource requirements or production
defaults. An insufficient ceiling must yield a retained failed experiment,
not a silent increase. Any changed configuration gets a new recorded source
identity before another attempt.

## Activation is not established

No probe has run. No configuration field or digest proves enforcement. Before
privileged execution, the workflow must bind this exact configuration, source
and workflow revisions to its retained inventory; establish the complete guest
and tool identities; and test each resource and extraction control. A pinned
nixpkgs input or historical #211 requisite closure is not a complete current
guest image/runtime identity. The current repository has no VM harness to
inherit as validated execution infrastructure.

The `native-profiling-preflight` workflow performs only unprivileged, read-only
host inspection on each native runner. It records the exact checked-out source
SHA, configuration/workflow/inspection/test file hashes, native architecture,
host kernel and KVM API result. It opens `/dev/kvm`, asks only for the stable
`KVM_GET_API_VERSION`, and closes the descriptor; it never creates a VM. Missing
access, an architecture mismatch, root execution or any API other than 12 fails
the prerequisite check. A passing check proves neither guest creation nor
resource, egress or destruction enforcement and never authorizes activation.
Mocked boundary tests do not replace the hosted observations.

The [Linux KVM API documentation](https://docs.kernel.org/6.18/virt/kvm/api.html)
specifies the system version ioctl and requires API 12. GitHub's
[hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
documents the native runner labels, not usable KVM on each selected host.
Retained negative observations determine the next infrastructure action; do not
substitute cross-architecture emulation or root execution on the runner.

For each native class, use one fresh VM and no more than two native jobs in
parallel. Guest writable disk limits must cover every writable backing store,
not just a filesystem inside the guest. Host build ceilings include all build
and provisioning subprocesses. Reporter limits are imposed by an unprivileged
outside-guest owner before parsing any guest-produced input. Artifact ceilings
apply before allocation or extraction, including expanded bytes and duplicate
entries, and encompass profiles, observations and logs. Inventory/object tools
must also run within the reporting budget.

External destruction must finish and be independently verified within 120
seconds after success, failure or cancellation. A guest assertion or shutdown
is insufficient. If cleanup exceeds its deadline or residual process/storage
state cannot be excluded, fail the evidence run and retain bounded diagnostics;
never report a successful probe. Orchestration must reserve cleanup time outside
the experiment deadline and remain owned outside the privileged guest.

## Enforcement evidence required

Exercise count, per-file, aggregate and expanded-byte boundaries, unsafe paths,
duplicates, links, special/sparse files and nested archives. Reject missing,
corrupt or identity-mismatched objects/profiles. Independently force guest,
build and reporter resource exhaustion and prove termination and external
cleanup; test interrupted/cancelled orchestration and unsuccessful destruction
verification. Until these controls exist and pass, this configuration is an
execution prerequisite only, not evidence of a bounded run.

All seven ADR-079 probe criteria remain required on both native classes. Do
not substitute synthetic exec, normal-exit profile writing, profiling environment
inheritance or favorable joint coverage for native observations. Instrumented
coverage and exact admitted release HCP conformance remain separate. Production
integration requires subsequent explicit review of the complete probe evidence.
