# Native Sandbox Provider coverage evidence options

Research for Redmine #214, 2026-09-17. This is evidence for a decision, not an
accepted recommendation, implementation, or a reduced #214 success criterion.
The research phase ran no Cargo command, privileged experiment, hook, tracker
write, or commit. Coordinator publication is recorded separately on #214.

## Decision boundary and inspected harness

Question: how can root-owned filesystem and launch-barrier paths be exercised in
a disposable VM while retaining trustworthy source coverage and preserving the
accepted empty-environment and descriptor contracts?

Repository inspected at base `4e2630af`: `CONTEXT.md`, `README.md`, `AGENTS.md`,
`.github/workflows/ci.yml`, `docs/test-policy.md`, and `scripts/ci.sh`.
The coordinator supplied canonical ADR-069 v84 and ADR-072 v2 snapshots. Their
normative boundary is the systemd provider's static, identity-bound executable,
including launch-barrier mode, held-descriptor `execveat`, empty adapter
environment, and exact named descriptor sets. Image/root staging requires UID 0.
The production provider daemon does not yet exist; #133 is a pure filter-library
slice. The #211 prototype cannot substitute for production behavior tests.

Current CI runs the full workspace once, as non-root, with all features and
ignored tests included. Its detailed JSON feeds exact-base changed-production
`covgate`; report-only commands enforce 99% lines/regions and export LCOV for
the existing CRAP gate. Rust is pinned to 1.97.1 with llvm-tools-preview, but
`tool: cargo-llvm-cov` is unversioned. The coordinator's authoritative job
104889371316 executable log observed 0.9.0; the release API currently identifies
0.9.1 as latest. Released 0.9.0 docs/help, not 0.9.1 behavior, inform this
comparison. [S1][S2] There is no native profile-import or provider VM job today.

All options retain the accepted disposable-VM boundary: fresh pinned guest,
read-only source, no credentials or shared cache, unprivileged build with bounded
egress, then privileged tests with no egress, and unconditional independently
verified destruction. This research does not select a new binding: rustix 1.1.4
was already selected. No custom telemetry reader is required for LLVM profiles.

## Source facts versus project inference

Released cargo-llvm-cov supports accumulating multiple test conditions before a
report, and building instrumented Cargo binaries for external test execution via
`show-env`. Its released help exposes JSON/LCOV and fail-on-any merge failure.
This is a maintained integration surface, not proof that arbitrary imported
cross-build profiles or guest paths are automatically discovered. [S1]

LLVM reports require indexed profile data and corresponding coverage mappings
from instrumented objects; export supports JSON and LCOV. Merge is an official
operation, not concatenation of summary percentages. [S3][S4] Raw profile formats
have no compatibility guarantee, even between compiler revisions. [S5]

Ordinary runtime initialization registers an exit writer. Successful exec
replaces the launcher image; forced termination likewise cannot depend on that
normal exit writer. Inference: merely collecting ordinary `.profraw` files after
a successful adapter run does not demonstrate launcher success-path coverage.
The provider and subsequently executed adapter are separate profile lifetimes.
[S6]

LLVM 22.1 documentation describes continuous mode and backend counter relocation,
but explicitly treats Linux continuous support as requiring testing. This is
conditional feature evidence, not proof of the selected Rust runtime. [S5]
The upstream 22.1.6 compiler-rt source has a Linux relocation implementation using
`MAP_SHARED`, checks for emitted bias symbols, opens/truncates a profile file,
maps it, and closes its file handle after initialization. [S6] Inference: a
mapping surviving file closure is promising for the launcher's closed descriptor
set, but its writable mount and initializer behavior still change the test
execution environment. That environment cannot establish release HCP conformance.

## Three viable architectures to evaluate

| Option | Coverage ownership and feasibility | Limits and decision implications |
|---|---|---|
| A. Entire instrumented workspace in guest | Unprivileged guest build; non-root full-workspace execution; privileged native execution separately inside that same guest; one object/profile inventory and official final report. External execution and report accumulation are supported surfaces. [S1] | Expensive guest sizing and full-workspace dependencies; does not mean running the workspace as root. Keeping the current host ordinary run as well avoids silently replacing its accepted evidence. Continuous launcher evidence remains unresolved. |
| B. Ordinary central run plus separately built native profiles | Retain current ordinary job; guest produces native instrumented objects and profiles from the same source SHA; official LLVM merges profiles and exports against the complete object set. [S3][S4] | Highest compatibility/provenance burden: compiler revision, target, features, source mappings and object discovery must be exact. Distinct function instances must not hide uncovered production regions. Cross-build/source-path reporting requires measured fixtures before selection. |
| C. One instrumented build, native execution confined to guest | Build unprivileged; ordinary workspace run remains non-root; stage exact instrumented native binaries into a fresh guest; guest alone owns privileged execution and profile output. Export guest profiles for the official single report against original objects. [S1][S4] | Reduces cross-build identity ambiguity relative to B. Requires target/static-musl and guest closure compatibility, root-owned staging of exact binaries, complete raw-profile inventory and continuous-mode measurements. Same binaries do not make instrumented and release executables identical. |

These are project inferences about feasibility, not upstream guarantees. C has
the smallest object-identity uncertainty; A has the simplest guest-local profile
inventory; B retains independent build ownership at the cost of more provenance
work. No option is presently proved end-to-end or approved. Each must keep the
full-workspace and changed-production floors and the same completed-report LCOV
CRAP checks. Missing profiles, unmapped production functions, or collection
failure fail the evidence run; the 1% reporting tolerance is not an exemption.

## Evidence separation and lifecycle

```text
same source SHA -> instrumented objects -> ordinary non-root execution
                                      -> isolated guest privileged execution
                                               -> bounded profiles + observations
objects + complete profiles -> official merge/export -> JSON + LCOV -> gates
same source SHA -> exact release executable -> separate guest HCP conformance
each guest -> external unconditional destruction -> independent verification
```

Coverage demonstrates execution of mapped source in instrumented binaries.
Release conformance must independently exercise the exact production executable,
root staging, launch-barrier, empty environment and descriptor closed sets,
systemd lifecycle, cleanup, cancellation, reconciliation, and all other required
#214/ADR-069 root runtime/evidence behavior on required HostCapabilityProfiles.
Instrumentation profiles or favorable coverage percentages cannot replace any
of that evidence. No conditional production branches, unsafe test bypasses,
synthetic successful exec, exemptions, or provider API expansion are proposed.

NixOS documents VM test orchestration and explicit state reuse; this supports
guest integration-test feasibility, not unconditional independent destruction.
[S7] Guest success and guest shutdown cannot be trusted as proof that the host
destroyed all guest state. GitHub documents persistent compromise risks for
self-hosted runners and warns that JIT registration alone does not sanitize
reused hardware. [S8] Inference: the lifecycle owner and its no-secrets/destruction
controls must remain outside PR-controlled privileged guest code.

## Measurements and unresolved blockers

| Unknown | Required bounded evidence before implementation/selection |
|---|---|
| Actual hosted Rust/runtime revision | Coordinator's read-only local `rustc --version --verbose` reports Rust 1.97.1, commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`, 2026-07-14, x86_64-unknown-linux-gnu, LLVM 22.1.6. This establishes local compiler metadata, not hosted executable identity or exact bundled compiler-rt source. Match hosted reporter and raw-profile producer exactly. |
| Static-musl Linux relocation support on both architectures | In a disposable guest, verify emitted bias symbols, successful runtime initialization, correct source counters, and static link closure using the exact pinned compiler/runtime. No experiment was performed here. |
| Successful `execveat` and forced-kill counter preservation | Known source fixture with success-before-exec and kill-before-exit regions; require exact counts after process replacement/termination and official merge. Distinguish process kill from VM crash durability. |
| Initializer descriptor and environment effects | Observe pre/post-initializer and both normative closed-set scans; confirm no extra retained FD or inherited profile environment reaches the adapter. Test default filename/compile-time filename feasibility rather than assuming `LLVM_PROFILE_FILE` survives empty env. |
| Mount and filesystem effects | Identify profile writer's credentials, exact root-stage path, writable mapping/mount, truncation/collision policy, permissions and confinement. Guest-local evidence mounts are instrumentation deviations and never release conformance claims. |
| Complete profile/object inventory | Manifest source SHA, compiler/runtime/tool hashes, target/features/build flags, object digest, profile origin and expected process lifetimes; reject missing/corrupt/mismatched data. Demonstrate guest path normalization and uncovered-region retention with official reports. |
| Artifact trust and cleanup | Guest root can fabricate its profiles; hashes authenticate identity/transport, not truth. Trusted orchestration must constrain inputs and outputs, bound parsing, verify expected behavioral observations, and independently verify VM process/storage destruction on failure too. |
| Report integration | Demonstrate one final detailed JSON includes native production regions and feeds exact-base covgate, 99/99 workspace gate and matching LCOV CRAP; retain ordinary complete workspace execution. No custom format reader or weakened filter. |

If these cannot cover production branches through real behavior, simplify/remove
the untestable code. Stop at explicit unknowns rather than claiming readiness.
No Timeline schema, Event, or Replay behavior is changed by this evidence design;
the provider boundary and full acceptance criteria remain unchanged.

## Primary evidence register

All accessed 2026-09-17. Publication dates are unknown unless stated.

| ID | Source / publisher / version or date | Exact supported claim |
|---|---|---|
| S1 | [cargo-llvm-cov released README and embedded help](https://github.com/taiki-e/cargo-llvm-cov/blob/v0.9.0/README.md), taiki-e, v0.9.0 | `--no-report`/report accumulation; external instrumented Cargo execution with show-env; JSON/LCOV export and fail-on-any merging. Inspected released help text; executable was not run. |
| S2 | [Latest release API](https://api.github.com/repos/taiki-e/cargo-llvm-cov/releases/latest), taiki-e/GitHub, v0.9.1 published 2026-09-06 | Latest release differs from coordinator-observed CI executable 0.9.0; not authority for current job semantics. |
| S3 | [llvm-profdata](https://releases.llvm.org/20.1.0/docs/CommandGuide/llvm-profdata.html), LLVM, 20.1.0 | Official profile merge/index operation and merge failure policy; conditional reference rather than selected toolchain identity. |
| S4 | [llvm-cov](https://releases.llvm.org/20.1.0/docs/CommandGuide/llvm-cov.html), LLVM, 20.1.0 | Reports combine profile with instrumented object mappings; multiple objects; JSON region/function output versus LCOV line/branch output. |
| S5 | [Source-based Code Coverage](https://releases.llvm.org/22.1.0/tools/clang/docs/SourceBasedCodeCoverage.html), LLVM/Clang, 22.1.0 | Continuous mode and relocation candidate; Linux qualification; raw-format incompatibility; static initialization and runtime APIs. Not static-musl Rust proof. |
| S6 | [InstrProfilingFile.c](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.6/compiler-rt/lib/profile/InstrProfilingFile.c), LLVM compiler-rt, llvmorg-22.1.6 | Linux conditional relocation branch, bias checks, shared file mapping, initialization open/close and exit-writer registration. Exact bundled Rust runtime source remains unverified. |
| S7 | [NixOS Manual, VM tests](https://nixos.org/manual/nixos/stable/#sec-nixos-tests), NixOS, rolling stable accessed 2026-09-17 | VM integration tests and explicit keep-machine-state reuse; no assertion of selected guest revision or independently verified destruction. Must pin actual guest source separately. |
| S8 | [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners), GitHub, rolling documentation accessed 2026-09-17 | Self-hosted persistence/secret risks; JIT one-job runner registration does not by itself clean reused hardware. |
