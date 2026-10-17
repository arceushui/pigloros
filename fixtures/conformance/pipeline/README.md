# Cross-path pipeline conformance fixtures

These fixtures drive the first-party and in-process ADR-021 pipeline
conformance profile (Redmine #488, the first half of #321). The profile proves
human and AI ingress through atomic host admission, failure precedence,
recovery, Replay and evaluation non-authority, the ADR-021 Revision 3
observation profiles, exclusive Event-type ownership and source quarantine
(ADR-024 Revisions 1 and 2) and
revocation persistence. Its runner is
`apps/piglor-gateway/tests/pipeline_conformance/main.rs`, which the workspace test
job executes.

Each version directory is immutable. The runner pins the SHA-256 of every file
it reads, so a changed byte fails the suite. A changed expected result needs a
new version directory, not an edit; rollback selects an older directory.

## `v1/manifest.json` (`PPC1`, version 1)

- `cases` lists every case with its stores (`memory`, `sqlite` or `none`),
  whether it is mandatory, its applicability, the scheduled observation
  profile its evidence must carry, and the exact observations a run must
  capture. Expected values are data. They never come from the implementation
  under test.
- A case marked `profile-inapplicable` gives its reason and must not run. The
  Wave 9 Scenario Room host case is recorded this way rather than omitted.
- `exclusions` names requirements this profile does not prove yet, with the
  owner of the missing implementation or contract.

The runner fails closed on an unknown magic, version or field, a mandatory
case without a runner, a runner without a case, a missing or unexpected
capture, a diverging value, and evidence whose observation profile differs
from the declared one.

## `community/v1/manifest.json` (`PCH1`, version 1)

The sibling profile of the community Plugin host (Redmine #489, the second
half of #321). It proves ADR-021 decision 7 across the two accepted isolation
classes: a first-party operator-trusted native Driver and a governed community
Driver that runs a real Component in the real `pos-plugin-worker`. Parity is
semantic: pass result, Timeline Order and Event types, Event entity, commit
receipt, Driver steps, Plugin availability and scheduled observation profile.
The owner's isolation class is recorded and differs; payload bytes are compared
only between the Local and Air-Gapped runs of one community release.

Its runner is `apps/pos-plugin-worker/tests/pipeline_community/main.rs`,
because only that package's tests can launch the worker binary. It includes
the `PPC1` harness (`apps/piglor-gateway/tests/pipeline_conformance/harness.rs`)
unchanged, checks the `PCH1` magic and version first, and then applies every
`PPC1` rule above: closed fields, stores, applicability, observation-profile
tags, pinned bytes, skipped mandatory cases and runners without a case.

The community pass world runs on `MemoryStore` only, so every case names the
`memory` store, and the `SQLITE-STORE` exclusion records that this profile
proves no SQLite parity of the community path. The other exclusions name the
#489 subtasks that add the remaining cases.

## `v1/legacy-eval-history.json` (`PLH1`, version 1)

Legacy `eval.prediction` and `eval.outcome` Events in the form the
pre-ADR-024-Revision-1 Persona composition emitted them: no causation,
`pred-<n>` ids and no outcome label. `expected_report` is the canonical text of
their Calibration Report: one field per line, floats in shortest round-trip
form. The values are exact binary fractions computed by hand from the Events.

These files are not part of the CPF1 bundle inventories (`SHA256SUMS`,
`BLAKE3SUMS`) and are not materialized into Draft bundles.
