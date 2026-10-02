# Cross-path pipeline conformance fixtures

These fixtures drive the first-party and in-process ADR-021 pipeline
conformance profile (Redmine #488, the first half of #321). The profile proves
human and AI ingress through atomic host admission, failure precedence,
recovery, Replay and evaluation non-authority, the ADR-021 Revision 3
observation profiles, exclusive Event-type ownership (ADR-024 Revision 1) and
revocation persistence. Its runner is
`apps/piglor-gateway/tests/pipeline_conformance.rs`, which the workspace test
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

## `v1/legacy-eval-history.json` (`PLH1`, version 1)

Legacy `eval.prediction` and `eval.outcome` Events in the form the
pre-ADR-024-Revision-1 Persona composition emitted them: no causation,
`pred-<n>` ids and no outcome label. `expected_report` is the canonical text of
their Calibration Report: one field per line, floats in shortest round-trip
form. The values are exact binary fractions computed by hand from the Events.

These files are not part of the CPF1 bundle inventories (`SHA256SUMS`,
`BLAKE3SUMS`) and are not materialized into Draft bundles.
