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
new version directory, not an edit; rollback selects an older directory. An
edit that changes no expected value, such as removing an exclusion or running
a case on one more store, has been made in place with a new pin, each time by
user decision (see `PCH1` below).

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
- Community Plugin-host parity is not a `PPC1` exclusion. The sibling profile
  `PCH1` below proves it (#489, #636), and what it cannot prove yet (some
  invalid-Plugin and resource-limit shapes) is recorded as `PCH1`
  exclusions. The `COMMUNITY-PLUGIN-HOST` exclusion was removed from `v1` in
  place: removing an exclusion changes no expected result.

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

`PCF-CPH-003` and `PCF-CPH-004` (#632) cover authority parity. A Driver of
either class that proposes another Plugin's Event type fails the pass with
the same typed refusal, `Authority(UnauthorizedSource)`, commits nothing and
leaves every Plugin available. An Event type has one owner, whichever class
claims it first: a later claim of either class, or a claim of the Gateway's
reserved consent type, is refused before the registry changes. The real
guests emit only `prototype.driven`, so the community Driver proposes a
foreign type by owning another type than the one its guest emits.

`PCF-CPH-013` (#654) covers a community proposal of a reserved host Event
type. The lane steers the probe guest with the `reserved` selector, so the
community Driver drafts the host's `pigloros.plugin.release-activated` type
after the first-party sibling staged. The registry refuses the draft before
ownership with `ReservedHostDraft`, the same refusal as the first-party
proposal of that type, and `classify_pass_failure` classifies both as
`Unrelated`, so the community host does not take the refusal as its own: the
whole pass commits nothing, no Plugin is quarantined, the community receipt is
discarded, and the next pass with the guest unsteered commits both Events. The
`COMMUNITY-RESERVED-PROPOSAL` exclusion was removed in place.

`PCF-CPH-005` to `PCF-CPH-009` (#633) cover failure containment and fail-closed
composition. A Driver of either class that fails while it stages (a real guest
trap on the worker, or a first-party Driver failure) discards the whole pass,
the other class's staged output included; the sibling stays available, only
the trapping community Plugin is quarantined (`Trapped`, recorded but not
compared), and the next pass commits. A failed pass launches one worker for the
failing step, a first-party Plugin with the same domain contract is never run
in its place, a quarantined Plugin refuses the whole pass, and recovery is a new
pass under new invocation identities (the context source issues them, so the
case models them). A missing, unavailable or invalid Plugin of either class gets
the same typed refusal: `MissingImplementation` from exact resolution,
`ImplementationUnavailable` before any Driver runs (community unavailability is
injected through the host's refusal record), and
`IncompatibleImplementation(Isolation)` from exact resolution. Only the
community path has a release, so a release that is not active is refused at the
trust gate and one with a denied capability never becomes a Driver. An invalid
community guest output needs a new guest Component and an ABI- or
manifest-invalid release needs a malformed release fixture; the
`INVALID-GUEST-OUTPUT` exclusion records both.

`PCF-CPH-010` (#634) covers over-budget parity. The two classes are bound by
different budgets, so the equivalence is semantic: a typed non-commit that
discards the whole pass, the other class's staged output included, commits no
Event, leaves the sibling available, and the next pass within budget commits.
A community release whose memory budget (one page) the real guest exceeds ends
every launch `MemoryLimitExceeded` and is quarantined `ResourceExhausted`
(recorded but not compared); the budget belongs to the release, so the Plugin is
exhausted again after the host clears the quarantine, and the pass within budget
runs, in a fresh lane, a Driver built from an in-budget successor release. A
first-party Driver that stages more drafts than the registry's host Tick draft
budget leaves fails the pass `ResourceExhausted` and quarantines nothing. The
fuel, host-call and output limits of a community Driver are not exercised on the
real worker; the `OTHER-RESOURCE-LIMITS` exclusion records them.

`PCF-CPH-011` and `PCF-CPH-012` (#635) cover Replay and lost-acknowledgement
recovery. A Replay registry over the same first-party and community Drivers
folds the Events a live pass of both committed into the projection the live
registry folds (a first-party observer's Reducer that records Timeline Order,
Event type and payload size; the observer joins the live registry after its
pass, so the two folds are equal by construction and the case proves that the
Events of either class fold and no Plugin runs), refuses at the registry seam to
step its Drivers (`ModeMismatch`), steps no first-party Driver and launches no
worker; the Local and Air-Gapped passes commit the same Events, payload bytes
included. A pass whose commit acknowledgement is lost is `InDoubt` with its
batch on the Timeline, in a mixed lane and in a first-party-only lane alike:
`recover_scheduled_pass` returns a receipt that names exactly that batch,
commits nothing again, re-runs no first-party Driver, launches no worker, and
finds nothing in doubt a second time. The community member's receipt stays
staged until the recovery commits it and adopts its state (recorded, not
compared).

Every case runs on both stores of the community pass world, `memory`
(`MemoryStore`) and `sqlite` (`SqliteStore` on an in-memory database), and
records the same expected values on each (#638, #651). SQLite parity is proven
for the pass store, the store every pass admits to, reads Events from and
recovers from; the trust registry of the signed-release test world stays on
`MemoryStore`. A case that runs no pass, or none that commits (parts of
`PCF-CPH-004`, `PCF-CPH-007` and `PCF-CPH-009`), still runs on both stores and
records the same values on each. The exclusions name what the real guests and
release fixtures cannot yet exercise (owned by #637).

`PCH1` version 1 was re-pinned in place to add SQLite, by user decision
(2026-10-17), following the in-place re-pins of #632 to #636: every case's
`stores` grew from `memory` to `memory` and `sqlite`, the `SQLITE-STORE`
exclusion was removed, and #638 and #651 joined the sources. No expected value
changed; only the store set grew, so the manifest's pinned SHA-256 changed.

`PCH1` version 1 was re-pinned in place again for #637, by user decision
(2026-10-17): #654 appended `PCF-CPH-013` and removed the
`COMMUNITY-RESERVED-PROPOSAL` exclusion, and #637 and #654 joined the sources.
No expected value of an earlier case changed.

Every `PCH1` case (`PCF-CPH-001` to `PCF-CPH-013`) is mandatory and applicable
and has exactly one runner, in manifest order; the runner asserts that none is
skipped.

## `v1/legacy-eval-history.json` (`PLH1`, version 1)

Legacy `eval.prediction` and `eval.outcome` Events in the form the
pre-ADR-024-Revision-1 Persona composition emitted them: no causation,
`pred-<n>` ids and no outcome label. `expected_report` is the canonical text of
their Calibration Report: one field per line, floats in shortest round-trip
form. The values are exact binary fractions computed by hand from the Events.

These files are not part of the CPF1 bundle inventories (`SHA256SUMS`,
`BLAKE3SUMS`) and are not materialized into Draft bundles.
