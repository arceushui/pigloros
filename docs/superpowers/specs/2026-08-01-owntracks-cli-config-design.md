# OwnTracks CLI Configuration Design

## Scope

This document specifies the approved preparatory portion of Redmine #146:
local, CLI-only administration for one V1 OwnTracks binding. It deliberately
does not add an HTTP ingress route or append `geo.location` Events. Those
actions remain separately gated after Accepted ADR-053, Accepted ADR-054, and
resolved #169.

## Goals

- Give the local deployment owner commands to pair, inspect, rotate, and
  revoke exactly one device binding.
- Use ADR-054's core-owned enrollment-state capability for binding, consent,
  policy, withdrawal, epoch, and keyed-verifier state, and connect it to
  #169's geographic-admission fence without maintaining parallel state.
- Keep the owner Gateway key in a separate owner-only file outside version
  control; never persist the generated 256-bit Basic secret with that key.
- Make revocation durable and immediately observable by a future ingress
  adapter, without changing immutable Timeline state.
- Keep every command deterministic except secure secret generation, and make
  all behavior independently testable.

## Non-goals

- `POST /v1/bridges/owntracks`, HTTP Basic verification, rate limiting, body
  decoding, metrics, or Timeline admission.
- A UI, remote pairing/recovery, multiple bindings, public/same-LAN ingress,
  any `geo.location` append, or a generic geographic-store capability.
- Schema migration, historical conversion, backfill, dual-write, upcast, or
  any change to the existing V1 location payload.

## Command surface

The existing manual `piglor-gateway` parser gains a top-level `owntracks`
command group:

```text
piglor-gateway owntracks pair <sqlite-path> <owner-key-path> <timeline-id> <entity-id>
piglor-gateway owntracks status <sqlite-path>
piglor-gateway owntracks rotate <sqlite-path> <owner-key-path>
piglor-gateway owntracks revoke <sqlite-path>
```

`pair` fails if an active binding already exists. On success it prints a fresh
random Basic handle and independent 256-bit secret exactly once to the local
terminal; it does not write either plaintext value to logs, errors, the
Timeline, or durable state. `rotate` follows the same generation and one-time
output rule.

The current command surface has no separately authorized source for the
current consent and policy fence required by `OwnTracksEnrollmentRequestV1`.
Until that source is approved, `pair` validates its identifier arguments and
then returns the bounded `OwnTracks policy configuration is unavailable` error
before creating an owner key or credential. It must not synthesize placeholder
consent, policy, revision, or epoch data. `status`, `rotate`, and `revoke`
remain narrow lifecycle commands for enrollment state created by an authorized
future pairing source.
`status` prints only bounded, non-sensitive state: unpaired, active, or
revoked plus the configured policy version. `rotate` replaces the active
credential verifier and prints a new secret exactly once. `revoke` makes the
binding inactive and deletes the removable verifier and transient state.

Every invalid invocation returns a bounded local error and a non-zero exit
status. Secrets are never repeated by `status`, `rotate` failures, or usage
text.

## Admission-state and ownership boundary

`OwnTracksEnrollmentStateV1` is the private core-owned ADR-054 capability
that supplies the state later revalidated by #169's admission fence. It has:

- a fixed state schema version of `1`;
- one binding state: absent, active, or revoked;
- an authorized Timeline and `EntityId`;
- the fixed V1 purpose, compact degree-grid precision, source-time bucket,
  local visibility scope, and current policy version;
- an owner-keyed verifier only, never the plaintext Basic handle or secret;
- consent identity, revision, typed hash, withdrawal state, and binding
  revision; and
- a monotonically increasing binding/admission revision for future revocation
  fencing.

The owner-key file contains an independently generated 256-bit key. It is
created with owner-only permissions, rejects symlinks and unsafe existing
paths, and uses create-new semantics with a directory sync. It must remain
outside version control. Binding, consent, verifier, policy, withdrawal, and
epoch state are durable only through ADR-054's core enrollment-state
transaction; the CLI must not maintain a parallel configuration file or
mutable copy.

The composition root may open a SQLite-backed `OwnTracksEnrollmentStore`, but
that factory returns neither generic `EventStore` nor geographic-admission
authority. The CLI cannot use it to append Timeline events.

The verifier derives from the owner key, random handle, and 256-bit secret
with a domain-separated keyed BLAKE3 operation. Later HTTP verification will
use constant-time comparison. This preparatory slice writes the verifier only
through the ADR-054 capability and does not expose an HTTP verifier or a
geographic admission capability.

## State transitions

```text
absent --pair--> active --rotate--> active
                    |                |
                    +----revoke------+--> revoked
revoked --pair--> active
```

Pair and rotate transactionally increment the binding/admission epoch with the
core enrollment state. Revoke transactionally advances that epoch and removes
removable verifier material, so #169's admission fence rejects requests
authenticated against a superseded binding. A stale policy version fails closed
until explicit re-pairing and re-consent establish the current version. The
command does not append a Timeline Event or geographic evidence.

## Module boundaries

`main.rs` stays responsible only for argument dispatch and terminal output.
A new focused module owns command parsing helpers, secure path/file handling,
secret generation, verifier derivation, and command-state transitions. It
depends only on a narrow ADR-054 administration capability, not a generic
`EventStore`; it has no Axum, OwnTracks decoder, or geographic-admission
dependency. The CLI cannot construct, serialize, or widen the core capability.

## Errors and privacy

The module distinguishes malformed CLI input, missing/unsafe owner-key files,
absent/active/revoked binding transitions, stale policy, unavailable core
state, and durable I/O failure. Error strings are stable and bounded. They
exclude secret bytes, verifier bytes, Basic headers, raw locations, Timeline
payloads, and full configuration contents.

The core transaction leaves either the old complete state or no new state; it
must never leave a partially valid active binding. A failure while pairing must
not make a credential usable. A failure while revoking must fail closed: future
commands treat the state as unavailable rather than active.

## Tests and acceptance

Tests will cover:

- every command's accepted and rejected argument forms;
- the fail-closed pair response when authorized policy configuration is absent,
  including proof that it creates no owner key or credential material;
- single-binding enforcement, active-to-active rotation, revoke behavior, and
  re-pairing after revocation;
- unique 256-bit credentials and one-time secret output without secret reuse;
- verifier domain separation and constant-time comparison seam;
- owner-only owner-key file/directory permissions, symlink rejection,
  create-new failures, and no plaintext-handle persistence;
- core capability policy/version/withdrawal/epoch behavior, including stale
  policy rejection and re-pair/re-consent requirements;
- proof that the module has no route registration, EventStore call,
  `geo.location` construction, or Timeline mutation.

The #146 change set must pass formatter, ignored-inclusive workspace tests,
pedantic clippy, the project CI checks, and the documented 99% line and region
coverage floor in a non-privileged test context. It also requires independent
code review before merge. Development databases may be recreated without a
migration. Production OwnTracks ingress remains disabled until #149 is
Resolved and a separate activation decision is recorded.
