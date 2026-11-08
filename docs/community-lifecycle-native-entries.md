# Community lifecycle native entry inventory

This inventory belongs to #560 and the accepted ADR-129 Linux activation
profile. The source baseline before this batch is
`da6a7e1cacbefce0902b52c39dc1b8f855849bd0`. It covers the supported
PiglorOS factories in `crates/`, `apps/` and `plugins/`. Test-only raw
connections remain isolated adversarial/ordinary fixtures. A fixture marker or
passing refusal test is not native owner qualification.

## Native constructors

| File / function | Native entry and callers | Namespace refusal |
| --- | --- | --- |
| `crates/pos-store/src/sqlite.rs`, `SqliteStore::open_with_options` | URI-enabled `Connection::open_with_flags`; `open`, `open_read_only`, `open_with_hasher`, `open_with_clock`, Memory SQLite wrappers | Check filename before the first connection or schema/configuration work |
| Same file, `open_writer_reservation_connection` | A second read-write connection for a read-only store | Independent filename check before this native edge; forbidden entirely in the qualified one-connection factory |
| `crates/pos-store/src/trusted_clock/sqlite.rs`, `connect` | Separate trusted-clock reservation/guard connections, including reopen and maintenance | Check filename before native open; the protected composition must use its own same-context clock operations |
| `crates/pos-store/src/trust_policy_registry.rs`, `open_connection` | Independent deployment TPS1 policy database for `open_current` and explicit provisioning | Check literal path before native open; `create_state_file` also checks before creating a provisioning file |
| `apps/piglor-ledger/src/key_output.rs`, `bind_owned_secret_key` | Independent ledger signing-key binding database | Check literal database path before reading the owned secret or opening SQLite |
| Same file, `require_owned_secret_key_binding` | Independent key-binding verification before managed signing-key deletion | Check literal database path before native open |

The two ledger constructors are production entries in addition to the
illustrative ADR-129 baseline table. They must not bypass the reserved namespace
merely because the key owner is a different role.

## Wrapper reachability

`pos-store::open_store`, `open_store_with_hasher`, `open_store_read_only` and
`open_owntracks_enrollment_store` reach the checked `SqliteStore` factories.
`pos-runtime::erasure_host::{open_host_store,open_gateway_host_store}` dispatch
SQLite through those same factories. Their verified-empty, authority-bound,
Gateway, recovery and read wrappers do not receive a separate native exemption.
Gateway/OwnTracks, CLI, experiment and ledger EventStore composition follows
these store or erasure-host paths. The ledger key-file functions above are the
additional independent native edges.

`SqliteStore` Plugin trust registry operations use its existing connection;
they do not construct another connection. They still need common admission at
every protected current-use/authority/trust/floor mutation. Passing the pre-open
screen does not add that admission. Test-support admission/interlock helpers
remain test-support-only; only their fixed coordination basename is shared.

## Refusal boundary

On Linux, `protected_sqlite_namespace` checks the fixed
`.pigloros-store-namespace-v1` entry. Any kind of entry denies an ordinary open.
It checks lexical and resolved ancestry, including existing and dangling leaf
aliases. URI-enabled factories screen the filename after its SQLite path
interpretation: `file:` authority, percent escapes, query/fragment removal and
the pinned parser's `%00` path termination. The pinned bundled build script
enables `SQLITE_USE_URI`, so even native factories without an explicit URI flag
check both the literal filesystem path and its native URI interpretation.
Filesystem provisioning itself still uses the literal path. Main, WAL, SHM and unrelated names inside the
reserved directory receive the same refusal.

The empty/`:memory:` exemption applies only to SQLite filename interpretation.
Literal filesystem provisioning checks those names like any other path before
creating a file; it cannot use a SQLite special name to escape a reserved cwd.

SQLite URI semantics are grounded in the [official URI specification](https://sqlite.org/uri.html)
and the pinned `libsqlite3-sys 0.38.2` amalgamation's `sqlite3ParseUri`. The
guard only denies; it does not implement a new VFS or certify a native file.

## Remaining activation obligations

These pre-open refusals do not make namespace installation atomic. The actual
factory still must register the complete activation/context/handle inventory
before exposing handles, retire pre-existing connections quiescently, and join
all supported operations to common admission/interlock order. Path screening is
not an actual-main/WAL/SHM witness or proof against an installation race.

The selected factory must qualify the exact pinned native build using safe SQL
`sqlite_filestat('main')`, restore diagnostic limits, pin metadata-only procfd
witnesses and check the actual native triplet around use. The first profile
still forbids alternate VFS/URI/ATTACH/backup/restore/VACUUM escapes, second
connections, destructor fallback close and replacement after uncertain cleanup.
Managed close, retained/quarantined native owners, complete worker/copy
accounting, current authority and transactional lifecycle publication remain
required before activation. No qualified constructor is supplied by this
inventory or its refusal tests.
