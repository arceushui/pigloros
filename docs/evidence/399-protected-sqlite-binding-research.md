# Protected SQLite file binding: investigation for #399

Date: 2026-10-30. Inspected revision:
`e9e6f43dc1de95821a5eee4422ae1e6876d40433` (PR #763 merged).
This is investigation evidence, not an accepted architecture decision or an
implementation of the SubjectDataEncryption consumer. The canonical proposal is
[ADR-123](https://redmine.piglor.com/projects/pigloros/wiki/ADR-123_Linux_Protected_SQLite_File_Binding).

## Completion audit

[Ticket #399](https://redmine.piglor.com/issues/399) requires an owner-authorized
encrypt/decrypt consumer, rotation, confirmed destruction, rollback behavior and
Replay redaction. PRs #726, #739, #747, #755 and #763 supply nonce-ledger and Linux
file primitives. The candidate descriptor helper in #763 does not prove that its
argument belongs to SQLite. These primitives do not satisfy the full ticket.

The accepted baseline remains ADR-097 wiki9, ADR-110 wiki29 and ADR-121 wiki5.
ADR-110 E16 already defines the Linux identity as `[1, st_dev, st_ino]` measured
from the open main database descriptor. ADR-097 B1 leaves the concrete Gateway
lease protocol separately undecided. The proposed binding does not select that
lease or the durable intent/receipt protocol, and does not enable production
activation.

## Existing seams and constructor inventory

The following inventory names inspected entry-point families. It is not a claim
that every caller has been qualified for protected use.

| Area at the inspected revision | Current behavior | Consequence for protected admission |
| --- | --- | --- |
| `pos-store/src/sqlite.rs`: `open`, `open_with_hasher`, private `open_with_options` | Opens a URI-capable read/write/create `rusqlite::Connection` | An ordinary store cannot itself prove protected admission |
| `open_read_only`, `open_writer_reservation_connection` | Read-only main connection can have a second writable reservation connection | Both connections need an explicit policy; exclude this constructor family from the first qualified profile |
| `open_with_clock` | Wraps ordinary `open` and changes clock authority | Clock customization cannot mint file-binding authority |
| `open_in_memory`, `open_in_memory_with_hasher` | Delegate to the ordinary open family using `:memory:` | No persistent main-file identity; refuse protected file binding |
| `pos-store/src/lib.rs`: `open_store`, `open_store_with_hasher`, `open_store_read_only`, `open_owntracks_enrollment_store` | Erase concrete stores behind capability traits | A trait object is not evidence of a qualified SQLite connection |
| `pos-runtime/src/erasure_host.rs`: standard/Gateway open helpers and recovered read-only hosts | Wrap and recover stores behind host capabilities | A protected composition root must preserve the concrete binding's ownership |
| `pos-store/src/trust_policy_registry.rs`: separate trust-policy database opener | Independently opens a different logical store | Its pathname identity check is not the subject store's canonical file identity |
| `pos-owner-bridge/src/encryptor_lock/linux/store_file.rs` | Borrows any candidate descriptor and checks regular/euid/exact `0600` metadata | Reuse the metadata rule, never promote an arbitrary caller-supplied pair into authority |

`SqliteStore` privately owns its connection. The inspected type has no `Clone`
implementation, raw-connection getter or `Deref` to `Connection`. Its ordinary
constructors permit a much broader profile than the proposed protected opener.
The workspace and `pos-store` forbid unsafe Rust. Pinned dependencies are
`rusqlite 0.40.2`, `libsqlite3-sys 0.38.2` and SQLite `3.53.2`.
These are repository observations at the revision above, not upstream guarantees.

Before a constructor PR, inventory every supported opener, wrapper, additional
connection, alias, metadata observer, error path and quarantine disposal path.
Classify test-only callers by their actual module gates. A textual search that
merely excludes paths named `tests` is insufficient: many fixtures live inside
source modules. Reconcile the inventory with the final qualified API and its
public acceptance tests.

## Primary-source findings

| Label | Source, version and access date | Supported fact |
| --- | --- | --- |
| S1 | SQLite, [How To Corrupt An SQLite Database File, §2.2](https://sqlite.org/howtocorrupt.html#posix_advisory_locks_canceled_by_a_separate_thread_doing_close), accessed 2026-10-30 | An ordinary same-process descriptor close can cancel SQLite's POSIX locks |
| S2 | Linux man-pages, [open(2), O_PATH](https://man7.org/linux/man-pages/man2/open.2.html), accessed 2026-10-30 | `O_PATH` supports metadata inspection without opening the file for ordinary I/O |
| S3 | Linux [v6.12 `fs/open.c`, `filp_flush`](https://github.com/torvalds/linux/blob/v6.12/fs/open.c), accessed 2026-10-30 | The close path skips POSIX lock removal for `FMODE_PATH` |
| S4 | SQLite [3.53.2 `src/func.c`, `filestatFunc`](https://github.com/sqlite/sqlite/blob/version-3.53.2/src/func.c), accessed 2026-10-30 | `SQLITE_ENABLE_FILESTAT` enables `sqlite_filestat(SCHEMA)` on the connection's pager |
| S5 | SQLite [3.53.2 `src/os_unix.c`, `unixFileControl` and `unixDescribeShm`](https://github.com/sqlite/sqlite/blob/version-3.53.2/src/os_unix.c), accessed 2026-10-30 | The Unix diagnostic describes actual main/journal descriptors and the shared-memory node descriptor |
| S6 | Rusqlite [0.40.2 `Connection`](https://docs.rs/rusqlite/0.40.2/rusqlite/struct.Connection.html), accessed 2026-10-30 | Safe connection queries and named VFS opening exist; `path()` supplies a pathname and the raw handle API is unsafe |
| S7 | SQLite, [Standard File Control Opcodes](https://sqlite.org/c3ref/c_fcntl_begin_atomic_write.html) and [file control](https://sqlite.org/c3ref/file_control.html), accessed 2026-10-30 | `FILE_POINTER` identifies a `sqlite3_file`, not a portable OS descriptor; `FILESTAT` is optional diagnostic JSON |
| S8 | SQLite, [VFS](https://sqlite.org/vfs.html) and [I/O methods](https://sqlite.org/c3ref/io_methods.html), accessed 2026-10-30 | A VFS shim is possible; complete WAL support includes shared-memory methods |
| S9 | Maintainer's [`rkusa/sqlite-vfs` README](https://github.com/rkusa/sqlite-vfs), accessed 2026-10-30 | Its documented interface does not support WAL; it cannot replace this shared-WAL profile as-is |
| S10 | SQLite, [copyright](https://sqlite.org/copyright.html) and [compile options](https://sqlite.org/compile.html), accessed 2026-10-30 | SQLite deliverables are public domain; nonstandard compile profiles require additional validation |

The pinned `libsqlite3-sys` build script accepts extra compiler definitions through
`LIBSQLITE3_FLAGS`. Its default bundled profile does not enable `FILESTAT`.
This was checked in the cached published package, not inferred from latest docs.
The `filestatFunc` and `unixDescribeShm` bodies match the separately downloaded
3.53.2 upstream source exactly. The inspected Unix `FILESTAT` case differs only
in trailing whitespace between the upstream file and the bundled amalgamation.
The amalgamation SHA-256 is
`0a409f1633283fa31a9126b11fbfd64a1991c5d30defad07e5745d4667f5e23d`;
the package's `build.rs` SHA-256 is
`269acf1864de5046ac5b77814926d41fe24108b0d027f635812a1db3c965f81f`.

## Alternatives

| Option | Fit and ownership | Cost and reason for disposition |
| --- | --- | --- |
| Pinned SQLite diagnostic plus `O_PATH` witness | Can obtain the actual connection's main/WAL/SHM descriptors through safe SQL, then observe their objects using owned metadata-only descriptors [S2–S6] | Proposed first option. Adds a native build flag and a deliberately versioned dependency on diagnostic output; fail closed after an unqualified upgrade |
| Small native accessor integrated with SQLite/Rusqlite | Can perform `fstat` inside the native owner and return only typed metadata, without transferring descriptor ownership [S7] | Technically viable, but requires maintained native changes or a new audited binding dependency and a deliberate exception if unsafe Rust is introduced |
| Delegating VFS shim | Can record open-file provenance while forwarding SQLite I/O and WAL behavior [S8] | Technically viable with a complete implementation; increases the locking/close/error-path implementation to maintain. The checked safe Rust VFS library lacks the required WAL support [S9] |
| Separate ordinary file open, pathname comparison or `/proc/self/fd` scan | Does not attest which main descriptor this connection owns | Reject. A separate ordinary close threatens locks [S1]; a scan or equal pathname is not connection provenance |

Recommendation is a project inference from the evidence, not an upstream promise
that diagnostic JSON is a supported security API. A maintained typed upstream
accessor would warrant revisiting the first option. This investigation does not
select a custom VFS, new crate, unsafe exception or SQLite version upgrade.

## Throwaway experiment

Built the already pinned SQLite amalgamation directly with `cc -shared -fPIC -O0
-DSQLITE_ENABLE_FILESTAT -DSQLITE_THREADSAFE=1`, linking pthread/dl/math. A Python
3.12.9 `ctypes` driver used only disposable fixture databases. Kernel:
`5.15.167.4-microsoft-standard-WSL2`. No Cargo commands or repository hooks ran.
The experiment used a local temporary filesystem and a held `BEGIN IMMEDIATE`.

For each of five fresh databases, `sqlite_filestat('main')` supplied `db.h`,
`journal.h` and `db.shm.h`. The driver opened `/proc/self/fd/<n>` with
`O_PATH | O_CLOEXEC`, compared its `fstat` device/inode with the actual native
descriptor, checked regular/euid/exact `0600`, and closed the witness. A separate
process attempted whole-file POSIX write locks before and after the close.

| Observation | Result |
| --- | --- |
| Main/WAL/SHM metadata identities agree with native descriptors | 15/15 |
| Main and SHM remain locked after metadata-witness close | 10/10 |
| Positive control: ordinary main-file descriptor close releases main POSIX locks | 5/5 |
| SHM remains locked during that main-file positive control | 5/5 |

No competing SQLite writer ran during the positive control. The driver rolled
back and closed each fixture afterward. SQLite source ID was
`2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`.

These observations validate a mechanism on this setup. They do not establish
race freedom, qualified production constructors, supported-kernel coverage,
cross-process Gateway lease behavior, erasure coordination or Rust acceptance.
Required hosted tests must cover missing diagnostic support, namespace changes,
wrong metadata, supported aliases, quarantine and lock preservation. The
diagnostic's allocation and output growth with additional connections also need
qualification; a post-query output bound alone does not bound native allocation.
