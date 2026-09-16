# systemd v260.2 production syscall records

These are the production SCS1 records selected by ADR-069 for the first
systemd Sandbox Provider Adapter. They are authority inputs, not host-derived
runtime defaults:

- `systemd-v260.2-x86_64.scs1.cbor`
- `systemd-v260.2-aarch64.scs1.cbor`

`manifest.json` binds their lengths, BLAKE3 digests, SCS1 self-digests, and
the exact upstream derivation inputs. The pinned build closure uses systemd
v260.2 revision `f1d0952a125b96b7ab2f1ff29a87448ade8ac29b` and libseccomp
v2.6.1 from nixpkgs revision `6713828a351efa628b025a1adf7f43cbf8597513`.

Materialization is deliberately offline. Obtain and authenticate the pinned
systemd Git checkout and official libseccomp release archive separately, then run:

```bash
python3 scripts/materialize-systemd-scs1.py \
  --systemd-source /path/to/systemd-v260.2 \
  --libseccomp-archive /path/to/libseccomp-2.6.1.tar.gz \
  --output crates/pos-conformance/vectors/systemd-provider-v260.2
```

The materializer requires the exact systemd Git HEAD and checks the source-file,
libseccomp archive, and archive-contained syscall-table SHA-256 digests against
the pinned inputs. It recursively expands `@system-service`, maps names through
the pinned target interfaces, emits explicit sorted names, requires the six
launcher/provider syscalls named by ADR-069, and writes canonical SCS1 bytes.
Target materialization includes native syscall numbers, not libseccomp `PNR`
pseudo-syscall names. The only exception is aarch64 `poll`, expressly retained
by ADR-069. It describes the required systemd `SystemCallFilter` D-Bus property
readback, not a native aarch64 kernel rule. The pinned expansion yields 315
x86_64 names and 275 aarch64 names; the two arrays are architecture-specific.
Requested and expected-readback arrays are deliberately distinct. The pinned
systemd transient-unit allow-list setter inserts `@default` before the supplied
names, and its D-Bus getter retains resolvable PNR identifiers. The offline
materializer enumerates those implicit additions into the expected array:
333 names for x86_64 and 300 for aarch64. These additional readback names do not
claim native kernel rules and are never added to the requested arrays. Actual
runtime readback/enforcement proof remains in #214.

Production code must consume these checked-in records through APT1/SIC1; it
must never invoke `systemd-analyze`, expand groups, infer architecture, or add
names from the running host.

Add `--check` to verify all checked-in records and the complete manifest without
writing files. The `conformance-fixtures` CI job obtains the pinned inputs,
reproduces these outputs twice, and exercises revision, digest, parser, target,
required-syscall, and output/provenance rejection boundaries.
