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
source trees separately, then run:

```bash
python3 scripts/materialize-systemd-scs1.py \
  --systemd-source /path/to/systemd-v260.2 \
  --libseccomp-source /path/to/libseccomp-2.6.1 \
  --output crates/pos-conformance/vectors/systemd-provider-v260.2
```

The materializer rejects source files whose SHA-256 digests differ from the
pinned inputs. It recursively expands `@system-service`, maps names through
the pinned target interfaces, emits explicit sorted names, requires the six
launcher/provider syscalls named by ADR-069, and writes canonical SCS1 bytes.
Production code must consume these checked-in records through APT1/SIC1; it
must never invoke `systemd-analyze`, expand groups, infer architecture, or add
names from the running host.
