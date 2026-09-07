# Sandbox Provider contract package

`sandbox-provider-v1.cddl` is the provider-neutral public wire schema selected
by ADR-069. Canonical CBOR vectors in `../vectors/sandbox-provider-v1` are
decoded by both `pos-conformance` and the independently implemented
`pos-reference` consumer. Systemd, OCI, youki, installation paths, and mutable
host state are not part of this package.

The checked-in `.cbor` files are public interoperability vectors, not runtime
state. Hosted CI rematerializes them from the producer, rejects byte drift, and
passes the same bytes through the independent decoder.

Version 1 replaces the former Draft EVR1 layout directly. There is no legacy
reader, migration, alias, or direct-command fallback.
