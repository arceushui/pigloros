# Plugin host seam profile requirements

The evaluator must drive the ADR-061 public plugin protocol using the declared
ABI and exact fixed-width invocation and timeline identifiers. It must verify
canonical outputs, capability denial before effects, deterministic resource
failure, migration behavior, and release admission without invoking private
host helpers.
