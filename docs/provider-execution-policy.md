# Provider execution policy admission

The #441 execution composition implements the source exchange proposed in
[ADR-122 revision 3](https://redmine.piglor.com/projects/pigloros/wiki/ADR-122_Provider_execution_policy_provenance).
The ADR remains Proposed. This document describes the implementation, not a
change to its formal decision status or permission to activate a daemon.

The selector sends canonical EVR1 and then SPX1, each with its own four-byte
big-endian length prefix and 16 MiB payload ceiling. The provider authenticates
the root peer and its fixed SIC1 installation before reading either record. It
reconstructs the selected case from retained CFB1/TPS1, rederives both complete
request IDs, and compares the exact SPX1 before reserving an attempt or issuing
AGR1. The current authenticated network-plan source is the empty sequence;
nonempty plans fail admission.

The provider derives all seventeen ELM1 limits and the expected RBS1 commitment
using the existing commitment algorithm. One opaque prepared context retains
that policy and the source/input reservations. AGR1 is signed from those facts
and checked under the installed runtime key. Only after authenticating AGR1
does the selector send SBC1 input. Complete descriptor, EAI1 case and framing
verification inside a private staging file produces the admitted entry.

Execution derives systemd limits, `/work` and the watchdog from that entry.
The release barrier takes its expected RBS1 digest from the same context. A
different context, including otherwise equal IDs with different policy, cannot
replace the rechecked root. Observed readback remains the #443 evidence port.

The owner configures only the aggregate staging byte cap. Retained canonical
EVR1/SPX1 buffers, reconstructed case buffers and payload storage share that
accounting. Installed artifact bytes held only by descriptors are not staging
copies. Buffer ownership drops each charge after its actual bytes. Pending controls use a separate pool
bounded by the smaller of BHC1 ConcurrentAttempts and 256. One original BHC1
deadline spans both source frames and reconstruction, preserving any stricter
original transport bound. The derived input deadline starts at completion of
SPX1 and is never reset after reconstruction or signing. Checks refuse extra
bytes already visible before reservation and grant writing. Source decoding
accepts exactly its two records; the transition to grant writing starts the
AGR1 output phase. Later peer bytes can only be input, including while AGR1 is
being written. An injected SPX1 is invalid input and cannot mint an admitted
entry or start a unit. A queue peek supplies no authority or prediction about
future peer bytes. Zero is a denial, never an implicit default.

Attempt and queued-input counts preserve the minimum of the candidate's ceiling
and every live counted reservation's ceiling under one lock. Retained output
keeps the original attempt counted once. Failed admission releases its partial
reservations; successful inputs retain their bytes and execution context.

Selector and provider must be upgraded together while admission is closed.
There is no SPX1-only fallback. The record schemas and digest preimages are
unchanged, but the live connection sequence is incompatible. #442 must restore
retained reservations and ceilings before reopening after restart; #443 owns
durable evidence and observed readback, #444 owns packaged conformance, and #911
owns actual Local networking. No listener or daemon is activated by this code.
