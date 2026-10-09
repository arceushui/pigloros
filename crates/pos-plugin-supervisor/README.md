# pos-plugin-supervisor

The community Plugin worker supervisor and the host pass member (ADR-061 Sandboxed Community
Plugin Runtime and Decentralized Artifact Trust, revision 7; #542, #543, #583 to #585).

## Handoff to #194

`CommunityPluginSubjectOutcomeV1` is the stable outcome record of one Plugin in one host pass.
`CommunityPluginSubjectOutcomeV1::assemble(entry, tick, mode, receipt)` builds it, and is
total, from a `MemberPassV1` of `CommunityPassOutcomeV1::gates` and the invocation receipt
found with `CommunityPluginHandleV1::receipt_for()` for the entry's `invocation_id`. The
caller passes no receipt when the entry has no `invocation_id`: `assemble` compares no IDs.

The record carries the exact closed strings of decisions 3 and 5 of ADR-061 (Sandboxed Community
Plugin Runtime and Decentralized Artifact Trust) revision 7 (error, basis and class names), the
content-validation fact (`NotPerformed` until #574) and the execution profile digest. It
carries no claim of signature validity: a release that fails the gate is `Refused`, and
nothing else says it was verified.

The EAI1/EAO1 subject adapter binary is owned by #194.

Results are Local-relaxation engineering evidence, not hosted conformance.

`scripts/check_handoff_readme.py` checks the ownership sentence and the evidence sentence
above on every CI run.
