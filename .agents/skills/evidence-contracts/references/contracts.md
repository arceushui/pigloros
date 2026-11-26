# Design and contracts

Internal PiglorOS guidance. Apply the relevant lessons within the current task's
authorization and repository policy.

- **Leave-one-out for per-entity baselines.** When computing entity-specific metrics, exclude the current observation from the historical baseline. Otherwise single-observation entities get perfect scores.

- **Prefer iterators over owned collections in API.** `fn plugin_names() -> impl Iterator<Item = &str>` is consistent. `fn plugin_versions() -> HashMap<String, String>` is not.

- **State acceptance criteria separately from evidence.** Every claim needs an audience, public boundary, pass/fail condition, named module or schema owner, authoritative artifact, evaluator, maturity, and remaining gate.

- **Metadata does not prove behavior.** Fixture IDs, digests, and screenshots are references, not conformance. Mandatory cases must execute through the public boundary, and equality claims must bind to independently produced outputs.

- **Keep evidence roles distinct.** Record host evidence, evaluator validation, independent reproduction, and authorship or organizational independence as separate fields.

- **Use the smallest deterministic fixture that proves the claim.** Do not strengthen domain semantics merely because a fixture makes a stronger statement convenient.

- **Separate computational Replay from empirical validity.** Keep Replay, world-model evidence, Persona calibration, Society Signal, route-level security enforcement, and future architecture distinct; a deterministic fixture or descriptor must not claim validity outside its declared role.

- **Audit contract changes as graph changes.** When an enum, trait, schema, or public constructor changes, search every exhaustive match, adapter, composition root, test seam, fixture, migration, and downstream consumer before pushing; hosted compile failures often reveal fan-out missed at the declaration site.

- **Keep authority independent from its consumer.** A caller must not mint, grant, or self-validate the authority it presents. Bind opaque capabilities and permits at the trusted composition boundary, reject foreign or unbound values, and retain only the lifecycle operations authorized by the port.

- **Pair privacy-preserving reads with host-owned continuation seams.** If a generic API intentionally hides protected data, model the authenticated head, replay, retry, or revocation seam explicitly and exercise it with fixtures that satisfy every consent and capability precondition.

- **Make unsupported evidence structurally incomplete.** Unavailable authority bytes, signatures, or external attestations stay Draft or pending; they must not look like Candidate or materialized evidence through placeholder paths, digests, or metadata.

- **Keep cryptographic integrity and trust authorization distinct.** A valid signature does not establish that the signer is trusted for the requested lifecycle transition. Require both checks at the promotion boundary, and bind recursive containers through explicit layered commitments.

- **Treat V1 contract evolution as replacement-first when compatibility is out of scope.** Replace obsolete interfaces directly, remove stale compatibility shims and claims, and update migrations, fixtures, and public tests to the one normative contract rather than preserving an unused legacy path.

- **Treat conformance metadata as executable input.** A changed matrix, fixture, profile, byte count, digest, checksum, or workflow key requires recomputation and static verification of every dependent field before publication. Paired execution modes share authoritative content but may differ in transport paths; compare by case, layer, and content identity.

- **Separate new authoring from historical persistence.** A policy rejecting new
  Event authoring must not accidentally reject copying already committed history
  through a lower storage helper. Review both public contracts before placing
  the guard.

- **Bind digests to checkout bytes.** Verify newline and other checkout
  transformations for digest-bound assets with narrow attributes and manifest
  checks. Regenerate linked fixture inventories and their integrity manifests in
  dependency order; hashing an edited artifact does not repair a stale inventory.
