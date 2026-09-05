---
name: prepare-adr
description: Prepare a decision-ready Architecture Decision Record for PiglorOS. Use before implementing a new crate, plugin, binary, durable public API, external dependency, storage/security boundary, protocol, coordinate model, or other significant/reversible architectural choice. Requires substantial online primary-source research, explicit alternatives and risks, and a Proposed Redmine ADR for user review before code.
---

# Prepare a Research-Backed ADR

This is an internal PiglorOS workflow. Use the canonical ADR wiki on Redmine;
do not substitute repository documentation for the decision record.

## Required model

When ADR research or drafting is delegated, use `gpt-5.6-sol` explicitly.
If it is unavailable, `gpt-5.6-terra` is the only permitted fallback. Do not
silently substitute a cheaper model; report which model was used before
publishing or materially revising the ADR.

## 1. Establish the decision boundary

1. Read `CONTEXT.md`, `README.md`, relevant ticket(s), related Redmine ADRs,
   and the affected public interfaces.
   Fetch accepted ADRs from canonical Redmine and classify the proposed work as
   already covered, a clarification, or a genuinely new decision before opening
   another ADR.
2. State one decision question. Split unrelated choices into separate ADRs.
3. Identify the decision owner, affected Timeline/event/replay boundaries, and
   acceptance criteria. Use exact project vocabulary.
4. Invoke `start-work` and journal the investigation when the work has a
   Redmine ticket. Invoke `adr-wiki` for Redmine hierarchy and formatting.
5. Separate the requested architectural decision from external enabling
   prerequisites. Record prerequisites as activation blockers/non-goals unless
   the user explicitly authorizes deciding them or the architecture cannot be
   evaluated without that choice.

## 2. Research before recommending

Do not draft a recommendation from memory. Browse the web and record an
evidence table before selecting an option.

- Investigate the recommended option and at least two viable alternatives.
- Use primary sources first: official specifications, maintainers' API/docs,
  release/migration notes, standards bodies, source repositories, and original
  research papers. Use secondary material only to find primary sources and
  label it as secondary.
- Collect at least four relevant primary sources across the alternatives. If
  the field genuinely has fewer authoritative sources, state that limitation
  and explain the extra validation used instead.
- For every material source, capture title, URL, publisher/version or release
  date, access date, and the exact claim it supports. Never manufacture a
  citation or treat a search-result snippet as evidence.
- Compare each option against the decision-specific dimensions below. Mark
  unknowns explicitly; do not convert them into assumptions.

| Dimension | Questions to answer |
|---|---|
| Functional fit | Does it satisfy the ticket's concrete acceptance criteria? |
| Determinism and replay | Can historical Timelines replay without a live service, changing solver, or changing model? |
| Privacy and security | What data, credentials, capabilities, and attack surfaces cross the boundary? What is persisted? |
| Compatibility | Schema versions, wire format, migration, upcasting, old Timeline behavior, and interoperability. |
| Operational cost | Dependencies, build support, latency, resource use, observability, failure modes, and maintenance ownership. |
| Licence and supply chain | Licence, release health, native/system dependencies, pinning, and update risk. |

For numeric or behavior claims, prefer a small reproducible prototype or
fixture when documentation alone cannot establish the claim. Record the
measurement setup and result in the ADR or ticket journal.

## 3. Make the recommendation auditable

Separate **facts** (with sources) from the **recommendation** (the project
inference). Specify:

- selected option, version/format, and the smallest architecture-consistent
  initial slice;
- public types, ownership boundaries, validation, error behavior, canonical
  serialization, and configuration/provenance fields;
- deterministic ordering, fixed inputs, and replay behavior;
- privacy/security controls and explicit non-goals;
- migration/upcasting and rollback plan where persisted data is affected;
- risks, mitigations, and conditions that would trigger a new ADR.

For configurable policy that changes deterministic interpretation, bind the
selected value into the canonical identity/digest contract and keep compiled
constants as outer admissibility maxima. For machine-readable schemas, review
formal cardinality/optionality operators as code. Enumerate positional fields,
signers, digest preimages, and outbound digest references; reject accidental
self-edges/cycles and require closed numeric-enum mappings before review.

Reject alternatives with concrete reasons. Do not write vague conclusions such
as “more flexible” or “industry standard.”

### Show the decision, do not only describe it

Add one compact, decision-relevant diagram whenever the ADR changes a boundary,
message/data flow, lifecycle, state transition, ownership relationship, or
rollout sequence. Prefer a Markdown-safe text diagram because it renders in the
canonical Redmine wiki without a plugin. Keep it adjacent to the section it
explains, label it, and use the project's exact vocabulary. Do not add a
decorative diagram or repeat prose in picture form.

For example:

```text
Adapter -> keyed ingress identity -> EventStore transaction -> Timeline Event
                                      | duplicate/conflict
                                      v
                               bounded identity retention
```

Use a table instead when comparing two or more options, and a short timeline
when the decision changes ordering or rollout. A diagram is required when such
a relationship would otherwise need several sentences to make the affected
boundaries or ordering clear.

### Cite claims where the reader needs them

Assign each source a stable label (`[S1]`, `[S2]`, ...) in the evidence table.
Place that label immediately after every material factual claim, including
claims in diagrams, tables, risks, and alternatives. The Sources section must
then provide the full title, direct URL, publisher/version, publication date
when available, access date, and the claim(s) each source supports. Do not make
readers infer which source supports a claim from an undifferentiated link list.

## 4. Publish a Proposed ADR, then pause

Create a Markdown Redmine wiki page with `ADR` as its parent. Use the next
unique ADR number after checking existing wiki titles. Include:

```markdown
**Status:** Proposed | **Wave:** <wave> | **Deciders:** core team | **Date:** <date>

Related: #ticket · [[related ADR]]

---

## Context
## Decision drivers
## Evidence and alternatives
## Proposed decision
## Consequences and risks
## Migration and rollout
## Non-goals
## Sources
```

The Sources section must map links to claims, not be a link dump. Add a
Redmine journal note with the ADR link, selected option, main trade-off, and
the decision needed from the user. Do not implement a significant new contract
until the ADR is accepted, unless the user explicitly authorizes proceeding
while it is Proposed.

## Pre-flight check

Before presenting the ADR, re-read it and verify:

- [ ] One decision, with ticket and existing ADR relationships correct.
- [ ] At least two alternatives and four primary sources, or a documented
      reason this was impossible.
- [ ] Every important fact has a source; every recommendation is labelled as
      an inference.
- [ ] Every material source has a stable label, and each material factual claim
      cites that label where it appears.
- [ ] A compact Markdown-safe diagram, table, or timeline makes every changed
      boundary, lifecycle, or ordering relationship easier to audit; no
      decorative visual was added.
- [ ] Replay, security/privacy, compatibility/migration, operational, and
      licence/supply-chain effects are addressed or declared out of scope.
- [ ] Existing canonical ADR scope was checked before proposing new design work.
- [ ] Enabling prerequisites did not silently broaden the decision boundary.
- [ ] Formal cardinalities, field labels, enum mappings, and digest dependency
      graph agree with the prose and are acyclic where required.
- [ ] Deterministic configurable policy is identity-bound, not only range-checked.
- [ ] Risks include a mitigation or an explicit acceptance decision.
- [ ] Redmine page is Markdown, parented under `ADR`, marked Proposed, and
      journaled on the ticket.
