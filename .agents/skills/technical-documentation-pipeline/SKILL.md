---
name: technical-documentation-pipeline
description: Choose the canonical home and workflow for PiglorOS ADRs, Notion design documents, and contributor documentation. Use for technical documentation planning or publication; architectural research and ADR decisions belong to prepare-adr.
---

# Technical documentation pipeline

Internal PiglorOS workflow. Read
[documentation boundary lessons](references/documentation-boundaries.md) before
editing or publishing. Find the existing canonical source before creating a
second document.

## Select the owner

| Need | Owner and destination |
| --- | --- |
| Choose an architecture, dependency, or significant public boundary | [prepare-adr](../prepare-adr/SKILL.md), Proposed Redmine ADR |
| Create or amend a canonical ADR page, publish its status, or record approval | [adr-wiki](../adr-wiki/SKILL.md), Redmine under the ADR parent |
| Explain an accepted design, APIs, implementation sequence, or rollout | Notion design document using [the design template](references/design-doc-template.md) |
| Current usage, contributor policy, or durable public contract guidance | The existing repository document or contract owner |
| Dated investigation, execution evidence, or decision discussion | The linked Redmine or Notion record |

For a request containing both a decision and its implementation design, establish
the ADR boundary first, then link the design document to the accepted revision.
A design document does not confer architecture approval or implementation
authority. Follow the ADR owners for triggers, canonical headers, lifecycle,
revision receipts, and publication; this skill does not define a second format.

## Write and publish

State the audience, current maturity, source of truth, and concrete acceptance
claim before adding technical detail. Use exact domain vocabulary. Keep Notion
tables, Mermaid, code, links, and page hierarchy in their native serialization
forms. Use a diagram only when it explains a boundary or ordering relationship.

Fetch canonical content before editing. Use supported provider revision guards
for writes and reconcile conflicts instead of overwriting a newer record.
Read the result back, including the full text, links, hierarchy, status, and any
server-generated structural changes.

## Pre-flight

- [ ] One canonical document owns the claim; the destination matches its purpose.
- [ ] ADR procedure comes from prepare-adr and adr-wiki, with no competing template.
- [ ] Current capability and approval claims match their authoritative artifacts.
- [ ] Required fields are concrete, links resolve, and diagrams explain the text.
- [ ] Canonical writes were read back with their revision and hierarchy.
