# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root — domain glossary
- **Redmine wiki** (`redmine.piglor.com/projects/pigloros/wiki`) — canonical ADRs and architectural decisions
- **Notion** — design docs and Wave specs (MCP configured)

If `CONTEXT.md` doesn't exist, proceed silently. Don't flag its absence; don't suggest creating it upfront. The `/domain-modeling` skill creates it lazily when terms get resolved.

## File structure

Single-context repo:

```
/
├── CONTEXT.md                           ← domain glossary
└── src/                                 ← workspace source
```

ADRs live on the Redmine wiki, not in the filesystem.

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0007 — but worth reopening because…_
