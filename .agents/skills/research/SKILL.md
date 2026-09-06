---
name: research
description: Investigate a question against high-trust primary sources and capture the findings as a Markdown file in the repo. Use when the user wants a topic researched, docs or API facts gathered, or reading legwork delegated to a background agent.
---

Spin up a **background agent** to do the research, so you keep working while it reads.

Its job:

1. Inspect the repository's existing executable harness, dependency policy,
   sample/report format, pinned versions, and operational constraints before
   comparing tools. State whether the desired capability can consume existing
   outputs and justify every new dependency separately.
2. Investigate the question against **primary sources** — official docs, source
   code, specs, first-party APIs — not a secondary write-up. Follow every claim
   back to the source that owns it.
3. After finding a transport or base library, explicitly search for maintained
   generated bindings and protocol-specific clients before recommending a
   custom proxy. Verify protocol version, release health, MSRV/runtime support,
   licence, and feature-probing requirements.
   For CI/tool integrations, inspect the pinned released executable's help and
   representative output. Treat default-branch documentation as forward-looking
   unless it is explicitly versioned for the selected release.
4. Write the findings to a single Markdown file, citing each claim's source.
5. Save it where the repo already keeps such notes; match the existing
   convention, and if there is none, put it somewhere sensible and say where.

Before delivery, verify that the recommendation fits the inspected harness and
that no custom protocol surface is proposed where a maintained compatible
binding already satisfies the requirement.
