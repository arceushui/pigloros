# Multi-agent Model Policy

- Use `gpt-5.6-terra` for implementation and execution agents.
- Prefer `gpt-5.3-codex-spark` for independent code-review agents when the runtime exposes it.
- If Spark is unavailable, prefer the cheaper `gpt-5.4-mini` fallback.
- If neither model is exposed by the collaboration interface, use `gpt-5.6-terra` rather than the more expensive `gpt-5.6-sol`.
- Announce any fallback instead of silently substituting a different model.
- Keep Standards and Spec reviews independent, following the `code-review` skill.
