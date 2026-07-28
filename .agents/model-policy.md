# Multi-agent Model Policy

- Use `gpt-5.6-terra` for implementation and execution agents.
- Prefer `gpt-5.3-codex` for independent code-review agents when the runtime exposes it.
- If `gpt-5.3-codex` is unavailable, use the strongest available coding-review model. In the current Codex runtime, use `gpt-5.6-sol`.
- Announce any fallback instead of silently substituting a different model.
- Keep Standards and Spec reviews independent, following the `code-review` skill.
