# Task 4 Report: WASM packaging and CI checks

## TDD

- RED: Added `scripts/test-check-world-client-wasm.sh` before the implementation. It failed because `scripts/check-world-client-wasm.sh` was missing.
- GREEN: Added the packaging script, CI job, and README commands. The contract test now passes with `World-client WASM contract OK.`

## Files

- Created `scripts/check-world-client-wasm.sh`.
- Created `scripts/test-check-world-client-wasm.sh`.
- Added only the additive `world-client-wasm` job to `.github/workflows/ci.yml`.
- Added native and WASM commands to `README.md`.

## Exact packaging checks

The script runs these commands in order:

```text
cargo check -p piglor-world-client --target wasm32-unknown-unknown --locked --no-default-features
wasm-pack build apps/piglor-world-client --target web --release -- --locked
wasm-pack test apps/piglor-world-client --headless --chrome -- --locked
```

The CI job uses Rust 1.97.1, installs the `wasm32-unknown-unknown` target and `wasm-pack`, installs stable Chrome plus ChromeDriver, and invokes the script. The existing jobs remain unchanged. The client manifest remains WebGL2-only and no browser HTTP or WebGPU selection was added.

## Checks run

- `scripts/test-check-world-client-wasm.sh` — passed.
- `bash -n scripts/check-world-client-wasm.sh scripts/test-check-world-client-wasm.sh` — passed.
- PyYAML parse of `.github/workflows/ci.yml` — passed.
- `git diff --check` — passed.

## Concerns and blockers

- Per the task instruction, no `cargo` check and no `wasm-pack` build/test were run.
- `bash scripts/check-pinned-dependencies.sh` was attempted but blocked by the environment's PyYAML 6.0.1; this repository checker accepts only 5.4.1 or 6.0.2.
- `actionlint` and `shellcheck` were unavailable.
- Redmine start-work journaling was blocked because `redmine.piglor.com` DNS did not resolve and no Redmine API key was available.
