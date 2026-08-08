# Task 4 Report: WASM packaging and CI checks

## TDD

- RED command at parent `a7720b9`:

  ```text
  scripts/test-check-world-client-wasm.sh
  ```

  Result:

  ```text
  ERROR: missing executable /root/pigloros-ticket-115-3d-world-client/scripts/check-world-client-wasm.sh
  contract_test_exit=1
  ```

  At `a7720b9`, the same contract's workflow lookup found no `world-client-wasm` job and the script path was absent.
- GREEN command:

  ```text
  scripts/test-check-world-client-wasm.sh
  ```

  Output:

  ```text
  World-client WASM contract OK.
  ```

- Review fixes: workflow assertions now extract the `world-client-wasm` job block and validate all required settings plus 40-character action pins within that block; the packaging script uses the shared local target with a GitHub Actions override; README commands document that shared target; `wasm-pack`, Chrome for Testing, and ChromeDriver are version-pinned; the page exposes a loading/error status; and the contract test runs in both local `scripts/ci.sh` and the WASM job.

## Files

- Created `scripts/check-world-client-wasm.sh`.
- Created `scripts/test-check-world-client-wasm.sh` and made it a required local/CI contract gate.
- Added only the additive `world-client-wasm` job to `.github/workflows/ci.yml`.
- Added native and WASM commands to `README.md`.

## Exact packaging checks

The script runs these commands in order:

```text
cargo check -p piglor-world-client --target wasm32-unknown-unknown --locked --no-default-features
wasm-pack build apps/piglor-world-client --target web --release -- --locked
wasm-pack test --headless --chrome apps/piglor-world-client --locked --no-default-features --test wasm_parity
```

The CI job uses Rust 1.97.1, installs the `wasm32-unknown-unknown` target, `wasm-pack` 0.15.0, and Chrome for Testing 151.0.7922.47 plus matching ChromeDriver, and invokes the contract and packaging scripts. The existing jobs remain unchanged. The client manifest remains WebGL2-only and no browser HTTP or WebGPU selection was added.

## Checks run

- `scripts/test-check-world-client-wasm.sh` — passed: `World-client WASM contract OK.`
- `CARGO_TARGET_DIR=/root/pigloros/target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 bash scripts/check-world-client-wasm.sh` — passed end to end on the final tree: locked no-default-features WASM check; optimized full Bevy/WebGL2 package (46m 15s including `wasm-opt`); and pinned Chrome for Testing 151.0.7922.47 parity test (1/1). A bounded temporary 2 GiB swap protected the full-shell optimizer on the 7.6 GiB host and was fully disabled and removed afterward.
- `bash -n scripts/check-world-client-wasm.sh scripts/test-check-world-client-wasm.sh` — passed.
- `python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/ci.yml"))'` — passed: `ci.yml YAML OK`.
- `git diff --check` — passed.
- `CARGO_TARGET_DIR=/root/pigloros/target bash scripts/ci.sh` — not rerun after the final review edits; the prior capability-dropped run reached the existing gateway process-test restrictions and did not provide final-tree evidence.
- `CARGO_TARGET_DIR=/root/pigloros/target CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p piglor-world-client --all-features --locked -- --include-ignored` — passed on the final tree: 48 library tests, 2 binary tests, and 1 parity test. The public builder and native runner initialized Bevy through Mesa llvmpipe's Vulkan backend.
- `cargo clippy -p piglor-world-client --all-features --all-targets --locked -- -D warnings -W clippy::pedantic` — passed on the final tree.
- `cargo check -p piglor-world-client --all-features --locked` — passed on the final Rust source before the test-harness-only validation attempt.
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov -p piglor-world-client --all-features --locked --summary-only --fail-under-lines 99 --fail-under-regions 99 -- --include-ignored` — passed on the final post-review source tree with 51 tests, 99.61% lines, and 99.60% regions. The isolated coverage target was removed after recording the report, reclaiming 10.6 GiB.
- `CARGO_TARGET_DIR=/root/pigloros/target timeout --signal=TERM --kill-after=5s 10s xvfb-run -a env WGPU_BACKEND=vulkan /root/pigloros/target/release/piglor-world-client` — passed on the final post-review source tree: the exact optimized binary initialized Mesa llvmpipe/Vulkan, enabled GPU clustering and preprocessing, created the `piglor-world-client` Winit window, and remained alive until the expected timeout exit 124. The final incremental `mold -run cargo build ...` completed in 12m 51s while preserving the repository's LTO/codegen settings. A bounded temporary 4 GiB swap prevented the previously kernel-confirmed GNU-linker OOM and was fully disabled and removed after the smoke.

## Concerns and blockers

- The previous CTO review (`gpt-5.6-sol`) returned **REQUEST_CHANGES**: final-tree test/coverage/CI evidence was incomplete; the production window path was bypassed by the libtest-only Winit disable; and the browser loader needed to catch module-import failures. The loader now uses a dynamic import with a persistent hidden status plus WebGL2 preflight and global asynchronous error handlers; the final optimized production Winit/Vulkan path has passed under Xvfb; focused tests, strict Clippy, final post-review coverage, and the release smoke are green. The independent review's shadow-payload finding was addressed by using the canonical `SocietySignal`, `SocietyDimension`, `EVENT_TYPE_SIGNAL`, and `decode_signal` APIs; local `scripts/ci.sh` now invokes both the WASM contract and real packaging/browser gate. Full repository CI and fresh Sol approval remain open.
- Local `wasm-pack` 0.15.0, `wasm32-unknown-unknown`, Chrome for Testing 151.0.7922.47, and matching ChromeDriver are installed. Executable evidence exposed two accepted-command defects: browser flags must precede the variadic crate path, and building every default-feature test target drags the full Bevy shell into a parity-only browser test, causing kernel-confirmed OOM in both debug runner transformation and release integration-test LTO. The corrected command selects only `wasm_parity` with `--no-default-features`; the complete final script now passes the optimized full-shell package and real Chrome parity 1/1. Script, contract, design, plan, report, and canonical ADR v9 agree without changing product scope.
- The pinned-dependency checker initially found PyYAML 6.0.1; the repository-accepted 6.0.2 wheel was then installed from the local uv cache in an isolated temporary environment, and the checker passed.
- No Redmine MCP tool is exposed in this agent session. Authenticated Redmine REST access is healthy and journal #1640 was added to ticket #115; Notion journal synchronization also succeeded.
