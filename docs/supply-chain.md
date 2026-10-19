# Supply-chain pinning

External GitHub Actions, Docker Actions, and Docker base images are pinned to
immutable revisions. The repository syntactically enforces these reference
forms with:

```bash
bash scripts/check-pinned-dependencies.sh
bash scripts/test-check-pinned-dependencies.sh
```

The `pinned-dependencies` CI job runs the first command on every pull request
and push. The second command is run locally and in CI to verify that the guard
rejects floating, multiline, and malformed Action and image references. The
offline checker validates reference syntax; it cannot prove that a 40-hex
Action revision exists or is a commit in the upstream repository.

Workflow and Action metadata is safely parsed with PyYAML, then every mapping
and sequence is traversed for semantic `uses` keys. This includes compact/flow
maps, explicit or folded keys, tagged scalars, escaped key text, and anchor
aliases. Duplicate mapping keys, unsafe tags, non-mapping documents, collection
alias cycles, and non-string `uses` values fail closed. A local `./path`
reference must stay inside the repository and resolve to one of:

- a reusable workflow under `.github/workflows`;
- a directory containing exactly one `action.yml` or `action.yaml`.

Local Action metadata is checked recursively wherever it lives in the
repository. Missing metadata, ambiguous metadata, references outside the
repository, and local-reference cycles fail the policy check.

CI installs PyYAML 6.0.2 from
`requirements-pinned-dependencies.txt` using `--require-hashes` and binary-only
wheels under a commit-pinned Python setup Action and Python 3.12.11. The
requirement records the SHA-256 hashes for the CPython 3.10 and 3.12 Linux
x86-64 wheels. The checker also supports the repository host's distro-provided
PyYAML 5.4.1; other versions fail closed until their behavior and artifact
provenance are reviewed.

## Updating a pin intentionally

Use a reviewed dependency update rather than editing a tag in place.

1. Resolve the desired Action release. Prefer the dereferenced entry for an
   annotated tag, then validate that exactly one 40-hex revision was found:

   ```bash
   action_repository=https://github.com/OWNER/REPOSITORY.git
   action_version=VERSION
   action_refs=$(git ls-remote "$action_repository" \
     "refs/tags/$action_version" "refs/tags/$action_version^{}")
   action_sha=$(printf '%s\n' "$action_refs" | awk '$2 ~ /\^\{\}$/ { print $1 }')
   if [[ -z "$action_sha" ]]; then
     action_sha=$(printf '%s\n' "$action_refs" | awk '$2 !~ /\^\{\}$/ { print $1 }')
   fi
   [[ "$action_sha" =~ ^[0-9a-f]{40}$ ]] || {
     echo 'expected exactly one 40-hex Action revision' >&2
     exit 1
   }
   ```

   Replace the revision in the workflow or composite Action and retain/update
   its trailing release comment. Review the upstream tag and commit before
   accepting the update; the local syntax checker cannot do that remotely.

2. Resolve the desired Docker image to its multi-platform index digest:

   ```bash
   docker buildx imagetools inspect IMAGE:TAG
   ```

   Replace the `sha256:` digest while retaining the human-readable tag before
   `@`.

3. Run both policy commands above, then build and smoke-test the image:

   ```bash
   docker build --tag pigloros-gateway:pin-check .
   docker run --rm -d -p 18080:8080 --name pigloros-pin-check pigloros-gateway:pin-check
   curl -fsS http://localhost:18080/health
   docker stop pigloros-pin-check
   ```

4. Include the upstream release or digest source in the pull request review.

Cargo builds in `Dockerfile` use `--locked`, so the image build fails if
`Cargo.lock` does not resolve the workspace dependencies.

## Third-party notice bundle

Binary distributions must carry the upstream licence texts and notices of
everything they link (#545, from the #539 licence review). The reusable
workflow `.github/workflows/third-party-notices.yml` generates them as the
`third-party-notices` artifact: `THIRD-PARTY-NOTICES.txt` plus the
`third-party-notices.json` index. CI calls it on every Rust-affecting change,
and `preflight-gate` requires it to pass.

The bundle covers:

- **Workspace crates.** The non-dev dependency graph of every workspace
  binary on `x86_64-unknown-linux-gnu`, from `Cargo.lock`. This includes
  the Wasmtime tree that `pos-plugin-host` links. `cargo about generate
  --workspace --all-features` with `about.toml` scans the whole workspace,
  which is a superset of each binary's graph.
- **Guest crates.** The crates in each Rust guest fixture's own `Cargo.lock`
  under `plugins/community/examples`, on `wasm32-unknown-unknown`, using
  `third_party/about-guest.toml`.
- **Rust std's crates.io dependencies.** The Rust guests link `std`, which
  brings crates.io crates such as `dlmalloc` and `hashbrown`. The generator
  runs cargo-about on the toolchain's rust-src `library/std` for
  `wasm32-unknown-unknown`. It uses the features the Rust release builds std
  with, which are bootstrap's defaults `backtrace` and `panic-unwind`.
  Before that run, it checks that rust-src's `library/Cargo.lock` and
  `library/std/Cargo.toml` equal the files at the pinned Rust 1.97.1 commit.
  Every crate in that graph must also ship as a `wasm32-unknown-unknown`
  rlib in the sysroot. The sysroot's other wasm32 rlibs must equal the
  reviewed `other_rlibs` list in the manifest. For Rust 1.97.1 that list is
  `compiler_builtins`, which the Rust component covers, and crates that only
  `test` and `proc_macro` use, which the guests do not link. A toolchain bump
  that ships a new rlib fails until it is reviewed.
- **Non-Cargo fixture components.** The parts that the committed
  compatibility fixtures statically contain:
  - wasi-libc, including the CC0 dlmalloc, MIT musl and BSD-2-Clause
    cloudlibc parts;
  - the BLAKE3 C sources;
  - LLVM compiler-rt;
  - Rust core, alloc and compiler-builtins;
  - wit-bindgen 0.61.1, whose generated C bindings the C guest links.

  Their texts live in `third_party/notices/`. `manifest.toml` there records,
  for each text, the upstream repository, tag or submodule pin, commit, path
  and SHA-256. It also maps every committed fixture to the components and
  guest lockfiles it contains.

The generator is `cargo-about` 0.9.2, pinned exactly, plus
`scripts/third_party_notices.py`. The job fails when:

- a crate's licence is unknown or not accepted;
- a crate or component has no licence text;
- a committed text differs from its upstream file at the recorded commit;
- a tag or submodule no longer resolves to the recorded commit;
- a fixture or guest lockfile is not mapped;
- the `about.toml` or `about-guest.toml` accepted lists drift from the
  `deny.toml` allow list and its crate-scoped exceptions.

Never edit a notice text by hand. To bump a component, update its pin in
`install-tools.sh` or the guest toolchain, re-fetch every file from the new
upstream commit, and update the manifest in the same reviewed change.

**Release requirement.** No binary release workflow exists today: `deploy.yml`
publishes only the `piglor-gateway` image, which links neither
`pos-plugin-host` nor the fixtures. Any future workflow that releases
`pos-plugin-worker` (the only binary that links `pos-plugin-host`) or the
compatibility fixtures must:

1. call `third-party-notices.yml` as a required job;
2. ship the `third-party-notices` artifact from the same commit with the
   release.

Shipping notices in the gateway image is tracked separately in Redmine #798.
