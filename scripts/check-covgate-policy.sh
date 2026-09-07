#!/usr/bin/env bash
# Enforce the repository's pinned covgate policy and immutable configuration.
set -euo pipefail

base_ref=${1:?usage: check-covgate-policy.sh RESOLVED_BASE_REF}
root="$(git rev-parse --show-toplevel)"
expected=$'[[gates]]\nname = "new-rust-code"\nfail-under-lines = 99\nfail-under-regions = 99'

if ! command -v covgate >/dev/null 2>&1; then
  echo "ERROR: covgate 0.2.0 is required for the new-code coverage gate" >&2
  echo "Install it with: cargo install covgate --version 0.2.0 --locked" >&2
  exit 1
fi

if [[ "$(covgate --version 2>&1)" != "covgate 0.2.0" ]]; then
  echo "ERROR: covgate 0.2.0 is required for the new-code coverage gate" >&2
  covgate --version >&2 || true
  exit 1
fi

if [[ ! -f "${root}/covgate.toml" || "$(<"${root}/covgate.toml")" != "${expected}" ]]; then
  echo "ERROR: covgate.toml must define the immutable 99% line and region policy" >&2
  exit 1
fi

if git cat-file -e "${base_ref}:covgate.toml" 2>/dev/null \
  && ! git diff --quiet --no-ext-diff "${base_ref}" HEAD -- covgate.toml; then
  echo "ERROR: covgate.toml changed after the policy was established" >&2
  exit 1
fi
