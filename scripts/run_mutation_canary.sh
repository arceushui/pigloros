#!/usr/bin/env bash
set -euo pipefail

temporary_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
canary_root="$(mktemp -d "${temporary_root%/}/mutation-canary.XXXXXX")"
project="${canary_root}/project"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "${project}/src"

cat > "${project}/Cargo.toml" <<'EOF'
[package]
name = "mutation-gate-canary"
version = "0.1.0"
edition = "2024"
EOF

cat > "${project}/Cargo.lock" <<'EOF'
version = 4

[[package]]
name = "mutation-gate-canary"
version = "0.1.0"
EOF

cp "${script_directory}/../rust-toolchain.toml" "${project}/rust-toolchain.toml"

cat > "${project}/src/lib.rs" <<'EOF'
pub fn deliberately_weakened_canary() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::deliberately_weakened_canary;

    #[test]
    fn canary_assertion_starts_strong() {
        assert!(std::hint::black_box(deliberately_weakened_canary()));
    }
}
EOF

git -C "${project}" init --quiet
git -C "${project}" config user.name "Mutation Gate Canary"
git -C "${project}" config user.email "mutation-canary@localhost"
git -C "${project}" add Cargo.toml Cargo.lock rust-toolchain.toml src/lib.rs
git -C "${project}" commit --quiet -m "Add strong mutation canary assertion"

# Touch the function line so diff-scoped mutation testing selects it, then
# deliberately weaken the assertion so the false-return mutant survives.
python3 - "${project}/src/lib.rs" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
strong = "assert!(std::hint::black_box(deliberately_weakened_canary()));"
weak = "assert!(std::hint::black_box(deliberately_weakened_canary()) || true);"
if source.count(strong) != 1:
    raise SystemExit("canary's strong assertion was missing or duplicated")
source = source.replace(strong, weak, 1)
source = source.replace("    true\n", "    true // selected by the diff-scoped canary\n", 1)
path.write_text(source, encoding="utf-8")
PY

git -C "${project}" diff --no-ext-diff --unified=0 HEAD -- src/lib.rs \
  > "${canary_root}/changes.diff"
if [[ ! -s "${canary_root}/changes.diff" ]]; then
  echo "Canary fixture did not produce a diff."
  exit 1
fi

cd "${project}"
set +e
timeout --foreground 8m cargo mutants \
  --workspace \
  --all-features \
  --in-diff "${canary_root}/changes.diff" \
  --no-shuffle \
  --annotations=none \
  --baseline run \
  --jobs 1 \
  --timeout 90 \
  --build-timeout 240 \
  --cap-lints true \
  --cargo-arg=--locked \
  -- \
  -- \
  -Zunstable-options \
  --fail-fast \
  --include-ignored \
  --test-threads=4 \
  2>&1 | tee "${canary_root}/cargo-mutants.log"
pipeline_status=("${PIPESTATUS[@]}")
set -e

mutation_status="${pipeline_status[0]}"
tee_status="${pipeline_status[1]}"
if [[ "${tee_status}" -ne 0 ]]; then
  echo "tee failed while recording cargo-mutants output (status ${tee_status})." >&2
  exit "${tee_status}"
fi

if [[ "${mutation_status}" -ne 2 ]]; then
  echo "Expected cargo mutants to exit 2 for the deliberately missed canary; got ${mutation_status}."
  exit 1
fi

missed_file="${project}/mutants.out/missed.txt"
expected="replace deliberately_weakened_canary -> bool with false"
if [[ ! -s "${missed_file}" ]] || ! grep -Fq "${expected}" "${missed_file}"; then
  echo "The expected deliberately weakened-test mutant was not recorded as missed."
  cat "${missed_file}" 2>/dev/null || true
  exit 1
fi

grep -F "${expected}" "${missed_file}" | while IFS= read -r mutant; do
  printf 'MISSED (expected deliberately weakened-test canary): %s\n' "${mutant}"
done
