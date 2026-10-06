#!/usr/bin/env bash
# Build the ADR-061 revision 4 compatibility Components from source.
#
# Requires the tools from install-tools.sh in PROTOTYPE_TOOLS, plus rustup with
# network access for the pinned Rust toolchain. Writes the Components and their
# SHA256SUMS to OUT_DIR. The build is reproducible: verify-fixtures.sh compares
# a fresh build with the committed fixtures byte for byte.
#
# Usage: PROTOTYPE_TOOLS=DIR build-fixtures.sh OUT_DIR
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "${here}/../../../.." && pwd)"
tools="${PROTOTYPE_TOOLS:?set PROTOTYPE_TOOLS to the install-tools.sh directory}"
out_dir="${1:?usage: build-fixtures.sh OUT_DIR}"
mkdir -p -- "${out_dir}"
out_dir="$(cd -- "${out_dir}" && pwd)"

wasm_tools="${tools}/wasm-tools/wasm-tools"
wit_bindgen="${tools}/wit-bindgen/wit-bindgen"
clang="${tools}/wasi-sdk/bin/clang"

work="$(mktemp -d)"
trap 'rm -rf -- "${work}"' EXIT

# Bindings come straight from the canonical WIT package, which is
# byte-identical to the ADR-061 "Versioned WIT world" block.
wit_dir="${repo}/plugins/community/wit"

# Rust guest: wasm32-unknown-unknown has no WASI, so the core module can import
# only what the bindings declare.
cp -R -- "${here}/rust-guest" "${work}/rust-guest"
mkdir -p -- "${work}/rust-guest/generated"
"${wit_bindgen}" rust --world community-plugin \
  --out-dir "${work}/rust-guest/generated" "${wit_dir}"
cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
(
  cd -- "${work}/rust-guest"
  RUSTFLAGS="--remap-path-prefix=${work}=/build --remap-path-prefix=${cargo_home}=/cargo" \
    cargo build --locked --release --target wasm32-unknown-unknown \
    --target-dir "${work}/rust-target"
)
"${wasm_tools}" component new \
  "${work}/rust-target/wasm32-unknown-unknown/release/pigloros_compatibility_prototype.wasm" \
  --output "${out_dir}/rust-guest.wasm"

# C guest: wasi-sdk's libc supplies malloc and memcpy only. `component new` has
# no WASI adapter, so any remaining WASI import fails the build.
mkdir -p -- "${work}/c-guest"
"${wit_bindgen}" c --world community-plugin \
  --out-dir "${work}/c-guest" "${wit_dir}"
c_flags=(
  --target=wasm32-wasip1 -O2 -std=c11
  "-ffile-prefix-map=${work}=/build" "-ffile-prefix-map=${here}=/src"
)
"${clang}" "${c_flags[@]}" -Wall -Wextra -Werror -I "${work}/c-guest" \
  -c "${here}/c-guest/guest.c" -o "${work}/c-guest/guest.o"
"${clang}" "${c_flags[@]}" -I "${work}/c-guest" \
  -c "${work}/c-guest/community_plugin.c" -o "${work}/c-guest/bindings.o"
"${clang}" --target=wasm32-wasip1 -mexec-model=reactor -O2 \
  "${work}/c-guest/guest.o" "${work}/c-guest/bindings.o" \
  "${work}/c-guest/community_plugin_component_type.o" \
  -o "${work}/c-guest/c-guest.core.wasm"
"${wasm_tools}" component new "${work}/c-guest/c-guest.core.wasm" \
  --output "${out_dir}/c-guest.wasm"

# Negative variants written directly in the Component text format.
for source in "${here}"/variants/*.wat; do
  name="$(basename -- "${source}" .wat)"
  "${wasm_tools}" parse "${source}" --output "${out_dir}/${name}.wasm"
done

# Both guests must import exactly the world's imports: host-v1 and the
# types-only contract-v1 interface that the world's `use` statements elaborate.
expected_imports="import pigloros:plugin/contract-v1@0.1.0;
import pigloros:plugin/host-v1@0.1.0;"
for guest in rust-guest c-guest; do
  imports="$("${wasm_tools}" component wit "${out_dir}/${guest}.wasm" |
    grep -E '^\s*import ' | sed -E 's/^\s+//' | sort)"
  if [[ "${imports}" != "${expected_imports}" ]]; then
    printf '%s imports differ from the world:\n%s\n' "${guest}" "${imports}" >&2
    exit 1
  fi
done

(
  cd -- "${out_dir}"
  sha256sum -- *.wasm >SHA256SUMS
)
