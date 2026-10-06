#!/usr/bin/env bash
# Install the pinned Component guest toolchains into one directory.
#
# Every archive is fetched from its upstream GitHub release and checked against
# a pinned SHA-256 digest before it is unpacked. Bump a pin by updating both its
# URL and its digest in one reviewed change.
#
# Usage: install-tools.sh TOOLS_DIR
set -euo pipefail

tools_dir="${1:?usage: install-tools.sh TOOLS_DIR}"
mkdir -p -- "${tools_dir}"
tools_dir="$(cd -- "${tools_dir}" && pwd)"

fetch() {
  local name="$1" url="$2" digest="$3"
  local archive="${tools_dir}/${name}.tar.gz"
  curl --fail --location --silent --show-error --retry 3 --max-time 300 \
    --output "${archive}" "${url}"
  printf '%s  %s\n' "${digest}" "${archive}" | sha256sum --check --strict -
  mkdir -p -- "${tools_dir}/${name}"
  tar --extract --gzip --file "${archive}" --strip-components 1 \
    --directory "${tools_dir}/${name}"
  rm -f -- "${archive}"
}

fetch wasm-tools \
  https://github.com/bytecodealliance/wasm-tools/releases/download/v1.258.3/wasm-tools-1.258.3-x86_64-linux.tar.gz \
  99b486a9ddc19af0260cd5f98f3b709a60817a3acd20efc9c582d719caebbf6d
fetch wit-bindgen \
  https://github.com/bytecodealliance/wit-bindgen/releases/download/v0.61.1/wit-bindgen-0.61.1-x86_64-linux.tar.gz \
  1aea51f8379e36e76081c08fcc5faada928c03a6d0965a55132d72c8d966463c
fetch wasi-sdk \
  https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz \
  b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4

"${tools_dir}/wasm-tools/wasm-tools" --version
"${tools_dir}/wit-bindgen/wit-bindgen" --version
"${tools_dir}/wasi-sdk/bin/clang" --version | head -n 1
