#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

if [[ $# -ne 1 || -z $1 ]]; then
  printf '%s\n' 'usage: package-reference-evaluator.sh OUTPUT_DIRECTORY' >&2
  exit 2
fi

output_directory=$1
output_parent=$(dirname -- "${output_directory}")
if [[ -e ${output_directory} || -L ${output_directory} ]]; then
  printf '%s\n' 'evaluator package output must not already exist' >&2
  exit 2
fi
if [[ ! -d ${output_parent} || -L ${output_parent} ]]; then
  printf '%s\n' 'evaluator package output parent must be a trusted directory' >&2
  exit 2
fi

for command in b3sum cargo git gzip jq rustc; do
  command -v "${command}" >/dev/null || {
    printf 'required packaging command is unavailable: %s\n' "${command}" >&2
    exit 2
  }
done

if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  printf '%s\n' 'evaluator packages must be built from a clean source tree' >&2
  exit 2
fi

work_directory=$(mktemp -d)
cleanup() {
  rm -rf -- "${work_directory}"
}
trap cleanup EXIT

package_directory=${work_directory}/reference-evaluator
mkdir -p -- "${package_directory}/bin" "${package_directory}/source"

target_directory=${work_directory}/target
CARGO_TARGET_DIR=${target_directory} cargo build \
  --locked \
  --release \
  --package pos-reference \
  --bin pos-reference-evaluator
install -m 0755 -- \
  "${target_directory}/release/pos-reference-evaluator" \
  "${package_directory}/bin/pos-reference-evaluator"

git archive --format=tar HEAD | gzip -n >"${package_directory}/source/pigloros-source.tar.gz"
install -m 0644 -- Cargo.lock "${package_directory}/Cargo.lock"

metadata=${work_directory}/cargo-metadata.json
target=$(rustc -vV | sed -n 's/^host: //p')
cargo metadata --format-version 1 --locked --filter-platform "${target}" >"${metadata}"

jq --sort-keys '
  (.packages | map({ key: .id, value: . }) | from_entries) as $packages
  | (.resolve.nodes | map({
      key: .id,
      value: [.deps[] | select(any(.dep_kinds[]; .kind != "dev")) | .pkg]
    }) | from_entries) as $edges
  | ($packages | to_entries[] | select(.value.name == "pos-reference") | .key) as $root
  | def closure($id): [$id] + [($edges[$id] // [])[] | closure(.)[]];
    (closure($root) | unique) as $ids
  | {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      version: 1,
      metadata: {
        component: {
          type: "application",
          "bom-ref": $root,
          name: $packages[$root].name,
          version: $packages[$root].version
        }
      },
      components: [
        $ids[] as $id
        | $packages[$id]
        | {
            type: (if .source == null then "application" else "library" end),
            "bom-ref": .id,
            name: .name,
            version: .version,
            licenses: (if .license == null then [] else [{ expression: .license }] end)
          }
      ] | sort_by(.name, .version, ."bom-ref"),
      dependencies: [
        $ids[] as $id
        | {
            ref: $id,
            dependsOn: [($edges[$id] // [])[] | select(. as $dependency | $ids | index($dependency))]
              | sort
          }
      ] | sort_by(.ref)
    }
' "${metadata}" >"${package_directory}/sbom.cdx.json"

jq --sort-keys '
  (.packages | map({ key: .id, value: . }) | from_entries) as $packages
  | (.resolve.nodes | map({
      key: .id,
      value: [.deps[] | select(any(.dep_kinds[]; .kind != "dev")) | .pkg]
    }) | from_entries) as $edges
  | ($packages | to_entries[] | select(.value.name == "pos-reference") | .key) as $root
  | def closure($id): [$id] + [($edges[$id] // [])[] | closure(.)[]];
    (closure($root) | unique) as $ids
  | {
      schema: "PiglorOS.EvaluatorLicences.v1",
      packages: [
        $ids[] as $id
        | $packages[$id]
        | { name: .name, version: .version, licence_expression: .license }
      ] | sort_by(.name, .version)
    }
' "${metadata}" >"${package_directory}/licences.json"

source_digest=$(b3sum "${package_directory}/source/pigloros-source.tar.gz" | cut -d ' ' -f 1)
binary_digest=$(b3sum "${package_directory}/bin/pos-reference-evaluator" | cut -d ' ' -f 1)
lock_digest=$(b3sum "${package_directory}/Cargo.lock" | cut -d ' ' -f 1)
sbom_digest=$(b3sum "${package_directory}/sbom.cdx.json" | cut -d ' ' -f 1)
licences_digest=$(b3sum "${package_directory}/licences.json" | cut -d ' ' -f 1)
commit=$(git rev-parse HEAD)
toolchain=$(rustc --version)

jq -n --sort-keys \
  --arg commit "${commit}" \
  --arg target "${target}" \
  --arg toolchain "${toolchain}" \
  --arg source_digest "${source_digest}" \
  --arg binary_digest "${binary_digest}" \
  --arg lock_digest "${lock_digest}" \
  --arg sbom_digest "${sbom_digest}" \
  --arg licences_digest "${licences_digest}" \
  '{
    schema: "PiglorOS.EvaluatorBuildProvenance.v1",
    source_commit: $commit,
    build_target: $target,
    rust_toolchain: $toolchain,
    cargo_locked: true,
    evaluator_source_blake3: $source_digest,
    evaluator_binary_blake3: $binary_digest,
    dependency_lock_blake3: $lock_digest,
    sbom_blake3: $sbom_digest,
    licences_blake3: $licences_digest
  }' >"${package_directory}/provenance.json"

(
  cd -- "${package_directory}"
  find . -type f ! -name BLAKE3SUMS -print0 \
    | sort -z \
    | xargs -0 b3sum >BLAKE3SUMS
  b3sum --check BLAKE3SUMS
)

mv -- "${package_directory}" "${output_directory}"
trap - EXIT
rm -rf -- "${work_directory}"
