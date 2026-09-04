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

for command in b3sum cargo git gzip jq rustc rustup tar; do
  command -v "${command}" >/dev/null || {
    printf 'required packaging command is unavailable: %s\n' "${command}" >&2
    exit 2
  }
done

commit=$(git rev-parse --verify 'HEAD^{commit}')
if ! git diff --quiet "${commit}" -- || [[ -n $(git ls-files --others --exclude-standard) ]]; then
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

source_tar=${work_directory}/pigloros-source.tar
git archive --format=tar "${commit}" >"${source_tar}"
archived_commit=$(git get-tar-commit-id <"${source_tar}")
if [[ ${archived_commit} != "${commit}" ]]; then
  printf '%s\n' 'source archive commit identity does not match the selected commit' >&2
  exit 2
fi
gzip -n <"${source_tar}" >"${package_directory}/source/pigloros-source.tar.gz"
source_directory=${work_directory}/source-checkout
mkdir -p -- "${source_directory}"
tar -xzf "${package_directory}/source/pigloros-source.tar.gz" -C "${source_directory}"

pinned_rustc=$(env -u RUSTUP_TOOLCHAIN rustup which rustc)
pinned_cargo=$(env -u RUSTUP_TOOLCHAIN rustup which cargo)
if [[ ! -x ${pinned_rustc} || ! -x ${pinned_cargo} ]]; then
  printf '%s\n' 'selected Rust toolchain does not contain cargo and rustc executables' >&2
  exit 2
fi
toolchain_bin=$(dirname -- "${pinned_rustc}")
target=$(${pinned_rustc} -vV | sed -n 's/^host: //p')
if [[ -z ${target} ]]; then
  printf '%s\n' 'selected Rust compiler did not report a host target' >&2
  exit 2
fi
toolchain=$(${pinned_rustc} --version)

target_directory=${work_directory}/target
build_home=${work_directory}/build-home
cargo_home=${work_directory}/cargo-home
mkdir -p -- "${build_home}" "${cargo_home}"
(
  cd -- "${source_directory}"
  env -i \
    PATH="${toolchain_bin}:${PATH}" \
    HOME="${build_home}" \
    CARGO_HOME="${cargo_home}" \
    CARGO_TARGET_DIR="${target_directory}" \
    RUSTC="${pinned_rustc}" \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    "${pinned_cargo}" build \
    --locked \
    --release \
    --target "${target}" \
    --package pos-reference \
    --bin pos-reference-evaluator
)
install -m 0755 -- \
  "${target_directory}/${target}/release/pos-reference-evaluator" \
  "${package_directory}/bin/pos-reference-evaluator"

install -m 0644 -- "${source_directory}/Cargo.lock" "${package_directory}/Cargo.lock"

metadata=${work_directory}/cargo-metadata.json
(
  cd -- "${source_directory}"
  env -i \
    PATH="${toolchain_bin}:${PATH}" \
    HOME="${build_home}" \
    CARGO_HOME="${cargo_home}" \
    RUSTC="${pinned_rustc}" \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    "${pinned_cargo}" metadata \
    --format-version 1 \
    --locked \
    --filter-platform "${target}" >"${metadata}"
)

jq --sort-keys '
  .workspace_root as $workspace_root
  | (.packages | map({ key: .id, value: . }) | from_entries) as $packages
  | (.resolve.nodes | map({
      key: .id,
      value: [.deps[] | select(any(.dep_kinds[]; .kind != "dev")) | .pkg]
    }) | from_entries) as $edges
  | ($packages | to_entries[] | select(.value.name == "pos-reference") | .key) as $root
  | def closure($id): [$id] + [($edges[$id] // [])[] | closure(.)[]];
    (closure($root) | unique) as $ids
  | def stable_ref($package):
      ($workspace_root + "/") as $workspace_prefix
      | (if $package.source == null then
           if ($package.manifest_path | startswith($workspace_prefix)) then
             ($package.manifest_path | ltrimstr($workspace_prefix))
           else
             error("path package is outside the archived workspace: " + $package.name)
           end
         else
           null
         end) as $manifest
      | ({
          name: $package.name,
          version: $package.version,
          source: ($package.source // "path"),
          manifest: $manifest
        } | tojson | @base64)
      | "urn:pigloros:cargo:" + .;
    ([$ids[] as $id | { id: $id, ref: stable_ref($packages[$id]) }]) as $selected
  | if ($selected | group_by(.ref) | any(length != 1)) then
      error("stable Cargo package references are not unique")
    else
      .
    end
  | ($selected | map({ key: .id, value: .ref }) | from_entries) as $refs
  | {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      version: 1,
      metadata: {
        component: {
          type: "application",
          "bom-ref": $refs[$root],
          name: $packages[$root].name,
          version: $packages[$root].version
        }
      },
      components: [
        $ids[] as $id
        | $packages[$id]
        | {
            type: (if .source == null then "application" else "library" end),
            "bom-ref": $refs[$id],
            name: .name,
            version: .version,
            licenses: (if .license == null then [] else [{ expression: .license }] end)
          }
      ] | sort_by(.name, .version, ."bom-ref"),
      dependencies: [
        $ids[] as $id
        | {
            ref: $refs[$id],
            dependsOn: [($edges[$id] // [])[] | $refs[.]]
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

jq -cS -n \
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

jq -e \
  --arg source_digest "${source_digest}" \
  --arg binary_digest "${binary_digest}" \
  '.schema == "PiglorOS.EvaluatorBuildProvenance.v1"
    and .cargo_locked == true
    and .evaluator_source_blake3 == $source_digest
    and .evaluator_binary_blake3 == $binary_digest' \
  "${package_directory}/provenance.json" >/dev/null

(
  cd -- "${package_directory}"
  b3sum \
    Cargo.lock \
    bin/pos-reference-evaluator \
    licences.json \
    provenance.json \
    sbom.cdx.json \
    source/pigloros-source.tar.gz >BLAKE3SUMS
  b3sum --check BLAKE3SUMS
)

mv -- "${package_directory}" "${output_directory}"
trap - EXIT
rm -rf -- "${work_directory}"
