#!/usr/bin/env bash
set -euo pipefail

# The fixture adapter of the replay-conformance provider (ADR-062 Revision 8 slice R4, #1222).
# It validates the provider declaration and renders the payload, oracle, evidence-status record
# and `RCS1` composite of one family by calling the fixture generator, which is their only
# writer. The composite carries the closure members (exported Timelines, recomputation subjects
# and licences) of the family's sub-cases and is written to the auxiliary path the provider
# declares, under the root of the generated tree (the parent of `inputs/`). Provider contract
# 1.0.0 has no reader: any other contract version fails validation.

command_name="$1"
provider_manifest="$2"
family_contract="$3"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
generator="${script_dir}/../generate_replay_conformance_fixtures.py"

validate_provider() {
  local fixture_root="${provider_manifest%/providers/*}"
  jq -e --slurpfile families "${family_contract}" '
    ([$families[0].families[].name]) as $names | . as $provider |
    .fixture_adapter == {id: "replay-cbor-v1", config: {}} and
    .provider_id == "pigloros.fixture.replay-conformance" and
    .contract_version == "2.0.0" and .abi_major == 1 and .abi_minor == 0 and
    .claim_layer == "replay-conformance" and
    .subject_adapter == "exported-artifact" and
    .artifact_media_types == {
      schema: "application/schema+json",
      payload: "application/json",
      oracle: "application/json",
      evidence_status: "application/json"
    } and
    (.schemas | keys | sort) == ($names | sort) and
    (.auxiliary | keys | sort) == ($names | sort) and
    all($names[]; . as $name |
      $provider.auxiliary[$name] == [{
        path: ("inputs/replay-conformance/" + $name + ".rcs1"),
        media_type: "application/vnd.pigloros.replay-cases.v1+cbor"
      }])
  ' "${provider_manifest}" >/dev/null
  while IFS= read -r schema; do
    jq -e '.properties.schema.const == "pigloros.replay-conformance.case.v2"' \
      "${fixture_root}/${schema}" >/dev/null
  done < <(jq -r '.schemas[]' "${provider_manifest}")
}

case "${command_name}" in
  validate)
    validate_provider
    ;;
  render)
    validate_provider
    case_id="$4"
    family="$6"
    input_path="$8"
    oracle_path="$9"
    evidence_path="${10}"
    generated_root="${input_path%/inputs/*}"
    composite_path="${generated_root}/$(jq -er --arg family "${family}" '.auxiliary[$family][0].path' "${provider_manifest}")"
    oracle_kind="$(jq -er --arg family "${family}" '.families[] | select(.name == $family) | .oracle.kind' "${family_contract}")"
    code_id="$(jq -r --arg family "${family}" '.families[] | select(.name == $family) | .oracle.code_id // ""' "${family_contract}")"
    mkdir -p -- "$(dirname "${composite_path}")"
    python3 "${generator}" render \
      --family "${family}" --case-id "${case_id}" \
      --provider-id "$(jq -er '.provider_id' "${provider_manifest}")" \
      --contract-version "$(jq -er '.contract_version' "${provider_manifest}")" \
      --oracle-kind "${oracle_kind}" --code-id "${code_id}" \
      --payload-out "${input_path}" --oracle-out "${oracle_path}" \
      --evidence-out "${evidence_path}" --composite-out "${composite_path}"
    ;;
  *)
    echo "usage: $0 validate|render PROVIDER FAMILY_CONTRACT [...]" >&2
    exit 2
    ;;
esac
