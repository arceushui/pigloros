#!/usr/bin/env bash
set -euo pipefail

# The fixture adapter of the gateway-client-conformance provider 2.0.0 (#1295). It validates the
# provider declaration and renders the payload, oracle and evidence-status record of one family
# by calling the fixture generator, which is their only writer. The provider declares no
# auxiliary member: every request of a sub-case is in its payload.

command_name="$1"
provider_manifest="$2"
family_contract="$3"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
generator="${script_dir}/../generate_gateway_conformance_fixtures.py"

validate_provider() {
  local fixture_root="${provider_manifest%/providers/*}"
  jq -e --slurpfile families "${family_contract}" '
    ([$families[0].families[].name]) as $names |
    .fixture_adapter == {id: "gateway-http-v1", config: {}} and
    .provider_id == "pigloros.fixture.gateway-client-conformance" and
    .contract_version == "2.0.0" and .abi_major == 1 and .abi_minor == 0 and
    .claim_layer == "gateway-client-conformance" and
    .subject_adapter == "public-gateway-protocol" and
    .artifact_media_types == {
      schema: "application/schema+json",
      payload: "application/json",
      oracle: "application/json",
      evidence_status: "application/json"
    } and
    (.schemas | keys | sort) == ($names | sort) and
    (.auxiliary | keys | sort) == ($names | sort) and
    all(.auxiliary[]; . == []) and
    all(.fixture_contracts[]; .network_allowed == false)
  ' "${provider_manifest}" >/dev/null
  while IFS= read -r schema; do
    jq -e '.properties.schema.const == "pigloros.gateway-client-conformance.case.v2"' \
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
    oracle_kind="$(jq -er --arg family "${family}" '.families[] | select(.name == $family) | .oracle.kind' "${family_contract}")"
    code_id="$(jq -r --arg family "${family}" '.families[] | select(.name == $family) | .oracle.code_id // ""' "${family_contract}")"
    python3 "${generator}" render \
      --family "${family}" --case-id "${case_id}" \
      --provider-id "$(jq -er '.provider_id' "${provider_manifest}")" \
      --contract-version "$(jq -er '.contract_version' "${provider_manifest}")" \
      --oracle-kind "${oracle_kind}" --code-id "${code_id}" \
      --payload-out "${input_path}" --oracle-out "${oracle_path}" \
      --evidence-out "${evidence_path}"
    ;;
  *)
    echo "usage: $0 validate|render PROVIDER FAMILY_CONTRACT [...]" >&2
    exit 2
    ;;
esac
