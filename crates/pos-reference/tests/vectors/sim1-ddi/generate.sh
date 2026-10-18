#!/usr/bin/env bash
# Produce one SIM1 DDI fixture with systemd-repart's offline signing workflow.
#
# Usage: generate.sh <x86-64|arm64> <output-directory>
#
# Run inside the pinned tool shell recorded in README.md. The script follows
# systemd-repart(8) example "Generate a dm-verity signature offline and append
# it to a pre-built image": the image is built with the signature partition
# deferred, the exact root hash is signed separately with OpenSSL, and the
# signature is joined afterwards. The private key exists only in a private
# temporary directory and is deleted on exit; it is never a release key.
set -euo pipefail

architecture=$1
output=$2
case "${architecture}" in
x86-64 | arm64) ;;
*)
	echo "unsupported architecture: ${architecture}" >&2
	exit 2
	;;
esac

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "${output}"
output=$(cd "${output}" && pwd)
umask 077
work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT

mkdir -p "${work}/tree/usr/lib" "${work}/tree/usr/bin" "${work}/repart.d"
printf 'ID=pigloros-sim1-fixture\nVERSION_ID=1\n' >"${work}/tree/usr/lib/os-release"
printf '#!/bin/sh\nexit 0\n' >"${work}/tree/usr/bin/adapter"
chmod 0755 "${work}/tree/usr/bin/adapter"
# About 150 data blocks force a two-level verity tree; repetition keeps the
# compressed fixture small.
mkdir -p "${work}/tree/usr/share/pigloros"
python3 -I -c 'import sys; sys.stdout.write("PiglorOS SIM1 DDI fixture payload\n" * 17000)' \
	>"${work}/tree/usr/share/pigloros/payload.txt"

cat >"${work}/repart.d/10-root.conf" <<'EOF'
[Partition]
Type=root
Format=erofs
CopyFiles=/
Verity=data
VerityMatchKey=root
VerityDataBlockSizeBytes=4096
VerityHashBlockSizeBytes=4096
Minimize=best
EOF

cat >"${work}/repart.d/11-root-verity.conf" <<'EOF'
[Partition]
Type=root-verity
Verity=hash
VerityMatchKey=root
VerityDataBlockSizeBytes=4096
VerityHashBlockSizeBytes=4096
Minimize=best
EOF

cat >"${work}/repart.d/12-root-verity-sig.conf" <<'EOF'
[Partition]
Type=root-verity-sig
Verity=signature
VerityMatchKey=root
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
	-keyout "${work}/key.pem" -out "${work}/certificate.pem" \
	-subj "/CN=PiglorOS SIM1 DDI fixture ${architecture}" \
	-set_serial 30 -days 3650 -sha256 \
	-addext 'basicConstraints=critical,CA:FALSE' \
	-addext 'keyUsage=critical,digitalSignature' \
	-addext 'extendedKeyUsage=codeSigning'

seed=6f1c5d2a-8b7e-4c19-9a3d-2e5f7b8c9d01
export SOURCE_DATE_EPOCH=0

systemd-repart --offline=yes --architecture="${architecture}" --seed="${seed}" \
	--definitions="${work}/repart.d" \
	--defer-partitions=root-verity-sig \
	--copy-source="${work}/tree" \
	--empty=create --size=auto --dry-run=no \
	--json=short \
	"${work}/image.raw" >"${work}/plan.json"

# The man page uses jq --raw-output0, which appends a NUL byte. ADR-087 signs
# exactly the 64 lowercase hexadecimal bytes, so emit them without a separator.
jq --join-output '
  [.[] | .roothash? | select(type == "string" and test("^[0-9a-f]{64}$"))]
  | unique
  | if length == 1 then .[0] else error("expected exactly one root hash") end
' "${work}/plan.json" >"${output}/root-hash.txt"
test "$(wc -c <"${output}/root-hash.txt")" -eq 64

openssl smime -sign -in "${output}/root-hash.txt" \
	-inkey "${work}/key.pem" -signer "${work}/certificate.pem" \
	-md sha256 -noattr -binary -outform der \
	-out "${output}/proof.der"

systemd-repart --offline=yes --architecture="${architecture}" --seed="${seed}" \
	--definitions="${work}/repart.d" \
	--dry-run=no \
	--join-signature="$(cat "${output}/root-hash.txt"):${output}/proof.der" \
	--certificate="${work}/certificate.pem" \
	--json=short \
	"${work}/image.raw" >"${output}/repart.json"

openssl x509 -in "${work}/certificate.pem" -outform DER -out "${output}/signer.der"
python3 -I "${here}/describe.py" "${architecture}" "${work}/image.raw" "${output}"
gzip -9 -n -c "${work}/image.raw" >"${output}/image.raw.gz"
{
	systemd-repart --version | head -n 1
	mkfs.erofs --version 2>&1 | head -n 1
	openssl version
} >"${output}/tools.txt"
