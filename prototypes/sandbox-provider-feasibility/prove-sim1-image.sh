#!/usr/bin/env bash
# THROWAWAY PROTOTYPE: hosted ADR-069 feasibility evidence only.
set -euo pipefail

readonly evidence_dir=/tmp/pigloros-sim1-evidence
readonly work_dir=/tmp/pigloros-sim1-work
readonly image_path="$work_dir/sim1.raw"
readonly unit_name=pigloros-sim1-proof.service
readonly static_true=${STATIC_TRUE:?STATIC_TRUE must name the static adapter executable}

cleanup() {
  systemctl stop "$unit_name" >/dev/null 2>&1 || true
  systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

rm -rf "$evidence_dir" "$work_dir"
mkdir -p "$evidence_dir" "$work_dir/definitions" "$work_dir/tree/.pigloros" \
  "$work_dir/tree/usr/bin" "$work_dir/tree/usr/lib"

losetup --list --noheadings --output NAME,BACK-FILE | sort \
  >"$work_dir/loops-before.txt"
dmsetup ls --noheadings 2>/dev/null | sort >"$work_dir/mappers-before.txt" || true
findmnt --raw --noheadings --output SOURCE,TARGET | sort \
  >"$work_dir/mounts-before.txt"

cp "$static_true" "$work_dir/tree/usr/bin/sleep"
install -m 0755 "$static_true" \
  "$work_dir/tree/.pigloros/release-launcher"
printf 'ID=pigloros-sim1-proof\nVERSION_ID=1\n' \
  >"$work_dir/tree/usr/lib/os-release"

cat >"$work_dir/definitions/10-root.conf" <<'EOF'
[Partition]
Type=root
Format=erofs
Verity=data
VerityMatchKey=root
Minimize=guess
EOF

cat >"$work_dir/definitions/20-root-verity.conf" <<'EOF'
[Partition]
Type=root-verity
Verity=hash
VerityMatchKey=root
VerityDataBlockSizeBytes=4096
VerityHashBlockSizeBytes=4096
Minimize=best
EOF

cat >"$work_dir/definitions/30-root-verity-signature.conf" <<'EOF'
[Partition]
Type=root-verity-sig
Verity=signature
VerityMatchKey=root
EOF

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj /CN=PiglorOS-ADR-069-SIM1-Proof/ \
  -keyout "$work_dir/verity-key.pem" \
  -out "$work_dir/verity-certificate.pem" >/dev/null 2>&1

systemd-repart --definitions="$work_dir/definitions" \
  --defer-partitions=root-verity-sig \
  --copy-source="$work_dir/tree" \
  --empty=create --size=128M --json=short "$image_path" \
  >"$work_dir/repart-before-signature.json"

root_hash=$(jq -er 'map(select(.roothash != null)) | last | .roothash' \
  "$work_dir/repart-before-signature.json")
test "${#root_hash}" -eq 64
printf %s "$root_hash" >"$work_dir/sim1.roothash"

openssl smime -sign -binary -noattr -outform DER \
  -in "$work_dir/sim1.roothash" \
  -inkey "$work_dir/verity-key.pem" \
  -signer "$work_dir/verity-certificate.pem" \
  -out "$work_dir/sim1.roothash.p7s"

# This is the provider-owned fail-closed trust gate. systemd v260.2 may retry
# dm-verity activation without kernel signature verification, so successful
# RootHashSignature= activation is never treated as signer admission.
openssl smime -verify -binary -inform DER \
  -in "$work_dir/sim1.roothash.p7s" \
  -content "$work_dir/sim1.roothash" \
  -CAfile "$work_dir/verity-certificate.pem" \
  -purpose any -out /dev/null >/dev/null 2>&1

systemd-repart --definitions="$work_dir/definitions" --dry-run=no \
  --root="$work_dir/tree" \
  --join-signature="$root_hash:$work_dir/sim1.roothash.p7s" \
  --certificate="$work_dir/verity-certificate.pem" \
  --json=short "$image_path" >"$work_dir/repart-signed.json"

systemd-dissect --json=short "$image_path" >"$evidence_dir/dissect.json"
test "$(jq '[.[] | select(.designator == "root")] | length' \
  "$evidence_dir/dissect.json")" -eq 1
test "$(jq '[.[] | select(.designator == "root-verity")] | length' \
  "$evidence_dir/dissect.json")" -eq 1
test "$(jq '[.[] | select(.designator == "root-verity-sig")] | length' \
  "$evidence_dir/dissect.json")" -eq 1

image_digest=$(b3sum "$image_path" | cut -d' ' -f1)
certificate_fingerprint=$(openssl x509 -in "$work_dir/verity-certificate.pem" \
  -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :)
signature_digest=$(sha256sum "$work_dir/sim1.roothash.p7s" | cut -d' ' -f1)
adapter_digest=$(b3sum "$work_dir/tree/usr/bin/sleep" | cut -d' ' -f1)
launcher_placeholder_digest=$(b3sum \
  "$work_dir/tree/.pigloros/release-launcher" | cut -d' ' -f1)

systemd-run --unit="$unit_name" --property=Type=exec \
  --property="RootImage=$image_path" \
  --property="RootHash=$root_hash" \
  --property="RootHashSignature=$work_dir/sim1.roothash.p7s" \
  --property='RootImagePolicy=root=verity+signed+read-only-on:=absent' \
  --property=PrivateMounts=yes --property=DynamicUser=yes \
  /usr/bin/sleep 30

main_pid=$(systemctl show "$unit_name" --property=MainPID --value)
test "$main_pid" -gt 1
test "$(b3sum "/proc/$main_pid/exe" | cut -d' ' -f1)" = "$adapter_digest"
stat -Lc 'adapter_device=%d\nadapter_inode=%i' "/proc/$main_pid/exe" \
  >"$evidence_dir/adapter-runtime-identity.txt"
awk '$5 == "/" { print }' "/proc/$main_pid/mountinfo" \
  >"$evidence_dir/root-mountinfo.txt"
grep -Eq '(^|,)ro(,|$)' <(awk '{ print $6 }' \
  "$evidence_dir/root-mountinfo.txt")
dmsetup table --showkeys >"$evidence_dir/device-mapper-table.txt"
grep -F "$root_hash" "$evidence_dir/device-mapper-table.txt"

systemctl show "$unit_name" \
  --property=RootImage --property=RootHash --property=RootImagePolicy \
  --property=Result >"$evidence_dir/unit-readback.txt"
grep -Fx "RootImage=$image_path" "$evidence_dir/unit-readback.txt"
grep -Fx "RootHash=$root_hash" "$evidence_dir/unit-readback.txt"
grep -Fx 'RootImagePolicy=root=verity+signed+read-only-on:=absent' \
  "$evidence_dir/unit-readback.txt"
grep -Fx 'Result=success' "$evidence_dir/unit-readback.txt"
systemctl stop "$unit_name"
systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true

cp "$work_dir/repart-before-signature.json" "$evidence_dir/"
cp "$work_dir/repart-signed.json" "$evidence_dir/"
cp "$work_dir/sim1.roothash.p7s" "$evidence_dir/"
cp "$work_dir/verity-certificate.pem" "$evidence_dir/"
printf '%s\n' \
  "architecture=$(uname -m)" \
  "kernel=$(uname -r)" \
  "systemd=$(systemctl --version | head -1)" \
  "image_bytes=$(stat -c %s "$image_path")" \
  "image_blake3=$image_digest" \
  "root_hash_sha256=$root_hash" \
  "signature_sha256=$signature_digest" \
  "certificate_sha256=$certificate_fingerprint" \
  "adapter_blake3=$adapter_digest" \
  "launcher_placeholder_blake3=$launcher_placeholder_digest" \
  >"$evidence_dir/identity.txt"

# A changed root hash must fail activation and leave no unit behind.
invalid_root_hash="f${root_hash:1}"
if test "$invalid_root_hash" = "$root_hash"; then
  invalid_root_hash="e${root_hash:1}"
fi
if systemd-run --unit=pigloros-sim1-invalid-hash.service \
  --property=Type=exec --property="RootImage=$image_path" \
  --property="RootHash=$invalid_root_hash" \
  --property="RootHashSignature=$work_dir/sim1.roothash.p7s" \
  --property='RootImagePolicy=root=verity+signed+read-only-on:=absent' \
  --collect --wait /usr/bin/sleep 1 \
  >"$evidence_dir/invalid-hash.txt" 2>&1; then
  printf 'invalid root hash unexpectedly activated\n' >&2
  exit 1
fi
systemctl reset-failed pigloros-sim1-invalid-hash.service >/dev/null 2>&1 || true

# A changed signature is rejected by the provider gate before systemd sees it.
cp "$work_dir/sim1.roothash.p7s" "$work_dir/invalid-signature.p7s"
truncate -s -1 "$work_dir/invalid-signature.p7s"
if openssl smime -verify -binary -inform DER \
  -in "$work_dir/invalid-signature.p7s" \
  -content "$work_dir/sim1.roothash" \
  -CAfile "$work_dir/verity-certificate.pem" \
  -purpose any -out /dev/null \
  >"$evidence_dir/invalid-signature.txt" 2>&1; then
  printf 'invalid signature unexpectedly verified\n' >&2
  exit 1
fi
test "$(systemctl show pigloros-sim1-invalid-signature.service \
  --property=LoadState --value 2>/dev/null || true)" != loaded

udevadm settle
losetup --list --noheadings --output NAME,BACK-FILE | sort \
  >"$evidence_dir/loops-after.txt"
dmsetup ls --noheadings 2>/dev/null | sort \
  >"$evidence_dir/mappers-after.txt" || true
findmnt --raw --noheadings --output SOURCE,TARGET | sort \
  >"$evidence_dir/mounts-after.txt"
cmp "$work_dir/loops-before.txt" "$evidence_dir/loops-after.txt"
cmp "$work_dir/mappers-before.txt" "$evidence_dir/mappers-after.txt"
cmp "$work_dir/mounts-before.txt" "$evidence_dir/mounts-after.txt"
if losetup --list --noheadings --output BACK-FILE | grep -Fx "$image_path"; then
  printf 'residual loop device for SIM1 image\n' >&2
  exit 1
fi
if dmsetup ls --noheadings 2>/dev/null | grep -F pigloros; then
  printf 'residual device-mapper mapping\n' >&2
  exit 1
fi
if findmnt --raw --noheadings --output SOURCE,TARGET | grep -F "$image_path"; then
  printf 'residual SIM1 mount\n' >&2
  exit 1
fi

printf '%s\n' \
  'valid_signature=provider-verified' \
  'valid_image=activated-and-executed' \
  'invalid_root_hash=rejected' \
  'invalid_signature=rejected-before-unit' \
  'residual_unit=absent' \
  'residual_loop=absent' \
  'residual_device_mapper=absent' \
  'residual_mount=absent' \
  >"$evidence_dir/outcome.txt"

cat "$evidence_dir/identity.txt"
cat "$evidence_dir/outcome.txt"
