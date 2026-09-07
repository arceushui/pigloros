#!/usr/bin/env bash
# THROWAWAY PROTOTYPE: hosted ADR-069 feasibility evidence only.
set -euo pipefail

readonly evidence_dir=/tmp/pigloros-sim1-evidence
readonly work_dir=/tmp/pigloros-sim1-work
readonly image_path="$work_dir/sim1.raw"
readonly unit_name=pigloros-sim1-proof.service
readonly static_true=${STATIC_TRUE:?STATIC_TRUE must name the static adapter executable}
readonly static_prototype=${STATIC_PROTOTYPE:?STATIC_PROTOTYPE must name the static proof executable}

cleanup() {
  systemctl stop "$unit_name" >/dev/null 2>&1 || true
  systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
  rm -rf "$work_dir"
}
trap cleanup EXIT

rm -rf "$evidence_dir" "$work_dir"
mkdir -p "$evidence_dir" "$work_dir/definitions" "$work_dir/tree/.pigloros" \
  "$work_dir/tree/dev" "$work_dir/tree/proc" "$work_dir/tree/run" \
  "$work_dir/tree/sys" "$work_dir/tree/tmp" "$work_dir/tree/usr/bin" \
  "$work_dir/tree/usr/lib"

losetup --list --noheadings --output NAME,BACK-FILE | sort \
  >"$work_dir/loops-before.txt"
dmsetup ls --noheadings 2>/dev/null | sort >"$work_dir/mappers-before.txt" || true
findmnt --raw --noheadings --output SOURCE,TARGET | sort \
  >"$work_dir/mounts-before.txt"

cp "$static_true" "$work_dir/tree/usr/bin/sleep"
install -m 0755 "$static_prototype" \
  "$work_dir/tree/usr/bin/sandbox-provider-feasibility"
install -m 0755 /dev/null "$work_dir/tree/.pigloros/release-launcher"
printf 'ID=pigloros-sim1-proof\nVERSION_ID=1\n' \
  >"$work_dir/tree/usr/lib/os-release"

cat >"$work_dir/definitions/10-root.conf" <<'EOF'
[Partition]
Type=root
Format=erofs
CopyFiles=/
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
sfdisk --json "$image_path" >"$evidence_dir/partition-table.json"
test "$(jq '.partitiontable.partitions | length' \
  "$evidence_dir/partition-table.json")" -eq 3
test "$(jq '[.[] | select(.file | endswith("10-root.conf"))] | length' \
  "$work_dir/repart-signed.json")" -eq 1
test "$(jq '[.[] | select(.file | endswith("20-root-verity.conf"))] | length' \
  "$work_dir/repart-signed.json")" -eq 1
test "$(jq '[.[] | select(.file | endswith("30-root-verity-signature.conf"))] | length' \
  "$work_dir/repart-signed.json")" -eq 1

image_digest=$(b3sum "$image_path" | cut -d' ' -f1)
certificate_fingerprint=$(openssl x509 -in "$work_dir/verity-certificate.pem" \
  -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :)
signature_digest=$(sha256sum "$work_dir/sim1.roothash.p7s" | cut -d' ' -f1)
adapter_digest=$(b3sum \
  "$work_dir/tree/usr/bin/sandbox-provider-feasibility" | cut -d' ' -f1)
launcher_digest=$(b3sum "$static_prototype" | cut -d' ' -f1)
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
systemctl stop "$unit_name" >/dev/null 2>&1 || true
systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true

# Exercise the integrated trusted launch barrier. This command independently
# repeats the provider-owned PKCS#7/TRS1 gate before its typed
# StartTransientUnit call, observes ReadyV1 while the adapter is blocked, then
# releases the held native ELF. The adapter proves that only its Local proxy
# survives as FD 3.
"$static_prototype" --release-barrier-proof \
  "--root-image=$image_path" \
  "--root-hash-file=$work_dir/sim1.roothash" \
  "--root-signature=$work_dir/sim1.roothash.p7s" \
  "--root-certificate=$work_dir/verity-certificate.pem" \
  "--certificate-fingerprint=$certificate_fingerprint" \
  | tee "$evidence_dir/release-barrier.txt"
grep -F 'release_barrier=typed-local-release-ok' \
  "$evidence_dir/release-barrier.txt"
grep -F 'fd3=proxy-only;fd4=closed-before-adapter' \
  "$evidence_dir/release-barrier.txt"

: >"$evidence_dir/release-barrier-negative.txt"
for barrier_case in malformed-release mismatched-release replayed-release \
  expired-release readback-mismatch cancellation provider-eof \
  missing-descriptor extra-descriptor reordered-descriptors \
  wrong-descriptor-name wrong-descriptor-type higher-descriptor; do
  "$static_prototype" --release-barrier-proof \
    "--barrier-case=$barrier_case" \
    "--root-image=$image_path" \
    "--root-hash-file=$work_dir/sim1.roothash" \
    "--root-signature=$work_dir/sim1.roothash.p7s" \
    "--root-certificate=$work_dir/verity-certificate.pem" \
    "--certificate-fingerprint=$certificate_fingerprint" \
    | tee -a "$evidence_dir/release-barrier-negative.txt"
done
test "$(grep -c '^release_barrier_negative=' \
  "$evidence_dir/release-barrier-negative.txt")" -eq 13
test "$(grep -c 'adapter=unexecuted;unit=terminated$' \
  "$evidence_dir/release-barrier-negative.txt")" -eq 13

: >"$evidence_dir/provider-death.txt"
"$static_prototype" --release-barrier-proof \
  --barrier-case=provider-death-hold \
  "--root-image=$image_path" \
  "--root-hash-file=$work_dir/sim1.roothash" \
  "--root-signature=$work_dir/sim1.roothash.p7s" \
  "--root-certificate=$work_dir/verity-certificate.pem" \
  "--certificate-fingerprint=$certificate_fingerprint" \
  >"$evidence_dir/provider-death.txt" 2>&1 &
provider_pid=$!
for _ in $(seq 1 100); do
  grep -q '^release_barrier_provider_ready;' \
    "$evidence_dir/provider-death.txt" && break
  sleep 0.05
done
grep -q '^release_barrier_provider_ready;.*adapter=unexecuted$' \
  "$evidence_dir/provider-death.txt"
provider_death_unit=$(sed -n \
  's/^release_barrier_provider_ready;unit=\([^;]*\);.*/\1/p' \
  "$evidence_dir/provider-death.txt")
test -n "$provider_death_unit"
kill -KILL "$provider_pid"
wait "$provider_pid" 2>/dev/null || true
for _ in $(seq 1 100); do
  provider_death_state=$(systemctl show "$provider_death_unit" \
    --property=ActiveState --value)
  case "$provider_death_state" in
    inactive|failed) break ;;
  esac
  sleep 0.05
done
test "$provider_death_state" = failed
test "$(systemctl show "$provider_death_unit" \
  --property=ExecMainStatus --value)" -ne 0
systemctl stop "$provider_death_unit" >/dev/null 2>&1 || true
systemctl reset-failed "$provider_death_unit" >/dev/null 2>&1 || true
printf '%s\n' \
  'provider_death=release-endpoint-closed' \
  'adapter=unexecuted' \
  'unit=terminated-and-cleaned' \
  >>"$evidence_dir/provider-death.txt"

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
  "launcher_blake3=$launcher_digest" \
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
systemctl list-units --all 'pigloros-release-*' --no-legend \
  >"$work_dir/release-units-before-invalid-signature.txt"
if "$static_prototype" --release-barrier-proof \
  "--root-image=$image_path" \
  "--root-hash-file=$work_dir/sim1.roothash" \
  "--root-signature=$work_dir/invalid-signature.p7s" \
  "--root-certificate=$work_dir/verity-certificate.pem" \
  "--certificate-fingerprint=$certificate_fingerprint" \
  >"$evidence_dir/provider-invalid-signature.txt" 2>&1; then
  printf 'provider accepted invalid signature\n' >&2
  exit 1
fi
grep -F 'PKCS#7 verification failed before StartTransientUnit' \
  "$evidence_dir/provider-invalid-signature.txt"
systemctl list-units --all 'pigloros-release-*' --no-legend \
  >"$work_dir/release-units-after-invalid-signature.txt"
cmp "$work_dir/release-units-before-invalid-signature.txt" \
  "$work_dir/release-units-after-invalid-signature.txt"

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
test -z "$(systemctl list-units --all 'pigloros-release-*' --no-legend)"

printf '%s\n' \
  'valid_signature=provider-verified' \
  'valid_image=activated-and-executed' \
  'release_barrier=ready-before-adapter-and-local-fd3' \
  'invalid_root_hash=rejected' \
  'invalid_signature=rejected-before-unit' \
  'residual_unit=absent' \
  'residual_loop=absent' \
  'residual_device_mapper=absent' \
  'residual_mount=absent' \
  >"$evidence_dir/outcome.txt"

cat "$evidence_dir/identity.txt"
cat "$evidence_dir/outcome.txt"
