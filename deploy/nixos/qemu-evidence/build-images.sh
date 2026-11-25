# Builds the #444 part (b) SIM1 DDIs inside the Nix sandbox. Bash runs it
# with errexit, nounset and pipefail from the derivation's builder.
#
#   build-images.sh REPART_ARCHITECTURE OUT
#
# It follows systemd-repart(8)'s offline signing example, like
# crates/pos-reference/tests/vectors/sim1-ddi/generate.sh, with the public
# dev/test key pairs in deploy/nixos/dev-trust (owner decision D2): one
# EROFS root with dm-verity, signed by the key the evidence kernel trusts
# (positive), the same root signed by a key it does not trust (wrong-key),
# and the positive image with one byte of a file data block flipped after
# signing (tampered). Every input is fixed, so the images are reproducible.
#
# The root also holds the real static adapter as /adapter, byte for byte the
# ADAPTER file, which is copied to OUT/adapter. The staged SIM1 binds the
# digest of OUT/adapter.
#
# Environment: TRUSTED_KEY, TRUSTED_CERTIFICATE, UNTRUSTED_KEY and
# UNTRUSTED_CERTIFICATE name the PEM key pairs; ADAPTER names the executable.
set -euo pipefail

architecture="$1"
out="$2"
mkdir -p "${out}"
work="$(mktemp -d)"

# The readback file: 16 data blocks, each starting with its own marker line
# and padded with dots to 4096 bytes. The host checker derives the same
# bytes independently.
mkdir -p "${work}/tree/usr/lib" "${work}/tree/usr/share/pigloros" "${work}/repart.d"
printf 'ID=pigloros-444-evidence\nVERSION_ID=1\n' >"${work}/tree/usr/lib/os-release"
# Nothing in the image but the adapter may be needed to run it, so it must be a
# loadable static ELF executable of this architecture: a dynamic one has no
# loader inside the root, and a script or stub is not an ELF at all. The same
# rules, with the same size floor, are the host checker's (static_executable).
# This is a shell single-quoted block: it must not contain a single quote.
python3 -I -c '
import struct
import sys
path = sys.argv[2]
machine = {"x86-64": 62, "arm64": 183}[sys.argv[1]]
data = open(path, "rb").read()
if len(data) < 100_000 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1 or data[6] != 1:
    raise SystemExit(f"{path} is not a 64-bit little-endian ELF executable")
kind, found, version = struct.unpack_from("<HHI", data, 16)
if kind not in (2, 3) or found != machine or version != 1:
    raise SystemExit(f"{path} is not an executable for {sys.argv[1]}")
offset, = struct.unpack_from("<Q", data, 32)
size, count = struct.unpack_from("<HH", data, 54)
if size < 56 or offset + size * count > len(data):
    raise SystemExit(f"{path} has a malformed program header table")
segments = [struct.unpack_from("<IIQQQQQQ", data, offset + index * size) for index in range(count)]
loads = [segment for segment in segments if segment[0] == 1]
if not loads:
    raise SystemExit(f"{path} has no loadable segment")
if any(segment[0] == 3 for segment in segments):
    raise SystemExit(f"{path} is dynamically linked")
if any(segment[2] + segment[5] > len(data) for segment in loads):
    raise SystemExit(f"{path} is truncated: a loadable segment reaches beyond the file")
if any(segment[5] > segment[6] for segment in loads):
    raise SystemExit(f"{path} has a loadable segment whose file size exceeds its memory size")
entry, = struct.unpack_from("<Q", data, 24)
if not any(segment[1] & 1 and segment[3] <= entry < segment[3] + segment[6] for segment in loads):
    raise SystemExit(f"{path}: the entry point is in no executable loadable segment")
' "${architecture}" "${ADAPTER}"
cp -- "${ADAPTER}" "${out}/adapter"
chmod 0755 "${out}/adapter"
# The staged SIM1 names /adapter with the BLAKE3 of the bytes of OUT/adapter
# (StagedInstallation::stage_image), and activation reads it back through
# the mount. Any image the staged installation activates must carry it.
cp -- "${ADAPTER}" "${work}/tree/adapter"
chmod 0755 "${work}/tree/adapter"
python3 -I -c '
import sys
for index in range(16):
    marker = f"PiglorOS #444 readback block {index:04d}\n".encode()
    sys.stdout.buffer.write(marker + b"." * (4095 - len(marker)) + b"\n")
' >"${work}/tree/usr/share/pigloros/readback"

cat >"${work}/repart.d/10-root.conf" <<'EOF'
[Partition]
Type=root
Format=erofs
CopyFiles=/
# The Nix build sandbox's file systems have no user extended attributes.
AddValidateFS=no
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

seed=2f0d4c1a-6b3e-4f57-9a8c-1d2e3f405162
export SOURCE_DATE_EPOCH=0

systemd-repart --offline=yes --architecture="${architecture}" --seed="${seed}" \
  --definitions="${work}/repart.d" \
  --defer-partitions=root-verity-sig \
  --copy-source="${work}/tree" \
  --empty=create --size=auto --dry-run=no \
  --json=short \
  "${work}/unsigned.raw" >"${work}/plan.json"

# ADR-087 signs exactly the 64 lowercase hexadecimal root-hash bytes.
jq --join-output '
  [.[] | .roothash? | select(type == "string" and test("^[0-9a-f]{64}$"))]
  | unique
  | if length == 1 then .[0] else error("expected exactly one root hash") end
' "${work}/plan.json" >"${out}/root-hash.txt"
test "$(wc -c <"${out}/root-hash.txt")" -eq 64
root_hash="$(cat "${out}/root-hash.txt")"

# One signed image per key pair; the join writes the signature partition.
sign() { # NAME KEY CERTIFICATE
  openssl smime -sign -in "${out}/root-hash.txt" -inkey "$2" -signer "$3" \
    -md sha256 -noattr -binary -outform der -out "${work}/$1.p7s"
  cp "${work}/unsigned.raw" "${out}/$1.raw"
  systemd-repart --offline=yes --architecture="${architecture}" --seed="${seed}" \
    --definitions="${work}/repart.d" \
    --dry-run=no \
    --join-signature="${root_hash}:${work}/$1.p7s" \
    --certificate="$3" \
    --json=short \
    "${out}/$1.raw" >/dev/null
  openssl x509 -in "$3" -outform DER -out "${out}/$1.der"
  # The kernel key description (ADR-087 Part C.2): subject CN, then the
  # lowercase subjectKeyIdentifier hex.
  printf '%s: %s' \
    "$(openssl x509 -in "$3" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= //p')" \
    "$(openssl x509 -in "$3" -noout -ext subjectKeyIdentifier | tail -n 1 | tr -d ' :' | tr 'A-F' 'a-f')" \
    >"${out}/$1.description"
}
sign positive "${TRUSTED_KEY}" "${TRUSTED_CERTIFICATE}"
sign wrong-key "${UNTRUSTED_KEY}" "${UNTRUSTED_CERTIFICATE}"
cp "${UNTRUSTED_CERTIFICATE}" "${out}/wrong-key.crt"

# Flip one byte inside readback block 7 of the signed positive image. The
# marker must occur exactly once in the image, inside the root partition.
cp "${out}/positive.raw" "${out}/tampered.raw"
python3 -I -c '
import sys
path = sys.argv[1]
image = bytearray(open(path, "rb").read())
marker = b"PiglorOS #444 readback block 0007\n"
offset = image.find(marker)
if offset < 0 or image.find(marker, offset + 1) >= 0:
    raise SystemExit("the block 7 marker must occur exactly once")
image[offset + 100] ^= 0x01
open(path, "wb").write(image)
print(offset + 100)
' "${out}/tampered.raw" >"${out}/tampered-offset"
cp "${out}/positive.der" "${out}/tampered.der"
cp "${out}/positive.description" "${out}/tampered.description"
