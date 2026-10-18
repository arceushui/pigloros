# SIM1 DDI fixtures from systemd-repart offline signing

These test-only fixtures are externally generated candidates for
[Accepted ADR-087](https://redmine.piglor.com/projects/pigloros/wiki/ADR-087_Systemd_mountfsd_SIM1_activation_boundary)'s
#437 fixture acceptance. They cannot satisfy it yet: no valid SIM1 can
describe them (see the salt finding below). There is one Discoverable Disk
Image per supported architecture. Directories use systemd-repart's
`--architecture` names: `x86-64` is SIM1 `x86_64` and `arm64` is `aarch64`. Each
with an EROFS root, its dm-verity hash partition and a detached RSA-2048,
SHA-256, no-attributes PKCS#7 signature over the exact 64 lowercase
hexadecimal root-hash bytes. They were produced outside the Rust verifier by
[systemd-repart(8)](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html)'s
example "Generate a dm-verity signature offline and append it to a pre-built
image", followed by `generate.sh`.

The fixture keys are not release keys. Each private key existed only in a
private temporary directory on the generating runner and was deleted. No
certificate here is trusted by any host.

## Producer

`generate.sh <x86-64|arm64> <directory>` ran on GitHub-hosted `ubuntu-24.04`
(x86-64) and `ubuntu-24.04-arm` (arm64) runners in workflow run
[39120682232](https://github.com/arceushui/pigloros/actions/runs/39120682232)
from a temporary generation branch that is not part of this repository's
history. Both runners used only tools from nixpkgs commit
`26f4107e47e3ad0ffd0db220469ba83b6f6d96e8` (the `nixos-26.05` head at
generation time):

```sh
pin=github:NixOS/nixpkgs/26f4107e47e3ad0ffd0db220469ba83b6f6d96e8
nix --extra-experimental-features 'nix-command flakes' shell \
  "$pin#systemd" "$pin#erofs-utils" "$pin#openssl" "$pin#jq" "$pin#python3" "$pin#gzip" \
  --command bash generate.sh x86-64 x86-64
```

`tools.txt` records systemd 260.5, erofs-utils 1.9 and OpenSSL 3.6.5. The
systemd store paths were
`/nix/store/kmzlca218j6j1ar292fxj7707qzypij8-systemd-260.5` (x86-64) and
`/nix/store/jnsrd8c9vfdwv114xnkryg2ng2nsrcn0-systemd-260.5` (arm64). This is the
fixture producer only; it is not the reviewed appliance systemd build, whose
identity and source delta remain #444 evidence.

The workflow differs from the man-page example only where ADR-087 is stricter
or the example is incomplete:

- `jq --join-output` writes the root hash; the example's `--raw-output0`
  appends a NUL byte, which ADR-087 forbids in the signed content.
- `openssl smime -sign` adds the explicit `-md sha256` that ADR-087 requires.
- The root definition adds `CopyFiles=/`, without which `--copy-source` copies
  nothing, and both verity definitions pin 4096-byte data and hash blocks.
- Both `systemd-repart` invocations use `--offline=yes`, the same `--seed` and an
  explicit `--architecture`; the join step omits the example's `--root`.

Regeneration creates a new random key and new certificate dates, so it does
not reproduce the committed bytes. Update this README when replacing fixtures.

## Independent description

`describe.py` uses only the Python standard library. Before the image is
compressed it parses the GPT with `zlib.crc32`, requires exactly the three DPS
root partitions for the architecture, checks the EROFS superblock magic at
byte 1024 of the root partition, recomputes the dm-verity format-1 SHA-256
tree and requires its root to equal `root-hash.txt`, and requires the
`root-verity-sig` partition JSON to embed exactly `proof.der` and the SHA-256
fingerprint of `signer.der`. It writes `partitions.json` (canonical type UUID
bytes, instance UUID bytes, byte offset and byte length in root, verity,
signature order) and `verity.json`. `repart.json` is systemd-repart's own
final JSON output, including runner-local temporary paths.

Both images are 1,683,456 bytes with 142 verity data blocks, so the hash tree
has two levels. Certificates are self-signed serial 30 with critical
`CA:FALSE`, critical `digitalSignature` KU and `codeSigning` EKU, valid from
2026-10-18 through 2036-10-15. Certificate subjects are
`CN=PiglorOS SIM1 DDI fixture x86-64` and `CN=PiglorOS SIM1 DDI fixture arm64`.

The producer's actual CMS encodings, as ADR-087 requires them to be recorded:
SignedData v1 with one SHA-256 digest identifier, id-data with absent
eContent, one v1 issuer-and-serial SignerInfo, one certificate, and no CRLs or
signed/unsigned attributes. Every algorithm identifier carries an explicit
ASN.1 NULL parameter: SHA-256 (digest set and SignerInfo), `rsaEncryption`
(SignerInfo and SPKI) and `sha256WithRSAEncryption` (certificate). The
signatures are 256 bytes. The verifier's accepted webpki constant
(`RSA_PKCS1_2048_8192_SHA256`) verifies them in the public cases below.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `x86-64/image.raw.gz` | 6809 | `8f231112087613a538253d6a97795c9272c9159730ee030f0a9f1f7a98385f02` |
| `x86-64/partitions.json` | 400 | `9658b85335803101835abe3efc1b121fe352480d52c4a63ee99897155319fd55` |
| `x86-64/proof.der` | 1253 | `e88b7cb06dfc00b5ede3a1790849d99ca43a4cf46108fe2624878c2036027000` |
| `x86-64/signer.der` | 842 | `f48a0bea1049e25fd489d92a9db849b126874434fa0c6ccb234af21842accf74` |
| `x86-64/root-hash.txt` | 64 | `8d61e13433694f939a314791ec12e2dc714f0f16859c4304650c41586148e6e0` |
| `x86-64/repart.json` | 1301 | `775e5b8f57cbfdccd544676b3771837e16a82a2d3761a6af4c4a7bde0974d10f` |
| `x86-64/verity.json` | 298 | `8955e79533ba65725d19022f0f18b148a0506c2f952d10edff6a7269528f7fc1` |
| `x86-64/tools.txt` | 112 | `97ba9dc239890ce173e1a600f1b1a73e94409e12cbed98c2307b8dd2d7fd1806` |
| `arm64/image.raw.gz` | 6802 | `aad697a862e5ca5c68a2ae7e8644b1cd5475b15f0c38bc09edbee4bbe92aafd3` |
| `arm64/partitions.json` | 406 | `0f0b73a2206018debec655018137115c661ca877f22bffc2bc15ab79a138a1ff` |
| `arm64/proof.der` | 1250 | `9710bb3fbc0131c0eac57a6461f7fc09b2228586e4b870c79c43bbe25a8e0186` |
| `arm64/signer.der` | 840 | `dd530c4d3932d1bb17bbabdd06e186e0ca200c1cbdbb3e34c9bf7477bfdbde40` |
| `arm64/root-hash.txt` | 64 | `7a4ffd558f7d04d4023dd6f8b9a36e1b2e8857d9094a136a9e6736eff1fd5042` |
| `arm64/repart.json` | 1295 | `5256186a8365de4acd770a2dde55961afe0fa9eb19c94b887faabba2041247b4` |
| `arm64/verity.json` | 298 | `8e94ae6c83634a5fc50ef899fc8056b2bb9e66ecac74e87eec2c0f713847f417` |
| `arm64/tools.txt` | 112 | `97ba9dc239890ce173e1a600f1b1a73e94409e12cbed98c2307b8dd2d7fd1806` |

Gzip is storage compression only; `verity.json` records the SHA-256 of each
expanded image.

## Public cases

`sandbox_admission_contract_public` verifies each `proof.der` through
`AdmittedSandboxProvider::verify_image_proof` with independently signed
SIM1/APT1/TRS1/RVS1 test records pinning that `signer.der` and declaring that
root hash, at Unix second 1,800,000,000, and rejects each proof against the
other architecture's root hash (`InvalidSignature`) or signer pin
(`UnauthorizedSigner`). The `sim1-proof-risk` workflow runs these public cases
on a hosted aarch64 runner in addition to the x86-64 workspace gates.

A separate fixture-integrity case runs no production code: it checks that
the `root-verity-sig` partition, identified by its DPS type, embeds the same
proof, signer fingerprint and root hash that systemd will read.

## What these fixtures do not prove

- **No SIM1 for these images.** In the v260.2, v260.4 and `main` sources,
  systemd-repart always formats the verity hash partition with a 32-byte salt
  derived from `--seed` (`derive_salt` and `salt_size = sizeof(p->verity_salt)`
  in `src/repart/repart.c`). For the 260.5 producer used here, `verity.json`
  records the salt that `describe.py` read from each verity superblock. Accepted ADR-069 SIM1
  requires a zero-length salt, so no valid SIM1 can describe these images and
  an exact dm-verity table readback against SIM1 could not match them. The proof cases above
  declare the root hash in a test SIM1 only to exercise the CMS verifier. The
  incompatibility is an open owner decision on #437.
- **No release trust installation.** ADR-069 already commits SIM1 and TRS1 to
  an administrator kernel-keyring serial. It does not settle which kernel
  keyring trusts the release certificate (builtin, secondary or `.platform`),
  how the certificate is installed there, what the serial identifies across
  boots, or how the signing key is held. That is an open owner decision on
  #437. These fixtures install nothing.
- **No activation evidence.** Nothing here mounts an image, activates
  dm-verity or exercises the kernel keyring. Supported systemd/kernel evidence
  on both architectures runs on the pinned appliance under hosted QEMU TCG in
  #444.
