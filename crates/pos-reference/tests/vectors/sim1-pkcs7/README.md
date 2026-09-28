# SIM1 PKCS#7 interoperability fixture

This test-only fixture records the RSA-2048, SHA-256, detached no-attributes
profile selected by [Accepted ADR-087](https://redmine.piglor.com/projects/pigloros/wiki/ADR-087_Systemd_mountfsd_SIM1_activation_boundary).
It exercises the pinned parsing and signature libraries through their public
APIs. It does not prove SIM1 admission, TRS1 authorization, certificate path or
time validation, held-image identity, or systemd/kernel activation. Those are
separate acceptance requirements of existing #437–#444.

The signature was produced independently of the Rust verifier using OpenSSL
3.0.13 (library 3.0.13), following the detached signing form in
[systemd-repart's offline signing example](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html).
The private fixture key was discarded and is not a release or trusted key.
The synthetic root hash does not identify a mountable image.

## Regeneration

In a disposable private directory, create `root-hash.txt` containing exactly
the following 64 ASCII bytes, without a newline:

```text
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out certificate.pem \
  -subj '/CN=PiglorOS SIM1 interoperability fixture' \
  -set_serial 1 -days 3650 -sha256 \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=codeSigning'
openssl x509 -in certificate.pem -outform DER -out signer.der
openssl smime -sign -binary -noattr -md sha256 \
  -in root-hash.txt -signer certificate.pem -inkey key.pem \
  -outform DER -out proof.der
```

Regeneration creates a fresh random key and new certificate dates, so it does
not reproduce the committed bytes. Update the hashes when replacing fixtures.
The committed certificate validity is 2026-09-28 02:24:35 UTC through
2036-09-25 02:24:35 UTC; these dependency tests do not use the wall clock.

## Encodings and identities

The fixture has one v1 issuer-and-serial SignerInfo, one self-signed certificate,
no embedded content, no attributes and no CRLs. Both digest identifiers use
SHA-256 with ASN.1 NULL. SignerInfo and SPKI use `rsaEncryption` with NULL;
both certificate signature identifiers use `sha256WithRSAEncryption` with
NULL. The signature is 256 bytes. Tests assert these actual encodings and use
`webpki::ring::RSA_PKCS1_2048_8192_SHA256` for the detached signature and
certificate self-signature. This does not treat the certificate as a webpki
trust anchor or grant it authority.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `root-hash.txt` | 64 | `6c86c6aac5fb24bcf5d9939cb7d7d5645ce39418f449e03b262dd4fa14b4b92b` |
| `signer.der` | 854 | `ed34156300de1831b61c44eaef5ba11f44db19bf793c2cfb78f89cc84b42c246` |
| `proof.der` | 1271 | `773b7635b2b63568855d1e833f5db9e5c1c6588f7c8db86bf627b09eea3d7d68` |

Hosted workspace tests execute `sim1_pkcs7_interoperability`. The runtime
OpenSSL dependency ban remains in force: OpenSSL is only the offline fixture
producer, never a production verifier or subprocess fallback.

## Public proof-verifier cases

`sandbox_admission_contract_public` also uses these fixtures through
`AdmittedSandboxProvider::verify_image_proof`, with independently signed
SIM1/APT1/TRS1/RVS1 test records. The test admission time is Unix second
1,800,000,000, never the test runner's wall clock.

Additional OpenSSL 3.0.13 fixtures use fresh RSA-2048 keys and the same detached
signing command above. Their private keys were discarded:

- `chain-proof.der`: one root (serial 10), one intermediate (serial 11), and
  a signer (serial 12). Subjects are `CN=SIM1 fixture root`,
  `CN=SIM1 fixture intermediate`, and `CN=SIM1 fixture leaf` respectively.
  The root is self-signed with `-days 1`; intermediate and signer are issued
  with `openssl x509 -req -CA ... -CAkey ... -days 3650 -sha256`.
  Both CAs have critical BasicConstraints and keyCertSign KU, with path lengths
  1 and 0. The signer has critical CA:FALSE, digitalSignature KU and codeSigning
  EKU. Signing adds the intermediate and root PEM certificates with `-certfile`.
  At the test time the root is expired, while leaf and intermediate are valid:
  this exercises ADR-087's explicit root-time policy.
- `optional-usage-proof.der`: self-signed serial 20, subject
  `CN=SIM1 fixture optional usage`, `-days 3650`, and critical CA:FALSE.
  KU and EKU are absent, proving that their presence is not mandatory.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `chain-proof.der` | 2826 | `e41957401b886f1db78039fc70d6cbb2f4d1a7927fdf291df7b5e56afca858ca` |
| `chain-signer.der` | 820 | `cfeaea01e4fc1038d8fa122ad715ba98226401dd2b5ef9149626b6bc10f488fe` |
| `optional-usage-proof.der` | 1201 | `6c36c7edd53d4df1f977aa59f945d8649ae55466ca29776bc0f8747020a55e39` |
| `optional-usage-signer.der` | 795 | `28766a02f3f9ea2d4b21e8835e1807a4ceb920f321c0da4b867582c178905535` |

These fixtures exercise proof verification only. They still do not supply a
mountable image or systemd/kernel acceptance evidence.

## Hosted allocation evidence

The `sim1-proof-risk` workflow builds the public admission test executable and
runs three adversarial cases in separate
[Massif](https://valgrind.org/docs/manual/ms-manual.html) processes: an excessive
digest set, an oversized certificate, and forbidden attributes. Each case
asserts that its DER proof is larger than 1 MiB minus 4 KiB and at most 1 MiB,
then checks rejection through `AdmittedSandboxProvider::verify_image_proof`.

The artifact retains the raw heap traces, readable allocation trees, exact
source and checkout commits, executable hash, compiler/profiler versions and
machine-readable peak measurements. The collector requires exactly one passing
test per process and a nonempty peak snapshot; a missing or filtered-out test
cannot produce successful evidence.

Measurements include fixture construction and the test harness. They exclude
stack and RSS, and do not establish a production memory ceiling or replace
systemd/kernel conformance. Inspect the allocation trees and independent review
alongside the recorded peak before accepting the resource-risk evidence.
