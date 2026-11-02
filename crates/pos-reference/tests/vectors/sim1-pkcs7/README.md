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
  OpenSSL 3.0.13's `smime` encoder retains the chain insertion order, so finalize
  the DER certificate set with
  `openssl cms -cmsout -inform DER -in chain-unsorted.der -outform DER -out chain-proof.der`.
  This changes only certificate-set ordering; certificate and signature bytes
  remain unchanged. The verifier rejects the unsorted input.
  At the test time the root is expired, while leaf and intermediate are valid:
  this exercises ADR-087's explicit root-time policy.
- `optional-usage-proof.der`: self-signed serial 20, subject
  `CN=SIM1 fixture optional usage`, `-days 3650`, and critical CA:FALSE.
  KU and EKU are absent, proving that their presence is not mandatory.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `chain-proof.der` | 2826 | `3bca9d38d46ee28016af9c56d509f7b57f5af74fee267f640ebf47ca52d15367` |
| `chain-signer.der` | 820 | `cfeaea01e4fc1038d8fa122ad715ba98226401dd2b5ef9149626b6bc10f488fe` |
| `optional-usage-proof.der` | 1201 | `6c36c7edd53d4df1f977aa59f945d8649ae55466ca29776bc0f8747020a55e39` |
| `optional-usage-signer.der` | 795 | `28766a02f3f9ea2d4b21e8835e1807a4ceb920f321c0da4b867582c178905535` |

These fixtures exercise proof verification only. They still do not supply a
mountable image or systemd/kernel acceptance evidence.

## Hosted allocation evidence

The `sim1-proof-risk` workflow builds the public admission test executable and
runs seven adversarial cases in separate
[Massif](https://valgrind.org/docs/manual/ms-manual.html) processes. All cases use
`AdmittedSandboxProvider::verify_image_proof`.

| Input | Asserted proof size | Exercised boundary |
| --- | --- | --- |
| Excessive digest set | > 1020 KiB, <= 1024 KiB | Rejection before eager SET decoding |
| Oversized certificate | > 1020 KiB, <= 1024 KiB | Per-certificate bound before decoding |
| Forbidden attributes | > 1020 KiB, <= 1024 KiB | Rejection before attribute decoding |
| Oversized issuer SID | > 1020 KiB, <= 1024 KiB | SID cannot exceed its matching certificate |
| Reverse-ordered issuer RDN | > 60 KiB, <= 64 KiB | Canonical order checked before eager sorting |
| Canonical issuer RDN | > 60 KiB, <= 64 KiB | Large allowed nested SET decoded before signer rejection |
| Eight exactly-64-KiB certificates | > 512 KiB, <= 516 KiB | Inclusive size/count limits, eager CMS decoding, path rejection |

Mutated certificate signatures are not valid; these fixtures measure rejection
paths, not new trusted chains. The SID size bound follows from the certificate
bound: a matching issuer/serial or SKI identity is contained within the selected
certificate's DER. Canonical RDN order is checked with borrowed elements before
the library can normalize an unauthorized issuer's SET.

The artifact retains the raw heap traces, readable allocation trees, exact
source and checkout commits, executable hash, compiler/profiler versions and
machine-readable peak measurements. The collector requires exactly one passing
test per process and a nonempty peak snapshot; a missing or filtered-out test
cannot produce successful evidence.

Measurements include fixture construction and the test harness. They exclude
stack and RSS, and do not establish a production memory ceiling or replace
systemd/kernel conformance. Inspect the allocation trees and independent review
alongside the recorded peak before accepting the resource-risk evidence.

## Signed reversed-root validity fixture

`reversed-root-proof.der` contains one self-signed root (serial 1,
`CN=SIM1 reversed fixture root`) and its directly issued signer (serial 2,
`CN=SIM1 reversed fixture leaf`). Both keys are RSA-2048 with exponent 65537.
The root's notBefore is 2036-01-01 00:00:00 UTC and its notAfter is
2026-01-01 00:00:00 UTC. The leaf's interval has the same endpoints in the
normal order, containing fixed admission time 1,800,000,000.

The root's self-signature, leaf certificate signature and detached CMS signature
are authentic. This isolates root interval coherence from signature corruption.
The public verifier requires `CertificateTime`; the existing coherent expired
root chain remains a passing control. Root expiry and reversed root dates are
separate policy cases. This does not establish a new root-expiry requirement.

To regenerate with OpenSSL 3.0.13 in a disposable private directory:

1. Create fresh RSA-2048 root and leaf keys and CSRs. Issue the root with
   `openssl ca -selfsign` and the leaf with `openssl ca`, setting
   `-startdate 20260101000000Z -enddate 20360101000000Z` and serials 1 and 2.
   The root has critical CA:TRUE/pathlen:0 and keyCertSign/cRLSign KU. The leaf
   has critical CA:FALSE, digitalSignature KU and codeSigning EKU.
2. Export the root's DER, exchange the two complete UTCTime elements in its
   TBSCertificate validity sequence, and DER-encode that changed TBSCertificate
   as `root-reversed-tbs.der`. Keep all its other fields unchanged. Sign it
   with the root's private key:

   ```sh
   openssl dgst -sha256 -sign root.key \
     -out root-reversed-signature.bin root-reversed-tbs.der
   ```

   Assemble the final certificate SEQUENCE from the changed TBSCertificate,
   the original signatureAlgorithm and a BIT STRING containing zero unused
   bits followed by that signature. Convert it to `root-reversed.pem` with
   `openssl x509 -inform DER`. This signs the malformed interval deliberately;
   editing a signed certificate without re-signing is not this fixture.
3. Export the leaf as `reversed-root-signer.der`, then sign the same 64-byte
   `root-hash.txt` and canonicalize the certificate SET:

   ```sh
   openssl smime -sign -binary -noattr -md sha256 -in root-hash.txt \
     -signer leaf.pem -inkey leaf.key -certfile root-reversed.pem \
     -outform DER -out proof-unsorted.der
   openssl cms -cmsout -inform DER -in proof-unsorted.der \
     -outform DER -out reversed-root-proof.der
   ```

Check both certificate signatures directly against the root's public key and
the detached signature against the leaf's public key and exact content.
OpenSSL's normal path-time policy is not the root-time policy tested here.
Discard both private keys. Fresh keys change the bytes; update these hashes.
CMS uses one v1 issuer-and-serial signer, SHA-256/RSA with NULL parameters,
no embedded content, attributes or CRLs, and a 256-byte signature.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `reversed-root-signer.der` | 830 | `a9fc317b88600f95efc7a3417e19d41233107785de18946ecc09e0d4a05bec0b` |
| `reversed-root-proof.der` | 2017 | `a022f225f52f410dda089625eb23144bf4df7e720ba81fc374b85fd961e2ca82` |
