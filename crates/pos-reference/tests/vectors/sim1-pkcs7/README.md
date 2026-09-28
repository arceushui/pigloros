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
