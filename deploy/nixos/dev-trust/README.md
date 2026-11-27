# Public dev/test root-hash trust domain

The key pairs in this directory are public development and test material. They
are not production trust roots. Do not use them to sign evidence for a release
appliance or another production host.

- `root-hash-dev-test.crt` is included in the QEMU evidence guest's kernel
  trust store. Its matching private key is committed so contributors can
  reproduce the signed development evidence images.
- The QEMU evidence guest does not trust `root-hash-untrusted-dev-test`. It
  uses that key for the wrong-root and `verity.d` refusal cases.

The release root-hash private key is not stored in this repository. A released
build must use evidence signed under its release certificate.
