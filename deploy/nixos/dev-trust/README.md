# Public dev/test root-hash trust domain

The key pairs in this directory are **public** and belong to the PiglorOS
dev/test trust domain (#444 owner decision D2, 2026-11-15). They are **never a
production trust root**. Do not use them to sign anything that a release
appliance or any other host should trust.

- `root-hash-dev-test.crt` is compiled into the kernel of the #444 QEMU
  evidence guest (ADR-087 Part C.1). Its private key,
  `root-hash-dev-test.key`, is committed so that anyone can rebuild the
  signed evidence images byte for byte (#444 owner decision Q1, 2026-11-16).
- No kernel trusts `root-hash-untrusted-dev-test`. The evidence guest uses it
  for the wrong-key and `verity.d` refusal cases.

The release root-hash key stays offline (ADR-087 Part C.4). A released build
gets fresh evidence under that release certificate.
