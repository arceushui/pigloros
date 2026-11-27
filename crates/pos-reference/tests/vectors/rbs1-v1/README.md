# RBS1 v1 golden vectors

These eight complete RBS1 CBOR wrappers are independent test inputs for the
public selector commitment boundary: x86_64 and aarch64, each in local,
air-gapped, replay, and fork mode.  The wrapper's second array element is the
expected `PiglorOS.SandboxReadbackSet.v1\0` BLAKE3 digest.

The inputs follow the checked-in RBS1, ELM1 and FDL1 codecs and deliberately match
the public admission fixture:
`sandbox_admission_contract_public.rs`: fixed signing seeds 1 through 6, the closed
16-element host-feature list, `img` root-image bytes, `adapter executable`,
and the stated BHC1 and attempt-limit values. SIM1 carries the exact 32-byte
verity salt and the kernel key description that TRS1 also binds.

`generate.py` is a standalone oracle using Python 3 with `blake3`, `cbor2`,
and `cryptography`.  From the repository root, run it with a Python
environment containing those packages.  It emits these files only; Cargo is
not an input to generation. Review generator and vector changes together with
the checked-in codecs and public admission tests.
