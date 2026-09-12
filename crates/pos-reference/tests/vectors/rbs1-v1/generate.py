"""Generate ADR-069 v80 RBS1 golden vectors without Rust implementation code."""

import hashlib
from pathlib import Path

import blake3
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

features = [
    "broker-lifecycle",
    "cgroup-kill",
    "cgroup-v2-cpu",
    "cgroup-v2-memory",
    "cgroup-v2-pids",
    "ipc-namespace",
    "limit-observation",
    "managed-attempt-exec",
    "mount-namespace",
    "network-namespace",
    "nftables-atomic",
    "pid-namespace",
    "process-isolation-controls",
    "signed-root-image",
    "user-namespace",
    "uts-namespace",
]
x86 = [
    bytes.fromhex(x)
    for x in [
        "4f68bce3e8cd4db196e7fbcaf984b709",
        "2c7357edebd246d9aec123d437ec2bf5",
        "41092b059fc84523994f2def0408b176",
    ]
]
arm = [
    bytes.fromhex(x)
    for x in [
        "b921b0451df041c3af444c6f280d3fae",
        "df3300ced69f4c92978c9bfb0f38d820",
        "6db69de629f44758a7a5962190f00ce3",
    ]
]


def enc(x):
    return cbor2.dumps(x, canonical=True)


def h(domain, x):
    return blake3.blake3(domain + enc(x)).digest()


def rec(magic, x):
    return h(f"PiglorOS.{magic}.v1\0".encode(), x)


def wrap(magic, x):
    return [x, rec(magic, x), bytes(64)]


def ordered(values):
    return sorted(values, key=enc)


def lim():
    return [[i, 256 if i == 13 else 2000] for i in range(17)]


keys = {
    n: Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32)
    .public_key()
    .public_bytes(Encoding.Raw, PublicFormat.Raw)
    for n, i in [
        ("policy", 2),
        ("release", 3),
        ("runtime", 4),
        ("reviewer", 5),
        ("image", 6),
    ]
}
trust_u = [
    "TRS1",
    1,
    2,
    ordered(
        [
            [n, role, keys[n], 2]
            for n, role in [
                ("policy", 1),
                ("release", 2),
                ("runtime", 3),
                ("reviewer", 4),
                ("image", 5),
            ]
        ]
    ),
    [[bytes([9]) * 32, 77, 2]],
    "root",
]
trust = wrap("TRS1", trust_u)
trustd = trust[1]
rev = wrap("RVS1", ["RVS1", 1, trustd, 3, [], [], [], "policy"])
revd = rev[1]
cap = [["execute", 1, 1]]
capd = h(b"PiglorOS.ProviderCapabilitySet.v1\0", cap)
featd = h(b"PiglorOS.RequiredHostFeatureSet.v1\0", features)
bhc = ["BHC1", 1, lim()]
bhcbytes = enc(bhc)
bhcd = blake3.blake3(bhcbytes).digest()
binary = b"exact provider binary"
bind = blake3.blake3(binary).digest()
for arch, name, parts in [(0, "x86_64", x86), (1, "aarch64", arm)]:
    spmu = [
        "SPM1",
        1,
        "provider",
        bytes([10]) * 32,
        bytes([11]) * 32,
        bind,
        bytes([12]) * 32,
        "runtime",
        cap,
        [arch],
        bytes([13]) * 32,
        bytes([14]) * 32,
        bytes([15]) * 32,
        bytes([16]) * 32,
        2,
        bytes([17]) * 32,
        featd,
        "release",
    ]
    spm = wrap("SPM1", spmu)
    spmd = spm[1]
    scsu = ["SCS1", 1, arch, ["read"], ["read"]]
    scs = [scsu, rec("SCS1", scsu)]
    scsd = scs[1]
    proofs = ordered([[f, 1, bytes([18]) * 32] for f in features])
    hcpu = [
        "HCP1",
        1,
        arch,
        "6.12.0",
        proofs,
        bytes([19]) * 32,
        bytes([20]) * 32,
        bytes([21]) * 32,
        "runtime",
    ]
    hcp = wrap("HCP1", hcpu)
    hcpd = hcp[1]
    pcru = [
        "PCR1",
        1,
        bytes([17]) * 32,
        bind,
        bytes([12]) * 32,
        capd,
        featd,
        arch,
        hcpd,
        0,
        "reviewer",
    ]
    pcr = wrap("PCR1", pcru)
    pcrd = pcr[1]
    sim_u = [
        "SIM1",
        1,
        "image",
        arch,
        3,
        blake3.blake3(b"img").digest(),
        [
            [r, parts[r], bytes([r + 1]) * 16, r, 1, bytes([r + 1]) * 32]
            for r in range(3)
        ],
        bytes([22]) * 32,
        4096,
        4096,
        1,
        b"",
        [5, hashlib.sha256(b"pkcs7").digest(), b"pkcs7"],
        bytes([9]) * 32,
        77,
        "/adapter",
        blake3.blake3(b"adapter executable").digest(),
        [],
        2,
        "image",
    ]
    sim = wrap("SIM1", sim_u)
    simd = sim[1]
    for mode, mn in enumerate(["local", "air_gapped", "replay", "fork"]):
        lpsu = ["LPS1", 1, "air-gapped", mode, simd, lim(), []]
        lps = [lpsu, rec("LPS1", lpsu)]
        lpsd = lps[1]
        aptu = [
            "APT1",
            1,
            4,
            spmd,
            bind,
            [lpsd],
            [simd],
            bhcd,
            bytes([17]) * 32,
            pcrd,
            trustd,
            revd,
            2,
            3,
            scsd,
            "policy",
        ]
        apt = wrap("APT1", aptu)
        aptd = apt[1]
        actual = [
            [i, 1 if i in (0, 4, 8, 9) else 256 if i == 13 else 2000] for i in range(17)
        ]
        elmu = [
            "ELM1",
            1,
            actual,
            bhcd,
            aptd,
            lpsd,
            bytes([8]) * 32,
            bytes([38]) * 32,
            "runtime",
        ]
        elmd = rec("ELM1", elmu)
        fdlu = ["FDL1", 1, mode, [[3, 0], [4, 1]] if mode == 0 else [[3, 1]]]
        fdld = rec("FDL1", fdlu)
        rbsu = [
            "RBS1",
            1,
            0,
            "provider",
            spmd,
            bind,
            bytes([12]) * 32,
            hcpd,
            arch,
            "runtime",
            ["execute", 1, 1],
            mode,
            lpsd,
            simd,
            scsd,
            elmd,
            fdld,
            features,
            [],
        ]
        rbsd = h(b"PiglorOS.SandboxReadbackSet.v1\0", rbsu)
        out = enc([rbsu, rbsd])
        path = Path(__file__).parent / f"{name}-{mn}.cbor"
        with path.open("wb") as output:
            output.write(out)
        print(name, mn, rbsd.hex(), len(out))
