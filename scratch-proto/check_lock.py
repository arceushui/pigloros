#!/usr/bin/env python3
"""THROWAWAY (#471): compare main's Cargo.lock with the lock after adding the
ADR-110 r6 prototype crates, and assert the r6 §3 tables."""
import sys, tomllib, collections

base = tomllib.load(open(sys.argv[1], "rb"))["package"]
new = tomllib.load(open(sys.argv[2], "rb"))["package"]
key = lambda p: (p["name"], p["version"])
b = {key(p): p for p in base}
n = {key(p): p for p in new}
fail = []

print("== packages added by the r6 set (name version checksum)")
added = sorted(set(n) - set(b))
for k in added:
    p = n[k]
    print(f"  {k[0]} {k[1]} {p.get('checksum', '(path/workspace)')}")
print(f"  total added: {len(added)}")
print("== packages removed:", sorted(set(b) - set(n)) or "none")

expect = {
    "p256": ("0.14.0", "d2c9239b2dbc807adbbe147e8cf72ea7450c3a0aabe62cb8e75ff4ec22e1f72a"),
    "sha2": ("0.11.0", "446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4"),
    "httparse": ("1.10.1", "6dbf3de79e51f3d586ab4cb9d5c3e2c14aa28ed23d180cf89b4df0454a69cc87"),
    "base64": ("0.22.1", "72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6"),
    "getrandom": ("0.4.3", "300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099"),
    "aes-gcm": ("0.11.1", "7f2b8006a0c83f52b62ba44a97b58bf76fe2f70a329e588f67f89691d93d498f"),
    "hkdf": ("0.13.0", "4aaa26c720c68b866f2c96ef5c1264b3e6f473fe5d4ce61cd44bbe913e553018"),
    "webview2-com": ("0.39.1", "3f89fca7a704cee10dcb3654c1dbb8941d1783132f1917358af75bec37a7d7e6"),
    "windows": ("0.62.2", "527fadee13e0c05939a6a05d5bd6eec6cd2e3dbd648b9f8e447c6518133d8580"),
    "webview2-com-sys": ("0.39.1", "b3a07132775117d6065853d9d1178157b8c90e228de47129d6bce2c7edebedfb"),
    "webview2-com-macros": ("0.8.1", "67a921c1b6914c367b2b823cd4cde6f96beec77d30a939c8199bb377cf9b9b54"),
    "windows-core": ("0.62.2", "b8e83a14d34d0623b51dce9581199302a221863196a1dde71a7663a4c2be9deb"),
    "windows-implement": ("0.60.2", "053e2e040ab57b9dc951b72c264860db7eb3b0200ba345b4e4c3b14f67855ddf"),
    "windows-interface": ("0.59.3", "3f316c4a2570ba26bbec722032c4099d8c8bc095efccdc15688708623367e358"),
}
single = {"webview2-com", "webview2-com-sys", "webview2-com-macros", "windows", "windows-core",
          "windows-implement", "windows-interface"}
byname = collections.defaultdict(list)
for p in new:
    byname[p["name"]].append(p)
print("== r6 §3 pin and checksum table")
for name, (ver, ck) in expect.items():
    ps = [p for p in byname.get(name, []) if p["version"] == ver]
    got = ps[0].get("checksum") if ps else None
    st = "OK" if got == ck else "MISMATCH"
    if got != ck:
        fail.append(f"{name} {ver}: lock checksum {got} != ADR {ck}")
    allv = [p["version"] for p in byname.get(name, [])]
    extra = ""
    if name in single and len(allv) != 1:
        extra = f" SINGLE-VERSION VIOLATION {allv}"
        fail.append(f"{name} has versions {allv}")
    print(f"  {st:8} {name} {ver} {got} (all versions in lock: {allv}){extra}")

print("== banned crates (openssl, openssl-sys, openssl-src, tauri, wry, webauthn-rs*)")
banned = [p for p in new if p["name"] in {"openssl", "openssl-sys", "openssl-src", "tauri", "wry"}
          or p["name"].startswith("webauthn-rs")]
print("  ", [key(p) for p in banned] or "none present")
if banned:
    fail.append(f"banned present: {banned}")

print("== every windows* crate and its versions (whole lock)")
for name in sorted(k for k in byname if k.startswith("windows")):
    vs = sorted(p["version"] for p in byname[name])
    print(f"  {name}: {vs}{'  <-- multiple' if len(vs) > 1 else ''}")

print("== crates that gained a second (or further) version from the r6 set")
bn = collections.Counter(p["name"] for p in base)
nn = collections.Counter(p["name"] for p in new)
for name in sorted(nn):
    if nn[name] > 1 and nn[name] > bn.get(name, 0):
        print(f"  {name}: {sorted(p['version'] for p in byname[name])}")

print("== RESULT:", "PASS" if not fail else "FAIL")
for f in fail:
    print("  -", f)
sys.exit(1 if fail else 0)
