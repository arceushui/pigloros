#!/usr/bin/env python3
"""Verify #444 part (a) packaged-closure evidence from one QEMU TCG boot.

ADR-087 gate 5 (Parts A.1, C.1, C.3 and D.1) asks #444 to record, on the
packaged NixOS 26.05 closure and on both architectures:

- the package and kernel store identities of the pinned closure;
- the full .builtin_trusted_keys contents, tied to the root-hash certificate
  by its exact kernel key description: exactly one member carries it, and
  that member is `asymmetric`;
- the three dm-verity root-hash signature keyring options;
- the kernel command line, which must pass the provider's strict
  `systemd.allow_userspace_verity=0` rule;
- every verity.d directory systemd consults;
- mountfsd's units, drop-ins and environment, without a
  SYSTEMD_MOUNTFSD_*, SYSTEMD_PROC_CMDLINE or SYSTEMD_VERITY_SHARING
  override, outside any container.

scripts/qemu-closure-evidence.sh only records. This checker owns every
judgement and derives the expected key description from the certificate
itself, independently of the kernel. A published artifact can be checked
again: its checker-verdict.json and SHA256SUMS sit beside guest/ and host/,
and every file must then match SHA256SUMS.
Usage:

  check_qemu_closure_evidence.py --architecture ARCH --certificate PEM \
      --flake-lock LOCK --verdict OUT EVIDENCE_DIR
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys


PINNED_NIXPKGS_REV = "f1e5c356f35d07e7b71a6b5e6c9338e0b029e0c0"
PINNED_NIXPKGS_URL = f"https://github.com/NixOS/nixpkgs/archive/{PINNED_NIXPKGS_REV}.tar.gz"
PINNED_NIXPKGS_NAR_HASH = "sha256-qXFIqA6FCcx7XeDzw0ZNlkDT9UiCzrNDwK8RuU8RcHM="
PINNED_NIXPKGS_LAST_MODIFIED = 1794552581
SYSTEMD_VERSION_LINE = ("systemd", "260", "(260.5)")
KERNEL_SERIES = "6.12"
ARCHITECTURES = {"x86_64": "bzImage", "aarch64": "Image"}
STORE_PATH = re.compile(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+")
STORE_NAMES = ("vm", "toplevel", "kernel", "systemd", "qemu", "trustedCertificate")
VERITY_SIG = "DM_VERITY_VERIFY_ROOTHASH_SIG"
VERITY_FALLBACKS = (
    "DM_VERITY_VERIFY_ROOTHASH_SIG_SECONDARY_KEYRING",
    "DM_VERITY_VERIFY_ROOTHASH_SIG_PLATFORM_KEYRING",
)
CONTEXT_OPTIONS = ("SECONDARY_TRUSTED_KEYRING", "INTEGRITY_PLATFORM_KEYRING", "MODULE_SIG")
USERSPACE_VERITY_KEYS = {"systemd.allow_userspace_verity", "rd.systemd.allow_userspace_verity"}
REQUIRED_USERSPACE_VERITY_WORD = "systemd.allow_userspace_verity=0"
FORBIDDEN_QEMU_OPTIONS = {"enable-kvm", "accel", "net", "netdev"}
# The workflow writes these beside guest/ and host/ after the check.
SEAL_FILES = {"checker-verdict.json", "SHA256SUMS"}
FORBIDDEN_EXACT = {"SYSTEMD_PROC_CMDLINE", "SYSTEMD_VERITY_SHARING"}
FORBIDDEN_PREFIX = "SYSTEMD_MOUNTFSD_"
STATIC_VERITY_DIRS = ("/etc/verity.d", "/run/verity.d", "/usr/local/lib/verity.d", "/usr/lib/verity.d")
CONTAINER_MARKERS = ("/run/systemd/container", "/run/host/container-manager")
HOST_FILES = {
    "flake-metadata.json", "store-paths.json", "path-info.json", "toplevel-closure.json",
    "system-trusted-keys.pem", "runner", "serial-console.log", "qemu-argv", "qemu-exe",
    "qemu-net-dev", "vm-exit-status",
}
GUEST_FILES = {
    "status", "uname-machine", "uname-release", "systemctl-version", "current-system",
    "booted-system", "booted-kernel", "systemd-package", "detect-virt-vm",
    "detect-virt-container", "container-markers", "proc-cmdline", "kernel-config",
    "kernel-log", "proc-keys", "builtin-trusted-keys", "verity-d", "mountfsd-units",
    "mountfsd-service-properties", "mountfsd-socket-properties", "manager-environment",
    "pid1-namespaces",
}
PROCESS_FILES = {"exe", "environ", "namespaces"}
OID_COMMON_NAME = "2.5.4.3"
OID_ORGANIZATION = "2.5.4.10"
OID_EMAIL = "1.2.840.113549.1.9.1"
OID_SUBJECT_KEY_ID = "2.5.29.14"


class EvidenceError(ValueError):
    """The recorded evidence does not establish a required property."""


# --- Certificate: the kernel key description, derived independently --------


def der_read(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one definite-length DER element; return (tag, content, next offset)."""
    if offset + 2 > len(data):
        raise EvidenceError("truncated DER element")
    tag, first = data[offset], data[offset + 1]
    offset += 2
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise EvidenceError("unsupported DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    else:
        length = first
    if offset + length > len(data):
        raise EvidenceError("truncated DER content")
    return tag, data[offset:offset + length], offset + length


def der_children(content: bytes) -> list[tuple[int, bytes]]:
    children, offset = [], 0
    while offset < len(content):
        tag, value, offset = der_read(content, offset)
        children.append((tag, value))
    return children


def der_oid(content: bytes) -> str:
    if not content:
        raise EvidenceError("empty OID")
    arcs, value = [], 0
    for byte in content:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if content[-1] & 0x80:
        raise EvidenceError("truncated OID")
    first = min(arcs[0] // 40, 2)
    return ".".join(str(arc) for arc in [first, arcs[0] - 40 * first, *arcs[1:]])


def pem_certificate(text: str) -> bytes:
    match = re.fullmatch(
        r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n", text
    )
    if not match:
        raise EvidenceError("certificate is not exactly one PEM CERTIFICATE block")
    return base64.b64decode(match.group(1).replace("\n", ""), validate=True)


def kernel_key_description(der: bytes) -> str:
    """Return x509_key_preparse()'s description (ADR-087 Part C.2)."""
    tag, certificate, end = der_read(der, 0)
    if tag != 0x30 or end != len(der):
        raise EvidenceError("certificate is not one DER SEQUENCE")
    fields = der_children(certificate)
    if len(fields) != 3 or fields[0][0] != 0x30:
        raise EvidenceError("certificate is not tbsCertificate, algorithm, signature")
    tbs = der_children(fields[0][1])
    if tbs and tbs[0][0] == 0xA0:
        tbs = tbs[1:]
    if len(tbs) < 6 or tbs[0][0] != 0x02 or tbs[4][0] != 0x30:
        raise EvidenceError("tbsCertificate lacks serial or subject")
    serial, subject = tbs[0][1], tbs[4][1]
    segments: dict[str, bytes] = {}
    for rdn_tag, rdn in der_children(subject):
        if rdn_tag != 0x31:
            raise EvidenceError("subject RDN is not a SET")
        for attribute_tag, attribute in der_children(rdn):
            parts = der_children(attribute)
            if attribute_tag != 0x30 or len(parts) != 2 or parts[0][0] != 0x06:
                raise EvidenceError("malformed subject attribute")
            oid = der_oid(parts[0][1])
            if oid in (OID_COMMON_NAME, OID_ORGANIZATION, OID_EMAIL):
                segments[oid] = parts[1][1]  # the kernel keeps the last one
    cn, o = segments.get(OID_COMMON_NAME, b""), segments.get(OID_ORGANIZATION, b"")
    if cn and o and not (cn.startswith(o) or (len(cn) >= 7 and len(o) >= 7 and cn[:7] == o[:7])):
        name = o + b": " + cn
    else:
        name = cn or o or segments.get(OID_EMAIL, b"")
    name = name.split(b"\0", 1)[0]  # strlen()
    identifier = serial
    for tag, extensions in tbs[5:]:
        if tag != 0xA3:
            continue
        sequence = der_children(extensions)
        if len(sequence) != 1 or sequence[0][0] != 0x30:
            raise EvidenceError("malformed extensions")
        for extension_tag, extension in der_children(sequence[0][1]):
            parts = der_children(extension)
            if extension_tag != 0x30 or not parts or parts[0][0] != 0x06 or parts[-1][0] != 0x04:
                raise EvidenceError("malformed extension")
            if der_oid(parts[0][1]) == OID_SUBJECT_KEY_ID:
                value = parts[-1][1]
                if len(value) < 2 or value[0] != 0x04 or value[1] != len(value) - 2:
                    raise EvidenceError("malformed subjectKeyIdentifier")
                identifier = value[2:]
    try:
        return name.decode("utf-8") + ": " + identifier.hex()
    except UnicodeDecodeError as error:
        raise EvidenceError("certificate subject is not UTF-8") from error


# --- Recorded evidence --------------------------------------------------------


class Evidence:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.processes = self._inventory()

    def _inventory(self) -> list[str]:
        top = {path.name for path in self.root.iterdir()}
        if not {"guest", "host"} <= top <= {"guest", "host"} | SEAL_FILES \
                or any((self.root / name).is_dir() for name in top & SEAL_FILES):
            raise EvidenceError(f"evidence root must hold guest/ and host/, found {sorted(top)}")
        for name, expected in (("host", HOST_FILES), ("guest", GUEST_FILES | {"processes"})):
            found = {path.name for path in (self.root / name).iterdir()}
            if found != expected:
                missing, extra = sorted(expected - found), sorted(found - expected)
                raise EvidenceError(f"{name}/ files differ: missing {missing}, unexpected {extra}")
        processes = sorted(path.name for path in (self.root / "guest" / "processes").iterdir())
        for pid in processes:
            directory = self.root / "guest" / "processes" / pid
            if not pid.isdigit() or {path.name for path in directory.iterdir()} != PROCESS_FILES:
                raise EvidenceError(f"malformed process record: {pid}")
        for path in self.root.rglob("*"):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise EvidenceError(f"evidence entry is not a regular file: {path}")
        if "SHA256SUMS" in top:
            self._verify_manifest()
        return processes

    def _verify_manifest(self) -> None:
        """A sealed artifact must match its manifest, file for file."""
        manifest = self.root / "SHA256SUMS"
        files = sorted(f"./{path.relative_to(self.root).as_posix()}" for path in self.root.rglob("*")
                       if path.is_file() and path != manifest)
        listed = {}
        for line in (self.root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (\./.+)", line)
            if not match or match.group(2) in listed:
                raise EvidenceError(f"malformed SHA256SUMS line: {line!r}")
            listed[match.group(2)] = match.group(1)
        if sorted(listed) != files:
            raise EvidenceError("SHA256SUMS does not list exactly the evidence files")
        for name, digest in listed.items():
            if hashlib.sha256((self.root / name).read_bytes()).hexdigest() != digest:
                raise EvidenceError(f"{name} differs from SHA256SUMS")

    def raw(self, name: str) -> bytes:
        return (self.root / name).read_bytes()

    def text(self, name: str) -> str:
        try:
            return self.raw(name).decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError(f"{name} is not UTF-8") from error

    def line(self, name: str) -> str:
        value = self.text(name)
        if not value.endswith("\n") or "\n" in value[:-1]:
            raise EvidenceError(f"{name} must be exactly one line")
        return value[:-1]

    def json(self, name: str):
        try:
            return json.loads(self.text(name))
        except json.JSONDecodeError as error:
            raise EvidenceError(f"{name} is not JSON") from error


def tab_fields(line: str, count: int, name: str) -> list[str]:
    fields = line.split("\t")
    if len(fields) != count:
        raise EvidenceError(f"malformed {name} line: {line!r}")
    return fields


def tab_map(text: str, name: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        key, value = tab_fields(line, 2, name)
        if key in result:
            raise EvidenceError(f"{name} repeats {key}")
        result[key] = value
    return result


def store_info(evidence: Evidence, name: str) -> dict:
    """`nix path-info --json --json-format 2`: store objects keyed by base name."""
    document = evidence.json(name)
    if not isinstance(document, dict) or document.get("version") != 2 \
            or document.get("storeDir") != "/nix/store" or not isinstance(document.get("info"), dict):
        raise EvidenceError(f"{name} is not a version 2 store path info document")
    return document["info"]


def check_store_identity(evidence: Evidence, architecture: str, lock: dict) -> dict:
    paths = evidence.json("host/store-paths.json")
    if not isinstance(paths, dict) or sorted(paths) != sorted(STORE_NAMES):
        raise EvidenceError("store-paths.json must name exactly the recorded store identities")
    for name, path in paths.items():
        if not isinstance(path, str) or not STORE_PATH.fullmatch(path):
            raise EvidenceError(f"{name} is not a store path: {path!r}")
    locked = lock.get("nodes", {}).get("nixpkgs", {}).get("locked")
    pinned = {"lastModified": PINNED_NIXPKGS_LAST_MODIFIED, "narHash": PINNED_NIXPKGS_NAR_HASH,
              "type": "tarball", "url": PINNED_NIXPKGS_URL}
    if locked != pinned or lock.get("nodes", {}).get("root") != {"inputs": {"nixpkgs": "nixpkgs"}}:
        raise EvidenceError("flake.lock does not pin exactly the reviewed nixpkgs revision")
    metadata = evidence.json("host/flake-metadata.json")
    recorded = metadata.get("locks", {}).get("nodes", {}).get("nixpkgs", {}).get("locked")
    if recorded != locked:
        raise EvidenceError("evaluated flake inputs differ from flake.lock")
    path_info = store_info(evidence, "host/path-info.json")
    closure = store_info(evidence, "host/toplevel-closure.json")
    nar_hashes = {}
    for name, path in paths.items():
        info = path_info.get(path.removeprefix("/nix/store/"))
        if not isinstance(info, dict) or not isinstance(info.get("narHash"), str):
            raise EvidenceError(f"path-info.json lacks {name}")
        nar_hashes[name] = info["narHash"]
    for name in ("toplevel", "kernel", "systemd"):
        if paths[name].removeprefix("/nix/store/") not in closure:
            raise EvidenceError(f"the toplevel closure lacks {name}")
    toplevel = evidence.line("guest/current-system")
    if toplevel != paths["toplevel"] or evidence.line("guest/booted-system") != toplevel:
        raise EvidenceError("the guest did not boot the recorded toplevel")
    if evidence.line("guest/booted-kernel") != f"{paths['kernel']}/{ARCHITECTURES[architecture]}":
        raise EvidenceError("the guest did not boot the recorded kernel image")
    if evidence.line("guest/systemd-package") != paths["systemd"]:
        raise EvidenceError("the guest systemd package differs from the recorded one")
    version = evidence.text("guest/systemctl-version").split("\n", 1)[0].split()
    if tuple(version[:3]) != SYSTEMD_VERSION_LINE:
        raise EvidenceError(f"unexpected systemd version: {version[:3]}")
    release = evidence.line("guest/uname-release")
    kernel_name = paths["kernel"].split("-", 1)[1]
    if not release.startswith(KERNEL_SERIES + ".") or kernel_name != f"linux-{release}":
        raise EvidenceError(f"unexpected kernel release {release!r} for {kernel_name!r}")
    return {"nixpkgs": locked, "store_paths": paths,
            "nar_hashes": nar_hashes,
            "systemd_version": " ".join(version[:3]), "kernel_release": release}


def check_runner(evidence: Evidence, architecture: str, paths: dict) -> dict:
    if evidence.line("guest/uname-machine") != architecture:
        raise EvidenceError("the guest architecture differs from the job architecture")
    runner = tab_map(evidence.text("host/runner"), "runner")
    if sorted(runner) != ["dev-kvm", "uname"] or not runner["uname"].endswith(" " + architecture):
        raise EvidenceError("the runner record does not show the job architecture")
    if evidence.line("host/vm-exit-status") != "0" or evidence.line("guest/status") != "complete":
        raise EvidenceError("the guest did not complete its evidence and power off cleanly")
    argv = evidence.raw("host/qemu-argv").split(b"\0")
    if argv[-1] != b"" or len(argv) < 2:
        raise EvidenceError("qemu-argv is not a NUL-terminated argument vector")
    argv = [argument.decode("utf-8") for argument in argv[:-1]]
    executable = f"{paths['qemu']}/bin/qemu-system-{architecture}"
    if evidence.line("host/qemu-exe") != executable or argv[0] != executable:
        raise EvidenceError("the running QEMU is not the recorded package's system emulator")
    accelerator, nics, kernels, appends = None, [], [], []
    for index, flag in enumerate(argv[1:], start=1):
        value = argv[index + 1] if index + 1 < len(argv) else ""
        if flag.lstrip("-") in FORBIDDEN_QEMU_OPTIONS and flag.startswith("-"):
            raise EvidenceError(f"QEMU option {flag} is not allowed in the evidence boot")
        if flag in ("-nic", "--nic"):
            nics.append(value)
        if flag in ("-kernel", "--kernel"):
            kernels.append(value)
        if flag in ("-append", "--append"):
            appends.append(value)
        if flag in ("-device", "--device") and value.split(",", 1)[0].startswith("virtio-net"):
            raise EvidenceError("the evidence guest must have no network device")
        if flag in ("-machine", "--machine", "-M"):
            if ",," in value:
                raise EvidenceError("escaped commas in -machine are not interpreted")
            for option in value.split(","):
                if option.startswith("accel="):
                    accelerator = option.removeprefix("accel=")
    # QEMU merges repeated -machine options; the last accel= wins.
    if accelerator != "tcg":
        raise EvidenceError(f"QEMU's effective accelerator is {accelerator!r}, not tcg")
    if nics != ["none"]:
        raise EvidenceError("QEMU must run with exactly one -nic none")
    init = f"init={paths['toplevel']}/init"
    if kernels != [f"{paths['toplevel']}/kernel"] or len(appends) != 1 \
            or appends[0].split().count(init) != 1:
        raise EvidenceError("QEMU did not boot the recorded toplevel's kernel and init")
    interfaces = [line.split(":", 1)[0].strip() for line in evidence.text("host/qemu-net-dev").splitlines()[2:]]
    if interfaces != ["lo"]:
        raise EvidenceError(f"QEMU's network namespace has interfaces {interfaces}, not only lo")
    if evidence.line("guest/detect-virt-vm") != "qemu":
        raise EvidenceError("the guest does not detect TCG QEMU virtualization")
    return {"accelerator": accelerator, "virtualization": "qemu", "runner": runner}


def check_command_line(evidence: Evidence, toplevel: str) -> str:
    """ADR-087 Part C.3: the provider's strict command-line precondition."""
    raw = evidence.raw("guest/proc-cmdline")
    if any(byte > 0x7E or (byte < 0x20 and byte not in b"\t\n\r") for byte in raw):
        raise EvidenceError("the kernel command line has non-ASCII or control bytes")
    line = raw.decode("ascii")
    if any(character in line for character in "\"'\\"):
        raise EvidenceError("the kernel command line has a quote or backslash")
    words = [word for word in re.split(r"[ \t\n\r]", line) if word]
    if words.count(f"init={toplevel}/init") != 1:
        raise EvidenceError("the kernel command line does not start the recorded toplevel")
    matches = [word for word in words
               if word.split("=", 1)[0].replace("-", "_") in USERSPACE_VERITY_KEYS]
    if matches != [REQUIRED_USERSPACE_VERITY_WORD]:
        raise EvidenceError(f"the command line must carry exactly one {REQUIRED_USERSPACE_VERITY_WORD}")
    return line.rstrip("\n")


def check_kernel_config(evidence: Evidence, certificate_path: str) -> dict:
    values: dict[str, str] = {}
    for line in evidence.text("guest/kernel-config").splitlines():
        match = re.fullmatch(r"CONFIG_([A-Za-z0-9_]+)=(.*)|# CONFIG_([A-Za-z0-9_]+) is not set", line)
        if not match:
            if line and not line.startswith("#"):
                raise EvidenceError(f"unparsed kernel config line: {line!r}")
            continue
        name, value = (match.group(1), match.group(2)) if match.group(1) else (match.group(3), "n")
        if name in values:
            raise EvidenceError(f"kernel config repeats {name}")
        values[name] = value
    recorded = {name: values.get(name, "absent") for name in (VERITY_SIG, *VERITY_FALLBACKS)}
    if recorded[VERITY_SIG] != "y":
        raise EvidenceError(f"CONFIG_{VERITY_SIG} must be y")
    for name in VERITY_FALLBACKS:
        if recorded[name] not in ("n", "absent"):
            raise EvidenceError(f"CONFIG_{name} must be disabled")
    if values.get("SYSTEM_TRUSTED_KEYS") != f'"{certificate_path}"':
        raise EvidenceError("CONFIG_SYSTEM_TRUSTED_KEYS is not the recorded certificate")
    return {"dm_verity_keyring": recorded,
            "system_trusted_keys": certificate_path,
            "context": {name: values.get(name, "absent") for name in CONTEXT_OPTIONS}}


def check_keyring(evidence: Evidence, description: str) -> list[dict]:
    """ADR-087 Part C.3, Q6.2/Q6.9: exactly one asymmetric member carries it."""
    keyrings = []
    for line in evidence.text("guest/proc-keys").splitlines():
        fields = line.split(None, 8)
        if len(fields) == 9 and fields[7] == "keyring" \
                and fields[8].split(": ", 1)[0] == ".builtin_trusted_keys":
            keyrings.append(fields)
    if len(keyrings) != 1:
        raise EvidenceError("/proc/keys must show exactly one .builtin_trusted_keys")
    serial, summary = int(keyrings[0][0], 16), keyrings[0][8].split(": ", 1)
    members = []
    for line in evidence.text("guest/builtin-trusted-keys").splitlines():
        key, described = tab_fields(line, 2, "builtin-trusted-keys")
        parts = described.split(";", 4)
        if not key.isdigit() or len(parts) != 5:
            raise EvidenceError(f"malformed key description: {line!r}")
        members.append({"serial": int(key), "type": parts[0], "uid": parts[1], "gid": parts[2],
                        "permissions": parts[3], "description": parts[4]})
    if not members or members[0]["serial"] != serial or members[0]["type"] != "keyring" \
            or members[0]["description"] != ".builtin_trusted_keys":
        raise EvidenceError("builtin-trusted-keys does not start with the /proc/keys keyring")
    keyring, members = members[0], members[1:]
    if len({member["serial"] for member in members}) != len(members) or keyring["serial"] in \
            {member["serial"] for member in members}:
        raise EvidenceError("builtin-trusted-keys repeats a member")
    expected_count = "empty" if not members else str(len(members))
    if len(summary) != 2 or summary[1] != expected_count:
        raise EvidenceError("/proc/keys and keyctl disagree on the member count")
    carriers = [member for member in members if member["description"] == description]
    if len(carriers) != 1 or carriers[0]["type"] != "asymmetric":
        raise EvidenceError("exactly one asymmetric member must carry the certificate description")
    if f"Loaded X.509 cert '{description}'" not in evidence.text("guest/kernel-log"):
        raise EvidenceError("the kernel log does not show the certificate being loaded")
    return members


def check_verity_d(evidence: Evidence, systemd: str) -> list[dict]:
    expected = [*STATIC_VERITY_DIRS, f"{systemd}/lib/verity.d"]
    records = []
    for line in evidence.text("guest/verity-d").splitlines():
        path, kind = tab_fields(line, 2, "verity-d")
        if len(records) == len(expected) or path != expected[len(records)]:
            raise EvidenceError(f"unexpected verity.d entry: {line!r}")
        if kind not in ("absent", "directory"):
            raise EvidenceError(f"{path} is a {kind}")
        records.append({"path": path, "state": kind})
    if len(records) != len(expected):
        raise EvidenceError("verity-d does not cover every directory systemd consults")
    return records


def forbidden(names) -> list[str]:
    return sorted(name for name in names
                  if name in FORBIDDEN_EXACT or name.startswith(FORBIDDEN_PREFIX))


def properties(evidence: Evidence, name: str) -> dict[str, str]:
    result = {}
    for line in evidence.text(name).splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in result:
            raise EvidenceError(f"malformed {name} line: {line!r}")
        result[key] = value
    return result


def check_mountfsd(evidence: Evidence, systemd: str) -> dict:
    service = properties(evidence, "guest/mountfsd-service-properties")
    socket = properties(evidence, "guest/mountfsd-socket-properties")
    if service.get("Id") != "systemd-mountfsd.service" or service.get("ActiveState") != "active" \
            or socket.get("Id") != "systemd-mountfsd.socket" or socket.get("ActiveState") != "active":
        raise EvidenceError("mountfsd's service and socket must both be active")
    for key in ("Environment", "EnvironmentFiles", "PassEnvironment", "DropInPaths"):
        if service.get(key) != "":
            raise EvidenceError(f"systemd-mountfsd.service must have an empty {key}=")
    for line in evidence.text("guest/mountfsd-units").splitlines():
        directive = line.strip().split("=", 1)[0].strip()
        if directive in ("Environment", "EnvironmentFile", "PassEnvironment"):
            raise EvidenceError(f"a mountfsd unit or drop-in sets {directive}=")
    manager = [line.split("=", 1)[0] for line in evidence.text("guest/manager-environment").splitlines()]
    if forbidden(manager):
        raise EvidenceError(f"the manager environment sets {forbidden(manager)}")
    if evidence.line("guest/detect-virt-container") != "none" or [
        tab_fields(line, 2, "container-markers")
        for line in evidence.text("guest/container-markers").splitlines()
    ] != [[marker, "absent"] for marker in CONTAINER_MARKERS]:
        raise EvidenceError("the evidence guest runs in a container")
    init = tab_map(evidence.text("guest/pid1-namespaces"), "pid1-namespaces")
    daemon, worker = f"{systemd}/lib/systemd/systemd-mountfsd", f"{systemd}/lib/systemd/systemd-mountwork"
    executables = {}
    for pid in evidence.processes:
        base = f"guest/processes/{pid}"
        executables[pid] = evidence.line(f"{base}/exe")
        if executables[pid] not in (daemon, worker):
            raise EvidenceError(f"unexpected process in mountfsd's cgroup: {executables[pid]}")
        environ = evidence.raw(f"{base}/environ")
        if environ and not environ.endswith(b"\0"):
            raise EvidenceError(f"process {pid} environment is not NUL-terminated")
        names = [entry.split(b"=", 1)[0].decode("utf-8", "replace")
                 for entry in environ.split(b"\0")[:-1]]
        if forbidden(names):
            raise EvidenceError(f"mountfsd process {pid} sets {forbidden(names)}")
        namespaces = tab_map(evidence.text(f"{base}/namespaces"), "namespaces")
        if sorted(init) != ["mnt", "pid", "user"] or sorted(namespaces) != sorted(init) \
                or namespaces["pid"] != init["pid"] or namespaces["user"] != init["user"]:
            raise EvidenceError(f"mountfsd process {pid} is not in the host PID and user namespaces")
    if executables.get(service.get("MainPID")) != daemon or worker not in executables.values():
        raise EvidenceError("mountfsd's main process and at least one worker must be recorded")
    return {"service": service, "socket": socket, "processes": executables}


def check(root: pathlib.Path, architecture: str, certificate: str, lock: dict) -> dict:
    if architecture not in ARCHITECTURES:
        raise EvidenceError(f"unsupported architecture {architecture!r}")
    description = kernel_key_description(pem_certificate(certificate))
    evidence = Evidence(root)
    identity = check_store_identity(evidence, architecture, lock)
    paths = identity["store_paths"]
    if evidence.text("host/system-trusted-keys.pem") != certificate \
            or not paths["trustedCertificate"].endswith("-root-hash-dev-test.crt"):
        raise EvidenceError("the kernel's trusted-keys file is not the reviewed certificate")
    return {
        "architecture": architecture,
        **identity,
        **check_runner(evidence, architecture, paths),
        "kernel_command_line": check_command_line(evidence, paths["toplevel"]),
        "kernel_config": check_kernel_config(evidence, paths["trustedCertificate"]),
        "certificate_key_description": description,
        "builtin_trusted_keys": check_keyring(evidence, description),
        "verity_d": check_verity_d(evidence, paths["systemd"]),
        "mountfsd": check_mountfsd(evidence, paths["systemd"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--certificate", required=True, type=pathlib.Path)
    parser.add_argument("--flake-lock", required=True, type=pathlib.Path)
    parser.add_argument("--verdict", required=True, type=pathlib.Path)
    parser.add_argument("evidence", type=pathlib.Path)
    arguments = parser.parse_args(argv)
    try:
        verdict = check(arguments.evidence, arguments.architecture,
                        arguments.certificate.read_text(encoding="utf-8"),
                        json.loads(arguments.flake_lock.read_text(encoding="utf-8")))
        with arguments.verdict.open("x", encoding="utf-8") as output:
            json.dump(verdict, output, indent=2, sort_keys=True)
            output.write("\n")
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"qemu closure evidence: {error}", file=sys.stderr)
        return 1
    print(f"qemu closure evidence holds for {arguments.architecture}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
