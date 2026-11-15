#!/usr/bin/env python3
"""Adversarial tests for the #444 part (a) packaged-closure evidence checker."""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

import check_qemu_closure_evidence as checker


ROOT = pathlib.Path(__file__).resolve().parent.parent
CERTIFICATE_PATH = ROOT / "deploy/nixos/dev-trust/root-hash-dev-test.crt"
FLAKE_LOCK_PATH = ROOT / "deploy/nixos/flake.lock"
CERTIFICATE = CERTIFICATE_PATH.read_text(encoding="utf-8")
FLAKE_LOCK = json.loads(FLAKE_LOCK_PATH.read_text(encoding="utf-8"))
# Independent oracle: `openssl x509 -noout -subject -ext subjectKeyIdentifier`
# on the committed certificate, formatted by ADR-087 Part C.2.
DESCRIPTION = "PiglorOS public dev-test root-hash signing: bfe242fa5e161b8499d08a5bbe21d46726836d74"
HASH = "0123456789abcdfghijklmnpqrsvwxyz"


def store(name: str, digit: str = "a") -> str:
    return f"/nix/store/{HASH[:31]}{digit}-{name}"


PATHS = {
    "vm": store("nixos-vm"),
    "toplevel": store("nixos-system-piglor-qemu-evidence-26.05"),
    "kernel": store("linux-6.12.117"),
    "systemd": store("systemd-260.5"),
    "qemu": store("qemu-host-cpu-only-10.1.2"),
    "trustedCertificate": store("root-hash-dev-test.crt"),
}
SYSTEMD = PATHS["systemd"]
DAEMON = f"{SYSTEMD}/lib/systemd/systemd-mountfsd"
WORKER = f"{SYSTEMD}/lib/systemd/systemd-mountwork"
CMDLINE = (
    f"init={PATHS['toplevel']}/init loglevel=4 lsm=landlock,yama,bpf "
    "systemd.allow_userspace_verity=0 console=ttyS0\n"
)
NET_DEV = (
    "Inter-|   Receive                            |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes\n"
    "    lo:       0       0    0    0    0     0          0         0        0\n"
)
NS = "pid\tpid:[4026531836]\nuser\tuser:[4026531837]\nmnt\tmnt:[4026531841]\n"


def info(*names: str, paths: dict[str, str] = PATHS) -> str:
    return json.dumps({"version": 2, "storeDir": "/nix/store", "info": {
        paths[name].removeprefix("/nix/store/"): {"narHash": f"sha256-{name}"} for name in names
    }})


def with_paths(files: dict, **changes: str) -> dict[str, str]:
    """Record other store identities consistently on the host side."""
    paths = {**PATHS, **changes}
    files["host/store-paths.json"] = json.dumps(paths)
    files["host/path-info.json"] = info(*paths, paths=paths)
    files["host/toplevel-closure.json"] = info("toplevel", "kernel", "systemd", paths=paths)
    return paths


def qemu_argv(architecture: str, *extra: str) -> bytes:
    machine = {"x86_64": "accel=kvm:tcg", "aarch64": "virt,gic-version=max,accel=kvm:tcg"}
    argv = [f"{PATHS['qemu']}/bin/qemu-system-{architecture}", "-machine", machine[architecture],
            "-cpu", "max", "-name", "piglor-qemu-evidence", "-m", "2048",
            "-device", "virtio-rng-pci", "-virtfs", "local,path=/nix/store,mount_tag=nix-store",
            "-kernel", f"{PATHS['toplevel']}/kernel", "-initrd", f"{store('initrd')}/initrd",
            "-append", f"loglevel=4 init={PATHS['toplevel']}/init regInfo=/x console=ttyS0",
            "-machine", "accel=tcg", "-nic", "none", "-no-reboot", *extra]
    return b"".join(argument.encode() + b"\0" for argument in argv)


def valid_files(architecture: str) -> dict[str, bytes | str]:
    image = checker.ARCHITECTURES[architecture]
    files: dict[str, bytes | str] = {
        "host/flake-metadata.json": json.dumps({"locks": FLAKE_LOCK, "revision": "0" * 40}),
        "host/store-paths.json": json.dumps(PATHS),
        "host/path-info.json": info(*PATHS),
        "host/toplevel-closure.json": info("toplevel", "kernel", "systemd"),
        "host/system-trusted-keys.pem": CERTIFICATE,
        "host/runner": f"uname\tLinux 6.11.0-1018-azure #18 SMP {architecture}\ndev-kvm\tabsent\n",
        "host/serial-console.log": "[    0.000000] Booting Linux\n",
        "host/qemu-argv": qemu_argv(architecture),
        "host/qemu-exe": f"{PATHS['qemu']}/bin/qemu-system-{architecture}\n",
        "host/qemu-net-dev": NET_DEV,
        "host/vm-exit-status": "0\n",
        "guest/status": "complete\n",
        "guest/uname-machine": f"{architecture}\n",
        "guest/uname-release": "6.12.117\n",
        "guest/systemctl-version": "systemd 260 (260.5)\n+PAM +AUDIT -SELINUX\n",
        "guest/current-system": PATHS["toplevel"] + "\n",
        "guest/booted-system": PATHS["toplevel"] + "\n",
        "guest/booted-kernel": f"{PATHS['kernel']}/{image}\n",
        "guest/systemd-package": SYSTEMD + "\n",
        "guest/detect-virt-vm": "qemu\n",
        "guest/detect-virt-container": "none\n",
        "guest/container-markers": "/run/systemd/container\tabsent\n/run/host/container-manager\tabsent\n",
        "guest/proc-cmdline": CMDLINE,
        "guest/kernel-config": (
            "#\n# Automatically generated file; DO NOT EDIT.\n#\n"
            "CONFIG_DM_VERITY=m\nCONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y\n"
            "# CONFIG_MODULE_SIG is not set\n"
            f'CONFIG_SYSTEM_TRUSTED_KEYS="{PATHS["trustedCertificate"]}"\n\n'
        ),
        "guest/kernel-log": f"Loading compiled-in X.509 certificates\nLoaded X.509 cert '{DESCRIPTION}'\n",
        "guest/proc-keys": (
            "0d4a3c2e I------     1 perm 1f0b0000     0     0 keyring   .builtin_trusted_keys: 1\n"
            "1f2e3d4c I------     1 perm 1f030000     0     0 asymmetri "
            f"{DESCRIPTION}: X509.rsa 26836d74 []\n"
            "2a3b4c5d I------     1 perm 1f0b0000     0     0 keyring   .blacklist: empty\n"
        ),
        "guest/builtin-trusted-keys": (
            f"{0x0d4a3c2e}\tkeyring;0;0;1f0b0000;.builtin_trusted_keys\n"
            f"{0x1f2e3d4c}\tasymmetric;0;0;1f030000;{DESCRIPTION}\n"
        ),
        "guest/verity-d": "".join(
            f"{path}\tabsent\n" for path in [*checker.STATIC_VERITY_DIRS, f"{SYSTEMD}/lib/verity.d"]
        ),
        "guest/mountfsd-units": (
            "# /etc/systemd/system/systemd-mountfsd.service\n[Service]\n"
            f"ExecStart={DAEMON}\nNoNewPrivileges=yes\n"
            "# /etc/systemd/system/systemd-mountfsd.socket\n[Socket]\n"
            "ListenStream=/run/systemd/io.systemd.MountFileSystem\n"
            "# /etc/systemd/system/systemd-mountfsd.socket.d/overrides.conf\n[Unit]\n[Socket]\n"
        ),
        "guest/mountfsd-service-properties": (
            "Id=systemd-mountfsd.service\nActiveState=active\nSubState=running\nMainPID=310\n"
            "ControlGroup=/system.slice/systemd-mountfsd.service\n"
            "FragmentPath=/etc/systemd/system/systemd-mountfsd.service\nDropInPaths=\n"
            f"ExecStart={{ path={DAEMON} ; argv[]={DAEMON} }}\n"
            "Environment=\nEnvironmentFiles=\nPassEnvironment=\nUnsetEnvironment=\n"
        ),
        "guest/mountfsd-socket-properties": (
            "Id=systemd-mountfsd.socket\nActiveState=active\nSubState=listening\n"
            "FragmentPath=/etc/systemd/system/systemd-mountfsd.socket\n"
            "DropInPaths=/etc/systemd/system/systemd-mountfsd.socket.d/overrides.conf\n"
            "Listen=/run/systemd/io.systemd.MountFileSystem (Stream)\n"
        ),
        "guest/manager-environment": "LANG=C.UTF-8\nPATH=/run/current-system/sw/bin\n",
        "guest/pid1-namespaces": NS,
    }
    for pid, exe, environ in (
        ("310", DAEMON, b"LANG=C.UTF-8\0NOTIFY_SOCKET=/run/systemd/notify\0"),
        ("311", WORKER, b"LANG=C.UTF-8\0MOUNTFS_FIXED_WORKER=1\0"),
    ):
        files[f"guest/processes/{pid}/exe"] = exe + "\n"
        files[f"guest/processes/{pid}/environ"] = environ
        files[f"guest/processes/{pid}/namespaces"] = NS
    return files


def write(root: pathlib.Path, files: dict[str, bytes | str]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))


# --- Independent DER encoder for certificate-description cases ----------------


def der(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    length = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def oid(text: str) -> bytes:
    arcs = [int(arc) for arc in text.split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        while arc > 0x7F:
            arc >>= 7
            chunk.append(0x80 | (arc & 0x7F))
        body.extend(reversed(chunk))
    return der(0x06, bytes(body))


def certificate(subject: list[tuple[str, bytes]], serial: bytes, skid: bytes | None) -> str:
    name = der(0x30, b"".join(der(0x31, der(0x30, oid(o) + der(0x0C, v))) for o, v in subject))
    algorithm = der(0x30, oid("1.2.840.113549.1.1.11") + b"\x05\x00")
    fields = [der(0xA0, der(0x02, b"\x02")), der(0x02, serial), algorithm, name,
              der(0x30, der(0x17, b"260101000000Z") * 2), name,
              der(0x30, algorithm + der(0x03, b"\x00\x01"))]
    if skid is not None:
        extension = der(0x30, oid(checker.OID_SUBJECT_KEY_ID) + der(0x04, der(0x04, skid)))
        fields.append(der(0xA3, der(0x30, extension)))
    body = der(0x30, der(0x30, b"".join(fields)) + algorithm + der(0x03, b"\x00\x01"))
    encoded = base64.b64encode(body).decode()
    lines = [encoded[index:index + 64] for index in range(0, len(encoded), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def description_of(text: str) -> str:
    return checker.kernel_key_description(checker.pem_certificate(text))


CN, O, EMAIL = checker.OID_COMMON_NAME, checker.OID_ORGANIZATION, checker.OID_EMAIL


class CertificateDescriptionTests(unittest.TestCase):
    def test_committed_certificate_matches_the_openssl_oracle(self):
        self.assertEqual(description_of(CERTIFICATE), DESCRIPTION)

    def test_x509_fabricate_name_rules(self):
        skid = bytes.fromhex("00ff10")
        cases = [
            ([(CN, b"Release")], "Release: 00ff10"),
            ([(O, b"Piglor"), (CN, b"Piglor release")], "Piglor release: 00ff10"),
            ([(O, b"PiglorOS Project"), (CN, b"PiglorOS signing")], "PiglorOS signing: 00ff10"),
            ([(O, b"Example"), (CN, b"Release")], "Example: Release: 00ff10"),
            ([(O, b"Example")], "Example: 00ff10"),
            ([(EMAIL, b"root@example.org")], "root@example.org: 00ff10"),
            ([], ": 00ff10"),
            ([(CN, b"First"), (CN, b"Last")], "Last: 00ff10"),
            ([(CN, b"Release\0hidden")], "Release: 00ff10"),
        ]
        for subject, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(description_of(certificate(subject, b"\x01", skid)), expected)

    def test_serial_is_the_fallback_identifier(self):
        text = certificate([(CN, b"Release")], b"\x00\x80\x01", None)
        self.assertEqual(description_of(text), "Release: 008001")

    def test_malformed_certificates_are_refused(self):
        valid = certificate([(CN, b"Release")], b"\x01", b"\x01")
        der_bytes = base64.b64decode("".join(valid.splitlines()[1:-1]))
        broken = [
            "", valid.replace("CERTIFICATE", "PUBLIC KEY"), valid + valid, valid[:-30] + "\n",
        ]
        for text in broken:
            with self.subTest(text=text[:40]), self.assertRaises(checker.EvidenceError):
                description_of(text)
        for data in (der_bytes[:-1], der_bytes + b"\0", b"\x30\x80\x00\x00", b"\x31\x00",
                     der(0x30, der(0x02, b"\x01")), b"\x30\x85\x01\x00\x00\x00\x00"):
            with self.subTest(data=data[:8]), self.assertRaises(checker.EvidenceError):
                checker.kernel_key_description(data)
        for content in (b"", b"\x2a\x86"):
            with self.subTest(oid=content), self.assertRaises(checker.EvidenceError):
                checker.der_oid(content)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = pathlib.Path(self.directory.name)
        self.count = 0

    def evidence(self, architecture: str = "x86_64", change=None) -> pathlib.Path:
        self.count += 1
        root = self.base / str(self.count)
        files = valid_files(architecture)
        if change:
            change(files)
        write(root, files)
        return root

    def verdict(self, architecture: str = "x86_64", change=None) -> dict:
        return checker.check(self.evidence(architecture, change), architecture, CERTIFICATE, FLAKE_LOCK)

    def refuses(self, change, architecture: str = "x86_64") -> None:
        with self.assertRaises(checker.EvidenceError):
            self.verdict(architecture, change)

    def test_valid_evidence_holds_on_both_architectures(self):
        for architecture in ("x86_64", "aarch64"):
            with self.subTest(architecture=architecture):
                verdict = self.verdict(architecture)
                self.assertEqual(verdict["accelerator"], "tcg")
                self.assertEqual(verdict["certificate_key_description"], DESCRIPTION)
                self.assertEqual(verdict["kernel_config"]["dm_verity_keyring"], {
                    checker.VERITY_SIG: "y",
                    checker.VERITY_FALLBACKS[0]: "absent",
                    checker.VERITY_FALLBACKS[1]: "absent",
                })
                self.assertEqual(verdict["kernel_config"]["context"]["MODULE_SIG"], "n")
                self.assertEqual([m["type"] for m in verdict["builtin_trusted_keys"]], ["asymmetric"])
                self.assertEqual(verdict["mountfsd"]["processes"], {"310": DAEMON, "311": WORKER})
                self.assertEqual(verdict["nixpkgs"]["narHash"], checker.PINNED_NIXPKGS_NAR_HASH)
                self.assertEqual(verdict["kernel_command_line"], CMDLINE.rstrip("\n"))

    def test_sealed_evidence_can_be_checked_again(self):
        def sealed(files):
            files["checker-verdict.json"] = "{}"
            files["SHA256SUMS"] = "0  ./host/runner\n"
        self.assertEqual(self.verdict(change=sealed)["accelerator"], "tcg")

    def test_fallbacks_recorded_as_not_set_still_hold(self):
        def not_set(files):
            files["guest/kernel-config"] += "".join(
                f"# CONFIG_{name} is not set\n" for name in checker.VERITY_FALLBACKS)
        self.assertEqual(set(self.verdict(change=not_set)["kernel_config"]["dm_verity_keyring"].values()),
                         {"y", "n"})

    def test_other_builtin_keys_are_recorded_but_do_not_satisfy_the_tie(self):
        def extra(files):
            files["guest/proc-keys"] = files["guest/proc-keys"].replace("keys: 1", "keys: 2")
            files["guest/builtin-trusted-keys"] += "77\tasymmetric;0;0;1f030000;Build time autogenerated kernel key: 01\n"
        self.assertEqual(len(self.verdict(change=extra)["builtin_trusted_keys"]), 2)

    def test_inventory_refuses_missing_extra_and_non_regular_entries(self):
        def without_status(files):
            files.pop("guest/status")
        changes = [
            lambda f: f.pop("guest/verity-d"),
            lambda f: f.pop("host/qemu-argv"),
            lambda f: f.update({"guest/fabricated": "x"}),
            lambda f: f.update({"host/extra": "x"}),
            lambda f: f.update({"fabricated.json": "{}"}),
            lambda f: f.update({"SHA256SUMS/x": "{}"}),
            lambda f: f.pop("host/runner") and f.update({"host/runner.d/x": "x"}),
            lambda f: f.update({"guest/processes/abc/exe": DAEMON + "\n"}),
            lambda f: f.pop("guest/processes/311/environ"),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)
        root = self.evidence(change=without_status)
        os.symlink("/etc/hostname", root / "guest/status")
        with self.assertRaises(checker.EvidenceError):
            checker.check(root, "x86_64", CERTIFICATE, FLAKE_LOCK)

    def test_identity_fabrication_is_refused(self):
        other = store("nixos-system-other", "b")
        changes = [
            lambda f: f.update({"host/store-paths.json": json.dumps({**PATHS, "extra": other})}),
            lambda f: f.update({"host/store-paths.json": json.dumps({**PATHS, "vm": "/tmp/vm"})}),
            lambda f: f.update({"host/flake-metadata.json": json.dumps({"locks": {"nodes": {}}})}),
            lambda f: f.update({"host/path-info.json": info("vm", "toplevel", "kernel", "systemd", "qemu")}),
            lambda f: f.update({"host/path-info.json": json.dumps({PATHS["vm"]: {"narHash": "x"}})}),
            lambda f: f.update({"host/toplevel-closure.json": info("toplevel", "systemd")}),
            lambda f: f.update({"host/toplevel-closure.json": "not json"}),
            lambda f: f.update({"guest/current-system": other + "\n"}),
            lambda f: f.update({"guest/booted-system": other + "\n"}),
            lambda f: f.update({"guest/current-system": PATHS["toplevel"] + "\n\n"}),
            lambda f: f.update({"guest/booted-kernel": f"{PATHS['kernel']}/vmlinux\n"}),
            lambda f: f.update({"guest/systemd-package": store("systemd-260.4") + "\n"}),
            lambda f: f.update({"guest/systemctl-version": "systemd 260 (260.4)\n"}),
            lambda f: f.update({"guest/uname-release": "6.12.118\n"}),
            lambda f: f.update({"guest/uname-release": b"\xff\n"}),
            lambda f: f.update({"host/system-trusted-keys.pem": certificate([(CN, b"Other")], b"\1", b"\1")}),
            lambda f: with_paths(f, trustedCertificate=store("other.pem")),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_kernel_release_series_is_pinned(self):
        def kernel(release: str):
            def change(files):
                paths = with_paths(files, kernel=store(f"linux-{release}"))
                files["guest/uname-release"] = f"{release}\n"
                files["guest/booted-kernel"] = f"{paths['kernel']}/bzImage\n"
            return change
        self.assertEqual(self.verdict(change=kernel("6.12.118"))["kernel_release"], "6.12.118")
        self.refuses(kernel("6.18.63"))

    def test_flake_lock_must_pin_the_reviewed_nixpkgs(self):
        root = self.evidence()
        for change in (
            lambda lock: lock["nodes"]["nixpkgs"]["locked"].update(narHash="sha256-AAAA"),
            lambda lock: lock["nodes"]["nixpkgs"]["locked"].update(url="https://example.org/n.tar.gz"),
            lambda lock: lock["nodes"]["nixpkgs"]["locked"].update(lastModified=1),
            lambda lock: lock["nodes"]["root"].update(inputs={"nixpkgs": "nixpkgs", "x": "x"}),
        ):
            lock = json.loads(json.dumps(FLAKE_LOCK))
            change(lock)
            with self.subTest(change=change), self.assertRaises(checker.EvidenceError):
                checker.check(root, "x86_64", CERTIFICATE, lock)

    def test_runner_accelerator_and_network_are_verified(self):
        changes = [
            lambda f: f.update({"guest/uname-machine": "aarch64\n"}),
            lambda f: f.update({"host/runner": "uname\tLinux 6.11 aarch64\ndev-kvm\tabsent\n"}),
            lambda f: f.update({"host/runner": "uname\tLinux 6.11 x86_64\n"}),
            lambda f: f.update({"host/vm-exit-status": "124\n"}),
            lambda f: f.update({"guest/status": "partial\n"}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-machine", "accel=kvm:tcg")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-enable-kvm")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-accel", "kvm")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "--accel", "tcg")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-netdev", "user,id=n0")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-nic", "user")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-nic", "none")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"-nic\0none\0", b"")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-kernel", "/boot/vmlinuz")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                f"{PATHS['toplevel']}/kernel".encode(), f"{store('other')}/kernel".encode())}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                f"init={PATHS['toplevel']}/init".encode(), b"init=/bin/sh")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-append", "init=/bin/sh")}),
            lambda f: f.update({"host/qemu-net-dev": NET_DEV + "  eth0: 0 0 0 0 0 0 0 0 0\n"}),
            lambda f: f.update({"host/qemu-net-dev": NET_DEV.replace("lo:", "eth0:")}),
            lambda f: f.update({"host/runner": f["host/runner"] + "dev-kvm\tcrw-rw-rw- root kvm\n"}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-device", "virtio-net-pci,netdev=n0")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-machine", "accel=tcg,,kvm")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64")[:-1]}),
            lambda f: f.update({"host/qemu-argv": b"\0"}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"accel=tcg", b"accel=kvm")}),
            lambda f: f.update({"host/qemu-exe": "/usr/bin/qemu-system-x86_64\n"}),
            lambda f: f.update({"guest/detect-virt-vm": "kvm\n"}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_command_line_follows_the_strict_provider_rule(self):
        init = f"init={PATHS['toplevel']}/init "
        for line in (
            "console=ttyS0\n",
            "systemd.allow_userspace_verity=1\n",
            "systemd.allow_userspace_verity=0 systemd.allow_userspace_verity=0\n",
            "systemd.allow_userspace_verity=0 rd.systemd.allow_userspace_verity=1\n",
            "systemd.allow_userspace_verity=0 systemd.allow-userspace-verity=1\n",
            "systemd.allow_userspace_verity=0 systemd_allow_userspace_verity\n".replace("systemd_", "systemd."),
            "systemd.allow_userspace_verity=no\n",
            'systemd.allow_userspace_verity=0 init="/x y"\n',
            "systemd.allow_userspace_verity=0 init=/x\\y\n",
            "systemd.allow_userspace_verity=0 x='y'\n",
            "systemd.allow_userspace_verity=0 x=\x01\n",
            "systemd.allow_userspace_verity=0 x=\x7f\n",
            "systemd.allow_userspace_verity=0 x=é\n",
        ):
            with self.subTest(line=line):
                self.refuses(lambda f, line=line: f.update({"guest/proc-cmdline": init + line}))
        for line in ("systemd.allow_userspace_verity=0\n", "a\tsystemd.allow_userspace_verity=0\r\nb\n"):
            with self.subTest(line=line):
                self.verdict(change=lambda f, line=line: f.update({"guest/proc-cmdline": init + line}))
        for line in ("systemd.allow_userspace_verity=0\n", init + init + "systemd.allow_userspace_verity=0\n",
                     f"init={store('other')}/init systemd.allow_userspace_verity=0\n"):
            with self.subTest(line=line):
                self.refuses(lambda f, line=line: f.update({"guest/proc-cmdline": line}))

    def test_kernel_configuration_is_exact(self):
        sig = "CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y\n"
        changes = [
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"].replace(sig, "")}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"].replace(
                sig, "# CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG is not set\n")}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"] +
                                f"CONFIG_{checker.VERITY_FALLBACKS[0]}=y\n"}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"] +
                                f"CONFIG_{checker.VERITY_FALLBACKS[1]}=y\n"}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"] + sig}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"] + "garbage\n"}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"].replace(
                PATHS["trustedCertificate"], store("other.pem"))}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"].replace(
                f'"{PATHS["trustedCertificate"]}"', PATHS["trustedCertificate"])}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_builtin_keyring_tie_is_exact(self):
        keys = "guest/builtin-trusted-keys"
        proc = "guest/proc-keys"
        member = f"{0x1f2e3d4c}\tasymmetric;0;0;1f030000;{DESCRIPTION}\n"
        changes = [
            lambda f: f.update({proc: f[proc].replace(".builtin_trusted_keys", ".other")}),
            lambda f: f.update({proc: f[proc] + f[proc].splitlines(keepends=True)[0]}),
            lambda f: f.update({proc: f[proc].replace("keys: 1", "keys: 2")}),
            lambda f: f.update({proc: f[proc].replace("keys: 1", "keys")}),
            lambda f: f.update({keys: f[keys].replace(member, ""),
                                proc: f[proc].replace("keys: 1", "keys: empty")}),
            lambda f: f.update({keys: f[keys].replace("asymmetric;", "user;")}),
            lambda f: f.update({keys: f[keys].replace(DESCRIPTION, DESCRIPTION + "0")}),
            lambda f: f.update({keys: f[keys].replace(DESCRIPTION, DESCRIPTION.upper())}),
            lambda f: f.update({keys: f[keys] + member.replace(str(0x1f2e3d4c), "88"),
                                proc: f[proc].replace("keys: 1", "keys: 2")}),
            lambda f: f.update({keys: f[keys] + member.replace("asymmetric", "user").replace(str(0x1f2e3d4c), "88"),
                                proc: f[proc].replace("keys: 1", "keys: 2")}),
            lambda f: f.update({keys: f[keys] + member, proc: f[proc].replace("keys: 1", "keys: 2")}),
            lambda f: f.update({keys: member}),
            lambda f: f.update({keys: f[keys].replace(f"{0x0d4a3c2e}\t", "999\t")}),
            lambda f: f.update({keys: f[keys].replace(";0;0;1f030000;", ";0;0;1f030000")}),
            lambda f: f.update({keys: f[keys].replace("\t", " ")}),
            lambda f: f.update({keys: ""}),
            lambda f: f.update({"guest/kernel-log": "Loading compiled-in X.509 certificates\n"}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_every_verity_d_directory_is_recorded_and_empty(self):
        prefix = f"{SYSTEMD}/lib/verity.d"
        changes = [
            lambda f: f.update({"guest/verity-d": f["guest/verity-d"] + "/etc/verity.d/x.crt\tf\n"}),
            lambda f: f.update({"guest/verity-d": f["guest/verity-d"].replace(
                "/etc/verity.d\tabsent\n", "/etc/verity.d\tdirectory\n/etc/verity.d/a.crt\tf\n")}),
            lambda f: f.update({"guest/verity-d": f["guest/verity-d"].replace(f"{prefix}\tabsent\n", "")}),
            lambda f: f.update({"guest/verity-d": "".join(reversed(f["guest/verity-d"].splitlines(True)))}),
            lambda f: f.update({"guest/verity-d": f["guest/verity-d"].replace(
                "/run/verity.d\tabsent", "/run/verity.d\tregular file")}),
            lambda f: f.update({"guest/verity-d": f["guest/verity-d"].replace(prefix, store("systemd") + "/lib/verity.d")}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)
        self.verdict(change=lambda f: f.update({"guest/verity-d": f["guest/verity-d"].replace(
            "/run/verity.d\tabsent", "/run/verity.d\tdirectory")}))

    def test_mountfsd_environment_and_container_checks(self):
        service, units = "guest/mountfsd-service-properties", "guest/mountfsd-units"
        changes = [
            lambda f: f.update({service: f[service].replace("Environment=\n", "Environment=A=1\n")}),
            lambda f: f.update({service: f[service].replace("EnvironmentFiles=\n", "EnvironmentFiles=/e (ignore_errors=no)\n")}),
            lambda f: f.update({service: f[service].replace("PassEnvironment=\n", "PassEnvironment=X\n")}),
            lambda f: f.update({service: f[service].replace("DropInPaths=\n", "DropInPaths=/etc/x.conf\n")}),
            lambda f: f.update({service: f[service].replace("ActiveState=active", "ActiveState=failed")}),
            lambda f: f.update({service: f[service] + "Id=duplicate\n"}),
            lambda f: f.update({service: f[service] + "garbage\n"}),
            lambda f: f.update({"guest/mountfsd-socket-properties": f["guest/mountfsd-socket-properties"].replace(
                "ActiveState=active", "ActiveState=inactive")}),
            lambda f: f.update({units: f[units] + "Environment=SYSTEMD_VERITY_SHARING=1\n"}),
            lambda f: f.update({units: f[units] + " EnvironmentFile = /etc/mountfsd.env\n"}),
            lambda f: f.update({"guest/manager-environment": "SYSTEMD_PROC_CMDLINE=x\n"}),
            lambda f: f.update({"guest/manager-environment": "SYSTEMD_MOUNTFSD_IMAGE_POLICY_TRUSTED=x\n"}),
            lambda f: f.update({"guest/processes/311/environ": b"SYSTEMD_VERITY_SHARING=1\0"}),
            lambda f: f.update({"guest/processes/310/environ": b"SYSTEMD_MOUNTFSD_IMAGE_POLICY_UNTRUSTED=root=open\0"}),
            lambda f: f.update({"guest/processes/310/environ": b"SYSTEMD_PROC_CMDLINE=x\0"}),
            lambda f: f.update({"guest/processes/310/environ": b"A=1"}),
            lambda f: f.update({"guest/processes/311/exe": DAEMON + "\n"}),
            lambda f: f.update({"guest/processes/311/exe": "/usr/bin/sh\n"}),
            lambda f: f.update({service: f[service].replace("MainPID=310", "MainPID=311")}),
            lambda f: f.update({"guest/processes/311/namespaces": NS.replace("4026531836", "4026532000")}),
            lambda f: f.update({"guest/processes/311/namespaces": NS.replace("4026531837", "4026532000")}),
            lambda f: f.update({"guest/processes/311/namespaces": "pid\tpid:[4026531836]\n"}),
            lambda f: f.update({"guest/processes/311/namespaces": NS + "pid\tpid:[4026531836]\n"}),
            lambda f: f.update({"guest/pid1-namespaces": NS + "user\tuser:[4026531837]\n"}),
            lambda f: f.update({"guest/detect-virt-container": "systemd-nspawn\n"}),
            lambda f: f.update({"guest/container-markers": f["guest/container-markers"].replace(
                "container\tabsent", "container\tpresent")}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)
        mount_namespace = NS.replace("4026531841", "4026532111")
        self.verdict(change=lambda f: f.update({"guest/processes/310/namespaces": mount_namespace}))

    def test_cli_writes_one_verdict_and_refuses_bad_input(self):
        root = self.evidence()
        verdict = self.base / "verdict.json"
        command = [sys.executable, str(pathlib.Path(checker.__file__)), "--architecture", "x86_64",
                   "--certificate", str(CERTIFICATE_PATH), "--flake-lock", str(FLAKE_LOCK_PATH),
                   "--verdict", str(verdict), str(root)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(verdict.read_text())["architecture"], "x86_64")
        self.assertEqual(checker.main(command[2:]), 1)  # the verdict already exists
        for arguments in (
            ["--architecture", "riscv64"],
            ["--certificate", str(root / "missing.pem")],
            ["--flake-lock", str(CERTIFICATE_PATH)],
        ):
            changed = list(command[2:])
            changed[changed.index(arguments[0]) + 1] = arguments[1]
            changed[changed.index("--verdict") + 1] = str(self.base / f"v{len(arguments[1])}.json")
            with self.subTest(arguments=arguments):
                self.assertEqual(checker.main(changed), 1)


if __name__ == "__main__":
    unittest.main()
