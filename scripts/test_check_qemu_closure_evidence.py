#!/usr/bin/env python3
"""Adversarial tests for the #444 part (a) packaged-closure evidence checker."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import io
from contextlib import redirect_stderr

import check_qemu_closure_evidence as checker


ROOT = pathlib.Path(__file__).resolve().parent.parent
CERTIFICATE_PATH = ROOT / "deploy/nixos/dev-trust/root-hash-dev-test.crt"
FLAKE_LOCK_PATH = ROOT / "deploy/nixos/flake.lock"
CERTIFICATE = CERTIFICATE_PATH.read_text(encoding="utf-8")
FLAKE_LOCK = json.loads(FLAKE_LOCK_PATH.read_text(encoding="utf-8"))
# Independent oracle: `openssl x509 -noout -subject -ext subjectKeyIdentifier`
# on the committed certificate, formatted by ADR-087 Part C.2.
DESCRIPTION = "PiglorOS public dev-test root-hash signing: 0539d5095cd5ea12c02ab66d7328aa1351b9fe0d"
UNTRUSTED_PATH = ROOT / "deploy/nixos/dev-trust/root-hash-untrusted-dev-test.crt"
UNTRUSTED = UNTRUSTED_PATH.read_text(encoding="utf-8")
UNTRUSTED_DESCRIPTION = (
    "PiglorOS public dev-test untrusted root-hash signing: 681f6802dd22c3b9ec796fa30fa238c18d8e857d"
)
HASH = "0123456789abcdfghijklmnpqrsvwxyz"


def store(name: str, digit: str = "a") -> str:
    return f"/nix/store/{HASH[:31]}{digit}-{name}"


PATHS = {
    "vm": store("nixos-vm"),
    "toplevel": store("nixos-system-piglor-qemu-evidence-26.05"),
    "kernel": store("linux-6.12.117"),
    "kernelDev": store("linux-6.12.117-dev"),
    "systemd": store("systemd-260.5"),
    "qemu": store("qemu-host-cpu-only-10.1.2"),
    "trustedCertificate": store("root-hash-dev-test.crt"),
    "kernelConfig": store("linux-config-6.12.117"),
    "collector": store("piglor-qemu-evidence"),
    "collectorUnit": store("unit-piglor-qemu-evidence.service"),
    "conformance": store("pos-sandboxd-conformance-0"),
    "images": store("piglor-qemu-evidence-images"),
}
COMMIT_SHA = "1" * 40
PR_HEAD_SHA = "2" * 40
PROVENANCE = (
    f"git-head\t{COMMIT_SHA}\ngithub-sha\t{COMMIT_SHA}\npr-head-sha\t{PR_HEAD_SHA}\n"
    f"merge-parent\t{'4' * 40}\nmerge-parent\t{PR_HEAD_SHA}\n" + "".join(
        f"file\t{name}\t{hashlib.sha256((ROOT / name).read_bytes()).hexdigest()}\n"
        for name in checker.PROVENANCE_FILES))
SYSTEMD = PATHS["systemd"]
DAEMON = f"{SYSTEMD}/lib/systemd/systemd-mountfsd"
WORKER = f"{SYSTEMD}/lib/systemd/systemd-mountwork"
CMDLINE = (
    f"init={PATHS['toplevel']}/init loglevel=4 lsm=landlock,yama,bpf "
    "systemd.allow_userspace_verity=0 console=ttyS0\n"
)
MOUNTINFO = (
    "22 1 0:21 / / rw,relatime shared:1 - tmpfs tmpfs rw,mode=755\n"
    "23 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=4096k\n"
    "30 22 0:30 / /nix/.ro-store rw,relatime shared:9 - 9p nix-store rw,cache=loose,trans=virtio\n"
    "31 22 0:31 / /nix/.rw-store rw,relatime shared:10 - tmpfs tmpfs rw,mode=755\n"
    "32 22 0:32 / /nix/store ro,relatime shared:11 - overlay overlay rw,lowerdir=/nix/.ro-store\n"
    "40 22 0:40 / /tmp/xchg rw,relatime shared:20 - 9p xchg rw,trans=virtio\n"
)
NET_DEV = (
    "Inter-|   Receive                            |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes\n"
    "    lo:       0       0    0    0    0     0          0         0        0\n"
)
NS = "pid\tpid:[4026531836]\nuser\tuser:[4026531837]\nmnt\tmnt:[4026531841]\n"


CLOSURE = ("toplevel", "kernel", "systemd", "collector", "collectorUnit", "conformance", "images")


INITRD = store("initrd-linux-6.12.117", "c")


def info(*names: str, paths: dict[str, str] = PATHS) -> str:
    # The kernel's outputs share one derivation; every other path has its own.
    entries = {paths[name].removeprefix("/nix/store/"): {
        "narHash": f"sha256-{name}",
        "deriver": f"{HASH}-{'linux-6.12.117' if name.startswith('kernel') else name}.drv",
    } for name in names}
    if "toplevel" in names and len(names) > 1:  # a toplevel closure also holds its initrd
        entries[INITRD.removeprefix("/nix/store/")] = {"narHash": "sha256-initrd"}
    return json.dumps({"version": 2, "storeDir": "/nix/store", "info": entries})


def with_paths(files: dict, **changes: str) -> dict[str, str]:
    """Record other store identities consistently on the host side."""
    paths = {**PATHS, **changes}
    files["host/store-paths.json"] = json.dumps(paths)
    files["host/path-info.json"] = info(*paths, paths=paths)
    files["host/toplevel-closure.json"] = info(*CLOSURE, paths=paths)
    return paths


def qemu_argv(architecture: str, *extra: str) -> bytes:
    # The derived runner: qemu-vm's -machine without its kvm:tcg list, then -accel tcg.
    machine = {"x86_64": [], "aarch64": ["-machine", "virt,gic-version=max"]}
    # qemu-vm's aarch64 input and display devices, as recorded on the hosted runner.
    devices = {"x86_64": ["-device", "virtio-keyboard", "-usb", "-device", "usb-tablet,bus=usb-bus.0"],
               "aarch64": ["-device", "virtio-keyboard", "-device", "virtio-gpu-pci",
                                         "-device", "usb-ehci,id=usb0", "-device", "usb-kbd",
                                         "-device", "usb-tablet"]}
    argv = [f"{PATHS['qemu']}/bin/qemu-system-{architecture}", *machine[architecture],
            "-accel", "tcg", "-cpu", "max", "-name", "piglor-qemu-evidence", "-m", "2048", "-smp", "2",
            "-device", "virtio-rng-pci", "-virtfs", "local,path=/nix/store,security_model=none,mount_tag=nix-store",
            "-virtfs", "local,path=/tmp/qemu-evidence.AbCdEf0123/xchg,security_model=none,mount_tag=xchg",
            "-virtfs", "local,path=/tmp/qemu-evidence.AbCdEf0123/xchg,security_model=none,mount_tag=shared",
            *devices[architecture],
            "-kernel", f"{PATHS['toplevel']}/kernel", "-initrd", f"{INITRD}/initrd",
            "-append", f"loglevel=4 init={PATHS['toplevel']}/init regInfo=/x console=ttyS0",
            "-nographic", "-nic", "none", "-no-reboot", "-qmp", "unix:qmp.sock,server=on,wait=off", *extra]
    return b"".join(argument.encode() + b"\0" for argument in argv)


def valid_files(architecture: str) -> dict[str, bytes | str]:
    image = checker.ARCHITECTURES[architecture]
    files: dict[str, bytes | str] = {
        "host/flake-metadata.json": json.dumps({"locks": FLAKE_LOCK, "revision": "0" * 40}),
        "host/store-paths.json": json.dumps(PATHS),
        "host/path-info.json": info(*PATHS),
        "host/toplevel-closure.json": info(*CLOSURE),
        "host/provenance": PROVENANCE,
        "host/system-trusted-keys.pem": CERTIFICATE,
        "host/system-certificate-list": checker.pem_certificate(CERTIFICATE),
        "host/runner": f"uname\tLinux 6.11.0-1018-azure #18 SMP {architecture}\ndev-kvm\tabsent\n",
        "host/serial-console.log": "[    0.000000] Booting Linux\n"
                                   "\x1b]3008;start=1;bootid=5f431e7d06ad4bf8a0985e35ceb5569a;pid=1\x1b\\\n",
        "host/qemu-argv": qemu_argv(architecture),
        "host/qemu-exe": f"{PATHS['qemu']}/bin/qemu-system-{architecture}\n",
        "host/qemu-net-dev": NET_DEV,
        "host/vm-exit-status": "0\n",
        "host/qemu-query-kvm.json": '{"return": {"enabled": false, "present": true}}\n',
        "host/vm-cleanup": "qemu-process\texited\nwork-directory\tremoved\n",
        "guest/boot-id": "5f431e7d-06ad-4bf8-a098-5e35ceb5569a\n",
        "guest/mountinfo": MOUNTINFO,
        "guest/status": "complete\n",
        "guest/collector": f"{PATHS['collector']}/bin/piglor-qemu-evidence\n",
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
    files["host/kernel-config"] = files["guest/kernel-config"]
    files.update(case_files())
    files.update(executable_files(architecture))
    files.update(network_files())
    files.update(daemon_files())
    for pid, exe, environ in (
        ("310", DAEMON, b"LANG=C.UTF-8\0NOTIFY_SOCKET=/run/systemd/notify\0"),
        ("311", WORKER, b"LANG=C.UTF-8\0MOUNTFS_FIXED_WORKER=1\0"),
    ):
        files[f"guest/processes/{pid}/exe"] = exe + "\n"
        files[f"guest/processes/{pid}/environ"] = environ
        files[f"guest/processes/{pid}/namespaces"] = NS
    return files


# --- Part (b) case records -------------------------------------------------------

ROOT_HASH, SALT = "ab" * 32, "cd" * 32
IMAGES = PATHS["images"]
ATTEMPT = "/run/pigloros/sandbox/attempts/" + "e" * 32 + "/root"
BACKING = "/var/lib/pigloros/sandbox/images/" + "f" * 64
MAPPER = "root-8a5cfdc4b2c35aa0"
HELD_DEVICES = (
    f"loop\tloop0\t{BACKING}\t{BACKING}\t7:0\tloop0p1,loop0p2,loop0p3\n"
    f"dm\tdm-0\t{MAPPER}\tCRYPT-VERITY-8a5cfdc4b2c35aa0-{MAPPER}\t253:0\tloop0p1,loop0p2\n"
)
TABLE = (f"{MAPPER}: 0 1136 verity 1 7:1 7:2 4096 4096 142 1 sha256 {ROOT_HASH} {SALT} "
         "2 root_hash_sig_key_desc cryptsetup:8a5cfdc4\n")
READBACK = checker.readback_bytes()
RUNTIME_AFTER = ("\td\t700\nsandbox\td\t700\nsandbox/attempts\td\t700\n"
                 "sandbox/registry\td\t700\nsandbox/registry/activation\tf\t600\n")
REPLY = json.dumps({
    "partitions": [{"designator": "root", "writable": False, "growFileSystem": False,
                    "partitionNumber": 1, "architecture": "x86-64", "fileSystemType": "erofs",
                    "size": 581632, "offset": 20480, "mountFileDescriptor": 0, "mountPoint": ["/"]}],
    "singleFileSystem": False, "imagePolicy": "root=signed:=absent",
    "imageSize": 0, "sectorSize": 512, "imageName": "piglor-evidence-image",
}, indent=4) + "\n"


def ddi(root_hash: str = ROOT_HASH, salt: str = SALT, version: int = 1, hash_type: int = 1,
        salt_size: int = 32, adapter: bytes | None = None, extra: bytes = b"") -> bytes:
    """A minimal three-partition GPT image: data, a verity superblock and the
    root-verity-sig JSON, at 512-byte sectors."""
    image = bytearray(512 * 8)
    header = bytearray(92)
    header[:8] = b"EFI PART"
    struct.pack_into("<QII", header, 72, 2, 3, 128)
    image[512:604] = header
    for index, (first, last) in enumerate(((5, 5), (6, 6), (7, 7))):
        entry = bytearray(128)
        entry[:16] = bytes([index + 1]) * 16
        struct.pack_into("<QQ", entry, 32, first, last)
        image[1024 + 128 * index:1024 + 128 * (index + 1)] = entry
    superblock = bytearray(512)
    superblock[:8] = b"verity\0\0"
    struct.pack_into("<II", superblock, 8, version, hash_type)
    struct.pack_into("<H", superblock, 80, salt_size)
    superblock[88:120] = bytes.fromhex(salt)
    image[6 * 512:7 * 512] = superblock
    signature = json.dumps({"rootHash": root_hash, "signature": "AA=="}).encode()
    image[7 * 512:7 * 512 + len(signature)] = signature
    return bytes(image) + erofs_file(X86_ADAPTER if adapter is None else adapter) + extra


def erofs_file(data: bytes) -> bytes:
    """How mkfs.erofs stores an uncompressed file: whole blocks contiguously,
    then the trailing partial block inline after the next inode, so the file
    never occurs contiguously unless its size is a multiple of the block."""
    whole = len(data) - len(data) % 4096
    return data[:whole] + b"\0inode\0" + data[whole:]


TAMPERED_OFFSET = 5 * 512 + 10


def tampered_ddi(adapter: bytes | None = None, extra: bytes = b"") -> bytes:
    image = bytearray(ddi(adapter=adapter, extra=extra))
    image[TAMPERED_OFFSET] ^= 0x01
    return bytes(image)


def static_elf(machine: int, tag: bytes, *, interpreter: bool = False, size: int = 200_000) -> bytes:
    """A minimal 64-bit ELF header and two program headers, then tagged filler."""
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 3, machine, 1)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<HH", header, 54, 56, 2)
    headers = bytearray(112)
    # One PT_LOAD that maps the whole file at 0x400000, with the entry point
    # just after the headers.
    total = 176 + size
    struct.pack_into("<IIQQQQQQ", headers, 0, 1, 5, 0, 0x400000, 0x400000, total, total, 4096)
    struct.pack_into("<Q", header, 24, 0x400000 + 176)
    # PT_INTERP names the loader of a dynamic executable; PT_NOTE does not.
    struct.pack_into("<I", headers, 56, 3 if interpreter else 4)
    # Non-repeating filler, so that no part of the file occurs elsewhere.
    return bytes(header + headers) + tag + hashlib.shake_256(tag).digest(size - len(tag))


X86_ADAPTER = static_elf(62, b"adapter")


def elf_defects() -> list[bytes]:
    """Adapters that are not loadable static x86-64 executables, each wrong in one way."""
    machine = checker.ELF_MACHINES["x86_64"]

    def patched(offset: int, data: bytes) -> bytes:
        return X86_ADAPTER[:offset] + data + X86_ADAPTER[offset + len(data):]

    return [
        # The 7-byte stand-in the staged SIM1 used to name, a script, and truncations: below the
        # size floor, and above it with the headers intact.
        b"adapter", b"#!/bin/sh\n" + bytes(200_000), X86_ADAPTER[:99_999], X86_ADAPTER[:150_000],
        # A wrong class, byte order or ident version.
        patched(4, b"\x01"), patched(5, b"\x02"), patched(6, b"\x09"),
        # Another architecture, a relocatable object and a wrong ELF version.
        static_elf(checker.ELF_MACHINES["aarch64"], b"adapter"), patched(16, struct.pack("<H", 1)),
        patched(20, struct.pack("<I", 9)),
        # Dynamically linked: no loader exists inside the image's root.
        static_elf(machine, b"adapter", interpreter=True),
        # Nothing to load: no program headers, or none of type PT_LOAD.
        patched(56, struct.pack("<H", 0)), patched(64, struct.pack("<I", 4)),
        # A program header table beyond the file, or too small an entry.
        patched(32, struct.pack("<Q", 10**9)), patched(54, struct.pack("<H", 8)),
        # An entry point outside every segment, and a segment larger than the file.
        patched(24, struct.pack("<Q", 0x10)), patched(96, struct.pack("<Q", 300_000)),
    ]
# The raw reply's imageSize is the positive image's length, adapter included.
IMAGE_SIZE = len(ddi())
REPLY = REPLY.replace('"imageSize": 0', f'"imageSize": {IMAGE_SIZE}')


def executable_files(architecture: str, adapter: bytes | None = None) -> dict[str, bytes]:
    """The architecture's adapter, and the images that carry it."""
    machine = checker.ELF_MACHINES[architecture]
    adapter = static_elf(machine, b"adapter") if adapter is None else adapter
    return {
        "host/images/adapter": adapter,
        "host/images/positive.raw": ddi(adapter=adapter),
        "host/images/wrong-key.raw": ddi(adapter=adapter),
        "host/images/tampered.raw": tampered_ddi(adapter),
    }


def case_files() -> dict[str, bytes | str]:
    files: dict[str, bytes | str] = {
        "host/images/positive.raw": ddi(),
        "host/images/tampered.raw": tampered_ddi(),
        "host/images/wrong-key.raw": ddi(),
        "host/images/tampered-offset": f"{TAMPERED_OFFSET}\n",
        "host/images/positive.der": checker.pem_certificate(CERTIFICATE),
        "host/images/wrong-key.der": checker.pem_certificate(UNTRUSTED),
        "host/images/root-hash.txt": ROOT_HASH,
        "guest/cases/verity-d-planted": "/run/verity.d/piglor-untrusted.crt\tf\n",
        "guest/cases/kernel-log": "device-mapper: verity: 7:1: data block 7 is corrupted\n",
        "guest/cases/mountfsd-log": "[   12.000000] piglor-qemu-evidence systemd-mountwork[311]: Mounted image.\n",
        "guest/cases/mountfsd-reply/devices-before": "",
        "guest/cases/mountfsd-reply/reply": REPLY,
        "guest/cases/mountfsd-reply/stderr": "",
        "guest/cases/mountfsd-reply/status": "0\n",
        "guest/cases/mountfsd-reply/timing": "mountimage-seconds\t71.25\n",
        "guest/cases/mountfsd-reply/devices-after": "",
    }
    for case, image, signer, description in (
        ("positive", "positive", "positive", DESCRIPTION),
        ("tampered", "tampered", "tampered", DESCRIPTION),
        ("wrong-key", "wrong-key", "wrong-key", UNTRUSTED_DESCRIPTION),
        ("verity-d", "wrong-key", "wrong-key", UNTRUSTED_DESCRIPTION),
    ):
        base = f"guest/cases/{case}"
        files.update({
            f"{base}/arguments": (f"{IMAGES}/{image}.raw\n{IMAGES}/{signer}.der\n{description}\n"
                                  f"{IMAGES}/adapter\nhonest\n"),
            f"{base}/driver-stderr": "",
            f"{base}/driver-status": "0\n",
            f"{base}/timing": "activation-seconds\t12.50\n",
            f"{base}/devices-before": "",
            f"{base}/devices-after": "",
            f"{base}/runtime-after": RUNTIME_AFTER,
        })
        if case in checker.MOUNTED_CASES:
            whole = (f"0\t{hashlib.sha256(READBACK).hexdigest()}" if case == "positive"
                     else "1\tsha256sum: -: Input/output error")
            files.update({
                f"{base}/report": f"activation\tmounted\t1234\t{ATTEMPT}\nrelease\tdetached\nremoval\tremoved\n",
                f"{base}/devices-held": HELD_DEVICES,
                f"{base}/mountinfo-held": MOUNTINFO + (
                    f"90 22 253:0 / {ATTEMPT} ro,relatime shared:50 - erofs /proc/self/fd/20 ro\n"),
                f"{base}/dm-table-held": TABLE,
                f"{base}/readback": (f"file\t{whole}\n"
                                     f"block-0\t0\t{hashlib.sha256(READBACK[:4096]).hexdigest()}\n"),
            })
        else:
            files[f"{base}/report"] = "activation\trefused\tMethodRejected\nrelease\tnone\nremoval\tremoved\n"
    return files


INIT_NETNS = "net:[4026531840]"
UNIT_NETNS = "net:[4026532200]"
LINK_LO = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
def link(index: int, name: str, kind: str) -> str:
    return (f"{index}: {name}@NONE: <NOARP> mtu 1480 qdisc noop state DOWN mode DEFAULT group default "
            f"qlen 1000\\    link/{kind} 0.0.0.0 brd 0.0.0.0\n")


LINK_TUNL = link(2, "tunl0", "ipip")
FALLBACKS = LINK_TUNL + link(3, "sit0", "sit") + link(4, "ip6tnl0", "tunnel6") + link(5, "gre0", "gre")
MODULES = "".join(f"{name} 12288 0 - Live 0x0000000000000000\n" for name in ("ipip", "sit", "ip6_tunnel", "ip_gre"))
ADDRESSES = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
             "1: lo    inet6 ::1/128 scope host noprefixroute \\       valid_lft forever preferred_lft forever\n")
ROUTES4 = ("local 127.0.0.0/8 dev lo table local proto kernel scope host src 127.0.0.1\n"
           "local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1\n"
           "broadcast 127.255.255.255 dev lo table local proto kernel scope link src 127.0.0.1\n")
ROUTES6 = ("local ::1 dev lo table local proto kernel metric 0 pref medium\n"
           "multicast ff00::/8 dev lo table local proto kernel metric 256 pref medium\n")


def network_files() -> dict[str, bytes | str]:
    files: dict[str, bytes | str] = {
        "guest/network/boot-sysctl": "0\n",
        "guest/network/init-netns": INIT_NETNS + "\n",
        "guest/network/init-links": LINK_LO + FALLBACKS,
        "guest/network/modules": MODULES,
    }
    for case, value in checker.NETWORK_CASES.items():
        base = f"guest/network/{case}"
        files.update({
            f"{base}/sysctl": f"{value}\n", f"{base}/status": "0\n", f"{base}/netns": UNIT_NETNS + "\n",
            f"{base}/stderr": "", f"{base}/journal": "Nov 25 piglor-network: Finished.\n",
            f"{base}/links": LINK_LO + (FALLBACKS if value == "0" else ""),
            f"{base}/addrs": ADDRESSES, f"{base}/routes4": ROUTES4, f"{base}/routes6": ROUTES6,
        })
    return files


PROVIDER_BINARY = "/var/lib/pigloros/sandbox/providers/" + "ab" * 32
RUNTIME_PROPERTIES = (
    "Id=piglor-sandbox-runtime.service\nActiveState=active\nSubState=running\nMainPID=412\n"
    "Type=notify\nNotifyAccess=main\nExitType=main\nKillMode=control-group\nRestart=no\n"
    "CollectMode=inactive-or-failed\nUMask=0077\nStandardInput=null\nTimeoutStartUSec=30s\n"
    f"ExecStart={{ path={PROVIDER_BINARY} ; argv[]={PROVIDER_BINARY} provider-runtime ; ignore_errors=no ; "
    "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n"
)


def daemon_files() -> dict[str, bytes | str]:
    base = "guest/daemon/start"
    return {
        f"{base}/stage-report": f"staged\t{PROVIDER_BINARY}\nunstaged\n", f"{base}/stage-stderr": "",
        f"{base}/stage-status": "0\n", f"{base}/start-status": "0\n", f"{base}/stop-status": "0\n",
        f"{base}/runtime-properties": RUNTIME_PROPERTIES, f"{base}/runtime-exe": PROVIDER_BINARY + "\n",
        f"{base}/runtime-tree": "\td\t700\nsandbox\td\t700\nprovider-execute.sock\ts\t600\n"
                               "provider-control.sock\ts\t600\n",
        f"{base}/runtime-log": "[ 100.0] piglor-sandbox-runtime[412]: ready\n",
    }


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


# --- Independent ELF64 writer for the certificate-list extraction ------------

LIST_ADDRESS, SIZE_ADDRESS = 0xFFFFFFFF83000000, 0xFFFFFFFF83001000


def vmlinux(listed: bytes, length: int | None = None, symbols=None, symtab: bool = True,
            size_kind: int = 1, padding: int = 0) -> bytes:
    """A little-endian ELF64 image: .init.rodata holds the list, .rodata its
    64-bit length; .symtab and .strtab name them (section indexes 1 and 2).
    PADDING bytes precede each symbol inside its section."""
    length = len(listed) if length is None else length
    symbols = symbols if symbols is not None else [
        ("system_certificate_list", 1, LIST_ADDRESS + padding),
        ("system_certificate_list_size", 2, SIZE_ADDRESS + padding)]
    strings = b"\0" + b"".join(name.encode() + b"\0" for name, _, _ in symbols)
    table, offset = bytearray(24), 1
    for name, section, address in symbols:
        table += struct.pack("<IBBHQQ", offset, 0x10, 0, section, address, 0)
        offset += len(name) + 1
    blobs = [b"\xdd" * padding + listed + b"\xee" * 16, b"\xdd" * padding + struct.pack("<Q", length),
             bytes(table), strings]
    position, offsets = 64, []
    for blob in blobs:
        offsets.append(position)
        position += len(blob)
    headers = [bytes(64),
               struct.pack("<IIQQQQIIQQ", 0, 1, 0, LIST_ADDRESS, offsets[0], len(blobs[0]), 0, 0, 1, 0),
               struct.pack("<IIQQQQIIQQ", 0, size_kind, 0, SIZE_ADDRESS, offsets[1], len(blobs[1]), 0, 0, 8, 0)]
    if symtab:
        headers.append(struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, offsets[2], len(blobs[2]), 4, 1, 8, 24))
    headers.append(struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, offsets[3], len(blobs[3]), 0, 0, 1, 0))
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, position, 0, 64, 0, 0, 64, len(headers), 0)
    return header + b"".join(blobs) + b"".join(headers)


class CertificateListTests(unittest.TestCase):
    DER = checker.pem_certificate(CERTIFICATE)

    def test_the_list_is_read_through_the_elf_symbols(self):
        self.assertEqual(checker.certificate_list(vmlinux(self.DER)), self.DER)
        # The recorded length decides, so trailing bytes are copied, not hidden.
        self.assertEqual(checker.certificate_list(vmlinux(self.DER, len(self.DER) + 4)),
                         self.DER + b"\xee" * 4)
        # Symbols inside their sections are read at their offset from sh_addr.
        self.assertEqual(checker.certificate_list(vmlinux(self.DER, padding=0x10)), self.DER)

    def test_malformed_or_stripped_images_are_refused(self):
        stripped = vmlinux(self.DER, symtab=False)
        cases = {
            "not ELF": b"MZ" + vmlinux(self.DER)[2:],
            "stripped": stripped,
            "symbol absent": vmlinux(self.DER, symbols=[("system_certificate_list_size", 2, SIZE_ADDRESS)]),
            "symbol twice": vmlinux(self.DER, symbols=[
                ("system_certificate_list", 1, LIST_ADDRESS), ("system_certificate_list", 1, LIST_ADDRESS),
                ("system_certificate_list_size", 2, SIZE_ADDRESS)]),
            "undefined symbol": vmlinux(self.DER, symbols=[
                ("system_certificate_list", 0, LIST_ADDRESS), ("system_certificate_list_size", 2, SIZE_ADDRESS)]),
            "length past the section": vmlinux(self.DER, len(self.DER) + 17),
            "offset list past the section": vmlinux(self.DER, len(self.DER) + 17, padding=0x10),
            "offset size past the section": vmlinux(self.DER, symbols=[
                ("system_certificate_list", 1, LIST_ADDRESS + 0x10),
                ("system_certificate_list_size", 2, SIZE_ADDRESS + 0x14)], padding=0x10),
            "address before the section": vmlinux(self.DER, symbols=[
                ("system_certificate_list", 1, LIST_ADDRESS - 1), ("system_certificate_list_size", 2, SIZE_ADDRESS)]),
            "length in a NOBITS section": vmlinux(self.DER, size_kind=checker.SHT_NOBITS),
            "section headers cut off": vmlinux(self.DER)[:-10],
        }
        for case, image in cases.items():
            with self.subTest(case=case), self.assertRaises(checker.EvidenceError):
                checker.certificate_list(image)

    def test_extract_cli_writes_the_list_once_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = pathlib.Path(directory)
            (base / "vmlinux").write_bytes(vmlinux(self.DER))
            (base / "stripped").write_bytes(vmlinux(self.DER, symtab=False))
            (base / "short").write_bytes(b"\x7fELF\x02\x01")
            command = [sys.executable, str(pathlib.Path(checker.__file__)), "extract-certificate-list",
                       str(base / "vmlinux"), str(base / "list")]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((base / "list").read_bytes(), self.DER)
            for arguments, code in (
                ([str(base / "vmlinux"), str(base / "list")], 1),  # never overwrites
                ([str(base / "missing"), str(base / "a")], 1),
                ([str(base / "stripped"), str(base / "b")], 1),
                ([str(base / "short"), str(base / "c")], 1),
                ([str(base / "vmlinux")], 2),
            ):
                with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                    self.assertEqual(checker.main(["extract-certificate-list", *arguments]), code)
            self.assertFalse((base / "a").exists() or (base / "b").exists() or (base / "c").exists())


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
        store_config = files["host/kernel-config"]
        if change:
            change(files)
        if files.get("host/kernel-config") == store_config and "guest/kernel-config" in files:
            # A guest kernel-config case models a different store kernel too,
            # so that only the option under test differs.
            files["host/kernel-config"] = files["guest/kernel-config"]
        write(root, files)
        return root

    def verdict(self, architecture: str = "x86_64", change=None) -> dict:
        return checker.check(self.evidence(architecture, change), architecture, CERTIFICATE, FLAKE_LOCK,
                             untrusted_certificate=UNTRUSTED)

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

    def test_sealed_evidence_can_be_checked_again_against_its_manifest(self):
        def seal(edit=None):
            def change(files):
                files["checker-verdict.json"] = "{}"
                digests = {f"./{name}": hashlib.sha256(
                    content if isinstance(content, bytes) else content.encode()).hexdigest()
                    for name, content in files.items()}
                lines = [f"{digest}  {name}" for name, digest in sorted(digests.items())]
                if edit:
                    lines = edit(lines)
                files["SHA256SUMS"] = "".join(line + "\n" for line in lines)
            return change
        self.assertEqual(self.verdict(change=seal())["accelerator"], "tcg")
        for edit in (
            lambda lines: lines[1:],
            lambda lines: [*lines, lines[0]],
            lambda lines: [*lines, "0" * 64 + "  ./host/missing"],
            lambda lines: ["0" * 64 + lines[0][64:], *lines[1:]],
            lambda lines: [lines[0].replace("  ", " "), *lines[1:]],
        ):
            with self.subTest(edit=edit):
                self.refuses(seal(edit))
        def tampered(files):
            seal()(files)
            files["guest/status"] = "complete\n\n"
        self.refuses(tampered)

    def test_module_signing_must_be_off(self):
        def module_sig(value):
            def change(files):
                files["guest/kernel-config"] = files["guest/kernel-config"].replace(
                    "# CONFIG_MODULE_SIG is not set\n", value)
            return change
        self.assertEqual(self.verdict(change=module_sig(""))["kernel_config"]["context"]["MODULE_SIG"], "absent")
        for value in ("CONFIG_MODULE_SIG=y\n", "CONFIG_MODULE_SIG=m\n"):
            with self.subTest(value=value), self.assertRaisesRegex(
                    checker.EvidenceError, "signing_key.x509 into system_certificate_list"):
                self.verdict(change=module_sig(value))

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
            checker.check(root, "x86_64", CERTIFICATE, FLAKE_LOCK, untrusted_certificate=UNTRUSTED)

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

    def test_evidence_is_bound_to_the_tested_commit_and_inputs(self):
        name = checker.PROVENANCE_FILES[0]
        line = next(l for l in PROVENANCE.splitlines() if l.startswith(f"file\t{name}\t"))
        changes = [
            lambda f: f.update({"host/provenance": PROVENANCE.replace(f"github-sha\t{COMMIT_SHA}", "github-sha\t" + "3" * 40)}),
            lambda f: f.update({"host/provenance": PROVENANCE.replace(f"pr-head-sha\t{PR_HEAD_SHA}\n", "")}),
            lambda f: f.update({"host/provenance": PROVENANCE.replace(PR_HEAD_SHA, "main")}),
            lambda f: f.update({"host/provenance": PROVENANCE + f"git-head\t{COMMIT_SHA}\n"}),
            lambda f: f.update({"host/provenance": PROVENANCE.replace(line + "\n", "")}),
            lambda f: f.update({"host/provenance": PROVENANCE + line + "\n"}),
            lambda f: f.update({"host/provenance": PROVENANCE.replace(line, line[:-64] + "0" * 64)}),
            lambda f: f.update({"host/provenance": PROVENANCE + "file\tREADME.md\t" + "0" * 64 + "\n"}),
            lambda f: f.update({"host/provenance": PROVENANCE + "garbage\n"}),
            lambda f: f.update({"host/provenance": PROVENANCE.replace(f"merge-parent\t{PR_HEAD_SHA}\n", "")}),
            lambda f: f.update({"host/provenance": PROVENANCE.replace(f"merge-parent\t{PR_HEAD_SHA}", "merge-parent\t" + "5" * 40)}),
            lambda f: f.update({"host/provenance": PROVENANCE + f"merge-parent\t{PR_HEAD_SHA}\n"}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)
        with tempfile.TemporaryDirectory() as directory:
            repository = pathlib.Path(directory)
            for other in checker.PROVENANCE_FILES:
                (repository / other).parent.mkdir(parents=True, exist_ok=True)
                (repository / other).write_bytes((ROOT / other).read_bytes())
            checker.check(self.evidence(), "x86_64", CERTIFICATE, FLAKE_LOCK, repository,
                          untrusted_certificate=UNTRUSTED)
            (repository / name).write_bytes(b"# edited after the run\n")
            with self.assertRaises(checker.EvidenceError):
                checker.check(self.evidence(), "x86_64", CERTIFICATE, FLAKE_LOCK, repository,
                          untrusted_certificate=UNTRUSTED)

    def test_the_compiled_in_list_must_be_exactly_the_certificate(self):
        der = checker.pem_certificate(CERTIFICATE)
        self.assertEqual(self.verdict()["compiled_in_certificate_list"],
                         {"bytes": len(der), "sha256": hashlib.sha256(der).hexdigest()})
        # Same CN and SKID, so the same kernel key description, but another key.
        twin = checker.pem_certificate(certificate([(CN, b"PiglorOS public dev-test root-hash signing")],
                                                   b"\1", bytes.fromhex(DESCRIPTION.rsplit(": ", 1)[1])))
        self.assertEqual(checker.kernel_key_description(twin), DESCRIPTION)
        key = "host/system-certificate-list"
        changes = [
            lambda f: f.update({key: twin}),
            lambda f: f.update({key: der + b"\0"}),
            lambda f: f.update({key: der + twin}),
            lambda f: f.update({key: der[:-1]}),
            lambda f: f.update({key: b""}),
            lambda f: f.pop(key),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_the_vmlinux_is_the_booted_kernel_build(self):
        def deriver(files, value):
            document = json.loads(files["host/path-info.json"])
            document["info"][PATHS["kernelDev"].removeprefix("/nix/store/")]["deriver"] = value
            files["host/path-info.json"] = json.dumps(document)
        changes = [
            lambda f: deriver(f, f"{HASH}-linux-6.12.118.drv"),
            lambda f: deriver(f, None),
            lambda f: with_paths(f, kernelDev=store("linux-6.12.117-headers")),
            lambda f: with_paths(f, kernelDev=store("linux-6.12.117", "b")),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_verdict_names_the_checker_and_the_commit(self):
        verdict = self.verdict()
        self.assertEqual(verdict["checker_sha256"],
                         hashlib.sha256(pathlib.Path(checker.__file__).read_bytes()).hexdigest())
        self.assertEqual(verdict["provenance"]["commits"]["github-sha"], COMMIT_SHA)

    def test_guest_facts_match_the_store(self):
        changes = [
            lambda f: f.update({"guest/collector": "/tmp/fake-collector\n"}),
            lambda f: f.update({"host/toplevel-closure.json": info("toplevel", "kernel", "systemd", "collector")}),
            lambda f: f.update({"host/toplevel-closure.json": info("toplevel", "kernel", "systemd", "collectorUnit")}),
            lambda f: f.update({"host/kernel-config": f["host/kernel-config"] + "CONFIG_EXTRA=y\n"}),
            lambda f: f.update({"host/kernel-config": f["host/kernel-config"].replace("CONFIG_DM_VERITY=m", "CONFIG_DM_VERITY=y")}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"].replace("CONFIG_DM_VERITY=m\n", ""),
                                "host/kernel-config": f["host/kernel-config"].replace("CONFIG_DM_VERITY=m\n", "")}),
            lambda f: f.update({"guest/kernel-config": f["guest/kernel-config"].replace("CONFIG_DM_VERITY=m", "# CONFIG_DM_VERITY is not set"),
                                "host/kernel-config": f["host/kernel-config"].replace("CONFIG_DM_VERITY=m", "# CONFIG_DM_VERITY is not set")}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)
        self.verdict(change=lambda f: f.update({"host/kernel-config": "# comment\n" + f["host/kernel-config"]}))

    def test_the_wrapped_emulator_image_is_accepted(self):
        wrapped = f"{PATHS['qemu']}/bin/.qemu-system-x86_64-wrapped\n"
        self.verdict(change=lambda f: f.update({"host/qemu-exe": wrapped}))

    def test_aarch64_devices_are_its_own(self):
        self.refuses(lambda f: f.update({"host/qemu-argv": qemu_argv("aarch64", "-usb")}), "aarch64")
        self.refuses(lambda f: f.update({"host/qemu-argv": qemu_argv("aarch64").replace(
            b"virt,gic-version=max", b"virt,gic-version=3,secure=on")}), "aarch64")
        self.refuses(lambda f: f.update({"host/qemu-argv": qemu_argv("aarch64").replace(
            b"-device\0virtio-gpu-pci\0", b"")}), "aarch64")

    def test_systemctl_omits_an_empty_environment_files_list(self):
        key = "guest/mountfsd-service-properties"
        self.verdict(change=lambda f: f.update({key: f[key].replace("EnvironmentFiles=\n", "")}))

    def test_escaped_mount_points_are_unescaped(self):
        spaced = MOUNTINFO + "64 22 0:64 / /run/with\\040space rw - tmpfs tmpfs rw\n"
        self.verdict(change=lambda f: f.update({"guest/mountinfo": spaced}))
        self.assertEqual(checker.unescape_mount_field("/run/with\\040space\\134x"), "/run/with space\\x")
        # A block device behind an escaped mount point is still found.
        hidden = MOUNTINFO + "65 22 254:0 / /srv/a\\040b rw - ext4 /dev/vdd rw\n"
        with self.assertRaisesRegex(checker.EvidenceError, "/srv/a b"):
            self.verdict(change=lambda f: f.update({"guest/mountinfo": hidden}))

    def test_boot_nonce_disks_and_overlays_are_recorded(self):
        verdict = self.verdict()["guest_storage"]
        self.assertEqual(verdict["boot_id"], "5f431e7d-06ad-4bf8-a098-5e35ceb5569a")
        self.assertEqual(verdict["mounts"]["/nix/store"]["fstype"], "overlay")
        changes = [
            lambda f: f.update({"guest/boot-id": "not-a-uuid\n"}),
            lambda f: f.update({"guest/boot-id": "00000000-06ad-4bf8-a098-5e35ceb5569a\n"}),
            lambda f: f.update({"guest/mountinfo": MOUNTINFO.replace("- tmpfs tmpfs rw,mode=755\n", "- ext4 /dev/vda rw\n", 1)}),
            lambda f: f.update({"guest/mountinfo": MOUNTINFO + "50 22 254:0 / /mnt rw - ext4 /dev/vdb rw\n"}),
            lambda f: f.update({"guest/mountinfo": MOUNTINFO.replace(" - overlay overlay", " - 9p nix-store")}),
            lambda f: f.update({"guest/mountinfo": MOUNTINFO.replace("/nix/.rw-store", "/nix/.other")}),
            lambda f: f.update({"guest/mountinfo": MOUNTINFO + "garbage\n"}),
            lambda f: f.update({"guest/mountinfo": MOUNTINFO + "62 22 254:0 / /mnt/a\\040b rw - ext4 data rw\n"}),
            lambda f: f.update({"guest/mountinfo": MOUNTINFO + "63 22 254:0 / /media rw - erofs image rw\n"}),
            lambda f: f.update({"guest/mountinfo": MOUNTINFO + "60 22 254:0 / /srv rw - ext4 /dev/vdc rw\n"
                                                              "61 22 0:61 / /srv rw - tmpfs tmpfs rw\n"}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_kernel_release_series_is_pinned(self):
        def kernel(release: str):
            def change(files):
                paths = with_paths(files, kernel=store(f"linux-{release}"),
                                   kernelDev=store(f"linux-{release}-dev"))
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
                checker.check(root, "x86_64", CERTIFICATE, lock, untrusted_certificate=UNTRUSTED)

    def test_runner_accelerator_and_network_are_verified(self):
        changes = [
            lambda f: f.update({"guest/uname-machine": "aarch64\n"}),
            lambda f: f.update({"host/runner": "uname\tLinux 6.11 aarch64\ndev-kvm\tabsent\n"}),
            lambda f: f.update({"host/runner": "uname\tLinux 6.11 x86_64\n"}),
            lambda f: f.update({"host/vm-exit-status": "124\n"}),
            lambda f: f.update({"guest/status": "partial\n"}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-machine", "accel=kvm:tcg")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-machine", "accel=tcg")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"-accel\0tcg\0", b"")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-drive", "file=disk.qcow2")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-fsdev", "local,id=f,path=/")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-device", "virtio-blk-pci,drive=d")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-virtfs", "local,path=/home,mount_tag=home")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-virtfs", "local,path=/home")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-device", "vmxnet3")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-monitor", "stdio")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "disk.img")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-qmp", "tcp:0.0.0.0:4444,server=on")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                b"unix:qmp.sock,server=on,wait=off", b"tcp:0.0.0.0:4444,server=on,wait=off")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"-m\x002048", b"-m\x004096")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"-smp\x002", b"-smp\x008")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"-nographic\x00", b"")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                f"{INITRD}/initrd".encode(), f"{store('initrd-linux-6.12.117', 'd')}/initrd".encode())}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                f"{INITRD}/initrd".encode(), b"/tmp/initrd")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-cpu")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-S")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-machine", "q35")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                b"usb-tablet,bus=usb-bus.0", b"usb-tablet,bus=usb-bus.0,serial=x")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-device", "virtio-fs-pci")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-device", "usb-host,hostbus=1")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-device", "virtio-rng-pci")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"-device\0usb-tablet,bus=usb-bus.0\0", b"")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"-usb\0", b"")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-usb")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                b"qemu-evidence.AbCdEf0123/xchg,security_model=none,mount_tag=xchg",
                b"qemu-evidence.AbCdEf0123/../xchg,security_model=none,mount_tag=xchg")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                b"/tmp/qemu-evidence.AbCdEf0123/xchg", b"/nix/store/xchg")}),
            *[lambda f, o=option: f.update({"host/qemu-argv": qemu_argv("x86_64", o, "x")})
              for option in ("-hdc", "-hdd", "-fda", "-pflash", "-sd", "-mtdblock", "-global",
                             "-usbdevice", "-cdrom")],
            *[lambda f, d=device: f.update({"host/qemu-argv": qemu_argv("x86_64", "-device", d)})
              for device in ("scsi-hd,drive=d", "virtio-scsi-pci", "ide-cd", "usb-storage",
                             "nvme,serial=1", "e1000,netdev=n", "vhost-user-fs-pci", "usb-net",
                             "usb-uas")],
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                b"path=/nix/store,", b"path=/,")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                b"path=/tmp/qemu-evidence.AbCdEf0123/xchg,security_model=none,mount_tag=shared", b"path=/home,security_model=none,mount_tag=shared")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                b"security_model=none,mount_tag=xchg", b"security_model=passthrough,mount_tag=xchg")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(
                b"mount_tag=xchg", b"mount_tag=xchg,readonly=on")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"mount_tag=shared", b"mount_tag=home")}),
            lambda f: f.update({"host/qemu-query-kvm.json": '{"return": {"enabled": true, "present": true}}'}),
            lambda f: f.update({"host/qemu-query-kvm.json": '{"error": {"class": "GenericError"}}'}),
            lambda f: f.update({"host/qemu-query-kvm.json": ""}),
            lambda f: f.update({"host/vm-cleanup": "qemu-process\tunobserved-or-running\nwork-directory\tremoved\n"}),
            lambda f: f.update({"host/vm-cleanup": "qemu-process\texited\nwork-directory\tpresent\n"}),
            lambda f: f.update({"host/vm-cleanup": "qemu-process\texited\n"}),
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
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64", "-M", "accel=kvm")}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64")[:-1]}),
            lambda f: f.update({"host/qemu-argv": b"\0"}),
            lambda f: f.update({"host/qemu-argv": qemu_argv("x86_64").replace(b"-accel\0tcg", b"-accel\0kvm")}),
            lambda f: f.update({"host/qemu-exe": "/usr/bin/qemu-system-x86_64\n"}),
            lambda f: f.update({"host/qemu-exe": f"{PATHS['qemu']}/bin/.qemu-system-aarch64-wrapped\n"}),
            lambda f: f.update({"host/qemu-exe": f"{store('qemu-other')}/bin/.qemu-system-x86_64-wrapped\n"}),
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

    def test_mount_image_cases_hold_and_report_the_live_state(self):
        verdict = self.verdict()["mount_image_cases"]
        self.assertEqual((verdict["root_hash"], verdict["salt"]), (ROOT_HASH, SALT))
        held = verdict["positive"]["held"]
        self.assertEqual((held["loop"], held["partitions"], held["dm"]), ("loop0", "loop0p1,loop0p2,loop0p3", "dm-0"))
        self.assertEqual(held["root_hash_sig_key_desc"], "cryptsetup:8a5cfdc4")
        self.assertEqual(verdict["tampered"]["readback"]["file"][0], "1")
        self.assertEqual(verdict["wrong-key"]["report"][0], ["activation", "refused", "MethodRejected"])
        self.assertEqual((verdict["mountfsd_reply"]["imageSize"], verdict["mountfsd_reply"]["sectorSize"]),
                         (IMAGE_SIZE, 512))
        self.assertEqual(verdict["tampered_offset"], TAMPERED_OFFSET)
        self.assertEqual(verdict["mountfsd_reply"]["cold_mountimage_seconds"], 71.25)
        self.assertEqual(verdict["positive"]["activation_seconds"], 12.5)
        self.assertEqual(verdict["positive"]["held"]["dm_device"], "253:0")

    def test_the_adapter_is_a_real_static_executable_the_image_carries(self):
        for architecture in ("x86_64", "aarch64"):
            adapter = self.verdict(architecture)["mount_image_cases"]["adapter"]
            expected = executable_files(architecture)["host/images/adapter"]
            self.assertEqual(adapter["adapter_sha256"], hashlib.sha256(expected).hexdigest())
            self.assertEqual(adapter["adapter_bytes"], len(expected))
        # Like the real image, the file is not contiguous in it: its tail is inline.
        self.assertEqual(len(X86_ADAPTER) % 4096 != 0, True)
        self.assertEqual(ddi().count(X86_ADAPTER), 0)

    def test_a_stand_in_or_broken_adapter_fails_closed(self):
        def broken(adapter):
            """An adapter carried by every image, so only it is wrong."""
            return lambda f: f.update(executable_files("x86_64", adapter))

        def carried(**image):
            """Images built with `image`, all alike, so only the carrying is wrong."""
            return lambda f: f.update({
                "host/images/positive.raw": ddi(**image), "host/images/wrong-key.raw": ddi(**image),
                "host/images/tampered.raw": tampered_ddi(**image)})

        changes = [broken(defect) for defect in elf_defects()] + [
            # The stand-in in the file alone.
            lambda f: f.update({"host/images/adapter": b"adapter"}),
            # The images do not carry the adapter's blocks exactly once, then its tail.
            carried(adapter=b"other"),
            carried(extra=erofs_file(X86_ADAPTER)),
            carried(adapter=X86_ADAPTER[:-1] + b"X"),
            carried(adapter=X86_ADAPTER[:196_608]),
            lambda f: f.pop("host/images/adapter"),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_a_tiny_or_constant_tail_is_not_a_positional_binding(self):
        # A tail under MIN_TAIL_BYTES is left to the SIM1 digest; a longer one that is a single
        # repeated byte would be found in any zero-filled block, so it is refused.
        machine = checker.ELF_MACHINES["x86_64"]
        blocks = 196_608 - 176
        short = static_elf(machine, b"adapter", size=blocks + checker.MIN_TAIL_BYTES - 1)
        resized = REPLY.replace(f'"imageSize": {IMAGE_SIZE}', f'"imageSize": {len(ddi(adapter=short))}')
        self.verdict(change=lambda f: f.update({**executable_files("x86_64", short),
                                                "guest/cases/mountfsd-reply/reply": resized}))
        constant = static_elf(machine, b"adapter", size=blocks + checker.MIN_TAIL_BYTES)
        constant = constant[:-checker.MIN_TAIL_BYTES] + bytes(checker.MIN_TAIL_BYTES)
        resized = REPLY.replace(f'"imageSize": {IMAGE_SIZE}', f'"imageSize": {len(ddi(adapter=constant))}')
        with self.assertRaisesRegex(checker.EvidenceError, "adapter's tail"):
            self.verdict(change=lambda f: f.update({**executable_files("x86_64", constant),
                                                    "guest/cases/mountfsd-reply/reply": resized}))

    def test_build_images_applies_the_checkers_rules_to_the_adapter(self):
        text = (ROOT / "deploy/nixos/qemu-evidence/build-images.sh").read_text(encoding="utf-8")
        start = text.index("python3 -I -c '", text.index("(static_executable)")) + len("python3 -I -c '")
        code = text[start:text.index("' \"${architecture}\" \"${ADAPTER}\"", start)]
        aarch64 = static_elf(checker.ELF_MACHINES["aarch64"], b"adapter")
        names = {"x86-64": "x86_64", "arm64": "aarch64"}
        cases = [("x86-64", X86_ADAPTER, True), ("arm64", aarch64, True)]
        cases += [("x86-64", defect, False) for defect in elf_defects()]
        # Each architecture's adapter is wrong for the other.
        cases += [("x86-64", aarch64, False), ("arm64", X86_ADAPTER, False)]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "adapter"
            for name, adapter, accepted in cases:
                path.write_bytes(adapter)
                script = subprocess.run([sys.executable, "-I", "-c", code, name, str(path)],
                                        capture_output=True, text=True, check=False)
                try:
                    checker.static_executable(adapter, names[name], "adapter")
                    checked = True
                except checker.EvidenceError:
                    checked = False
                with self.subTest(name=name, size=len(adapter), accepted=accepted):
                    self.assertEqual((script.returncode == 0, checked), (accepted, accepted), script.stderr)

    def test_mount_image_case_fabrication_fails_closed(self):
        positive, tampered = "guest/cases/positive", "guest/cases/tampered"
        refused, reply = "guest/cases/wrong-key", "guest/cases/mountfsd-reply"
        leftover = f"loop\tloop1\t{BACKING}\t{BACKING}\t7:32\tloop1p1,loop1p2,loop1p3\n"
        def without(key):
            return json.dumps({name: value for name, value in json.loads(REPLY).items() if name != key})
        held_mount = f"90 22 253:0 / {ATTEMPT} ro,relatime shared:50 - erofs /proc/self/fd/20 ro\n"
        other_mount = f"90 22 0:44 / {ATTEMPT} ro,relatime shared:50 - erofs /dev/loop0p1 ro\n"
        changes = [
            # Inventory: a missing case, file, or extra case.
            lambda f: [f.pop(name) for name in list(f) if name.startswith("guest/cases/verity-d/")],
            lambda f: f.pop(f"{positive}/readback"),
            lambda f: f.update({"guest/cases/extra/report": ""}),
            lambda f: f.pop("host/images/root-hash.txt"),
            lambda f: f.update({f"{reply}/extra": ""}),
            # Inputs: other signers, descriptions or images.
            lambda f: f.update({"host/images/positive.der": checker.pem_certificate(UNTRUSTED)}),
            lambda f: f.update({"host/images/wrong-key.der": checker.pem_certificate(CERTIFICATE)}),
            lambda f: f.update({"host/images/root-hash.txt": "ef" * 32}),
            lambda f: f.update({"host/images/positive.raw": b"not a disk"}),
            lambda f: f.update({"host/images/positive.raw": ddi(root_hash="AB" * 32)}),
            lambda f: f.update({"host/images/positive.raw": ddi(version=2)}),
            lambda f: f.update({"host/images/positive.raw": ddi(hash_type=0)}),
            lambda f: f.update({"host/images/positive.raw": ddi(salt_size=64)}),
            lambda f: f.update({"host/images/positive.raw": ddi()[:6 * 512 + 100]}),
            lambda f: f.update({"host/images/positive.raw": ddi()[:6 * 512] + b"veriti\0\0" + ddi()[6 * 512 + 8:]}),
            lambda f: f.update({"host/images/wrong-key.raw": ddi(root_hash="ef" * 32)}),
            lambda f: f.update({"host/images/wrong-key.raw": ddi(salt="ef" * 32)}),
            lambda f: f.update({"host/images/tampered.raw": ddi()}),
            lambda f: f.update({"host/images/tampered.raw": tampered_ddi()[:-1]}),
            lambda f: f.update({"host/images/tampered-offset": f"{TAMPERED_OFFSET + 1}\n"}),
            lambda f: f.update({"host/images/tampered-offset": "x\n"}),
            lambda f: f.update({"host/images/tampered.raw": bytes(b ^ (i == 600) for i, b in enumerate(ddi())),
                                "host/images/tampered-offset": "600\n"}),
            lambda f: f.pop("host/images/wrong-key.raw"),
            lambda f: f.update({f"{positive}/arguments": f[f"{positive}/arguments"].replace(
                DESCRIPTION, UNTRUSTED_DESCRIPTION)}),
            lambda f: f.update({f"{refused}/arguments": f[f"{refused}/arguments"].replace(
                "wrong-key.der", "positive.der")}),
            lambda f: f.update({"guest/cases/verity-d/arguments": f["guest/cases/positive/arguments"]}),
            # Outcomes: refusals, failed releases, unfinished protocols.
            lambda f: f.update({f"{positive}/driver-status": "1\n"}),
            lambda f: f.update({f"{positive}/report": "activation\trefused\tMethodRejected\n"}),
            lambda f: f.update({f"{positive}/report": f[f"{positive}/report"].replace("detached", "failed\tTeardownFailure")}),
            lambda f: f.update({f"{positive}/report": f[f"{positive}/report"].replace("\tremoved", "\tfailed\tUnsafeRegistry")}),
            lambda f: f.update({f"{positive}/report": f[f"{positive}/report"].replace(ATTEMPT, "/tmp/root")}),
            lambda f: f.update({f"{refused}/report": f"activation\tmounted\t1\t{ATTEMPT}\nrelease\tdetached\nremoval\tremoved\n"}),
            lambda f: f.update({f"{refused}/report": "activation\trefused\tTransport\nrelease\tnone\nremoval\tremoved\n"}),
            lambda f: f.update({"guest/cases/verity-d/report": ""}),
            # Live state: topology, table, mount and readback.
            lambda f: f.update({f"{positive}/devices-held": HELD_DEVICES.replace(BACKING + "\t" + BACKING, BACKING + "\t-")}),
            lambda f: f.update({f"{positive}/devices-held": HELD_DEVICES.replace(",loop0p3", "")}),
            lambda f: f.update({f"{positive}/devices-held": HELD_DEVICES.replace("CRYPT-VERITY-", "CRYPT-PLAIN-")}),
            lambda f: f.update({f"{positive}/devices-held": HELD_DEVICES.replace("\tloop0p1,loop0p2\n", "\tloop0p1\n")}),
            lambda f: f.update({f"{positive}/devices-held": HELD_DEVICES + leftover}),
            lambda f: f.update({f"{positive}/dm-table-held": TABLE.replace(ROOT_HASH, "ef" * 32)}),
            lambda f: f.update({f"{positive}/dm-table-held": TABLE.replace(SALT, "-")}),
            lambda f: f.update({f"{positive}/dm-table-held": TABLE.replace(" 2 root_hash_sig_key_desc cryptsetup:8a5cfdc4", "")}),
            lambda f: f.update({f"{positive}/dm-table-held": TABLE.replace(" 2 root_hash", " 3 root_hash")}),
            lambda f: f.update({f"{positive}/dm-table-held": TABLE.replace("sha256", "sha1")}),
            lambda f: f.update({f"{positive}/dm-table-held": TABLE + TABLE}),
            lambda f: f.update({f"{positive}/mountinfo-held": f[f"{positive}/mountinfo-held"].replace(" ro,relatime", " rw,relatime")}),
            lambda f: f.update({f"{positive}/mountinfo-held": f[f"{positive}/mountinfo-held"].replace("- erofs", "- squashfs")}),
            lambda f: f.update({f"{positive}/mountinfo-held": MOUNTINFO}),
            lambda f: f.update({f"{positive}/mountinfo-held": MOUNTINFO + other_mount}),
            lambda f: f.update({f"{positive}/mountinfo-held": MOUNTINFO + held_mount.replace(
                "/proc/self/fd/20", "/dev/loop0p1")}),
            lambda f: f.update({f"{positive}/mountinfo-held": MOUNTINFO + held_mount.replace(
                "/proc/self/fd/20", "/proc/self/fd/x")}),
            # A non-ASCII decimal digit (ARABIC-INDIC DIGIT TWO) is not a descriptor number.
            lambda f: f.update({f"{positive}/mountinfo-held": MOUNTINFO + held_mount.replace(
                "/proc/self/fd/20", "/proc/self/fd/\u0662")}),
            # mountfsd's journal is recorded, not judged, but it must be there exactly once.
            lambda f: f.pop("guest/cases/mountfsd-log"),
            lambda f: f.update({"guest/cases/mountfsd-log.1": ""}),
            lambda f: f.update({f"{positive}/timing": "activation-seconds\tlong\n"}),
            lambda f: f.pop(f"{positive}/timing"),
            lambda f: f.update({f"{positive}/mountinfo-held": MOUNTINFO + held_mount.replace("253:0", "253:1")}),
            lambda f: f.update({f"{positive}/mountinfo-held": MOUNTINFO + held_mount + held_mount}),
            lambda f: f.update({f"{positive}/devices-held": HELD_DEVICES.replace("253:0", "dm-0")}),
            lambda f: f.update({f"{positive}/readback": f[f"{tampered}/readback"]}),
            lambda f: f.update({f"{tampered}/readback": f[f"{positive}/readback"]}),
            lambda f: f.update({f"{tampered}/readback": f[f"{tampered}/readback"].replace("block-0\t0", "block-0\t1")}),
            lambda f: f.update({f"{tampered}/readback": "file\t1\tsha256sum: -: Input/output error\n"}),
            lambda f: f.update({"guest/cases/kernel-log": "device-mapper: verity: loaded\n"}),
            # Cleanup: devices or attempt directories that remain.
            lambda f: f.update({f"{positive}/devices-after": leftover}),
            lambda f: f.update({f"{refused}/devices-after": HELD_DEVICES}),
            lambda f: f.update({f"{refused}/devices-before": leftover}),
            lambda f: f.update({f"{positive}/runtime-after": RUNTIME_AFTER + "sandbox/attempts/x\td\t700\n"}),
            lambda f: f.update({"guest/cases/verity-d-planted": ""}),
            # The raw reply.
            lambda f: f.update({f"{reply}/status": "1\n"}),
            lambda f: f.update({f"{reply}/timing": "activation-seconds\t71.25\n"}),
            lambda f: f.update({f"{reply}/timing": "mountimage-seconds\t\u0667\u0661.25\n"}),
            lambda f: f.update({f"{reply}/reply": without("imageSize")}),
            lambda f: f.update({f"{reply}/reply": REPLY.replace('"sectorSize": 512', '"sectorSize": true')}),
            lambda f: f.update({f"{reply}/reply": REPLY.replace('"erofs"', '"ext4"')}),
            lambda f: f.update({f"{reply}/reply": REPLY.replace(f'"imageSize": {IMAGE_SIZE}', f'"imageSize": {IMAGE_SIZE + 1}')}),
            lambda f: f.update({f"{reply}/reply": REPLY.replace('"sectorSize": 512', '"sectorSize": 4096')}),
            lambda f: f.update({f"{reply}/reply": REPLY.replace("root=signed:=absent", "root=verity:=absent")}),
            lambda f: f.update({f"{reply}/reply": REPLY.replace("root=signed:=absent", "root=signed+erofs:=absent")}),
            lambda f: f.update({f"{reply}/reply": without("imagePolicy")}),
            lambda f: f.update({f"{reply}/reply": "[]\n"}),
            lambda f: f.update({f"{reply}/devices-after": "loop\tloop2\t/run/piglor-evidence-image.raw\t-\t7:64\t\n"}),
            lambda f: f.update({f"{reply}/devices-after": "dm\tdm-1\tx\tCRYPT-VERITY-x\t253:1\tloop2p1\n"}),
            lambda f: f.update({f"{reply}/devices-after": "loop\tloop5\t/var/lib/other.img\t/var/lib/other.img\t7:80\t\n"}),
            lambda f: f.update({f"{reply}/devices-before": "garbage\n"}),
        ]
        for change in changes:
            with self.subTest(change=change):
                self.refuses(change)

    def test_private_network_unit_holds_only_the_loopback_once_the_sysctl_is_set(self):
        network = self.verdict()["private_network"]
        self.assertEqual(network["boot_sysctl"], 0)
        self.assertEqual(network["fb-0"]["links"], ["lo", "tunl0", "sit0", "ip6tnl0", "gre0"])
        for case in ("fb-1", "fb-2"):
            self.assertEqual(network[case]["links"], ["lo"])
            self.assertEqual(network[case]["addresses"], sorted(checker.LOOPBACK_ADDRESSES))
            self.assertEqual(network[case]["routes6"], ROUTES6.splitlines())

    def test_private_network_main_table_loopback_route_is_accepted_deliberately(self):
        main_table = "::1 dev lo proto kernel metric 256 pref medium\n"
        # The kernel names a local-table route's kind, so the main table is the
        # only place an unkinded ::1 route is accepted (explicit or implied).
        for routes in (main_table, ROUTES6 + main_table, ROUTES6.replace("::1 ", "::1/128 "),
                       "::1 dev lo table main proto kernel metric 256 pref medium\n"):
            with self.subTest(routes=routes):
                verdict = self.verdict(change=lambda f, r=routes: f.update({"guest/network/fb-1/routes6": r}))
                self.assertEqual(verdict["private_network"]["fb-1"]["links"], ["lo"])

    def test_private_network_linked_device_names_are_normalised(self):
        addresses = ADDRESSES.replace("1: lo ", "1: lo@lo ", 1)
        self.assertEqual(self.verdict(change=lambda f: f.update({"guest/network/fb-1/addrs": addresses}))
                         ["private_network"]["fb-1"]["addresses"], sorted(checker.LOOPBACK_ADDRESSES))

    def test_the_provider_runtime_is_the_staged_binary_started_as_the_selector_would(self):
        daemon = self.verdict()["provider_runtime"]["start"]
        self.assertEqual(daemon["binary"], PROVIDER_BINARY)
        self.assertEqual(daemon["properties"]["Type"], "notify")
        self.assertEqual(sorted(daemon["endpoints"]), ["provider-control.sock", "provider-execute.sock"])

    def test_provider_runtime_fabrication_fails_closed(self):
        base = "guest/daemon/start"
        changes = [
            (lambda f: f.pop(f"{base}/runtime-log"), "malformed daemon record start"),
            (lambda f: f.update({f"{base}/extra": ""}), "unexpected"),
            (lambda f: f.update({"guest/daemon/other/x": ""}), "does not hold exactly"),
            (lambda f: f.update({f"{base}/stage-status": "1\n"}), "did not stage and unstage"),
            (lambda f: f.update({f"{base}/stage-report": "staged\t/tmp/x\nunstaged\n"}), "did not stage"),
            (lambda f: f.update({f"{base}/stage-report": f"staged\t{PROVIDER_BINARY}\n"}), "did not stage"),
            (lambda f: f.update({f"{base}/stage-report": ""}), "did not stage"),
            (lambda f: f.update({f"{base}/start-status": "1\n"}), "did not start and stop cleanly"),
            (lambda f: f.update({f"{base}/stop-status": "1\n"}), "did not start and stop cleanly"),
            (lambda f: f.update({f"{base}/runtime-properties": RUNTIME_PROPERTIES.replace("Type=notify", "Type=exec")}),
             "Type='exec'"),
            (lambda f: f.update({f"{base}/runtime-properties":
                                 RUNTIME_PROPERTIES.replace("ActiveState=active", "ActiveState=failed")}),
             "ActiveState='failed'"),
            (lambda f: f.update({f"{base}/runtime-properties": RUNTIME_PROPERTIES.replace("MainPID=412", "MainPID=0")}),
             "does not run"),
            (lambda f: f.update({f"{base}/runtime-properties":
                                 RUNTIME_PROPERTIES.replace(" provider-runtime ;", " recovery-peer ;")}),
             "does not run"),
            (lambda f: f.update({f"{base}/runtime-properties": RUNTIME_PROPERTIES + "Id=again\n"}), "malformed"),
            (lambda f: f.update({f"{base}/runtime-exe": "/nix/store/x-other\n"}), "not the staged provider binary"),
            (lambda f: f.update({f"{base}/runtime-tree": "\td\t700\nprovider-execute.sock\ts\t600\n"}),
             "no socket at /run/pigloros/provider-control.sock"),
            (lambda f: f.update({f"{base}/runtime-tree": "provider-execute.sock\tf\t600\n"
                                                         "provider-control.sock\ts\t600\n"}),
             "no socket at /run/pigloros/provider-execute.sock"),
        ]
        for change, message in changes:
            with self.subTest(change=change), self.assertRaisesRegex(checker.EvidenceError, message):
                self.verdict(change=change)

    def test_a_failed_probe_explains_itself(self):
        """The first QEMU run failed with no probe files: the error must carry the unit's stderr."""
        def failed(files):
            for name in checker.NETWORK_PROBE_FILES:
                files.pop(f"guest/network/fb-0/{name}")
            files["guest/network/fb-0/status"] = "1\n"
            files["guest/network/fb-0/stderr"] = "Failed to find executable bash\n"
        with self.assertRaisesRegex(checker.EvidenceError,
                                    r"status 1\); stderr: 'Failed to find executable bash'; "
                                    r"probe files written: \[\]"):
            self.verdict(change=failed)

        # A failed `ip` leaves the files it had created: the case is still judged by its
        # status and stderr first, and says which probe files exist.
        def partial(files):
            for name in ("addrs", "routes4", "routes6"):
                files.pop(f"guest/network/fb-1/{name}")
            files["guest/network/fb-1/status"] = "2\n"
            files["guest/network/fb-1/stderr"] = "  RTNETLINK answers: Operation not permitted \n"
        with self.assertRaisesRegex(checker.EvidenceError,
                                    r"status 2\); stderr: 'RTNETLINK answers: Operation not permitted'; "
                                    r"probe files written: \['links', 'netns'\]"):
            self.verdict(change=partial)

        def silent(files):
            for name in checker.NETWORK_PROBE_FILES:
                files.pop(f"guest/network/fb-1/{name}")
        with self.assertRaisesRegex(checker.EvidenceError, r"completed but wrote only \[\]"):
            self.verdict(change=silent)

        def incomplete(files):
            files.pop("guest/network/fb-1/routes6")
        with self.assertRaisesRegex(checker.EvidenceError, r"completed but wrote only \['addrs', 'links'"):
            self.verdict(change=incomplete)
        with self.assertRaisesRegex(checker.EvidenceError, "wrote to stderr: 'warning'"):
            self.verdict(change=lambda f: f.update({"guest/network/fb-2/stderr": "warning\n"}))
        # Whitespace alone is no output.
        self.verdict(change=lambda f: f.update({"guest/network/fb-2/stderr": " \n"}))
        # A record with a missing run file or an unexpected file is named precisely, with the
        # probe files that exist.
        with self.assertRaisesRegex(
                checker.EvidenceError,
                r"malformed network record fb-1: missing \['journal'\], unexpected \[\], "
                r"probe files \['addrs', 'links', 'netns', 'routes4', 'routes6'\]"):
            self.verdict(change=lambda f: f.pop("guest/network/fb-1/journal"))
        with self.assertRaisesRegex(checker.EvidenceError, r"unexpected \['extra'\]"):
            self.verdict(change=lambda f: f.update({"guest/network/fb-1/extra": ""}))

    def test_private_network_fabrication_fails_closed(self):
        base = "guest/network"
        changes = [
            (lambda f: f.pop(f"{base}/modules"), "does not hold exactly"),
            (lambda f: f.update({f"{base}/extra": ""}), "does not hold exactly"),
            (lambda f: f.pop(f"{base}/fb-1/routes6"), "completed but wrote only"),
            (lambda f: f.update({f"{base}/boot-sysctl": "x\n"}), "does not boot"),
            (lambda f: f.update({f"{base}/boot-sysctl": "1\n"}), "does not boot"),
            (lambda f: f.update({f"{base}/boot-sysctl": "7\n"}), "does not boot"),
            # The modules, and the control: value 0 must show the host's fallback devices.
            (lambda f: f.update({f"{base}/modules": ""}), "tunnel modules are not loaded"),
            (lambda f: f.update({f"{base}/modules": MODULES.replace("ip_gre", "ip_gre2")}),
             "tunnel modules are not loaded"),
            (lambda f: f.update({f"{base}/init-links": LINK_LO}), "no fallback tunnel device"),
            (lambda f: f.update({f"{base}/init-links": LINK_LO + LINK_TUNL}), "no fallback tunnel device"),
            (lambda f: f.update({f"{base}/fb-0/links": LINK_LO}), "lacks the host's fallback"),
            (lambda f: f.update({f"{base}/fb-0/links": LINK_LO + LINK_TUNL}), "lacks the host's fallback"),
            (lambda f: f.update({f"{base}/fb-0/links": LINK_LO + FALLBACKS + link(6, "evil0", "ipip")}),
             "lacks the host's fallback"),
            (lambda f: f.update({f"{base}/fb-1/links": LINK_LO + LINK_TUNL}), "more than lo"),
            (lambda f: f.update({f"{base}/fb-2/links": LINK_TUNL}), "lacks exactly one lo"),
            (lambda f: f.update({f"{base}/fb-1/links": LINK_LO + LINK_LO}), "lacks exactly one lo"),
            (lambda f: f.update({f"{base}/fb-1/links": "garbage\n"}), "malformed"),
            (lambda f: f.update({f"{base}/fb-1/sysctl": "0\n"}), "did not run with"),
            (lambda f: f.update({f"{base}/fb-1/status": "1\n"}), "did not complete"),
            (lambda f: f.update({f"{base}/fb-1/netns": INIT_NETNS + "\n"}), "network namespace of its own"),
            (lambda f: f.update({f"{base}/fb-1/netns": "net:[x]\n"}), "network namespace of its own"),
            (lambda f: f.update({f"{base}/fb-1/addrs": ADDRESSES.split("\n")[0] + "\n"}), "lacks exactly one lo"),
            (lambda f: f.update({f"{base}/fb-1/addrs": ADDRESSES + "2: eth0    inet 10.0.0.2/24 scope global eth0\n"}),
             "more than lo"),
            (lambda f: f.update({f"{base}/fb-1/addrs": "1: lo\n"}), "malformed"),
            # Routes: empty, off lo, via a gateway, outside the allowlist.
            (lambda f: f.update({f"{base}/fb-1/routes4": ""}), "lacks the loopback host route"),
            (lambda f: f.update({f"{base}/fb-2/routes6": ""}), "lacks the loopback host route"),
            (lambda f: f.update({f"{base}/fb-1/routes4": "\n"}), "blank line"),
            (lambda f: f.update({f"{base}/fb-1/routes4": ROUTES4 + "default via 10.0.0.1 dev eth0\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-1/routes4": ROUTES4 + "local 127.0.0.0/8 via 127.0.0.2 dev lo table local\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-1/routes4": ROUTES4 + "local 10.0.0.0/8 dev lo table local\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-1/routes4": ROUTES4 + "127.0.0.0/8 dev lo\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-1/routes4": ROUTES4 + "unreachable 127.0.0.1 dev lo table local\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-1/routes4": "broadcast 127.255.255.255 dev lo table local\n"}),
             "lacks the loopback host route"),
            (lambda f: f.update({f"{base}/fb-2/routes6": "local ::1 dev eth0 table local\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-2/routes6": "local ::1 dev\n"}), "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-2/routes6": ROUTES6 + "fe80::/64 dev lo proto kernel\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-2/routes6": ROUTES6 + "default via fe80::1 dev lo\n"}),
             "other than the loopback's own"),
            # An unkinded ::1 route in the local table is refused: the kernel
            # always prints `local` for that table, so it is not what it printed.
            (lambda f: f.update({f"{base}/fb-2/routes6": ROUTES6 + "::1 dev lo table local\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-2/routes6": ROUTES6 + "local ::1 dev lo table main\n"}),
             "other than the loopback's own"),
            # Fields beyond the first dev and table: a second device or table,
            # a gateway, a nexthop id, encapsulation, a global scope or source.
            *[(lambda f, tail=tail: f.update(
                {f"{base}/fb-1/routes6": ROUTES6 + "local ::1 dev lo table local " + tail + "\n"}),
               "other than the loopback's own")
              for tail in ("dev eth0", "table main", "gateway fe80::1", "nhid 5", "encap ip id 1",
                           "src 2001:db8::1", "scope global", "proto bgp", "metric x", "linkdown extra", "dev",
                           # A repeated flag; a non-ASCII digit; an unbounded metric; the IPv4
                           # loopback as an IPv6 source; an allowed value on the wrong key.
                           "linkdown linkdown", "metric ٧", "metric " + "1" * 11, "src 127.0.0.1",
                           "dev local", "table lo", "scope table", "pref kernel")],
            (lambda f: f.update({f"{base}/fb-1/routes4": ROUTES4 + "local 127.0.0.0/8 dev lo table local src ::1\n"}),
             "other than the loopback's own"),
            (lambda f: f.update(
                {f"{base}/fb-1/routes4": ROUTES4 + "local 127.0.0.0/8 dev lo table local metric 0 metric 1\n"}),
             "other than the loopback's own"),
            (lambda f: f.update(
                {f"{base}/fb-1/routes4": ROUTES4 + "local 127.0.0.0/8 dev lo table local src 10.0.0.1\n"}),
             "other than the loopback's own"),
            (lambda f: f.update({f"{base}/fb-2/routes6": "multicast ff00::/8 dev lo table local\n"}),
             "lacks the loopback host route"),
        ]
        for change, message in changes:
            with self.subTest(change=change), self.assertRaisesRegex(checker.EvidenceError, message):
                self.verdict(change=change)

    def test_cli_writes_one_verdict_and_refuses_bad_input(self):
        root = self.evidence()
        verdict = self.base / "verdict.json"
        command = [sys.executable, str(pathlib.Path(checker.__file__)), "--architecture", "x86_64",
                   "--certificate", str(CERTIFICATE_PATH), "--untrusted-certificate", str(UNTRUSTED_PATH),
                   "--flake-lock", str(FLAKE_LOCK_PATH),
                   "--verdict", str(verdict), str(root)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(verdict.read_text())["architecture"], "x86_64")
        self.assertEqual(checker.main(command[2:]), 1)  # the verdict already exists
        for arguments in (
            ["--architecture", "riscv64"],
            ["--certificate", str(root / "missing.pem")],
            ["--untrusted-certificate", str(CERTIFICATE_PATH)],
            ["--flake-lock", str(CERTIFICATE_PATH)],
        ):
            changed = list(command[2:])
            changed[changed.index(arguments[0]) + 1] = arguments[1]
            changed[changed.index("--verdict") + 1] = str(self.base / f"v{len(arguments[1])}.json")
            with self.subTest(arguments=arguments):
                self.assertEqual(checker.main(changed), 1)


if __name__ == "__main__":
    unittest.main()
