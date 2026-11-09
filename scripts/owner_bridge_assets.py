#!/usr/bin/env python3
"""Bundle the private owner core and sealed ADR-131 qualification adapters.

These checked-in outputs are compiled assets, never runtime script inputs.
``--check`` is also called by the independent wire/response vector checker.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

from owner_bridge_webauthn_fixtures import N, ecdsa_der_signature, ecdsa_signature_values

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "crates/pos-owner-bridge"
ASSETS = BRIDGE / "assets"
PROFILES = (
    "pending", "popup", "popup_receipt", "permission", "external", "navigation",
    "download", "authentication", "readonly_write", "readonly_control",
    "duplicate_request", "interleaved_pair", "delayed_delivery", "successful_get",
    "successful_get_release_delay", "successful_get_writing_delay", "withheld_delivery",
)
TRIGGERS = {
    "popup": 'window.open("http://localhost:49291/denied-popup", "_blank");',
    "permission": (
        "var reported = false; "
        "function report(uri) { if (!reported) { reported = true; window.location.href = uri; } } "
        "setTimeout(function () { report(\"http://localhost:49291/permission-diag/noresult\"); }, 12000); "
        "try { if (!window.Notification || !window.Notification.requestPermission) { report(\"http://localhost:49291/permission-diag/unavailable\"); } "
        "else if (window.Notification.permission !== \"default\") { report(\"http://localhost:49291/permission-diag/unexpectedstate\"); } "
        "else { window.Notification.requestPermission().then(function (state) { "
        "if (state === \"denied\") { report(\"http://localhost:49291/permission-diag/denied\"); } "
        "else if (state === \"default\") { report(\"http://localhost:49291/permission-diag/default\"); } "
        "else if (state === \"granted\") { report(\"http://localhost:49291/permission-diag/unexpectedgranted\"); } "
        "else { report(\"http://localhost:49291/permission-diag/unknown\"); } "
        "}, function () { report(\"http://localhost:49291/permission-diag/rejected\"); }); } } "
        "catch (_) { report(\"http://localhost:49291/permission-diag/exception\"); }"
    ),
    "external": 'setTimeout(function () { window.location.href = "ms-settings:privacy-location"; }, 1000);',
    "navigation": 'window.location.href = "http://localhost:49291/denied-navigation";',
}


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def csp_hash(data: bytes) -> str:
    return base64.b64encode(digest(data)).decode("ascii")


def document(core: str, shell: str, bootstrap: str) -> bytes:
    return shell.replace("@@OWNER_SCRIPT@@", core + bootstrap).encode("utf-8")


def delivery_port(profile: str) -> str:
    """Schedule genuine SDK events; these adversaries are never normal G3 cases."""
    schedules = {
        "duplicate_request": (
            "          if (!done && event.additionalData.role === \"request\") {\n"
            "            done = true; listener(event); listener(event); return;\n"
            "          }\n"
            "          listener(event);\n"
        ),
        "interleaved_pair": (
            "          var generation = new DataView(event.getBuffer()).getUint32(12, true);\n"
            "          if (first === null) { first = generation; }\n"
            "          if (!done && generation === first && event.additionalData.role === \"reply\") {\n"
            "            held = event; return;\n"
            "          }\n"
            # Receipt must imply the declared insertion actually ran, even if
            # the SDK delivers the first reply after a complete newer pair.
            "          if (!done && generation !== first && event.additionalData.role === \"reply\") {\n"
            "            waiting.push(event); return;\n"
            "          }\n"
            "          listener(event);\n"
            "          if (!done && generation !== first && held && event.additionalData.role === \"request\") {\n"
            "            done = true; var delayed = held; held = null; listener(delayed);\n"
            "            var queued = waiting; waiting = []; queued.forEach(listener);\n"
            "          }\n"
        ),
        "delayed_delivery": (
            "          if (done) { listener(event); return; }\n"
            "          queue.push(event);\n"
            "          if (queue.length === 1) {\n"
            "            setTimeout(function () {\n"
            "              done = true; queue.forEach(listener); queue = [];\n"
            "            }, 700);\n"
            "          }\n"
        ),
        "withheld_delivery": "          queue.push(event);\n",
    }
    declarations = {
        "duplicate_request": "done = false",
        "interleaved_pair": "done = false, first = null, held = null, waiting = []",
        "delayed_delivery": "done = false, queue = []",
        "withheld_delivery": "queue = []",
    }
    return (
        "  function deliveryPort() {\n"
        "    var port = window.chrome && window.chrome.webview;\n"
        "    if (!port) { return null; }\n"
        f"    var {declarations[profile]};\n"
        "    return {\n"
        "      releaseBuffer: function (buffer) { port.releaseBuffer(buffer); },\n"
        "      addEventListener: function (name, listener) {\n"
        "        port.addEventListener(name, function (event) {\n"
        + schedules[profile]
        + "        });\n"
        "      }\n"
        "    };\n"
        "  }\n"
    )


def successful_get_bootstrap(pause: str = "none") -> str:
    """One fixed public test-key assertion, never real-authenticator PRF qualification."""
    challenge = bytes([2]) * 32
    client = (
        b'{"type":"webauthn.get","challenge":"'
        + base64.urlsafe_b64encode(challenge).rstrip(b"=")
        + b'","origin":"http://localhost:49291"}'
    )
    auth = digest(b"localhost") + b"\x05\x00\x00\x00\x01"
    r, s = ecdsa_signature_values(auth + digest(client))
    signature = ecdsa_der_signature(r, min(s, N - s))
    # One adversarial variant holds the next task after READY for release expiry;
    # the other holds this getter after the core's real WRITING CAS, before bytes
    # are encoded. Neither changes core bytes, host clocks, or normal G3 delivery.
    stalls = {
        "none": "",
        "release": (
            "          queueMicrotask(function () {\n"
            "            var until = performance.now() + 2500;\n"
            "            while (performance.now() < until) { /* declared release delay */ }\n"
            "          });\n"
        ),
        "writing": (
            "          var until = performance.now() + 1500;\n"
            "          while (performance.now() < until) { /* declared writing delay */ }\n"
        ),
    }
    return (
        "(function () {\n"
        "  function bytes(hex) {\n"
        "    return new Uint8Array(hex.match(/../g).map(function (pair) { return parseInt(pair, 16); })).buffer;\n"
        "  }\n"
        "  function equal(value, hex) {\n"
        "    var actual = new Uint8Array(value), expected = new Uint8Array(bytes(hex));\n"
        "    return actual.length === expected.length && actual.every(function (byte, index) { return byte === expected[index]; });\n"
        "  }\n"
        "  function unsupported() { return Promise.reject(new DOMException(\"Sealed Get fixture\", \"NotSupportedError\")); }\n"
        "  function get(options) {\n"
        "    var key = options.publicKey;\n"
        f"    if (key.rpId !== \"localhost\" || !equal(key.challenge, \"{challenge.hex()}\") ||\n"
        "        key.allowCredentials.length !== 1 || !equal(key.allowCredentials[0].id, \"8081\") ||\n"
        f"        !equal(key.extensions.prf.eval.first, \"{(bytes([3]) * 32).hex()}\")) {{ return unsupported(); }}\n"
        "    return new Promise(function (resolve, reject) {\n"
        "      function aborted() { clearTimeout(timer); reject(new DOMException(\"Fixture aborted\", \"AbortError\")); }\n"
        "      var timer = setTimeout(function () {\n"
        "        options.signal.removeEventListener(\"abort\", aborted);\n"
        "        resolve({ rawId: bytes(\"8081\"), response: {\n"
        f"          clientDataJSON: bytes(\"{client.hex()}\"),\n"
        f"          authenticatorData: bytes(\"{auth.hex()}\"),\n"
        f"          signature: bytes(\"{signature.hex()}\"),\n"
        f"          userHandle: bytes(\"{(bytes([4]) * 32).hex()}\")\n"
        "        }, getClientExtensionResults: function () {\n"
        + stalls[pause]
        + f"          return {{ prf: {{ results: {{ first: bytes(\"{bytes(range(0xA0, 0xC0)).hex()}\") }} }} }};\n"
        "        } });\n"
        "      }, 100);\n"
        "      if (options.signal.aborted) { aborted(); }\n"
        "      else { options.signal.addEventListener(\"abort\", aborted, { once: true }); }\n"
        "    });\n"
        "  }\n"
        "  ownerProtocol({ create: unsupported, get: get },\n"
        "    function () { return window.chrome && window.chrome.webview; });\n"
        "})();\n"
    )


def fixture_bootstrap(profile: str) -> str:
    success_modes = {
        "successful_get": "none",
        "successful_get_release_delay": "release",
        "successful_get_writing_delay": "writing",
    }
    if profile in success_modes:
        return successful_get_bootstrap(success_modes[profile])
    # The credential adapter only waits for abort and never invokes a real
    # authenticator. Separate native-event adapters below induce declared faults.
    trigger = TRIGGERS.get(profile, "")
    native = "function () { return window.chrome && window.chrome.webview; }"
    prelude = ""
    if profile in ("duplicate_request", "interleaved_pair", "delayed_delivery", "withheld_delivery"):
        prelude = delivery_port(profile)
        native = "deliveryPort"
    if profile in ("readonly_write", "readonly_control"):
        # This adversarial profile is never part of normal G3. Keep the real
        # SDK event and ArrayBuffers; after core receipt, attempt exactly one
        # prohibited write to the request mapping. Require actual native crash.
        prelude = (
            "  var request = null, reply = null, attempted = false;\n"
            "  function faultPort() {\n"
            "    var port = window.chrome && window.chrome.webview;\n"
            "    if (!port) { return null; }\n"
            "    return {\n"
            "      releaseBuffer: function (buffer) { port.releaseBuffer(buffer); },\n"
            "      addEventListener: function (name, listener) {\n"
            "        port.addEventListener(name, function (event) {\n"
            "          var buffer = event.getBuffer();\n"
            "          if (event.additionalData.role === \"request\") { request = buffer; }\n"
            "          else if (event.additionalData.role === \"reply\") { reply = buffer; }\n"
            "          listener(event);\n"
            "          if (!attempted && request && reply && Atomics.load(new Int32Array(reply, 0, 16), 10) === 7) {\n"
            "            attempted = true;\n"
            "            if (Atomics.compareExchange(new Int32Array(reply, 0, 16), 10, 7, 1) !== 7) { return; }\n"
            + (
                "            new Uint8Array(request)[64] = 0;\n"
                if profile == "readonly_write"
                else ""
            )
            + "          }\n"
            "        });\n"
            "      }\n"
            "    };\n"
            "  }\n"
        )
        native = "faultPort"
    return (
        "(function () {\n"
        + prelude
        +
        "  function pending(options) {\n"
        + (f"    {TRIGGERS['popup']}\n" if profile == "popup_receipt" else "")
        +
        "    return new Promise(function (_resolve, reject) {\n"
        "      function aborted() { reject(new DOMException(\"Fixture aborted\", \"AbortError\")); }\n"
        "      if (options.signal.aborted) { aborted(); }\n"
        "      else { options.signal.addEventListener(\"abort\", aborted, { once: true }); }\n"
        "    });\n"
        "  }\n"
        "  ownerProtocol({ create: pending, get: pending },\n"
        f"    {native});\n"
        + (f'  window.addEventListener("DOMContentLoaded", function () {{ {trigger} }}, {{ once: true }});\n' if trigger else "")
        + "})();\n"
    )


def response_head(body: bytes, profile: str) -> str:
    script = re.search(rb"<script>(.*?)</script>", body, re.S).group(1)
    style = re.search(rb"<style>(.*?)</style>", body, re.S).group(1)
    status = "401 Unauthorized" if profile == "authentication" else "200 OK"
    extra = {
        "download": 'Content-Disposition: attachment; filename="denied-fixture.txt"\r\n',
        "authentication": 'WWW-Authenticate: Basic realm="sealed-owner-qualification"\r\n',
    }.get(profile, "")
    return (
        f"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n{extra}"
        "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\n"
        "Cross-Origin-Resource-Policy: same-origin\r\n"
        "Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self), "
        "clipboard-read=(), clipboard-write=(), camera=(), microphone=(), geolocation=()\r\n"
        "Connection: close\r\n"
        "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; "
        f"script-src 'sha256-{csp_hash(script)}'; style-src 'sha256-{csp_hash(style)}'; "
        "img-src 'none'; connect-src 'none'\r\n\r\n"
    )


def outputs() -> dict[Path, bytes]:
    core = (ASSETS / "owner-core.js").read_text(encoding="utf-8")
    shell = (ASSETS / "owner-shell.html").read_text(encoding="utf-8")
    production = document(core, shell, (ASSETS / "owner-production.js").read_text(encoding="utf-8"))
    result = {
        ASSETS / "owner.html": production,
        ASSETS / "manifest.v1": f"{digest(production).hex()}  /owner.html  text/html; charset=utf-8\n".encode(),
    }
    native = ["// Generated by scripts/owner_bridge_assets.py; do not edit.\n", "use super::assets::Response;\n"]
    manifest = {"core_sha256": digest(core.encode()).hex(), "production_sha256": digest(production).hex(), "profiles": {}}
    for profile in PROFILES:
        body = document(core, shell, fixture_bootstrap(profile))
        head = response_head(body, profile).encode("ascii")
        result[ASSETS / "qualification" / f"{profile}.html"] = body
        manifest["profiles"][profile] = {"html_sha256": digest(body).hex(), "response_sha256": digest(head + body).hex()}
        values = ", ".join(f"0x{byte:02x}" for byte in digest(head + body))
        native.append(
            f"pub(super) const {profile.upper()}: Response = Response {{\n"
            f'    body: include_bytes!("../../assets/qualification/{profile}.html"),\n'
            f'    head: {json.dumps(head.decode("ascii"))},\n'
            f"    digest: [{values}],\n}};\n"
        )
    result[ASSETS / "qualification" / "manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    # Rustfmt is allowed locally but Cargo is not. The generated byte array is
    # split at 15 values to match the pinned formatter's stable output.
    rust = "\n".join(native)
    rust = re.sub(r"    digest: \[(.*?)\],", lambda m: "    digest: [\n        " + ",\n        ".join(
        ", ".join(m.group(1).split(", ")[i:i + 15]) for i in (0, 15, 30)
    ) + ",\n    ],", rust)
    result[BRIDGE / "src/listener/fixture_assets.rs"] = rust.encode()
    return result


def check() -> None:
    for path, expected in outputs().items():
        if path.read_bytes() != expected:
            raise AssertionError(f"owner bundle drift: {path.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        for path, data in outputs().items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    check()
    print("owner core and sealed bundles: ALL MATCH")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
