//! The packaged owner document and its pinned digests (ADR-110 §4).
//!
//! `scripts/owner_bridge_vectors.py` recomputes every value here independently. The constants the
//! listener does not need are compiled for the unit tests only.

/// The one packaged asset, served as `/owner.html`.
pub(super) const OWNER_HTML: &[u8] = include_bytes!("../../assets/owner.html");

/// The checked-in manifest line: `sha256  path  content-type`.
#[cfg(all(test, feature = "test-support"))]
pub(super) const ASSET_MANIFEST: &str = include_str!("../../assets/manifest.v1");

/// The SHA-256 of the owner document body.
#[cfg(all(test, feature = "test-support"))]
pub(super) const OWNER_HTML_SHA256: [u8; 32] = [
    0x26, 0x95, 0x9c, 0x19, 0x5e, 0xfa, 0xdd, 0x77, 0x6a, 0x96, 0xed, 0x61, 0xfc, 0x9c, 0xb9, 0xb9,
    0x11, 0xac, 0xd1, 0xe0, 0xd3, 0x65, 0x7a, 0xc9, 0xcb, 0x25, 0xc6, 0x04, 0x32, 0x26, 0x87, 0x1c,
];

/// The SHA-256 of the exact full owner response: status line, fixed headers and body.
pub(super) const OWNER_RESPONSE_SHA256: [u8; 32] = [
    0xd3, 0x82, 0x58, 0x7c, 0x99, 0xf9, 0xf8, 0xb6, 0x45, 0x46, 0xb0, 0xae, 0x03, 0x2d, 0xa0, 0x4d,
    0x1e, 0x99, 0xb7, 0xf8, 0x69, 0x15, 0x2c, 0xac, 0x31, 0x9b, 0xfe, 0x6d, 0xa1, 0xa2, 0x90, 0xfa,
];

/// The base64 SHA-256 of the inline script block pinned by the CSP.
#[cfg(all(test, feature = "test-support"))]
pub(super) const CSP_SCRIPT_SHA256: &str = "AtlDCzUThGI7TLQE2BbBBbZRz2Q74VVh54D3xnDda1E=";

/// The base64 SHA-256 of the inline style block pinned by the CSP.
#[cfg(all(test, feature = "test-support"))]
pub(super) const CSP_STYLE_SHA256: &str = "Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk=";

/// The status line and fixed headers of the owner response, ending in the blank line.
pub(super) const OWNER_RESPONSE_HEAD: &str = concat!(
    "HTTP/1.1 200 OK\r\n",
    "Content-Type: text/html; charset=utf-8\r\n",
    "Content-Length: 13108\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cross-Origin-Opener-Policy: same-origin\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
    "Permissions-Policy: publickey-credentials-create=(self), ",
    "publickey-credentials-get=(self), clipboard-read=(), ",
    "clipboard-write=(), camera=(), microphone=(), geolocation=()\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; ",
    "form-action 'none'; frame-ancestors 'none'; ",
    "script-src 'sha256-AtlDCzUThGI7TLQE2BbBBbZRz2Q74VVh54D3xnDda1E='; ",
    "style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; ",
    "img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);

/// The fixed `404` for every other admitted path.
pub(super) const NOT_FOUND_RESPONSE: &str = concat!(
    "HTTP/1.1 404 Not Found\r\n",
    "Content-Length: 0\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; ",
    "form-action 'none'; frame-ancestors 'none'; ",
    "script-src 'sha256-AtlDCzUThGI7TLQE2BbBBbZRz2Q74VVh54D3xnDda1E='; ",
    "style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; ",
    "img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);

/// The fixed `400` for every malformed request.
pub(super) const BAD_REQUEST_RESPONSE: &str = concat!(
    "HTTP/1.1 400 Bad Request\r\n",
    "Content-Length: 0\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; ",
    "form-action 'none'; frame-ancestors 'none'; ",
    "script-src 'sha256-AtlDCzUThGI7TLQE2BbBBbZRz2Q74VVh54D3xnDda1E='; ",
    "style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; ",
    "img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);
