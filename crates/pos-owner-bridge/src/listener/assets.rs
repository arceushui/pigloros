//! The packaged owner document and its pinned digests (ADR-110 §4).
//!
//! `scripts/owner_bridge_vectors.py` recomputes every value here independently. The constants the
//! listener does not need are compiled for the unit tests only.

/// The one packaged asset, served as `/owner.html`.
pub(super) const OWNER_HTML: &[u8] = include_bytes!("../../assets/owner.html");

/// A compiled response keeps its bytes and expected digest together.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Response {
    pub(super) body: &'static [u8],
    pub(super) head: &'static str,
    pub(super) digest: [u8; 32],
}

pub(super) const OWNER: Response = Response {
    body: OWNER_HTML,
    head: OWNER_RESPONSE_HEAD,
    digest: OWNER_RESPONSE_SHA256,
};

/// The checked-in manifest line: `sha256  path  content-type`.
#[cfg(all(test, feature = "test-support"))]
pub(super) const ASSET_MANIFEST: &str = include_str!("../../assets/manifest.v1");

/// The SHA-256 of the owner document body.
#[cfg(all(test, feature = "test-support"))]
pub(super) const OWNER_HTML_SHA256: [u8; 32] = [
    0x16, 0x74, 0xd2, 0xd9, 0x83, 0x59, 0xc9, 0x40, 0x22, 0x09, 0x04, 0xf0, 0xb8, 0x4c, 0xa8, 0xae,
    0xc7, 0x00, 0x59, 0xe0, 0xd8, 0xd7, 0xfc, 0x95, 0x68, 0xf4, 0x78, 0xd5, 0x35, 0xbe, 0xac, 0xac,
];

/// The SHA-256 of the exact full owner response: status line, fixed headers and body.
pub(super) const OWNER_RESPONSE_SHA256: [u8; 32] = [
    0x5d, 0xc1, 0x5a, 0xce, 0x0f, 0xde, 0xf9, 0xb3, 0xee, 0xc9, 0x4c, 0xb9, 0xd2, 0x28, 0x11, 0x68,
    0xf8, 0x7d, 0x09, 0xad, 0x83, 0x38, 0xbd, 0x06, 0x22, 0x5a, 0x0e, 0xda, 0x25, 0xa9, 0xc9, 0x5c,
];

/// The base64 SHA-256 of the inline script block pinned by the CSP.
#[cfg(all(test, feature = "test-support"))]
pub(super) const CSP_SCRIPT_SHA256: &str = "1j7YP6tBlv7MEi44Vv3Ope5ctyTFZEUAmsMbdxyvWd0=";

/// The base64 SHA-256 of the inline style block pinned by the CSP.
#[cfg(all(test, feature = "test-support"))]
pub(super) const CSP_STYLE_SHA256: &str = "Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk=";

/// The status line and fixed headers of the owner response, ending in the blank line.
pub(super) const OWNER_RESPONSE_HEAD: &str = concat!(
    "HTTP/1.1 200 OK\r\n",
    "Content-Type: text/html; charset=utf-8\r\n",
    "Content-Length: 14431\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cross-Origin-Opener-Policy: same-origin\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
    "Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self), clipboard-read=(), clipboard-write=(), camera=(), microphone=(), geolocation=()\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-1j7YP6tBlv7MEi44Vv3Ope5ctyTFZEUAmsMbdxyvWd0='; style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);

/// The fixed `404` for every other admitted path.
pub(super) const NOT_FOUND_RESPONSE: &str = concat!(
    "HTTP/1.1 404 Not Found\r\n",
    "Content-Length: 0\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-1j7YP6tBlv7MEi44Vv3Ope5ctyTFZEUAmsMbdxyvWd0='; style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);

/// The fixed `400` for every malformed request.
pub(super) const BAD_REQUEST_RESPONSE: &str = concat!(
    "HTTP/1.1 400 Bad Request\r\n",
    "Content-Length: 0\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-1j7YP6tBlv7MEi44Vv3Ope5ctyTFZEUAmsMbdxyvWd0='; style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);
