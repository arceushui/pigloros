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
    0x6a, 0x3a, 0x14, 0xb8, 0xd5, 0xa8, 0x6b, 0xd8, 0x03, 0x13, 0x5a, 0x97, 0x12, 0x7c, 0x59, 0xec,
    0x59, 0x9a, 0x2c, 0x56, 0xa6, 0xa7, 0x98, 0x4a, 0x9c, 0x23, 0x00, 0xe6, 0x5f, 0x98, 0xa2, 0xb5,
];

/// The SHA-256 of the exact full owner response: status line, fixed headers and body.
pub(super) const OWNER_RESPONSE_SHA256: [u8; 32] = [
    0x4d, 0x30, 0xfd, 0x70, 0x1b, 0x05, 0x16, 0xd1, 0xb4, 0x6d, 0x83, 0xdb, 0x85, 0x6c, 0x51, 0x62,
    0x82, 0x9b, 0x32, 0x60, 0xb5, 0x92, 0x1a, 0x8e, 0x3f, 0x16, 0x29, 0xd2, 0x85, 0x8c, 0xa9, 0x7b,
];

/// The base64 SHA-256 of the inline script block pinned by the CSP.
#[cfg(all(test, feature = "test-support"))]
pub(super) const CSP_SCRIPT_SHA256: &str = "1ypFyah3RYh3RHqn5Fk5ofzpiF7/JD5SLr4sBrvix0E=";

/// The base64 SHA-256 of the inline style block pinned by the CSP.
#[cfg(all(test, feature = "test-support"))]
pub(super) const CSP_STYLE_SHA256: &str = "Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk=";

/// The status line and fixed headers of the owner response, ending in the blank line.
pub(super) const OWNER_RESPONSE_HEAD: &str = concat!(
    "HTTP/1.1 200 OK\r\n",
    "Content-Type: text/html; charset=utf-8\r\n",
    "Content-Length: 13313\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cross-Origin-Opener-Policy: same-origin\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
    "Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self), clipboard-read=(), clipboard-write=(), camera=(), microphone=(), geolocation=()\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-1ypFyah3RYh3RHqn5Fk5ofzpiF7/JD5SLr4sBrvix0E='; style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);

/// The fixed `404` for every other admitted path.
pub(super) const NOT_FOUND_RESPONSE: &str = concat!(
    "HTTP/1.1 404 Not Found\r\n",
    "Content-Length: 0\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-1ypFyah3RYh3RHqn5Fk5ofzpiF7/JD5SLr4sBrvix0E='; style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);

/// The fixed `400` for every malformed request.
pub(super) const BAD_REQUEST_RESPONSE: &str = concat!(
    "HTTP/1.1 400 Bad Request\r\n",
    "Content-Length: 0\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'sha256-1ypFyah3RYh3RHqn5Fk5ofzpiF7/JD5SLr4sBrvix0E='; style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);
