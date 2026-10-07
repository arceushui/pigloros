//! The packaged owner document and its pinned digests (ADR-110 §4).
//!
//! `scripts/owner_bridge_vectors.py` recomputes every value here independently.

/// The one packaged asset, served as `/owner.html`.
pub const OWNER_HTML: &[u8] = include_bytes!("../../assets/owner.html");

/// The checked-in manifest line: `sha256  path  content-type`.
pub const ASSET_MANIFEST: &str = include_str!("../../assets/manifest.v1");

/// The SHA-256 of the owner document body.
pub const OWNER_HTML_SHA256: [u8; 32] = [
    0x69, 0xf1, 0x20, 0x2c, 0x74, 0xc7, 0x37, 0xbd, 0x79, 0x24, 0xe1, 0x30, 0xd5, 0xe9, 0x38, 0xac,
    0x5a, 0x68, 0xd3, 0xf0, 0x32, 0x95, 0x08, 0xd4, 0xef, 0x73, 0xf0, 0x47, 0x03, 0xfe, 0xc0, 0xb4,
];

/// The SHA-256 of the exact full owner response: status line, fixed headers and body.
pub const OWNER_RESPONSE_SHA256: [u8; 32] = [
    0x04, 0x76, 0xb0, 0xe4, 0x85, 0x7b, 0x38, 0x39, 0x7f, 0x43, 0x8c, 0x7e, 0xc2, 0xa8, 0x48, 0xf8,
    0xb1, 0x60, 0x31, 0xc7, 0xf7, 0xda, 0xe1, 0x7a, 0xd4, 0xaa, 0xe2, 0x9c, 0xb9, 0x41, 0x38, 0x33,
];

/// The base64 SHA-256 of the inline script block pinned by the CSP.
pub const CSP_SCRIPT_SHA256: &str = "dTkjYAZyEUxzw49iwnvZZLEbeFEnY0IvE69JOU4CTnE=";

/// The base64 SHA-256 of the inline style block pinned by the CSP.
pub const CSP_STYLE_SHA256: &str = "Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk=";

/// The status line and fixed headers of the owner response, ending in the blank line.
pub const OWNER_RESPONSE_HEAD: &str = concat!(
    "HTTP/1.1 200 OK\r\n",
    "Content-Type: text/html; charset=utf-8\r\n",
    "Content-Length: 13045\r\n",
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
    "script-src 'sha256-dTkjYAZyEUxzw49iwnvZZLEbeFEnY0IvE69JOU4CTnE='; ",
    "style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; ",
    "img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);

/// The fixed `404` for every other admitted path.
pub const NOT_FOUND_RESPONSE: &str = concat!(
    "HTTP/1.1 404 Not Found\r\n",
    "Content-Length: 0\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; ",
    "form-action 'none'; frame-ancestors 'none'; ",
    "script-src 'sha256-dTkjYAZyEUxzw49iwnvZZLEbeFEnY0IvE69JOU4CTnE='; ",
    "style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; ",
    "img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);

/// The fixed `400` for every malformed request.
pub const BAD_REQUEST_RESPONSE: &str = concat!(
    "HTTP/1.1 400 Bad Request\r\n",
    "Content-Length: 0\r\n",
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Connection: close\r\n",
    "Content-Security-Policy: default-src 'none'; base-uri 'none'; ",
    "form-action 'none'; frame-ancestors 'none'; ",
    "script-src 'sha256-dTkjYAZyEUxzw49iwnvZZLEbeFEnY0IvE69JOU4CTnE='; ",
    "style-src 'sha256-Q5v//7IetSl8ReqUsE3bO7kt7fOgIkckocSNwunJJmk='; ",
    "img-src 'none'; connect-src 'none'\r\n",
    "\r\n",
);
