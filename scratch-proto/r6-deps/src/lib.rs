//! THROWAWAY (#471 prototype). References every r6 dependency so that
//! `cargo shear` sees each one as used.
#![no_std]

pub use aes_gcm as _aes_gcm;
pub use base64 as _base64;
pub use getrandom as _getrandom;
pub use hkdf as _hkdf;
pub use httparse as _httparse;
pub use p256 as _p256;
pub use sha2 as _sha2;
pub use thiserror as _thiserror;
pub use zeroize as _zeroize;

#[cfg(windows)]
pub mod win {
    pub use webview2_com as _webview2_com;
    pub use windows as _windows;
}
