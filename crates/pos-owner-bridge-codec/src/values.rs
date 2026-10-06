//! Named fixed-width values carried by the owner-bridge wire contracts.

macro_rules! fixed_bytes_value {
    ($name:ident, $length:expr_2021, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[repr(transparent)]
        pub struct $name([u8; $length]);

        impl $name {
            /// Construct this exact-width value from its wire bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact bytes carried by this value.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }
    };
}

fixed_bytes_value!(
    CeremonyId,
    16,
    "The exact 16-byte identity of one owner-bridge `WebAuthn` ceremony."
);
fixed_bytes_value!(
    WebAuthnChallenge,
    32,
    "The exact 32-byte `WebAuthn` challenge owned by the host."
);
fixed_bytes_value!(
    OwnerUserHandle,
    32,
    "The exact 32-byte opaque user handle for the owner credential."
);
fixed_bytes_value!(
    PrfInput,
    32,
    "The exact 32-byte input supplied to the `WebAuthn` PRF extension."
);
fixed_bytes_value!(
    PrfResult,
    32,
    "The exact 32-byte result returned by the `WebAuthn` PRF extension."
);
fixed_bytes_value!(
    SubjectId,
    16,
    "The exact 16-byte durable subject identity that owns a credential binding."
);
fixed_bytes_value!(
    ImagePathSha256,
    32,
    "The exact SHA-256 digest of the browser image path retained for cleanup."
);
