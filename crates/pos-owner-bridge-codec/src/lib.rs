#![no_std]
#![forbid(unsafe_code)]

//! Closed, fixed-buffer codecs for the ADR-110 local owner bridge.
//!
//! This crate deliberately exposes only deterministic binary values and their
//! validation. It owns no transport, allocation, `WebView`, or credential
//! lifecycle policy; those belong to the `pos-owner-bridge` Module in the
//! next stack slice.

mod authenticator_data;
mod cbor;
mod client_data;
mod control;
mod error;
mod http;
mod payload;
mod webauthn;

pub use authenticator_data::{
    parse_assertion_authenticator_data, parse_none_attestation_object, AssertionAuthenticatorData,
    CoseEs256PublicKey, CreateAuthenticatorData, CANONICAL_COSE_ES256_KEY_BYTES,
};
pub use client_data::validate_client_data_json;
pub use control::{
    CeremonyKind, ControlRole, ControlState, OwnerBridgeControlV1, CONTROL_HEADER_BYTES,
    CREATE_REPLY_BUFFER_CAPACITY, GET_REPLY_BUFFER_CAPACITY, REQUEST_BUFFER_CAPACITY,
};
pub use error::OwnerBridgeCodecError;
pub use http::{admit_loopback_http_request, LoopbackRequestDisposition};
pub use payload::{
    decode_assertion_reply, decode_attestation_reply, decode_create_options, decode_get_options,
    encode_assertion_reply, encode_attestation_reply, encode_create_options, encode_get_options,
    AssertionReplyV1, AttestationReplyV1, CreateOptionsV1, GetOptionsV1, TransportCodes,
};
pub use webauthn::{
    verify_assertion_reply, verify_attestation_reply, AssertionVerificationContext,
    CreateVerificationContext, StoredCredential, VerifiedAssertion, VerifiedRegistration,
};
