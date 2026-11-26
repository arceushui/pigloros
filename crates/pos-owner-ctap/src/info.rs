//! The capability check before any `makeCredential` (ADR-110 E20 LS6).

use pos_owner_bridge::{BridgeError, UnavailableCode};

use crate::cbor::Value;
use crate::hid::MAX_MESSAGE_BYTES;

const PRF_UNSUPPORTED: BridgeError = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);

/// What the client needs from an authenticator that passed the capability check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    /// The authenticator has built-in user verification (`options.uv`), tried before the PIN.
    pub uv: bool,
    /// The largest CTAPHID message either side may send: `maxMsgSize`, capped at 7,609 bytes.
    pub max_message: usize,
}

fn contains_text(value: Option<&Value<'_>>, wanted: &[&str]) -> bool {
    value.is_some_and(|value| {
        value
            .items()
            .iter()
            .any(|item| matches!(item, Value::Text(text) if wanted.contains(text)))
    })
}

fn option_set(info: &Value<'_>, name: &str) -> bool {
    info.int(0x04)
        .and_then(|options| options.text_key(name))
        .is_some_and(|value| *value == Value::Bool(true))
}

fn es256(algorithm: &Value<'_>) -> bool {
    algorithm.text_key("alg") == Some(&Value::Negative(6))
        && algorithm.text_key("type") == Some(&Value::Text("public-key"))
}

/// Check the decoded `authenticatorGetInfo` response `info` against LS6.
///
/// Every item must hold: `versions` has `FIDO_2_1` or `FIDO_2_1_PRE`; `pinUvAuthProtocols` has
/// 2; `options.pinUvAuthToken` and `options.clientPin` are `true` (a key with no PIN is
/// refused); `extensions` has `hmac-secret`; and `algorithms` is absent or has ES256.
///
/// # Errors
///
/// Returns `Unavailable(PrfUnsupported)` when any item fails or has the wrong type.
pub(crate) fn check(info: &Value<'_>) -> Result<Capabilities, BridgeError> {
    let versions = contains_text(info.int(0x01), &["FIDO_2_1", "FIDO_2_1_PRE"]);
    let protocol = info
        .int(0x06)
        .is_some_and(|protocols| protocols.items().contains(&Value::Unsigned(2)));
    let token = option_set(info, "pinUvAuthToken");
    let pin = option_set(info, "clientPin");
    let hmac_secret = contains_text(info.int(0x02), &["hmac-secret"]);
    let algorithm = info
        .int(0x0a)
        .is_none_or(|algorithms| algorithms.items().iter().any(es256));
    if !(versions && protocol && token && pin && hmac_secret && algorithm) {
        return Err(PRF_UNSUPPORTED);
    }
    let max_message = info
        .int(0x05)
        .and_then(Value::unsigned)
        .and_then(|size| usize::try_from(size).ok())
        .map_or(MAX_MESSAGE_BYTES, |size| size.min(MAX_MESSAGE_BYTES));
    Ok(Capabilities {
        uv: option_set(info, "uv"),
        max_message,
    })
}

#[cfg(test)]
mod tests;
