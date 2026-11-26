use pos_owner_bridge::{BridgeError, UnavailableCode};

use super::{check, Capabilities};
use crate::cbor::{decode, Writer};
use crate::hid::MAX_MESSAGE_BYTES;

const REFUSED: BridgeError = BridgeError::Unavailable(UnavailableCode::PrfUnsupported);

/// The parts of an `authenticatorGetInfo` body a test varies.
#[derive(Clone, Copy)]
struct Info {
    versions: &'static [&'static str],
    extensions: &'static [&'static str],
    options: &'static [(&'static str, bool)],
    max_message: Option<u64>,
    protocols: &'static [u64],
    algorithms: Option<&'static [(u64, &'static str)]>,
}

const HONEST: Info = Info {
    versions: &["U2F_V2", "FIDO_2_0", "FIDO_2_1"],
    extensions: &["credProtect", "hmac-secret"],
    options: &[("uv", true), ("clientPin", true), ("pinUvAuthToken", true)],
    max_message: Some(1_200),
    protocols: &[2, 1],
    algorithms: Some(&[(7, "public-key"), (6, "public-key")]),
};

fn texts(writer: &mut Writer, items: &[&str]) {
    writer.array(items.len());
    for item in items {
        writer.text(item);
    }
}

fn options(writer: &mut Writer, options: &[(&str, bool)]) {
    writer.map(options.len());
    for (name, value) in options {
        writer.text(name).boolean(*value);
    }
}

fn protocols(writer: &mut Writer, protocols: &[u64]) {
    writer.array(protocols.len());
    for protocol in protocols {
        writer.unsigned(*protocol);
    }
}

fn algorithms(writer: &mut Writer, algorithms: &[(u64, &str)]) {
    writer.array(algorithms.len());
    for (magnitude, kind) in algorithms {
        writer
            .map(2)
            .text("alg")
            .negative(*magnitude)
            .text("type")
            .text(kind);
    }
}

fn encode(info: Info) -> Vec<u8> {
    let entries =
        4 + usize::from(info.max_message.is_some()) + usize::from(info.algorithms.is_some());
    let mut writer = Writer::default();
    writer.map(entries).unsigned(1);
    texts(&mut writer, info.versions);
    writer.unsigned(2);
    texts(&mut writer, info.extensions);
    writer.unsigned(4);
    options(&mut writer, info.options);
    if let Some(size) = info.max_message {
        writer.unsigned(5).unsigned(size);
    }
    writer.unsigned(6);
    protocols(&mut writer, info.protocols);
    if let Some(listed) = info.algorithms {
        writer.unsigned(10);
        algorithms(&mut writer, listed);
    }
    writer.finish()
}

fn checked(info: Info) -> Result<Capabilities, BridgeError> {
    let encoded = encode(info);
    decode(&encoded).map_or(Err(REFUSED), |value| check(&value))
}

#[test]
fn an_honest_ctap_2_1_key_passes_with_its_uv_and_message_size() {
    let expected = Capabilities {
        uv: true,
        max_message: 1_200,
    };
    assert_eq!(checked(HONEST), Ok(expected));
    let pre = Info {
        versions: &["FIDO_2_1_PRE"],
        options: &[("clientPin", true), ("pinUvAuthToken", true)],
        max_message: None,
        algorithms: None,
        ..HONEST
    };
    let expected = Capabilities {
        uv: false,
        max_message: MAX_MESSAGE_BYTES,
    };
    assert_eq!(checked(pre), Ok(expected));
}

#[test]
fn every_capability_check_item_refuses_on_its_own() {
    let failing = [
        Info {
            versions: &["U2F_V2", "FIDO_2_0"],
            ..HONEST
        },
        Info {
            protocols: &[1],
            ..HONEST
        },
        Info {
            options: &[("uv", true), ("clientPin", true)],
            ..HONEST
        },
        Info {
            options: &[("clientPin", true), ("pinUvAuthToken", false)],
            ..HONEST
        },
        Info {
            options: &[("clientPin", false), ("pinUvAuthToken", true)],
            ..HONEST
        },
        Info {
            options: &[("pinUvAuthToken", true)],
            ..HONEST
        },
        Info {
            extensions: &["credProtect"],
            ..HONEST
        },
        Info {
            algorithms: Some(&[(7, "public-key")]),
            ..HONEST
        },
        Info {
            algorithms: Some(&[(6, "other")]),
            ..HONEST
        },
    ];
    for info in failing {
        assert_eq!(checked(info), Err(REFUSED));
    }
}

#[test]
fn a_field_of_the_wrong_type_refuses_and_a_bad_size_is_capped() {
    let text_versions = Writer::default()
        .map(1)
        .unsigned(1)
        .text("FIDO_2_1")
        .finish();
    let refused = decode(&text_versions).map(|value| check(&value));
    assert_eq!(refused, Some(Err(REFUSED)));
    let mixed = Writer::default()
        .map(1)
        .unsigned(1)
        .array(2)
        .unsigned(1)
        .text("FIDO_2_1")
        .finish();
    let mixed = decode(&mixed).map(|value| super::contains_text(value.int(1), &["FIDO_2_1"]));
    assert_eq!(mixed, Some(true));
    let huge = Info {
        max_message: Some(60_000),
        ..HONEST
    };
    assert_eq!(
        checked(huge).map(|capabilities| capabilities.max_message),
        Ok(MAX_MESSAGE_BYTES)
    );
    let mut text_size = encode(HONEST);
    let at = text_size
        .windows(3)
        .position(|window| window == [0x05, 0x19, 0x04])
        .unwrap_or_default();
    text_size[at + 1] = 0x42;
    let size = decode(&text_size).map(|value| check(&value).map(|found| found.max_message));
    assert_eq!(size, Some(Ok(MAX_MESSAGE_BYTES)));
}
