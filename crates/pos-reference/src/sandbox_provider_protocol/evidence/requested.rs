//! RQE1, the requested-configuration evidence of ADR-069 R9 §4.3, with the
//! R10 §4.3 and §4.4 stdio properties and value code 10.

use std::collections::BTreeSet;

use ciborium::value::Value;

use super::{
    code, code_value, consistent, digest, digest_value, open, optional, optional_value, seal,
    Result,
};
use crate::sandbox_provider_protocol::codec::{
    array, bool_value, bytes_value, id16, require_canonical_order, text, text_value, uint,
    uint_value,
};
use crate::sandbox_provider_protocol::{
    RequestedConfigurationStatus, SandboxProviderProtocolError,
};

const MAGIC: &str = "RQE1";
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_PROPERTIES: usize = 128;
const MAX_PROPERTY_NAME_BYTES: usize = 64;
const MAX_DBUS_TEXT_BYTES: usize = 262_144;
const MAX_STRINGS: usize = 512;
const MAX_PAIRS: usize = 64;
const MAX_COMMANDS: usize = 8;
const MAX_ARGUMENTS: usize = 256;
const MAX_DESCRIPTORS: usize = 8;
const MAX_DESCRIPTOR_NAME_BYTES: usize = 255;
/// The manager-only property every verified readback adds (R9 §4.3).
const ROOT_IMAGE_POLICY: &str = "RootImagePolicy";
/// Read back as `ExtraFileDescriptorNames` (`as`) under this name.
const EXTRA_FILE_DESCRIPTORS: &str = "ExtraFileDescriptors";
/// The three R10 stdio descriptors: requested as `h` (code 10), and each
/// read back as its `…FileDescriptorName` (`s`) under this name.
const STDIO_DESCRIPTORS: [&str; 3] = [
    "StandardInputFileDescriptor",
    "StandardOutputFileDescriptor",
    "StandardErrorFileDescriptor",
];
/// The three R10 stdio enums, each requested and read back as `null`.
const STDIO_ENUMS: [&str; 3] = ["StandardInput", "StandardOutput", "StandardError"];
/// The R10 §4.3 verified value of a stdio enum.
const STDIO_ENUM_VALUE: &str = "null";

/// One typed D-Bus value as RQE1 records it; its variant is its value code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DbusValue {
    /// 0, `b`.
    Bool(bool),
    /// 1, `s`.
    String(String),
    /// 2, `t`.
    U64(u64),
    /// 3, `u`.
    U32(u32),
    /// 4, `as`.
    StringArray(Vec<String>),
    /// 5, `(bas)`.
    FlaggedStrings(bool, Vec<String>),
    /// 6, `a(ssbt)`.
    BindPaths(Vec<(String, String, bool, u64)>),
    /// 7, `a(ss)`.
    StringPairs(Vec<(String, String)>),
    /// 8, `a(sasb)`, or the `(path, argv, ignore-failure)` projection of
    /// `a(sasbttttuii)`.
    Commands(Vec<(String, Vec<String>, bool)>),
    /// 9, `a(hs)` with its descriptor names only, in submission order.
    DescriptorNames(Vec<String>),
    /// 10, `h`: one descriptor, which is never recorded (R10 §4.4).
    Descriptor,
}

impl DbusValue {
    /// The R9 or R10 value code.
    #[must_use]
    pub const fn code(&self) -> u8 {
        match self {
            Self::Bool(_) => 0,
            Self::String(_) => 1,
            Self::U64(_) => 2,
            Self::U32(_) => 3,
            Self::StringArray(_) => 4,
            Self::FlaggedStrings(..) => 5,
            Self::BindPaths(_) => 6,
            Self::StringPairs(_) => 7,
            Self::Commands(_) => 8,
            Self::DescriptorNames(_) | Self::Descriptor => self.descriptor_code(),
        }
    }

    /// Code 9 lists descriptor names; code 10 is one descriptor, which is
    /// never recorded (R10 §4.4).
    const fn descriptor_code(&self) -> u8 {
        if matches!(self, Self::Descriptor) {
            10
        } else {
            9
        }
    }

    fn value(&self) -> Value {
        Value::Array(vec![uint_value(u64::from(self.code())), self.payload()])
    }

    /// The value-code-specific payload of [`Self::value`].
    fn payload(&self) -> Value {
        match self {
            Self::Bool(value) => Value::Bool(*value),
            Self::String(value) => text_value(value),
            Self::U64(value) => uint_value(*value),
            Self::U32(value) => uint_value(u64::from(*value)),
            Self::StringArray(values) | Self::DescriptorNames(values) => texts_value(values),
            Self::Descriptor => Value::Null,
            Self::FlaggedStrings(flag, values) => {
                Value::Array(vec![Value::Bool(*flag), texts_value(values)])
            }
            Self::BindPaths(paths) => Value::Array(
                paths
                    .iter()
                    .map(|(source, destination, ignore, flags)| {
                        Value::Array(vec![
                            text_value(source),
                            text_value(destination),
                            Value::Bool(*ignore),
                            uint_value(*flags),
                        ])
                    })
                    .collect(),
            ),
            Self::StringPairs(pairs) => Value::Array(
                pairs
                    .iter()
                    .map(|(first, second)| {
                        Value::Array(vec![text_value(first), text_value(second)])
                    })
                    .collect(),
            ),
            Self::Commands(commands) => Value::Array(
                commands
                    .iter()
                    .map(|(path, arguments, ignore)| {
                        Value::Array(vec![
                            text_value(path),
                            texts_value(arguments),
                            Value::Bool(*ignore),
                        ])
                    })
                    .collect(),
            ),
        }
    }

    fn decode(value: &Value) -> Result<Self> {
        let [code, payload] = array::<2>(value)?;
        Self::decode_payload(uint(code)?, payload)
    }

    /// The value of code `code` from its payload.
    fn decode_payload(code: u64, payload: &Value) -> Result<Self> {
        match code {
            0 => bool_value(payload).map(Self::Bool),
            1 => dbus_text(payload).map(Self::String),
            2 => uint(payload).map(Self::U64),
            3 => super::u32_in(payload, 0..=u32::MAX).map(Self::U32),
            4 => texts(payload, MAX_STRINGS).map(Self::StringArray),
            5 => {
                let [flag, values] = array::<2>(payload)?;
                Ok(Self::FlaggedStrings(
                    bool_value(flag)?,
                    texts(values, MAX_STRINGS)?,
                ))
            }
            6 => list(payload, 0, MAX_PAIRS)?
                .iter()
                .map(bind_path)
                .collect::<Result<_>>()
                .map(Self::BindPaths),
            7 => list(payload, 0, MAX_PAIRS)?
                .iter()
                .map(string_pair)
                .collect::<Result<_>>()
                .map(Self::StringPairs),
            8 => list(payload, 0, MAX_COMMANDS)?
                .iter()
                .map(command)
                .collect::<Result<_>>()
                .map(Self::Commands),
            9 => list(payload, 0, MAX_DESCRIPTORS)?
                .iter()
                .map(descriptor_name)
                .collect::<Result<_>>()
                .map(Self::DescriptorNames),
            10 if payload == &Value::Null => Ok(Self::Descriptor),
            10 => Err(SandboxProviderProtocolError::InvalidEncoding),
            _ => Err(SandboxProviderProtocolError::FieldOutOfBounds),
        }
    }
}

/// One recorded property: a systemd property name and its typed value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbusProperty {
    /// The property name: an ASCII capital, then up to 63 ASCII letters and
    /// digits.
    pub name: String,
    /// The typed value.
    pub value: DbusValue,
}

impl DbusProperty {
    fn value(&self) -> Value {
        Value::Array(vec![text_value(&self.name), self.value.value()])
    }

    fn decode(value: &Value) -> Result<Self> {
        let [name, value] = array::<2>(value)?;
        Ok(Self {
            name: property_name(name)?,
            value: DbusValue::decode(value)?,
        })
    }
}

/// The unsigned fields of one RQE1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestedConfigurationEvidenceFields {
    /// The attempt.
    pub attempt_id: [u8; 16],
    /// The AGR1 self-digest.
    pub agr1_digest: [u8; 32],
    /// The requested-state verification result.
    pub status: RequestedConfigurationStatus,
    /// The properties passed to `StartTransientUnit`, sorted by name; null
    /// exactly when the status is `NotRequested`.
    pub requested: Option<Vec<DbusProperty>>,
    /// The typed readback the verifier compared, sorted by name; present
    /// for `Verified` and `Mismatch`.
    pub readback: Option<Vec<DbusProperty>>,
}

impl RequestedConfigurationEvidenceFields {
    fn unsigned(&self) -> Vec<Value> {
        vec![
            text_value(MAGIC),
            uint_value(1),
            bytes_value(&self.attempt_id),
            digest_value(&self.agr1_digest),
            code_value(self.status),
            optional_value(self.requested.as_deref(), properties_value),
            optional_value(self.readback.as_deref(), properties_value),
        ]
    }

    fn decode(fields: &[Value; 7]) -> Result<Self> {
        let decoded = Self {
            attempt_id: id16(&fields[2])?,
            agr1_digest: digest(&fields[3])?,
            status: code(&fields[4])?,
            requested: optional(&fields[5], properties)?,
            readback: optional(&fields[6], properties)?,
        };
        decoded.validate().map(|()| decoded)
    }

    /// The status decides which lists exist; a readback carries the R9
    /// §4.3 value code of each property, and a verified one exactly the
    /// requested names and `RootImagePolicy`, with the R10 §4.3 value of
    /// every stdio property.
    fn validate(&self) -> Result<()> {
        use RequestedConfigurationStatus as Status;
        match (self.status, &self.requested, &self.readback) {
            (Status::NotRequested, None, None) => Ok(()),
            (Status::ReadbackUnavailable, Some(requested), None) => {
                consistent(requested_codes_match(requested))
            }
            (Status::Verified, Some(requested), Some(readback)) => consistent(
                requested_codes_match(requested) && readback_verified(requested, readback),
            ),
            (Status::Mismatch, Some(requested), Some(readback)) => consistent(
                requested_codes_match(requested) && readback_codes_match(requested, readback),
            ),
            _ => Err(SandboxProviderProtocolError::InconsistentFields),
        }
    }
}

/// One RQE1: its validated fields, self-digest and canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestedConfigurationEvidence {
    fields: RequestedConfigurationEvidenceFields,
    digest: [u8; 32],
    bytes: Vec<u8>,
}

impl RequestedConfigurationEvidence {
    /// Encode and seal `fields`.
    ///
    /// # Errors
    /// Any R9 rule the decoded record would fail.
    pub fn new(fields: &RequestedConfigurationEvidenceFields) -> Result<Self> {
        seal(MAGIC, fields.unsigned()).and_then(|bytes| Self::from_canonical_cbor(&bytes))
    }

    /// Decode and validate exact canonical RQE1 bytes.
    ///
    /// # Errors
    /// A closed protocol error for every R9 §6 rule the record alone decides.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        open(
            bytes,
            MAGIC,
            MAX_RECORD_BYTES,
            RequestedConfigurationEvidenceFields::decode,
        )
        .map(|(fields, digest)| Self {
            fields,
            digest,
            bytes: bytes.to_vec(),
        })
    }

    /// The fields.
    #[must_use]
    pub const fn fields(&self) -> &RequestedConfigurationEvidenceFields {
        &self.fields
    }

    /// The self-digest under `PiglorOS.RQE1.v1\0`.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The canonical record bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The submitted value code of each requested property the R9 §4.3 and
/// R10 §4.3 tables fix; the static hardening properties keep their own
/// signatures. Code 10 is valid only under the three stdio descriptor names.
fn requested_code(name: &str) -> Option<u8> {
    r9_requested_code(name).or_else(|| stdio_requested_code(name))
}

/// The R9 §4.3 table of submitted value codes.
fn r9_requested_code(name: &str) -> Option<u8> {
    match name {
        "RootDirectory" => Some(1),
        "SystemCallFilter" | "RestrictAddressFamilies" => Some(5),
        "BindReadOnlyPaths" => Some(6),
        "MemoryMax" | "MemorySwapMax" | "TasksMax" | "CPUQuotaPerSecUSec" | "RuntimeMaxUSec"
        | "LimitNOFILE" | "LimitFSIZE" => Some(2),
        "FileDescriptorStoreMax" => Some(3),
        "TemporaryFileSystem" => Some(7),
        "ExecStart" => Some(8),
        EXTRA_FILE_DESCRIPTORS => Some(9),
        _ => None,
    }
}

/// The R10 §4.3 table: each stdio enum is submitted as `s` and each stdio
/// descriptor as `h`.
fn stdio_requested_code(name: &str) -> Option<u8> {
    if STDIO_ENUMS.contains(&name) {
        Some(1)
    } else if STDIO_DESCRIPTORS.contains(&name) {
        Some(10)
    } else {
        None
    }
}

/// `RootImagePolicy` is never requested, every requested property the
/// table fixes has its submitted code, and code 10 appears under no other
/// name.
fn requested_codes_match(requested: &[DbusProperty]) -> bool {
    requested.iter().all(|property| {
        let code = property.value.code();
        property.name != ROOT_IMAGE_POLICY
            && requested_code(&property.name)
                .map_or(code != DbusValue::Descriptor.code(), |fixed| fixed == code)
    })
}

/// Every readback entry has its R9 §4.3 or R10 §4.3 value code:
/// `RootImagePolicy` and the three stdio descriptors (read back as their
/// names) are `s`, `ExtraFileDescriptors` is read back as `as`, and every
/// other property is read back with the code it was requested with, so
/// code 10 is never read back. A mismatch may read back
/// `ExtraFileDescriptors` or a stdio descriptor without having requested
/// it, as the tables allow.
fn readback_codes_match(requested: &[DbusProperty], readback: &[DbusProperty]) -> bool {
    readback.iter().all(|property| {
        let expected = match property.name.as_str() {
            ROOT_IMAGE_POLICY => Some(1),
            EXTRA_FILE_DESCRIPTORS => Some(4),
            name if STDIO_DESCRIPTORS.contains(&name) => Some(1),
            name => requested
                .iter()
                .find(|requested| requested.name == name)
                .map(|requested| requested.value.code()),
        };
        expected == Some(property.value.code())
    })
}

/// A verified readback names exactly the requested properties and
/// `RootImagePolicy`.
fn readback_complete(requested: &[DbusProperty], readback: &[DbusProperty]) -> bool {
    let expected = requested
        .iter()
        .map(|property| property.name.as_str())
        .chain([ROOT_IMAGE_POLICY])
        .collect::<BTreeSet<_>>();
    let actual = readback
        .iter()
        .map(|property| property.name.as_str())
        .collect::<BTreeSet<_>>();
    expected == actual
}

/// A verified readback carries the R9 §4.3 and R10 §4.3 value code of each
/// property, exactly the requested names and `RootImagePolicy`, and the
/// R10 §4.3 value of every stdio property.
fn readback_verified(requested: &[DbusProperty], readback: &[DbusProperty]) -> bool {
    readback_codes_match(requested, readback)
        && readback_complete(requested, readback)
        && stdio_verified(readback)
}

/// A verified readback has the R10 §4.3 value of every stdio property it
/// names: `"null"` for the three enums and `""` for the three descriptor
/// names, so no stream is routed to the journal, a terminal, a socket or a
/// file.
fn stdio_verified(readback: &[DbusProperty]) -> bool {
    readback.iter().all(|property| {
        verified_stdio_value(&property.name)
            .is_none_or(|verified| property.value == DbusValue::String(verified.to_owned()))
    })
}

/// The R10 §4.3 verified readback value under `name`, if it is a stdio
/// property.
fn verified_stdio_value(name: &str) -> Option<&'static str> {
    if STDIO_ENUMS.contains(&name) {
        Some(STDIO_ENUM_VALUE)
    } else if STDIO_DESCRIPTORS.contains(&name) {
        Some("")
    } else {
        None
    }
}

fn properties_value(properties: &[DbusProperty]) -> Value {
    Value::Array(properties.iter().map(DbusProperty::value).collect())
}

/// 1 to 128 properties, strictly sorted by the canonical encoding of their
/// names.
fn properties(value: &Value) -> Result<Vec<DbusProperty>> {
    let properties = list(value, 1, MAX_PROPERTIES)?
        .iter()
        .map(DbusProperty::decode)
        .collect::<Result<Vec<_>>>()?;
    require_canonical_order(
        &properties
            .iter()
            .map(|property| text_value(&property.name))
            .collect::<Vec<_>>(),
    )
    .map(|()| properties)
}

fn property_name(value: &Value) -> Result<String> {
    let name = text(value)?;
    let mut bytes = name.bytes();
    let valid = name.len() <= MAX_PROPERTY_NAME_BYTES
        && bytes.next().is_some_and(|first| first.is_ascii_uppercase())
        && bytes.all(|byte| byte.is_ascii_alphanumeric());
    if valid {
        Ok(name.to_owned())
    } else {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

/// An array of `minimum..=maximum` entries.
fn list(value: &Value, minimum: usize, maximum: usize) -> Result<&[Value]> {
    let Value::Array(values) = value else {
        return Err(SandboxProviderProtocolError::InvalidEncoding);
    };
    if (minimum..=maximum).contains(&values.len()) {
        Ok(values)
    } else {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

fn bounded_text(value: &Value, minimum: usize, maximum: usize) -> Result<String> {
    let value = text(value)?;
    if (minimum..=maximum).contains(&value.len()) {
        Ok(value.to_owned())
    } else {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    }
}

fn dbus_text(value: &Value) -> Result<String> {
    bounded_text(value, 0, MAX_DBUS_TEXT_BYTES)
}

fn texts(value: &Value, maximum: usize) -> Result<Vec<String>> {
    list(value, 0, maximum)?.iter().map(dbus_text).collect()
}

fn texts_value(values: &[String]) -> Value {
    Value::Array(values.iter().map(|value| text_value(value)).collect())
}

fn bind_path(value: &Value) -> Result<(String, String, bool, u64)> {
    let [source, destination, ignore, flags] = array::<4>(value)?;
    Ok((
        dbus_text(source)?,
        dbus_text(destination)?,
        bool_value(ignore)?,
        uint(flags)?,
    ))
}

fn string_pair(value: &Value) -> Result<(String, String)> {
    let [first, second] = array::<2>(value)?;
    Ok((dbus_text(first)?, dbus_text(second)?))
}

fn command(value: &Value) -> Result<(String, Vec<String>, bool)> {
    let [path, arguments, ignore] = array::<3>(value)?;
    Ok((
        dbus_text(path)?,
        texts(arguments, MAX_ARGUMENTS)?,
        bool_value(ignore)?,
    ))
}

fn descriptor_name(value: &Value) -> Result<String> {
    bounded_text(value, 1, MAX_DESCRIPTOR_NAME_BYTES)
}
