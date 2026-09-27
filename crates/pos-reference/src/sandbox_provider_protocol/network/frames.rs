//! Closed NXQ1/NXY1 framing. These values grant no connection authority.

use std::io::{Read, Write};

use ciborium::value::Value;

use super::{
    content_digest, validate_retention, NetworkExchangePlan, NetworkExchangeTranscript,
    SandboxProviderProtocolError, REQUEST_DOMAIN,
};
use crate::{
    control_framing,
    sandbox_provider_protocol::codec::{
        array, byte_string, bytes_value, decode_document, encode, text_value, uint, uint_value,
        MAX_DOCUMENT_BYTES,
    },
};

/// A complete NXQ1 verified against one independently authorized NXP1 occurrence.
///
/// Fields are private so the verified bytes and their plan cannot diverge.
/// This is a content check, not permission to connect: the provider's active
/// attempt must independently bind the endpoint, FD 3 and effective limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkExchangeRequest {
    plan: NetworkExchangePlan,
    bytes: Vec<u8>,
}

impl NetworkExchangeRequest {
    /// Prepare the exact adapter request for one planned occurrence.
    ///
    /// # Errors
    /// Rejects invalid plans, unsupported retention, unequal request identity,
    /// or an NXQ1 that cannot fit the 16 MiB encoded control-document ceiling.
    pub fn new(
        plan: &NetworkExchangePlan,
        request: &[u8],
    ) -> Result<Self, SandboxProviderProtocolError> {
        validate_plan(plan).and_then(|()| {
            check_encoded_size(plan.occurrence, plan.request_length, PayloadFrame::Query).and_then(
                |()| {
                    if request.len() as u64 != plan.request_length
                        || content_digest(REQUEST_DOMAIN, request) != plan.request_digest
                    {
                        return Err(SandboxProviderProtocolError::DigestMismatch);
                    }
                    Ok(Self {
                        plan: plan.clone(),
                        bytes: request.to_vec(),
                    })
                },
            )
        })
    }

    /// Read exactly one bounded, four-byte-length-prefixed NXQ1.
    ///
    /// The session supplies its deadline-aware reader and next ordered plan.
    /// Subsequent frames belong to subsequent calls; EOF is not an empty query.
    ///
    /// # Errors
    /// Rejects incomplete/oversized framing, noncanonical CBOR, wrong direction,
    /// and any field or content that differs from the expected occurrence.
    pub fn read_from(
        reader: &mut impl Read,
        plan: &NetworkExchangePlan,
    ) -> Result<Self, SandboxProviderProtocolError> {
        read_document(reader).and_then(|document| {
            array::<6>(&document).and_then(|fields| {
                byte_string(&fields[4]).and_then(|bytes| {
                    Self::new(plan, bytes).and_then(|expected| {
                        exact_document(&document, &expected.document()).map(|()| expected)
                    })
                })
            })
        })
    }

    /// Write the exact NXQ1 frame to the host-service channel.
    ///
    /// # Errors
    /// Rejects a writer that cannot accept the complete bounded frame.
    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), SandboxProviderProtocolError> {
        write_document(writer, &self.document())
    }

    /// Bytes verified before the provider may create its one destination socket.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Validate a successful response and construct its closed Captured reply.
    ///
    /// The provider must durably store the response and returned NXT1 before
    /// writing this reply. This method does not perform or attest persistence.
    ///
    /// # Errors
    /// Rejects a zero attempt, response mismatch, or encoded-size breach.
    pub fn capture(
        &self,
        attempt_id: [u8; 16],
        response: &[u8],
    ) -> Result<NetworkExchangeReply, SandboxProviderProtocolError> {
        check_encoded_size(
            self.plan.occurrence,
            response.len() as u64,
            PayloadFrame::Reply,
        )
        .and_then(|()| {
            NetworkExchangeTranscript::capture(attempt_id, &self.plan, &self.bytes, response).map(
                |transcript| NetworkExchangeReply {
                    exchange_id: self.plan.exchange_id,
                    occurrence: self.plan.occurrence,
                    outcome: ReplyOutcome::Captured {
                        bytes: response.to_vec(),
                        transcript,
                    },
                },
            )
        })
    }

    /// A terminal failed exchange, with no response bytes or transcript evidence.
    #[must_use]
    pub fn failed(&self, failure: NetworkExchangeFailure) -> NetworkExchangeReply {
        NetworkExchangeReply {
            exchange_id: self.plan.exchange_id,
            occurrence: self.plan.occurrence,
            outcome: ReplyOutcome::Failed(failure),
        }
    }

    fn document(&self) -> Value {
        Value::Array(vec![
            text_value("NXQ1"),
            uint_value(1),
            bytes_value(&self.plan.exchange_id),
            uint_value(self.plan.occurrence),
            bytes_value(&self.bytes),
            bytes_value(&self.plan.request_digest),
        ])
    }
}

/// NXY1's two terminal failure statuses. Neither can become capture evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkExchangeFailure {
    /// The single remote exchange could not complete within its required bounds.
    RemoteUnavailable,
    /// The complete response did not match the planned response identity.
    DigestMismatch,
}

#[derive(Clone, Debug, PartialEq)]
enum ReplyOutcome {
    Captured {
        bytes: Vec<u8>,
        transcript: NetworkExchangeTranscript,
    },
    Failed(NetworkExchangeFailure),
}

/// A closed NXY1 reply. Captured responses always retain their matching NXT1.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkExchangeReply {
    exchange_id: [u8; 16],
    occurrence: u64,
    outcome: ReplyOutcome,
}

impl NetworkExchangeReply {
    /// Read one NXY1 for the exact independently authorized attempt and plan.
    ///
    /// This validates capture identity but does not authenticate the peer or
    /// attest storage durability. The provider lifecycle owns those checks.
    ///
    /// # Errors
    /// Rejects framing/encoding errors, unknown status, inconsistent failure
    /// fields, or captured bytes/transcript digest that differ from the plan.
    pub fn read_from(
        reader: &mut impl Read,
        attempt_id: [u8; 16],
        plan: &NetworkExchangePlan,
    ) -> Result<Self, SandboxProviderProtocolError> {
        validate_plan(plan).and_then(|()| {
            if attempt_id == [0; 16] {
                return Err(SandboxProviderProtocolError::FieldOutOfBounds);
            }
            read_document(reader).and_then(|document| {
                array::<9>(&document).and_then(|fields| {
                    uint(&fields[4]).and_then(|status| {
                        let outcome = match status {
                            0 => byte_string(&fields[7]).and_then(|bytes| {
                                NetworkExchangeTranscript::from_response(attempt_id, plan, bytes)
                                    .map(|transcript| ReplyOutcome::Captured {
                                        bytes: bytes.to_vec(),
                                        transcript,
                                    })
                            }),
                            1 => Ok(ReplyOutcome::Failed(
                                NetworkExchangeFailure::RemoteUnavailable,
                            )),
                            2 => Ok(ReplyOutcome::Failed(NetworkExchangeFailure::DigestMismatch)),
                            _ => Err(SandboxProviderProtocolError::InvalidEncoding),
                        };
                        outcome.and_then(|outcome| {
                            let expected = Self {
                                exchange_id: plan.exchange_id,
                                occurrence: plan.occurrence,
                                outcome,
                            };
                            exact_document(&document, &expected.document()).map(|()| expected)
                        })
                    })
                })
            })
        })
    }

    /// Write one exact, bounded NXY1 frame.
    ///
    /// # Errors
    /// Rejects a writer that cannot accept the complete bounded frame.
    pub fn write_to(&self, writer: &mut impl Write) -> Result<(), SandboxProviderProtocolError> {
        write_document(writer, &self.document())
    }

    /// Return validated capture bytes, or no bytes for either terminal failure.
    #[must_use]
    pub fn response_bytes(&self) -> Option<&[u8]> {
        match &self.outcome {
            ReplyOutcome::Captured { bytes, .. } => Some(bytes),
            ReplyOutcome::Failed(_) => None,
        }
    }

    /// Return the exact transcript that must be persisted before Captured is sent.
    #[must_use]
    pub fn transcript(&self) -> Option<&NetworkExchangeTranscript> {
        match &self.outcome {
            ReplyOutcome::Captured { transcript, .. } => Some(transcript),
            ReplyOutcome::Failed(_) => None,
        }
    }

    /// Return the terminal failure, if this reply contains no capture.
    #[must_use]
    pub fn failure(&self) -> Option<NetworkExchangeFailure> {
        match self.outcome {
            ReplyOutcome::Failed(failure) => Some(failure),
            ReplyOutcome::Captured { .. } => None,
        }
    }

    fn document(&self) -> Value {
        let mut fields = vec![
            text_value("NXY1"),
            uint_value(1),
            bytes_value(&self.exchange_id),
            uint_value(self.occurrence),
        ];
        match &self.outcome {
            ReplyOutcome::Captured { bytes, transcript } => {
                let digest = super::content_digest(super::RESPONSE_DOMAIN, bytes);
                fields.extend([
                    uint_value(0),
                    uint_value(bytes.len() as u64),
                    bytes_value(&digest),
                    bytes_value(bytes),
                    bytes_value(&transcript.digest()),
                ]);
            }
            ReplyOutcome::Failed(failure) => {
                let status = match failure {
                    NetworkExchangeFailure::RemoteUnavailable => 1,
                    NetworkExchangeFailure::DigestMismatch => 2,
                };
                fields.extend([
                    uint_value(status),
                    uint_value(0),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                ]);
            }
        }
        Value::Array(fields)
    }
}

enum PayloadFrame {
    Query,
    Reply,
}

fn validate_plan(plan: &NetworkExchangePlan) -> Result<(), SandboxProviderProtocolError> {
    plan.validate()
        .and_then(|()| validate_retention(plan).map(|_| ()))
}

fn check_encoded_size(
    occurrence: u64,
    length: u64,
    frame: PayloadFrame,
) -> Result<(), SandboxProviderProtocolError> {
    // NXQ1 has 58 fixed bytes plus occurrence, byte-string length and payload.
    // Captured NXY1 has 93 fixed bytes and repeats the response length.
    let overhead = match frame {
        PayloadFrame::Reply => 93 + 2 * integer_size(length),
        PayloadFrame::Query => 58 + integer_size(length),
    };
    let encoded = length.saturating_add(overhead + integer_size(occurrence));
    if encoded > MAX_DOCUMENT_BYTES as u64 {
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

const fn integer_size(value: u64) -> u64 {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        65536..=4294967295 => 5,
        _ => 9,
    }
}

fn exact_document(actual: &Value, expected: &Value) -> Result<(), SandboxProviderProtocolError> {
    if actual == expected {
        Ok(())
    } else {
        Err(SandboxProviderProtocolError::InconsistentFields)
    }
}

fn read_document(reader: &mut impl Read) -> Result<Value, SandboxProviderProtocolError> {
    control_framing::read_frame(reader, MAX_DOCUMENT_BYTES)
        .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)
        .and_then(|bytes| bytes.ok_or(SandboxProviderProtocolError::InvalidEncoding))
        .and_then(|bytes| decode_document(&bytes))
}

fn write_document(
    writer: &mut impl Write,
    document: &Value,
) -> Result<(), SandboxProviderProtocolError> {
    encode(document).and_then(|bytes| {
        control_framing::write_frame(writer, &bytes, MAX_DOCUMENT_BYTES)
            .map_err(|_| SandboxProviderProtocolError::InvalidEncoding)
    })
}
