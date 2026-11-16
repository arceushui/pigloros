//! The provider-side revocation control responder (ADR-069 R11 §8).
//!
//! [`RevocationUpdateResponder`] owns every step of one RCC1/RCU1 → RCA1
//! exchange, in the normative order of R11 §8.3:
//!
//! 1. read RCC1, then RCU1, then the client's EOF, all by the deadline;
//! 2. decode RCC1: canonical, self-digested, attempt sets strictly
//!    increasing, nonzero and at most 256, the required set a subset of the
//!    live set;
//! 3. resolve the installed authority ([`InstalledAuthorityObjects`]) and
//!    authenticate RCU1 under it: the next epoch is exactly the current one
//!    plus one, under the unchanged TRS1. RCC1 must bind the exact RCU1
//!    bytes;
//! 4. fence: await the [`AttemptStateSource`] within the remaining deadline;
//! 5. require every attempt of its view to be in RCC1's live set and to
//!    have proved its cleanup (R11 D8);
//! 6. build RCA1 (`remaining-matching-attempts = 0`), sign it through the
//!    one runtime-attestation signer, verify it, and write it.
//!
//! Every other outcome writes zero bytes. The last acknowledged exchange is
//! retained: a byte-identical RCC1 and RCU1 get the retained RCA1 bytes
//! again, with no new signature and without repeating steps 3 to 5. Once
//! signing is closed (a self-revoking update was acknowledged), only that
//! resend remains.
//!
//! The responder takes a stream that already passed the UID 0 peer check
//! and knows nothing of endpoints, units or modes. Its only variable input
//! is the [`AttemptStateSource`]: the live runtime's fenced lifecycle, or
//! the recovery peer's read-only registry (#349, R12).

use std::future::Future;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use pos_reference::control_framing;
use pos_reference::sandbox_provider_protocol::{
    RecoveryCancellationContext, RevocationAcknowledgement, RevocationAcknowledgementFields,
    RevocationUpdateRequest, SandboxRevocationSnapshot, SandboxTrustSnapshot,
};
use pos_reference::selector::installation::authority::{
    AuthorityResolution, InstalledAuthorityObjects,
};

use crate::{sign_verified, AdmittedRuntimeKey, RuntimeAttestationSigner};

/// The framing bound of every provider record (ADR-069 §4).
const FRAME_LIMIT: usize = 16 * 1024 * 1024;

/// One attempt of a fenced view, as the responder reads it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptCleanupState {
    /// The `AttemptId`.
    pub attempt_id: [u8; 16],
    /// Whether the attempt ended with its cleanup proved.
    pub cleanup_proved: bool,
}

/// The attempt state an acknowledgement is decided on (R11 §8.1).
pub trait AttemptStateSource {
    /// Fence admission and yield every attempt, or `None` when the view
    /// cannot be taken.
    fn attempt_states(&self) -> impl Future<Output = Option<Vec<AttemptCleanupState>>> + Send;
}

/// What one exchange did.
#[derive(Debug)]
pub enum ExchangeOutcome {
    /// A fresh RCA1 was written, acknowledging the authenticated `next`
    /// RVS1 under `trust`.
    Acknowledged {
        /// The unchanged TRS1.
        trust: Box<SandboxTrustSnapshot>,
        /// The acknowledged RVS1.
        next: Box<SandboxRevocationSnapshot>,
    },
    /// The retained RCA1 was written again.
    Resent,
    /// Zero bytes were written; `fenced` once the attempt state source was
    /// reached, whatever it returned.
    Refused {
        /// Whether the exchange reached the fence.
        fenced: bool,
    },
}

/// The last acknowledged exchange.
#[derive(Debug)]
struct Acknowledged {
    rcc1: Vec<u8>,
    rcu1: Vec<u8>,
    rca1: Vec<u8>,
}

/// The one RCC1/RCU1 → RCA1 responder of a provider process.
#[derive(Debug)]
pub struct RevocationUpdateResponder<'a, S, A> {
    signer: &'a S,
    key: AdmittedRuntimeKey<'a>,
    resolution: AuthorityResolution,
    source: A,
    acknowledged: Mutex<Option<Acknowledged>>,
    signing_closed: AtomicBool,
}

impl<'a, S: RuntimeAttestationSigner, A: AttemptStateSource> RevocationUpdateResponder<'a, S, A> {
    /// The responder that signs with `signer` under the admitted `key`,
    /// resolves RCU1 authority under `resolution` and reads attempt state
    /// from `source`.
    pub const fn new(
        signer: &'a S,
        key: AdmittedRuntimeKey<'a>,
        resolution: AuthorityResolution,
        source: A,
    ) -> Self {
        Self {
            signer,
            key,
            resolution,
            source,
            acknowledged: Mutex::new(None),
            signing_closed: AtomicBool::new(false),
        }
    }

    /// Sign nothing more: only the retained RCA1 may be resent (R11 §8.4).
    pub fn close_signing(&self) {
        self.signing_closed.store(true, Ordering::Release);
    }

    /// Answer the exchange on `stream`, whose reads and writes end at
    /// `deadline`, as `deadline` also bounds the fence. The caller sends
    /// server write EOF after an RCA1.
    pub fn respond(&self, stream: &mut (impl Read + Write), deadline: Instant) -> ExchangeOutcome {
        let frames = read_exchange(stream);
        let retained = self
            .acknowledged
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|retained| {
                frames
                    .as_ref()
                    .is_some_and(|(context_bytes, update_bytes)| {
                        *context_bytes == retained.rcc1 && *update_bytes == retained.rcu1
                    })
            })
            .map(|retained| retained.rca1.clone());
        match (retained, frames) {
            (Some(acknowledgement_bytes), _) => write_record(stream, &acknowledgement_bytes)
                .map_or(ExchangeOutcome::Refused { fenced: false }, |()| {
                    ExchangeOutcome::Resent
                }),
            (None, Some((context_bytes, update_bytes)))
                if !self.signing_closed.load(Ordering::Acquire) =>
            {
                self.acknowledge(stream, context_bytes, update_bytes, deadline)
            }
            (None, _) => ExchangeOutcome::Refused { fenced: false },
        }
    }

    /// Steps 2 to 6 for an exchange that is not a resend.
    fn acknowledge(
        &self,
        stream: &mut impl Write,
        context_bytes: Vec<u8>,
        update_bytes: Vec<u8>,
        deadline: Instant,
    ) -> ExchangeOutcome {
        let authenticated = RecoveryCancellationContext::from_canonical_cbor(&context_bytes)
            .ok()
            .zip(InstalledAuthorityObjects::resolve(&update_bytes, self.resolution).ok())
            .and_then(|(context, authority)| {
                RevocationUpdateRequest::authenticate(
                    &update_bytes,
                    authority.trust(),
                    authority.previous_revocation(),
                )
                .ok()
                .filter(|request| context.binds(request))
                .map(|request| (context, authority, request))
            });
        let Some((context, authority, request)) = authenticated else {
            return ExchangeOutcome::Refused { fenced: false };
        };
        let fields = self
            .fenced_view(deadline)
            .filter(|view| {
                view.iter().all(|attempt| {
                    attempt.cleanup_proved
                        && context
                            .previous_live_attempt_ids
                            .contains(&attempt.attempt_id)
                })
            })
            .map(|_| RevocationAcknowledgementFields {
                request_id: request.request_id,
                revocation_digest: request.next_revocation.snapshot_digest(),
                sir1_digest: context.sir1_digest,
                previous_provider_binding_digest: context.previous_provider_binding_digest,
                cancelled_attempt_ids: context.required_cancelled_attempt_ids.clone(),
                runtime_attestation_key_id: self.signer.runtime_attestation_key_id().to_owned(),
            });
        fields
            .and_then(|fields| self.sign(fields))
            .and_then(|acknowledgement_bytes| {
                write_record(stream, &acknowledgement_bytes)
                    .ok()
                    .map(|()| acknowledgement_bytes)
            })
            .map_or(
                ExchangeOutcome::Refused { fenced: true },
                |acknowledgement_bytes| {
                    *self
                        .acknowledged
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = Some(Acknowledged {
                        rcc1: context_bytes,
                        rcu1: update_bytes,
                        rca1: acknowledgement_bytes,
                    });
                    ExchangeOutcome::Acknowledged {
                        trust: Box::new(authority.trust().clone()),
                        next: Box::new(request.next_revocation),
                    }
                },
            )
    }

    /// Step 4: the view of the attempt state source, if it is taken by
    /// `deadline`. A view not taken in time is dropped part-way.
    fn fenced_view(&self, deadline: Instant) -> Option<Vec<AttemptCleanupState>> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .ok()
            .and_then(|runtime| {
                runtime
                    .block_on(tokio::time::timeout(
                        remaining,
                        self.source.attempt_states(),
                    ))
                    .ok()
                    .flatten()
            })
    }

    /// The canonical bytes of the signed, verified RCA1 of `fields`.
    fn sign(&self, fields: RevocationAcknowledgementFields) -> Option<Vec<u8>> {
        RevocationAcknowledgement::self_digested(fields)
            .ok()
            .and_then(|record| sign_verified(self.signer, self.key, record).ok())
            .and_then(|verified| RevocationAcknowledgement::new(verified, self.key.key()).ok())
            .and_then(|acknowledgement| acknowledgement.to_canonical_cbor().ok())
    }
}

/// RCC1, RCU1 and the client's EOF, or `None` for any other stream.
fn read_exchange(stream: &mut impl Read) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut frame = || control_framing::read_frame(stream, FRAME_LIMIT).ok();
    frame()
        .flatten()
        .zip(frame().flatten())
        .filter(|_| matches!(frame(), Some(None)))
}

fn write_record(stream: &mut impl Write, bytes: &[u8]) -> Result<(), ()> {
    control_framing::write_frame(stream, bytes, FRAME_LIMIT).map_err(drop)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
