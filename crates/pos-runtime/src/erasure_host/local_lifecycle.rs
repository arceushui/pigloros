//! The Local lifecycle host commands of `LocalErasureDriverV1` and
//! `LocalErasureSignerV1` (ADR-136 §5 and §6; ticket #1431).
//!
//! The driver is the only lifecycle caller. It prepares each step through
//! these commands, which run the Local authority's pure preparation over a
//! fresh snapshot and the request's verified progress, and retain what the
//! step will reference before its lifecycle command. The signer re-derives
//! each preimage through the same commands before it signs, so it signs only
//! what the committed state yields. The startup sweep deletes erasure
//! objects no committed record references and no active attempt needs.

use std::collections::BTreeSet;
use std::sync::Arc;

use pos_core::{
    local_erasure_host_timeline_v1, local_erasure_receipt_body_reference_v1, ErasureErrorV1,
    ErasureHostErrorV1, ErasureLifecycleV1, ErasurePersistencePortV1, ErasureReceiptProvenanceV1,
    ErasureReceiptV1, ErasureRecordedProgressReadV1, ErasureRecordedProgressV1, ErasureReferenceV1,
    ErasureRequestV1, ErasureStateV1, ErasureVerifiedInventoryV1, KeyRegistryStateV1,
    LocalErasureOwnerResultV1, LocalErasureRejectionV1, LocalErasureSignaturePurposeV1,
    LocalErasureSignatureV1, TimelineId, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1,
};

use super::{
    map_erasure_error, ErasureCommandSenderV1, ErasureHostStore, HostedCoordinatorPortV1,
    LocalAttemptPreparationV1, LocalErasureSubmissionBindingV1, LocalReceiptPreparationV1,
};

/// The record tags of the startup sweep (owner decision Q13 on #1431).
const SWEPT_TAGS: [&str; 6] = ["ELS1", "ELO1", "ELAD1", "ELCG1", "ELNEG1", "ELRP1"];

/// The most objects one startup sweep reads per tag and deletes (Q13).
const SWEEP_MAX: usize = 4_096;

impl ErasureCommandSenderV1<'_> {
    /// The verified progress of `request` by its complete core recovery,
    /// `Ok(None)` when it has no manifest.
    ///
    /// # Errors
    /// A payload-free stale-generation, recovery or authorization error;
    /// [`ErasureHostErrorV1::AuthorizationDenied`] on a host without an
    /// authority composition.
    pub(super) fn recorded_local_progress(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<Option<ErasureRecordedProgressV1>, ErasureHostErrorV1> {
        let limits = self.host.recovery_limits;
        let authority = self.host.authority.clone();
        self.host
            .ensure_generation_with_inventory(self.generation)
            .and_then(|installed| {
                authority
                    .ok_or(ErasureHostErrorV1::AuthorizationDenied)
                    .map(|authority| (installed, authority))
            })
            .and_then(|(installed, authority)| {
                let port = HostedCoordinatorPortV1::new(
                    self.host.store.host_store(),
                    authority.as_ref(),
                    limits,
                )
                .with_verified_inventory(installed);
                let persistence: &dyn ErasurePersistencePortV1 = &port;
                persistence
                    .recorded_progress(&port, &port, request)
                    .map_err(map_erasure_error)
            })
    }

    /// The verified progress of a request with a manifest.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::Conflict`] for a request without one;
    /// otherwise as [`Self::recorded_local_progress`].
    fn manifested_progress(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<ErasureRecordedProgressV1, ErasureHostErrorV1> {
        self.recorded_local_progress(request)
            .and_then(|progress| progress.ok_or(ErasureHostErrorV1::Conflict))
    }

    /// Prepare the next attempt of a frozen Local request (ADR-136 §6;
    /// owner decision Q10 on #1431).
    ///
    /// With an active attempt the result is
    /// [`LocalAttemptPreparationV1::Active`]. Otherwise the Local authority
    /// builds the attempt that is due, if any, and the host retains the ELB1
    /// it pins under `CA(ELB1)` before returning it, because
    /// `admit_attempt` requires that bundle to be retained.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::AuthorizationDenied`] on a host without a Local
    /// composition, [`ErasureHostErrorV1::Conflict`] for a request the host
    /// does not hold; otherwise the payload-free recovery or store error.
    pub(crate) fn prepare_local_attempt(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<LocalAttemptPreparationV1, ErasureHostErrorV1> {
        self.host
            .local_submission
            .clone()
            .ok_or(ErasureHostErrorV1::AuthorizationDenied)
            .and_then(|binding| {
                self.manifested_progress(request)
                    .map(|progress| (binding, progress))
            })
            .and_then(|(binding, progress)| {
                if progress.active.is_some() {
                    Ok(LocalAttemptPreparationV1::Active)
                } else {
                    self.due_attempt(&binding, request, &progress)
                }
            })
    }

    /// The installed inventory and the ERQ1 of `request` in it.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::Conflict`] for a request the inventory does not
    /// hold; otherwise the host's readiness error.
    fn installed_request(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<(Arc<ErasureVerifiedInventoryV1>, ErasureRequestV1), ErasureHostErrorV1> {
        self.host.ready_state().and_then(|(_, _, installed)| {
            installed
                .states()
                .find(|state| state.request().reference() == request)
                .map(|state| state.request().clone())
                .ok_or(ErasureHostErrorV1::Conflict)
                .map(|erq1| (installed, erq1))
        })
    }

    /// The lifecycle of `request` in the installed inventory, which the
    /// signer requires to be `authorized` before it signs a freeze.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::Conflict`] for a request the inventory does not
    /// hold; otherwise the host's readiness error.
    pub(crate) fn local_request_lifecycle(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<ErasureLifecycleV1, ErasureHostErrorV1> {
        self.host.ready_state().and_then(|(_, _, installed)| {
            installed
                .states()
                .find(|state| state.request().reference() == request)
                .map(pos_core::ErasureVerifiedStateV1::lifecycle)
                .ok_or(ErasureHostErrorV1::Conflict)
        })
    }

    /// The attempt of `request` due after `progress`, which has no active
    /// attempt, with the ELB1 it pins retained.
    fn due_attempt(
        &mut self,
        binding: &LocalErasureSubmissionBindingV1,
        request: ErasureReferenceV1,
        progress: &ErasureRecordedProgressV1,
    ) -> Result<LocalAttemptPreparationV1, ErasureHostErrorV1> {
        self.installed_request(request)
            .and_then(|(installed, erq1)| {
                self.with_local_view(installed, |view| {
                    binding.preparation.prepare_attempt(view, &erq1, progress)
                })
            })
            .and_then(|prepared| {
                prepared.map_or(
                    Ok(LocalAttemptPreparationV1::Idle),
                    |(admission, bundle)| {
                        self.retain_local_erasure_object(&bundle)
                            .map(|_| LocalAttemptPreparationV1::Dispatch(Box::new(admission)))
                    },
                )
            })
    }

    /// Prepare the receipt that closes the active attempt of a Local
    /// request (ADR-136 §5 purpose 2 and §6).
    ///
    /// The Local authority builds the receipt input from the request's
    /// verified progress, the host retains the ELD1 disclosures it names,
    /// and core previews the receipt finalize would commit for it, whose
    /// `CA(ERCB1)` a purpose-2 ELS1 must sign.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::AuthorizationDenied`] on a host without a Local
    /// composition; otherwise the payload-free error of a receipt that
    /// cannot be built or previewed, such as an attempt with commands left
    /// to acknowledge.
    pub(crate) fn prepare_local_receipt(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<LocalReceiptPreparationV1, ErasureHostErrorV1> {
        self.host
            .local_submission
            .clone()
            .ok_or(ErasureHostErrorV1::AuthorizationDenied)
            .and_then(|binding| {
                self.manifested_progress(request).and_then(|progress| {
                    self.installed_request(request).and_then(|(_, erq1)| {
                        binding
                            .preparation
                            .prepare_receipt(&erq1, &progress)
                            .map_err(map_erasure_error)
                    })
                })
            })
            .and_then(|(input, disclosures)| {
                disclosures
                    .iter()
                    .try_for_each(|disclosure| {
                        self.retain_local_erasure_object(disclosure).map(drop)
                    })
                    .map(|()| input)
            })
            .and_then(|input| {
                self.preview_erasure_receipt(request, &input)
                    .and_then(|receipt| {
                        local_erasure_receipt_body_reference_v1(&receipt).map_err(map_erasure_error)
                    })
                    .map(|body| LocalReceiptPreparationV1 { input, body })
            })
    }

    /// Commit the authorize-stage rejection of a submitted Local request
    /// whose ERAZ1 no longer verifies (ADR-136 §6, *Failure before
    /// destruction*): its ELREJ1 is retained, then named as the rejection's
    /// provenance.
    ///
    /// # Errors
    /// The payload-free error of the retention or the rejection.
    pub(crate) fn reject_local_erasure(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Result<ErasureStateV1, ErasureHostErrorV1> {
        LocalErasureRejectionV1 {
            request,
            error: ErasureErrorV1::Unauthorized,
        }
        .to_canonical_cbor()
        .map_err(map_erasure_error)
        .and_then(|rejection| self.retain_local_erasure_object(&rejection))
        .and_then(|provenance| self.reject_erasure_request(request, provenance))
    }

    /// Retain one canonical erasure object, non-authoritative until a
    /// committed record references it.
    ///
    /// # Errors
    /// A payload-free stale-generation or store error.
    pub(crate) fn retain_local_erasure_object(
        &mut self,
        object: &[u8],
    ) -> Result<ErasureReferenceV1, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation).and_then(|()| {
            self.host
                .store
                .host_store()
                .retain_erasure_object(object, ERASURE_RETAINED_OBJECT_MAX_BYTES_V1)
                .map_err(map_erasure_error)
        })
    }

    /// The store's key registry, which the signer signs under inside this
    /// one host command.
    ///
    /// # Errors
    /// [`ErasureHostErrorV1::AuthorizationDenied`] when the store holds no
    /// readable key registry; otherwise the stale-generation error.
    pub(crate) fn local_signing_registry(
        &mut self,
    ) -> Result<KeyRegistryStateV1, ErasureHostErrorV1> {
        self.host.ensure_generation(self.generation).and_then(|()| {
            self.host
                .store
                .host_store()
                .load_key_registry()
                .ok()
                .flatten()
                .ok_or(ErasureHostErrorV1::AuthorizationDenied)
        })
    }

    /// The store's Erasure Host Timeline, `ELHT1` of its erasure store
    /// identity (owner decision of 2026-11-18 on #1431): the only Timeline
    /// the composed executor fences key destruction on.
    ///
    /// # Errors
    /// The payload-free error of a store identity that cannot be read or
    /// was never written.
    pub(crate) fn local_erasure_host_timeline(&mut self) -> Result<TimelineId, ErasureHostErrorV1> {
        self.host
            .store
            .host_store()
            .erasure_store_identity()
            .and_then(|identity| identity.ok_or(ErasureErrorV1::PolicyConflict))
            .and_then(|identity| {
                local_erasure_host_timeline_v1(ErasureReferenceV1::from_digest(
                    *identity.as_bytes(),
                ))
            })
            .map_err(map_erasure_error)
    }

    /// Every request of the installed inventory.
    ///
    /// # Errors
    /// A payload-free stale-generation error.
    pub(crate) fn local_erasure_requests(
        &mut self,
    ) -> Result<Vec<ErasureReferenceV1>, ErasureHostErrorV1> {
        self.host
            .ensure_generation_with_inventory(self.generation)
            .map(|installed| {
                installed
                    .states()
                    .map(|state| state.request().reference())
                    .collect()
            })
    }

    /// The startup sweep of unreferenced erasure objects (ADR-136 §5,
    /// *Sweep*; owner decision Q13 on #1431), or `None` when it was
    /// skipped.
    ///
    /// It deletes at most 4,096 ELS1, ELO1, ELAD1, ELCG1, ELNEG1 and ELRP1
    /// objects and keeps:
    /// - the purpose-2 ELS1 each receipt of every installed request names
    ///   as its signature;
    /// - every ELO1 of an installed request, every effect such an ELO1
    ///   binds, and every purpose-1 ELS1 over such an ELO1. That holds the
    ///   evidence of every committed acknowledgement and every ELO1 and ELS1
    ///   of an active attempt; an ELO1 its attempt later superseded is kept
    ///   too, which is safe.
    ///
    /// A committed freeze carries its purpose-0 ELS1 inside its ERFA1
    /// evidence and references no ELS1 object, so a purpose-0 ELS1 object
    /// is deleted, as is a purpose-2 ELS1 no receipt names, left by a
    /// re-prepare or a crash before its lifecycle command: Ed25519 is
    /// deterministic, so a later re-sign restores the same object. The
    /// sweep is skipped, never failed, when any read fails or a tag holds
    /// more than 4,096 objects.
    pub(crate) fn sweep_local_erasure_objects(&mut self) -> Option<usize> {
        self.sweep_inputs().and_then(|(requests, committed)| {
            let store = self.host.store.host_store();
            store
                .retained_erasure_objects("ELO1", SWEEP_MAX)
                .ok()
                .zip(store.retained_erasure_objects("ELS1", SWEEP_MAX).ok())
                .and_then(|(results, signatures)| {
                    sweep_keep(&requests, committed, &results, &signatures)
                })
                .and_then(|keep| {
                    store
                        .sweep_unreferenced_erasure_objects(&SWEPT_TAGS, &keep, SWEEP_MAX)
                        .ok()
                })
        })
    }

    /// Every installed request and the receipt signatures they reference.
    fn sweep_inputs(&mut self) -> Option<(Vec<ErasureReferenceV1>, BTreeSet<ErasureReferenceV1>)> {
        self.local_erasure_requests().ok().and_then(|requests| {
            requests
                .iter()
                .map(|request| self.committed_signatures(*request))
                .collect::<Option<Vec<_>>>()
                .map(|lists| (requests, lists.into_iter().flatten().collect()))
        })
    }

    /// The ELS1 addresses the receipts of `request` reference: the
    /// signature of each of its receipts.
    fn committed_signatures(
        &mut self,
        request: ErasureReferenceV1,
    ) -> Option<Vec<ErasureReferenceV1>> {
        self.recorded_local_progress(request)
            .ok()
            .flatten()
            .and_then(|progress| {
                receipt_chain(self.host.store.host_store(), progress.latest_receipt)
            })
            .map(|receipts| receipts.iter().map(ErasureReceiptV1::signature).collect())
    }
}

/// Every receipt of one request, from `latest` back through each
/// predecessor its receipt provenance names, or `None` when one cannot be
/// read. Core recovery has already verified the chain in this host
/// command.
fn receipt_chain(
    store: &dyn ErasureHostStore,
    latest: Option<ErasureReceiptV1>,
) -> Option<Vec<ErasureReceiptV1>> {
    let mut chain = Vec::new();
    let mut next = Some(latest);
    while let Some(Some(receipt)) = next {
        next = predecessor(store, &receipt);
        chain.push(receipt);
    }
    next.map(|_| chain)
}

/// The predecessor receipt of `receipt`, `Some(None)` for the first
/// attempt's, or `None` when it cannot be read.
fn predecessor(
    store: &dyn ErasureHostStore,
    receipt: &ErasureReceiptV1,
) -> Option<Option<ErasureReceiptV1>> {
    store
        .read_object(receipt.provenance())
        .ok()
        .and_then(|bytes| ErasureReceiptProvenanceV1::from_canonical_cbor(&bytes).ok())
        .and_then(|provenance| {
            provenance
                .predecessor_receipt()
                .map_or(Some(None), |digest| {
                    store
                        .read_object(digest)
                        .ok()
                        .and_then(|bytes| ErasureReceiptV1::from_canonical_cbor(&bytes).ok())
                        .map(Some)
                })
        })
}

/// Decode every retained object of one record type with its address, or
/// `None` when one does not decode.
fn decoded<R>(
    objects: &[Vec<u8>],
    decode: impl Fn(&[u8]) -> Result<R, ErasureErrorV1>,
    address: impl Fn(&R) -> Result<ErasureReferenceV1, ErasureErrorV1>,
) -> Option<Vec<(ErasureReferenceV1, R)>> {
    objects
        .iter()
        .map(|bytes| {
            decode(bytes.as_slice())
                .and_then(|record| address(&record).map(|reference| (reference, record)))
                .ok()
        })
        .collect()
}

/// The sweep's `keep` list: `committed`, every ELO1 of one of `requests`
/// with the effect it binds, and every purpose-1 ELS1 over such an ELO1;
/// `None` when a retained ELO1 or ELS1 does not decode.
fn sweep_keep(
    requests: &[ErasureReferenceV1],
    mut committed: BTreeSet<ErasureReferenceV1>,
    results: &[Vec<u8>],
    signatures: &[Vec<u8>],
) -> Option<Vec<ErasureReferenceV1>> {
    decoded(
        results,
        LocalErasureOwnerResultV1::from_canonical_cbor,
        LocalErasureOwnerResultV1::reference,
    )
    .zip(decoded(
        signatures,
        LocalErasureSignatureV1::from_canonical_cbor,
        LocalErasureSignatureV1::reference,
    ))
    .map(|(results, signatures)| {
        let kept = results
            .iter()
            .filter(|(_, result)| requests.contains(&result.request))
            .collect::<Vec<_>>();
        let addresses = kept
            .iter()
            .map(|(address, _)| *address)
            .collect::<BTreeSet<_>>();
        committed.extend(signatures.iter().filter_map(|(address, signature)| {
            (signature.purpose == LocalErasureSignaturePurposeV1::OwnerResult
                && addresses.contains(&signature.signed_digest))
            .then_some(*address)
        }));
        committed.extend(kept.iter().map(|(_, result)| result.effect_digest));
        committed.extend(addresses);
        committed.into_iter().collect()
    })
}
