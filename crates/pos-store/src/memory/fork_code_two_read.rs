//! `MemoryStore` side of the ADR-105 r6 R6.9 trusted reads.
//!
//! Validator (a) is the existing local-only admission and classified graph,
//! which every write path keeps. Validator (b) is this module: for a local
//! `FAR1` it is exactly validator (a), and for a code-2 `FAR1` it replaces
//! only the `FCC1` admission row, with the import admission row, and the local
//! `FCS1` custody store, with the imported `FCS1` store keyed by `FCT1` field
//! 6. A code-2 child never consults the local custody store, and a local child
//! never consults the imported one.

use std::collections::HashMap;

use pos_core::{
    Event, EventId, ForkClassifierRegistrationV1, ForkPublicationOperationV1, Hash,
    ImportedForkAttributionAdmissionV1, ImportedForkClassifierGraphV1, Seq, TimelineId,
};

use super::MemoryStore;
use crate::{
    fork_event_authority::{
        imported_admission_matches, imported_graph_matches, AuthorityValidatorV1,
        ValidatedAdmissionV1, ValidatedGraphV1, ValidatedImportV1, ValidatedOriginV1,
    },
    fork_manifest_publication::{
        publication_parent_head, trusted_committed_manifest, CommittedPublicationRowsV1,
        CommittedPublicationSourcesV1, PublicationSourceErrorV1, PublicationSourceResultV1,
        PublicationSuffixV1, RetainedImportedKeyV1, RetainedKeyEvidenceV1,
    },
    ForkEventAuthorityErrorV1 as AuthorityError,
    ForkManifestPublicationErrorV1 as PublicationError,
};

impl MemoryStore {
    /// The one `FCR1` of a child, or corrupt authority for none or several.
    pub(super) fn child_registration(
        &self,
        child_timeline_id: TimelineId,
    ) -> Result<&ForkClassifierRegistrationV1, AuthorityError> {
        let mut registrations = self
            .fork_classifier_registrations
            .values()
            .filter(|registration| registration.input().child_timeline_id == child_timeline_id);
        let (Some(registration), None) = (registrations.next(), registrations.next()) else {
            return Err(AuthorityError::CorruptAuthority);
        };
        Ok(registration)
    }

    /// Read one child's `FAR1` under an explicit R6.9 validator.
    pub(super) fn validated_admission(
        &self,
        child_timeline_id: TimelineId,
        validator: AuthorityValidatorV1,
    ) -> Result<ValidatedAdmissionV1, AuthorityError> {
        let local = self
            .validated_local_fork_admission(child_timeline_id)
            .map(|admission| ValidatedAdmissionV1::local(&admission));
        match validator {
            AuthorityValidatorV1::LocalOnly => local,
            AuthorityValidatorV1::CodeTwoAware => {
                local.or_else(|_| self.imported_fork_admission(child_timeline_id))
            }
        }
    }

    /// Read one child's classified authority graph under an explicit R6.9
    /// validator.
    pub(super) fn validated_graph(
        &self,
        child_timeline_id: TimelineId,
        validator: AuthorityValidatorV1,
    ) -> Result<ValidatedGraphV1, AuthorityError> {
        let local =
            self.classified_authority_graph(child_timeline_id)
                .map(|(admission, table, _)| ValidatedGraphV1 {
                    admission: ValidatedAdmissionV1::local(&admission),
                    table,
                });
        match validator {
            AuthorityValidatorV1::LocalOnly => local,
            AuthorityValidatorV1::CodeTwoAware => {
                local.or_else(|_| self.imported_graph(child_timeline_id))
            }
        }
    }

    /// R6.9 (b), `FAR1` admission: the code-2 `FAR1` of the child has exactly
    /// one import admission row, which names this child, this origin, and
    /// this `FAR1` digest.
    fn imported_fork_admission(
        &self,
        child_timeline_id: TimelineId,
    ) -> Result<ValidatedAdmissionV1, AuthorityError> {
        let admission = self
            .imported_fork_admissions
            .get(&child_timeline_id)
            .ok_or(AuthorityError::CorruptAuthority)?;
        let mut rows = self
            .imported_fork_attributions
            .values()
            .filter(|row| row.child == child_timeline_id);
        let (Some(row), None) = (rows.next(), rows.next()) else {
            return Err(AuthorityError::CorruptAuthority);
        };
        ImportedForkAttributionAdmissionV1::from_canonical_cbor(&row.stored.admission_bytes)
            .ok()
            .filter(|record| imported_admission_matches(admission, record, child_timeline_id))
            .map(|record| ValidatedAdmissionV1::imported(admission, &record))
            .ok_or(AuthorityError::CorruptAuthority)
    }

    /// R6.9 (b), `FCS1` resolution: the imported `FCS1` is looked up by `FCT1`
    /// field 6, and the triple must satisfy G1-G8 against the code-2 `FAR1`.
    fn imported_graph(
        &self,
        child_timeline_id: TimelineId,
    ) -> Result<ValidatedGraphV1, AuthorityError> {
        let admission = self.imported_fork_admission(child_timeline_id)?;
        let table = self
            .fork_classifier_tables
            .get(&child_timeline_id)
            .ok_or(AuthorityError::CorruptAuthority)?;
        let registration = self.child_registration(child_timeline_id)?;
        let source = self
            .imported_fork_classifier_sources
            .get(&table.input().source_configuration_revision_digest)
            .ok_or(AuthorityError::CorruptAuthority)?;
        let graph = ImportedForkClassifierGraphV1 {
            source: source.clone(),
            table: table.clone(),
            registration: registration.clone(),
        };
        imported_graph_matches(&graph, &admission)
            .then_some(ValidatedGraphV1 {
                admission,
                table: graph.table,
            })
            .ok_or(AuthorityError::CorruptAuthority)
    }

    /// The `FPO1` of one operation ID with its origin: a local row, or, for
    /// validator (b) only, an imported code-2 row read through its local
    /// projection. Validator (a) never reads an imported row.
    fn publication_operation_row(
        &self,
        operation_id: Hash,
        validator: AuthorityValidatorV1,
    ) -> Option<(ForkPublicationOperationV1, ValidatedOriginV1)> {
        let local = self
            .fork_publication_operations
            .get(&operation_id)
            .map(|operation| (operation.clone(), ValidatedOriginV1::Local));
        match validator {
            AuthorityValidatorV1::LocalOnly => local,
            AuthorityValidatorV1::CodeTwoAware => local.or_else(|| {
                self.imported_fork_publication_operations
                    .get(&operation_id)
                    .map(|operation| {
                        (
                            operation.projection().clone(),
                            ValidatedOriginV1::Imported(operation.authority_origin_digest()),
                        )
                    })
            }),
        }
    }

    /// Where the trusted publication read takes the retained key from (ADR-105
    /// erratum E12): the live registry for a local `FAR1` and for any failed
    /// admission, whose own error surfaces first, and the `IKR1`/`IKT1`
    /// evidence of the import admission for a code-2 one.
    fn retained_key_evidence(
        &self,
        admission: &PublicationSourceResultV1<ValidatedAdmissionV1>,
    ) -> PublicationSourceResultV1<RetainedKeyEvidenceV1> {
        admission
            .as_ref()
            .ok()
            .and_then(ValidatedAdmissionV1::import)
            .map_or(Ok(RetainedKeyEvidenceV1::LiveRegistry), |import| {
                self.imported_key_evidence(import)
            })
    }

    /// The `IKR1` and `IKT1` stored under one import operation ID, only when
    /// that import's stored full-envelope digest is the admission's.
    fn imported_key_evidence(
        &self,
        import: ValidatedImportV1,
    ) -> PublicationSourceResultV1<RetainedKeyEvidenceV1> {
        self.imported_fork_key_evidence
            .get(&import.import_operation_id)
            .zip(
                self.imported_fork_attributions
                    .get(&import.import_operation_id)
                    .filter(|row| row.stored.envelope_digest == import.full_envelope_digest),
            )
            .map(|(evidence, _)| {
                RetainedKeyEvidenceV1::Imported(Box::new(RetainedImportedKeyV1 {
                    record: evidence.record,
                    tombstone: evidence.tombstone,
                }))
            })
            .ok_or(PublicationSourceErrorV1::Invalid)
    }

    /// Read the classified suffix after `from_logical_seq` under an explicit
    /// R6.9 validator.
    ///
    /// The trait method `read_fork_event_suffix` is the read caller and passes
    /// validator (b). Issuance reaches this through
    /// `fork_publication_suffix` and passes validator (a).
    pub(super) fn read_fork_event_suffix_as(
        &self,
        child_timeline_id: TimelineId,
        from_logical_seq: u64,
        validator: AuthorityValidatorV1,
    ) -> Result<PublicationSuffixV1, AuthorityError> {
        let prefix = self
            .logical_prefix(child_timeline_id)
            .map_err(|_| AuthorityError::CorruptAuthority)?;
        let events = &self.state(child_timeline_id).events;
        let logical_seqs = events
            .iter()
            .filter_map(|event| {
                prefix
                    .checked_add(event.seq.as_u64())
                    .map(|logical_seq| (event.id, logical_seq))
            })
            .collect::<HashMap<_, _>>();
        let anchored =
            |event_id: EventId, logical_seq: u64| logical_seqs.get(&event_id) == Some(&logical_seq);
        let orphaned_operation = self.fork_append_operations.values().any(|operation| {
            operation.input().child_timeline_id == child_timeline_id
                && !anchored(operation.input().event_id, operation.input().logical_seq)
        });
        let orphaned_origin = self.fork_event_origins.values().any(|origin| {
            origin.input().fork_timeline_id == child_timeline_id
                && !anchored(origin.input().event_id, origin.input().logical_seq)
        });
        let orphaned_intervention = self.fork_intervention_admissions.values().any(|record| {
            record.input().fork_timeline_id == child_timeline_id
                && !anchored(record.input().event_id, record.input().logical_seq)
        });
        if orphaned_operation || orphaned_origin || orphaned_intervention {
            return Err(AuthorityError::CorruptAuthority);
        }
        if events.is_empty() {
            return Ok(Vec::new());
        }
        let mut operations = HashMap::with_capacity(logical_seqs.len());
        for operation in self.fork_append_operations.values() {
            if logical_seqs.contains_key(&operation.input().event_id)
                && operations
                    .insert(operation.input().event_id, operation)
                    .is_some()
            {
                return Err(AuthorityError::CorruptAuthority);
            }
        }
        let graph = self.validated_graph(child_timeline_id, validator)?;
        events
            .iter()
            .filter_map(|event| {
                prefix
                    .checked_add(event.seq.as_u64())
                    .filter(|logical_seq| *logical_seq >= from_logical_seq)
                    .map(|logical_seq| (event, logical_seq))
            })
            .map(|(event, logical_seq)| {
                let operation = operations
                    .get(&event.id)
                    .copied()
                    .ok_or(AuthorityError::CorruptAuthority)?;
                if operation.input().logical_seq != logical_seq
                    || operation.input().fork_admission_digest != graph.admission.digest()
                    || operation.input().classifier_revision_digest != graph.table.digest()
                {
                    return Err(AuthorityError::CorruptAuthority);
                }
                let committed = Event {
                    seq: Seq::from_u64(logical_seq),
                    ..event.clone()
                };
                self.validate_classified_records(
                    operation,
                    &committed,
                    &graph.table,
                    graph.admission.origin(),
                )
                .map(|(origin, intervention)| (origin, intervention, operation.clone()))
            })
            .collect()
    }

    /// Read and trust one committed publication graph under an explicit R6.9
    /// validator.
    ///
    /// The trait method `read_committed` is the read caller and passes
    /// validator (b). `commit_authorized` recovery passes validator (a).
    pub(super) fn read_committed_as(
        &self,
        child_timeline_id: TimelineId,
        final_logical_head: u64,
        validator: AuthorityValidatorV1,
    ) -> Result<crate::CommittedForkManifestV1, PublicationError> {
        self.fork_publication_bindings
            .get(&(child_timeline_id, final_logical_head))
            .copied()
            .ok_or(PublicationError::PublicationMissing)
            .and_then(|binding| {
                let input = binding.input();
                let artifact = self
                    .fork_publication_artifacts
                    .get(&input.signed_manifest_record_id)
                    .cloned();
                self.publication_operation_row(input.operation_id, validator)
                    .zip(artifact)
                    .map(
                        |((operation, origin), artifact)| CommittedPublicationRowsV1 {
                            child_timeline_id,
                            final_logical_head,
                            binding,
                            operation,
                            origin,
                            artifact,
                        },
                    )
                    .ok_or(PublicationError::PublicationConflict)
            })
            .and_then(|rows| {
                let admission = self.fork_publication_admission(child_timeline_id, validator);
                let retained = self.retained_key_evidence(&admission);
                let head = Seq::from_u64(final_logical_head);
                let final_chain_head_hash = self
                    .compute_chain_hash_at_unchecked(child_timeline_id, head)
                    .map_err(PublicationSourceErrorV1::from);
                let suffix = self.fork_publication_suffix(
                    child_timeline_id,
                    publication_parent_head(&admission),
                    validator,
                );
                let sources = CommittedPublicationSourcesV1 {
                    admission,
                    retained,
                    final_chain_head_hash,
                    suffix,
                    registry: Ok(self.key_registry.clone()),
                };
                trusted_committed_manifest(&rows, sources)
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_core::{
        store::EventStore, ForkAppendSourceIdentityV1, ForkClassifierRegistrationInputV1,
        ForkClassifierSourceInputV1, ForkClassifierSourceV1, ForkEventSourceDescriptorV1,
        ImportedForkAttributionAdmissionInputV1, ImportedForkPublicationOperationV1,
        ImportedKeyRecordV1, PublicKey, Signature, WallTime,
    };

    use super::*;
    use crate::{
        fae1_fixture::{
            attribution_identity, attribution_material, gateway_source, hash, open_session,
            pin_policy, request_for, Fallible, Shape, Spec, World, GATEWAY_REGISTRAR, PARENT_CUT,
        },
        memory::fork_attribution_authority_import::ImportedAttributionV1,
        ForkAttributionAuthorityImportPortV1, ForkEventPermitIssuerPortV1,
        ForkEventProvenanceAuthorityPortV1, ForkManifestPublicationPortV1,
        ForkManifestPublicationRequestV1,
    };

    /// One committed import in a `MemoryStore`, whose live registry holds no
    /// attribution key.
    struct Imported {
        world: World,
        store: MemoryStore,
        child: TimelineId,
        head: u64,
    }

    fn imported(shape: Shape) -> Fallible<Imported> {
        imported_with(shape, &Spec::default())
    }

    fn imported_with(shape: Shape, spec: &Spec) -> Fallible<Imported> {
        let world = World::new(shape, false)?;
        let built = world.build(spec)?;
        let mut store = MemoryStore::new();
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        store.import_verified(&request_for(&world, &built))?;
        let child = world.child_at(0)?.id;
        Ok(Imported {
            world,
            store,
            child,
            head: PARENT_CUT + shape.events(),
        })
    }

    /// The suffix read and publication read of one imported child.
    fn reads(state: &Imported) -> (Option<AuthorityError>, Option<PublicationError>) {
        (
            state
                .store
                .read_fork_event_suffix(state.child, PARENT_CUT + 1)
                .err(),
            state.store.read_committed(state.child, state.head).err(),
        )
    }

    const BOTH_REFUSED: (Option<AuthorityError>, Option<PublicationError>) = (
        Some(AuthorityError::CorruptAuthority),
        Some(PublicationError::PublicationConflict),
    );

    type Tamper = fn(&mut Imported) -> Fallible<()>;

    /// Rewrite the stored `IFA1` of the import.
    fn rewrite_admission(
        state: &mut Imported,
        edit: fn(&mut ImportedForkAttributionAdmissionInputV1),
    ) -> Fallible<()> {
        for row in state.store.imported_fork_attributions.values_mut() {
            let mut input = ImportedForkAttributionAdmissionV1::from_canonical_cbor(
                &row.stored.admission_bytes,
            )?
            .input()
            .clone();
            edit(&mut input);
            row.stored.admission_bytes =
                ImportedForkAttributionAdmissionV1::new(input)?.to_canonical_cbor();
        }
        Ok(())
    }

    fn rewrite_events(state: &mut Imported, edit: fn(&mut pos_core::Event)) -> Fallible<()> {
        let child = state.child;
        let timeline = state.store.timelines.get_mut(&child).ok_or("child")?;
        timeline.events.iter_mut().for_each(edit);
        Ok(())
    }

    /// Every stored-state tamper that both reads must refuse.
    fn refused_tampers() -> Vec<(&'static str, Tamper)> {
        let tampers: [(&'static str, Tamper); 14] = [
            ("missing import admission", |state| {
                state.store.imported_fork_attributions.clear();
                Ok(())
            }),
            ("two import admissions", |state| {
                let row = state
                    .store
                    .imported_fork_attributions
                    .values()
                    .next()
                    .ok_or("no import admission")?;
                let copy = ImportedAttributionV1 {
                    child: row.child,
                    stored: row.stored.clone(),
                };
                state
                    .store
                    .imported_fork_attributions
                    .insert(hash(0xaa), copy);
                Ok(())
            }),
            ("undecodable import admission", |state| {
                for row in state.store.imported_fork_attributions.values_mut() {
                    row.stored.admission_bytes = vec![0];
                }
                Ok(())
            }),
            ("import admission naming another origin", |state| {
                rewrite_admission(state, |input| {
                    input.authority_origin_digest = hash(0x99);
                })
            }),
            ("import admission naming another FAR1", |state| {
                rewrite_admission(state, |input| {
                    input.fork_admission_digest = hash(0x98);
                })
            }),
            ("import admission naming another child", |state| {
                rewrite_admission(state, |input| {
                    input.child_timeline_id = TimelineId::new();
                })
            }),
            ("missing code-2 FAR1", |state| {
                state.store.imported_fork_admissions.clear();
                Ok(())
            }),
            ("missing FCT1", |state| {
                state.store.fork_classifier_tables.clear();
                Ok(())
            }),
            ("missing FCR1", |state| {
                state.store.fork_classifier_registrations.clear();
                Ok(())
            }),
            ("two FCR1", |state| {
                let registration = state
                    .store
                    .fork_classifier_registrations
                    .values()
                    .next()
                    .ok_or("no registration")?;
                let copy = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
                    operation_id: hash(0xab),
                    ..registration.input().clone()
                })?;
                state
                    .store
                    .fork_classifier_registrations
                    .insert(hash(0xab), copy);
                Ok(())
            }),
            ("missing imported FCS1", |state| {
                state.store.imported_fork_classifier_sources.clear();
                Ok(())
            }),
            ("imported FCS1 substituted by another source", |state| {
                let other = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
                    room_revision_descriptor_hash: hash(0x41),
                    registrar_identifier: "other-registrar".to_owned(),
                    routes: vec![],
                })?;
                for source in state.store.imported_fork_classifier_sources.values_mut() {
                    source.clone_from(&other);
                }
                Ok(())
            }),
            ("imported Event with its signature stripped", |state| {
                rewrite_events(state, |event| event.signature = None)
            }),
            (
                "imported Event with another WallTime than its FOP1",
                |state| {
                    rewrite_events(state, |event| {
                        event.wall_time = WallTime::from_micros(event.wall_time.as_micros() + 1);
                    })
                },
            ),
        ];
        tampers.into()
    }

    #[test]
    fn every_tampered_imported_row_fails_both_reads_closed() -> Fallible<()> {
        let mut seen = 0;
        for (name, tamper) in refused_tampers() {
            let mut state = imported(Shape::Mixed)?;
            assert_eq!(reads(&state), (None, None), "{name} untampered");
            tamper(&mut state)?;
            assert_eq!(reads(&state), BOTH_REFUSED, "{name}");
            seen += 1;
        }
        assert_eq!(seen, 14);
        Ok(())
    }

    #[test]
    fn an_fpo1_that_disagrees_with_its_far1_fails_the_publication_read_only() -> Fallible<()> {
        let mut state = imported(Shape::Mixed)?;
        for operation in state
            .store
            .imported_fork_publication_operations
            .values_mut()
        {
            *operation = ImportedForkPublicationOperationV1::from_local(
                operation.projection().clone(),
                hash(0x99),
            );
        }
        assert_eq!(
            reads(&state),
            (None, Some(PublicationError::PublicationConflict))
        );
        Ok(())
    }

    #[test]
    fn a_missing_fpo1_fails_the_publication_read_only() -> Fallible<()> {
        let mut state = imported(Shape::Mixed)?;
        state.store.imported_fork_publication_operations.clear();
        assert_eq!(
            reads(&state),
            (None, Some(PublicationError::PublicationConflict))
        );
        Ok(())
    }

    #[test]
    fn validator_a_refuses_what_validator_b_accepts() -> Fallible<()> {
        let state = imported(Shape::Mixed)?;
        let store = &state.store;
        let b = store.validated_admission(state.child, AuthorityValidatorV1::CodeTwoAware)?;
        assert!(matches!(b.origin(), ValidatedOriginV1::Imported(_)));
        assert_eq!(
            store
                .validated_admission(state.child, AuthorityValidatorV1::LocalOnly)
                .err(),
            Some(AuthorityError::CorruptAuthority)
        );
        assert_eq!(
            store
                .validated_graph(state.child, AuthorityValidatorV1::LocalOnly)
                .err(),
            Some(AuthorityError::CorruptAuthority)
        );
        assert!(store
            .validated_graph(state.child, AuthorityValidatorV1::CodeTwoAware)
            .is_ok());
        assert_eq!(
            store
                .read_fork_event_suffix_as(state.child, 1, AuthorityValidatorV1::LocalOnly)
                .err(),
            Some(AuthorityError::CorruptAuthority)
        );
        assert_eq!(
            store
                .read_committed_as(state.child, state.head, AuthorityValidatorV1::LocalOnly)
                .err(),
            Some(PublicationError::PublicationConflict)
        );
        Ok(())
    }

    #[test]
    fn an_empty_import_needs_its_admission_to_publish_and_not_to_read_a_suffix() -> Fallible<()> {
        for shape in [Shape::EmptyClassified, Shape::EmptyUnclassified] {
            let mut state = imported(shape)?;
            assert_eq!(reads(&state), (None, None));
            state.store.imported_fork_attributions.clear();
            assert_eq!(
                reads(&state),
                (None, Some(PublicationError::PublicationConflict))
            );
        }
        Ok(())
    }

    /// Both permit issuers, the FCC1 admission read and publication issuance
    /// refuse the imported child, whatever local FCS1 rows exist.
    fn assert_local_authority_refused(state: &mut Imported) -> Fallible<()> {
        let fcs1 = gateway_source()?;
        let route_a = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "adapter-a".to_owned(),
            source: ForkEventSourceDescriptorV1::new("route-a", hash(0x51))?,
        };
        let child = state.child;
        let corrupt = Some(AuthorityError::CorruptAuthority);
        let mut session = open_session(&mut state.store)?;
        let mut issuer = session.take_event_permit_issuer().ok_or("no issuer")?;
        issuer.trust_external_source(route_a.clone());
        assert_eq!(
            state
                .store
                .issue_classifier_registrar_permit(&issuer, &session, child, fcs1.clone())
                .err(),
            corrupt
        );
        assert_eq!(
            state
                .store
                .issue_append_source_permit(&issuer, &session, child, &fcs1, route_a)
                .err(),
            corrupt
        );
        assert_eq!(
            state.store.read_validated_local_fork_admission(child).err(),
            corrupt
        );
        // Publication issuance reaches the provenance sources, where
        // validator (a) refuses it, and its signer never runs.
        let registry = state
            .world
            .registry_with_attribution_key("creator-a", 0x71)?;
        state.store.save_key_registry(&registry)?;
        let material = attribution_material();
        let request = ForkManifestPublicationRequestV1 {
            operation_id: hash(0xc1),
            child_timeline_id: child,
            expected_final_logical_head: state.head + 1,
            signing_identity: attribution_identity("creator-a", 1),
            private_material_digest: material.material_digest(),
            public_verification_key: material.public_verification_key(),
            expected_registry: registry,
        };
        let signed = std::cell::Cell::new(false);
        let refused = state.store.commit_authorized(request, |_, _| {
            signed.set(true);
            Err::<Signature, &str>("the signer must not run")
        });
        assert_eq!(refused, Err(PublicationError::CorruptAuthority));
        assert!(!signed.get());
        Ok(())
    }

    /// Stored-state tampers that only the publication read consults.
    fn publication_only_tampers() -> Vec<(&'static str, Tamper)> {
        let tampers: [(&'static str, Tamper); 3] = [
            ("missing retained key evidence", |state| {
                state.store.imported_fork_key_evidence.clear();
                Ok(())
            }),
            ("IKR1 naming another key than the FPO1", |state| {
                for evidence in state.store.imported_fork_key_evidence.values_mut() {
                    evidence.record = ImportedKeyRecordV1::new(
                        attribution_identity("creator-a", 1),
                        Some(hash(0x77)),
                        PublicKey::from_bytes([0x78; 32]),
                    )?;
                }
                Ok(())
            }),
            (
                "import admission with another full-envelope digest",
                |state| {
                    for row in state.store.imported_fork_attributions.values_mut() {
                        row.stored.envelope_digest = hash(0x66);
                    }
                    Ok(())
                },
            ),
        ];
        tampers.into()
    }

    #[test]
    fn the_retained_key_comes_from_the_import_evidence_not_the_live_registry() -> Fallible<()> {
        // No key in the live registry: the read still succeeds (erratum E12).
        let state = imported(Shape::Mixed)?;
        assert_eq!(reads(&state), (None, None));
        for (name, tamper) in publication_only_tampers() {
            let mut state = imported(Shape::Mixed)?;
            tamper(&mut state)?;
            assert_eq!(
                reads(&state),
                (None, Some(PublicationError::PublicationConflict)),
                "{name}"
            );
        }
        // A local record of the same identity must equal the retained one.
        for (seed, expected) in [
            (0x71, None),
            (0x72, Some(PublicationError::PublicationConflict)),
        ] {
            let mut state = imported(Shape::Mixed)?;
            let registry = state
                .world
                .registry_with_attribution_key("creator-a", seed)?;
            state.store.save_key_registry(&registry)?;
            assert_eq!(reads(&state), (None, expected), "seed {seed:#x}");
        }
        Ok(())
    }

    #[test]
    fn a_local_fcs1_equal_to_the_imported_one_is_never_consulted() -> Fallible<()> {
        let mut state = imported_with(
            Shape::Mixed,
            &Spec {
                registrar: GATEWAY_REGISTRAR,
                ..Spec::default()
            },
        )?;
        let local = gateway_source()?;
        state.store.fork_classifier_sources.insert(
            (
                local.input().room_revision_descriptor_hash,
                local.input().registrar_identifier.clone(),
            ),
            local,
        );
        assert_eq!(reads(&state), (None, None));
        assert_eq!(
            state
                .store
                .validated_graph(state.child, AuthorityValidatorV1::LocalOnly)
                .err(),
            Some(AuthorityError::CorruptAuthority)
        );
        assert_local_authority_refused(&mut state)?;
        // With the imported row gone, the equal local row does not stand in.
        state.store.imported_fork_classifier_sources.clear();
        assert_eq!(reads(&state), BOTH_REFUSED);
        Ok(())
    }

    #[test]
    fn validator_a_never_reads_an_imported_publication_row() -> Fallible<()> {
        let state = imported(Shape::Mixed)?;
        let operation = *state
            .store
            .imported_fork_publication_operations
            .keys()
            .next()
            .ok_or("no imported FPO1")?;
        assert!(state
            .store
            .publication_operation_row(operation, AuthorityValidatorV1::LocalOnly)
            .is_none());
        assert!(matches!(
            state
                .store
                .publication_operation_row(operation, AuthorityValidatorV1::CodeTwoAware),
            Some((_, ValidatedOriginV1::Imported(_)))
        ));
        Ok(())
    }
}
