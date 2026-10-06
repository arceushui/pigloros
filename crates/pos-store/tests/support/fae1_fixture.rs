//! Shared ADR-105 `FAE1` import fixtures.
//!
//! A `World` is a real source host: a signed root Timeline, one or more
//! signed Fork children, and the registry that verifies them. `World::build`
//! turns one child into a complete, issuer-signed `FAE1` whose every
//! cross-record equality holds, and a `Spec` selects one controlled deviation.
//! The public tests and the adapter unit tests include this one file; the
//! items are public so that no test crate sees them as unused.

use std::{error::Error, sync::Arc};

use ed25519_dalek::{Signer, SigningKey};
use pos_core::{
    store::{EventStore, SeqRange, TimelineExport},
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, CanonicalBytes, EntityId, ErasureArtifactClassV1,
    ErasureContainmentGateV1, ErasureReferenceV1, ErasureReplayClaimV1, EventDraft,
    EventOriginRecordV1, ForkAdmissionRecordInputV1, ForkAdmissionRecordV1,
    ForkAppendOperationInputV1, ForkAppendOperationV1, ForkAppendSourceIdentityV1,
    ForkAttributionAuthorityEnvelopeInputV1, ForkAttributionAuthorityEnvelopeV1,
    ForkAttributionAuthorityRecordsV1, ForkAttributionAuthorityUnsignedEnvelopeV1,
    ForkAttributionClassifierRecordsV1, ForkAttributionIssuerPolicyEntryV1,
    ForkAttributionIssuerPolicyInputV1, ForkAttributionIssuerPolicyV1,
    ForkAttributionIssuerStateV1, ForkAttributionIssuerV1, ForkAttributionOriginV1,
    ForkAuthorityOriginV1, ForkClassifierRegistrationInputV1, ForkClassifierRegistrationV1,
    ForkClassifierSourceInputV1, ForkClassifierSourceV1, ForkClassifierTableInputV1,
    ForkClassifierTableV1, ForkEventClassifierV1, ForkEventEvidenceV1,
    ForkEventSourceDescriptorV1, ForkExternalInputRouteV1, ForkInterventionAdmissionV1,
    ForkPublicationArtifactInputV1, ForkPublicationArtifactV1, ForkPublicationBindingInputV1,
    ForkPublicationBindingV1, ForkPublicationOperationInputV1, ForkPublicationOperationV1,
    ForkReproManifestInputV1, ForkReproManifestV1, ForkTimelineImportInputV1,
    ForkTimelineImportV1, Hash, ImportedForkAdmissionRecordV1, ImportedForkClassifierGraphV1,
    ImportedForkPublicationOperationV1, ImportedKeyRecordV1, ImportedKeyTombstoneV1,
    ImportedPrincipalOwnerBindingV1, KeyIdentityV1, KeyRegistrationV1, KeyRegistryStateV1,
    KeyRoleV1, Kind, OwnerIdV1, PrincipalOwnerBindingInputV1, PrincipalOwnerBindingV1,
    PublicKey, RegisteredArtifactV1, ReplayClaimEvaluationV1, ReplayClaimEvaluatorV1, Seq,
    Signature, SignedForkReproManifestV1, TimelineEventEnvelopeV1, TimelineId, TimelineMeta,
};
use pos_crypto::key_roles::{
    sign_for_registered_role, sign_timeline_event_for_registered_role, SigningKeyMaterial,
};
use pos_store::{
    export_timeline_own, import_timeline_verified_v1, memory::MemoryStore,
    AuthenticatedOperatorPolicyPinV1, ForkAttributionAuthorityImportRequestV1,
    ForkAttributionIssuerPolicyInstallationPortV1,
};

pub type Fallible<T> = Result<T, Box<dyn Error>>;

/// The parent cut of every fixture Fork.
pub const PARENT_CUT: u64 = 4;
/// The issuer-policy scope every fixture destination pins.
pub const POLICY_SCOPE: &str = "destination-a";
const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([201; 32]);
const ROUTE_A_SCHEMA: u8 = 0x51;
const ROUTE_B_SCHEMA: u8 = 0x52;

/// A digest of 32 copies of `value`.
#[must_use]
pub const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

/// The child segment of one fixture Fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shape {
    /// Four Events classified `(0,0)`, `(1,0)`, `(1,1)`, and `(1,1)`.
    Mixed,
    /// No Events; the source registered a classifier.
    EmptyClassified,
    /// No Events and no classifier triple.
    EmptyUnclassified,
}

impl Shape {
    /// The number of child Events of this shape.
    #[must_use]
    pub const fn events(self) -> u64 {
        match self {
            Self::Mixed => 4,
            Self::EmptyClassified | Self::EmptyUnclassified => 0,
        }
    }
}

/// Whether `FTI1` keeps the exported owner or names another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FtiOwner {
    /// The exported Timeline owner.
    Keep,
    /// Another owner, or none.
    Replace(Option<EntityId>),
}

/// One controlled deviation of a built `FAE1`. Defaults build a valid one.
#[derive(Clone, Debug)]
pub struct Spec {
    /// Which child of the world to import.
    pub child: usize,
    pub import_seed: u8,
    pub binding_seed: u8,
    pub principal_seed: u8,
    /// The Principal digest, instead of one derived from `principal_seed`.
    pub principal_digest: Option<Hash>,
    pub admission_seed: u8,
    pub registration_seed: u8,
    pub publication_seed: u8,
    pub operations_seed: u8,
    pub issuer_id: &'static str,
    pub issuer_seed: u8,
    /// Sign the envelope with this key instead of the issuer's.
    pub envelope_signer_seed: Option<u8>,
    /// Sign `FSM1` with this key instead of the attribution key.
    pub manifest_signer_seed: Option<u8>,
    pub destroyed_key: bool,
    /// Replace the `FRM1` and `FPO1` final chain hash.
    pub final_hash: Option<Hash>,
    /// Replace `FAE1` field 4.
    pub policy_digest: Option<Hash>,
    /// Replace the parent chain hash in `FTI1`, `FAR1`, and `FRM1`.
    pub parent_hash: Option<Hash>,
    /// The `FTI1` owner.
    pub fti_owner: FtiOwner,
    /// The creator Owner of `POB1`, `FAR1`, and the attribution key.
    pub creator: &'static str,
    /// Retype the first child Event as protected geographic evidence.
    pub geographic: bool,
    /// Replace the registrar of the imported `FCS1`.
    pub registrar: &'static str,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            child: 0,
            import_seed: 0x11,
            binding_seed: 0x21,
            principal_seed: 0x22,
            principal_digest: None,
            admission_seed: 0x31,
            registration_seed: 0x61,
            publication_seed: 0x91,
            operations_seed: 0xa0,
            issuer_id: "issuer-a",
            issuer_seed: 0x31,
            envelope_signer_seed: None,
            manifest_signer_seed: None,
            destroyed_key: false,
            final_hash: None,
            policy_digest: None,
            parent_hash: None,
            fti_owner: FtiOwner::Keep,
            creator: "creator-a",
            geographic: false,
            registrar: "registrar-a",
        }
    }
}

impl Spec {
    /// A spec whose every id differs from the default, so it can share a
    /// destination with a default import.
    #[must_use]
    pub fn distinct(child: usize) -> Self {
        Self {
            child,
            import_seed: 0x12,
            binding_seed: 0x23,
            principal_seed: 0x24,
            admission_seed: 0x32,
            registration_seed: 0x62,
            publication_seed: 0x92,
            operations_seed: 0xb0,
            ..Self::default()
        }
    }
}

/// One source Fork child with its exact own-segment export.
pub struct Child {
    pub id: TimelineId,
    pub shape: Shape,
    pub export: TimelineExport,
    pub final_hash: Hash,
}

/// A real source host and the trust context that verifies its Timelines.
pub struct World {
    pub source: MemoryStore,
    pub root: TimelineId,
    pub owner: Option<EntityId>,
    pub registry: KeyRegistryStateV1,
    pub anchors: Vec<(KeyIdentityV1, PublicKey)>,
    pub children: Vec<Child>,
    timeline_identity: KeyIdentityV1,
    timeline_material: SigningKeyMaterial,
}

/// A built, signed `FAE1` with the policy that admits its issuer.
pub struct Built {
    pub bytes: Vec<u8>,
    pub envelope: ForkAttributionAuthorityEnvelopeV1,
    pub policy: ForkAttributionIssuerPolicyV1,
    pub issuer: ForkAttributionIssuerV1,
}

fn export_evaluation() -> Fallible<ReplayClaimEvaluationV1> {
    Ok(ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                EXPORT_DIGEST,
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([202; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .map_err(|error| error.to_string())?)
}

fn append_signed(
    store: &mut MemoryStore,
    timeline: TimelineId,
    registry: &KeyRegistryStateV1,
    identity: KeyIdentityV1,
    material: &SigningKeyMaterial,
    payload: Vec<u8>,
) -> Fallible<()> {
    let mut sign = |authorized: &mut KeyRegistryStateV1,
                    envelope: &TimelineEventEnvelopeV1,
                    body: &CanonicalBytes| {
        sign_timeline_event_for_registered_role(authorized, material, envelope, body)
            .map_err(|error| pos_core::CoreError::Storage(error.to_string()))
    };
    store.append_timeline_signed_authorized(
        timeline,
        registry,
        EventDraft::new(
            EntityId::new(),
            Kind::new("fae1.import.test"),
            CanonicalBytes::from_vec(payload),
        ),
        identity,
        material.material_digest(),
        material.public_verification_key(),
        &mut sign,
    )?;
    Ok(())
}

fn owner(value: &str) -> Fallible<OwnerIdV1> {
    Ok(OwnerIdV1::new(value)?)
}

/// The attribution-signing identity of `creator` at `epoch`.
#[must_use]
pub fn attribution_identity(creator: &'static str, epoch: u64) -> KeyIdentityV1 {
    KeyIdentityV1::new(creator, KeyRoleV1::SubjectAttributionSigning, epoch)
}

/// The first item of a list.
///
/// # Errors
/// Returns an error when the list is empty.
pub fn first<T>(items: &[T]) -> Fallible<&T> {
    items.first().ok_or_else(|| "empty list".into())
}

fn material(seed: u8) -> SigningKeyMaterial {
    SigningKeyMaterial::new(SigningKey::from_bytes(&[seed; 32]))
}

fn route(name: &str, schema: u8, intervention: bool) -> Fallible<ForkExternalInputRouteV1> {
    Ok(ForkExternalInputRouteV1::new(
        ForkEventSourceDescriptorV1::new(name, hash(schema))?,
        intervention,
    ))
}

fn external(name: &str, schema: u8) -> Fallible<ForkAppendSourceIdentityV1> {
    Ok(ForkAppendSourceIdentityV1::ExternalInput {
        adapter_identifier: "adapter-a".to_owned(),
        source: ForkEventSourceDescriptorV1::new(name, hash(schema))?,
    })
}

/// The source of the child Event at local sequence `local`.
fn source_at(local: u64) -> Fallible<ForkAppendSourceIdentityV1> {
    match local {
        1 => Ok(ForkAppendSourceIdentityV1::HostInternal),
        2 => external("route-b", ROUTE_B_SCHEMA),
        _ => external("route-a", ROUTE_A_SCHEMA),
    }
}

fn classifier(
    child: TimelineId,
    admission_digest: Hash,
    spec: &Spec,
) -> Fallible<ImportedForkClassifierGraphV1> {
    let routes = || -> Fallible<Vec<ForkExternalInputRouteV1>> {
        Ok(vec![
            route("route-a", ROUTE_A_SCHEMA, true)?,
            route("route-b", ROUTE_B_SCHEMA, false)?,
        ])
    };
    let source = ForkClassifierSourceV1::new(ForkClassifierSourceInputV1 {
        room_revision_descriptor_hash: hash(0x41),
        registrar_identifier: spec.registrar.to_owned(),
        routes: routes()?,
    })?;
    let table = ForkClassifierTableV1::new(ForkClassifierTableInputV1 {
        child_timeline_id: child,
        fork_admission_digest: admission_digest,
        room_revision_descriptor_hash: hash(0x41),
        registrar_identifier: spec.registrar.to_owned(),
        source_configuration_revision_digest: source.digest(),
        routes: routes()?,
    })?;
    let registration = ForkClassifierRegistrationV1::new(ForkClassifierRegistrationInputV1 {
        operation_id: hash(spec.registration_seed),
        child_timeline_id: child,
        fork_admission_digest: admission_digest,
        room_revision_descriptor_hash: hash(0x41),
        classifier_revision_digest: table.digest(),
    })?;
    Ok(ImportedForkClassifierGraphV1 {
        source,
        table,
        registration,
    })
}

/// The derived records of one classified Event.
struct Provenance {
    origin: EventOriginRecordV1,
    intervention: Option<ForkInterventionAdmissionV1>,
    operation: ForkAppendOperationV1,
}

/// Derive `EOR1`, the implied `FIA1`, and `FOP1` for one Event, exactly as
/// the source host's classified append does.
fn provenance(
    event: &ForkEventEvidenceV1,
    local: u64,
    child: TimelineId,
    table: &ForkClassifierTableV1,
    spec: &Spec,
) -> Fallible<Provenance> {
    let fields = event.envelope().input();
    let source = source_at(local)?;
    let classification = ForkEventClassifierV1::from_table(table).classify_identity(&source)?;
    let operation_byte = spec.operations_seed.wrapping_add(u8::try_from(local)?);
    let draft = ForkAppendOperationInputV1 {
        operation_id: hash(operation_byte),
        child_timeline_id: child,
        logical_seq: fields.origin_logical_seq.as_u64(),
        event_id: fields.event_id,
        request_digest: hash(0xb0),
        source,
        wall_time: fields.wall_time,
        payload_hash: event.envelope().payload_hash(),
        classifier_revision_digest: table.digest(),
        fork_admission_digest: table.input().fork_admission_digest,
        event_origin_digest: hash(0x01),
        intervention_admission_digest: None,
    };
    let placeholder = ForkAppendOperationV1::new(draft.clone())?;
    let (origin, implied) = placeholder.expected_provenance(table, classification);
    let implied_digest = implied.as_ref().map(ForkInterventionAdmissionV1::digest);
    let operation = ForkAppendOperationV1::new(ForkAppendOperationInputV1 {
        event_origin_digest: origin.digest(),
        intervention_admission_digest: implied_digest,
        ..draft
    })?;
    Ok(Provenance {
        origin,
        intervention: implied,
        operation,
    })
}

impl World {
    /// A world with one signed Fork child of `shape`.
    ///
    /// # Errors
    /// Returns the construction error of any fixture record.
    pub fn new(shape: Shape, with_owner: bool) -> Fallible<Self> {
        let timeline_material = material(0x41);
        let timeline_identity =
            KeyIdentityV1::new("import-owner", KeyRoleV1::TimelineIntegritySigning, 1);
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(
            timeline_identity,
            timeline_material.material_digest(),
            Some(timeline_material.public_verification_key()),
        ))?;
        let mut source = MemoryStore::new();
        source.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        source.save_key_registry(&registry)?;
        let owner = with_owner.then(EntityId::new);
        let root_meta = owner.map_or_else(
            || TimelineMeta::root("fae1-root"),
            |owner| TimelineMeta::root_owned("fae1-root", owner),
        );
        let root = source.create_timeline_with_meta(root_meta)?.id();
        for index in 1..=PARENT_CUT {
            let payload = format!("root-{index}").into_bytes();
            append_signed(
                &mut source,
                root,
                &registry,
                timeline_identity,
                &timeline_material,
                payload,
            )?;
        }
        let anchors = vec![(timeline_identity, timeline_material.public_verification_key())];
        let mut world = Self {
            source,
            root,
            owner,
            registry,
            anchors,
            children: Vec::new(),
            timeline_identity,
            timeline_material,
        };
        world.add_child(shape)?;
        Ok(world)
    }

    /// Fork another signed child of `shape` at the parent cut.
    ///
    /// # Errors
    /// Returns the construction error of any fixture record.
    pub fn add_child(&mut self, shape: Shape) -> Fallible<()> {
        let name = format!("fae1-child-{}", self.children.len());
        let child = self
            .source
            .fork(self.root, Seq::from_u64(PARENT_CUT), &name)?
            .id();
        for index in 1..=shape.events() {
            let payload = format!("child-{index}").into_bytes();
            append_signed(
                &mut self.source,
                child,
                &self.registry,
                self.timeline_identity,
                &self.timeline_material,
                payload,
            )?;
        }
        let evaluation = export_evaluation()?;
        let export = export_timeline_own(&self.source, child, EXPORT_DIGEST, &evaluation)?;
        let final_head = Seq::from_u64(PARENT_CUT + shape.events());
        let final_hash = self.source.chain_hash_at(child, final_head)?;
        self.children.push(Child {
            id: child,
            shape,
            export,
            final_hash,
        });
        Ok(())
    }

    /// The child at `index`.
    ///
    /// # Errors
    /// Returns an error when there is no such child.
    pub fn child_at(&self, index: usize) -> Fallible<&Child> {
        self.children.get(index).ok_or_else(|| "no such child".into())
    }

    /// The exact own-segment export of the root, the destination parent.
    ///
    /// # Errors
    /// Returns the export error.
    pub fn root_export(&self) -> Fallible<TimelineExport> {
        Ok(export_timeline_own(
            &self.source,
            self.root,
            EXPORT_DIGEST,
            &export_evaluation()?,
        )?)
    }

    /// Bind the erasure gate, save the registry, and import the verified
    /// root Timeline, so a destination can accept this world's Forks.
    ///
    /// # Errors
    /// Returns the store or verification error.
    pub fn seed_destination(&self, store: &mut dyn EventStore) -> Fallible<()> {
        self.seed_prefix(store, usize::MAX)
    }

    /// Like [`Self::seed_destination`], but the destination parent keeps only
    /// its first `keep` Events.
    ///
    /// # Errors
    /// Returns the store or verification error.
    pub fn seed_truncated(&self, store: &mut dyn EventStore, keep: usize) -> Fallible<()> {
        self.seed_prefix(store, keep)
    }

    fn seed_prefix(&self, store: &mut dyn EventStore, keep: usize) -> Fallible<()> {
        store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open()))?;
        store.save_key_registry(&self.registry)?;
        let mut export = self.root_export()?;
        export.events.truncate(keep);
        export.timeline.head = Seq::from_u64(u64::try_from(export.events.len())?);
        import_timeline_verified_v1(store, export, &self.anchors)?;
        Ok(())
    }

    /// The Event evidence of `child`, with the requested deviation.
    fn evidence(child: &Child, spec: &Spec) -> Fallible<Vec<ForkEventEvidenceV1>> {
        let mut events = child.export.events.clone();
        if spec.geographic {
            if let Some(first) = events.first_mut() {
                first.event_type = Kind::new("geo.location");
            }
        }
        events
            .iter()
            .map(|event| Ok(ForkEventEvidenceV1::from_event(event)?))
            .collect()
    }

    fn timeline_import(child: &Child, spec: &Spec) -> Fallible<ForkTimelineImportV1> {
        let (projection, _) = ForkTimelineImportV1::from_export(&child.export)?;
        let mut input: ForkTimelineImportInputV1 = projection.input().clone();
        if let FtiOwner::Replace(owner) = spec.fti_owner {
            input.owner = owner;
        }
        if let Some(parent_hash) = spec.parent_hash {
            input.parent_chain_hash = parent_hash;
        }
        Ok(ForkTimelineImportV1::new(input)?)
    }

    /// Build and sign the `FAE1` that `spec` describes.
    ///
    /// # Errors
    /// Returns the construction error of any record.
    pub fn build(&self, spec: &Spec) -> Fallible<Built> {
        let child = self.children.get(spec.child).ok_or("no such child")?;
        let issuer_key = SigningKey::from_bytes(&[spec.issuer_seed; 32]);
        let issuer = ForkAttributionIssuerV1::new(
            spec.issuer_id,
            1,
            PublicKey::from_bytes(issuer_key.verifying_key().to_bytes()),
        )?;
        let policy = pinned_policy(&issuer, ForkAttributionIssuerStateV1::Active)?;
        let policy_digest = spec.policy_digest.unwrap_or_else(|| policy.digest());
        let import_operation_id = hash(spec.import_seed);
        let origin = pos_core::fork_attribution_authority_origin_digest_v1(
            import_operation_id,
            &issuer,
            policy_digest,
            self.root,
            child.id,
        );
        let records = self.records(child, spec, origin)?;
        let input = ForkAttributionAuthorityEnvelopeInputV1 {
            import_operation_id,
            issuer: issuer.clone(),
            issuer_policy_digest: policy_digest,
            records: records.records,
            key_record: records.key_record,
            key_tombstone: records.key_tombstone,
            event_evidence: records.evidence,
            timeline_import: records.timeline_import,
            classifier: records.classifier,
            append_operations: records.operations,
        };
        let unsigned = ForkAttributionAuthorityUnsignedEnvelopeV1::new(input)?;
        let signer_seed = spec.envelope_signer_seed.unwrap_or(spec.issuer_seed);
        let signer = SigningKey::from_bytes(&[signer_seed; 32]);
        let message = unsigned.signature_message();
        let signature = Signature::from_bytes(signer.sign(&message).to_bytes());
        let envelope = ForkAttributionAuthorityEnvelopeV1::new(unsigned, signature);
        Ok(Built {
            bytes: envelope.to_canonical_cbor(),
            envelope,
            policy,
            issuer,
        })
    }

    fn records(&self, child: &Child, spec: &Spec, origin: Hash) -> Fallible<BuiltRecords> {
        let exported_hash = child.export.parent_fork_hash.ok_or("no parent hash")?;
        let parent_hash = spec.parent_hash.unwrap_or(exported_hash);
        let authority = self.authority(child, spec, origin, parent_hash)?;
        let graph = (child.shape != Shape::EmptyUnclassified)
            .then(|| classifier(child.id, authority.digest, spec))
            .transpose()?;
        let evidence = Self::evidence(child, spec)?;
        let derived = match graph.as_ref() {
            Some(graph) => evidence
                .iter()
                .zip(1_u64..)
                .map(|(event, local)| provenance(event, local, child.id, &graph.table, spec))
                .collect::<Fallible<Vec<_>>>()?,
            None => Vec::new(),
        };
        let publication = self.publication(child, spec, origin, &authority, &derived)?;
        let attribution = material(0x71);
        let (key_record, key_tombstone) =
            key_evidence(&attribution, spec.destroyed_key, spec.creator)?;
        Ok(BuiltRecords {
            records: ForkAttributionAuthorityRecordsV1 {
                principal_owner_binding: authority.binding.to_canonical_cbor(),
                fork_admission: authority.admission.to_canonical_cbor(),
                event_origins: derived
                    .iter()
                    .map(|record| record.origin.to_canonical_cbor())
                    .collect(),
                intervention_admissions: derived
                    .iter()
                    .filter_map(|record| record.intervention.as_ref())
                    .map(ForkInterventionAdmissionV1::to_canonical_cbor)
                    .collect(),
                publication_operation: publication.operation.to_canonical_cbor(),
                publication_binding: publication.binding.to_canonical_cbor(),
                publication_artifact: publication.artifact.to_canonical_cbor(),
            },
            key_record,
            key_tombstone,
            evidence,
            timeline_import: Self::timeline_import(child, spec)?,
            classifier: graph.as_ref().map(|graph| ForkAttributionClassifierRecordsV1 {
                source: graph.source.to_canonical_cbor(),
                table: graph.table.to_canonical_cbor(),
                registration: graph.registration.to_canonical_cbor(),
            }),
            operations: derived
                .iter()
                .map(|record| record.operation.to_canonical_cbor())
                .collect(),
        })
    }

    /// The code-2 `POB1` and `FAR1` of one import.
    fn authority(
        &self,
        child: &Child,
        spec: &Spec,
        origin: Hash,
        parent_hash: Hash,
    ) -> Fallible<Authority> {
        let binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
            operation_id: hash(spec.binding_seed),
            principal_digest: spec
                .principal_digest
                .unwrap_or_else(|| hash(spec.principal_seed)),
            owner: owner(spec.creator)?,
            origin: ForkAuthorityOriginV1::Local,
        })?;
        let binding = ImportedPrincipalOwnerBindingV1::from_local(binding, origin);
        let admission = ForkAdmissionRecordV1::new(ForkAdmissionRecordInputV1 {
            operation_id: hash(spec.admission_seed),
            principal_owner_binding_digest: binding.digest(),
            creator: owner(spec.creator)?,
            parent_timeline_id: self.root,
            child_timeline_id: child.id,
            room_revision_descriptor_hash: hash(0x41),
            parent_logical_head: PARENT_CUT,
            parent_chain_head_hash: parent_hash,
            completed_fold_cursor: PARENT_CUT,
            post_fold_tick_boundary: PARENT_CUT,
            plugin_composition_hash: hash(0x42),
            attribution_required: true,
            origin: ForkAttributionOriginV1::Local,
        })?;
        let admission = ImportedForkAdmissionRecordV1::from_local(admission, origin);
        Ok(Authority {
            digest: admission.digest(),
            binding,
            admission,
        })
    }

    /// The signed `FSM1` with its `FPO1`, `FPB1`, and `FPA1`.
    fn publication(
        &self,
        child: &Child,
        spec: &Spec,
        origin: Hash,
        authority: &Authority,
        derived: &[Provenance],
    ) -> Fallible<Publication> {
        let exported_hash = child.export.parent_fork_hash.ok_or("no parent hash")?;
        let parent_hash = spec.parent_hash.unwrap_or(exported_hash);
        let final_head = PARENT_CUT + child.shape.events();
        let final_hash = spec.final_hash.unwrap_or(child.final_hash);
        let sequences = derived
            .iter()
            .filter(|record| record.intervention.is_some())
            .map(|record| record.operation.input().logical_seq)
            .collect::<Vec<_>>();
        let manifest = Self::signed_manifest(
            ForkReproManifestInputV1 {
                parent_timeline_id: self.root,
                fork_timeline_id: child.id,
                admission_digest: authority.digest,
                room_revision_descriptor_hash: hash(0x41),
                parent_logical_head: PARENT_CUT,
                parent_chain_head_hash: parent_hash,
                post_fold_tick_boundary: PARENT_CUT,
                plugin_composition_hash: hash(0x42),
                intervention_sequences: sequences,
                final_fork_logical_head: final_head,
                final_fork_chain_head_hash: final_hash,
            },
            spec,
        )?;
        let attribution = material(0x71);
        let operation = ForkPublicationOperationV1::new(ForkPublicationOperationInputV1 {
            operation_id: hash(spec.publication_seed),
            child_timeline_id: child.id,
            final_logical_head: final_head,
            final_chain_head_hash: final_hash,
            admission_digest: authority.digest,
            signing_identity: attribution_identity(spec.creator, 1),
            private_material_digest: attribution.material_digest(),
            public_verification_key: attribution.public_verification_key(),
            signed_manifest_record_id: manifest.record_id(),
            origin: ForkAttributionOriginV1::Local,
        })?;
        Ok(Publication {
            operation: ImportedForkPublicationOperationV1::from_local(operation, origin),
            binding: ForkPublicationBindingV1::new(ForkPublicationBindingInputV1 {
                child_timeline_id: child.id,
                final_logical_head: final_head,
                operation_id: hash(spec.publication_seed),
                signed_manifest_record_id: manifest.record_id(),
            })?,
            artifact: ForkPublicationArtifactV1::new(ForkPublicationArtifactInputV1 {
                signed_manifest_record_id: manifest.record_id(),
                operation_id: hash(spec.publication_seed),
                signed_manifest_bytes: manifest.to_canonical_cbor(),
            })?,
        })
    }

    /// Sign `FRM1` under the creator's attribution identity.
    ///
    /// The manifest names the code-2 `FAR1` digest, so the local-admission
    /// signing helper cannot be used.
    fn signed_manifest(
        input: ForkReproManifestInputV1,
        spec: &Spec,
    ) -> Fallible<SignedForkReproManifestV1> {
        let signer = material(spec.manifest_signer_seed.unwrap_or(0x71));
        let mut registry = KeyRegistryStateV1::new();
        registry.register_key(KeyRegistrationV1::new(
            attribution_identity(spec.creator, 1),
            signer.material_digest(),
            Some(signer.public_verification_key()),
        ))?;
        let manifest = ForkReproManifestV1::new(input)?;
        let payload = CanonicalBytes::from_vec(manifest.to_canonical_cbor());
        let identity = attribution_identity(spec.creator, 1);
        let signature = sign_for_registered_role(&mut registry, &signer, identity, &payload)?;
        Ok(SignedForkReproManifestV1::new(identity, manifest, signature)?)
    }
}

/// The code-2 `POB1` and `FAR1` with the `FAR1` digest.
struct Authority {
    binding: ImportedPrincipalOwnerBindingV1,
    admission: ImportedForkAdmissionRecordV1,
    digest: Hash,
}

/// The publication records of one import.
struct Publication {
    operation: ImportedForkPublicationOperationV1,
    binding: ForkPublicationBindingV1,
    artifact: ForkPublicationArtifactV1,
}

struct BuiltRecords {
    records: ForkAttributionAuthorityRecordsV1,
    key_record: ImportedKeyRecordV1,
    key_tombstone: Option<ImportedKeyTombstoneV1>,
    evidence: Vec<ForkEventEvidenceV1>,
    timeline_import: ForkTimelineImportV1,
    classifier: Option<ForkAttributionClassifierRecordsV1>,
    operations: Vec<Vec<u8>>,
}

fn key_evidence(
    attribution: &SigningKeyMaterial,
    destroyed: bool,
    creator: &'static str,
) -> Fallible<(ImportedKeyRecordV1, Option<ImportedKeyTombstoneV1>)> {
    let identity = attribution_identity(creator, 1);
    let key = attribution.public_verification_key();
    if destroyed {
        Ok((
            ImportedKeyRecordV1::new(identity, None, key)?,
            Some(ImportedKeyTombstoneV1::new(
                identity,
                attribution.material_digest(),
                hash(0x45),
                hash(0x46),
            )?),
        ))
    } else {
        Ok((
            ImportedKeyRecordV1::new(identity, Some(attribution.material_digest()), key)?,
            None,
        ))
    }
}

/// The genesis `FIP1` of the fixture destination, naming one issuer.
///
/// # Errors
/// Returns the policy construction error.
pub fn pinned_policy(
    issuer: &ForkAttributionIssuerV1,
    state: ForkAttributionIssuerStateV1,
) -> Fallible<ForkAttributionIssuerPolicyV1> {
    Ok(ForkAttributionIssuerPolicyV1::new(
        ForkAttributionIssuerPolicyInputV1 {
            scope: POLICY_SCOPE.to_owned(),
            generation: 1,
            previous_policy_digest: None,
            entries: vec![ForkAttributionIssuerPolicyEntryV1 {
                issuer: issuer.clone(),
                state,
            }],
        },
    )?)
}

/// All own Events of one Timeline in a store.
///
/// # Errors
/// Returns the store error.
pub fn own_events(
    store: &dyn EventStore,
    timeline: TimelineId,
) -> Fallible<Vec<pos_core::Event>> {
    Ok(store.read_own(timeline, SeqRange::all())?)
}

/// The import request that pins `built`'s own policy and `world`'s root.
#[must_use]
pub fn request_for<'a>(
    world: &'a World,
    built: &'a Built,
) -> ForkAttributionAuthorityImportRequestV1<'a> {
    ForkAttributionAuthorityImportRequestV1 {
        envelope_bytes: &built.bytes,
        expected_issuer_policy_digest: built.policy.digest(),
        parent_timeline_id: world.root,
        trust_anchors: &world.anchors,
    }
}

/// Install `policy` under the operator pin for the fixture scope.
///
/// # Errors
/// Returns the policy installation error.
pub fn pin_policy(
    store: &mut dyn ForkAttributionIssuerPolicyInstallationPortV1,
    policy: &ForkAttributionIssuerPolicyV1,
) -> Fallible<()> {
    let pin = AuthenticatedOperatorPolicyPinV1::new(POLICY_SCOPE, policy.digest());
    store.install(&pin, &policy.to_canonical_cbor())?;
    Ok(())
}
