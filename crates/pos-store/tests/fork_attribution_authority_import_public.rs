#![cfg(feature = "sqlite")]

//! Public adapter-parity evidence for the ADR-105 `FAE1` authority import
//! (R6.10): install, exact retry, recovery before current policy, conflicts,
//! every closed validation error, and zero partial visibility, each on
//! `MemoryStore` and file-backed `SqliteStore`.

#[path = "support/fae1_fixture.rs"]
pub mod fixture;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use fixture::{
    hash, pin_policy, pinned_policy, Built, Fallible, FtiOwner, Shape, Spec, World, PARENT_CUT,
    POLICY_SCOPE,
};
use pos_core::{
    fork_authentication::{
        principal_digest_v1, AuthenticatedPrincipalRecordV1, ForkAuthenticationAdapterPolicyV1,
        ForkAuthenticationPolicyV1,
    },
    store::{EventStore, SeqRange},
    CanonicalBytes, EntityId, EventDraft, ForkAdmissionErrorV1, ForkAdmissionHostCommandV1,
    ForkAdmissionOperationResultV1, ForkAttributionIssuerPolicyEntryV1,
    ForkAttributionIssuerPolicyInputV1, ForkAttributionIssuerPolicyV1,
    ForkAttributionIssuerStateV1 as State, ForkAttributionIssuerV1,
    ImportedForkAttributionAdmissionV1, Kind, PrincipalRefV1, PublicKey, TimelineId,
};
use pos_crypto::fork_authentication::{
    verify_authenticated_principal_evidence_v1, ForkAuthenticationAdapterSigningKeyV1,
    ForkHostSigningKeyV1,
};
use pos_store::{
    memory::MemoryStore, sqlite::SqliteStore, ForkAdmissionAuthorityBootstrapPortV1,
    ForkAdmissionAuthorityPortV1, ForkAdmissionAuthoritySessionV1,
    ForkAttributionAuthorityImportErrorV1 as ImportError, ForkAttributionAuthorityImportPortV1,
    ForkAttributionAuthorityImportReceiptV1 as Receipt,
    ForkAttributionAuthorityImportRequestV1 as Request, ForkEventProvenanceAuthorityPortV1,
    ForkManifestPublicationPortV1,
};

/// One adapter under test.
trait Destination:
    ForkAttributionAuthorityImportPortV1 + EventStore + ForkEventProvenanceAuthorityPortV1
{
}

impl<T> Destination for T where
    T: ForkAttributionAuthorityImportPortV1 + EventStore + ForkEventProvenanceAuthorityPortV1
{
}

/// Run one scenario against both reference adapters.
fn on_both_adapters(scenario: impl Fn(&mut dyn Destination) -> Fallible<()>) -> Fallible<()> {
    let mut memory = MemoryStore::new();
    scenario(&mut memory)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fae1-import.sqlite");
    let mut sqlite = SqliteStore::open(path.to_str().ok_or("utf-8 path")?)?;
    scenario(&mut sqlite)
}

fn install_policy(
    store: &mut dyn Destination,
    policy: &ForkAttributionIssuerPolicyV1,
) -> Fallible<()> {
    pin_policy(store, policy)
}

/// Seed the destination parent and install the policy admitting `built`.
fn prepare(store: &mut dyn Destination, world: &World, built: &Built) -> Fallible<()> {
    world.seed_destination(store)?;
    install_policy(store, &built.policy)
}

fn request<'a>(world: &'a World, built: &'a Built) -> Request<'a> {
    Request {
        envelope_bytes: &built.bytes,
        expected_issuer_policy_digest: built.policy.digest(),
        parent_timeline_id: world.root,
        trust_anchors: &world.anchors,
    }
}

fn import(
    store: &mut dyn Destination,
    world: &World,
    built: &Built,
) -> Result<Receipt, ImportError> {
    store.import_verified(&request(world, built))
}

/// Import `built`, which must be refused with `error`, and keep it invisible.
fn refuse(
    store: &mut dyn Destination,
    world: &World,
    built: &Built,
    error: ImportError,
) -> Fallible<()> {
    let child = world.child_at(0)?.id;
    assert_eq!(import(store, world, built), Err(error));
    assert_eq!(store.get_timeline(child)?, None);
    Ok(())
}

fn receipt_for(built: &Built, generation: u64) -> Fallible<Receipt> {
    Ok(Receipt {
        admission: ImportedForkAttributionAdmissionV1::from_envelope(&built.envelope, generation)?,
    })
}

fn assert_installed(store: &dyn Destination, world: &World, shape: Shape) -> Fallible<()> {
    let child = world.child_at(0)?;
    assert_eq!(
        store.get_timeline(child.id)?,
        Some(child.export.timeline.clone())
    );
    assert_eq!(
        store.read_own(child.id, SeqRange::all())?,
        child.export.events
    );
    assert_eq!(
        store.logical_head(child.id)?.as_u64(),
        PARENT_CUT + shape.events()
    );
    Ok(())
}

fn successor(
    previous: &ForkAttributionIssuerPolicyV1,
    entries: &[(&ForkAttributionIssuerV1, State)],
) -> Fallible<ForkAttributionIssuerPolicyV1> {
    Ok(ForkAttributionIssuerPolicyV1::new(
        ForkAttributionIssuerPolicyInputV1 {
            scope: POLICY_SCOPE.to_owned(),
            generation: previous.input().generation + 1,
            previous_policy_digest: Some(previous.digest()),
            entries: entries
                .iter()
                .map(|(issuer, state)| ForkAttributionIssuerPolicyEntryV1 {
                    issuer: (*issuer).clone(),
                    state: *state,
                })
                .collect(),
        },
    )?)
}

fn other_issuer(id: &str, seed: u8) -> Fallible<ForkAttributionIssuerV1> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    Ok(ForkAttributionIssuerV1::new(
        id,
        1,
        PublicKey::from_bytes(key.verifying_key().to_bytes()),
    )?)
}

/// Genesis admitting both the fixture issuer and `other`.
fn two_issuer_genesis(
    built: &Built,
    other: &ForkAttributionIssuerV1,
) -> Fallible<ForkAttributionIssuerPolicyV1> {
    Ok(ForkAttributionIssuerPolicyV1::new(
        ForkAttributionIssuerPolicyInputV1 {
            scope: POLICY_SCOPE.to_owned(),
            generation: 1,
            previous_policy_digest: None,
            entries: vec![
                ForkAttributionIssuerPolicyEntryV1 {
                    issuer: built.issuer.clone(),
                    state: State::Active,
                },
                ForkAttributionIssuerPolicyEntryV1 {
                    issuer: other.clone(),
                    state: State::Active,
                },
            ],
        },
    )?)
}

#[test]
fn mixed_import_installs_and_every_retry_returns_the_original_receipt() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    on_both_adapters(|store| {
        prepare(store, &world, &built)?;
        let receipt = import(store, &world, &built)?;
        assert_eq!(receipt, receipt_for(&built, 1)?);
        let fields = receipt.admission.input();
        assert_eq!(fields.import_operation_id, hash(0x11));
        assert_eq!(fields.child_timeline_id, world.child_at(0)?.id);
        assert_eq!(fields.final_logical_head, PARENT_CUT + 4);
        assert_eq!(fields.issuer_policy_generation, 1);
        assert_installed(store, &world, Shape::Mixed)?;
        let again = import(store, &world, &built)?;
        assert_eq!(again.to_canonical_cbor(), receipt.to_canonical_cbor());
        Ok(())
    })
}

#[test]
fn empty_segments_install_with_and_without_a_classifier() -> Fallible<()> {
    for shape in [Shape::EmptyClassified, Shape::EmptyUnclassified] {
        let world = World::new(shape, true)?;
        let built = world.build(&Spec::default())?;
        on_both_adapters(|store| {
            prepare(store, &world, &built)?;
            let receipt = import(store, &world, &built)?;
            assert_eq!(receipt, receipt_for(&built, 1)?);
            assert_installed(store, &world, shape)?;
            assert_eq!(import(store, &world, &built)?, receipt);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn a_destroyed_source_key_installs_its_tombstone() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let spec = Spec {
        destroyed_key: true,
        ..Spec::default()
    };
    let built = world.build(&spec)?;
    on_both_adapters(|store| {
        prepare(store, &world, &built)?;
        let receipt = import(store, &world, &built)?;
        assert_eq!(receipt, receipt_for(&built, 1)?);
        assert_eq!(import(store, &world, &built)?, receipt);
        Ok(())
    })
}

#[test]
fn two_forks_share_one_imported_classifier_source() -> Fallible<()> {
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::Mixed)?;
    let first = world.build(&Spec::default())?;
    let second = world.build(&Spec::distinct(1))?;
    on_both_adapters(|store| {
        prepare(store, &world, &first)?;
        let one = import(store, &world, &first)?;
        let two = import(store, &world, &second)?;
        assert_ne!(one, two);
        assert_eq!(import(store, &world, &first)?, one);
        assert_eq!(import(store, &world, &second)?, two);
        Ok(())
    })
}

#[test]
fn committed_imports_recover_before_current_policy_admission() -> Fallible<()> {
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::Mixed)?;
    let built = world.build(&Spec::default())?;
    let revoked = successor(&built.policy, &[(&built.issuer, State::Revoked)])?;
    let fresh = world.build(&Spec {
        policy_digest: Some(revoked.digest()),
        ..Spec::distinct(1)
    })?;
    on_both_adapters(|store| {
        prepare(store, &world, &built)?;
        let receipt = import(store, &world, &built)?;
        install_policy(store, &revoked)?;
        // The retry names the historical policy, and the issuer is now revoked.
        assert_eq!(import(store, &world, &built), Ok(receipt));
        // A new import by the revoked issuer is refused.
        let mut denied = request(&world, &fresh);
        denied.expected_issuer_policy_digest = revoked.digest();
        assert_eq!(
            store.import_verified(&denied),
            Err(ImportError::IssuerRevoked)
        );
        assert_eq!(store.get_timeline(world.child_at(1)?.id)?, None);
        Ok(())
    })
}

#[test]
fn issuer_admission_errors_follow_the_pinned_policy() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let base = world.build(&Spec::default())?;
    let other = other_issuer("issuer-b", 0x32)?;
    let genesis = two_issuer_genesis(&base, &other)?;
    let retired = successor(
        &genesis,
        &[(&base.issuer, State::Retired), (&other, State::Active)],
    )?;
    let revoked = successor(
        &genesis,
        &[(&base.issuer, State::Revoked), (&other, State::Active)],
    )?;
    let stranger = pinned_policy(&other, State::Active)?;
    let cases = [
        (&genesis, Some(&retired), ImportError::IssuerRetired),
        (&genesis, Some(&revoked), ImportError::IssuerRevoked),
        (&stranger, None, ImportError::UntrustedIssuer),
    ];
    for (installed, moved, expected) in cases {
        let latest = moved.unwrap_or(installed);
        let spec = Spec {
            policy_digest: Some(latest.digest()),
            ..Spec::default()
        };
        let built = world.build(&spec)?;
        on_both_adapters(|store| {
            world.seed_destination(store)?;
            install_policy(store, installed)?;
            if let Some(moved) = moved {
                install_policy(store, moved)?;
            }
            let mut asked = request(&world, &built);
            asked.expected_issuer_policy_digest = latest.digest();
            assert_eq!(store.import_verified(&asked), Err(expected));
            assert_eq!(store.get_timeline(world.child_at(0)?.id)?, None);
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn a_missing_stale_or_unpinned_policy_changes_nothing() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let other = other_issuer("issuer-b", 0x32)?;
    let rotated = successor(
        &built.policy,
        &[(&built.issuer, State::Active), (&other, State::Active)],
    )?;
    on_both_adapters(|store| {
        world.seed_destination(store)?;
        // No policy is installed, so no issuer is trusted.
        refuse(store, &world, &built, ImportError::UntrustedIssuer)?;
        install_policy(store, &built.policy)?;
        // The operator pinned another digest than the envelope names.
        let mut unpinned = request(&world, &built);
        unpinned.expected_issuer_policy_digest = hash(0x77);
        assert_eq!(
            store.import_verified(&unpinned),
            Err(ImportError::PolicyChanged)
        );
        // The floor moved past the envelope's policy.
        install_policy(store, &rotated)?;
        refuse(store, &world, &built, ImportError::PolicyChanged)
    })
}

#[test]
fn issuer_and_manifest_signatures_must_verify() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    for (spec, expected) in [
        (
            Spec {
                envelope_signer_seed: Some(0x55),
                ..Spec::default()
            },
            ImportError::InvalidSignature,
        ),
        (
            Spec {
                manifest_signer_seed: Some(0x56),
                ..Spec::default()
            },
            ImportError::InvalidSignature,
        ),
    ] {
        let built = world.build(&spec)?;
        on_both_adapters(|store| {
            prepare(store, &world, &built)?;
            refuse(store, &world, &built, expected)
        })?;
    }
    Ok(())
}

#[test]
fn event_evidence_needs_the_registry_the_anchors_and_non_geographic_events() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let geographic = world.build(&Spec {
        geographic: true,
        ..Spec::default()
    })?;
    let (identity, _) = *world.anchors.first().ok_or("no anchor")?;
    let wrong_key = vec![(identity, PublicKey::from_bytes([0x13; 32]))];
    let no_anchors = Vec::new();
    on_both_adapters(|store| {
        install_policy(store, &built.policy)?;
        // The parent exists, but the destination has no key registry.
        store.bind_erasure_gate(std::sync::Arc::new(
            pos_core::ErasureContainmentGateV1::new_test_open(),
        ))?;
        pos_store::import_timeline_with_id(store, world.root_export()?)?;
        refuse(store, &world, &built, ImportError::InvalidEventEvidence)?;
        store.save_key_registry(&world.registry)?;
        for anchors in [no_anchors.as_slice(), wrong_key.as_slice()] {
            let asked = Request {
                trust_anchors: anchors,
                ..request(&world, &built)
            };
            assert_eq!(
                store.import_verified(&asked),
                Err(ImportError::InvalidEventEvidence)
            );
        }
        refuse(
            store,
            &world,
            &geographic,
            ImportError::InvalidEventEvidence,
        )?;
        // Nothing above changed the destination: the valid import succeeds.
        import(store, &world, &built)?;
        assert_installed(store, &world, Shape::Mixed)
    })
}

#[test]
fn the_fti_owner_must_equal_the_parent_owner_in_both_directions() -> Fallible<()> {
    let owned = World::new(Shape::Mixed, true)?;
    let unowned = World::new(Shape::Mixed, false)?;
    let claims_owner = unowned.build(&Spec {
        fti_owner: FtiOwner::Replace(Some(EntityId::new())),
        ..Spec::default()
    })?;
    let drops_owner = owned.build(&Spec {
        fti_owner: FtiOwner::Replace(None),
        ..Spec::default()
    })?;
    on_both_adapters(|store| {
        prepare(store, &unowned, &claims_owner)?;
        refuse(
            store,
            &unowned,
            &claims_owner,
            ImportError::InvalidAuthorityClosure,
        )
    })?;
    on_both_adapters(|store| {
        prepare(store, &owned, &drops_owner)?;
        refuse(
            store,
            &owned,
            &drops_owner,
            ImportError::InvalidAuthorityClosure,
        )
    })
}

#[test]
fn the_requested_parent_must_be_the_present_fti_parent() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    on_both_adapters(|store| {
        install_policy(store, &built.policy)?;
        store.bind_erasure_gate(std::sync::Arc::new(
            pos_core::ErasureContainmentGateV1::new_test_open(),
        ))?;
        // The parent Timeline is absent from the destination.
        refuse(store, &world, &built, ImportError::InvalidAuthorityClosure)
    })?;
    on_both_adapters(|store| {
        prepare(store, &world, &built)?;
        let mut elsewhere = request(&world, &built);
        elsewhere.parent_timeline_id = TimelineId::new();
        assert_eq!(
            store.import_verified(&elsewhere),
            Err(ImportError::InvalidAuthorityClosure)
        );
        assert_eq!(store.get_timeline(world.child_at(0)?.id)?, None);
        Ok(())
    })
}

#[test]
fn a_shorter_or_divergent_destination_parent_is_range_evidence() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let divergent = world.build(&Spec {
        parent_hash: Some(hash(0x98)),
        ..Spec::default()
    })?;
    on_both_adapters(|store| {
        prepare(store, &world, &divergent)?;
        refuse(store, &world, &divergent, ImportError::InvalidRangeEvidence)
    })?;
    on_both_adapters(|store| {
        install_policy(store, &built.policy)?;
        world.seed_truncated(store, 3)?;
        refuse(store, &world, &built, ImportError::InvalidRangeEvidence)
    })
}

#[test]
fn a_wrong_final_chain_hash_is_range_evidence_and_rolls_back() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let wrong = world.build(&Spec {
        final_hash: Some(hash(0x99)),
        ..Spec::default()
    })?;
    let right = world.build(&Spec::default())?;
    on_both_adapters(|store| {
        prepare(store, &world, &right)?;
        refuse(store, &world, &wrong, ImportError::InvalidRangeEvidence)?;
        // The staged child was rolled back, so the same operation can retry.
        import(store, &world, &right)?;
        assert_installed(store, &world, Shape::Mixed)
    })
}

#[test]
fn malformed_envelopes_fail_closed_before_any_effect() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let mut unsupported = built.bytes.clone();
    // Byte 6 is the version: it follows the array head (1 byte) and the
    // text string "FAE1" (5 bytes).
    *unsupported.get_mut(6).ok_or("short envelope")? = 2;
    let mut truncated = built.bytes.clone();
    truncated.truncate(built.bytes.len() / 2);
    let oversized = vec![0_u8; 64 * 1024 * 1024 + 1];
    on_both_adapters(|store| {
        prepare(store, &world, &built)?;
        for (bytes, expected) in [
            (&truncated, ImportError::InvalidEncoding),
            (&unsupported, ImportError::UnsupportedVersion),
            (&oversized, ImportError::BoundsExceeded),
        ] {
            let mut asked = request(&world, &built);
            asked.envelope_bytes = bytes;
            assert_eq!(store.import_verified(&asked), Err(expected));
        }
        assert_eq!(store.get_timeline(world.child_at(0)?.id)?, None);
        Ok(())
    })
}

#[test]
fn an_unequal_import_reuse_or_occupied_child_is_a_conflict() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let reused = world.build(&Spec {
        operations_seed: 0xc0,
        ..Spec::default()
    })?;
    let same_child = world.build(&Spec::distinct(0))?;
    on_both_adapters(|store| {
        prepare(store, &world, &built)?;
        let receipt = import(store, &world, &built)?;
        // The same import operation ID with another complete envelope.
        assert_eq!(import(store, &world, &reused), Err(ImportError::Conflict));
        // Another operation naming the same child Fork.
        assert_eq!(
            import(store, &world, &same_child),
            Err(ImportError::Conflict)
        );
        assert_eq!(import(store, &world, &built), Ok(receipt));
        Ok(())
    })
}

/// Check that an imported Fork is readable through the code-2 reads (ADR-105
/// r6 R6.9) and stays closed to local appends.
fn assert_code_two_reads_and_closed_appends<S>(
    store: &mut S,
    world: &World,
    built: &Built,
) -> Fallible<()>
where
    S: Destination + ForkManifestPublicationPortV1,
{
    prepare(store, world, built)?;
    import(store, world, built)?;
    // No key is in the destination's live registry: the publication read takes
    // the retained key from the import evidence (ADR-105 erratum E12).
    let child = world.child_at(0)?.id;
    let head = PARENT_CUT + 4;
    assert_eq!(
        store.read_fork_event_suffix(child, PARENT_CUT + 1)?.len(),
        4
    );
    assert_eq!(
        store
            .read_committed(child, head)?
            .receipt
            .final_logical_head,
        head
    );
    let draft = EventDraft::new(
        EntityId::new(),
        Kind::new("fae1.import.test"),
        CanonicalBytes::from_vec(b"local".to_vec()),
    );
    assert!(store.append(child, &[draft]).is_err());
    Ok(())
}

#[test]
fn imported_code_two_is_readable_and_closed_to_local_appends() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    assert_code_two_reads_and_closed_appends(&mut MemoryStore::new(), &world, &built)?;
    let mut sqlite = SqliteStore::open_in_memory()?;
    assert_code_two_reads_and_closed_appends(&mut sqlite, &world, &built)
}

#[test]
fn a_file_backed_sqlite_import_survives_reopen_and_a_second_connection() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fae1-durable.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    let receipt = {
        let mut store = SqliteStore::open(path)?;
        prepare(&mut store, &world, &built)?;
        import(&mut store, &world, &built)?
    };
    let mut reopened = SqliteStore::open(path)?;
    reopened.bind_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ))?;
    assert_eq!(import(&mut reopened, &world, &built), Ok(receipt.clone()));
    let mut second = SqliteStore::open(path)?;
    second.bind_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ))?;
    assert_eq!(import(&mut second, &world, &built), Ok(receipt));
    Ok(())
}

/// A Fork admission authority session on one store, for local `POB1` commands.
struct LocalAuthority {
    host: ForkHostSigningKeyV1,
    adapter: ForkAuthenticationAdapterSigningKeyV1,
    policy: ForkAuthenticationPolicyV1,
    session: ForkAdmissionAuthoritySessionV1,
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// The Principal digest that every local `POB1` command of this file binds.
fn principal() -> Fallible<pos_core::Hash> {
    Ok(principal_digest_v1(&PrincipalRefV1::try_new(
        [4; 16],
        "test.local",
    )?)?)
}

impl LocalAuthority {
    fn open<S: ForkAdmissionAuthorityBootstrapPortV1>(store: &mut S) -> Fallible<Self> {
        let host = ForkHostSigningKeyV1::from_seed([111; 32])?;
        let adapter = ForkAuthenticationAdapterSigningKeyV1::from_seed([112; 32])?;
        let policy = ForkAuthenticationPolicyV1::new(vec![ForkAuthenticationAdapterPolicyV1 {
            adapter_id: "test-adapter".to_owned(),
            verifying_key: adapter.public_key(),
            minimum_assurance: 1,
            registry_bindings: vec![pos_core::Hash::from_bytes([3; 32])],
        }])?;
        let key = PublicKey::from_bytes(host.public_key());
        let initialize = store.begin_fork_admission_initialize(key, policy.digest()?)?;
        store.finalize_fork_admission_initialize(
            &initialize,
            &host.sign_initialize(&initialize.to_canonical_cbor()?)?,
        )?;
        let open = store.begin_fork_admission_open(key, policy.digest()?)?;
        let signature = host.sign_open(&open.to_canonical_cbor()?)?;
        let session = store.finalize_fork_admission_open(&open, &signature)?;
        Ok(Self {
            host,
            adapter,
            policy,
            session,
        })
    }

    fn command<S: ForkAdmissionAuthorityBootstrapPortV1>(
        &self,
        store: &S,
        operation: u8,
        owner: &str,
    ) -> Fallible<ForkAdmissionHostCommandV1> {
        let record = AuthenticatedPrincipalRecordV1 {
            principal: PrincipalRefV1::try_new([4; 16], "test.local")?,
            adapter_id: "test-adapter".to_owned(),
            assurance: 1,
            issued_at: 0,
            expires_at: u64::MAX,
            registry_binding: pos_core::Hash::from_bytes([3; 32]),
            operation_nonce: [5; 32],
        };
        let evidence = self.adapter.sign_authenticated_principal(record)?;
        let verified = verify_authenticated_principal_evidence_v1(&self.policy, evidence)?;
        let digest = principal_digest_v1(&verified.evidence().record().principal)?;
        let host_record = store.fork_admission_host_record()?;
        let inner = encode(&Value::Array(vec![
            Value::Text("POC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(host_record.store_id().as_bytes().to_vec()),
            Value::Bytes(self.session.identity().as_bytes().to_vec()),
            Value::Bytes(vec![operation; 32]),
            Value::Bytes(verified.evidence().digest()?.as_bytes().to_vec()),
            Value::Bytes(digest.as_bytes().to_vec()),
            Value::Text(owner.to_owned()),
        ]))?;
        let signature = self.host.sign_command(&inner, &verified)?;
        let fac1 = encode(&Value::Array(vec![
            Value::Text("FAC1".to_owned()),
            Value::Integer(1.into()),
            Value::Bytes(inner),
            Value::Bytes(verified.evidence().to_canonical_cbor()?),
            Value::Bytes(signature.as_bytes().to_vec()),
        ]))?;
        Ok(ForkAdmissionHostCommandV1::from_canonical_cbor(&fac1)?)
    }

    /// Bind the shared Principal to `owner` through the local authority.
    fn bind<S>(
        &self,
        store: &mut S,
        operation: u8,
        owner: &str,
    ) -> Fallible<Result<ForkAdmissionOperationResultV1, ForkAdmissionErrorV1>>
    where
        S: ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1,
    {
        let command = self.command(&*store, operation, owner)?;
        Ok(store.execute_fork_admission_command(&self.session, &self.policy, &command))
    }
}

/// A store that imports Forks and admits local Principal bindings.
trait Admitting:
    Destination + ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1
{
}

impl<T> Admitting for T where
    T: Destination + ForkAdmissionAuthorityBootstrapPortV1 + ForkAdmissionAuthorityPortV1
{
}

/// Import a Fork of the shared Principal, then bind it locally (erratum E11).
fn check_local_binding_after_import<S: Admitting>(store: &mut S) -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec {
        principal_digest: Some(principal()?),
        ..Spec::default()
    })?;
    prepare(store, &world, &built)?;
    import(store, &world, &built)?;
    let authority = LocalAuthority::open(store)?;
    // An equal Owner writes a normal local row under its own operation ID.
    let ForkAdmissionOperationResultV1::PrincipalOwner(binding) =
        authority.bind(store, 1, "creator-a")??
    else {
        return Err("unexpected result".into());
    };
    assert_eq!(binding.input().operation_id, hash(1));
    assert_eq!(
        binding.input().origin,
        pos_core::ForkAuthorityOriginV1::Local
    );
    // The local Principal now has exactly that one binding.
    let ForkAdmissionOperationResultV1::PrincipalOwner(again) =
        authority.bind(store, 2, "creator-a")??
    else {
        return Err("unexpected result".into());
    };
    assert_eq!(again, binding);
    // Another Owner, or an operation ID that the import holds, is a conflict.
    let other = authority.bind(store, 3, "creator-b")?;
    assert_eq!(
        other.err(),
        Some(ForkAdmissionErrorV1::PrincipalOwnerConflict)
    );
    let held = authority.bind(store, 0x21, "creator-a")?;
    assert_eq!(held.err(), Some(ForkAdmissionErrorV1::Conflict));
    Ok(())
}

/// Bind the shared Principal locally to `local`, then import a Fork of it.
fn import_after_bind<S: Admitting>(
    store: &mut S,
    local: &str,
) -> Fallible<Result<Receipt, ImportError>> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec {
        principal_digest: Some(principal()?),
        ..Spec::default()
    })?;
    let authority = LocalAuthority::open(store)?;
    let ForkAdmissionOperationResultV1::PrincipalOwner(binding) =
        authority.bind(store, 1, local)??
    else {
        return Err("unexpected result".into());
    };
    prepare(store, &world, &built)?;
    let outcome = import(store, &world, &built);
    if let Ok(receipt) = &outcome {
        // An exact retry returns the original receipt.
        assert_eq!(import(store, &world, &built).as_ref(), Ok(receipt));
        // A local re-bind with the same Owner still returns the original
        // local binding: the import wrote no second Principal binding.
        let ForkAdmissionOperationResultV1::PrincipalOwner(again) =
            authority.bind(store, 2, local)??
        else {
            return Err("unexpected result".into());
        };
        assert_eq!(again, binding);
    }
    Ok(outcome)
}

#[test]
fn a_principal_forking_twice_reuses_its_equal_owner_binding() -> Fallible<()> {
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::Mixed)?;
    let first = world.build(&Spec::default())?;
    let second = world.build(&Spec {
        principal_seed: 0x22,
        ..Spec::distinct(1)
    })?;
    on_both_adapters(|store| {
        prepare(store, &world, &first)?;
        let one = import(store, &world, &first)?;
        let two = import(store, &world, &second)?;
        assert_ne!(one, two);
        // Recovery and retry read each import's own POB1 record.
        assert_eq!(import(store, &world, &first), Ok(one));
        assert_eq!(import(store, &world, &second), Ok(two));
        Ok(())
    })
}

#[test]
fn another_owner_for_an_imported_principal_is_a_conflict() -> Fallible<()> {
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::Mixed)?;
    let first = world.build(&Spec::default())?;
    let other = world.build(&Spec {
        creator: "creator-b",
        principal_seed: 0x22,
        ..Spec::distinct(1)
    })?;
    on_both_adapters(|store| {
        prepare(store, &world, &first)?;
        let receipt = import(store, &world, &first)?;
        assert_eq!(import(store, &world, &other), Err(ImportError::Conflict));
        assert_eq!(store.get_timeline(world.child_at(1)?.id)?, None);
        assert_eq!(import(store, &world, &first), Ok(receipt));
        Ok(())
    })
}

#[test]
fn a_local_binding_after_an_import_writes_its_own_row_for_an_equal_owner_only() -> Fallible<()> {
    check_local_binding_after_import(&mut MemoryStore::new())?;
    check_local_binding_after_import(&mut SqliteStore::open_in_memory()?)
}

// The local different-Owner code is the ADR-099 `PrincipalOwnerConflict`; the
// import side reports the ADR-105 `Conflict` (erratum E10). The row counts of
// the local and imported Principal tables are asserted in the adapter unit
// tests, which can read them.
#[test]
fn an_import_after_a_local_binding_resolves_for_an_equal_owner_only() -> Fallible<()> {
    let memory_equal = import_after_bind(&mut MemoryStore::new(), "creator-a")?;
    assert!(memory_equal.is_ok());
    let sqlite_equal = import_after_bind(&mut SqliteStore::open_in_memory()?, "creator-a")?;
    assert!(sqlite_equal.is_ok());
    let memory_other = import_after_bind(&mut MemoryStore::new(), "creator-b")?;
    assert_eq!(memory_other.err(), Some(ImportError::Conflict));
    let sqlite_other = import_after_bind(&mut SqliteStore::open_in_memory()?, "creator-b")?;
    assert_eq!(sqlite_other.err(), Some(ImportError::Conflict));
    Ok(())
}

#[test]
fn an_occupied_operation_key_of_another_fork_is_a_conflict() -> Fallible<()> {
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::Mixed)?;
    let first = world.build(&Spec::default())?;
    let colliding = [
        // The same append operation IDs.
        Spec {
            operations_seed: 0xa0,
            ..Spec::distinct(1)
        },
        // The same classifier registration operation ID.
        Spec {
            registration_seed: 0x61,
            ..Spec::distinct(1)
        },
        // The same POB1 operation ID under another Principal.
        Spec {
            binding_seed: 0x21,
            ..Spec::distinct(1)
        },
        // The same publication operation ID.
        Spec {
            publication_seed: 0x91,
            ..Spec::distinct(1)
        },
    ];
    for spec in colliding {
        let other = world.build(&spec)?;
        on_both_adapters(|store| {
            prepare(store, &world, &first)?;
            import(store, &world, &first)?;
            assert_eq!(import(store, &world, &other), Err(ImportError::Conflict));
            assert_eq!(store.get_timeline(world.child_at(1)?.id)?, None);
            Ok(())
        })?;
    }
    Ok(())
}

/// Reopen a file-backed store. A write by another connection makes a live
/// store fail closed, so every raw edit happens between two handles.
fn reopen(path: &str) -> Fallible<SqliteStore> {
    let mut store = SqliteStore::open(path)?;
    store.bind_erasure_gate(std::sync::Arc::new(
        pos_core::ErasureContainmentGateV1::new_test_open(),
    ))?;
    Ok(store)
}

fn raw_edit(path: &str, sql: &str) -> Fallible<()> {
    rusqlite::Connection::open(path)?.execute_batch(sql)?;
    Ok(())
}

#[test]
fn a_file_backed_store_reports_partial_state_and_indeterminate_writes() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fae1-tamper.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    prepare(&mut SqliteStore::open(path)?, &world, &built)?;
    // An uncertain write is reported and rolled back.
    raw_edit(
        path,
        "CREATE TRIGGER fault BEFORE INSERT ON fork_publication_artifacts
         BEGIN SELECT RAISE(ABORT, 'injected fault'); END;",
    )?;
    let mut store = reopen(path)?;
    assert_eq!(
        import(&mut store, &world, &built),
        Err(ImportError::StorageIndeterminate)
    );
    assert_eq!(store.get_timeline(world.child_at(0)?.id)?, None);
    drop(store);
    // The identical retry then installs it.
    raw_edit(path, "DROP TRIGGER fault")?;
    let mut store = reopen(path)?;
    import(&mut store, &world, &built)?;
    drop(store);
    // Partial committed state is corrupt authority, never repaired.
    raw_edit(path, "DELETE FROM fork_append_operations")?;
    let mut store = reopen(path)?;
    assert_eq!(
        import(&mut store, &world, &built),
        Err(ImportError::CorruptAuthority)
    );
    assert_eq!(
        import(&mut store, &world, &built),
        Err(ImportError::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn a_tampered_shared_source_or_retained_policy_is_corrupt_authority() -> Fallible<()> {
    let mut world = World::new(Shape::Mixed, false)?;
    world.add_child(Shape::Mixed)?;
    let base = world.build(&Spec::default())?;
    let second = world.build(&Spec::distinct(1))?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fae1-source.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    let mut store = SqliteStore::open(path)?;
    prepare(&mut store, &world, &base)?;
    import(&mut store, &world, &base)?;
    drop(store);
    raw_edit(
        path,
        "UPDATE imported_fork_classifier_sources SET fcs1_cbor = x'00'",
    )?;
    let mut store = reopen(path)?;
    assert_eq!(
        import(&mut store, &world, &second),
        Err(ImportError::CorruptAuthority)
    );
    assert_eq!(store.get_timeline(world.child_at(1)?.id)?, None);
    drop(store);
    raw_edit(
        path,
        "UPDATE fork_attribution_issuer_policies SET fip1_cbor = x'00'",
    )?;
    let mut store = reopen(path)?;
    assert_eq!(
        import(&mut store, &world, &base),
        Err(ImportError::CorruptAuthority)
    );
    Ok(())
}

#[test]
fn rows_keyed_only_by_the_child_are_an_occupied_key_not_corruption() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fae1-orphan.sqlite");
    let path = path.to_str().ok_or("utf-8 path")?;
    prepare(&mut SqliteStore::open(path)?, &world, &built)?;
    let child = world.child_at(0)?.id;
    raw_edit(
        path,
        &format!("INSERT INTO fork_admissions (child_id, far1_cbor) VALUES ('{child}', x'00')"),
    )?;
    let mut store = reopen(path)?;
    assert_eq!(
        import(&mut store, &world, &built),
        Err(ImportError::Conflict)
    );
    Ok(())
}

#[test]
fn an_unreadable_imported_principal_store_fails_a_local_binding_closed() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec {
        principal_digest: Some(principal()?),
        ..Spec::default()
    })?;
    for (edit, expected) in [
        (
            // A wrong stored type fails the Principal read.
            "UPDATE imported_fork_principal_owner_bindings SET pob1_cbor = 'text'",
            ForkAdmissionErrorV1::StorageIndeterminate,
        ),
        (
            "UPDATE imported_fork_principal_owner_bindings SET pob1_cbor = x'00'",
            ForkAdmissionErrorV1::CorruptAuthority,
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("fae1-principal.sqlite");
        let path = path.to_str().ok_or("utf-8 path")?;
        let mut store = SqliteStore::open(path)?;
        prepare(&mut store, &world, &built)?;
        import(&mut store, &world, &built)?;
        drop(store);
        raw_edit(path, edit)?;
        let mut store = reopen(path)?;
        let authority = LocalAuthority::open(&mut store)?;
        assert_eq!(
            authority.bind(&mut store, 1, "creator-a")?.err(),
            Some(expected),
            "{edit}"
        );
    }
    Ok(())
}

#[test]
fn an_empty_segment_whose_final_hash_is_not_the_parent_hash_is_a_closure_failure() -> Fallible<()> {
    let world = World::new(Shape::EmptyClassified, false)?;
    let built = world.build(&Spec {
        final_hash: Some(hash(0x99)),
        ..Spec::default()
    })?;
    on_both_adapters(|store| {
        prepare(store, &world, &built)?;
        refuse(store, &world, &built, ImportError::InvalidAuthorityClosure)
    })
}
