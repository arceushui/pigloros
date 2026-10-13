//! Public native length contracts, checked against the existing byte encoders.

#[path = "support/fae1_fixture.rs"]
pub mod fixture;

use ciborium::value::Value;
use fixture::{Fallible, Shape, Spec, World, hash};
use pos_core::{
    ForkAdmissionRecordV1, ForkAttributionImportClosureV1, ForkClassifierSourceV1,
    ForkClassifierTableV1, ForkCreateCommitmentInputV1, ForkEventSourceDescriptorV1,
    ForkExternalInputRouteV1, ForkPublicationOperationV1, ForkReproManifestV1, OwnerIdV1,
    PrincipalOwnerBindingV1, PrincipalOwnerCommitmentInputV1, SignedForkReproManifestV1,
    MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1, MAX_FORK_EVENT_REGISTRAR_BYTES_V1,
    MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1, MAX_FORK_MANIFEST_INTERVENTIONS_V1,
};

macro_rules! parity {
    ($record:expr) => {{
        let record = $record;
        assert_eq!(record.canonical_cbor_len()?, record.to_canonical_cbor().len());
    }};
}

#[test]
fn complete_native_surface_matches_live_destroyed_mixed_and_empty_imports() -> Fallible<()> {
    for shape in [Shape::Mixed, Shape::EmptyClassified, Shape::EmptyUnclassified] {
        for destroyed_key in [false, true] {
            let world = World::new(shape, false)?;
            let built = world.build(&Spec { destroyed_key, ..Spec::default() })?;
            let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
            parity!(PrincipalOwnerBindingV1::new(closure.principal_owner_binding().input().clone())?);
            parity!(ForkAdmissionRecordV1::new(closure.fork_admission().fields().clone())?);
            parity!(closure.fork_admission());
            parity!(closure.publication_operation().projection());
            parity!(closure.publication_operation());
            parity!(closure.publication_binding());
            parity!(closure.publication_artifact());
            parity!(closure.signed_manifest());
            parity!(closure.signed_manifest().manifest());
            parity!(&built.issuer);
            parity!(pos_core::ImportedForkAttributionAdmissionV1::from_envelope(&built.envelope, 1)?);
            let input = built.envelope.unsigned().input();
            parity!(&input.key_record);
            if let Some(tombstone) = &input.key_tombstone {
                parity!(tombstone);
            }
            if let Some(graph) = closure.classifier() {
                parity!(&graph.source);
                parity!(&graph.table);
                parity!(&graph.registration);
            }
            for record in closure.append_operations() { parity!(record); }
            for record in closure.event_origins() { parity!(record); }
            for record in closure.intervention_admissions() { parity!(record); }
        }
    }
    Ok(())
}

fn oracle(value: Value) -> Fallible<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

fn digest(domain: &[u8], bytes: &[u8]) -> pos_core::Hash {
    let mut state = blake3::Hasher::new();
    state.update(domain);
    state.update(bytes);
    pos_core::Hash::from_bytes(*state.finalize().as_bytes())
}

fn field(value: pos_core::Hash) -> Value { Value::Bytes(value.as_bytes().to_vec()) }

#[test]
fn commitment_lengths_and_digests_match_independent_positional_arrays() -> Fallible<()> {
    let owner = OwnerIdV1::new(&"x".repeat(128))?;
    let input = PrincipalOwnerCommitmentInputV1 {
        store_id: hash(1), operation_id: hash(2), evidence_digest: hash(3),
        principal_digest: hash(4), owner,
    };
    let bytes = oracle(Value::Array(vec![field(hash(1)), field(hash(2)), field(hash(3)), field(hash(4)), Value::Text(owner.as_str().to_owned())]))?;
    assert_eq!(input.canonical_preimage_len()?, bytes.len());
    assert_eq!(input.commitment(), digest(b"pigloros/principal-owner-command/v1", &bytes));
    let parent_id = pos_core::TimelineId::new();
    for cut in [0, 23, 24, 255, 256, 65_535, 65_536, u64::from(u32::MAX), u64::from(u32::MAX) + 1, u64::MAX] {
        for length in [0, 23, 24, 255, 256, 65_535, 65_536] {
            for attribution_required in [false, true] {
                let name = "n".repeat(length);
                let input = ForkCreateCommitmentInputV1 {
                    store_id: hash(1), operation_id: hash(2), evidence_digest: hash(3),
                    principal_digest: hash(4), parent_id, cut, descriptor_hash: hash(5),
                    composition_hash: hash(6), attribution_required, child_name: &name,
                };
                let measured = input.canonical_preimage_len()?;
                let committed = input.commitment();
                let bytes = oracle(Value::Array(vec![field(hash(1)), field(hash(2)), field(hash(3)), field(hash(4)), Value::Bytes(parent_id.inner().to_bytes().to_vec()), Value::Integer(cut.into()), Value::Integer(cut.into()), field(hash(5)), field(hash(6)), Value::Integer(u8::from(attribution_required).into()), Value::Text(name)]))?;
                assert_eq!(measured, bytes.len());
                assert_eq!(committed, digest(b"pigloros/fork-create-command/v1", &bytes));
            }
        }
    }
    assert_eq!(pos_core::CanonicalLengthErrorV1::LengthOverflow.to_string(), "canonical length overflow");
    Ok(())
}

#[test]
fn maximal_native_cardinalities_and_every_integer_width_use_the_same_emitter() -> Fallible<()> {
    let world = World::new(Shape::Mixed, false)?;
    let built = world.build(&Spec::default())?;
    let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
    let mut manifest = closure.signed_manifest().manifest().input().clone();
    manifest.final_fork_logical_head = u64::MAX;
    manifest.intervention_sequences = (1..=MAX_FORK_MANIFEST_INTERVENTIONS_V1)
        .map(|index| u64::try_from(index).map(|index| index + manifest.parent_logical_head))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = ForkReproManifestV1::new(manifest)?;
    parity!(&manifest);
    parity!(SignedForkReproManifestV1::new(closure.signed_manifest().identity(), manifest, closure.signed_manifest().signature())?);
    let graph = closure.classifier().ok_or("missing classifier")?;
    let mut source = graph.source.input().clone();
    source.registrar_identifier = "r".repeat(MAX_FORK_EVENT_REGISTRAR_BYTES_V1);
    source.routes = (0..MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1).map(|index| {
        let mut route = format!("{index:08}");
        route.push_str(&"r".repeat(MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1 - route.len()));
        ForkEventSourceDescriptorV1::new(route, hash(9)).map(|source| ForkExternalInputRouteV1::new(source, index % 2 == 0))
    }).collect::<Result<Vec<_>, _>>()?;
    let source = ForkClassifierSourceV1::new(source)?;
    parity!(&source);
    let mut table = graph.table.input().clone();
    table.registrar_identifier.clone_from(&source.input().registrar_identifier);
    table.routes.clone_from(&source.input().routes);
    parity!(ForkClassifierTableV1::new(table)?);
    for head in [0, 23, 24, 255, 256, 65_535, 65_536, u64::from(u32::MAX), u64::from(u32::MAX) + 1, u64::MAX] {
        let mut input = closure.publication_operation().projection().input().clone();
        input.final_logical_head = head;
        parity!(ForkPublicationOperationV1::new(input)?);
    }
    Ok(())
}
