#![cfg(all(feature = "sqlite", not(target_os = "linux")))]

//! Public non-Linux contract for recipient export custody.

use pos_core::{
    ArtifactClaimInputV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1,
    ArtifactTransitionRuleV1, ConsentAuthority, ConsentGrantedV1, CoreError, EntityId,
    ErasureArtifactClassV1, ErasureReferenceV1, ErasureReplayClaimV1, RecipientKeyDescriptorV1,
    RegisteredArtifactV1, ReplayClaimEvaluatorV1, TimelineId,
};
use pos_store::sqlite::{
    RecipientExportDecryptionErrorV1, RecipientExportPublicationErrorV1, RecipientExportRequestV1,
    RecipientKeyOwnerV1, SqliteStore,
};

const EXPORT_DIGEST: ErasureReferenceV1 = ErasureReferenceV1::from_digest([243; 32]);

fn evaluation() -> Result<pos_core::ReplayClaimEvaluationV1, Box<dyn std::error::Error>> {
    ReplayClaimEvaluatorV1::evaluate(
        ErasureReplayClaimV1::Exact,
        &[ArtifactClaimInputV1 {
            registration: RegisteredArtifactV1::new(
                ErasureArtifactClassV1::Export,
                EXPORT_DIGEST,
                ArtifactDataClassV1::StructuralAuditMetadata,
                None,
                ErasureReferenceV1::from_digest([244; 32]),
                ArtifactOptionalityV1::Required,
                ArtifactTransitionRuleV1::PreserveExact,
            ),
            current_claim: ErasureReplayClaimV1::Exact,
            state: ArtifactStateV1::Retained,
        }],
    )
    .map_err(|error| error.to_string().into())
}

#[test]
fn recipient_export_decryption_public_contract_is_unavailable_without_linux_custody(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteStore::open_in_memory()?;
    let owner = RecipientKeyOwnerV1;
    let descriptor = RecipientKeyDescriptorV1::for_grantee(EntityId::new(), 1, [0; 32])?;
    assert!(matches!(
        store.decrypt_recipient_export(&owner, &[], [0; 16], descriptor),
        Err(RecipientExportDecryptionErrorV1::MaterialUnavailable)
    ));
    Ok(())
}

#[test]
fn recipient_export_publication_public_contract_fails_closed_without_linux_custody(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = SqliteStore::open_in_memory()?;
    let owner = RecipientKeyOwnerV1;
    let authority = ConsentAuthority::new();
    let timeline = TimelineId::new();
    let subject = EntityId::new();
    let grantee = EntityId::new();
    let token = authority.record_grant_on_timeline(
        timeline,
        &ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: grantee,
            purpose: "non-linux-recipient-export".to_owned(),
            modalities: pos_core::MODALITY_EXPORT,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: true,
            retention_days: 1,
            expiry_secs: 0,
            grant_seq: 1,
        },
    );
    let descriptor = RecipientKeyDescriptorV1::for_grantee(grantee, 1, [0; 32])?;
    let evaluation = evaluation()?;
    let request = RecipientExportRequestV1 {
        timeline_id: timeline,
        recipient: descriptor,
        artifact_digest: EXPORT_DIGEST,
        evaluation: &evaluation,
        token: &token,
        now_secs: 1,
    };

    assert!(matches!(
        store.publish_recipient_export(&authority, &owner, request),
        Err(RecipientExportPublicationErrorV1::Store(
            CoreError::Storage(_)
        ))
    ));
    assert!(matches!(
        store.read_recipient_export(&owner, [1; 16]),
        Err(RecipientExportPublicationErrorV1::Store(
            CoreError::Storage(_)
        ))
    ));
    assert!(matches!(
        store.recover_recipient_exports(&owner),
        Err(RecipientExportPublicationErrorV1::Store(
            CoreError::Storage(_)
        ))
    ));
    Ok(())
}
