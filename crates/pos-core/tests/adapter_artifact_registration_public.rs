use pos_core::{
    extract_adapter_admission_registration_v1, extract_adapter_transcript_registration_v1,
    AdapterArtifactRegistrationErrorV1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactRegistrationFieldsV1, ArtifactRegistrationV1, ArtifactTransitionRuleV1,
    ErasureArtifactClassV1, Hash,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

fn from_hex(text: &str) -> TestResult<Vec<u8>> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn admission_bytes() -> TestResult<Vec<u8>> {
    from_hex(concat!(
        "86444d414131015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a6517",
        "6c015820515151515151515151515151515151515151515151515151515151515151515180"
    ))
}

fn transcript_bytes() -> TestResult<Vec<u8>> {
    from_hex(concat!(
        "87444d415431015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a6517",
        "6c58a2894457524831015820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e95",
        "0a65176c501010101010101010101010101010101007582021212121212121212121212121212121",
        "21212121212121212121212121212121582031313131313131313131313131313131313131313131",
        "31313131313131313131015820414141414141414141414141414141414141414141414141414141",
        "41414141415820424242424242424242424242424242424242424242424242424242424242424258",
        "20c40ae5d5380762fb743e192e291b526832f982d6d5a58893163ff0b10bf8142380",
    ))
}

#[test]
fn admission_extractor_derives_the_complete_public_root_fields() -> TestResult<()> {
    let bytes = admission_bytes()?;
    let registration = extract_adapter_admission_registration_v1(&bytes)?;
    let fields = registration.fields();
    assert_eq!(fields.artifact_class, ErasureArtifactClassV1::ReproManifest);
    assert_eq!(
        fields.artifact_digest,
        ArtifactRegistrationV1::artifact_digest(ErasureArtifactClassV1::ReproManifest, &bytes)?
    );
    assert_eq!(fields.owner_reference, Hash::from_bytes([0x36; 32]));
    assert_eq!(fields.data_class, ArtifactDataClassV1::PublicRecord);
    assert_eq!(fields.optionality, ArtifactOptionalityV1::Required);
    assert_eq!(
        fields.transition_rule,
        ArtifactTransitionRuleV1::PreserveExact
    );
    assert!(fields.required_key_roles.is_empty());
    assert!(fields.key_dependencies.is_empty());
    assert!(fields.child_artifacts.is_empty());
    Ok(())
}

#[test]
fn transcript_extractor_binds_its_exact_required_admission_child() -> TestResult<()> {
    let admission_bytes = admission_bytes()?;
    let admission = extract_adapter_admission_registration_v1(&admission_bytes)?;
    let transcript_bytes = transcript_bytes()?;
    let registration = extract_adapter_transcript_registration_v1(
        &transcript_bytes,
        &admission_bytes,
        &admission,
    )?;
    let fields = registration.fields();
    assert_eq!(fields.artifact_class, ErasureArtifactClassV1::ReproManifest);
    assert_eq!(
        fields.artifact_digest,
        ArtifactRegistrationV1::artifact_digest(
            ErasureArtifactClassV1::ReproManifest,
            &transcript_bytes
        )?
    );
    assert_eq!(fields.child_artifacts.len(), 1);
    assert_eq!(fields.child_artifacts[0].artifact_class, ErasureArtifactClassV1::ReproManifest);
    assert_eq!(fields.child_artifacts[0].artifact_digest, admission.fields().artifact_digest);
    assert_eq!(fields.child_artifacts[0].registration_address, admission.address());
    assert!(fields.child_artifacts[0].required);
    Ok(())
}

#[test]
fn extractor_rejects_foreign_or_unmatched_admission_material() -> TestResult<()> {
    let admission_bytes = admission_bytes()?;
    let foreign_registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::ReproManifest,
        artifact_digest: Hash::from_bytes([9; 32]),
        owner_reference: Hash::from_bytes([0x36; 32]),
        data_class: ArtifactDataClassV1::PublicRecord,
        optionality: ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::PreserveExact,
        required_key_roles: Vec::new(),
        key_dependencies: Vec::new(),
        child_artifacts: Vec::new(),
    })?;
    assert_eq!(
        extract_adapter_transcript_registration_v1(
            &transcript_bytes()?,
            &admission_bytes,
            &foreign_registration,
        ),
        Err(AdapterArtifactRegistrationErrorV1::AdmissionRegistrationMismatch)
    );
    assert_eq!(
        extract_adapter_admission_registration_v1(&[]),
        Err(AdapterArtifactRegistrationErrorV1::InvalidAdmission)
    );
    assert_eq!(
        extract_adapter_transcript_registration_v1(&[], &admission_bytes, &foreign_registration),
        Err(AdapterArtifactRegistrationErrorV1::InvalidTranscript)
    );
    Ok(())
}
