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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
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
        hex(fields.artifact_digest.as_bytes()),
        "b9985dff75c07700a95fe1b060b8b5965ab7c2173aceb7497d664f5f80d27caa"
    );
    assert_eq!(
        fields.owner_reference,
        Hash::from_bytes(<[u8; 32]>::try_from(&bytes[9..41])?)
    );
    assert_eq!(fields.data_class, ArtifactDataClassV1::PublicRecord);
    assert_eq!(fields.optionality, ArtifactOptionalityV1::Required);
    assert_eq!(
        fields.transition_rule,
        ArtifactTransitionRuleV1::PreserveExact
    );
    assert!(fields.required_key_roles.is_empty());
    assert!(fields.key_dependencies.is_empty());
    assert!(fields.child_artifacts.is_empty());
    assert_eq!(
        hex(registration.canonical_cbor()),
        concat!(
            "8b444152443101015820b9985dff75c07700a95fe1b060b8b5965ab7c2173aceb7497d664f5f80d27caa",
            "5820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a65176c020000808080"
        )
    );
    assert_eq!(
        hex(registration.address().as_bytes()),
        "6119adf54fe59d2967383e91d729416854c23415d73754f772a893607778f4d6"
    );
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
        hex(fields.artifact_digest.as_bytes()),
        "d0d8004c71f5ffbecbfab85222600dcfa0924f6fee2a69837b093f0fd1394469"
    );
    assert_eq!(fields.child_artifacts.len(), 1);
    assert_eq!(
        fields.child_artifacts[0].artifact_class,
        ErasureArtifactClassV1::ReproManifest
    );
    assert_eq!(
        hex(fields.child_artifacts[0].artifact_digest.as_bytes()),
        "b9985dff75c07700a95fe1b060b8b5965ab7c2173aceb7497d664f5f80d27caa"
    );
    assert_eq!(
        hex(fields.child_artifacts[0].registration_address.as_bytes()),
        "6119adf54fe59d2967383e91d729416854c23415d73754f772a893607778f4d6"
    );
    assert!(fields.child_artifacts[0].required);
    assert_eq!(
        hex(registration.canonical_cbor()),
        concat!(
            "8b444152443101015820d0d8004c71f5ffbecbfab85222600dcfa0924f6fee2a69837b093f0fd1394469",
            "5820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a65176c020000808081",
            "84015820b9985dff75c07700a95fe1b060b8b5965ab7c2173aceb7497d664f5f80d27caa",
            "58206119adf54fe59d2967383e91d729416854c23415d73754f772a893607778f4d6f5"
        )
    );
    assert_eq!(
        hex(registration.address().as_bytes()),
        "34d1de754b69a4c86a35bac6409b5524319ee01e405a9aa9f03beee723fa127a"
    );
    Ok(())
}

#[test]
fn extractor_rejects_foreign_or_unmatched_admission_material() -> TestResult<()> {
    let admission_bytes = admission_bytes()?;
    let foreign_registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::ReproManifest,
        artifact_digest: Hash::from_bytes([9; 32]),
        owner_reference: Hash::from_bytes(<[u8; 32]>::try_from(&admission_bytes[9..41])?),
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
