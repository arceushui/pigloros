mod image_proof_cases {
    include!("image_proof_certificate_cases.rs");
    include!("image_proof_chain_cases.rs");
    include!("image_proof_envelope_cases.rs");
    include!("image_proof_ddi_cases.rs");

    use self::MutableCertificate as Certificate;
    use super::*;
    use cms::{
        cert::CertificateChoices,
        content_info::{CmsVersion, ContentInfo},
        revocation::RevocationInfoChoices,
        signed_data::{SignedData, SignerIdentifier},
    };
    use der::{
        asn1::{ObjectIdentifier, OctetString, SetOfVec},
        Decode, Encode,
    };
    use pos_reference::sandbox_provider_protocol::{
        SandboxImageProofError, VerifiedSandboxImageProof,
    };
    use x509_cert::ext::{pkix::SubjectKeyIdentifier, Extension};

    const PROOF: &[u8] = include_bytes!("../vectors/sim1-pkcs7/proof.der");
    const CERTIFICATE: &[u8] = include_bytes!("../vectors/sim1-pkcs7/signer.der");
    const CHAIN: &[u8] = include_bytes!("../vectors/sim1-pkcs7/chain-proof.der");
    const CHAIN_SIGNER: &[u8] = include_bytes!("../vectors/sim1-pkcs7/chain-signer.der");
    const OPTIONAL: &[u8] = include_bytes!("../vectors/sim1-pkcs7/optional-usage-proof.der");
    const OPTIONAL_SIGNER: &[u8] =
        include_bytes!("../vectors/sim1-pkcs7/optional-usage-signer.der");
    const NOW: u64 = 1_800_000_000;
    // The bytes whose lowercase hexadecimal text is `sim1-pkcs7/root-hash.txt`.
    const SYNTHETIC_ROOT_HASH: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    fn fixture(proof: &[u8], certificate: &[u8]) -> TestResult<Fixture> {
        fixture_for_root(proof, certificate, SYNTHETIC_ROOT_HASH)
    }

    fn fixture_for_root(
        proof: &[u8],
        certificate: &[u8],
        root_hash: [u8; 32],
    ) -> TestResult<Fixture> {
        let mut fixture = Fixture::new()?;
        let fingerprint = Sha256::digest(certificate).into();
        fixture.trust = fixture.authority.trust_with_certificate(fingerprint)?;
        fixture.revocation = revocation(&fixture.trust, &fixture.authority, vec![], vec![])?;
        fixture.sim1 = resign_unsigned_fields(
            &fixture.sim1,
            "SIM1",
            &[
                (7, bytes(root_hash)),
                (
                    12,
                    Value::Array(vec![
                        integer(u64::try_from(proof.len())?),
                        Value::Bytes(Sha256::digest(proof).to_vec()),
                        Value::Bytes(proof.to_vec()),
                    ]),
                ),
                (13, bytes(fingerprint)),
            ],
            &fixture.authority.image,
        )?;
        fixture.lps1 = launch_policy(wrapped_digest(&fixture.sim1)?)?;
        fixture.policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
        Ok(fixture)
    }

    fn verify(
        fixture: &Fixture,
        time: u64,
    ) -> TestResult<Result<VerifiedSandboxImageProof, SandboxImageProofError>> {
        let provider = fixture.admit()?;
        let image =
            provider.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
        Ok(provider.verify_image_proof(&image, time))
    }

    fn edit_cms(
        proof: &[u8],
        edit: impl FnOnce(&mut SignedData) -> TestResult,
    ) -> TestResult<Vec<u8>> {
        let mut outer = ContentInfo::from_der(proof)?;
        let mut cms_data: SignedData = outer.content.decode_as()?;
        edit(&mut cms_data)?;
        outer.content = der::Any::encode_from(&cms_data)?;
        Ok(outer.to_der()?)
    }

    #[test]
    fn public_proof_verification_accepts_pinned_signer_and_complete_chain() -> TestResult {
        for (name, proof, certificate) in [
            ("self-signed", PROOF, CERTIFICATE),
            ("complete chain", CHAIN, CHAIN_SIGNER),
            ("optional usage", OPTIONAL, OPTIONAL_SIGNER),
        ] {
            let fixture = fixture(proof, certificate)?;
            let verified = verify(&fixture, NOW)?.map_err(|error| format!("{name}: {error}"))?;
            assert_eq!(format!("{verified:?}"), "VerifiedSandboxImageProof { .. }");
            assert_eq!(verified, verify(&fixture, NOW)??);
            assert_ne!(verified, verify(&fixture, NOW + 1)??);
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_accepts_inclusive_certificate_time_endpoints() -> TestResult {
        let fixture = fixture(PROOF, CERTIFICATE)?;
        // The signed fixture's UTCTimes are 260928022435Z and 360925022435Z.
        for time in [NOW, 1_790_562_275, 2_105_922_275] {
            let result = verify(&fixture, time)?;
            assert!(
                result.is_ok(),
                "signed certificate rejected at valid time {time}: {result:?}"
            );
        }
        for time in [1_790_562_274, 2_105_922_276] {
            assert_eq!(
                verify(&fixture, time)?,
                Err(SandboxImageProofError::CertificateTime),
                "signed certificate accepted outside its validity interval at {time}"
            );
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_accepts_zero_width_certificate_validity() -> TestResult {
        verify(&fixture(PROOF, CERTIFICATE)?, NOW)??;
        let proof = include_bytes!("../vectors/sim1-pkcs7/zero-width-proof.der");
        let certificate = include_bytes!("../vectors/sim1-pkcs7/zero-width-signer.der");
        let parsed = Certificate::from_der(certificate)?;
        let validity = parsed.tbs_certificate.validity;
        assert_eq!(validity.not_before.to_unix_duration().as_secs(), NOW);
        assert_eq!(validity.not_after.to_unix_duration().as_secs(), NOW);
        let fixture = fixture(proof, certificate)?;
        let result = verify(&fixture, NOW)?;
        assert!(
            result.is_ok(),
            "signed zero-width certificate rejected at its valid instant: {result:?}"
        );
        for time in [NOW - 1, NOW + 1] {
            assert_eq!(
                verify(&fixture, time)?,
                Err(SandboxImageProofError::CertificateTime),
                "signed zero-width certificate accepted outside its validity at {time}"
            );
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_accepts_ski_and_absent_cms_parameters() -> TestResult {
        let certificate = Certificate::from_der(CERTIFICATE)?;
        let (_, key_id) = certificate
            .to_x509()?
            .tbs_certificate()
            .get_extension::<SubjectKeyIdentifier>()?
            .ok_or("missing SKI")?;
        let proof = edit_cms(PROOF, |cms_data| {
            let mut signer = cms_data
                .signer_infos
                .0
                .get(0)
                .ok_or("missing signer")?
                .clone();
            signer.sid = SignerIdentifier::SubjectKeyIdentifier(key_id);
            signer.version = CmsVersion::V3;
            signer.digest_alg.parameters = None;
            signer.signature_algorithm.parameters = None;
            cms_data.version = CmsVersion::V3;
            cms_data.signer_infos = vec![signer].try_into()?;
            let mut digest = cms_data
                .digest_algorithms
                .get(0)
                .ok_or("missing digest")?
                .clone();
            digest.parameters = None;
            cms_data.digest_algorithms = vec![digest].try_into()?;
            Ok(())
        })?;
        verify(&fixture(&proof, CERTIFICATE)?, NOW)??;
        Ok(())
    }

    #[derive(Clone, Copy, Debug)]
    enum ProfileDefect {
        ContentType,
        EmbeddedContent,
        Crls,
        NoDigest,
        ExtraDigest,
        NoSigner,
        ExtraSigner,
        DataVersion,
        SignerVersion,
        SignedAttributes,
        UnsignedAttributes,
        DigestAlgorithm,
        SignerDigest,
        SignatureAlgorithm,
        Parameters,
    }

    fn profile_defect(defect: ProfileDefect) -> TestResult<Vec<u8>> {
        edit_cms(PROOF, |cms_data| {
            let mut signer = cms_data
                .signer_infos
                .0
                .get(0)
                .ok_or("missing signer")?
                .clone();
            let mut digest = cms_data
                .digest_algorithms
                .get(0)
                .ok_or("missing digest")?
                .clone();
            let other = ObjectIdentifier::new("1.2.3.4")?;
            match defect {
                ProfileDefect::ContentType => {
                    cms_data.encap_content_info.econtent_type = other;
                }
                ProfileDefect::EmbeddedContent => {
                    cms_data.encap_content_info.econtent = Some(der::Any::null());
                }
                ProfileDefect::Crls => {
                    cms_data.crls = Some(RevocationInfoChoices(SetOfVec::default()));
                }
                ProfileDefect::NoDigest => {
                    cms_data.digest_algorithms = SetOfVec::default();
                }
                ProfileDefect::ExtraDigest => {
                    let original = digest.clone();
                    digest.oid = other;
                    cms_data.digest_algorithms = vec![original, digest].try_into()?;
                }
                ProfileDefect::NoSigner => {
                    cms_data.signer_infos = vec![].try_into()?;
                    return Ok(());
                }
                ProfileDefect::ExtraSigner => {
                    let original = signer.clone();
                    signer.version = CmsVersion::V3;
                    cms_data.signer_infos = vec![original, signer].try_into()?;
                    return Ok(());
                }
                ProfileDefect::DataVersion => {
                    cms_data.version = CmsVersion::V3;
                }
                ProfileDefect::SignerVersion => {
                    signer.version = CmsVersion::V3;
                }
                ProfileDefect::SignedAttributes => {
                    signer.signed_attrs = Some(SetOfVec::default());
                }
                ProfileDefect::UnsignedAttributes => {
                    signer.unsigned_attrs = Some(SetOfVec::default());
                }
                ProfileDefect::DigestAlgorithm => {
                    digest.oid = other;
                    cms_data.digest_algorithms = vec![digest].try_into()?;
                }
                ProfileDefect::SignerDigest => {
                    signer.digest_alg.oid = other;
                }
                ProfileDefect::SignatureAlgorithm => {
                    signer.signature_algorithm.oid = other;
                }
                ProfileDefect::Parameters => {
                    signer.signature_algorithm.parameters = Some(der::Any::encode_from(&1_u8)?);
                }
            }
            cms_data.signer_infos = vec![signer].try_into()?;
            Ok(())
        })
    }

    #[test]
    fn public_proof_verification_rejects_each_closed_cms_profile_violation() -> TestResult {
        for defect in [
            ProfileDefect::ContentType,
            ProfileDefect::EmbeddedContent,
            ProfileDefect::Crls,
            ProfileDefect::NoDigest,
            ProfileDefect::ExtraDigest,
            ProfileDefect::NoSigner,
            ProfileDefect::ExtraSigner,
            ProfileDefect::DataVersion,
            ProfileDefect::SignerVersion,
            ProfileDefect::SignedAttributes,
            ProfileDefect::UnsignedAttributes,
            ProfileDefect::DigestAlgorithm,
            ProfileDefect::SignerDigest,
            ProfileDefect::SignatureAlgorithm,
            ProfileDefect::Parameters,
        ] {
            let proof = profile_defect(defect)?;
            assert_eq!(
                verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
                Err(SandboxImageProofError::UnsupportedProfile),
                "{defect:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_malformed_signer_content_and_time() -> TestResult {
        for proof in [
            b"bad DER".to_vec(),
            [PROOF, &[0]].concat(),
            PROOF[..PROOF.len() - 1].to_vec(),
        ] {
            assert_eq!(
                verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
                Err(SandboxImageProofError::Malformed)
            );
        }
        for time in [0, u64::MAX] {
            assert_eq!(
                verify(&fixture(PROOF, CERTIFICATE)?, time)?,
                Err(SandboxImageProofError::CertificateTime)
            );
        }
        assert_eq!(
            verify(&fixture(PROOF, OPTIONAL_SIGNER)?, NOW)?,
            Err(SandboxImageProofError::UnauthorizedSigner)
        );
        let mut changed = fixture(PROOF, CERTIFICATE)?;
        changed.sim1 = resign_unsigned_field(
            &changed.sim1,
            "SIM1",
            7,
            bytes([1; 32]),
            &changed.authority.image,
        )?;
        changed.policy = changed.policy_for_image(&changed.sim1, &changed.lps1)?;
        assert_eq!(
            verify(&changed, NOW)?,
            Err(SandboxImageProofError::InvalidSignature)
        );
        let proof = edit_cms(PROOF, |cms_data| {
            let mut signer = cms_data
                .signer_infos
                .0
                .get(0)
                .ok_or("missing signer")?
                .clone();
            signer.signature = OctetString::new(vec![0; 256])?;
            cms_data.signer_infos = vec![signer].try_into()?;
            Ok(())
        })?;
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_rechecks_provider_authority_and_binds_snapshots() -> TestResult {
        let mut fixture = fixture(PROOF, CERTIFICATE)?;
        let original = fixture.admit()?;
        let image =
            original.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;
        let proof = original.verify_image_proof(&image, NOW)?;
        assert_eq!(
            Fixture::new()?.admit()?.verify_image_proof(&image, NOW),
            Err(SandboxImageProofError::AuthorityMismatch)
        );
        fixture.revocation = revocation(
            &fixture.trust,
            &fixture.authority,
            vec![],
            vec![bytes(image.manifest().manifest_digest)],
        )?;
        fixture.policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
        assert_eq!(
            fixture.admit()?.verify_image_proof(&image, NOW),
            Err(SandboxImageProofError::AuthorityMismatch)
        );
        fixture.revocation = revocation(
            &fixture.trust,
            &fixture.authority,
            vec![],
            vec![bytes([77; 32])],
        )?;
        fixture.policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
        assert_ne!(proof, fixture.admit()?.verify_image_proof(&image, NOW)?);
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_foreign_mapping_and_revoked_image_key() -> TestResult {
        let mut fixture = fixture(PROOF, CERTIFICATE)?;
        let original = fixture.admit()?;
        let image =
            original.admit_image(&fixture.sim1, &fixture.root_image, &fixture.executable)?;

        // These are independently authenticated provider snapshots, not a
        // selector update transition; current-head continuity belongs to #438.
        fixture.trust = fixture.authority.trust_with_certificate([77; 32])?;
        fixture.revocation = revocation(&fixture.trust, &fixture.authority, vec![], vec![])?;
        fixture.policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
        assert_eq!(
            fixture.admit()?.verify_image_proof(&image, NOW),
            Err(SandboxImageProofError::AuthorityMismatch)
        );

        fixture.trust = fixture
            .authority
            .trust_with_certificate(Sha256::digest(CERTIFICATE).into())?;
        let revoked = sign_record(
            "RVS1",
            Value::Array(vec![
                Value::Text("RVS1".to_owned()),
                integer(1),
                bytes(fixture.trust.snapshot_digest()),
                integer(3),
                Value::Array(vec![Value::Text("image".to_owned())]),
                Value::Array(vec![]),
                Value::Array(vec![]),
                Value::Text("policy".to_owned()),
            ]),
            &fixture.authority.policy,
        )?;
        fixture.revocation = SandboxRevocationSnapshot::authenticate(&revoked, &fixture.trust)?;
        fixture.policy = fixture.policy_for_image(&fixture.sim1, &fixture.lps1)?;
        assert_eq!(
            fixture.admit()?.verify_image_proof(&image, NOW),
            Err(SandboxImageProofError::AuthorityMismatch)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_extra_or_missing_certificate_material() -> TestResult {
        let absent = edit_cms(PROOF, |cms_data| {
            cms_data.certificates = None;
            Ok(())
        })?;
        assert_eq!(
            verify(&fixture(&absent, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::UnauthorizedSigner)
        );
        let extra = edit_cms(PROOF, |cms_data| {
            let original = Certificate::from_der(CERTIFICATE)?;
            let other = Certificate::from_der(OPTIONAL_SIGNER)?;
            cms_data.certificates = Some(
                vec![
                    CertificateChoices::Certificate(original.to_x509()?),
                    CertificateChoices::Certificate(other.to_x509()?),
                ]
                .try_into()?,
            );
            Ok(())
        })?;
        assert_eq!(
            verify(&fixture(&extra, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::InvalidPath)
        );
        let large = edit_cms(PROOF, |cms_data| {
            let mut certificate = Certificate::from_der(CERTIFICATE)?;
            certificate
                .tbs_certificate
                .extensions
                .as_mut()
                .ok_or("missing extensions")?
                .push(Extension {
                    extn_id: ObjectIdentifier::new("1.2.3.4")?,
                    critical: false,
                    extn_value: OctetString::new(vec![0; 65_536])?,
                });
            cms_data.certificates =
                Some(vec![CertificateChoices::Certificate(certificate.to_x509()?)].try_into()?);
            Ok(())
        })?;
        assert_eq!(
            verify(&fixture(&large, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::ResourceLimit)
        );
        Ok(())
    }
}
