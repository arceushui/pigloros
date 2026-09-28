mod chain_cases {
    use super::*;

    fn edited_chain(
        edit: impl FnOnce(&mut Vec<Certificate>, usize, usize, usize) -> TestResult,
    ) -> TestResult<(Vec<u8>, Vec<u8>)> {
        let original_leaf = Certificate::from_der(CHAIN_SIGNER)?;
        let mut selected_der = Vec::new();
        let proof = edit_cms(CHAIN, |cms_data| {
            let mut certificates: Vec<_> = cms_data
                .certificates
                .as_ref()
                .ok_or("missing certificates")?
                .0
                .iter()
                .map(|choice| match choice {
                    CertificateChoices::Certificate(certificate) => Ok(certificate.clone()),
                    CertificateChoices::Other(_) => Err("unexpected certificate choice"),
                })
                .collect::<Result<_, _>>()?;
            let leaf = certificates
                .iter()
                .position(|cert| *cert == original_leaf)
                .ok_or("missing leaf")?;
            let root = certificates
                .iter()
                .position(|cert| cert.tbs_certificate.subject == cert.tbs_certificate.issuer)
                .ok_or("missing root")?;
            let intermediate = (0..certificates.len())
                .find(|index| *index != leaf && *index != root)
                .ok_or("missing intermediate")?;
            edit(&mut certificates, leaf, root, intermediate)?;
            selected_der = certificates
                .iter()
                .find(|cert| cert.tbs_certificate.subject == original_leaf.tbs_certificate.subject)
                .ok_or("missing edited leaf")?
                .to_der()?;
            cms_data.certificates = Some(
                certificates
                    .into_iter()
                    .map(CertificateChoices::Certificate)
                    .collect::<Vec<_>>()
                    .try_into()?,
            );
            Ok(())
        })?;
        Ok((proof, selected_der))
    }

    #[test]
    fn public_proof_verification_requires_exactly_one_chain_root() -> TestResult {
        for extra in [false, true] {
            let (proof, leaf) = edited_chain(|certificates, _, root, _| {
                if extra {
                    let mut duplicate = certificates[root].clone();
                    duplicate.tbs_certificate.serial_number =
                        x509_cert::serial_number::SerialNumber::new(&[99])?;
                    certificates.push(duplicate);
                } else {
                    certificates.remove(root);
                }
                Ok(())
            })?;
            assert_eq!(
                verify(&fixture(&proof, &leaf)?, NOW)?,
                Err(SandboxImageProofError::InvalidPath)
            );
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_non_ca_chain_members() -> TestResult {
        for root_member in [false, true] {
            let (proof, leaf) = edited_chain(|certificates, _, root, intermediate| {
                let index = if root_member { root } else { intermediate };
                replace_extension(&mut certificates[index], "2.5.29.19", &[0x30, 0])
            })?;
            assert_eq!(
                verify(&fixture(&proof, &leaf)?, NOW)?,
                Err(SandboxImageProofError::InvalidPath)
            );
        }
        let (proof, leaf) = edited_chain(|certificates, _, _, intermediate| {
            // digitalSignature alone cannot authorize certificate issuance.
            replace_extension(
                &mut certificates[intermediate],
                "2.5.29.15",
                &[3, 2, 7, 128],
            )
        })?;
        assert_eq!(
            verify(&fixture(&proof, &leaf)?, NOW)?,
            Err(SandboxImageProofError::InvalidPath)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_checks_intermediate_time_and_signatures() -> TestResult {
        let (proof, leaf) = edited_chain(|certificates, _, _, intermediate| {
            let validity = &mut certificates[intermediate].tbs_certificate.validity;
            validity.not_before = validity.not_after;
            Ok(())
        })?;
        assert_eq!(
            verify(&fixture(&proof, &leaf)?, NOW)?,
            Err(SandboxImageProofError::CertificateTime)
        );
        for (root_member, expected) in [
            (true, SandboxImageProofError::InvalidSignature),
            (false, SandboxImageProofError::InvalidPath),
        ] {
            let (proof, leaf) = edited_chain(|certificates, _, root, intermediate| {
                let index = if root_member { root } else { intermediate };
                certificates[index].signature = der::asn1::BitString::from_bytes(&[0; 256])?;
                Ok(())
            })?;
            assert_eq!(verify(&fixture(&proof, &leaf)?, NOW)?, Err(expected));
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_unsupported_root_usage() -> TestResult {
        for (value, expected) in [
            (&[5, 0][..], SandboxImageProofError::Malformed),
            (
                &[0x30, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 3][..],
                SandboxImageProofError::UnsupportedProfile,
            ),
        ] {
            let (proof, leaf) = edited_chain(|certificates, _, root, _| {
                replace_extension(&mut certificates[root], "2.5.29.37", value)
            })?;
            assert_eq!(verify(&fixture(&proof, &leaf)?, NOW)?, Err(expected));
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_unsupported_chain_certificate_versions() -> TestResult {
        for root_member in [false, true] {
            let (proof, leaf) = edited_chain(|certificates, leaf, root, _| {
                let index = if root_member { root } else { leaf };
                certificates[index].tbs_certificate.version = x509_cert::certificate::Version::V2;
                Ok(())
            })?;
            assert_eq!(
                verify(&fixture(&proof, &leaf)?, NOW)?,
                Err(SandboxImageProofError::InvalidPath)
            );
        }
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_unused_intermediates() -> TestResult {
        let (proof, leaf) = edited_chain(|certificates, _, _, intermediate| {
            let mut unused = certificates[intermediate].clone();
            // Its distinct subject cannot satisfy the selected leaf's issuer.
            // The original complete chain remains present and valid.
            unused.tbs_certificate.subject = Certificate::from_der(OPTIONAL_SIGNER)?
                .tbs_certificate
                .subject;
            unused.tbs_certificate.serial_number =
                x509_cert::serial_number::SerialNumber::new(&[99])?;
            certificates.push(unused);
            Ok(())
        })?;
        assert_eq!(
            verify(&fixture(&proof, &leaf)?, NOW)?,
            Err(SandboxImageProofError::InvalidPath)
        );
        Ok(())
    }
}
