mod identity_cases {
    use super::*;

    fn issuer_proof(
        attribute_bytes: usize,
        reverse: bool,
        last_label_padding: usize,
    ) -> TestResult<Vec<u8>> {
        fn attribute(index: usize, padding: usize) -> TestResult<Vec<u8>> {
            let label = format!("{index:0width$x}", width = 8 + padding);
            Ok(x509_cert::attr::AttributeTypeAndValue {
                oid: ObjectIdentifier::new("2.5.4.3")?,
                value: der::Any::encode_from(&der::asn1::Utf8StringRef::new(&label)?)?,
            }
            .to_der()?)
        }
        let count = attribute_bytes / attribute(0, 0)?.len();
        let mut attributes = (0..count)
            .map(|index| {
                let padding = if index + 1 == count {
                    last_label_padding
                } else {
                    0
                };
                attribute(index, padding)
            })
            .collect::<TestResult<Vec<_>>>()?;
        if reverse {
            attributes.reverse();
        }
        let rdn = der::Any::new(Tag::Set, attributes.concat())?;
        let issuer = der::Any::new(Tag::Sequence, rdn.to_der()?)?;
        edit_field(PROOF, 4, |signers| {
            edit_children(signers, |entries| {
                edit_children(entries.get_mut(0).ok_or("missing signer")?, |fields| {
                    edit_children(fields.get_mut(1).ok_or("missing SID")?, |sid| {
                        *sid.get_mut(0).ok_or("missing issuer")? = issuer;
                        Ok(())
                    })
                })
            })
        })
    }

    fn signer_identifier(proof: &[u8]) -> TestResult<SignerIdentifier> {
        let outer = ContentInfo::from_der(proof)?;
        let cms_data: SignedData = outer.content.decode_as()?;
        Ok(cms_data
            .signer_infos
            .0
            .get(0)
            .ok_or("missing signer")?
            .sid
            .clone())
    }

    #[test]
    fn public_proof_verification_rejects_malformed_issuer_names() -> TestResult {
        for issuer in [
            der::Any::null(),
            der::Any::new(Tag::Sequence, vec![5, 0])?,
            der::Any::new(Tag::Sequence, vec![0x31, 0x82, 0xff, 0xff])?,
            der::Any::new(
                Tag::Sequence,
                der::Any::new(Tag::Set, vec![0x30, 0x82, 0xff, 0xff])?.to_der()?,
            )?,
        ] {
            let proof = edit_field(PROOF, 4, |signers| {
                edit_children(signers, |entries| {
                    edit_children(entries.get_mut(0).ok_or("missing signer")?, |fields| {
                        edit_children(fields.get_mut(1).ok_or("missing SID")?, |sid| {
                            *sid.get_mut(0).ok_or("missing issuer")? = issuer;
                            Ok(())
                        })
                    })
                })
            })?;
            assert_eq!(
                verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
                Err(SandboxImageProofError::Malformed)
            );
        }
        let proof = edit_field(PROOF, 4, |signers| {
            edit_children(signers, |entries| {
                edit_children(entries.get_mut(0).ok_or("missing signer")?, |fields| {
                    *fields.get_mut(1).ok_or("missing SID")? =
                        der::Any::new(Tag::Sequence, vec![])?;
                    Ok(())
                })
            })
        })?;
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_checks_complete_certificate_roundtrip() -> TestResult {
        let (canonical, certificate) = edited_certificate(|certificate| {
            certificate.tbs_certificate.subject = "CN=proof+OU=unit".parse()?;
            Ok(())
        })?;
        let proof = edit_field(&canonical, 3, |certificates| {
            edit_children(certificates, |entries| {
                edit_children(entries.get_mut(0).ok_or("missing certificate")?, |fields| {
                    edit_children(fields.get_mut(0).ok_or("missing TBS")?, |tbs| {
                        edit_children(tbs.get_mut(5).ok_or("missing subject")?, |rdns| {
                            edit_children(rdns.get_mut(0).ok_or("missing RDN")?, |attributes| {
                                assert_eq!(attributes.len(), 2);
                                attributes.reverse();
                                Ok(())
                            })
                        })
                    })
                })
            })
        })?;
        assert_ne!(proof, canonical);
        assert_eq!(
            verify(&fixture(&canonical, &certificate)?, NOW)?,
            Err(SandboxImageProofError::InvalidPath)
        );
        assert_eq!(
            verify(&fixture(&proof, &certificate)?, NOW)?,
            Err(SandboxImageProofError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_bounds_near_limit_issuer_before_decoding() -> TestResult {
        let proof = issuer_proof(1024 * 1024 - 4096, false, 0)?;
        assert!(proof.len() > 1024 * 1024 - 4096);
        assert!(proof.len() <= 1024 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::ResourceLimit)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_bounds_sid_before_signer_selection() -> TestResult {
        verify(&fixture(PROOF, CERTIFICATE)?, NOW)??;
        let proof = issuer_proof(96 * 1024, false, 0)?;
        let SignerIdentifier::IssuerAndSerialNumber(sid) = signer_identifier(&proof)? else {
            return Err("expected issuer-and-serial SID".into());
        };
        assert!(sid.to_der()?.len() > 64 * 1024);
        // The later per-RDN count limit must not mask the earlier SID bound.
        assert!(sid.issuer.as_ref().iter().all(|rdn| rdn.len() < 32_768));
        assert!(proof.len() <= 1024 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::ResourceLimit),
            "oversized SID must be rejected before signer selection"
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_reaches_signer_selection_at_sid_limit() -> TestResult {
        verify(&fixture(PROOF, CERTIFICATE)?, NOW)??;
        // 3,854 attributes plus three final-label bytes and 15 bytes of SID structure.
        let proof = issuer_proof(3_854 * 17, false, 3)?;
        assert_eq!(signer_identifier(&proof)?.to_der()?.len(), 64 * 1024);
        assert!(proof.len() <= 1024 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::UnauthorizedSigner),
            "at-limit SID must reach signer selection"
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_rejects_reverse_ordered_bounded_issuer() -> TestResult {
        let proof = issuer_proof(64 * 1024 - 4096, true, 0)?;
        assert!(proof.len() > 64 * 1024 - 4096);
        assert!(proof.len() <= 64 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn public_proof_verification_decodes_canonical_bounded_issuer() -> TestResult {
        let proof = issuer_proof(64 * 1024 - 4096, false, 0)?;
        assert!(proof.len() > 64 * 1024 - 4096);
        assert!(proof.len() <= 64 * 1024);
        assert_eq!(
            verify(&fixture(&proof, CERTIFICATE)?, NOW)?,
            Err(SandboxImageProofError::UnauthorizedSigner)
        );
        Ok(())
    }
}
