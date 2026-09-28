//! Borrowed CMS envelope bounds before eager collection decoding.
//!
//! DER's `SetOfVec` sorts its decoded elements. Reject excess collections,
//! forbidden attributes and noncanonical ordering before that work occurs.

use der::{asn1::AnyRef, Any, Decode, Reader, SliceReader, Tag, TagNumber, Tagged};

use super::SandboxImageProofError as Error;

const IMPLICIT_ZERO: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber::N0,
};
const IMPLICIT_ONE: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber::N1,
};

pub(super) fn validate(content: &Any) -> Result<(), Error> {
    let mut reader = sequence(AnyRef::from(content))?;
    let _version: AnyRef<'_> = reader.decode()?;
    let digests: AnyRef<'_> = reader.decode()?;
    digests.tag().assert_eq(Tag::Set)?;
    bounded_elements(digests.value(), 1, Error::UnsupportedProfile)?;
    let _encapsulation: AnyRef<'_> = reader.decode()?;
    let mut next: AnyRef<'_> = reader.decode()?;
    if next.tag() == IMPLICIT_ZERO {
        for certificate in bounded_elements(next.value(), 8, Error::ResourceLimit)? {
            if certificate.len() > 64 * 1024 {
                return Err(Error::ResourceLimit);
            }
        }
        next = reader.decode()?;
    }
    if next.tag() == IMPLICIT_ONE {
        return Err(Error::UnsupportedProfile);
    }
    next.tag().assert_eq(Tag::Set)?;
    for signer in bounded_elements(next.value(), 1, Error::UnsupportedProfile)? {
        reject_attributes(signer)?;
    }
    reader.finish(())?;
    Ok(())
}

fn sequence(value: AnyRef<'_>) -> Result<SliceReader<'_>, Error> {
    value.tag().assert_eq(Tag::Sequence)?;
    SliceReader::new(value.value()).map_err(Error::from)
}

fn bounded_elements(body: &[u8], maximum: usize, limit_error: Error) -> Result<Vec<&[u8]>, Error> {
    SliceReader::new(body)
        .map_err(Error::from)
        .and_then(|mut reader| {
            let mut elements = Vec::new();
            while !reader.is_finished() {
                if elements.len() == maximum {
                    return Err(limit_error);
                }
                let encoded = reader.tlv_bytes()?;
                if elements.last().is_some_and(|previous| *previous >= encoded) {
                    return Err(Error::Malformed);
                }
                elements.push(encoded);
            }
            Ok(elements)
        })
}

fn reject_attributes(encoded: &[u8]) -> Result<(), Error> {
    let mut reader = AnyRef::from_der(encoded)
        .map_err(Error::from)
        .and_then(sequence)?;
    let _version: AnyRef<'_> = reader.decode()?;
    let _sid: AnyRef<'_> = reader.decode()?;
    let _digest: AnyRef<'_> = reader.decode()?;
    let signature_algorithm: AnyRef<'_> = reader.decode()?;
    if signature_algorithm.tag() == IMPLICIT_ZERO {
        return Err(Error::UnsupportedProfile);
    }
    let _signature: AnyRef<'_> = reader.decode()?;
    if !reader.is_finished() {
        return Err(Error::UnsupportedProfile);
    }
    Ok(())
}
