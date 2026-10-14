//! The private V1 registry grammar. Semantic validation remains in its owner.

mod cursor;

use std::collections::BTreeMap;

use cursor::{Cursor, Header};

use super::{
    read_guard::ReadContext, KeyDestructionRequestV1, KeyIdentityV1,
    KeyRecordV1, KeyRegistryFormatVersionV1, KeyRegistryReadErrorV1 as Error,
    KeyRegistryStateV1, KeyRoleV1, KeyTombstoneV1, OwnerIdV1,
};
use crate::{Hash, PublicKey};

type Result<T> = std::result::Result<T, Error>;

pub(super) fn read(bytes: &[u8], context: &mut ReadContext<'_>) -> Result<KeyRegistryStateV1> {
    context.step(|context| {
        let registry = Cursor::new(bytes).registry(context)?;
        registry.validate_with_read_context(context).map(|()| registry)
    })
}

impl Cursor<'_> {
    fn registry(&mut self, context: &mut ReadContext<'_>) -> Result<KeyRegistryStateV1> {
        let mut records = None;
        let mut active = None;
        let mut tombstones = None;
        let mut highest_epoch = None;
        let mut pending_destructions = None;
        let mut version = None;
        self.fields(context, |cursor, field, context| match field {
            b"records" => cursor.field(context, &mut records, |cursor, context| {
                cursor.map(context, Self::identity, Self::record)
            }),
            b"active" => cursor.field(context, &mut active, |cursor, context| {
                cursor.map(context, Self::scope, Self::identity)
            }),
            b"tombstones" => cursor.field(context, &mut tombstones, |cursor, context| {
                cursor.map(context, Self::identity, Self::tombstone)
            }),
            b"highest_epoch" => cursor.field(context, &mut highest_epoch, |cursor, context| {
                cursor.map(context, Self::scope, Self::epoch)
            }),
            b"pending_destructions" => {
                cursor.field(context, &mut pending_destructions, |cursor, context| {
                    cursor.map(context, Self::identity, Self::request)
                })
            }
            b"version" => cursor.field(context, &mut version, Self::version),
            _ => Err(Error::InvalidSnapshot),
        })?;
        Ok(KeyRegistryStateV1 {
            records: records.ok_or(Error::InvalidSnapshot)?,
            active: active.ok_or(Error::InvalidSnapshot)?,
            tombstones: tombstones.ok_or(Error::InvalidSnapshot)?,
            highest_epoch: highest_epoch.ok_or(Error::InvalidSnapshot)?,
            pending_destructions: pending_destructions.ok_or(Error::InvalidSnapshot)?,
            version: version.ok_or(Error::InvalidSnapshot)?,
        })
    }

    fn fields(
        &mut self,
        context: &mut ReadContext<'_>,
        mut field: impl FnMut(&mut Self, &[u8], &mut ReadContext<'_>) -> Result<()>,
    ) -> Result<()> {
        let Header::Map(mut remaining) = self.untagged(context)? else {
            return Err(Error::InvalidSnapshot);
        };
        self.nested(context, |cursor, context| {
            while cursor.next(&mut remaining, context)? {
                context.step(|context| {
                    let name = cursor.identifier(context)?;
                    field(cursor, name, context)
                })?;
            }
            Ok(())
        })
    }

    fn field<T>(
        &mut self,
        context: &mut ReadContext<'_>,
        slot: &mut Option<T>,
        read: impl FnOnce(&mut Self, &mut ReadContext<'_>) -> Result<T>,
    ) -> Result<()> {
        context.step(|context| {
            // Derived struct visitors reject a duplicate before its value is
            // decoded. Optional fields use Option<Option<_>> for that reason.
            if slot.is_some() {
                return Err(Error::InvalidSnapshot);
            }
            read(self, context).map(|value| *slot = Some(value))
        })
    }

    fn map<K: Ord, V>(
        &mut self,
        context: &mut ReadContext<'_>,
        mut key: impl FnMut(&mut Self, &mut ReadContext<'_>) -> Result<K>,
        mut value: impl FnMut(&mut Self, &mut ReadContext<'_>) -> Result<V>,
    ) -> Result<BTreeMap<K, V>> {
        let Header::Map(mut remaining) = self.untagged(context)? else {
            return Err(Error::InvalidSnapshot);
        };
        self.nested(context, |cursor, context| {
            let mut map = BTreeMap::new();
            while cursor.next(&mut remaining, context)? {
                context.step(|context| {
                    let key = key(cursor, context)?;
                    let value = value(cursor, context)?;
                    context.checkpoint()?;
                    // Move already charged fields; duplicate map keys replace
                    // the old entry exactly as Serde's BTreeMap visitor does.
                    map.insert(key, value);
                    Ok(())
                })?;
            }
            Ok(map)
        })
    }

    fn identity(&mut self, context: &mut ReadContext<'_>) -> Result<KeyIdentityV1> {
        context.step(|context| {
            let mut owner_id = None;
            let mut role = None;
            let mut epoch = None;
            self.fields(context, |cursor, field, context| match field {
                b"owner_id" => cursor.field(context, &mut owner_id, Self::owner),
                b"role" => cursor.field(context, &mut role, Self::role),
                b"epoch" => cursor.field(context, &mut epoch, Self::epoch),
                _ => cursor.skip(context),
            })?;
            Ok(KeyIdentityV1::from_parts(
                owner_id.ok_or(Error::InvalidSnapshot)?,
                role.ok_or(Error::InvalidSnapshot)?,
                epoch.ok_or(Error::InvalidSnapshot)?,
            ))
        })
    }

    fn scope(&mut self, context: &mut ReadContext<'_>) -> Result<(OwnerIdV1, KeyRoleV1)> {
        let Header::Array(mut remaining) = self.untagged(context)? else {
            return Err(Error::InvalidSnapshot);
        };
        self.nested(context, |cursor, context| {
            if !cursor.next(&mut remaining, context)? {
                return Err(Error::InvalidSnapshot);
            }
            let owner = cursor.owner(context)?;
            if !cursor.next(&mut remaining, context)? {
                return Err(Error::InvalidSnapshot);
            }
            let role = cursor.role(context)?;
            // Ciborium's tuple visitor reads exactly two items, without asking
            // for a third item or consuming an indefinite-array terminator.
            Ok((owner, role))
        })
    }

    fn record(&mut self, context: &mut ReadContext<'_>) -> Result<KeyRecordV1> {
        context.step(|context| {
            let mut identity = None;
            let mut private_material_digest = None;
            let mut public_verification_key = None;
            self.fields(context, |cursor, field, context| match field {
                b"identity" => cursor.field(context, &mut identity, Self::identity),
                b"private_material_digest" => {
                    cursor.field(context, &mut private_material_digest, |cursor, context| {
                        cursor.optional(context, Self::digest)
                    })
                }
                b"public_verification_key" => {
                    cursor.field(context, &mut public_verification_key, |cursor, context| {
                        cursor.optional(context, Self::public_key)
                    })
                }
                _ => cursor.skip(context),
            })?;
            Ok(KeyRecordV1 {
                identity: identity.ok_or(Error::InvalidSnapshot)?,
                private_material_digest: private_material_digest.unwrap_or(None),
                public_verification_key: public_verification_key.unwrap_or(None),
            })
        })
    }

    fn tombstone(&mut self, context: &mut ReadContext<'_>) -> Result<KeyTombstoneV1> {
        context.step(|context| {
            let mut identity = None;
            let mut material = None;
            let mut destruction = None;
            let mut receipt = None;
            self.fields(context, |cursor, field, context| match field {
                b"identity" => cursor.field(context, &mut identity, Self::identity),
                b"destroyed_material_digest" => cursor.field(context, &mut material, Self::digest),
                b"destruction_digest" => cursor.field(context, &mut destruction, Self::digest),
                b"deletion_receipt" => cursor.field(context, &mut receipt, Self::digest),
                _ => cursor.skip(context),
            })?;
            Ok(KeyTombstoneV1 {
                identity: identity.ok_or(Error::InvalidSnapshot)?,
                destroyed_material_digest: material.ok_or(Error::InvalidSnapshot)?,
                destruction_digest: destruction.ok_or(Error::InvalidSnapshot)?,
                deletion_receipt: receipt.ok_or(Error::InvalidSnapshot)?,
            })
        })
    }

    fn request(&mut self, context: &mut ReadContext<'_>) -> Result<KeyDestructionRequestV1> {
        context.step(|context| {
            let mut identity = None;
            let mut material = None;
            let mut authorization = None;
            self.fields(context, |cursor, field, context| match field {
                b"identity" => cursor.field(context, &mut identity, Self::identity),
                b"expected_material_digest" => cursor.field(context, &mut material, Self::digest),
                b"authorization_digest" => cursor.field(context, &mut authorization, Self::digest),
                _ => cursor.skip(context),
            })?;
            Ok(KeyDestructionRequestV1 {
                identity: identity.ok_or(Error::InvalidSnapshot)?,
                expected_material_digest: material.ok_or(Error::InvalidSnapshot)?,
                authorization_digest: authorization.ok_or(Error::InvalidSnapshot)?,
            })
        })
    }

    fn owner(&mut self, context: &mut ReadContext<'_>) -> Result<OwnerIdV1> {
        context.step(|context| {
            let Header::Text(length) = self.untagged(context)? else {
                return Err(Error::InvalidSnapshot);
            };
            let mut owner = String::new();
            self.segments(length, true, context, |bytes, context| {
                let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidSnapshot)?;
                context.materialize(bytes.len())?;
                owner.push_str(text);
                Ok(())
            })?;
            OwnerIdV1::validate_text(&owner).map_err(|_| Error::InvalidSnapshot)?;
            context.materialize(owner.len())?;
            OwnerIdV1::from_borrowed(&owner).map_err(|_| Error::InvalidSnapshot)
        })
    }

    fn role(&mut self, context: &mut ReadContext<'_>) -> Result<KeyRoleV1> {
        context.step(|context| {
            let header = self.untagged(context)?;
            if !matches!(header, Header::Text(_) | Header::Map(Some(1))) {
                return Err(Error::InvalidSnapshot);
            }
            // A text enum identifier must be read again by identifier(). A
            // one-entry enum map instead leaves its value unread, as the
            // pinned unit-variant visitor does; no stricter CBOR is invented.
            if matches!(header, Header::Text(_)) {
                self.return_header(header);
            }
            self.nested(context, |cursor, context| {
                let code = match cursor.identifier(context)? {
                    b"SubjectDataEncryption" => 0,
                    b"SubjectAttributionSigning" => 1,
                    b"TimelineIntegritySigning" => 2,
                    b"PluginReleaseSigning" => 3,
                    b"ExportRecipientEncryption" => 4,
                    _ => return Err(Error::InvalidSnapshot),
                };
                context.materialize(1).map(|()| match code {
                    0 => KeyRoleV1::SubjectDataEncryption,
                    1 => KeyRoleV1::SubjectAttributionSigning,
                    2 => KeyRoleV1::TimelineIntegritySigning,
                    3 => KeyRoleV1::PluginReleaseSigning,
                    _ => KeyRoleV1::ExportRecipientEncryption,
                })
            })
        })
    }

    fn epoch(&mut self, context: &mut ReadContext<'_>) -> Result<u64> {
        context.step(|context| {
            let epoch = self.integer(context)?;
            context.materialize(8).map(|()| epoch)
        })
    }

    fn version(&mut self, context: &mut ReadContext<'_>) -> Result<KeyRegistryFormatVersionV1> {
        context.step(|context| {
            if self.integer(context)? != 1 {
                return Err(Error::InvalidSnapshot);
            }
            context.materialize(1).map(|()| KeyRegistryFormatVersionV1)
        })
    }

    fn optional<T>(
        &mut self,
        context: &mut ReadContext<'_>,
        read: impl FnOnce(&mut Self, &mut ReadContext<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        context.step(|context| {
            // Options do not strip tags before their null/undefined decision.
            // A tagged null is Some whose native digest decoder then rejects.
            let header = self.header(context)?;
            if matches!(header, Header::Simple(22 | 23)) {
                Ok(None)
            } else {
                self.return_header(header);
                read(self, context).map(Some)
            }
        })
    }

    fn fixed_bytes(&mut self, context: &mut ReadContext<'_>) -> Result<[u8; 32]> {
        context.step(|context| {
            let mut bytes = Vec::new();
            match self.untagged(context)? {
                Header::Bytes(length) => {
                    self.segments(length, false, context, |chunk, context| {
                        context.materialize(chunk.len())?;
                        bytes.extend_from_slice(chunk);
                        Ok(())
                    })?;
                }
                Header::Array(mut remaining) => {
                    self.nested(context, |cursor, context| {
                        while cursor.next(&mut remaining, context)? {
                            context.step(|context| {
                                let byte = u8::try_from(cursor.integer(context)?)
                                    .map_err(|_| Error::InvalidSnapshot)?;
                                context.materialize(1)?;
                                bytes.push(byte);
                                Ok(())
                            })?;
                        }
                        Ok(())
                    })?;
                }
                _ => return Err(Error::InvalidSnapshot),
            }
            if bytes.len() != 32 {
                return Err(Error::InvalidSnapshot);
            }
            context.materialize(32)?;
            let mut fixed = [0; 32];
            fixed.copy_from_slice(&bytes);
            Ok(fixed)
        })
    }

    fn digest(&mut self, context: &mut ReadContext<'_>) -> Result<Hash> {
        self.fixed_bytes(context).map(Hash::from_bytes)
    }

    fn public_key(&mut self, context: &mut ReadContext<'_>) -> Result<PublicKey> {
        self.fixed_bytes(context).map(PublicKey::from_bytes)
    }
}
