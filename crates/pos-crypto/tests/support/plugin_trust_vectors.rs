// Independently generated fixed PTR1/PRV1 wire fixtures.
// Shared by the unit preimage oracle and the public verifier contract.
const PTR1_HEX: &str = "8c6450545231016d74727573742e6578616d706c65182a201a01e284fff601818258209d7043381b703609599e44f8e8c09abb52faad21b96b60306764dfcb160712935820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787378184697075626c697368657203095820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f081826c616c7068612f706c7567696e697075626c6973686572818258209d7043381b703609599e44f8e8c09abb52faad21b96b60306764dfcb16071293584008e30fd5d68f52f16af09657e58937789e4fbf37f306204d4bf0b6756eabd5a34bd445246cbdde58cdf8bd6e3a7d9b39010f93c79543fc6001f96cf979492407";
const PRV1_HEX: &str = "8c6450525631016d74727573742e6578616d706c6507201a01e284ff5820ae7a0ddfc0690d64ec7f2cdb4d34dcd9d21d357a2039a2e23d4e43ce5779c5d3f60a8187697075626c697368657203095820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f00a01f6818458208fafa054a5f8bebcc9f979e00f851dc064db4a18bece1c8b974f62edfefbd72d0a025820ee791594f8eff6021e834de16a79b82f550aad57c19c98ef24bbab0494c8de6a818258209d7043381b703609599e44f8e8c09abb52faad21b96b60306764dfcb160712935840bc6fb9ac3c455770c5aa68dc532cd9367be6a4edd95869547569094dae130a6c67afefe5fb3ec87742562101dcada416bfd46b057288ccf70ff749648e0d6e0c";

/// Decode the fixed lower-case hexadecimal wire fixture.
fn hex_bytes(value: &str) -> Result<Vec<u8>, &'static str> {
    let pairs = value.as_bytes().chunks_exact(2);
    if !pairs.remainder().is_empty() {
        return Err("hex input has an odd length");
    }
    pairs
        .map(|pair| {
            let nibble = |byte| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err("hex input contains a non-lowercase digit"),
            };
            Ok((nibble(pair[0])? << 4) | nibble(pair[1])?)
        })
        .collect()
}
