# HTTPS release-source TLS fixtures (test-only)

These fixtures serve the in-process TLS server of
`tests/https_release_public.rs` (Redmine #426, ADR-061 amendment revision 1).
No test reaches the internet.

**Every file here is test-only.** `server.key.der` is the private key of the
test server certificate. It is committed on purpose so that the tests can run
the server without generating keys. It authorizes nothing: no release, no
signature and no production trust root. The CA keys were discarded after
signing.

| File | Content |
|---|---|
| `test-ca.der` | Self-signed P-256 test CA, `CA:TRUE` |
| `server.der` | Leaf for `DNS:localhost` and `IP:127.0.0.1`, signed by `test-ca.der`, `serverAuth` |
| `server.key.der` | PKCS#8 DER key of `server.der` (test-only) |
| `other-ca.der` | Self-signed P-256 CA unrelated to the server |
| `pad-root-small.der` | Self-signed P-256 root with a padding extension (495 bytes) |
| `pad-root-65536.der` | The same root padded to exactly 65,536 bytes |
| `pad-root-65537.der` | The same root padded to exactly 65,537 bytes |

The padded roots exercise the explicit root-set bounds. Each holds a
non-critical UTF8String extension that starts with the marker
`PIGLOROS-ROOT-00`. The tests rewrite the last two marker characters to make
distinct roots. Root parsing does not check a root's self-signature, so the
rewritten copies still parse.

SHA-256 of the committed bytes:

```text
a3bc4748420fbcfe556acd00f5770223492243e92b20aff16b6b87d541009de5  test-ca.der
2c13f8d9c3ad0158fe8ab656738cbbf38b92724c9b981930e5386be7af3b4487  server.der
0576f159d1329c18e88e57d8a885d4814d0ce3a676020f2aa58c0f01e8cae5e3  server.key.der
300850c51612205876ac290cc3342a21bd7df88df646b66472138def4547c044  other-ca.der
522e8d55fa2ed21bd24d1fb344f5d0c451f76b551f84284545dcd386d8cf40a5  pad-root-small.der
5fa30088427504f726ad911a30fb8ba79fd803bce35b35f4c64c95ea6c7a8b07  pad-root-65536.der
99b178b6bf825ed7758fbd5e211f2cd0ea80b280dab8321742a144682e8664f9  pad-root-65537.der
```

## Regeneration

Generated once with OpenSSL 3.6.1, in a disposable private directory:

```sh
set -e
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 36500 -set_serial 1 \
  -subj '/CN=PiglorOS HTTPS release test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -outform DER -out test-ca.der

openssl ecparam -name prime256v1 -genkey -noout -out server-ec.key
openssl pkcs8 -topk8 -nocrypt -in server-ec.key -outform DER -out server.key.der
openssl req -new -key server-ec.key -subj '/CN=localhost' -out server.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > server.ext
openssl x509 -req -in server.csr -CA test-ca.der -CAform DER -CAkey ca.key \
  -set_serial 2 -days 36500 -sha256 -extfile server.ext \
  -outform DER -out server.der

openssl ecparam -name prime256v1 -genkey -noout -out other.key
openssl req -x509 -new -key other.key -sha256 -days 36500 -set_serial 3 \
  -subj '/CN=PiglorOS HTTPS release unrelated CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -outform DER -out other-ca.der

openssl ecparam -name prime256v1 -genkey -noout -out pad.key
make_pad() { # $1 padding length, $2 output file
  filler=$(head -c "$1" /dev/zero | tr '\0' 'p')
  openssl req -x509 -new -key pad.key -sha256 -days 36500 -set_serial 4 \
    -subj '/CN=PiglorOS HTTPS release root-bound fixture' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign' \
    -addext "2.25.329800735698586629295641978511506172918=ASN1:UTF8String:PIGLOROS-ROOT-00$filler" \
    -outform DER -out "$2"
}
make_pad 0 pad-root-small.der
make_pad 65033 pad-root-65536.der
make_pad 65035 pad-root-65537.der
```

Then keep only the `.der` files listed above and delete the `.key`, `.csr`
and `.ext` files. Signatures make every run produce different bytes. Check
each padded root's exact size and adjust its padding length if needed, then
update the hashes above.
