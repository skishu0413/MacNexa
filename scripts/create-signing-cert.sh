#!/usr/bin/env bash
# Creates a stable, self-signed code-signing identity ("MacNexa Dev") in the
# login keychain so local Debug builds have a consistent signature.
#
# Why: ad-hoc-signed builds get a NEW signature on every rebuild, which
# invalidates the Keychain access ACL for MacNexa's stored secrets and makes
# macOS prompt for the login password on each launch. A stable signature keeps
# that ACL valid, so the prompt goes away after you click "Always Allow" once.
#
# Run once per machine. Requires no Apple Developer account.
set -euo pipefail

NAME="MacNexa Dev"
LOGIN_KC="$HOME/Library/Keychains/login.keychain-db"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if security find-identity -v -p codesigning | grep -q "$NAME"; then
  echo "Identity '$NAME' already present. Nothing to do."
  exit 0
fi

echo "==> Generating self-signed code-signing certificate '$NAME'"
cat > "$TMP/cert.conf" <<EOF
[ req ]
distinguished_name = dn
prompt = no
x509_extensions = codesign_ext
[ dn ]
CN = $NAME
[ codesign_ext ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" \
  -days 3650 -config "$TMP/cert.conf" >/dev/null 2>&1

# -legacy + SHA1/3DES so Apple's Security framework can import the PKCS#12.
openssl pkcs12 -export \
  -inkey "$TMP/key.pem" -in "$TMP/cert.pem" \
  -out "$TMP/id.p12" -name "$NAME" -passout pass:macnexa \
  -legacy -macalg sha1 -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES >/dev/null 2>&1

echo "==> Importing into login keychain (may prompt for your keychain password)"
security import "$TMP/id.p12" -k "$LOGIN_KC" -P macnexa \
  -T /usr/bin/codesign -T /usr/bin/security

echo "==> Verifying codesign can use the identity"
cp /bin/echo "$TMP/testbin"
codesign -s "$NAME" -f "$TMP/testbin" >/dev/null 2>&1
echo "Done. '$NAME' is ready. Now run: xcodegen generate && rebuild."
