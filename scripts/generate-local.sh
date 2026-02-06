#!/usr/bin/env bash
set -euo pipefail

CERTS_DIR="${1:-certs}"
NAME="${CERT_NAME:-example}"
DAYS="${CERT_DAYS:-365}"
KEY_SIZE="${CERT_KEY_SIZE:-2048}"
PASSWORD="${CERT_PASSWORD:-testpass}"

mkdir -p "$CERTS_DIR"

cert_path="$CERTS_DIR/${NAME}.pem"
key_path="$CERTS_DIR/${NAME}.key"
pfx_path="$CERTS_DIR/${NAME}.pfx"
pfx_pass_path="$CERTS_DIR/${NAME}-pass.pfx"
pfx_b64_path="$CERTS_DIR/${NAME}.pfx.base64"

openssl req -x509 -nodes -days "$DAYS" -newkey "rsa:${KEY_SIZE}" \
  -keyout "$key_path" -out "$cert_path" \
  -subj "/CN=${NAME}.local/O=CertConv" \
  -addext "subjectAltName = DNS:${NAME}.local,DNS:localhost" \
  -addext "keyUsage = digitalSignature" \
  -addext "extendedKeyUsage = serverAuth" >/dev/null 2>&1

chmod 600 "$key_path"

openssl pkcs12 -export -out "$pfx_path" -in "$cert_path" \
  -inkey "$key_path" -passout pass: >/dev/null 2>&1

openssl pkcs12 -export -out "$pfx_pass_path" -in "$cert_path" \
  -inkey "$key_path" -passout "pass:${PASSWORD}" >/dev/null 2>&1

base64 <"$pfx_path" | tr -d '\n' >"$pfx_b64_path"

cat <<EOF_SUMMARY
Generated sample certs in: $CERTS_DIR

- $cert_path
- $key_path
- $pfx_path
- $pfx_pass_path (password: ${PASSWORD})
- $pfx_b64_path
EOF_SUMMARY
