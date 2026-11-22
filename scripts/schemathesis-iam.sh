#!/usr/bin/env bash
# Run the Schemathesis contract check with credentials for IAM's own operations.
#
# Usage: scripts/schemathesis-iam.sh
# Generates an ephemeral RSA key pair in a temporary directory, signs a short-lived ROLE_SERVICE token
# that names the IAM caller audience, mounts the public half as the key file of the service under test
# (JWT_PUBLIC_KEYS_HOST_FILE) and runs `make schemathesis-validate` with the token in SCHEMATHESIS_FLAGS,
# so Schemathesis reaches the IAM operations past the 401. No key and no token is committed or kept: the
# directory is removed on every exit path and the token lives for ten minutes.
# Reads JWT_ISSUER, JWT_AUDIENCE and JWT_CALLER_AUDIENCE (defaults as in docs/environment.md) and
# SCHEMATHESIS_FLAGS_BASE (default: --checks all --phases=examples,coverage).
# Exit status: that of `make schemathesis-validate`; 2 when the key or the token cannot be made.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v openssl >/dev/null || { echo "schemathesis-iam.sh: openssl is required" >&2; exit 2; }

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

base64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

openssl genrsa -out "$workdir/private.pem" 2048 2>/dev/null || { echo "schemathesis-iam.sh: could not generate a key" >&2; exit 2; }
openssl rsa -in "$workdir/private.pem" -pubout -out "$workdir/public-keys.pem" 2>/dev/null || { echo "schemathesis-iam.sh: could not export the public key" >&2; exit 2; }
chmod 644 "$workdir/public-keys.pem"

issuer="${JWT_ISSUER:-vilnacrm-user-service}"
audience="${JWT_AUDIENCE:-vilnacrm-api}"
caller_audience="${JWT_CALLER_AUDIENCE:-vilnacrm-iam}"
now="$(date +%s)"
header="$(printf '%s' '{"alg":"RS256","typ":"JWT"}' | base64url)"
payload="$(printf '{"iss":"%s","aud":["%s","%s"],"sub":"schemathesis","sid":"schemathesis-session","jti":"schemathesis-%s","roles":["ROLE_SERVICE"],"iat":%s,"nbf":%s,"exp":%s}' \
  "$issuer" "$audience" "$caller_audience" "$now" "$now" "$now" "$((now + 600))" | base64url)"
signature="$(printf '%s.%s' "$header" "$payload" | openssl dgst -sha256 -sign "$workdir/private.pem" | base64url)"
[ -n "$signature" ] || { echo "schemathesis-iam.sh: could not sign the token" >&2; exit 2; }
token="${header}.${payload}.${signature}"

export JWT_PUBLIC_KEYS_HOST_FILE="$workdir/public-keys.pem"
base_flags="${SCHEMATHESIS_FLAGS_BASE:---checks all --phases=examples,coverage}"
make schemathesis-validate "SCHEMATHESIS_FLAGS=${base_flags} -H 'Authorization: Bearer ${token}'"
