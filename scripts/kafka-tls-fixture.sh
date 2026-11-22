#!/bin/sh
# Generates the TLS material of the SASL_SSL listeners of the compose broker `kafka` (Story 1.5): a root CA
# standing in for the Strimzi cluster CA, a broker certificate it signs for `localhost`, `kafka` and
# 127.0.0.1, and a second, unrelated CA that the spike tests use as the untrusted one. Nothing it writes is
# committed: the output directory lies under the git-ignored `target/`.
#
# The compose one-shot service `kafka-tls` runs it, as the host user, before the broker starts, so the
# material exists when the broker reads it and the test process can read the CA file from the checkout.
# It keeps a complete set that is still valid for a day and regenerates everything otherwise; after the
# set has been regenerated, a running broker must be recreated (`docker compose up --detach
# --force-recreate kafka`) to load the new certificate.
#
# Usage: scripts/kafka-tls-fixture.sh <output-directory>
# Needs: openssl (the `apache/kafka` image ships it).
#
# The keys are throwaway test keys and are written readable by every user, because the broker container
# runs as its own user and must read them.
set -eu

out="${1:?usage: kafka-tls-fixture.sh <output-directory>}"
days=30

complete() {
    for file in ca.pem broker.pem broker-keystore.pem untrusted-ca.pem; do
        [ -s "$out/$file" ] || return 1
    done
    openssl verify -CAfile "$out/ca.pem" "$out/broker.pem" > /dev/null 2>&1 || return 1
    openssl x509 -in "$out/broker.pem" -noout -checkend 86400 > /dev/null 2>&1 || return 1
    openssl x509 -in "$out/ca.pem" -noout -checkend 86400 > /dev/null 2>&1 || return 1
}

if complete; then
    echo "kafka-tls-fixture: keeping the valid TLS material in $out"
    exit 0
fi

mkdir -p "$out"
work="$(mktemp -d "$out/.work.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# A self-signed root CA: basic constraints CA:TRUE and key usage keyCertSign, as WebPKI (rustls) requires.
new_ca() {
    name="$1"
    subject="$2"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/$name.key" 2> /dev/null
    openssl req -x509 -new -key "$work/$name.key" -sha256 -days "$days" -subj "$subject" \
        -addext 'basicConstraints=critical,CA:TRUE' \
        -addext 'keyUsage=critical,keyCertSign,cRLSign' \
        -addext 'subjectKeyIdentifier=hash' \
        -out "$work/$name.pem"
}

new_ca ca '/O=api-gateway-service test/CN=Kafka spike cluster CA'
new_ca untrusted-ca '/O=api-gateway-service test/CN=Kafka spike untrusted CA'

# The broker certificate: an unencrypted PKCS#8 key (the PEM keystore of the broker reads it without a
# password) and a leaf certificate for every name the tests connect through.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work/broker.key" 2> /dev/null
openssl req -new -key "$work/broker.key" -subj '/O=api-gateway-service test/CN=kafka' -out "$work/broker.csr"
cat > "$work/broker.ext" << 'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:kafka,IP:127.0.0.1
EOF
openssl x509 -req -in "$work/broker.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -CAcreateserial \
    -sha256 -days "$days" -extfile "$work/broker.ext" -out "$work/broker.pem" 2> /dev/null

# The broker's PEM keystore: the private key followed by its certificate chain.
cat "$work/broker.key" "$work/broker.pem" "$work/ca.pem" > "$work/broker-keystore.pem"

for file in ca.pem broker.pem broker-keystore.pem untrusted-ca.pem; do
    chmod 0644 "$work/$file"
    mv -f "$work/$file" "$out/$file"
done
chmod 0755 "$out"
echo "kafka-tls-fixture: generated new TLS material in $out"
