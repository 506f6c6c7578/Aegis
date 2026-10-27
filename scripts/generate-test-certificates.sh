#!/usr/bin/env sh
set -eu

output="$(dirname "$0")/../tests/fixtures/tls"
mkdir -p "$output"
cd "$output"

curve="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"

openssl req -x509 $curve -keyout ca.key -out ca.crt -subj "/O=Aegis Tests/CN=Aegis Test CA" \
    -not_before 20260101000000Z -not_after 20460101000000Z \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

issue() {
    name="$1"
    printf "subjectAltName=DNS:aegis-test.fr,DNS:www.aegis-test.fr\nextendedKeyUsage=serverAuth\n" > "$name.ext"
    openssl req $curve -keyout "$name.key" -out "$name.csr" -subj "/CN=aegis-test.fr"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -out "$name.crt" \
        -not_before "$2" -not_after "$3" -extfile "$name.ext"
    rm "$name.csr" "$name.ext"
}

issue valid 20260101000000Z 20460101000000Z
issue expired 20200101000000Z 20210101000000Z

openssl req -x509 $curve -keyout self-signed.key -out self-signed.crt -subj "/CN=aegis-test.fr" \
    -not_before 20260101000000Z -not_after 20460101000000Z -addext "subjectAltName=DNS:aegis-test.fr"

rm -f ca.srl
