#!/usr/bin/env bash
# PKI de laboratorio para o agente TLS: CA ML-DSA-87; certificados DU/RU ML-DSA-65.
# Uso: make-pki.sh DIR   (OpenSSL >= 3.5). SAN: macsec-du / macsec-ru.
set -euo pipefail
d=${1:?uso: make-pki.sh DIR}; mkdir -p "$d"; cd "$d"; umask 077
openssl genpkey -algorithm ML-DSA-87 -out ca.key 2>/dev/null
openssl req -new -x509 -key ca.key -subj "/CN=macsec-testbed-ca" -days 30 -out ca.crt \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign
for n in du ru; do
  openssl genpkey -algorithm ML-DSA-65 -out $n.key 2>/dev/null
  openssl req -new -key $n.key -subj "/CN=macsec-$n" -out $n.csr
  printf 'subjectAltName=DNS:macsec-%s\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n' $n > $n.ext
  openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -out $n.crt -extfile $n.ext 2>/dev/null
  rm -f $n.csr $n.ext
done
chmod 0644 ca.crt du.crt ru.crt
