#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")
binary=/home/poc/macsec-fronthaul/build-openssl36/src/keying/poc_tls_keying
pki=/home/poc/macsec-pki36
output=/home/poc/macsec-keys.env

ssh "${ssh_options[@]}" poc@192.168.122.101 \
  "sudo rm -f $output
   sudo systemctl stop macsec-keying.service 2>/dev/null || true
   sudo systemctl reset-failed macsec-keying.service 2>/dev/null || true
   sudo systemd-run --collect --unit=macsec-keying --property=Type=simple \\
     --property=User=poc --setenv=LD_LIBRARY_PATH=/opt/openssl/lib64 \\
     $binary server 9443 $pki/du.crt $pki/du.key $pki/ca.crt $output"

# Give the transient server time to bind before starting the only accepted client.
sleep 1
ssh "${ssh_options[@]}" poc@192.168.122.102 \
  "rm -f $output
   LD_LIBRARY_PATH=/opt/openssl/lib64 $binary client 192.168.122.101 9443 \\
     $pki/ru.crt $pki/ru.key $pki/ca.crt $output"

du_hash=$(ssh "${ssh_options[@]}" poc@192.168.122.101 "sha256sum $output | cut -d' ' -f1")
ru_hash=$(ssh "${ssh_options[@]}" poc@192.168.122.102 "sha256sum $output | cut -d' ' -f1")
if [[ "$du_hash" != "$ru_hash" ]]; then
  echo "Erro: O-DU e O-RU derivaram chaves diferentes" >&2
  exit 1
fi
echo "Chaves MACsec derivadas e confirmadas nos dois pares (SHA-256: $du_hash)"
