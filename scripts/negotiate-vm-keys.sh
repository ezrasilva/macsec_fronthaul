#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")
binary=/home/poc/macsec-fronthaul/build-openssl36/src/keying/poc_tls_keying
pki=/home/poc/macsec-pki36
control_socket=/tmp/macsec-poc-control.sock
control_an=${1:-0}
if [[ ! "$control_an" =~ ^[0-3]$ ]]; then
  echo "AN inválido: $control_an" >&2
  exit 1
fi

ssh "${ssh_options[@]}" poc@192.168.122.101 \
  "sudo systemctl stop macsec-keying.service 2>/dev/null || true
   sudo systemctl reset-failed macsec-keying.service 2>/dev/null || true
   sudo systemd-run --collect --unit=macsec-keying --property=Type=simple \\
     --property=User=poc --setenv=LD_LIBRARY_PATH=/opt/openssl/lib64 \\
     --setenv=MACSEC_ENDPOINT_ROLE=du --setenv=MACSEC_CONTROL_AN=$control_an \\
     $binary server 9443 $pki/du.crt $pki/du.key $pki/ca.crt unix:$control_socket"

sleep 1
ssh "${ssh_options[@]}" poc@192.168.122.102 \
  "MACSEC_ENDPOINT_ROLE=ru MACSEC_CONTROL_AN=$control_an \
   MACSEC_TLS_SERVER_NAME=macsec-du LD_LIBRARY_PATH=/opt/openssl/lib64 \
   $binary client 192.168.122.101 9443 \
     $pki/ru.crt $pki/ru.key $pki/ca.crt unix:$control_socket"

echo "Chaves MACsec derivadas, confirmadas e ativadas via Unix socket"
