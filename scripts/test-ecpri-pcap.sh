#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")
host=poc@192.168.122.101

scp "${ssh_options[@]}" \
  "$project_dir/scripts/generate-ecpri-pcap.py" \
  "$project_dir/scripts/inspect-macsec-pcap.py" \
  "$project_dir/scripts/compare-pcap.py" \
  "$host:/home/poc/"

ssh "${ssh_options[@]}" "$host" 'bash -s' <<'REMOTE'
set -euo pipefail
artifacts=/home/poc/macsec-pcap-artifacts
mkdir -p "$artifacts"
cd "$artifacts"
rm -f input.pcap empty.pcap plain-output.pcap secure-output.pcap recovered.pcap discard.pcap
python3 /home/poc/generate-ecpri-pcap.py input.pcap --count 32
python3 /home/poc/generate-ecpri-pcap.py empty.pcap --count 0

set +e
timeout -s INT 3 \
  /home/poc/macsec-fronthaul/build/apps/dpdk/poc_macsec_dpdk \
  --no-huge --no-pci --file-prefix=macsec-pcap -l 0-2 \
  --vdev=crypto_aesni_gcm0 \
  --vdev=net_pcap0,rx_pcap=input.pcap,tx_pcap=plain-output.pcap \
  --vdev=net_pcap1,rx_pcap=input.pcap,tx_pcap=secure-output.pcap \
  -- \
  --enable-legacy-keying \
  --tx-key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --rx-key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f \
  --tx-sci=0200000000010001 \
  --rx-sci=0200000000020001 \
  --tx-salt=000102030405060708090a0b --rx-salt=101112131415161718191a1b \
  --tx-ssci=1 --rx-ssci=2
result=$?
set -e
if [[ $result -ne 0 && $result -ne 124 ]]; then
  exit "$result"
fi

python3 /home/poc/inspect-macsec-pcap.py secure-output.pcap \
  --sci=0200000000010001 --expected=32

set +e
timeout -s INT 3 \
  /home/poc/macsec-fronthaul/build/apps/dpdk/poc_macsec_dpdk \
  --no-huge --no-pci --file-prefix=macsec-pcap-rx -l 0-2 \
  --vdev=crypto_aesni_gcm0 \
  --vdev=net_pcap0,rx_pcap=empty.pcap,tx_pcap=recovered.pcap \
  --vdev=net_pcap1,rx_pcap=secure-output.pcap,tx_pcap=discard.pcap \
  -- \
  --enable-legacy-keying \
  --tx-key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f \
  --rx-key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --tx-sci=0200000000020001 \
  --rx-sci=0200000000010001 \
  --tx-salt=101112131415161718191a1b --rx-salt=000102030405060708090a0b \
  --tx-ssci=2 --rx-ssci=1
result=$?
set -e
if [[ $result -ne 0 && $result -ne 124 ]]; then
  exit "$result"
fi
python3 /home/poc/compare-pcap.py input.pcap recovered.pcap
ls -lh input.pcap secure-output.pcap recovered.pcap
REMOTE

echo "Artefatos preservados na O-DU: /home/poc/macsec-pcap-artifacts"
