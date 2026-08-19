#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")
host=poc@192.168.122.101
count=${1:-100000}
log="$project_dir/artifacts/ecpri-load-benchmark.log"

if [[ ! "$count" =~ ^[1-9][0-9]*$ || "$count" -gt 1000000 ]]; then
  echo "Uso: $0 [frames entre 1 e 1000000]" >&2
  exit 2
fi
mkdir -p "$project_dir/artifacts"

"$project_dir/scripts/stop-vm-endpoints.sh"
restart_endpoints() {
  "$project_dir/scripts/start-vm-endpoints.sh" >/dev/null
}
trap restart_endpoints EXIT

scp "${ssh_options[@]}" "$project_dir/scripts/generate-ecpri-pcap.py" \
  "$project_dir/scripts/inspect-macsec-pcap.py" "$host:/home/poc/"

ssh "${ssh_options[@]}" "$host" "bash -s -- '$count'" >"$log" <<'REMOTE'
set -euo pipefail
count=$1
artifacts=/home/poc/macsec-load-artifacts
mkdir -p "$artifacts"
cd "$artifacts"
rm -f input.pcap empty.pcap secure-output.pcap plain-output.pcap
python3 /home/poc/generate-ecpri-pcap.py input.pcap --count "$count"
python3 /home/poc/generate-ecpri-pcap.py empty.pcap --count 0

output=$(timeout 120 \
  /home/poc/macsec-fronthaul/build/apps/dpdk/poc_macsec_dpdk \
  --no-huge --no-pci --file-prefix=macsec-load -l 0-2 \
  --vdev=crypto_aesni_gcm0 \
  --vdev=net_pcap0,rx_pcap=input.pcap,tx_pcap=plain-output.pcap \
  --vdev=net_pcap1,rx_pcap=empty.pcap,tx_pcap=secure-output.pcap \
  -- \
  --tx-key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --rx-key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f \
  --tx-sci=0200000000010001 \
  --rx-sci=0200000000020001 \
  --tx-salt=000102030405060708090a0b --rx-salt=101112131415161718191a1b \
  --tx-ssci=1 --rx-ssci=2 \
  --latency-stats \
  --exit-on-idle-ms=100)
printf '%s\n' "$output"
summary=$(tr '\r' '\n' <<<"$output" | grep 'protected=' | tail -1)
runtime=$(grep -o 'runtime_us=[0-9]* processed=[0-9]* pps=[0-9.]*' <<<"$output" | tail -1)
latency=$(grep 'latency_us_avg=' <<<"$output" | tail -1)
grep -q "protected=$count " <<<"$summary"
grep -q 'auth=0 replay=0 format=0 other=0 alloc_drop=0 tx_drop=0 ring_drop=0' <<<"$summary"
python3 /home/poc/inspect-macsec-pcap.py secure-output.pcap \
  --sci=0200000000010001 --expected="$count"
test -n "$latency"
echo "LOAD_RESULT frames=$count $runtime $latency"
sha256sum input.pcap secure-output.pcap
REMOTE

cat "$log"
echo "Log: $log"
