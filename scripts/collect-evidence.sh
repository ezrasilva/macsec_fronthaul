#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")
evidence="$project_dir/artifacts/evidence"

mkdir -p "$evidence/pcap" "$evidence/logs"
meson test -C "$project_dir/build" --print-errorlogs >"$evidence/logs/unit-tests.txt"
"$project_dir/scripts/vm-status.sh" >"$evidence/logs/vm-status.txt"

for host in 192.168.122.101 192.168.122.102; do
  name=du
  [[ "$host" == 192.168.122.102 ]] && name=ru
  ssh "${ssh_options[@]}" "poc@$host" \
    'sudo journalctl -u macsec-poc.service --no-pager -n 200' \
    >"$evidence/logs/macsec-$name.log"
done

scp "${ssh_options[@]}" \
  poc@192.168.122.101:/home/poc/macsec-pcap-artifacts/input.pcap \
  "$evidence/pcap/ecpri-input.pcap"
scp "${ssh_options[@]}" \
  poc@192.168.122.101:/home/poc/macsec-pcap-artifacts/secure-output.pcap \
  "$evidence/pcap/ecpri-macsec.pcap"
scp "${ssh_options[@]}" \
  poc@192.168.122.101:/home/poc/macsec-pcap-artifacts/recovered.pcap \
  "$evidence/pcap/ecpri-recovered.pcap"

cp "$project_dir/artifacts/handshake-benchmark.csv" "$evidence/"
cp "$project_dir/artifacts/handshake-benchmark.md" "$evidence/"
if [[ -f "$project_dir/artifacts/ecpri-load-benchmark.log" ]]; then
  cp "$project_dir/artifacts/ecpri-load-benchmark.log" "$evidence/"
fi

(
  cd "$evidence"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS
)
echo "Evidências coletadas em: $evidence"
