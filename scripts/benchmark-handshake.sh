#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")
du=poc@192.168.122.101
ru=poc@192.168.122.102
iterations=${1:-10}
artifacts="$project_dir/artifacts"
csv="$artifacts/handshake-benchmark.csv"
summary="$artifacts/handshake-benchmark.md"
binary=/home/poc/macsec-fronthaul/build-openssl36/src/keying/poc_tls_keying
pki=/home/poc/macsec-pki36

if [[ ! "$iterations" =~ ^[1-9][0-9]*$ ]]; then
  echo "Uso: $0 [iterações]" >&2
  exit 2
fi
mkdir -p "$artifacts"
printf 'mode,iteration,group,handshake_us,rx_bytes,tx_bytes\n' >"$csv"

run_mode() {
  local mode=$1
  local group=$2
  local iteration output value

  for iteration in $(seq 1 "$iterations"); do
    ssh "${ssh_options[@]}" "$du" \
      "rm -f /home/poc/benchmark-server.log /home/poc/benchmark-du.env; nohup env LD_LIBRARY_PATH=/opt/openssl/lib64 MACSEC_TLS_GROUP=$group $binary server 9444 $pki/du.crt $pki/du.key $pki/ca.crt /home/poc/benchmark-du.env >/home/poc/benchmark-server.log 2>&1 </dev/null &"
    sleep 0.2
    output=$(ssh "${ssh_options[@]}" "$ru" \
      "rm -f /home/poc/benchmark-ru.env; env LD_LIBRARY_PATH=/opt/openssl/lib64 MACSEC_TLS_GROUP=$group $binary client 192.168.122.101 9444 $pki/ru.crt $pki/ru.key $pki/ca.crt /home/poc/benchmark-ru.env")
    value=$(sed -n 's/.*handshake-us=\([0-9]*\) rx-bytes=\([0-9]*\) tx-bytes=\([0-9]*\).*/\1,\2,\3/p' <<<"$output")
    if [[ -z "$value" ]]; then
      echo "Falha ao interpretar benchmark: $output" >&2
      exit 1
    fi
    printf '%s,%d,%s,%s\n' "$mode" "$iteration" "$group" "$value" >>"$csv"
  done
}

# Both modes retain ML-DSA-65 mutual authentication; only the KEX group changes.
run_mode classical X25519
run_mode hybrid-pqc X25519MLKEM768

awk -F, '
  NR > 1 { n[$1]++; time[$1]+=$4; rx[$1]+=$5; tx[$1]+=$6 }
  END {
    print "# Benchmark TLS 1.3 — clássico vs. híbrido PQC"
    print ""
    print "Autenticação mútua ML-DSA-65 em ambos os modos; comparação isola o grupo de troca de chave."
    print ""
    print "| Modo | Amostras | Handshake médio (µs) | RX médio (bytes) | TX médio (bytes) |"
    print "|---|---:|---:|---:|---:|"
    for (mode in n)
      printf "| %s | %d | %.1f | %.1f | %.1f |\n", mode, n[mode], time[mode]/n[mode], rx[mode]/n[mode], tx[mode]/n[mode]
  }
' "$csv" >"$summary"

cat "$summary"
echo
echo "Dados brutos: $csv"
