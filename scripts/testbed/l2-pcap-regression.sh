#!/usr/bin/env bash
# L2/L3: regressao local do gateway DPDK com net_pcap (sem root, sem hugepages).
# Verifica protect+unprotect pelo pipeline real, com e sem tag 802.1Q.
# Uso: scripts/testbed/l2-pcap-regression.sh [build-dir]   (precisa de: source ~/opt/env.sh)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
build=${1:-$root/build}; app=$build/apps/dpdk/poc_macsec_dpdk
out=${OUT:-$root/build/l2-pcap}; mkdir -p "$out"; cd "$out"
tools="python3 -I $here/pcap-tools.py"
N=32
python3 -I "$root/scripts/generate-ecpri-pcap.py" plain.pcap --count $N
$tools vlan plain.pcap vlan.pcap 2161
python3 -I "$root/scripts/generate-ecpri-pcap.py" empty.pcap --count 0

run() { # nome rx_pcap_plain rx_pcap_secure tx_plain tx_secure txkey rxkey txsci rxsci txsalt rxsalt txssci rxssci
  set +e
  timeout -s INT 4 "$app" --no-huge --no-pci --file-prefix="l2-$1" -l 0-2 \
    --vdev=crypto_aesni_gcm0 \
    --vdev=net_pcap0,rx_pcap=$2,tx_pcap=$4 --vdev=net_pcap1,rx_pcap=$3,tx_pcap=$5 \
    -- --enable-legacy-keying --tx-key=$6 --rx-key=$7 --tx-sci=$8 --rx-sci=$9 \
    --tx-salt=${10} --rx-salt=${11} --tx-ssci=${12} --rx-ssci=${13} >"$1.log" 2>&1
  local r=$?; set -e
  [[ $r -eq 0 || $r -eq 124 ]] || { echo "falha ($1): codigo $r"; tail -20 "$1.log"; exit $r; }
}
K1=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
K2=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
for v in plain vlan; do
  echo "== $v"
  run $v-tx $v.pcap $v.pcap $v-plain-out.pcap $v-secure.pcap $K1 $K2 0200000000010001 0200000000020001 000102030405060708090a0b 101112131415161718191a1b 1 2
  $tools check-secure $v-secure.pcap $N
  run $v-rx empty.pcap $v-secure.pcap $v-recovered.pcap $v-discard.pcap $K2 $K1 0200000000020001 0200000000010001 101112131415161718191a1b 000102030405060708090a0b 2 1
  $tools same $v.pcap $v-recovered.pcap
done
echo "L2 pcap regression: OK"
