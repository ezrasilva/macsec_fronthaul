#!/usr/bin/env bash
# L3 sem root: mapa de VLAN, --no-crypto, VLAN desconhecida e limite de tamanho,
# usando net_pcap. Uso: scripts/testbed/l3-pcap-checks.sh [build-dir]  (source ~/opt/env.sh)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
build=${1:-$root/build}; app=$build/apps/dpdk/poc_macsec_dpdk
out=${OUT:-$build/l3-pcap}; mkdir -p "$out"; cd "$out"
T="python3 -I $here/pcap-tools.py"
python3 -I "$root/scripts/generate-ecpri-pcap.py" p.pcap --count 8
python3 -I "$root/scripts/generate-ecpri-pcap.py" empty.pcap --count 0
$T vlan p.pcap red161.pcap 161; $T vlan p.pcap red999.pcap 999
$T pad red161.pcap ok.pcap 1518      # limite: MTU 1500 + 14 + 4
$T pad red161.pcap big.pcap 1519     # 1 byte acima
KEYS="--enable-legacy-keying --tx-key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --rx-key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f --tx-sci=0200000000010001 --rx-sci=0200000000020001 --tx-salt=000102030405060708090a0b --rx-salt=101112131415161718191a1b --tx-ssci=1 --rx-ssci=2"

gw() { # nome rx_red [opcoes do app apos --]
  local n=$1 red=$2; shift 2
  set +e
  timeout -s INT 4 "$app" --no-huge --no-pci -m 256 --file-prefix=l3p-$n -l 0-2 \
    --vdev=crypto_aesni_gcm0 --vdev=net_pcap0,rx_pcap=$red,tx_pcap=$n-red.pcap \
    --vdev=net_pcap1,rx_pcap=${BLACK:-p.pcap},tx_pcap=$n-black.pcap -- "$@" >$n.log 2>&1
  local r=$?; set -e
  [[ $r -eq 0 || $r -eq 124 ]] || { echo "falha ($n): $r"; tail $n.log; exit $r; }
  tr '\r' '\n' <$n.log | grep '^protected=' | tail -1 > $n.stats
}
expect() { grep -q "$2" "$1.stats" || { echo "FALHOU ($1): esperava '$2'"; cat "$1.stats"; exit 1; }; echo "  ok: $1 -> $2"; }

echo "== macsec: red 161 -> black 2161 (VLAN fora do SecTAG)"
gw a red161.pcap $KEYS --vlan-map 2161:161
expect a 'protected=8 '; expect a 'vlan_drop=0 oversize=0'
$T vids a-black.pcap | grep -q '^2161/88e5 n=8$' && echo "  ok: VID 2161 + 88e5 em 8 quadros" || { $T vids a-black.pcap; exit 1; }
echo "== black 2161 -> red 161 (verifica e traduz a VID de volta; quadros curtos incluidos)"
RXKEYS="--enable-legacy-keying --tx-key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f --rx-key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --tx-sci=0200000000020001 --rx-sci=0200000000010001 --tx-salt=101112131415161718191a1b --rx-salt=000102030405060708090a0b --tx-ssci=2 --rx-ssci=1"
BLACK=a-black.pcap gw f empty.pcap $RXKEYS --vlan-map 2161:161
expect f 'unprotected=8 '; expect f 'vlan_drop=0'
$T same red161.pcap f-red.pcap
echo "== VLAN desconhecida (999) e sem tag"
gw b red999.pcap $KEYS --vlan-map 2161:161; expect b 'protected=0 '; expect b 'vlan_drop=8'
gw u p.pcap $KEYS --vlan-map 2161:161;     expect u 'vlan_drop=8'
echo "== limite de tamanho (MTU 1500 => quadro vermelho <= 1518)"
gw c ok.pcap  $KEYS --vlan-map 2161:161; expect c 'protected=8 '; expect c 'oversize=0'
gw d big.pcap $KEYS --vlan-map 2161:161; expect d 'protected=0 '; expect d 'oversize=8'
echo "== --no-crypto (E0): so troca de VLAN"
gw e red161.pcap --no-crypto --vlan-map 2161:161; expect e 'protected=8 '
$T vids e-black.pcap | grep -q '^2161/aefe n=8$' && echo "  ok: VID 2161, EtherType original em claro" || { $T vids e-black.pcap; exit 1; }
echo "L3 pcap checks: OK"
