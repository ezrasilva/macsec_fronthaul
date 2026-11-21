#!/usr/bin/env bash
# L3: gateway DPDK (2 portas) em namespaces, com o MACsec do kernel como SecY A.
#
#   du (OCUDU simulado)          gw (gateway DPDK)            ru (O-RU simulada)
#   vdu.2161 [macsec0 | E1] <-> gwb  [black] ==DPDK== gwr [red] <-> vru.161
#   10.61.0.1                                                       10.61.0.2
#
# Experimentos: E0 = --no-crypto (so troca de VLAN) ; E1 = MACsec ativo.
# Uso: sudo scripts/testbed/l3-netns.sh [e0|e1|all|down]    (padrao: all)
# Variaveis: BUILD, CORES (padrao 0,2,4), MTU (padrao 8950), LIBDIR, OUT
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
BUILD=${BUILD:-$root/build}
APP=$BUILD/apps/dpdk/poc_macsec_dpdk
CORES=${CORES:-0,2,4}
MTU=${MTU:-8950}
OUT=${OUT:-$BUILD/l3}
user_home=$(getent passwd "${SUDO_USER:-$USER}" | cut -d: -f6)
# instalacao em /opt/macsec-testbed traz suas proprias libs (e o caminho de PMDs correspondente)
if [ -d "$root/lib" ] && [ -z "${LIBDIR:-}" ]; then LIBDIR=$root/lib; else LIBDIR=${LIBDIR:-$user_home/opt/local/lib}; fi
VID_BLACK=2161; VID_RED=161
MAC_DU=02:00:00:00:00:0a; MAC_RU=02:00:00:00:00:0c
SCI_A=0x02000000000a0001; SCI_B=0x02000000000b0001          # A = du (kernel), B = gateway
KEY_AB=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
KEY_BA=1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
SALT_AB=aabbccddeeff001122334455; SALT_BA=112233445566778899aabbcc
KEYID=00000000000000000000000000000000

nsx() { local n=$1; shift; ip netns exec "$n" "$@"; }

down() { pkill -x poc_macsec_dpdk 2>/dev/null || true; for n in du gw ru; do ip netns del $n 2>/dev/null || true; done; }

up() { # $1 = e0|e1
  down
  for n in du gw ru; do ip netns add $n; nsx $n sysctl -qw net.ipv6.conf.all.disable_ipv6=1; nsx $n ip link set lo up; done
  ip link add vdu type veth peer name gwb; ip link set vdu netns du; ip link set gwb netns gw
  ip link add vru type veth peer name gwr; ip link set vru netns ru; ip link set gwr netns gw
  nsx du ip link set vdu address $MAC_DU mtu 9000 up
  nsx ru ip link set vru address $MAC_RU mtu 9000 up
  nsx gw ip link set gwb mtu 9000 up; nsx gw ip link set gwr mtu 9000 up
  nsx du ip link add link vdu name vdu.$VID_BLACK type vlan id $VID_BLACK
  nsx du ip link set vdu.$VID_BLACK mtu 9000 up
  nsx ru ip link add link vru name vru.$VID_RED type vlan id $VID_RED
  nsx ru ip link set vru.$VID_RED mtu 9000 up
  nsx ru ip addr add 10.61.0.2/24 dev vru.$VID_RED
  if [ "$1" = e1 ]; then
    nsx du ip link add link vdu.$VID_BLACK macsec0 type macsec sci $SCI_A encrypt on cipher gcm-aes-xpn-256
    nsx du ip macsec add macsec0 tx sa 0 xpn 1 salt $SALT_AB ssci 1 on key $KEYID $KEY_AB
    nsx du ip macsec add macsec0 rx sci $SCI_B on
    nsx du ip macsec add macsec0 rx sci $SCI_B sa 0 xpn 1 salt $SALT_BA ssci 2 on key $KEYID $KEY_BA
    nsx du ip link set macsec0 up
    nsx du ip addr add 10.61.0.1/24 dev macsec0
  else
    nsx du ip addr add 10.61.0.1/24 dev vdu.$VID_BLACK
  fi
}

# net_af_packet: (framesz - 32) <= data room do mbuf, e blocksz DEVE ser multiplo exato de
# framesz (o PMD assume quadros contiguos; com sobra por bloco ele le o endereco errado
# a partir do 5o quadro). framesz = multiplo de 256 (~MTU+200); 16 quadros/bloco.
af() {
  local fs=$(( (MTU + 200 + 255) / 256 * 256 )); local bs=$(( fs * 16 ))
  echo "--vdev=net_af_packet$1,iface=$2,blocksz=$bs,framesz=$fs,framecnt=$(( 16 * 32 )),qdisc_bypass=1"
}

run() { # $1 = e0|e1
  local mode=$1 log=$OUT/$1-gateway.log gwpid args
  mkdir -p "$OUT"; rm -f "$log"
  up "$mode"
  args=(--vlan-map $VID_BLACK:$VID_RED --mtu "$MTU" --latency-stats)
  if [ "$mode" = e0 ]; then args+=(--no-crypto)
  else args+=(--enable-legacy-keying --tx-key=$KEY_BA --rx-key=$KEY_AB --tx-sci=${SCI_B#0x} --rx-sci=${SCI_A#0x}
              --tx-salt=$SALT_BA --rx-salt=$SALT_AB --tx-ssci=2 --rx-ssci=1); fi
  local eal=(--no-pci --in-memory -m 512 -l "$CORES" --file-prefix=l3-$mode $(af 0 gwr) $(af 1 gwb))
  [ "$mode" = e1 ] && eal+=(--vdev=crypto_aesni_gcm0)
  nsx gw env LD_LIBRARY_PATH="$LIBDIR" "$APP" "${eal[@]}" -- "${args[@]}" >"$log" 2>&1 &
  gwpid=$!
  trap 'kill -INT $gwpid 2>/dev/null || true' EXIT
  for _ in $(seq 1 100); do grep -q 'press Ctrl-C' "$log" 2>/dev/null && break; kill -0 $gwpid 2>/dev/null || { echo "gateway morreu:"; cat "$log"; exit 1; }; sleep 0.1; done
  echo "=== $mode: gateway ativo ($(grep -m1 '^mode=' "$log"))"
  echo "--- diagnostico inicial (ping de 3 pacotes, saida completa)"
  nsx ru tcpdump -nn -e -xx -U -i vru -w "$OUT/$mode-ru.pcap" >/dev/null 2>&1 & local tp1=$!
  nsx du tcpdump -nn -e -xx -U -i vdu -w "$OUT/$mode-du.pcap" >/dev/null 2>&1 & local tp2=$!
  sleep 0.5
  nsx ru ping -c 3 -W 1 -s 72 10.61.0.1 2>&1 | sed 's/^/    /' || true
  sleep 0.5; kill $tp1 $tp2 2>/dev/null || true; wait $tp1 $tp2 2>/dev/null || true
  for who in ru du; do echo "    [captura $who: $OUT/$mode-$who.pcap]"; tcpdump -nn -e -xx -r "$OUT/$mode-$who.pcap" 2>/dev/null | head -${DUMPLINES:-24} | sed 's/^/      /'; done
  nsx ru ip neigh show | sed 's/^/    ru neigh: /'
  tr '\r' '\n' <"$log" | grep '^protected=' | tail -1 | sed 's/^/    gateway: /'
  for n in "ru vru" "du vdu" "gw gwr" "gw gwb"; do set -- $n; echo "    $1/$2: $(nsx $1 ip -s link show $2 | awk '/RX:/{getline; r=$1" rx_pkts="$2" rx_drop="$4} /TX:/{getline; print r" tx_pkts="$2" tx_drop="$4}')"; done
  local fail=0 size loss
  # tamanhos = payload ICMP; pacote IP = size+28. Limite do OFH: IP ate $MTU.
  for size in 72 472 1372 3972 7972 $((MTU-28)); do
    out=$(nsx ru ping -c 20 -i 0.02 -W 1 -s $size 10.61.0.1 2>&1 | tail -2 | tr '\n' ' ' || true)
    loss=$(echo "$out" | grep -oE '[0-9]+% packet loss' | head -1 || true)
    printf '  IP %5d B  %s\n' $((size+28)) "$loss"
    [ "$loss" = "0% packet loss" ] || fail=1
  done
  size=$((MTU-27))   # 1 byte acima do limite: deve ser descartado e contado
  out=$(nsx ru ping -c 5 -i 0.05 -W 1 -s $size 10.61.0.1 2>&1 | tail -2 | tr '\n' ' ' || true)
  loss=$(echo "$out" | grep -oE '[0-9]+% packet loss' | head -1 || true)
  printf '  IP %5d B  %s  (acima do limite: esperado 100%%)\n' $((size+28)) "$loss"
  [ "$loss" = "100% packet loss" ] || fail=1
  kill -INT $gwpid; wait $gwpid || true; trap - EXIT
  echo "--- estatisticas finais do gateway ($mode)"
  { tr '\r' '\n' <"$log" | grep '^protected=' | tail -1
    grep -E '^sa an|^runtime_us|^latency_us' "$log"; } | tee "$OUT/$mode-summary.txt"
  grep -q 'ring_drop=0 .*vlan_drop=0 oversize=5' "$OUT/$mode-summary.txt" || { echo "contadores inesperados (esperado ring_drop=0 vlan_drop=0 oversize=5)"; fail=1; }
  grep -q 'tx_drop=0' "$OUT/$mode-summary.txt" && grep -q 'alloc_drop=0' "$OUT/$mode-summary.txt" || { echo "tx_drop/alloc_drop != 0"; fail=1; }
  [ "$mode" = e1 ] && { grep -q 'auth=0 replay=0' "$OUT/$mode-summary.txt" || { echo "auth/replay != 0"; fail=1; }; }
  [ $fail -eq 0 ] && echo "L3 $mode: OK" || { echo "L3 $mode: FALHOU (log: $log)"; return 1; }
}

case "${1:-all}" in
  down) down ;;
  e0) run e0 ;;
  e1) run e1 ;;
  all) run e0; run e1 ;;
esac
