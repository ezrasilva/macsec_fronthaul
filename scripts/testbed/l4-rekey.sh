#!/usr/bin/env bash
# L4: chaves PQC + rekey sob ping continuo, em namespaces.
#
#   du: macsec do kernel (SecY A)  <-- kernel-control.py (mesmo protocolo do gateway)
#   gw: gateway DPDK com --control-socket
#   agente TLS 1.3 X25519MLKEM768 + ML-DSA-65: servidor na du (papel du), cliente no gw (papel ru),
#   falando por um link de GERENCIA (172.16.0.0/24) separado do caminho cifrado.
#
# Uso: sudo scripts/testbed/l4-rekey.sh [run|down]     Variaveis: CORES, MTU, REKEYS (3), GRACE (2)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$here/l3-netns.sh"
OUT=$BUILD/l4
KEYING=$BUILD/src/keying/poc_tls_keying; CTL=$BUILD/src/keying/poc_keyctl
REKEYS=${REKEYS:-3}; GRACE=${GRACE:-2}
PORT=9443

up_l4() {
  down
  for n in du gw ru; do ip netns add $n; nsx $n sysctl -qw net.ipv6.conf.all.disable_ipv6=1; nsx $n ip link set lo up; done
  ip link add vdu type veth peer name gwb; ip link set vdu netns du; ip link set gwb netns gw
  ip link add vru type veth peer name gwr; ip link set vru netns ru; ip link set gwr netns gw
  ip link add vmd type veth peer name vmg; ip link set vmd netns du; ip link set vmg netns gw     # gerencia
  nsx du ip link set vdu address $MAC_DU mtu 9000 up; nsx ru ip link set vru address $MAC_RU mtu 9000 up
  nsx gw ip link set gwb mtu 9000 up; nsx gw ip link set gwr mtu 9000 up
  nsx du ip addr add 172.16.0.1/24 dev vmd; nsx du ip link set vmd up
  nsx gw ip addr add 172.16.0.2/24 dev vmg; nsx gw ip link set vmg up
  nsx du ip link add link vdu name vdu.$VID_BLACK type vlan id $VID_BLACK; nsx du ip link set vdu.$VID_BLACK mtu 9000 up
  nsx ru ip link add link vru name vru.$VID_RED type vlan id $VID_RED; nsx ru ip link set vru.$VID_RED mtu 9000 up
  nsx ru ip addr add 10.61.0.2/24 dev vru.$VID_RED
  # macsec do kernel SEM nenhuma SA: so existe o SC de recepcao do par. As SAs chegam pelo agente.
  nsx du ip link add link vdu.$VID_BLACK macsec0 type macsec sci $SCI_A encrypt on cipher gcm-aes-xpn-256
  nsx du ip macsec add macsec0 rx sci $SCI_B on
  nsx du ip link set macsec0 up; nsx du ip addr add 10.61.0.1/24 dev macsec0
}

negotiate() { # $1 = AN
  local an=$1 sp
  nsx du env MACSEC_ENDPOINT_ROLE=du MACSEC_CONTROL_AN=$an MACSEC_TLS_PEER_KEY=ML-DSA-65 \
    timeout 30 "$KEYING" server $PORT "$OUT/pki/du.crt" "$OUT/pki/du.key" "$OUT/pki/ca.crt" unix:"$OUT/du.sock" >"$OUT/agent-du-$an.log" 2>&1 & sp=$!
  sleep 0.3
  nsx gw env MACSEC_ENDPOINT_ROLE=ru MACSEC_CONTROL_AN=$an MACSEC_TLS_SERVER_NAME=macsec-du MACSEC_TLS_PEER_KEY=ML-DSA-65 \
    timeout 30 "$KEYING" client 172.16.0.1 $PORT "$OUT/pki/ru.crt" "$OUT/pki/ru.key" "$OUT/pki/ca.crt" unix:"$OUT/gw.sock" >"$OUT/agent-gw-$an.log" 2>&1
  wait $sp
}

status() { printf 'STATUS\n' | nsx "$1" "$CTL" "$OUT/$2.sock"; }
active_of() { sed -n 's/.*ACTIVE=\([0-3]\).*/\1/p' <<<"$1"; }

run() {
  local fail=0 gwpid kcpid tpid
  mkdir -p "$OUT"; rm -f "$OUT"/*.log "$OUT"/*.pcap "$OUT"/*.sock "$OUT"/*.txt
  "$here/make-pki.sh" "$OUT/pki"
  up_l4
  trap 'kill -INT ${gwpid:-} ${kcpid:-} ${tpid:-} 2>/dev/null || true' EXIT
  nsx du tcpdump -nn -s 128 -U -i vdu -w "$OUT/black.pcap" >/dev/null 2>&1 & tpid=$!
  # adaptador do kernel (du) e gateway (gw), ambos sem chaves
  nsx du python3 -I "$here/kernel-control.py" --socket "$OUT/du.sock" --peer-sci $SCI_B --tx-ssci 1 --rx-ssci 2 >"$OUT/kernel-control.log" 2>&1 & kcpid=$!
  local eal=(--no-pci --in-memory -m 512 -l "$CORES" --file-prefix=l4 $(af 0 gwr) $(af 1 gwb) --vdev=crypto_aesni_gcm0)
  nsx gw env LD_LIBRARY_PATH="$LIBDIR" "$APP" "${eal[@]}" -- --vlan-map $VID_BLACK:$VID_RED --mtu "$MTU" --latency-stats \
    --control-socket "$OUT/gw.sock" --control-uid 0 --tx-sci=${SCI_B#0x} --rx-sci=${SCI_A#0x} --tx-ssci=2 --rx-ssci=1 >"$OUT/gateway.log" 2>&1 & gwpid=$!
  for _ in $(seq 100); do grep -q 'press Ctrl-C' "$OUT/gateway.log" 2>/dev/null && [ -S "$OUT/du.sock" ] && break
    kill -0 $gwpid 2>/dev/null || { echo "gateway morreu:"; cat "$OUT/gateway.log"; exit 1; }; sleep 0.1; done
  echo "=== L4: gateway e adaptador do kernel ativos, sem chaves"

  echo "--- 1) sem chave, nada passa"
  local out; out=$(nsx ru ping -c 3 -W 1 10.61.0.1 2>&1 | tail -2 | tr '\n' ' ' || true)
  echo "    ping da RU: $(grep -oE '[0-9]+% packet loss' <<<"$out")"; grep -q '100% packet loss' <<<"$out" || fail=1
  echo "    $(status gw gw)"; echo "    $(status du du)"

  echo "--- 2) handshake PQC inicial (AN=0)"
  negotiate 0 || { echo "negociacao falhou"; cat "$OUT"/agent-*-0.log; fail=1; }
  head -1 "$OUT/agent-gw-0.log" | sed 's/^/    /'
  echo "    $(status gw gw)"; echo "    $(status du du)"
  out=$(nsx ru ping -c 5 -i 0.05 -W 1 10.61.0.1 2>&1 | tail -2 | tr '\n' ' ' || true)
  echo "    ping da RU apos negociar: $(grep -oE '[0-9]+% packet loss' <<<"$out")"; grep -q ' 0% packet loss' <<<"$out" || fail=1

  echo "--- 3) $REKEYS rekeys sob ping continuo (100 B a 20 ms e IP $MTU B a 50 ms)"
  local npings=$(( 2 + REKEYS * (GRACE + 2) + 4 ))
  nsx ru ping -c $(( npings * 50 )) -i 0.02 -W 1 -s 72 10.61.0.1 >"$OUT/ping-small.txt" 2>&1 & local p1=$!
  nsx ru ping -c $(( npings * 20 )) -i 0.05 -W 1 -s $((MTU-28)) 10.61.0.1 >"$OUT/ping-big.txt" 2>&1 & local p2=$!
  sleep 2
  local i active next ds gs
  for i in $(seq $REKEYS); do
    gs=$(status gw gw); ds=$(status du du)
    active=$(active_of "$gs")
    if [ "$(active_of "$ds")" != "$active" ] || [[ "$gs$ds" != *READY=1*READY=1* ]]; then echo "estado inconsistente: gw='$gs' du='$ds'"; fail=1; break; fi
    next=$(( (active + 1) % 4 ))
    negotiate $next || { echo "negociacao AN=$next falhou"; fail=1; break; }
    sleep "$GRACE"
    printf 'RETIRE AN=%s\n' "$active" | nsx gw "$CTL" "$OUT/gw.sock" | tr -d '\n'; printf ' <- gw  '
    printf 'RETIRE AN=%s\n' "$active" | nsx du "$CTL" "$OUT/du.sock" | tr -d '\n'; printf ' <- du\n'
    echo "    rekey $i: AN $active -> $next  ($(grep -oE 'handshake-us=[0-9]+' "$OUT/agent-gw-$next.log"))  gw: $(status gw gw)  du: $(status du du)"
    sleep 1
  done
  wait $p1 $p2 || true
  for f in small big; do
    echo "    ping-$f: $(grep -E 'packets transmitted|pacotes transmitidos' "$OUT/ping-$f.txt" | sed 's/, time.*//')"
    grep -qE ' 0% packet loss' "$OUT/ping-$f.txt" || fail=1
  done

  echo "--- 4) verificacoes finais"
  kill -INT $gwpid; wait $gwpid || true; kill -INT $tpid 2>/dev/null || true; sleep 0.3
  { tr '\r' '\n' <"$OUT/gateway.log" | grep '^protected=' | tail -1; grep -E '^sa an|^runtime_us|^latency_us' "$OUT/gateway.log"; } | tee "$OUT/gateway-summary.txt" | sed 's/^/    /'
  local g="$OUT/gateway-summary.txt" expect_rekeys=$(( REKEYS + 1 ))
  grep -q "auth=0 replay=0 format=0" "$g" && grep -q "ring_drop=0 rekeys=$expect_rekeys " "$g" || { echo "    contadores inesperados (esperado auth/replay/format=0 e rekeys=$expect_rekeys)"; fail=1; }
  grep -q "tx_drop=0 ring_drop=0" "$g" && grep -q "alloc_drop=0" "$g" || { echo "    drops != 0"; fail=1; }
  for an in $(seq 0 $(( REKEYS < 3 ? REKEYS : 3 ))); do grep -qE "^sa an=$an protected=[1-9][0-9]* unprotected=[1-9][0-9]* errors=0" "$g" || { echo "    AN $an sem trafego nos dois sentidos"; fail=1; }; done
  echo "    kernel (DU), ip -s macsec show macsec0:"
  # linha de valores do bloco do RXSC: OctetsValidated OctetsDecrypted Unchecked Delayed OK Invalid Late NotValid NotUsingSA UnusedSA
  local rx; rx=$(nsx du ip -s macsec show macsec0 | grep -A1 'InOctetsValidated' | sed -n 2p)
  echo "      InPktsOK=$(awk '{print $5}' <<<"$rx") InPktsInvalid=$(awk '{print $6}' <<<"$rx") InPktsNotValid=$(awk '{print $8}' <<<"$rx") InPktsNotUsingSA=$(awk '{print $9}' <<<"$rx")"
  [ "$(awk '{print $6+$8}' <<<"$rx")" = 0 ] || { echo "    kernel rejeitou quadros (Invalid/NotValid != 0)"; fail=1; }
  local clear; clear=$(tcpdump -nn -r "$OUT/black.pcap" 'not (vlan 2161 and ether proto 0x88e5)' 2>/dev/null | wc -l)
  local total; total=$(tcpdump -nn -r "$OUT/black.pcap" 2>/dev/null | wc -l)
  echo "    lado black: $total quadros capturados, $clear fora de MACsec (esperado 0)"; [ "$clear" = 0 ] || fail=1
  [ $fail -eq 0 ] && echo "L4: OK" || { echo "L4: FALHOU (logs em $OUT)"; return 1; }
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-run}" in down) down ;; run) run ;; esac
fi
