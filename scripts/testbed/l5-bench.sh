#!/usr/bin/env bash
# L5: medicao local RELATIVA (E-1 sem gateway, E0 so VLAN, E1 MACsec) com iperf3 UDP em namespaces.
# Vale como custo relativo neste notebook, NUNCA como desempenho do fronthaul nem contra as janelas do OFH.
# Uso: sudo scripts/testbed/l5-bench.sh [run|down]
# Variaveis: CORES (gateway, padrao 0,2,4), SRV_CPU (6), CLI_CPU (8), DUR (5 s), MTU (8950), RTT_COUNT (500)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$here/l3-netns.sh"
OUT=$BUILD/l5
SRV_CPU=${SRV_CPU:-6}; CLI_CPU=${CLI_CPU:-8}; DUR=${DUR:-5}; RTT_COUNT=${RTT_COUNT:-500}
IPERF=${IPERF:-$BUILD/bin/iperf3}; [ -x "$IPERF" ] || IPERF=$user_home/opt/local/bin/iperf3
SIZES=${SIZES:-"128 1500 8950"}          # tamanho do pacote IP (iperf3 -l = IP - 28)
RATES=${RATES:-"50M 500M max"}
CSV=$OUT/results.csv

up_direct() { # E-1: RU e DU ligados direto, VLAN 161, sem gateway
  down
  for n in du ru; do ip netns add $n; nsx $n sysctl -qw net.ipv6.conf.all.disable_ipv6=1; nsx $n ip link set lo up; done
  ip link add vdu type veth peer name vru; ip link set vdu netns du; ip link set vru netns ru
  nsx du ip link set vdu address $MAC_DU mtu 9000 up; nsx ru ip link set vru address $MAC_RU mtu 9000 up
  nsx du ip link add link vdu name vdu.$VID_RED type vlan id $VID_RED; nsx du ip link set vdu.$VID_RED mtu 9000 up
  nsx ru ip link add link vru name vru.$VID_RED type vlan id $VID_RED; nsx ru ip link set vru.$VID_RED mtu 9000 up
  nsx du ip addr add 10.61.0.1/24 dev vdu.$VID_RED; nsx ru ip addr add 10.61.0.2/24 dev vru.$VID_RED
}

# Sem offload: o gateway captura/reinjeta quadros crus (AF_PACKET), entao checksums parciais do veth
# (CHECKSUM_PARTIAL) chegariam invalidos ao receptor e o TCP/UDP seria descartado. Igual nos 3 modos.
no_offload() {
  local pair ns i
  for pair in "du vdu vdu.$VID_BLACK vdu.$VID_RED macsec0" "ru vru vru.$VID_RED" "gw gwb gwr"; do
    set -- $pair; ns=$1; shift
    for i in "$@"; do nsx $ns ethtool -K "$i" tx off rx off tso off gso off gro off lro off >/dev/null 2>&1 || true; done
  done
}

gwpid=
gw_start() { # $1 = e0|e1 ; $2 = tag
  local mode=$1 log=$OUT/gw-$2.log args
  args=(--vlan-map $VID_BLACK:$VID_RED --mtu "$MTU" --latency-stats)
  if [ "$mode" = e0 ]; then args+=(--no-crypto)
  else args+=(--enable-legacy-keying --tx-key=$KEY_BA --rx-key=$KEY_AB --tx-sci=${SCI_B#0x} --rx-sci=${SCI_A#0x}
              --tx-salt=$SALT_BA --rx-salt=$SALT_AB --tx-ssci=2 --rx-ssci=1); fi
  local eal=(--no-pci --in-memory -m 512 -l "$CORES" --file-prefix=l5 $(af 0 gwr) $(af 1 gwb))
  [ "$mode" = e1 ] && eal+=(--vdev=crypto_aesni_gcm0)
  nsx gw env LD_LIBRARY_PATH="$LIBDIR" "$APP" "${eal[@]}" -- "${args[@]}" >"$log" 2>&1 & gwpid=$!
  for _ in $(seq 100); do grep -q 'press Ctrl-C' "$log" 2>/dev/null && return 0
    kill -0 $gwpid 2>/dev/null || { echo "gateway morreu:"; cat "$log"; return 1; }; sleep 0.1; done
  return 1
}
gw_stop() { [ -n "$gwpid" ] && { kill -INT $gwpid 2>/dev/null || true; wait $gwpid 2>/dev/null || true; gwpid=; }; }

# "50M"|"500M"|"max" -> argumento -b do iperf3
rate_arg() { [ "$1" = max ] && echo 0 || echo "$1"; }

bench_one() { # $1 modo(base|e0|e1)  $2 dir(UL|DL)  $3 tamanho IP  $4 taxa
  local mode=$1 dir=$2 size=$3 rate=$4 tag="$1-$2-$3-$4" l=$(( $3 - 28 )) rflag=""
  [ "$dir" = DL ] && rflag="-R"
  if [ "$mode" = base ]; then up_direct; else up "$mode"; gw_start "$mode" "$tag" || return 1; fi
  no_offload
  nsx ru ping -c 3 -i 0.2 -W 1 10.61.0.1 >/dev/null 2>&1 || true            # ARP / aquecimento
  nsx du timeout $((DUR + 20)) taskset -c "$SRV_CPU" "$IPERF" -s -1 >/dev/null 2>&1 & local sp=$!
  sleep 0.4
  nsx ru timeout $((DUR + 20)) taskset -c "$CLI_CPU" "$IPERF" -c 10.61.0.1 --connect-timeout 3000 -u -b "$(rate_arg "$rate")" -l $l -t "$DUR" $rflag -J >"$OUT/iperf-$tag.json" 2>"$OUT/iperf-$tag.err" || true
  grep -q '"error"' "$OUT/iperf-$tag.json" 2>/dev/null && echo "  AVISO ($tag): iperf3 falhou: $(grep -m1 '"error"' "$OUT/iperf-$tag.json" | cut -c1-120)"
  pkill -x iperf3 2>/dev/null || true; wait $sp 2>/dev/null || true
  [ "$mode" != base ] && gw_stop
  python3 -I - "$mode" "$dir" "$size" "$rate" "$OUT/iperf-$tag.json" "$OUT/gw-$tag.log" >>"$CSV" <<'PY'
import json, re, sys
mode, dire, size, rate, jf, gf = sys.argv[1:7]
try:
    e = json.load(open(jf))['end']
    s = e.get('sum_received') or e.get('sum') or {}
    mbps = s.get('bits_per_second', 0) / 1e6; loss = s.get('lost_percent', float('nan')); jit = s.get('jitter_ms', float('nan'))
    sent = (e.get('sum_sent') or e.get('sum') or {}).get('bits_per_second', 0) / 1e6
except Exception as ex:
    mbps = loss = jit = sent = float('nan')
g = dict(p50='', p95='', p99='', mx='', gj='', rx='', cr='', tx='', drops='')
try:
    t = open(gf, errors='replace').read().replace('\r', '\n')
    st = [l for l in t.split('\n') if l.startswith('protected=')][-1]
    d = dict(re.findall(r'(\w+)=(\d+)', st))
    g['drops'] = sum(int(d[k]) for k in ('alloc_drop', 'tx_drop', 'ring_drop', 'vlan_drop', 'oversize'))
    m = re.search(r'p50=(\d+) p95=(\d+) p99=(\d+) max=(\d+) jitter_avg=([\d.]+)', t)
    if m: g['p50'], g['p95'], g['p99'], g['mx'], g['gj'] = m.groups()
    m = re.search(r'lcore_busy_pct rx=([\d.]+) crypto=([\d.]+) tx=([\d.]+)', t)
    if m: g['rx'], g['cr'], g['tx'] = m.groups()
except Exception:
    pass
print(','.join(str(x) for x in (mode, dire, size, rate, '%.1f' % sent, '%.1f' % mbps, '%.2f' % loss, '%.3f' % jit,
      g['p50'], g['p95'], g['p99'], g['mx'], g['gj'], g['rx'], g['cr'], g['tx'], g['drops'])))
PY
  tail -1 "$CSV" | awk -F, '{printf "  %-4s %s %5sB %-4s  enviado=%7s Mb/s  recebido=%7s Mb/s  perda=%5s%%  gw p50/p99=%s/%s us  busy rx/cr/tx=%s/%s/%s%%\n",$1,$2,$3,$4,$5,$6,$7,$9,$11,$14,$15,$16}'
}

rtt_one() { # $1 modo ; $2 tamanho IP
  local mode=$1 size=$2 l=$(( $2 - 28 ))
  if [ "$mode" = base ]; then up_direct; else up "$mode"; gw_start "$mode" "rtt-$mode-$size" || return 1; fi
  no_offload
  nsx ru ping -c 3 -i 0.2 -W 1 10.61.0.1 >/dev/null 2>&1 || true
  nsx ru taskset -c "$CLI_CPU" ping -c "$RTT_COUNT" -i 0.01 -W 1 -s $l 10.61.0.1 >"$OUT/rtt-$mode-$size.txt" 2>&1 || true
  [ "$mode" != base ] && gw_stop
  python3 -I - "$mode" "$size" "$OUT/rtt-$mode-$size.txt" >>"$OUT/rtt.csv" <<'PY'
import re, sys, statistics as st
mode, size, f = sys.argv[1:4]
v = sorted(float(x) for x in re.findall(r'(?:time|tempo)[=<]([\d.]+) ?ms', open(f, errors='replace').read()))
n = len(v)
def p(q): return v[min(n - 1, int(q * n))] * 1000 if n else float('nan')
print('%s,%s,%d,%.0f,%.0f,%.0f,%.0f,%.0f' % (mode, size, n, p(.5), p(.95), p(.99), v[-1] * 1000 if n else float('nan'), st.mean(v) * 1000 if n else float('nan')))
PY
}

summary() {
  python3 -I - "$CSV" "$OUT/rtt.csv" <<'PY'
import csv, sys
rows = list(csv.reader(open(sys.argv[1])))[1:]
def pick(mode, d, size, rate):
    for r in rows:
        if r[0] == mode and r[1] == d and r[2] == size and r[3] == rate: return r
print('\n### Vazao maxima recebida (Mb/s) e perda — UDP, iperf3 -b 0 (UL = RU->DU, passa por PROTECT; DL = DU->RU, passa por VERIFY)')
print('| sentido | pacote IP | E-1 (sem gw) | E0 (so VLAN) | E1 (MACsec) | E1/E0 | perda E-1 / E0 / E1 (%) |')
print('|---|---|---|---|---|---|---|')
for d in ('UL', 'DL'):
    for sz in sorted({r[2] for r in rows}, key=int):
        b, e0, e1 = (pick(m, d, sz, 'max') for m in ('base', 'e0', 'e1'))
        if not (b and e0 and e1): continue
        f = lambda r: float(r[5])
        print('| %s | %s B | %.0f | %.0f | %.0f | %.2f | %s / %s / %s |' % (d, sz, f(b), f(e0), f(e1), f(e1) / f(e0) if f(e0) else float('nan'), b[6], e0[6], e1[6]))
print('\n### Latencia de software no gateway (RX->TX, us) e tempo ocupado dos lcores (%) — carga leve (-b 50M) e maxima')
print('| modo | sentido | pacote | taxa | p50 | p95 | p99 | max | jitter | rx% | crypto% | tx% | drops |')
print('|---|---|---|---|---|---|---|---|---|---|---|---|---|')
for r in rows:
    if r[0] in ('e0', 'e1') and r[3] in ('50M', 'max'):
        print('| %s | %s | %s B | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (r[0], r[1], r[2], r[3], *r[8:17]))
print('\n### RTT ocioso RU<->DU via ping (us), %s pings a 10 ms' % '500')
print('| modo | pacote IP | n | p50 | p95 | p99 | max | media |')
print('|---|---|---|---|---|---|---|---|')
for r in csv.reader(open(sys.argv[2])):
    print('| %s | %s B | %s | %s | %s | %s | %s | %s |' % tuple(r))
PY
}

run() {
  mkdir -p "$OUT"; rm -f "$OUT"/*.json "$OUT"/*.err "$OUT"/gw-*.log "$OUT"/rtt-*.txt "$CSV" "$OUT/rtt.csv"
  echo "mode,dir,size,rate,sent_mbps,recv_mbps,loss_pct,iperf_jitter_ms,gw_p50,gw_p95,gw_p99,gw_max,gw_jitter,busy_rx,busy_crypto,busy_tx,drops" >"$CSV"
  {
    echo "# L5 — medicao local relativa"
    echo "- CPU: $(lscpu | sed -n 's/^Nome do modelo: *//p;s/^Model name: *//p' | head -1); kernel $(uname -r); DPDK libs $(basename "$(readlink -f "$LIBDIR/librte_eal.so")") em $LIBDIR"
    echo "- gateway lcores: $CORES; iperf3 servidor cpu $SRV_CPU, cliente cpu $CLI_CPU; governor cpu0=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null) no_turbo=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null)"
    echo "- iperf3 $($IPERF --version | head -1); duracao $DUR s por execucao; MTU $MTU; $(date -Is)"
  } | tee "$OUT/header.md"
  echo "--- iperf3 UDP"
  for mode in base e0 e1; do for dir in UL DL; do for size in $SIZES; do for rate in $RATES; do
    bench_one $mode $dir $size $rate || echo "  FALHOU: $mode $dir $size $rate"
  done; done; done; done
  echo "--- RTT ocioso"
  for mode in base e0 e1; do for size in $SIZES; do rtt_one $mode $size; done; done
  down
  { cat "$OUT/header.md"; summary; } >"$OUT/report.md"
  cat "$OUT/report.md"
  echo "L5: concluida (resultados em $OUT)"
}

trap 'gw_stop' EXIT
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-run}" in
    down) pkill -f 'l5-bench.sh run' 2>/dev/null || true; down ;;
    run) run ;;
  esac
fi
