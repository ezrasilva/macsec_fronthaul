#!/usr/bin/env bash
# E0 com o gNB REAL do OCUDU, sem root: gNB(du) <-> [gateway DPDK --no-crypto] <-> ru_emulator(ru).
# MODE=direct: gNB <-> emulador pelo mesmo veth (baseline). MODE=gateway: com o gateway no meio.
# Namespaces como processos dentro de um user namespace (ver comentarios). Precisa de: source ~/opt/env.sh
# Uso: scripts/testbed/e0-ocudu.sh [direct|gateway] [segundos]     Variaveis: BLACK(2161) RED(161) BW(20)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
MODE=${1:-gateway}; SECS=${2:-30}
OCUDU=${OCUDU:-$HOME/opt/src/ocudu-src/build}; APP=${APP:-$root/build/apps/dpdk/poc_macsec_dpdk}
BLACK=${BLACK:-2161}; RED=${RED:-161}; BW=${BW:-20}; MTU=${MTU:-1500}
W=${W:-$HOME/opt/src/ocudu-src/e0-$MODE}; rm -rf "$W"; mkdir -p "$W"
# o lado do gNB usa a VLAN black no gateway e a red direto; o emulador sempre transmite com a sua VLAN
GNB_VLAN=$BLACK; [ "$MODE" = direct ] && GNB_VLAN=$RED
cat >"$W/emu.yml" <<YML
log: {filename: stdout, level: info}
ru_emu:
  cells:
    - network_interface: v2
      ru_mac_addr: 02:00:00:00:00:0c
      du_mac_addr: 02:00:00:00:00:0a
      vlan_tag: $RED
      bandwidth: $BW
      dl_port_id: [0, 1]
      ul_port_id: [0, 1]
      prach_port_id: [4, 5]
      prach_format: short
YML
cat >"$W/gnb.yml" <<YML
cu_cp:
  amf: {addrs: 127.0.1.100, port: 38412, bind_addrs: 127.0.0.1, no_core: true,
        supported_tracking_areas: [{tac: 7, plmn_list: [{plmn: "00101", tai_slice_support_list: [{sst: 1}]}]}]}
ru_ofh:
  t1a_max_cp_dl: 420
  t1a_min_cp_dl: 250
  t1a_max_cp_ul: 420
  t1a_min_cp_ul: 250
  t1a_max_up: 196
  t1a_min_up: 80
  ta4_max: 500
  ta4_min: 25
  is_prach_cp_enabled: true
  ignore_ecpri_payload_size: true
  compr_method_ul: bfp
  compr_bitwidth_ul: 9
  compr_method_dl: bfp
  compr_bitwidth_dl: 9
  compr_method_prach: bfp
  compr_bitwidth_prach: 9
  enable_ul_static_compr_hdr: false
  enable_dl_static_compr_hdr: false
  iq_scaling: 1.0
  cells:
    - network_interface: v1
      ru_mac_addr: 02:00:00:00:00:0c
      du_mac_addr: 02:00:00:00:00:0a
      vlan_tag_cp: $GNB_VLAN
      vlan_tag_up: $GNB_VLAN
      prach_port_id: [4, 5]
      dl_port_id: [0, 1]
      ul_port_id: [0, 1]
cell_cfg:
  dl_arfcn: 640000
  band: 78
  channel_bandwidth_MHz: $BW
  common_scs: 30
  plmn: "00101"
  tac: 7
  pci: 1
  nof_antennas_dl: 2
  nof_antennas_ul: 2
  prach: {prach_config_index: 159, prach_root_sequence_index: 1, zero_correlation_zone: 0, prach_frequency_start: 15}
log: {filename: $W/gnb.log, all_level: info}
YML
# framesz do net_af_packet: (framesz-32) <= data room do mbuf e blocksz multiplo exato de framesz
fs=$(( (MTU + 200 + 255) / 256 * 256 )); bs=$(( fs * 16 ))
af() { echo "--vdev=net_af_packet$1,iface=$2,blocksz=$bs,framesz=$fs,framecnt=$(( 16 * 32 )),qdisc_bypass=1"; }
export W OCUDU APP MODE SECS BLACK RED MTU
export AFA="$(af 0 gwr)" AFB="$(af 1 gwb)"
unshare -Urmn bash -c '
  set -e; mount -t tmpfs tmpfs /run; ip link set lo up
  unshare -n sleep $((SECS + 60)) & DU=$!
  unshare -n sleep $((SECS + 60)) & RU=$!
  if [ "$MODE" = gateway ]; then unshare -n sleep $((SECS + 60)) & GW=$!; fi
  sleep 0.5
  ns() { local p=$1; shift; nsenter -t "$p" -n "$@"; }
  if [ "$MODE" = direct ]; then
    ip link add v1 type veth peer name v2; ip link set v1 netns $DU; ip link set v2 netns $RU
  else
    ip link add v1 type veth peer name gwb; ip link set v1 netns $DU; ip link set gwb netns $GW
    ip link add v2 type veth peer name gwr; ip link set v2 netns $RU; ip link set gwr netns $GW
  fi
  for p in $DU $RU ${GW:-}; do ns $p ip link set lo up; ns $p sysctl -qw net.ipv6.conf.all.disable_ipv6=1; done
  ns $DU ip link set v1 address 02:00:00:00:00:0a mtu 9000 up; ns $RU ip link set v2 address 02:00:00:00:00:0c mtu 9000 up
  if [ "$MODE" = gateway ]; then ns $GW ip link set gwb mtu 9000 up; ns $GW ip link set gwr mtu 9000 up; fi
  for spec in "$DU v1" "$RU v2" "${GW:-} gwb" "${GW:-} gwr"; do set -- $spec; [ -n "$1" ] && ns $1 ethtool -K $2 tx off rx off tso off gso off gro off lro off >/dev/null 2>&1 || true; done
  ns $RU taskset -c 9-11 $OCUDU/apps/examples/ofh/ru_emulator -c $W/emu.yml > $W/emu.out 2>&1 & EP=$!
  if [ "$MODE" = gateway ]; then
    ns $GW $APP --no-pci --no-huge -m 512 -l 0,2,4 --file-prefix=e0o $AFA $AFB -- \
      --no-crypto --vlan-map $BLACK:$RED --mtu $MTU --latency-stats > $W/gw.out 2>&1 & GP=$!
    for _ in $(seq 100); do grep -q "press Ctrl-C" $W/gw.out 2>/dev/null && break; kill -0 $GP 2>/dev/null || { echo "gateway morreu"; cat $W/gw.out; exit 1; }; sleep 0.1; done
  fi
  sleep 1
  ns $DU taskset -c 5-8 $OCUDU/apps/gnb_split_7_2/gnb -c $W/gnb.yml > $W/gnb.out 2>&1 & GN=$!
  sleep $SECS
  kill -INT $GN 2>/dev/null || true; sleep 3
  [ -n "${GP:-}" ] && { kill -INT $GP 2>/dev/null || true; sleep 1; }
  kill -INT $EP 2>/dev/null || true; sleep 1
  kill -9 $GN ${GP:-} $EP 2>/dev/null || true
' || true

python3 -I - "$W" "$MODE" <<'PY'
import re, sys
w, mode = sys.argv[1:3]
hdr = "ID RX_TOTAL RX_ON_TIME RX_EARLY RX_LATE RX_SEQ_ERR RX_ON_TIME_C RX_EARLY_C RX_LATE_C RX_SEQ_ERR_C RX_ON_TIME_C_U RX_EARLY_C_U RX_LATE_C_U RX_SEQ_ERR_C_U RX_SEQ_ERR_PRACH RX_CORRUPT RX_ERR_DROP TX_TOTAL".split()
tot = {h: 0 for h in hdr}; n = 0
for l in open(w + '/emu.out', errors='replace'):
    m = re.match(r'^(?:\x1b\[0m)?\| (\d\d:\d\d:\d\d) \|(.*)$', l)
    if m:
        n += 1
        for h, v in zip(hdr, [x.strip() for x in m.group(2).split('|')][:-1]):
            if re.fullmatch(r'\d+', v): tot[h] += int(v)
g = open(w + '/gnb.log', errors='replace').read()
def pct(a, b): return '%.1f%%' % (100.0 * a / b) if b else 'n/a'
dl_up = tot['RX_ON_TIME'] + tot['RX_EARLY'] + tot['RX_LATE']; dl_cp = tot['RX_ON_TIME_C'] + tot['RX_EARLY_C'] + tot['RX_LATE_C']; ul_cp = tot['RX_ON_TIME_C_U'] + tot['RX_EARLY_C_U'] + tot['RX_LATE_C_U']
print('=== E0 com gNB real (%s), %d linhas de KPI do emulador' % (mode, n))
print('emulador: RX_TOTAL=%d TX_TOTAL=%d  corrompidos=%d  descartados=%d  erros de seq=%d' % (tot['RX_TOTAL'], tot['TX_TOTAL'], tot['RX_CORRUPT'], tot['RX_ERR_DROP'], tot['RX_SEQ_ERR'] + tot['RX_SEQ_ERR_C'] + tot['RX_SEQ_ERR_C_U'] + 0))
print('  DL U-Plane  on-time/early/late = %d/%d/%d (%s on-time)' % (tot['RX_ON_TIME'], tot['RX_EARLY'], tot['RX_LATE'], pct(tot['RX_ON_TIME'], dl_up)))
print('  DL C-Plane  on-time/early/late = %d/%d/%d (%s on-time)' % (tot['RX_ON_TIME_C'], tot['RX_EARLY_C'], tot['RX_LATE_C'], pct(tot['RX_ON_TIME_C'], dl_cp)))
print('  UL C-Plane  on-time/early/late = %d/%d/%d (%s on-time)' % (tot['RX_ON_TIME_C_U'], tot['RX_EARLY_C_U'], tot['RX_LATE_C_U'], pct(tot['RX_ON_TIME_C_U'], ul_cp)))
print('gNB: "no uplink PRACH context"=%d  "missed PRACH"=%d  "out-of-order DL grid"=%d  "late/missed" total=%d' % (
    g.count('no uplink PRACH context'), g.count('missed incoming User-Plane PRACH'), g.count('out-of-order downlink'), g.count('missed incoming')))
if mode == 'gateway':
    t = open(w + '/gw.out', errors='replace').read().replace('\r', '\n')
    st = [l for l in t.split('\n') if l.startswith('protected=')]
    print('gateway:', st[-1] if st else 'sem estatisticas')
    for pat in (r'lcore_busy_pct.*', r'latency_us_avg.*', r'mode=.*'):
        m = re.search(pat, t)
        if m: print('gateway:', m.group(0))
PY
