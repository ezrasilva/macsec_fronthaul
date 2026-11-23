#!/usr/bin/env bash
# E1 com o gNB REAL do OCUDU e a SecY DENTRO dele, sem root:
#   gNB (OCUDU_MACSEC=1, modo DPDK/af_packet, VLAN black) <-> gateway DPDK (MACsec) <-> ru_emulator (VLAN red)
# As chaves entram pelo socket de controle (INSTALL/ACTIVATE) nas duas pontas, como no gateway.
# Precisa de: source ~/opt/env.sh. Uso: scripts/testbed/e1-ocudu.sh [segundos]
set -euo pipefail
# nao empilhar execucoes: sobras de uma rodada anterior consomem 1-2 GB de RAM cada
if pgrep -x gnb >/dev/null || pgrep -x poc_macsec_dpdk >/dev/null || pgrep -x ru_emulator >/dev/null; then
  echo "ja existe gnb/poc_macsec_dpdk/ru_emulator rodando; encerre antes (pkill -x gnb; pkill -x poc_macsec_dpdk; pkill -x ru_emulator)" >&2; exit 1
fi
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
SECS=${1:-30}
OCUDU=${OCUDU:-$HOME/opt/src/ocudu-src/build}; APP=${APP:-$root/build/apps/dpdk/poc_macsec_dpdk}
KEYCTL=${KEYCTL:-$root/build/src/keying/poc_keyctl}
BLACK=${BLACK:-2161}; RED=${RED:-161}; BW=${BW:-20}; MTU=${MTU:-1500}
W=${W:-$HOME/opt/src/ocudu-src/e1}; rm -rf "$W"; mkdir -p "$W"
K1=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   # DU -> RU
K2=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f   # RU -> DU
S1=000102030405060708090a0b; S2=101112131415161718191a1b
SCI_DU=0200000000010001; SCI_GW=0200000000020001
fs=$(( (MTU + 32 + 200 + 255) / 256 * 256 )); bs=$(( fs * 16 ))
af() { echo "--vdev=net_af_packet$1,iface=$2,blocksz=$bs,framesz=$fs,framecnt=$(( 16 * 32 )),qdisc_bypass=1"; }
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
hal:
  eal_args: "--no-pci --no-huge -m 1024 -l 0 --file-prefix=gnb $(af 0 v1) --vdev=crypto_aesni_gcm0"
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
    - network_interface: net_af_packet0
      mtu: $MTU
      ru_mac_addr: 02:00:00:00:00:0c
      du_mac_addr: 02:00:00:00:00:0a
      vlan_tag_cp: $BLACK
      vlan_tag_up: $BLACK
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
export CAPTURE=${CAPTURE:-}; export W OCUDU APP KEYCTL SECS BLACK RED MTU K1 K2 S1 S2 SCI_DU SCI_GW
export AFA="$(af 0 gwr)" AFB="$(af 1 gwb)"
# PID ns (-p -f): quando o bash interno sai por QUALQUER motivo, o kernel mata tudo dentro; --kill-child cobre morte do pai.
# O bash interno e o init do PID ns e ignora SIGTERM/SIGINT; por isso o trap abaixo mata o unshare com SIGKILL
# (Ctrl-C, timeout, kill do script) e o kernel derruba o namespace inteiro. timeout -s KILL limita o tempo total.
UP=
trap '[ -n "$UP" ] && { pkill -9 -P $UP; kill -9 $UP; } 2>/dev/null || true' EXIT INT TERM
timeout -s KILL $((SECS + 120)) unshare -Urmnpf --kill-child --mount-proc bash -c '
  set -e; mount -t tmpfs tmpfs /run; ip link set lo up
  unshare -n sleep $((SECS + 90)) & DU=$!; unshare -n sleep $((SECS + 90)) & RU=$!; unshare -n sleep $((SECS + 90)) & GW=$!
  sleep 0.5
  ns() { local p=$1; shift; nsenter -t "$p" -n "$@"; }
  ip link add v1 type veth peer name gwb; ip link set v1 netns $DU; ip link set gwb netns $GW
  ip link add v2 type veth peer name gwr; ip link set v2 netns $RU; ip link set gwr netns $GW
  for p in $DU $RU $GW; do ns $p ip link set lo up; ns $p sysctl -qw net.ipv6.conf.all.disable_ipv6=1; done
  ns $DU ip link set v1 address 02:00:00:00:00:0a mtu 9000 up; ns $RU ip link set v2 address 02:00:00:00:00:0c mtu 9000 up
  ns $GW ip link set gwb mtu 9000 up; ns $GW ip link set gwr mtu 9000 up
  for spec in "$DU v1" "$RU v2" "$GW gwb" "$GW gwr"; do set -- $spec; ns $1 ethtool -K $2 tx off rx off tso off gso off gro off lro off >/dev/null 2>&1 || true; done
  [ -n "${CAPTURE:-}" ] && { ns $GW tcpdump -nn -s 0 -U -i gwb -w $W/gwb.pcap >/dev/null 2>&1 & TP=$!; sleep 0.3; }
  ns $RU taskset -c 9-11 $OCUDU/apps/examples/ofh/ru_emulator -c $W/emu.yml > $W/emu.out 2>&1 & EP=$!
  # gateway: MACsec, chaves pelo socket de controle (nenhuma chave no argv)
  ns $GW $APP --no-pci --no-huge -m 512 -l 0,2,4 --file-prefix=e1g $AFA $AFB --vdev=crypto_aesni_gcm0 -- \
    --vlan-map $BLACK:$RED --mtu $MTU --latency-stats --control-socket $W/gw.sock --control-uid 0 \
    --tx-sci=$SCI_GW --rx-sci=$SCI_DU --tx-ssci=2 --rx-ssci=1 > $W/gw.out 2>&1 & GP=$!
  for _ in $(seq 100); do [ -S $W/gw.sock ] && grep -q "press Ctrl-C" $W/gw.out 2>/dev/null && break; kill -0 $GP 2>/dev/null || { echo "gateway morreu"; cat $W/gw.out; exit 1; }; sleep 0.1; done
  # gNB com a SecY: configuracao por ambiente
  OCUDU_MACSEC=1 OCUDU_MACSEC_CONTROL_SOCKET=$W/gnb.sock OCUDU_MACSEC_TX_SCI=$SCI_DU OCUDU_MACSEC_RX_SCI=$SCI_GW \
    OCUDU_MACSEC_TX_SSCI=1 OCUDU_MACSEC_RX_SSCI=2 \
    ns $DU taskset -c 5-8 $OCUDU/apps/gnb_split_7_2/gnb -c $W/gnb.yml > $W/gnb.out 2>&1 & GN=$!
  for _ in $(seq 150); do [ -S $W/gnb.sock ] && break; kill -0 $GN 2>/dev/null || { echo "gnb morreu"; tail -20 $W/gnb.out; exit 1; }; sleep 0.2; done
  [ -S $W/gnb.sock ] || { echo "socket do gNB nao apareceu"; tail -20 $W/gnb.out; exit 1; }
  echo "--- chaves pelo socket de controle (DU: tx=K1 rx=K2 ; gateway: tx=K2 rx=K1)"
  printf "INSTALL AN=0 TX_KEY=$K1 RX_KEY=$K2 TX_SALT=$S1 RX_SALT=$S2\n" | $KEYCTL $W/gnb.sock | tr -d "\n"; echo " <- gnb install"
  printf "INSTALL AN=0 TX_KEY=$K2 RX_KEY=$K1 TX_SALT=$S2 RX_SALT=$S1\n" | $KEYCTL $W/gw.sock | tr -d "\n"; echo " <- gw install"
  printf "ACTIVATE AN=0\n" | $KEYCTL $W/gw.sock | tr -d "\n"; echo " <- gw activate"
  printf "ACTIVATE AN=0\n" | $KEYCTL $W/gnb.sock | tr -d "\n"; echo " <- gnb activate"
  printf "STATUS\n" | $KEYCTL $W/gnb.sock | tr -d "\n"; echo " <- gnb status"
  sleep $SECS
  printf "STATUS\n" | $KEYCTL $W/gnb.sock | tr -d "\n"; echo " <- gnb status (fim)"
  kill -INT $GN 2>/dev/null || true; sleep 4
  kill -INT $GP 2>/dev/null || true; sleep 1
  kill -INT $EP 2>/dev/null || true; sleep 1
  kill -INT ${TP:-} 2>/dev/null || true; sleep 0.5
  kill -9 $GN $GP $EP ${TP:-} 2>/dev/null || true
' & UP=$!
wait $UP || echo "AVISO: o namespace terminou com erro/timeout (processos internos ja foram encerrados)" >&2

python3 -I - "$W" <<'PY'
import re, sys
w = sys.argv[1]
hdr = "ID RX_TOTAL RX_ON_TIME RX_EARLY RX_LATE RX_SEQ_ERR RX_ON_TIME_C RX_EARLY_C RX_LATE_C RX_SEQ_ERR_C RX_ON_TIME_C_U RX_EARLY_C_U RX_LATE_C_U RX_SEQ_ERR_C_U RX_SEQ_ERR_PRACH RX_CORRUPT RX_ERR_DROP TX_TOTAL".split()
tot = {h: 0 for h in hdr}; n = 0
for l in open(w + '/emu.out', errors='replace'):
    m = re.match(r'^(?:\x1b\[0m)?\| (\d\d:\d\d:\d\d) \|(.*)$', l)
    if m:
        n += 1
        for h, v in zip(hdr, [x.strip() for x in m.group(2).split('|')][:-1]):
            if re.fullmatch(r'\d+', v): tot[h] += int(v)
print('=== E1 com SecY dentro do gNB: emulador (%d linhas de KPI)' % n)
print('RX_TOTAL=%d TX_TOTAL=%d corrompidos=%d descartados=%d erros de seq=%d' % (tot['RX_TOTAL'], tot['TX_TOTAL'], tot['RX_CORRUPT'], tot['RX_ERR_DROP'], tot['RX_SEQ_ERR'] + tot['RX_SEQ_ERR_C'] + tot['RX_SEQ_ERR_C_U']))
g = open(w + '/gnb.out', errors='replace').read()
for l in g.split('\n'):
    if l.startswith('MACsec'): print('gnb:', l)
t = open(w + '/gw.out', errors='replace').read().replace('\r', '\n')
st = [l for l in t.split('\n') if l.startswith('protected=')]
print('gateway:', st[-1] if st else 'sem estatisticas')
for pat in (r'sa an=.*', r'lcore_busy_pct.*'):
    for m in re.finditer(pat, t): print('gateway:', m.group(0))
PY
