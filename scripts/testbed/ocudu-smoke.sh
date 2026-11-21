#!/usr/bin/env bash
# Teste de fumaça SEM root: gNB do OCUDU (split 7.2, modo socket) <-> ru_emulator por um veth,
# dentro de um user+net namespace. Sem gateway. Verifica se o gNB roda neste notebook e o que o
# emulador conta. Uso: scripts/testbed/ocudu-smoke.sh [segundos]   (precisa de: source ~/opt/env.sh)
# Variaveis: OCUDU (padrao ~/opt/src/ocudu-src/build), VLAN (161), BW (20)
set -euo pipefail
secs=${1:-20}
OCUDU=${OCUDU:-$HOME/opt/src/ocudu-src/build}; VLAN=${VLAN:-161}; BW=${BW:-20}
W=${W:-$HOME/opt/src/ocudu-src/smoke}; mkdir -p "$W"
cat >"$W/emu.yml" <<YML
log: {filename: stdout, level: info}
ru_emu:
  cells:
    - network_interface: v2
      ru_mac_addr: 02:00:00:00:00:0c
      du_mac_addr: 02:00:00:00:00:0a
      vlan_tag: $VLAN
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
      vlan_tag_cp: $VLAN
      vlan_tag_up: $VLAN
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
unshare -Urmn bash -c "
  set -e; ip link set lo up
  ip link add v1 type veth peer name v2
  ip link set v1 address 02:00:00:00:00:0a mtu 9000 up; ip link set v2 address 02:00:00:00:00:0c mtu 9000 up
  for i in v1 v2; do ethtool -K \$i tx off rx off tso off gso off gro off >/dev/null 2>&1 || true; done
  $OCUDU/apps/examples/ofh/ru_emulator -c $W/emu.yml > $W/emu.out 2>&1 & ep=\$!
  sleep 1
  $OCUDU/apps/gnb_split_7_2/gnb -c $W/gnb.yml > $W/gnb.out 2>&1 & gp=\$!
  sleep $secs
  kill -INT \$gp 2>/dev/null || true; sleep 3; kill -INT \$ep 2>/dev/null || true; sleep 1
  kill -9 \$gp \$ep 2>/dev/null || true
" || true
echo "== gnb.out (fim)"; tail -15 "$W/gnb.out" | cut -c1-200
echo "== emulador: cabecalho e ultima linha de KPIs"; grep -a "RX_TOTAL" "$W/emu.out" | head -1 | cut -c1-260; grep -a '^.\[0m\?|\|^| ' "$W/emu.out" | tail -2 | cut -c1-260
