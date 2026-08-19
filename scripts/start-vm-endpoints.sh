#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")

start_endpoint() {
  local host=$1
  local address=$2
  local tx_sci=$3
  local rx_sci=$4
  local tx_ssci=$5
  local rx_ssci=$6

  ssh "${ssh_options[@]}" "poc@$host" \
    "sudo systemctl stop macsec-poc.service 2>/dev/null || true
     sudo install -d -o poc -g poc -m 0700 /run/macsec-pqc
     sudo systemd-run --unit=macsec-poc --property=Type=simple \\
       /home/poc/macsec-fronthaul/build/apps/dpdk/poc_macsec_dpdk \\
       --no-huge --no-pci -l 0-2 \\
       --vdev=crypto_aesni_gcm0 \\
       --vdev=net_tap0,iface=tap_plain \\
       --vdev=net_af_packet0,iface=fh0 -- \\
       --tx-sci=$tx_sci --rx-sci=$rx_sci \\
       --tx-ssci=$tx_ssci --rx-ssci=$rx_ssci \\
       --control-socket=/run/macsec-pqc/control.sock --control-uid=\$(id -u poc)
     for attempt in \$(seq 1 30); do
       ip link show tap_plain >/dev/null 2>&1 && \\
         test -S /run/macsec-pqc/control.sock && break
       sleep 0.2
     done
     sudo ip addr replace $address/24 dev tap_plain
     sudo ip link set tap_plain up
     test -S /run/macsec-pqc/control.sock"
}

du_sci=0200000000010001
ru_sci=0200000000020001

start_endpoint 192.168.122.101 10.10.0.1 "$du_sci" "$ru_sci" 1 2 &
du_pid=$!
start_endpoint 192.168.122.102 10.10.0.2 "$ru_sci" "$du_sci" 2 1 &
ru_pid=$!
wait "$du_pid"
wait "$ru_pid"

"$project_dir/scripts/negotiate-vm-keys.sh"

echo "Endpoints ativos: O-DU=10.10.0.1 O-RU=10.10.0.2"
