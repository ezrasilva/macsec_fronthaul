#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")

"$project_dir/scripts/negotiate-vm-keys.sh"

read_remote_key() {
  local host=$1
  local name=$2
  ssh "${ssh_options[@]}" "poc@$host" \
    "sed -n 's/^${name}=//p' /home/poc/macsec-keys.env"
}

start_endpoint() {
  local host=$1
  local address=$2
  local tx_key=$3
  local rx_key=$4
  local tx_sci=$5
  local rx_sci=$6

  ssh "${ssh_options[@]}" "poc@$host" \
    "sudo systemctl stop macsec-poc.service 2>/dev/null || true
     sudo systemd-run --unit=macsec-poc --property=Type=simple \\
       /home/poc/macsec-fronthaul/build/apps/dpdk/poc_macsec_dpdk \\
       --no-huge --no-pci -l 0-1 \\
       --vdev=crypto_aesni_gcm0 \\
       --vdev=net_tap0,iface=tap_plain \\
       --vdev=net_af_packet0,iface=fh0 -- \\
       --tx-key=$tx_key --rx-key=$rx_key \\
       --tx-sci=$tx_sci --rx-sci=$rx_sci \\
       --rekey-file=/home/poc/macsec-rekey.env
     for attempt in \$(seq 1 30); do
       ip link show tap_plain >/dev/null 2>&1 && break
       sleep 0.2
     done
     sudo ip addr replace $address/24 dev tap_plain
     sudo ip link set tap_plain up"
}

du_key=$(read_remote_key 192.168.122.101 DU_TO_RU_KEY)
ru_key=$(read_remote_key 192.168.122.101 RU_TO_DU_KEY)
if [[ ! "$du_key" =~ ^[[:xdigit:]]{32}$ || ! "$ru_key" =~ ^[[:xdigit:]]{32}$ ]]; then
  echo "Erro: material de chave MACsec inválido" >&2
  exit 1
fi
ssh "${ssh_options[@]}" poc@192.168.122.101 \
  "printf 'TX_KEY=%s\nRX_KEY=%s\n' '$du_key' '$ru_key' > /home/poc/macsec-rekey.env; chmod 600 /home/poc/macsec-rekey.env"
ssh "${ssh_options[@]}" poc@192.168.122.102 \
  "printf 'TX_KEY=%s\nRX_KEY=%s\n' '$ru_key' '$du_key' > /home/poc/macsec-rekey.env; chmod 600 /home/poc/macsec-rekey.env"
du_sci=0200000000010001
ru_sci=0200000000020001

start_endpoint 192.168.122.101 10.10.0.1 "$du_key" "$ru_key" "$du_sci" "$ru_sci" &
du_pid=$!
start_endpoint 192.168.122.102 10.10.0.2 "$ru_key" "$du_key" "$ru_sci" "$du_sci" &
ru_pid=$!
wait "$du_pid"
wait "$ru_pid"

echo "Endpoints ativos: O-DU=10.10.0.1 O-RU=10.10.0.2"
