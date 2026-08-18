#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")

echo "Ping O-DU -> O-RU"
ssh "${ssh_options[@]}" poc@192.168.122.101 'ping -c 5 -W 2 10.10.0.2'

echo
echo "Amostra MACsec no fronthaul da O-DU"
capture_pid=''
ssh "${ssh_options[@]}" poc@192.168.122.101 \
  'sudo timeout 8 tcpdump -l -eni fh0 -c 2 ether proto 0x88e5' &
capture_pid=$!
sleep 1
ssh "${ssh_options[@]}" poc@192.168.122.101 'ping -c 2 -W 2 10.10.0.2' >/dev/null
wait "$capture_pid"

