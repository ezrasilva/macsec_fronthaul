#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
result=$(mktemp)
trap 'rm -f "$result"' EXIT

ssh -F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts" \
  poc@192.168.122.101 'ping -i 0.1 -c 100 -W 1 10.10.0.2' >"$result" &
ping_pid=$!
sleep 1
"$project_dir/scripts/rekey-vm-endpoints.sh"
wait "$ping_pid"
cat "$result"
grep -q '100 packets transmitted, 100 received, 0% packet loss' "$result"
echo "Rekey concluído sem perda de pacotes"
