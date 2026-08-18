#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"

for host in 192.168.122.101 192.168.122.102; do
  ssh -F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts" \
    "poc@$host" 'sudo systemctl stop macsec-poc.service' &
done
wait

