#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")

"$project_dir/scripts/negotiate-vm-keys.sh"

read_key() {
  ssh "${ssh_options[@]}" poc@192.168.122.101 \
    "sed -n 's/^$1=//p' /home/poc/macsec-keys.env"
}

du_key=$(read_key DU_TO_RU_KEY)
ru_key=$(read_key RU_TO_DU_KEY)
if [[ ! "$du_key" =~ ^[[:xdigit:]]{32}$ || ! "$ru_key" =~ ^[[:xdigit:]]{32}$ ]]; then
  echo "Erro: material de rekey inválido" >&2
  exit 1
fi

ssh "${ssh_options[@]}" poc@192.168.122.101 \
  "printf 'TX_KEY=%s\nRX_KEY=%s\n' '$du_key' '$ru_key' > /home/poc/macsec-rekey.env; chmod 600 /home/poc/macsec-rekey.env; sudo systemctl kill -s SIGUSR1 macsec-poc.service"
ssh "${ssh_options[@]}" poc@192.168.122.102 \
  "printf 'TX_KEY=%s\nRX_KEY=%s\n' '$ru_key' '$du_key' > /home/poc/macsec-rekey.env; chmod 600 /home/poc/macsec-rekey.env; sudo systemctl kill -s SIGUSR1 macsec-poc.service"

sleep 1
ssh "${ssh_options[@]}" poc@192.168.122.101 "sudo systemctl kill -s SIGUSR2 macsec-poc.service"
ssh "${ssh_options[@]}" poc@192.168.122.102 "sudo systemctl kill -s SIGUSR2 macsec-poc.service"

echo "Rekey preparado e ativado nos dois endpoints"
