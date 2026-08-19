#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
key="$project_dir/vm/.ssh/id_ed25519"
known_hosts="$project_dir/vm/.ssh/known_hosts"
ssh_options=(-F /dev/null -i "$key" -o "UserKnownHostsFile=$known_hosts")
keyctl=/home/poc/macsec-fronthaul/build-openssl36/src/keying/poc_keyctl
control_socket=/tmp/macsec-poc-control.sock
grace_seconds=${MACSEC_RETIRE_GRACE_SECONDS:-2}

status() {
  ssh "${ssh_options[@]}" "poc@$1" \
    "printf 'STATUS\\n' | $keyctl $control_socket"
}

du_status=$(status 192.168.122.101)
ru_status=$(status 192.168.122.102)
du_active=$(sed -n 's/.*ACTIVE=\([0-3]\).*/\1/p' <<<"$du_status")
ru_active=$(sed -n 's/.*ACTIVE=\([0-3]\).*/\1/p' <<<"$ru_status")

if [[ "$du_status" != *"READY=1"* || "$ru_status" != *"READY=1"* ||
      -z "$du_active" || "$du_active" != "$ru_active" ]]; then
  echo "Estado inconsistente: DU='$du_status' RU='$ru_status'" >&2
  exit 1
fi

next_an=$(( (du_active + 1) % 4 ))
"$project_dir/scripts/negotiate-vm-keys.sh" "$next_an"

sleep "$grace_seconds"
retire_command="RETIRE AN=$du_active"
ssh "${ssh_options[@]}" poc@192.168.122.101 \
  "printf '%s\\n' '$retire_command' | $keyctl $control_socket" &
du_pid=$!
ssh "${ssh_options[@]}" poc@192.168.122.102 \
  "printf '%s\\n' '$retire_command' | $keyctl $control_socket" &
ru_pid=$!
wait "$du_pid"
wait "$ru_pid"

echo "Rekey AN=$du_active→$next_an concluído; AN antigo retirado após ${grace_seconds}s"
