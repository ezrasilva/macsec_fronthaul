#!/usr/bin/env bash
set -euo pipefail

connection="qemu:///system"
virsh -c "$connection" list --all
echo
virsh -c "$connection" net-dhcp-leases default
echo
virsh -c "$connection" net-info macsec-fronthaul
echo
for address in 192.168.122.101 192.168.122.102; do
  if ping -c 1 -W 1 "$address" >/dev/null 2>&1; then
    echo "$address: acessível"
  else
    echo "$address: ainda não acessível"
  fi
done
