#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "execute com sudo: sudo $0" >&2
  exit 1
fi

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
vm_dir="$project_dir/vm"
image_dir="/var/lib/libvirt/images/macsec-poc"
generated_dir="$image_dir/cloud-init"
key_dir="$vm_dir/.ssh"
base_image="$image_dir/ubuntu-24.04-server-cloudimg-amd64.img"
image_url="https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img"
connection="qemu:///system"
recreate=false

if [[ ${1:-} == "--recreate" ]]; then
  recreate=true
elif [[ $# -ne 0 ]]; then
  echo "uso: sudo $0 [--recreate]" >&2
  exit 1
fi

install -d -m 0755 "$image_dir" "$generated_dir"
install -d -m 0700 -o "${SUDO_UID:-0}" -g "${SUDO_GID:-0}" "$key_dir"
# Repara o diretório caso uma execução anterior o tenha criado como root.
chown "${SUDO_UID:-0}:${SUDO_GID:-0}" "$key_dir"

if [[ ! -f "$key_dir/id_ed25519" ]]; then
  sudo -u "${SUDO_USER:-root}" ssh-keygen -q -t ed25519 -N '' \
    -C macsec-poc -f "$key_dir/id_ed25519"
fi

if [[ ! -f "$base_image" ]]; then
  curl -fL --progress-bar "$image_url" -o "$base_image"
fi

public_key=$(<"$key_dir/id_ed25519.pub")
sed "s|@SSH_PUBLIC_KEY@|$public_key|" \
  "$vm_dir/cloud-init/user-data.template" > "$generated_dir/user-data"

for node in du ru; do
  disk="$image_dir/o-$node.qcow2"
  seed="$generated_dir/o-$node-seed.img"
  if [[ ! -f "$disk" ]]; then
    qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" "$disk" 12G
  fi
  cloud-localds --network-config="$vm_dir/cloud-init/network-config-$node" \
    "$seed" "$generated_dir/user-data" "$vm_dir/cloud-init/meta-data-$node"
done

if ! virsh -c "$connection" net-info default >/dev/null 2>&1; then
  echo "rede libvirt 'default' não encontrada" >&2
  exit 1
fi
virsh -c "$connection" net-start default >/dev/null 2>&1 || true
virsh -c "$connection" net-autostart default >/dev/null

if ! virsh -c "$connection" net-info macsec-fronthaul >/dev/null 2>&1; then
  virsh -c "$connection" net-define "$vm_dir/networks/macsec-fronthaul.xml" >/dev/null
fi
virsh -c "$connection" net-start macsec-fronthaul >/dev/null 2>&1 || true
virsh -c "$connection" net-autostart macsec-fronthaul >/dev/null

for node in du ru; do
  name="macsec-o-$node"
  if virsh -c "$connection" dominfo "$name" >/dev/null 2>&1; then
    if [[ $recreate == false ]]; then
      echo "$name já existe; preservando a VM"
      continue
    fi
    virsh -c "$connection" destroy "$name" >/dev/null 2>&1 || true
    virsh -c "$connection" undefine "$name" --nvram >/dev/null 2>&1 || \
      virsh -c "$connection" undefine "$name" >/dev/null
    rm -f "$image_dir/o-$node.qcow2" "$generated_dir/o-$node-seed.img"
    qemu-img create -q -f qcow2 -F qcow2 -b "$base_image" \
      "$image_dir/o-$node.qcow2" 12G
    cloud-localds --network-config="$vm_dir/cloud-init/network-config-$node" \
      "$generated_dir/o-$node-seed.img" "$generated_dir/user-data" \
      "$vm_dir/cloud-init/meta-data-$node"
  fi
  if [[ $node == du ]]; then
    mgmt_mac="52:54:00:ae:00:01"
    fronthaul_mac="52:54:00:ae:00:02"
  else
    mgmt_mac="52:54:00:ae:00:11"
    fronthaul_mac="52:54:00:ae:00:12"
  fi
  virt-install --connect "$connection" \
    --name "$name" --memory 3072 --vcpus 4 --cpu host-passthrough \
    --import --osinfo ubuntu24.04 --noautoconsole \
    --disk "path=$image_dir/o-$node.qcow2,format=qcow2,bus=virtio" \
    --disk "path=$generated_dir/o-$node-seed.img,device=cdrom" \
    --network "network=default,model=virtio,mac=$mgmt_mac" \
    --network "network=macsec-fronthaul,model=virtio,mac=$fronthaul_mac" \
    --graphics none
done

echo
virsh -c "$connection" list --all
echo
echo "Chave SSH: $key_dir/id_ed25519"
echo "Endereços de gerenciamento: O-DU=192.168.122.101 O-RU=192.168.122.102"
echo "Acompanhe com: sudo $project_dir/scripts/vm-status.sh"
