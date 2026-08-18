# Pré-requisitos para duas VMs O-DU/O-RU

O host possui VT-x, KVM e `/dev/kvm`, mas ainda não possui QEMU, libvirt,
virt-install nem cloud-init tooling. No Arch Linux, instale-os antes do
provisionamento:

```sh
sudo pacman -S --needed qemu-desktop libvirt virt-install dnsmasq edk2-ovmf cloud-image-utils
sudo systemctl enable --now libvirtd
sudo usermod -aG libvirt,kvm "$USER"
```

É necessário encerrar e iniciar novamente a sessão depois da alteração de
grupos. A verificação esperada é:

```sh
virsh --connect qemu:///system list --all
qemu-system-x86_64 --version
```

Cada VM terá duas interfaces virtio:

- `plain`: interface usada pela pilha IP de teste;
- `fronthaul`: enlace L2 entre O-DU e O-RU, processado pelo endpoint DPDK.

As SAs serão direcionais: o TX da O-DU corresponde ao RX da O-RU, e o TX da
O-RU corresponde ao RX da O-DU.

O provisionador usa a imagem Ubuntu Server Cloud completa. A variante Ubuntu
Minimal não é usada porque seu boot não ativou o datasource NoCloud necessário
para aplicar rede, usuário e chave SSH nesta topologia.
