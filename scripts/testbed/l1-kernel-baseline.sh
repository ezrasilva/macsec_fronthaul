#!/usr/bin/env bash
# L1: linha de base com o MACsec do kernel (sem codigo nosso).
# Dois netns (a, b) ligados por veth; VLAN 2161 e macsec empilhado sobre a VLAN.
# Uso: sudo scripts/testbed/l1-kernel-baseline.sh [up|test|down]  (padrao: up+test, sem down)
# Saida: artifacts/l1/baseline-kernel.pcap e logs
set -euo pipefail

CIPHER=${CIPHER:-gcm-aes-xpn-256}   # ou gcm-aes-256 se o kernel recusar XPN
VID=2161
MTU=9000
OUT=${OUT:-$(dirname "$0")/../../artifacts/l1}
MAC_A=02:00:00:00:00:0a; MAC_B=02:00:00:00:00:0b
SCI_A=0x02000000000a0001;  SCI_B=0x02000000000b0001
KEY_AB=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f  # A->B
KEY_BA=1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100  # B->A
KEYID=00000000000000000000000000000000
SALT_AB=aabbccddeeff001122334455; SALT_BA=112233445566778899aabbcc
SSCI_A=1; SSCI_B=2

ipa() { ip netns exec a "$@"; }
ipb() { ip netns exec b "$@"; }

down() {
  ip netns del a 2>/dev/null || true
  ip netns del b 2>/dev/null || true
}

if [ "$CIPHER" = gcm-aes-xpn-256 ]; then
  XA="xpn 1 salt $SALT_AB ssci $SSCI_A"; XB="xpn 1 salt $SALT_BA ssci $SSCI_B"
else
  XA="pn 1"; XB="pn 1"
fi

up() {
  down
  ip netns add a; ip netns add b
  ip link add va type veth peer name vb
  ip link set va netns a; ip link set vb netns b
  for s in a b; do
    [ $s = a ] && { N=ipa; M=$MAC_A; } || { N=ipb; M=$MAC_B; }
    d=v$s
    $N ip link set $d address $M mtu $MTU up
    $N ip link set lo up
    $N ip link add link $d name $d.$VID type vlan id $VID
    $N ip link set $d.$VID mtu $MTU up
  done
  # macsec sobre a VLAN; MTU do macsec = MTU da VLAN - overhead (deixa o kernel ajustar)
  ipa ip link add link va.$VID macsec0 type macsec sci $SCI_A encrypt on cipher $CIPHER
  ipb ip link add link vb.$VID macsec0 type macsec sci $SCI_B encrypt on cipher $CIPHER
  # A: tx com KEY_AB; rx do par B com KEY_BA
  ipa ip macsec add macsec0 tx sa 0 $XA on key $KEYID $KEY_AB
  ipa ip macsec add macsec0 rx sci $SCI_B on
  ipa ip macsec add macsec0 rx sci $SCI_B sa 0 ${XB/ssci $SSCI_B/ssci $SSCI_B} on key $KEYID $KEY_BA
  ipb ip macsec add macsec0 tx sa 0 $XB on key $KEYID $KEY_BA
  ipb ip macsec add macsec0 rx sci $SCI_A on
  ipb ip macsec add macsec0 rx sci $SCI_A sa 0 $XA on key $KEYID $KEY_AB
  ipa ip addr add 10.61.0.1/24 dev macsec0; ipa ip link set macsec0 up
  ipb ip addr add 10.61.0.2/24 dev macsec0; ipb ip link set macsec0 up
}

test_() {
  mkdir -p "$OUT"
  ipa ip -d link show macsec0 | tee "$OUT/macsec0-a.txt"
  ipa tcpdump -nn -e -i va -w "$OUT/baseline-kernel.pcap" -U >/dev/null 2>&1 &
  TP=$!; sleep 1
  ipa ping -c 3 -s 100 10.61.0.2 | tee "$OUT/ping-100.txt"
  ipa ping -c 3 -s 8000 10.61.0.2 | tee "$OUT/ping-8000-ab.txt"
  ipb ping -c 3 -s 8000 10.61.0.1 | tee "$OUT/ping-8000-ba.txt"
  sleep 1; kill $TP; wait $TP 2>/dev/null || true
  ipa ip -s macsec show > "$OUT/macsec-stats-a.txt"
  ipb ip -s macsec show > "$OUT/macsec-stats-b.txt"
  tcpdump -nn -e -r "$OUT/baseline-kernel.pcap" 2>/dev/null | head -5 | tee "$OUT/pcap-head.txt"
  chown -R "${SUDO_USER:-root}": "$OUT" 2>/dev/null || true
}

case "${1:-all}" in
  up) up ;; test) test_ ;; down) down ;;
  all) up; test_ ;;
esac
