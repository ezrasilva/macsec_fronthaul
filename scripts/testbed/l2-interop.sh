#!/usr/bin/env bash
# L2: interoperabilidade da nossa SecY com o MACsec do kernel (netns do L1).
# Lado A = kernel (macsec0 sobre va.2161). Lado B = tests/interop/interop_peer (nossa SecY).
# Uso: sudo scripts/testbed/l2-interop.sh [build-dir]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
peer=${1:-$root/build}/tests/interop/interop_peer
[ -x "$peer" ] || { echo "compile primeiro: ninja -C build"; exit 1; }

"$here/l1-kernel-baseline.sh" up        # estado limpo (PN do kernel em 1)
# o lado B passa a ser a nossa SecY: remove o macsec do kernel em b
ip netns exec b ip link del macsec0
# A responde ao ICMP de 10.61.0.2: neighbor estatico (nao ha ARP sobre o nosso lado)
ip netns exec a ip neigh replace 10.61.0.2 lladdr 02:00:00:00:00:0b dev macsec0 nud permanent

fail=0
for size in 100 1400 8000; do
  echo "--- payload ICMP $size B"
  ip netns exec b "$peer" vb "$size" 2161 || fail=1
done
echo "--- contadores do kernel (lado A)"
ip netns exec a ip -s macsec show macsec0 | grep -E 'InPktsOK|InPktsInvalid|InPktsNotValid|OutPktsEncrypted|InPktsNoSCI|InPktsUnknownSCI' -A1 | head -20
[ $fail -eq 0 ] && echo "L2 interop: OK" || { echo "L2 interop: FALHOU"; exit 1; }
