#!/usr/bin/env bash
# Compila uma 2a copia do DPDK com --prefix=/opt/macsec-testbed e instala em um diretorio de
# staging (SEM root). O install-testbed.sh copia esse staging para /opt como root.
# Motivo: o DPDK grava o diretorio de plugins (PMDs) a partir do prefixo; com o prefixo de
# ~/opt/local, um processo root carregaria PMDs de uma pasta gravavel pelo usuario.
# Uso: source ~/opt/env.sh; scripts/testbed/build-dpdk-stage.sh [src-dpdk] [stage-dir]
set -euo pipefail
src=${1:-$HOME/opt/src/dpdk-26.07}; stage=${2:-$HOME/opt/stage}; L=${DEPS:-$HOME/opt/local}
cd "$src"; rm -rf build-opt "$stage"
CFLAGS="-I$L/include" LDFLAGS="-L$L/lib" meson setup build-opt --prefix=/opt/macsec-testbed \
  -Dplatform=native -Dtests=false -Dexamples= -Denable_docs=false \
  -Denable_drivers='net/af_packet,net/tap,net/null,net/ring,net/virtio,net/i40e,net/ice,net/pcap,crypto/ipsec_mb,crypto/openssl,crypto/null,mempool/ring'
ninja -C build-opt
DESTDIR="$stage" ninja -C build-opt install
echo "staging em $stage/opt/macsec-testbed (libIPSec_MB vem de $L/lib e e copiado pelo instalador)"
