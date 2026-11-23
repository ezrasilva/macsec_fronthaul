#!/usr/bin/env bash
# Copia o nucleo SecY (C, sem DPDK) deste repositorio para a arvore do OCUDU (copia "vendored").
# Uso: sync-secy-to-ocudu.sh [OCUDU_REPO]
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
dst=${1:-$HOME/opt/src/ocudu-src/repo}/lib/ofh/ethernet/dpdk/macsec/secy_core
mkdir -p "$dst"
cp "$root/include/macsec.h" "$root/include/key_control.h" "$root/src/macsec/macsec.c" "$root/src/keying/key_control.c" "$dst/"
echo "copiado para $dst"
