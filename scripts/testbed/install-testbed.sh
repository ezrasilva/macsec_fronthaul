#!/usr/bin/env bash
# Instala os scripts do testbed em /opt/macsec-testbed (root:root) e uma regra sudoers NOPASSWD
# RESTRITA a eles, para que o Claude Code os rode sem pedir senha.
#
#   sudo scripts/testbed/install-testbed.sh              # snapshot (recomendado)
#   sudo scripts/testbed/install-testbed.sh --live       # roda direto do repositorio (INSEGURO)
#   sudo scripts/testbed/install-testbed.sh --uninstall
#
# Snapshot: copia scripts, gateway, interop_peer e libs DPDK para /opt (root-owned). Ninguem que
# rode como seu usuario consegue alterar o que roda como root. Custo: cada vez que o codigo mudar
# e for recompilado, reinstale (pede senha).
# --live: a regra aponta para wrappers que executam os scripts DO REPOSITORIO. Quem puder gravar
# no repo (qualquer processo seu, inclusive o Claude) passa a ter root sem senha. So use se aceitar.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "rode com sudo"; exit 1; }
user=${SUDO_USER:?rode via sudo, nao como root direto}
home=$(getent passwd "$user" | cut -d: -f6)
here=$(cd "$(dirname "$0")" && pwd); repo=$(cd "$here/../.." && pwd)
DEST=${DEST:-/opt/macsec-testbed}
STAGE=${STAGE:-$home/opt/stage/opt/macsec-testbed}
SUDOERS=${SUDOERS:-/etc/sudoers.d/macsec-testbed}
mode=snapshot
case "${1:-}" in --live) mode=live ;; --uninstall) rm -f "$SUDOERS"; rm -rf "$DEST"; echo "removido"; exit 0 ;; "") ;; *) echo "opcao invalida"; exit 2 ;; esac

L1=l1-kernel-baseline.sh; L2=l2-interop.sh; L3=l3-netns.sh; L4=l4-rekey.sh
HELPERS="make-pki.sh kernel-control.py"
if [ $mode = snapshot ]; then
  for f in "$repo/build/apps/dpdk/poc_macsec_dpdk" "$repo/build/tests/interop/interop_peer" "$repo/build/src/keying/poc_tls_keying" "$repo/build/src/keying/poc_keyctl" "$STAGE/lib/librte_eal.so" "$home/opt/local/lib/libIPSec_MB.so.2"; do
    [ -e "$f" ] || { echo "faltando: $f  (compile; rode scripts/testbed/build-dpdk-stage.sh)"; exit 1; }
  done
  # o binario precisa ter sido ligado ao DPDK 26.07 (mesma ABI do staging)
  rm -rf "$DEST"; install -d -m 0755 -o root -g root "$DEST" "$DEST/scripts/testbed" "$DEST/build/apps/dpdk" "$DEST/build/tests/interop" "$DEST/build/src/keying" "$DEST/lib"
  for s in $L1 $L2 $L3 $L4 $HELPERS; do install -m 0755 -o root -g root "$repo/scripts/testbed/$s" "$DEST/scripts/testbed/$s"; done
  install -m 0755 -o root -g root "$repo/build/src/keying/poc_tls_keying" "$repo/build/src/keying/poc_keyctl" "$DEST/build/src/keying/"
  install -m 0755 -o root -g root "$repo/build/apps/dpdk/poc_macsec_dpdk" "$DEST/build/apps/dpdk/"
  install -m 0755 -o root -g root "$repo/build/tests/interop/interop_peer" "$DEST/build/tests/interop/"
  cp -a "$STAGE"/lib/*.so* "$STAGE/lib/dpdk" "$DEST/lib/"
  cp -a "$home"/opt/local/lib/libIPSec_MB.so* "$DEST/lib/"
  chown -R root:root "$DEST"; chmod -R go-w "$DEST"
  bin=$DEST/scripts/testbed
else
  install -d -m 0755 -o root -g root "$DEST/live"
  for s in $L1 $L2 $L3 $L4; do
    printf '#!/bin/sh\nexec %s/scripts/testbed/%s "$@"\n' "$repo" "$s" > "$DEST/live/$s"; chmod 0755 "$DEST/live/$s"
  done
  chown -R root:root "$DEST"; bin=$DEST/live
fi

# Regra: apenas estes comandos, com estes argumentos exatos (\"\" = sem argumentos).
rule() { local c=$1; shift; local a; for a in "$@"; do printf '%s %s, ' "$bin/$c" "$a"; done; }
tmp=$(mktemp)
{
  echo "# gerado por install-testbed.sh ($mode); remover: sudo install-testbed.sh --uninstall"
  printf '%s ALL=(root) NOPASSWD: ' "$user"
  { rule $L1 '""' up test down; rule $L2 '""'; rule $L3 '""' e0 e1 all down; rule $L4 '""' run down; } | sed 's/, $//'
  echo
} > "$tmp"
visudo -cf "$tmp" >/dev/null || { echo "sudoers invalido:"; cat "$tmp"; rm -f "$tmp"; exit 1; }
install -m 0440 -o root -g root "$tmp" "$SUDOERS"; rm -f "$tmp"
echo "instalado ($mode) em $DEST ; regra em $SUDOERS:"; sed 's/^/  /' "$SUDOERS"
echo "teste: sudo -n $bin/$L3 down"
