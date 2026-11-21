#!/usr/bin/env bash
# L4 sem root: agente TLS PQC real <-> adaptadores kernel-control em --dry-run (um por ponta).
# Confere que a chave/salt de TX de uma ponta e a de RX da outra, e que cada rekey gera chaves novas.
# Uso: scripts/testbed/l4-local-check.sh [build-dir]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); root=$(cd "$here/../.." && pwd)
build=${1:-$root/build}; K=$build/src/keying/poc_tls_keying; CTL=$build/src/keying/poc_keyctl
w=${OUT:-$build/l4-local}; rm -rf "$w"; mkdir -p "$w"; cd "$w"
"$here/make-pki.sh" pki
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }; trap cleanup EXIT
python3 -I "$here/kernel-control.py" --socket du.sock --peer-sci 0x02000000000b0001 --tx-ssci 1 --rx-ssci 2 --dry-run >du.out 2>&1 & pids+=($!)
python3 -I "$here/kernel-control.py" --socket ru.sock --peer-sci 0x02000000000a0001 --tx-ssci 2 --rx-ssci 1 --dry-run >ru.out 2>&1 & pids+=($!)
for _ in $(seq 50); do [ -S du.sock ] && [ -S ru.sock ] && break; sleep 0.1; done
for an in 0 1 2; do
  MACSEC_ENDPOINT_ROLE=du MACSEC_CONTROL_AN=$an MACSEC_TLS_PEER_KEY=ML-DSA-65 \
    timeout 20 "$K" server 9443 pki/du.crt pki/du.key pki/ca.crt unix:du.sock >srv$an.log 2>&1 & sp=$!
  sleep 0.3
  MACSEC_ENDPOINT_ROLE=ru MACSEC_CONTROL_AN=$an MACSEC_TLS_SERVER_NAME=macsec-du MACSEC_TLS_PEER_KEY=ML-DSA-65 \
    timeout 20 "$K" client 127.0.0.1 9443 pki/ru.crt pki/ru.key pki/ca.crt unix:ru.sock >cli$an.log 2>&1
  wait $sp
  echo "rekey AN=$an: $(head -1 cli$an.log | cut -c1-120)"
  if [ $an -gt 0 ]; then printf 'RETIRE AN=%d\n' $((an-1)) | "$CTL" du.sock | tr -d '\n'; printf 'RETIRE AN=%d\n' $((an-1)) | "$CTL" ru.sock; fi
done
echo "DU: $(printf 'STATUS\n' | "$CTL" du.sock)"; echo "RU: $(printf 'STATUS\n' | "$CTL" ru.sock)"
# o ativo nao pode ser retirado; INSTALL no AN ativo tambem e recusado
printf 'RETIRE AN=2\n' | "$CTL" du.sock && { echo "FALHOU: retirou AN ativo"; exit 1; } || echo "ok: RETIRE do AN ativo recusado"
python3 - <<'PY'
import re
def keys(f):
    out = {}
    for l in open(f):
        if 'DRY' in l and ' macsec add ' in l and ' sa ' in l:
            m = re.search(r'macsec add \S+ (tx|rx)(?: sci \S+)? sa (\d) .* salt ([0-9a-f]{24}) ssci (\d) (on|off) key \S+ ([0-9a-f]{64})', l)
            out[(m.group(1), m.group(2))] = (m.group(6), m.group(3), m.group(4))
    return out
d, r = keys('du.out'), keys('ru.out')
assert len(d) == 6 and len(r) == 6, (len(d), len(r))
for an in '012':
    assert d[('tx', an)][:2] == r[('rx', an)][:2], 'DU tx != RU rx (AN%s)' % an
    assert d[('rx', an)][:2] == r[('tx', an)][:2], 'DU rx != RU tx (AN%s)' % an
    assert d[('tx', an)][0] != d[('rx', an)][0], 'chave igual nas duas direcoes'
    assert d[('tx', an)][2] == '1' and d[('rx', an)][2] == '2' and r[('tx', an)][2] == '2' and r[('rx', an)][2] == '1', 'SSCI'
assert len({d[('tx', a)][0] for a in '012'}) == 3, 'rekey reutilizou chave'
print('OK: TX de cada ponta == RX da outra (chave, salt); direcoes distintas; 3 rekeys = 3 chaves distintas')
PY
grep -E 'macsec (set|del)|link set' du.out | sed 's/DRY //' | head -8
echo "L4 local check: OK"
