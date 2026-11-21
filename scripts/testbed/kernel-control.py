#!/usr/bin/env python3
"""Adaptador: socket de controle MACsec (INSTALL/ACTIVATE/RETIRE/STATUS) -> MACsec do kernel.

Faz, para o macsec do kernel (a SecY A simulada), o papel que o gateway DPDK faz com o mesmo
protocolo e que o driver do hostap fara na F3. Mensagem de 96 bytes (include/key_control.h):
  version(1)=1 op(1) an(1) reserved(1)=0 payload_len_be(4) tx_key(32) rx_key(32) tx_salt(12) rx_salt(12)
op: 1 INSTALL, 2 ACTIVATE, 3 RETIRE, 4 STATUS. Resposta: "OK\\n", "REJECTED\\n" ou "STATUS ...\\n".
INSTALL cria a SA de TX desligada e a de RX ligada; ACTIVATE liga a de TX e a seleciona.
Uso: kernel-control.py --socket PATH --dev macsec0 --peer-sci 0x... --tx-ssci 1 --rx-ssci 2 [--dry-run]
"""
import argparse, os, re, socket, struct, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument('--socket', required=True); ap.add_argument('--dev', default='macsec0')
ap.add_argument('--peer-sci', required=True); ap.add_argument('--tx-ssci', type=int, required=True)
ap.add_argument('--rx-ssci', type=int, required=True); ap.add_argument('--dry-run', action='store_true')
ap.add_argument('--max-requests', type=int, default=0)
a = ap.parse_args()
IP = os.environ.get('IP_BIN', 'ip')
state = {'active': None, 'pending': None, 'ready': False}

def ip(*args, check=True):
    cmd = [IP] + list(args)
    if a.dry_run:
        print('DRY ' + ' '.join(cmd), flush=True); return ''
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        print('ip falhou: %s: %s' % (' '.join(cmd[:6]), r.stderr.strip()), file=sys.stderr, flush=True)
        raise RuntimeError(r.stderr)
    return r.stdout

def keyid(an): return '%032x' % an

def handle(msg):
    if len(msg) != 96 or msg[0] != 1 or msg[3] != 0: return b'INVALID\n'
    op, an = msg[1], msg[2]; plen = struct.unpack('>I', msg[4:8])[0]
    d = a.dev
    if op == 4:
        if not a.dry_run:
            m = re.search(r'encodingsa (\d)', ip('-d', 'link', 'show', d)); act = m.group(1) if m else '?'
        else: act = state['active'] if state['active'] is not None else 0
        p = '-' if state['pending'] is None else str(state['pending'])
        return ('STATUS ACTIVE=%s READY=%d PENDING=%s\n' % (act, 1 if state['ready'] else 0, p)).encode()
    if an > 3: return b'REJECTED\n'
    if op == 1:
        if plen != 88 or (an == state['active'] and state['ready']): return b'REJECTED\n'
        txk, rxk = msg[8:40].hex(), msg[40:72].hex(); txs, rxs = msg[72:84].hex(), msg[84:96].hex()
        ip('macsec', 'del', d, 'tx', 'sa', str(an), check=False)
        ip('macsec', 'del', d, 'rx', 'sci', a.peer_sci, 'sa', str(an), check=False)
        ip('macsec', 'add', d, 'tx', 'sa', str(an), 'xpn', '1', 'salt', txs, 'ssci', str(a.tx_ssci), 'off', 'key', keyid(an), txk)
        ip('macsec', 'add', d, 'rx', 'sci', a.peer_sci, 'sa', str(an), 'xpn', '1', 'salt', rxs, 'ssci', str(a.rx_ssci), 'on', 'key', keyid(an), rxk)
        state['pending'] = an; return b'OK\n'
    if op == 2:
        if state['pending'] != an or plen != 0: return b'REJECTED\n'
        ip('macsec', 'set', d, 'tx', 'sa', str(an), 'on')
        ip('link', 'set', d, 'type', 'macsec', 'encodingsa', str(an))
        state.update(active=an, pending=None, ready=True); return b'OK\n'
    if op == 3:
        if an == state['active'] or plen != 0: return b'REJECTED\n'
        ip('macsec', 'del', d, 'tx', 'sa', str(an), check=False)
        ip('macsec', 'del', d, 'rx', 'sci', a.peer_sci, 'sa', str(an), check=False)
        if state['pending'] == an: state['pending'] = None
        return b'OK\n'
    return b'REJECTED\n'

try: os.unlink(a.socket)
except FileNotFoundError: pass
srv = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET); srv.bind(a.socket); os.chmod(a.socket, 0o600); srv.listen(4)
print('kernel-control pronto em ' + a.socket, flush=True)
n = 0
while True:
    c, _ = srv.accept()
    try:
        try: reply = handle(c.recv(256))
        except Exception as e: print('erro: %s' % e, file=sys.stderr, flush=True); reply = b'REJECTED\n'
        c.send(reply)
    finally: c.close()
    n += 1
    if a.max_requests and n >= a.max_requests: break
