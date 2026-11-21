#!/usr/bin/env python3
"""Auxiliar do teste de regressao local por pcap (l2-pcap-regression.sh).

  pcap-tools.py vlan IN OUT VID      insere tag 802.1Q apos DA/SA em cada quadro
  pcap-tools.py check-secure PCAP N  confere N quadros [VLAN] 88e5 SecTAG, SCI e tamanho
  pcap-tools.py same A B             A e B contem os mesmos quadros, na mesma ordem
  pcap-tools.py vids PCAP            VIDs externas + ethertype seguinte
  pcap-tools.py pad IN OUT TOTAL     preenche cada quadro ate TOTAL bytes
"""
import struct, sys

def read(path):
    d = open(path, 'rb').read()
    assert d[:4] in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'), 'pcap little-endian esperado'
    off, out = 24, []
    while off + 16 <= len(d):
        s, u, cap, _ = struct.unpack('<IIII', d[off:off + 16])
        out.append((s, u, d[off + 16:off + 16 + cap]))
        off += 16 + cap
    return out

def write(path, frames):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for s, u, b in frames:
            f.write(struct.pack('<IIII', s, u, len(b), len(b)) + b)

cmd = sys.argv[1]
if cmd == 'vlan':
    vid = int(sys.argv[4])
    write(sys.argv[3], [(s, u, b[:12] + struct.pack('!HH', 0x8100, vid) + b[12:]) for s, u, b in read(sys.argv[2])])
elif cmd == 'check-secure':
    fr = read(sys.argv[2]); n = int(sys.argv[3])
    assert len(fr) == n, 'esperava %d quadros, obtive %d' % (n, len(fr))
    vlan = 0
    for _, _, b in fr:
        l2 = 16 if b[12:14] == b'\x81\x00' else 12
        vlan += l2 == 16
        assert b[l2:l2 + 2] == b'\x88\xe5', 'sem SecTAG apos DA/SA[/VLAN]'
        assert b[l2 + 2] & 0x2c == 0x2c, 'TCI sem SC/E/C'
    print('ok: %d quadros MACsec (%d com VLAN fora do SecTAG)' % (n, vlan))
elif cmd == 'same':
    a, b = read(sys.argv[2]), read(sys.argv[3])
    assert len(a) == len(b), 'contagens diferem: %d vs %d' % (len(a), len(b))
    for i, (x, y) in enumerate(zip(a, b)):
        assert x[2] == y[2], 'quadro %d difere' % i
    print('ok: %d quadros identicos' % len(a))
elif cmd == 'vids':   # VIDs externas e o ethertype seguinte, uma entrada por tipo
    out = []
    for _, _, b in read(sys.argv[2]):
        if b[12:14] in (b'\x81\x00', b'\x88\xa8'):
            out.append('%d/%s' % (struct.unpack('!H', b[14:16])[0] & 0xfff, b[16:18].hex()))
        else:
            out.append('untagged/%s' % b[12:14].hex())
    print(' '.join(sorted(set(out))) + ' n=%d' % len(out))
elif cmd == 'pad':    # pad IN OUT TOTAL: preenche cada quadro ate TOTAL bytes
    total = int(sys.argv[4])
    write(sys.argv[3], [(s, u, b + bytes(max(0, total - len(b)))) for s, u, b in read(sys.argv[2])])
