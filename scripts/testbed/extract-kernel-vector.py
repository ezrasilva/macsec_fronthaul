#!/usr/bin/env python3
"""Extrai quadros MACsec do kernel (L1) para tests/vectors/kernel_vlan_xpn.h.

Uso: extract-kernel-vector.py artifacts/l1/baseline-kernel.pcap > tests/vectors/kernel_vlan_xpn.h
Escolhe o primeiro quadro 802.1Q(2161)+0x88e5 de 178 B em cada sentido.
Chaves/salt/SSCI/SCI sao as de l1-kernel-baseline.sh.
"""
import struct, sys

def frames(path):
    d = open(path, 'rb').read()
    magic = d[:4]
    assert magic in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'), "pcap classico esperado"
    e = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
    off = 24
    while off + 16 <= len(d):
        _, _, cap, _ = struct.unpack(e + 'IIII', d[off:off + 16])
        yield d[off + 16:off + 16 + cap]
        off += 16 + cap

def carray(name, b):
    body = ',\n'.join('    ' + ', '.join('0x%02x' % x for x in b[i:i + 12]) for i in range(0, len(b), 12))
    return 'static const uint8_t %s[] = {\n%s\n};\n' % (name, body)

pick = {}
for f in frames(sys.argv[1]):
    if len(f) == 178 and f[12:14] == b'\x81\x00' and f[16:18] == b'\x88\xe5':
        pick.setdefault(f[6:12], f)
out = ['/* Gerado por scripts/testbed/extract-kernel-vector.py a partir de quadros reais do\n'
       ' * MACsec do kernel (gcm-aes-xpn-256, VLAN 2161, SCI explicito). Nao editar. */\n']
for tag, mac in (('ab', bytes.fromhex('02000000000a')), ('ba', bytes.fromhex('02000000000b'))):
    out.append(carray('kernel_frame_' + tag, pick[mac]))
print('\n'.join(out))
