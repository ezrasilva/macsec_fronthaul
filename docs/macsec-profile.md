# Perfil MACsec da PoC

Este documento fixa as escolhas da primeira camada. Mudanças neste perfil devem
ser acompanhadas por novos vetores de teste e por uma nova identificação de SA.

## Parâmetros

- algoritmo: GCM-AES-XPN-256;
- SAK: 32 bytes;
- ICV: 16 bytes;
- Packet Number: 64 bits, iniciado em valor não zero;
- SCI: 8 bytes, sempre presente no SecTAG;
- Association Number: 2 bits;
- confidencialidade: sempre habilitada;
- janela anti-replay: configurável entre 1 e 64 pacotes;
- XPN: SSCI de 32 bits e salt de 96 bits por direção;
- VLAN: a tag `802.1Q` ou `802.1ad` (uma só) fica **fora** do MACsec, logo
  após DA/SA e antes do SecTAG; não entra no AAD, na cifra nem no ICV. Isso
  permite que os ToRs vejam a VID e que o gateway a troque (216x ↔ 16x) sem
  recalcular o ICV. Sem tag, o SecTAG segue direto após DA/SA.

## Frame protegido

```text
DA (6) | SA (6) | [802.1Q (4)] | 88-E5 (2) | TCI/AN (1) | SL (1) | PN (4) | SCI (8)
| ciphertext (EtherType original + payload) | ICV (16)
```

Com SCI explícito e ICV de 16 bytes, o frame protegido cresce 32 bytes. A
checagem de capacidade e o tailroom do mbuf usam esse valor integral.

O AAD tem 28 bytes e é montado em buffer próprio: `DA | SA | 88-E5 | TCI/AN |
SL | PN | SCI` (a tag de VLAN, quando existe, fica de fora). Este layout é o do
MACsec do kernel Linux empilhado sobre uma subinterface VLAN. O SecTAG transporta os
32 bits inferiores do PN. O receptor reconstrói o PN de 64 bits e o nonce é
`(SSCI || PN64) XOR salt`, conforme o perfil XPN. Frames menores que 48 bytes usam
o campo SL; para os demais, SL é zero.

## Limites de segurança

O PN nunca pode ser reutilizado com a mesma SAK/salt/SSCI. A transição do word
inferior `0xffffffff → 0x00000000` mantém a SA ativa e incrementa a parte alta.
Somente após `0xffffffffffffffff` a SA se esgota. A recepção só atualiza a janela
após autenticação GCM bem-sucedida.

Na reconstrução do XPN, pacotes fora de ordem podem pertencer ao bloco de 32
bits imediatamente anterior ou seguinte ao PN esperado. A parte alta é ajustada
nas duas direções antes da autenticação, permitindo reordenação legítima ao
redor de `0xffffffff → 0x00000000` sem ampliar a janela anti-replay.

Esta camada não implementa MKA nem interoperabilidade certificada IEEE 802.1AE.

## Validação do layout (L1/L2)

- `tests/vectors/kernel_vlan_xpn.h`: dois quadros reais (um por sentido) gerados
  pelo kernel 7.2.14 com `gcm-aes-xpn-256`, VLAN 2161 e SCI explícito
  (`scripts/testbed/l1-kernel-baseline.sh`, extraídos por `extract-kernel-vector.py`).
  `test_macsec_vlan` verifica o quadro do kernel com a nossa SecY e reproduz o
  mesmo quadro byte a byte.
- Interoperabilidade ao vivo nos dois sentidos: `scripts/testbed/l2-interop.sh`.
- Regressão do pipeline DPDK com net_pcap, com e sem VLAN:
  `scripts/testbed/l2-pcap-regression.sh`.
- A SecY aceita quadros sem VLAN; exigir VLAN é política do gateway (L3).
