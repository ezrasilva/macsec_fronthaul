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
- VLAN: preservada dentro dos dados protegidos quando o EtherType original é
  `802.1Q` ou `802.1ad`.

## Frame protegido

```text
DA (6) | SA (6) | 88-E5 (2) | TCI/AN (1) | SL (1) | PN (4) | SCI (8)
| ciphertext (EtherType original + payload) | ICV (16)
```

O AAD é todo o cabeçalho, de `DA` até o final do `SCI`. O SecTAG transporta os
32 bits inferiores do PN. O receptor reconstrói o PN de 64 bits e o nonce é
`(SSCI || PN64) XOR salt`, conforme o perfil XPN. Frames menores que 48 bytes usam
o campo SL; para os demais, SL é zero.

## Limites de segurança

O PN nunca pode ser reutilizado com a mesma SAK/salt/SSCI. A transição do word
inferior `0xffffffff → 0x00000000` mantém a SA ativa e incrementa a parte alta.
Somente após `0xffffffffffffffff` a SA se esgota. A recepção só atualiza a janela
GCM bem-sucedida.

Esta camada não implementa MKA nem interoperabilidade certificada IEEE 802.1AE.
