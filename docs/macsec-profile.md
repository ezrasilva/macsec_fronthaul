# Perfil MACsec da PoC

Este documento fixa as escolhas da primeira camada. Mudanças neste perfil devem
ser acompanhadas por novos vetores de teste e por uma nova identificação de SA.

## Parâmetros

- algoritmo: GCM-AES-128;
- SAK: 16 bytes;
- ICV: 16 bytes;
- Packet Number: 32 bits, iniciado em valor não zero;
- SCI: 8 bytes, sempre presente no SecTAG;
- Association Number: 2 bits;
- confidencialidade: sempre habilitada;
- janela anti-replay: configurável entre 1 e 64 pacotes;
- XPN: ainda não suportado;
- VLAN: preservada dentro dos dados protegidos quando o EtherType original é
  `802.1Q` ou `802.1ad`.

## Frame protegido

```text
DA (6) | SA (6) | 88-E5 (2) | TCI/AN (1) | SL (1) | PN (4) | SCI (8)
| ciphertext (EtherType original + payload) | ICV (16)
```

O AAD é todo o cabeçalho, de `DA` até o final do `SCI`. O nonce de 96 bits é a
concatenação `SCI || PN`. Frames menores que 48 bytes de dados protegidos usam
o campo SL; para os demais, SL é zero.

## Limites de segurança

O PN nunca pode ser reutilizado com a mesma SAK/SCI. Ao proteger o frame de PN
`0xffffffff`, a SA passa ao estado esgotado e deve ser substituída antes de um
novo envio. A recepção só atualiza a janela anti-replay depois da autenticação
GCM bem-sucedida.

Esta camada não implementa MKA, negociação de cifras, gerenciamento de múltiplas
SAs nem interoperabilidade certificada IEEE 802.1AE. Essas responsabilidades
serão acrescentadas nas camadas de controle e rekey.

