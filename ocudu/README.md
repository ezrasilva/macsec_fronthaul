# SecY (MACsec) dentro do OCUDU — protótipo da F4

**Estado: protótipo, NÃO validado.** Funciona em parte; há um defeito aberto (abaixo).

## O que é
`patches/0001-*.patch` é um commit sobre `gitlab.com/ocudu/ocudu` (base `698c4a5`, 20/11/2026).
Adiciona `lib/ofh/ethernet/dpdk/macsec/`: motor MACsec no transmitter e no receiver **DPDK**.
- **TX:** SecTAG inserido durante o `memcpy` para o mbuf, ICV no fim, AES-256-GCM-XPN em burst no cryptodev.
- **RX:** verificação in-place após `rte_eth_rx_burst`, antes do `rte_vlan_strip`.
- SAs em 4 slots, PN atômico, retirada por época, thread de controle (`INSTALL/ACTIVATE/RETIRE/STATUS`,
  mesmo protocolo de 96 B do gateway). Desligado, o caminho de dados não muda.
- O núcleo (`secy_core/`) é cópia de `include/macsec.h`, `src/macsec/macsec.c`, `key_control.*`
  (`scripts/testbed/sync-secy-to-ocudu.sh` atualiza). Compila sem OpenSSL (`MACSEC_NO_OPENSSL`).

## Aplicar e compilar
```
git clone https://gitlab.com/ocudu/ocudu.git && cd ocudu && git checkout 698c4a5
git am /caminho/macsec_fronthaul/ocudu/patches/0001-*.patch
cmake -S . -B build -G Ninja -DENABLE_DPDK=ON ... && ninja -C build gnb_split_7_2
```
Dependências que o `apps/` exige: SCTP (`lksctp-tools`) e mbedtls 2.28. DPDK ≥ 22.11 (testado 26.07).

## Configurar (por ambiente; ainda não há opção no `ru_ofh`)
`OCUDU_MACSEC=1`, `OCUDU_MACSEC_CONTROL_SOCKET=/caminho.sock`, `OCUDU_MACSEC_TX_SCI`, `OCUDU_MACSEC_RX_SCI`
(16 hex), `OCUDU_MACSEC_TX_SSCI` (1), `OCUDU_MACSEC_RX_SSCI` (2), `OCUDU_MACSEC_REPLAY_WINDOW` (64).
O gNB precisa do `hal: eal_args` com `--vdev=crypto_aesni_gcm0` (ou um cryptodev real) e do `mtu` do
`ru_ofh` compatível com o dispositivo (+32 B de MACsec). Sem chave instalada nada é transmitido.

## Teste
`scripts/testbed/e1-ocudu.sh` (sem root): gNB ⇄ gateway DPDK ⇄ `ru_emulator`, chaves pelos sockets.

## Defeito aberto (importante)
Na última execução completa: plano de controle OK nas duas pontas; o gateway verificou 25.357 quadros do
gNB e o gNB verificou os 6.408 de uplink, mas o gateway registrou **`auth=132.854`** (~84% dos quadros do gNB
falham na autenticação). Causa **desconhecida**; é intermitente, então não é chave errada. Hipóteses não
testadas: concorrência entre threads de TX (sessão/PN/fila do cryptodev), ou dependência do tamanho do quadro.
`tools/verify_pcap.c` verifica um pcap quadro a quadro para isolar o padrão. A última tentativa de captura
(`CAPTURE=1`) não produziu dados, então o diagnóstico não foi concluído. Não usar como validação do E1.
