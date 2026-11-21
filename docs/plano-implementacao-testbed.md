# Plano de implementação — MACsec-PQC no Open Fronthaul (OpenRAN@Brasil)

Base: repositório `macsec_fronthaul` (commit `f7f6aa1`) + documento "MACsec com chaves pós-quânticas no Open Fronthaul" (branch `macsec_pqc`, 20/11/2026, enviado por Murilo).

Etiquetas: **[CONFIRMADO]** lido no repositório ou no documento · **[PROPOSTA]** decisão de projeto · **[ESTIMATIVA]** prazo meu, não medido · **[A CONFIRMAR]** depende da RNP ou de verificação · **[REFERÊNCIA]** conhecimento de padrão/biblioteca a conferir na fonte.

---

## 0. Premissas (tratadas como fatos, por vindas do Murilo, operador do testbed)

- Nenhuma O-RU (Benetel RAN550, LiteOn FlexFi) termina MACsec; a FPGA termina o C/U-Plane e o Linux do ARM não o vê. Os ToRs ArcOS não têm MACsec no ASIC.
- Topologia: SecY A dentro do OCUDU (host oran-cloud4, VF X710 em DPDK) ⇄ ToR-D01 ⇄ Tor-RR ⇄ gateway DPDK de duas portas (SecY B, oran-cloud5, portas E810) ⇄ Tor-RR ⇄ O-RU. Só o trecho Tor-RR → O-RU fica em claro.
- VLAN "black" (cifrada) 2161–2163; VLAN "red" (da RU) 161–163. A tag 802.1Q fica **fora** do MACsec; DA e SA são preservados.
- Payload do OFH até 8950 B (ToRs levam 9000 B sem FCS). EAPOL do MKA só atravessa os ToRs em unicast.
- Uma RU por vez (enlace de 10 Gb/s entre os ToRs). Margem de uplink na LiteOn: cerca de 70 µs (chega até ~430 µs contra `ta4_max` 500 µs). Atraso adicional estimado pelo documento: 10–20 µs por sentido, a medir.
- Chaves: MKA (802.1X-2020), CAK de EAP-TLS 1.3 com X25519MLKEM768 e certificados ML-DSA-65. Primeiro passo permitido pelo documento: MKA com CAK pré-compartilhada entregue por canal pós-quântico.
- OCUDU pode ser modificado; **eu faço a SecY no OCUDU (item 4)**.

## 1. Onde o repositório está hoje e para onde vai

| Hoje [CONFIRMADO] | Problema para o novo plano | Destino [PROPOSTA] |
|---|---|---|
| `src/macsec/macsec.c` (559 linhas): XPN-256, SCI sempre presente (SecTAG de 16 B, +32 B), SecTAG logo após DA/SA, AAD contíguo `frame[0..27]` | A VLAN ficaria **dentro** do payload cifrado (`docs/macsec-profile.md`); os ToRs não veriam a VID. Só existe XPN; o KaY do hostap pode não ter XPN | Núcleo `secy` sem dependência de DPDK: SecTAG depois da tag de VLAN, AAD = DA‖SA‖SecTAG montado em buffer pequeno, SCI opcional (SecTAG de 8 B), GCM-AES-256 (PN 32 bits) **e** XPN, offset de confidencialidade 0 (30 opcional) |
| `apps/dpdk/main.c` (1437 linhas): 2 portas plain/secure, pipeline RX → `rte_ring` → crypto → `rte_ring` → TX, 3 lcores, `RTE_MBUF_DEFAULT_BUF_SIZE` (2176 B) | Dois anéis e 3 lcores por endpoint somam salto e jitter; o pool de mbufs não comporta quadros de 9000 B | Gateway B run-to-completion: 1 lcore por sentido, troca de VLAN, EAPOL → TAP, pool de mbufs para MTU 9000+, modo `--no-crypto` (E0) |
| `src/keying/tls_keying.c` (618): TLS 1.3 X25519MLKEM768 + ML-DSA-65, EKM + HKDF, chaves direcionais, papéis `du`/`ru`, TCP | MKA distribui **uma SAK** por CAK/CKN, com SCs por SCI; não há chaves direcionais por HKDF | Agente PQC passa a produzir **CAK/CKN** a partir do EKM (fase 1 do documento) e entregá-los ao wpa_supplicant das duas pontas |
| `src/keying/key_control.c` + `keyctl.c`: socket SEQPACKET (`INSTALL`/`ACTIVATE`/`RETIRE`/`STATUS`), mensagem de 96 B com tx/rx key e salt | Não carrega SCI, SSCI, PN inicial nem "enable" por SA, que o driver do hostap precisa | Protocolo v2 (SCI, SSCI, PN, AN, enable/disable, PN corrente); **mesmo socket nas duas pontas** (gateway e OCUDU) |
| Instalação de SA em `main()`: espera `crypto_ring` vazio e `worker_busy` falso antes de sobrescrever | Esse drenar bloqueia; não serve na thread de TX do OCUDU | SA em slots duplos com troca atômica (padrão `active_tx_an` + `rx_valid` que já existe) e liberação adiada por época |
| `tests/unit` (macsec, key_control), `scripts/` de PCAP/eCPRI/VM, `vm/`, `docs/two-vm-prerequisites.md`, `Plano_Implementacao_PoC_Simulacao.docx` | Cenário de duas VMs deixa de ser o alvo | PCAP/eCPRI viram testes de regressão; `vm/` e plano antigo vão para `legacy/` |

Estrutura-alvo do repositório [PROPOSTA]:

```
include/        macsec.h (núcleo SecY), key_control.h (v2)
src/secy/       núcleo C, sem DPDK  (de src/macsec)
src/keying/     agente PQC; ponte CAK/CKN → wpa_supplicant
apps/gateway/   gateway B (DPDK)    (de apps/dpdk)
ocudu/          patch/lib da SecY para lib/ofh/ethernet + wrapper C++
hostap/         driver_macsec_ocudu.c + patches
tests/          unit/, vectors/, interop/ (netns + MACsec do kernel)
scripts/        testbed/ (E-1, E0, E1, E2, E3), análise
docs/           perfil, pipeline, este plano, relatório
legacy/         vm/, scripts de VM, plano antigo
```

## 2. Fases

Prazos em dias de trabalho focado **[ESTIMATIVA]**, sem folga para imprevistos. O alvo de submissão é janeiro; as fases F0–F4 e F6 são o caminho mínimo para ter números.

### F0 — Preparação (1–2 dias)
- Clonar de novo o `macsec_fronthaul` e o OCUDU; compilar DPDK 26.07 (versão que o testbed usa **[A CONFIRMAR]**), Intel IPsec-MB, hostap com MKA/MACsec, OpenSSL ≥ 3.5.
- Reexecutar no notebook o teste de `port_init` com a DPDK 26.07 (pendente desde antes).
- Ler `lib/ofh/ethernet` do OCUDU (transmitter, receiver, `frame_builder`, `vlan_frame_decoder`) para fixar os pontos de gancho da F4.
- Pedir ao Murilo: `ROADMAP.md`, acesso à branch `macsec_pqc` e versão/imagem do OCUDU e do DPDK. (O emulador de RU **existe no código do OCUDU**: ver seção 7.)
- **Aceite:** ambiente compila; lista dos pontos de gancho do OCUDU escrita.

### F1 — Núcleo SecY (3–5 dias)
- Novo layout de quadro: `DA SA [802.1Q] 88E5 SecTAG … ICV`; AAD montado em buffer (DA‖SA‖SecTAG), já que a tag de VLAN fica no meio. O backend AEAD (`macsec_aead_backend_fn`) e o espaço de AAD do cryptodev (`CRYPTO_AAD_OFFSET`, 32 B) comportam isso.
- SCI opcional; GCM-AES-256 com PN de 32 bits (nonce SCI‖PN) além do XPN atual; teste do salto de PN.
- Vetores do IEEE 802.1AE-2018 Annex C, se disponíveis **[REFERÊNCIA]**; testes negativos: ICV adulterado, replay, chave errada, AN desconhecido.
- Interoperabilidade com o MACsec do kernel Linux em namespaces (`veth`, dispositivo `macsec` sobre interface VLAN), nos dois sentidos. Confirmar que o kernel do notebook aceita `gcm-aes-xpn-256` **[A CONFIRMAR]**.
- **Aceite:** quadros do núcleo são aceitos pelo kernel e vice-versa; testes negativos passam.

### F2 — Gateway B (5–7 dias)
- Run-to-completion: lcore DL (RX black → verifica → troca VLAN 216x→16x → TX red) e lcore UL (inverso). Sem `rte_ring` no caminho de dados.
- DA/SA intactos; promiscuous ligado (a RU filtra pelo MAC da DU); sem strip de VLAN por offload; mapa de VLAN por argumento.
- Quadros `0x888E` vão para um TAP (`net_tap`) e voltam; reescrita do DA de grupo `01:80:C2:00:00:03` ↔ MAC unicast do par no gateway, para não exigir patch no hostap **[PROPOSTA, a validar]**.
- Pool de mbufs com data room ≥ 9000 + overhead + headroom (lição do teste anterior com virtio: os 2176 B padrão não bastam) e MTU configurável.
- Histograma de latência TSC e contadores por SA já existem no `main.c`; manter. Modo `--no-crypto` (só troca de VLAN) para o E0.
- **Aceite:** em netns com `veth`/TAP, tráfego sintético 128 B–9000 B passa nos dois sentidos, sem perdas; E0 e E1 medidos no notebook como custo **relativo**.

### F3 — Chaves, fase 1: MKA com CAK entregue por canal PQC (4–6 dias)
- Validar primeiro a configuração do MKA sem o nosso código: wpa_supplicant nos dois lados, em PSK, contra o MACsec do kernel.
- Driver `driver_macsec_ocudu.c` no hostap, implementando a interface `macsec_ops` (SC/SA de TX e RX, enable/disable, PN) e traduzindo para o socket de controle v2 **[REFERÊNCIA: conferir a lista exata na árvore do hostap]**.
- Agente PQC: após o handshake X25519MLKEM768 + ML-DSA-65, deriva CAK (256 bits) e CKN do EKM e os instala no wpa_supplicant (ctrl_iface) nas duas pontas.
- Rekey por MKA (nova SAK por limiar de PN ou tempo); a nossa lógica de duas fases (`INSTALL`/`ACTIVATE`) vira consequência do driver.
- XPN no KaY: o documento trata como contribuição futura. Fase 1 roda em GCM-AES-256 (PN 32 bits) com rekey antes de esgotar o PN; XPN fica para depois.
- **Aceite:** MKA sobe entre dois wpa_supplicant e o gateway; rekey sem perda em teste de ping contínuo; sem MKA, o dataplane não transmite.

### F4 — SecY no OCUDU (7–10 dias; maior risco) — **responsável: você**
- Módulo C++ em `lib/ofh/ethernet/macsec/` com o núcleo da F1 por trás de interface fina (`extern "C"` ou reescrita mínima).
- TX: proteger **depois** do `frame_builder` e **antes** do `transmitter::send()`, in-place; o builder reserva a folga para a SecTAG depois da tag de VLAN e o tailroom do ICV.
- RX: verificar antes do `vlan_frame_decoder`; `0x888E` segue para um TAP.
- Cripto em burst, sem alocação e sem lock nas threads de TX/RX existentes; troca de SA atômica (slots duplos, sem drenar fila).
- Socket de controle em thread fora do tempo real, reaproveitando `key_control.c` v2 e o mesmo driver do hostap.
- Opções de configuração em `ru_ofh` (ligar/desligar, SCI, VLAN, cipher suite) e conta de `+24/+32 B` e do limite de 8950 B no MTU.
- Imagem própria do OCUDU em repositório público (sem segredos) **[A CONFIRMAR com a RNP]**.
- Validação sem RU real: testes de unidade da SecY e injeção de quadros contra o gateway; e o `ru_emulator` do OCUDU (`apps/examples/ofh`) do lado red, em claro, com o gateway no meio (seção 7). Falta saber se o gNB roda no notebook **[A CONFIRMAR]**.
- **Aceite:** OCUDU modificado compila na versão do testbed; com a opção desligada, o tráfego é bit a bit idêntico ao original; com ela ligada, os quadros são aceitos pelo gateway.

### F5 — EAP-TLS 1.3 pós-quântico (opcional, depois dos números; 5–8 dias)
- hostapd (authenticator + EAP server interno) no gateway, wpa_supplicant no OCUDU, certificados ML-DSA-65 e raiz ML-DSA-87 emitidos por CA do testbed, OpenSSL ≥ 3.5, fragmentação EAPOL.
- Contribuição de XPN no KaY (hoje não prevista no hostap, segundo o documento).
- Fora do caminho mínimo para janeiro.

### F6 — Testbed e experimentos (janela a definir pela RNP)
- Entregáveis: imagem do OCUDU modificado, imagem do gateway, charts/manifests com hugepages, CPU pinning NUMA-local, VF para o OCUDU e portas E810 para o gateway, e a VPN do testbed.
- Experimentos: **E-1** (OCUDU direto, sem gateway) · **E0** (gateway só com troca de VLAN, sem cifra) · **E1** (MACsec ativo) · **E2** (rekey sob tráfego) · **E3** (variação de carga/UEs) · **E4** (UE real). O E0 separa o custo do salto extra do custo da cifra.
- Métricas: avisos de pacotes cedo/tarde no log do OCUDU contra as janelas (margem de uplink ~70 µs na LiteOn), histograma e jitter do gateway, CPU por lcore, perdas.
- **E5** (replay, ICV adulterado, chave errada) só com autorização por escrito (Termo, item 8.7), com quadros sintéticos e sem tocar nas O-RUs.

## 3. Ordem de execução e dependências

```
F0 ─► F1 ─► F2 ─► F3 ─┐
        └────────────► F4 ─► F6
                       F5 (depois)
```
F4 depende da F1 (núcleo) e da F3 (driver/protocolo v2). F2 e F4 podem andar em paralelo depois da F1. Tudo até a F4 roda no notebook (i5-1335U, 16 GB), sem RU.

## 4. O que o notebook não prova

Latência e jitter em números absolutos, comportamento do ArcOS (EAPOL de grupo, VLANs 216x, MTU 9000), PMDs X710/E810 e a interação com a RU. Os resultados locais são de **custo relativo e correção**, não de desempenho do fronthaul (regra já adotada no projeto).

## 5. Riscos

1. **Tempo real no TX do OCUDU (F4).** Não li ainda o caminho de TX; se o OCUDU enviar muitos quadros pequenos ou cópias extras, o custo por quadro muda. *Mitigação:* F0 de leitura antes de comprometer prazo.
2. **MKA com PQC.** O hostap pode não ter XPN; o EAP-TLS com ML-KEM/ML-DSA depende de OpenSSL ≥ 3.5 e da integração com o EAP. *Mitigação:* fase 1 com CAK pré-compartilhada e GCM-AES-256.
3. **Janelas.** Margem de ~70 µs no uplink e 10–20 µs estimados por sentido; o jitter do gateway pode importar mais que a média.
4. **Dependências da RNP:** VLANs 216x, MTU, EAPOL, janela de experimento, autorização do Termo, imagem pública.
5. **Prazo.** Janeiro é apertado para F0–F4 + F6; F5 e XPN no KaY ficam como trabalho futuro.
6. **Escopo do Termo/Proposta.** O plano aprovado descreve A→B no host da DU; o gateway no oran-cloud5 e a alteração do OCUDU precisam estar cobertos (a conferir na revisão da proposta).

## 6. Decisões pendentes

- Aceitar GCM-AES-256 (PN 32 bits) na fase 1 e deixar XPN para depois?
- Qual ponte de chaves na fase 1: CAK/CKN pelo nosso canal TLS PQC, ou outro canal PQC (por exemplo OpenSSH `mlkem768x25519-sha256`, como cita o documento)?
- ~~O Murilo tem emulador de RU para a F4?~~ Resolvido: há um `ru_emulator` no código do OCUDU (seção 7). Resta confirmar se o gNB roda no notebook e se a versão do OCUDU da testbed o inclui.
- Versão exata do OCUDU/DPDK do testbed e política de imagem pública.

## 7. Achados da leitura do OCUDU (21/11/2026) [CONFIRMADO: lido e compilado]

Repositório `gitlab.com/ocudu/ocudu`, commit `698c4a5` (20/11/2026, versão 26.10.0). Clone em `~/opt/src/ocudu-src/repo`; build em `~/opt/src/ocudu-src/build`.

**RU emulator.** `apps/examples/ofh/ru_emulator*`. Recebe C/U-Plane do DU, confere janelas T2a (DL C-Plane, UL C-Plane, DL U-Plane) e sequence ID, e responde ao C-Plane de uplink com U-Plane sintético (IQ e PRACH formatos 0 e B4). Configura-se por `ru_mac_addr`, `du_mac_addr`, `vlan_tag` (TCI inteiro), promiscuous, portas e compressão. Transceiver por socket (AF_PACKET) ou DPDK (`--eal_args`, aceita `--vdev`). Só filtra o EtherType eCPRI; não confere o MAC de destino, então funciona atrás do gateway (DA/SA preservados). O `lib/ru/dummy` **não serve**: é um RU dentro do DU, sem Ethernet.
- Compilou, sem alterar código nem gerar avisos, contra a DPDK 26.07 (`-DENABLE_DPDK=ON`, GCC 16.2.1, yaml-cpp 0.9.0 compilado à parte; `ENABLE_WERROR=OFF`, `DISABLE_MBEDTLS`, `DISABLE_SCTP`). Teste de fumaça em `veth`: abre a interface e fica aguardando pacotes.
- Sem privilégio de tempo real o worker de timing reclama de "woke up late": para as estatísticas on-time/early/late valerem, precisa de RT e núcleo isolado.
- **Não valida a margem de uplink (~70 µs)**: não há modelagem de ta4/atraso; responde ao C-Plane de UL assim que o recebe [HIPÓTESE: o DU pode contá-las como "early"]. Valida correção do caminho e as janelas de DL.

**Ganchos para a F4 (DPDK).**
- **TX** `lib/ofh/ethernet/dpdk/dpdk_ethernet_transmitter.cpp`: `send()` aloca o mbuf, faz `memcpy` e chama `rte_eth_tx_burst`. O SecTAG pode entrar nesse `memcpy` (copiar DA/SA/VLAN, deixar 16 B, copiar o resto), com cryptodev em burst antes do `tx_burst`: sem cópia extra.
- **RX** `dpdk_ethernet_receiver.cpp`: após `rte_eth_rx_burst`, cada mbuf passa por `rte_vlan_strip` **por software** e vai ao decoder, que assume quadro sem tag ("VLAN parameters are stripped by the NIC"). A verificação entra logo ali, em burst. Isso confirma a decisão da L2 (VLAN fora do AAD): com a tag dentro do protegido a verificação falharia.
- `MAX_BURST_SIZE = 64`; builder em `vlan_ethernet_frame_builder_impl.cpp`.

**Pontos de atenção.**
1. mbuf de `MAX_ETH_FRAME_LENGTH (9600) + 14 + 4`: precisa de +32 B (SecTAG e ICV), e 9600 difere do limite de 9000 dos ToRs.
2. O decoder descarta quadros < 64 B (`MIN_ETH_LEN`); depois de remover SecTAG e ICV um C-Plane curto pode cair abaixo disso. A conferir (FCS, re-padding).
3. O receiver por socket filtra `ETH_P_ECPRI`: quadros `0x88E5` não chegam. Só o modo DPDK serve para a F4.
4. [HIPÓTESE] filas do cryptodev não são thread-safe: TX e RX do OCUDU precisarão de filas distintas.
5. **gNB no notebook: viável [CONFIRMADO].** `gnb_split_7_2` compilado (17 min, `-j8`, 6 avisos do GCC 16; exigiu compilar `mbedtls` 2.28.10 e `lksctp-tools` 1.0.21 à parte, porque o `apps/` só é construído com SCTP e mbedtls). Teste de fumaça (`scripts/testbed/ocudu-smoke.sh`, user namespace + `veth`, modo socket, **sem root nem tempo real**, célula n78 de 20 MHz 2T2R, `no_core`): em 25 s o emulador recebeu 241.734 quadros (0 corrompidos, 0 descartados, 0 erros de sequência) e enviou 56.376 de U-Plane de uplink, que o gNB recebeu. Sem RT o timing é ruim (DL U-Plane 66% on-time; UL C-Plane 50% on-time, 35% early, 14% late) e o gNB registrou 24 mensagens "no uplink PRACH context" e 1 "missed PRACH". Os early de UL são coerentes com a HIPÓTESE do item acima (o emulador responde ao C-Plane de UL imediatamente). Ainda **não testado**: o modo DPDK (`--vdev`) e o gateway no meio. Dois ajustes de configuração que mordem: `prach_format: short` no emulador para `prach_config_index 159` (B4), e `iq_scaling`/`enable_*_static_compr_hdr` obrigatórios no gNB.

