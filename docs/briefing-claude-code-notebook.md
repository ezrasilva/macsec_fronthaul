# Briefing para o Claude Code (notebook) — validação local do caminho rápido

Leia primeiro `docs/plano-implementacao-testbed.md` (seções 0, 1 e 3b) e `docs/macsec-profile.md`. Este arquivo diz **o que executar agora, em ordem**, e como reportar.

## Contexto em 5 linhas
- PoC `macsec_fronthaul`: MACsec em software sobre DPDK (GCM-AES-XPN-256, SCI explícito) com keying TLS 1.3 X25519MLKEM768 + ML-DSA-65 (EKM/HKDF) e socket de controle (`INSTALL`/`ACTIVATE`/`RETIRE`).
- Alvo: gateway DPDK de 2 portas (black cifrada, VLAN 2161–2163 ↔ red em claro, VLAN 161–163) no testbed OpenRAN@Brasil. A tag 802.1Q fica **fora** do MACsec; DA e SA ficam intactos; payload do OFH ≤ 8950 B.
- Testbed usa a DPDK 26.x (a última). Meta: rodar o quanto antes; otimizações ficam para depois.
- Notebook: i5-1335U (2 P-cores + 8 E-cores), 16 GB RAM, Arch Linux. Fixe lcores nos P-cores; resultados daqui valem para **correção e custo relativo**, nunca como desempenho do fronthaul.
- Sem root não há hugepages/namespaces; peça ao usuário o comando exato para cada passo que precisar de root.

## Regras
- Não inventar capacidades nem resultados. Marque cada afirmação como CONFIRMADO (você viu rodar), HIPÓTESE ou A CONFIRMAR.
- Não mexa em `legacy/`, no perfil documentado ou em testes existentes sem dizer antes; mudanças no perfil exigem novos vetores de teste e novo `docs/macsec-profile.md`.
- Um commit por tarefa, mensagem curta; não faça push sem pedir.
- Se um passo falhar duas vezes, pare e reporte o erro exato em vez de tentar variações.
- Os comandos abaixo são esboços do que se pretende; confira a sintaxe com `--help` na sua versão de `iproute2`/DPDK antes de rodar.

## Tarefas (em ordem; só avance se o aceite passar)

### L0 — Ambiente (aceite: tudo listado com versão)
1. Versão do kernel e `modinfo macsec` (módulo presente? `CONFIG_MACSEC`).
2. DPDK 26.x: compilar (ou confirmar instalada) e anotar a versão exata; `pkg-config --modversion libdpdk`.
3. `crypto_aesni_gcm` disponível? (`dpdk-testpmd --vdev crypto_aesni_gcm0 ...` ou `dpdk-test-crypto-perf --help`); dependência Intel IPsec-MB/ISA-L.
4. OpenSSL ≥ 3.5 (`openssl version`; `openssl list -kem-algorithms | grep -i mlkem`).
5. Hugepages disponíveis (reserve ~1 GB), `ip -V`, `meson`, `ninja`.
6. Rodar `meson setup build && ninja -C build && meson test -C build` no repositório e reportar o resultado **antes de qualquer mudança**.

### L1 — Linha de base com o MACsec do kernel (sem código nosso)
Dois namespaces ligados por `veth`, com VLAN e `macsec` do kernel empilhado sobre a VLAN, nos dois lados. Objetivo: ter o quadro de referência (pcap) que a nossa SecY deve reproduzir.
- Esboço: `ip netns add a`/`b`; `ip link add va type veth peer name vb`; subinterface `va.2161` com MTU 9000; `ip link add link va.2161 macsec0 type macsec sci <SCI> encrypt on cipher gcm-aes-xpn-256` (se o kernel recusar XPN, usar `gcm-aes-256` e anotar); `ip macsec add macsec0 tx sa 0 pn 1 on key 00 <64 hex>` (XPN pede também salt e ssci: ver `ip macsec help`); `ip macsec add macsec0 rx sci <SCI_peer> on` + `... rx sci <SCI_peer> sa 0 pn 1 on key 00 <64 hex>` (idem no outro lado).
- **Aceite:** `ping -s 8000` passa nos dois sentidos; `tcpdump -nn -e -i va` mostra `DA SA 802.1Q(vid 2161) ethertype 0x88e5` com SecTAG logo depois da tag de VLAN; salvar `baseline-kernel.pcap`.

### L2 — Núcleo SecY nosso contra o kernel (mudança em `macsec.c`)
- Alterar o layout: **SecTAG depois da tag 802.1Q**; AAD = DA‖SA‖SecTAG (a VLAN fica fora do AAD e do ICV), montado em buffer pequeno (o cryptodev já reserva `CRYPTO_AAD_OFFSET`, 32 B). Manter XPN e SCI explícito.
- Teste de unidade novo: proteger um quadro com VLAN e comparar byte a byte com o do `baseline-kernel.pcap` (mesma chave/PN/SCI/salt/ssci), e o inverso (verificar um quadro do kernel).
- Testes negativos: ICV adulterado, replay, chave errada, AN desconhecido, quadro sem VLAN.
- **Aceite:** unit tests passam; quadros nossos são aceitos pelo kernel e os do kernel pelos nossos (teste com os dois lados, ver `ip -s macsec show`).

### L3 — Gateway em namespaces (mudança em `apps/dpdk/main.c`)
- Opções novas: mapa de VLAN (`--vlan-map 2161:161`), promiscuous ligado, MTU e pool de mbufs para ≥ 9000 B (o pool atual é `RTE_MBUF_DEFAULT_BUF_SIZE` = 2176 B e **não** comporta; com virtio o data room precisa de MTU+30+headroom, achado anterior: 9374 para MTU 9216), `--no-crypto` (só troca de VLAN, para o E0).
- Manter o pipeline atual de 3 lcores nesta etapa. Sem EAPOL, sem TAP, sem MKA.
- Portas DPDK: `net_af_packet` ou `net_tap` sobre `veth` nos namespaces (a escolher; reportar o que funcionou).
- **Aceite (CONFIRMADO só se você rodar):** tráfego de 128 B a 8950 B passa nos dois sentidos em `--no-crypto` (E0) e com cifra (E1), sem perdas (`ring_drop=0`, `tx_drops=0`); contadores por SA e histograma de latência saem no final; quadros de 8951–9000 B são tratados de forma definida (descartados e contados, ou erro explícito).

### L4 — Rekey e chaves (reaproveitar o que existe)
- Rodar o agente PQC atual contra o gateway em namespaces (`scripts/negotiate-vm-keys.sh` como referência) e fazer rekey sob ping contínuo.
- **Aceite:** 0 perda no rekey; mesma verificação feita nas VMs, agora nos namespaces.

### L5 — Medição local relativa
- E0 (`--no-crypto`) vs E1 (cifra) com carga sintética em P-cores fixados: pps, latência p50/p95/p99, jitter, CPU por lcore.
- **Reportar como custo relativo no notebook**, com a CPU e o kernel; não comparar com as janelas do OFH.

## O que ainda **não** faça
SecY dentro do OCUDU, MKA, EAP-TLS, run-to-completion e qualquer execução em hardware do testbed. Essas ficam para depois dos primeiros números (ver seção 3b do plano).

## Formato do relatório por tarefa
`Tarefa · o que foi feito · comandos rodados · resultado (CONFIRMADO/HIPÓTESE) · erros e correções · arquivos alterados · próximo passo`.
