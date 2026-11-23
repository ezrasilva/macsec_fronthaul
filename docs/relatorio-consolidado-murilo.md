# MACsec-PQC no Open Fronthaul — relatório consolidado da validação local

Data: 21/11/2026 · Base: repositório `macsec_fronthaul` (commit inicial `f7f6aa1`; trabalho em `f50c4e7`…`f146b9c`) · Plano: `docs/plano-implementacao-testbed.md`

Marcação: **CONFIRMADO** = rodou e foi observado · **HIPÓTESE** = explicação provável, não testada · **A DECIDIR / A CONFIRMAR** = depende de você ou da RNP.

## 1. Resumo

Validamos no notebook, sem RU e sem a testbed, o caminho de dados e de chaves do gateway B do plano. O gateway DPDK de duas portas protege e verifica MACsec (GCM-AES-XPN-256) com a **tag 802.1Q fora do MACsec**, troca a VLAN black↔red, e interopera nos dois sentidos com o MACsec do kernel Linux. As chaves vêm do agente TLS 1.3 `X25519MLKEM768` + `ML-DSA-65`, com **rekey sem perda de pacotes** sob ping contínuo.

Isso prova **correção e custo relativo**. **Não prova** latência absoluta, comportamento do ArcOS, os PMDs X710/E810 nem a interação com a RU. Também **não existe ainda** a SecY dentro do OCUDU (F4), o MKA (F3) nem o EAP-TLS (F5): o par DU dos testes é o MACsec do kernel.

## 2. O que foi feito e o que foi observado

| Etapa | Resultado (CONFIRMADO) |
|---|---|
| **Ambiente** | DPDK 26.07, Intel IPsec-MB 2.0.3, OpenSSL 3.6.5 (ML-KEM e ML-DSA nativos), kernel 7.2.14 aceita `gcm-aes-xpn-256`. Testes unitários e build passam. |
| **L1 — referência do kernel** | Quadro real: `DA SA 802.1Q(2161) 88e5 SecTAG…`, SecTAG logo após a VLAN, 8078 B no fio para ICMP de 8000 B. |
| **L2 — núcleo SecY** | Novo layout: SecTAG depois da VLAN; AAD de 28 B montado em buffer próprio. A SecY **reproduz byte a byte** dois quadros reais do kernel (um por sentido) e verifica os do kernel. Interop ao vivo nos dois sentidos (100, 1400 e 8000 B). Testes negativos: ICV, ciphertext, PN, DA adulterados; chave, salt, SSCI, AN e SCI errados; truncamentos; replay. Trocar a VID 2161→161 no quadro cifrado continua autenticando, que é o requisito da troca de VLAN. |
| **L3 — gateway em namespaces** | `--vlan-map`, `--no-crypto` (E0), `--mtu`. Pings de IP 100 a 8950 B nos dois sentidos com **0% de perda** em E0 e E1; 8951 B é descartado e contado (`oversize`). Contadores zerados (`ring/tx/alloc/vlan_drop`, `auth/replay/format`). |
| **L4 — chaves PQC e rekey** | Handshake `X25519MLKEM768` + `ML-DSA-65` em **49–54 ms**. 3 rekeys (AN 0→1→2→3) sob dois pings contínuos: **900/900** (100 B) e **360/360** (IP 8950 B), 0% de perda. Kernel: `InPktsOK=1270` igual ao `protected=1270` do gateway, `InPktsInvalid/NotValid=0`. Sem chave, nada passa (100% de perda). Lado black: 19603 quadros capturados, **0 fora de MACsec**. |
| **L5 — medição relativa** | Ver seção 3. |

Limites de tamanho: `--mtu 8950` leva o quadro black a 9000 B sem FCS (N+50). O gateway descarta e conta o que passaria disso.

## 3. Desempenho local (relativo, notebook i5-1335U)

Cores do gateway `0,2,4` (2 P-cores físicos + 1 E-core), governor `powersave`, `veth` + `net_af_packet`, offloads desligados nos três modos. **Não comparar com as janelas do OFH.**

**Latência de software no gateway, carga leve (50 Mb/s), µs** (do RX ao TX; histograma de 1 µs):

| IP | E0 p50 / p99 | E1 p50 / p99 |
|---|---|---|
| 128 B | 1 / 21–23 | 1 / 10–26 |
| 1500 B | 1 / 1–6 | 2 / 5–10 |
| 8950 B | 1 / 1–2 | 4 / 7–8 |

A cripto acrescenta ~1–3 µs (p50) e até ~6 µs (p99) por sentido a 8950 B. **Cauda:** mesmo com carga leve o `max` chegou a 570–650 µs (128 B), por ruído de SO em cores não isolados. Contra a margem de ~70 µs do uplink isso importa (seção 5).

**Vazão máxima (UDP `-b 0`, Mb/s):** a 8950 B, E-1 (sem gateway) 8671/8143, E0 7700/7242, E1 3880/4791 (UL/DL). Tabelas completas e RTT em `docs/l5-local-bench.md`.

**Ressalvas de interpretação:**
- **A vazão do E1 não isola a cripto do gateway** (HIPÓTESE forte): o MACsec do kernel na DU cifra/decifra no mesmo caminho do teste. O lcore de cripto do gateway ficou só em 8–15% ocupado.
- **O E-1 não é piso de latência**: seu RTT (90 µs) é maior que o do E0 (46 µs). Hipótese: o polling do gateway mantém os cores acordados.
- Extrapolação linear (HIPÓTESE): ~35–38 Gb/s a 8950 B e ~2 Mpps a 128 B por lcore de cripto.
- **Estimativa do documento (10–20 µs por sentido): o que medimos é só a parte de software do gateway.** Não inclui NIC, ToR nem O-RU.

## 4. O que ainda não existe

- **Núcleo SecY (F1), itens do plano não feitos:** GCM-AES-256 com PN de 32 bits (só há XPN), SCI opcional (hoje sempre explícito, SecTAG de 16 B), vetores do 802.1AE Annex C. **Isso importa para a fase 1 do MKA**, se o KaY do hostap não suportar XPN.
- **Gateway (F2):** run-to-completion, EAPOL→TAP e reescrita do DA de grupo. O gateway ainda usa o pipeline de 3 lcores com `rte_ring`.
- **MKA (F3) e driver do hostap:** não iniciados. O `kernel-control.py` faz, para o kernel, o papel que o driver teria (mesmo protocolo de 96 B do gateway). A ponte CAK/CKN ainda não existe: o agente atual entrega chaves direcionais por EKM+HKDF, não CAK/CKN.
- **SecY no OCUDU (F4):** não iniciada. Ganchos achados no código (commit `698c4a5`): no TX, o `send()` do transmitter DPDK já copia cada quadro para um mbuf antes do `tx_burst`, e o SecTAG entra nessa cópia; no RX, a verificação entra após o `rte_eth_rx_burst`, antes do `rte_vlan_strip` por software. Isso confirma a VLAN fora do AAD. Precisa de mbuf +32 B, atenção a quadros < 64 B após a verificação, e só o modo DPDK serve (o receiver por socket filtra `ETH_P_ECPRI`). Detalhes em `docs/plano-implementacao-testbed.md`, seção 7. O `INSTALL` do gateway **drena o pipeline** (bloqueante). Serve no gateway, **não na thread de TX do OCUDU**, que exigirá SA em slots duplos com troca atômica.
- **Rekey:** é disparado por fora, executando o agente de novo (um handshake por rekey). Não há gatilho automático por limiar de PN ou tempo. O `RETIRE` foi testado só com carência de 2 s.
- **E5 (replay, ICV adulterado, chave errada no gateway):** não executado. Só com autorização por escrito (Termo, item 8.7), quadros sintéticos e sem tocar nas O-RUs. A PKI é de laboratório.

## 5. Riscos e o que a testbed precisa

1. **Jitter/cauda.** `max` de centenas de µs em carga leve exige, na testbed: CPUs isoladas (`isolcpus`/`nohz_full`), governor `performance`, lcores em núcleos físicos distintos (sem irmãos de hyperthread) e NUMA-local.
2. **IPsec-MB.** A série **3.0.x é incompatível** com o driver `ipsec_mb` do DPDK 26.07 (`IMB_MGR` opaco); usamos a 2.0.3. Qual versão a testbed tem?
3. **Dependência da RNP:** VLANs 216x nos ToRs, MTU 9000, EAPOL em unicast, janela de experimento, imagem pública do OCUDU, escopo do Termo (gateway no oran-cloud5 e alteração do OCUDU).
4. **O emulador de RU não mede a margem de uplink:** responde ao C-Plane de UL assim que o recebe, sem modelar ta4 (HIPÓTESE: o DU pode contar as respostas como "early"). Os ~70 µs só se validam com a RU real.
5. **Prazo.** Pelas estimativas do plano (não medidas): F3 4–6 dias, F4 7–10 dias (maior risco), F6 na janela da RNP. Janeiro é apertado para F0–F4 + F6.

## 6. Decisões e pedidos (A DECIDIR / A CONFIRMAR)

1. **Fase 1 do MKA:** aceitar GCM-AES-256 (PN 32 bits) com rekey antes de esgotar o PN e deixar XPN no KaY para depois, ou exigir XPN? O gateway e o kernel já falam XPN.
2. **Ponte de chaves na fase 1:** CAK/CKN pelo nosso canal TLS PQC ou outro canal PQC (por exemplo, OpenSSH `mlkem768x25519-sha256`)?
3. **Emulador de RU:** há um `ru_emulator` no código do OCUDU (`apps/examples/ofh`; compilado aqui contra a DPDK 26.07). O gNB `gnb_split_7_2` também compilou e fala OFH com ele por `veth` no notebook, sem root, com 0 quadros corrompidos em 241 mil (timing ruim sem tempo real). A versão do OCUDU da testbed o inclui? Ele serve para a F4 sem hardware, mas **não valida a margem de uplink** (seção 4).
4. **Versões exatas** do OCUDU, DPDK e IPsec-MB da testbed, e política de imagem pública (sem segredos).
5. **Acesso:** `ROADMAP.md` e a branch `macsec_pqc`.
6. **Experimentos prévios** sem MACsec, para medir o caminho real: E-1 (OCUDU direto) e E0 (gateway só com troca de VLAN), que separam o custo do salto extra do custo da cifra. E confirmar nos ToRs: EAPOL unicast, VLAN 2161–2163 e MTU 9000.
7. **Autorização** do E5 por escrito.

## 7. Como reproduzir

Os scripts estão em `scripts/testbed/`. Sem root: `ninja -C build && meson test -C build`, `l2-pcap-regression.sh`, `l3-pcap-checks.sh`, `l4-local-check.sh` (precisa de `source ~/opt/env.sh` neste notebook). Com namespaces (root): `l1-kernel-baseline.sh`, `l2-interop.sh`, `l3-netns.sh`, `l4-rekey.sh`, `l5-bench.sh`. O `install-testbed.sh` instala uma cópia root-owned e uma regra `sudoers` restrita a esses scripts.

## 8. Validação adicional — máquina Ubuntu 26.04 (23/11/2026)

Repetimos toda a bateria de testes do projeto numa segunda máquina (Xeon Silver 4114, 8 CPUs, Ubuntu 26.04, kernel 7.0.0-34-generic), do zero, sem nada pré-instalado além do pacote `dpdk` do sistema (25.11.3, insuficiente). Commit validado: `c2237c3`. Esta máquina também tinha, em paralelo e o tempo todo **sem interrupção**, uma testbed OpenRAN separada rodando (core 5G `open5gs` em Docker + UERANSIM em `cu-ns`/`du-ns`/`ue-*`) — os dois ambientes não compartilham netns, portas nem dispositivos DPDK (o app usa `--no-pci --no-huge`), então coexistem sem conflito.

**Ambiente construído (CONFIRMADO):** Intel IPsec-MB 2.0.3 e DPDK 26.07 compilados a partir do fonte (driver `crypto_aesni_gcm` confirmado presente), instalados em `~/opt/local` e `~/opt/stage`. `/opt/macsec-testbed` criado como link para o staging, para satisfazer o caminho padrão de plugins da EAL — **nota de segurança**: isso é um link para um diretório gravável pelo usuário, então enfraquece a garantia original do `install-testbed.sh` de que só o root altera o que roda como root; aceitável para validação local, não para a testbed real.

**Achado de infraestrutura (CONFIRMADO):** o pacote `dpdk` 25.11.3 do Ubuntu instala bibliotecas com o mesmo SONAME principal (`.26`) da nossa DPDK 26.07 (ABI diferente, `26.0` vs `26.2`). Se o `LD_LIBRARY_PATH` não priorizar explicitamente os caminhos da nossa build, a resolução de dependências de um plugin carregado pela EAL (ex.: `net_af_packet` → `librte_bus_pci`) pode puxar a cópia do sistema enquanto a EAL carrega explicitamente a nossa cópia do diretório de plugins — duas instâncias físicas distintas do mesmo módulo, causando `PANIC` por registro duplicado de tailq (`UIO_RESOURCE_LIST`). Resolvido fixando `LD_LIBRARY_PATH` com os caminhos da nossa build na frente de qualquer outro. **Vale verificar se a testbed real tem DPDK do sistema instalada; se tiver, o mesmo cuidado se aplica.**

**Resultados (CONFIRMADO, todos no commit `c2237c3`):**

| Teste | Resultado |
|---|---|
| Testes unitários (`meson test`) | 3/3 OK |
| `l1-kernel-baseline` | OK, 0% perda |
| `l2-interop` (SecY ↔ MACsec do kernel) | OK, interop nos dois sentidos |
| `l2-pcap-regression` / `l3-pcap-checks` | OK |
| `l3-netns e0` (VLAN, sem cripto) | OK, 0% perda 72–8950 B |
| `l3-netns e1` (MACsec GCM-AES-XPN-256) | OK, 0% perda 72–8950 B, 8951 B descartado como esperado |
| `l4-rekey` (TLS 1.3 X25519MLKEM768+ML-DSA-65, 3 rekeys sob ping contínuo) | OK, 0% perda, `InPktsInvalid=0` no kernel |
| `l5-bench` | Concluído; vazão E1/E0 na faixa 0.56–1.04 dependendo de tamanho/sentido, latência de software e0 p50 2–8 µs / e1 p50 3–8 µs sob carga leve — **mesma ressalva da seção 3: não é piso de desempenho do fronthaul físico** |
| `ocudu-smoke` (gNB real `gnb_split_7_2` ↔ `ru_emulator`, commit OCUDU `698c4a5` + patch SecY) | Funcional (E1 Setup completo, sem crash); KPIs de timing inconclusivos sem prioridade RT (sem root) |
| `e0-ocudu` (gateway, gNB real) | Funcional, **0 corrupção / 0 descarte / 0 erro de sequência**; timing com atraso alto (DL U-Plane 26.6% on-time) — mesma limitação de ambiente sem RT |
| `e1-ocudu` (SecY dentro do gNB) | **3 rodadas, todas com `auth=0 replay=0`** — o defeito intermitente já documentado (~84% de falha de autenticação, seção descrição do `ocudu/README.md`) **não se manifestou em nenhuma das 3 execuções**. Não é prova de correção (o defeito é intermitente por natureza), mas é evidência a favor. |

**Bugs de script corrigidos durante a validação (CONFIRMADO, não requerem decisão, só registro):**
- `l5-bench.sh`: default `CLI_CPU=8` é inválido em máquinas com 8 CPUs (0–7); `taskset` falhava silenciosamente e zerava todo o tráfego do cliente. Contornado passando `CLI_CPU=7` via variável de ambiente; vale corrigir o default no script.
- `e0-ocudu.sh` / `e1-ocudu.sh`: `taskset -c 9-11` (RU) e `taskset -c 5-8` (DU) hardcoded assumem ≥12 CPUs; em máquina de 8 CPUs ambos os `taskset` falham e nada roda. Contornado com uma cópia local ajustada (`6-7` e `1,3,5`); os scripts originais no repositório não foram alterados.

**Bloqueio de ambiente (A CONFIRMAR na testbed):** os scripts `*-ocudu.sh` usam `unshare -Urmnpf` (user namespace sem privilégio). No Ubuntu 26.04 isso é bloqueado por padrão (`kernel.apparmor_restrict_unprivileged_userns=1`, AppArmor). Precisou de `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (não persistente, revertido ao final dos testes) para rodar. **Se a testbed física também for Ubuntu 24.04+/26.04 com AppArmor, o mesmo ajuste será necessário**, ou os scripts precisam de outro caminho de execução (ex.: dentro de um namespace já privilegiado).
