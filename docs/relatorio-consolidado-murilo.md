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
- **SecY no OCUDU (F4):** não iniciada. O `INSTALL` do gateway **drena o pipeline** (bloqueante). Serve no gateway, **não na thread de TX do OCUDU**, que exigirá SA em slots duplos com troca atômica.
- **Rekey:** é disparado por fora, executando o agente de novo (um handshake por rekey). Não há gatilho automático por limiar de PN ou tempo. O `RETIRE` foi testado só com carência de 2 s.
- **E5 (replay, ICV adulterado, chave errada no gateway):** não executado. Só com autorização por escrito (Termo, item 8.7), quadros sintéticos e sem tocar nas O-RUs. A PKI é de laboratório.

## 5. Riscos e o que a testbed precisa

1. **Jitter/cauda.** `max` de centenas de µs em carga leve exige, na testbed: CPUs isoladas (`isolcpus`/`nohz_full`), governor `performance`, lcores em núcleos físicos distintos (sem irmãos de hyperthread) e NUMA-local.
2. **IPsec-MB.** A série **3.0.x é incompatível** com o driver `ipsec_mb` do DPDK 26.07 (`IMB_MGR` opaco); usamos a 2.0.3. Qual versão a testbed tem?
3. **Dependência da RNP:** VLANs 216x nos ToRs, MTU 9000, EAPOL em unicast, janela de experimento, imagem pública do OCUDU, escopo do Termo (gateway no oran-cloud5 e alteração do OCUDU).
4. **Prazo.** Pelas estimativas do plano (não medidas): F3 4–6 dias, F4 7–10 dias (maior risco), F6 na janela da RNP. Janeiro é apertado para F0–F4 + F6.

## 6. Decisões e pedidos (A DECIDIR / A CONFIRMAR)

1. **Fase 1 do MKA:** aceitar GCM-AES-256 (PN 32 bits) com rekey antes de esgotar o PN e deixar XPN no KaY para depois, ou exigir XPN? O gateway e o kernel já falam XPN.
2. **Ponte de chaves na fase 1:** CAK/CKN pelo nosso canal TLS PQC ou outro canal PQC (por exemplo, OpenSSH `mlkem768x25519-sha256`)?
3. **Emulador de RU** para testar a F4 sem hardware: existe? Sem ele, a F4 fica validada só por testes de unidade e injeção contra o gateway.
4. **Versões exatas** do OCUDU, DPDK e IPsec-MB da testbed, e política de imagem pública (sem segredos).
5. **Acesso:** `ROADMAP.md` e a branch `macsec_pqc`.
6. **Experimentos prévios** sem MACsec, para medir o caminho real: E-1 (OCUDU direto) e E0 (gateway só com troca de VLAN), que separam o custo do salto extra do custo da cifra. E confirmar nos ToRs: EAPOL unicast, VLAN 2161–2163 e MTU 9000.
7. **Autorização** do E5 por escrito.

## 7. Como reproduzir

Os scripts estão em `scripts/testbed/`. Sem root: `ninja -C build && meson test -C build`, `l2-pcap-regression.sh`, `l3-pcap-checks.sh`, `l4-local-check.sh` (precisa de `source ~/opt/env.sh` neste notebook). Com namespaces (root): `l1-kernel-baseline.sh`, `l2-interop.sh`, `l3-netns.sh`, `l4-rekey.sh`, `l5-bench.sh`. O `install-testbed.sh` instala uma cópia root-owned e uma regra `sudoers` restrita a esses scripts.
