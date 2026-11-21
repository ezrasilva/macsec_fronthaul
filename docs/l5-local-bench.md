# L5 — medicao local relativa
- CPU: 13th Gen Intel(R) Core(TM) i5-1335U; kernel 7.2.14-arch1-1; DPDK 26.07 (libs ABI 26.2), ipsec_mb 2.0.3
- gateway lcores: 0,2,4; iperf3 servidor cpu 6, cliente cpu 8; governor cpu0=powersave no_turbo=0
- iperf3 iperf 3.22.1 (cJSON 1.7.15); duracao 5 s por execucao; MTU 8950; 2026-11-21T15:58:39-03:00

### Vazao maxima recebida (Mb/s) e perda — UDP, iperf3 -b 0 (UL = RU->DU, passa por PROTECT; DL = DU->RU, passa por VERIFY)
| sentido | pacote IP | E-1 (sem gw) | E0 (so VLAN) | E1 (MACsec) | E1/E0 | perda E-1 / E0 / E1 (%) |
|---|---|---|---|---|---|---|
| UL | 128 B | 207 | 217 | 156 | 0.72 | 0.02 / 18.97 / 43.38 |
| UL | 1500 B | 2592 | 2628 | 1782 | 0.68 | 0.02 / 23.45 / 50.65 |
| UL | 8950 B | 8671 | 7700 | 3880 | 0.50 | 0.08 / 28.21 / 66.77 |
| DL | 128 B | 181 | 199 | 152 | 0.76 | 0.10 / 13.98 / 0.04 |
| DL | 1500 B | 2442 | 2460 | 1796 | 0.73 | 0.02 / 18.21 / 0.50 |
| DL | 8950 B | 8143 | 7242 | 4791 | 0.66 | 0.13 / 22.70 / 1.49 |

### Latencia de software no gateway (RX->TX, us) e tempo ocupado dos lcores (%) — carga leve (-b 50M) e maxima
| modo | sentido | pacote | taxa | p50 | p95 | p99 | max | jitter | rx% | crypto% | tx% | drops |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| e0 | UL | 128 B | 50M | 1 | 1 | 21 | 653 | 0.21 | 3.2 | 1.7 | 25.5 | 0 |
| e0 | UL | 128 B | max | 3585 | 3940 | 4096 | 4782 | 7.05 | 7.0 | 3.7 | 71.5 | 0 |
| e0 | UL | 1500 B | 50M | 1 | 1 | 6 | 66 | 0.19 | 0.3 | 0.1 | 2.5 | 0 |
| e0 | UL | 1500 B | max | 4096 | 4096 | 4096 | 5813 | 8.69 | 7.6 | 2.5 | 72.3 | 0 |
| e0 | UL | 8950 B | 50M | 1 | 1 | 1 | 31 | 0.08 | 0.1 | 0.0 | 0.7 | 0 |
| e0 | UL | 8950 B | max | 4096 | 4096 | 4096 | 10789 | 18.16 | 11.6 | 1.1 | 71.5 | 0 |
| e0 | DL | 128 B | 50M | 1 | 1 | 23 | 324 | 0.32 | 3.0 | 1.4 | 26.8 | 0 |
| e0 | DL | 128 B | max | 3949 | 4096 | 4096 | 4646 | 7.70 | 6.9 | 3.2 | 71.6 | 0 |
| e0 | DL | 1500 B | 50M | 1 | 1 | 1 | 39 | 0.14 | 0.3 | 0.1 | 2.5 | 0 |
| e0 | DL | 1500 B | max | 4096 | 4096 | 4096 | 5460 | 9.32 | 7.4 | 2.1 | 71.4 | 0 |
| e0 | DL | 8950 B | 50M | 1 | 1 | 2 | 44 | 0.13 | 0.1 | 0.0 | 0.7 | 0 |
| e0 | DL | 8950 B | max | 4096 | 4096 | 4096 | 11240 | 19.25 | 11.8 | 1.1 | 71.8 | 0 |
| e1 | UL | 128 B | 50M | 1 | 2 | 26 | 573 | 0.30 | 3.0 | 4.0 | 35.4 | 0 |
| e1 | UL | 128 B | max | 4096 | 4096 | 4096 | 6945 | 9.98 | 3.5 | 7.8 | 71.5 | 0 |
| e1 | UL | 1500 B | 50M | 2 | 2 | 10 | 69 | 0.25 | 0.3 | 0.5 | 3.6 | 0 |
| e1 | UL | 1500 B | max | 4096 | 4096 | 4096 | 9470 | 12.98 | 4.7 | 9.6 | 71.6 | 0 |
| e1 | UL | 8950 B | 50M | 4 | 5 | 7 | 63 | 0.57 | 0.1 | 0.2 | 1.3 | 0 |
| e1 | UL | 8950 B | max | 4096 | 4096 | 4096 | 20609 | 36.29 | 5.7 | 10.1 | 71.5 | 0 |
| e1 | DL | 128 B | 50M | 1 | 2 | 10 | 233 | 0.28 | 3.0 | 4.2 | 26.2 | 0 |
| e1 | DL | 128 B | max | 6 | 8 | 17 | 159 | 3.29 | 8.7 | 13.2 | 70.5 | 0 |
| e1 | DL | 1500 B | 50M | 2 | 2 | 5 | 58 | 0.13 | 0.3 | 0.5 | 2.6 | 0 |
| e1 | DL | 1500 B | max | 5 | 8 | 13 | 122 | 0.97 | 9.7 | 14.8 | 69.1 | 0 |
| e1 | DL | 8950 B | 50M | 4 | 5 | 8 | 66 | 0.44 | 0.1 | 0.2 | 0.7 | 0 |
| e1 | DL | 8950 B | max | 3 | 4 | 7 | 181 | 0.19 | 9.3 | 13.8 | 50.7 | 0 |

### RTT ocioso RU<->DU via ping (us), 500 pings a 10 ms
| modo | pacote IP | n | p50 | p95 | p99 | max | media |
|---|---|---|---|---|---|---|---|
| E-1 | 128 B | 500 | 90 | 134 | 171 | 187 | 90 |
| E-1 | 1500 B | 500 | 90 | 126 | 151 | 180 | 89 |
| E-1 | 8950 B | 500 | 107 | 158 | 199 | 233 | 106 |
| E0 | 128 B | 500 | 46 | 75 | 100 | 110 | 50 |
| E0 | 1500 B | 500 | 49 | 86 | 108 | 122 | 53 |
| E0 | 8950 B | 500 | 79 | 107 | 135 | 150 | 82 |
| E1 | 128 B | 500 | 53 | 84 | 106 | 120 | 57 |
| E1 | 1500 B | 500 | 60 | 97 | 139 | 190 | 65 |
| E1 | 8950 B | 500 | 108 | 143 | 196 | 208 | 112 |

## Como ler (leia antes de citar qualquer numero)

**Valem so como custo relativo neste notebook** (i5-1335U, governor `powersave`, cores nao isolados,
`veth` + `net_af_packet`). Nao sao desempenho do fronthaul e nao se comparam com as janelas do OFH.
Offloads de checksum/segmentacao foram desligados nos 3 modos (necessario: o gateway reinjeta quadros crus).

1. **O E-1 nao e piso de latencia.** O RTT do E-1 (90 us) e *maior* que o do E0 (46 us). HIPOTESE: com o
   gateway, os lcores 0/2/4 ficam em polling e mantem os cores acordados; sem ele, os cores ociosos saem de
   C-states com atraso. Por isso nao subtraio E-1; compare E0 com E1.
2. **A vazao do E1 nao isola o custo da cripto do gateway.** O MACsec do *kernel* na DU (par de teste)
   cifra/decifra no mesmo caminho: no UL a decifragem do kernel roda dentro do `sendto` do lcore de TX
   (veth entrega no contexto de quem envia); no DL a cifragem roda no iperf3 da DU. HIPOTESE, coerente
   com o lcore de cripto do gateway ficar so em 8-15% ocupado enquanto o TX fica em ~71%.
3. **Perda e latencia "max" nao sao comparaveis.** No `-b 0` o remetente passa do que o gateway/kernel
   absorvem (E0 perde 14-28%, E-1 <0,2%); no E1 DL o remetente (kernel cifrando) e mais lento e por isso
   quase nao perde. As latencias p50/p95/p99 = 4096 us estao no bucket de overflow do histograma (filas
   cheias). Para latencia use as linhas de 50 Mb/s.
4. **Latencia de software do gateway com carga leve (50 Mb/s)** — o dado mais limpo:
   p50 E0->E1: 128 B 1->1 us, 1500 B 1->2 us, 8950 B 1->4 us; p99: 128 B 21-23->10-26, 8950 B 1-2->7-8 us.
   Ou seja, a cripto acrescenta ~1-3 us (p50) e ate ~6 us (p99) por sentido a 8950 B.
5. **Cauda:** mesmo com carga leve, o `max` chegou a 570-650 us (128 B). E ruido de SO em cores nao isolados;
   na testbed isso importa contra a margem de ~70 us do uplink: sera preciso isolar CPUs, governor
   `performance` e evitar irmaos de hyperthread.
6. **RTT E1-E0 (p50):** 128 B +7 us, 1500 B +11 us, 8950 B +29 us. Inclui a cripto do kernel da DU nos dois
   sentidos, nao so a do gateway.
7. **Folga do lcore de cripto (extrapolacao linear, HIPOTESE):** vazao / fracao ocupada do lcore de cripto
   da ~35-38 Gb/s a 8950 B, ~18 Gb/s a 1500 B e ~2 Mpps a 128 B. Valida so se a ocupacao escalar linearmente.
