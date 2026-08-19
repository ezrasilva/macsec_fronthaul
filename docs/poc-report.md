# Relatório de validação da PoC MACsec + PQC via DPDK

## Escopo validado

- MACsec restrito com GCM-AES-XPN-256, SCI explícito, PN de 64 bits, SSCI,
  salt, ICV de 16 bytes e janela anti-replay.
- Dataplane DPDK entre VMs O-DU e O-RU.
- AES-GCM pelo `rte_cryptodev`/`crypto_aesni_gcm`.
- Pipeline concorrente com lcore de IO, lcore de criptografia e filas
  `rte_ring`.
- TLS 1.3 híbrido `X25519MLKEM768`, autenticação mútua `ML-DSA-65`, EKM e
  HKDF para duas chaves MACsec direcionais, com confirmação mútua do material
  derivado por HMAC-SHA256.
- Rekey em duas fases, mantendo a SA anterior durante a transição.
- Replay PCAP de frames eCPRI IQ Data.

## Resultados funcionais

| Validação | Resultado |
|---|---|
| Testes unitários MACsec | 1/1 aprovado |
| Ping O-DU → O-RU | 5/5, 0% de perda |
| Rekey sob ping contínuo | 100/100, 0% de perda |
| PCAP eCPRI protegido | 32/32 frames, EtherType `0x88e5` |
| PCAP eCPRI desprotegido | 32/32, zero falhas de autenticação |
| Round-trip PCAP | Igualdade byte a byte |
| Saturação das filas no ensaio | `ring_drop=0` |
| Carga eCPRI sintética | 100.000/100.000, zero descartes |

## Ensaio de carga PCAP

O pipeline XPN-256 instrumentado, com cryptodev em burst e transformação
in-place e reposicionamento por headroom, processou 100.000 frames eCPRI em
137.810 µs, correspondendo a aproximadamente 725.637 pacotes/s. Não ocorreram
erros de autenticação,
formato, replay, alocação, transmissão ou saturação de `rte_ring`. A captura
MACsec resultante contém todos os frames com PN final 100.000.

A latência interna entre entrada no `crypto_ring` e consumo pelo estágio TX foi
de 86,35 µs em média, p50 de 7 µs, p95 de 510 µs, p99 de 666 µs e máximo de
782 µs. O jitter médio entre amostras consecutivas foi 0,44 µs. A distribuição
bimodal reflete o processamento em bursts e o buffering do PMD PCAP. A medição
inclui o custo da instrumentação e o buffering do PMD PCAP; não representa RTT
nem latência física de enlace.

O valor mede este pipeline sintético com PMD PCAP em duas vCPUs e não deve ser
interpretado como capacidade do fronthaul físico.

O benchmark emite `latency_us_avg`, `p50`, `p95`, `p99`, `max`, `jitter_avg` e
número de amostras. Para throughput sem interferência de timestamps, execute
uma rodada separada sem `--latency-stats`.

## Benchmark TLS

Foram executadas dez conexões por modo nas mesmas VMs. Ambos os modos usam
certificados ML-DSA-65; portanto, a comparação abaixo isola apenas o grupo de
troca de chave.

| Modo | Handshake médio | RX médio | TX médio |
|---|---:|---:|---:|
| X25519 | 7.928 ms | 14.716 bytes | 14.725 bytes |
| X25519MLKEM768 | 9.432 ms | 15.804 bytes | 15.903 bytes |

No ambiente virtual, o modo híbrido acrescentou aproximadamente 1,504 ms e
2.266 bytes bidirecionais. Esses valores servem como evidência funcional e
ordem de grandeza; não substituem medições no testbed físico.

## Reprodução

```sh
./scripts/start-vm-endpoints.sh
./scripts/test-vm-ping.sh
./scripts/test-vm-rekey.sh
./scripts/test-ecpri-pcap.sh
./scripts/benchmark-handshake.sh 10
./scripts/benchmark-ecpri-load.sh 100000
./scripts/collect-evidence.sh
```

Os arquivos resultantes ficam em `artifacts/evidence`, acompanhados de
`SHA256SUMS` para verificação de integridade.

## Limitações remanescentes

- O perfil não é uma implementação completa/conformante de IEEE 802.1AE.
- As VMs usam quatro vCPUs e lcores distintos para RX, criptografia e TX.
- As medições virtualizadas não caracterizam latência, jitter ou throughput do
  fronthaul físico.
- Ainda faltam vetores oficiais de conformidade e ensaio de carga sustentada.
