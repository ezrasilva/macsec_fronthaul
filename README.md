# PoC MACsec + PQC via DPDK

Prova de conceito local de um fronthaul O-DU/O-RU protegido por MACsec, com
chaves derivadas por TLS 1.3 pós-quântico e dataplane DPDK. O ambiente usa duas
VMs QEMU/KVM e pode ser reproduzido antes da migração para o testbed físico do
OpenRAN@Brasil.

## Funcionalidades

- perfil MACsec com GCM-AES-XPN-256, SCI explícito, PN de 64 bits, SSCI, salt,
  AN, ICV de 16 bytes e janela anti-replay;
- AES-GCM no dataplane pelo `rte_cryptodev` e PMD `crypto_aesni_gcm`;
- pipeline concorrente com lcore de IO, lcore de criptografia e filas
  `rte_ring` SPSC;
- submissão AES-GCM em bursts de até 32 operações diretamente nos `rte_mbuf`;
- inserção e retirada do SecTAG por headroom/tailroom, sem copiar o payload;
- TLS 1.3 com troca híbrida `X25519MLKEM768`;
- autenticação mútua com certificados `ML-DSA-65`;
- EKM + HKDF-SHA256 para gerar chaves MACsec direcionais;
- confirmação mútua por HMAC das SAKs e salts derivados;
- rekey em duas fases, preservando a SA anterior durante a transição;
- testes por ping, PCAP eCPRI e carga sintética.

## Arquitetura

```text
                    TLS 1.3 / X25519MLKEM768 / ML-DSA-65
             O-DU  <------------------------------------>  O-RU
               |          EKM + HKDF + rekey                |
               |                                             |
      tap_plain 10.10.0.1                           10.10.0.2 tap_plain
               |                                             |
        RX/TX lcore → rte_ring → MACsec/Cryptodev lcore      |
               |                                             |
              fh0 ========= 0x88e5 / rede isolada ========= fh0
```

O tráfego de gerenciamento TLS usa a rede libvirt padrão. O fronthaul utiliza
uma segunda rede L2 isolada, sem endereço IP no enlace protegido.

## Requisitos

No host:

- Linux com KVM/libvirt;
- `virsh`, `virt-install` e `cloud-localds`;
- Meson, Ninja, compilador C e OpenSSL;
- DPDK com os PMDs TAP, AF_PACKET, PCAP e AESNI-GCM;
- Python 3.

Os detalhes estão em [pré-requisitos das VMs](docs/two-vm-prerequisites.md).

## Compilação

```sh
meson setup build
meson compile -C build
meson test -C build --print-errorlogs
```

Os testes unitários verificam round-trip, corrupção, replay, recepção fora de
ordem, janela de sequência e esgotamento do Packet Number.

## Provisionamento das VMs

O provisionamento manipula libvirt e deve ser executado com `sudo`. O script
preserva a propriedade da chave SSH para o usuário que chamou o comando:

```sh
sudo ./scripts/provision-vms.sh
sudo ./scripts/vm-status.sh
```

| Função | Endereço de gerenciamento |
|---|---|
| O-DU | `192.168.122.101` |
| O-RU | `192.168.122.102` |

O OpenSSL 3.6 usado para ML-KEM/ML-DSA fica isolado em `/opt/openssl` dentro
das VMs. Os certificados de laboratório ficam em `/home/poc/macsec-pki36`.
Para exigir um tipo específico de chave do certificado remoto, defina
`MACSEC_TLS_PEER_KEY` (por exemplo, `ML-DSA-65`); divergências encerram o
handshake antes da exportação das chaves.
Quando o endereço de conexão difere da identidade do certificado, use
`MACSEC_TLS_SERVER_NAME`; a verificação de nome permanece obrigatória.

## Execução ponta a ponta

```sh
./scripts/start-vm-endpoints.sh
./scripts/test-vm-ping.sh
./scripts/stop-vm-endpoints.sh
```

O primeiro comando negocia as chaves PQC e executa confirmação mútua por HMAC,
vinculada às duas SAKs e aos dois salts derivados, antes de iniciar os endpoints
DPDK. O teste confirma o ping e captura
frames com EtherType MACsec `0x88e5`.

## Rekey sem interrupção

```sh
./scripts/test-vm-rekey.sh
```

O rekey possui duas fases:

1. o agente TLS envia `INSTALL` pelo Unix socket nos dois pares;
2. após a confirmação mútua por HMAC, envia `ACTIVATE` para o novo AN.

O dataplane inicia em `WAITING_FOR_SA` e não processa tráfego plain até a
primeira ativação. SAKs e salts não passam por `argv` nem por arquivos
temporários no fluxo padrão das VMs.

O teste executa a troca durante 100 pings e exige 0% de perda.

## Replay PCAP eCPRI

```sh
./scripts/test-ecpri-pcap.sh
```

São gerados 32 frames eCPRI IQ Data com EtherType `0xAEFE`. O pipeline cria uma
captura MACsec e executa a operação inversa, validando SCI, PN, ICV e igualdade
byte a byte do round-trip.

## Benchmarks

```sh
./scripts/benchmark-handshake.sh 10
./scripts/benchmark-ecpri-load.sh 100000
```

O ensaio de carga validado processou 100.000 frames sem descartes, erros ou
saturação das filas. Resultados em VMs são apenas referência funcional e não
representam o desempenho do fronthaul físico.

## Evidências e relatório

```sh
./scripts/collect-evidence.sh
```

As evidências são geradas em `artifacts/evidence` com hashes SHA-256. O
diretório é ignorado pelo Git porque logs podem conter chaves efêmeras na linha
de comando.

- [Relatório da PoC](docs/poc-report.md)
- [Perfil MACsec](docs/macsec-profile.md)
- [Pipeline DPDK](docs/dpdk-pipeline.md)

## Limitações

- Perfil restrito, não uma implementação completa de IEEE 802.1AE.
- Ainda não há validação por vetores oficiais de conformidade IEEE 802.1AE.
- As VMs usam quatro vCPUs; RX, criptografia e TX ocupam lcores distintos.
- Latência, jitter e throughput definitivos devem ser medidos no testbed.

## Segurança

Chaves, certificados privados, discos de VM, builds e evidências geradas não
devem ser versionados. O material da PoC é exclusivo para laboratório.
