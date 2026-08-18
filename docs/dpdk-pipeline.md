# Pipeline DPDK local

O aplicativo `poc_macsec_dpdk` usa duas portas Ethernet DPDK e três lcores:

```text
lcore RX: RX das duas portas → crypto_ring
lcore crypto: SecTAG/anti-replay → rte_cryptodev → tx_ring
lcore TX: tx_ring → TX da porta de destino
```

O processamento AES-GCM usa `rte_cryptodev` com o PMD virtual
`crypto_aesni_gcm`. A biblioteca mantém
OpenSSL como backend de referência para os testes unitários, enquanto o
dataplane registra o backend DPDK após inicializar a fila e as sessões AEAD.

## Execução

A criação de TAPs exige `CAP_NET_ADMIN`. Compile e execute:

```sh
meson compile -C build
sudo ./build/apps/dpdk/poc_macsec_dpdk \
  --no-huge -l 0-2 \
  --vdev=crypto_aesni_gcm0 \
  --vdev=net_tap0,iface=tap_plain \
  --vdev=net_tap1,iface=tap_secure \
  -- \
  --tx-key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --rx-key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f \
  --tx-sci=0200000000010001 \
  --rx-sci=0200000000020001 \
  --tx-salt=000102030405060708090a0b \
  --rx-salt=101112131415161718191a1b \
  --tx-ssci=1 --rx-ssci=2
```

As filas têm 1024 entradas e semântica single-producer/single-consumer. A
estatística `ring_drop` contabiliza descarte por saturação na entrada; a saída
aplica backpressure até o lcore de IO consumir o resultado.

## Replay eCPRI por PCAP

```sh
./scripts/test-ecpri-pcap.sh
```

O teste gera frames eCPRI IQ Data com EtherType `0xAEFE`, protege os frames em
uma primeira execução do pipeline e reproduz a captura MACsec na direção
inversa. A validação exige 32 frames, SCI correto, PN crescente, ICV de 16
bytes, zero erros de autenticação e igualdade byte a byte após o round-trip.

A chave do exemplo é pública e serve somente para tráfego de teste. Em outro
terminal, enquanto o processo estiver ativo:

```sh
sudo ip link set tap_plain up
sudo ip link set tap_secure up
sudo tcpdump -eni tap_secure ether proto 0x88e5
```

Tráfego enviado pelo kernel em `tap_plain` deve aparecer em `tap_secure` com
EtherType `0x88e5`. Um frame MACsec válido injetado em `tap_secure`, com os
mesmos parâmetros de SA, deve reaparecer decifrado em `tap_plain`.

## Execução sem privilégio para validar inicialização

As portas ring permitem confirmar EAL, alocação de mbufs e configuração de
filas sem criar interfaces do kernel:

```sh
./build/apps/dpdk/poc_macsec_dpdk \
  --no-huge -l 0-2 --vdev=crypto_aesni_gcm0 \
  --vdev=net_ring0 --vdev=net_ring1 -- \
  --tx-key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  --rx-key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f \
  --tx-sci=0200000000010001 \
  --rx-sci=0200000000020001 \
  --tx-salt=000102030405060708090a0b \
  --rx-salt=101112131415161718191a1b \
  --tx-ssci=1 --rx-ssci=2
```

## Contadores

O processo informa frames protegidos e recuperados, falhas de autenticação,
replay, formato, alocação e transmissão. `Ctrl-C` encerra as portas e imprime os
valores finais.

## Duas pontas

Os argumentos são direcionais. Na ponta O-RU, os valores devem ser invertidos:

```text
O-DU TX key/SCI = O-RU RX key/SCI
O-DU RX key/SCI = O-RU TX key/SCI
```

Isso cria duas Secure Channels independentes e evita reutilizar nonce entre os
sentidos do enlace.
