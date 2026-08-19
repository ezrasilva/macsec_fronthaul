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
O IV e o AAD ficam na área privada pré-alocada de `rte_crypto_op`, sem
`rte_malloc` por pacote. O crypto lcore retira até 32 jobs por vez, prepara os
nonces XPN e submete as operações juntas por `rte_cryptodev_enqueue_burst`.
O PMD cifra ou autentica diretamente o mbuf recebido; não existe mbuf
criptográfico ou buffer de frame intermediário. Também não há `memmove`: na
proteção, `adj(12)`, `prepend(28)` e `append(16)` reposicionam os metadados do
mbuf e deixam o EtherType/payload original após o SecTAG. Na recuperação,
`trim(16)` e `adj(16)` restauram o layout Ethernet. O PMD informa suporte a
in-place SGL, mas segmentação não é necessária e adicionaria descritores.

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
  --enable-legacy-keying \
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
  --enable-legacy-keying \
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

Com `--latency-stats`, cada job recebe timestamp na entrada do `crypto_ring` e
é observado na saída para TX. O relatório inclui média, p50, p95, p99, máximo e
jitter médio em microssegundos. A instrumentação é opcional para não afetar os
ensaios de throughput puro.

## Duas pontas

Os argumentos são direcionais. Na ponta O-RU, os valores devem ser invertidos:

```text
O-DU TX key/SCI = O-RU RX key/SCI
O-DU RX key/SCI = O-RU TX key/SCI
```

Isso cria duas Secure Channels independentes e evita reutilizar nonce entre os
sentidos do enlace.

## Controle de SAs

Com `--control-socket /run/macsec-pqc/control.sock`, o dataplane cria um Unix
socket `SOCK_SEQPACKET` com modo `0600`, transfere sua propriedade para o UID
configurado e valida cada conexão com `SO_PEERCRED`. O diretório do socket deve
ser criado com modo `0700`. Os comandos entram pelo `stdin` do `poc_keyctl`,
evitando chaves em `argv`:

```sh
printf '%s\n' 'INSTALL AN=1 TX_KEY=... RX_KEY=... TX_SALT=... RX_SALT=...' |
  ./build/src/keying/poc_keyctl /run/macsec-pqc/control.sock
printf '%s\n' 'ACTIVATE AN=1' |
  ./build/src/keying/poc_keyctl /run/macsec-pqc/control.sock
printf '%s\n' 'RETIRE AN=0' |
  ./build/src/keying/poc_keyctl /run/macsec-pqc/control.sock
printf '%s\n' 'STATUS' |
  ./build/src/keying/poc_keyctl /run/macsec-pqc/control.sock
```

`INSTALL` só escreve em AN inativo e publica a RX SA depois da inicialização
completa. `ACTIVATE` exige que o AN tenha sido instalado. `RETIRE` rejeita o AN
TX ativo, interrompe sua publicação RX, aguarda o crypto lcore e limpa a SA da
memória. No socket, o `poc_keyctl` converte essa interface textual em mensagens
binárias versionadas de tamanho fixo; chaves e salts não passam por parsing de
texto no dataplane. O mecanismo antigo por sinais e argumentos só é habilitado
explicitamente com `--enable-legacy-keying`.

Quando inicia com `--control-socket`, mas sem chaves e salts, o dataplane fica
em `WAITING_FOR_SA`: ele não retira frames da porta plain antes da ativação da
primeira SA. `--control-uid UID` permite entregar o socket a um keying agent
com UID diferente e restringe `SO_PEERCRED` exatamente a esse usuário.

O `poc_tls_keying` aceita `unix:/caminho/do/socket` no lugar do arquivo de
saída. `MACSEC_ENDPOINT_ROLE=du|ru` seleciona as direções e
`MACSEC_CONTROL_AN=0..3` seleciona o AN. O agente envia `INSTALL` após derivar
as chaves, realiza a confirmação mútua por HMAC no canal TLS e somente então
envia `ACTIVATE`; nenhum arquivo contendo SAK ou salt é criado.

`rekey-vm-endpoints.sh` consulta `STATUS` nas duas pontas, exige que os ANs
ativos coincidam, escolhe `(AN + 1) mod 4`, negocia e ativa a nova SA e, após
`MACSEC_RETIRE_GRACE_SECONDS` (dois segundos por padrão), envia `RETIRE` para o
AN anterior nos dois endpoints.
