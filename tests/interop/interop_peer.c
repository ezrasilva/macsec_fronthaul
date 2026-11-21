/* Peer de interoperabilidade: faz o papel do lado B usando a NOSSA SecY e fala
 * com o MACsec do kernel (lado A) via AF_PACKET. Roda como root dentro do netns b.
 * Constantes iguais a scripts/testbed/l1-kernel-baseline.sh (A->B: key_ab, B->A: key_ba).
 *
 * Envia um ICMP echo request (protegido, dentro da VLAN) e verifica o echo reply
 * protegido pelo kernel. Uso: interop_peer IFACE [payload_len] [vid] */
#include "macsec.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static const uint8_t mac_a[6] = {0x02, 0, 0, 0, 0, 0x0a};
static const uint8_t mac_b[6] = {0x02, 0, 0, 0, 0, 0x0b};
static const uint8_t sci_a[8] = {0x02, 0, 0, 0, 0, 0x0a, 0, 0x01};
static const uint8_t sci_b[8] = {0x02, 0, 0, 0, 0, 0x0b, 0, 0x01};
static const uint8_t salt_ab[12] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
static const uint8_t salt_ba[12] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc};

static uint16_t csum(const uint8_t *p, size_t n)
{
    uint32_t s = 0;
    for (; n > 1; n -= 2, p += 2) s += (uint32_t)(p[0] << 8 | p[1]);
    if (n) s += (uint32_t)(p[0] << 8);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* Recebe um quadro; se a tag VLAN veio como metadado (offload do veth),
 * reinsere em linha para que a SecY veja o quadro como estava no fio. */
static ssize_t recv_frame(int fd, uint8_t *buf, size_t cap)
{
    struct iovec iov = {.iov_base = buf, .iov_len = cap - 4};
    char ctrl[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = ctrl,
                         .msg_controllen = sizeof(ctrl)};
    struct cmsghdr *c;
    ssize_t n = recvmsg(fd, &msg, 0);

    if (n < 14) return n;
    for (c = CMSG_FIRSTHDR(&msg); c != NULL; c = CMSG_NXTHDR(&msg, c)) {
        struct tpacket_auxdata *a;
        if (c->cmsg_level != SOL_PACKET || c->cmsg_type != PACKET_AUXDATA) continue;
        a = (struct tpacket_auxdata *)CMSG_DATA(c);
        if ((a->tp_status & TP_STATUS_VLAN_VALID) != 0 && !(buf[12] == 0x81 && buf[13] == 0x00)) {
            uint16_t tpid = (a->tp_status & TP_STATUS_VLAN_TPID_VALID) ? a->tp_vlan_tpid : 0x8100;
            memmove(buf + 16, buf + 12, (size_t)n - 12);
            buf[12] = (uint8_t)(tpid >> 8); buf[13] = (uint8_t)tpid;
            buf[14] = (uint8_t)(a->tp_vlan_tci >> 8); buf[15] = (uint8_t)a->tp_vlan_tci;
            n += 4;
        }
    }
    return n;
}

static size_t build_request(uint8_t *f, size_t payload, unsigned vid, uint16_t seq)
{
    size_t i, icmp_len = 8 + payload, ip_len = 20 + icmp_len;
    uint8_t *ip, *icmp;

    memcpy(f, mac_a, 6); memcpy(f + 6, mac_b, 6);
    f[12] = 0x81; f[13] = 0x00; f[14] = (uint8_t)(vid >> 8); f[15] = (uint8_t)vid;
    f[16] = 0x08; f[17] = 0x00;
    ip = f + 18; icmp = ip + 20;
    memset(ip, 0, 20);
    ip[0] = 0x45; ip[2] = (uint8_t)(ip_len >> 8); ip[3] = (uint8_t)ip_len;
    ip[6] = 0x40; ip[8] = 64; ip[9] = 1;
    ip[12] = 10; ip[13] = 61; ip[14] = 0; ip[15] = 2;   /* origem 10.61.0.2 */
    ip[16] = 10; ip[17] = 61; ip[18] = 0; ip[19] = 1;   /* destino 10.61.0.1 */
    ip[10] = (uint8_t)(csum(ip, 20) >> 8); ip[11] = (uint8_t)csum(ip, 20);
    icmp[0] = 8; icmp[1] = 0; icmp[2] = icmp[3] = 0;
    icmp[4] = 0x4d; icmp[5] = 0x53; icmp[6] = (uint8_t)(seq >> 8); icmp[7] = (uint8_t)seq;
    for (i = 0; i < payload; i++) icmp[8 + i] = (uint8_t)(i * 7 + 3);
    icmp[2] = (uint8_t)(csum(icmp, icmp_len) >> 8); icmp[3] = (uint8_t)csum(icmp, icmp_len);
    return 18 + ip_len;
}

int main(int argc, char **argv)
{
    const char *ifname = argc > 1 ? argv[1] : "vb";
    size_t payload = argc > 2 ? (size_t)atoi(argv[2]) : 100;
    unsigned vid = argc > 3 ? (unsigned)atoi(argv[3]) : 2161;
    uint8_t key_ab[32], key_ba[32];
    static uint8_t plain[9100], secure[9200], rx[9200], inner[9200];
    struct macsec_tx_sa tx;
    struct macsec_rx_sa rxsa;
    struct sockaddr_ll sll = {0};
    size_t plain_len, secure_len = 0, inner_len = 0;
    int fd, i, got_reply = 0;
    time_t start;

    for (i = 0; i < 32; i++) { key_ab[i] = (uint8_t)i; key_ba[i] = (uint8_t)(31 - i); }
    if (payload > 8900) { fprintf(stderr, "payload grande demais\n"); return 2; }
    macsec_tx_sa_init(&tx, key_ba, sci_b, salt_ba, 2, 0, 1000);
    macsec_rx_sa_init(&rxsa, key_ab, sci_a, salt_ab, 1, 0, 64);

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket(AF_PACKET)"); return 2; }
    {
        int one = 1;
        setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one));
    }
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)if_nametoindex(ifname);
    if (sll.sll_ifindex == 0 || bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind"); return 2;
    }

    plain_len = build_request(plain, payload, vid, 1);
    if (macsec_protect(&tx, plain, plain_len, secure, sizeof(secure), &secure_len) != MACSEC_OK) {
        fprintf(stderr, "macsec_protect falhou\n"); return 1;
    }
    if (sendto(fd, secure, secure_len, 0, (struct sockaddr *)&sll, sizeof(sll)) != (ssize_t)secure_len) {
        perror("sendto"); return 1;
    }
    printf("enviado: request protegido por nos (%zu B no fio, payload ICMP %zu B, VLAN %u)\n",
           secure_len, payload, vid);

    start = time(NULL);
    while (time(NULL) - start < 3 && !got_reply) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        ssize_t n;
        enum macsec_status st;

        if (poll(&p, 1, 500) <= 0) continue;
        n = recv_frame(fd, rx, sizeof(rx));
        if (n < 20 || memcmp(rx + 6, mac_a, 6) != 0 || rx[12] != 0x81 || rx[16] != 0x88 || rx[17] != 0xe5)
            continue;
        st = macsec_unprotect(&rxsa, rx, (size_t)n, inner, sizeof(inner), &inner_len);
        printf("recebido do kernel: %zd B -> unprotect: %s\n", n, macsec_status_string(st));
        if (st != MACSEC_OK) return 1;
        /* inner: DA SA 8100 vid 0800 IP ICMP(type 0) */
        if (inner_len == plain_len && inner[18 + 20] == 0 && inner[18 + 20 + 6] == 0 &&
            inner[18 + 20 + 7] == 1 && memcmp(inner + 18 + 28, plain + 18 + 28, payload) == 0) {
            got_reply = 1;
        } else {
            fprintf(stderr, "reply inesperado (len %zu vs %zu)\n", inner_len, plain_len);
            return 1;
        }
    }
    if (!got_reply) { fprintf(stderr, "FALHA: sem reply do kernel em 3 s\n"); return 1; }
    printf("OK: kernel aceitou nosso quadro e respondeu; nos aceitamos o do kernel (payload %zu B)\n", payload);
    return 0;
}
