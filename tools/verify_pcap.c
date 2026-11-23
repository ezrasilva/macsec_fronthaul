/* Ferramenta de depuracao: verifica, quadro a quadro, os quadros MACsec de um pcap com a nossa SecY e
 * imprime um resumo por tamanho. Uso: verify_pcap FILE.pcap KEY_HEX64 SALT_HEX24 SSCI SCI_HEX16 [verbose]
 * (a chave/salt/SSCI/SCI sao os do REMETENTE dos quadros). Nao exige ordem: usa janela de replay 64 mas
 * reinicia a SA a cada quadro para isolar problemas de autenticacao. */
#include "macsec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex(const char *t, uint8_t *o, size_t n)
{
    if (strlen(t) != n * 2U) return 0;
    for (size_t i = 0; i < n; i++) { unsigned v; if (sscanf(t + 2 * i, "%2x", &v) != 1) return 0; o[i] = (uint8_t)v; }
    return 1;
}

int main(int argc, char **argv)
{
    uint8_t key[32], salt[12], sci[8];
    unsigned ssci;
    FILE *f;
    uint8_t gh[24], rec[16];
    static uint8_t frame[20000], plain[20000];
    unsigned long total = 0, ok = 0, fail = 0, notmac = 0;
    unsigned long by_len_ok[16] = {0}, by_len_fail[16] = {0};
    int verbose = argc > 6;

    if (argc < 6 || !hex(argv[2], key, 32) || !hex(argv[3], salt, 12) || !hex(argv[5], sci, 8)) {
        fprintf(stderr, "uso: %s FILE KEY64 SALT24 SSCI SCI16 [v]\n", argv[0]); return 2;
    }
    ssci = (unsigned)strtoul(argv[4], NULL, 0);
    f = fopen(argv[1], "rb");
    if (!f || fread(gh, 1, 24, f) != 24) { perror("pcap"); return 2; }
    while (fread(rec, 1, 16, f) == 16) {
        uint32_t cap = (uint32_t)rec[8] | (uint32_t)rec[9] << 8 | (uint32_t)rec[10] << 16 | (uint32_t)rec[11] << 24;
        struct macsec_rx_sa rx;
        size_t plain_len = 0, l2;
        enum macsec_status st;
        uint8_t an;
        if (cap > sizeof(frame) || fread(frame, 1, cap, f) != cap) break;
        total++;
        if (!macsec_peek_secure(frame, cap, &an)) { notmac++; continue; }
        macsec_rx_sa_init(&rx, key, sci, salt, ssci, an, 64);
        st = macsec_unprotect(&rx, frame, cap, plain, sizeof(plain), &plain_len);
        l2 = macsec_l2_header_len(frame, cap);
        {
            unsigned b = cap < 128 ? 0 : cap < 256 ? 1 : cap < 512 ? 2 : cap < 1024 ? 3 : cap < 1500 ? 4 : 5;
            if (st == MACSEC_OK) { ok++; by_len_ok[b]++; } else { fail++; by_len_fail[b]++; }
            if (verbose && st != MACSEC_OK && fail <= 12)
                printf("FALHA len=%u l2=%zu tci=%02x sl=%u pn=%02x%02x%02x%02x -> %s\n", cap, l2,
                       frame[l2 + 2], frame[l2 + 3], frame[l2 + 4], frame[l2 + 5], frame[l2 + 6], frame[l2 + 7],
                       macsec_status_string(st));
        }
    }
    printf("quadros=%lu macsec_ok=%lu falha=%lu nao_macsec=%lu\n", total, ok, fail, notmac);
    {
        const char *names[] = {"<128", "128-255", "256-511", "512-1023", "1024-1499", ">=1500"};
        for (int i = 0; i < 6; i++) if (by_len_ok[i] || by_len_fail[i])
            printf("  %-10s ok=%lu falha=%lu\n", names[i], by_len_ok[i], by_len_fail[i]);
    }
    return 0;
}
