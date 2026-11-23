/* Layout com VLAN fora do MACsec (SecTAG depois da tag 802.1Q), vetores reais
 * do kernel Linux e testes negativos. Ver docs/macsec-profile.md. */
#include "macsec.h"
#include "../vectors/kernel_vlan_xpn.h"

#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static uint8_t key_ab[MACSEC_KEY_LEN], key_ba[MACSEC_KEY_LEN];
static const uint8_t salt_ab[MACSEC_SALT_LEN] = {0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55};
static const uint8_t salt_ba[MACSEC_SALT_LEN] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc};
static const uint8_t sci_a[MACSEC_SCI_LEN] = {0x02,0,0,0,0,0x0a,0,0x01};
static const uint8_t sci_b[MACSEC_SCI_LEN] = {0x02,0,0,0,0,0x0b,0,0x01};

static const uint8_t vlan_frame[] = {
    0x02,0,0,0,0,0x0b, 0x02,0,0,0,0,0x0a,
    0x81,0x00, 0x08,0x71,              /* 802.1Q vid 2161 */
    0x08,0x00,
    0x45,0x00,0x00,0x1c,0x00,0x01,0x00,0x00,0x40,0x11,0x00,0x00,
    0xc0,0x00,0x02,0x01,0xc0,0x00,0x02,0x02,0xde,0xad,0xbe,0xef,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
};

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void init_keys(void)
{
    for (unsigned i = 0; i < MACSEC_KEY_LEN; i++) {
        key_ab[i] = (uint8_t)i;
        key_ba[i] = (uint8_t)(31U - i);
    }
}

static void run_encrypt(const struct macsec_crypto_request *r)
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0;

    assert(c != NULL && r->encrypt);
    assert(EVP_EncryptInit_ex2(c, EVP_aes_256_gcm(), r->key, r->nonce, NULL) == 1);
    assert(EVP_EncryptUpdate(c, NULL, &n, r->aad, (int)r->aad_len) == 1);
    assert(EVP_EncryptUpdate(c, r->output, &n, r->input, (int)r->input_len) == 1);
    assert(EVP_EncryptFinal_ex(c, r->output + n, &n) == 1);
    assert(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, MACSEC_ICV_LEN, r->tag) == 1);
    EVP_CIPHER_CTX_free(c);
}

static void tx_ab(struct macsec_tx_sa *tx, uint64_t pn) { macsec_tx_sa_init(tx, key_ab, sci_a, salt_ab, 1, 0, pn); }
static void rx_ab(struct macsec_rx_sa *rx) { macsec_rx_sa_init(rx, key_ab, sci_a, salt_ab, 1, 0, 64); }

static void test_kernel_frame(const uint8_t *kf, size_t len, const uint8_t *key,
                              const uint8_t *sci, const uint8_t *salt, uint32_t ssci)
{
    struct macsec_rx_sa rx;
    struct macsec_tx_sa tx;
    uint8_t plain[512], again[512];
    size_t plain_len = 0, again_len = 0;
    uint32_t pn = be32(kf + 16 + 4);

    /* quadro do kernel -> verificado pela nossa SecY */
    macsec_rx_sa_init(&rx, key, sci, salt, ssci, 0, 64);
    assert(macsec_unprotect(&rx, kf, len, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(plain_len == len - MACSEC_FRAME_OVERHEAD);
    assert(plain[12] == 0x81 && plain[13] == 0x00 && plain[14] == 0x08 && plain[15] == 0x71);
    assert(plain[16] == 0x08 && plain[17] == 0x00);       /* EtherType IPv4 */
    /* nosso quadro -> identico, byte a byte, ao do kernel (mesmo PN) */
    macsec_tx_sa_init(&tx, key, sci, salt, ssci, 0, pn);
    assert(macsec_protect(&tx, plain, plain_len, again, sizeof(again), &again_len) == MACSEC_OK);
    assert(again_len == len);
    assert(memcmp(again, kf, len) == 0);
}

static void test_kernel_vectors(void)
{
    test_kernel_frame(kernel_frame_ab, sizeof(kernel_frame_ab), key_ab, sci_a, salt_ab, 1);
    test_kernel_frame(kernel_frame_ba, sizeof(kernel_frame_ba), key_ba, sci_b, salt_ba, 2);
}

static void test_layout_and_aad(void)
{
    struct macsec_tx_sa tx;
    struct macsec_crypto_request req;
    uint8_t secure[256];
    size_t len = 0;

    tx_ab(&tx, 7);
    assert(macsec_prepare_protect(&tx, vlan_frame, sizeof(vlan_frame), secure,
                                  sizeof(secure), &len, &req) == MACSEC_OK);
    assert(len == sizeof(vlan_frame) + MACSEC_FRAME_OVERHEAD);
    assert(secure[12] == 0x81 && secure[13] == 0x00);                /* VLAN fora */
    assert(secure[16] == 0x88 && secure[17] == 0xe5);                /* SecTAG depois da VLAN */
    assert(req.l2_len == 16U && req.aad_len == MACSEC_AAD_LEN);
    assert(memcmp(req.aad, vlan_frame, 12) == 0);                    /* AAD = DA SA ... */
    assert(req.aad[12] == 0x88 && req.aad[13] == 0xe5);              /* ... SecTAG (sem VLAN) */
    assert(memcmp(req.aad + 14, secure + 18, 14) == 0);
    assert(req.input == vlan_frame + 16 || req.input == secure + 32);
}

static void test_vlan_swap_keeps_icv_valid(void)
{
    struct macsec_tx_sa tx;
    struct macsec_rx_sa rx;
    uint8_t secure[256], plain[256];
    size_t len = 0, plain_len = 0;

    tx_ab(&tx, 1); rx_ab(&rx);
    assert(macsec_protect(&tx, vlan_frame, sizeof(vlan_frame), secure, sizeof(secure), &len) == MACSEC_OK);
    secure[14] = 0x00; secure[15] = 0xa1;                            /* 2161 -> 161 (gateway) */
    assert(macsec_unprotect(&rx, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(plain[14] == 0x00 && plain[15] == 0xa1);
    assert(memcmp(plain + 16, vlan_frame + 16, sizeof(vlan_frame) - 16) == 0);
}

static void test_in_place_and_direct_match_copy(void)
{
    struct macsec_tx_sa t1, t2, t3;
    struct macsec_crypto_request req;
    uint8_t ref[256], inpl[256], dir[256];
    size_t ref_len = 0, l1 = 0, l2 = 0;

    tx_ab(&t1, 5); tx_ab(&t2, 5); tx_ab(&t3, 5);
    assert(macsec_protect(&t1, vlan_frame, sizeof(vlan_frame), ref, sizeof(ref), &ref_len) == MACSEC_OK);

    memcpy(inpl, vlan_frame, sizeof(vlan_frame));
    assert(macsec_prepare_protect_in_place(&t2, inpl, sizeof(vlan_frame), sizeof(inpl), &l1, &req) == MACSEC_OK);
    run_encrypt(&req);
    assert(l1 == ref_len && memcmp(inpl, ref, ref_len) == 0);

    memset(dir, 0, sizeof(dir));
    memcpy(dir, vlan_frame, 16);
    memcpy(dir + 32, vlan_frame + 16, sizeof(vlan_frame) - 16);
    assert(macsec_prepare_protect_direct(&t3, dir, 16, sizeof(vlan_frame), sizeof(dir), &l2, &req) == MACSEC_OK);
    run_encrypt(&req);
    assert(l2 == ref_len && memcmp(dir, ref, ref_len) == 0);
}

static void test_stateless_pn_variant(void)
{
    struct macsec_tx_sa t_ref, t_sa;
    struct macsec_crypto_request req;
    uint8_t ref[256], dir[256];
    size_t ref_len = 0, len = 0;

    tx_ab(&t_ref, 0x1234); tx_ab(&t_sa, 1);              /* PN da SA ignorado: usa o passado */
    assert(macsec_protect(&t_ref, vlan_frame, sizeof(vlan_frame), ref, sizeof(ref), &ref_len) == MACSEC_OK);
    memset(dir, 0, sizeof(dir));
    memcpy(dir, vlan_frame, 16);
    memcpy(dir + 32, vlan_frame + 16, sizeof(vlan_frame) - 16);
    assert(macsec_prepare_protect_direct_pn(&t_sa, 0x1234, dir, 16, sizeof(vlan_frame), sizeof(dir), &len, &req) == MACSEC_OK);
    run_encrypt(&req);
    assert(len == ref_len && memcmp(dir, ref, ref_len) == 0);
    assert(t_sa.next_pn == 1U);                           /* a SA nao foi modificada */
    assert(macsec_prepare_protect_direct_pn(&t_sa, 0, dir, 16, sizeof(vlan_frame), sizeof(dir), &len, &req) == MACSEC_ERR_PN_EXHAUSTED);
    assert(macsec_prepare_protect_direct_pn(&t_sa, 1, dir, 16, sizeof(vlan_frame), sizeof(vlan_frame) + 31, &len, &req) == MACSEC_ERR_CAPACITY);
    assert(macsec_prepare_protect_direct_pn(&t_sa, 1, dir, 13, sizeof(vlan_frame), sizeof(dir), &len, &req) == MACSEC_ERR_ARGUMENT);
}

static void test_negatives(void)
{
    struct macsec_tx_sa tx;
    struct macsec_rx_sa rx, wrong;
    uint8_t secure[256], bad[256], plain[256];
    size_t len = 0, plain_len = 0;
    size_t i;

    tx_ab(&tx, 1); rx_ab(&rx);
    assert(macsec_protect(&tx, vlan_frame, sizeof(vlan_frame), secure, sizeof(secure), &len) == MACSEC_OK);

    /* ICV adulterado, cifrado adulterado, SecTAG (PN) adulterado, DA adulterado */
    memcpy(bad, secure, len); bad[len - 1] ^= 1;
    assert(macsec_unprotect(&rx, bad, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_AUTH);
    memcpy(bad, secure, len); bad[40] ^= 1;
    assert(macsec_unprotect(&rx, bad, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_AUTH);
    memcpy(bad, secure, len); bad[22] ^= 1;
    assert(macsec_unprotect(&rx, bad, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_AUTH);
    memcpy(bad, secure, len); bad[0] ^= 1;
    assert(macsec_unprotect(&rx, bad, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_AUTH);
    /* chave errada */
    macsec_rx_sa_init(&wrong, key_ba, sci_a, salt_ab, 1, 0, 64);
    assert(macsec_unprotect(&wrong, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_AUTH);
    /* salt/SSCI errados */
    macsec_rx_sa_init(&wrong, key_ab, sci_a, salt_ba, 1, 0, 64);
    assert(macsec_unprotect(&wrong, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_AUTH);
    macsec_rx_sa_init(&wrong, key_ab, sci_a, salt_ab, 2, 0, 64);
    assert(macsec_unprotect(&wrong, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_AUTH);
    /* AN desconhecido e SCI desconhecido */
    macsec_rx_sa_init(&wrong, key_ab, sci_a, salt_ab, 1, 1, 64);
    assert(macsec_unprotect(&wrong, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_FORMAT);
    macsec_rx_sa_init(&wrong, key_ab, sci_b, salt_ab, 1, 0, 64);
    assert(macsec_unprotect(&wrong, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_FORMAT);
    /* truncamentos nao podem ler fora do quadro */
    for (i = 0; i < len; i++) {
        enum macsec_status s = macsec_unprotect(&rx, secure, i, plain, sizeof(plain), &plain_len);
        assert(s == MACSEC_ERR_FORMAT || s == MACSEC_ERR_AUTH);
    }
    /* nada acima consumiu o PN: o quadro original ainda passa, uma unica vez */
    assert(macsec_unprotect(&rx, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_REPLAY);
    /* quadro que nao e MACsec */
    assert(macsec_unprotect(&rx, vlan_frame, sizeof(vlan_frame), plain, sizeof(plain), &plain_len) == MACSEC_ERR_FORMAT);
}

static void test_without_vlan_and_qinq(void)
{
    struct macsec_tx_sa tx;
    struct macsec_rx_sa rx;
    uint8_t untagged[sizeof(vlan_frame) - 4], tagged[sizeof(vlan_frame)];
    uint8_t secure[256], plain[256];
    size_t len = 0, plain_len = 0;

    /* sem VLAN: SecTAG logo apos DA SA (comportamento anterior preservado) */
    memcpy(untagged, vlan_frame, 12);
    memcpy(untagged + 12, vlan_frame + 16, sizeof(untagged) - 12);
    tx_ab(&tx, 1); rx_ab(&rx);
    assert(macsec_protect(&tx, untagged, sizeof(untagged), secure, sizeof(secure), &len) == MACSEC_OK);
    assert(secure[12] == 0x88 && secure[13] == 0xe5);
    assert(macsec_unprotect(&rx, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(plain_len == sizeof(untagged) && memcmp(plain, untagged, plain_len) == 0);

    /* 802.1ad (0x88a8) tambem fica fora */
    memcpy(tagged, vlan_frame, sizeof(tagged));
    tagged[12] = 0x88; tagged[13] = 0xa8;
    tx_ab(&tx, 1); rx_ab(&rx);
    assert(macsec_protect(&tx, tagged, sizeof(tagged), secure, sizeof(secure), &len) == MACSEC_OK);
    assert(secure[12] == 0x88 && secure[13] == 0xa8 && secure[16] == 0x88 && secure[17] == 0xe5);
    assert(macsec_unprotect(&rx, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(memcmp(plain, tagged, sizeof(tagged)) == 0);
}

static void test_short_frame_sl(void)
{
    struct macsec_tx_sa tx;
    struct macsec_rx_sa rx;
    uint8_t shortf[16 + 2 + 10], secure[128], plain[128];
    size_t len = 0, plain_len = 0;

    memcpy(shortf, vlan_frame, 18);
    memset(shortf + 18, 0x5a, 10);
    tx_ab(&tx, 1); rx_ab(&rx);
    assert(macsec_protect(&tx, shortf, sizeof(shortf), secure, sizeof(secure), &len) == MACSEC_OK);
    assert(secure[16 + 3] == 12U);  /* SL = EtherType + 10 bytes */
    assert(macsec_unprotect(&rx, secure, len, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(memcmp(plain, shortf, sizeof(shortf)) == 0);
}

int main(void)
{
    init_keys();
    test_kernel_vectors();
    test_layout_and_aad();
    test_vlan_swap_keeps_icv_valid();
    test_in_place_and_direct_match_copy();
    test_stateless_pn_variant();
    test_negatives();
    test_without_vlan_and_qinq();
    test_short_frame_sl();
    puts("all MACsec VLAN unit tests passed");
    return 0;
}
