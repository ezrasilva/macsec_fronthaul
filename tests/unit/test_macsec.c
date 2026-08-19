#include "macsec.h"

#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static const uint8_t key[MACSEC_KEY_LEN] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const uint8_t sci[MACSEC_SCI_LEN] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01
};
static const uint8_t salt[MACSEC_SALT_LEN] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76
};
static const uint8_t frame[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00,
    0x40, 0x11, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x01,
    0xc0, 0x00, 0x02, 0x02, 0xde, 0xad, 0xbe, 0xef
};

static size_t protect_with_pn(uint64_t pn, uint8_t *secure)
{
    struct macsec_tx_sa tx;
    size_t secure_len = 0;

    macsec_tx_sa_init(&tx, key, sci, salt, 0x11223344, 0, pn);
    assert(macsec_protect(&tx, frame, sizeof(frame), secure, 256, &secure_len) == MACSEC_OK);
    return secure_len;
}

static enum macsec_status execute_request(struct macsec_crypto_request *request)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int count = 0;
    int final_count = 0;
    int ok;

    assert(context != NULL);
    if (request->encrypt) {
        ok = EVP_EncryptInit_ex2(context, EVP_aes_256_gcm(), request->key,
                                 request->nonce, NULL) == 1 &&
             EVP_EncryptUpdate(context, NULL, &count, request->aad,
                               (int)request->aad_len) == 1 &&
             EVP_EncryptUpdate(context, request->output, &count, request->input,
                               (int)request->input_len) == 1 &&
             EVP_EncryptFinal_ex(context, request->output + count,
                                 &final_count) == 1 &&
             EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG,
                                 MACSEC_ICV_LEN, request->tag) == 1;
    } else {
        ok = EVP_DecryptInit_ex2(context, EVP_aes_256_gcm(), request->key,
                                 request->nonce, NULL) == 1 &&
             EVP_DecryptUpdate(context, NULL, &count, request->aad,
                               (int)request->aad_len) == 1 &&
             EVP_DecryptUpdate(context, request->output, &count, request->input,
                               (int)request->input_len) == 1 &&
             EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG,
                                 MACSEC_ICV_LEN, request->tag) == 1 &&
             EVP_DecryptFinal_ex(context, request->output + count,
                                 &final_count) == 1;
    }
    EVP_CIPHER_CTX_free(context);
    return ok ? MACSEC_OK : MACSEC_ERR_AUTH;
}

static void test_round_trip(void)
{
    struct macsec_tx_sa tx;
    struct macsec_rx_sa rx;
    uint8_t secure[256];
    uint8_t plain[256];
    size_t secure_len = 0;
    size_t plain_len = 0;

    macsec_tx_sa_init(&tx, key, sci, salt, 0x11223344, 0, 1);
    macsec_rx_sa_init(&rx, key, sci, salt, 0x11223344, 0, 64);
    assert(macsec_protect(&tx, frame, sizeof(frame), secure, sizeof(secure), &secure_len) == MACSEC_OK);
    assert(secure[12] == 0x88 && secure[13] == 0xe5);
    assert(macsec_unprotect(&rx, secure, secure_len, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(plain_len == sizeof(frame));
    assert(memcmp(plain, frame, sizeof(frame)) == 0);
}

static void test_integrity_failure_does_not_consume_pn(void)
{
    struct macsec_rx_sa rx;
    uint8_t secure[256];
    uint8_t corrupted[256];
    uint8_t plain[256];
    size_t secure_len = protect_with_pn(7, secure);
    size_t plain_len = 0;

    memcpy(corrupted, secure, secure_len);
    corrupted[30] ^= 0x80;
    macsec_rx_sa_init(&rx, key, sci, salt, 0x11223344, 0, 64);
    assert(macsec_unprotect(&rx, corrupted, secure_len, plain, sizeof(plain), &plain_len) == MACSEC_ERR_AUTH);
    assert(macsec_unprotect(&rx, secure, secure_len, plain, sizeof(plain), &plain_len) == MACSEC_OK);
}

static void test_replay_and_out_of_order(void)
{
    struct macsec_rx_sa rx;
    uint8_t packet10[256], packet11[256], packet12[256];
    uint8_t plain[256];
    size_t len10 = protect_with_pn(10, packet10);
    size_t len11 = protect_with_pn(11, packet11);
    size_t len12 = protect_with_pn(12, packet12);
    size_t plain_len = 0;

    macsec_rx_sa_init(&rx, key, sci, salt, 0x11223344, 0, 4);
    assert(macsec_unprotect(&rx, packet10, len10, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, packet12, len12, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, packet11, len11, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, packet11, len11, plain, sizeof(plain), &plain_len) == MACSEC_ERR_REPLAY);
}

static void test_old_packet_and_pn_exhaustion(void)
{
    struct macsec_tx_sa tx;
    struct macsec_rx_sa rx;
    uint8_t packet1[256], packet5[256], secure[256], plain[256];
    size_t len1 = protect_with_pn(1, packet1);
    size_t len5 = protect_with_pn(5, packet5);
    size_t secure_len = 0;
    size_t plain_len = 0;

    macsec_rx_sa_init(&rx, key, sci, salt, 0x11223344, 0, 4);
    assert(macsec_unprotect(&rx, packet5, len5, plain, sizeof(plain), &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, packet1, len1, plain, sizeof(plain), &plain_len) == MACSEC_ERR_REPLAY);

    macsec_tx_sa_init(&tx, key, sci, salt, 0x11223344, 0, UINT64_MAX);
    assert(macsec_protect(&tx, frame, sizeof(frame), secure, sizeof(secure), &secure_len) == MACSEC_OK);
    assert(macsec_protect(&tx, frame, sizeof(frame), secure, sizeof(secure), &secure_len) == MACSEC_ERR_PN_EXHAUSTED);
}

static void test_xpn_low_word_rollover(void)
{
    struct macsec_tx_sa tx;
    struct macsec_rx_sa rx;
    uint8_t before[256], after[256], plain[256];
    size_t before_len = 0, after_len = 0, plain_len = 0;

    macsec_tx_sa_init(&tx, key, sci, salt, 0x11223344, 0, UINT32_MAX);
    macsec_rx_sa_init(&rx, key, sci, salt, 0x11223344, 0, 64);
    assert(macsec_protect(&tx, frame, sizeof(frame), before, sizeof(before),
                          &before_len) == MACSEC_OK);
    assert(macsec_protect(&tx, frame, sizeof(frame), after, sizeof(after),
                          &after_len) == MACSEC_OK);
    assert(before[16] == 0xff && before[17] == 0xff &&
           before[18] == 0xff && before[19] == 0xff);
    assert(after[16] == 0 && after[17] == 0 && after[18] == 0 && after[19] == 0);
    assert(macsec_unprotect(&rx, before, before_len, plain, sizeof(plain),
                            &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, after, after_len, plain, sizeof(plain),
                            &plain_len) == MACSEC_OK);
    assert(rx.highest_pn == UINT64_C(0x100000000));
}

static void test_xpn_rollover_out_of_order(void)
{
    struct macsec_rx_sa rx;
    uint8_t delayed[256], anchor[256], at_rollover[256], after[256], plain[256];
    size_t delayed_len = protect_with_pn(UINT64_C(0xfffffffe), delayed);
    size_t anchor_len = protect_with_pn(UINT32_MAX, anchor);
    size_t rollover_len = protect_with_pn(UINT64_C(0x100000000), at_rollover);
    size_t after_len = protect_with_pn(UINT64_C(0x100000001), after);
    size_t plain_len = 0;

    macsec_rx_sa_init(&rx, key, sci, salt, 0x11223344, 0, 64);
    assert(macsec_unprotect(&rx, anchor, anchor_len, plain,
                            sizeof(plain), &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, at_rollover, rollover_len, plain,
                            sizeof(plain), &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, after, after_len, plain,
                            sizeof(plain), &plain_len) == MACSEC_OK);
    assert(macsec_unprotect(&rx, delayed, delayed_len, plain,
                            sizeof(plain), &plain_len) == MACSEC_OK);
    assert(rx.highest_pn == UINT64_C(0x100000001));
    assert(macsec_unprotect(&rx, delayed, delayed_len, plain,
                            sizeof(plain), &plain_len) == MACSEC_ERR_REPLAY);
}

static void test_xpn_rollover_boundaries(void)
{
    struct macsec_rx_sa rx;
    uint8_t packets[4][256];
    uint8_t plain[256];
    const uint64_t pns[] = {
        UINT64_C(0xfffffffe), UINT64_C(0xffffffff),
        UINT64_C(0x100000000), UINT64_C(0x100000001)
    };
    size_t lengths[4];
    size_t plain_len = 0;
    size_t i;

    for (i = 0; i < 4U; i++) {
        lengths[i] = protect_with_pn(pns[i], packets[i]);
    }
    macsec_rx_sa_init(&rx, key, sci, salt, 0x11223344, 0, 64);
    for (i = 0; i < 4U; i++) {
        assert(macsec_unprotect(&rx, packets[i], lengths[i], plain,
                                sizeof(plain), &plain_len) == MACSEC_OK);
    }
    assert(rx.highest_pn == UINT64_C(0x100000001));
}

static void test_in_place_async_round_trip(void)
{
    struct macsec_tx_sa tx;
    struct macsec_tx_sa reference_tx;
    struct macsec_rx_sa rx;
    struct macsec_crypto_request request;
    uint8_t packet[256];
    uint8_t secure_copy[256];
    uint8_t reference_secure[256];
    size_t secure_len = 0;
    size_t reference_len = 0;
    size_t plain_len = 0;

    memcpy(packet, frame, sizeof(frame));
    macsec_tx_sa_init(&tx, key, sci, salt, 0x11223344, 0, 1);
    macsec_tx_sa_init(&reference_tx, key, sci, salt, 0x11223344, 0, 1);
    macsec_rx_sa_init(&rx, key, sci, salt, 0x11223344, 0, 64);
    assert(macsec_prepare_protect_in_place(&tx, packet, sizeof(frame),
                                           sizeof(packet), &secure_len,
                                           &request) == MACSEC_OK);
    assert(execute_request(&request) == MACSEC_OK);
    assert(secure_len == sizeof(frame) + MACSEC_FRAME_OVERHEAD);
    assert(macsec_protect(&reference_tx, frame, sizeof(frame), reference_secure,
                          sizeof(reference_secure), &reference_len) == MACSEC_OK);
    assert(reference_len == secure_len);
    assert(memcmp(reference_secure, packet, secure_len) == 0);
    memcpy(secure_copy, packet, secure_len);
    assert(macsec_prepare_unprotect_in_place(&rx, packet, secure_len,
                                             &plain_len, &request) == MACSEC_OK);
    assert(macsec_finish_unprotect_in_place(&rx, &request,
                                             execute_request(&request),
                                             packet) == MACSEC_OK);
    assert(plain_len == sizeof(frame));
    assert(memcmp(packet, frame, sizeof(frame)) == 0);
    assert(macsec_prepare_unprotect_in_place(&rx, secure_copy, secure_len,
                                             &plain_len, &request) == MACSEC_ERR_REPLAY);
}

static void test_exact_frame_capacity(void)
{
    struct macsec_tx_sa tx;
    uint8_t too_small[sizeof(frame) + MACSEC_FRAME_OVERHEAD - 1U];
    uint8_t exact[sizeof(frame) + MACSEC_FRAME_OVERHEAD];
    size_t secure_len = 0;

    macsec_tx_sa_init(&tx, key, sci, salt, 0x11223344, 0, 1);
    assert(macsec_protect(&tx, frame, sizeof(frame), too_small,
                          sizeof(too_small), &secure_len) == MACSEC_ERR_CAPACITY);
    assert(tx.next_pn == 1U);
    assert(macsec_protect(&tx, frame, sizeof(frame), exact, sizeof(exact),
                          &secure_len) == MACSEC_OK);
    assert(secure_len == sizeof(exact));
}

int main(void)
{
    test_round_trip();
    test_integrity_failure_does_not_consume_pn();
    test_replay_and_out_of_order();
    test_old_packet_and_pn_exhaustion();
    test_xpn_low_word_rollover();
    test_xpn_rollover_out_of_order();
    test_xpn_rollover_boundaries();
    test_in_place_async_round_trip();
    test_exact_frame_capacity();
    puts("all MACsec unit tests passed");
    return 0;
}
