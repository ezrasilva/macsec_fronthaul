#include "macsec.h"

#include <assert.h>
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

int main(void)
{
    test_round_trip();
    test_integrity_failure_does_not_consume_pn();
    test_replay_and_out_of_order();
    test_old_packet_and_pn_exhaustion();
    test_xpn_low_word_rollover();
    puts("all MACsec unit tests passed");
    return 0;
}
