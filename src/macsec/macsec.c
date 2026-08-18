#include "macsec.h"

#include <limits.h>
#include <openssl/evp.h>
#include <string.h>

#define ETHERNET_HEADER_LEN 14U
#define MAC_ADDRESSES_LEN 12U
#define SECTAG_WITH_SCI_LEN 16U
#define SECURE_HEADER_LEN (MAC_ADDRESSES_LEN + SECTAG_WITH_SCI_LEN)
#define MACSEC_OVERHEAD (SECTAG_WITH_SCI_LEN - 2U + MACSEC_ICV_LEN)

#define TCI_SC 0x20U
#define TCI_E 0x08U
#define TCI_C 0x04U
#define TCI_AN_MASK 0x03U
#define TCI_PROFILE (TCI_SC | TCI_E | TCI_C)

static macsec_aead_backend_fn aead_backend;
static void *aead_backend_context;

void macsec_set_aead_backend(macsec_aead_backend_fn backend, void *context)
{
    aead_backend = backend;
    aead_backend_context = context;
}

static uint16_t load_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void store_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void store_be32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void store_be64(uint8_t *p, uint64_t value)
{
    store_be32(p, (uint32_t)(value >> 32));
    store_be32(p + 4, (uint32_t)value);
}

static void make_xpn_nonce(uint8_t nonce[12], uint32_t ssci, uint64_t pn,
                           const uint8_t salt[MACSEC_SALT_LEN])
{
    size_t i;
    store_be32(nonce, ssci);
    store_be64(nonce + 4, pn);
    for (i = 0; i < 12U; i++) {
        nonce[i] ^= salt[i];
    }
}

static uint64_t recover_xpn(const struct macsec_rx_sa *sa, uint32_t low)
{
    uint64_t expected = sa->highest_pn == 0U ? 1U : sa->highest_pn + 1U;
    uint64_t recovered = (expected & UINT64_C(0xffffffff00000000)) | low;
    uint32_t expected_low = (uint32_t)expected;
    if (low < expected_low && ((low ^ expected_low) & UINT32_C(0x80000000)) != 0U) {
        recovered += UINT64_C(0x100000000);
    }
    return recovered;
}

static bool replay_rejected(const struct macsec_rx_sa *sa, uint64_t pn)
{
    uint64_t distance;

    if (pn == 0U) {
        return true;
    }
    if (sa->highest_pn == 0U || pn > sa->highest_pn) {
        return false;
    }
    distance = sa->highest_pn - pn;
    return distance >= sa->replay_window ||
           (sa->replay_bitmap & (UINT64_C(1) << distance)) != 0U;
}

static void replay_accept(struct macsec_rx_sa *sa, uint64_t pn)
{
    if (sa->highest_pn == 0U) {
        sa->highest_pn = pn;
        sa->replay_bitmap = UINT64_C(1);
    } else if (pn > sa->highest_pn) {
        uint64_t shift = pn - sa->highest_pn;
        sa->replay_bitmap = shift >= MACSEC_MAX_REPLAY_WINDOW
                                ? UINT64_C(1)
                                : (sa->replay_bitmap << shift) | UINT64_C(1);
        sa->highest_pn = pn;
    } else {
        sa->replay_bitmap |= UINT64_C(1) << (sa->highest_pn - pn);
    }

    if (sa->replay_window < MACSEC_MAX_REPLAY_WINDOW) {
        sa->replay_bitmap &= (UINT64_C(1) << sa->replay_window) - 1U;
    }
}

static enum macsec_status gcm_encrypt(const uint8_t key[MACSEC_KEY_LEN],
                                      const uint8_t nonce[12],
                                      const uint8_t *aad,
                                      size_t aad_len,
                                      const uint8_t *input,
                                      size_t input_len,
                                      uint8_t *output,
                                      uint8_t tag[MACSEC_ICV_LEN])
{
    EVP_CIPHER_CTX *ctx = NULL;
    int count = 0;
    int final_count = 0;
    enum macsec_status status = MACSEC_ERR_CRYPTO;

    if (aad_len > INT_MAX || input_len > INT_MAX) {
        return MACSEC_ERR_ARGUMENT;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_EncryptInit_ex2(ctx, EVP_aes_256_gcm(), key, nonce, NULL) != 1 ||
        EVP_EncryptUpdate(ctx, NULL, &count, aad, (int)aad_len) != 1 ||
        EVP_EncryptUpdate(ctx, output, &count, input, (int)input_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, output + count, &final_count) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, MACSEC_ICV_LEN, tag) != 1) {
        goto done;
    }
    status = MACSEC_OK;

done:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

static enum macsec_status gcm_decrypt(const uint8_t key[MACSEC_KEY_LEN],
                                      const uint8_t nonce[12],
                                      const uint8_t *aad,
                                      size_t aad_len,
                                      const uint8_t *input,
                                      size_t input_len,
                                      const uint8_t tag[MACSEC_ICV_LEN],
                                      uint8_t *output)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int count = 0;
    int final_count = 0;
    enum macsec_status status = MACSEC_ERR_CRYPTO;

    if (aad_len > INT_MAX || input_len > INT_MAX) {
        return MACSEC_ERR_ARGUMENT;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || EVP_DecryptInit_ex2(ctx, EVP_aes_256_gcm(), key, nonce, NULL) != 1 ||
        EVP_DecryptUpdate(ctx, NULL, &count, aad, (int)aad_len) != 1 ||
        EVP_DecryptUpdate(ctx, output, &count, input, (int)input_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, MACSEC_ICV_LEN, (void *)tag) != 1) {
        goto done;
    }
    if (EVP_DecryptFinal_ex(ctx, output + count, &final_count) != 1) {
        status = MACSEC_ERR_AUTH;
        goto done;
    }
    status = MACSEC_OK;

done:
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

void macsec_tx_sa_init(struct macsec_tx_sa *sa,
                       const uint8_t key[MACSEC_KEY_LEN],
                       const uint8_t sci[MACSEC_SCI_LEN],
                       const uint8_t salt[MACSEC_SALT_LEN], uint32_t ssci,
                       uint8_t association_number,
                       uint64_t initial_pn)
{
    memset(sa, 0, sizeof(*sa));
    memcpy(sa->key, key, MACSEC_KEY_LEN);
    memcpy(sa->sci, sci, MACSEC_SCI_LEN);
    memcpy(sa->salt, salt, MACSEC_SALT_LEN);
    sa->ssci = ssci;
    sa->association_number = association_number & TCI_AN_MASK;
    sa->next_pn = initial_pn;
}

void macsec_rx_sa_init(struct macsec_rx_sa *sa,
                       const uint8_t key[MACSEC_KEY_LEN],
                       const uint8_t sci[MACSEC_SCI_LEN],
                       const uint8_t salt[MACSEC_SALT_LEN], uint32_t ssci,
                       uint8_t association_number,
                       uint8_t replay_window)
{
    memset(sa, 0, sizeof(*sa));
    memcpy(sa->key, key, MACSEC_KEY_LEN);
    memcpy(sa->sci, sci, MACSEC_SCI_LEN);
    memcpy(sa->salt, salt, MACSEC_SALT_LEN);
    sa->ssci = ssci;
    sa->association_number = association_number & TCI_AN_MASK;
    sa->replay_window = replay_window == 0U || replay_window > MACSEC_MAX_REPLAY_WINDOW
                            ? MACSEC_MAX_REPLAY_WINDOW
                            : replay_window;
}

enum macsec_status macsec_protect(struct macsec_tx_sa *sa,
                                  const uint8_t *plain_frame,
                                  size_t plain_len,
                                  uint8_t *secure_frame,
                                  size_t secure_capacity,
                                  size_t *secure_len)
{
    size_t protected_len;
    uint8_t nonce[12];
    uint8_t *tag;
    enum macsec_status status;

    if (sa == NULL || plain_frame == NULL || secure_frame == NULL || secure_len == NULL ||
        plain_len < ETHERNET_HEADER_LEN) {
        return MACSEC_ERR_ARGUMENT;
    }
    if (sa->next_pn == 0U) {
        return MACSEC_ERR_PN_EXHAUSTED;
    }
    if (plain_len > SIZE_MAX - MACSEC_OVERHEAD ||
        secure_capacity < plain_len + MACSEC_OVERHEAD) {
        return MACSEC_ERR_CAPACITY;
    }

    protected_len = plain_len - MAC_ADDRESSES_LEN;
    memcpy(secure_frame, plain_frame, MAC_ADDRESSES_LEN);
    store_be16(secure_frame + 12, MACSEC_ETHERTYPE);
    secure_frame[14] = (uint8_t)(TCI_PROFILE | sa->association_number);
    secure_frame[15] = protected_len < 48U ? (uint8_t)protected_len : 0U;
    store_be32(secure_frame + 16, (uint32_t)sa->next_pn);
    memcpy(secure_frame + 20, sa->sci, MACSEC_SCI_LEN);

    make_xpn_nonce(nonce, sa->ssci, sa->next_pn, sa->salt);
    tag = secure_frame + SECURE_HEADER_LEN + protected_len;
    status = aead_backend != NULL
                 ? aead_backend(true, sa->key, nonce, secure_frame,
                                SECURE_HEADER_LEN, plain_frame + MAC_ADDRESSES_LEN,
                                protected_len, secure_frame + SECURE_HEADER_LEN,
                                tag, aead_backend_context)
                 : gcm_encrypt(sa->key, nonce, secure_frame, SECURE_HEADER_LEN,
                               plain_frame + MAC_ADDRESSES_LEN, protected_len,
                               secure_frame + SECURE_HEADER_LEN, tag);
    if (status != MACSEC_OK) {
        return status;
    }

    *secure_len = SECURE_HEADER_LEN + protected_len + MACSEC_ICV_LEN;
    sa->next_pn = sa->next_pn == UINT64_MAX ? 0U : sa->next_pn + 1U;
    return MACSEC_OK;
}

enum macsec_status macsec_unprotect(struct macsec_rx_sa *sa,
                                    const uint8_t *secure_frame,
                                    size_t secure_len,
                                    uint8_t *plain_frame,
                                    size_t plain_capacity,
                                    size_t *plain_len)
{
    size_t protected_len;
    size_t result_len;
    uint8_t nonce[12];
    uint8_t tci;
    uint8_t short_length;
    uint64_t pn;
    enum macsec_status status;

    if (sa == NULL || secure_frame == NULL || plain_frame == NULL || plain_len == NULL) {
        return MACSEC_ERR_ARGUMENT;
    }
    if (secure_len < SECURE_HEADER_LEN + 2U + MACSEC_ICV_LEN ||
        load_be16(secure_frame + 12) != MACSEC_ETHERTYPE) {
        return MACSEC_ERR_FORMAT;
    }
    tci = secure_frame[14];
    if ((tci & (TCI_SC | TCI_E | TCI_C)) != TCI_PROFILE ||
        (tci & TCI_AN_MASK) != sa->association_number ||
        memcmp(secure_frame + 20, sa->sci, MACSEC_SCI_LEN) != 0) {
        return MACSEC_ERR_FORMAT;
    }

    protected_len = secure_len - SECURE_HEADER_LEN - MACSEC_ICV_LEN;
    short_length = secure_frame[15];
    if ((protected_len < 48U && short_length != protected_len) ||
        (protected_len >= 48U && short_length != 0U)) {
        return MACSEC_ERR_FORMAT;
    }
    result_len = MAC_ADDRESSES_LEN + protected_len;
    if (plain_capacity < result_len) {
        return MACSEC_ERR_CAPACITY;
    }

    pn = recover_xpn(sa, load_be32(secure_frame + 16));
    if (replay_rejected(sa, pn)) {
        return MACSEC_ERR_REPLAY;
    }
    make_xpn_nonce(nonce, sa->ssci, pn, sa->salt);
    memcpy(plain_frame, secure_frame, MAC_ADDRESSES_LEN);
    if (aead_backend != NULL) {
        uint8_t tag[MACSEC_ICV_LEN];

        memcpy(tag, secure_frame + SECURE_HEADER_LEN + protected_len,
               sizeof(tag));
        status = aead_backend(false, sa->key, nonce, secure_frame,
                              SECURE_HEADER_LEN, secure_frame + SECURE_HEADER_LEN,
                              protected_len, plain_frame + MAC_ADDRESSES_LEN,
                              tag, aead_backend_context);
    } else {
        status = gcm_decrypt(sa->key, nonce, secure_frame, SECURE_HEADER_LEN,
                             secure_frame + SECURE_HEADER_LEN, protected_len,
                             secure_frame + SECURE_HEADER_LEN + protected_len,
                             plain_frame + MAC_ADDRESSES_LEN);
    }
    if (status != MACSEC_OK) {
        return status;
    }

    replay_accept(sa, pn);
    *plain_len = result_len;
    return MACSEC_OK;
}

const char *macsec_status_string(enum macsec_status status)
{
    static const char *const names[] = {
        "ok", "invalid argument", "insufficient capacity", "invalid frame",
        "authentication failed", "replay rejected", "packet number exhausted",
        "cryptographic failure"
    };
    return status >= MACSEC_OK && status <= MACSEC_ERR_CRYPTO
               ? names[status]
               : "unknown status";
}
