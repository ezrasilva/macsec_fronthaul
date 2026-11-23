#include "macsec.h"

#include <limits.h>
#ifndef MACSEC_NO_OPENSSL
#include <openssl/evp.h>
#endif
#include <string.h>

#define ETHERNET_HEADER_LEN 14U
#define MAC_ADDRESSES_LEN 12U
#define SECTAG_WITH_SCI_LEN 16U
#define VLAN_TAG_LEN 4U
#define MACSEC_OVERHEAD (SECTAG_WITH_SCI_LEN + MACSEC_ICV_LEN)

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
    uint64_t upper = expected & UINT64_C(0xffffffff00000000);
    uint64_t recovered = upper | low;
    uint32_t expected_low = (uint32_t)expected;

    if (low < expected_low && ((low ^ expected_low) & UINT32_C(0x80000000)) != 0U) {
        if (upper != UINT64_C(0xffffffff00000000)) {
            recovered += UINT64_C(0x100000000);
        }
    } else if (low > expected_low &&
               ((low ^ expected_low) & UINT32_C(0x80000000)) != 0U &&
               upper != 0U) {
        recovered -= UINT64_C(0x100000000);
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

#ifndef MACSEC_NO_OPENSSL
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

#endif /* MACSEC_NO_OPENSSL */

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

/* Layout (VLAN opcional fica FORA do AAD, do ICV e da cifra):
 *   plain : DA SA [8100 TCI] ET payload
 *   secure: DA SA [8100 TCI] 88E5 SecTAG(TCI SL PN SCI) ET payload ICV
 *   AAD   : DA SA 88E5 TCI SL PN SCI (28 bytes, montado em buffer proprio) */

static bool is_vlan_ethertype(uint16_t et)
{
    return et == 0x8100U || et == 0x88a8U;
}

size_t macsec_l2_header_len(const uint8_t *frame, size_t len)
{
    size_t hdr;

    if (frame == NULL || len < ETHERNET_HEADER_LEN) return 0U;
    hdr = is_vlan_ethertype(load_be16(frame + 12)) ? MAC_ADDRESSES_LEN + VLAN_TAG_LEN
                                                    : MAC_ADDRESSES_LEN;
    return len >= hdr + 2U ? hdr : 0U;
}

bool macsec_peek_secure(const uint8_t *frame, size_t len, uint8_t *an)
{
    size_t l2;

    if (frame == NULL || len < MAC_ADDRESSES_LEN + 2U) return false;
    l2 = is_vlan_ethertype(load_be16(frame + 12)) ? MAC_ADDRESSES_LEN + VLAN_TAG_LEN
                                                   : MAC_ADDRESSES_LEN;
    if (len < l2 + 3U || load_be16(frame + l2) != MACSEC_ETHERTYPE) return false;
    if (an != NULL) *an = frame[l2 + 2U] & TCI_AN_MASK;
    return true;
}

static void write_sectag(uint8_t *p, const struct macsec_tx_sa *sa,
                         size_t protected_len, uint64_t pn)
{
    store_be16(p, MACSEC_ETHERTYPE);
    p[2] = (uint8_t)(TCI_PROFILE | sa->association_number);
    p[3] = protected_len < 48U ? (uint8_t)protected_len : 0U;
    store_be32(p + 4, (uint32_t)pn);
    memcpy(p + 8, sa->sci, MACSEC_SCI_LEN);
}

static void build_aad(uint8_t aad[MACSEC_AAD_LEN], const uint8_t *macs,
                      const uint8_t *sectag)
{
    memcpy(aad, macs, MAC_ADDRESSES_LEN);
    memcpy(aad + MAC_ADDRESSES_LEN, sectag, SECTAG_WITH_SCI_LEN);
}

static void fill_request(struct macsec_crypto_request *request, bool encrypt,
                         const uint8_t *key, uint32_t ssci, uint64_t pn,
                         const uint8_t *salt, size_t l2, const uint8_t *input,
                         size_t input_len, uint8_t *output, uint8_t *tag)
{
    request->encrypt = encrypt;
    request->key = key;
    make_xpn_nonce(request->nonce, ssci, pn, salt);
    request->aad = request->aad_storage;
    request->aad_len = MACSEC_AAD_LEN;
    request->input = input;
    request->input_len = input_len;
    request->output = output;
    request->tag = tag;
    request->packet_number = pn;
    request->l2_len = l2;
}

/* Monta SecTAG e requisicao com um PN JA reservado; nao altera a SA. */
static void protect_layout_pn(
    const struct macsec_tx_sa *sa, uint64_t pn, uint8_t *frame, size_t l2,
    size_t plain_len, const uint8_t *input, uint8_t *output,
    size_t *secure_len, struct macsec_crypto_request *request)
{
    size_t protected_len = plain_len - l2;

    write_sectag(frame + l2, sa, protected_len, pn);
    memset(request, 0, sizeof(*request));
    build_aad(request->aad_storage, frame, frame + l2);
    fill_request(request, true, sa->key, sa->ssci, pn, sa->salt, l2, input,
                 protected_len, output, output + protected_len);
    *secure_len = plain_len + MACSEC_OVERHEAD;
}

/* secure_frame: DA SA [VLAN] <espaco p/ SecTAG> ET payload <espaco p/ ICV>.
 * O chamador ja posicionou ET/payload em frame[l2 + 16]. */
static enum macsec_status protect_layout(
    struct macsec_tx_sa *sa, uint8_t *frame, size_t l2, size_t plain_len,
    const uint8_t *input, uint8_t *output, size_t *secure_len,
    struct macsec_crypto_request *request)
{
    uint64_t pn = sa->next_pn;

    protect_layout_pn(sa, pn, frame, l2, plain_len, input, output, secure_len,
                      request);
    /* Reservar o PN antes da submissao assincrona evita reutilizar nonce. */
    sa->next_pn = pn == UINT64_MAX ? 0U : pn + 1U;
    return MACSEC_OK;
}

static enum macsec_status protect_check_l2(const struct macsec_tx_sa *sa,
                                           size_t l2, size_t plain_len,
                                           size_t capacity)
{
    if (sa == NULL || (l2 != MAC_ADDRESSES_LEN && l2 != MAC_ADDRESSES_LEN + VLAN_TAG_LEN) ||
        plain_len < l2 + 2U) return MACSEC_ERR_ARGUMENT;
    if (sa->next_pn == 0U) return MACSEC_ERR_PN_EXHAUSTED;
    if (plain_len > SIZE_MAX - MACSEC_OVERHEAD || capacity < plain_len + MACSEC_OVERHEAD)
        return MACSEC_ERR_CAPACITY;
    return MACSEC_OK;
}

static enum macsec_status protect_check(const struct macsec_tx_sa *sa,
                                        const uint8_t *frame, size_t plain_len,
                                        size_t capacity, size_t *l2)
{
    if (sa == NULL || frame == NULL) return MACSEC_ERR_ARGUMENT;
    *l2 = macsec_l2_header_len(frame, plain_len);
    return protect_check_l2(sa, *l2, plain_len, capacity);
}

enum macsec_status macsec_prepare_protect(
    struct macsec_tx_sa *sa, const uint8_t *plain_frame, size_t plain_len,
    uint8_t *secure_frame, size_t secure_capacity, size_t *secure_len,
    struct macsec_crypto_request *request)
{
    size_t l2;
    enum macsec_status status;

    if (secure_frame == NULL || secure_len == NULL || request == NULL)
        return MACSEC_ERR_ARGUMENT;
    status = protect_check(sa, plain_frame, plain_len, secure_capacity, &l2);
    if (status != MACSEC_OK) return status;
    memcpy(secure_frame, plain_frame, l2);
    return protect_layout(sa, secure_frame, l2, plain_len, plain_frame + l2,
                          secure_frame + l2 + SECTAG_WITH_SCI_LEN, secure_len,
                          request);
}

enum macsec_status macsec_prepare_protect_direct(
    struct macsec_tx_sa *sa, uint8_t *frame, size_t l2, size_t plain_len,
    size_t frame_capacity, size_t *secure_len,
    struct macsec_crypto_request *request)
{
    enum macsec_status status;

    if (frame == NULL || secure_len == NULL || request == NULL)
        return MACSEC_ERR_ARGUMENT;
    status = protect_check_l2(sa, l2, plain_len, frame_capacity);
    if (status != MACSEC_OK) return status;
    return protect_layout(sa, frame, l2, plain_len,
                          frame + l2 + SECTAG_WITH_SCI_LEN,
                          frame + l2 + SECTAG_WITH_SCI_LEN, secure_len, request);
}

enum macsec_status macsec_prepare_protect_direct_pn(
    const struct macsec_tx_sa *sa, uint64_t pn, uint8_t *frame, size_t l2,
    size_t plain_len, size_t frame_capacity, size_t *secure_len,
    struct macsec_crypto_request *request)
{
    if (sa == NULL || frame == NULL || secure_len == NULL || request == NULL ||
        (l2 != MAC_ADDRESSES_LEN && l2 != MAC_ADDRESSES_LEN + VLAN_TAG_LEN) ||
        plain_len < l2 + 2U) return MACSEC_ERR_ARGUMENT;
    if (pn == 0U) return MACSEC_ERR_PN_EXHAUSTED;
    if (plain_len > SIZE_MAX - MACSEC_OVERHEAD ||
        frame_capacity < plain_len + MACSEC_OVERHEAD) return MACSEC_ERR_CAPACITY;
    protect_layout_pn(sa, pn, frame, l2, plain_len,
                      frame + l2 + SECTAG_WITH_SCI_LEN,
                      frame + l2 + SECTAG_WITH_SCI_LEN, secure_len, request);
    return MACSEC_OK;
}

enum macsec_status macsec_prepare_protect_in_place(
    struct macsec_tx_sa *sa, uint8_t *frame, size_t plain_len,
    size_t frame_capacity, size_t *secure_len,
    struct macsec_crypto_request *request)
{
    size_t l2;
    enum macsec_status status;

    if (secure_len == NULL || request == NULL) return MACSEC_ERR_ARGUMENT;
    status = protect_check(sa, frame, plain_len, frame_capacity, &l2);
    if (status != MACSEC_OK) return status;
    memmove(frame + l2 + SECTAG_WITH_SCI_LEN, frame + l2, plain_len - l2);
    return protect_layout(sa, frame, l2, plain_len,
                          frame + l2 + SECTAG_WITH_SCI_LEN,
                          frame + l2 + SECTAG_WITH_SCI_LEN, secure_len, request);
}

static enum macsec_status parse_secure(const struct macsec_rx_sa *sa,
                                       const uint8_t *frame, size_t len,
                                       size_t *l2_out, size_t *protected_len,
                                       uint64_t *pn)
{
    size_t l2;
    const uint8_t *tag;
    uint8_t tci;
    uint8_t short_length;

    if (len < MAC_ADDRESSES_LEN + 2U) return MACSEC_ERR_FORMAT;
    l2 = is_vlan_ethertype(load_be16(frame + 12)) ? MAC_ADDRESSES_LEN + VLAN_TAG_LEN
                                                   : MAC_ADDRESSES_LEN;
    if (len < l2 + SECTAG_WITH_SCI_LEN + 2U + MACSEC_ICV_LEN ||
        load_be16(frame + l2) != MACSEC_ETHERTYPE) return MACSEC_ERR_FORMAT;
    tag = frame + l2;
    tci = tag[2];
    if ((tci & (TCI_SC | TCI_E | TCI_C)) != TCI_PROFILE ||
        (tci & TCI_AN_MASK) != sa->association_number ||
        memcmp(tag + 8, sa->sci, MACSEC_SCI_LEN) != 0) return MACSEC_ERR_FORMAT;
    *protected_len = len - l2 - SECTAG_WITH_SCI_LEN - MACSEC_ICV_LEN;
    short_length = tag[3];
    if ((*protected_len < 48U && short_length != *protected_len) ||
        (*protected_len >= 48U && short_length != 0U)) return MACSEC_ERR_FORMAT;
    *pn = recover_xpn(sa, load_be32(tag + 4));
    if (replay_rejected(sa, *pn)) return MACSEC_ERR_REPLAY;
    *l2_out = l2;
    return MACSEC_OK;
}

enum macsec_status macsec_prepare_unprotect(
    struct macsec_rx_sa *sa, const uint8_t *secure_frame, size_t secure_len,
    uint8_t *plain_frame, size_t plain_capacity, size_t *plain_len,
    struct macsec_crypto_request *request)
{
    size_t l2, protected_len;
    uint64_t pn;
    enum macsec_status status;

    if (sa == NULL || secure_frame == NULL || plain_frame == NULL ||
        plain_len == NULL || request == NULL) return MACSEC_ERR_ARGUMENT;
    status = parse_secure(sa, secure_frame, secure_len, &l2, &protected_len, &pn);
    if (status != MACSEC_OK) return status;
    if (plain_capacity < l2 + protected_len) return MACSEC_ERR_CAPACITY;
    memcpy(plain_frame, secure_frame, l2);
    memset(request, 0, sizeof(*request));
    build_aad(request->aad_storage, secure_frame, secure_frame + l2);
    fill_request(request, false, sa->key, sa->ssci, pn, sa->salt, l2,
                 secure_frame + l2 + SECTAG_WITH_SCI_LEN, protected_len,
                 plain_frame + l2,
                 (uint8_t *)(secure_frame + l2 + SECTAG_WITH_SCI_LEN + protected_len));
    *plain_len = l2 + protected_len;
    return MACSEC_OK;
}

enum macsec_status macsec_complete_unprotect(
    struct macsec_rx_sa *sa, const struct macsec_crypto_request *request,
    enum macsec_status crypto_status)
{
    if (sa == NULL || request == NULL || request->encrypt) return MACSEC_ERR_ARGUMENT;
    if (crypto_status != MACSEC_OK) return crypto_status;
    if (replay_rejected(sa, request->packet_number)) return MACSEC_ERR_REPLAY;
    replay_accept(sa, request->packet_number);
    return MACSEC_OK;
}

enum macsec_status macsec_prepare_unprotect_in_place(
    struct macsec_rx_sa *sa, uint8_t *frame, size_t secure_len,
    size_t *plain_len, struct macsec_crypto_request *request)
{
    size_t l2, protected_len;
    uint64_t pn;
    enum macsec_status status;

    if (sa == NULL || frame == NULL || plain_len == NULL || request == NULL)
        return MACSEC_ERR_ARGUMENT;
    status = parse_secure(sa, frame, secure_len, &l2, &protected_len, &pn);
    if (status != MACSEC_OK) return status;
    memset(request, 0, sizeof(*request));
    build_aad(request->aad_storage, frame, frame + l2);
    fill_request(request, false, sa->key, sa->ssci, pn, sa->salt, l2,
                 frame + l2 + SECTAG_WITH_SCI_LEN, protected_len,
                 frame + l2 + SECTAG_WITH_SCI_LEN,
                 frame + l2 + SECTAG_WITH_SCI_LEN + protected_len);
    *plain_len = l2 + protected_len;
    return MACSEC_OK;
}

enum macsec_status macsec_finish_unprotect_in_place(
    struct macsec_rx_sa *sa, const struct macsec_crypto_request *request,
    enum macsec_status crypto_status, uint8_t *frame)
{
    enum macsec_status status =
        macsec_complete_unprotect(sa, request, crypto_status);
    if (status != MACSEC_OK) return status;
    memmove(frame + request->l2_len,
            frame + request->l2_len + SECTAG_WITH_SCI_LEN, request->input_len);
    return MACSEC_OK;
}

static enum macsec_status run_backend(const struct macsec_crypto_request *r,
                                      const uint8_t *tag_in)
{
    uint8_t tag[MACSEC_ICV_LEN];

    if (r->encrypt) {
        if (aead_backend != NULL)
            return aead_backend(true, r->key, r->nonce, r->aad, r->aad_len,
                                r->input, r->input_len, r->output, r->tag,
                                aead_backend_context);
#ifndef MACSEC_NO_OPENSSL
        return gcm_encrypt(r->key, r->nonce, r->aad, r->aad_len, r->input,
                           r->input_len, r->output, r->tag);
#else
        return MACSEC_ERR_CRYPTO;
#endif
    }
    memcpy(tag, tag_in, sizeof(tag));
    if (aead_backend != NULL)
        return aead_backend(false, r->key, r->nonce, r->aad, r->aad_len,
                            r->input, r->input_len, r->output, tag,
                            aead_backend_context);
#ifndef MACSEC_NO_OPENSSL
    return gcm_decrypt(r->key, r->nonce, r->aad, r->aad_len, r->input,
                       r->input_len, tag, r->output);
#else
    return MACSEC_ERR_CRYPTO;   /* sem OpenSSL: exige backend (cryptodev) */
#endif
}

enum macsec_status macsec_protect(struct macsec_tx_sa *sa,
                                  const uint8_t *plain_frame,
                                  size_t plain_len,
                                  uint8_t *secure_frame,
                                  size_t secure_capacity,
                                  size_t *secure_len)
{
    struct macsec_crypto_request request;
    uint64_t saved_pn;
    enum macsec_status status;

    if (sa == NULL) return MACSEC_ERR_ARGUMENT;
    saved_pn = sa->next_pn;
    status = macsec_prepare_protect(sa, plain_frame, plain_len, secure_frame,
                                    secure_capacity, secure_len, &request);
    if (status != MACSEC_OK) return status;
    status = run_backend(&request, NULL);
    if (status != MACSEC_OK) sa->next_pn = saved_pn;  /* nada saiu na rede */
    return status;
}

enum macsec_status macsec_unprotect(struct macsec_rx_sa *sa,
                                    const uint8_t *secure_frame,
                                    size_t secure_len,
                                    uint8_t *plain_frame,
                                    size_t plain_capacity,
                                    size_t *plain_len)
{
    struct macsec_crypto_request request;
    enum macsec_status status;

    status = macsec_prepare_unprotect(sa, secure_frame, secure_len, plain_frame,
                                      plain_capacity, plain_len, &request);
    if (status != MACSEC_OK) return status;
    status = run_backend(&request, request.tag);
    return macsec_complete_unprotect(sa, &request, status);
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
