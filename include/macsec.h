#ifndef POC_MACSEC_H
#define POC_MACSEC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MACSEC_KEY_LEN 16U
#define MACSEC_SCI_LEN 8U
#define MACSEC_ICV_LEN 16U
#define MACSEC_MAX_REPLAY_WINDOW 64U
#define MACSEC_ETHERTYPE 0x88E5U

enum macsec_status {
    MACSEC_OK = 0,
    MACSEC_ERR_ARGUMENT,
    MACSEC_ERR_CAPACITY,
    MACSEC_ERR_FORMAT,
    MACSEC_ERR_AUTH,
    MACSEC_ERR_REPLAY,
    MACSEC_ERR_PN_EXHAUSTED,
    MACSEC_ERR_CRYPTO
};

typedef enum macsec_status (*macsec_aead_backend_fn)(
    bool encrypt, const uint8_t key[MACSEC_KEY_LEN], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
    uint8_t *output, uint8_t tag[MACSEC_ICV_LEN], void *context);

void macsec_set_aead_backend(macsec_aead_backend_fn backend, void *context);

struct macsec_tx_sa {
    uint8_t key[MACSEC_KEY_LEN];
    uint8_t sci[MACSEC_SCI_LEN];
    uint32_t next_pn;
    uint8_t association_number;
};

struct macsec_rx_sa {
    uint8_t key[MACSEC_KEY_LEN];
    uint8_t sci[MACSEC_SCI_LEN];
    uint32_t highest_pn;
    uint64_t replay_bitmap;
    uint8_t association_number;
    uint8_t replay_window;
};

void macsec_tx_sa_init(struct macsec_tx_sa *sa,
                       const uint8_t key[MACSEC_KEY_LEN],
                       const uint8_t sci[MACSEC_SCI_LEN],
                       uint8_t association_number,
                       uint32_t initial_pn);

void macsec_rx_sa_init(struct macsec_rx_sa *sa,
                       const uint8_t key[MACSEC_KEY_LEN],
                       const uint8_t sci[MACSEC_SCI_LEN],
                       uint8_t association_number,
                       uint8_t replay_window);

enum macsec_status macsec_protect(struct macsec_tx_sa *sa,
                                  const uint8_t *plain_frame,
                                  size_t plain_len,
                                  uint8_t *secure_frame,
                                  size_t secure_capacity,
                                  size_t *secure_len);

enum macsec_status macsec_unprotect(struct macsec_rx_sa *sa,
                                    const uint8_t *secure_frame,
                                    size_t secure_len,
                                    uint8_t *plain_frame,
                                    size_t plain_capacity,
                                    size_t *plain_len);

const char *macsec_status_string(enum macsec_status status);

#endif
