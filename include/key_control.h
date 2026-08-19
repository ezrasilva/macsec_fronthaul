#ifndef POC_KEY_CONTROL_H
#define POC_KEY_CONTROL_H

#include "macsec.h"

#include <stdbool.h>
#include <stdint.h>

enum key_control_operation {
    KEY_CONTROL_INVALID = 0,
    KEY_CONTROL_INSTALL,
    KEY_CONTROL_ACTIVATE,
    KEY_CONTROL_RETIRE,
    KEY_CONTROL_STATUS
};

struct key_control_command {
    enum key_control_operation operation;
    uint8_t association_number;
    uint8_t tx_key[MACSEC_KEY_LEN];
    uint8_t rx_key[MACSEC_KEY_LEN];
    uint8_t tx_salt[MACSEC_SALT_LEN];
    uint8_t rx_salt[MACSEC_SALT_LEN];
};

bool key_control_parse(const char *message, struct key_control_command *command);
void key_control_clear(struct key_control_command *command);

#endif
