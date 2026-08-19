#ifndef POC_KEY_CONTROL_H
#define POC_KEY_CONTROL_H

#include "macsec.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define KEY_CONTROL_VERSION 1U
#define KEY_CONTROL_WIRE_SIZE 96U
#define KEY_CONTROL_INSTALL_PAYLOAD_SIZE 88U

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

struct key_control_wire_message {
    uint8_t version;
    uint8_t operation;
    uint8_t association_number;
    uint8_t reserved;
    uint8_t payload_length_be[4];
    uint8_t tx_key[MACSEC_KEY_LEN];
    uint8_t rx_key[MACSEC_KEY_LEN];
    uint8_t tx_salt[MACSEC_SALT_LEN];
    uint8_t rx_salt[MACSEC_SALT_LEN];
};

bool key_control_parse(const char *message, struct key_control_command *command);
bool key_control_encode(const struct key_control_command *command,
                        struct key_control_wire_message *wire);
bool key_control_decode(const struct key_control_wire_message *wire,
                        size_t wire_length, struct key_control_command *command);
void key_control_clear(struct key_control_command *command);
void key_control_wire_clear(struct key_control_wire_message *wire);

#endif
