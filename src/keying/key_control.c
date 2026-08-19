#include "key_control.h"

#include <openssl/crypto.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static bool parse_hex(const char *text, size_t text_len,
                      uint8_t *output, size_t output_len)
{
    size_t i;

    if (text_len != output_len * 2U) return false;
    for (i = 0; i < output_len; i++) {
        int high = hex_nibble(text[i * 2U]);
        int low = hex_nibble(text[i * 2U + 1U]);
        if (high < 0 || low < 0) return false;
        output[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static bool parse_an(const char *text, size_t length, uint8_t *an)
{
    if (length != 1U || text[0] < '0' || text[0] > '3') return false;
    *an = (uint8_t)(text[0] - '0');
    return true;
}

static bool field(const char *token, size_t token_len, const char *name,
                  const char **value, size_t *value_len)
{
    size_t name_len = strlen(name);
    if (token_len <= name_len || memcmp(token, name, name_len) != 0 ||
        token[name_len] != '=') return false;
    *value = token + name_len + 1U;
    *value_len = token_len - name_len - 1U;
    return true;
}

bool key_control_parse(const char *message, struct key_control_command *command)
{
    const char *cursor;
    bool have_an = false, have_tx = false, have_rx = false;
    bool have_tx_salt = false, have_rx_salt = false;

    if (message == NULL || command == NULL) return false;
    memset(command, 0, sizeof(*command));
    if (strcmp(message, "STATUS") == 0 || strcmp(message, "STATUS\n") == 0) {
        command->operation = KEY_CONTROL_STATUS;
        return true;
    } else if (strncmp(message, "INSTALL ", 8U) == 0) {
        command->operation = KEY_CONTROL_INSTALL;
        cursor = message + 8U;
    } else if (strncmp(message, "ACTIVATE ", 9U) == 0) {
        command->operation = KEY_CONTROL_ACTIVATE;
        cursor = message + 9U;
    } else if (strncmp(message, "RETIRE ", 7U) == 0) {
        command->operation = KEY_CONTROL_RETIRE;
        cursor = message + 7U;
    } else {
        return false;
    }

    while (*cursor != '\0' && *cursor != '\n') {
        const char *end;
        const char *value;
        size_t token_len, value_len;
        while (*cursor == ' ') cursor++;
        if (*cursor == '\0' || *cursor == '\n') break;
        end = cursor;
        while (*end != '\0' && *end != '\n' && *end != ' ') end++;
        token_len = (size_t)(end - cursor);
        if (field(cursor, token_len, "AN", &value, &value_len)) {
            if (have_an || !parse_an(value, value_len, &command->association_number)) goto invalid;
            have_an = true;
        } else if (field(cursor, token_len, "TX_KEY", &value, &value_len)) {
            if (have_tx || !parse_hex(value, value_len, command->tx_key, MACSEC_KEY_LEN)) goto invalid;
            have_tx = true;
        } else if (field(cursor, token_len, "RX_KEY", &value, &value_len)) {
            if (have_rx || !parse_hex(value, value_len, command->rx_key, MACSEC_KEY_LEN)) goto invalid;
            have_rx = true;
        } else if (field(cursor, token_len, "TX_SALT", &value, &value_len)) {
            if (have_tx_salt || !parse_hex(value, value_len, command->tx_salt, MACSEC_SALT_LEN)) goto invalid;
            have_tx_salt = true;
        } else if (field(cursor, token_len, "RX_SALT", &value, &value_len)) {
            if (have_rx_salt || !parse_hex(value, value_len, command->rx_salt, MACSEC_SALT_LEN)) goto invalid;
            have_rx_salt = true;
        } else {
invalid:
            key_control_clear(command);
            return false;
        }
        cursor = end;
    }
    if (!have_an || (command->operation == KEY_CONTROL_INSTALL &&
        (!have_tx || !have_rx || !have_tx_salt || !have_rx_salt)) ||
        (command->operation != KEY_CONTROL_INSTALL &&
         (have_tx || have_rx || have_tx_salt || have_rx_salt))) {
        key_control_clear(command);
        return false;
    }
    return true;
}

void key_control_clear(struct key_control_command *command)
{
    if (command != NULL) OPENSSL_cleanse(command, sizeof(*command));
}
