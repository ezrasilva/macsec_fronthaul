#include "key_control.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_install(void)
{
    struct key_control_command command;
    const char *message =
        "INSTALL AN=2 "
        "TX_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
        "RX_KEY=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
        "TX_SALT=000102030405060708090a0b "
        "RX_SALT=101112131415161718191a1b\n";

    assert(key_control_parse(message, &command));
    assert(command.operation == KEY_CONTROL_INSTALL);
    assert(command.association_number == 2U);
    assert(command.tx_key[0] == 0U && command.tx_key[31] == 0x1fU);
    assert(command.rx_salt[0] == 0x10U && command.rx_salt[11] == 0x1bU);
    key_control_clear(&command);
}

static void test_state_commands(void)
{
    struct key_control_command command;
    assert(key_control_parse("STATUS\n", &command));
    assert(command.operation == KEY_CONTROL_STATUS);
    assert(key_control_parse("ACTIVATE AN=3\n", &command));
    assert(command.operation == KEY_CONTROL_ACTIVATE && command.association_number == 3U);
    assert(key_control_parse("RETIRE AN=1", &command));
    assert(command.operation == KEY_CONTROL_RETIRE && command.association_number == 1U);
}

static void test_rejections(void)
{
    struct key_control_command command;
    assert(!key_control_parse("ACTIVATE AN=4", &command));
    assert(!key_control_parse("ACTIVATE AN=1 TX_KEY=00", &command));
    assert(!key_control_parse("INSTALL AN=1", &command));
    assert(!key_control_parse("RETIRE AN=1 AN=2", &command));
    assert(!key_control_parse("ACTIVATE AN=x AN=1", &command));
    assert(!key_control_parse("UNKNOWN AN=1", &command));
}

static void test_binary_wire_format(void)
{
    struct key_control_command original;
    struct key_control_command decoded;
    struct key_control_wire_message wire;
    const char *install =
        "INSTALL AN=2 "
        "TX_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
        "RX_KEY=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f "
        "TX_SALT=000102030405060708090a0b "
        "RX_SALT=101112131415161718191a1b";

    assert(sizeof(wire) == KEY_CONTROL_WIRE_SIZE);
    assert(key_control_parse(install, &original));
    assert(key_control_encode(&original, &wire));
    assert(wire.version == KEY_CONTROL_VERSION);
    assert(wire.payload_length_be[3] == KEY_CONTROL_INSTALL_PAYLOAD_SIZE);
    assert(key_control_decode(&wire, sizeof(wire), &decoded));
    assert(decoded.operation == original.operation);
    assert(decoded.association_number == original.association_number);
    assert(memcmp(decoded.tx_key, original.tx_key, MACSEC_KEY_LEN) == 0);
    assert(memcmp(decoded.rx_salt, original.rx_salt, MACSEC_SALT_LEN) == 0);

    wire.version++;
    assert(!key_control_decode(&wire, sizeof(wire), &decoded));
    wire.version = KEY_CONTROL_VERSION;
    wire.reserved = 1U;
    assert(!key_control_decode(&wire, sizeof(wire), &decoded));
    wire.reserved = 0U;
    assert(!key_control_decode(&wire, sizeof(wire) - 1U, &decoded));
    key_control_wire_clear(&wire);
    key_control_clear(&original);
    key_control_clear(&decoded);
}

int main(void)
{
    test_install();
    test_state_commands();
    test_rejections();
    test_binary_wire_format();
    puts("all key-control unit tests passed");
    return 0;
}
