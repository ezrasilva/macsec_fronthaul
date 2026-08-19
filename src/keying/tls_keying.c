#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define EXPORTER_LEN 32U
#define SAK_LEN 32U
#define CONFIRMATION_LEN 32U
#define EXPORTER_LABEL "EXPORTER-MACSEC-PQC-v1"
#define HYBRID_GROUP "X25519MLKEM768"

static void print_errors(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ERR_print_errors_fp(stderr);
}

static int tcp_listen(const char *port)
{
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    struct addrinfo *current;
    int listener = -1;
    int enabled = 1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &addresses) != 0) {
        return -1;
    }
    for (current = addresses; current != NULL; current = current->ai_next) {
        listener = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (listener < 0) {
            continue;
        }
        (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
        if (bind(listener, current->ai_addr, current->ai_addrlen) == 0 &&
            listen(listener, 1) == 0) {
            break;
        }
        close(listener);
        listener = -1;
    }
    freeaddrinfo(addresses);
    return listener;
}

static int tcp_connect(const char *host, const char *port)
{
    struct addrinfo hints = {0};
    struct addrinfo *addresses = NULL;
    struct addrinfo *current;
    int socket_fd = -1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        return -1;
    }
    for (current = addresses; current != NULL; current = current->ai_next) {
        socket_fd = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (socket_fd >= 0 && connect(socket_fd, current->ai_addr, current->ai_addrlen) == 0) {
            break;
        }
        if (socket_fd >= 0) {
            close(socket_fd);
        }
        socket_fd = -1;
    }
    freeaddrinfo(addresses);
    return socket_fd;
}

static SSL_CTX *create_context(bool server, const char *cert, const char *key, const char *ca)
{
    SSL_CTX *context = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    const char *group = getenv("MACSEC_TLS_GROUP");

    if (group == NULL || group[0] == '\0') {
        group = HYBRID_GROUP;
    }

    if (context == NULL ||
        SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set1_groups_list(context, group) != 1 ||
        SSL_CTX_use_certificate_chain_file(context, cert) != 1 ||
        SSL_CTX_use_PrivateKey_file(context, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(context) != 1 ||
        SSL_CTX_load_verify_locations(context, ca, NULL) != 1) {
        SSL_CTX_free(context);
        return NULL;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return context;
}

static bool hkdf(const uint8_t *secret, size_t secret_len,
                 const char *info, uint8_t *output, size_t requested_len)
{
    static const uint8_t salt[] = "macsec-pqc-poc-v1";
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t output_len = requested_len;
    bool success = false;

    if (context == NULL || EVP_PKEY_derive_init(context) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(context, salt, sizeof(salt) - 1U) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(context, secret, (int)secret_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(context, (const unsigned char *)info,
                                    (int)strlen(info)) <= 0 ||
        EVP_PKEY_derive(context, output, &output_len) <= 0 || output_len != requested_len) {
        goto done;
    }
    success = true;
done:
    EVP_PKEY_CTX_free(context);
    return success;
}

static void write_hex(FILE *file, const uint8_t *data, size_t length)
{
    size_t i;
    for (i = 0; i < length; i++) {
        fprintf(file, "%02x", data[i]);
    }
}

static char *append_hex(char *output, const uint8_t *data, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < length; i++) {
        *output++ = digits[data[i] >> 4];
        *output++ = digits[data[i] & 0x0fU];
    }
    return output;
}

static bool control_send(const char *path, const char *message, size_t length)
{
    struct sockaddr_un address = {0};
    char response[16];
    ssize_t received;
    int descriptor;

    if (strlen(path) >= sizeof(address.sun_path)) return false;
    descriptor = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (descriptor < 0) return false;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (connect(descriptor, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        send(descriptor, message, length, MSG_NOSIGNAL) != (ssize_t)length) {
        close(descriptor);
        return false;
    }
    received = recv(descriptor, response, sizeof(response), 0);
    close(descriptor);
    return received == 3 && memcmp(response, "OK\n", 3U) == 0;
}

static bool control_parameters(const char *output_path, const char **socket_path,
                               bool *du, uint8_t *an)
{
    const char *role;
    const char *an_text;
    char *end = NULL;
    unsigned long parsed;

    if (strncmp(output_path, "unix:", 5U) != 0) return false;
    role = getenv("MACSEC_ENDPOINT_ROLE");
    an_text = getenv("MACSEC_CONTROL_AN");
    if (role == NULL || (strcmp(role, "du") != 0 && strcmp(role, "ru") != 0)) {
        fprintf(stderr, "MACSEC_ENDPOINT_ROLE must be du or ru for Unix delivery\n");
        return false;
    }
    parsed = an_text == NULL ? 0U : strtoul(an_text, &end, 10);
    if ((an_text != NULL && (end == an_text || *end != '\0')) || parsed > 3U) {
        fprintf(stderr, "MACSEC_CONTROL_AN must be between 0 and 3\n");
        return false;
    }
    *socket_path = output_path + 5U;
    *du = strcmp(role, "du") == 0;
    *an = (uint8_t)parsed;
    return (*socket_path)[0] != '\0';
}

static bool install_over_control(const char *output_path,
                                 const uint8_t du_to_ru[SAK_LEN],
                                 const uint8_t ru_to_du[SAK_LEN],
                                 const uint8_t du_salt[12],
                                 const uint8_t ru_salt[12])
{
    const char *socket_path;
    const uint8_t *tx_key, *rx_key, *tx_salt, *rx_salt;
    bool du;
    uint8_t an;
    char message[320];
    char *cursor;
    int prefix;

    if (!control_parameters(output_path, &socket_path, &du, &an)) return false;
    tx_key = du ? du_to_ru : ru_to_du;
    rx_key = du ? ru_to_du : du_to_ru;
    tx_salt = du ? du_salt : ru_salt;
    rx_salt = du ? ru_salt : du_salt;
    prefix = snprintf(message, sizeof(message), "INSTALL AN=%u TX_KEY=", an);
    if (prefix < 0 || (size_t)prefix >= sizeof(message)) return false;
    cursor = message + prefix;
    cursor = append_hex(cursor, tx_key, SAK_LEN);
    memcpy(cursor, " RX_KEY=", 8U); cursor += 8U;
    cursor = append_hex(cursor, rx_key, SAK_LEN);
    memcpy(cursor, " TX_SALT=", 9U); cursor += 9U;
    cursor = append_hex(cursor, tx_salt, 12U);
    memcpy(cursor, " RX_SALT=", 9U); cursor += 9U;
    cursor = append_hex(cursor, rx_salt, 12U);
    *cursor++ = '\n';
    return control_send(socket_path, message, (size_t)(cursor - message));
}

static bool activate_control(const char *output_path)
{
    const char *socket_path;
    bool du;
    uint8_t an;
    char message[32];
    int length;

    if (strncmp(output_path, "unix:", 5U) != 0) return true;
    if (!control_parameters(output_path, &socket_path, &du, &an)) return false;
    (void)du;
    length = snprintf(message, sizeof(message), "ACTIVATE AN=%u\n", an);
    return length > 0 && control_send(socket_path, message, (size_t)length);
}

static bool make_confirmation(const char *role,
                              const uint8_t key[CONFIRMATION_LEN],
                              const uint8_t du_to_ru[SAK_LEN],
                              const uint8_t ru_to_du[SAK_LEN],
                              const uint8_t du_salt[12],
                              const uint8_t ru_salt[12],
                              uint8_t output[CONFIRMATION_LEN])
{
    static const uint8_t label[] = "MACSEC-KEY-CONFIRM-v1:";
    char digest[] = "SHA256";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()
    };
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *context = mac == NULL ? NULL : EVP_MAC_CTX_new(mac);
    size_t output_len = 0;
    bool success = context != NULL &&
                   EVP_MAC_init(context, key, CONFIRMATION_LEN, parameters) == 1 &&
                   EVP_MAC_update(context, label, sizeof(label) - 1U) == 1 &&
                   EVP_MAC_update(context, (const uint8_t *)role, strlen(role)) == 1 &&
                   EVP_MAC_update(context, du_to_ru, SAK_LEN) == 1 &&
                   EVP_MAC_update(context, ru_to_du, SAK_LEN) == 1 &&
                   EVP_MAC_update(context, du_salt, 12U) == 1 &&
                   EVP_MAC_update(context, ru_salt, 12U) == 1 &&
                   EVP_MAC_final(context, output, &output_len, CONFIRMATION_LEN) == 1 &&
                   output_len == CONFIRMATION_LEN;

    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);
    return success;
}

static bool export_keys(SSL *ssl, const char *output_path,
                        uint8_t confirmations[2][CONFIRMATION_LEN])
{
    uint8_t exporter[EXPORTER_LEN];
    uint8_t du_to_ru[SAK_LEN];
    uint8_t ru_to_du[SAK_LEN];
    uint8_t du_salt[12];
    uint8_t ru_salt[12];
    uint8_t confirmation_key[CONFIRMATION_LEN];
    FILE *output = NULL;
    int output_fd = -1;
    bool success = false;

    if (SSL_export_keying_material(ssl, exporter, sizeof(exporter),
                                   EXPORTER_LABEL, strlen(EXPORTER_LABEL),
                                   NULL, 0, 0) != 1 ||
        !hkdf(exporter, sizeof(exporter), "macsec-sak:du-to-ru", du_to_ru, sizeof(du_to_ru)) ||
        !hkdf(exporter, sizeof(exporter), "macsec-sak:ru-to-du", ru_to_du, sizeof(ru_to_du)) ||
        !hkdf(exporter, sizeof(exporter), "macsec-salt:du-to-ru", du_salt, sizeof(du_salt)) ||
        !hkdf(exporter, sizeof(exporter), "macsec-salt:ru-to-du", ru_salt, sizeof(ru_salt)) ||
        !hkdf(exporter, sizeof(exporter), "macsec-key-confirm:v1",
              confirmation_key, sizeof(confirmation_key)) ||
        !make_confirmation("server", confirmation_key, du_to_ru, ru_to_du,
                           du_salt, ru_salt, confirmations[0]) ||
        !make_confirmation("client", confirmation_key, du_to_ru, ru_to_du,
                           du_salt, ru_salt, confirmations[1])) {
        goto done;
    }
    if (strncmp(output_path, "unix:", 5U) == 0) {
        success = install_over_control(output_path, du_to_ru, ru_to_du,
                                       du_salt, ru_salt);
        goto done;
    }
    output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
                     S_IRUSR | S_IWUSR);
    if (output_fd < 0 || fchmod(output_fd, S_IRUSR | S_IWUSR) != 0) {
        goto done;
    }
    output = fdopen(output_fd, "w");
    if (output == NULL) {
        goto done;
    }
    output_fd = -1;
    fputs("DU_TO_RU_KEY=", output);
    write_hex(output, du_to_ru, sizeof(du_to_ru));
    fputs("\nRU_TO_DU_KEY=", output);
    write_hex(output, ru_to_du, sizeof(ru_to_du));
    fputs("\nDU_TO_RU_SALT=", output);
    write_hex(output, du_salt, sizeof(du_salt));
    fputs("\nRU_TO_DU_SALT=", output);
    write_hex(output, ru_salt, sizeof(ru_salt));
    fputc('\n', output);
    if (fclose(output) != 0) {
        output = NULL;
        goto done;
    }
    output = NULL;
    success = true;
done:
    if (output != NULL) {
        fclose(output);
    }
    if (output_fd >= 0) {
        close(output_fd);
    }
    OPENSSL_cleanse(exporter, sizeof(exporter));
    OPENSSL_cleanse(du_to_ru, sizeof(du_to_ru));
    OPENSSL_cleanse(ru_to_du, sizeof(ru_to_du));
    OPENSSL_cleanse(du_salt, sizeof(du_salt));
    OPENSSL_cleanse(ru_salt, sizeof(ru_salt));
    OPENSSL_cleanse(confirmation_key, sizeof(confirmation_key));
    return success;
}

static bool peer_policy_ok(SSL *ssl)
{
    const char *expected = getenv("MACSEC_TLS_PEER_KEY");
    X509 *peer;
    EVP_PKEY *peer_key;
    const char *actual;
    bool matches;

    if (expected == NULL || expected[0] == '\0') {
        return true;
    }
    peer = SSL_get1_peer_certificate(ssl);
    peer_key = peer == NULL ? NULL : X509_get_pubkey(peer);
    actual = peer_key == NULL ? NULL : EVP_PKEY_get0_type_name(peer_key);
    matches = actual != NULL && strcmp(actual, expected) == 0;
    if (!matches) {
        fprintf(stderr, "TLS peer key policy failed: expected=%s actual=%s\n",
                expected, actual == NULL ? "unknown" : actual);
    }
    EVP_PKEY_free(peer_key);
    X509_free(peer);
    return matches;
}

static bool ssl_write_all(SSL *ssl, const uint8_t *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        size_t written = 0;
        if (SSL_write_ex(ssl, data + offset, length - offset, &written) != 1 ||
            written == 0U) {
            return false;
        }
        offset += written;
    }
    return true;
}

static bool ssl_read_all(SSL *ssl, uint8_t *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        size_t received = 0;
        if (SSL_read_ex(ssl, data + offset, length - offset, &received) != 1 ||
            received == 0U) {
            return false;
        }
        offset += received;
    }
    return true;
}

static uint64_t elapsed_us(const struct timespec *start, const struct timespec *end)
{
    int64_t nanoseconds = (int64_t)(end->tv_sec - start->tv_sec) * INT64_C(1000000000) +
                          (int64_t)end->tv_nsec - (int64_t)start->tv_nsec;
    return (uint64_t)(nanoseconds / INT64_C(1000));
}

static void print_session(SSL *ssl, uint64_t handshake_us)
{
    X509 *peer = SSL_get1_peer_certificate(ssl);
    EVP_PKEY *peer_key = peer == NULL ? NULL : X509_get_pubkey(peer);
    int group_id = SSL_get_negotiated_group(ssl);

    printf("TLS=%s cipher=%s group=%s peer-key=%s verify=%ld "
           "handshake-us=%llu rx-bytes=%llu tx-bytes=%llu\n",
           SSL_get_version(ssl), SSL_get_cipher_name(ssl),
           SSL_group_to_name(ssl, group_id),
           peer_key == NULL ? "unknown" : EVP_PKEY_get0_type_name(peer_key),
           SSL_get_verify_result(ssl), (unsigned long long)handshake_us,
           (unsigned long long)BIO_number_read(SSL_get_rbio(ssl)),
           (unsigned long long)BIO_number_written(SSL_get_wbio(ssl)));
    EVP_PKEY_free(peer_key);
    X509_free(peer);
}

static int run_server(SSL_CTX *context, const char *port, const char *output_path)
{
    int listener = tcp_listen(port);
    int client = -1;
    SSL *ssl = NULL;
    struct timespec started;
    struct timespec finished;
    int result = EXIT_FAILURE;
    uint8_t confirmations[2][CONFIRMATION_LEN] = {{0}};
    uint8_t peer_confirmation[CONFIRMATION_LEN] = {0};

    if (listener < 0) {
        perror("listen");
        return result;
    }
    client = accept(listener, NULL, NULL);
    if (client < 0) {
        perror("accept");
        goto done;
    }
    ssl = SSL_new(context);
    clock_gettime(CLOCK_MONOTONIC, &started);
    if (ssl == NULL || SSL_set_fd(ssl, client) != 1 || SSL_accept(ssl) != 1) {
        print_errors("TLS server handshake failed");
        goto done;
    }
    clock_gettime(CLOCK_MONOTONIC, &finished);
    print_session(ssl, elapsed_us(&started, &finished));
    if (!peer_policy_ok(ssl)) {
        goto done;
    }
    if (!export_keys(ssl, output_path, confirmations)) {
        print_errors("TLS exporter/HKDF failed");
        goto done;
    }
    if (!ssl_write_all(ssl, confirmations[0], sizeof(confirmations[0])) ||
        !ssl_read_all(ssl, peer_confirmation, sizeof(peer_confirmation)) ||
        CRYPTO_memcmp(confirmations[1], peer_confirmation,
                      sizeof(peer_confirmation)) != 0) {
        print_errors("TLS key confirmation failed");
        goto done;
    }
    if (!activate_control(output_path)) {
        print_errors("cannot activate confirmed MACsec SA");
        goto done;
    }
    result = EXIT_SUCCESS;
done:
    OPENSSL_cleanse(confirmations, sizeof(confirmations));
    OPENSSL_cleanse(peer_confirmation, sizeof(peer_confirmation));
    SSL_free(ssl);
    if (client >= 0) {
        close(client);
    }
    close(listener);
    return result;
}

static int run_client(SSL_CTX *context, const char *host, const char *port,
                      const char *output_path)
{
    const char *server_name = getenv("MACSEC_TLS_SERVER_NAME");
    int socket_fd = tcp_connect(host, port);
    SSL *ssl = NULL;
    struct timespec started;
    struct timespec finished;
    int result = EXIT_FAILURE;
    uint8_t local_confirmations[2][CONFIRMATION_LEN] = {{0}};
    uint8_t peer_confirmation[CONFIRMATION_LEN] = {0};

    if (socket_fd < 0) {
        perror("connect");
        return result;
    }
    if (server_name == NULL || server_name[0] == '\0') server_name = host;
    ssl = SSL_new(context);
    clock_gettime(CLOCK_MONOTONIC, &started);
    if (ssl == NULL || SSL_set_tlsext_host_name(ssl, server_name) != 1 ||
        SSL_set1_host(ssl, server_name) != 1 ||
        SSL_set_fd(ssl, socket_fd) != 1 || SSL_connect(ssl) != 1) {
        print_errors("TLS client handshake failed");
        goto done;
    }
    clock_gettime(CLOCK_MONOTONIC, &finished);
    print_session(ssl, elapsed_us(&started, &finished));
    if (!peer_policy_ok(ssl)) {
        goto done;
    }
    if (!export_keys(ssl, output_path, local_confirmations)) {
        print_errors("TLS exporter/HKDF failed");
        goto done;
    }
    if (!ssl_read_all(ssl, peer_confirmation, sizeof(peer_confirmation)) ||
        CRYPTO_memcmp(local_confirmations[0], peer_confirmation,
                      sizeof(peer_confirmation)) != 0 ||
        !ssl_write_all(ssl, local_confirmations[1],
                       sizeof(local_confirmations[1]))) {
        print_errors("TLS MACsec key confirmation failed");
        goto done;
    }
    if (!activate_control(output_path)) {
        print_errors("cannot activate confirmed MACsec SA");
        goto done;
    }
    result = EXIT_SUCCESS;
done:
    OPENSSL_cleanse(local_confirmations, sizeof(local_confirmations));
    OPENSSL_cleanse(peer_confirmation, sizeof(peer_confirmation));
    SSL_free(ssl);
    close(socket_fd);
    return result;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s server PORT CERT KEY CA OUTPUT\n"
            "  %s client HOST PORT CERT KEY CA OUTPUT\n",
            program, program);
}

int main(int argc, char **argv)
{
    bool server;
    const char *host = NULL;
    const char *port;
    const char *cert;
    const char *key;
    const char *ca;
    const char *output;
    OSSL_PROVIDER *default_provider;
    OSSL_PROVIDER *oqs_provider;
    SSL_CTX *context;
    int result;

    if ((argc != 7 && argc != 8) ||
        (strcmp(argv[1], "server") != 0 && strcmp(argv[1], "client") != 0)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    server = strcmp(argv[1], "server") == 0;
    if ((server && argc != 7) || (!server && argc != 8)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (server) {
        port = argv[2]; cert = argv[3]; key = argv[4]; ca = argv[5]; output = argv[6];
    } else {
        host = argv[2]; port = argv[3]; cert = argv[4]; key = argv[5]; ca = argv[6]; output = argv[7];
    }

    default_provider = OSSL_PROVIDER_load(NULL, "default");
    oqs_provider = OSSL_PROVIDER_load(NULL, "oqsprovider");
    if (oqs_provider == NULL) {
        ERR_clear_error();
    }
    if (default_provider == NULL) {
        print_errors("cannot load the OpenSSL default provider");
        return EXIT_FAILURE;
    }
    context = create_context(server, cert, key, ca);
    if (context == NULL) {
        print_errors("cannot configure TLS context");
        return EXIT_FAILURE;
    }
    result = server ? run_server(context, port, output)
                    : run_client(context, host, port, output);
    SSL_CTX_free(context);
    if (oqs_provider != NULL) {
        OSSL_PROVIDER_unload(oqs_provider);
    }
    OSSL_PROVIDER_unload(default_provider);
    return result;
}
