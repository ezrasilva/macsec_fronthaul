#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define EXPORTER_LEN 32U
#define SAK_LEN 16U
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
                 const char *info, uint8_t output[SAK_LEN])
{
    static const uint8_t salt[] = "macsec-pqc-poc-v1";
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t output_len = SAK_LEN;
    bool success = false;

    if (context == NULL || EVP_PKEY_derive_init(context) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(context, salt, sizeof(salt) - 1U) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(context, secret, (int)secret_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(context, (const unsigned char *)info,
                                    (int)strlen(info)) <= 0 ||
        EVP_PKEY_derive(context, output, &output_len) <= 0 || output_len != SAK_LEN) {
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

static bool export_keys(SSL *ssl, const char *output_path)
{
    uint8_t exporter[EXPORTER_LEN];
    uint8_t du_to_ru[SAK_LEN];
    uint8_t ru_to_du[SAK_LEN];
    FILE *output;

    if (SSL_export_keying_material(ssl, exporter, sizeof(exporter),
                                   EXPORTER_LABEL, strlen(EXPORTER_LABEL),
                                   NULL, 0, 0) != 1 ||
        !hkdf(exporter, sizeof(exporter), "macsec-sak:du-to-ru", du_to_ru) ||
        !hkdf(exporter, sizeof(exporter), "macsec-sak:ru-to-du", ru_to_du)) {
        return false;
    }
    output = fopen(output_path, "w");
    if (output == NULL) {
        return false;
    }
    (void)chmod(output_path, S_IRUSR | S_IWUSR);
    fputs("DU_TO_RU_KEY=", output);
    write_hex(output, du_to_ru, sizeof(du_to_ru));
    fputs("\nRU_TO_DU_KEY=", output);
    write_hex(output, ru_to_du, sizeof(ru_to_du));
    fputc('\n', output);
    fclose(output);
    OPENSSL_cleanse(exporter, sizeof(exporter));
    OPENSSL_cleanse(du_to_ru, sizeof(du_to_ru));
    OPENSSL_cleanse(ru_to_du, sizeof(ru_to_du));
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
    if (!export_keys(ssl, output_path)) {
        print_errors("TLS exporter/HKDF failed");
        goto done;
    }
    if (SSL_write(ssl, "K", 1) != 1) {
        print_errors("TLS key confirmation failed");
        goto done;
    }
    result = EXIT_SUCCESS;
done:
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
    int socket_fd = tcp_connect(host, port);
    SSL *ssl = NULL;
    struct timespec started;
    struct timespec finished;
    int result = EXIT_FAILURE;

    if (socket_fd < 0) {
        perror("connect");
        return result;
    }
    ssl = SSL_new(context);
    clock_gettime(CLOCK_MONOTONIC, &started);
    if (ssl == NULL || SSL_set_tlsext_host_name(ssl, host) != 1 ||
        SSL_set_fd(ssl, socket_fd) != 1 || SSL_connect(ssl) != 1) {
        print_errors("TLS client handshake failed");
        goto done;
    }
    clock_gettime(CLOCK_MONOTONIC, &finished);
    print_session(ssl, elapsed_us(&started, &finished));
    if (!export_keys(ssl, output_path)) {
        print_errors("TLS exporter/HKDF failed");
        goto done;
    }
    {
        char confirmation;

        if (SSL_read(ssl, &confirmation, 1) != 1 || confirmation != 'K') {
            print_errors("TLS key confirmation failed");
            goto done;
        }
    }
    result = EXIT_SUCCESS;
done:
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
