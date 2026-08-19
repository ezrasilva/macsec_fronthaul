#include "macsec.h"
#include "key_control.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_pause.h>
#include <rte_ring.h>

#define RX_RING_SIZE 1024U
#define TX_RING_SIZE 1024U
#define NUM_MBUFS 8191U
#define MBUF_CACHE_SIZE 250U
#define BURST_SIZE 32U
#define MACSEC_AN_COUNT 4U
#define CRYPTO_OPS 1024U
#define PIPELINE_SIZE 1024U
#define CRYPTO_IV_OFFSET (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define CRYPTO_AAD_OFFSET (CRYPTO_IV_OFFSET + 16U)
#define CRYPTO_INDEX_OFFSET (CRYPTO_AAD_OFFSET + 32U)
#define CRYPTO_PRIVATE_SIZE (16U + 32U + 8U)
#define LATENCY_BUCKETS 4097U

struct crypto_session_entry {
    uint8_t key[MACSEC_KEY_LEN];
    bool encrypt;
    bool valid;
    void *session;
    uint64_t last_used;
};

struct crypto_backend {
    uint8_t device_id;
    struct rte_mempool *op_pool;
    struct rte_mempool *session_pool;
    struct rte_mempool *packet_pool;
    struct crypto_session_entry sessions[MACSEC_AN_COUNT * 2U];
    uint64_t session_clock;
    bool in_place_sgl;
};

struct app_config {
    uint8_t tx_key[MACSEC_KEY_LEN];
    uint8_t rx_key[MACSEC_KEY_LEN];
    uint8_t tx_sci[MACSEC_SCI_LEN];
    uint8_t rx_sci[MACSEC_SCI_LEN];
    uint8_t tx_salt[MACSEC_SALT_LEN];
    uint8_t rx_salt[MACSEC_SALT_LEN];
    uint32_t tx_ssci;
    uint32_t rx_ssci;
    uint8_t association_number;
    uint8_t replay_window;
    uint32_t initial_pn;
    uint16_t plain_port;
    uint16_t secure_port;
    bool have_tx_key;
    bool have_rx_key;
    bool have_tx_sci;
    bool have_rx_sci;
    bool have_tx_salt;
    bool have_rx_salt;
    bool have_tx_ssci;
    bool have_rx_ssci;
    const char *rekey_file;
    const char *control_socket;
    uid_t control_uid;
    bool have_control_uid;
    uint32_t exit_on_idle_ms;
    bool latency_stats;
    bool legacy_keying;
};

struct app_stats {
    _Atomic uint64_t protected_ok;
    _Atomic uint64_t unprotected_ok;
    _Atomic uint64_t auth_errors;
    _Atomic uint64_t replay_errors;
    _Atomic uint64_t format_errors;
    _Atomic uint64_t other_errors;
    _Atomic uint64_t alloc_drops;
    _Atomic uint64_t tx_drops;
    _Atomic uint64_t rekeys;
    _Atomic uint64_t ring_drops;
    _Atomic uint64_t latency_hist[LATENCY_BUCKETS];
    _Atomic uint64_t latency_total_us;
    _Atomic uint64_t latency_jitter_total_us;
    _Atomic uint64_t latency_samples;
    _Atomic uint64_t latency_max_us;
};

struct packet_job {
    struct rte_mbuf *packet;
    bool protect;
    uint8_t tx_an;
    uint64_t enqueued_cycles;
};

struct pipeline_context {
    struct rte_ring *crypto_ring;
    struct rte_ring *tx_ring;
    struct rte_mempool *job_pool;
    struct rte_mempool *packet_pool;
    struct crypto_backend *crypto;
    struct macsec_tx_sa *tx_sa;
    struct macsec_rx_sa *rx_sa;
    atomic_bool *rx_valid;
    atomic_uchar *active_tx_an;
    atomic_bool *tx_ready;
    struct app_stats *stats;
    atomic_bool worker_busy;
    atomic_bool tx_busy;
    bool latency_stats;
    uint64_t previous_latency_us;
    uint16_t plain_port;
    uint16_t secure_port;
};

static volatile sig_atomic_t force_quit;
static volatile sig_atomic_t prepare_rekey;
static volatile sig_atomic_t activate_rekey;

static void handle_signal(int signal_number)
{
    if (signal_number == SIGUSR1) {
        prepare_rekey = 1;
    } else if (signal_number == SIGUSR2) {
        activate_rekey = 1;
    } else {
        force_quit = 1;
    }
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static bool parse_hex(const char *text, uint8_t *output, size_t output_len)
{
    size_t i;

    if (strlen(text) != output_len * 2U) {
        return false;
    }
    for (i = 0; i < output_len; i++) {
        int high = hex_nibble(text[i * 2U]);
        int low = hex_nibble(text[i * 2U + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        output[i] = (uint8_t)((high << 4) | low);
    }
    return true;
}

static bool parse_u32(const char *text, uint32_t minimum, uint32_t maximum, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    parsed = strtoul(text, &end, 0);
    if (text[0] == '\0' || end == NULL || *end != '\0' || parsed < minimum || parsed > maximum) {
        return false;
    }
    *value = (uint32_t)parsed;
    return true;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [EAL options] -- --tx-sci HEX16 --rx-sci HEX16 [options]\n"
            "       Provide initial keys or --control-socket PATH.\n"
            "  --enable-legacy-keying  allow key argv, rekey file and signals\n"
            "  --plain-port N       unprotected Ethernet port (default 0)\n"
            "  --secure-port N      protected Ethernet port (default 1)\n"
            "  --an N               association number, 0..3 (default 0)\n"
            "  --initial-pn N       first transmit PN (default 1)\n"
            "  --replay-window N    receive window, 1..64 (default 64)\n"
            "  --rekey-file PATH    file containing TX_KEY and RX_KEY\n"
            "  --control-socket PATH  local INSTALL/ACTIVATE/RETIRE socket\n"
            "  --control-uid UID     owner/authorized UID for control socket\n"
            "  --tx-salt HEX24 --rx-salt HEX24 --tx-ssci N --rx-ssci N\n"
            "  --exit-on-idle-ms N  stop after PCAP input becomes idle\n"
            "  --latency-stats      report p50/p95/p99 and jitter\n",
            program);
}

static bool parse_app_args(int argc, char **argv, struct app_config *config)
{
    static const struct option options[] = {
        {"tx-key", required_argument, NULL, 'k'},
        {"rx-key", required_argument, NULL, 'K'},
        {"tx-sci", required_argument, NULL, 's'},
        {"rx-sci", required_argument, NULL, 'S'},
        {"plain-port", required_argument, NULL, 'p'},
        {"secure-port", required_argument, NULL, 'q'},
        {"an", required_argument, NULL, 'a'},
        {"initial-pn", required_argument, NULL, 'i'},
        {"replay-window", required_argument, NULL, 'w'},
        {"rekey-file", required_argument, NULL, 'r'},
        {"control-socket", required_argument, NULL, 'u'},
        {"control-uid", required_argument, NULL, 'U'},
        {"tx-salt", required_argument, NULL, 't'},
        {"rx-salt", required_argument, NULL, 'T'},
        {"tx-ssci", required_argument, NULL, 'c'},
        {"rx-ssci", required_argument, NULL, 'C'},
        {"exit-on-idle-ms", required_argument, NULL, 'x'},
        {"latency-stats", no_argument, NULL, 'L'},
        {"enable-legacy-keying", no_argument, NULL, 'g'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    int option;

    memset(config, 0, sizeof(*config));
    config->secure_port = 1;
    config->initial_pn = 1;
    config->replay_window = MACSEC_MAX_REPLAY_WINDOW;
    optind = 1;
    while ((option = getopt_long(argc, argv, "", options, NULL)) != -1) {
        uint32_t value;
        switch (option) {
        case 'k':
            config->have_tx_key = parse_hex(optarg, config->tx_key, sizeof(config->tx_key));
            if (!config->have_tx_key) {
                fprintf(stderr, "invalid --tx-key: expected 64 hexadecimal characters\n");
                return false;
            }
            break;
        case 'K':
            config->have_rx_key = parse_hex(optarg, config->rx_key, sizeof(config->rx_key));
            if (!config->have_rx_key) {
                fprintf(stderr, "invalid --rx-key: expected 64 hexadecimal characters\n");
                return false;
            }
            break;
        case 's':
            config->have_tx_sci = parse_hex(optarg, config->tx_sci, sizeof(config->tx_sci));
            if (!config->have_tx_sci) {
                fprintf(stderr, "invalid --tx-sci: expected 16 hexadecimal characters\n");
                return false;
            }
            break;
        case 'S':
            config->have_rx_sci = parse_hex(optarg, config->rx_sci, sizeof(config->rx_sci));
            if (!config->have_rx_sci) {
                fprintf(stderr, "invalid --rx-sci: expected 16 hexadecimal characters\n");
                return false;
            }
            break;
        case 'p':
        case 'q':
            if (!parse_u32(optarg, 0, UINT16_MAX, &value)) {
                return false;
            }
            if (option == 'p') {
                config->plain_port = (uint16_t)value;
            } else {
                config->secure_port = (uint16_t)value;
            }
            break;
        case 'a':
            if (!parse_u32(optarg, 0, 3, &value)) {
                return false;
            }
            config->association_number = (uint8_t)value;
            break;
        case 'i':
            if (!parse_u32(optarg, 1, UINT32_MAX, &config->initial_pn)) {
                return false;
            }
            break;
        case 'w':
            if (!parse_u32(optarg, 1, MACSEC_MAX_REPLAY_WINDOW, &value)) {
                return false;
            }
            config->replay_window = (uint8_t)value;
            break;
        case 'r':
            config->rekey_file = optarg;
            break;
        case 'u':
            config->control_socket = optarg;
            break;
        case 'U':
            if (!parse_u32(optarg, 0, UINT32_MAX, &value)) return false;
            config->control_uid = (uid_t)value;
            config->have_control_uid = true;
            break;
        case 't':
            config->have_tx_salt = parse_hex(optarg, config->tx_salt, sizeof(config->tx_salt));
            if (!config->have_tx_salt) return false;
            break;
        case 'T':
            config->have_rx_salt = parse_hex(optarg, config->rx_salt, sizeof(config->rx_salt));
            if (!config->have_rx_salt) return false;
            break;
        case 'c':
            config->have_tx_ssci = parse_u32(optarg, 0, UINT32_MAX, &config->tx_ssci);
            if (!config->have_tx_ssci) return false;
            break;
        case 'C':
            config->have_rx_ssci = parse_u32(optarg, 0, UINT32_MAX, &config->rx_ssci);
            if (!config->have_rx_ssci) return false;
            break;
        case 'x':
            if (!parse_u32(optarg, 1, 60000, &config->exit_on_idle_ms)) {
                return false;
            }
            break;
        case 'L':
            config->latency_stats = true;
            break;
        case 'g':
            config->legacy_keying = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return false;
        }
    }
    if ((!config->legacy_keying &&
         (config->have_tx_key || config->have_rx_key ||
          config->have_tx_salt || config->have_rx_salt ||
          config->rekey_file != NULL)) ||
        !config->have_tx_sci || !config->have_rx_sci ||
        !config->have_tx_ssci || !config->have_rx_ssci ||
        config->plain_port == config->secure_port ||
        ((config->have_tx_key || config->have_rx_key ||
          config->have_tx_salt || config->have_rx_salt) &&
         !(config->have_tx_key && config->have_rx_key &&
           config->have_tx_salt && config->have_rx_salt)) ||
        ((!config->have_tx_key || !config->have_rx_key ||
          !config->have_tx_salt || !config->have_rx_salt) &&
         config->control_socket == NULL)) {
        if (!config->legacy_keying &&
            (config->have_tx_key || config->have_rx_key ||
             config->have_tx_salt || config->have_rx_salt ||
             config->rekey_file != NULL)) {
            fprintf(stderr, "legacy key arguments require --enable-legacy-keying\n");
        }
        usage(argv[0]);
        return false;
    }
    return true;
}

static int control_socket_open(const char *path, uid_t owner)
{
    struct sockaddr_un address = {0};
    struct stat status;
    int descriptor;
    int flags;

    if (path == NULL) return -1;
    if (strlen(path) >= sizeof(address.sun_path)) {
        fprintf(stderr, "control socket path is too long\n");
        return -1;
    }
    if (lstat(path, &status) == 0) {
        if (!S_ISSOCK(status.st_mode) || unlink(path) != 0) {
            fprintf(stderr, "refusing to replace non-socket control path %s\n", path);
            return -1;
        }
    } else if (errno != ENOENT) {
        return -1;
    }
    descriptor = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (descriptor < 0) return -1;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1U);
    if (bind(descriptor, (const struct sockaddr *)&address, sizeof(address)) != 0 ||
        chown(path, owner, (gid_t)-1) != 0 ||
        chmod(path, S_IRUSR | S_IWUSR) != 0 || listen(descriptor, 4) != 0) {
        close(descriptor);
        unlink(path);
        return -1;
    }
    flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(descriptor);
        unlink(path);
        return -1;
    }
    return descriptor;
}

static int control_receive(int listener, struct key_control_command *command,
                           int *client, uid_t allowed_uid)
{
    struct key_control_wire_message wire;
    struct ucred credentials;
    socklen_t credentials_len = sizeof(credentials);
    ssize_t length;

    if (*client < 0) {
        *client = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (*client < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
        if (getsockopt(*client, SOL_SOCKET, SO_PEERCRED, &credentials,
                       &credentials_len) != 0 || credentials.uid != allowed_uid) {
            (void)send(*client, "DENIED\n", 7U, MSG_NOSIGNAL);
            close(*client);
            *client = -1;
            return 0;
        }
    }
    memset(&wire, 0, sizeof(wire));
    length = recv(*client, &wire, sizeof(wire), MSG_TRUNC);
    if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
    if (length != (ssize_t)sizeof(wire) ||
        !key_control_decode(&wire, (size_t)(length > 0 ? length : 0), command)) {
        (void)send(*client, "INVALID\n", 8U, MSG_NOSIGNAL);
        key_control_wire_clear(&wire);
        close(*client);
        *client = -1;
        return 0;
    }
    key_control_wire_clear(&wire);
    return 1;
}

static void *crypto_session(struct crypto_backend *backend, bool encrypt,
                            const uint8_t key[MACSEC_KEY_LEN])
{
    struct rte_crypto_sym_xform transform = {0};
    struct crypto_session_entry *entry = NULL;
    size_t i;

    for (i = 0; i < RTE_DIM(backend->sessions); i++) {
        if (backend->sessions[i].valid && backend->sessions[i].encrypt == encrypt &&
            memcmp(backend->sessions[i].key, key, MACSEC_KEY_LEN) == 0) {
            backend->sessions[i].last_used = ++backend->session_clock;
            return backend->sessions[i].session;
        }
        if (!backend->sessions[i].valid && entry == NULL) {
            entry = &backend->sessions[i];
        }
    }
    if (entry == NULL) {
        entry = &backend->sessions[0];
        for (i = 1; i < RTE_DIM(backend->sessions); i++) {
            if (backend->sessions[i].last_used < entry->last_used) {
                entry = &backend->sessions[i];
            }
        }
        rte_cryptodev_sym_session_free(backend->device_id, entry->session);
        memset(entry, 0, sizeof(*entry));
    }
    transform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
    transform.aead.op = encrypt ? RTE_CRYPTO_AEAD_OP_ENCRYPT
                                : RTE_CRYPTO_AEAD_OP_DECRYPT;
    transform.aead.algo = RTE_CRYPTO_AEAD_AES_GCM;
    transform.aead.key.data = key;
    transform.aead.key.length = MACSEC_KEY_LEN;
    transform.aead.iv.offset = CRYPTO_IV_OFFSET;
    transform.aead.iv.length = 12U;
    transform.aead.digest_length = MACSEC_ICV_LEN;
    transform.aead.aad_length = 28U;
    entry->session = rte_cryptodev_sym_session_create(backend->device_id,
                                                       &transform,
                                                       backend->session_pool);
    if (entry->session == NULL) {
        return NULL;
    }
    memcpy(entry->key, key, MACSEC_KEY_LEN);
    entry->encrypt = encrypt;
    entry->valid = true;
    entry->last_used = ++backend->session_clock;
    return entry->session;
}

static enum macsec_status cryptodev_aead(
    bool encrypt, const uint8_t key[MACSEC_KEY_LEN], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len, const uint8_t *input, size_t input_len,
    uint8_t *output, uint8_t tag[MACSEC_ICV_LEN], void *context)
{
    struct crypto_backend *backend = context;
    struct rte_crypto_op *operation = NULL;
    struct rte_crypto_op *completed = NULL;
    struct rte_mbuf *packet = NULL;
    uint8_t *aad_copy = NULL;
    uint8_t *data;
    void *session;
    enum macsec_status result = MACSEC_ERR_CRYPTO;
    unsigned spins = 0;

    if (aad_len != 28U || input_len + MACSEC_ICV_LEN > UINT16_MAX) {
        return MACSEC_ERR_ARGUMENT;
    }
    session = crypto_session(backend, encrypt, key);
    packet = rte_pktmbuf_alloc(backend->packet_pool);
    operation = rte_crypto_op_alloc(backend->op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
    if (operation != NULL) {
        aad_copy = rte_crypto_op_ctod_offset(operation, uint8_t *, CRYPTO_AAD_OFFSET);
    }
    if (session == NULL || packet == NULL || operation == NULL ||
        rte_pktmbuf_tailroom(packet) < input_len + MACSEC_ICV_LEN) {
        goto done;
    }
    data = (uint8_t *)rte_pktmbuf_append(
        packet, (uint16_t)(input_len + MACSEC_ICV_LEN));
    memcpy(data, input, input_len);
    if (!encrypt) {
        memcpy(data + input_len, tag, MACSEC_ICV_LEN);
    }
    memcpy(aad_copy, aad, aad_len);
    memcpy(rte_crypto_op_ctod_offset(operation, uint8_t *, CRYPTO_IV_OFFSET),
           nonce, 12U);
    rte_crypto_op_attach_sym_session(operation, session);
    operation->sym->m_src = packet;
    operation->sym->aead.data.offset = 0;
    operation->sym->aead.data.length = (uint32_t)input_len;
    operation->sym->aead.digest.data = data + input_len;
    operation->sym->aead.digest.phys_addr =
        rte_pktmbuf_iova_offset(packet, (uint32_t)input_len);
    operation->sym->aead.aad.data = aad_copy;
    operation->sym->aead.aad.phys_addr =
        rte_crypto_op_ctophys_offset(operation, CRYPTO_AAD_OFFSET);
    if (rte_cryptodev_enqueue_burst(backend->device_id, 0, &operation, 1) != 1) {
        goto done;
    }
    operation = NULL;
    while (rte_cryptodev_dequeue_burst(backend->device_id, 0, &completed, 1) == 0) {
        if (++spins == 1000000U) {
            goto done;
        }
        rte_pause();
    }
    if (completed->status == RTE_CRYPTO_OP_STATUS_SUCCESS) {
        memcpy(output, data, input_len);
        if (encrypt) {
            memcpy(tag, data + input_len, MACSEC_ICV_LEN);
        }
        result = MACSEC_OK;
    } else if (!encrypt && completed->status == RTE_CRYPTO_OP_STATUS_AUTH_FAILED) {
        result = MACSEC_ERR_AUTH;
    }

done:
    rte_crypto_op_free(operation != NULL ? operation : completed);
    rte_pktmbuf_free(packet);
    return result;
}

static void cryptodev_aead_mbuf_burst(
    struct crypto_backend *backend, struct macsec_crypto_request *requests,
    struct rte_mbuf **packets, enum macsec_status *statuses, uint16_t count)
{
    struct rte_crypto_op *operations[BURST_SIZE] = {0};
    struct rte_crypto_op *queued[BURST_SIZE];
    uint16_t queued_count = 0, submitted = 0, completed_count = 0;
    uint16_t i;

    for (i = 0; i < count; i++) {
        struct macsec_crypto_request *request = &requests[i];
        uint8_t *base = rte_pktmbuf_mtod(packets[i], uint8_t *);
        uint32_t data_offset = (uint32_t)(request->input - base);
        uint32_t tag_offset = (uint32_t)(request->tag - base);
        uint8_t *aad_copy;
        void *session = crypto_session(backend, request->encrypt, request->key);

        statuses[i] = MACSEC_ERR_CRYPTO;
        operations[i] = rte_crypto_op_alloc(backend->op_pool,
                                             RTE_CRYPTO_OP_TYPE_SYMMETRIC);
        if (session == NULL || operations[i] == NULL) continue;
        aad_copy = rte_crypto_op_ctod_offset(operations[i], uint8_t *,
                                             CRYPTO_AAD_OFFSET);
        memcpy(aad_copy, request->aad, request->aad_len);
        memcpy(rte_crypto_op_ctod_offset(operations[i], uint8_t *,
                                        CRYPTO_IV_OFFSET), request->nonce, 12U);
        *rte_crypto_op_ctod_offset(operations[i], uint16_t *, CRYPTO_INDEX_OFFSET) = i;
        rte_crypto_op_attach_sym_session(operations[i], session);
        operations[i]->sym->m_src = packets[i];
        operations[i]->sym->aead.data.offset = data_offset;
        operations[i]->sym->aead.data.length = (uint32_t)request->input_len;
        operations[i]->sym->aead.digest.data = request->tag;
        operations[i]->sym->aead.digest.phys_addr =
            rte_pktmbuf_iova_offset(packets[i], tag_offset);
        operations[i]->sym->aead.aad.data = aad_copy;
        operations[i]->sym->aead.aad.phys_addr =
            rte_crypto_op_ctophys_offset(operations[i], CRYPTO_AAD_OFFSET);
        queued[queued_count++] = operations[i];
    }
    while (submitted < queued_count) {
        uint16_t sent = rte_cryptodev_enqueue_burst(
            backend->device_id, 0, queued + submitted,
            (uint16_t)(queued_count - submitted));
        submitted = (uint16_t)(submitted + sent);
        if (sent == 0U) rte_pause();
    }
    while (completed_count < submitted) {
        struct rte_crypto_op *done[BURST_SIZE];
        uint16_t received = rte_cryptodev_dequeue_burst(
            backend->device_id, 0, done,
            (uint16_t)(submitted - completed_count));
        uint16_t j;
        if (received == 0U) {
            rte_pause();
            continue;
        }
        for (j = 0; j < received; j++) {
            uint16_t index = *rte_crypto_op_ctod_offset(
                done[j], uint16_t *, CRYPTO_INDEX_OFFSET);
            if (done[j]->status == RTE_CRYPTO_OP_STATUS_SUCCESS) {
                statuses[index] = MACSEC_OK;
            } else if (!requests[index].encrypt &&
                       done[j]->status == RTE_CRYPTO_OP_STATUS_AUTH_FAILED) {
                statuses[index] = MACSEC_ERR_AUTH;
            }
            rte_crypto_op_free(done[j]);
            operations[index] = NULL;
        }
        completed_count = (uint16_t)(completed_count + received);
    }
    for (i = 0; i < count; i++) rte_crypto_op_free(operations[i]);
}

static int initialize_crypto(struct crypto_backend *backend,
                             struct rte_mempool *packet_pool)
{
    struct rte_cryptodev_config config = {0};
    struct rte_cryptodev_info info;
    struct rte_cryptodev_qp_conf queue_config = {0};
    uint32_t session_size;

    if (rte_cryptodev_count() == 0U) {
        fprintf(stderr, "no DPDK crypto device; add --vdev=crypto_aesni_gcm0\n");
        return -1;
    }
    memset(backend, 0, sizeof(*backend));
    backend->device_id = 0;
    backend->packet_pool = packet_pool;
    rte_cryptodev_info_get(backend->device_id, &info);
    backend->in_place_sgl =
        (info.feature_flags & RTE_CRYPTODEV_FF_IN_PLACE_SGL) != 0U;
    printf("cryptodev=%s in_place_sgl=%s\n", info.driver_name,
           backend->in_place_sgl ? "yes" : "no");
    config.nb_queue_pairs = 1;
    config.socket_id = rte_socket_id();
    if (rte_cryptodev_configure(backend->device_id, &config) != 0) {
        return -1;
    }
    queue_config.nb_descriptors = CRYPTO_OPS;
    if (rte_cryptodev_queue_pair_setup(backend->device_id, 0, &queue_config,
                                       rte_socket_id()) != 0) {
        return -1;
    }
    session_size = rte_cryptodev_sym_get_private_session_size(backend->device_id);
    backend->session_pool = rte_cryptodev_sym_session_pool_create(
        "MACSEC_SESSION_POOL", 32U, session_size, 0, 0, rte_socket_id());
    backend->op_pool = rte_crypto_op_pool_create(
        "MACSEC_CRYPTO_OP_POOL", RTE_CRYPTO_OP_TYPE_SYMMETRIC, CRYPTO_OPS,
        0, CRYPTO_PRIVATE_SIZE, rte_socket_id());
    if (backend->session_pool == NULL || backend->op_pool == NULL ||
        rte_cryptodev_start(backend->device_id) != 0) {
        return -1;
    }
    macsec_set_aead_backend(cryptodev_aead, backend);
    return 0;
}

static int initialize_port(uint16_t port, struct rte_mempool *pool)
{
    struct rte_eth_conf port_conf = {0};
    struct rte_eth_dev_info info;
    uint16_t rx_desc = RX_RING_SIZE;
    uint16_t tx_desc = TX_RING_SIZE;
    int result;

    if (!rte_eth_dev_is_valid_port(port)) {
        fprintf(stderr, "DPDK port %" PRIu16 " is not available\n", port);
        return -1;
    }
    result = rte_eth_dev_info_get(port, &info);
    if (result != 0) {
        fprintf(stderr, "cannot query port %" PRIu16 ": %s\n", port, rte_strerror(-result));
        return -1;
    }
    result = rte_eth_dev_configure(port, 1, 1, &port_conf);
    if (result != 0 || rte_eth_dev_adjust_nb_rx_tx_desc(port, &rx_desc, &tx_desc) != 0) {
        fprintf(stderr, "cannot configure port %" PRIu16 "\n", port);
        return -1;
    }
    result = rte_eth_rx_queue_setup(port, 0, rx_desc, rte_eth_dev_socket_id(port),
                                    &info.default_rxconf, pool);
    if (result != 0) {
        fprintf(stderr, "cannot configure RX queue on port %" PRIu16 ": %s\n",
                port, rte_strerror(-result));
        return -1;
    }
    result = rte_eth_tx_queue_setup(port, 0, tx_desc, rte_eth_dev_socket_id(port),
                                    &info.default_txconf);
    if (result != 0) {
        fprintf(stderr, "cannot configure TX queue on port %" PRIu16 ": %s\n",
                port, rte_strerror(-result));
        return -1;
    }
    result = rte_eth_dev_start(port);
    if (result != 0) {
        fprintf(stderr, "cannot start port %" PRIu16 ": %s\n", port, rte_strerror(-result));
        return -1;
    }
    result = rte_eth_promiscuous_enable(port);
    if (result != 0 && result != -ENOTSUP) {
        fprintf(stderr, "cannot enable promiscuous mode on port %" PRIu16 "\n", port);
        rte_eth_dev_stop(port);
        return -1;
    }
    return 0;
}

static void account_error(struct app_stats *stats, enum macsec_status status)
{
    switch (status) {
    case MACSEC_ERR_AUTH:
        stats->auth_errors++;
        break;
    case MACSEC_ERR_REPLAY:
        stats->replay_errors++;
        break;
    case MACSEC_ERR_FORMAT:
        stats->format_errors++;
        break;
    default:
        stats->other_errors++;
        break;
    }
}

static uint16_t receive_stage(uint16_t input_port, bool protect,
                              struct pipeline_context *pipeline)
{
    struct rte_mbuf *packets[BURST_SIZE];
    uint16_t received;
    uint16_t i;

    if ((protect && !atomic_load_explicit(pipeline->tx_ready,
                                          memory_order_acquire)) ||
        rte_ring_free_count(pipeline->crypto_ring) < BURST_SIZE ||
        rte_mempool_avail_count(pipeline->job_pool) < BURST_SIZE ||
        rte_mempool_avail_count(pipeline->packet_pool) < BURST_SIZE * 4U) {
        return 0;
    }
    received = rte_eth_rx_burst(input_port, 0, packets, BURST_SIZE);

    for (i = 0; i < received; i++) {
        struct packet_job *job = NULL;

        if (rte_mempool_get(pipeline->job_pool, (void **)&job) != 0) {
            rte_pktmbuf_free(packets[i]);
            pipeline->stats->alloc_drops++;
            continue;
        }
        job->packet = packets[i];
        job->protect = protect;
        job->tx_an = protect
                         ? atomic_load_explicit(pipeline->active_tx_an,
                                                memory_order_acquire)
                         : 0U;
        job->enqueued_cycles = pipeline->latency_stats ? rte_get_timer_cycles() : 0U;
        if (rte_ring_enqueue(pipeline->crypto_ring, job) != 0) {
            rte_pktmbuf_free(job->packet);
            rte_mempool_put(pipeline->job_pool, job);
            pipeline->stats->ring_drops++;
        }
    }
    return received;
}

static void finish_crypto_job(struct pipeline_context *pipeline,
                              struct packet_job *job, size_t result_len,
                              enum macsec_status status)
{
    if (status != MACSEC_OK) {
        rte_pktmbuf_free(job->packet);
        account_error(pipeline->stats, status);
        rte_mempool_put(pipeline->job_pool, job);
        return;
    }
    if (rte_pktmbuf_pkt_len(job->packet) > result_len &&
        rte_pktmbuf_trim(job->packet,
                         rte_pktmbuf_pkt_len(job->packet) - (uint32_t)result_len) != 0) {
        rte_pktmbuf_free(job->packet);
        pipeline->stats->other_errors++;
        rte_mempool_put(pipeline->job_pool, job);
        return;
    }
    if (job->protect) pipeline->stats->protected_ok++;
    else pipeline->stats->unprotected_ok++;
    while (!force_quit && rte_ring_enqueue(pipeline->tx_ring, job) != 0) rte_pause();
    if (force_quit) {
        rte_pktmbuf_free(job->packet);
        rte_mempool_put(pipeline->job_pool, job);
    }
}

static int crypto_stage(void *argument)
{
    struct pipeline_context *pipeline = argument;

    while (!force_quit) {
        struct packet_job *jobs[BURST_SIZE];
        struct macsec_crypto_request requests[BURST_SIZE];
        struct macsec_rx_sa *request_rx_sa[BURST_SIZE] = {0};
        struct rte_mbuf *request_packets[BURST_SIZE];
        enum macsec_status crypto_statuses[BURST_SIZE];
        enum macsec_status statuses[BURST_SIZE];
        uint16_t request_job[BURST_SIZE];
        size_t result_lens[BURST_SIZE] = {0};
        uint32_t frame_lens[BURST_SIZE] = {0};
        unsigned count;
        uint16_t request_count = 0;
        unsigned i;

        count = rte_ring_dequeue_burst(pipeline->crypto_ring, (void **)jobs,
                                       BURST_SIZE, NULL);
        if (count == 0U) {
            rte_pause();
            continue;
        }
        atomic_store_explicit(&pipeline->worker_busy, true, memory_order_release);
        for (i = 0; i < count; i++) {
            uint8_t *frame;
            struct macsec_crypto_request request;

            statuses[i] = MACSEC_ERR_FORMAT;
            if (rte_pktmbuf_linearize(jobs[i]->packet) != 0) continue;
            frame = rte_pktmbuf_mtod(jobs[i]->packet, uint8_t *);
            frame_lens[i] = rte_pktmbuf_pkt_len(jobs[i]->packet);
            if (jobs[i]->protect) {
                uint8_t mac_addresses[12];
                memcpy(mac_addresses, frame, sizeof(mac_addresses));
                if (rte_pktmbuf_headroom(jobs[i]->packet) < 16U ||
                    rte_pktmbuf_tailroom(jobs[i]->packet) < MACSEC_ICV_LEN ||
                    rte_pktmbuf_append(jobs[i]->packet, MACSEC_ICV_LEN) == NULL ||
                    rte_pktmbuf_adj(jobs[i]->packet, 12U) == NULL ||
                    rte_pktmbuf_prepend(jobs[i]->packet, 28U) == NULL) {
                    statuses[i] = MACSEC_ERR_CAPACITY;
                    continue;
                }
                frame = rte_pktmbuf_mtod(jobs[i]->packet, uint8_t *);
                memcpy(frame, mac_addresses, sizeof(mac_addresses));
                statuses[i] = macsec_prepare_protect_direct(
                    &pipeline->tx_sa[jobs[i]->tx_an], frame, frame_lens[i],
                    rte_pktmbuf_pkt_len(jobs[i]->packet), &result_lens[i], &request);
            } else if (frame_lens[i] >= 15U && frame[12] == 0x88U &&
                       frame[13] == 0xe5U &&
                       atomic_load_explicit(&pipeline->rx_valid[frame[14] & 0x03U],
                                            memory_order_acquire)) {
                uint8_t an = frame[14] & 0x03U;
                statuses[i] = macsec_prepare_unprotect_in_place(
                    &pipeline->rx_sa[an], frame, frame_lens[i], &result_lens[i],
                    &request);
                if (statuses[i] == MACSEC_OK) request_rx_sa[request_count] = &pipeline->rx_sa[an];
            }
            if (statuses[i] == MACSEC_OK) {
                requests[request_count] = request;
                request_packets[request_count] = jobs[i]->packet;
                request_job[request_count] = (uint16_t)i;
                request_count++;
            }
        }
        if (request_count != 0U) {
            cryptodev_aead_mbuf_burst(pipeline->crypto, requests, request_packets,
                                      crypto_statuses, request_count);
            for (i = 0; i < request_count; i++) {
                uint16_t job_index = request_job[i];
                if (request_rx_sa[i] == NULL) {
                    statuses[job_index] = crypto_statuses[i];
                } else {
                    uint8_t mac_addresses[12];
                    uint8_t *frame = rte_pktmbuf_mtod(request_packets[i], uint8_t *);
                    memcpy(mac_addresses, frame, sizeof(mac_addresses));
                    statuses[job_index] = macsec_complete_unprotect(
                        request_rx_sa[i], &requests[i], crypto_statuses[i]);
                    if (statuses[job_index] == MACSEC_OK) {
                        if (rte_pktmbuf_trim(request_packets[i], MACSEC_ICV_LEN) != 0 ||
                            rte_pktmbuf_adj(request_packets[i], 16U) == NULL) {
                            statuses[job_index] = MACSEC_ERR_FORMAT;
                        } else {
                            frame = rte_pktmbuf_mtod(request_packets[i], uint8_t *);
                            memcpy(frame, mac_addresses, sizeof(mac_addresses));
                        }
                    }
                }
            }
        }
        for (i = 0; i < count; i++) {
            finish_crypto_job(pipeline, jobs[i], result_lens[i], statuses[i]);
        }
        atomic_store_explicit(&pipeline->worker_busy, false, memory_order_release);
    }
    return 0;
}

static void transmit_stage(uint16_t plain_port, uint16_t secure_port,
                           struct pipeline_context *pipeline)
{
    struct packet_job *jobs[BURST_SIZE];
    struct rte_mbuf *plain[BURST_SIZE];
    struct rte_mbuf *secure[BURST_SIZE];
    unsigned count = rte_ring_dequeue_burst(pipeline->tx_ring, (void **)jobs,
                                             BURST_SIZE, NULL);
    uint16_t plain_count = 0;
    uint16_t secure_count = 0;
    unsigned i;

    for (i = 0; i < count; i++) {
        if (pipeline->latency_stats && jobs[i]->enqueued_cycles != 0U) {
            uint64_t latency_us =
                (rte_get_timer_cycles() - jobs[i]->enqueued_cycles) * UINT64_C(1000000) /
                rte_get_timer_hz();
            uint64_t bucket = latency_us < LATENCY_BUCKETS - 1U
                                  ? latency_us
                                  : LATENCY_BUCKETS - 1U;
            uint64_t maximum = atomic_load_explicit(&pipeline->stats->latency_max_us,
                                                     memory_order_relaxed);
            atomic_fetch_add_explicit(&pipeline->stats->latency_hist[bucket], 1U,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&pipeline->stats->latency_total_us, latency_us,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&pipeline->stats->latency_samples, 1U,
                                      memory_order_relaxed);
            if (pipeline->previous_latency_us != 0U) {
                uint64_t jitter = latency_us > pipeline->previous_latency_us
                                      ? latency_us - pipeline->previous_latency_us
                                      : pipeline->previous_latency_us - latency_us;
                atomic_fetch_add_explicit(&pipeline->stats->latency_jitter_total_us,
                                          jitter, memory_order_relaxed);
            }
            pipeline->previous_latency_us = latency_us;
            while (latency_us > maximum &&
                   !atomic_compare_exchange_weak_explicit(
                       &pipeline->stats->latency_max_us, &maximum, latency_us,
                       memory_order_relaxed, memory_order_relaxed)) {
            }
        }
        if (jobs[i]->protect) {
            secure[secure_count++] = jobs[i]->packet;
        } else {
            plain[plain_count++] = jobs[i]->packet;
        }
        rte_mempool_put(pipeline->job_pool, jobs[i]);
    }
    if (secure_count != 0U) {
        uint16_t sent = rte_eth_tx_burst(secure_port, 0, secure, secure_count);
        for (i = sent; i < secure_count; i++) {
            rte_pktmbuf_free(secure[i]);
            pipeline->stats->tx_drops++;
        }
    }
    if (plain_count != 0U) {
        uint16_t sent = rte_eth_tx_burst(plain_port, 0, plain, plain_count);
        for (i = sent; i < plain_count; i++) {
            rte_pktmbuf_free(plain[i]);
            pipeline->stats->tx_drops++;
        }
    }
}

static uint64_t latency_percentile(const struct app_stats *stats,
                                   uint64_t samples, unsigned percentile)
{
    uint64_t target = (samples * percentile + 99U) / 100U;
    uint64_t cumulative = 0;
    size_t i;

    for (i = 0; i < LATENCY_BUCKETS; i++) {
        cumulative += atomic_load_explicit(&stats->latency_hist[i],
                                           memory_order_relaxed);
        if (cumulative >= target) return i;
    }
    return LATENCY_BUCKETS - 1U;
}

static void print_latency_stats(const struct app_stats *stats)
{
    uint64_t samples = atomic_load_explicit(&stats->latency_samples,
                                            memory_order_relaxed);
    uint64_t total = atomic_load_explicit(&stats->latency_total_us,
                                          memory_order_relaxed);
    uint64_t jitter = atomic_load_explicit(&stats->latency_jitter_total_us,
                                           memory_order_relaxed);
    uint64_t maximum = atomic_load_explicit(&stats->latency_max_us,
                                            memory_order_relaxed);
    if (samples == 0U) return;
    printf("latency_us_avg=%.2f p50=%" PRIu64 " p95=%" PRIu64
           " p99=%" PRIu64 " max=%" PRIu64 " jitter_avg=%.2f samples=%" PRIu64 "\n",
           (double)total / (double)samples,
           latency_percentile(stats, samples, 50U),
           latency_percentile(stats, samples, 95U),
           latency_percentile(stats, samples, 99U), maximum,
           samples > 1U ? (double)jitter / (double)(samples - 1U) : 0.0,
           samples);
}

static int tx_stage(void *argument)
{
    struct pipeline_context *pipeline = argument;
    while (!force_quit || !rte_ring_empty(pipeline->tx_ring)) {
        if (rte_ring_empty(pipeline->tx_ring)) {
            rte_pause();
            continue;
        }
        atomic_store_explicit(&pipeline->tx_busy, true, memory_order_release);
        transmit_stage(pipeline->plain_port, pipeline->secure_port, pipeline);
        atomic_store_explicit(&pipeline->tx_busy, false, memory_order_release);
    }
    return 0;
}

static void print_stats(const struct app_stats *stats)
{
    uint64_t protected_ok = atomic_load_explicit(&stats->protected_ok, memory_order_relaxed);
    uint64_t unprotected_ok = atomic_load_explicit(&stats->unprotected_ok, memory_order_relaxed);
    uint64_t auth_errors = atomic_load_explicit(&stats->auth_errors, memory_order_relaxed);
    uint64_t replay_errors = atomic_load_explicit(&stats->replay_errors, memory_order_relaxed);
    uint64_t format_errors = atomic_load_explicit(&stats->format_errors, memory_order_relaxed);
    uint64_t other_errors = atomic_load_explicit(&stats->other_errors, memory_order_relaxed);
    uint64_t alloc_drops = atomic_load_explicit(&stats->alloc_drops, memory_order_relaxed);
    uint64_t tx_drops = atomic_load_explicit(&stats->tx_drops, memory_order_relaxed);
    uint64_t ring_drops = atomic_load_explicit(&stats->ring_drops, memory_order_relaxed);
    uint64_t rekeys = atomic_load_explicit(&stats->rekeys, memory_order_relaxed);

    printf("\rprotected=%" PRIu64 " unprotected=%" PRIu64
           " auth=%" PRIu64 " replay=%" PRIu64 " format=%" PRIu64
           " other=%" PRIu64 " alloc_drop=%" PRIu64 " tx_drop=%" PRIu64
           " ring_drop=%" PRIu64 " rekeys=%" PRIu64,
           protected_ok, unprotected_ok, auth_errors, replay_errors,
           format_errors, other_errors, alloc_drops, tx_drops, ring_drops,
           rekeys);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct app_config config;
    struct app_stats stats = {0};
    struct macsec_tx_sa tx_sa[MACSEC_AN_COUNT];
    struct macsec_rx_sa rx_sa[MACSEC_AN_COUNT];
    atomic_bool rx_valid[MACSEC_AN_COUNT];
    atomic_uchar active_tx_an;
    atomic_bool tx_ready;
    uint8_t pending_an = 0;
    bool rekey_pending = false;
    struct rte_mempool *pool;
    struct crypto_backend crypto;
    struct pipeline_context pipeline;
    unsigned worker_lcore;
    unsigned tx_lcore;
    uint64_t next_stats;
    uint64_t started_cycles;
    uint64_t last_input_cycles = 0;
    bool had_input = false;
    int eal_args;
    int control_listener = -1;
    int control_client = -1;
    int exit_code = EXIT_FAILURE;

    eal_args = rte_eal_init(argc, argv);
    if (eal_args < 0) {
        return EXIT_FAILURE;
    }
    argc -= eal_args;
    argv += eal_args;
    if (!parse_app_args(argc, argv, &config)) {
        goto cleanup_eal;
    }
    if (config.control_socket != NULL) {
        uid_t control_uid = config.have_control_uid ? config.control_uid : geteuid();
        control_listener = control_socket_open(config.control_socket, control_uid);
        if (control_listener < 0) {
            fprintf(stderr, "cannot create control socket %s: %s\n",
                    config.control_socket, strerror(errno));
            goto cleanup_eal;
        }
    }
    if (rte_eth_dev_count_avail() < 2U) {
        fprintf(stderr, "two DPDK Ethernet ports are required\n");
        goto cleanup_eal;
    }

    pool = rte_pktmbuf_pool_create("MACSEC_MBUF_POOL", NUM_MBUFS,
                                   MBUF_CACHE_SIZE, 0,
                                   RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (pool == NULL) {
        fprintf(stderr, "cannot create mbuf pool: %s\n", rte_strerror(rte_errno));
        goto cleanup_eal;
    }
    if (initialize_crypto(&crypto, pool) != 0) {
        fprintf(stderr, "cannot initialize rte_cryptodev AES-GCM backend\n");
        goto cleanup_eal;
    }
    if (initialize_port(config.plain_port, pool) != 0 ||
        initialize_port(config.secure_port, pool) != 0) {
        goto cleanup_ports;
    }
    memset(&pipeline, 0, sizeof(pipeline));
    pipeline.crypto_ring = rte_ring_create("MACSEC_CRYPTO_RING", PIPELINE_SIZE,
                                           rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    pipeline.tx_ring = rte_ring_create("MACSEC_TX_RING", PIPELINE_SIZE,
                                       rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    pipeline.job_pool = rte_mempool_create(
        "MACSEC_JOB_POOL", PIPELINE_SIZE, sizeof(struct packet_job), 0, 0,
        NULL, NULL, NULL, NULL, rte_socket_id(), 0);
    if (pipeline.crypto_ring == NULL || pipeline.tx_ring == NULL ||
        pipeline.job_pool == NULL) {
        fprintf(stderr, "cannot create pipeline rings/pool\n");
        goto cleanup_ports;
    }

    for (size_t i = 0; i < MACSEC_AN_COUNT; i++) {
        atomic_init(&rx_valid[i], false);
    }
    atomic_init(&active_tx_an, config.association_number);
    atomic_init(&tx_ready, false);
    atomic_init(&pipeline.worker_busy, false);
    atomic_init(&pipeline.tx_busy, false);
    if (config.have_tx_key && config.have_rx_key &&
        config.have_tx_salt && config.have_rx_salt) {
        macsec_tx_sa_init(&tx_sa[config.association_number], config.tx_key,
                          config.tx_sci, config.tx_salt, config.tx_ssci,
                          config.association_number, config.initial_pn);
        macsec_rx_sa_init(&rx_sa[config.association_number], config.rx_key,
                          config.rx_sci, config.rx_salt, config.rx_ssci,
                          config.association_number, config.replay_window);
        atomic_store_explicit(&rx_valid[config.association_number], true,
                              memory_order_release);
        atomic_store_explicit(&tx_ready, true, memory_order_release);
    }
    pipeline.packet_pool = pool;
    pipeline.crypto = &crypto;
    pipeline.tx_sa = tx_sa;
    pipeline.rx_sa = rx_sa;
    pipeline.rx_valid = rx_valid;
    pipeline.active_tx_an = &active_tx_an;
    pipeline.tx_ready = &tx_ready;
    pipeline.stats = &stats;
    pipeline.plain_port = config.plain_port;
    pipeline.secure_port = config.secure_port;
    pipeline.latency_stats = config.latency_stats;
    memset(config.tx_key, 0, sizeof(config.tx_key));
    memset(config.rx_key, 0, sizeof(config.rx_key));
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    if (config.legacy_keying) {
        signal(SIGUSR1, handle_signal);
        signal(SIGUSR2, handle_signal);
    }
    worker_lcore = rte_get_next_lcore(rte_lcore_id(), 1, 0);
    tx_lcore = worker_lcore >= RTE_MAX_LCORE
                   ? RTE_MAX_LCORE
                   : rte_get_next_lcore(worker_lcore, 1, 0);
    if (worker_lcore >= RTE_MAX_LCORE ||
        tx_lcore >= RTE_MAX_LCORE ||
        rte_eal_remote_launch(crypto_stage, &pipeline, worker_lcore) != 0 ||
        rte_eal_remote_launch(tx_stage, &pipeline, tx_lcore) != 0) {
        fprintf(stderr, "three enabled lcores are required for RX, crypto and TX\n");
        goto cleanup_ports;
    }
    printf("plain port %" PRIu16 " <-> secure port %" PRIu16
           "; RX lcore=%u crypto lcore=%u TX lcore=%u; press Ctrl-C to stop\n",
           config.plain_port, config.secure_port, rte_lcore_id(), worker_lcore,
           tx_lcore);
    next_stats = rte_get_timer_cycles() + rte_get_timer_hz();
    started_cycles = rte_get_timer_cycles();

    while (!force_quit) {
        uint16_t received;
        uint64_t now;

        if (control_listener >= 0) {
            struct key_control_command command;
            int received_command = control_receive(control_listener, &command,
                                                   &control_client,
                                                   config.have_control_uid
                                                       ? config.control_uid
                                                       : geteuid());

            if (received_command < 0) {
                fprintf(stderr, "control socket receive failed: %s\n", strerror(errno));
            } else if (received_command > 0) {
                uint8_t current_an = atomic_load_explicit(&active_tx_an,
                                                          memory_order_acquire);
                bool accepted = false;
                char response[80];
                size_t response_len = 0;

                if (command.operation == KEY_CONTROL_STATUS) {
                    int length = rekey_pending
                                     ? snprintf(response, sizeof(response),
                                                "STATUS ACTIVE=%u READY=%u PENDING=%u\n",
                                                current_an,
                                                atomic_load_explicit(&tx_ready,
                                                                     memory_order_acquire) ? 1U : 0U,
                                                pending_an)
                                     : snprintf(response, sizeof(response),
                                                "STATUS ACTIVE=%u READY=%u PENDING=-\n",
                                                current_an,
                                                atomic_load_explicit(&tx_ready,
                                                                     memory_order_acquire) ? 1U : 0U);
                    if (length > 0 && (size_t)length < sizeof(response)) {
                        response_len = (size_t)length;
                        accepted = true;
                    }
                } else if (command.operation == KEY_CONTROL_INSTALL &&
                    (command.association_number != current_an ||
                     !atomic_load_explicit(&tx_ready, memory_order_acquire))) {
                    uint8_t an = command.association_number;
                    atomic_store_explicit(&rx_valid[an], false, memory_order_release);
                    while (!rte_ring_empty(pipeline.crypto_ring) ||
                           atomic_load_explicit(&pipeline.worker_busy,
                                                memory_order_acquire)) {
                        rte_pause();
                    }
                    macsec_tx_sa_init(&tx_sa[an], command.tx_key, config.tx_sci,
                                      command.tx_salt, config.tx_ssci, an, 1U);
                    macsec_rx_sa_init(&rx_sa[an], command.rx_key, config.rx_sci,
                                      command.rx_salt, config.rx_ssci, an,
                                      config.replay_window);
                    atomic_store_explicit(&rx_valid[an], true, memory_order_release);
                    pending_an = an;
                    rekey_pending = true;
                    accepted = true;
                    printf("\ncontrol installed AN=%u\n", an);
                } else if (command.operation == KEY_CONTROL_ACTIVATE &&
                           rekey_pending && command.association_number == pending_an &&
                           atomic_load_explicit(&rx_valid[pending_an],
                                                memory_order_acquire)) {
                    atomic_store_explicit(&active_tx_an, pending_an,
                                          memory_order_release);
                    atomic_store_explicit(&tx_ready, true, memory_order_release);
                    rekey_pending = false;
                    stats.rekeys++;
                    accepted = true;
                    printf("\ncontrol activated AN=%u\n", pending_an);
                } else if (command.operation == KEY_CONTROL_RETIRE &&
                           command.association_number != current_an) {
                    uint8_t an = command.association_number;
                    atomic_store_explicit(&rx_valid[an], false, memory_order_release);
                    while (!rte_ring_empty(pipeline.crypto_ring) ||
                           atomic_load_explicit(&pipeline.worker_busy,
                                                memory_order_acquire)) {
                        rte_pause();
                    }
                    OPENSSL_cleanse(&tx_sa[an], sizeof(tx_sa[an]));
                    OPENSSL_cleanse(&rx_sa[an], sizeof(rx_sa[an]));
                    if (rekey_pending && pending_an == an) rekey_pending = false;
                    accepted = true;
                    printf("\ncontrol retired AN=%u\n", an);
                }
                if (response_len == 0U) {
                    memcpy(response, accepted ? "OK\n" : "REJECTED\n",
                           accepted ? 3U : 9U);
                    response_len = accepted ? 3U : 9U;
                }
                (void)send(control_client, response, response_len, MSG_NOSIGNAL);
                close(control_client);
                control_client = -1;
                key_control_clear(&command);
            }
        }

        if (prepare_rekey) {
            FILE *file;
            char line[128];
            uint8_t new_tx_key[MACSEC_KEY_LEN] = {0};
            uint8_t new_rx_key[MACSEC_KEY_LEN] = {0};
            uint8_t new_tx_salt[MACSEC_SALT_LEN] = {0};
            uint8_t new_rx_salt[MACSEC_SALT_LEN] = {0};
            bool have_tx = false;
            bool have_rx = false;
            bool have_tx_salt = false;
            bool have_rx_salt = false;

            prepare_rekey = 0;
            file = config.rekey_file == NULL ? NULL : fopen(config.rekey_file, "r");
            while (file != NULL && fgets(line, sizeof(line), file) != NULL) {
                line[strcspn(line, "\r\n")] = '\0';
                if (strncmp(line, "TX_KEY=", 7) == 0) {
                    have_tx = parse_hex(line + 7, new_tx_key, sizeof(new_tx_key));
                } else if (strncmp(line, "RX_KEY=", 7) == 0) {
                    have_rx = parse_hex(line + 7, new_rx_key, sizeof(new_rx_key));
                } else if (strncmp(line, "TX_SALT=", 8) == 0) {
                    have_tx_salt = parse_hex(line + 8, new_tx_salt, sizeof(new_tx_salt));
                } else if (strncmp(line, "RX_SALT=", 8) == 0) {
                    have_rx_salt = parse_hex(line + 8, new_rx_salt, sizeof(new_rx_salt));
                }
            }
            if (file != NULL) {
                fclose(file);
            }
            if (have_tx && have_rx && have_tx_salt && have_rx_salt) {
                pending_an = (uint8_t)((atomic_load_explicit(&active_tx_an,
                                                             memory_order_acquire) + 1U) %
                                       MACSEC_AN_COUNT);
                /* Stop publishing the slot and wait until no crypto job can
                 * still reference its previous generation before overwrite. */
                atomic_store_explicit(&rx_valid[pending_an], false,
                                      memory_order_release);
                while (!rte_ring_empty(pipeline.crypto_ring) ||
                       atomic_load_explicit(&pipeline.worker_busy,
                                            memory_order_acquire)) {
                    rte_pause();
                }
                macsec_tx_sa_init(&tx_sa[pending_an], new_tx_key, config.tx_sci,
                                  new_tx_salt, config.tx_ssci,
                                  pending_an, 1U);
                macsec_rx_sa_init(&rx_sa[pending_an], new_rx_key, config.rx_sci,
                                  new_rx_salt, config.rx_ssci,
                                  pending_an, config.replay_window);
                atomic_store_explicit(&rx_valid[pending_an], true,
                                      memory_order_release);
                rekey_pending = true;
                printf("\nprepared rekey AN=%u\n", pending_an);
            } else {
                fprintf(stderr, "\ncannot prepare rekey from %s\n",
                        config.rekey_file == NULL ? "(unset)" : config.rekey_file);
            }
            memset(new_tx_key, 0, sizeof(new_tx_key));
            memset(new_rx_key, 0, sizeof(new_rx_key));
            memset(new_tx_salt, 0, sizeof(new_tx_salt));
            memset(new_rx_salt, 0, sizeof(new_rx_salt));
        }
        if (activate_rekey) {
            activate_rekey = 0;
            if (rekey_pending) {
                atomic_store_explicit(&active_tx_an, pending_an,
                                      memory_order_release);
                rekey_pending = false;
                stats.rekeys++;
                printf("\nactivated rekey AN=%u\n", pending_an);
            }
        }
        received = receive_stage(config.plain_port, true, &pipeline);
        received = (uint16_t)(received +
                   receive_stage(config.secure_port, false, &pipeline));
        now = rte_get_timer_cycles();
        if (received != 0U) {
            had_input = true;
            last_input_cycles = now;
        } else if (config.exit_on_idle_ms != 0U && had_input &&
                   rte_ring_empty(pipeline.crypto_ring) &&
                   rte_ring_empty(pipeline.tx_ring) &&
                   !atomic_load_explicit(&pipeline.worker_busy, memory_order_acquire) &&
                   !atomic_load_explicit(&pipeline.tx_busy, memory_order_acquire) &&
                   now - last_input_cycles >=
                       (rte_get_timer_hz() * config.exit_on_idle_ms) / 1000U) {
            force_quit = 1;
        }
        if (now >= next_stats) {
            print_stats(&stats);
            next_stats = now + rte_get_timer_hz();
        }
    }
    print_stats(&stats);
    putchar('\n');
    rte_eal_wait_lcore(worker_lcore);
    rte_eal_wait_lcore(tx_lcore);
    {
        uint64_t runtime_us =
            (rte_get_timer_cycles() - started_cycles) * UINT64_C(1000000) /
            rte_get_timer_hz();
        uint64_t processed =
            atomic_load_explicit(&stats.protected_ok, memory_order_relaxed) +
            atomic_load_explicit(&stats.unprotected_ok, memory_order_relaxed);
        double packets_per_second = runtime_us == 0U
                                        ? 0.0
                                        : (double)processed * 1000000.0 /
                                              (double)runtime_us;
        printf("runtime_us=%" PRIu64 " processed=%" PRIu64 " pps=%.1f\n",
               runtime_us, processed, packets_per_second);
        if (config.latency_stats) print_latency_stats(&stats);
    }
    exit_code = EXIT_SUCCESS;

cleanup_ports:
    macsec_set_aead_backend(NULL, NULL);
    rte_cryptodev_stop(crypto.device_id);
    for (size_t i = 0; i < RTE_DIM(crypto.sessions); i++) {
        if (crypto.sessions[i].valid) {
            rte_cryptodev_sym_session_free(crypto.device_id,
                                           crypto.sessions[i].session);
        }
    }
    rte_cryptodev_close(crypto.device_id);
    if (rte_eth_dev_is_valid_port(config.plain_port)) {
        rte_eth_dev_stop(config.plain_port);
        rte_eth_dev_close(config.plain_port);
    }
    if (rte_eth_dev_is_valid_port(config.secure_port)) {
        rte_eth_dev_stop(config.secure_port);
        rte_eth_dev_close(config.secure_port);
    }
cleanup_eal:
    if (control_listener >= 0) {
        if (control_client >= 0) close(control_client);
        close(control_listener);
        if (config.control_socket != NULL) unlink(config.control_socket);
    }
    rte_eal_cleanup();
    return exit_code;
}
