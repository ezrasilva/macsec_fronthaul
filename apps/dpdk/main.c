#include "macsec.h"

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_cycles.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_lcore.h>
#include <rte_pause.h>
#include <rte_ring.h>

#define RX_RING_SIZE 1024U
#define TX_RING_SIZE 1024U
#define NUM_MBUFS 8191U
#define MBUF_CACHE_SIZE 250U
#define BURST_SIZE 32U
#define MAX_FRAME_SIZE 10240U
#define MACSEC_AN_COUNT 4U
#define CRYPTO_OPS 1024U
#define PIPELINE_SIZE 1024U
#define CRYPTO_IV_OFFSET (sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))

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
    uint32_t exit_on_idle_ms;
};

struct app_stats {
    uint64_t protected_ok;
    uint64_t unprotected_ok;
    uint64_t auth_errors;
    uint64_t replay_errors;
    uint64_t format_errors;
    uint64_t other_errors;
    uint64_t alloc_drops;
    uint64_t tx_drops;
    uint64_t rekeys;
    uint64_t ring_drops;
};

struct packet_job {
    struct rte_mbuf *packet;
    bool protect;
};

struct pipeline_context {
    struct rte_ring *crypto_ring;
    struct rte_ring *tx_ring;
    struct rte_mempool *job_pool;
    struct rte_mempool *packet_pool;
    struct macsec_tx_sa *tx_sa;
    struct macsec_rx_sa *rx_sa;
    bool *rx_valid;
    volatile uint8_t *active_tx_an;
    struct app_stats *stats;
    volatile bool worker_busy;
    volatile bool tx_busy;
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
            "Usage: %s [EAL options] -- --tx-key HEX64 --rx-key HEX64\\\n\n"
            "       --tx-sci HEX16 --rx-sci HEX16 [options]\n"
            "  --plain-port N       unprotected Ethernet port (default 0)\n"
            "  --secure-port N      protected Ethernet port (default 1)\n"
            "  --an N               association number, 0..3 (default 0)\n"
            "  --initial-pn N       first transmit PN (default 1)\n"
            "  --replay-window N    receive window, 1..64 (default 64)\n"
            "  --rekey-file PATH    file containing TX_KEY and RX_KEY\n"
            "  --tx-salt HEX24 --rx-salt HEX24 --tx-ssci N --rx-ssci N\n"
            "  --exit-on-idle-ms N  stop after PCAP input becomes idle\n",
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
        {"tx-salt", required_argument, NULL, 't'},
        {"rx-salt", required_argument, NULL, 'T'},
        {"tx-ssci", required_argument, NULL, 'c'},
        {"rx-ssci", required_argument, NULL, 'C'},
        {"exit-on-idle-ms", required_argument, NULL, 'x'},
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
        case 'h':
        default:
            usage(argv[0]);
            return false;
        }
    }
    if (!config->have_tx_key || !config->have_rx_key ||
        !config->have_tx_sci || !config->have_rx_sci ||
        !config->have_tx_salt || !config->have_rx_salt ||
        !config->have_tx_ssci || !config->have_rx_ssci ||
        config->plain_port == config->secure_port) {
        usage(argv[0]);
        return false;
    }
    return true;
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
    aad_copy = rte_malloc(NULL, aad_len, 16U);
    if (session == NULL || packet == NULL || operation == NULL || aad_copy == NULL ||
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
    operation->sym->aead.aad.phys_addr = rte_malloc_virt2iova(aad_copy);
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
    rte_free(aad_copy);
    return result;
}

static int initialize_crypto(struct crypto_backend *backend,
                             struct rte_mempool *packet_pool)
{
    struct rte_cryptodev_config config = {0};
    struct rte_cryptodev_qp_conf queue_config = {0};
    uint32_t session_size;

    if (rte_cryptodev_count() == 0U) {
        fprintf(stderr, "no DPDK crypto device; add --vdev=crypto_aesni_gcm0\n");
        return -1;
    }
    memset(backend, 0, sizeof(*backend));
    backend->device_id = 0;
    backend->packet_pool = packet_pool;
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
        0, 16U, rte_socket_id());
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

    if (rte_ring_free_count(pipeline->crypto_ring) < BURST_SIZE ||
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
        if (rte_ring_enqueue(pipeline->crypto_ring, job) != 0) {
            rte_pktmbuf_free(job->packet);
            rte_mempool_put(pipeline->job_pool, job);
            pipeline->stats->ring_drops++;
        }
    }
    return received;
}

static int crypto_stage(void *argument)
{
    struct pipeline_context *pipeline = argument;

    while (!force_quit) {
        struct packet_job *job;
        struct rte_mbuf *result;
        uint8_t transformed[MAX_FRAME_SIZE];
        uint8_t *frame;
        uint32_t frame_len;
        size_t transformed_len = 0;
        enum macsec_status status;

        if (rte_ring_dequeue(pipeline->crypto_ring, (void **)&job) != 0) {
            rte_pause();
            continue;
        }
        pipeline->worker_busy = true;
        if (rte_pktmbuf_linearize(job->packet) != 0) {
            status = MACSEC_ERR_FORMAT;
        } else {
            frame = rte_pktmbuf_mtod(job->packet, uint8_t *);
            frame_len = rte_pktmbuf_pkt_len(job->packet);
            if (job->protect) {
                status = macsec_protect(
                    &pipeline->tx_sa[*pipeline->active_tx_an], frame, frame_len,
                    transformed, sizeof(transformed), &transformed_len);
            } else if (frame_len >= 15U && frame[12] == 0x88U &&
                       frame[13] == 0xe5U &&
                       pipeline->rx_valid[frame[14] & 0x03U]) {
                uint8_t an = frame[14] & 0x03U;
                status = macsec_unprotect(&pipeline->rx_sa[an], frame, frame_len,
                                          transformed, sizeof(transformed),
                                          &transformed_len);
            } else {
                status = MACSEC_ERR_FORMAT;
            }
        }
        rte_pktmbuf_free(job->packet);
        if (status != MACSEC_OK) {
            account_error(pipeline->stats, status);
            rte_mempool_put(pipeline->job_pool, job);
            pipeline->worker_busy = false;
            continue;
        }
        result = rte_pktmbuf_alloc(pipeline->packet_pool);
        if (result == NULL || rte_pktmbuf_tailroom(result) < transformed_len) {
            rte_pktmbuf_free(result);
            pipeline->stats->alloc_drops++;
            rte_mempool_put(pipeline->job_pool, job);
            pipeline->worker_busy = false;
            continue;
        }
        memcpy(rte_pktmbuf_append(result, (uint16_t)transformed_len), transformed,
               transformed_len);
        job->packet = result;
        if (job->protect) {
            pipeline->stats->protected_ok++;
        } else {
            pipeline->stats->unprotected_ok++;
        }
        while (!force_quit && rte_ring_enqueue(pipeline->tx_ring, job) != 0) {
            rte_pause();
        }
        if (force_quit) {
            rte_pktmbuf_free(job->packet);
            rte_mempool_put(pipeline->job_pool, job);
        }
        pipeline->worker_busy = false;
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

static int tx_stage(void *argument)
{
    struct pipeline_context *pipeline = argument;
    while (!force_quit || !rte_ring_empty(pipeline->tx_ring)) {
        if (rte_ring_empty(pipeline->tx_ring)) {
            rte_pause();
            continue;
        }
        pipeline->tx_busy = true;
        transmit_stage(pipeline->plain_port, pipeline->secure_port, pipeline);
        pipeline->tx_busy = false;
    }
    return 0;
}

static void print_stats(const struct app_stats *stats)
{
    printf("\rprotected=%" PRIu64 " unprotected=%" PRIu64
           " auth=%" PRIu64 " replay=%" PRIu64 " format=%" PRIu64
           " other=%" PRIu64 " alloc_drop=%" PRIu64 " tx_drop=%" PRIu64
           " ring_drop=%" PRIu64 " rekeys=%" PRIu64,
           stats->protected_ok, stats->unprotected_ok, stats->auth_errors,
           stats->replay_errors, stats->format_errors, stats->other_errors,
           stats->alloc_drops, stats->tx_drops, stats->ring_drops, stats->rekeys);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    struct app_config config;
    struct app_stats stats = {0};
    struct macsec_tx_sa tx_sa[MACSEC_AN_COUNT];
    struct macsec_rx_sa rx_sa[MACSEC_AN_COUNT];
    bool rx_valid[MACSEC_AN_COUNT] = {false};
    uint8_t active_tx_an;
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

    active_tx_an = config.association_number;
    macsec_tx_sa_init(&tx_sa[active_tx_an], config.tx_key, config.tx_sci,
                      config.tx_salt, config.tx_ssci,
                      config.association_number, config.initial_pn);
    macsec_rx_sa_init(&rx_sa[active_tx_an], config.rx_key, config.rx_sci,
                      config.rx_salt, config.rx_ssci,
                      config.association_number, config.replay_window);
    rx_valid[active_tx_an] = true;
    pipeline.packet_pool = pool;
    pipeline.tx_sa = tx_sa;
    pipeline.rx_sa = rx_sa;
    pipeline.rx_valid = rx_valid;
    pipeline.active_tx_an = &active_tx_an;
    pipeline.stats = &stats;
    pipeline.plain_port = config.plain_port;
    pipeline.secure_port = config.secure_port;
    memset(config.tx_key, 0, sizeof(config.tx_key));
    memset(config.rx_key, 0, sizeof(config.rx_key));
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGUSR1, handle_signal);
    signal(SIGUSR2, handle_signal);
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
                pending_an = (uint8_t)((active_tx_an + 1U) % MACSEC_AN_COUNT);
                macsec_tx_sa_init(&tx_sa[pending_an], new_tx_key, config.tx_sci,
                                  new_tx_salt, config.tx_ssci,
                                  pending_an, 1U);
                macsec_rx_sa_init(&rx_sa[pending_an], new_rx_key, config.rx_sci,
                                  new_rx_salt, config.rx_ssci,
                                  pending_an, config.replay_window);
                rx_valid[pending_an] = true;
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
                active_tx_an = pending_an;
                rekey_pending = false;
                stats.rekeys++;
                printf("\nactivated rekey AN=%u\n", active_tx_an);
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
                   rte_ring_empty(pipeline.tx_ring) && !pipeline.worker_busy &&
                   !pipeline.tx_busy &&
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
        uint64_t processed = stats.protected_ok + stats.unprotected_ok;
        double packets_per_second = runtime_us == 0U
                                        ? 0.0
                                        : (double)processed * 1000000.0 /
                                              (double)runtime_us;
        printf("runtime_us=%" PRIu64 " processed=%" PRIu64 " pps=%.1f\n",
               runtime_us, processed, packets_per_second);
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
    rte_eal_cleanup();
    return exit_code;
}
