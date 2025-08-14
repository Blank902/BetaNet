#ifndef HTX_H
#define HTX_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "../shape/shape.h"
#include "quic.h"

// Transport type for HTX session.
// TCP: TLS1.3/HTTP2 mimic (§5.1, §5.5, technical-overview.md:21, 58-59, 102-104).
// QUIC: future support (see §5.6, technical-overview.md:21, 124, 137, 153-174).
// UDP: fallback/cover logic (§5.6).
typedef enum {
    HTX_TRANSPORT_TCP = 0,
    HTX_TRANSPORT_QUIC = 1,
    HTX_TRANSPORT_UDP = 2 // For fallback/cover logic
} htx_transport_type_t;

// HTX session context.
// Holds transport state, negotiated ALPN, and shaping configuration.
// Implements fingerprint tuning and mirroring as per Betanet Spec §5.1, §5.5 (JA3/JA4, SETTINGS, extension order).
// Modular for future QUIC integration (§5.6, technical-overview.md:21, 124, 137, 153-174).
typedef struct htx_ctx_s {
    htx_transport_type_t transport;
    int is_connected;
    char alpn_selected[32];
    shape_config_t* shape_cfg;
    // Peer fingerprint mirroring (optional, for SETTINGS/PADDING/PRIORITY)
    uint8_t peer_settings[64];
    size_t peer_settings_len;
    uint8_t peer_priority[16];
    size_t peer_priority_len;
    uint32_t peer_idle_padding_len;
    // --- Fingerprint tuning profile (JA3/JA4, SETTINGS, extension order) ---
    int fingerprint_profile_id; // Reserved for future use (stub, §5.1, §5.5)
    // --- Betanet API extensions ---
    int privacy_mode;      // betanet_privacy_mode_t (but avoid type dependency)
    struct {
        float uptime_score;
        float relay_score;
        float staked_ecash;
        float trust_score;
    } peer_trust;
    union {
        struct {
            int sockfd;
            SSL *ssl;
            SSL_CTX *ssl_ctx;
        } tcp;
        struct {
            htx_quic_conn_t* quic_conn; // opaque handle for QUIC
        } quic;
        struct {
            int sockfd; // UDP socket
        } udp;
    } state;
} htx_ctx_t;

// Profile/ALPN configuration
// ALPN and profile tuning as per Betanet Spec §5.1, §5.5.
#define HTX_ALPN_HTTP2 "h2"
#define HTX_PROFILE_ID "betanet-htx/1"


/**
 * Create context with transport type.
 * Initializes shaping config and transport state.
 * Accepts future fingerprint profile tuning (stub, §5.1, §5.5).
 */
htx_ctx_t* htx_ctx_create(htx_transport_type_t transport);
void htx_ctx_free(htx_ctx_t* ctx);

/**
 * Set fingerprint tuning profile (JA3/JA4, SETTINGS, extension order).
 * Stub for future use. See Betanet Spec §5.1, §5.5.
 */
static inline void htx_set_fingerprint_profile(htx_ctx_t* ctx, int profile_id) {
    if (ctx) ctx->fingerprint_profile_id = profile_id;
}

/**
 * Attempt connection with QUIC/UDP, fallback to TCP on failure.
 * Implements anti-correlation cover connections as per Betanet Spec §5.6.
 * Returns 0 on success, -1 on failure.
 * If fallback occurs, ctx->transport is updated.
 */
int htx_connect_with_fallback(htx_ctx_t* ctx, const char* host, uint16_t port, const char* alpn);

/**
 * Low-level connect (single transport, no fallback).
 */
int htx_connect(htx_ctx_t* ctx, const char* host, uint16_t port, const char* alpn);

int htx_tls_handshake(htx_ctx_t* ctx, const char* host, const char* alpn);
int htx_send_http2_preamble(htx_ctx_t* ctx);
int htx_is_connected(htx_ctx_t* ctx);

/**
 * Server-side functions
 */
int htx_listen(htx_ctx_t* ctx, uint16_t port);
int htx_accept(htx_ctx_t* ctx, htx_ctx_t** client_ctx);
int htx_tls_accept(htx_ctx_t* ctx, const char* cert_file, const char* key_file);

/**
 * Launch cover connections (stub, for anti-correlation).
 * Used to defeat linkability on UDP→TCP fallback (§5.6).
 * Returns 0 on success.
 */
int htx_launch_cover_connections(const char* host, uint16_t port);

#ifdef __cplusplus
}
#endif

#endif // HTX_H