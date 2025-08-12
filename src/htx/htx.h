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

// Transport type for HTX session.
// TCP: TLS1.3/HTTP2 mimic; QUIC: future support; UDP: fallback/cover logic.
typedef enum {
    HTX_TRANSPORT_TCP = 0,
    HTX_TRANSPORT_QUIC = 1,
    HTX_TRANSPORT_UDP = 2 // For fallback/cover logic
} htx_transport_type_t;

// HTX session context.
// Holds transport state, negotiated ALPN, and shaping configuration.
// See Betanet Spec §5 for required behaviors.
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
    union {
        struct {
            int sockfd;
            SSL *ssl;
            SSL_CTX *ssl_ctx;
        } tcp;
        struct {
            void* quic_conn; // opaque pointer for picoquic/msquic
        } quic;
        struct {
            int sockfd; // UDP socket
        } udp;
    } state;
} htx_ctx_t;

// Profile/ALPN configuration
#define HTX_ALPN_HTTP2 "h2"
#define HTX_PROFILE_ID "betanet-htx/1"

// QUIC stub API (for BETANET_ENABLE_QUIC)
#ifdef BETANET_ENABLE_QUIC
int htx_quic_connect_stub(const char* host, uint16_t port, void** out_conn);
int htx_quic_send_stub(void* quic_conn, const uint8_t* data, size_t len);
int htx_quic_recv_stub(void* quic_conn, uint8_t* buf, size_t maxlen);
void htx_quic_close_stub(void* quic_conn);
#endif

/**
 * Create context with transport type.
 * Initializes shaping config and transport state.
 */
htx_ctx_t* htx_ctx_create(htx_transport_type_t transport);
void htx_ctx_free(htx_ctx_t* ctx);

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
 * Launch cover connections (stub, for anti-correlation).
 * Used to defeat linkability on UDP→TCP fallback (§5.6).
 * Returns 0 on success.
 */
int htx_launch_cover_connections(const char* host, uint16_t port);

#ifdef __cplusplus
}
#endif

#endif // HTX_H