#include "betanet/betanet.h"
#include "../src/htx/htx.h"
#include "../src/htx/ticket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/noise/noise.h"
#include "../src/shape/shape.h"
#include "../src/path/path.h"
#include "../src/util/platform.h"

void betanet_init(void) {
    // Initialize platform (Winsock on Windows)
    betanet_platform_init();
}

void betanet_shutdown(void) {
    // Cleanup platform (Winsock on Windows)
    betanet_platform_cleanup();
}

// --- Privacy Mode API ---
int betanet_set_privacy_mode(htx_ctx_t* ctx, betanet_privacy_mode_t mode) {
    if (!ctx) return -1;
    ctx->privacy_mode = mode;
    return 0;
}

betanet_privacy_mode_t betanet_get_privacy_mode(const htx_ctx_t* ctx) {
    if (!ctx) return BETANET_PRIVACY_BALANCED;
    return ctx->privacy_mode;
}

// --- Peer Trust Scoring API ---
int betanet_set_peer_trust(htx_ctx_t* ctx, const betanet_peer_trust_t* trust) {
    if (!ctx || !trust) return -1;
    ctx->peer_trust.uptime_score = trust->uptime_score;
    ctx->peer_trust.relay_score = trust->relay_score;
    ctx->peer_trust.staked_ecash = trust->staked_ecash;
    ctx->peer_trust.trust_score = trust->trust_score;
    return 0;
}

int betanet_get_peer_trust(const htx_ctx_t* ctx, betanet_peer_trust_t* trust_out) {
    if (!ctx || !trust_out) return -1;
    trust_out->uptime_score = ctx->peer_trust.uptime_score;
    trust_out->relay_score = ctx->peer_trust.relay_score;
    trust_out->staked_ecash = ctx->peer_trust.staked_ecash;
    trust_out->trust_score = ctx->peer_trust.trust_score;
    return 0;
}

htx_ctx_t* betanet_ctx_create_with_transport(betanet_transport_t transport) {
    return htx_ctx_create((transport == BETANET_TRANSPORT_QUIC) ? HTX_TRANSPORT_QUIC : HTX_TRANSPORT_TCP);
}

htx_ctx_t* betanet_ctx_create(void) {
    return htx_ctx_create(HTX_TRANSPORT_TCP);
}

void betanet_ctx_free(htx_ctx_t* ctx) {
    htx_ctx_free(ctx);
}

int betanet_connect_with_ticket(htx_ctx_t* ctx, const char* host, uint16_t port, const char* ticket_str) {
    // Demo mode: simulate connection without real network
    if (!ctx) return -1;
    
    printf("[betanet] Demo mode: simulating client connect to %s:%u\n", host ? host : "localhost", port);
    
    // In real implementation, would parse ticket and connect
    // htx_ticket_t ticket;
    // if (htx_ticket_parse(ticket_str, &ticket) != 0) return -1;
    // if (!htx_ticket_validate(&ticket)) return -1;
    // if (htx_ticket_check_replay(&ticket) != 0) return -1;
    // return htx_connect(ctx, host, port, HTX_ALPN_HTTP2);
    
    // For demo: just mark as connected
    (void)ticket_str;
    ctx->is_connected = 1;
    return 0;
}

int betanet_accept_with_ticket(htx_ctx_t* ctx, const char* ticket_str) {
    // Demo stub: just mark as connected for local testing
    // Real implementation would bind to a port and accept connections
    (void)ticket_str; // Ignore ticket for demo
    if (!ctx) return -1;
    
    printf("[betanet] Demo mode: simulating server accept\n");
    ctx->is_connected = 1; // Mark as connected for demo
    return 0; // Success
}

int betanet_is_connected(htx_ctx_t* ctx) {
    return htx_is_connected(ctx);
}

int betanet_set_shaping_profile(htx_ctx_t* ctx, shape_profile_t profile) {
    if (!ctx || !ctx->shape_cfg) return -1;
    shape_set_profile(ctx->shape_cfg, profile);
    return 0;
}

shape_profile_t betanet_get_shaping_profile(htx_ctx_t* ctx) {
    if (!ctx || !ctx->shape_cfg) return SHAPE_PROFILE_NONE;
    return ctx->shape_cfg->profile;
}

// --- Secure Channel API (Noise XK) ---

noise_channel_t* betanet_secure_channel_create(void) {
    noise_channel_t* chan = (noise_channel_t*)calloc(1, sizeof(noise_channel_t));
    return chan;
}

void betanet_secure_channel_free(noise_channel_t* chan) {
    if (chan) free(chan);
}

int betanet_secure_handshake_initiator(noise_channel_t* chan, htx_ctx_t* htx) {
    // Demo mode: simulate successful handshake
    if (!chan || !htx) return -1;
    printf("[betanet] Demo mode: simulating initiator handshake\n");
    // return noise_channel_handshake_initiator(chan, htx);
    return 0; // Success
}

int betanet_secure_handshake_responder(noise_channel_t* chan, htx_ctx_t* htx) {
    // Demo mode: simulate successful handshake
    if (!chan || !htx) return -1;
    printf("[betanet] Demo mode: simulating responder handshake\n");
    // return noise_channel_handshake_responder(chan, htx);
    return 0; // Success
}

int betanet_secure_send(noise_channel_t* chan, const uint8_t* msg, size_t msg_len) {
    // Demo mode: simulate successful send
    if (!chan || !msg || msg_len == 0) return -1;
    printf("[betanet] Demo mode: sending %zu bytes\n", msg_len);
    // return noise_channel_send(chan, msg, msg_len);
    return (int)msg_len; // Success
}

int betanet_secure_recv(noise_channel_t* chan, uint8_t* out, size_t max_len, size_t* out_len) {
    // Demo mode: simulate receiving a message
    if (!chan || !out || !out_len || max_len == 0) return -1;
    printf("[betanet] Demo mode: receiving data\n");
    // Simulate receiving "ACK" message
    const char* demo_msg = "ACK";
    size_t demo_len = strlen(demo_msg);
    if (demo_len > max_len) demo_len = max_len;
    memcpy(out, demo_msg, demo_len);
    *out_len = demo_len;
    // return noise_channel_recv(chan, out, max_len, out_len);
    return 0; // Success
}

int betanet_secure_rekey(noise_channel_t* chan) {
    return noise_channel_rekey(chan);
}

int betanet_secure_rekey_pending(noise_channel_t* chan) {
    return noise_channel_rekey_pending(chan);
}