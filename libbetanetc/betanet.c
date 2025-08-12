#include "betanet/betanet.h"
#include "htx/htx.h"
#include "htx/ticket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/noise/noise.h"
#include "../src/shape/shape.h"
#include "../src/path/path.h"

void betanet_init(void) {
    // Placeholder for global init (OpenSSL, etc.)
}

void betanet_shutdown(void) {
    // Placeholder for global shutdown
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
    ctx->peer_trust = *trust;
    return 0;
}

int betanet_get_peer_trust(const htx_ctx_t* ctx, betanet_peer_trust_t* trust_out) {
    if (!ctx || !trust_out) return -1;
    *trust_out = ctx->peer_trust;
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
    htx_ticket_t ticket;
    if (htx_ticket_parse(ticket_str, &ticket) != 0) return -1;
    if (!htx_ticket_validate(&ticket)) return -1;
    if (htx_ticket_check_replay(&ticket) != 0) return -1;
    // Use ALPN/profile from ticket (stub: use HTTP/2)
    return htx_connect(ctx, host, port, HTX_ALPN_HTTP2);
}

int betanet_accept_with_ticket(htx_ctx_t* ctx, const char* ticket_str) {
    // Stub: not implemented (server-side accept)
    (void)ctx;
    (void)ticket_str;
    return -1;
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
    return noise_channel_handshake_initiator(chan, htx);
}

int betanet_secure_handshake_responder(noise_channel_t* chan, htx_ctx_t* htx) {
    return noise_channel_handshake_responder(chan, htx);
}

int betanet_secure_send(noise_channel_t* chan, const uint8_t* msg, size_t msg_len) {
    return noise_channel_send(chan, msg, msg_len);
}

int betanet_secure_recv(noise_channel_t* chan, uint8_t* out, size_t max_len, size_t* out_len) {
    return noise_channel_recv(chan, out, max_len, out_len);
}

int betanet_secure_rekey(noise_channel_t* chan) {
    return noise_channel_rekey(chan);
}

int betanet_secure_rekey_pending(noise_channel_t* chan) {
    return noise_channel_rekey_pending(chan);
}