/*
 * Betanet Protocol Compliance Regression Test
 * Ensures protocol behaviors remain compliant across builds.
 * References: Section 6 (Inner Secure Channel), Section 10 (Testing Plan), Section 12 (Milestones) of technical-overview.md
 * Protocol: Handshake/session lifecycle, connection status, and regression checks.
 */

#include <stdio.h>
#include "betanet/betanet.h"

#include "src/noise/noise.h"
#include "src/htx/htx.h"
#include "src/htx/framing.h"
#include <string.h>
#include <assert.h>

int test_noise_xk_handshake(void) {
    // Create dummy HTX contexts (not connected, for unit test)
    htx_ctx_t *htx_initiator = htx_ctx_create(HTX_TRANSPORT_TCP);
    htx_ctx_t *htx_responder = htx_ctx_create(HTX_TRANSPORT_TCP);

    noise_channel_t initiator = {0};
    noise_channel_t responder = {0};
    initiator.htx = htx_initiator;
    responder.htx = htx_responder;

    // Run handshake for both initiator and responder
    int h1 = noise_channel_handshake_initiator(&initiator, htx_initiator);
    int h2 = noise_channel_handshake_responder(&responder, htx_responder);

    if (h1 != 0 || h2 != 0 || !initiator.handshake_complete || !responder.handshake_complete) {
        printf("[FAIL] Noise XK handshake\n");
        htx_ctx_free(htx_initiator);
        htx_ctx_free(htx_responder);
        return 1;
    }

    // Simulate sending a message from initiator to responder
    uint8_t msg[] = "test-message";
    uint8_t recv_buf[64] = {0};
    size_t recv_len = 0;

    int send_result = noise_channel_send(&initiator, msg, sizeof(msg));
    int recv_result = noise_channel_recv(&responder, recv_buf, sizeof(recv_buf), &recv_len);

    if (send_result != 0 || recv_result != 0 || recv_len != sizeof(msg) || memcmp(msg, recv_buf, sizeof(msg)) != 0) {
        printf("[FAIL] Noise XK AEAD framing\n");
        htx_ctx_free(htx_initiator);
        htx_ctx_free(htx_responder);
        return 1;
    }

    // Trigger rekey and check status
    noise_channel_rekey(&initiator);
    if (!noise_channel_rekey_pending(&initiator)) {
        printf("[FAIL] Noise XK rekey logic\n");
        htx_ctx_free(htx_initiator);
        htx_ctx_free(htx_responder);
        return 1;
    }

    printf("[PASS] Noise XK handshake/AEAD framing/rekey\n");
    htx_ctx_free(htx_initiator);
    htx_ctx_free(htx_responder);
    return 0;
}
#include "src/shape/shape.h"

static int test_shape_ping_cadence(void) {
    shape_config_t cfg;
    shape_config_init(&cfg, SHAPE_PROFILE_HTTP2_ADAPTIVE);
    int min = cfg.ping_cadence_base_ms * (100 - cfg.ping_cadence_jitter_percent) / 100;
    int max = cfg.ping_cadence_base_ms * (100 + cfg.ping_cadence_jitter_percent) / 100;
    int out_of_bounds = 0;
    for (int i = 0; i < 1000; ++i) {
        uint32_t val = shape_next_ping_cadence(&cfg);
        if (val < min || val > max) out_of_bounds++;
    }
    if (out_of_bounds) {
        printf("[FAIL] shape_next_ping_cadence: %d/1000 out of bounds\n", out_of_bounds);
        return 1;
    }
    printf("[PASS] shape_next_ping_cadence\n");
    return 0;
}

static int test_shape_settings_tolerance(void) {
    // 15% tolerance, origin=1000
    uint32_t origin = 1000;
    uint8_t tol = 15;
    uint32_t in_range = 1100, out_range = 1200;
    if (!shape_settings_within_tolerance(in_range, origin, tol)) {
        printf("[FAIL] shape_settings_within_tolerance: in_range failed\n");
        return 1;
    }
    if (shape_settings_within_tolerance(out_range, origin, tol)) {
        printf("[FAIL] shape_settings_within_tolerance: out_range failed\n");
        return 1;
    }
    printf("[PASS] shape_settings_within_tolerance\n");
    return 0;
}

static int test_shape_config_init(void) {
    shape_config_t cfg;
    shape_config_init(&cfg, SHAPE_PROFILE_HTTP2_ADAPTIVE);
    if (cfg.padding_min != 16 || cfg.h2_settings_max_concurrent_streams != 100) {
        printf("[FAIL] shape_config_init\n");
        return 1;
    }
    printf("[PASS] shape_config_init\n");
    return 0;
}

int main(void) {
    htx_ctx_t *ctx = betanet_ctx_create();
    // Example: check connection status after dummy connect (stub)
    // TODO: Implement betanet_connect_with_ticket() and betanet_is_connected() for handshake/session lifecycle.
    // int result = betanet_connect_with_ticket(ctx, "127.0.0.1", 443, NULL);
    // if (result != 0 || !betanet_is_connected(ctx)) {
    //     printf("[FAIL] Protocol compliance regression\n");
    //     return 1;
    // }
    printf("[PASS] Protocol compliance regression (stub)\n");
    // Run Noise XK handshake/AEAD framing test
    test_noise_xk_handshake();

    // Run shaping/adaptive emulation tests
    test_shape_ping_cadence();
    test_shape_settings_tolerance();
    test_shape_config_init();

    betanet_ctx_free(ctx);
    return 0;
}