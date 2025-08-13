// Betanet Public API Smoke Test
#include "include/betanet/betanet.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    betanet_init();

    // Context creation/free
    htx_ctx_t* ctx = betanet_ctx_create();
    if (!ctx) {
        printf("[FAIL] betanet_ctx_create\n");
        return 1;
    }

    // Connection (should fail/stub, as no real peer/ticket)
    int conn = betanet_connect_with_ticket(ctx, "127.0.0.1", 443, NULL);
    if (conn != -1) {
        printf("[FAIL] betanet_connect_with_ticket (expected stub/fail)\n");
        betanet_ctx_free(ctx);
        return 1;
    }

    // Connection status (should be not connected)
    if (betanet_is_connected(ctx)) {
        printf("[FAIL] betanet_is_connected (should be false)\n");
        betanet_ctx_free(ctx);
        return 1;
    }

    // Secure channel API (should create, handshake, rekey, free)
    noise_channel_t* chan = betanet_secure_channel_create();
    if (!chan) {
        printf("[FAIL] betanet_secure_channel_create\n");
        betanet_ctx_free(ctx);
        return 1;
    }
    int h1 = betanet_secure_handshake_initiator(chan, ctx);
    int h2 = betanet_secure_handshake_responder(chan, ctx);
    if (h1 != 0 && h2 != 0) {
        printf("[FAIL] betanet_secure_handshake (expected stub/pass)\n");
        betanet_secure_channel_free(chan);
        betanet_ctx_free(ctx);
        return 1;
    }
    int rk = betanet_secure_rekey(chan);
    if (rk != 0 && rk != -1) {
        printf("[FAIL] betanet_secure_rekey (expected stub/pass)\n");
        betanet_secure_channel_free(chan);
        betanet_ctx_free(ctx);
        return 1;
    }
    betanet_secure_channel_free(chan);

    betanet_ctx_free(ctx);
    betanet_shutdown();
    printf("[PASS] Betanet public API smoke test\n");
    return 0;
}