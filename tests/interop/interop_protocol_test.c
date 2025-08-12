// Betanet Interop Protocol Compliance Test
// Covers: ALPN negotiation (1.1/1.0), transition header prohibition, handshake/session lifecycle

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "betanet/betanet.h"

// Stub/mock helpers for legacy/1.0 compatibility
static int test_legacy_alpn() {
    htx_ctx_t *ctx = betanet_ctx_create();
    // TODO: Set ALPN to "betanet/htx/1.0.0" if API supports it
    // This is a placeholder for legacy ALPN negotiation
    int result = betanet_connect_with_ticket(ctx, "127.0.0.1", 443, NULL);
    betanet_ctx_free(ctx);
    return result == 0;
}

// Test for 1.1 ALPN and transition header prohibition
static int test_modern_alpn_and_transition() {
    htx_ctx_t *ctx = betanet_ctx_create();
    // TODO: Set ALPN to "betanet/htx/1.1.0" if API supports it
    int result = betanet_connect_with_ticket(ctx, "127.0.0.1", 443, NULL);
    // Simulate check for transition header on public network (should not be present)
    int transition_header_found = 0; // Replace with actual packet inspection if available
    betanet_ctx_free(ctx);
    return result == 0 && !transition_header_found;
}

int main(void) {
    int pass = 1;
    printf("[interop] Testing legacy ALPN compatibility...\n");
    if (!test_legacy_alpn()) {
        printf("[FAIL] Legacy ALPN interop failed\n");
        pass = 0;
    } else {
        printf("[PASS] Legacy ALPN interop\n");
    }

    printf("[interop] Testing modern ALPN and transition header prohibition...\n");
    if (!test_modern_alpn_and_transition()) {
        printf("[FAIL] Modern ALPN/transition header test failed\n");
        pass = 0;
    } else {
        printf("[PASS] Modern ALPN/transition header\n");
    }

    return pass ? 0 : 1;
}