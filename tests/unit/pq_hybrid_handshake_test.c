// PQ Hybrid Handshake Feature Flag Test
// Verifies that enabling BETANET_ENABLE_PQ_HYBRID triggers the hybrid (X25519+Kyber768) handshake path.

#define BETANET_ENABLE_PQ_HYBRID 1

#include <stdio.h>
#include <assert.h>
#include "src/noise/noise.h"
#include "src/htx/htx.h"

// Stub: If the hybrid path is executed, assume noise_channel_handshake_initiator returns 42
// (or check for a log or field if available in the real implementation).

int test_pq_hybrid_handshake(void) {
    htx_ctx_t *htx_initiator = htx_ctx_create(HTX_TRANSPORT_TCP);
    noise_channel_t initiator = {0};
    initiator.htx = htx_initiator;

    // The handshake function should detect the macro and take the hybrid path.
    int result = noise_channel_handshake_initiator(&initiator, htx_initiator);

    // Check for a stubbed hybrid handshake indicator (adjust as needed for actual implementation).
    if (result == 42) {
        printf("[PASS] PQ hybrid handshake path executed (stub)\n");
        htx_ctx_free(htx_initiator);
        return 0;
    } else {
        printf("[FAIL] PQ hybrid handshake path NOT executed (stub)\n");
        htx_ctx_free(htx_initiator);
        return 1;
    }
}

int main(void) {
    return test_pq_hybrid_handshake();
}