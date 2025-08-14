#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "betanet/betanet.h"
#include "betanet/pq_hybrid.h"
#include "betanet/scion.h"
#include "betanet/payment.h"
#include "betanet/secure_log.h"

// BetaNet v1.1 Specification Compliance Test
// Tests integration between all protocol layers

static int test_count = 0;
static int test_passed = 0;

#define TEST_ASSERT(condition, message) do { \
    test_count++; \
    if (condition) { \
        test_passed++; \
        printf("[PASS] %s\n", message); \
    } else { \
        printf("[FAIL] %s\n", message); \
    } \
} while(0)

void test_post_quantum_integration(void) {
    printf("\n=== Testing Post-Quantum Cryptography ===\n");
    
    // Initialize PQ subsystem
    int result = betanet_pq_init();
    TEST_ASSERT(result == 0, "PQ subsystem initialization");
    
    // Test key generation
    betanet_pq_private_key_t private_key;
    betanet_pq_public_key_t public_key;
    
    result = betanet_pq_keygen(&private_key, &public_key);
    TEST_ASSERT(result == 0, "PQ key generation");
    
    // Test encapsulation/decapsulation
    betanet_pq_ciphertext_t ciphertext;
    uint8_t shared_secret1[BETANET_PQ_SHARED_SECRET_SIZE];
    uint8_t shared_secret2[BETANET_PQ_SHARED_SECRET_SIZE];
    
    result = betanet_pq_encaps(&public_key, &ciphertext, shared_secret1);
    TEST_ASSERT(result == 0, "PQ encapsulation");
    
    result = betanet_pq_decaps(&private_key, &ciphertext, shared_secret2);
    TEST_ASSERT(result == 0, "PQ decapsulation");
    
    // Verify shared secrets match
    int secrets_match = (memcmp(shared_secret1, shared_secret2, BETANET_PQ_SHARED_SECRET_SIZE) == 0);
    TEST_ASSERT(secrets_match, "PQ shared secret consistency");
    
    // Test mandatory flag (should be 0 for dates before 2027)
    int is_mandatory = betanet_pq_is_mandatory();
    printf("Post-quantum mandatory: %s\n", is_mandatory ? "Yes" : "No");
    
    betanet_pq_cleanup();
}

void test_scion_path_discovery(void) {
    printf("\n=== Testing SCION Path Discovery ===\n");
    
    // Test enhanced path discovery configuration
    betanet_scion_discovery_config_t config = {0};
    config.enable_path_diversity = 1;
    config.prefer_long_paths = 0;
    config.max_path_length = 16;
    config.discovery_timeout_ms = 5000;
    
    // Add some ASes to avoid (simulating censorship resistance)
    config.avoided_as_list[0].isd = 1;
    config.avoided_as_list[0].as = 1234;
    config.num_avoided_as = 1;
    
    scion_ia_t src_ia = {.isd = 1, .as = 110};
    scion_ia_t dst_ia = {.isd = 1, .as = 120};
    
    scion_path_t paths[8];
    size_t num_found = 0;
    
    int result = betanet_scion_discover_diverse_paths(&src_ia, &dst_ia, &config,
                                                     paths, 8, &num_found);
    TEST_ASSERT(result == 0, "SCION diverse path discovery");
    TEST_ASSERT(num_found > 0, "Found at least one path");
    
    if (num_found > 0) {
        // Test path validation
        int is_safe = betanet_scion_validate_censorship_resistance(&paths[0], &config);
        TEST_ASSERT(is_safe == 1, "Path censorship resistance validation");
        
        // Test path diversity calculation
        if (num_found > 1) {
            uint8_t diversity = betanet_scion_calculate_path_diversity(paths, num_found);
            TEST_ASSERT(diversity > 0, "Path diversity calculation");
            printf("Path diversity score: %u/100\n", diversity);
        }
    }
}

void test_payment_system(void) {
    printf("\n=== Testing Payment System ===\n");
    
    // Initialize payment system
    betanet_payment_config_t config = {0};
    config.default_fee_rate_ppm = 1000;  // 0.1%
    config.token_refresh_interval = 3600;  // 1 hour
    config.enable_auto_split = 1;
    strcpy(config.preferred_mint_url, "https://mint.betanet.example");
    
    int result = betanet_payment_init(&config);
    TEST_ASSERT(result == 0, "Payment system initialization");
    
    // Create wallet
    betanet_wallet_t wallet;
    result = betanet_wallet_create("test-wallet-001", &wallet);
    TEST_ASSERT(result == 0, "Wallet creation");
    
    // Test initial balance
    uint64_t balance = betanet_wallet_get_balance(&wallet);
    TEST_ASSERT(balance == 0, "Initial wallet balance is zero");
    
    // Test mint discovery (simulated)
    int mints_found = betanet_payment_discover_mints(&wallet);
    TEST_ASSERT(mints_found >= 0, "Mint discovery");
    
    // Test payment calculations
    uint64_t bandwidth_cost = betanet_payment_calculate_bandwidth_cost(1000000, 3600);  // 1MB for 1 hour
    TEST_ASSERT(bandwidth_cost > 0, "Bandwidth cost calculation");
    printf("Bandwidth cost (1MB/1h): %lu sats\n", (unsigned long)bandwidth_cost);
    
    uint64_t routing_cost = betanet_payment_calculate_routing_cost(3, 1024);  // 3 hops, 1KB payload
    TEST_ASSERT(routing_cost > 0, "Routing cost calculation");
    printf("Routing cost (3 hops/1KB): %lu sats\n", (unsigned long)routing_cost);
    
    // Test payment request creation
    betanet_payment_request_t request;
    result = betanet_payment_create_request(1000, BETANET_SERVICE_HTX_BANDWIDTH,
                                           "HTX bandwidth payment", &request);
    TEST_ASSERT(result == 0, "Payment request creation");
    TEST_ASSERT(request.amount_sats == 1000, "Payment request amount");
    
    betanet_payment_cleanup();
}

void test_protocol_integration(void) {
    printf("\n=== Testing Protocol Integration ===\n");
    
    // Test that all subsystems can be initialized together
    int pq_result = betanet_pq_init();
    
    betanet_payment_config_t payment_config = {0};
    payment_config.default_fee_rate_ppm = 1000;
    int payment_result = betanet_payment_init(&payment_config);
    
    TEST_ASSERT(pq_result == 0 && payment_result == 0, "Multi-subsystem initialization");
    
    // Test cross-layer interaction
    // Example: Payment for SCION path discovery
    betanet_wallet_t wallet;
    int wallet_result = betanet_wallet_create("integration-test", &wallet);
    TEST_ASSERT(wallet_result == 0, "Wallet for integration test");
    
    // Simulate paying for enhanced path discovery service
    betanet_payment_request_t request;
    int request_result = betanet_payment_create_request(500, BETANET_SERVICE_ACCESS_TICKET,
                                                       "SCION path discovery service", &request);
    TEST_ASSERT(request_result == 0, "Payment request for SCION service");
    
    // Test that components can work together without conflicts
    scion_ia_t local_ia = {.isd = 1, .as = 110};
    betanet_scion_discovery_config_t scion_config = {0};
    scion_config.enable_path_diversity = 1;
    
    scion_path_t paths[4];
    size_t num_paths = 0;
    
    int scion_result = betanet_scion_discover_diverse_paths(&local_ia, &local_ia, &scion_config,
                                                           paths, 4, &num_paths);
    TEST_ASSERT(scion_result == 0, "SCION discovery with payment context");
    
    // Cleanup
    betanet_pq_cleanup();
    betanet_payment_cleanup();
}

void test_specification_compliance(void) {
    printf("\n=== Testing BetaNet v1.1 Specification Compliance ===\n");
    
    // Test that critical features are available
    TEST_ASSERT(BETANET_PQ_SHARED_SECRET_SIZE == 64, "PQ shared secret size (64 bytes)");
    TEST_ASSERT(BETANET_PAYMENT_MAX_MINTS >= 16, "Minimum mint support (16+)");
    TEST_ASSERT(SCION_VERSION == 0x02, "SCION protocol version 2");
    
    // Test denomination support
    TEST_ASSERT(BETANET_DENOM_1_SAT == 1, "1 satoshi denomination");
    TEST_ASSERT(BETANET_DENOM_1000000_SAT == 1000000, "1M satoshi denomination");
    
    // Test service types
    TEST_ASSERT(BETANET_SERVICE_HTX_BANDWIDTH == 0x01, "HTX bandwidth service type");
    TEST_ASSERT(BETANET_SERVICE_MIXNET_ROUTING == 0x02, "Mixnet routing service type");
    TEST_ASSERT(BETANET_SERVICE_ACCESS_TICKET == 0x03, "Access ticket service type");
    TEST_ASSERT(BETANET_SERVICE_GOVERNANCE_VOTE == 0x04, "Governance vote service type");
    
    printf("BetaNet version: %d.%d\n", BETANET_VERSION_MAJOR, BETANET_VERSION_MINOR);
}

int main(void) {
    printf("BetaNet v1.1 Specification Compliance Test Suite\n");
    printf("================================================\n");
    
    // Initialize secure logging
    secure_log_init();
    secure_log(LOG_INFO, "Starting BetaNet v1.1 compliance test suite");
    
    // Run all tests
    test_specification_compliance();
    test_post_quantum_integration();
    test_scion_path_discovery();
    test_payment_system();
    test_protocol_integration();
    
    // Print summary
    printf("\n=== Test Summary ===\n");
    printf("Tests run: %d\n", test_count);
    printf("Tests passed: %d\n", test_passed);
    printf("Tests failed: %d\n", test_count - test_passed);
    printf("Success rate: %.1f%%\n", (test_passed * 100.0) / test_count);
    
    if (test_passed == test_count) {
        printf("\n✅ All tests passed! BetaNet v1.1 compliance verified.\n");
        secure_log(LOG_INFO, "All compliance tests passed");
    } else {
        printf("\n❌ Some tests failed. Review implementation.\n");
        secure_log(LOG_WARNING, "Some compliance tests failed");
    }
    
    secure_log_cleanup();
    return (test_passed == test_count) ? 0 : 1;
}
