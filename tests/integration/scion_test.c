#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

// Include BetaNet API
#include "betanet/betanet.h"
#include "betanet/scion.h"

// Test configuration
#define TEST_DESTINATION_IA "1-ff00:0:111"
#define TEST_HOST "example.com"
#define TEST_PORT 443
#define TEST_DISCOVERY_TIMEOUT 5000
#define TEST_MESSAGE "Hello, SCION-enabled BetaNet!"

// Test results tracking
typedef struct {
    int tests_run;
    int tests_passed;
    int tests_failed;
} test_results_t;

static test_results_t g_results = {0, 0, 0};

// Test helper macros
#define TEST_START(name) \
    printf("\n=== Testing %s ===\n", name); \
    g_results.tests_run++;

#define TEST_ASSERT(condition, message) \
    do { \
        if (condition) { \
            printf("✓ %s\n", message); \
        } else { \
            printf("✗ %s\n", message); \
            g_results.tests_failed++; \
            return -1; \
        } \
    } while(0)

#define TEST_PASS(name) \
    do { \
        printf("✓ %s completed successfully\n", name); \
        g_results.tests_passed++; \
    } while(0)

// ==============================================================================
// SCION Basic Functionality Tests
// ==============================================================================

int test_scion_path_discovery(void) {
    TEST_START("SCION Path Discovery");
    
    // Test path discovery to a destination
    int result = betanet_scion_discover_paths(TEST_DESTINATION_IA, TEST_DISCOVERY_TIMEOUT);
    TEST_ASSERT(result == 0, "Path discovery should succeed");
    
    // Print discovered paths metrics
    printf("Path discovery metrics:\n");
    betanet_scion_print_metrics();
    
    TEST_PASS("SCION Path Discovery");
    return 0;
}

int test_scion_path_selection_criteria(void) {
    TEST_START("SCION Path Selection Criteria");
    
    // Test different selection criteria
    scion_selection_criteria_t criteria[] = {
        SCION_SELECT_LATENCY,
        SCION_SELECT_BANDWIDTH, 
        SCION_SELECT_RELIABILITY,
        SCION_SELECT_BALANCED
    };
    
    const char* criteria_names[] = {
        "Latency-optimized",
        "Bandwidth-optimized",
        "Reliability-optimized", 
        "Balanced"
    };
    
    for (int i = 0; i < 4; i++) {
        printf("Testing %s selection...\n", criteria_names[i]);
        
        int result = betanet_scion_set_selection_criteria(criteria[i]);
        TEST_ASSERT(result == 0, "Setting selection criteria should succeed");
        
        // Discover paths with this criteria
        result = betanet_scion_discover_paths(TEST_DESTINATION_IA, TEST_DISCOVERY_TIMEOUT);
        TEST_ASSERT(result == 0, "Path discovery with criteria should succeed");
        
        printf("Active path quality with %s criteria:\n", criteria_names[i]);
        scion_path_quality_t quality;
        if (betanet_scion_get_active_path_quality(&quality) == 0) {
            printf("  Latency: %u ms\n", quality.latency_ms);
            printf("  Bandwidth: %u kbps\n", quality.bandwidth_kbps);
            printf("  Packet loss: %u (0.%02u%%)\n", quality.packet_loss, quality.packet_loss);
            printf("  Jitter: %u ms\n", quality.jitter_ms);
        }
    }
    
    TEST_PASS("SCION Path Selection Criteria");
    return 0;
}

int test_scion_path_monitoring(void) {
    TEST_START("SCION Path Monitoring");
    
    // Set up balanced criteria for monitoring test
    int result = betanet_scion_set_selection_criteria(SCION_SELECT_BALANCED);
    TEST_ASSERT(result == 0, "Setting balanced criteria should succeed");
    
    // Discover initial paths
    result = betanet_scion_discover_paths(TEST_DESTINATION_IA, TEST_DISCOVERY_TIMEOUT);
    TEST_ASSERT(result == 0, "Initial path discovery should succeed");
    
    // Test path monitoring and potential switching
    printf("Testing path monitoring...\n");
    for (int i = 0; i < 5; i++) {
        int monitor_result = betanet_scion_monitor_paths();
        if (monitor_result == 1) {
            printf("✓ Path switched during monitoring iteration %d\n", i + 1);
        } else if (monitor_result == 0) {
            printf("✓ No path switch needed in iteration %d\n", i + 1);
        } else {
            printf("⚠ Monitoring error in iteration %d\n", i + 1);
        }
        
        // Small delay between monitoring checks
        #ifdef _WIN32
        Sleep(100);
        #else
        usleep(100000);
        #endif
    }
    
    TEST_PASS("SCION Path Monitoring");
    return 0;
}

// ==============================================================================
// SCION Integration Tests
// ==============================================================================

int test_scion_integrated_connection(void) {
    TEST_START("SCION Integrated Connection");
    
    // Create BetaNet context
    htx_ctx_t* ctx = betanet_ctx_create();
    TEST_ASSERT(ctx != NULL, "Context creation should succeed");
    
    // Discover paths before connection
    int result = betanet_scion_discover_paths(TEST_DESTINATION_IA, TEST_DISCOVERY_TIMEOUT);
    TEST_ASSERT(result == 0, "Pre-connection path discovery should succeed");
    
    printf("Attempting SCION-enhanced connection...\n");
    
    // Attempt connection with SCION path selection
    result = betanet_connect_with_ticket(ctx, TEST_HOST, TEST_PORT, NULL);
    TEST_ASSERT(result == 0, "SCION-enhanced connection should succeed");
    
    printf("Connection established with SCION routing\n");
    
    // Check if we have an active path
    scion_path_quality_t quality;
    if (betanet_scion_get_active_path_quality(&quality) == 0) {
        printf("Active SCION path quality:\n");
        printf("  Latency: %u ms\n", quality.latency_ms);
        printf("  Bandwidth: %u kbps\n", quality.bandwidth_kbps);
        printf("  Active: %s\n", quality.is_active ? "Yes" : "No");
    }
    
    // Clean up
    betanet_ctx_free(ctx);
    
    TEST_PASS("SCION Integrated Connection");
    return 0;
}

int test_scion_with_secure_messaging(void) {
    TEST_START("SCION with Secure Messaging");
    
    // Create context and secure channel
    htx_ctx_t* ctx = betanet_ctx_create();
    TEST_ASSERT(ctx != NULL, "Context creation should succeed");
    
    noise_channel_t* chan = betanet_secure_channel_create();
    TEST_ASSERT(chan != NULL, "Secure channel creation should succeed");
    
    // Set up SCION routing
    int result = betanet_scion_set_selection_criteria(SCION_SELECT_BALANCED);
    TEST_ASSERT(result == 0, "Setting SCION criteria should succeed");
    
    result = betanet_scion_discover_paths(TEST_DESTINATION_IA, TEST_DISCOVERY_TIMEOUT);
    TEST_ASSERT(result == 0, "Path discovery should succeed");
    
    // Connect with SCION routing
    result = betanet_connect_with_ticket(ctx, TEST_HOST, TEST_PORT, NULL);
    TEST_ASSERT(result == 0, "SCION connection should succeed");
    
    printf("Testing secure messaging over SCION paths...\n");
    
    // Test secure send (demo mode)
    const uint8_t* test_msg = (const uint8_t*)TEST_MESSAGE;
    size_t msg_len = strlen(TEST_MESSAGE);
    
    result = betanet_secure_send(chan, test_msg, msg_len);
    TEST_ASSERT(result == 0, "Secure send over SCION should succeed");
    
    // Test secure receive (demo mode)
    uint8_t recv_buffer[256];
    size_t recv_len;
    result = betanet_secure_recv(chan, recv_buffer, sizeof(recv_buffer), &recv_len);
    TEST_ASSERT(result == 0, "Secure receive over SCION should succeed");
    TEST_ASSERT(recv_len > 0, "Should receive data");
    
    printf("Secure messaging test completed\n");
    printf("Sent: %zu bytes, Received: %zu bytes\n", msg_len, recv_len);
    
    // Clean up
    betanet_secure_channel_free(chan);
    betanet_ctx_free(ctx);
    
    TEST_PASS("SCION with Secure Messaging");
    return 0;
}

// ==============================================================================
// SCION Performance and Stress Tests
// ==============================================================================

int test_scion_performance_optimization(void) {
    TEST_START("SCION Performance Optimization");
    
    printf("Testing SCION performance impact...\n");
    
    // Test without SCION (baseline)
    clock_t start = clock();
    htx_ctx_t* ctx1 = betanet_ctx_create();
    int result1 = betanet_connect_with_ticket(ctx1, TEST_HOST, TEST_PORT, NULL);
    clock_t baseline_time = clock() - start;
    betanet_ctx_free(ctx1);
    
    TEST_ASSERT(result1 == 0, "Baseline connection should succeed");
    
    // Test with SCION path selection
    start = clock();
    betanet_scion_discover_paths(TEST_DESTINATION_IA, TEST_DISCOVERY_TIMEOUT);
    htx_ctx_t* ctx2 = betanet_ctx_create();
    int result2 = betanet_connect_with_ticket(ctx2, TEST_HOST, TEST_PORT, NULL);
    clock_t scion_time = clock() - start;
    betanet_ctx_free(ctx2);
    
    TEST_ASSERT(result2 == 0, "SCION-enhanced connection should succeed");
    
    printf("Performance comparison:\n");
    printf("  Baseline time: %ld ms\n", (baseline_time * 1000) / CLOCKS_PER_SEC);
    printf("  SCION time: %ld ms\n", (scion_time * 1000) / CLOCKS_PER_SEC);
    
    // SCION should not add excessive overhead (within 200% of baseline)
    TEST_ASSERT(scion_time < (baseline_time * 3), "SCION overhead should be reasonable");
    
    TEST_PASS("SCION Performance Optimization");
    return 0;
}

int test_scion_stress_test(void) {
    TEST_START("SCION Stress Test");
    
    printf("Running SCION stress test with multiple connections...\n");
    
    const int num_connections = 10;
    int successful_connections = 0;
    
    // Set optimal criteria for stress test
    betanet_scion_set_selection_criteria(SCION_SELECT_BALANCED);
    
    for (int i = 0; i < num_connections; i++) {
        printf("Connection attempt %d/%d...\n", i + 1, num_connections);
        
        // Discover paths for each connection
        int discovery_result = betanet_scion_discover_paths(TEST_DESTINATION_IA, 2000);
        if (discovery_result != 0) {
            printf("⚠ Path discovery failed for connection %d\n", i + 1);
            continue;
        }
        
        // Create context and connect
        htx_ctx_t* ctx = betanet_ctx_create();
        if (!ctx) {
            printf("⚠ Context creation failed for connection %d\n", i + 1);
            continue;
        }
        
        int connect_result = betanet_connect_with_ticket(ctx, TEST_HOST, TEST_PORT, NULL);
        if (connect_result == 0) {
            successful_connections++;
            printf("✓ Connection %d successful\n", i + 1);
        } else {
            printf("✗ Connection %d failed\n", i + 1);
        }
        
        betanet_ctx_free(ctx);
        
        // Monitor paths during stress test
        betanet_scion_monitor_paths();
    }
    
    printf("Stress test results: %d/%d connections successful\n", 
           successful_connections, num_connections);
    
    // Require at least 70% success rate
    TEST_ASSERT(successful_connections >= (num_connections * 7 / 10), 
                "Should achieve at least 70% success rate in stress test");
    
    // Print final SCION metrics
    printf("Final SCION metrics after stress test:\n");
    betanet_scion_print_metrics();
    
    TEST_PASS("SCION Stress Test");
    return 0;
}

// ==============================================================================
// Test Runner
// ==============================================================================

int main(void) {
    printf("BetaNet SCION Advanced Routing Integration Test\n");
    printf("==============================================\n");
    
    // Initialize BetaNet with all features
    printf("Initializing BetaNet with SCION support...\n");
    betanet_init();
    
    // Seed random number generator for realistic path simulation
    srand((unsigned int)time(NULL));
    
    // Run all tests
    int test_results[] = {
        test_scion_path_discovery(),
        test_scion_path_selection_criteria(),
        test_scion_path_monitoring(),
        test_scion_integrated_connection(),
        test_scion_with_secure_messaging(),
        test_scion_performance_optimization(),
        test_scion_stress_test()
    };
    
    // Count failed tests
    int failed_tests = 0;
    for (int i = 0; i < 7; i++) {
        if (test_results[i] != 0) {
            failed_tests++;
        }
    }
    
    // Print final results
    printf("\n==============================================\n");
    printf("SCION Integration Test Results\n");
    printf("==============================================\n");
    printf("Tests run: %d\n", g_results.tests_run);
    printf("Tests passed: %d\n", g_results.tests_passed);
    printf("Tests failed: %d\n", g_results.tests_failed);
    printf("Overall success rate: %.1f%%\n", 
           (g_results.tests_passed * 100.0) / g_results.tests_run);
    
    // Print comprehensive metrics
    printf("\nFinal SCION Performance Metrics:\n");
    betanet_scion_print_metrics();
    
    // Cleanup
    betanet_shutdown();
    
    if (failed_tests == 0) {
        printf("\n🎉 ALL SCION TESTS PASSED! 🎉\n");
        printf("BetaNet SCION advanced routing is working perfectly!\n");
        return 0;
    } else {
        printf("\n❌ %d tests failed\n", failed_tests);
        return 1;
    }
}
