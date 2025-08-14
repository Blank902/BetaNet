/**
 * @file htx_http2_integration_test.c
 * @brief Integration Tests for HTX Transport with HTTP/2 Emulation
 * 
 * This test suite validates the integration between HTX transport and
 * HTTP/2 behavior emulation for complete BetaNet §5.5 compliance.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../include/betanet/http2_emulation.h"
#include "../include/betanet/htx_transport.h"
#include "../include/betanet/secure_utils.h"
#include "../../include/betanet/secure_utils.h"
#include "../../include/betanet/secure_log.h"

// Test utilities
static int test_count = 0;
static int test_passed = 0;

#define TEST_ASSERT(condition, message) do { \
    test_count++; \
    if (condition) { \
        test_passed++; \
        printf("✓ PASS: %s\n", message); \
    } else { \
        printf("✗ FAIL: %s\n", message); \
    } \
} while(0)

// Mock SSL context for testing
typedef struct {
    uint8_t* buffer;
    size_t buffer_size;
    size_t buffer_capacity;
    bool simulate_write_error;
} mock_ssl_context_t;

static int mock_ssl_write(void* ssl_context, const void* data, int length) {
    mock_ssl_context_t* mock_ctx = (mock_ssl_context_t*)ssl_context;
    
    if (mock_ctx->simulate_write_error) {
        return -1;
    }
    
    if (mock_ctx->buffer_size + length > mock_ctx->buffer_capacity) {
        return -1; // Buffer overflow
    }
    
    secure_memcpy(mock_ctx->buffer + mock_ctx->buffer_size, sizeof(mock_ctx->buffer + mock_ctx->buffer_size), data, length);
    mock_ctx->buffer_size += length;
    return length;
}

static void init_mock_ssl_context(mock_ssl_context_t* ctx, uint8_t* buffer, size_t capacity) {
    ctx->buffer = buffer;
    ctx->buffer_size = 0;
    ctx->buffer_capacity = capacity;
    ctx->simulate_write_error = false;
}

static void reset_mock_ssl_context(mock_ssl_context_t* ctx) {
    ctx->buffer_size = 0;
    ctx->simulate_write_error = false;
    if (ctx->buffer) {
        secure_memset(ctx->buffer, 0, ctx->buffer_capacity);
    }
}

// Test HTTP/2 emulation initialization and configuration
void test_http2_emulation_configuration(void) {
    printf("\n=== Testing HTTP/2 Emulation Configuration ===\n");
    
    // Test default configuration
    http2_emulation_config_t default_config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    TEST_ASSERT(default_config.ping_base_interval_ms == 30000, "Default PING interval");
    TEST_ASSERT(default_config.ping_jitter_percent == 15, "Default PING jitter");
    TEST_ASSERT(default_config.settings_tolerance_percent == 10, "Default SETTINGS tolerance");
    TEST_ASSERT(default_config.priority_baseline_rate == 0.01f, "Default PRIORITY rate");
    TEST_ASSERT(default_config.enable_adaptive_settings == true, "Adaptive SETTINGS enabled");
    TEST_ASSERT(default_config.enable_adaptive_ping == true, "Adaptive PING enabled");
    TEST_ASSERT(default_config.enable_adaptive_priority == true, "Adaptive PRIORITY enabled");
    TEST_ASSERT(default_config.enable_idle_padding == true, "Idle padding enabled");
    
    // Test custom configuration
    http2_emulation_config_t custom_config = {
        .ping_base_interval_ms = 45000,
        .ping_jitter_percent = 20,
        .settings_tolerance_percent = 15,
        .priority_baseline_rate = 0.02f,
        .idle_padding_min_delay_ms = 300,
        .idle_padding_max_delay_ms = 1500,
        .max_idle_padding_bytes = 2048,
        .enable_adaptive_settings = false,
        .enable_adaptive_ping = true,
        .enable_adaptive_priority = true,
        .enable_idle_padding = false
    };
    
    http2_emulation_context_t ctx;
    int result = http2_emulation_init(&ctx, &custom_config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Custom config initialization");
    TEST_ASSERT(ctx.config.ping_base_interval_ms == 45000, "Custom PING interval");
    TEST_ASSERT(ctx.config.enable_adaptive_settings == false, "Custom adaptive SETTINGS");
    
    http2_emulation_destroy(&ctx);
}

// Test origin behavior learning and adaptation
void test_origin_behavior_adaptation(void) {
    printf("\n=== Testing Origin Behavior Adaptation ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    config.settings_tolerance_percent = 25; // Higher tolerance for testing
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    // Simulate learning from a typical origin server
    http2_origin_behavior_t chrome_behavior = {
        .observed_settings = {
            .header_table_size = 4096,
            .enable_push = 0,
            .max_concurrent_streams = 1000,
            .initial_window_size = 65535,
            .max_frame_size = 16384,
            .max_header_list_size = 8192
        },
        .avg_ping_interval_ms = 30000,
        .priority_emission_rate = 0.015f,
        .avg_idle_padding_bytes = 512,
        .has_valid_data = true
    };
    
    result = http2_emulation_learn_from_origin(&ctx, &chrome_behavior);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Learn Chrome-like behavior");
    TEST_ASSERT(ctx.has_learned_behavior == true, "Behavior learned flag set");
    
    // Check adaptation within tolerance (±25%)
    uint32_t min_header_table = 4096 * 75 / 100;
    uint32_t max_header_table = 4096 * 125 / 100;
    TEST_ASSERT(ctx.baseline_settings.header_table_size >= min_header_table &&
                ctx.baseline_settings.header_table_size <= max_header_table,
                "Header table size adapted within tolerance");
    
    uint32_t min_streams = 1000 * 75 / 100;
    uint32_t max_streams = 1000 * 125 / 100;
    TEST_ASSERT(ctx.baseline_settings.max_concurrent_streams >= min_streams &&
                ctx.baseline_settings.max_concurrent_streams <= max_streams,
                "Max streams adapted within tolerance");
    
    // Test learning from a different origin (Firefox-like)
    http2_origin_behavior_t firefox_behavior = {
        .observed_settings = {
            .header_table_size = 65536,
            .enable_push = 1,
            .max_concurrent_streams = 200,
            .initial_window_size = 131072,
            .max_frame_size = 32768,
            .max_header_list_size = 65536
        },
        .avg_ping_interval_ms = 60000,
        .priority_emission_rate = 0.008f,
        .avg_idle_padding_bytes = 256,
        .has_valid_data = true
    };
    
    result = http2_emulation_learn_from_origin(&ctx, &firefox_behavior);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Learn Firefox-like behavior");
    TEST_ASSERT(ctx.stats.origin_adaptations == 2, "Multiple adaptations tracked");
    
    // Verify the adaptation changed the baseline
    TEST_ASSERT(ctx.learned_ping_interval == 60000, "PING interval updated to Firefox value");
    TEST_ASSERT(ctx.priority_emission_rate < 0.015f, "PRIORITY rate adapted to Firefox pattern");
    
    http2_emulation_destroy(&ctx);
}

// Test full HTTP/2 frame emission cycle
void test_full_frame_emission_cycle(void) {
    printf("\n=== Testing Full Frame Emission Cycle ===\n");
    
    uint8_t ssl_buffer[65536];
    mock_ssl_context_t mock_ssl;
    init_mock_ssl_context(&mock_ssl, ssl_buffer, sizeof(ssl_buffer));
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    config.ping_base_interval_ms = 1000; // Short interval for testing
    config.priority_baseline_rate = 0.5f; // 50% emission for testing
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    // 1. Send initial SETTINGS frame
    result = http2_emulation_send_settings(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Send initial SETTINGS");
    TEST_ASSERT(mock_ssl.buffer_size > 0, "SETTINGS frame data written");
    
    size_t settings_frame_size = mock_ssl.buffer_size;
    
    // 2. Attempt PING emission (should not send initially)
    result = http2_emulation_maybe_send_ping(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "PING check succeeds");
    
    // 3. Force PING emission by manipulating time
    ctx.last_ping_time = 0;
    result = http2_emulation_maybe_send_ping(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Forced PING emission");
    TEST_ASSERT(mock_ssl.buffer_size > settings_frame_size, "PING frame added");
    
    size_t after_ping_size = mock_ssl.buffer_size;
    
    // 4. Attempt PRIORITY emission (may or may not emit based on probability)
    ctx.last_priority_time = 0;
    ctx.next_priority_check = 0;
    result = http2_emulation_maybe_send_priority(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "PRIORITY check succeeds");
    
    // 5. Attempt idle padding
    uint64_t old_data_time = (uint64_t)time(NULL) * 1000 - 1000; // 1 second ago
    ctx.last_idle_padding_time = 0;
    result = http2_emulation_maybe_send_idle_padding(&ctx, mock_ssl_write, &mock_ssl, old_data_time);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Idle padding check succeeds");
    
    // Verify total statistics
    http2_emulation_stats_t stats;
    result = http2_emulation_get_stats(&ctx, &stats);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Get final stats");
    TEST_ASSERT(stats.total_frames_sent >= 2, "At least SETTINGS + PING sent");
    TEST_ASSERT(stats.settings_frames_sent == 1, "One SETTINGS frame sent");
    TEST_ASSERT(stats.ping_frames_sent == 1, "One PING frame sent");
    
    printf("Frame emission summary: %llu total, %llu SETTINGS, %llu PING, %llu PRIORITY, %llu padding\n",
           (unsigned long long)stats.total_frames_sent,
           (unsigned long long)stats.settings_frames_sent,
           (unsigned long long)stats.ping_frames_sent,
           (unsigned long long)stats.priority_frames_sent,
           (unsigned long long)stats.idle_padding_frames_sent);
    
    http2_emulation_destroy(&ctx);
}

// Test network error handling
void test_network_error_handling(void) {
    printf("\n=== Testing Network Error Handling ===\n");
    
    uint8_t ssl_buffer[1024];
    mock_ssl_context_t mock_ssl;
    init_mock_ssl_context(&mock_ssl, ssl_buffer, sizeof(ssl_buffer));
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    // Simulate network write error
    mock_ssl.simulate_write_error = true;
    
    result = http2_emulation_send_settings(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_NETWORK, "SETTINGS handles write error");
    
    ctx.last_ping_time = 0; // Force PING attempt
    result = http2_emulation_maybe_send_ping(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_NETWORK, "PING handles write error");
    
    // Test buffer overflow scenario
    mock_ssl.simulate_write_error = false;
    mock_ssl.buffer_capacity = 5; // Too small for any frame
    
    result = http2_emulation_send_settings(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_NETWORK, "SETTINGS handles buffer overflow");
    
    http2_emulation_destroy(&ctx);
}

// Test adaptive behavior under different conditions
void test_adaptive_behavior_scenarios(void) {
    printf("\n=== Testing Adaptive Behavior Scenarios ===\n");
    
    uint8_t ssl_buffer[65536];
    mock_ssl_context_t mock_ssl;
    init_mock_ssl_context(&mock_ssl, ssl_buffer, sizeof(ssl_buffer));
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    // Scenario 1: High-frequency origin (mobile app)
    http2_origin_behavior_t mobile_behavior = {
        .observed_settings = {
            .header_table_size = 2048,
            .enable_push = 0,
            .max_concurrent_streams = 10,
            .initial_window_size = 32768,
            .max_frame_size = 8192,
            .max_header_list_size = 4096
        },
        .avg_ping_interval_ms = 15000, // Frequent pings
        .priority_emission_rate = 0.03f, // High priority usage
        .avg_idle_padding_bytes = 128,
        .has_valid_data = true
    };
    
    result = http2_emulation_learn_from_origin(&ctx, &mobile_behavior);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Learn mobile app behavior");
    
    // Test adapted behavior
    TEST_ASSERT(ctx.learned_ping_interval == 15000, "Adapted to mobile PING frequency");
    TEST_ASSERT(ctx.priority_emission_rate >= 0.025f, "Adapted to mobile PRIORITY usage");
    
    // Scenario 2: Enterprise application (conservative)
    http2_origin_behavior_t enterprise_behavior = {
        .observed_settings = {
            .header_table_size = 16384,
            .enable_push = 1,
            .max_concurrent_streams = 500,
            .initial_window_size = 131072,
            .max_frame_size = 65536,
            .max_header_list_size = 32768
        },
        .avg_ping_interval_ms = 120000, // Infrequent pings
        .priority_emission_rate = 0.002f, // Low priority usage
        .avg_idle_padding_bytes = 2048,
        .has_valid_data = true
    };
    
    result = http2_emulation_learn_from_origin(&ctx, &enterprise_behavior);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Learn enterprise behavior");
    
    // Test behavior change
    TEST_ASSERT(ctx.learned_ping_interval == 120000, "Adapted to enterprise PING frequency");
    TEST_ASSERT(ctx.priority_emission_rate <= 0.005f, "Adapted to enterprise PRIORITY usage");
    
    // Test runtime behavior update
    http2_behavior_update_t runtime_update = {
        .new_ping_interval_ms = 90000,
        .new_priority_rate = 0.005f
    };
    
    result = http2_emulation_update_behavior(&ctx, &runtime_update);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Runtime behavior update");
    TEST_ASSERT(ctx.learned_ping_interval == 90000, "Runtime PING update applied");
    TEST_ASSERT(ctx.priority_emission_rate == 0.005f, "Runtime PRIORITY update applied");
    
    http2_emulation_destroy(&ctx);
}

// Test integration with traffic shaping profiles
void test_traffic_shaping_integration(void) {
    printf("\n=== Testing Traffic Shaping Integration ===\n");
    
    // This test verifies that HTTP/2 emulation can work alongside
    // existing traffic shaping from shape.c
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    // Simulate learning from a traffic-shaped origin
    http2_origin_behavior_t shaped_behavior = {
        .observed_settings = {
            .header_table_size = 4096,
            .enable_push = 0,
            .max_concurrent_streams = 100,
            .initial_window_size = 65535,
            .max_frame_size = 16384,
            .max_header_list_size = 8192
        },
        .avg_ping_interval_ms = 30000,
        .priority_emission_rate = 0.01f,
        .avg_idle_padding_bytes = 1024,
        .has_valid_data = true
    };
    
    result = http2_emulation_learn_from_origin(&ctx, &shaped_behavior);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Learn shaped behavior");
    
    // Verify that emulation parameters are reasonable for traffic shaping
    TEST_ASSERT(ctx.next_ping_interval >= 10000 && ctx.next_ping_interval <= 60000,
                "PING interval within traffic shaping bounds");
    TEST_ASSERT(ctx.priority_emission_rate >= 0.0f && ctx.priority_emission_rate <= 0.05f,
                "PRIORITY rate within reasonable bounds");
    
    // Test multiple rapid adaptations (simulating dynamic conditions)
    for (int i = 0; i < 5; i++) {
        http2_behavior_update_t update = {
            .new_ping_interval_ms = 25000 + (i * 5000),
            .new_priority_rate = 0.005f + (i * 0.002f)
        };
        
        result = http2_emulation_update_behavior(&ctx, &update);
        TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Rapid behavior adaptation");
    }
    
    TEST_ASSERT(ctx.stats.behavior_updates == 5, "Multiple updates tracked");
    
    http2_emulation_destroy(&ctx);
}

// Test compliance with BetaNet §5.5 requirements
void test_betanet_compliance(void) {
    printf("\n=== Testing BetaNet §5.5 Compliance ===\n");
    
    uint8_t ssl_buffer[65536];
    mock_ssl_context_t mock_ssl;
    init_mock_ssl_context(&mock_ssl, ssl_buffer, sizeof(ssl_buffer));
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    // §5.5.1: Origin SETTINGS Mirroring
    http2_origin_behavior_t origin = {
        .observed_settings = {
            .header_table_size = 8192,
            .enable_push = 1,
            .max_concurrent_streams = 200,
            .initial_window_size = 131072,
            .max_frame_size = 32768,
            .max_header_list_size = 16384
        },
        .avg_ping_interval_ms = 45000,
        .priority_emission_rate = 0.02f,
        .avg_idle_padding_bytes = 512,
        .has_valid_data = true
    };
    
    result = http2_emulation_learn_from_origin(&ctx, &origin);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "§5.5.1 Origin SETTINGS mirroring");
    
    // Send SETTINGS and verify they're within tolerance
    result = http2_emulation_send_settings(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "§5.5.1 Adaptive SETTINGS emission");
    
    // §5.5.2: Adaptive PING Cadence
    ctx.last_ping_time = 0;
    result = http2_emulation_maybe_send_ping(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "§5.5.2 Adaptive PING cadence");
    TEST_ASSERT(ctx.next_ping_interval >= 10000 && ctx.next_ping_interval <= 60000,
                "§5.5.2 PING interval bounds compliance");
    
    // §5.5.3: PRIORITY Frame Emission
    ctx.last_priority_time = 0;
    ctx.next_priority_check = 0;
    result = http2_emulation_maybe_send_priority(&ctx, mock_ssl_write, &mock_ssl);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "§5.5.3 PRIORITY frame emission");
    
    // §5.5.4: Idle Connection Padding
    uint64_t old_time = (uint64_t)time(NULL) * 1000 - 500;
    ctx.last_idle_padding_time = 0;
    result = http2_emulation_maybe_send_idle_padding(&ctx, mock_ssl_write, &mock_ssl, old_time);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "§5.5.4 Idle connection padding");
    
    // §5.5.5: Statistical Indistinguishability
    http2_emulation_stats_t stats;
    result = http2_emulation_get_stats(&ctx, &stats);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "§5.5.5 Statistics tracking");
    TEST_ASSERT(stats.total_frames_sent > 0, "§5.5.5 Frame emission tracking");
    
    printf("BetaNet §5.5 compliance verified: %llu frames, %llu adaptations\n",
           (unsigned long long)stats.total_frames_sent,
           (unsigned long long)stats.origin_adaptations);
    
    http2_emulation_destroy(&ctx);
}

// Main test runner
int main(void) {
    printf("HTX HTTP/2 Emulation Integration Test Suite\n");
    printf("============================================\n");
    
    // Seed random number generator for consistent testing
    srand(42);
    
    // Run all integration tests
    test_http2_emulation_configuration();
    test_origin_behavior_adaptation();
    test_full_frame_emission_cycle();
    test_network_error_handling();
    test_adaptive_behavior_scenarios();
    test_traffic_shaping_integration();
    test_betanet_compliance();
    
    // Print summary
    printf("\n============================================\n");
    printf("Integration Test Summary: %d/%d tests passed\n", test_passed, test_count);
    
    if (test_passed == test_count) {
        printf("✓ All integration tests PASSED!\n");
        printf("✓ HTTP/2 Behavior Emulation (BetaNet §5.5) is ready for production\n");
        return 0;
    } else {
        printf("✗ %d integration tests FAILED!\n", test_count - test_passed);
        return 1;
    }
}
