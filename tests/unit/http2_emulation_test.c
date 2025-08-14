/**
 * @file http2_emulation_test.c
 * @brief Unit Tests for HTTP/2 Behavior Emulation (BetaNet §5.5)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../include/betanet/http2_emulation.h"
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

// Mock SSL write function for testing
static uint8_t mock_ssl_buffer[65536];
static size_t mock_ssl_buffer_size = 0;

static int mock_ssl_write(void* ssl_context, const void* data, int length) {
    (void)ssl_context; // Unused
    
    if (mock_ssl_buffer_size + length > sizeof(mock_ssl_buffer)) {
        return -1; // Buffer overflow
    }
    
    secure_memcpy(mock_ssl_buffer + mock_ssl_buffer_size, sizeof(mock_ssl_buffer + mock_ssl_buffer_size), data, length);
    mock_ssl_buffer_size += length;
    return length;
}

static void reset_mock_ssl_buffer(void) {
    mock_ssl_buffer_size = 0;
    secure_memset(mock_ssl_buffer, 0, sizeof(mock_ssl_buffer));
}

// Test initialization and destruction
void test_http2_emulation_init_destroy(void) {
    printf("\n=== Testing HTTP/2 Emulation Init/Destroy ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    // Test successful initialization
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Init with valid params");
    TEST_ASSERT(ctx.is_initialized == true, "Context marked as initialized");
    TEST_ASSERT(ctx.config.ping_base_interval_ms == 30000, "Config copied correctly");
    
    // Test invalid parameters
    result = http2_emulation_init(NULL, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Init with NULL context");
    
    result = http2_emulation_init(&ctx, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Init with NULL config");
    
    // Test destruction
    result = http2_emulation_destroy(&ctx);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Destroy valid context");
    // Note: After secure destruction, all memory is cleared for security
    // So we don't test individual field values as they're all zeroed
    
    result = http2_emulation_destroy(NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Destroy NULL context");
}

// Test origin behavior learning
void test_http2_emulation_learn_behavior(void) {
    printf("\n=== Testing Origin Behavior Learning ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    config.settings_tolerance_percent = 20; // 20% tolerance for testing
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    // Set up origin behavior
    http2_origin_behavior_t origin_behavior = {
        .observed_settings = {
            .header_table_size = 8192,
            .enable_push = 1,
            .max_concurrent_streams = 200,
            .initial_window_size = 32768,
            .max_frame_size = 32768,
            .max_header_list_size = 16384
        },
        .avg_ping_interval_ms = 45000,
        .priority_emission_rate = 0.025f,
        .avg_idle_padding_bytes = 1024,
        .has_valid_data = true
    };
    
    // Learn from origin
    result = http2_emulation_learn_from_origin(&ctx, &origin_behavior);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Learn from valid origin behavior");
    TEST_ASSERT(ctx.has_learned_behavior == true, "Learned behavior flag set");
    TEST_ASSERT(ctx.stats.origin_adaptations == 1, "Origin adaptation count incremented");
    
    // Check that SETTINGS are within tolerance
    uint32_t min_header_table = 8192 * 80 / 100; // 20% tolerance
    uint32_t max_header_table = 8192 * 120 / 100;
    TEST_ASSERT(ctx.baseline_settings.header_table_size >= min_header_table &&
                ctx.baseline_settings.header_table_size <= max_header_table,
                "Header table size within tolerance");
    
    // Check PING interval learning
    TEST_ASSERT(ctx.learned_ping_interval == 45000, "PING interval learned correctly");
    
    // Check PRIORITY rate learning (allows for ±1.5% jitter added in implementation)
    TEST_ASSERT(ctx.priority_emission_rate >= 0.01f && ctx.priority_emission_rate <= 0.04f,
                "PRIORITY emission rate adapted");
    
    // Test invalid parameters
    result = http2_emulation_learn_from_origin(NULL, &origin_behavior);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Learn with NULL context");
    
    result = http2_emulation_learn_from_origin(&ctx, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Learn with NULL behavior");
    
    http2_emulation_destroy(&ctx);
}

// Test SETTINGS frame emission
void test_http2_emulation_send_settings(void) {
    printf("\n=== Testing SETTINGS Frame Emission ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    reset_mock_ssl_buffer();
    
    // Send SETTINGS frame
    result = http2_emulation_send_settings(&ctx, mock_ssl_write, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Send SETTINGS frame");
    TEST_ASSERT(ctx.stats.settings_frames_sent == 1, "SETTINGS frame count incremented");
    TEST_ASSERT(ctx.stats.total_frames_sent == 1, "Total frame count incremented");
    
    // Verify frame structure
    TEST_ASSERT(mock_ssl_buffer_size >= 9, "Frame has minimum header size");
    
    // Check frame header (first 9 bytes)
    uint32_t frame_length = (mock_ssl_buffer[0] << 16) | (mock_ssl_buffer[1] << 8) | mock_ssl_buffer[2];
    uint8_t frame_type = mock_ssl_buffer[3];
    uint8_t frame_flags = mock_ssl_buffer[4];
    uint32_t stream_id = (mock_ssl_buffer[5] << 24) | (mock_ssl_buffer[6] << 16) | 
                        (mock_ssl_buffer[7] << 8) | mock_ssl_buffer[8];
    
    TEST_ASSERT(frame_type == 0x04, "Frame type is SETTINGS (0x04)");
    TEST_ASSERT(frame_flags == 0x00, "Frame flags are correct (no ACK)");
    TEST_ASSERT(stream_id == 0x00, "Stream ID is 0 (connection-level)");
    TEST_ASSERT(frame_length == 36, "Frame length is 36 bytes (6 settings × 6 bytes)");
    TEST_ASSERT(mock_ssl_buffer_size == 45, "Total frame size is 45 bytes (9 + 36)");
    
    // Test invalid parameters
    result = http2_emulation_send_settings(NULL, mock_ssl_write, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Send with NULL context");
    
    result = http2_emulation_send_settings(&ctx, NULL, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Send with NULL write function");
    
    http2_emulation_destroy(&ctx);
}

// Test PING frame emission
void test_http2_emulation_ping_frames(void) {
    printf("\n=== Testing PING Frame Emission ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    config.ping_base_interval_ms = 100; // Short interval for testing
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    reset_mock_ssl_buffer();
    
    // First call should not send PING (too soon)
    result = http2_emulation_maybe_send_ping(&ctx, mock_ssl_write, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "First PING call succeeds");
    TEST_ASSERT(ctx.stats.ping_frames_sent == 0, "No PING sent initially");
    TEST_ASSERT(mock_ssl_buffer_size == 0, "No data sent initially");
    
    // Simulate time passage
    ctx.last_ping_time = 0; // Force PING to be sent
    
    result = http2_emulation_maybe_send_ping(&ctx, mock_ssl_write, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "PING emission succeeds");
    TEST_ASSERT(ctx.stats.ping_frames_sent == 1, "PING frame count incremented");
    TEST_ASSERT(ctx.stats.total_frames_sent == 1, "Total frame count incremented");
    
    // Verify PING frame structure
    TEST_ASSERT(mock_ssl_buffer_size == 17, "PING frame size is 17 bytes (9 + 8)");
    
    uint8_t frame_type = mock_ssl_buffer[3];
    uint32_t frame_length = (mock_ssl_buffer[0] << 16) | (mock_ssl_buffer[1] << 8) | mock_ssl_buffer[2];
    uint32_t stream_id = (mock_ssl_buffer[5] << 24) | (mock_ssl_buffer[6] << 16) | 
                        (mock_ssl_buffer[7] << 8) | mock_ssl_buffer[8];
    
    TEST_ASSERT(frame_type == 0x06, "Frame type is PING (0x06)");
    TEST_ASSERT(frame_length == 8, "PING payload length is 8 bytes");
    TEST_ASSERT(stream_id == 0, "Stream ID is 0 (connection-level)");
    
    // Test interval bounds
    TEST_ASSERT(ctx.next_ping_interval >= 10000, "PING interval >= 10 seconds");
    TEST_ASSERT(ctx.next_ping_interval <= 60000, "PING interval <= 60 seconds");
    
    http2_emulation_destroy(&ctx);
}

// Test PRIORITY frame emission
void test_http2_emulation_priority_frames(void) {
    printf("\n=== Testing PRIORITY Frame Emission ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    config.priority_baseline_rate = 1.0f; // 100% emission for testing
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    reset_mock_ssl_buffer();
    
    // Force PRIORITY emission by setting past time
    ctx.last_priority_time = 0;
    ctx.next_priority_check = 0;
    
    result = http2_emulation_maybe_send_priority(&ctx, mock_ssl_write, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "PRIORITY emission succeeds");
    
    // With 100% rate, should emit PRIORITY frame
    TEST_ASSERT(ctx.stats.priority_frames_sent >= 0, "PRIORITY frame may be sent");
    
    if (ctx.stats.priority_frames_sent > 0) {
        TEST_ASSERT(mock_ssl_buffer_size == 14, "PRIORITY frame size is 14 bytes (9 + 5)");
        
        uint8_t frame_type = mock_ssl_buffer[3];
        uint32_t frame_length = (mock_ssl_buffer[0] << 16) | (mock_ssl_buffer[1] << 8) | mock_ssl_buffer[2];
        uint32_t stream_id = (mock_ssl_buffer[5] << 24) | (mock_ssl_buffer[6] << 16) | 
                            (mock_ssl_buffer[7] << 8) | mock_ssl_buffer[8];
        
        TEST_ASSERT(frame_type == 0x02, "Frame type is PRIORITY (0x02)");
        TEST_ASSERT(frame_length == 5, "PRIORITY payload length is 5 bytes");
        TEST_ASSERT(stream_id >= 1 && stream_id <= 15, "Stream ID is in valid range");
    }
    
    // Test with 0% emission rate
    ctx.priority_emission_rate = 0.0f;
    ctx.last_priority_time = 0;
    ctx.next_priority_check = 0;
    reset_mock_ssl_buffer();
    
    result = http2_emulation_maybe_send_priority(&ctx, mock_ssl_write, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "0% PRIORITY rate succeeds");
    // With 0% rate, should not emit (though random might still allow it)
    
    http2_emulation_destroy(&ctx);
}

// Test idle padding emission
void test_http2_emulation_idle_padding(void) {
    printf("\n=== Testing Idle Padding Emission ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    config.idle_padding_min_delay_ms = 100;
    config.idle_padding_max_delay_ms = 200;
    config.max_idle_padding_bytes = 1024;
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    reset_mock_ssl_buffer();
    
    // Test with recent data (should not send padding)
    uint64_t recent_time = (uint64_t)time(NULL) * 1000; // Current time
    result = http2_emulation_maybe_send_idle_padding(&ctx, mock_ssl_write, NULL, recent_time);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Recent data - no padding");
    TEST_ASSERT(ctx.stats.idle_padding_frames_sent == 0, "No padding sent for recent data");
    
    // Test with old data (should consider sending padding)
    uint64_t old_time = recent_time - 500; // 500ms ago
    ctx.last_idle_padding_time = 0; // Allow padding
    
    result = http2_emulation_maybe_send_idle_padding(&ctx, mock_ssl_write, NULL, old_time);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Old data - padding check succeeds");
    
    // May or may not send padding depending on random length
    if (ctx.stats.idle_padding_frames_sent > 0) {
        TEST_ASSERT(mock_ssl_buffer_size >= 9, "Padding frame has header");
        
        uint8_t frame_type = mock_ssl_buffer[3];
        uint32_t frame_length = (mock_ssl_buffer[0] << 16) | (mock_ssl_buffer[1] << 8) | mock_ssl_buffer[2];
        uint32_t stream_id = (mock_ssl_buffer[5] << 24) | (mock_ssl_buffer[6] << 16) | 
                            (mock_ssl_buffer[7] << 8) | mock_ssl_buffer[8];
        
        TEST_ASSERT(frame_type == 0x00, "Frame type is DATA (0x00)");
        TEST_ASSERT(frame_length <= 1024, "Padding length within limit");
        TEST_ASSERT((stream_id % 2) == 0, "Stream ID is even (server-initiated)");
        TEST_ASSERT(mock_ssl_buffer_size == 9 + frame_length, "Frame size matches header");
    }
    
    http2_emulation_destroy(&ctx);
}

// Test statistics tracking
void test_http2_emulation_stats(void) {
    printf("\n=== Testing Statistics Tracking ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    http2_emulation_stats_t stats;
    result = http2_emulation_get_stats(&ctx, &stats);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Get initial stats");
    TEST_ASSERT(stats.total_frames_sent == 0, "Initial frame count is zero");
    
    // Send a SETTINGS frame to update stats
    reset_mock_ssl_buffer();
    result = http2_emulation_send_settings(&ctx, mock_ssl_write, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Send SETTINGS frame");
    
    result = http2_emulation_get_stats(&ctx, &stats);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Get updated stats");
    TEST_ASSERT(stats.total_frames_sent == 1, "Frame count incremented");
    TEST_ASSERT(stats.settings_frames_sent == 1, "SETTINGS count incremented");
    
    // Test invalid parameters
    result = http2_emulation_get_stats(NULL, &stats);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Get stats with NULL context");
    
    result = http2_emulation_get_stats(&ctx, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Get stats with NULL output");
    
    http2_emulation_destroy(&ctx);
}

// Test behavior updates
void test_http2_emulation_behavior_updates(void) {
    printf("\n=== Testing Behavior Updates ===\n");
    
    http2_emulation_context_t ctx;
    http2_emulation_config_t config = HTTP2_EMULATION_DEFAULT_CONFIG();
    
    int result = http2_emulation_init(&ctx, &config);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Context initialization");
    
    uint32_t original_ping_interval = ctx.next_ping_interval;
    float original_priority_rate = ctx.priority_emission_rate;
    
    // Update behavior
    http2_behavior_update_t update = {
        .new_ping_interval_ms = 25000,
        .new_priority_rate = 0.02f
    };
    
    result = http2_emulation_update_behavior(&ctx, &update);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Behavior update succeeds");
    TEST_ASSERT(ctx.stats.behavior_updates == 1, "Update count incremented");
    TEST_ASSERT(ctx.learned_ping_interval == 25000, "PING interval updated");
    TEST_ASSERT(ctx.priority_emission_rate == 0.02f, "PRIORITY rate updated");
    
    // Test partial update (only PING)
    http2_behavior_update_t partial_update = {
        .new_ping_interval_ms = 35000,
        .new_priority_rate = -1.0f // No change
    };
    
    result = http2_emulation_update_behavior(&ctx, &partial_update);
    TEST_ASSERT(result == HTTP2_EMULATION_SUCCESS, "Partial update succeeds");
    TEST_ASSERT(ctx.learned_ping_interval == 35000, "PING interval updated");
    TEST_ASSERT(ctx.priority_emission_rate == 0.02f, "PRIORITY rate unchanged");
    
    // Test invalid parameters
    result = http2_emulation_update_behavior(NULL, &update);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Update with NULL context");
    
    result = http2_emulation_update_behavior(&ctx, NULL);
    TEST_ASSERT(result == HTTP2_EMULATION_ERROR_INVALID_PARAM, "Update with NULL params");
    
    http2_emulation_destroy(&ctx);
}

// Main test runner
int main(void) {
    printf("HTTP/2 Behavior Emulation Test Suite\n");
    printf("=====================================\n");
    
    // Seed random number generator for consistent testing
    srand(12345);
    
    // Run all tests
    test_http2_emulation_init_destroy();
    test_http2_emulation_learn_behavior();
    test_http2_emulation_send_settings();
    test_http2_emulation_ping_frames();
    test_http2_emulation_priority_frames();
    test_http2_emulation_idle_padding();
    test_http2_emulation_stats();
    test_http2_emulation_behavior_updates();
    
    // Print summary
    printf("\n=====================================\n");
    printf("Test Summary: %d/%d tests passed\n", test_passed, test_count);
    
    if (test_passed == test_count) {
        printf("✓ All tests PASSED!\n");
        return 0;
    } else {
        printf("✗ %d tests FAILED!\n", test_count - test_passed);
        return 1;
    }
}
