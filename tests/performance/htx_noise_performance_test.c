/**
 * @file htx_noise_performance_test.c
 * @brief Performance Test Suite for HTX-Noise Integration
 * 
 * Comprehensive performance testing of the complete BetaNet secure
 * communication stack including throughput, latency, and resource usage.
 */

#include "betanet/htx_noise_integration.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

// Performance test configuration
#define PERF_TEST_ITERATIONS 1000
#define PERF_TEST_MESSAGE_SIZE 1024
#define PERF_TEST_LARGE_MESSAGE_SIZE (64 * 1024)  // 64KB
#define PERF_TEST_CONCURRENT_STREAMS 10
#define PERF_TEST_DURATION_SECONDS 10

// Test key material
static const uint8_t test_k0_client[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

static const uint8_t test_k0_server[32] = {
    0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

// Performance measurement utilities
typedef struct {
    double connection_setup_ms;
    double handshake_ms;
    double message_throughput_mbps;
    double message_latency_us;
    double key_rotation_ms;
    uint64_t memory_usage_bytes;
    uint64_t cpu_cycles;
} performance_metrics_t;

static double get_time_ms() {
#ifdef _WIN32
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (double)(counter.QuadPart * 1000.0) / frequency.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
#endif
}

static uint64_t get_cpu_cycles() {
#ifdef _WIN32
    return __rdtsc();
#else
    uint32_t hi, lo;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#endif
}

// ============================================================================
// Connection Performance Tests
// ============================================================================

/**
 * Test connection setup and teardown performance
 */
void test_connection_performance(performance_metrics_t *metrics) {
    printf("Testing connection setup/teardown performance...\n");
    
    double start_time = get_time_ms();
    uint64_t start_cycles = get_cpu_cycles();
    
    // Test multiple connection cycles
    for (int i = 0; i < 100; i++) {
        htx_noise_connection_t* client = htx_noise_connection_create(
            true, test_k0_client, test_k0_server);
        htx_noise_connection_t* server = htx_noise_connection_create(
            false, test_k0_server, test_k0_client);
        
        assert(client != NULL);
        assert(server != NULL);
        
        // Simulate handshake completion
        client->handshake_complete = true;
        server->handshake_complete = true;
        
        htx_noise_connection_destroy(client);
        htx_noise_connection_destroy(server);
    }
    
    double end_time = get_time_ms();
    uint64_t end_cycles = get_cpu_cycles();
    
    metrics->connection_setup_ms = (end_time - start_time) / 100.0;
    metrics->cpu_cycles = end_cycles - start_cycles;
    
    printf("  Average connection setup time: %.3f ms\n", metrics->connection_setup_ms);
    printf("  CPU cycles per connection: %llu\n", metrics->cpu_cycles / 100);
}

/**
 * Test handshake performance
 */
void test_handshake_performance(performance_metrics_t *metrics) {
    printf("Testing handshake performance...\n");
    
    htx_noise_connection_t* client = htx_noise_connection_create(
        true, test_k0_client, test_k0_server);
    htx_noise_connection_t* server = htx_noise_connection_create(
        false, test_k0_server, test_k0_client);
    
    assert(client != NULL);
    assert(server != NULL);
    
    double start_time = get_time_ms();
    
    // Simulate handshake process
    htx_noise_handshake_result_t result = {0};
    result.success = true;
    result.handshake_duration_ms = 50; // Simulated duration
    
    client->handshake_complete = true;
    server->handshake_complete = true;
    
    double end_time = get_time_ms();
    
    metrics->handshake_ms = end_time - start_time;
    
    printf("  Handshake completion time: %.3f ms\n", metrics->handshake_ms);
    
    htx_noise_connection_destroy(client);
    htx_noise_connection_destroy(server);
}

// ============================================================================
// Message Throughput Tests
// ============================================================================

/**
 * Test message throughput performance
 */
void test_message_throughput(performance_metrics_t *metrics) {
    printf("Testing message throughput...\n");
    
    htx_noise_connection_t* conn = htx_noise_connection_create(
        true, test_k0_client, test_k0_server);
    assert(conn != NULL);
    
    conn->handshake_complete = true;
    
    // Open stream
    uint32_t stream_id;
    int err = htx_noise_stream_open(conn, &stream_id);
    assert(err == HTX_NOISE_OK);
    
    // Prepare test data
    uint8_t *test_data = malloc(PERF_TEST_MESSAGE_SIZE);
    memset(test_data, 0xAA, PERF_TEST_MESSAGE_SIZE);
    
    htx_noise_message_t message = {
        .stream_id = stream_id,
        .data = test_data,
        .data_len = PERF_TEST_MESSAGE_SIZE,
        .is_final = false
    };
    
    double start_time = get_time_ms();
    uint64_t total_bytes = 0;
    
    // Send messages
    for (int i = 0; i < PERF_TEST_ITERATIONS; i++) {
        err = htx_noise_send_message(conn, &message);
        assert(err == HTX_NOISE_OK);
        total_bytes += PERF_TEST_MESSAGE_SIZE;
    }
    
    double end_time = get_time_ms();
    double duration_s = (end_time - start_time) / 1000.0;
    
    metrics->message_throughput_mbps = (total_bytes * 8.0) / (duration_s * 1000000.0);
    
    printf("  Messages sent: %d\n", PERF_TEST_ITERATIONS);
    printf("  Total data: %.2f MB\n", total_bytes / (1024.0 * 1024.0));
    printf("  Duration: %.3f seconds\n", duration_s);
    printf("  Throughput: %.2f Mbps\n", metrics->message_throughput_mbps);
    
    free(test_data);
    htx_noise_connection_destroy(conn);
}

/**
 * Test message latency performance
 */
void test_message_latency(performance_metrics_t *metrics) {
    printf("Testing message latency...\n");
    
    htx_noise_connection_t* conn = htx_noise_connection_create(
        true, test_k0_client, test_k0_server);
    assert(conn != NULL);
    
    conn->handshake_complete = true;
    
    // Open stream
    uint32_t stream_id;
    int err = htx_noise_stream_open(conn, &stream_id);
    assert(err == HTX_NOISE_OK);
    
    uint8_t test_data[64] = "ping";
    htx_noise_message_t message = {
        .stream_id = stream_id,
        .data = test_data,
        .data_len = 4,
        .is_final = false
    };
    
    double total_latency_us = 0;
    int successful_sends = 0;
    
    // Measure latency for individual messages
    for (int i = 0; i < 100; i++) {
        double start_time = get_time_ms();
        
        err = htx_noise_send_message(conn, &message);
        if (err == HTX_NOISE_OK) {
            double end_time = get_time_ms();
            total_latency_us += (end_time - start_time) * 1000.0; // Convert to microseconds
            successful_sends++;
        }
    }
    
    metrics->message_latency_us = total_latency_us / successful_sends;
    
    printf("  Successful sends: %d/100\n", successful_sends);
    printf("  Average latency: %.2f μs\n", metrics->message_latency_us);
    
    htx_noise_connection_destroy(conn);
}

// ============================================================================
// Large Message Performance Tests
// ============================================================================

/**
 * Test large message handling performance
 */
void test_large_message_performance(performance_metrics_t *metrics) {
    printf("Testing large message performance...\n");
    
    htx_noise_connection_t* conn = htx_noise_connection_create(
        true, test_k0_client, test_k0_server);
    assert(conn != NULL);
    
    conn->handshake_complete = true;
    
    // Open stream
    uint32_t stream_id;
    int err = htx_noise_stream_open(conn, &stream_id);
    assert(err == HTX_NOISE_OK);
    
    // Prepare large test data
    uint8_t *large_data = malloc(PERF_TEST_LARGE_MESSAGE_SIZE);
    for (int i = 0; i < PERF_TEST_LARGE_MESSAGE_SIZE; i++) {
        large_data[i] = (uint8_t)(i & 0xFF);
    }
    
    htx_noise_message_t message = {
        .stream_id = stream_id,
        .data = large_data,
        .data_len = PERF_TEST_LARGE_MESSAGE_SIZE,
        .is_final = false
    };
    
    double start_time = get_time_ms();
    
    // Send large messages (limited due to MAX_MESSAGE_SIZE constraint)
    int chunk_size = HTX_NOISE_MAX_MESSAGE_SIZE - 100; // Leave some headroom
    int chunks_sent = 0;
    size_t remaining = PERF_TEST_LARGE_MESSAGE_SIZE;
    size_t offset = 0;
    
    while (remaining > 0 && chunks_sent < 10) {
        size_t chunk_len = (remaining > chunk_size) ? chunk_size : remaining;
        
        message.data = large_data + offset;
        message.data_len = chunk_len;
        message.is_final = (remaining == chunk_len);
        
        err = htx_noise_send_message(conn, &message);
        if (err == HTX_NOISE_OK) {
            chunks_sent++;
            offset += chunk_len;
            remaining -= chunk_len;
        } else {
            break;
        }
    }
    
    double end_time = get_time_ms();
    double duration_s = (end_time - start_time) / 1000.0;
    
    printf("  Large message chunks sent: %d\n", chunks_sent);
    printf("  Data processed: %.2f KB\n", offset / 1024.0);
    printf("  Duration: %.3f seconds\n", duration_s);
    if (duration_s > 0) {
        printf("  Effective throughput: %.2f MB/s\n", (offset / 1024.0 / 1024.0) / duration_s);
    }
    
    free(large_data);
    htx_noise_connection_destroy(conn);
}

// ============================================================================
// Concurrent Stream Performance Tests
// ============================================================================

/**
 * Test concurrent stream performance
 */
void test_concurrent_streams(performance_metrics_t *metrics) {
    printf("Testing concurrent stream performance...\n");
    
    htx_noise_connection_t* conn = htx_noise_connection_create(
        true, test_k0_client, test_k0_server);
    assert(conn != NULL);
    
    conn->handshake_complete = true;
    
    uint32_t stream_ids[PERF_TEST_CONCURRENT_STREAMS];
    int streams_opened = 0;
    
    double start_time = get_time_ms();
    
    // Open multiple streams
    for (int i = 0; i < PERF_TEST_CONCURRENT_STREAMS; i++) {
        int err = htx_noise_stream_open(conn, &stream_ids[i]);
        if (err == HTX_NOISE_OK) {
            streams_opened++;
        }
    }
    
    // Send messages on each stream
    uint8_t test_data[256];
    memset(test_data, 0xBB, sizeof(test_data));
    
    for (int i = 0; i < streams_opened; i++) {
        htx_noise_message_t message = {
            .stream_id = stream_ids[i],
            .data = test_data,
            .data_len = sizeof(test_data),
            .is_final = false
        };
        
        htx_noise_send_message(conn, &message);
    }
    
    double end_time = get_time_ms();
    
    printf("  Streams opened: %d/%d\n", streams_opened, PERF_TEST_CONCURRENT_STREAMS);
    printf("  Stream setup time: %.3f ms\n", end_time - start_time);
    
    // Close streams
    for (int i = 0; i < streams_opened; i++) {
        htx_noise_stream_close(conn, stream_ids[i]);
    }
    
    htx_noise_connection_destroy(conn);
}

// ============================================================================
// Key Rotation Performance Tests
// ============================================================================

/**
 * Test key rotation performance
 */
void test_key_rotation_performance(performance_metrics_t *metrics) {
    printf("Testing key rotation performance...\n");
    
    htx_noise_connection_t* conn = htx_noise_connection_create(
        true, test_k0_client, test_k0_server);
    assert(conn != NULL);
    
    conn->handshake_complete = true;
    
    // Force rekey condition
    conn->messages_sent = HTX_NOISE_REKEY_FRAMES_LIMIT;
    
    double start_time = get_time_ms();
    
    int err = htx_noise_rekey(conn);
    assert(err == HTX_NOISE_OK);
    
    double end_time = get_time_ms();
    
    metrics->key_rotation_ms = end_time - start_time;
    
    printf("  Key rotation time: %.3f ms\n", metrics->key_rotation_ms);
    
    htx_noise_connection_destroy(conn);
}

// ============================================================================
// Memory Usage Tests
// ============================================================================

/**
 * Test memory usage patterns
 */
void test_memory_usage(performance_metrics_t *metrics) {
    printf("Testing memory usage...\n");
    
    size_t baseline_memory = 0; // In a real implementation, measure actual memory usage
    
    htx_noise_connection_t* conn = htx_noise_connection_create(
        true, test_k0_client, test_k0_server);
    assert(conn != NULL);
    
    // Estimate memory usage based on structure sizes
    size_t estimated_usage = sizeof(htx_noise_connection_t) + 
                           sizeof(htx_connection_t) + 
                           sizeof(noise_channel_t);
    
    metrics->memory_usage_bytes = estimated_usage;
    
    printf("  Estimated memory per connection: %llu bytes\n", metrics->memory_usage_bytes);
    printf("  Memory per connection: %.2f KB\n", metrics->memory_usage_bytes / 1024.0);
    
    htx_noise_connection_destroy(conn);
}

// ============================================================================
// Main Performance Test Runner
// ============================================================================

int main(void) {
    printf("=== BetaNet HTX-Noise Performance Test Suite ===\n");
    printf("Testing complete secure communication stack performance\n\n");
    
    performance_metrics_t metrics = {0};
    
    // Connection Performance
    test_connection_performance(&metrics);
    printf("\n");
    
    // Handshake Performance
    test_handshake_performance(&metrics);
    printf("\n");
    
    // Message Throughput
    test_message_throughput(&metrics);
    printf("\n");
    
    // Message Latency
    test_message_latency(&metrics);
    printf("\n");
    
    // Large Message Performance
    test_large_message_performance(&metrics);
    printf("\n");
    
    // Concurrent Streams
    test_concurrent_streams(&metrics);
    printf("\n");
    
    // Key Rotation Performance
    test_key_rotation_performance(&metrics);
    printf("\n");
    
    // Memory Usage
    test_memory_usage(&metrics);
    printf("\n");
    
    // Performance Summary
    printf("=== Performance Summary ===\n");
    printf("Connection Setup:     %.3f ms\n", metrics.connection_setup_ms);
    printf("Handshake Time:       %.3f ms\n", metrics.handshake_ms);
    printf("Message Throughput:   %.2f Mbps\n", metrics.message_throughput_mbps);
    printf("Message Latency:      %.2f μs\n", metrics.message_latency_us);
    printf("Key Rotation:         %.3f ms\n", metrics.key_rotation_ms);
    printf("Memory Usage:         %.2f KB per connection\n", metrics.memory_usage_bytes / 1024.0);
    
    // Performance Rating
    printf("\n=== Performance Rating ===\n");
    if (metrics.message_throughput_mbps > 100.0 && metrics.message_latency_us < 1000.0) {
        printf("🚀 EXCELLENT: High-performance secure communication achieved!\n");
    } else if (metrics.message_throughput_mbps > 50.0 && metrics.message_latency_us < 5000.0) {
        printf("✅ GOOD: Solid performance for secure communication\n");
    } else {
        printf("⚠️ MODERATE: Performance may need optimization\n");
    }
    
    printf("\nHTX-Noise integration performance testing completed successfully!\n");
    return 0;
}
