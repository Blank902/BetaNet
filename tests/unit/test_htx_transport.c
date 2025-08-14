/**
 * @file test_htx_transport.c
 * @brief HTX Transport Protocol Tests
 * 
 * Tests for HTX Transport Protocol with SCION integration,
 * origin mirroring, and automatic failover capabilities.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "../../include/betanet/htx_transport.h"
#include "../../include/betanet/scion.h"

// Test configuration
#define TEST_ORIGIN_COUNT 3
#define TEST_PATH_COUNT 2

/**
 * @brief Test HTX transport session creation and destruction
 */
static void test_transport_session_lifecycle(void) {
    printf("Testing HTX transport session lifecycle...\n");
    
    // Create session with default config
    htx_transport_session_t *session = htx_transport_create_session(NULL);
    assert(session != NULL && "Failed to create transport session");
    assert(session->session_id != 0 && "Invalid session ID");
    assert(session->state == HTX_TRANSPORT_DISCONNECTED && "Invalid initial state");
    assert(session->origin_count == 0 && "Origins should be empty initially");
    assert(session->path_count == 0 && "Paths should be empty initially");
    
    // Verify flow control defaults
    assert(session->send_window == 65536 && "Invalid default send window");
    assert(session->recv_window == 65536 && "Invalid default receive window");
    assert(session->congestion_window == 4096 && "Invalid default congestion window");
    
    // Destroy session
    htx_transport_destroy_session(session);
    
    // Test NULL safety
    htx_transport_destroy_session(NULL);
    
    printf("✓ HTX transport session lifecycle test passed\n");
}

/**
 * @brief Test origin mirror management
 */
static void test_origin_management(void) {
    printf("Testing HTX origin management...\n");
    
    htx_transport_session_t *session = htx_transport_create_session(NULL);
    assert(session != NULL);
    
    // Test adding IPv4 origins
    uint8_t ipv4_addr1[] = {192, 168, 1, 10};
    uint8_t ipv4_addr2[] = {10, 0, 0, 1};
    uint8_t ipv4_addr3[] = {172, 16, 0, 1};
    
    htx_transport_result_t result;
    
    result = htx_transport_add_origin(session, 0x1110000000000001ULL, ipv4_addr1, 4, 8080);
    assert(result == HTX_TRANSPORT_SUCCESS && "Failed to add origin 1");
    
    result = htx_transport_add_origin(session, 0x1110000000000002ULL, ipv4_addr2, 4, 8443);
    assert(result == HTX_TRANSPORT_SUCCESS && "Failed to add origin 2");
    
    result = htx_transport_add_origin(session, 0x1110000000000003ULL, ipv4_addr3, 4, 9090);
    assert(result == HTX_TRANSPORT_SUCCESS && "Failed to add origin 3");
    
    assert(session->origin_count == 3 && "Invalid origin count");
    
    // Verify origin data
    assert(session->origins[0].ia == 0x1110000000000001ULL && "Origin 1 IA mismatch");
    assert(session->origins[0].port == 8080 && "Origin 1 port mismatch");
    assert(session->origins[0].addr_len == 4 && "Origin 1 address length mismatch");
    assert(session->origins[0].is_active == true && "Origin 1 should be active");
    assert(session->origins[0].reliability_score == 1.0f && "Origin 1 initial reliability");
    
    // Test parameter validation
    result = htx_transport_add_origin(NULL, 0, ipv4_addr1, 4, 8080);
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject NULL session");
    
    result = htx_transport_add_origin(session, 0, NULL, 4, 8080);
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject NULL address");
    
    result = htx_transport_add_origin(session, 0, ipv4_addr1, 3, 8080);
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject invalid address length");
    
    htx_transport_destroy_session(session);
    
    printf("✓ HTX origin management test passed\n");
}

/**
 * @brief Test SCION path management
 */
static void test_path_management(void) {
    printf("Testing HTX SCION path management...\n");
    
    htx_transport_session_t *session = htx_transport_create_session(NULL);
    assert(session != NULL);
    
    // Create test SCION packets as path templates
    scion_packet_t path1, path2;
    
    // Address arrays for paths
    uint8_t src_addr1[] = {10, 0, 0, 1};
    uint8_t dst_addr1[] = {10, 0, 0, 2};
    uint8_t src_addr2[] = {172, 16, 0, 1};
    uint8_t dst_addr2[] = {172, 16, 0, 2};
    
    // Initialize path 1
    bool scion_result = scion_packet_init(&path1);
    assert(scion_result && "Failed to initialize SCION packet 1");
    
    scion_result = scion_create_packet(
        0x1110000000000001ULL,  // Source IA
        0x1110000000000002ULL,  // Destination IA
        src_addr1, sizeof(src_addr1),
        dst_addr1, sizeof(dst_addr1),
        NULL, 0,  // No payload for path template
        &path1
    );
    assert(scion_result && "Failed to create SCION packet 1");
    
    // Initialize path 2  
    scion_result = scion_packet_init(&path2);
    assert(scion_result && "Failed to initialize SCION packet 2");
    
    scion_result = scion_create_packet(
        0x1110000000000001ULL,  // Source IA
        0x1110000000000003ULL,  // Destination IA
        src_addr2, sizeof(src_addr2),
        dst_addr2, sizeof(dst_addr2),
        NULL, 0,  // No payload for path template
        &path2
    );
    assert(scion_result && "Failed to create SCION packet 2");
    
    // Add paths to transport session
    htx_transport_result_t result;
    
    result = htx_transport_add_path(session, &path1);
    assert(result == HTX_TRANSPORT_SUCCESS && "Failed to add path 1");
    
    result = htx_transport_add_path(session, &path2);
    assert(result == HTX_TRANSPORT_SUCCESS && "Failed to add path 2");
    
    assert(session->path_count == 2 && "Invalid path count");
    
    // Verify path data
    assert(session->paths[0].path_template != NULL && "Path 1 template should not be NULL");
    assert(session->paths[0].is_active == true && "Path 1 should be active");
    assert(session->paths[0].latency_ms == 50 && "Path 1 default latency");
    assert(session->paths[0].loss_rate == 0.0f && "Path 1 initial loss rate");
    
    // Test parameter validation
    result = htx_transport_add_path(NULL, &path1);
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject NULL session");
    
    result = htx_transport_add_path(session, NULL);
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject NULL path");
    
    // Cleanup
    scion_packet_cleanup(&path1);
    scion_packet_cleanup(&path2);
    htx_transport_destroy_session(session);
    
    printf("✓ HTX SCION path management test passed\n");
}

/**
 * @brief Test origin calibration and selection
 */
static void test_origin_calibration(void) {
    printf("Testing HTX origin calibration and selection...\n");
    
    htx_transport_session_t *session = htx_transport_create_session(NULL);
    assert(session != NULL);
    
    // Add test origins
    uint8_t addr1[] = {192, 168, 1, 10};
    uint8_t addr2[] = {10, 0, 0, 1};
    uint8_t addr3[] = {172, 16, 0, 1};
    
    htx_transport_add_origin(session, 0x1110000000000001ULL, addr1, 4, 8080);
    htx_transport_add_origin(session, 0x1110000000000002ULL, addr2, 4, 8443);
    htx_transport_add_origin(session, 0x1110000000000003ULL, addr3, 4, 9090);
    
    // Test calibration
    htx_transport_result_t result = htx_transport_calibrate_origins(session);
    assert(result == HTX_TRANSPORT_SUCCESS && "Origin calibration failed");
    
    // Test origin selection
    int best_origin = htx_transport_select_best_origin(session);
    assert(best_origin >= 0 && best_origin < 3 && "Invalid best origin index");
    
    // Test failover
    result = htx_transport_failover_origin(session);
    assert(result == HTX_TRANSPORT_SUCCESS && "Origin failover failed");
    
    // Test metric updates (after calibration)
    // Reset failure counts first for predictable testing
    session->origins[0].failure_count = 0;
    session->origins[1].failure_count = 0;
    
    htx_transport_update_origin_metrics(session, 0, true, 50);
    htx_transport_update_origin_metrics(session, 1, false, 0);
    
    assert(session->origins[0].rtt_ms == 50 && "RTT update failed");
    assert(session->origins[0].failure_count == 0 && "Success should reset failure count");
    assert(session->origins[1].failure_count == 1 && "Failure count should increment after manual update");
    
    htx_transport_destroy_session(session);
    
    printf("✓ HTX origin calibration test passed\n");
}

/**
 * @brief Test complete connection establishment
 */
static void test_connection_establishment(void) {
    printf("Testing HTX connection establishment...\n");
    
    htx_transport_session_t *session = htx_transport_create_session(NULL);
    assert(session != NULL);
    
    // Test connection without origins/paths
    htx_transport_result_t result = htx_transport_connect(session, NULL, 0);
    assert(result == HTX_TRANSPORT_ERR_NO_ORIGINS && "Should fail without origins");
    
    // Add origins
    uint8_t addr1[] = {192, 168, 1, 10};
    htx_transport_add_origin(session, 0x1110000000000001ULL, addr1, 4, 8080);
    
    result = htx_transport_connect(session, NULL, 0);
    assert(result == HTX_TRANSPORT_ERR_NO_PATHS && "Should fail without paths");
    
    // Add SCION path
    scion_packet_t path;
    uint8_t src_addr[] = {10, 0, 0, 1};
    uint8_t dst_addr[] = {10, 0, 0, 2};
    
    bool path_result = scion_packet_init(&path);
    assert(path_result && "Failed to initialize SCION packet");
    
    path_result = scion_create_packet(
        0x1110000000000001ULL,  // Source IA
        0x1110000000000002ULL,  // Destination IA
        src_addr, sizeof(src_addr),
        dst_addr, sizeof(dst_addr),
        NULL, 0,  // No payload for path template
        &path
    );
    assert(path_result && "Failed to create SCION packet");
    
    htx_transport_add_path(session, &path);
    
    // Test successful connection
    result = htx_transport_connect(session, NULL, 0);
    assert(result == HTX_TRANSPORT_SUCCESS && "Connection should succeed");
    assert(session->state == HTX_TRANSPORT_CONNECTED && "Should be connected");
    
    // Cleanup
    scion_packet_cleanup(&path);
    htx_transport_destroy_session(session);
    
    printf("✓ HTX connection establishment test passed\n");
}

/**
 * @brief Test data transmission
 */
static void test_data_transmission(void) {
    printf("Testing HTX data transmission...\n");
    
    // Set up connected session
    htx_transport_session_t *session = htx_transport_create_session(NULL);
    assert(session != NULL);
    
    uint8_t addr[] = {192, 168, 1, 10};
    htx_transport_add_origin(session, 0x1110000000000001ULL, addr, 4, 8080);
    
    scion_packet_t path;
    
    bool path_result = scion_packet_init(&path);
    assert(path_result && "Failed to initialize SCION packet");
    
    path_result = scion_create_packet(
        0x1110000000000001ULL,  // Source IA
        0x1110000000000002ULL,  // Destination IA
        addr, sizeof(addr),
        addr, sizeof(addr),     // Same addresses for simplicity
        NULL, 0,  // No payload for path template
        &path
    );
    assert(path_result && "Failed to create SCION packet");
    
    htx_transport_add_path(session, &path);
    htx_transport_connect(session, NULL, 0);
    
    // Test data sending
    const char *test_data = "Hello, BetaNet HTX Transport!";
    size_t data_len = strlen(test_data);
    
    htx_transport_result_t result = htx_transport_send(session, 
                                                       (const uint8_t*)test_data, 
                                                       data_len, 
                                                       1001);
    assert(result == HTX_TRANSPORT_SUCCESS && "Data send should succeed");
    assert(session->bytes_sent == data_len && "Bytes sent counter should update");
    assert(session->packets_sent == 1 && "Packets sent counter should update");
    
    // Test data receiving
    uint8_t recv_buffer[1024];
    size_t received_len;
    uint32_t stream_id;
    
    result = htx_transport_receive(session, recv_buffer, sizeof(recv_buffer), 
                                   &received_len, &stream_id);
    assert(result == HTX_TRANSPORT_SUCCESS && "Data receive should succeed");
    
    // Test parameter validation
    result = htx_transport_send(NULL, (const uint8_t*)test_data, data_len, 1001);
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject NULL session");
    
    result = htx_transport_send(session, NULL, data_len, 1001);
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject NULL data");
    
    // Cleanup
    scion_packet_cleanup(&path);
    htx_transport_destroy_session(session);
    
    printf("✓ HTX data transmission test passed\n");
}

/**
 * @brief Test statistics gathering
 */
static void test_statistics(void) {
    printf("Testing HTX transport statistics...\n");
    
    htx_transport_session_t *session = htx_transport_create_session(NULL);
    assert(session != NULL);
    
    // Get statistics
    char stats_buffer[2048];
    htx_transport_result_t result = htx_transport_get_stats(session, 
                                                            stats_buffer, 
                                                            sizeof(stats_buffer));
    assert(result == HTX_TRANSPORT_SUCCESS && "Statistics gathering should succeed");
    
    // Verify JSON format (basic check)
    assert(strstr(stats_buffer, "session_id") != NULL && "Should contain session_id");
    assert(strstr(stats_buffer, "state") != NULL && "Should contain state");
    assert(strstr(stats_buffer, "uptime_ms") != NULL && "Should contain uptime");
    
    printf("Stats: %s\n", stats_buffer);
    
    // Test parameter validation
    result = htx_transport_get_stats(NULL, stats_buffer, sizeof(stats_buffer));
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject NULL session");
    
    result = htx_transport_get_stats(session, NULL, sizeof(stats_buffer));
    assert(result == HTX_TRANSPORT_ERR_INVALID_PARAM && "Should reject NULL buffer");
    
    htx_transport_destroy_session(session);
    
    printf("✓ HTX transport statistics test passed\n");
}

/**
 * @brief Test error handling and edge cases
 */
static void test_error_handling(void) {
    printf("Testing HTX transport error handling...\n");
    
    // Test error message strings
    assert(strcmp(htx_transport_result_to_string(HTX_TRANSPORT_SUCCESS), "Success") == 0);
    assert(strcmp(htx_transport_result_to_string(HTX_TRANSPORT_ERR_INVALID_PARAM), "Invalid parameter") == 0);
    assert(strcmp(htx_transport_result_to_string(HTX_TRANSPORT_ERR_NO_MEMORY), "Out of memory") == 0);
    
    // Test NULL parameter handling throughout API
    assert(htx_transport_create_session(NULL) != NULL && "Should accept NULL config");
    
    htx_transport_destroy_session(NULL); // Should not crash
    
    assert(htx_transport_add_origin(NULL, 0, NULL, 0, 0) == HTX_TRANSPORT_ERR_INVALID_PARAM);
    assert(htx_transport_add_path(NULL, NULL) == HTX_TRANSPORT_ERR_INVALID_PARAM);
    assert(htx_transport_connect(NULL, NULL, 0) == HTX_TRANSPORT_ERR_INVALID_PARAM);
    assert(htx_transport_send(NULL, NULL, 0, 0) == HTX_TRANSPORT_ERR_INVALID_PARAM);
    assert(htx_transport_receive(NULL, NULL, 0, NULL, NULL) == HTX_TRANSPORT_ERR_INVALID_PARAM);
    
    printf("✓ HTX transport error handling test passed\n");
}

/**
 * @brief Main test function
 */
int main(void) {
    printf("Starting BetaNet HTX Transport Tests\n");
    printf("==================================\n");
    
    // Initialize random seed for testing with fixed seed for reproducibility
    srand(12345);
    
    // Run all tests
    test_transport_session_lifecycle();
    test_origin_management();
    test_path_management();
    test_origin_calibration();
    test_connection_establishment();
    test_data_transmission();
    test_statistics();
    test_error_handling();
    
    printf("\n🎉 All HTX Transport tests passed!\n");
    printf("BetaNet HTX Transport Protocol implementation is working correctly.\n");
    
    return 0;
}
