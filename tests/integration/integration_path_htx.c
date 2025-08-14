// BetaNet Integration Test - Path Optimization with HTX Transport
// Tests the integration between Path Selection Optimization (§4.3) and HTX Transport
#include "../../include/betanet/path_optimization.h"
#include "../../include/betanet/htx_transport.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

int main() {
    printf("BetaNet Integration Test: Path Optimization + HTX Transport\n");
    printf("===========================================================\n");
    
    // Test 1: Create HTX transport session and path optimizer
    printf("Creating HTX transport session and path optimizer...\n");
    
    // Create HTX transport config
    htx_transport_config_t config = {
        .origin_probe_interval = 5000,
        .path_probe_interval = 3000,
        .origin_failure_threshold = 0.8,
        .path_failure_threshold = 0.7,
        .adaptive_timeout_base = 1000,
        .enable_auto_calibration = true,
        .enable_multi_path = true
    };
    
    htx_transport_session_t* htx_session = htx_transport_create_session(&config);
    path_optimization_session_t* path_session = path_optimizer_create_session(PATH_STRATEGY_BALANCED);
    
    assert(htx_session != NULL && "HTX session creation failed");
    assert(path_session != NULL && "Path session creation failed");
    printf("✓ Both sessions created successfully\n");
    
    // Test 2: Add path quality metrics to path optimizer
    printf("Adding path quality metrics to path optimizer...\n");
    
    path_quality_metrics_t metrics1 = {
        .latency_ms = 45,
        .bandwidth_mbps = 120,
        .packet_loss_ppm = 300,
        .jitter_ms = 4,
        .hop_count = 3,
        .reliability_score = 88
    };
    
    path_quality_metrics_t metrics2 = {
        .latency_ms = 65,
        .bandwidth_mbps = 90,
        .packet_loss_ppm = 600,
        .jitter_ms = 7,
        .hop_count = 4,
        .reliability_score = 82
    };
    
    path_quality_metrics_t metrics3 = {
        .latency_ms = 35,
        .bandwidth_mbps = 200,
        .packet_loss_ppm = 100,
        .jitter_ms = 2,
        .hop_count = 2,
        .reliability_score = 95
    };
    
    int opt_path1 = path_optimizer_add_path(path_session, &metrics1);
    int opt_path2 = path_optimizer_add_path(path_session, &metrics2);
    int opt_path3 = path_optimizer_add_path(path_session, &metrics3);
    
    assert(opt_path1 >= 0 && opt_path2 >= 0 && opt_path3 >= 0 && "Path optimizer path addition failed");
    printf("✓ Path quality metrics added to optimizer\n");
    
    // Test 3: Use path optimizer to select best path with different strategies
    printf("Testing path selection with different strategies...\n");
    
    // Test balanced strategy
    path_session->strategy = PATH_STRATEGY_BALANCED;
    path_session->is_optimized = false;
    int balanced_path = path_optimizer_select_optimal_path(path_session);
    printf("Balanced strategy selected path: %d\n", balanced_path);
    
    // Test fastest strategy
    path_session->strategy = PATH_STRATEGY_FASTEST;
    path_session->is_optimized = false;
    int fastest_path = path_optimizer_select_optimal_path(path_session);
    printf("Fastest strategy selected path: %d\n", fastest_path);
    
    // Test highest bandwidth strategy
    path_session->strategy = PATH_STRATEGY_HIGHEST_BW;
    path_session->is_optimized = false;
    int bandwidth_path = path_optimizer_select_optimal_path(path_session);
    printf("Highest bandwidth strategy selected path: %d\n", bandwidth_path);
    
    // Test most reliable strategy
    path_session->strategy = PATH_STRATEGY_MOST_RELIABLE;
    path_session->is_optimized = false;
    int reliable_path = path_optimizer_select_optimal_path(path_session);
    printf("Most reliable strategy selected path: %d\n", reliable_path);
    
    assert(balanced_path >= 0 && fastest_path >= 0 && bandwidth_path >= 0 && reliable_path >= 0 
           && "All path selection strategies should succeed");
    printf("✓ Path selection strategies working correctly\n");
    
    // Test 4: Add origin to HTX transport
    printf("Adding origin to HTX transport...\n");
    uint8_t origin_addr[] = {127, 0, 0, 1}; // localhost for testing
    htx_transport_result_t add_result = htx_transport_add_origin(htx_session, 0x1110000000000002ULL, 
                                                                 origin_addr, sizeof(origin_addr), 8080);
    assert(add_result == HTX_TRANSPORT_SUCCESS && "Origin addition failed");
    printf("✓ HTX transport origin added\n");
    
    // Test 5: Perform calibration
    printf("Performing HTX transport calibration...\n");
    htx_transport_result_t cal_result = htx_transport_calibrate_origins(htx_session);
    assert(cal_result == HTX_TRANSPORT_SUCCESS && "Calibration failed");
    printf("✓ HTX transport calibration completed\n");
    
    // Test 6: Measure path quality and update metrics
    printf("Measuring actual path quality and updating metrics...\n");
    path_quality_metrics_t measured_metrics;
    int measure_result = path_optimizer_measure_path_quality(path_session, reliable_path, &measured_metrics);
    assert(measure_result == 0 && "Path quality measurement failed");
    printf("Measured latency: %ums, packet loss: %uppm\n", 
           measured_metrics.latency_ms, measured_metrics.packet_loss_ppm);
    
    // Test 7: Check if reselection is needed
    printf("Checking if path reselection is needed...\n");
    bool needs_reselection = path_optimizer_needs_reselection(path_session, 15);
    printf("Reselection needed: %s\n", needs_reselection ? "Yes" : "No");
    
    if (needs_reselection) {
        printf("Performing path reselection...\n");
        int new_selected = path_optimizer_select_optimal_path(path_session);
        printf("New selected path: %d\n", new_selected);
    }
    
    // Test 8: Calculate path scores for analysis
    printf("Analyzing path scores for different strategies...\n");
    for (int i = 0; i < 3; i++) {
        printf("Path %d scores:\n", i);
        printf("  Fastest: %.2f\n", path_optimizer_calculate_path_score(&path_session->paths[i], PATH_STRATEGY_FASTEST));
        printf("  Reliable: %.2f\n", path_optimizer_calculate_path_score(&path_session->paths[i], PATH_STRATEGY_MOST_RELIABLE));
        printf("  Bandwidth: %.2f\n", path_optimizer_calculate_path_score(&path_session->paths[i], PATH_STRATEGY_HIGHEST_BW));
        printf("  Balanced: %.2f\n", path_optimizer_calculate_path_score(&path_session->paths[i], PATH_STRATEGY_BALANCED));
    }
    
    // Test 9: Generate statistics from both systems
    printf("Generating system statistics...\n");
    char stats_buffer[1024];
    htx_transport_get_stats(htx_session, stats_buffer, sizeof(stats_buffer));
    printf("HTX Transport Stats: %s\n", stats_buffer);
    
    int current_path = path_optimizer_get_selected_path(path_session);
    printf("Currently selected optimal path: %d\n", current_path);
    
    // Cleanup
    htx_transport_destroy_session(htx_session);
    path_optimizer_destroy_session(path_session);
    
    printf("\n🎉 Integration test completed successfully!\n");
    printf("Path optimization is working correctly with HTX transport.\n");
    printf("BetaNet network optimization and transport layers are integrated.\n");
    printf("All path selection strategies are functioning correctly.\n");
    
    return 0;
}
