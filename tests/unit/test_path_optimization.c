// BetaNet Path Selection Optimization Unit Test
// Specification: BetaNet §4.3
#include "../../include/betanet/path_optimization.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

int main() {
    srand(42); // Fixed seed for reproducible tests
    
    printf("Starting BetaNet Path Optimization Tests\n");
    printf("========================================\n");
    
    // Test 1: Session creation and destruction
    printf("Testing path optimization session lifecycle...\n");
    path_optimization_session_t* session = path_optimizer_create_session(PATH_STRATEGY_BALANCED);
    assert(session != NULL && "Session creation failed");
    assert(session->strategy == PATH_STRATEGY_BALANCED && "Strategy not set correctly");
    assert(session->path_count == 0 && "Initial path count should be 0");
    printf("✓ Path optimization session lifecycle test passed\n");
    
    // Test 2: Adding paths
    printf("Testing path addition...\n");
    
    path_quality_metrics_t path1 = {
        .latency_ms = 50,
        .bandwidth_mbps = 100,
        .packet_loss_ppm = 500,
        .jitter_ms = 5,
        .hop_count = 3,
        .reliability_score = 85
    };
    
    path_quality_metrics_t path2 = {
        .latency_ms = 80,
        .bandwidth_mbps = 150,
        .packet_loss_ppm = 200,
        .jitter_ms = 3,
        .hop_count = 4,
        .reliability_score = 92
    };
    
    path_quality_metrics_t path3 = {
        .latency_ms = 30,
        .bandwidth_mbps = 80,
        .packet_loss_ppm = 1000,
        .jitter_ms = 8,
        .hop_count = 2,
        .reliability_score = 75
    };
    
    int idx1 = path_optimizer_add_path(session, &path1);
    int idx2 = path_optimizer_add_path(session, &path2);
    int idx3 = path_optimizer_add_path(session, &path3);
    
    assert(idx1 == 0 && "First path index should be 0");
    assert(idx2 == 1 && "Second path index should be 1");
    assert(idx3 == 2 && "Third path index should be 2");
    assert(session->path_count == 3 && "Path count should be 3");
    printf("✓ Path addition test passed\n");
    
    // Test 3: Path selection with different strategies
    printf("Testing path selection strategies...\n");
    
    // Test balanced strategy
    int selected = path_optimizer_select_optimal_path(session);
    assert(selected >= 0 && selected < 3 && "Selected path index out of range");
    printf("Balanced strategy selected path: %d\n", selected);
    
    // Test fastest strategy
    session->strategy = PATH_STRATEGY_FASTEST;
    session->is_optimized = false;
    selected = path_optimizer_select_optimal_path(session);
    printf("Fastest strategy selected path: %d\n", selected);
    // Path 3 has lowest latency (30ms), should be selected
    assert(selected == 2 && "Fastest strategy should select path with lowest latency");
    
    // Test most reliable strategy
    session->strategy = PATH_STRATEGY_MOST_RELIABLE;
    session->is_optimized = false;
    selected = path_optimizer_select_optimal_path(session);
    printf("Most reliable strategy selected path: %d\n", selected);
    // Path 2 has highest reliability (92) and low packet loss
    assert(selected == 1 && "Most reliable strategy should select most reliable path");
    
    // Test highest bandwidth strategy
    session->strategy = PATH_STRATEGY_HIGHEST_BW;
    session->is_optimized = false;
    selected = path_optimizer_select_optimal_path(session);
    printf("Highest bandwidth strategy selected path: %d\n", selected);
    // Path 2 has highest bandwidth (150 Mbps)
    assert(selected == 1 && "Highest bandwidth strategy should select path with most bandwidth");
    
    printf("✓ Path selection strategies test passed\n");
    
    // Test 4: Path quality measurement
    printf("Testing path quality measurement...\n");
    path_quality_metrics_t measured;
    int result = path_optimizer_measure_path_quality(session, 0, &measured);
    assert(result == 0 && "Path measurement should succeed");
    printf("✓ Path quality measurement test passed\n");
    
    // Test 5: Score calculation
    printf("Testing path score calculation...\n");
    float score1 = path_optimizer_calculate_path_score(&path1, PATH_STRATEGY_FASTEST);
    float score2 = path_optimizer_calculate_path_score(&path2, PATH_STRATEGY_FASTEST);
    float score3 = path_optimizer_calculate_path_score(&path3, PATH_STRATEGY_FASTEST);
    
    printf("Path scores (fastest): %.2f, %.2f, %.2f\n", score1, score2, score3);
    // Path 3 should have highest score for fastest strategy (lowest latency)
    assert(score3 > score1 && score3 > score2 && "Path 3 should have highest score for fastest strategy");
    printf("✓ Path score calculation test passed\n");
    
    // Test 6: Reselection necessity
    printf("Testing reselection necessity...\n");
    session->strategy = PATH_STRATEGY_BALANCED;
    session->is_optimized = false;
    path_optimizer_select_optimal_path(session);
    
    bool needs_reselection = path_optimizer_needs_reselection(session, 20);
    printf("Reselection needed: %s\n", needs_reselection ? "Yes" : "No");
    printf("✓ Reselection necessity test passed\n");
    
    // Test 7: Error handling
    printf("Testing error handling...\n");
    assert(path_optimizer_add_path(NULL, &path1) == -1 && "NULL session should fail");
    assert(path_optimizer_add_path(session, NULL) == -1 && "NULL metrics should fail");
    assert(path_optimizer_select_optimal_path(NULL) == -1 && "NULL session should fail");
    assert(path_optimizer_get_selected_path(NULL) == -1 && "NULL session should fail");
    printf("✓ Error handling test passed\n");
    
    // Cleanup
    path_optimizer_destroy_session(session);
    
    printf("\n🎉 All Path Optimization tests passed!\n");
    printf("BetaNet Path Selection Optimization implementation is working correctly.\n");
    
    return 0;
}
