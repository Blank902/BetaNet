// BetaNet Path Selection Optimization Implementation
// Specification: BetaNet §4.3
#include "../../include/betanet/path_optimization.h"
#include "../../include/betanet/secure_log.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

// Internal helper functions
static uint64_t get_timestamp_ms(void) {
    return (uint64_t)time(NULL) * 1000;
}

path_optimization_session_t* path_optimizer_create_session(path_selection_strategy_t strategy) {
    path_optimization_session_t* session = calloc(1, sizeof(path_optimization_session_t));
    if (!session) return NULL;
    
    session->session_id = ((uint64_t)rand() << 32) | rand();
    session->strategy = strategy;
    session->path_count = 0;
    session->selected_path_idx = 0;
    session->is_optimized = false;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_PATH, "Path Optimizer: Created session %016llX with strategy %d\n", 
           (unsigned long long)session->session_id, strategy);
    
    return session;
}

void path_optimizer_destroy_session(path_optimization_session_t* session) {
    if (!session) return;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_PATH, "Path Optimizer: Destroying session %016llX\n", 
           (unsigned long long)session->session_id);
    free(session);
}

int path_optimizer_add_path(path_optimization_session_t* session, 
                           const path_quality_metrics_t* metrics) {
    if (!session || !metrics || session->path_count >= 16) {
        return -1;
    }
    
    session->paths[session->path_count] = *metrics;
    session->path_count++;
    session->is_optimized = false; // Need to re-optimize
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_PATH, "Path Optimizer: Added path %d - Latency:%ums BW:%uMbps Loss:%uppm\n",
           session->path_count - 1, metrics->latency_ms, 
           metrics->bandwidth_mbps, metrics->packet_loss_ppm);
    
    return session->path_count - 1;
}

int path_optimizer_measure_path_quality(path_optimization_session_t* session,
                                       uint8_t path_idx,
                                       path_quality_metrics_t* metrics) {
    if (!session || !metrics || path_idx >= session->path_count) {
        return -1;
    }
    
    // In a real implementation, this would:
    // 1. Send probe packets along the path
    // 2. Measure actual RTT, bandwidth, loss
    // 3. Update the stored metrics
    
    // For now, simulate with some measurement variation
    path_quality_metrics_t* stored = &session->paths[path_idx];
    
    metrics->latency_ms = stored->latency_ms + (rand() % 20) - 10; // ±10ms variation
    metrics->bandwidth_mbps = stored->bandwidth_mbps;
    metrics->packet_loss_ppm = stored->packet_loss_ppm + (rand() % 100);
    metrics->jitter_ms = stored->jitter_ms + (rand() % 5);
    metrics->hop_count = stored->hop_count;
    metrics->reliability_score = stored->reliability_score;
    
    // Update stored metrics with measured values
    session->paths[path_idx] = *metrics;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_PATH, "Path Optimizer: Measured path %d - RTT:%ums Jitter:%ums Loss:%uppm\n",
           path_idx, metrics->latency_ms, metrics->jitter_ms, metrics->packet_loss_ppm);
    
    return 0;
}

float path_optimizer_calculate_path_score(const path_quality_metrics_t* metrics,
                                         path_selection_strategy_t strategy) {
    if (!metrics) return 0.0f;
    
    float score = 0.0f;
    
    switch (strategy) {
        case PATH_STRATEGY_FASTEST:
            // Lower latency = higher score
            score = 1000.0f / (float)(metrics->latency_ms + 1);
            if (metrics->packet_loss_ppm > 1000) score *= 0.5f; // Penalize high loss
            break;
            
        case PATH_STRATEGY_MOST_RELIABLE:
            // Higher reliability, lower loss = higher score
            score = (float)metrics->reliability_score;
            score *= (1000000.0f - (float)metrics->packet_loss_ppm) / 1000000.0f;
            break;
            
        case PATH_STRATEGY_HIGHEST_BW:
            // Higher bandwidth = higher score
            score = (float)metrics->bandwidth_mbps;
            if (metrics->latency_ms > 200) score *= 0.7f; // Penalize high latency
            break;
            
        case PATH_STRATEGY_BALANCED:
            // Balanced score considering all factors
            score = ((float)metrics->reliability_score * 0.3f) +
                   (1000.0f / (float)(metrics->latency_ms + 1) * 0.3f) +
                   ((float)metrics->bandwidth_mbps / 100.0f * 0.2f) +
                   ((1000000.0f - (float)metrics->packet_loss_ppm) / 10000.0f * 0.2f);
            break;
            
        case PATH_STRATEGY_GEOGRAPHIC:
            // Prefer paths with more hops for geographic diversity
            score = (float)metrics->hop_count * 10.0f;
            if (metrics->reliability_score < 70) score *= 0.5f; // But still reliable
            break;
            
        default:
            score = 50.0f; // Default neutral score
            break;
    }
    
    return score;
}

int path_optimizer_select_optimal_path(path_optimization_session_t* session) {
    if (!session || session->path_count == 0) {
        return -1;
    }
    
    float best_score = -1.0f;
    uint8_t best_path = 0;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_PATH, "Path Optimizer: Evaluating %u paths with strategy %d\n", 
           session->path_count, session->strategy);
    
    for (uint32_t i = 0; i < session->path_count; i++) {
        float score = path_optimizer_calculate_path_score(&session->paths[i], session->strategy);
        
        BETANET_LOG_INFO(BETANET_LOG_TAG_PATH, "Path Optimizer: Path %u score: %.2f\n", i, score);
        
        if (score > best_score) {
            best_score = score;
            best_path = i;
        }
    }
    
    session->selected_path_idx = best_path;
    session->is_optimized = true;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_PATH, "Path Optimizer: Selected path %u with score %.2f\n", best_path, best_score);
    
    return best_path;
}

int path_optimizer_get_selected_path(path_optimization_session_t* session) {
    if (!session || !session->is_optimized) {
        return -1;
    }
    
    return session->selected_path_idx;
}

bool path_optimizer_needs_reselection(path_optimization_session_t* session,
                                     uint32_t threshold_change_percent) {
    if (!session || !session->is_optimized) {
        return true;
    }
    
    // Re-measure current path and see if performance degraded
    path_quality_metrics_t current_metrics;
    if (path_optimizer_measure_path_quality(session, session->selected_path_idx, &current_metrics) != 0) {
        return true; // Error measuring, should reselect
    }
    
    float current_score = path_optimizer_calculate_path_score(&current_metrics, session->strategy);
    
    // Check if any other path now has significantly better score
    for (uint32_t i = 0; i < session->path_count; i++) {
        if (i == session->selected_path_idx) continue;
        
        float other_score = path_optimizer_calculate_path_score(&session->paths[i], session->strategy);
        
        // If another path is significantly better, recommend reselection
        float improvement = ((other_score - current_score) / current_score) * 100.0f;
        if (improvement > (float)threshold_change_percent) {
            BETANET_LOG_INFO(BETANET_LOG_TAG_PATH, "Path Optimizer: Path %u shows %.1f%% improvement, reselection recommended\n", 
                   i, improvement);
            return true;
        }
    }
    
    return false;
}
