// BetaNet Path Selection Optimization API
// Specification: BetaNet §4.3
#ifndef BETANET_PATH_OPTIMIZATION_H
#define BETANET_PATH_OPTIMIZATION_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Path quality metrics
typedef struct {
    uint32_t latency_ms;           // Round-trip time
    uint32_t bandwidth_mbps;       // Available bandwidth
    uint32_t packet_loss_ppm;      // Packet loss in parts per million
    uint32_t jitter_ms;            // Jitter variance
    uint8_t  hop_count;            // Number of hops
    uint8_t  reliability_score;    // 0-100 reliability rating
} path_quality_metrics_t;

// Path selection strategy
typedef enum {
    PATH_STRATEGY_FASTEST = 0,     // Lowest latency
    PATH_STRATEGY_MOST_RELIABLE,   // Highest reliability
    PATH_STRATEGY_HIGHEST_BW,      // Maximum bandwidth
    PATH_STRATEGY_BALANCED,        // Balanced performance
    PATH_STRATEGY_GEOGRAPHIC       // Geographic diversity
} path_selection_strategy_t;

// Path optimization session
typedef struct {
    uint64_t session_id;
    path_selection_strategy_t strategy;
    uint32_t path_count;
    path_quality_metrics_t paths[16];
    uint8_t selected_path_idx;
    bool is_optimized;
    void* user_data;
} path_optimization_session_t;

// API Functions
path_optimization_session_t* path_optimizer_create_session(path_selection_strategy_t strategy);
void path_optimizer_destroy_session(path_optimization_session_t* session);

int path_optimizer_add_path(path_optimization_session_t* session, 
                           const path_quality_metrics_t* metrics);

int path_optimizer_measure_path_quality(path_optimization_session_t* session,
                                       uint8_t path_idx,
                                       path_quality_metrics_t* metrics);

int path_optimizer_select_optimal_path(path_optimization_session_t* session);

int path_optimizer_get_selected_path(path_optimization_session_t* session);

float path_optimizer_calculate_path_score(const path_quality_metrics_t* metrics,
                                         path_selection_strategy_t strategy);

bool path_optimizer_needs_reselection(path_optimization_session_t* session,
                                     uint32_t threshold_change_percent);

#ifdef __cplusplus
}
#endif

#endif // BETANET_PATH_OPTIMIZATION_H
