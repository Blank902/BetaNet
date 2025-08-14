#include "betanet/scion.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
// Platform headers already included via betanet.h
#else
#include <sys/time.h>
#include <unistd.h>
#endif

// ==============================================================================
// Internal Helper Functions
// ==============================================================================

/**
 * Get current time in milliseconds (platform-specific)
 */
uint64_t scion_get_time_ms(void) {
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER ui;
    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    return (ui.QuadPart - 116444736000000000ULL) / 10000;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

/**
 * Calculate path score based on selection criteria
 */
static double calculate_path_score(const scion_path_t* path, 
                                   scion_selection_criteria_t criteria) {
    if (!path || !path->is_valid) {
        return -1.0;
    }

    const scion_path_quality_t* q = &path->quality;
    double score = 0.0;

    switch (criteria) {
        case SCION_SELECT_LATENCY:
            // Lower latency is better (invert and normalize)
            score = q->latency_ms > 0 ? 1000.0 / q->latency_ms : 0.0;
            break;

        case SCION_SELECT_BANDWIDTH:
            // Higher bandwidth is better
            score = (double)q->bandwidth_kbps / 1000.0;
            break;

        case SCION_SELECT_RELIABILITY:
            // Lower packet loss is better (invert)
            score = q->packet_loss > 0 ? 10000.0 / q->packet_loss : 100.0;
            break;

        case SCION_SELECT_BALANCED:
            // Balanced score considering all factors
            {
                double latency_score = q->latency_ms > 0 ? 1000.0 / q->latency_ms : 0.0;
                double bandwidth_score = (double)q->bandwidth_kbps / 1000.0;
                double reliability_score = q->packet_loss > 0 ? 10000.0 / q->packet_loss : 100.0;
                
                // Weighted average: 40% latency, 30% bandwidth, 30% reliability
                score = (latency_score * 0.4) + (bandwidth_score * 0.3) + (reliability_score * 0.3);
            }
            break;
    }

    return score;
}

/**
 * Check if path meets quality requirements
 */
static bool path_meets_requirements(const scion_path_t* path,
                                    const scion_selection_config_t* config) {
    if (!path || !path->is_valid || !config) {
        return false;
    }

    const scion_path_quality_t* q = &path->quality;
    
    return (q->latency_ms <= config->max_latency_ms) &&
           (q->bandwidth_kbps >= config->min_bandwidth_kbps) &&
           (q->packet_loss <= config->max_packet_loss);
}

// ==============================================================================
// SCION Path Management
// ==============================================================================

scion_path_t* scion_path_create(const scion_ia_t* src_ia,
                                const scion_ia_t* dst_ia,
                                const uint8_t* raw_path,
                                size_t path_len) {
    if (!src_ia || !dst_ia || !raw_path || path_len == 0) {
        return NULL;
    }

    scion_path_t* path = calloc(1, sizeof(scion_path_t));
    if (!path) {
        return NULL;
    }

    // Copy IA information
    path->src_ia = *src_ia;
    path->dst_ia = *dst_ia;

    // Copy raw path data
    path->raw_path = malloc(path_len);
    if (!path->raw_path) {
        free(path);
        return NULL;
    }
    memcpy(path->raw_path, raw_path, path_len);
    path->path_len = path_len;

    // Initialize path metadata
    path->path_id = rand(); // Simple random ID for now
    path->is_valid = true;
    path->expiry = time(NULL) + (SCION_PATH_EXPIRY_HOURS * 3600);
    path->next = NULL;

    // Initialize quality with default values
    path->quality.latency_ms = 100;
    path->quality.bandwidth_kbps = 10000;
    path->quality.packet_loss = 10; // 0.1%
    path->quality.jitter_ms = 5;
    path->quality.last_measured = time(NULL);
    path->quality.is_active = false;

    return path;
}

void scion_path_free(scion_path_t* path) {
    if (!path) {
        return;
    }

    if (path->raw_path) {
        free(path->raw_path);
    }
    free(path);
}

bool scion_path_is_valid(const scion_path_t* path) {
    if (!path) {
        return false;
    }

    time_t now = time(NULL);
    return path->is_valid && (now < path->expiry);
}

int scion_path_compare(const scion_path_t* path1,
                       const scion_path_t* path2,
                       scion_selection_criteria_t criteria) {
    if (!path1 || !path2) {
        return 0;
    }

    double score1 = calculate_path_score(path1, criteria);
    double score2 = calculate_path_score(path2, criteria);

    if (score1 > score2) return -1;
    if (score1 < score2) return 1;
    return 0;
}

// ==============================================================================
// SCION Selector Implementation
// ==============================================================================

scion_error_t scion_selector_init(scion_selector_t* selector,
                                  const scion_selection_config_t* config) {
    if (!selector) {
        return SCION_ERROR_CONFIG;
    }

    memset(selector, 0, sizeof(scion_selector_t));

    // Use provided config or default
    if (config) {
        selector->config = *config;
    } else {
        selector->config = scion_get_default_config();
    }

    // Initialize metrics
    selector->metrics = calloc(1, sizeof(scion_metrics_t));
    if (!selector->metrics) {
        return SCION_ERROR_MEMORY;
    }

    selector->metrics->last_update = time(NULL);
    selector->available_paths = NULL;
    selector->active_path = NULL;
    selector->is_initialized = true;
    selector->last_path_update = time(NULL);

    return SCION_SUCCESS;
}

scion_error_t scion_discover_paths(scion_selector_t* selector,
                                   const scion_ia_t* dst_ia,
                                   uint32_t timeout_ms) {
    if (!selector || !selector->is_initialized || !dst_ia) {
        return SCION_ERROR_CONFIG;
    }

    // Simulate path discovery (in real implementation, this would query SCION daemon)
    // For demonstration, we'll create several example paths with different characteristics

    uint64_t start_time = scion_get_time_ms();
    
    // Clear existing paths for this destination
    scion_path_t* current = selector->available_paths;
    scion_path_t* prev = NULL;
    
    while (current) {
        if (current->dst_ia.isd == dst_ia->isd && current->dst_ia.as == dst_ia->as) {
            if (prev) {
                prev->next = current->next;
            } else {
                selector->available_paths = current->next;
            }
            scion_path_t* to_free = current;
            current = current->next;
            scion_path_free(to_free);
        } else {
            prev = current;
            current = current->next;
        }
    }

    // Simulate discovering 3 different paths
    scion_ia_t src_ia = {.isd = 1, .as = 0xff00000110};
    
    // Path 1: Low latency, medium bandwidth
    uint8_t path1_data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    scion_path_t* path1 = scion_path_create(&src_ia, dst_ia, path1_data, sizeof(path1_data));
    if (path1) {
        path1->quality.latency_ms = 50 + (rand() % 50);
        path1->quality.bandwidth_kbps = 5000 + (rand() % 5000);
        path1->quality.packet_loss = 5 + (rand() % 10);
        path1->quality.jitter_ms = 2 + (rand() % 8);
        path1->next = selector->available_paths;
        selector->available_paths = path1;
        selector->metrics->paths_discovered++;
    }

    // Path 2: High bandwidth, medium latency
    uint8_t path2_data[] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
    scion_path_t* path2 = scion_path_create(&src_ia, dst_ia, path2_data, sizeof(path2_data));
    if (path2) {
        path2->quality.latency_ms = 100 + (rand() % 100);
        path2->quality.bandwidth_kbps = 15000 + (rand() % 10000);
        path2->quality.packet_loss = 2 + (rand() % 5);
        path2->quality.jitter_ms = 5 + (rand() % 10);
        path2->next = selector->available_paths;
        selector->available_paths = path2;
        selector->metrics->paths_discovered++;
    }

    // Path 3: Balanced performance
    uint8_t path3_data[] = {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28};
    scion_path_t* path3 = scion_path_create(&src_ia, dst_ia, path3_data, sizeof(path3_data));
    if (path3) {
        path3->quality.latency_ms = 80 + (rand() % 40);
        path3->quality.bandwidth_kbps = 10000 + (rand() % 5000);
        path3->quality.packet_loss = 8 + (rand() % 7);
        path3->quality.jitter_ms = 3 + (rand() % 6);
        path3->next = selector->available_paths;
        selector->available_paths = path3;
        selector->metrics->paths_discovered++;
    }

    uint64_t elapsed = scion_get_time_ms() - start_time;
    if (elapsed > timeout_ms) {
        return SCION_ERROR_TIMEOUT;
    }

    selector->last_path_update = time(NULL);
    return SCION_SUCCESS;
}

scion_error_t scion_select_path(scion_selector_t* selector,
                                const scion_ia_t* dst_ia,
                                scion_path_t** selected_path) {
    if (!selector || !selector->is_initialized || !dst_ia || !selected_path) {
        return SCION_ERROR_CONFIG;
    }

    *selected_path = NULL;

    // Find best path to destination
    scion_path_t* best_path = NULL;
    double best_score = -1.0;

    scion_path_t* current = selector->available_paths;
    while (current) {
        // Check if path is for the destination and meets requirements
        if (current->dst_ia.isd == dst_ia->isd && 
            current->dst_ia.as == dst_ia->as &&
            scion_path_is_valid(current) &&
            path_meets_requirements(current, &selector->config)) {
            
            double score = calculate_path_score(current, selector->config.criteria);
            if (score > best_score) {
                best_score = score;
                best_path = current;
            }
        }
        current = current->next;
    }

    if (!best_path) {
        return SCION_ERROR_NO_PATHS;
    }

    // Update active path if different
    if (selector->active_path != best_path) {
        if (selector->active_path) {
            selector->active_path->quality.is_active = false;
            selector->metrics->path_switches++;
        }
        
        selector->active_path = best_path;
        best_path->quality.is_active = true;
        selector->metrics->paths_selected++;
    }

    *selected_path = best_path;
    return SCION_SUCCESS;
}

scion_error_t scion_update_path_quality(scion_path_t* path,
                                        const scion_path_quality_t* quality) {
    if (!path || !quality) {
        return SCION_ERROR_CONFIG;
    }

    path->quality = *quality;
    path->quality.last_measured = time(NULL);
    
    return SCION_SUCCESS;
}

scion_error_t scion_monitor_and_switch(scion_selector_t* selector) {
    if (!selector || !selector->is_initialized) {
        return SCION_ERROR_CONFIG;
    }

    if (!selector->active_path) {
        return SCION_SUCCESS; // No active path to monitor
    }

    // Check if current path still meets requirements
    if (!scion_path_is_valid(selector->active_path) ||
        !path_meets_requirements(selector->active_path, &selector->config)) {
        
        selector->metrics->path_failures++;
        
        // Try to find alternative path
        scion_path_t* new_path = NULL;
        scion_error_t result = scion_select_path(selector, &selector->active_path->dst_ia, &new_path);
        
        if (result == SCION_SUCCESS && new_path != selector->active_path) {
            return 1; // Path switched
        } else {
            return SCION_ERROR_NO_PATHS;
        }
    }

    return SCION_SUCCESS; // No switch needed
}

// ==============================================================================
// Utility Functions
// ==============================================================================

scion_error_t scion_parse_ia(const char* ia_str, scion_ia_t* ia) {
    if (!ia_str || !ia) {
        return SCION_ERROR_CONFIG;
    }

    // Parse format: "isd-as" (e.g., "1-ff00:0:110")
    if (sscanf(ia_str, "%llu-%llx", &ia->isd, &ia->as) == 2) {
        return SCION_SUCCESS;
    }

    return SCION_ERROR_CONFIG;
}

int scion_format_ia(const scion_ia_t* ia, char* buffer, size_t buffer_size) {
    if (!ia || !buffer || buffer_size == 0) {
        return -1;
    }

    return snprintf(buffer, buffer_size, "%llu-%llx", ia->isd, ia->as);
}

const scion_metrics_t* scion_get_metrics(const scion_selector_t* selector) {
    if (!selector || !selector->is_initialized) {
        return NULL;
    }

    // Update derived metrics
    scion_metrics_t* metrics = selector->metrics;
    uint32_t total_latency = 0;
    uint32_t total_bandwidth = 0;
    uint32_t path_count = 0;

    scion_path_t* current = selector->available_paths;
    while (current) {
        if (scion_path_is_valid(current)) {
            total_latency += current->quality.latency_ms;
            total_bandwidth += current->quality.bandwidth_kbps;
            path_count++;
        }
        current = current->next;
    }

    if (path_count > 0) {
        metrics->avg_latency_ms = total_latency / path_count;
        metrics->avg_bandwidth_kbps = total_bandwidth / path_count;
    }

    metrics->last_update = time(NULL);
    return metrics;
}

void scion_print_metrics(const scion_selector_t* selector) {
    const scion_metrics_t* metrics = scion_get_metrics(selector);
    if (!metrics) {
        printf("SCION Metrics: Not available\n");
        return;
    }

    printf("\n=== SCION Path Selection Metrics ===\n");
    printf("Paths discovered: %llu\n", metrics->paths_discovered);
    printf("Paths selected: %llu\n", metrics->paths_selected);
    printf("Path switches: %llu\n", metrics->path_switches);
    printf("Path failures: %llu\n", metrics->path_failures);
    printf("Average latency: %u ms\n", metrics->avg_latency_ms);
    printf("Average bandwidth: %u kbps\n", metrics->avg_bandwidth_kbps);
    
    if (selector->active_path) {
        printf("\nActive Path Quality:\n");
        printf("  Latency: %u ms\n", selector->active_path->quality.latency_ms);
        printf("  Bandwidth: %u kbps\n", selector->active_path->quality.bandwidth_kbps);
        printf("  Packet loss: %u (0.%02u%%)\n", 
               selector->active_path->quality.packet_loss,
               selector->active_path->quality.packet_loss);
        printf("  Jitter: %u ms\n", selector->active_path->quality.jitter_ms);
    }
    
    printf("Last update: %s", ctime(&metrics->last_update));
    printf("=====================================\n\n");
}

void scion_reset_metrics(scion_selector_t* selector) {
    if (!selector || !selector->metrics) {
        return;
    }

    memset(selector->metrics, 0, sizeof(scion_metrics_t));
    selector->metrics->last_update = time(NULL);
}

void scion_selector_cleanup(scion_selector_t* selector) {
    if (!selector) {
        return;
    }

    // Free all paths
    scion_path_t* current = selector->available_paths;
    while (current) {
        scion_path_t* next = current->next;
        scion_path_free(current);
        current = next;
    }

    // Free metrics
    if (selector->metrics) {
        free(selector->metrics);
    }

    memset(selector, 0, sizeof(scion_selector_t));
}
