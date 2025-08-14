#ifndef BETANET_SCION_H
#define BETANET_SCION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
typedef struct scion_path scion_path_t;
typedef struct scion_selector scion_selector_t;
typedef struct scion_metrics scion_metrics_t;

// SCION Autonomous System (AS) identifier
typedef struct {
    uint64_t isd;  // Isolation Domain
    uint64_t as;   // Autonomous System
} scion_ia_t;

// SCION path segment types
typedef enum {
    SCION_SEGMENT_UP = 0,
    SCION_SEGMENT_CORE = 1,
    SCION_SEGMENT_DOWN = 2
} scion_segment_type_t;

// SCION path quality metrics
typedef struct {
    uint32_t latency_ms;        // End-to-end latency
    uint32_t bandwidth_kbps;    // Available bandwidth
    uint32_t packet_loss;       // Packet loss rate (per 10000)
    uint32_t jitter_ms;         // Jitter measurement
    time_t last_measured;       // Last measurement timestamp
    bool is_active;             // Path currently active
} scion_path_quality_t;

// SCION path information
struct scion_path {
    scion_ia_t src_ia;          // Source IA
    scion_ia_t dst_ia;          // Destination IA
    uint8_t* raw_path;          // Raw SCION path data
    size_t path_len;            // Path data length
    scion_path_quality_t quality; // Quality metrics
    uint32_t path_id;           // Unique path identifier
    time_t expiry;              // Path expiration time
    bool is_valid;              // Path validity flag
    struct scion_path* next;    // Linked list for multiple paths
};

// Path selection criteria
typedef enum {
    SCION_SELECT_LATENCY = 0,   // Minimize latency
    SCION_SELECT_BANDWIDTH = 1, // Maximize bandwidth
    SCION_SELECT_RELIABILITY = 2, // Minimize packet loss
    SCION_SELECT_BALANCED = 3   // Balanced performance
} scion_selection_criteria_t;

// Path selection configuration
typedef struct {
    scion_selection_criteria_t criteria;
    uint32_t max_latency_ms;    // Maximum acceptable latency
    uint32_t min_bandwidth_kbps; // Minimum required bandwidth
    uint32_t max_packet_loss;   // Maximum acceptable packet loss
    bool enable_multipath;      // Enable multipath routing
    uint32_t path_refresh_interval; // Path refresh interval (seconds)
} scion_selection_config_t;

// SCION path selector
struct scion_selector {
    scion_selection_config_t config;
    scion_path_t* available_paths;
    scion_path_t* active_path;
    scion_metrics_t* metrics;
    bool is_initialized;
    time_t last_path_update;
};

// SCION routing metrics
struct scion_metrics {
    uint64_t paths_discovered;  // Total paths discovered
    uint64_t paths_selected;    // Total path selections
    uint64_t path_switches;     // Number of path switches
    uint64_t path_failures;     // Path failure count
    uint32_t avg_latency_ms;    // Average path latency
    uint32_t avg_bandwidth_kbps; // Average path bandwidth
    time_t last_update;         // Last metrics update
};

// Error codes
typedef enum {
    SCION_SUCCESS = 0,
    SCION_ERROR_INIT = -1,
    SCION_ERROR_NO_PATHS = -2,
    SCION_ERROR_PATH_INVALID = -3,
    SCION_ERROR_TIMEOUT = -4,
    SCION_ERROR_NETWORK = -5,
    SCION_ERROR_CONFIG = -6,
    SCION_ERROR_MEMORY = -7
} scion_error_t;

// ==============================================================================
// SCION Path Discovery and Selection API
// ==============================================================================

/**
 * Initialize SCION path selector
 * @param selector Pointer to selector structure
 * @param config Selection configuration
 * @return SCION_SUCCESS on success, error code on failure
 */
scion_error_t scion_selector_init(scion_selector_t* selector, 
                                  const scion_selection_config_t* config);

/**
 * Discover available paths to destination
 * @param selector Path selector
 * @param dst_ia Destination IA
 * @param timeout_ms Discovery timeout in milliseconds
 * @return SCION_SUCCESS on success, error code on failure
 */
scion_error_t scion_discover_paths(scion_selector_t* selector,
                                   const scion_ia_t* dst_ia,
                                   uint32_t timeout_ms);

/**
 * Select optimal path based on criteria
 * @param selector Path selector
 * @param dst_ia Destination IA
 * @param selected_path Output selected path
 * @return SCION_SUCCESS on success, error code on failure
 */
scion_error_t scion_select_path(scion_selector_t* selector,
                                const scion_ia_t* dst_ia,
                                scion_path_t** selected_path);

/**
 * Update path quality metrics
 * @param path Path to update
 * @param quality New quality measurements
 * @return SCION_SUCCESS on success, error code on failure
 */
scion_error_t scion_update_path_quality(scion_path_t* path,
                                        const scion_path_quality_t* quality);

/**
 * Monitor active path and switch if necessary
 * @param selector Path selector
 * @return SCION_SUCCESS if no switch needed, positive value if switched
 */
scion_error_t scion_monitor_and_switch(scion_selector_t* selector);

// ==============================================================================
// Path Management Functions
// ==============================================================================

/**
 * Create new SCION path
 * @param src_ia Source IA
 * @param dst_ia Destination IA
 * @param raw_path Raw path data
 * @param path_len Path data length
 * @return New path structure, NULL on failure
 */
scion_path_t* scion_path_create(const scion_ia_t* src_ia,
                                const scion_ia_t* dst_ia,
                                const uint8_t* raw_path,
                                size_t path_len);

/**
 * Free SCION path
 * @param path Path to free
 */
void scion_path_free(scion_path_t* path);

/**
 * Check if path is valid and not expired
 * @param path Path to validate
 * @return true if valid, false otherwise
 */
bool scion_path_is_valid(const scion_path_t* path);

/**
 * Compare two paths for quality
 * @param path1 First path
 * @param path2 Second path
 * @param criteria Selection criteria
 * @return -1 if path1 better, 1 if path2 better, 0 if equal
 */
int scion_path_compare(const scion_path_t* path1,
                       const scion_path_t* path2,
                       scion_selection_criteria_t criteria);

// ==============================================================================
// Utility Functions
// ==============================================================================

/**
 * Parse IA from string (e.g., "1-ff00:0:110")
 * @param ia_str IA string
 * @param ia Output IA structure
 * @return SCION_SUCCESS on success, error code on failure
 */
scion_error_t scion_parse_ia(const char* ia_str, scion_ia_t* ia);

/**
 * Format IA to string
 * @param ia IA structure
 * @param buffer Output buffer
 * @param buffer_size Buffer size
 * @return Number of bytes written, -1 on error
 */
int scion_format_ia(const scion_ia_t* ia, char* buffer, size_t buffer_size);

/**
 * Get current time in milliseconds
 * @return Current time in milliseconds
 */
uint64_t scion_get_time_ms(void);

/**
 * Get SCION metrics
 * @param selector Path selector
 * @return Metrics structure, NULL on error
 */
const scion_metrics_t* scion_get_metrics(const scion_selector_t* selector);

/**
 * Print SCION metrics report
 * @param selector Path selector
 */
void scion_print_metrics(const scion_selector_t* selector);

/**
 * Reset SCION metrics
 * @param selector Path selector
 */
void scion_reset_metrics(scion_selector_t* selector);

/**
 * Cleanup SCION selector
 * @param selector Path selector to cleanup
 */
void scion_selector_cleanup(scion_selector_t* selector);

// ==============================================================================
// Default Configuration Values
// ==============================================================================

#define SCION_DEFAULT_MAX_LATENCY_MS        1000
#define SCION_DEFAULT_MIN_BANDWIDTH_KBPS    1000
#define SCION_DEFAULT_MAX_PACKET_LOSS       100    // 1%
#define SCION_DEFAULT_PATH_REFRESH_INTERVAL 300    // 5 minutes
#define SCION_DEFAULT_DISCOVERY_TIMEOUT_MS  5000
#define SCION_MAX_PATHS_PER_DESTINATION     10
#define SCION_PATH_EXPIRY_HOURS             24

/**
 * Get default SCION selection configuration
 * @return Default configuration
 */
static inline scion_selection_config_t scion_get_default_config(void) {
    scion_selection_config_t config = {
        .criteria = SCION_SELECT_BALANCED,
        .max_latency_ms = SCION_DEFAULT_MAX_LATENCY_MS,
        .min_bandwidth_kbps = SCION_DEFAULT_MIN_BANDWIDTH_KBPS,
        .max_packet_loss = SCION_DEFAULT_MAX_PACKET_LOSS,
        .enable_multipath = false,
        .path_refresh_interval = SCION_DEFAULT_PATH_REFRESH_INTERVAL
    };
    return config;
}

#ifdef __cplusplus
}
#endif

#endif // BETANET_SCION_H
