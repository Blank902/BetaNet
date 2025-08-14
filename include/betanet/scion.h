#ifndef BETANET_SCION_H
#define BETANET_SCION_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==============================================================================
// BetaNet 1.1 SCION Packet Format - §4.1 Compliance
// ==============================================================================

/* SCION Protocol Constants - BetaNet 1.1 Specification */
#define SCION_VERSION 0x02                   /**< SCION protocol version as per §4.1 */
#define SCION_MIN_HEADER_SIZE 12             /**< Minimum SCION common header size in bytes */
#define SCION_MAX_HEADER_SIZE 1020           /**< Maximum SCION header size in bytes */
#define SCION_MAX_PAYLOAD_SIZE 65535         /**< Maximum payload size in bytes */
#define SCION_MAX_HOPS 64                    /**< Maximum number of hops in path */

/* SCION Address Types */
#define SCION_ADDR_TYPE_IPV4 0x00           /**< IPv4 address type */
#define SCION_ADDR_TYPE_IPV6 0x01           /**< IPv6 address type */
#define SCION_ADDR_TYPE_SVC 0x02            /**< Service address type */

/* SCION Next Header Types */
#define SCION_NEXTHDR_NONE 0x00             /**< No next header */
#define SCION_NEXTHDR_UDP 0x11              /**< UDP protocol */
#define SCION_NEXTHDR_TCP 0x06              /**< TCP protocol */
#define SCION_NEXTHDR_SCMP 0xCA             /**< SCION Control Message Protocol */

/**
 * @brief SCION packet header structure (BetaNet 1.1 §4.1)
 * 
 * This structure represents the SCION common header as specified in
 * BetaNet 1.1 §4.1. All multi-byte fields are in network byte order.
 */
#pragma pack(push, 1)
typedef struct {
    uint8_t version_flags;          /**< Version (4 bits) + Flags (4 bits) */
    uint8_t qos_flow_id;           /**< QoS (8 bits) + Flow ID start (0 bits) */
    uint16_t flow_id;              /**< Flow ID (20 bits total, split across fields) */
    uint8_t next_hdr;              /**< Next header protocol type */
    uint8_t hdr_len;               /**< Header length in 4-byte units */
    uint16_t payload_len;          /**< Payload length in bytes */
    uint8_t path_type;             /**< Path type */
    uint8_t dt_dl_st_sl;           /**< DstType(2) + DstLen(6) + SrcType(2) + SrcLen(6) */
    uint16_t rsv;                  /**< Reserved field */
} scion_common_hdr_t;
#pragma pack(pop)

/**
 * @brief SCION address information structure
 * 
 * Contains addressing information for source and destination
 */
typedef struct {
    uint64_t src_ia;               /**< Source ISD-AS identifier */
    uint64_t dst_ia;               /**< Destination ISD-AS identifier */
    uint8_t src_addr[16];          /**< Source address (variable length) */
    uint8_t dst_addr[16];          /**< Destination address (variable length) */
    uint8_t src_addr_len;          /**< Source address length */
    uint8_t dst_addr_len;          /**< Destination address length */
} scion_addr_info_t;

/**
 * @brief Complete SCION packet structure (BetaNet 1.1 compliant)
 * 
 * Represents a complete SCION packet with header, addressing, and payload
 */
typedef struct {
    scion_common_hdr_t header;     /**< Common SCION header */
    scion_addr_info_t addr_info;   /**< Source and destination addressing */
    uint8_t *path_data;            /**< Path information (variable length) */
    size_t path_size;              /**< Size of path data */
    uint8_t *payload;              /**< Packet payload */
    size_t payload_size;           /**< Size of payload */
    size_t total_size;             /**< Total packet size */
} scion_packet_t;

/**
 * @brief SCION packet validation result
 */
typedef enum {
    SCION_PACKET_VALID = 0,               /**< Packet is valid */
    SCION_PACKET_ERR_INVALID_VERSION,     /**< Invalid SCION version */
    SCION_PACKET_ERR_INVALID_HEADER_LEN,  /**< Invalid header length */
    SCION_PACKET_ERR_INVALID_PAYLOAD_LEN, /**< Invalid payload length */
    SCION_PACKET_ERR_INVALID_ADDRESS,     /**< Invalid address format */
    SCION_PACKET_ERR_INVALID_PATH,        /**< Invalid path information */
    SCION_PACKET_ERR_BUFFER_TOO_SMALL,    /**< Buffer too small for packet */
    SCION_PACKET_ERR_INVALID_CHECKSUM     /**< Invalid packet checksum */
} scion_packet_validation_result_t;

// ==============================================================================
// BetaNet 1.1 SCION Packet API - §4.1 Compliance
// ==============================================================================

/**
 * @brief Initialize a SCION packet structure
 * 
 * @param packet Pointer to packet structure to initialize
 * @return true on success, false on failure
 */
bool scion_packet_init(scion_packet_t *packet);

/**
 * @brief Clean up a SCION packet structure
 * 
 * @param packet Pointer to packet structure to clean up
 */
void scion_packet_cleanup(scion_packet_t *packet);

/**
 * @brief Validate a SCION packet header (BetaNet 1.1 §4.1)
 * 
 * Validates the packet according to BetaNet 1.1 §4.1 requirements
 * 
 * @param packet Pointer to packet to validate
 * @return Validation result code
 */
scion_packet_validation_result_t scion_validate_packet(const scion_packet_t *packet);

/**
 * @brief Parse a SCION packet from raw bytes
 * 
 * @param buffer Raw packet data
 * @param buffer_size Size of raw data
 * @param packet Output packet structure
 * @return true on successful parsing, false on error
 */
bool scion_parse_packet(const uint8_t *buffer, size_t buffer_size, scion_packet_t *packet);

/**
 * @brief Serialize a SCION packet to raw bytes
 * 
 * @param packet Packet structure to serialize
 * @param buffer Output buffer for raw data
 * @param buffer_size Size of output buffer
 * @param written_size Output parameter for actual bytes written
 * @return true on successful serialization, false on error
 */
bool scion_serialize_packet(const scion_packet_t *packet, uint8_t *buffer, 
                           size_t buffer_size, size_t *written_size);

/**
 * @brief Create SCION packet with specified parameters
 * 
 * @param src_ia Source ISD-AS identifier
 * @param dst_ia Destination ISD-AS identifier
 * @param src_addr Source address
 * @param src_addr_len Source address length
 * @param dst_addr Destination address
 * @param dst_addr_len Destination address length
 * @param payload Packet payload data
 * @param payload_size Size of payload
 * @param packet Output packet structure
 * @return true on success, false on failure
 */
bool scion_create_packet(uint64_t src_ia, uint64_t dst_ia,
                        const uint8_t *src_addr, uint8_t src_addr_len,
                        const uint8_t *dst_addr, uint8_t dst_addr_len,
                        const uint8_t *payload, size_t payload_size,
                        scion_packet_t *packet);

/**
 * @brief Check if packet version matches BetaNet 1.1 requirements
 * 
 * @param packet Packet to check
 * @return true if version is valid, false otherwise
 */
bool scion_is_valid_version(const scion_packet_t *packet);

/**
 * @brief Get human-readable description of validation error
 * 
 * @param result Validation result code
 * @return String description of error
 */
const char* scion_packet_validation_error_string(scion_packet_validation_result_t result);

// ==============================================================================
// Legacy Path Selection API (Existing Implementation)
// ==============================================================================

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
// BetaNet v1.1 Enhanced Path Discovery
// ==============================================================================

/**
 * Enhanced path discovery for censorship resistance
 * Implements path diversity and AS-avoidance for BetaNet v1.1
 */
typedef struct {
    scion_ia_t avoided_as_list[16];    // ASes to avoid for censorship resistance
    uint8_t num_avoided_as;
    uint8_t enable_path_diversity;      // Use multiple disjoint paths
    uint8_t prefer_long_paths;          // Prefer longer paths for anonymity
    uint32_t max_path_length;           // Maximum acceptable path length
    uint32_t discovery_timeout_ms;      // Path discovery timeout
} betanet_scion_discovery_config_t;

/**
 * Discover censorship-resistant paths
 * 
 * @param src_ia Source ISD-AS
 * @param dst_ia Destination ISD-AS
 * @param config Discovery configuration
 * @param paths Output path array
 * @param max_paths Maximum number of paths
 * @param num_found Number of paths discovered
 * @return 0 on success, negative on error
 */
int betanet_scion_discover_diverse_paths(const scion_ia_t* src_ia,
                                         const scion_ia_t* dst_ia,
                                         const betanet_scion_discovery_config_t* config,
                                         scion_path_t* paths,
                                         size_t max_paths,
                                         size_t* num_found);

/**
 * Validate path does not traverse censored ASes
 * 
 * @param path Path to validate
 * @param config Discovery configuration with avoided ASes
 * @return 1 if path is safe, 0 if traverses censored AS
 */
int betanet_scion_validate_censorship_resistance(const scion_path_t* path,
                                                 const betanet_scion_discovery_config_t* config);

/**
 * Get AS-level path diversity score
 * 
 * @param paths Array of paths
 * @param num_paths Number of paths
 * @return Diversity score (0-100, higher is more diverse)
 */
uint8_t betanet_scion_calculate_path_diversity(const scion_path_t* paths,
                                               size_t num_paths);

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
