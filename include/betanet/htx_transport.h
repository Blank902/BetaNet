/**
 * @file htx_transport.h
 * @brief HTX Transport Protocol Integration with SCION (BetaNet §4.2 & §5.1)
 * 
 * This module implements the HTX Transport Protocol that provides origin mirroring,
 * resilient communication, and seamless integration between SCION path layer
 * and HTX application layer features.
 * 
 * Key Features (BetaNet 1.1 Compliance):
 * - Origin mirroring for censorship resistance (§5.1) 
 * - SCION path integration for multi-path resilience
 * - Access ticket validation with transport context
 * - Adaptive path selection based on network conditions
 * - Transparent failover between origins and paths
 * - Flow control integration with SCION QoS
 */

#ifndef HTX_TRANSPORT_H
#define HTX_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "scion.h"

// Forward declarations to avoid circular dependencies
typedef struct htx_ticket_context htx_ticket_context_t;
typedef struct htx_frame_context htx_frame_context_t;

#ifdef __cplusplus
extern "C" {
#endif

// Transport layer constants
#define HTX_TRANSPORT_MAX_ORIGINS 16         /**< Maximum origin mirrors */
#define HTX_TRANSPORT_MAX_PATHS 8            /**< Maximum SCION paths per origin */
#define HTX_TRANSPORT_ORIGIN_TIMEOUT 30000   /**< Origin timeout in ms */
#define HTX_TRANSPORT_PATH_TIMEOUT 15000     /**< Path timeout in ms */
#define HTX_TRANSPORT_RETRY_LIMIT 3          /**< Maximum retry attempts */

/**
 * @brief HTX Transport connection state
 */
typedef enum {
    HTX_TRANSPORT_DISCONNECTED = 0,    /**< No active connection */
    HTX_TRANSPORT_CONNECTING,          /**< Connection in progress */
    HTX_TRANSPORT_CONNECTED,           /**< Active connection established */
    HTX_TRANSPORT_DEGRADED,            /**< Connection degraded (fallback) */
    HTX_TRANSPORT_FAILED               /**< Connection failed */
} htx_transport_state_t;

/**
 * @brief Origin mirror information for resilient communication
 */
typedef struct {
    uint64_t ia;                       /**< ISD-AS identifier */
    uint8_t addr[16];                  /**< IP address (IPv4/IPv6) */
    uint8_t addr_len;                  /**< Address length */
    uint16_t port;                     /**< TCP/UDP port */
    bool is_active;                    /**< Origin availability status */
    uint32_t rtt_ms;                   /**< Round-trip time in milliseconds */
    uint32_t failure_count;            /**< Consecutive failures */
    uint64_t last_success;             /**< Last successful connection timestamp */
    uint64_t last_failure;             /**< Last failure timestamp */
    float reliability_score;           /**< Origin reliability (0.0-1.0) */
} htx_origin_mirror_t;

/**
 * @brief SCION path information for transport routing
 */
typedef struct {
    scion_packet_t *path_template;     /**< SCION path template */
    bool is_active;                    /**< Path availability status */
    uint32_t latency_ms;               /**< Path latency */
    uint32_t bandwidth_kbps;           /**< Estimated bandwidth */
    float loss_rate;                   /**< Packet loss rate (0.0-1.0) */
    uint64_t last_used;                /**< Last usage timestamp */
    uint32_t failure_count;            /**< Consecutive failures */
} htx_transport_path_t;

/**
 * @brief HTX Transport session context
 */
typedef struct {
    // Session identification
    uint64_t session_id;               /**< Unique session identifier */
    htx_transport_state_t state;       /**< Current connection state */
    
    // Origin mirroring (§5.1)
    htx_origin_mirror_t origins[HTX_TRANSPORT_MAX_ORIGINS];
    size_t origin_count;               /**< Number of configured origins */
    size_t active_origin_idx;          /**< Currently active origin index */
    
    // SCION path management
    htx_transport_path_t paths[HTX_TRANSPORT_MAX_PATHS];
    size_t path_count;                 /**< Number of available paths */
    size_t active_path_idx;            /**< Currently active path index */
    
    // HTX integration
    htx_ticket_context_t *ticket_ctx;  /**< Access ticket context */
    htx_frame_context_t *frame_ctx;    /**< Frame handling context */
    
    // Transport metrics
    uint64_t bytes_sent;               /**< Total bytes transmitted */
    uint64_t bytes_received;           /**< Total bytes received */
    uint32_t packets_sent;             /**< Total packets transmitted */
    uint32_t packets_received;         /**< Total packets received */
    uint32_t retransmissions;          /**< Number of retransmissions */
    
    // Timing and state
    uint64_t connection_start;         /**< Connection establishment time */
    uint64_t last_activity;            /**< Last activity timestamp */
    uint32_t keepalive_interval;       /**< Keepalive interval in ms */
    
    // Flow control
    uint32_t send_window;              /**< Send window size */
    uint32_t recv_window;              /**< Receive window size */
    uint32_t congestion_window;        /**< Congestion window size */
} htx_transport_session_t;

/**
 * @brief Transport configuration parameters
 */
typedef struct {
    uint32_t origin_probe_interval;    /**< Origin health check interval (ms) */
    uint32_t path_probe_interval;      /**< Path health check interval (ms) */
    float origin_failure_threshold;    /**< Origin failure threshold (0.0-1.0) */
    float path_failure_threshold;      /**< Path failure threshold (0.0-1.0) */
    uint32_t adaptive_timeout_base;    /**< Base timeout for adaptive algorithm */
    bool enable_auto_calibration;      /**< Enable automatic calibration */
    bool enable_multi_path;            /**< Enable multi-path routing */
} htx_transport_config_t;

/**
 * @brief Transport operation result codes
 */
typedef enum {
    HTX_TRANSPORT_SUCCESS = 0,         /**< Operation successful */
    HTX_TRANSPORT_ERR_INVALID_PARAM,   /**< Invalid parameter */
    HTX_TRANSPORT_ERR_NO_MEMORY,       /**< Memory allocation failed */
    HTX_TRANSPORT_ERR_NO_ORIGINS,      /**< No available origins */
    HTX_TRANSPORT_ERR_NO_PATHS,        /**< No available paths */
    HTX_TRANSPORT_ERR_CONNECTION_FAILED, /**< Connection establishment failed */
    HTX_TRANSPORT_ERR_TIMEOUT,         /**< Operation timed out */
    HTX_TRANSPORT_ERR_NETWORK,         /**< Network error */
    HTX_TRANSPORT_ERR_AUTH_FAILED,     /**< Authentication failed */
    HTX_TRANSPORT_ERR_DEGRADED         /**< Service degraded */
} htx_transport_result_t;

// ============================================================================
// Core Transport Functions
// ============================================================================

/**
 * @brief Initialize HTX transport session
 * 
 * Creates a new transport session with origin mirroring and SCION path
 * integration capabilities.
 * 
 * @param config Transport configuration parameters
 * @return New transport session or NULL on failure
 */
htx_transport_session_t *htx_transport_create_session(const htx_transport_config_t *config);

/**
 * @brief Destroy HTX transport session
 * 
 * @param session Transport session to destroy
 */
void htx_transport_destroy_session(htx_transport_session_t *session);

/**
 * @brief Add origin mirror to transport session
 * 
 * @param session Transport session
 * @param ia ISD-AS identifier
 * @param addr IP address
 * @param addr_len Address length (4 for IPv4, 16 for IPv6)
 * @param port TCP/UDP port
 * @return Result code
 */
htx_transport_result_t htx_transport_add_origin(htx_transport_session_t *session,
                                                uint64_t ia,
                                                const uint8_t *addr,
                                                uint8_t addr_len,
                                                uint16_t port);

/**
 * @brief Add SCION path to transport session
 * 
 * @param session Transport session
 * @param path_template SCION path template
 * @return Result code
 */
htx_transport_result_t htx_transport_add_path(htx_transport_session_t *session,
                                              scion_packet_t *path_template);

/**
 * @brief Establish transport connection with automatic origin/path selection
 * 
 * @param session Transport session
 * @param ticket_data Access ticket for authentication
 * @param ticket_len Ticket data length
 * @return Result code
 */
htx_transport_result_t htx_transport_connect(htx_transport_session_t *session,
                                             const uint8_t *ticket_data,
                                             size_t ticket_len);

/**
 * @brief Send data through HTX transport with automatic failover
 * 
 * @param session Transport session
 * @param data Data to send
 * @param data_len Data length
 * @param stream_id HTX stream identifier
 * @return Result code
 */
htx_transport_result_t htx_transport_send(htx_transport_session_t *session,
                                          const uint8_t *data,
                                          size_t data_len,
                                          uint32_t stream_id);

/**
 * @brief Receive data from HTX transport
 * 
 * @param session Transport session
 * @param buffer Buffer for received data
 * @param buffer_size Buffer size
 * @param received_len Actual received length
 * @param stream_id HTX stream identifier
 * @return Result code
 */
htx_transport_result_t htx_transport_receive(htx_transport_session_t *session,
                                             uint8_t *buffer,
                                             size_t buffer_size,
                                             size_t *received_len,
                                             uint32_t *stream_id);

// ============================================================================
// Origin Mirroring Functions (§5.1)
// ============================================================================

/**
 * @brief Perform origin health check and auto-calibration
 * 
 * Implements the origin mirroring auto-calibration system per BetaNet §5.1.
 * Tests all configured origins and updates reliability scores.
 * 
 * @param session Transport session
 * @return Result code
 */
htx_transport_result_t htx_transport_calibrate_origins(htx_transport_session_t *session);

/**
 * @brief Select best available origin based on current metrics
 * 
 * @param session Transport session
 * @return Index of best origin or -1 if none available
 */
int htx_transport_select_best_origin(htx_transport_session_t *session);

/**
 * @brief Switch to backup origin on failure
 * 
 * @param session Transport session
 * @return Result code
 */
htx_transport_result_t htx_transport_failover_origin(htx_transport_session_t *session);

/**
 * @brief Update origin metrics after network operation
 * 
 * @param session Transport session
 * @param origin_idx Origin index
 * @param success Whether operation succeeded
 * @param rtt_ms Round-trip time in milliseconds
 */
void htx_transport_update_origin_metrics(htx_transport_session_t *session,
                                         size_t origin_idx,
                                         bool success,
                                         uint32_t rtt_ms);

// ============================================================================
// Path Management Functions
// ============================================================================

/**
 * @brief Perform SCION path health check
 * 
 * @param session Transport session
 * @return Result code
 */
htx_transport_result_t htx_transport_probe_paths(htx_transport_session_t *session);

/**
 * @brief Select best available SCION path
 * 
 * @param session Transport session
 * @return Index of best path or -1 if none available
 */
int htx_transport_select_best_path(htx_transport_session_t *session);

/**
 * @brief Switch to backup path on failure
 * 
 * @param session Transport session
 * @return Result code
 */
htx_transport_result_t htx_transport_failover_path(htx_transport_session_t *session);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get transport session statistics
 * 
 * @param session Transport session
 * @param stats Buffer for statistics (JSON format)
 * @param stats_size Buffer size
 * @return Result code
 */
htx_transport_result_t htx_transport_get_stats(const htx_transport_session_t *session,
                                               char *stats,
                                               size_t stats_size);

/**
 * @brief Convert transport result to string
 * 
 * @param result Result code
 * @return Human-readable error message
 */
const char *htx_transport_result_to_string(htx_transport_result_t result);

#ifdef __cplusplus
}
#endif

#endif // HTX_TRANSPORT_H
