/**
 * @file htx_noise_integration.h
 * @brief HTX-Noise Integration Layer (BetaNet Specification §5.4 + §6.1)
 * 
 * Integrates Noise XK cryptographic handshakes with HTX Inner Frame Format
 * transport layer to provide end-to-end encrypted communication with stream
 * multiplexing and flow control.
 */

#ifndef HTX_NOISE_INTEGRATION_H
#define HTX_NOISE_INTEGRATION_H

#include "htx_frames.h"
#include "../../src/noise/noise.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ============================================================================
// Error Codes
// ============================================================================

#define HTX_NOISE_OK                    0   /**< Success */
#define HTX_NOISE_ERROR_INVALID_PARAM  -1   /**< Invalid parameter */
#define HTX_NOISE_ERROR_HANDSHAKE      -2   /**< Handshake failure */
#define HTX_NOISE_ERROR_ENCRYPTION     -3   /**< Encryption/decryption error */
#define HTX_NOISE_ERROR_TRANSPORT      -4   /**< HTX transport error */
#define HTX_NOISE_ERROR_OUT_OF_MEMORY  -5   /**< Memory allocation failure */
#define HTX_NOISE_ERROR_STREAM_CLOSED  -6   /**< Stream is closed */
#define HTX_NOISE_ERROR_REKEY_REQUIRED -7   /**< Key rotation required */

// ============================================================================
// Constants
// ============================================================================

#define HTX_NOISE_HANDSHAKE_STREAM_ID   0   /**< Reserved stream ID for handshake */
#define HTX_NOISE_MAX_MESSAGE_SIZE      4096 /**< Maximum message size */
#define HTX_NOISE_REKEY_BYTES_LIMIT     (1ULL << 30) /**< 1GB rekey limit */
#define HTX_NOISE_REKEY_FRAMES_LIMIT    (1ULL << 20) /**< 1M frames rekey limit */
#define HTX_NOISE_REKEY_TIME_LIMIT      3600 /**< 1 hour rekey limit */

// ============================================================================
// Data Structures
// ============================================================================

/**
 * @brief HTX-Noise integrated secure connection
 * 
 * Combines HTX transport with Noise XK cryptographic state for
 * secure multiplexed communication.
 */
typedef struct {
    htx_connection_t* htx_conn;      /**< HTX transport connection */
    noise_channel_t* noise_chan;     /**< Noise XK cryptographic channel */
    bool handshake_complete;         /**< True if handshake finished */
    uint32_t control_stream_id;      /**< Stream ID for control messages */
    
    // Statistics
    uint64_t messages_sent;          /**< Number of messages sent */
    uint64_t messages_received;      /**< Number of messages received */
    uint64_t bytes_sent;             /**< Total bytes sent */
    uint64_t bytes_received;         /**< Total bytes received */
    uint64_t last_activity;          /**< Timestamp of last activity */
} htx_noise_connection_t;

/**
 * @brief Secure message structure
 */
typedef struct {
    uint32_t stream_id;              /**< Target stream ID */
    uint8_t* data;                   /**< Message payload */
    size_t data_len;                 /**< Payload length */
    bool is_final;                   /**< True if this is the final message on stream */
} htx_noise_message_t;

/**
 * @brief Handshake result information
 */
typedef struct {
    bool success;                    /**< True if handshake succeeded */
    uint8_t peer_static_key[32];     /**< Peer's static public key */
    uint8_t session_id[16];          /**< Unique session identifier */
    uint64_t handshake_duration_ms;  /**< Handshake duration in milliseconds */
} htx_noise_handshake_result_t;

// ============================================================================
// Connection Management API
// ============================================================================

/**
 * Create a new HTX-Noise secure connection
 * 
 * @param is_client True if this is a client connection
 * @param k0_local Local key material for HTX frames
 * @param k0_remote Remote key material for HTX frames
 * @return Pointer to new connection, or NULL on failure
 */
htx_noise_connection_t* htx_noise_connection_create(bool is_client,
                                                   const uint8_t k0_local[32],
                                                   const uint8_t k0_remote[32]);

/**
 * Perform Noise XK handshake over HTX transport
 * 
 * @param conn HTX-Noise connection
 * @param result Handshake result information (output)
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_handshake(htx_noise_connection_t* conn,
                       htx_noise_handshake_result_t* result);

/**
 * Open a new secure stream for communication
 * 
 * @param conn HTX-Noise connection
 * @param stream_id Returned stream ID
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_stream_open(htx_noise_connection_t* conn, uint32_t* stream_id);

/**
 * Close a secure stream
 * 
 * @param conn HTX-Noise connection
 * @param stream_id Stream ID to close
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_stream_close(htx_noise_connection_t* conn, uint32_t stream_id);

/**
 * Cleanup and destroy HTX-Noise connection
 * 
 * @param conn HTX-Noise connection to destroy
 */
void htx_noise_connection_destroy(htx_noise_connection_t* conn);

// ============================================================================
// Secure Messaging API
// ============================================================================

/**
 * Send a secure message on a specific stream
 * 
 * @param conn HTX-Noise connection
 * @param message Message to send
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_send_message(htx_noise_connection_t* conn,
                          const htx_noise_message_t* message);

/**
 * Receive a secure message from any stream
 * 
 * @param conn HTX-Noise connection
 * @param message Received message (output, caller must free data field)
 * @param timeout_ms Timeout in milliseconds (0 for non-blocking)
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_receive_message(htx_noise_connection_t* conn,
                             htx_noise_message_t* message,
                             uint32_t timeout_ms);

/**
 * Send a message and wait for response (request-response pattern)
 * 
 * @param conn HTX-Noise connection
 * @param request Request message
 * @param response Response message (output, caller must free data field)
 * @param timeout_ms Timeout in milliseconds
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_request_response(htx_noise_connection_t* conn,
                              const htx_noise_message_t* request,
                              htx_noise_message_t* response,
                              uint32_t timeout_ms);

// ============================================================================
// Key Management API
// ============================================================================

/**
 * Check if key rotation is required
 * 
 * @param conn HTX-Noise connection
 * @return True if rekey is needed
 */
bool htx_noise_rekey_required(htx_noise_connection_t* conn);

/**
 * Perform key rotation for both HTX and Noise layers
 * 
 * @param conn HTX-Noise connection
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_rekey(htx_noise_connection_t* conn);

/**
 * Get current cryptographic state information
 * 
 * @param conn HTX-Noise connection
 * @param htx_key_age Age of HTX frame keys in seconds
 * @param noise_key_age Age of Noise session keys in seconds
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_get_key_state(htx_noise_connection_t* conn,
                           uint64_t* htx_key_age,
                           uint64_t* noise_key_age);

// ============================================================================
// Monitoring and Statistics API
// ============================================================================

/**
 * Get connection statistics
 * 
 * @param conn HTX-Noise connection
 * @param messages_sent Number of messages sent (output)
 * @param messages_received Number of messages received (output)
 * @param bytes_sent Total bytes sent (output)
 * @param bytes_received Total bytes received (output)
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_get_statistics(htx_noise_connection_t* conn,
                            uint64_t* messages_sent,
                            uint64_t* messages_received,
                            uint64_t* bytes_sent,
                            uint64_t* bytes_received);

/**
 * Check connection health and detect issues
 * 
 * @param conn HTX-Noise connection
 * @param health_score Health score 0-100 (output)
 * @param error_count Number of recent errors (output)
 * @return HTX_NOISE_OK on success, error code otherwise
 */
int htx_noise_health_check(htx_noise_connection_t* conn,
                          uint8_t* health_score,
                          uint32_t* error_count);

#endif // HTX_NOISE_INTEGRATION_H
