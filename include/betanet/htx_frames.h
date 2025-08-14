/**
 * @file htx_frames.h
 * @brief HTX Inner Frame Format Implementation (BetaNet Specification §5.4)
 * 
 * Provides secure transport framing with stream multiplexing over HTX connections.
 * Implements ChaCha20-Poly1305 encryption with flow control and key rotation.
 * 
 * Frame Structure:
 * - length (uint24): Ciphertext length excluding AEAD tag
 * - type (uint8): Frame type (STREAM, PING, CLOSE, KEY_UPDATE, WINDOW_UPDATE)
 * - stream_id (varint): Present for STREAM and WINDOW_UPDATE frames
 * - ciphertext: ChaCha20-Poly1305 encrypted payload with 16-byte tag
 * 
 * @author BetaNet Implementation Team
 * @date 2025
 * @version 1.0
 */

#ifndef BETANET_HTX_FRAMES_H
#define BETANET_HTX_FRAMES_H

#include "betanet.h"
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants and Configuration
// ============================================================================

/** Error codes for HTX frames operations */
#define HTX_OK                    0   /**< Success */
#define HTX_ERROR_INVALID_PARAM  -1   /**< Invalid parameter */
#define HTX_ERROR_OUT_OF_MEMORY  -2   /**< Memory allocation failed */
#define HTX_ERROR_CRYPTO         -3   /**< Cryptographic operation failed */
#define HTX_ERROR_INVALID_DATA   -4   /**< Invalid data format */
#define HTX_ERROR_AUTH_FAILED    -5   /**< Authentication failed */
#define HTX_ERROR_FLOW_CONTROL   -6   /**< Flow control violation */
#define HTX_ERROR_INVALID_STREAM -7   /**< Invalid stream ID */
#define HTX_ERROR_NOT_FOUND      -8   /**< Stream not found */
#define HTX_ERROR_LIMIT_EXCEEDED -9   /**< Resource limit exceeded */
#define HTX_ERROR_BUFFER_TOO_SMALL -10 /**< Buffer too small */

/** Maximum frame size (24-bit length field) */
#define HTX_MAX_FRAME_SIZE 0xFFFFFF

/** ChaCha20-Poly1305 AEAD tag size */
#define HTX_AEAD_TAG_SIZE 16

/** ChaCha20-Poly1305 nonce size */
#define HTX_AEAD_NONCE_SIZE 12

/** ChaCha20-Poly1305 key size */
#define HTX_AEAD_KEY_SIZE 32

/** Flow control window size (65,535 bytes) */
#define HTX_FLOW_CONTROL_WINDOW 65535

/** Window update threshold (50% of window) */
#define HTX_WINDOW_UPDATE_THRESHOLD (HTX_FLOW_CONTROL_WINDOW / 2)

/** Maximum number of concurrent streams per connection */
#define HTX_MAX_STREAMS 1024

/** Key rotation limits */
#define HTX_REKEY_DATA_LIMIT (8ULL * 1024 * 1024 * 1024)  // 8 GiB
#define HTX_REKEY_FRAME_LIMIT (1ULL << 16)                // 2^16 frames
#define HTX_REKEY_TIME_LIMIT 3600                         // 1 hour (seconds)

// ============================================================================
// Frame Types
// ============================================================================

/** HTX frame types as defined in BetaNet Specification §5.4 */
typedef enum {
    HTX_FRAME_STREAM = 0,       /**< Data stream frame */
    HTX_FRAME_PING = 1,         /**< Keepalive/RTT measurement */
    HTX_FRAME_CLOSE = 2,        /**< Connection/stream close */
    HTX_FRAME_KEY_UPDATE = 3,   /**< Key rotation frame */
    HTX_FRAME_WINDOW_UPDATE = 4 /**< Flow control update */
} htx_frame_type_t;

// ============================================================================
// Stream Management
// ============================================================================

/** Stream state for flow control and lifecycle management */
typedef enum {
    HTX_STREAM_IDLE = 0,        /**< Stream not yet opened */
    HTX_STREAM_OPEN,            /**< Stream active and transferring data */
    HTX_STREAM_HALF_CLOSED,     /**< One direction closed */
    HTX_STREAM_CLOSED           /**< Stream fully closed */
} htx_stream_state_t;

/** Stream direction for client/server initiated streams */
typedef enum {
    HTX_STREAM_CLIENT = 1,      /**< Client-initiated (odd stream IDs) */
    HTX_STREAM_SERVER = 0       /**< Server-initiated (even stream IDs) */
} htx_stream_direction_t;

/** Individual stream control block */
typedef struct {
    uint32_t stream_id;         /**< Stream identifier */
    htx_stream_state_t state;   /**< Current stream state */
    uint32_t send_window;       /**< Remaining send window */
    uint32_t recv_window;       /**< Remaining receive window */
    uint64_t bytes_sent;        /**< Total bytes sent on this stream */
    uint64_t bytes_received;    /**< Total bytes received on this stream */
    time_t last_activity;       /**< Last activity timestamp */
} htx_stream_t;

// ============================================================================
// Cryptographic State
// ============================================================================

/** Per-direction cryptographic state */
typedef struct {
    uint8_t key[HTX_AEAD_KEY_SIZE];         /**< ChaCha20-Poly1305 key */
    uint8_t nonce_salt[HTX_AEAD_NONCE_SIZE]; /**< Nonce salt (NS) */
    uint64_t frame_counter;                  /**< Frame counter for nonce */
    uint64_t bytes_encrypted;                /**< Total encrypted bytes */
    uint64_t frames_sent;                    /**< Total frames sent */
    time_t last_rekey;                       /**< Last key rotation time */
    bool pending_rekey;                      /**< Key update in progress */
} htx_crypto_state_t;

// ============================================================================
// Frame Structures
// ============================================================================

/** Wire format frame header (before encryption) */
typedef struct {
    uint32_t length;            /**< Ciphertext length (24-bit on wire) */
    uint8_t type;               /**< Frame type */
    uint32_t stream_id;         /**< Stream ID (varint on wire, if present) */
    bool has_stream_id;         /**< Whether stream_id field is present */
} htx_frame_header_t;

/** Complete frame structure for processing */
typedef struct {
    htx_frame_header_t header;                    /**< Frame header */
    uint8_t *plaintext;                           /**< Decrypted payload */
    size_t plaintext_len;                         /**< Plaintext length */
    uint8_t *ciphertext;                          /**< Encrypted payload + tag */
    size_t ciphertext_len;                        /**< Ciphertext + tag length */
} htx_frame_t;

// ============================================================================
// Connection State
// ============================================================================

/** HTX connection context with multiplexed streams */
typedef struct {
    // Connection metadata
    bool is_server;                               /**< Server vs client role */
    time_t created_at;                            /**< Connection creation time */
    
    // Cryptographic state (bidirectional)
    htx_crypto_state_t send_crypto;               /**< Outbound encryption */
    htx_crypto_state_t recv_crypto;               /**< Inbound decryption */
    
    // Stream multiplexing
    htx_stream_t streams[HTX_MAX_STREAMS];        /**< Active streams */
    uint32_t next_client_stream_id;               /**< Next client stream ID */
    uint32_t next_server_stream_id;               /**< Next server stream ID */
    size_t active_stream_count;                   /**< Number of active streams */
    
    // Flow control
    uint32_t connection_send_window;              /**< Connection-level send window */
    uint32_t connection_recv_window;              /**< Connection-level receive window */
    
    // Statistics and monitoring
    uint64_t total_frames_sent;                   /**< Total frames transmitted */
    uint64_t total_frames_received;               /**< Total frames received */
    uint64_t total_bytes_sent;                    /**< Total bytes transmitted */
    uint64_t total_bytes_received;                /**< Total bytes received */
    uint32_t ping_rtt_ms;                         /**< Last measured RTT */
    
    // Error state
    int last_error;                               /**< Last error code */
    char error_message[256];                      /**< Human-readable error */
} htx_connection_t;

// ============================================================================
// Frame Processing Results
// ============================================================================

/** Result of frame encoding operation */
typedef struct {
    uint8_t *wire_data;         /**< Serialized frame data */
    size_t wire_len;            /**< Length of wire data */
    bool needs_window_update;   /**< Flow control update required */
    uint32_t updated_stream_id; /**< Stream needing window update */
} htx_frame_encode_result_t;

/** Result of frame decoding operation */
typedef struct {
    htx_frame_t frame;          /**< Decoded frame */
    bool valid;                 /**< Frame validation result */
    bool connection_error;      /**< Fatal connection error */
    bool needs_key_update;      /**< Key rotation required */
    char error_message[128];    /**< Error description */
} htx_frame_decode_result_t;

// ============================================================================
// Core API Functions
// ============================================================================

/**
 * Initialize HTX connection with derived keys from TLS exporter
 * 
 * @param conn Connection context to initialize
 * @param is_server Whether this is server side of connection
 * @param k0_client Initial client key (32 bytes)
 * @param k0_server Initial server key (32 bytes)
 * @return HTX_OK on success, error code on failure
 */
int htx_connection_init(
    htx_connection_t *conn,
    bool is_server,
    const uint8_t *k0_client,
    const uint8_t *k0_server
);

/**
 * Clean up HTX connection and securely erase keys
 * 
 * @param conn Connection to cleanup
 */
void htx_connection_cleanup(htx_connection_t *conn);

// ============================================================================
// Stream Management API
// ============================================================================

/**
 * Open new stream for data transfer
 * 
 * @param conn HTX connection
 * @param stream_id Output for assigned stream ID
 * @return HTX_OK on success, error code on failure
 */
int htx_stream_open(htx_connection_t *conn, uint32_t *stream_id);

/**
 * Close stream and update flow control
 * 
 * @param conn HTX connection
 * @param stream_id Stream to close
 * @return HTX_OK on success, error code on failure
 */
int htx_stream_close(htx_connection_t *conn, uint32_t stream_id);

/**
 * Get stream information for flow control
 * 
 * @param conn HTX connection
 * @param stream_id Stream identifier
 * @return Pointer to stream or NULL if not found
 */
htx_stream_t *htx_stream_get(htx_connection_t *conn, uint32_t stream_id);

// ============================================================================
// Frame Encoding API
// ============================================================================

/**
 * Encode STREAM frame with data payload
 * 
 * @param conn HTX connection
 * @param stream_id Target stream
 * @param data Payload data
 * @param data_len Length of payload
 * @param result Output encoded frame
 * @return HTX_OK on success, error code on failure
 */
int htx_frame_encode_stream(
    htx_connection_t *conn,
    uint32_t stream_id,
    const uint8_t *data,
    size_t data_len,
    htx_frame_encode_result_t *result
);

/**
 * Encode PING frame for keepalive/RTT measurement
 * 
 * @param conn HTX connection
 * @param ping_data Optional ping payload (8 bytes)
 * @param result Output encoded frame
 * @return HTX_OK on success, error code on failure
 */
int htx_frame_encode_ping(
    htx_connection_t *conn,
    const uint8_t *ping_data,
    htx_frame_encode_result_t *result
);

/**
 * Encode CLOSE frame for connection/stream termination
 * 
 * @param conn HTX connection
 * @param stream_id Stream to close (0 for connection)
 * @param error_code Reason for closure
 * @param result Output encoded frame
 * @return HTX_OK on success, error code on failure
 */
int htx_frame_encode_close(
    htx_connection_t *conn,
    uint32_t stream_id,
    uint32_t error_code,
    htx_frame_encode_result_t *result
);

/**
 * Encode KEY_UPDATE frame for key rotation
 * 
 * @param conn HTX connection
 * @param result Output encoded frame
 * @return HTX_OK on success, error code on failure
 */
int htx_frame_encode_key_update(
    htx_connection_t *conn,
    htx_frame_encode_result_t *result
);

/**
 * Encode WINDOW_UPDATE frame for flow control
 * 
 * @param conn HTX connection
 * @param stream_id Stream to update (0 for connection)
 * @param increment Window size increment
 * @param result Output encoded frame
 * @return HTX_OK on success, error code on failure
 */
int htx_frame_encode_window_update(
    htx_connection_t *conn,
    uint32_t stream_id,
    uint32_t increment,
    htx_frame_encode_result_t *result
);

// ============================================================================
// Frame Decoding API
// ============================================================================

/**
 * Decode incoming HTX frame from wire format
 * 
 * @param conn HTX connection
 * @param wire_data Serialized frame data
 * @param wire_len Length of wire data
 * @param result Output decoded frame and metadata
 * @return HTX_OK on success, error code on failure
 */
int htx_frame_decode(
    htx_connection_t *conn,
    const uint8_t *wire_data,
    size_t wire_len,
    htx_frame_decode_result_t *result
);

// ============================================================================
// Flow Control API
// ============================================================================

/**
 * Update flow control window for stream or connection
 * 
 * @param conn HTX connection
 * @param stream_id Stream ID (0 for connection-level)
 * @param bytes_consumed Number of bytes consumed
 * @return HTX_OK on success, error code on failure
 */
int htx_flow_control_consume(
    htx_connection_t *conn,
    uint32_t stream_id,
    uint32_t bytes_consumed
);

/**
 * Check if flow control allows sending data
 * 
 * @param conn HTX connection
 * @param stream_id Stream ID
 * @param data_len Amount of data to send
 * @return true if send is allowed, false if blocked
 */
bool htx_flow_control_can_send(
    const htx_connection_t *conn,
    uint32_t stream_id,
    size_t data_len
);

// ============================================================================
// Key Management API
// ============================================================================

/**
 * Check if key rotation is required
 * 
 * @param conn HTX connection
 * @return true if key update needed, false otherwise
 */
bool htx_crypto_needs_rekey(const htx_connection_t *conn);

/**
 * Perform key rotation with new derived keys
 * 
 * @param conn HTX connection
 * @param transcript_hash Hash of handshake transcript
 * @param transcript_len Length of transcript hash
 * @return HTX_OK on success, error code on failure
 */
int htx_crypto_rekey(
    htx_connection_t *conn,
    const uint8_t *transcript_hash,
    size_t transcript_len
);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get frame type name for debugging
 * 
 * @param type Frame type
 * @return Human-readable frame type name
 */
const char *htx_frame_type_name(htx_frame_type_t type);

/**
 * Validate stream ID for client/server role
 * 
 * @param stream_id Stream identifier
 * @param is_client Whether we are client side
 * @return true if stream ID is valid for role
 */
bool htx_stream_id_valid(uint32_t stream_id, bool is_client);

/**
 * Get connection statistics for monitoring
 * 
 * @param conn HTX connection
 * @param stats_json Output JSON string with statistics
 * @param json_len Maximum length of JSON buffer
 * @return HTX_OK on success, error code on failure
 */
int htx_connection_get_stats(
    const htx_connection_t *conn,
    char *stats_json,
    size_t json_len
);

// ============================================================================
// Memory Management
// ============================================================================

/**
 * Allocate frame encode result with proper cleanup
 * 
 * @param max_size Maximum frame size to allocate
 * @return Allocated result or NULL on failure
 */
htx_frame_encode_result_t *htx_frame_encode_result_alloc(size_t max_size);

/**
 * Free frame encode result and clear sensitive data
 * 
 * @param result Result to free
 */
void htx_frame_encode_result_free(htx_frame_encode_result_t *result);

/**
 * Free frame decode result and clear sensitive data
 * 
 * @param result Result to free
 */
void htx_frame_decode_result_free(htx_frame_decode_result_t *result);

#ifdef __cplusplus
}
#endif

#endif // BETANET_HTX_FRAMES_H
