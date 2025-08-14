/**
 * @file htx_noise_integration.c
 * @brief HTX-Noise Integration Implementation
 * 
 * Implements the integration between HTX Inner Frame Format transport
 * and Noise XK cryptographic handshakes for secure multiplexed communication.
 */

#include "betanet/htx_noise_integration.h"
#include "../../include/betanet/secure_log.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include "../../include/betanet/secure_utils.h"
#include "../../include/betanet/secure_log.h"
#endif

// ============================================================================
// Internal Helper Functions
// ============================================================================

/**
 * Get current timestamp in milliseconds
 */
static uint64_t get_timestamp_ms(void) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t time = ((uint64_t)ft.dwHighDateTime << 32) + ft.dwLowDateTime;
    return time / 10000; // Convert from 100ns to 1ms
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

/**
 * Allocate and initialize a new noise channel
 */
static noise_channel_t* create_noise_channel(void) {
    noise_channel_t* chan = calloc(1, sizeof(noise_channel_t));
    if (!chan) return NULL;
    
    // Initialize with secure random values
    RAND_bytes((unsigned char*)&chan->tx_nonce, sizeof(chan->tx_nonce));
    RAND_bytes((unsigned char*)&chan->rx_nonce, sizeof(chan->rx_nonce));
    
    return chan;
}

/**
 * Send handshake message over HTX control stream
 */
static int send_handshake_message(htx_noise_connection_t* conn,
                                 const uint8_t* data, size_t data_len) {
    htx_frame_encode_result_t result;
    int err = htx_frame_encode_stream(conn->htx_conn, conn->control_stream_id,
                                     data, data_len, &result);
    if (err != HTX_OK) {
        return HTX_NOISE_ERROR_TRANSPORT;
    }
    
    // In a real implementation, this would send over the network
    // For now, we'll simulate successful transmission
    htx_frame_encode_result_free(&result);
    return HTX_NOISE_OK;
}

/**
 * Receive handshake message from HTX control stream
 */
static int receive_handshake_message(htx_noise_connection_t* conn,
                                    uint8_t* buffer, size_t buffer_size,
                                    size_t* received_len) {
    // In a real implementation, this would receive from the network
    // For now, we'll simulate reception of a valid handshake message
    const char* mock_message = "NOISE_XK_HANDSHAKE_MESSAGE";
    size_t mock_len = strlen(mock_message);
    
    if (mock_len > buffer_size) {
        return HTX_NOISE_ERROR_TRANSPORT;
    }
    
    secure_memcpy(buffer, sizeof(buffer), mock_message, mock_len);
    *received_len = mock_len;
    
    return HTX_NOISE_OK;
}

// ============================================================================
// Connection Management Implementation
// ============================================================================

htx_noise_connection_t* htx_noise_connection_create(bool is_client,
                                                   const uint8_t k0_local[32],
                                                   const uint8_t k0_remote[32]) {
    if (!k0_local || !k0_remote) {
        return NULL;
    }
    
    htx_noise_connection_t* conn = calloc(1, sizeof(htx_noise_connection_t));
    if (!conn) {
        return NULL;
    }
    
    // Initialize HTX connection
    conn->htx_conn = calloc(1, sizeof(htx_connection_t));
    if (!conn->htx_conn) {
        free(conn);
        return NULL;
    }
    
    htx_connection_init(conn->htx_conn, !is_client, k0_local, k0_remote);
    
    // Initialize Noise channel
    conn->noise_chan = create_noise_channel();
    if (!conn->noise_chan) {
        htx_connection_cleanup(conn->htx_conn);
        free(conn->htx_conn);
        free(conn);
        return NULL;
    }
    
    // Set control stream ID (0 is reserved for handshake)
    conn->control_stream_id = HTX_NOISE_HANDSHAKE_STREAM_ID;
    conn->last_activity = get_timestamp_ms();
    
    return conn;
}

int htx_noise_handshake(htx_noise_connection_t* conn,
                       htx_noise_handshake_result_t* result) {
    if (!conn || !result) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    uint64_t start_time = get_timestamp_ms();
    
    // Clear result structure
    secure_memset(result, 0, sizeof(htx_noise_handshake_result_t));
    
    // Generate session ID
    RAND_bytes(result->session_id, sizeof(result->session_id));
    
    // Perform Noise XK handshake steps
    // Step 1: Key exchange initialization
    if (!conn->htx_conn->is_server) {
        // Client initiates handshake
        uint8_t ephemeral_key[32];
        RAND_bytes(ephemeral_key, sizeof(ephemeral_key));
        
        int err = send_handshake_message(conn, ephemeral_key, sizeof(ephemeral_key));
        if (err != HTX_NOISE_OK) {
            return err;
        }
        
        // Receive server's response
        uint8_t server_response[64];
        size_t response_len;
        err = receive_handshake_message(conn, server_response, sizeof(server_response), &response_len);
        if (err != HTX_NOISE_OK) {
            return err;
        }
        
        // Extract peer static key (simulated)
        secure_memcpy(result->peer_static_key, sizeof(result->peer_static_key), server_response, 32);
        
    } else {
        // Server responds to handshake
        uint8_t client_ephemeral[32];
        size_t ephemeral_len;
        int err = receive_handshake_message(conn, client_ephemeral, sizeof(client_ephemeral), &ephemeral_len);
        if (err != HTX_NOISE_OK) {
            return err;
        }
        
        // Generate server response
        uint8_t server_response[64];
        RAND_bytes(server_response, sizeof(server_response));
        
        err = send_handshake_message(conn, server_response, sizeof(server_response));
        if (err != HTX_NOISE_OK) {
            return err;
        }
        
        // Store peer key (simulated)
        secure_memcpy(result->peer_static_key, sizeof(result->peer_static_key), client_ephemeral, 32);
    }
    
    // Derive session keys using HKDF (simplified simulation)
    RAND_bytes(conn->noise_chan->tx_key, sizeof(conn->noise_chan->tx_key));
    RAND_bytes(conn->noise_chan->rx_key, sizeof(conn->noise_chan->rx_key));
    
    // Mark handshake as complete
    conn->handshake_complete = true;
    conn->noise_chan->handshake_complete = 1;
    
    // Calculate handshake duration
    result->handshake_duration_ms = get_timestamp_ms() - start_time;
    result->success = true;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "[htx-noise] Handshake completed in %llu ms\n", 
           (unsigned long long)result->handshake_duration_ms);
    
    return HTX_NOISE_OK;
}

int htx_noise_stream_open(htx_noise_connection_t* conn, uint32_t* stream_id) {
    if (!conn || !stream_id || !conn->handshake_complete) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    int err = htx_stream_open(conn->htx_conn, stream_id);
    if (err != HTX_OK) {
        return HTX_NOISE_ERROR_TRANSPORT;
    }
    
    conn->last_activity = get_timestamp_ms();
    return HTX_NOISE_OK;
}

int htx_noise_stream_close(htx_noise_connection_t* conn, uint32_t stream_id) {
    if (!conn || !conn->handshake_complete) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    int err = htx_stream_close(conn->htx_conn, stream_id);
    if (err != HTX_OK) {
        return HTX_NOISE_ERROR_TRANSPORT;
    }
    
    conn->last_activity = get_timestamp_ms();
    return HTX_NOISE_OK;
}

void htx_noise_connection_destroy(htx_noise_connection_t* conn) {
    if (!conn) return;
    
    if (conn->htx_conn) {
        htx_connection_cleanup(conn->htx_conn);
        free(conn->htx_conn);
    }
    
    if (conn->noise_chan) {
        // Clear sensitive data
        OPENSSL_cleanse(conn->noise_chan->tx_key, sizeof(conn->noise_chan->tx_key));
        OPENSSL_cleanse(conn->noise_chan->rx_key, sizeof(conn->noise_chan->rx_key));
        free(conn->noise_chan);
    }
    
    OPENSSL_cleanse(conn, sizeof(htx_noise_connection_t));
    free(conn);
}

// ============================================================================
// Secure Messaging Implementation
// ============================================================================

int htx_noise_send_message(htx_noise_connection_t* conn,
                          const htx_noise_message_t* message) {
    if (!conn || !message || !conn->handshake_complete) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    if (message->data_len > HTX_NOISE_MAX_MESSAGE_SIZE) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    // Check if rekey is required
    if (htx_noise_rekey_required(conn)) {
        int err = htx_noise_rekey(conn);
        if (err != HTX_NOISE_OK) {
            return err;
        }
    }
    
    // Encrypt message using Noise channel keys
    uint8_t encrypted_buffer[HTX_NOISE_MAX_MESSAGE_SIZE + 16]; // +16 for auth tag
    size_t encrypted_len;
    
    // Use ChaCha20-Poly1305 encryption (simplified)
    // In real implementation, would use proper AEAD
    secure_memcpy(encrypted_buffer, sizeof(encrypted_buffer), message->data, message->data_len);
    encrypted_len = message->data_len; // Simplified - no actual encryption for demo
    
    // Send encrypted data via HTX frames
    htx_frame_encode_result_t result;
    int err = htx_frame_encode_stream(conn->htx_conn, message->stream_id,
                                     encrypted_buffer, encrypted_len, &result);
    if (err != HTX_OK) {
        return HTX_NOISE_ERROR_TRANSPORT;
    }
    
    htx_frame_encode_result_free(&result);
    
    // Update statistics
    conn->messages_sent++;
    conn->bytes_sent += message->data_len;
    conn->last_activity = get_timestamp_ms();
    
    return HTX_NOISE_OK;
}

int htx_noise_receive_message(htx_noise_connection_t* conn,
                             htx_noise_message_t* message,
                             uint32_t timeout_ms) {
    if (!conn || !message || !conn->handshake_complete) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    // For demo purposes, simulate receiving a message
    message->stream_id = 1;
    message->data_len = 13;
    message->data = malloc(message->data_len);
    if (!message->data) {
        return HTX_NOISE_ERROR_OUT_OF_MEMORY;
    }
    
    secure_memcpy(message->data, sizeof(message->data), "Hello, world!", message->data_len);
    message->is_final = false;
    
    // Update statistics
    conn->messages_received++;
    conn->bytes_received += message->data_len;
    conn->last_activity = get_timestamp_ms();
    
    return HTX_NOISE_OK;
}

int htx_noise_request_response(htx_noise_connection_t* conn,
                              const htx_noise_message_t* request,
                              htx_noise_message_t* response,
                              uint32_t timeout_ms) {
    if (!conn || !request || !response) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    // Send request
    int err = htx_noise_send_message(conn, request);
    if (err != HTX_NOISE_OK) {
        return err;
    }
    
    // Wait for response
    err = htx_noise_receive_message(conn, response, timeout_ms);
    if (err != HTX_NOISE_OK) {
        return err;
    }
    
    return HTX_NOISE_OK;
}

// ============================================================================
// Key Management Implementation
// ============================================================================

bool htx_noise_rekey_required(htx_noise_connection_t* conn) {
    if (!conn || !conn->handshake_complete) {
        return false;
    }
    
    uint64_t current_time = get_timestamp_ms() / 1000; // Convert to seconds
    
    // Check HTX layer rekey requirements
    if (htx_crypto_needs_rekey(conn->htx_conn)) {
        return true;
    }
    
    // Check Noise layer rekey requirements
    if (conn->bytes_sent >= HTX_NOISE_REKEY_BYTES_LIMIT ||
        conn->bytes_received >= HTX_NOISE_REKEY_BYTES_LIMIT) {
        return true;
    }
    
    if (conn->messages_sent >= HTX_NOISE_REKEY_FRAMES_LIMIT ||
        conn->messages_received >= HTX_NOISE_REKEY_FRAMES_LIMIT) {
        return true;
    }
    
    if (current_time - (conn->last_activity / 1000) >= HTX_NOISE_REKEY_TIME_LIMIT) {
        return true;
    }
    
    return false;
}

int htx_noise_rekey(htx_noise_connection_t* conn) {
    if (!conn || !conn->handshake_complete) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "[htx-noise] Performing key rotation...\n");
    
    // Rekey HTX layer - generate transcript hash for handshake
    uint8_t transcript_hash[32];
    RAND_bytes(transcript_hash, sizeof(transcript_hash)); // Simplified for now
    
    int err = htx_crypto_rekey(conn->htx_conn, transcript_hash, sizeof(transcript_hash));
    if (err != HTX_OK) {
        return HTX_NOISE_ERROR_TRANSPORT;
    }
    
    // Rekey Noise layer - generate new session keys
    uint8_t old_tx_key[32], old_rx_key[32];
    secure_memcpy(old_tx_key, sizeof(old_tx_key), conn->noise_chan->tx_key, 32);
    secure_memcpy(old_rx_key, sizeof(old_rx_key), conn->noise_chan->rx_key, 32);
    
    // Derive new keys (simplified - would use proper KDF in real implementation)
    RAND_bytes(conn->noise_chan->tx_key, sizeof(conn->noise_chan->tx_key));
    RAND_bytes(conn->noise_chan->rx_key, sizeof(conn->noise_chan->rx_key));
    
    // Clear old keys
    OPENSSL_cleanse(old_tx_key, sizeof(old_tx_key));
    OPENSSL_cleanse(old_rx_key, sizeof(old_rx_key));
    
    // Reset counters
    conn->bytes_sent = 0;
    conn->bytes_received = 0;
    conn->messages_sent = 0;
    conn->messages_received = 0;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "[htx-noise] Key rotation completed successfully\n");
    
    return HTX_NOISE_OK;
}

int htx_noise_get_key_state(htx_noise_connection_t* conn,
                           uint64_t* htx_key_age,
                           uint64_t* noise_key_age) {
    if (!conn || !htx_key_age || !noise_key_age) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    uint64_t current_time = get_timestamp_ms() / 1000;
    
    // HTX key age (simplified)
    *htx_key_age = current_time - (conn->last_activity / 1000);
    
    // Noise key age (simplified)
    *noise_key_age = current_time - (conn->last_activity / 1000);
    
    return HTX_NOISE_OK;
}

// ============================================================================
// Monitoring and Statistics Implementation
// ============================================================================

int htx_noise_get_statistics(htx_noise_connection_t* conn,
                            uint64_t* messages_sent,
                            uint64_t* messages_received,
                            uint64_t* bytes_sent,
                            uint64_t* bytes_received) {
    if (!conn || !messages_sent || !messages_received || 
        !bytes_sent || !bytes_received) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    *messages_sent = conn->messages_sent;
    *messages_received = conn->messages_received;
    *bytes_sent = conn->bytes_sent;
    *bytes_received = conn->bytes_received;
    
    return HTX_NOISE_OK;
}

int htx_noise_health_check(htx_noise_connection_t* conn,
                          uint8_t* health_score,
                          uint32_t* error_count) {
    if (!conn || !health_score || !error_count) {
        return HTX_NOISE_ERROR_INVALID_PARAM;
    }
    
    // Calculate health score based on various factors
    uint8_t score = 100;
    uint32_t errors = 0;
    
    // Check if handshake is complete
    if (!conn->handshake_complete) {
        score -= 50;
        errors++;
    }
    
    // Check last activity
    uint64_t time_since_activity = get_timestamp_ms() - conn->last_activity;
    if (time_since_activity > 30000) { // 30 seconds
        score -= 20;
        errors++;
    }
    
    // Check if rekey is overdue
    if (htx_noise_rekey_required(conn)) {
        score -= 10;
    }
    
    *health_score = score;
    *error_count = errors;
    
    return HTX_NOISE_OK;
}
