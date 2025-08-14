/**
 * @file htx_transport.c
 * @brief HTX Transport Protocol Implementation (BetaNet §4.2 & §5.1)
 * 
 * Implements the HTX Transport Protocol that bridges SCION networking
 * with HTX application features, providing origin mirroring, automatic
 * failover, and resilient communication capabilities.
 */

#include "../../include/betanet/htx_transport.h"
#include "../../include/betanet/secure_utils.h"
#include "../../include/betanet/secure_log.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/time.h>
#include <arpa/inet.h>
#endif

// Default configuration values
static const htx_transport_config_t DEFAULT_CONFIG = {
    .origin_probe_interval = 10000,    // 10 seconds
    .path_probe_interval = 5000,       // 5 seconds
    .origin_failure_threshold = 0.7f,  // 70% failure rate triggers failover
    .path_failure_threshold = 0.5f,    // 50% failure rate triggers failover
    .adaptive_timeout_base = 1000,     // 1 second base timeout
    .enable_auto_calibration = true,
    .enable_multi_path = true
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get current timestamp in milliseconds
 */
static uint64_t get_timestamp_ms(void) {
#ifdef _WIN32
    FILETIME ft;
    ULARGE_INTEGER uli;
    GetSystemTimeAsFileTime(&ft);
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return (uli.QuadPart / 10000ULL) - 11644473600000ULL;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}

/**
 * Calculate reliability score based on success/failure history
 */
static float calculate_reliability_score(uint32_t success_count, uint32_t failure_count) {
    if (success_count + failure_count == 0) {
        return 1.0f; // Default to optimistic
    }
    return (float)success_count / (success_count + failure_count);
}

/**
 * Generate session ID
 */
static uint64_t generate_session_id(void) {
    // Simple timestamp + random-based ID generation
    // In a production implementation, this would use secure random
    uint64_t timestamp = get_timestamp_ms();
    uint64_t random_part = (uint64_t)rand() ^ ((uint64_t)rand() << 32);
    return timestamp ^ random_part;
}

// ============================================================================
// Core Transport Functions
// ============================================================================

htx_transport_session_t *htx_transport_create_session(const htx_transport_config_t *config) {
    htx_transport_session_t *session = calloc(1, sizeof(htx_transport_session_t));
    if (!session) {
        return NULL;
    }
    
    // Initialize session
    session->session_id = generate_session_id();
    session->state = HTX_TRANSPORT_DISCONNECTED;
    session->connection_start = get_timestamp_ms();
    session->last_activity = session->connection_start;
    
    // Set default configuration if none provided
    if (!config) {
        config = &DEFAULT_CONFIG;
    }
    
    // Initialize flow control windows
    session->send_window = 65536;      // 64KB default
    session->recv_window = 65536;      // 64KB default 
    session->congestion_window = 4096; // 4KB initial congestion window
    session->keepalive_interval = 30000; // 30 seconds
    
    // Initialize origins and paths arrays
    for (size_t i = 0; i < HTX_TRANSPORT_MAX_ORIGINS; i++) {
        session->origins[i].reliability_score = 1.0f;
    }
    
    for (size_t i = 0; i < HTX_TRANSPORT_MAX_PATHS; i++) {
        session->paths[i].loss_rate = 0.0f;
        session->paths[i].is_active = false;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Created session %016llX\n", (unsigned long long)session->session_id);
    return session;
}

void htx_transport_destroy_session(htx_transport_session_t *session) {
    if (!session) {
        return;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Destroying session %016llX\n", (unsigned long long)session->session_id);
    
    // Clean up ticket context
    if (session->ticket_ctx) {
        // Note: htx_ticket_cleanup would be called here in full implementation
        session->ticket_ctx = NULL;
    }
    
    // Clean up frame context  
    if (session->frame_ctx) {
        // Note: htx_frame_cleanup would be called here in full implementation
        session->frame_ctx = NULL;
    }
    
    // Clean up path templates
    for (size_t i = 0; i < session->path_count; i++) {
        if (session->paths[i].path_template) {
            scion_packet_cleanup(session->paths[i].path_template);
            free(session->paths[i].path_template);
            session->paths[i].path_template = NULL;
        }
    }
    
    secure_memset(session, 0, sizeof(*session));
    free(session);
}

htx_transport_result_t htx_transport_add_origin(htx_transport_session_t *session,
                                                uint64_t ia,
                                                const uint8_t *addr,
                                                uint8_t addr_len,
                                                uint16_t port) {
    if (!session || !addr || (addr_len != 4 && addr_len != 16)) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    if (session->origin_count >= HTX_TRANSPORT_MAX_ORIGINS) {
        return HTX_TRANSPORT_ERR_NO_MEMORY;
    }
    
    htx_origin_mirror_t *origin = &session->origins[session->origin_count];
    
    origin->ia = ia;
    secure_memcpy(origin->addr, sizeof(origin->addr), addr, addr_len);
    origin->addr_len = addr_len;
    origin->port = port;
    origin->is_active = true;
    origin->rtt_ms = 0;
    origin->failure_count = 0;
    origin->last_success = 0;
    origin->last_failure = 0;
    origin->reliability_score = 1.0f; // Start optimistic
    
    session->origin_count++;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Added origin %zu - IA:%016llX Port:%u\n", 
           session->origin_count - 1, (unsigned long long)ia, port);
    
    return HTX_TRANSPORT_SUCCESS;
}

htx_transport_result_t htx_transport_add_path(htx_transport_session_t *session,
                                              scion_packet_t *path_template) {
    if (!session || !path_template) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    if (session->path_count >= HTX_TRANSPORT_MAX_PATHS) {
        return HTX_TRANSPORT_ERR_NO_MEMORY;
    }
    
    // Validate the path template
    if (scion_validate_packet(path_template) != SCION_PACKET_VALID) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    htx_transport_path_t *transport_path = &session->paths[session->path_count];
    
    // Create a copy of the path template
    transport_path->path_template = malloc(sizeof(scion_packet_t));
    if (!transport_path->path_template) {
        return HTX_TRANSPORT_ERR_NO_MEMORY;
    }
    
    secure_memcpy(transport_path->path_template, sizeof(transport_path->path_template), path_template, sizeof(scion_packet_t));
    
    // Initialize path metrics
    transport_path->is_active = true;
    transport_path->latency_ms = 50;        // Default 50ms
    transport_path->bandwidth_kbps = 1000;  // Default 1Mbps
    transport_path->loss_rate = 0.0f;       // No loss initially
    transport_path->last_used = 0;
    transport_path->failure_count = 0;
    
    session->path_count++;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Added SCION path %zu - SrcIA:%016llX DstIA:%016llX\n",
           session->path_count - 1,
           (unsigned long long)path_template->addr_info.src_ia,
           (unsigned long long)path_template->addr_info.dst_ia);
    
    return HTX_TRANSPORT_SUCCESS;
}

htx_transport_result_t htx_transport_connect(htx_transport_session_t *session,
                                             const uint8_t *ticket_data,
                                             size_t ticket_len) {
    if (!session) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    if (session->origin_count == 0) {
        return HTX_TRANSPORT_ERR_NO_ORIGINS;
    }
    
    if (session->path_count == 0) {
        return HTX_TRANSPORT_ERR_NO_PATHS;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Establishing connection for session %016llX\n",
           (unsigned long long)session->session_id);
    
    session->state = HTX_TRANSPORT_CONNECTING;
    
    // Perform origin calibration to select best origin
    htx_transport_result_t result = htx_transport_calibrate_origins(session);
    if (result != HTX_TRANSPORT_SUCCESS) {
        session->state = HTX_TRANSPORT_FAILED;
        return result;
    }
    
    // Select best origin
    int best_origin = htx_transport_select_best_origin(session);
    if (best_origin < 0) {
        session->state = HTX_TRANSPORT_FAILED;
        return HTX_TRANSPORT_ERR_NO_ORIGINS;
    }
    session->active_origin_idx = (size_t)best_origin;
    
    // Select best path
    int best_path = htx_transport_select_best_path(session);
    if (best_path < 0) {
        session->state = HTX_TRANSPORT_FAILED;
        return HTX_TRANSPORT_ERR_NO_PATHS;
    }
    session->active_path_idx = (size_t)best_path;
    
    // In a full implementation, we would:
    // 1. Validate access ticket
    // 2. Establish SCION connection to selected origin
    // 3. Perform HTX handshake
    // 4. Initialize frame context
    
    // For now, simulate successful connection
    session->state = HTX_TRANSPORT_CONNECTED;
    session->connection_start = get_timestamp_ms();
    session->last_activity = session->connection_start;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Connected via origin %zu, path %zu\n",
           session->active_origin_idx, session->active_path_idx);
    
    return HTX_TRANSPORT_SUCCESS;
}

htx_transport_result_t htx_transport_send(htx_transport_session_t *session,
                                          const uint8_t *data,
                                          size_t data_len,
                                          uint32_t stream_id) {
    if (!session || !data || data_len == 0) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    if (session->state != HTX_TRANSPORT_CONNECTED && 
        session->state != HTX_TRANSPORT_DEGRADED) {
        return HTX_TRANSPORT_ERR_CONNECTION_FAILED;
    }
    
    // Check flow control
    if (data_len > session->send_window) {
        return HTX_TRANSPORT_ERR_NETWORK; // Flow control violation
    }
    
    // In a full implementation, we would:
    // 1. Fragment data if necessary
    // 2. Create HTX frames
    // 3. Encrypt with ChaCha20-Poly1305
    // 4. Encapsulate in SCION packets
    // 5. Send via active path to active origin
    // 6. Handle retransmissions and flow control
    
    // For now, simulate successful send
    session->bytes_sent += data_len;
    session->packets_sent++;
    session->last_activity = get_timestamp_ms();
    
    // Update flow control
    session->send_window = (session->send_window > data_len) ? 
                          session->send_window - data_len : 0;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Sent %zu bytes on stream %u\n", data_len, stream_id);
    
    return HTX_TRANSPORT_SUCCESS;
}

htx_transport_result_t htx_transport_receive(htx_transport_session_t *session,
                                             uint8_t *buffer,
                                             size_t buffer_size,
                                             size_t *received_len,
                                             uint32_t *stream_id) {
    if (!session || !buffer || buffer_size == 0 || !received_len) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    if (session->state != HTX_TRANSPORT_CONNECTED && 
        session->state != HTX_TRANSPORT_DEGRADED) {
        return HTX_TRANSPORT_ERR_CONNECTION_FAILED;
    }
    
    // In a full implementation, we would:
    // 1. Receive SCION packets
    // 2. Extract HTX frames
    // 3. Decrypt and validate
    // 4. Reassemble fragmented data
    // 5. Update flow control windows
    
    // For now, simulate no data available
    *received_len = 0;
    if (stream_id) {
        *stream_id = 0;
    }
    
    session->last_activity = get_timestamp_ms();
    
    return HTX_TRANSPORT_SUCCESS;
}

// ============================================================================
// Origin Mirroring Functions (§5.1)
// ============================================================================

htx_transport_result_t htx_transport_calibrate_origins(htx_transport_session_t *session) {
    if (!session || session->origin_count == 0) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Calibrating %zu origins\n", session->origin_count);
    
    uint64_t now = get_timestamp_ms();
    
    for (size_t i = 0; i < session->origin_count; i++) {
        htx_origin_mirror_t *origin = &session->origins[i];
        
        // In a full implementation, we would:
        // 1. Send ICMP ping or HTTP probe to origin
        // 2. Measure actual RTT
        // 3. Test connection establishment
        // 4. Update reliability metrics
        
        // For now, simulate probe with some variation
        uint32_t simulated_rtt = 20 + (rand() % 100); // 20-120ms range
        bool probe_success = (rand() % 100) > 10; // 90% success rate
        
        if (probe_success) {
            origin->rtt_ms = simulated_rtt;
            origin->last_success = now;
            origin->failure_count = 0;
            origin->is_active = true;
        } else {
            origin->failure_count++;
            origin->last_failure = now;
            
            // Mark as inactive after repeated failures
            if (origin->failure_count >= 3) {
                origin->is_active = false;
            }
        }
        
        // Update reliability score
        uint32_t success_count = probe_success ? 1 : 0;
        origin->reliability_score = calculate_reliability_score(
            success_count, origin->failure_count);
        
        BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Origin %zu - RTT:%ums Active:%s Reliability:%.2f\n",
               i, origin->rtt_ms, origin->is_active ? "Yes" : "No", origin->reliability_score);
    }
    
    return HTX_TRANSPORT_SUCCESS;
}

int htx_transport_select_best_origin(htx_transport_session_t *session) {
    if (!session || session->origin_count == 0) {
        return -1;
    }
    
    int best_idx = -1;
    float best_score = 0.0f;
    
    for (size_t i = 0; i < session->origin_count; i++) {
        htx_origin_mirror_t *origin = &session->origins[i];
        
        if (!origin->is_active) {
            continue;
        }
        
        // Calculate composite score: reliability weighted by RTT
        float rtt_factor = (origin->rtt_ms > 0) ? (1000.0f / origin->rtt_ms) : 1.0f;
        float composite_score = origin->reliability_score * rtt_factor;
        
        if (composite_score > best_score) {
            best_score = composite_score;
            best_idx = (int)i;
        }
    }
    
    if (best_idx >= 0) {
        BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Selected origin %d with score %.2f\n", best_idx, best_score);
    }
    
    return best_idx;
}

htx_transport_result_t htx_transport_failover_origin(htx_transport_session_t *session) {
    if (!session) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Transport: Performing origin failover\n");
    
    // Mark current origin as failed
    if (session->active_origin_idx < session->origin_count) {
        session->origins[session->active_origin_idx].failure_count++;
        session->origins[session->active_origin_idx].last_failure = get_timestamp_ms();
    }
    
    // Select new best origin
    int new_origin = htx_transport_select_best_origin(session);
    if (new_origin < 0) {
        session->state = HTX_TRANSPORT_FAILED;
        return HTX_TRANSPORT_ERR_NO_ORIGINS;
    }
    
    session->active_origin_idx = (size_t)new_origin;
    session->state = HTX_TRANSPORT_DEGRADED; // Mark as degraded during failover
    
    BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Transport: Failed over to origin %zu\n", session->active_origin_idx);
    
    return HTX_TRANSPORT_SUCCESS;
}

void htx_transport_update_origin_metrics(htx_transport_session_t *session,
                                         size_t origin_idx,
                                         bool success,
                                         uint32_t rtt_ms) {
    if (!session || origin_idx >= session->origin_count) {
        return;
    }
    
    htx_origin_mirror_t *origin = &session->origins[origin_idx];
    uint64_t now = get_timestamp_ms();
    
    if (success) {
        origin->rtt_ms = rtt_ms;
        origin->last_success = now;
        origin->failure_count = 0;
        origin->is_active = true;
    } else {
        origin->failure_count++;
        origin->last_failure = now;
        
        if (origin->failure_count >= 5) {
            origin->is_active = false;
        }
    }
    
    // Recalculate reliability score using exponential moving average
    float alpha = 0.1f; // Smoothing factor
    float new_sample = success ? 1.0f : 0.0f;
    origin->reliability_score = alpha * new_sample + (1.0f - alpha) * origin->reliability_score;
}

// ============================================================================
// Path Management Functions
// ============================================================================

htx_transport_result_t htx_transport_probe_paths(htx_transport_session_t *session) {
    if (!session || session->path_count == 0) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Probing %zu SCION paths\n", session->path_count);
    
    uint64_t now = get_timestamp_ms();
    
    for (size_t i = 0; i < session->path_count; i++) {
        htx_transport_path_t *path = &session->paths[i];
        
        // In a full implementation, we would:
        // 1. Send SCION path probe packets
        // 2. Measure actual latency and bandwidth
        // 3. Test path connectivity
        // 4. Update path metrics
        
        // For now, simulate probe with variation
        uint32_t simulated_latency = 30 + (rand() % 150); // 30-180ms range
        bool probe_success = (rand() % 100) > 5; // 95% success rate
        
        if (probe_success) {
            path->latency_ms = simulated_latency;
            path->last_used = now;
            path->failure_count = 0;
            path->is_active = true;
            path->loss_rate = (rand() % 100) / 10000.0f; // 0-1% loss
        } else {
            path->failure_count++;
            
            if (path->failure_count >= 3) {
                path->is_active = false;
            }
        }
        
        BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Path %zu - Latency:%ums Active:%s Loss:%.2f%%\n",
               i, path->latency_ms, path->is_active ? "Yes" : "No", 
               path->loss_rate * 100.0f);
    }
    
    return HTX_TRANSPORT_SUCCESS;
}

int htx_transport_select_best_path(htx_transport_session_t *session) {
    if (!session || session->path_count == 0) {
        return -1;
    }
    
    int best_idx = -1;
    float best_score = 0.0f;
    
    for (size_t i = 0; i < session->path_count; i++) {
        htx_transport_path_t *path = &session->paths[i];
        
        if (!path->is_active) {
            continue;
        }
        
        // Calculate composite score: latency and loss weighted
        float latency_factor = (path->latency_ms > 0) ? (1000.0f / path->latency_ms) : 1.0f;
        float loss_factor = 1.0f - path->loss_rate;
        float composite_score = latency_factor * loss_factor;
        
        if (composite_score > best_score) {
            best_score = composite_score;
            best_idx = (int)i;
        }
    }
    
    if (best_idx >= 0) {
        BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Transport: Selected path %d with score %.2f\n", best_idx, best_score);
    }
    
    return best_idx;
}

htx_transport_result_t htx_transport_failover_path(htx_transport_session_t *session) {
    if (!session) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Transport: Performing path failover\n");
    
    // Mark current path as failed
    if (session->active_path_idx < session->path_count) {
        session->paths[session->active_path_idx].failure_count++;
    }
    
    // Select new best path
    int new_path = htx_transport_select_best_path(session);
    if (new_path < 0) {
        return HTX_TRANSPORT_ERR_NO_PATHS;
    }
    
    session->active_path_idx = (size_t)new_path;
    
    BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Transport: Failed over to path %zu\n", session->active_path_idx);
    
    return HTX_TRANSPORT_SUCCESS;
}

// ============================================================================
// Utility Functions
// ============================================================================

htx_transport_result_t htx_transport_get_stats(const htx_transport_session_t *session,
                                               char *stats,
                                               size_t stats_size) {
    if (!session || !stats || stats_size == 0) {
        return HTX_TRANSPORT_ERR_INVALID_PARAM;
    }
    
    uint64_t now = get_timestamp_ms();
    uint64_t uptime = now - session->connection_start;
    
    int written = secure_snprintf(stats, stats_size, "{"
        "\"session_id\":\"%016llX\","
        "\"state\":\"%s\","
        "\"uptime_ms\":%llu,"
        "\"origins\":%zu,"
        "\"active_origin\":%zu,"
        "\"paths\":%zu,"
        "\"active_path\":%zu,"
        "\"bytes_sent\":%llu,"
        "\"bytes_received\":%llu,"
        "\"packets_sent\":%u,"
        "\"packets_received\":%u,"
        "\"retransmissions\":%u"
        "}",
        (unsigned long long)session->session_id,
        (session->state == HTX_TRANSPORT_CONNECTED) ? "connected" :
        (session->state == HTX_TRANSPORT_CONNECTING) ? "connecting" :
        (session->state == HTX_TRANSPORT_DEGRADED) ? "degraded" : "failed",
        (unsigned long long)uptime,
        session->origin_count,
        session->active_origin_idx,
        session->path_count,
        session->active_path_idx,
        (unsigned long long)session->bytes_sent,
        (unsigned long long)session->bytes_received,
        session->packets_sent,
        session->packets_received,
        session->retransmissions);
    
    return (written >= 0 && (size_t)written < stats_size) ? 
           HTX_TRANSPORT_SUCCESS : HTX_TRANSPORT_ERR_NO_MEMORY;
}

const char *htx_transport_result_to_string(htx_transport_result_t result) {
    switch (result) {
        case HTX_TRANSPORT_SUCCESS: return "Success";
        case HTX_TRANSPORT_ERR_INVALID_PARAM: return "Invalid parameter";
        case HTX_TRANSPORT_ERR_NO_MEMORY: return "Out of memory";
        case HTX_TRANSPORT_ERR_NO_ORIGINS: return "No available origins";
        case HTX_TRANSPORT_ERR_NO_PATHS: return "No available paths";
        case HTX_TRANSPORT_ERR_CONNECTION_FAILED: return "Connection failed";
        case HTX_TRANSPORT_ERR_TIMEOUT: return "Operation timed out";
        case HTX_TRANSPORT_ERR_NETWORK: return "Network error";
        case HTX_TRANSPORT_ERR_AUTH_FAILED: return "Authentication failed";
        case HTX_TRANSPORT_ERR_DEGRADED: return "Service degraded";
        default: return "Unknown error";
    }
}
