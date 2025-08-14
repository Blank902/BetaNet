/**
 * @file http2_emulation.h
 * @brief HTTP/2 Behavior Emulation Header (BetaNet §5.5)
 * 
 * This module provides adaptive HTTP/2 behavior emulation for traffic analysis
 * resistance by mirroring origin server patterns while maintaining plausible
 * variability through configurable tolerances and jitter.
 */

#ifndef BETANET_HTTP2_EMULATION_H
#define BETANET_HTTP2_EMULATION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants and Error Codes
// ============================================================================

#define HTTP2_EMULATION_SUCCESS              0
#define HTTP2_EMULATION_ERROR_INVALID_PARAM -1
#define HTTP2_EMULATION_ERROR_MEMORY        -2
#define HTTP2_EMULATION_ERROR_NETWORK       -3
#define HTTP2_EMULATION_ERROR_CONFIG        -4

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * SSL write function pointer type for sending data
 */
typedef int (*ssl_write_function_t)(void* ssl_context, const void* data, int length);

/**
 * HTTP/2 SETTINGS parameters structure
 */
typedef struct {
    uint32_t header_table_size;
    uint32_t enable_push;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
} http2_settings_t;

/**
 * Configuration for HTTP/2 behavior emulation
 */
typedef struct {
    // PING frame parameters
    uint32_t ping_base_interval_ms;     // Base PING interval (default: 30000ms)
    uint8_t ping_jitter_percent;        // Jitter percentage (default: 15%)
    
    // SETTINGS mirroring parameters
    uint8_t settings_tolerance_percent; // Tolerance for SETTINGS values (default: 10%)
    
    // PRIORITY frame parameters
    float priority_baseline_rate;       // Baseline PRIORITY emission rate (default: 0.01)
    
    // Idle padding parameters
    uint32_t idle_padding_min_delay_ms; // Min delay before idle padding (default: 200ms)
    uint32_t idle_padding_max_delay_ms; // Max delay for idle padding (default: 1200ms)
    uint32_t max_idle_padding_bytes;    // Max padding bytes per frame (default: 3072)
    
    // Adaptive behavior flags
    bool enable_adaptive_settings;      // Enable SETTINGS adaptation
    bool enable_adaptive_ping;          // Enable PING cadence adaptation
    bool enable_adaptive_priority;      // Enable PRIORITY emission adaptation
    bool enable_idle_padding;           // Enable idle connection padding
} http2_emulation_config_t;

/**
 * Observed origin behavior for learning
 */
typedef struct {
    http2_settings_t observed_settings; // SETTINGS values from origin
    uint32_t avg_ping_interval_ms;      // Average PING interval observed
    float priority_emission_rate;       // Rate of PRIORITY frame emission
    uint32_t avg_idle_padding_bytes;    // Average idle padding observed
    bool has_valid_data;                // Whether the data is valid
} http2_origin_behavior_t;

/**
 * Statistics for HTTP/2 emulation
 */
typedef struct {
    uint64_t total_frames_sent;         // Total frames sent
    uint64_t settings_frames_sent;      // SETTINGS frames sent
    uint64_t ping_frames_sent;          // PING frames sent
    uint64_t priority_frames_sent;      // PRIORITY frames sent
    uint64_t idle_padding_frames_sent;  // Idle padding frames sent
    uint64_t total_idle_padding_bytes;  // Total idle padding bytes sent
    uint64_t origin_adaptations;        // Number of origin adaptations
    uint64_t behavior_updates;          // Number of behavior updates
} http2_emulation_stats_t;

/**
 * Runtime behavior update
 */
typedef struct {
    uint32_t new_ping_interval_ms;      // New PING interval (0 = no change)
    float new_priority_rate;            // New PRIORITY rate (-1 = no change)
} http2_behavior_update_t;

/**
 * HTTP/2 emulation context
 */
typedef struct {
    // Configuration
    http2_emulation_config_t config;
    
    // Current behavior baseline
    http2_settings_t baseline_settings;
    
    // Timing state
    uint64_t last_ping_time;
    uint32_t next_ping_interval;
    uint32_t learned_ping_interval;
    
    uint64_t last_priority_time;
    uint32_t next_priority_check;
    float priority_emission_rate;
    
    uint64_t last_idle_padding_time;
    
    // Adaptation state
    bool has_learned_behavior;
    
    // Statistics
    http2_emulation_stats_t stats;
    
    // Internal state
    bool is_initialized;
} http2_emulation_context_t;

// ============================================================================
// Core API Functions
// ============================================================================

/**
 * Initialize HTTP/2 emulation context
 * 
 * @param ctx Output context to initialize
 * @param config Configuration parameters
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_init(http2_emulation_context_t* ctx, 
                        const http2_emulation_config_t* config);

/**
 * Destroy HTTP/2 emulation context and clear sensitive data
 * 
 * @param ctx Context to destroy
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_destroy(http2_emulation_context_t* ctx);

/**
 * Learn behavior patterns from origin server
 * 
 * @param ctx Emulation context
 * @param behavior Observed origin behavior
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_learn_from_origin(http2_emulation_context_t* ctx,
                                     const http2_origin_behavior_t* behavior);

// ============================================================================
// Frame Emission Functions
// ============================================================================

/**
 * Send HTTP/2 SETTINGS frame with current baseline parameters
 * 
 * @param ctx Emulation context
 * @param ssl_write_func Function to write data to SSL connection
 * @param ssl_context SSL context for write function
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_send_settings(http2_emulation_context_t* ctx,
                                 ssl_write_function_t ssl_write_func,
                                 void* ssl_context);

/**
 * Send PING frame if timing conditions are met
 * 
 * @param ctx Emulation context
 * @param ssl_write_func Function to write data to SSL connection
 * @param ssl_context SSL context for write function
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_maybe_send_ping(http2_emulation_context_t* ctx,
                                   ssl_write_function_t ssl_write_func,
                                   void* ssl_context);

/**
 * Send PRIORITY frame based on emission rate
 * 
 * @param ctx Emulation context
 * @param ssl_write_func Function to write data to SSL connection
 * @param ssl_context SSL context for write function
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_maybe_send_priority(http2_emulation_context_t* ctx,
                                       ssl_write_function_t ssl_write_func,
                                       void* ssl_context);

/**
 * Send idle padding frame during connection idle periods
 * 
 * @param ctx Emulation context
 * @param ssl_write_func Function to write data to SSL connection
 * @param ssl_context SSL context for write function
 * @param last_data_time Timestamp of last data transmission
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_maybe_send_idle_padding(http2_emulation_context_t* ctx,
                                           ssl_write_function_t ssl_write_func,
                                           void* ssl_context,
                                           uint64_t last_data_time);

// ============================================================================
// Monitoring and Control Functions
// ============================================================================

/**
 * Get current emulation statistics
 * 
 * @param ctx Emulation context
 * @param stats Output statistics structure
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_get_stats(const http2_emulation_context_t* ctx,
                             http2_emulation_stats_t* stats);

/**
 * Update behavior parameters at runtime
 * 
 * @param ctx Emulation context
 * @param update New behavior parameters
 * @return HTTP2_EMULATION_SUCCESS on success, error code on failure
 */
int http2_emulation_update_behavior(http2_emulation_context_t* ctx,
                                   const http2_behavior_update_t* update);

// ============================================================================
// Helper Macros
// ============================================================================

/**
 * Default configuration initializer
 */
#define HTTP2_EMULATION_DEFAULT_CONFIG() {                      \
    .ping_base_interval_ms = 30000,      /* 30 seconds */      \
    .ping_jitter_percent = 15,           /* ±15% jitter */     \
    .settings_tolerance_percent = 10,    /* ±10% tolerance */  \
    .priority_baseline_rate = 0.01f,     /* 1% emission rate */ \
    .idle_padding_min_delay_ms = 200,    /* 200ms min delay */ \
    .idle_padding_max_delay_ms = 1200,   /* 1200ms max delay */ \
    .max_idle_padding_bytes = 3072,      /* Max 3KB padding */ \
    .enable_adaptive_settings = true,                          \
    .enable_adaptive_ping = true,                              \
    .enable_adaptive_priority = true,                          \
    .enable_idle_padding = true                                \
}

/**
 * Check if emulation context is initialized
 */
#define HTTP2_EMULATION_IS_INITIALIZED(ctx) ((ctx) && (ctx)->is_initialized)

#ifdef __cplusplus
}
#endif

#endif /* BETANET_HTTP2_EMULATION_H */
