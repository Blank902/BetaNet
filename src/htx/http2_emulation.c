/**
 * @file http2_emulation.c
 * @brief HTTP/2 Behavior Emulation Implementation (BetaNet §5.5)
 * 
 * This module implements adaptive HTTP/2 behavior emulation that mirrors the
 * origin's traffic patterns to maintain indistinguishability and avoid 
 * traffic analysis detection.
 * 
 * Key Features:
 * - Origin SETTINGS mirroring with configurable tolerances
 * - Adaptive PING cadence with randomized intervals
 * - PRIORITY frame emission matching origin patterns
 * - Dynamic idle padding and traffic shaping
 * - Real-time adaptation based on observed behavior
 */

#include "../../include/betanet/http2_emulation.h"
#include "../../include/betanet/secure_utils.h"
#include "../shape/shape.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "../../include/betanet/secure_log.h"

// ============================================================================
// HTTP/2 Frame Types and Constants
// ============================================================================

#define HTTP2_FRAME_DATA         0x00
#define HTTP2_FRAME_HEADERS      0x01
#define HTTP2_FRAME_PRIORITY     0x02
#define HTTP2_FRAME_RST_STREAM   0x03
#define HTTP2_FRAME_SETTINGS     0x04
#define HTTP2_FRAME_PUSH_PROMISE 0x05
#define HTTP2_FRAME_PING         0x06
#define HTTP2_FRAME_GOAWAY       0x07
#define HTTP2_FRAME_WINDOW_UPDATE 0x08
#define HTTP2_FRAME_CONTINUATION 0x09

#define HTTP2_SETTING_HEADER_TABLE_SIZE      0x01
#define HTTP2_SETTING_ENABLE_PUSH           0x02
#define HTTP2_SETTING_MAX_CONCURRENT_STREAMS 0x03
#define HTTP2_SETTING_INITIAL_WINDOW_SIZE   0x04
#define HTTP2_SETTING_MAX_FRAME_SIZE        0x05
#define HTTP2_SETTING_MAX_HEADER_LIST_SIZE  0x06

// ============================================================================
// Internal Data Structures
// ============================================================================

// HTTP/2 frame header structure
typedef struct {
    uint32_t length;    // 24-bit length
    uint8_t type;       // Frame type
    uint8_t flags;      // Frame flags
    uint32_t stream_id; // 31-bit stream ID
} http2_frame_header_t;

// SETTINGS parameter
typedef struct {
    uint16_t id;
    uint32_t value;
} http2_setting_t;

// Priority parameters
typedef struct {
    uint32_t stream_dependency;
    uint8_t weight;
    bool exclusive;
} http2_priority_t;

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get current timestamp in milliseconds
 */
static uint64_t get_current_time_ms(void) {
    return (uint64_t)time(NULL) * 1000;
}

/**
 * Generate random number in range [min, max]
 */
static uint32_t random_range(uint32_t min, uint32_t max) {
    if (min >= max) return min;
    return min + (rand() % (max - min + 1));
}

/**
 * Add jitter to a base value (±percentage)
 */
static uint32_t add_jitter(uint32_t base, uint8_t jitter_percent) {
    if (jitter_percent == 0) return base;
    
    uint32_t jitter = (base * jitter_percent) / 100;
    uint32_t min_val = base > jitter ? base - jitter : 0;
    uint32_t max_val = base + jitter;
    
    return random_range(min_val, max_val);
}

/**
 * Encode HTTP/2 frame header (9 bytes)
 */
static void encode_frame_header(const http2_frame_header_t* header, uint8_t* output) {
    // Length (24 bits)
    output[0] = (header->length >> 16) & 0xFF;
    output[1] = (header->length >> 8) & 0xFF;
    output[2] = header->length & 0xFF;
    
    // Type (8 bits)
    output[3] = header->type;
    
    // Flags (8 bits)
    output[4] = header->flags;
    
    // Stream ID (31 bits, R bit = 0)
    output[5] = (header->stream_id >> 24) & 0x7F;
    output[6] = (header->stream_id >> 16) & 0xFF;
    output[7] = (header->stream_id >> 8) & 0xFF;
    output[8] = header->stream_id & 0xFF;
}

/**
 * Encode HTTP/2 SETTINGS parameter
 */
static void encode_setting(const http2_setting_t* setting, uint8_t* output) {
    // Setting ID (16 bits)
    output[0] = (setting->id >> 8) & 0xFF;
    output[1] = setting->id & 0xFF;
    
    // Setting Value (32 bits)
    output[2] = (setting->value >> 24) & 0xFF;
    output[3] = (setting->value >> 16) & 0xFF;
    output[4] = (setting->value >> 8) & 0xFF;
    output[5] = setting->value & 0xFF;
}

// ============================================================================
// HTTP/2 Emulation API Implementation
// ============================================================================

int http2_emulation_init(http2_emulation_context_t* ctx, 
                        const http2_emulation_config_t* config) {
    if (!ctx || !config) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    secure_memset(ctx, 0, sizeof(http2_emulation_context_t));
    
    // Copy configuration
    if (secure_memcpy(&ctx->config, sizeof(ctx->config), config, sizeof(http2_emulation_config_t)) != SECURE_ERROR_NONE) {
        return HTTP2_EMULATION_ERROR_MEMORY;
    }
    
    // Initialize baseline behavior
    ctx->baseline_settings.header_table_size = 4096;
    ctx->baseline_settings.enable_push = 0;
    ctx->baseline_settings.max_concurrent_streams = 100;
    ctx->baseline_settings.initial_window_size = 65535;
    ctx->baseline_settings.max_frame_size = 16384;
    ctx->baseline_settings.max_header_list_size = 8192;
    
    // Initialize timing parameters
    ctx->last_ping_time = get_current_time_ms();
    ctx->next_ping_interval = add_jitter(config->ping_base_interval_ms, config->ping_jitter_percent);
    
    ctx->last_priority_time = get_current_time_ms();
    ctx->next_priority_check = random_range(1000, 5000); // Check in 1-5 seconds
    
    ctx->last_idle_padding_time = get_current_time_ms();
    
    // Initialize priority emission rate
    ctx->priority_emission_rate = config->priority_baseline_rate;
    
    ctx->is_initialized = true;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Initialized context with adaptive behavior\n");
    return HTTP2_EMULATION_SUCCESS;
}

int http2_emulation_destroy(http2_emulation_context_t* ctx) {
    if (!ctx) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Destroying context with %llu frames sent\n", 
           (unsigned long long)ctx->stats.total_frames_sent);
    
    // Clear sensitive data
    secure_memset(ctx, sizeof(http2_emulation_context_t), 0);
    
    return HTTP2_EMULATION_SUCCESS;
}

int http2_emulation_learn_from_origin(http2_emulation_context_t* ctx,
                                     const http2_origin_behavior_t* behavior) {
    if (!ctx || !behavior) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Learning behavior from origin\n");
    
    // Apply origin SETTINGS with tolerance
    uint32_t tolerance_percent = ctx->config.settings_tolerance_percent;
    
    if (behavior->observed_settings.header_table_size > 0) {
        uint32_t base = behavior->observed_settings.header_table_size;
        uint32_t min_val = base * (100 - tolerance_percent) / 100;
        uint32_t max_val = base * (100 + tolerance_percent) / 100;
        ctx->baseline_settings.header_table_size = random_range(min_val, max_val);
    }
    
    if (behavior->observed_settings.max_concurrent_streams > 0) {
        uint32_t base = behavior->observed_settings.max_concurrent_streams;
        uint32_t min_val = base * (100 - tolerance_percent) / 100;
        uint32_t max_val = base * (100 + tolerance_percent) / 100;
        ctx->baseline_settings.max_concurrent_streams = random_range(min_val, max_val);
    }
    
    if (behavior->observed_settings.initial_window_size > 0) {
        uint32_t base = behavior->observed_settings.initial_window_size;
        uint32_t min_val = base * (100 - tolerance_percent) / 100;
        uint32_t max_val = base * (100 + tolerance_percent) / 100;
        ctx->baseline_settings.initial_window_size = random_range(min_val, max_val);
    }
    
    if (behavior->observed_settings.max_frame_size > 0) {
        uint32_t base = behavior->observed_settings.max_frame_size;
        uint32_t min_val = base * (100 - tolerance_percent) / 100;
        uint32_t max_val = base * (100 + tolerance_percent) / 100;
        ctx->baseline_settings.max_frame_size = random_range(min_val, max_val);
    }
    
    // Learn PING cadence
    if (behavior->avg_ping_interval_ms > 0) {
        ctx->learned_ping_interval = behavior->avg_ping_interval_ms;
        ctx->next_ping_interval = add_jitter(ctx->learned_ping_interval, 
                                            ctx->config.ping_jitter_percent);
    }
    
    // Learn PRIORITY emission rate
    if (behavior->priority_emission_rate > 0.0f) {
        ctx->priority_emission_rate = behavior->priority_emission_rate;
        // Add some randomness to avoid perfect correlation
        float jitter = (float)(rand() % 30 - 15) / 1000.0f; // ±1.5%
        ctx->priority_emission_rate += jitter;
        if (ctx->priority_emission_rate < 0.0f) ctx->priority_emission_rate = 0.0f;
        if (ctx->priority_emission_rate > 0.05f) ctx->priority_emission_rate = 0.05f;
    }
    
    ctx->has_learned_behavior = true;
    ctx->stats.origin_adaptations++;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Adapted to origin - PING: %ums, PRIORITY rate: %.3f%%\n",
           ctx->next_ping_interval, ctx->priority_emission_rate * 100.0f);
    
    return HTTP2_EMULATION_SUCCESS;
}

int http2_emulation_send_settings(http2_emulation_context_t* ctx,
                                 ssl_write_function_t ssl_write_func,
                                 void* ssl_context) {
    if (!ctx || !ssl_write_func) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    // Prepare SETTINGS frame
    http2_setting_t settings[] = {
        {HTTP2_SETTING_HEADER_TABLE_SIZE, ctx->baseline_settings.header_table_size},
        {HTTP2_SETTING_ENABLE_PUSH, ctx->baseline_settings.enable_push},
        {HTTP2_SETTING_MAX_CONCURRENT_STREAMS, ctx->baseline_settings.max_concurrent_streams},
        {HTTP2_SETTING_INITIAL_WINDOW_SIZE, ctx->baseline_settings.initial_window_size},
        {HTTP2_SETTING_MAX_FRAME_SIZE, ctx->baseline_settings.max_frame_size},
        {HTTP2_SETTING_MAX_HEADER_LIST_SIZE, ctx->baseline_settings.max_header_list_size}
    };
    
    size_t num_settings = sizeof(settings) / sizeof(settings[0]);
    size_t payload_len = num_settings * 6; // Each setting is 6 bytes
    
    // Encode frame header
    http2_frame_header_t header = {
        .length = (uint32_t)payload_len,
        .type = HTTP2_FRAME_SETTINGS,
        .flags = 0, // No ACK flag
        .stream_id = 0 // Connection-level frame
    };
    
    uint8_t frame_header[9];
    encode_frame_header(&header, frame_header);
    
    // Encode settings payload
    uint8_t* settings_payload = malloc(payload_len);
    if (!settings_payload) {
        return HTTP2_EMULATION_ERROR_MEMORY;
    }
    
    for (size_t i = 0; i < num_settings; i++) {
        encode_setting(&settings[i], settings_payload + (i * 6));
    }
    
    // Send frame
    int result1 = ssl_write_func(ssl_context, frame_header, 9);
    int result2 = ssl_write_func(ssl_context, settings_payload, (int)payload_len);
    
    free(settings_payload);
    
    if (result1 <= 0 || result2 <= 0) {
        return HTTP2_EMULATION_ERROR_NETWORK;
    }
    
    ctx->stats.settings_frames_sent++;
    ctx->stats.total_frames_sent++;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Sent SETTINGS frame (%zu parameters)\n", num_settings);
    return HTTP2_EMULATION_SUCCESS;
}

int http2_emulation_maybe_send_ping(http2_emulation_context_t* ctx,
                                   ssl_write_function_t ssl_write_func,
                                   void* ssl_context) {
    if (!ctx || !ssl_write_func) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    uint64_t current_time = get_current_time_ms();
    
    // Check if it's time to send a PING
    if (current_time - ctx->last_ping_time < ctx->next_ping_interval) {
        return HTTP2_EMULATION_SUCCESS; // Not time yet
    }
    
    // Generate PING payload (8 bytes)
    uint8_t ping_data[8];
    for (int i = 0; i < 8; i++) {
        ping_data[i] = rand() & 0xFF;
    }
    
    // Encode PING frame
    http2_frame_header_t header = {
        .length = 8,
        .type = HTTP2_FRAME_PING,
        .flags = 0, // No ACK flag
        .stream_id = 0 // Connection-level frame
    };
    
    uint8_t frame_header[9];
    encode_frame_header(&header, frame_header);
    
    // Send frame
    int result1 = ssl_write_func(ssl_context, frame_header, 9);
    int result2 = ssl_write_func(ssl_context, ping_data, 8);
    
    if (result1 <= 0 || result2 <= 0) {
        return HTTP2_EMULATION_ERROR_NETWORK;
    }
    
    // Update timing
    ctx->last_ping_time = current_time;
    
    // Calculate next PING interval
    if (ctx->has_learned_behavior && ctx->learned_ping_interval > 0) {
        ctx->next_ping_interval = add_jitter(ctx->learned_ping_interval, 
                                            ctx->config.ping_jitter_percent);
    } else {
        ctx->next_ping_interval = add_jitter(ctx->config.ping_base_interval_ms,
                                            ctx->config.ping_jitter_percent);
    }
    
    // Ensure PING interval is within allowed range [10s, 60s]
    if (ctx->next_ping_interval < 10000) ctx->next_ping_interval = 10000;
    if (ctx->next_ping_interval > 60000) ctx->next_ping_interval = 60000;
    
    ctx->stats.ping_frames_sent++;
    ctx->stats.total_frames_sent++;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Sent PING frame, next in %ums\n", ctx->next_ping_interval);
    return HTTP2_EMULATION_SUCCESS;
}

int http2_emulation_maybe_send_priority(http2_emulation_context_t* ctx,
                                       ssl_write_function_t ssl_write_func,
                                       void* ssl_context) {
    if (!ctx || !ssl_write_func) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    uint64_t current_time = get_current_time_ms();
    
    // Check if it's time to consider sending a PRIORITY frame
    if (current_time - ctx->last_priority_time < ctx->next_priority_check) {
        return HTTP2_EMULATION_SUCCESS;
    }
    
    // Decide whether to emit a PRIORITY frame based on learned rate
    float random_val = (float)rand() / RAND_MAX;
    if (random_val > ctx->priority_emission_rate) {
        // Update next check time
        ctx->last_priority_time = current_time;
        ctx->next_priority_check = random_range(2000, 8000); // Check again in 2-8 seconds
        return HTTP2_EMULATION_SUCCESS;
    }
    
    // Generate PRIORITY frame parameters
    uint32_t stream_id = random_range(1, 15); // Random stream ID 1-15
    http2_priority_t priority = {
        .stream_dependency = random_range(0, 7),
        .weight = (uint8_t)random_range(1, 256),
        .exclusive = (rand() % 4 == 0) // 25% chance of exclusive
    };
    
    // Encode PRIORITY payload (5 bytes)
    uint8_t priority_payload[5];
    uint32_t dependency = priority.stream_dependency;
    if (priority.exclusive) {
        dependency |= 0x80000000; // Set E bit
    }
    
    priority_payload[0] = (dependency >> 24) & 0xFF;
    priority_payload[1] = (dependency >> 16) & 0xFF;
    priority_payload[2] = (dependency >> 8) & 0xFF;
    priority_payload[3] = dependency & 0xFF;
    priority_payload[4] = priority.weight;
    
    // Encode PRIORITY frame
    http2_frame_header_t header = {
        .length = 5,
        .type = HTTP2_FRAME_PRIORITY,
        .flags = 0,
        .stream_id = stream_id
    };
    
    uint8_t frame_header[9];
    encode_frame_header(&header, frame_header);
    
    // Send frame
    int result1 = ssl_write_func(ssl_context, frame_header, 9);
    int result2 = ssl_write_func(ssl_context, priority_payload, 5);
    
    if (result1 <= 0 || result2 <= 0) {
        return HTTP2_EMULATION_ERROR_NETWORK;
    }
    
    // Update timing
    ctx->last_priority_time = current_time;
    ctx->next_priority_check = random_range(3000, 12000); // Next check in 3-12 seconds
    
    ctx->stats.priority_frames_sent++;
    ctx->stats.total_frames_sent++;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Sent PRIORITY frame (stream %u, weight %u)\n", 
           stream_id, priority.weight);
    return HTTP2_EMULATION_SUCCESS;
}

int http2_emulation_maybe_send_idle_padding(http2_emulation_context_t* ctx,
                                           ssl_write_function_t ssl_write_func,
                                           void* ssl_context,
                                           uint64_t last_data_time) {
    if (!ctx || !ssl_write_func) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    uint64_t current_time = get_current_time_ms();
    uint64_t time_since_data = current_time - last_data_time;
    
    // Check if idle padding is needed (200ms - 1200ms without data)
    if (time_since_data < ctx->config.idle_padding_min_delay_ms ||
        time_since_data > ctx->config.idle_padding_max_delay_ms) {
        return HTTP2_EMULATION_SUCCESS;
    }
    
    // Check if enough time has passed since last idle padding
    if (current_time - ctx->last_idle_padding_time < 1000) { // Min 1 second between padding
        return HTTP2_EMULATION_SUCCESS;
    }
    
    // Generate random padding length [0, 3072] bytes
    uint32_t padding_len = random_range(0, ctx->config.max_idle_padding_bytes);
    if (padding_len == 0) {
        return HTTP2_EMULATION_SUCCESS;
    }
    
    // Generate random padding data
    uint8_t* padding_data = malloc(padding_len);
    if (!padding_data) {
        return HTTP2_EMULATION_ERROR_MEMORY;
    }
    
    for (uint32_t i = 0; i < padding_len; i++) {
        padding_data[i] = rand() & 0xFF;
    }
    
    // Send as DATA frame on a random stream
    uint32_t stream_id = random_range(1, 7) * 2; // Use even stream IDs (server-initiated)
    
    http2_frame_header_t header = {
        .length = padding_len,
        .type = HTTP2_FRAME_DATA,
        .flags = 0,
        .stream_id = stream_id
    };
    
    uint8_t frame_header[9];
    encode_frame_header(&header, frame_header);
    
    // Send frame
    int result1 = ssl_write_func(ssl_context, frame_header, 9);
    int result2 = ssl_write_func(ssl_context, padding_data, (int)padding_len);
    
    free(padding_data);
    
    if (result1 <= 0 || result2 <= 0) {
        return HTTP2_EMULATION_ERROR_NETWORK;
    }
    
    // Update timing
    ctx->last_idle_padding_time = current_time;
    
    ctx->stats.idle_padding_frames_sent++;
    ctx->stats.total_idle_padding_bytes += padding_len;
    ctx->stats.total_frames_sent++;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Sent idle padding (%u bytes on stream %u)\n", 
           padding_len, stream_id);
    return HTTP2_EMULATION_SUCCESS;
}

int http2_emulation_get_stats(const http2_emulation_context_t* ctx,
                             http2_emulation_stats_t* stats) {
    if (!ctx || !stats) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    *stats = ctx->stats;
    return HTTP2_EMULATION_SUCCESS;
}

int http2_emulation_update_behavior(http2_emulation_context_t* ctx,
                                   const http2_behavior_update_t* update) {
    if (!ctx || !update) {
        return HTTP2_EMULATION_ERROR_INVALID_PARAM;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Updating behavior parameters\n");
    
    // Update PING interval if provided
    if (update->new_ping_interval_ms > 0) {
        ctx->learned_ping_interval = update->new_ping_interval_ms;
        ctx->next_ping_interval = add_jitter(ctx->learned_ping_interval,
                                            ctx->config.ping_jitter_percent);
        
        // Ensure within bounds
        if (ctx->next_ping_interval < 10000) ctx->next_ping_interval = 10000;
        if (ctx->next_ping_interval > 60000) ctx->next_ping_interval = 60000;
    }
    
    // Update PRIORITY emission rate if provided
    if (update->new_priority_rate >= 0.0f && update->new_priority_rate <= 0.05f) {
        ctx->priority_emission_rate = update->new_priority_rate;
    }
    
    ctx->stats.behavior_updates++;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Emulation: Updated - PING: %ums, PRIORITY rate: %.3f%%\n",
           ctx->next_ping_interval, ctx->priority_emission_rate * 100.0f);
    
    return HTTP2_EMULATION_SUCCESS;
}
