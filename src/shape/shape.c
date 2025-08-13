#include "shape.h"
#include <stdlib.h>

void shape_config_init(shape_config_t* cfg, shape_profile_t profile) {
    if (!cfg) return;
    cfg->profile = profile;
    switch (profile) {
        case SHAPE_PROFILE_HTTP2_ADAPTIVE:
            cfg->padding_min = 16;
            cfg->padding_max = 128;
            cfg->keepalive_interval_ms = 15000;
            cfg->keepalive_jitter_ms = 3000;
            cfg->idle_timeout_min_ms = 200;
            cfg->idle_timeout_max_ms = 1200;
            cfg->idle_padding_max = 3072; // 3 KiB
            cfg->priority_emit_prob = 0.02f; // 2% default

            // HTTP/2 SETTINGS defaults (to be overwritten by origin-mirroring)
            cfg->h2_settings_max_concurrent_streams = 100;
            cfg->h2_settings_initial_window_size = 65535;
            cfg->h2_settings_max_frame_size = 16384;
            cfg->h2_settings_max_header_list_size = 8192;
            cfg->h2_settings_header_table_size = 4096;
            cfg->h2_settings_tolerance_percent = 15;

            // PING cadence: 30s base, ±10% jitter
            cfg->ping_cadence_base_ms = 30000;
            cfg->ping_cadence_jitter_percent = 10;
            break;
        case SHAPE_PROFILE_HTTP3_ADAPTIVE:
            cfg->padding_min = 32;
            cfg->padding_max = 256;
            cfg->keepalive_interval_ms = 12000;
            cfg->keepalive_jitter_ms = 4000;
            cfg->idle_timeout_min_ms = 200;
            cfg->idle_timeout_max_ms = 1200;
            cfg->idle_padding_max = 3072;
            cfg->priority_emit_prob = 0.02f;

            // HTTP/3 SETTINGS defaults (reuse h2 fields for now)
            cfg->h2_settings_max_concurrent_streams = 100;
            cfg->h2_settings_initial_window_size = 65535;
            cfg->h2_settings_max_frame_size = 16384;
            cfg->h2_settings_max_header_list_size = 8192;
            cfg->h2_settings_header_table_size = 4096;
            cfg->h2_settings_tolerance_percent = 15;

            // PING cadence: 20s base, ±10% jitter
            cfg->ping_cadence_base_ms = 20000;
            cfg->ping_cadence_jitter_percent = 10;
            break;
        case SHAPE_PROFILE_OBFUSCATED:
            cfg->padding_min = 64;
            cfg->padding_max = 512;
            cfg->keepalive_interval_ms = 10000;
            cfg->keepalive_jitter_ms = 5000;
            cfg->idle_timeout_min_ms = 500;
            cfg->idle_timeout_max_ms = 2000;
            cfg->idle_padding_max = 4096;
            cfg->priority_emit_prob = 0.01f;

            cfg->h2_settings_max_concurrent_streams = 50;
            cfg->h2_settings_initial_window_size = 32768;
            cfg->h2_settings_max_frame_size = 8192;
            cfg->h2_settings_max_header_list_size = 4096;
            cfg->h2_settings_header_table_size = 2048;
            cfg->h2_settings_tolerance_percent = 20;

            cfg->ping_cadence_base_ms = 40000;
            cfg->ping_cadence_jitter_percent = 20;
            break;
        case SHAPE_PROFILE_CUSTOM:
        case SHAPE_PROFILE_NONE:
        default:
            cfg->padding_min = 0;
            cfg->padding_max = 0;
            cfg->keepalive_interval_ms = 0;
            cfg->keepalive_jitter_ms = 0;
            cfg->idle_timeout_min_ms = 0;
            cfg->idle_timeout_max_ms = 0;
            cfg->idle_padding_max = 0;
            cfg->priority_emit_prob = 0.0f;

            cfg->h2_settings_max_concurrent_streams = 0;
            cfg->h2_settings_initial_window_size = 0;
            cfg->h2_settings_max_frame_size = 0;
            cfg->h2_settings_max_header_list_size = 0;
            cfg->h2_settings_header_table_size = 0;
            cfg->h2_settings_tolerance_percent = 0;

            cfg->ping_cadence_base_ms = 0;
            cfg->ping_cadence_jitter_percent = 0;
            break;
    }
}

int shape_apply_padding(const shape_config_t* cfg, uint8_t* buf, size_t len, size_t max_len) {
    if (!cfg || !buf || len > max_len) return (int)len;
    if (cfg->padding_max == 0 || cfg->padding_max <= cfg->padding_min) return (int)len;
    uint32_t pad = cfg->padding_min;
    if (cfg->padding_max > cfg->padding_min) {
        pad += rand() % (cfg->padding_max - cfg->padding_min + 1);
    }
    if (len + pad > max_len) pad = (uint32_t)(max_len - len);
    for (uint32_t i = 0; i < pad; ++i) buf[len + i] = (uint8_t)(rand() & 0xFF);
    return (int)(len + pad);
}

uint32_t shape_next_keepalive(const shape_config_t* cfg) {
    if (!cfg) return 0;
    if (cfg->keepalive_interval_ms == 0) return 0;
    uint32_t jitter = (cfg->keepalive_jitter_ms > 0) ? (rand() % (cfg->keepalive_jitter_ms + 1)) : 0;
    return cfg->keepalive_interval_ms + jitter;
}

void shape_set_profile(shape_config_t* cfg, shape_profile_t profile) {
    shape_config_init(cfg, profile);
}

/**
 * Get random idle timeout (ms) for sending dummy DATA if idle.
 */
uint32_t shape_next_idle_timeout(const shape_config_t* cfg) {
    if (!cfg || cfg->idle_timeout_max_ms == 0 || cfg->idle_timeout_max_ms < cfg->idle_timeout_min_ms)
        return 0;
    uint32_t range = cfg->idle_timeout_max_ms - cfg->idle_timeout_min_ms;
    return cfg->idle_timeout_min_ms + (range ? (rand() % (range + 1)) : 0);
}

/**
 * Decide whether to emit a PRIORITY frame on this connection.
 * Returns 1 if should emit, 0 otherwise.
 */
int shape_should_emit_priority(const shape_config_t* cfg) {
    if (!cfg || cfg->priority_emit_prob <= 0.0f) return 0;
    float r = (float)rand() / (float)RAND_MAX;
    return r < cfg->priority_emit_prob ? 1 : 0;
}
/**
 * Get randomized PING cadence (ms) with ±jitter_percent.
 */
uint32_t shape_next_ping_cadence(const shape_config_t* cfg) {
    if (!cfg || cfg->ping_cadence_base_ms == 0) return 0;
    uint32_t base = cfg->ping_cadence_base_ms;
    uint8_t jitter = cfg->ping_cadence_jitter_percent;
    if (jitter == 0) return base;
    int32_t delta = (int32_t)(base * jitter / 100);
    int32_t offset = (rand() % (2 * delta + 1)) - delta; // [-delta, +delta]
    int32_t result = (int32_t)base + offset;
    if (result < 0) result = 0;
    return (uint32_t)result;
}

/**
 * Check if a SETTINGS value is within tolerance of the mirrored origin value.
 * Returns 1 if compliant, 0 otherwise.
 */
int shape_settings_within_tolerance(uint32_t mirrored, uint32_t origin, uint8_t tolerance_percent) {
    if (tolerance_percent == 0) return mirrored == origin ? 1 : 0;
    uint32_t min = origin - (origin * tolerance_percent / 100);
    uint32_t max = origin + (origin * tolerance_percent / 100);
    return (mirrored >= min && mirrored <= max) ? 1 : 0;
}