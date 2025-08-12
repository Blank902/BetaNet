#ifndef SHAPE_H
#define SHAPE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SHAPE_PROFILE_NONE = 0,
    SHAPE_PROFILE_HTTP2_ADAPTIVE,
    SHAPE_PROFILE_HTTP3_ADAPTIVE,
    SHAPE_PROFILE_OBFUSCATED,
    SHAPE_PROFILE_CUSTOM
} shape_profile_t;

typedef struct {
    shape_profile_t profile;
    uint32_t padding_min;
    uint32_t padding_max;
    uint32_t keepalive_interval_ms;
    uint32_t keepalive_jitter_ms;
    uint32_t idle_timeout_min_ms;
    uint32_t idle_timeout_max_ms;
    uint32_t idle_padding_max;
    float priority_emit_prob; // Probability [0,1] to emit PRIORITY frame
    // Future: add HTTP2 SETTINGS mirroring, fingerprinting fields, etc.
} shape_config_t;
/**
 * Initialize shaping config with a profile.
 * Sets defaults for adaptive HTTP2/3, priorities, idle padding, etc.
 */
void shape_config_init(shape_config_t* cfg, shape_profile_t profile);


// Apply shaping to outgoing data (padding, etc.)
int shape_apply_padding(const shape_config_t* cfg, uint8_t* buf, size_t len, size_t max_len);
// Get next keepalive interval (with jitter)
uint32_t shape_next_keepalive(const shape_config_t* cfg);

/**
 * Get random idle timeout (ms) for sending dummy DATA if idle.
 */
uint32_t shape_next_idle_timeout(const shape_config_t* cfg);

/**
 * Decide whether to emit a PRIORITY frame on this connection.
 * Returns 1 if should emit, 0 otherwise.
 */
int shape_should_emit_priority(const shape_config_t* cfg);


// Set shaping profile at runtime
void shape_set_profile(shape_config_t* cfg, shape_profile_t profile);

#ifdef __cplusplus
}
#endif

#endif // SHAPE_H