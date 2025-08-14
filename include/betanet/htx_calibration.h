/**
 * @file htx_calibration.h
 * @brief HTX Origin Mirroring & Auto-Calibration (BetaNet Spec §5.1)
 * 
 * Implements TLS fingerprint calibration, HTTP/2 SETTINGS mirroring,
 * and origin parameter adaptation for indistinguishability.
 */

#ifndef BETANET_HTX_CALIBRATION_H
#define BETANET_HTX_CALIBRATION_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Types and Constants
// ============================================================================

#define HTX_CALIBRATION_MAX_EXTENSIONS 16
#define HTX_CALIBRATION_MAX_ALPN_COUNT 8
#define HTX_CALIBRATION_MAX_SETTINGS 16
#define HTX_CALIBRATION_TOLERANCE_PERCENT 15

/**
 * TLS Fingerprint Components (JA3/JA4 family)
 */
typedef struct {
    uint16_t version;                                   // TLS version
    uint16_t cipher_suites[32];                        // Cipher suite list
    size_t cipher_count;
    uint16_t extensions[HTX_CALIBRATION_MAX_EXTENSIONS]; // Extension types
    size_t extension_count;
    uint16_t supported_groups[16];                     // Elliptic curves
    size_t group_count;
    uint8_t signature_algorithms[32];                  // Signature algorithms
    size_t sig_alg_count;
    char alpn_list[HTX_CALIBRATION_MAX_ALPN_COUNT][32]; // ALPN protocols
    size_t alpn_count;
    bool has_grease;                                   // GREASE values present
    uint32_t ja3_hash;                                 // JA3 fingerprint hash
    uint32_t ja4_hash;                                 // JA4 fingerprint hash
} htx_tls_fingerprint_t;

/**
 * HTTP/2 SETTINGS Fingerprint
 */
typedef struct {
    uint16_t setting_id;
    uint32_t value;
} htx_h2_setting_t;

typedef struct {
    htx_h2_setting_t settings[HTX_CALIBRATION_MAX_SETTINGS];
    size_t setting_count;
    uint32_t header_table_size;
    uint32_t max_concurrent_streams;
    uint32_t initial_window_size;
    uint32_t max_frame_size;
    uint32_t max_header_list_size;
    bool enable_push;
    bool enable_connect_protocol;
} htx_h2_fingerprint_t;

/**
 * Complete Origin Fingerprint Profile
 */
typedef struct {
    char origin_host[256];                  // Target origin hostname
    uint16_t origin_port;                   // Target port
    htx_tls_fingerprint_t tls_profile;      // TLS fingerprint
    htx_h2_fingerprint_t h2_profile;        // HTTP/2 fingerprint
    uint32_t rtt_ms;                        // Measured RTT
    uint32_t connection_time_ms;            // Connection establishment time
    bool is_valid;                          // Calibration success flag
    uint64_t calibration_timestamp;         // When calibrated
    uint32_t keepalive_interval_ms;         // Observed keepalive pattern
    uint32_t ping_interval_ms;              // Observed PING cadence
} htx_origin_profile_t;

/**
 * Calibration Result
 */
typedef enum {
    HTX_CALIBRATION_SUCCESS = 0,
    HTX_CALIBRATION_ERR_NETWORK_FAILED,
    HTX_CALIBRATION_ERR_TLS_FAILED,
    HTX_CALIBRATION_ERR_FINGERPRINT_MISMATCH,
    HTX_CALIBRATION_ERR_TIMEOUT,
    HTX_CALIBRATION_ERR_INVALID_PARAM,
    HTX_CALIBRATION_ERR_NO_MEMORY
} htx_calibration_result_t;

// ============================================================================
// Core Calibration Functions
// ============================================================================

/**
 * @brief Perform pre-flight calibration of target origin
 * 
 * Establishes test connection to origin and captures complete fingerprint
 * profile including TLS parameters and HTTP/2 SETTINGS.
 * 
 * @param origin_host Target origin hostname
 * @param origin_port Target port (typically 443 for HTTPS)
 * @param timeout_ms Connection timeout in milliseconds
 * @param profile[out] Captured origin profile
 * @return HTX_CALIBRATION_SUCCESS on success, error code otherwise
 */
htx_calibration_result_t htx_calibrate_origin(const char *origin_host,
                                              uint16_t origin_port,
                                              uint32_t timeout_ms,
                                              htx_origin_profile_t *profile);

/**
 * @brief Validate fingerprint compliance with origin profile
 * 
 * Checks if current connection parameters match the calibrated origin
 * within acceptable tolerances per BetaNet Spec §5.1.
 * 
 * @param profile Reference origin profile
 * @param current_tls Current TLS fingerprint
 * @param current_h2 Current HTTP/2 settings
 * @return true if compliant, false if deviation detected
 */
bool htx_validate_fingerprint_compliance(const htx_origin_profile_t *profile,
                                         const htx_tls_fingerprint_t *current_tls,
                                         const htx_h2_fingerprint_t *current_h2);

/**
 * @brief Apply origin profile to connection configuration
 * 
 * Configures TLS and HTTP/2 parameters to match calibrated origin profile.
 * Must be called before establishing the actual connection.
 * 
 * @param ctx HTX context to configure
 * @param profile Origin profile to mirror
 * @return HTX_CALIBRATION_SUCCESS on success, error code otherwise
 */
htx_calibration_result_t htx_apply_origin_profile(void *ctx,
                                                  const htx_origin_profile_t *profile);

// ============================================================================
// Fingerprint Analysis Functions  
// ============================================================================

/**
 * @brief Extract TLS fingerprint from active connection
 * 
 * @param ssl_ctx OpenSSL context
 * @param fingerprint[out] Extracted TLS fingerprint
 * @return HTX_CALIBRATION_SUCCESS on success, error code otherwise
 */
htx_calibration_result_t htx_extract_tls_fingerprint(void *ssl_ctx,
                                                     htx_tls_fingerprint_t *fingerprint);

/**
 * @brief Extract HTTP/2 SETTINGS from connection
 * 
 * @param h2_session HTTP/2 session handle
 * @param fingerprint[out] Extracted HTTP/2 fingerprint
 * @return HTX_CALIBRATION_SUCCESS on success, error code otherwise
 */
htx_calibration_result_t htx_extract_h2_fingerprint(void *h2_session,
                                                    htx_h2_fingerprint_t *fingerprint);

/**
 * @brief Calculate JA3 fingerprint hash
 * 
 * @param fingerprint TLS fingerprint to hash
 * @return JA3 hash value
 */
uint32_t htx_calculate_ja3_hash(const htx_tls_fingerprint_t *fingerprint);

/**
 * @brief Calculate JA4 fingerprint hash
 * 
 * @param fingerprint TLS fingerprint to hash
 * @return JA4 hash value
 */
uint32_t htx_calculate_ja4_hash(const htx_tls_fingerprint_t *fingerprint);

// ============================================================================
// Profile Comparison Functions
// ============================================================================

/**
 * @brief Compare TLS fingerprints for compliance
 * 
 * @param reference Reference fingerprint from calibration
 * @param current Current connection fingerprint
 * @return true if compliant (exact match for critical fields), false otherwise
 */
bool htx_compare_tls_fingerprints(const htx_tls_fingerprint_t *reference,
                                  const htx_tls_fingerprint_t *current);

/**
 * @brief Compare HTTP/2 SETTINGS with tolerance
 * 
 * @param reference Reference settings from calibration
 * @param current Current connection settings
 * @param tolerance_percent Allowed deviation percentage (0-100)
 * @return true if within tolerance, false otherwise
 */
bool htx_compare_h2_settings(const htx_h2_fingerprint_t *reference,
                             const htx_h2_fingerprint_t *current,
                             uint8_t tolerance_percent);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get calibration result description
 * 
 * @param result Calibration result code
 * @return Human-readable description
 */
const char *htx_calibration_result_to_string(htx_calibration_result_t result);

/**
 * @brief Print origin profile details (debugging)
 * 
 * @param profile Origin profile to print
 */
void htx_print_origin_profile(const htx_origin_profile_t *profile);

/**
 * @brief Check if profile needs recalibration
 * 
 * @param profile Origin profile to check
 * @param max_age_seconds Maximum profile age in seconds
 * @return true if recalibration needed, false otherwise
 */
bool htx_profile_needs_recalibration(const htx_origin_profile_t *profile,
                                     uint32_t max_age_seconds);

#ifdef __cplusplus
}
#endif

#endif // BETANET_HTX_CALIBRATION_H
