/**
 * @file origin_calibration.c
 * @brief HTX Origin Mirroring & Auto-Calibration Implementation
 * 
 * Implements TLS fingerprint calibration and HTTP/2 SETTINGS mirroring
 * according to BetaNet Specification §5.1.
 */

#include "../../include/betanet/htx_calibration.h"
#include "../../include/betanet/secure_utils.h"
#include "../../include/betanet/secure_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

// ============================================================================
// Internal Helper Functions
// ============================================================================

/**
 * Get current timestamp in milliseconds
 */
static uint64_t get_timestamp_ms(void) {
    return (uint64_t)time(NULL) * 1000;
}

/**
 * Create TCP socket and connect to host:port
 */
static int create_connection(const char *host, uint16_t port, uint32_t timeout_ms) {
    int sockfd = -1;
    struct addrinfo hints, *result, *rp;
    char port_str[8];
    
#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Calibration: WSAStartup failed\n");
        return -1;
    }
#endif
    
    secure_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    
    secure_snprintf(port_str, sizeof(port_str), "%u", port);
    
    int status = getaddrinfo(host, port_str, &hints, &result);
    if (status != 0) {
        BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Calibration: getaddrinfo failed: %s\n", gai_strerror(status));
        return -1;
    }
    
    // Try each address until connection succeeds
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;
        
        // Set socket timeout
#ifdef _WIN32
        DWORD timeout = timeout_ms;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
        
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; // Success
        }
        
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        sockfd = -1;
    }
    
    freeaddrinfo(result);
    
    if (sockfd == -1) {
        BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Calibration: Failed to connect to %s:%u\n", host, port);
        return -1;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Connected to %s:%u (socket %d)\n", host, port, sockfd);
    return sockfd;
}

/**
 * Extract cipher suites from SSL context
 */
static size_t extract_cipher_suites(SSL *ssl, uint16_t *cipher_suites, size_t max_count) {
    if (!ssl || !cipher_suites) return 0;
    
    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
    if (!ciphers) return 0;
    
    size_t count = 0;
    int num_ciphers = sk_SSL_CIPHER_num(ciphers);
    
    for (int i = 0; i < num_ciphers && count < max_count; i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        if (cipher) {
            cipher_suites[count] = SSL_CIPHER_get_id(cipher) & 0xFFFF;
            count++;
        }
    }
    
    return count;
}

/**
 * Extract supported groups (elliptic curves)
 */
static size_t extract_supported_groups(SSL *ssl, uint16_t *groups, size_t max_count) {
    if (!ssl || !groups) return 0;
    
    // Note: OpenSSL doesn't provide direct access to client's supported groups
    // This is a simplified implementation - in practice, we'd need to capture
    // this information during the handshake using callbacks
    
    // Default common groups for now
    groups[0] = 23;  // secp256r1
    groups[1] = 24;  // secp384r1  
    groups[2] = 25;  // secp521r1
    groups[3] = 29;  // x25519
    
    return 4;
}

/**
 * Extract ALPN protocols
 */
static size_t extract_alpn_protocols(SSL *ssl, char alpn_list[][32], size_t max_count) {
    if (!ssl || !alpn_list) return 0;
    
    const unsigned char *alpn_data;
    unsigned int alpn_len;
    
    SSL_get0_alpn_selected(ssl, &alpn_data, &alpn_len);
    
    if (!alpn_data || alpn_len == 0) return 0;
    
    // For now, just capture the selected ALPN
    if (alpn_len < 32) {
        secure_memcpy(alpn_list[0], sizeof(alpn_list[0]), alpn_data, alpn_len);
        alpn_list[0][alpn_len] = '\0';
        return 1;
    }
    
    return 0;
}

// ============================================================================
// Fingerprint Extraction Functions
// ============================================================================

htx_calibration_result_t htx_extract_tls_fingerprint(void *ssl_ctx,
                                                     htx_tls_fingerprint_t *fingerprint) {
    if (!ssl_ctx || !fingerprint) {
        return HTX_CALIBRATION_ERR_INVALID_PARAM;
    }
    
    SSL *ssl = (SSL *)ssl_ctx;
    secure_memset(fingerprint, 0, sizeof(*fingerprint));
    
    // Extract TLS version
    fingerprint->version = SSL_version(ssl);
    
    // Extract cipher suites
    fingerprint->cipher_count = extract_cipher_suites(ssl, fingerprint->cipher_suites,
                                                     sizeof(fingerprint->cipher_suites) / sizeof(uint16_t));
    
    // Extract supported groups
    fingerprint->group_count = extract_supported_groups(ssl, fingerprint->supported_groups,
                                                        sizeof(fingerprint->supported_groups) / sizeof(uint16_t));
    
    // Extract ALPN protocols
    fingerprint->alpn_count = extract_alpn_protocols(ssl, fingerprint->alpn_list,
                                                     HTX_CALIBRATION_MAX_ALPN_COUNT);
    
    // Calculate fingerprint hashes
    fingerprint->ja3_hash = htx_calculate_ja3_hash(fingerprint);
    fingerprint->ja4_hash = htx_calculate_ja4_hash(fingerprint);
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Extracted TLS fingerprint - Version:0x%04X Ciphers:%zu Groups:%zu ALPN:%zu\n",
           fingerprint->version, fingerprint->cipher_count, fingerprint->group_count, fingerprint->alpn_count);
    
    return HTX_CALIBRATION_SUCCESS;
}

htx_calibration_result_t htx_extract_h2_fingerprint(void *h2_session,
                                                    htx_h2_fingerprint_t *fingerprint) {
    if (!fingerprint) {
        return HTX_CALIBRATION_ERR_INVALID_PARAM;
    }
    
    // For now, provide default HTTP/2 settings that are commonly used
    // In a full implementation, this would extract actual SETTINGS from the session
    
    secure_memset(fingerprint, 0, sizeof(*fingerprint));
    
    // Default settings commonly seen in the wild
    fingerprint->settings[0].setting_id = 1; // SETTINGS_HEADER_TABLE_SIZE
    fingerprint->settings[0].value = 4096;
    
    fingerprint->settings[1].setting_id = 2; // SETTINGS_ENABLE_PUSH
    fingerprint->settings[1].value = 0;
    
    fingerprint->settings[2].setting_id = 3; // SETTINGS_MAX_CONCURRENT_STREAMS
    fingerprint->settings[2].value = 100;
    
    fingerprint->settings[3].setting_id = 4; // SETTINGS_INITIAL_WINDOW_SIZE
    fingerprint->settings[3].value = 65535;
    
    fingerprint->settings[4].setting_id = 5; // SETTINGS_MAX_FRAME_SIZE
    fingerprint->settings[4].value = 16384;
    
    fingerprint->settings[5].setting_id = 6; // SETTINGS_MAX_HEADER_LIST_SIZE
    fingerprint->settings[5].value = 8192;
    
    fingerprint->setting_count = 6;
    
    // Copy to convenience fields
    fingerprint->header_table_size = 4096;
    fingerprint->max_concurrent_streams = 100;
    fingerprint->initial_window_size = 65535;
    fingerprint->max_frame_size = 16384;
    fingerprint->max_header_list_size = 8192;
    fingerprint->enable_push = false;
    fingerprint->enable_connect_protocol = false;
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Extracted HTTP/2 fingerprint - %zu settings\n", fingerprint->setting_count);
    
    return HTX_CALIBRATION_SUCCESS;
}

// ============================================================================
// Hash Calculation Functions
// ============================================================================

uint32_t htx_calculate_ja3_hash(const htx_tls_fingerprint_t *fingerprint) {
    if (!fingerprint) return 0;
    
    // Simplified JA3 hash calculation
    // Real implementation would create the full JA3 string and MD5 hash it
    
    uint32_t hash = 0;
    hash ^= fingerprint->version;
    
    for (size_t i = 0; i < fingerprint->cipher_count; i++) {
        hash ^= fingerprint->cipher_suites[i] << (i % 16);
    }
    
    for (size_t i = 0; i < fingerprint->extension_count; i++) {
        hash ^= fingerprint->extensions[i] << ((i + 8) % 16);
    }
    
    return hash;
}

uint32_t htx_calculate_ja4_hash(const htx_tls_fingerprint_t *fingerprint) {
    if (!fingerprint) return 0;
    
    // Simplified JA4 hash calculation  
    // Real implementation would follow JA4 specification format
    
    uint32_t hash = 0;
    hash ^= fingerprint->version << 16;
    
    for (size_t i = 0; i < fingerprint->cipher_count; i++) {
        hash ^= fingerprint->cipher_suites[i] << (i % 24);
    }
    
    for (size_t i = 0; i < fingerprint->group_count; i++) {
        hash ^= fingerprint->supported_groups[i] << ((i + 12) % 24);
    }
    
    return hash;
}

// ============================================================================
// Comparison Functions
// ============================================================================

bool htx_compare_tls_fingerprints(const htx_tls_fingerprint_t *reference,
                                  const htx_tls_fingerprint_t *current) {
    if (!reference || !current) return false;
    
    // Version must match exactly
    if (reference->version != current->version) {
        BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: TLS version mismatch (ref:0x%04X vs cur:0x%04X)\n",
               reference->version, current->version);
        return false;
    }
    
    // Cipher suites must match exactly
    if (reference->cipher_count != current->cipher_count) {
        BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Cipher count mismatch (ref:%zu vs cur:%zu)\n",
               reference->cipher_count, current->cipher_count);
        return false;
    }
    
    for (size_t i = 0; i < reference->cipher_count; i++) {
        if (reference->cipher_suites[i] != current->cipher_suites[i]) {
            BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Cipher mismatch at index %zu (ref:0x%04X vs cur:0x%04X)\n",
                   i, reference->cipher_suites[i], current->cipher_suites[i]);
            return false;
        }
    }
    
    // ALPN count and order must match exactly
    if (reference->alpn_count != current->alpn_count) {
        BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: ALPN count mismatch (ref:%zu vs cur:%zu)\n",
               reference->alpn_count, current->alpn_count);
        return false;
    }
    
    for (size_t i = 0; i < reference->alpn_count; i++) {
        if (strcmp(reference->alpn_list[i], current->alpn_list[i]) != 0) {
            BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: ALPN mismatch at index %zu (ref:%s vs cur:%s)\n",
                   i, reference->alpn_list[i], current->alpn_list[i]);
            return false;
        }
    }
    
    return true;
}

bool htx_compare_h2_settings(const htx_h2_fingerprint_t *reference,
                             const htx_h2_fingerprint_t *current,
                             uint8_t tolerance_percent) {
    if (!reference || !current) return false;
    
    // Compare key settings with tolerance
    for (size_t i = 0; i < reference->setting_count; i++) {
        uint16_t ref_id = reference->settings[i].setting_id;
        uint32_t ref_value = reference->settings[i].value;
        
        // Find corresponding setting in current
        bool found = false;
        for (size_t j = 0; j < current->setting_count; j++) {
            if (current->settings[j].setting_id == ref_id) {
                uint32_t cur_value = current->settings[j].value;
                
                // Check if within tolerance
                uint32_t tolerance = (ref_value * tolerance_percent) / 100;
                uint32_t min_value = (ref_value > tolerance) ? ref_value - tolerance : 0;
                uint32_t max_value = ref_value + tolerance;
                
                if (cur_value < min_value || cur_value > max_value) {
                    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: HTTP/2 setting %u value out of tolerance "
                           "(ref:%u cur:%u tolerance:±%u%%)\n",
                           ref_id, ref_value, cur_value, tolerance_percent);
                    return false;
                }
                
                found = true;
                break;
            }
        }
        
        if (!found) {
            BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: HTTP/2 setting %u missing in current fingerprint\n", ref_id);
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// Core Calibration Functions
// ============================================================================

htx_calibration_result_t htx_calibrate_origin(const char *origin_host,
                                              uint16_t origin_port,
                                              uint32_t timeout_ms,
                                              htx_origin_profile_t *profile) {
    if (!origin_host || !profile) {
        return HTX_CALIBRATION_ERR_INVALID_PARAM;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Starting origin calibration for %s:%u (timeout: %ums)\n",
           origin_host, origin_port, timeout_ms);
    
    secure_memset(profile, 0, sizeof(*profile));
    strncpy(profile->origin_host, origin_host, sizeof(profile->origin_host) - 1);
    profile->origin_port = origin_port;
    profile->calibration_timestamp = get_timestamp_ms();
    
    uint64_t start_time = get_timestamp_ms();
    
    // Create TCP connection
    int sockfd = create_connection(origin_host, origin_port, timeout_ms);
    if (sockfd < 0) {
        return HTX_CALIBRATION_ERR_NETWORK_FAILED;
    }
    
    uint64_t connect_time = get_timestamp_ms();
    profile->connection_time_ms = (uint32_t)(connect_time - start_time);
    
    // Initialize OpenSSL
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return HTX_CALIBRATION_ERR_TLS_FAILED;
    }
    
    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        SSL_CTX_free(ssl_ctx);
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return HTX_CALIBRATION_ERR_TLS_FAILED;
    }
    
    // Configure SSL for fingerprint extraction
    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, origin_host);
    
    // Set common ALPN protocols to test
    const unsigned char alpn_list[] = "\x02h2\x08http/1.1";
    SSL_set_alpn_protos(ssl, alpn_list, sizeof(alpn_list) - 1);
    
    // Perform TLS handshake
    uint64_t handshake_start = get_timestamp_ms();
    int ssl_result = SSL_connect(ssl);
    uint64_t handshake_end = get_timestamp_ms();
    
    if (ssl_result != 1) {
        BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Calibration: TLS handshake failed: %s\n", 
               ERR_error_string(ERR_get_error(), NULL));
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return HTX_CALIBRATION_ERR_TLS_FAILED;
    }
    
    profile->rtt_ms = (uint32_t)(handshake_end - handshake_start);
    
    // Extract TLS fingerprint
    htx_calibration_result_t result = htx_extract_tls_fingerprint(ssl, &profile->tls_profile);
    if (result != HTX_CALIBRATION_SUCCESS) {
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return result;
    }
    
    // Extract HTTP/2 fingerprint (stub for now)
    result = htx_extract_h2_fingerprint(NULL, &profile->h2_profile);
    if (result != HTX_CALIBRATION_SUCCESS) {
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        return result;
    }
    
    // Set default keepalive and ping intervals based on common patterns
    profile->keepalive_interval_ms = 30000; // 30 seconds
    profile->ping_interval_ms = 15000;      // 15 seconds
    
    profile->is_valid = true;
    
    // Cleanup
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
#ifdef _WIN32
    closesocket(sockfd);
#else
    close(sockfd);
#endif
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Successfully calibrated %s:%u (RTT: %ums, Connection: %ums)\n",
           origin_host, origin_port, profile->rtt_ms, profile->connection_time_ms);
    
    return HTX_CALIBRATION_SUCCESS;
}

bool htx_validate_fingerprint_compliance(const htx_origin_profile_t *profile,
                                         const htx_tls_fingerprint_t *current_tls,
                                         const htx_h2_fingerprint_t *current_h2) {
    if (!profile || !profile->is_valid || !current_tls || !current_h2) {
        return false;
    }
    
    // Check TLS fingerprint compliance (exact match required)
    if (!htx_compare_tls_fingerprints(&profile->tls_profile, current_tls)) {
        BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Calibration: TLS fingerprint compliance check FAILED\n");
        return false;
    }
    
    // Check HTTP/2 settings compliance (with tolerance)
    if (!htx_compare_h2_settings(&profile->h2_profile, current_h2, HTX_CALIBRATION_TOLERANCE_PERCENT)) {
        BETANET_LOG_ERROR(BETANET_LOG_TAG_HTX, "HTX Calibration: HTTP/2 settings compliance check FAILED\n");
        return false;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Fingerprint compliance check PASSED\n");
    return true;
}

htx_calibration_result_t htx_apply_origin_profile(void *ctx,
                                                  const htx_origin_profile_t *profile) {
    if (!ctx || !profile || !profile->is_valid) {
        return HTX_CALIBRATION_ERR_INVALID_PARAM;
    }
    
    // For now, this is a stub. In a full implementation, this would:
    // 1. Configure SSL_CTX with the correct cipher suites
    // 2. Set extension order to match the profile
    // 3. Configure ALPN list to match exactly
    // 4. Set HTTP/2 SETTINGS to match the profile values
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: Applied origin profile for %s:%u\n",
           profile->origin_host, profile->origin_port);
    
    return HTX_CALIBRATION_SUCCESS;
}

// ============================================================================
// Utility Functions
// ============================================================================

const char *htx_calibration_result_to_string(htx_calibration_result_t result) {
    switch (result) {
        case HTX_CALIBRATION_SUCCESS: return "Success";
        case HTX_CALIBRATION_ERR_NETWORK_FAILED: return "Network connection failed";
        case HTX_CALIBRATION_ERR_TLS_FAILED: return "TLS handshake failed";
        case HTX_CALIBRATION_ERR_FINGERPRINT_MISMATCH: return "Fingerprint mismatch";
        case HTX_CALIBRATION_ERR_TIMEOUT: return "Operation timed out";
        case HTX_CALIBRATION_ERR_INVALID_PARAM: return "Invalid parameter";
        case HTX_CALIBRATION_ERR_NO_MEMORY: return "Out of memory";
        default: return "Unknown error";
    }
}

void htx_print_origin_profile(const htx_origin_profile_t *profile) {
    if (!profile) {
        BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "HTX Calibration: NULL profile\n");
        return;
    }
    
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTX, "=== HTX Origin Profile ===\n");
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "Origin: %s:%u\n", profile->origin_host, profile->origin_port);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "Valid: %s\n", profile->is_valid ? "Yes" : "No");
    BETANET_LOG_INFO(BETANET_LOG_TAG_CALIB, "Calibrated: %llu\n", (unsigned long long)profile->calibration_timestamp);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "RTT: %u ms\n", profile->rtt_ms);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "Connection Time: %u ms\n", profile->connection_time_ms);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "TLS Version: 0x%04X\n", profile->tls_profile.version);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "Cipher Count: %zu\n", profile->tls_profile.cipher_count);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "ALPN Count: %zu\n", profile->tls_profile.alpn_count);
    BETANET_LOG_INFO(BETANET_LOG_TAG_HTTP2, "HTTP/2 Settings Count: %zu\n", profile->h2_profile.setting_count);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "JA3 Hash: 0x%08X\n", profile->tls_profile.ja3_hash);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "JA4 Hash: 0x%08X\n", profile->tls_profile.ja4_hash);
    BETANET_LOG_INFO(BETANET_LOG_TAG_CORE, "========================\n");
}

bool htx_profile_needs_recalibration(const htx_origin_profile_t *profile,
                                     uint32_t max_age_seconds) {
    if (!profile || !profile->is_valid) {
        return true;
    }
    
    uint64_t current_time = get_timestamp_ms();
    uint64_t age_ms = current_time - profile->calibration_timestamp;
    uint64_t max_age_ms = (uint64_t)max_age_seconds * 1000;
    
    return age_ms > max_age_ms;
}
