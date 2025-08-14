#ifndef HTX_TICKETS_H
#define HTX_TICKETS_H

/**
 * BetaNet HTX Access-Ticket Bootstrap System
 * Implementation of BetaNet Specification §5.2
 * 
 * This module implements the negotiated carrier, replay-bound access ticket system
 * that enables censorship-resistant access to BetaNet nodes while maintaining
 * plausible deniability and preventing traffic analysis.
 * 
 * Key Features:
 * - X25519 ECDH for ticket encryption
 * - Hour-based time binding for replay protection
 * - Multiple carrier types (Cookie, Query, Body) with negotiated probabilities
 * - Variable-length padding to defeat statistical analysis
 * - HKDF for proper key derivation
 * - Per-client nonce for unique tickets
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants from BetaNet Spec §5.2
#define HTX_TICKET_PUBKEY_SIZE 32      // X25519 public key
#define HTX_TICKET_PRIVKEY_SIZE 32     // X25519 private key
#define HTX_TICKET_KEYID_SIZE 8        // Ticket key ID
#define HTX_TICKET_NONCE_SIZE 32       // Client nonce
#define HTX_TICKET_ACCESS_SIZE 32      // Access ticket
#define HTX_TICKET_MIN_PADDING 24      // Minimum total length
#define HTX_TICKET_MAX_PADDING 64      // Maximum total length

// Carrier types as per spec
typedef enum {
    HTX_CARRIER_COOKIE = 1,
    HTX_CARRIER_QUERY = 2,
    HTX_CARRIER_BODY = 3
} htx_carrier_type_t;

// Carrier policy configuration
typedef struct {
    float cookie_prob;    // Probability of using cookie carrier
    float query_prob;     // Probability of using query carrier  
    float body_prob;      // Probability of using body carrier
    uint32_t min_len;     // Minimum total payload length
    uint32_t max_len;     // Maximum total payload length
} htx_carrier_policy_t;

// Server ticket configuration
typedef struct {
    uint8_t ticket_pubkey[HTX_TICKET_PUBKEY_SIZE];    // Server's X25519 public key
    uint8_t ticket_privkey[HTX_TICKET_PRIVKEY_SIZE];  // Server's X25519 private key
    uint8_t key_id[HTX_TICKET_KEYID_SIZE];            // Key identifier
    htx_carrier_policy_t policy;                       // Carrier selection policy
} htx_ticket_server_config_t;

// Client ticket request
typedef struct {
    uint8_t client_pubkey[HTX_TICKET_PUBKEY_SIZE];    // Client's X25519 public key
    uint8_t client_privkey[HTX_TICKET_PRIVKEY_SIZE];  // Client's X25519 private key
    uint8_t nonce[HTX_TICKET_NONCE_SIZE];             // Client nonce
    uint8_t server_pubkey[HTX_TICKET_PUBKEY_SIZE];    // Server's public key
    uint8_t key_id[HTX_TICKET_KEYID_SIZE];            // Server key ID
    htx_carrier_type_t selected_carrier;               // Chosen carrier type
    uint32_t payload_len;                              // Total payload length
} htx_ticket_request_t;

// Generated access ticket
typedef struct {
    uint8_t access_ticket[HTX_TICKET_ACCESS_SIZE];    // Computed access ticket
    uint8_t shared_secret[32];                         // X25519 shared secret
    uint64_t hour_timestamp;                           // Hour-based timestamp
    bool is_valid;                                     // Validity flag
} htx_access_ticket_t;

// Encoded ticket payload for transmission
typedef struct {
    uint8_t version;                                   // Version byte (0x01)
    uint8_t client_pubkey[HTX_TICKET_PUBKEY_SIZE];    
    uint8_t key_id[HTX_TICKET_KEYID_SIZE];
    uint8_t nonce[HTX_TICKET_NONCE_SIZE];
    uint8_t access_ticket[HTX_TICKET_ACCESS_SIZE];
    uint8_t* padding;                                  // Variable padding
    size_t padding_len;                                // Padding length
    size_t total_len;                                  // Total payload length
} htx_ticket_payload_t;

// Server verification result
typedef struct {
    bool is_valid;                                     // Verification result
    uint64_t hour_timestamp;                           // Verified timestamp
    uint8_t client_pubkey[HTX_TICKET_PUBKEY_SIZE];    // Client public key
    char rejection_reason[64];                         // Reason if rejected
} htx_ticket_verification_t;

// =============================================================================
// Server-side API
// =============================================================================

/**
 * Initialize server ticket configuration
 * Generates server X25519 keypair and sets carrier policy
 */
int htx_ticket_server_init(htx_ticket_server_config_t* config,
                          const htx_carrier_policy_t* policy);

/**
 * Parse carrier policy from BN-Ticket header string
 * Example: "v1; carriers=cookie:0.5,query:0.3,body:0.2; len=24..64"
 */
int htx_ticket_parse_policy(const char* policy_str, htx_carrier_policy_t* policy);

/**
 * Format carrier policy for BN-Ticket header
 */
int htx_ticket_format_policy(const htx_carrier_policy_t* policy, 
                            char* output, size_t output_size);

/**
 * Verify incoming ticket payload
 * Checks timestamp, prevents replay attacks, validates access ticket
 */
int htx_ticket_server_verify(const htx_ticket_server_config_t* config,
                            const uint8_t* payload, size_t payload_len,
                            htx_ticket_verification_t* result);

/**
 * Check for duplicate ticket (replay protection)
 * Server must track (client_pubkey, hour) tuples for 2 hours
 */
bool htx_ticket_is_duplicate(const uint8_t* client_pubkey, uint64_t hour);

/**
 * Record ticket usage (for duplicate prevention)
 */
int htx_ticket_record_usage(const uint8_t* client_pubkey, uint64_t hour);

// =============================================================================
// Client-side API  
// =============================================================================

/**
 * Create ticket request for server
 * Generates client keypair, selects carrier based on policy
 */
int htx_ticket_client_create_request(htx_ticket_request_t* request,
                                    const uint8_t* server_pubkey,
                                    const uint8_t* key_id,
                                    const htx_carrier_policy_t* policy);

/**
 * Generate access ticket from request
 * Performs X25519 ECDH and HKDF derivation
 */
int htx_ticket_client_generate(const htx_ticket_request_t* request,
                              htx_access_ticket_t* ticket);

/**
 * Encode ticket for transmission via selected carrier
 * Adds proper padding and formats for HTTP transport
 */
int htx_ticket_client_encode(const htx_ticket_request_t* request,
                            const htx_access_ticket_t* ticket,
                            htx_ticket_payload_t* payload);

/**
 * Format ticket for Cookie carrier
 * Example: "Cookie: __Host-example=Base64URL(payload)"
 */
int htx_ticket_format_cookie(const htx_ticket_payload_t* payload,
                            const char* site_name,
                            char* output, size_t output_size);

/**
 * Format ticket for Query carrier  
 * Example: "...?bn1=Base64URL(payload)"
 */
int htx_ticket_format_query(const htx_ticket_payload_t* payload,
                           char* output, size_t output_size);

/**
 * Format ticket for Body carrier
 * Example: "bn1=Base64URL(payload)" for application/x-www-form-urlencoded
 */
int htx_ticket_format_body(const htx_ticket_payload_t* payload,
                          char* output, size_t output_size);

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Get current hour timestamp (UTC)
 * Returns floor(unix_time / 3600)
 */
uint64_t htx_ticket_get_hour_timestamp(void);

/**
 * Generate cryptographically secure random bytes
 */
int htx_ticket_random_bytes(uint8_t* output, size_t len);

/**
 * Base64URL encode (URL-safe base64 without padding)
 */
int htx_ticket_base64url_encode(const uint8_t* input, size_t input_len,
                               char* output, size_t output_size);

/**
 * Base64URL decode
 */
int htx_ticket_base64url_decode(const char* input, size_t input_len,
                               uint8_t* output, size_t output_size, size_t* output_len);

/**
 * Free ticket payload (cleans up allocated padding)
 */
void htx_ticket_payload_free(htx_ticket_payload_t* payload);

/**
 * Print ticket statistics and configuration
 */
void htx_ticket_print_stats(void);

#ifdef __cplusplus
}
#endif

#endif // HTX_TICKETS_H
