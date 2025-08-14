/**
 * BetaNet HTX Access-Ticket Bootstrap Implementation
 * Implementation of BetaNet Specification §5.2
 * 
 * This module provides the complete implementation of the negotiated carrier,
 * replay-bound access ticket system for censorship-resistant authentication.
 * 
 * Compliance with BetaNet Spec §5.2:
 * - X25519 ECDH for secure key agreement
 * - Hour-based time binding (floor(unix_time/3600))
 * - HKDF-SHA256 for key derivation
 * - Variable-length padding (24-64 bytes)
 * - Multiple carrier support (Cookie, Query, Body)
 * - Replay protection via (client_pubkey, hour) tracking
 * - Base64URL encoding for HTTP compatibility
 * - Proper error handling and validation
 */

#include "../../include/betanet/htx_tickets.h"
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
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Global replay protection storage (simple implementation)
// In production, this should be a proper database with TTL
#define MAX_REPLAY_ENTRIES 10000
static struct {
    uint8_t client_pubkey[HTX_TICKET_PUBKEY_SIZE];
    uint64_t hour;
    time_t recorded_at;
} replay_tracker[MAX_REPLAY_ENTRIES];
static size_t replay_tracker_count = 0;

// Statistics tracking
static struct {
    uint64_t tickets_generated;
    uint64_t tickets_verified;
    uint64_t tickets_rejected;
    uint64_t replay_attempts;
    uint64_t carrier_usage[4]; // Index by carrier type
} ticket_stats = {0};

// =============================================================================
// Cryptographic Utilities
// =============================================================================

static int perform_x25519_ecdh(const uint8_t* private_key, const uint8_t* public_key, uint8_t* shared_secret) {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;
    EVP_PKEY* peer_key = NULL;
    size_t secret_len = 32;
    int ret = -1;

    // Create private key
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key, 32);
    if (!pkey) goto cleanup;

    // Create peer public key
    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, public_key, 32);
    if (!peer_key) goto cleanup;

    // Create context and derive shared secret
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) goto cleanup;
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0) goto cleanup;

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer_key);
    return ret;
}

static int hkdf_sha256(const uint8_t* secret, size_t secret_len,
                      const uint8_t* salt, size_t salt_len,
                      const uint8_t* info, size_t info_len,
                      uint8_t* output, size_t output_len) {
    EVP_PKEY_CTX* ctx = NULL;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, secret_len) <= 0) goto cleanup;
    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0) goto cleanup;
    }

    size_t out_len = output_len;
    if (EVP_PKEY_derive(ctx, output, &out_len) <= 0) goto cleanup;

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int generate_x25519_keypair(uint8_t* private_key, uint8_t* public_key) {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;
    size_t key_len = 32;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanup;

    if (EVP_PKEY_get_raw_private_key(pkey, private_key, &key_len) <= 0) goto cleanup;
    key_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key, &key_len) <= 0) goto cleanup;

    ret = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

// =============================================================================
// Utility Functions Implementation
// =============================================================================

uint64_t htx_ticket_get_hour_timestamp(void) {
    return (uint64_t)(time(NULL) / 3600);
}

int htx_ticket_random_bytes(uint8_t* output, size_t len) {
    return RAND_bytes(output, (int)len) == 1 ? 0 : -1;
}

// Base64URL implementation (URL-safe base64 without padding)
static const char base64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int htx_ticket_base64url_encode(const uint8_t* input, size_t input_len, char* output, size_t output_size) {
    if (!input || !output || input_len == 0) return -1;
    
    size_t needed = ((input_len + 2) / 3) * 4;
    if (output_size < needed + 1) return -1; // +1 for null terminator
    
    size_t i = 0, j = 0;
    while (i < input_len) {
        uint32_t a = input[i++];
        uint32_t b = (i < input_len) ? input[i++] : 0;
        uint32_t c = (i < input_len) ? input[i++] : 0;
        
        uint32_t triple = (a << 16) | (b << 8) | c;
        
        output[j++] = base64url_chars[(triple >> 18) & 63];
        output[j++] = base64url_chars[(triple >> 12) & 63];
        if (i - 2 < input_len) output[j++] = base64url_chars[(triple >> 6) & 63];
        if (i - 1 < input_len) output[j++] = base64url_chars[triple & 63];
    }
    
    // Remove padding (URL-safe variant)
    while (j > 0 && output[j-1] == '=') j--;
    output[j] = '\0';
    
    return 0;
}

int htx_ticket_base64url_decode(const char* input, size_t input_len, uint8_t* output, size_t output_size, size_t* output_len) {
    if (!input || !output || !output_len) return -1;
    
    // Decode table for base64url
    static int decode_table[256] = {-1};
    static int table_initialized = 0;
    
    if (!table_initialized) {
        secure_memset(decode_table, -1, sizeof(decode_table));
        for (int i = 0; i < 64; i++) {
            decode_table[(int)base64url_chars[i]] = i;
        }
        table_initialized = 1;
    }
    
    if (input_len == 0) input_len = strlen(input);
    size_t decoded_len = (input_len * 3) / 4;
    
    if (output_size < decoded_len) return -1;
    
    size_t i = 0, j = 0;
    while (i < input_len) {
        uint32_t sextet_a = (i < input_len) ? decode_table[(int)input[i++]] : 0;
        uint32_t sextet_b = (i < input_len) ? decode_table[(int)input[i++]] : 0;
        uint32_t sextet_c = (i < input_len) ? decode_table[(int)input[i++]] : 0;
        uint32_t sextet_d = (i < input_len) ? decode_table[(int)input[i++]] : 0;
        
        if (sextet_a == (uint32_t)-1 || sextet_b == (uint32_t)-1) return -1;
        
        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;
        
        if (j < decoded_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < decoded_len && sextet_c != (uint32_t)-1) output[j++] = (triple >> 8) & 0xFF;
        if (j < decoded_len && sextet_d != (uint32_t)-1) output[j++] = triple & 0xFF;
    }
    
    *output_len = j;
    return 0;
}

// =============================================================================
// Server-side Implementation
// =============================================================================

int htx_ticket_server_init(htx_ticket_server_config_t* config, const htx_carrier_policy_t* policy) {
    if (!config || !policy) return -1;
    
    // Generate server X25519 keypair
    if (generate_x25519_keypair(config->ticket_privkey, config->ticket_pubkey) != 0) {
        return -1;
    }
    
    // Generate random key ID
    if (htx_ticket_random_bytes(config->key_id, HTX_TICKET_KEYID_SIZE) != 0) {
        return -1;
    }
    
    // Copy carrier policy
    if (secure_memcpy(&config->policy, sizeof(config->policy), policy, sizeof(htx_carrier_policy_t)) != SECURE_ERROR_NONE) {
        return -1; // Failed to copy carrier policy
    }
    
    // Validate policy probabilities sum to ~1.0
    float total_prob = policy->cookie_prob + policy->query_prob + policy->body_prob;
    if (total_prob < 0.99f || total_prob > 1.01f) {
        return -1;
    }
    
    return 0;
}

int htx_ticket_parse_policy(const char* policy_str, htx_carrier_policy_t* policy) {
    if (!policy_str || !policy) return -1;
    
    // Example: "v1; carriers=cookie:0.5,query:0.3,body:0.2; len=24..64"
    secure_memset(policy, 0, sizeof(htx_carrier_policy_t));
    
    // Simple parsing (production would use a proper parser)
    const char* carriers_start = strstr(policy_str, "carriers=");
    if (!carriers_start) return -1;
    carriers_start += 9;
    
    if (sscanf(carriers_start, "cookie:%f,query:%f,body:%f", 
               &policy->cookie_prob, &policy->query_prob, &policy->body_prob) != 3) {
        return -1;
    }
    
    const char* len_start = strstr(policy_str, "len=");
    if (!len_start) return -1;
    len_start += 4;
    
    if (sscanf(len_start, "%u..%u", &policy->min_len, &policy->max_len) != 2) {
        return -1;
    }
    
    return 0;
}

int htx_ticket_format_policy(const htx_carrier_policy_t* policy, char* output, size_t output_size) {
    if (!policy || !output) return -1;
    
    // Use secure snprintf with bounds checking and validation
    int len = secure_snprintf(output, output_size,
                             "v1; carriers=cookie:%.1f,query:%.1f,body:%.1f; len=%u..%u",
                             policy->cookie_prob, policy->query_prob, policy->body_prob,
                             policy->min_len, policy->max_len);
    
    return (len == SECURE_ERROR_NONE) ? 0 : -1;
}

bool htx_ticket_is_duplicate(const uint8_t* client_pubkey, uint64_t hour) {
    time_t now = time(NULL);
    
    for (size_t i = 0; i < replay_tracker_count; i++) {
        // Clean up old entries (older than 2 hours)
        if (now - replay_tracker[i].recorded_at > 7200) {
            // Move last entry to this position
            if (i < replay_tracker_count - 1) {
                replay_tracker[i] = replay_tracker[replay_tracker_count - 1];
            }
            replay_tracker_count--;
            i--; // Check this position again
            continue;
        }
        
        if (memcmp(replay_tracker[i].client_pubkey, client_pubkey, HTX_TICKET_PUBKEY_SIZE) == 0 &&
            replay_tracker[i].hour == hour) {
            ticket_stats.replay_attempts++;
            return true;
        }
    }
    
    return false;
}

int htx_ticket_record_usage(const uint8_t* client_pubkey, uint64_t hour) {
    if (replay_tracker_count >= MAX_REPLAY_ENTRIES) {
        // Remove oldest entry
        memmove(&replay_tracker[0], &replay_tracker[1], 
                (MAX_REPLAY_ENTRIES - 1) * sizeof(replay_tracker[0]));
        replay_tracker_count--;
    }
    
    if (!secure_memcpy(replay_tracker[replay_tracker_count].client_pubkey, 
                       sizeof(replay_tracker[replay_tracker_count].client_pubkey),
                       client_pubkey, HTX_TICKET_PUBKEY_SIZE)) {
        return -1; // Failed to copy client public key
    }
    replay_tracker[replay_tracker_count].hour = hour;
    replay_tracker[replay_tracker_count].recorded_at = time(NULL);
    replay_tracker_count++;
    
    return 0;
}

int htx_ticket_server_verify(const htx_ticket_server_config_t* config,
                           const uint8_t* payload, size_t payload_len,
                           htx_ticket_verification_t* result) {
    if (!config || !payload || !result || payload_len < 1 + HTX_TICKET_PUBKEY_SIZE + HTX_TICKET_KEYID_SIZE + HTX_TICKET_NONCE_SIZE + HTX_TICKET_ACCESS_SIZE) {
        if (result) {
            result->is_valid = false;
            secure_strcpy(result->rejection_reason, sizeof(result->rejection_reason), "Invalid parameters");
        }
        return -1;
    }
    
    secure_memset(result, 0, sizeof(htx_ticket_verification_t));
    
    // Parse payload fields in order (version, client_pubkey, key_id, nonce, access_ticket)
    size_t offset = 0;
    
    // Version check
    if (payload[offset] != 0x01) {
        result->is_valid = false;
        secure_strcpy(result->rejection_reason, sizeof(result->rejection_reason), "Invalid version");
        ticket_stats.tickets_rejected++;
        return -1;
    }
    offset++;
    
    // Extract client public key
    if (secure_memcpy(result->client_pubkey, sizeof(result->client_pubkey), &payload[offset], HTX_TICKET_PUBKEY_SIZE) != SECURE_ERROR_NONE) {
        result->is_valid = false;
        secure_strcpy(result->rejection_reason, sizeof(result->rejection_reason), "Invalid client public key");
        return -1;
    }
    offset += HTX_TICKET_PUBKEY_SIZE;
    
    // Verify key ID
    if (memcmp(&payload[offset], config->key_id, HTX_TICKET_KEYID_SIZE) != 0) {
        result->is_valid = false;
        secure_strcpy(result->rejection_reason, sizeof(result->rejection_reason), "Invalid key ID");
        ticket_stats.tickets_rejected++;
        return -1;
    }
    offset += HTX_TICKET_KEYID_SIZE;
    
    // Extract nonce
    uint8_t nonce[HTX_TICKET_NONCE_SIZE];
    if (secure_memcpy(nonce, sizeof(nonce), &payload[offset], HTX_TICKET_NONCE_SIZE) != SECURE_ERROR_NONE) {
        result->is_valid = false;
        secure_strcpy(result->rejection_reason, sizeof(result->rejection_reason), "Invalid nonce");
        return -1;
    }
    offset += HTX_TICKET_NONCE_SIZE;
    
    // Extract claimed access ticket
    uint8_t claimed_ticket[HTX_TICKET_ACCESS_SIZE];
    if (secure_memcpy(claimed_ticket, sizeof(claimed_ticket), &payload[offset], HTX_TICKET_ACCESS_SIZE) != SECURE_ERROR_NONE) {
        result->is_valid = false;
        secure_strcpy(result->rejection_reason, sizeof(result->rejection_reason), "Invalid access ticket");
        return -1;
    }
    
    // Verify for current hour and adjacent hours (±1)
    uint64_t current_hour = htx_ticket_get_hour_timestamp();
    uint64_t test_hours[] = {current_hour - 1, current_hour, current_hour + 1};
    
    for (int i = 0; i < 3; i++) {
        uint64_t hour = test_hours[i];
        
        // Check for replay
        if (htx_ticket_is_duplicate(result->client_pubkey, hour)) {
            result->is_valid = false;
            secure_strcpy(result->rejection_reason, sizeof(result->rejection_reason), "Duplicate ticket");
            ticket_stats.tickets_rejected++;
            return -1;
        }
        
        // Compute expected access ticket
        uint8_t shared_secret[32];
        if (perform_x25519_ecdh(config->ticket_privkey, result->client_pubkey, shared_secret) != 0) {
            continue;
        }
        
        // Compute salt: SHA256("betanet-ticket-v1" || key_id || hour)
        uint8_t salt_input[17 + HTX_TICKET_KEYID_SIZE + 8];
        if (secure_memcpy(salt_input, sizeof(salt_input), "betanet-ticket-v1", 17) != SECURE_ERROR_NONE ||
            secure_memcpy(&salt_input[17], sizeof(salt_input) - 17, config->key_id, HTX_TICKET_KEYID_SIZE) != SECURE_ERROR_NONE) {
            continue;
        }
        
        // Convert hour to big-endian
        uint64_t hour_be = hour;
        for (int j = 0; j < 8; j++) {
            salt_input[17 + HTX_TICKET_KEYID_SIZE + j] = (uint8_t)((hour_be >> (56 - j * 8)) & 0xFF);
        }
        
        uint8_t salt[32];
        SHA256(salt_input, sizeof(salt_input), salt);
        
        // Derive access ticket
        uint8_t expected_ticket[HTX_TICKET_ACCESS_SIZE];
        if (hkdf_sha256(shared_secret, 32, salt, 32, NULL, 0, expected_ticket, HTX_TICKET_ACCESS_SIZE) != 0) {
            continue;
        }
        
        // Compare tickets
        if (memcmp(claimed_ticket, expected_ticket, HTX_TICKET_ACCESS_SIZE) == 0) {
            // Valid ticket found
            result->is_valid = true;
            result->hour_timestamp = hour;
            
            // Record usage to prevent replay
            htx_ticket_record_usage(result->client_pubkey, hour);
            ticket_stats.tickets_verified++;
            return 0;
        }
    }
    
    result->is_valid = false;
    secure_strcpy(result->rejection_reason, sizeof(result->rejection_reason), "Invalid access ticket");
    ticket_stats.tickets_rejected++;
    return -1;
}

// =============================================================================
// Client-side Implementation  
// =============================================================================

static htx_carrier_type_t select_carrier_by_policy(const htx_carrier_policy_t* policy) {
    float rand_val = (float)rand() / RAND_MAX;
    float cumulative = 0.0f;
    
    cumulative += policy->cookie_prob;
    if (rand_val < cumulative) return HTX_CARRIER_COOKIE;
    
    cumulative += policy->query_prob;
    if (rand_val < cumulative) return HTX_CARRIER_QUERY;
    
    return HTX_CARRIER_BODY;
}

int htx_ticket_client_create_request(htx_ticket_request_t* request,
                                   const uint8_t* server_pubkey,
                                   const uint8_t* key_id,
                                   const htx_carrier_policy_t* policy) {
    if (!request || !server_pubkey || !key_id || !policy) return -1;
    
    secure_memset(request, 0, sizeof(htx_ticket_request_t));
    
    // Generate client X25519 keypair
    if (generate_x25519_keypair(request->client_privkey, request->client_pubkey) != 0) {
        return -1;
    }
    
    // Generate client nonce
    if (htx_ticket_random_bytes(request->nonce, HTX_TICKET_NONCE_SIZE) != 0) {
        return -1;
    }
    
    // Copy server info
    if (secure_memcpy(request->server_pubkey, sizeof(request->server_pubkey), server_pubkey, HTX_TICKET_PUBKEY_SIZE) != SECURE_ERROR_NONE ||
        secure_memcpy(request->key_id, sizeof(request->key_id), key_id, HTX_TICKET_KEYID_SIZE) != SECURE_ERROR_NONE) {
        return -1; // Failed to copy server information
    }
    
    // Select carrier based on policy
    request->selected_carrier = select_carrier_by_policy(policy);
    
    // Select random length within policy range
    uint32_t range = policy->max_len - policy->min_len + 1;
    request->payload_len = policy->min_len + (rand() % range);
    
    ticket_stats.carrier_usage[request->selected_carrier]++;
    
    return 0;
}

int htx_ticket_client_generate(const htx_ticket_request_t* request, htx_access_ticket_t* ticket) {
    if (!request || !ticket) return -1;
    
    secure_memset(ticket, 0, sizeof(htx_access_ticket_t));
    
    // Perform X25519 ECDH
    if (perform_x25519_ecdh(request->client_privkey, request->server_pubkey, ticket->shared_secret) != 0) {
        return -1;
    }
    
    // Get current hour
    ticket->hour_timestamp = htx_ticket_get_hour_timestamp();
    
    // Compute salt: SHA256("betanet-ticket-v1" || key_id || hour)
    uint8_t salt_input[17 + HTX_TICKET_KEYID_SIZE + 8];
    if (secure_memcpy(salt_input, sizeof(salt_input), "betanet-ticket-v1", 17) != SECURE_ERROR_NONE ||
        secure_memcpy(&salt_input[17], sizeof(salt_input) - 17, request->key_id, HTX_TICKET_KEYID_SIZE) != SECURE_ERROR_NONE) {
        return -1; // Failed to build salt input
    }
    
    // Convert hour to big-endian
    uint64_t hour_be = ticket->hour_timestamp;
    for (int i = 0; i < 8; i++) {
        salt_input[17 + HTX_TICKET_KEYID_SIZE + i] = (uint8_t)((hour_be >> (56 - i * 8)) & 0xFF);
    }
    
    uint8_t salt[32];
    SHA256(salt_input, sizeof(salt_input), salt);
    
    // Derive access ticket using HKDF
    if (hkdf_sha256(ticket->shared_secret, 32, salt, 32, NULL, 0, ticket->access_ticket, HTX_TICKET_ACCESS_SIZE) != 0) {
        return -1;
    }
    
    ticket->is_valid = true;
    ticket_stats.tickets_generated++;
    
    return 0;
}

int htx_ticket_client_encode(const htx_ticket_request_t* request,
                           const htx_access_ticket_t* ticket,
                           htx_ticket_payload_t* payload) {
    if (!request || !ticket || !payload || !ticket->is_valid) return -1;
    
    secure_memset(payload, 0, sizeof(htx_ticket_payload_t));
    
    // Set version
    payload->version = 0x01;
    
    // Copy fields
    if (secure_memcpy(payload->client_pubkey, sizeof(payload->client_pubkey), request->client_pubkey, HTX_TICKET_PUBKEY_SIZE) != SECURE_ERROR_NONE ||
        secure_memcpy(payload->key_id, sizeof(payload->key_id), request->key_id, HTX_TICKET_KEYID_SIZE) != SECURE_ERROR_NONE ||
        secure_memcpy(payload->nonce, sizeof(payload->nonce), request->nonce, HTX_TICKET_NONCE_SIZE) != SECURE_ERROR_NONE ||
        secure_memcpy(payload->access_ticket, sizeof(payload->access_ticket), ticket->access_ticket, HTX_TICKET_ACCESS_SIZE) != SECURE_ERROR_NONE) {
        return -1; // Failed to copy payload fields
    }
    
    // Calculate required padding
    size_t fixed_size = 1 + HTX_TICKET_PUBKEY_SIZE + HTX_TICKET_KEYID_SIZE + HTX_TICKET_NONCE_SIZE + HTX_TICKET_ACCESS_SIZE;
    if (request->payload_len < fixed_size) {
        return -1; // Invalid payload length
    }
    
    payload->padding_len = request->payload_len - fixed_size;
    payload->total_len = request->payload_len;
    
    // Allocate and fill padding
    if (payload->padding_len > 0) {
        payload->padding = malloc(payload->padding_len);
        if (!payload->padding) return -1;
        
        if (htx_ticket_random_bytes(payload->padding, payload->padding_len) != 0) {
            free(payload->padding);
            payload->padding = NULL;
            return -1;
        }
    }
    
    return 0;
}

int htx_ticket_format_cookie(const htx_ticket_payload_t* payload,
                           const char* site_name,
                           char* output, size_t output_size) {
    if (!payload || !site_name || !output) return -1;
    
    // Create binary payload
    size_t binary_len = payload->total_len;
    uint8_t* binary_data = malloc(binary_len);
    if (!binary_data) return -1;
    
    // Pack binary data
    size_t offset = 0;
    binary_data[offset++] = payload->version;
    if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->client_pubkey, HTX_TICKET_PUBKEY_SIZE) != SECURE_ERROR_NONE) {
        free(binary_data);
        return -1;
    }
    offset += HTX_TICKET_PUBKEY_SIZE;
    if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->key_id, HTX_TICKET_KEYID_SIZE) != SECURE_ERROR_NONE) {
        free(binary_data);
        return -1;
    }
    offset += HTX_TICKET_KEYID_SIZE;
    if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->nonce, HTX_TICKET_NONCE_SIZE) != SECURE_ERROR_NONE) {
        free(binary_data);
        return -1;
    }
    offset += HTX_TICKET_NONCE_SIZE;
    if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->access_ticket, HTX_TICKET_ACCESS_SIZE) != SECURE_ERROR_NONE) {
        free(binary_data);
        return -1;
    }
    offset += HTX_TICKET_ACCESS_SIZE;
    if (payload->padding_len > 0) {
        if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->padding, payload->padding_len) != SECURE_ERROR_NONE) {
            free(binary_data);
            return -1;
        }
    }
    
    // Base64URL encode
    char* encoded = malloc(binary_len * 2); // Overallocate
    if (!encoded) {
        free(binary_data);
        return -1;
    }
    
    if (htx_ticket_base64url_encode(binary_data, binary_len, encoded, binary_len * 2) != 0) {
        free(binary_data);
        free(encoded);
        return -1;
    }
    
    // Format cookie header with secure formatting
    int len = secure_snprintf(output, output_size, "Cookie: __Host-%s=%s", site_name, encoded);
    
    free(binary_data);
    free(encoded);
    
    return (len == SECURE_ERROR_NONE) ? 0 : -1;
}

int htx_ticket_format_query(const htx_ticket_payload_t* payload, char* output, size_t output_size) {
    // Similar implementation to cookie but for query parameter
    if (!payload || !output) return -1;
    
    size_t binary_len = payload->total_len;
    uint8_t* binary_data = malloc(binary_len);
    if (!binary_data) return -1;
    
    // Pack binary data (same as cookie)
    size_t offset = 0;
    binary_data[offset++] = payload->version;
    if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->client_pubkey, HTX_TICKET_PUBKEY_SIZE) != SECURE_ERROR_NONE) {
        free(binary_data);
        return -1;
    }
    offset += HTX_TICKET_PUBKEY_SIZE;
    if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->key_id, HTX_TICKET_KEYID_SIZE) != SECURE_ERROR_NONE) {
        free(binary_data);
        return -1;
    }
    offset += HTX_TICKET_KEYID_SIZE;
    if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->nonce, HTX_TICKET_NONCE_SIZE) != SECURE_ERROR_NONE) {
        free(binary_data);
        return -1;
    }
    offset += HTX_TICKET_NONCE_SIZE;
    if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->access_ticket, HTX_TICKET_ACCESS_SIZE) != SECURE_ERROR_NONE) {
        free(binary_data);
        return -1;
    }
    offset += HTX_TICKET_ACCESS_SIZE;
    if (payload->padding_len > 0) {
        if (secure_memcpy(&binary_data[offset], binary_len - offset, payload->padding, payload->padding_len) != SECURE_ERROR_NONE) {
            free(binary_data);
            return -1;
        }
    }
    
    char* encoded = malloc(binary_len * 2);
    if (!encoded) {
        free(binary_data);
        return -1;
    }
    
    if (htx_ticket_base64url_encode(binary_data, binary_len, encoded, binary_len * 2) != 0) {
        free(binary_data);
        free(encoded);
        return -1;
    }
    
    int len = secure_snprintf(output, output_size, "bn1=%s", encoded);
    
    free(binary_data);
    free(encoded);
    
    return (len == SECURE_ERROR_NONE) ? 0 : -1;
}

int htx_ticket_format_body(const htx_ticket_payload_t* payload, char* output, size_t output_size) {
    // Same as query parameter format for application/x-www-form-urlencoded
    return htx_ticket_format_query(payload, output, output_size);
}

void htx_ticket_payload_free(htx_ticket_payload_t* payload) {
    if (payload && payload->padding) {
        free(payload->padding);
        payload->padding = NULL;
        payload->padding_len = 0;
    }
}

void htx_ticket_print_stats(void) {
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "=== HTX Ticket Statistics ===");
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "Tickets Generated: %llu", (unsigned long long)ticket_stats.tickets_generated);
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "Tickets Verified:  %llu", (unsigned long long)ticket_stats.tickets_verified);
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "Tickets Rejected:  %llu", (unsigned long long)ticket_stats.tickets_rejected);
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "Replay Attempts:   %llu", (unsigned long long)ticket_stats.replay_attempts);
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "Carrier Usage:");
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "  Cookie: %llu", (unsigned long long)ticket_stats.carrier_usage[HTX_CARRIER_COOKIE]);
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "  Query:  %llu", (unsigned long long)ticket_stats.carrier_usage[HTX_CARRIER_QUERY]);
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "  Body:   %llu", (unsigned long long)ticket_stats.carrier_usage[HTX_CARRIER_BODY]);
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "Active Replay Entries: %zu", replay_tracker_count);
    BETANET_LOG_INFO(BETANET_LOG_TAG_TICKET, "==============================");
}
