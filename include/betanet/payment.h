#ifndef BETANET_PAYMENT_H
#define BETANET_PAYMENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// BetaNet Payment System (Layer 6)
// Implements federated Cashu mints with Lightning Network settlement
// Based on ravendevteam/betanet v1.1 specification

#define BETANET_PAYMENT_TOKEN_SIZE 64
#define BETANET_PAYMENT_PROOF_SIZE 128
#define BETANET_PAYMENT_MAX_MINTS 16
#define BETANET_PAYMENT_MAX_TOKENS_PER_TX 32

// Payment denominations (in satoshis)
typedef enum {
    BETANET_DENOM_1_SAT = 1,
    BETANET_DENOM_10_SAT = 10,
    BETANET_DENOM_100_SAT = 100,
    BETANET_DENOM_1000_SAT = 1000,
    BETANET_DENOM_10000_SAT = 10000,
    BETANET_DENOM_100000_SAT = 100000,
    BETANET_DENOM_1000000_SAT = 1000000
} betanet_payment_denomination_t;

// Cashu token structure
typedef struct {
    uint8_t token[BETANET_PAYMENT_TOKEN_SIZE];
    uint8_t proof[BETANET_PAYMENT_PROOF_SIZE];
    betanet_payment_denomination_t denomination;
    uint64_t mint_id;
    uint32_t expiry;
    uint8_t is_spent;
} betanet_cashu_token_t;

// Mint information
typedef struct {
    uint64_t mint_id;
    char mint_url[256];
    uint8_t pubkey[32];  // Mint's public key
    uint32_t fee_rate_ppm;  // Fee rate in parts per million
    uint8_t is_trusted;
    uint8_t is_available;
    uint32_t last_seen;
} betanet_mint_info_t;

// Payment request
typedef struct {
    uint64_t amount_sats;
    char description[512];
    uint32_t expiry;
    uint8_t payment_hash[32];
    char ln_invoice[2048];  // Lightning invoice for settlement
} betanet_payment_request_t;

// Payment proof for bandwidth/services
typedef struct {
    uint8_t proof_id[32];
    uint64_t amount_paid;
    uint32_t service_type;  // HTX bandwidth, mixnet routing, etc.
    uint32_t validity_start;
    uint32_t validity_end;
    uint8_t signature[64];
} betanet_payment_proof_t;

// Wallet state
typedef struct {
    betanet_cashu_token_t tokens[1024];  // Local token storage
    size_t num_tokens;
    betanet_mint_info_t known_mints[BETANET_PAYMENT_MAX_MINTS];
    size_t num_mints;
    uint64_t total_balance_sats;
    char wallet_id[64];
} betanet_wallet_t;

// Payment system configuration
typedef struct {
    uint32_t default_fee_rate_ppm;
    uint32_t token_refresh_interval;
    uint32_t mint_discovery_interval;
    uint8_t enable_auto_split;  // Automatically split large denominations
    uint8_t enable_auto_merge;  // Automatically merge small denominations
    char preferred_mint_url[256];
} betanet_payment_config_t;

// Core payment functions

/**
 * Initialize payment subsystem
 * 
 * @param config Payment configuration
 * @return 0 on success, negative on error
 */
int betanet_payment_init(const betanet_payment_config_t* config);

/**
 * Cleanup payment subsystem
 */
void betanet_payment_cleanup(void);

/**
 * Create new wallet
 * 
 * @param wallet_id Unique wallet identifier
 * @param wallet Output wallet structure
 * @return 0 on success, negative on error
 */
int betanet_wallet_create(const char* wallet_id, betanet_wallet_t* wallet);

/**
 * Load existing wallet from storage
 * 
 * @param wallet_id Wallet identifier
 * @param wallet Output wallet structure
 * @return 0 on success, negative on error
 */
int betanet_wallet_load(const char* wallet_id, betanet_wallet_t* wallet);

/**
 * Save wallet to persistent storage
 * 
 * @param wallet Wallet to save
 * @return 0 on success, negative on error
 */
int betanet_wallet_save(const betanet_wallet_t* wallet);

// Mint management

/**
 * Discover available Cashu mints
 * 
 * @param wallet Wallet to update with discovered mints
 * @return Number of mints discovered, negative on error
 */
int betanet_payment_discover_mints(betanet_wallet_t* wallet);

/**
 * Add trusted mint
 * 
 * @param wallet Wallet to update
 * @param mint_url Mint URL
 * @param pubkey Mint public key (32 bytes)
 * @return 0 on success, negative on error
 */
int betanet_payment_add_mint(betanet_wallet_t* wallet,
                             const char* mint_url,
                             const uint8_t* pubkey);

/**
 * Verify mint is operational and trusted
 * 
 * @param mint_info Mint to verify
 * @return 1 if trusted and operational, 0 otherwise
 */
int betanet_payment_verify_mint(const betanet_mint_info_t* mint_info);

// Token operations

/**
 * Mint new tokens from Lightning payment
 * 
 * @param wallet Wallet to add tokens to
 * @param mint_id Target mint ID
 * @param ln_invoice Lightning invoice to pay
 * @param amount_sats Amount in satoshis
 * @return 0 on success, negative on error
 */
int betanet_payment_mint_tokens(betanet_wallet_t* wallet,
                                uint64_t mint_id,
                                const char* ln_invoice,
                                uint64_t amount_sats);

/**
 * Melt tokens to Lightning payment
 * 
 * @param wallet Wallet containing tokens
 * @param amount_sats Amount to melt
 * @param ln_invoice Lightning invoice to pay
 * @return 0 on success, negative on error
 */
int betanet_payment_melt_tokens(betanet_wallet_t* wallet,
                                uint64_t amount_sats,
                                const char* ln_invoice);

/**
 * Send tokens to another wallet
 * 
 * @param wallet Source wallet
 * @param amount_sats Amount to send
 * @param recipient_info Recipient information
 * @param tokens Output tokens for recipient
 * @param num_tokens Output number of tokens
 * @return 0 on success, negative on error
 */
int betanet_payment_send_tokens(betanet_wallet_t* wallet,
                                uint64_t amount_sats,
                                const char* recipient_info,
                                betanet_cashu_token_t* tokens,
                                size_t* num_tokens);

/**
 * Receive tokens from another wallet
 * 
 * @param wallet Destination wallet
 * @param tokens Received tokens
 * @param num_tokens Number of tokens
 * @return 0 on success, negative on error
 */
int betanet_payment_receive_tokens(betanet_wallet_t* wallet,
                                   const betanet_cashu_token_t* tokens,
                                   size_t num_tokens);

// Service payments

/**
 * Create payment request for service
 * 
 * @param amount_sats Amount required
 * @param service_type Type of service (bandwidth, routing, etc.)
 * @param description Human-readable description
 * @param request Output payment request
 * @return 0 on success, negative on error
 */
int betanet_payment_create_request(uint64_t amount_sats,
                                   uint32_t service_type,
                                   const char* description,
                                   betanet_payment_request_t* request);

/**
 * Pay for service and get proof of payment
 * 
 * @param wallet Wallet to pay from
 * @param request Payment request
 * @param proof Output payment proof
 * @return 0 on success, negative on error
 */
int betanet_payment_pay_service(betanet_wallet_t* wallet,
                                const betanet_payment_request_t* request,
                                betanet_payment_proof_t* proof);

/**
 * Verify payment proof is valid
 * 
 * @param proof Payment proof to verify
 * @param current_time Current timestamp
 * @return 1 if valid, 0 if invalid, negative on error
 */
int betanet_payment_verify_proof(const betanet_payment_proof_t* proof,
                                 uint32_t current_time);

// Wallet management

/**
 * Get wallet balance
 * 
 * @param wallet Wallet to check
 * @return Balance in satoshis
 */
uint64_t betanet_wallet_get_balance(const betanet_wallet_t* wallet);

/**
 * Refresh wallet token validity
 * 
 * @param wallet Wallet to refresh
 * @return Number of invalid tokens removed
 */
int betanet_wallet_refresh_tokens(betanet_wallet_t* wallet);

/**
 * Optimize wallet token distribution
 * 
 * @param wallet Wallet to optimize
 * @return 0 on success, negative on error
 */
int betanet_wallet_optimize_tokens(betanet_wallet_t* wallet);

// Service-specific payment types
#define BETANET_SERVICE_HTX_BANDWIDTH    0x01
#define BETANET_SERVICE_MIXNET_ROUTING   0x02
#define BETANET_SERVICE_ACCESS_TICKET    0x03
#define BETANET_SERVICE_GOVERNANCE_VOTE  0x04

/**
 * Calculate payment amount for HTX bandwidth
 * 
 * @param bytes_requested Number of bytes requested
 * @param duration_seconds Duration in seconds
 * @return Required payment in satoshis
 */
uint64_t betanet_payment_calculate_bandwidth_cost(uint64_t bytes_requested,
                                                  uint32_t duration_seconds);

/**
 * Calculate payment amount for mixnet routing
 * 
 * @param hops Number of mixnet hops
 * @param payload_size Payload size in bytes
 * @return Required payment in satoshis
 */
uint64_t betanet_payment_calculate_routing_cost(uint8_t hops,
                                                size_t payload_size);

#ifdef __cplusplus
}
#endif

#endif // BETANET_PAYMENT_H
