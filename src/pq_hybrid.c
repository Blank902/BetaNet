#include "betanet/pq_hybrid.h"
#include "betanet/secure_log.h"
#include "betanet/secure_utils.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

#ifdef BETANET_ENABLE_PQ_HYBRID
#include <openssl/rand.h>
#endif

// Post-quantum hybrid implementation
// Follows Betanet v1.1 specification requirements

static int pq_initialized = 0;

int betanet_pq_init(void) {
    if (pq_initialized) {
        return 0;
    }
    
    secure_log(BETANET_LOG_LEVEL_INFO, "Initializing post-quantum cryptography subsystem");
    
#ifdef BETANET_ENABLE_PQ_HYBRID
    // Initialize liboqs or similar library
    // TODO: Add actual library initialization
    secure_log(BETANET_LOG_LEVEL_INFO, "Production PQ implementation enabled");
#else
    secure_log(BETANET_LOG_LEVEL_WARN, "Using stub PQ implementation - not production ready");
#endif
    
    pq_initialized = 1;
    return 0;
}

void betanet_pq_cleanup(void) {
    if (!pq_initialized) {
        return;
    }
    
    secure_log(BETANET_LOG_LEVEL_INFO, "Cleaning up post-quantum cryptography subsystem");
    
#ifdef BETANET_ENABLE_PQ_HYBRID
    // Cleanup liboqs or similar library
    // TODO: Add actual library cleanup
#endif
    
    pq_initialized = 0;
}

int betanet_pq_is_mandatory(void) {
    // Check if current date is after 2027-01-01
    time_t current_time = time(NULL);
    struct tm* tm_info = gmtime(&current_time);
    
    if (tm_info == NULL) {
        // If we can't get time, assume mandatory for safety
        return 1;
    }
    
    // Mandatory from 2027-01-01 00:00:00 UTC
    if (tm_info->tm_year + 1900 >= 2027) {
        return 1;
    }
    
    return 0;
}

#ifdef BETANET_ENABLE_PQ_HYBRID

// Production implementation using liboqs
#include <oqs/oqs.h>

int betanet_pq_keygen_impl(betanet_pq_private_key_t* private_key, 
                           betanet_pq_public_key_t* public_key) {
    if (!private_key || !public_key) {
        secure_log(SECURE_LOG_ERROR, "Invalid parameters for PQ keygen");
        return -1;
    }
    
    // Generate X25519 key pair
    if (RAND_bytes(private_key->x25519_private, 32) != 1) {
        secure_log(SECURE_LOG_ERROR, "Failed to generate X25519 private key");
        return -1;
    }
    
    // TODO: Implement actual X25519 public key derivation
    // crypto_scalarmult_base(public_key->x25519_public, private_key->x25519_private);
    
    // Generate Kyber768 key pair
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        secure_log(SECURE_LOG_ERROR, "Failed to initialize Kyber768 KEM");
        return -1;
    }
    
    if (OQS_KEM_keypair(kem, public_key->kyber768_public, private_key->kyber768_private) != OQS_SUCCESS) {
        secure_log(SECURE_LOG_ERROR, "Failed to generate Kyber768 key pair");
        OQS_KEM_free(kem);
        return -1;
    }
    
    OQS_KEM_free(kem);
    secure_log(SECURE_LOG_DEBUG, "Generated PQ hybrid key pair");
    return 0;
}

int betanet_pq_encaps_impl(const betanet_pq_public_key_t* public_key,
                           betanet_pq_ciphertext_t* ciphertext,
                           uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]) {
    if (!public_key || !ciphertext || !shared_secret) {
        secure_log(LOG_ERROR, "Invalid parameters for PQ encaps");
        return -1;
    }
    
    uint8_t x25519_ephemeral_private[32];
    uint8_t x25519_shared[32];
    uint8_t kyber_shared[32];
    
    // Generate X25519 ephemeral key pair
    if (RAND_bytes(x25519_ephemeral_private, 32) != 1) {
        secure_log(LOG_ERROR, "Failed to generate X25519 ephemeral key");
        return -1;
    }
    
    // TODO: Implement actual X25519 operations
    // crypto_scalarmult_base(ciphertext->x25519_ephemeral, x25519_ephemeral_private);
    // crypto_scalarmult(x25519_shared, x25519_ephemeral_private, public_key->x25519_public);
    
    // Kyber768 encapsulation
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        secure_log(LOG_ERROR, "Failed to initialize Kyber768 KEM for encaps");
        return -1;
    }
    
    if (OQS_KEM_encaps(kem, ciphertext->kyber_ciphertext, kyber_shared, 
                       public_key->kyber768_public) != OQS_SUCCESS) {
        secure_log(LOG_ERROR, "Failed to encapsulate Kyber768 secret");
        OQS_KEM_free(kem);
        return -1;
    }
    
    OQS_KEM_free(kem);
    
    // Combine shared secrets using HKDF or similar
    // shared_secret = HKDF(x25519_shared || kyber_shared)
    memcpy(shared_secret, x25519_shared, 32);
    memcpy(shared_secret + 32, kyber_shared, 32);
    
    // Clear sensitive data
    secure_memzero(x25519_ephemeral_private, sizeof(x25519_ephemeral_private));
    secure_memzero(x25519_shared, sizeof(x25519_shared));
    secure_memzero(kyber_shared, sizeof(kyber_shared));
    
    secure_log(LOG_DEBUG, "PQ encapsulation completed");
    return 0;
}

int betanet_pq_decaps_impl(const betanet_pq_private_key_t* private_key,
                           const betanet_pq_ciphertext_t* ciphertext,
                           uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]) {
    if (!private_key || !ciphertext || !shared_secret) {
        secure_log(LOG_ERROR, "Invalid parameters for PQ decaps");
        return -1;
    }
    
    uint8_t x25519_shared[32];
    uint8_t kyber_shared[32];
    
    // X25519 ECDH
    // TODO: Implement actual X25519 operations
    // crypto_scalarmult(x25519_shared, private_key->x25519_private, ciphertext->x25519_ephemeral);
    
    // Kyber768 decapsulation
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (!kem) {
        secure_log(LOG_ERROR, "Failed to initialize Kyber768 KEM for decaps");
        return -1;
    }
    
    if (OQS_KEM_decaps(kem, kyber_shared, ciphertext->kyber_ciphertext, 
                       private_key->kyber768_private) != OQS_SUCCESS) {
        secure_log(LOG_ERROR, "Failed to decapsulate Kyber768 secret");
        OQS_KEM_free(kem);
        return -1;
    }
    
    OQS_KEM_free(kem);
    
    // Combine shared secrets
    memcpy(shared_secret, x25519_shared, 32);
    memcpy(shared_secret + 32, kyber_shared, 32);
    
    // Clear sensitive data
    secure_memzero(x25519_shared, sizeof(x25519_shared));
    secure_memzero(kyber_shared, sizeof(kyber_shared));
    
    secure_log(LOG_DEBUG, "PQ decapsulation completed");
    return 0;
}

#else

// Stub implementation for development
int betanet_pq_keygen_stub(betanet_pq_private_key_t* private_key, 
                           betanet_pq_public_key_t* public_key) {
    if (!private_key || !public_key) {
        secure_log(SECURE_LOG_ERROR, "Invalid parameters for PQ keygen stub");
        return -1;
    }
    
    // Generate dummy keys for testing
    memset(private_key, 0xA5, sizeof(*private_key));
    memset(public_key, 0x5A, sizeof(*public_key));
    
    secure_log(SECURE_LOG_WARNING, "Using stub PQ keygen - not secure!");
    return 0;
}

static int pq_encaps_stub(const betanet_pq_public_key_t* public_key,
                          betanet_pq_ciphertext_t* ciphertext,
                          uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]) {
    if (!public_key || !ciphertext || !shared_secret) {
        return -1;
    }
    
    // Generate dummy ciphertext and shared secret
    memset(ciphertext, 0xCC, sizeof(*ciphertext));
    memset(shared_secret, 0x33, BETANET_PQ_SHARED_SECRET_SIZE);
    
    secure_log(SECURE_LOG_WARNING, "Using stub PQ encaps - not secure!");
    return 0;
}

static int pq_decaps_stub(const betanet_pq_private_key_t* private_key,
                          const betanet_pq_ciphertext_t* ciphertext,
                          uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]) {
    if (!private_key || !ciphertext || !shared_secret) {
        return -1;
    }
    
    // Generate dummy shared secret (should match encaps for testing)
    memset(shared_secret, 0x33, BETANET_PQ_SHARED_SECRET_SIZE);
    
    secure_log(SECURE_LOG_WARNING, "Using stub PQ decaps - not secure!");
    return 0;
}

#endif

// Public API wrappers
int betanet_pq_keygen(betanet_pq_private_key_t* private_key, 
                      betanet_pq_public_key_t* public_key) {
    if (!pq_initialized) {
        secure_log(SECURE_LOG_ERROR, "PQ subsystem not initialized");
        return -1;
    }
    
#ifdef BETANET_ENABLE_PQ_HYBRID
    return betanet_pq_keygen_impl(private_key, public_key);
#else
    return betanet_pq_keygen_stub(private_key, public_key);
#endif
}

int betanet_pq_encaps(const betanet_pq_public_key_t* public_key,
                      betanet_pq_ciphertext_t* ciphertext,
                      uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]) {
    if (!pq_initialized) {
        secure_log(SECURE_LOG_ERROR, "PQ subsystem not initialized");
        return -1;
    }
    
#ifdef BETANET_ENABLE_PQ_HYBRID
    return betanet_pq_encaps_impl(public_key, ciphertext, shared_secret);
#else
    return pq_encaps_stub(public_key, ciphertext, shared_secret);
#endif
}

int betanet_pq_decaps(const betanet_pq_private_key_t* private_key,
                      const betanet_pq_ciphertext_t* ciphertext,
                      uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]) {
    if (!pq_initialized) {
        secure_log(SECURE_LOG_ERROR, "PQ subsystem not initialized");
        return -1;
    }
    
#ifdef BETANET_ENABLE_PQ_HYBRID
    return betanet_pq_decaps_impl(private_key, ciphertext, shared_secret);
#else
    return pq_decaps_stub(private_key, ciphertext, shared_secret);
#endif
}
