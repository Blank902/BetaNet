#ifndef BETANET_PQ_HYBRID_H
#define BETANET_PQ_HYBRID_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Post-quantum hybrid key exchange implementation
// Mandatory from 2027-01-01 as per Betanet v1.1 specification

#define BETANET_PQ_PRIVATE_KEY_SIZE (32 + 2400)  // X25519 + Kyber768 private key sizes
#define BETANET_PQ_PUBLIC_KEY_SIZE (32 + 1184)   // X25519 + Kyber768 public key sizes
#define BETANET_PQ_SHARED_SECRET_SIZE 64         // Combined shared secret size
#define BETANET_PQ_CIPHERTEXT_SIZE 1088          // Kyber768 ciphertext size

typedef struct {
    uint8_t x25519_private[32];
    uint8_t kyber768_private[2400];  // Kyber768 private key
} betanet_pq_private_key_t;

typedef struct {
    uint8_t x25519_public[32];
    uint8_t kyber768_public[1184];   // Kyber768 public key
} betanet_pq_public_key_t;

typedef struct {
    uint8_t kyber_ciphertext[1088];  // Encapsulated Kyber768 secret
    uint8_t x25519_ephemeral[32];    // X25519 ephemeral public key
} betanet_pq_ciphertext_t;

// Core PQ hybrid functions

/**
 * Generate a post-quantum hybrid key pair
 * 
 * @param private_key Output private key
 * @param public_key Output public key
 * @return 0 on success, negative on error
 */
int betanet_pq_keygen(betanet_pq_private_key_t* private_key, 
                      betanet_pq_public_key_t* public_key);

/**
 * Encapsulate shared secret using recipient's public key
 * 
 * @param public_key Recipient's public key
 * @param ciphertext Output encapsulated secret
 * @param shared_secret Output shared secret (64 bytes)
 * @return 0 on success, negative on error
 */
int betanet_pq_encaps(const betanet_pq_public_key_t* public_key,
                      betanet_pq_ciphertext_t* ciphertext,
                      uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]);

/**
 * Decapsulate shared secret using private key
 * 
 * @param private_key Private key for decapsulation
 * @param ciphertext Encapsulated secret
 * @param shared_secret Output shared secret (64 bytes)
 * @return 0 on success, negative on error
 */
int betanet_pq_decaps(const betanet_pq_private_key_t* private_key,
                      const betanet_pq_ciphertext_t* ciphertext,
                      uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]);

/**
 * Check if post-quantum mode is mandatory (after 2027-01-01)
 * 
 * @return 1 if mandatory, 0 if optional
 */
int betanet_pq_is_mandatory(void);

/**
 * Initialize post-quantum cryptography subsystem
 * 
 * @return 0 on success, negative on error
 */
int betanet_pq_init(void);

/**
 * Cleanup post-quantum cryptography subsystem
 */
void betanet_pq_cleanup(void);

#ifdef BETANET_ENABLE_PQ_HYBRID
// Production implementation using liboqs or similar
int betanet_pq_keygen_impl(betanet_pq_private_key_t* private_key, 
                           betanet_pq_public_key_t* public_key);
int betanet_pq_encaps_impl(const betanet_pq_public_key_t* public_key,
                           betanet_pq_ciphertext_t* ciphertext,
                           uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]);
int betanet_pq_decaps_impl(const betanet_pq_private_key_t* private_key,
                           const betanet_pq_ciphertext_t* ciphertext,
                           uint8_t shared_secret[BETANET_PQ_SHARED_SECRET_SIZE]);
#endif

#ifdef __cplusplus
}
#endif

#endif // BETANET_PQ_HYBRID_H
