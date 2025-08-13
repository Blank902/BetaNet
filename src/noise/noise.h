/**
 * @file noise.h
 * @brief Noise XK secure channel integration for Betanet.
 *
 * Implements the Noise XK handshake with X25519 and ChaCha20-Poly1305 AEAD framing,
 * as specified in [README.md](README.md:155-169, 397) and [technical-overview.md](technical-overview.md:22,44,60-63,103,121,125,158-159,176).
 * PQ hybrid (Kyber768) is behind feature flag (see NOISE_PQ_HYBRID_ENABLED).
 * AEAD framing, key separation, nonce lifecycle, and rekeying logic per spec.
 *
 * Limitations:
 * - Kyber768 support is stubbed; only X25519 is fully functional ([README.md:397]).
 * - Static keys, PSK, and prologue are not implemented.
 * - Rekey/rotation is simplified ([README.md:169]).
 * - Replay defense is nonce-based only ([README.md:169]).
 * - See noise.c for implementation details and stub markers.
 */
#ifndef NOISE_H
#define NOISE_H

#include <stdint.h>
#include <stddef.h>
#include "../htx/htx.h"

/**
 * @struct noise_frame_t
 * @brief AEAD frame structure for encrypted transport.
 *
 * Frame layout per [README.md:155-169] and [technical-overview.md:60-63]:
 *   [2 bytes]   len        - Length of ciphertext+tag (little-endian)
 *   [12 bytes]  nonce      - 96-bit nonce for ChaCha20-Poly1305 (see [README.md:162])
 *   [N bytes]   ciphertext - Encrypted payload (with 16-byte Poly1305 tag)
 *
 * Note: Used internally; not exposed to API.
 */
typedef struct noise_frame_s {
    uint16_t len;      // Length of ciphertext (excluding header)
    uint8_t nonce[12]; // 96-bit nonce for ChaCha20-Poly1305
    uint8_t* ciphertext; // Pointer to ciphertext+tag
} noise_frame_t;

/**
 * @struct noise_channel_t
 * @brief Noise XK secure channel context.
 *
 * Maintains handshake state, AEAD keys, nonces, and rekey/replay tracking.
 *
 * Fields:
 *   htx                - Underlying transport (see htx.h)
 *   rx_key, tx_key     - AEAD keys (ChaCha20-Poly1305)
 *   handshake_complete - 1 if handshake finished
 *   tx_nonce, rx_nonce - Nonces for sending/receiving (incremented per frame)
 *   tx_bytes, rx_bytes - Counters for rekey triggers (see [README.md](README.md#rekeying))
 *   tx_frames, rx_frames - Frame counters for rekey triggers
 *   last_rekey_time    - Unix timestamp of last rekey
 *   rekey_pending      - Set if rekey is required before next send
 *   last_rx_nonce      - Last received nonce (for replay defense, see [README.md](README.md#replay-defense))
 */
typedef struct noise_channel_s {
    htx_ctx_t* htx;      // Underlying transport
    uint8_t rx_key[32];  // Receive key (ChaCha20-Poly1305), see [README.md:166]
    uint8_t tx_key[32];  // Transmit key (ChaCha20-Poly1305), see [README.md:166]
    uint8_t handshake_complete;
    uint64_t tx_nonce;   // Incremented per frame sent ([README.md:162], [technical-overview.md:60])
    uint64_t rx_nonce;   // Incremented per frame received
    // Rekey/rotation tracking ([README.md:169], [technical-overview.md:158-159])
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint32_t tx_frames;
    uint32_t rx_frames;
    uint64_t last_rekey_time; // Unix timestamp (seconds)
    // Rekey status
    uint8_t rekey_pending;
    // Frame replay defense ([README.md:169])
    uint64_t last_rx_nonce;
#ifdef NOISE_PQ_HYBRID_ENABLED
    // PQ hybrid fields (stub, see [README.md:397])
    uint8_t pq_rx_key[32];
    uint8_t pq_tx_key[32];
#endif
} noise_channel_t;

/**
 * Initialize Noise XK channel as initiator (client).
 * Implements handshake per [README.md:155-169], [technical-overview.md:22,44,103,121,125].
 * PQ hybrid is only enabled if NOISE_PQ_HYBRID_ENABLED is defined.
 */
int noise_channel_handshake_initiator(noise_channel_t* chan, htx_ctx_t* htx);

/**
 * Initialize Noise XK channel as responder (server).
 * Implements handshake per [README.md:155-169], [technical-overview.md:22,44,103,121,125].
 * PQ hybrid is only enabled if NOISE_PQ_HYBRID_ENABLED is defined.
 */
int noise_channel_handshake_responder(noise_channel_t* chan, htx_ctx_t* htx);
/**
 * Encrypt and send a message frame.
 * AEAD framing per [README.md:155-169], [technical-overview.md:60-63].
 * Triggers rekey if limits are reached ([README.md:169], [technical-overview.md:158-159]).
 */
int noise_channel_send(noise_channel_t* chan, const uint8_t* msg, size_t msg_len);

/**
 * Receive and decrypt a message frame.
 * AEAD framing per [README.md:155-169], [technical-overview.md:60-63].
 * Triggers rekey if limits are reached ([README.md:169], [technical-overview.md:158-159]).
 */
int noise_channel_recv(noise_channel_t* chan, uint8_t* out, size_t max_len, size_t* out_len);

/// Rekey/rotation per [README.md:169], [technical-overview.md:158-159].
int noise_channel_rekey(noise_channel_t* chan);

/// Query if rekey is pending (1) or not (0).
int noise_channel_rekey_pending(noise_channel_t* chan);



#ifdef BETANET_ENABLE_PQ_HYBRID
/**
 * Kyber768 KEM keypair generation (stub).
 * @param[out] pk Public key buffer (must be at least 1184 bytes)
 * @param[out] sk Secret key buffer (must be at least 2400 bytes)
 * @return 0 (stub)
 */
int noise_kyber768_keypair(uint8_t *pk, uint8_t *sk);

/**
 * Kyber768 KEM encapsulation (stub).
 * @param[in] pk Public key buffer (1184 bytes)
 * @param[out] ct Ciphertext buffer (must be at least 1088 bytes)
 * @param[out] ss Shared secret buffer (must be at least 32 bytes)
 * @return 0 (stub)
 */
int noise_kyber768_encaps(const uint8_t *pk, uint8_t *ct, uint8_t *ss);

/**
 * Kyber768 KEM decapsulation (stub).
 * @param[in] ct Ciphertext buffer (1088 bytes)
 * @param[in] sk Secret key buffer (2400 bytes)
 * @param[out] ss Shared secret buffer (must be at least 32 bytes)
 * @return 0 (stub)
 */
int noise_kyber768_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t *ss);
#endif // BETANET_ENABLE_PQ_HYBRID

#endif // NOISE_H