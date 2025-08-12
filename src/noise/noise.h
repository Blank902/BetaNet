/**
 * @file noise.h
 * @brief Noise XK secure channel integration for Betanet.
 *
 * Implements a simplified Noise XK handshake with hybrid X25519 and (stubbed) Kyber768 support,
 * AEAD framing (ChaCha20-Poly1305), rekey/rotation, and replay defense.
 *
 * See Betanet specification, section "Transport Security" ([README.md](README.md#transport-security)),
 * and "Noise Protocol Handshake" ([README.md](README.md#noise-xk-handshake)).
 *
 * Limitations:
 * - Kyber768 support is stubbed; only X25519 is fully functional (see [README.md](README.md#post-quantum)).
 * - Static keys, PSK, and prologue are not implemented.
 * - Rekey/rotation is simplified (see [README.md](README.md#rekeying)).
 * - Replay defense is nonce-based only.
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
 * Frame layout (see [README.md](README.md#aead-framing)):
 *   [2 bytes]   len        - Length of ciphertext+tag (little-endian)
 *   [12 bytes]  nonce      - 96-bit nonce for ChaCha20-Poly1305
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
    uint8_t rx_key[32];  // Receive key (ChaCha20-Poly1305)
    uint8_t tx_key[32];  // Transmit key (ChaCha20-Poly1305)
    uint8_t handshake_complete;
    uint64_t tx_nonce;
    uint64_t rx_nonce;
    // Rekey/rotation tracking
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint32_t tx_frames;
    uint32_t rx_frames;
    uint64_t last_rekey_time; // Unix timestamp (seconds)
    // Rekey status
    uint8_t rekey_pending;
    // Frame replay defense
    uint64_t last_rx_nonce;
} noise_channel_t;

// Initialize Noise XK channel over established HTX transport (client)
int noise_channel_handshake_initiator(noise_channel_t* chan, htx_ctx_t* htx);

// Initialize Noise XK channel over established HTX transport (responder)
int noise_channel_handshake_responder(noise_channel_t* chan, htx_ctx_t* htx);
/**
 * Encrypt and send a message frame.
 * Triggers rekey if limits are reached.
 */
int noise_channel_send(noise_channel_t* chan, const uint8_t* msg, size_t msg_len);

/**
 * Receive and decrypt a message frame.
 * Triggers rekey if limits are reached.
 */
int noise_channel_recv(noise_channel_t* chan, uint8_t* out, size_t max_len, size_t* out_len);

/**
 * Manually trigger rekey/rotation.
 * Returns 0 on success, -1 on error.
 */
int noise_channel_rekey(noise_channel_t* chan);

/**
 * Query if rekey is pending (1) or not (0).
 */
int noise_channel_rekey_pending(noise_channel_t* chan);


#endif // NOISE_H