/**
 * @file noise.c
 * @brief Implementation of Noise XK handshake and AEAD framing for Betanet.
 *
 * Implements a simplified Noise XK handshake with hybrid X25519 and (stubbed) Kyber768 support,
 * AEAD framing (ChaCha20-Poly1305), rekey/rotation, and replay defense.
 *
 * See Betanet specification:
 *   - "Transport Security" ([README.md](README.md#transport-security))
 *   - "Noise Protocol Handshake" ([README.md](README.md#noise-xk-handshake))
 *   - "AEAD Framing" ([README.md](README.md#aead-framing))
 *   - "Rekeying" ([README.md](README.md#rekeying))
 *   - "Replay Defense" ([README.md](README.md#replay-defense))
 *
// Limitations:
//   - Kyber768 support is stubbed; only X25519 is fully functional (see [README.md:397], [technical-overview.md:176]).
//   - PQ hybrid handshake is not production-ready; see documentation for rationale and mitigation.
//   - Static keys, PSK, and prologue are not implemented.
//   - Rekey/rotation is simplified.
//   - Replay defense is nonce-based only.
//   - See stub/incomplete markers below.
 */
#include "noise.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/*
 * --- PQ Hybrid Handshake Stub ---
 * This is a stub for PQ hybrid handshake support.
 * The actual PQ hybrid handshake is NOT implemented.
 * To enable this stub, define ENABLE_PQ_HYBRID_HANDSHAKE at compile time.
 * All logic is disabled unless ENABLE_PQ_HYBRID_HANDSHAKE is defined.
 * See [README.md] for rationale and status.
 */
#ifdef ENABLE_PQ_HYBRID_HANDSHAKE
// PQ hybrid handshake stub (not implemented)
// This section is intentionally left as a stub.
// Do NOT use in production. No PQ hybrid handshake logic is present.
#endif
/*
 * --- Kyber768 KEM wrappers (stubbed) ---
 * PQ hybrid handshake is not implemented; these are placeholders.
 * See [README.md:397], [technical-overview.md:176] for rationale and mitigation.
 * Only X25519 is functional.
 * To enable PQ hybrid, define BETANET_ENABLE_PQ_HYBRID at compile time.
 */
#ifdef BETANET_ENABLE_PQ_HYBRID
#include "kyber768.h" // You must provide this header and link the Kyber768 C implementation

// TODO: Initialize Kyber768 library if required (e.g., PQClean/liboqs setup)
// void noise_kyber768_init(void) { /* Call PQClean/liboqs init if needed */ }
// void noise_kyber768_cleanup(void) { /* Call PQClean/liboqs cleanup if needed */ }
#endif

// PQ hybrid constants (see [README.md:397])
// Define constants even when PQ hybrid is disabled for struct compilation
#define KYBER_PUBLICKEYBYTES 1184
#define KYBER_SECRETKEYBYTES 2400
#define KYBER_CIPHERTEXTBYTES 1088
#define KYBER_SHAREDKEYBYTES 32

#ifdef BETANET_ENABLE_PQ_HYBRID
#include "kyber768.h" // You must provide this header and link the Kyber768 C implementation

// TODO: Initialize Kyber768 library if required (e.g., PQClean/liboqs setup)
// void noise_kyber768_init(void) { /* Call PQClean/liboqs init if needed */ }
// void noise_kyber768_cleanup(void) { /* Call PQClean/liboqs cleanup if needed */ }
#endif

/*
 * PQ hybrid stubs (see [README.md:397], [technical-overview.md:176])
 * All Kyber768 KEM functions are stubs when PQ hybrid is disabled.
 */
#ifdef BETANET_ENABLE_PQ_HYBRID
static int noise_kyber768_keypair(uint8_t *pk, uint8_t *sk) {
    // Returns 0 on success
    return kyber768_keypair(pk, sk);
}

static int noise_kyber768_encaps(const uint8_t *pk, uint8_t *ct, uint8_t *ss) {
    // Returns 0 on success
    return kyber768_enc(ct, ss, pk);
}

static int noise_kyber768_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t *ss) {
    // Returns 0 on success
    return kyber768_dec(ss, ct, sk);
}
#else
// Stubs for builds without PQ hybrid (see [README.md:397])
static int noise_kyber768_keypair(uint8_t *pk, uint8_t *sk) { 
    (void)pk; (void)sk; 
    // Fill with deterministic data for testing
    memset(pk, 0xAA, KYBER_PUBLICKEYBYTES);
    memset(sk, 0xBB, KYBER_SECRETKEYBYTES);
    return 0; 
}
static int noise_kyber768_encaps(const uint8_t *pk, uint8_t *ct, uint8_t *ss) { 
    (void)pk; 
    // Fill with deterministic data for testing
    memset(ct, 0xCC, KYBER_CIPHERTEXTBYTES);
    memset(ss, 0xDD, KYBER_SHAREDKEYBYTES);
    return 0; 
}
static int noise_kyber768_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t *ss) { 
    (void)ct; (void)sk; 
    // Fill with deterministic data for testing
    memset(ss, 0xDD, KYBER_SHAREDKEYBYTES);
    return 0; 
}
#endif

/*
/*
 * === Noise XK Handshake Implementation ===
 */

// --- Helpers for X25519 and ChaCha20-Poly1305 ---
// See [README.md](README.md#noise-xk-handshake) for key exchange details.

static int gen_x25519_keypair(uint8_t *priv, uint8_t *pub) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return -1;
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto err;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) goto err;
    size_t len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, priv, &len) <= 0) goto err;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &len) <= 0) goto err;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return 0;
err:
    if (pkey) EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return -1;
}

static int x25519_shared_secret(const uint8_t *priv, const uint8_t *pub, uint8_t *secret) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL, *peerkey = NULL;
    size_t secret_len = 32;
    int ret = -1;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pub, 32);
    if (!pkey || !peerkey) goto cleanup;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) goto cleanup;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) goto cleanup;
    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0) goto cleanup;
    ret = 0;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (peerkey) EVP_PKEY_free(peerkey);
    return ret;
}

static int chacha20poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *plaintext, size_t plaintext_len,
                                    uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len = 0, ret = -1;
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto cleanup;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) goto cleanup;
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) goto cleanup;
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) goto cleanup;
    ret = ciphertext_len;
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int chacha20poly1305_decrypt(const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *aad, size_t aad_len,
                                    const uint8_t *ciphertext, size_t ciphertext_len,
                                    const uint8_t *tag,
                                    uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len = 0, ret = -1;
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) goto cleanup;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto cleanup;
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) goto cleanup;
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) != 1) goto cleanup;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) goto cleanup;
    plaintext_len += len;
    ret = plaintext_len;
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * --- Noise XK Handshake ---
 * Implements handshake per [README.md:155-169], [technical-overview.md:22,44,103,121,125].
 * PQ hybrid is only enabled if BETANET_ENABLE_PQ_HYBRID is defined ([README.md:397]).
 * Static keys, PSK, and prologue are not implemented.
 */
// NOTE: This implementation omits static keys, PSK, and prologue for simplicity.
// Kyber768 is stubbed; only X25519 is functional. See [README.md:397], [technical-overview.md:176].
// See Betanet spec for full handshake flow.

// For demo: static prologue, no PSK, no static keys
static const uint8_t prologue[] = "betanet-noise-xk";

typedef struct {
    uint8_t e_priv[32], e_pub[32];
    uint8_t re_pub[32];
    uint8_t s_pub[32]; // not used in demo
    uint8_t rs_pub[32];
    uint8_t chaining_key[32];
    uint8_t handshake_hash[32];
    uint8_t temp_k1[32], temp_k2[32];

    // Kyber768 ephemeral keys (stubbed, see [README.md](README.md#post-quantum))
    uint8_t kyber_pk[KYBER_PUBLICKEYBYTES];
    uint8_t kyber_sk[KYBER_SECRETKEYBYTES];
    uint8_t re_kyber_pk[KYBER_PUBLICKEYBYTES];
    uint8_t re_kyber_ct[KYBER_CIPHERTEXTBYTES];
    uint8_t kyber_ss[KYBER_SHAREDKEYBYTES];
    uint8_t re_kyber_ss[KYBER_SHAREDKEYBYTES];
} noise_handshake_state_t;

// --- HKDF (SHA256) ---
// Used for key derivation in handshake and rekeying (see [README.md](README.md#rekeying))
static void hkdf_sha256(const uint8_t *ck, const uint8_t *input, size_t input_len, uint8_t *out1, uint8_t *out2) {
    uint8_t prk[32];
    unsigned int len;
    HMAC(EVP_sha256(), ck, 32, input, input_len, prk, &len);
    uint8_t t1[32], t2[32];
    uint8_t c = 1;
    HMAC(EVP_sha256(), prk, 32, &c, 1, t1, &len);
    c = 2;
    HMAC(EVP_sha256(), prk, 32, t1, 32 + 1, t2, &len);
    memcpy(out1, t1, 32);
    memcpy(out2, t2, 32);
}

// --- API Implementation ---

/*
 * Noise XK handshake initiator (client)
 * Implements [README.md:155-169], [technical-overview.md:22,44,103,121,125].
 * PQ hybrid is only enabled if BETANET_ENABLE_PQ_HYBRID is defined.
 */
int noise_channel_handshake_initiator(noise_channel_t* chan, htx_ctx_t* htx) {
    if (!chan || !htx) return -1;
    memset(chan, 0, sizeof(*chan));
    chan->htx = htx;

    // Generate X25519 ephemeral keypair
    uint8_t e_priv[32], e_pub[32];
    if (gen_x25519_keypair(e_priv, e_pub) != 0) return -1;

#ifdef BETANET_ENABLE_PQ_HYBRID
    // Generate Kyber768 ephemeral keypair
    uint8_t kyber_pk[KYBER_PUBLICKEYBYTES], kyber_sk[KYBER_SECRETKEYBYTES];
    if (noise_kyber768_keypair(kyber_pk, kyber_sk) != 0) return -1;
#endif

    // Send e_pub (always)
    if (SSL_write(htx->state.tcp.ssl, e_pub, 32) != 32) return -1;
#ifdef BETANET_ENABLE_PQ_HYBRID
    // Send kyber_pk if PQ hybrid enabled
    if (SSL_write(htx->state.tcp.ssl, kyber_pk, KYBER_PUBLICKEYBYTES) != KYBER_PUBLICKEYBYTES) return -1;
#endif

    // Receive re_pub (always)
    uint8_t re_pub[32];
    if (SSL_read(htx->state.tcp.ssl, re_pub, 32) != 32) return -1;
#ifdef BETANET_ENABLE_PQ_HYBRID
    // Receive re_kyber_ct if PQ hybrid enabled
    uint8_t re_kyber_ct[KYBER_CIPHERTEXTBYTES];
    if (SSL_read(htx->state.tcp.ssl, re_kyber_ct, KYBER_CIPHERTEXTBYTES) != KYBER_CIPHERTEXTBYTES) return -1;
#endif

    // Perform DH: ee (X25519)
    uint8_t dh[32];
    if (x25519_shared_secret(e_priv, re_pub, dh) != 0) return -1;

#ifdef BETANET_ENABLE_PQ_HYBRID
    // Kyber768 decapsulation
    uint8_t kyber_ss[KYBER_SHAREDKEYBYTES];
    if (noise_kyber768_decaps(re_kyber_ct, kyber_sk, kyber_ss) != 0) return -1;
    // Derive hybrid secret: concat(dh || kyber_ss)
    uint8_t hybrid_secret[32 + KYBER_SHAREDKEYBYTES];
    memcpy(hybrid_secret, dh, 32);
    memcpy(hybrid_secret + 32, kyber_ss, KYBER_SHAREDKEYBYTES);
    // Derive keys (tx_key, rx_key) = HKDF(hybrid_secret)
    hkdf_sha256(hybrid_secret, NULL, 0, chan->tx_key, chan->rx_key);
    // TODO: Negotiate/fallback if Kyber768 fails or is not supported by peer.
    // TODO: Add additional tests for hybrid secret derivation.
#else
    // Derive keys (tx_key, rx_key) = HKDF(dh)
    hkdf_sha256(dh, NULL, 0, chan->tx_key, chan->rx_key);
#endif

    chan->handshake_complete = 1;
    chan->tx_nonce = 0;
    chan->rx_nonce = 0;
    return 0;
}

/*
 * Noise XK handshake responder (server)
 * Implements [README.md:155-169], [technical-overview.md:22,44,103,121,125].
 * PQ hybrid is only enabled if BETANET_ENABLE_PQ_HYBRID is defined.
 */
int noise_channel_handshake_responder(noise_channel_t* chan, htx_ctx_t* htx) {
    if (!chan || !htx) return -1;
    memset(chan, 0, sizeof(*chan));
    chan->htx = htx;

    // Generate ephemeral keypair (X25519)
    uint8_t re_priv[32], re_pub[32];
    if (gen_x25519_keypair(re_priv, re_pub) != 0) return -1;

    // Receive e_pub (always)
    uint8_t e_pub[32];
    if (SSL_read(htx->state.tcp.ssl, e_pub, 32) != 32) return -1;
#ifdef BETANET_ENABLE_PQ_HYBRID
    // Receive kyber_pk if PQ hybrid enabled
    uint8_t kyber_pk[KYBER_PUBLICKEYBYTES];
    if (SSL_read(htx->tcp.ssl, kyber_pk, KYBER_PUBLICKEYBYTES) != KYBER_PUBLICKEYBYTES) return -1;
#endif

    // Send re_pub (always)
    if (SSL_write(htx->state.tcp.ssl, re_pub, 32) != 32) return -1;
#ifdef BETANET_ENABLE_PQ_HYBRID
    // Kyber768 encapsulation
    uint8_t re_kyber_ct[KYBER_CIPHERTEXTBYTES], re_kyber_ss[KYBER_SHAREDKEYBYTES];
    if (noise_kyber768_encaps(kyber_pk, re_kyber_ct, re_kyber_ss) != 0) return -1;
    // Send re_kyber_ct to initiator
    if (SSL_write(htx->state.tcp.ssl, re_kyber_ct, KYBER_CIPHERTEXTBYTES) != KYBER_CIPHERTEXTBYTES) return -1;
#endif

    // Perform DH: ee (X25519)
    uint8_t dh[32];
    if (x25519_shared_secret(re_priv, e_pub, dh) != 0) return -1;

#ifdef BETANET_ENABLE_PQ_HYBRID
    // Derive hybrid secret: concat(dh || re_kyber_ss)
    uint8_t hybrid_secret[32 + KYBER_SHAREDKEYBYTES];
    memcpy(hybrid_secret, dh, 32);
    memcpy(hybrid_secret + 32, re_kyber_ss, KYBER_SHAREDKEYBYTES);
    // Derive keys (tx_key, rx_key) = HKDF(hybrid_secret)
    hkdf_sha256(hybrid_secret, NULL, 0, chan->tx_key, chan->rx_key);
    // TODO: Negotiate/fallback if Kyber768 fails or is not supported by peer.
    // TODO: Add additional tests for hybrid secret derivation.
#else
    // Derive keys (tx_key, rx_key) = HKDF(dh)
    hkdf_sha256(dh, NULL, 0, chan->tx_key, chan->rx_key);
#endif

    chan->handshake_complete = 1;
    chan->tx_nonce = 0;
    chan->rx_nonce = 0;
    return 0;
}

// --- Rekey/rotation logic ---
// See [README.md](README.md#rekeying)
static int noise_channel_should_rekey(noise_channel_t* chan) {
    if (!chan) return 0;
    if (chan->tx_bytes >= (1ULL << 33)) return 1; // 8 GiB
    if (chan->tx_frames >= (1U << 16)) return 1;  // 2^16 frames
    time_t now = time(NULL);
    if (chan->last_rekey_time && (uint64_t)now - chan->last_rekey_time >= 3600) return 1; // 1h
    return 0;
}

// --- Rekey/rotation implementation ---
// See [README.md](README.md#rekeying)
int noise_channel_rekey(noise_channel_t* chan) {
    if (!chan || !chan->handshake_complete) return -1;
    // Derive new keys from current keys (simple HKDF)
    uint8_t new_tx[32], new_rx[32];
    hkdf_sha256(chan->tx_key, NULL, 0, new_tx, new_rx);
    memcpy(chan->tx_key, new_tx, 32);
    memcpy(chan->rx_key, new_rx, 32);
    chan->tx_nonce = 0;
    chan->rx_nonce = 0;
    chan->tx_bytes = 0;
    chan->rx_bytes = 0;
    chan->tx_frames = 0;
    chan->rx_frames = 0;
    chan->last_rekey_time = (uint64_t)time(NULL);
    chan->rekey_pending = 0;
    return 0;
}

int noise_channel_rekey_pending(noise_channel_t* chan) {
    if (!chan) return 0;
    return chan->rekey_pending;
}

// --- AEAD Framing ---
// See [README.md](README.md#aead-framing)

// --- Encrypt and send AEAD frame ---
// See [README.md](README.md#aead-framing) and [README.md](README.md#rekeying)
int noise_channel_send(noise_channel_t* chan, const uint8_t* msg, size_t msg_len) {
    if (!chan || !chan->handshake_complete) return -1;
    if (msg_len > 4096) return -2; // arbitrary max

    // Rekey if needed
    if (noise_channel_should_rekey(chan)) {
        chan->rekey_pending = 1;
        if (noise_channel_rekey(chan) != 0) return -5;
    }

    uint8_t nonce[12] = {0};
    memcpy(nonce + 4, &chan->tx_nonce, 8); // little-endian
    chan->tx_nonce++;

    uint8_t ciphertext[4096 + 16];
    uint8_t tag[16];
    int clen = chacha20poly1305_encrypt(chan->tx_key, nonce, NULL, 0, msg, msg_len, ciphertext, tag);
    if (clen < 0) return -3;

    uint16_t frame_len = (uint16_t)(clen + 16);
    uint8_t frame[2 + 12 + 4096 + 16];
    frame[0] = frame_len & 0xFF;
    frame[1] = (frame_len >> 8) & 0xFF;
    memcpy(frame + 2, nonce, 12);
    memcpy(frame + 14, ciphertext, clen);
    memcpy(frame + 14 + clen, tag, 16);

    int sent = SSL_write(chan->htx->state.tcp.ssl, frame, 2 + 12 + clen + 16);

    // Update counters
    chan->tx_bytes += msg_len;
    chan->tx_frames += 1;

    return (sent == 2 + 12 + clen + 16) ? 0 : -4;
}

int noise_channel_recv(noise_channel_t* chan, uint8_t* out, size_t max_len, size_t* out_len) {
    if (!chan || !chan->handshake_complete) return -1;
    uint8_t hdr[2 + 12];
    int r = SSL_read(chan->htx->state.tcp.ssl, hdr, 14);
    if (r != 14) return -2;
    uint16_t frame_len = hdr[0] | (hdr[1] << 8);
    if (frame_len > 4096 + 16) return -3;
    uint8_t* ciphertext = malloc(frame_len);
    if (!ciphertext) return -4;
    r = SSL_read(chan->htx->state.tcp.ssl, ciphertext, frame_len);
    if (r != frame_len) { free(ciphertext); return -5; }
    uint8_t* tag = ciphertext + (frame_len - 16);

    // Extract nonce from header (little-endian)
    uint64_t rx_nonce_val = 0;
    memcpy(&rx_nonce_val, hdr + 4, 8);

    // Frame replay defense: reject if nonce <= last_rx_nonce
    if (rx_nonce_val <= chan->last_rx_nonce) {
        free(ciphertext);
        return -7; // replay detected
    }

    uint8_t plaintext[4096];
    int plen = chacha20poly1305_decrypt(chan->rx_key, hdr + 2, NULL, 0, ciphertext, frame_len - 16, tag, plaintext);
    if (plen < 0 || (size_t)plen > max_len) { free(ciphertext); return -6; }
    memcpy(out, plaintext, plen);
    *out_len = plen;
    free(ciphertext);
    chan->rx_nonce++;
    chan->last_rx_nonce = rx_nonce_val;
    return 0;
}