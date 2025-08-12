#ifndef BETANET_H
#define BETANET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "../src/shape/shape.h"

// Forward declarations for HTX and ticket types
typedef struct htx_ctx_s htx_ctx_t;
typedef struct htx_ticket_s htx_ticket_t;

#include "../src/path/path.h"

// Public API function prototypes
void betanet_init(void);
void betanet_shutdown(void);

#include "../src/path/path.h"

// Privacy mode API
int betanet_set_privacy_mode(htx_ctx_t* ctx, betanet_privacy_mode_t mode);
betanet_privacy_mode_t betanet_get_privacy_mode(const htx_ctx_t* ctx);

// Peer trust scoring API
int betanet_set_peer_trust(htx_ctx_t* ctx, const betanet_peer_trust_t* trust);
int betanet_get_peer_trust(const htx_ctx_t* ctx, betanet_peer_trust_t* trust_out);

typedef enum {
    BETANET_TRANSPORT_TCP = 0,
    BETANET_TRANSPORT_QUIC = 1
} betanet_transport_t;

// Betanet context management
htx_ctx_t* betanet_ctx_create_with_transport(betanet_transport_t transport);
htx_ctx_t* betanet_ctx_create(void); // legacy, defaults to TCP
void betanet_ctx_free(htx_ctx_t* ctx);

// Connect to a peer using a ticket (client)
int betanet_connect_with_ticket(htx_ctx_t* ctx, const char* host, uint16_t port, const char* ticket_str);

// Accept a peer using a ticket (server stub)
int betanet_accept_with_ticket(htx_ctx_t* ctx, const char* ticket_str);

// Connection status
int betanet_is_connected(htx_ctx_t* ctx);

/**
 * Set shaping/fingerprinting profile for a context.
 * Returns 0 on success, -1 on error.
 */
int betanet_set_shaping_profile(htx_ctx_t* ctx, shape_profile_t profile);

/**
 * Get current shaping/fingerprinting profile for a context.
 * Returns profile enum.
 */
/**
 * --- Multipath Routing & SCION API ---
 *
 * These APIs enable multipath routing and SCION/Skyon path selection.
 * Paths are managed per-context and can be provided by user callbacks.
 */

#include "../src/path/path.h"

/**
 * Set the path list for a context (multipath).
 * Returns 0 on success, -1 on error.
 */
int betanet_set_path_list(htx_ctx_t* ctx, const betanet_path_list_t* plist);

/**
 * Get the current path list for a context.
 * Returns pointer to internal path list (do not free).
 */
const betanet_path_list_t* betanet_get_path_list(const htx_ctx_t* ctx);

/**
 * Register a custom path selection/provider callback.
 * The callback should fill out a betanet_path_list_t for the peer.
 */
typedef void (*betanet_path_provider_fn)(betanet_path_list_t* plist, void* user_data);
void betanet_path_set_provider(htx_ctx_t* ctx, betanet_path_provider_fn fn, void* user_data);

shape_profile_t betanet_get_shaping_profile(htx_ctx_t* ctx);

// --- Secure Channel API (Noise XK) ---

typedef struct noise_channel_s noise_channel_t;

// Create and initialize a secure channel context
noise_channel_t* betanet_secure_channel_create(void);
void betanet_secure_channel_free(noise_channel_t* chan);

// Perform Noise XK handshake (client/initiator)
int betanet_secure_handshake_initiator(noise_channel_t* chan, htx_ctx_t* htx);

// Perform Noise XK handshake (server/responder)
int betanet_secure_handshake_responder(noise_channel_t* chan, htx_ctx_t* htx);

/**
 * Send encrypted message.
 */
int betanet_secure_send(noise_channel_t* chan, const uint8_t* msg, size_t msg_len);

/**
 * Receive encrypted message.
 */
int betanet_secure_recv(noise_channel_t* chan, uint8_t* out, size_t max_len, size_t* out_len);

/**
 * Manually trigger rekey/rotation.
 * Returns 0 on success, -1 on error.
 */
int betanet_secure_rekey(noise_channel_t* chan);

/**
 * Query if rekey is pending (1) or not (0).
 */
int betanet_secure_rekey_pending(noise_channel_t* chan);

#ifdef __cplusplus
}
#endif
 
// --- Governance & Compliance API ---
#include "../../src/gov/gov.h"
#endif // BETANET_H