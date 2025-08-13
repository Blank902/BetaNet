// quic.h - Transport-agnostic QUIC API (opaque handle, conditional compilation)
//
// Copyright (c) BetaNet contributors
//
// This header defines the public API for QUIC transport integration.
// All logic is gated by BETANET_ENABLE_QUIC. Library-specific logic
// is selected via macros (e.g., BETANET_QUIC_USE_MOONQUIC).
//
// TODO: Implement library-specific logic in quic.c.

#ifndef HTX_QUIC_H
#define HTX_QUIC_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(BETANET_ENABLE_QUIC)

// Opaque QUIC connection handle
typedef struct htx_quic_conn htx_quic_conn_t;

// QUIC API

/**
 * Initialize global QUIC state.
 * Returns 0 on success, negative on error.
 */
int quic_init(void);

/**
 * Shutdown global QUIC state.
 * Returns 0 on success, negative on error.
 */
int quic_shutdown(void);

/**
 * Establish a new QUIC connection.
 * Returns handle on success, NULL on error.
 *
 * @param host  Remote host (UTF-8, null-terminated)
 * @param port  Remote port
 */
htx_quic_conn_t* quic_connect(const char* host, unsigned short port);

/**
 * Send data over a QUIC connection.
 * Returns number of bytes sent, or negative on error.
 *
 * @param conn  QUIC connection handle
 * @param data  Data buffer
 * @param len   Buffer length
 */
int quic_send(htx_quic_conn_t* conn, const void* data, unsigned int len);

/**
 * Receive data from a QUIC connection.
 * Returns number of bytes received, 0 for EOF, or negative on error.
 *
 * @param conn  QUIC connection handle
 * @param buf   Output buffer
 * @param len   Buffer length
 */
int quic_recv(htx_quic_conn_t* conn, void* buf, unsigned int len);

/**
 * Close a QUIC connection and free resources.
 *
 * @param conn  QUIC connection handle
 */
void quic_close(htx_quic_conn_t* conn);

#else // BETANET_ENABLE_QUIC not defined

// Stubs if QUIC is disabled
typedef void htx_quic_conn_t;
static inline int quic_init(void) { return 0; }
static inline int quic_shutdown(void) { return 0; }
static inline htx_quic_conn_t* quic_connect(const char* host, unsigned short port) { (void)host; (void)port; return 0; }
static inline int quic_send(htx_quic_conn_t* conn, const void* data, unsigned int len) { (void)conn; (void)data; (void)len; return -1; }
static inline int quic_recv(htx_quic_conn_t* conn, void* buf, unsigned int len) { (void)conn; (void)buf; (void)len; return -1; }
static inline void quic_close(htx_quic_conn_t* conn) { (void)conn; }

#endif // BETANET_ENABLE_QUIC

#ifdef __cplusplus
}
#endif

#endif // HTX_QUIC_H