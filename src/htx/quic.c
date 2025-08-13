// quic.c - Transport-agnostic QUIC API implementation
//
// Copyright (c) BetaNet contributors
//
// This file implements the stub logic for the QUIC API declared in quic.h.
// Actual library integration is selected via macros and implemented here.
//
// TODO: Implement library-specific logic for selected QUIC backend.

#include "quic.h"

#if defined(BETANET_ENABLE_QUIC)

#include <stdlib.h>
#include <string.h>

// Opaque QUIC connection handle definition
struct htx_quic_conn {
    // TODO: Add library-specific connection state here
    void* impl;
};

int quic_init(void) {
    // TODO: Initialize selected QUIC library (e.g., MoonQUIC, MsQUIC)
    return 0;
}

int quic_shutdown(void) {
    // TODO: Shutdown selected QUIC library
    return 0;
}

htx_quic_conn_t* quic_connect(const char* host, unsigned short port) {
    (void)host;
    (void)port;
    // TODO: Establish QUIC connection using selected library
    struct htx_quic_conn* conn = (struct htx_quic_conn*)malloc(sizeof(struct htx_quic_conn));
    if (!conn) return NULL;
    conn->impl = NULL;
    return conn;
}

int quic_send(htx_quic_conn_t* conn, const void* data, unsigned int len) {
    (void)conn;
    (void)data;
    (void)len;
    // TODO: Send data using selected QUIC library
    return -1;
}

int quic_recv(htx_quic_conn_t* conn, void* buf, unsigned int len) {
    (void)conn;
    (void)buf;
    (void)len;
    // TODO: Receive data using selected QUIC library
    return -1;
}

void quic_close(htx_quic_conn_t* conn) {
    if (!conn) return;
    // TODO: Close connection and free library-specific resources
    free(conn);
}

#endif // BETANET_ENABLE_QUIC