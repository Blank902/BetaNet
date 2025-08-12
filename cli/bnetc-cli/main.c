// Minimal Betanet CLI demo: local peer-to-peer session with HTX, Noise XK, and ticket stubs.
// See: technical-overview.md, README.md

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>

#include "betanet/betanet.h"

#define DEMO_PORT 44443
#define DEMO_HOST "127.0.0.1"
#define DEMO_TICKET "dummy-ticket-stub"

void* server_thread(void* arg) {
    printf("[server] Starting server peer...\n");
    htx_ctx_t* srv_ctx = betanet_ctx_create_with_transport(BETANET_TRANSPORT_TCP);
    if (!srv_ctx) {
        fprintf(stderr, "[server] Failed to create context\n");
        return NULL;
    }

    // Accept with ticket (stub)
    if (betanet_accept_with_ticket(srv_ctx, DEMO_TICKET) != 0) {
        fprintf(stderr, "[server] Accept with ticket failed (stub)\n");
        betanet_ctx_free(srv_ctx);
        return NULL;
    }
    printf("[server] Waiting for client connection...\n");
    while (!betanet_is_connected(srv_ctx)) {
        usleep(100000); // 100ms
    }
    printf("[server] Client connected!\n");

    // Secure channel (Noise XK handshake)
    noise_channel_t* srv_chan = betanet_secure_channel_create();
    if (!srv_chan) {
        fprintf(stderr, "[server] Failed to create secure channel\n");
        betanet_ctx_free(srv_ctx);
        return NULL;
    }
    if (betanet_secure_handshake_responder(srv_chan, srv_ctx) != 0) {
        fprintf(stderr, "[server] Noise XK handshake failed\n");
        betanet_secure_channel_free(srv_chan);
        betanet_ctx_free(srv_ctx);
        return NULL;
    }
    printf("[server] Noise XK handshake complete\n");

    // Echo loop: receive, then send back
    uint8_t buf[256];
    size_t out_len = 0;
    if (betanet_secure_recv(srv_chan, buf, sizeof(buf), &out_len) == 0) {
        printf("[server] Received: %.*s\n", (int)out_len, buf);
        betanet_secure_send(srv_chan, buf, out_len);
        printf("[server] Echoed back\n");
    } else {
        fprintf(stderr, "[server] Secure recv failed\n");
    }

    betanet_secure_channel_free(srv_chan);
    betanet_ctx_free(srv_ctx);
    printf("[server] Done\n");
    return NULL;
}

void* client_thread(void* arg) {
    usleep(200000); // Wait for server to start
    printf("[client] Starting client peer...\n");
    htx_ctx_t* cli_ctx = betanet_ctx_create_with_transport(BETANET_TRANSPORT_TCP);
    if (!cli_ctx) {
        fprintf(stderr, "[client] Failed to create context\n");
        return NULL;
    }

    // Connect with ticket (stub)
    if (betanet_connect_with_ticket(cli_ctx, DEMO_HOST, DEMO_PORT, DEMO_TICKET) != 0) {
        fprintf(stderr, "[client] Connect with ticket failed (stub)\n");
        betanet_ctx_free(cli_ctx);
        return NULL;
    }
    while (!betanet_is_connected(cli_ctx)) {
        usleep(100000); // 100ms
    }
    printf("[client] Connected to server!\n");

    // Secure channel (Noise XK handshake)
    noise_channel_t* cli_chan = betanet_secure_channel_create();
    if (!cli_chan) {
        fprintf(stderr, "[client] Failed to create secure channel\n");
        betanet_ctx_free(cli_ctx);
        return NULL;
    }
    if (betanet_secure_handshake_initiator(cli_chan, cli_ctx) != 0) {
        fprintf(stderr, "[client] Noise XK handshake failed\n");
        betanet_secure_channel_free(cli_chan);
        betanet_ctx_free(cli_ctx);
        return NULL;
    }
    printf("[client] Noise XK handshake complete\n");

    // Send message, receive echo
    const char* msg = "hello from client";
    if (betanet_secure_send(cli_chan, (const uint8_t*)msg, strlen(msg)) == 0) {
        printf("[client] Sent: %s\n", msg);
        uint8_t buf[256];
        size_t out_len = 0;
        if (betanet_secure_recv(cli_chan, buf, sizeof(buf), &out_len) == 0) {
            printf("[client] Received echo: %.*s\n", (int)out_len, buf);
        } else {
            fprintf(stderr, "[client] Secure recv failed\n");
        }
    } else {
        fprintf(stderr, "[client] Secure send failed\n");
    }

    betanet_secure_channel_free(cli_chan);
    betanet_ctx_free(cli_ctx);
    printf("[client] Done\n");
    return NULL;
}

int main() {
    pthread_t srv, cli;
    printf("Betanet CLI demo: local peer-to-peer session\n");

    // Initialize library (if needed)
    betanet_init();

    pthread_create(&srv, NULL, server_thread, NULL);
    pthread_create(&cli, NULL, client_thread, NULL);

    pthread_join(srv, NULL);
    pthread_join(cli, NULL);

    betanet_shutdown();
    printf("Demo complete.\n");
    return 0;
}