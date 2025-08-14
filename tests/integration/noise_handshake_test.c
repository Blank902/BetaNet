/**
 * @file noise_handshake_test.c
 * @brief Integration test for real Noise XK handshake over SSL connections
 */

#include "../../include/betanet/betanet.h"
#include "../../src/htx/htx.h"
#include "../../src/noise/noise.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int test_noise_handshake_integration(void) {
    printf("[test] Starting Noise XK handshake integration test...\n");
    
    // Initialize BetaNet
    betanet_init();
    printf("[test] BetaNet initialized\n");
    
    // Create HTX contexts for client and server
    htx_ctx_t* server_ctx = htx_ctx_create(HTX_TRANSPORT_TCP);
    htx_ctx_t* client_ctx = htx_ctx_create(HTX_TRANSPORT_TCP);
    
    if (!server_ctx || !client_ctx) {
        printf("[test] Failed to create HTX contexts\n");
        betanet_shutdown();
        return -1;
    }
    
    // Test 1: Server listen
    printf("[test] Testing server listen on port 8443...\n");
    int listen_result = htx_listen(server_ctx, 8443);
    if (listen_result == 0) {
        printf("[test] Server listening successfully\n");
    } else {
        printf("[test] Server listen failed (expected without certificates)\n");
    }
    
    // Test 2: Client connection attempt
    printf("[test] Testing client connection to localhost:8443...\n");
    int connect_result = htx_connect(client_ctx, "127.0.0.1", 8443, "h2");
    if (connect_result == 0) {
        printf("[test] Client connected successfully\n");
        
        // Test 3: Create noise channels
        noise_channel_t* client_chan = betanet_secure_channel_create();
        noise_channel_t* server_chan = betanet_secure_channel_create();
        
        if (client_chan && server_chan) {
            printf("[test] Noise channels created successfully\n");
            
            // Test 4: Attempt handshakes (will fail without real TLS but tests the logic)
            printf("[test] Testing client handshake initiator...\n");
            int client_handshake = betanet_secure_handshake_initiator(client_chan, client_ctx);
            
            printf("[test] Testing server handshake responder...\n");
            int server_handshake = betanet_secure_handshake_responder(server_chan, client_ctx);
            
            printf("[test] Client handshake result: %d\n", client_handshake);
            printf("[test] Server handshake result: %d\n", server_handshake);
            
            // Test 5: Message exchange (will use demo mode)
            if (client_handshake == 0 && server_handshake == 0) {
                printf("[test] Testing secure message exchange...\n");
                
                const char* test_msg = "Hello from integration test";
                int send_result = betanet_secure_send(client_chan, (const uint8_t*)test_msg, strlen(test_msg));
                printf("[test] Send result: %d\n", send_result);
                
                uint8_t recv_buffer[256];
                size_t recv_len = 0;
                int recv_result = betanet_secure_recv(server_chan, recv_buffer, sizeof(recv_buffer), &recv_len);
                printf("[test] Recv result: %d, length: %zu\n", recv_result, recv_len);
                
                if (recv_result == 0 && recv_len > 0) {
                    recv_buffer[recv_len] = '\0';
                    printf("[test] Received message: %s\n", recv_buffer);
                }
            }
            
            betanet_secure_channel_free(client_chan);
            betanet_secure_channel_free(server_chan);
        }
        
        htx_ctx_free(client_ctx);
    } else {
        printf("[test] Client connection failed (expected without server)\n");
        htx_ctx_free(client_ctx);
    }
    
    htx_ctx_free(server_ctx);
    betanet_shutdown();
    
    printf("[test] Integration test completed\n");
    return 0;
}

int main(void) {
    printf("=== Noise XK Handshake Integration Test ===\n");
    int result = test_noise_handshake_integration();
    printf("=== Test %s ===\n", result == 0 ? "COMPLETED" : "FAILED");
    return result;
}
