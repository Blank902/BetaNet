#include <stdio.h>
#include "betanet/betanet.h"

int main(void) {
    printf("Starting debug test...\n");
    
    printf("Calling betanet_init()...\n");
    betanet_init();
    printf("betanet_init() completed\n");
    
    printf("Creating context...\n");
    htx_ctx_t *ctx = betanet_ctx_create();
    if (!ctx) {
        printf("Failed to create context\n");
        betanet_shutdown();
        return 1;
    }
    printf("Context created successfully\n");
    
    printf("Freeing context...\n");
    betanet_ctx_free(ctx);
    printf("Context freed\n");
    
    printf("Calling betanet_shutdown()...\n");
    betanet_shutdown();
    printf("betanet_shutdown() completed\n");
    
    printf("Debug test completed successfully!\n");
    return 0;
}
