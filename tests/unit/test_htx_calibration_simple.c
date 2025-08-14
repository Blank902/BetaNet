// Simple HTX Calibration Test for debugging
#include "../../include/betanet/htx_calibration.h"
#include <stdio.h>
#include <string.h>

int main() {
    printf("Starting HTX Calibration Basic Test...\n");
    
    // Test calibration result strings first (simplest test)
    printf("Testing calibration result strings...\n");
    const char* result_str = htx_calibration_result_to_string(HTX_CALIBRATION_SUCCESS);
    printf("Got result string: '%s'\n", result_str);
    
    if (strcmp(result_str, "Success") == 0) {
        printf("✓ Calibration result string correct\n");
    } else {
        printf("✗ Expected 'Success', got '%s'\n", result_str);
        return 1;
    }
    
    printf("\n🎉 Basic HTX Calibration test passed!\n");
    return 0;
}
