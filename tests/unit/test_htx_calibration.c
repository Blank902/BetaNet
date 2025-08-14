/**
 * @file test_htx_calibration.c
 * @brief HTX Origin Calibration Tests
 * 
 * Tests for HTX origin mirroring and auto-calibration functionality
 * according to BetaNet Specification §5.1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../../include/betanet/htx_calibration.h"
#include "../../include/betanet/secure_utils.h"

/**
 * @brief Test fingerprint comparison functions
 */
static void test_fingerprint_comparison(void) {
    printf("Testing HTX fingerprint comparison...\n");
    
    // Create reference TLS fingerprint
    htx_tls_fingerprint_t reference = {0};
    reference.version = 0x0303; // TLS 1.2
    reference.cipher_count = 3;
    reference.cipher_suites[0] = 0xC02F; // ECDHE-RSA-AES128-GCM-SHA256
    reference.cipher_suites[1] = 0xC030; // ECDHE-RSA-AES256-GCM-SHA384
    reference.cipher_suites[2] = 0x009E; // DHE-RSA-AES128-GCM-SHA256
    reference.alpn_count = 1;
    secure_strcpy(reference.alpn_list[0], sizeof(reference.alpn_list[0]), "h2");
    
    // Test identical fingerprint
    htx_tls_fingerprint_t identical = reference;
    assert(htx_compare_tls_fingerprints(&reference, &identical) && "Identical fingerprints should match");
    
    // Test version mismatch
    htx_tls_fingerprint_t version_mismatch = reference;
    version_mismatch.version = 0x0304; // TLS 1.3
    assert(!htx_compare_tls_fingerprints(&reference, &version_mismatch) && "Version mismatch should fail");
    
    // Test cipher count mismatch
    htx_tls_fingerprint_t cipher_count_mismatch = reference;
    cipher_count_mismatch.cipher_count = 2;
    assert(!htx_compare_tls_fingerprints(&reference, &cipher_count_mismatch) && "Cipher count mismatch should fail");
    
    // Test cipher value mismatch
    htx_tls_fingerprint_t cipher_value_mismatch = reference;
    cipher_value_mismatch.cipher_suites[0] = 0x1234; // Different cipher
    assert(!htx_compare_tls_fingerprints(&reference, &cipher_value_mismatch) && "Cipher value mismatch should fail");
    
    // Test ALPN mismatch
    htx_tls_fingerprint_t alpn_mismatch = reference;
    secure_strcpy(alpn_mismatch.alpn_list[0], sizeof(alpn_mismatch.alpn_list[0]), "http/1.1");
    assert(!htx_compare_tls_fingerprints(&reference, &alpn_mismatch) && "ALPN mismatch should fail");
    
    printf("✓ HTX fingerprint comparison test passed\n");
}

/**
 * @brief Test HTTP/2 settings comparison with tolerance
 */
static void test_h2_settings_comparison(void) {
    printf("Testing HTX HTTP/2 settings comparison...\n");
    
    // Create reference HTTP/2 fingerprint
    htx_h2_fingerprint_t reference = {0};
    reference.setting_count = 3;
    reference.settings[0].setting_id = 1; // HEADER_TABLE_SIZE
    reference.settings[0].value = 4096;
    reference.settings[1].setting_id = 3; // MAX_CONCURRENT_STREAMS
    reference.settings[1].value = 100;
    reference.settings[2].setting_id = 4; // INITIAL_WINDOW_SIZE
    reference.settings[2].value = 65535;
    
    // Test identical settings
    htx_h2_fingerprint_t identical = reference;
    assert(htx_compare_h2_settings(&reference, &identical, 0) && "Identical settings should match");
    
    // Test within tolerance (15%)
    htx_h2_fingerprint_t within_tolerance = reference;
    within_tolerance.settings[0].value = 4300; // ~5% increase from 4096
    assert(htx_compare_h2_settings(&reference, &within_tolerance, 15) && "Settings within tolerance should match");
    
    // Test outside tolerance
    htx_h2_fingerprint_t outside_tolerance = reference;
    outside_tolerance.settings[0].value = 5000; // ~22% increase from 4096
    assert(!htx_compare_h2_settings(&reference, &outside_tolerance, 15) && "Settings outside tolerance should fail");
    
    // Test missing setting
    htx_h2_fingerprint_t missing_setting = reference;
    missing_setting.setting_count = 2; // One less setting
    assert(!htx_compare_h2_settings(&reference, &missing_setting, 15) && "Missing setting should fail");
    
    printf("✓ HTX HTTP/2 settings comparison test passed\n");
}

/**
 * @brief Test fingerprint hash calculations
 */
static void test_fingerprint_hashes(void) {
    printf("Testing HTX fingerprint hash calculations...\n");
    
    htx_tls_fingerprint_t fingerprint = {0};
    fingerprint.version = 0x0303;
    fingerprint.cipher_count = 2;
    fingerprint.cipher_suites[0] = 0xC02F;
    fingerprint.cipher_suites[1] = 0xC030;
    fingerprint.extension_count = 2;
    fingerprint.extensions[0] = 0x0000; // server_name
    fingerprint.extensions[1] = 0x0010; // application_layer_protocol_negotiation
    fingerprint.group_count = 2;
    fingerprint.supported_groups[0] = 23; // secp256r1
    fingerprint.supported_groups[1] = 29; // x25519
    
    // Test JA3 hash calculation
    uint32_t ja3_hash = htx_calculate_ja3_hash(&fingerprint);
    assert(ja3_hash != 0 && "JA3 hash should not be zero");
    
    // Test JA4 hash calculation
    uint32_t ja4_hash = htx_calculate_ja4_hash(&fingerprint);
    assert(ja4_hash != 0 && "JA4 hash should not be zero");
    
    // Test reproducibility
    uint32_t ja3_hash2 = htx_calculate_ja3_hash(&fingerprint);
    uint32_t ja4_hash2 = htx_calculate_ja4_hash(&fingerprint);
    assert(ja3_hash == ja3_hash2 && "JA3 hash should be reproducible");
    assert(ja4_hash == ja4_hash2 && "JA4 hash should be reproducible");
    
    // Test different fingerprint produces different hash
    fingerprint.version = 0x0304; // Change TLS version
    uint32_t ja3_hash_different = htx_calculate_ja3_hash(&fingerprint);
    assert(ja3_hash != ja3_hash_different && "Different fingerprint should produce different JA3 hash");
    
    printf("✓ HTX fingerprint hash calculation test passed\n");
}

/**
 * @brief Test origin profile lifecycle
 */
static void test_origin_profile_lifecycle(void) {
    printf("Testing HTX origin profile lifecycle...\n");
    
    htx_origin_profile_t profile = {0};
    
    // Test initial state
    assert(!profile.is_valid && "New profile should not be valid initially");
    assert(htx_profile_needs_recalibration(&profile, 3600) && "Invalid profile should need recalibration");
    
    // Simulate a valid profile
    secure_strcpy(profile.origin_host, sizeof(profile.origin_host), "example.com");
    profile.origin_port = 443;
    profile.is_valid = true;
    profile.calibration_timestamp = (uint64_t)time(NULL) * 1000; // Current time
    profile.rtt_ms = 50;
    profile.connection_time_ms = 100;
    
    // Test age calculation
    assert(!htx_profile_needs_recalibration(&profile, 3600) && "Fresh profile should not need recalibration");
    
    // Test old profile
    profile.calibration_timestamp = ((uint64_t)time(NULL) - 7200) * 1000; // 2 hours ago
    assert(htx_profile_needs_recalibration(&profile, 3600) && "Old profile should need recalibration");
    
    // Test profile printing (should not crash)
    htx_print_origin_profile(&profile);
    htx_print_origin_profile(NULL); // Test NULL safety
    
    printf("✓ HTX origin profile lifecycle test passed\n");
}

/**
 * @brief Test calibration result utilities
 */
static void test_calibration_utilities(void) {
    printf("Testing HTX calibration utilities...\n");
    
    // Test error code to string conversion
    const char *success_str = htx_calibration_result_to_string(HTX_CALIBRATION_SUCCESS);
    assert(strcmp(success_str, "Success") == 0 && "Success result string should match");
    
    const char *network_error_str = htx_calibration_result_to_string(HTX_CALIBRATION_ERR_NETWORK_FAILED);
    assert(strcmp(network_error_str, "Network connection failed") == 0 && "Network error string should match");
    
    const char *unknown_str = htx_calibration_result_to_string((htx_calibration_result_t)999);
    assert(strcmp(unknown_str, "Unknown error") == 0 && "Unknown error string should match");
    
    printf("✓ HTX calibration utilities test passed\n");
}

/**
 * @brief Test validation functions
 */
static void test_validation_functions(void) {
    printf("Testing HTX validation functions...\n");
    
    // Create valid profile
    htx_origin_profile_t profile = {0};
    secure_strcpy(profile.origin_host, sizeof(profile.origin_host), "example.com");
    profile.origin_port = 443;
    profile.is_valid = true;
    
    // Setup reference fingerprints
    profile.tls_profile.version = 0x0303;
    profile.tls_profile.cipher_count = 1;
    profile.tls_profile.cipher_suites[0] = 0xC02F;
    profile.tls_profile.alpn_count = 1;
    secure_strcpy(profile.tls_profile.alpn_list[0], sizeof(profile.tls_profile.alpn_list[0]), "h2");
    
    profile.h2_profile.setting_count = 1;
    profile.h2_profile.settings[0].setting_id = 1;
    profile.h2_profile.settings[0].value = 4096;
    
    // Create matching current fingerprints
    htx_tls_fingerprint_t current_tls = profile.tls_profile;
    htx_h2_fingerprint_t current_h2 = profile.h2_profile;
    
    // Test successful validation
    assert(htx_validate_fingerprint_compliance(&profile, &current_tls, &current_h2) && 
           "Matching fingerprints should validate successfully");
    
    // Test TLS mismatch
    current_tls.version = 0x0304;
    assert(!htx_validate_fingerprint_compliance(&profile, &current_tls, &current_h2) && 
           "TLS mismatch should fail validation");
    current_tls.version = 0x0303; // Reset
    
    // Test HTTP/2 setting mismatch
    current_h2.settings[0].value = 8192; // Too different
    assert(!htx_validate_fingerprint_compliance(&profile, &current_tls, &current_h2) && 
           "HTTP/2 setting mismatch should fail validation");
    
    // Test NULL parameters
    assert(!htx_validate_fingerprint_compliance(NULL, &current_tls, &current_h2) && 
           "NULL profile should fail validation");
    assert(!htx_validate_fingerprint_compliance(&profile, NULL, &current_h2) && 
           "NULL TLS fingerprint should fail validation");
    assert(!htx_validate_fingerprint_compliance(&profile, &current_tls, NULL) && 
           "NULL HTTP/2 fingerprint should fail validation");
    
    printf("✓ HTX validation functions test passed\n");
}

/**
 * @brief Test extraction function stubs
 */
static void test_extraction_stubs(void) {
    printf("Testing HTX extraction function stubs...\n");
    
    htx_tls_fingerprint_t tls_fp = {0};
    htx_h2_fingerprint_t h2_fp = {0};
    
    // Test NULL parameter handling
    assert(htx_extract_tls_fingerprint(NULL, &tls_fp) == HTX_CALIBRATION_ERR_INVALID_PARAM && 
           "NULL SSL context should return invalid param error");
    assert(htx_extract_tls_fingerprint((void*)0x1234, NULL) == HTX_CALIBRATION_ERR_INVALID_PARAM && 
           "NULL fingerprint pointer should return invalid param error");
    
    assert(htx_extract_h2_fingerprint(NULL, NULL) == HTX_CALIBRATION_ERR_INVALID_PARAM && 
           "NULL fingerprint pointer should return invalid param error");
    
    // Test successful extraction (using NULL session for now)
    assert(htx_extract_h2_fingerprint(NULL, &h2_fp) == HTX_CALIBRATION_SUCCESS && 
           "HTTP/2 fingerprint extraction should succeed");
    assert(h2_fp.setting_count > 0 && "HTTP/2 fingerprint should have settings");
    
    printf("✓ HTX extraction function stubs test passed\n");
}

/**
 * @brief Main test function
 */
int main(void) {
    printf("Starting BetaNet HTX Calibration Tests\n");
    printf("=====================================\n");
    
    // Run all tests
    test_fingerprint_comparison();
    test_h2_settings_comparison();
    test_fingerprint_hashes();
    test_origin_profile_lifecycle();
    test_calibration_utilities();
    test_validation_functions();
    test_extraction_stubs();
    
    printf("\n🎉 All HTX Calibration tests passed!\n");
    printf("BetaNet HTX Origin Calibration implementation is working correctly.\n");
    
    return 0;
}
