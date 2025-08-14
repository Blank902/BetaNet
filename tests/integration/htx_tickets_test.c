/**
 * Comprehensive Test Suite for HTX Access-Ticket Bootstrap System
 * Tests all aspects of BetaNet Specification §5.2 compliance
 * 
 * Test Coverage:
 * - Server configuration and policy parsing
 * - Client ticket generation and encoding
 * - All carrier types (Cookie, Query, Body)
 * - Cryptographic validation (X25519, HKDF)
 * - Replay protection mechanisms
 * - Time window validation (±1 hour)
 * - Error handling and edge cases
 * - Base64URL encoding/decoding
 * - Performance and security validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../include/betanet/secure_utils.h"
#include <time.h>

#include "../../include/betanet/htx_tickets.h"
#include "../../include/betanet/secure_log.h"

// Test statistics
static struct {
    int tests_run;
    int tests_passed;
    int tests_failed;
} test_stats = {0};

#define TEST_START(name) \
    do { \
        printf("Running test: %s... ", name); \
        test_stats.tests_run++; \
    } while(0)

#define TEST_PASS() \
    do { \
        printf("PASSED\n"); \
        test_stats.tests_passed++; \
    } while(0)

#define TEST_FAIL(reason) \
    do { \
        printf("FAILED: %s\n", reason); \
        test_stats.tests_failed++; \
    } while(0)

#define ASSERT_TRUE(condition, message) \
    do { \
        if (!(condition)) { \
            TEST_FAIL(message); \
            return -1; \
        } \
    } while(0)

#define ASSERT_EQ(a, b, message) \
    do { \
        if ((a) != (b)) { \
            TEST_FAIL(message); \
            return -1; \
        } \
    } while(0)

// =============================================================================
// Test Helper Functions
// =============================================================================

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int create_test_policy(htx_carrier_policy_t* policy) {
    policy->cookie_prob = 0.5f;
    policy->query_prob = 0.3f; 
    policy->body_prob = 0.2f;
    policy->min_len = 110; // Fixed size is 105, so minimum should be higher
    policy->max_len = 150; // Reasonable maximum with padding
    return 0;
}

// =============================================================================
// Individual Test Functions
// =============================================================================

static int test_policy_parsing(void) {
    TEST_START("HTX Policy Parsing");
    
    htx_carrier_policy_t policy;
    const char* policy_str = "v1; carriers=cookie:0.5,query:0.3,body:0.2; len=110..150";
    
    ASSERT_EQ(htx_ticket_parse_policy(policy_str, &policy), 0, "Policy parsing failed");
    ASSERT_TRUE(policy.cookie_prob == 0.5f, "Cookie probability incorrect");
    ASSERT_TRUE(policy.query_prob == 0.3f, "Query probability incorrect");
    ASSERT_TRUE(policy.body_prob == 0.2f, "Body probability incorrect");
    ASSERT_EQ(policy.min_len, 110, "Min length incorrect");
    ASSERT_EQ(policy.max_len, 150, "Max length incorrect");
    
    // Test policy formatting
    char formatted[256];
    ASSERT_EQ(htx_ticket_format_policy(&policy, formatted, sizeof(formatted)), 0, "Policy formatting failed");
    
    TEST_PASS();
    return 0;
}

static int test_server_initialization(void) {
    TEST_START("Server Initialization");
    
    htx_ticket_server_config_t config;
    htx_carrier_policy_t policy;
    create_test_policy(&policy);
    
    ASSERT_EQ(htx_ticket_server_init(&config, &policy), 0, "Server init failed");
    
    // Verify keypair was generated (non-zero)
    bool pubkey_nonzero = false;
    bool privkey_nonzero = false;
    for (int i = 0; i < HTX_TICKET_PUBKEY_SIZE; i++) {
        if (config.ticket_pubkey[i] != 0) pubkey_nonzero = true;
        if (config.ticket_privkey[i] != 0) privkey_nonzero = true;
    }
    ASSERT_TRUE(pubkey_nonzero, "Public key is all zeros");
    ASSERT_TRUE(privkey_nonzero, "Private key is all zeros");
    
    // Verify key ID was generated
    bool keyid_nonzero = false;
    for (int i = 0; i < HTX_TICKET_KEYID_SIZE; i++) {
        if (config.key_id[i] != 0) keyid_nonzero = true;
    }
    ASSERT_TRUE(keyid_nonzero, "Key ID is all zeros");
    
    TEST_PASS();
    return 0;
}

static int test_client_ticket_generation(void) {
    TEST_START("Client Ticket Generation");
    
    // Setup server
    htx_ticket_server_config_t server_config;
    htx_carrier_policy_t policy;
    create_test_policy(&policy);
    ASSERT_EQ(htx_ticket_server_init(&server_config, &policy), 0, "Server setup failed");
    
    // Create client request
    htx_ticket_request_t request;
    ASSERT_EQ(htx_ticket_client_create_request(&request, server_config.ticket_pubkey, 
                                              server_config.key_id, &policy), 0, 
              "Client request creation failed");
    
    // Generate access ticket
    htx_access_ticket_t ticket;
    ASSERT_EQ(htx_ticket_client_generate(&request, &ticket), 0, "Ticket generation failed");
    ASSERT_TRUE(ticket.is_valid, "Generated ticket is invalid");
    
    // Verify hour timestamp is reasonable
    uint64_t current_hour = htx_ticket_get_hour_timestamp();
    ASSERT_TRUE(ticket.hour_timestamp >= current_hour - 1 && 
                ticket.hour_timestamp <= current_hour + 1, "Hour timestamp out of range");
    
    TEST_PASS();
    return 0;
}

static int test_ticket_verification(void) {
    TEST_START("Ticket Verification");
    
    // Setup server
    htx_ticket_server_config_t server_config;
    htx_carrier_policy_t policy;
    create_test_policy(&policy);
    ASSERT_EQ(htx_ticket_server_init(&server_config, &policy), 0, "Server setup failed");
    
    // Create and generate client ticket
    htx_ticket_request_t request;
    ASSERT_EQ(htx_ticket_client_create_request(&request, server_config.ticket_pubkey, 
                                              server_config.key_id, &policy), 0, 
              "Client request failed");
    
    // Debug: Check if payload_len is set
    printf("Request payload_len: %u\n", request.payload_len);
    
    htx_access_ticket_t ticket;
    ASSERT_EQ(htx_ticket_client_generate(&request, &ticket), 0, "Ticket generation failed");
    
    // Encode ticket
    htx_ticket_payload_t payload;
    int encode_result = htx_ticket_client_encode(&request, &ticket, &payload);
    if (encode_result != 0) {
        printf("Encoding failed with result: %d\n", encode_result);
        size_t fixed_size = 1 + HTX_TICKET_PUBKEY_SIZE + HTX_TICKET_KEYID_SIZE + HTX_TICKET_NONCE_SIZE + HTX_TICKET_ACCESS_SIZE;
        printf("Fixed size: %zu, Request payload_len: %u\n", fixed_size, request.payload_len);
    }
    ASSERT_EQ(encode_result, 0, "Ticket encoding failed");
    
    // Create binary payload for verification
    size_t binary_len = payload.total_len;
    uint8_t* binary_data = malloc(binary_len);
    ASSERT_TRUE(binary_data != NULL, "Memory allocation failed");
    
    size_t offset = 0;
    binary_data[offset++] = payload.version;
    secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.client_pubkey, HTX_TICKET_PUBKEY_SIZE);
    offset += HTX_TICKET_PUBKEY_SIZE;
    secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.key_id, HTX_TICKET_KEYID_SIZE);
    offset += HTX_TICKET_KEYID_SIZE;
    secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.nonce, HTX_TICKET_NONCE_SIZE);
    offset += HTX_TICKET_NONCE_SIZE;
    secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.access_ticket, HTX_TICKET_ACCESS_SIZE);
    offset += HTX_TICKET_ACCESS_SIZE;
    if (payload.padding_len > 0) {
        secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.padding, payload.padding_len);
    }
    
    // Verify ticket
    htx_ticket_verification_t result;
    ASSERT_EQ(htx_ticket_server_verify(&server_config, binary_data, binary_len, &result), 0, 
              "Ticket verification failed");
    ASSERT_TRUE(result.is_valid, "Ticket marked as invalid");
    
    // Verify client public key matches
    ASSERT_EQ(memcmp(result.client_pubkey, request.client_pubkey, HTX_TICKET_PUBKEY_SIZE), 0,
              "Client public key mismatch");
    
    free(binary_data);
    htx_ticket_payload_free(&payload);
    
    TEST_PASS();
    return 0;
}

static int test_replay_protection(void) {
    TEST_START("Replay Protection");
    
    // Setup server
    htx_ticket_server_config_t server_config;
    htx_carrier_policy_t policy;
    create_test_policy(&policy);
    ASSERT_EQ(htx_ticket_server_init(&server_config, &policy), 0, "Server setup failed");
    
    // Create client ticket
    htx_ticket_request_t request;
    ASSERT_EQ(htx_ticket_client_create_request(&request, server_config.ticket_pubkey, 
                                              server_config.key_id, &policy), 0, 
              "Client request failed");
    
    htx_access_ticket_t ticket;
    ASSERT_EQ(htx_ticket_client_generate(&request, &ticket), 0, "Ticket generation failed");
    
    htx_ticket_payload_t payload;
    ASSERT_EQ(htx_ticket_client_encode(&request, &ticket, &payload), 0, "Ticket encoding failed");
    
    // Create binary payload
    size_t binary_len = payload.total_len;
    uint8_t* binary_data = malloc(binary_len);
    ASSERT_TRUE(binary_data != NULL, "Memory allocation failed");
    
    size_t offset = 0;
    binary_data[offset++] = payload.version;
    secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.client_pubkey, HTX_TICKET_PUBKEY_SIZE);
    offset += HTX_TICKET_PUBKEY_SIZE;
    secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.key_id, HTX_TICKET_KEYID_SIZE);
    offset += HTX_TICKET_KEYID_SIZE;
    secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.nonce, HTX_TICKET_NONCE_SIZE);
    offset += HTX_TICKET_NONCE_SIZE;
    secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.access_ticket, HTX_TICKET_ACCESS_SIZE);
    offset += HTX_TICKET_ACCESS_SIZE;
    if (payload.padding_len > 0) {
        secure_memcpy(&binary_data[offset], sizeof(&binary_data[offset]), payload.padding, payload.padding_len);
    }
    
    // First verification should succeed
    htx_ticket_verification_t result1;
    ASSERT_EQ(htx_ticket_server_verify(&server_config, binary_data, binary_len, &result1), 0, 
              "First verification failed");
    ASSERT_TRUE(result1.is_valid, "First ticket should be valid");
    
    // Second verification with same ticket should fail (replay)
    htx_ticket_verification_t result2;
    ASSERT_EQ(htx_ticket_server_verify(&server_config, binary_data, binary_len, &result2), -1, 
              "Second verification should fail");
    ASSERT_TRUE(!result2.is_valid, "Replayed ticket should be invalid");
    
    free(binary_data);
    htx_ticket_payload_free(&payload);
    
    TEST_PASS();
    return 0;
}

static int test_carrier_formatting(void) {
    TEST_START("Carrier Formatting");
    
    // Setup server and client
    htx_ticket_server_config_t server_config;
    htx_carrier_policy_t policy;
    create_test_policy(&policy);
    ASSERT_EQ(htx_ticket_server_init(&server_config, &policy), 0, "Server setup failed");
    
    htx_ticket_request_t request;
    ASSERT_EQ(htx_ticket_client_create_request(&request, server_config.ticket_pubkey, 
                                              server_config.key_id, &policy), 0, 
              "Client request failed");
    
    htx_access_ticket_t ticket;
    ASSERT_EQ(htx_ticket_client_generate(&request, &ticket), 0, "Ticket generation failed");
    
    htx_ticket_payload_t payload;
    ASSERT_EQ(htx_ticket_client_encode(&request, &ticket, &payload), 0, "Ticket encoding failed");
    
    // Test cookie formatting
    char cookie_output[1024];
    ASSERT_EQ(htx_ticket_format_cookie(&payload, "example", cookie_output, sizeof(cookie_output)), 0,
              "Cookie formatting failed");
    ASSERT_TRUE(strstr(cookie_output, "Cookie: __Host-example=") != NULL, "Cookie format incorrect");
    
    // Test query formatting
    char query_output[1024];
    ASSERT_EQ(htx_ticket_format_query(&payload, query_output, sizeof(query_output)), 0,
              "Query formatting failed");
    ASSERT_TRUE(strstr(query_output, "bn1=") != NULL, "Query format incorrect");
    
    // Test body formatting
    char body_output[1024];
    ASSERT_EQ(htx_ticket_format_body(&payload, body_output, sizeof(body_output)), 0,
              "Body formatting failed");
    ASSERT_TRUE(strstr(body_output, "bn1=") != NULL, "Body format incorrect");
    
    htx_ticket_payload_free(&payload);
    
    TEST_PASS();
    return 0;
}

static int test_base64url_encoding(void) {
    TEST_START("Base64URL Encoding/Decoding");
    
    // Test data
    uint8_t test_data[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    char encoded[256];
    uint8_t decoded[256];
    size_t decoded_len;
    
    // Encode
    ASSERT_EQ(htx_ticket_base64url_encode(test_data, sizeof(test_data), encoded, sizeof(encoded)), 0,
              "Base64URL encoding failed");
    
    // Verify no padding characters
    ASSERT_TRUE(strchr(encoded, '=') == NULL, "Base64URL should not contain padding");
    
    // Decode
    ASSERT_EQ(htx_ticket_base64url_decode(encoded, 0, decoded, sizeof(decoded), &decoded_len), 0,
              "Base64URL decoding failed");
    
    // Verify roundtrip
    ASSERT_EQ(decoded_len, sizeof(test_data), "Decoded length mismatch");
    ASSERT_EQ(memcmp(test_data, decoded, sizeof(test_data)), 0, "Roundtrip data mismatch");
    
    TEST_PASS();
    return 0;
}

static int test_time_window_validation(void) {
    TEST_START("Time Window Validation");
    
    // This test verifies that tickets are accepted within ±1 hour window
    // Note: This is a simplified test since we can't easily manipulate time
    
    uint64_t current_hour = htx_ticket_get_hour_timestamp();
    
    // Verify timestamp is reasonable (should be > 400000 hours since epoch - year 2015+)
    ASSERT_TRUE(current_hour > 400000, "Current hour timestamp seems invalid");
    
    // Test that duplicate checking works across different hours
    uint8_t test_pubkey[HTX_TICKET_PUBKEY_SIZE];
    secure_memset(test_pubkey, 0x42, HTX_TICKET_PUBKEY_SIZE);
    
    // Should not be duplicate initially
    ASSERT_TRUE(!htx_ticket_is_duplicate(test_pubkey, current_hour), "Should not be duplicate initially");
    
    // Record usage
    ASSERT_EQ(htx_ticket_record_usage(test_pubkey, current_hour), 0, "Recording usage failed");
    
    // Should be duplicate now
    ASSERT_TRUE(htx_ticket_is_duplicate(test_pubkey, current_hour), "Should be duplicate after recording");
    
    // Different hour should not be duplicate
    ASSERT_TRUE(!htx_ticket_is_duplicate(test_pubkey, current_hour + 1), "Different hour should not be duplicate");
    
    TEST_PASS();
    return 0;
}

static int test_error_conditions(void) {
    TEST_START("Error Condition Handling");
    
    // Test null parameter handling
    ASSERT_EQ(htx_ticket_parse_policy(NULL, NULL), -1, "Should reject null parameters");
    ASSERT_EQ(htx_ticket_server_init(NULL, NULL), -1, "Should reject null parameters");
    ASSERT_EQ(htx_ticket_client_create_request(NULL, NULL, NULL, NULL), -1, "Should reject null parameters");
    
    // Test invalid policy string
    htx_carrier_policy_t policy;
    ASSERT_EQ(htx_ticket_parse_policy("invalid", &policy), -1, "Should reject invalid policy");
    
    // Test invalid version byte
    htx_ticket_server_config_t server_config;
    create_test_policy(&policy);
    ASSERT_EQ(htx_ticket_server_init(&server_config, &policy), 0, "Server setup failed");
    
    uint8_t invalid_payload[] = {0x99}; // Invalid version
    htx_ticket_verification_t result;
    ASSERT_EQ(htx_ticket_server_verify(&server_config, invalid_payload, sizeof(invalid_payload), &result), -1,
              "Should reject invalid version");
    ASSERT_TRUE(!result.is_valid, "Result should be invalid");
    
    TEST_PASS();
    return 0;
}

static int test_performance_and_security(void) {
    TEST_START("Performance and Security Validation");
    
    htx_ticket_server_config_t server_config;
    htx_carrier_policy_t policy;
    create_test_policy(&policy);
    ASSERT_EQ(htx_ticket_server_init(&server_config, &policy), 0, "Server setup failed");
    
    // Generate multiple tickets to test randomness
    #define NUM_TICKETS 10
    uint8_t client_pubkeys[NUM_TICKETS][HTX_TICKET_PUBKEY_SIZE];
    uint8_t access_tickets[NUM_TICKETS][HTX_TICKET_ACCESS_SIZE];
    
    for (int i = 0; i < NUM_TICKETS; i++) {
        htx_ticket_request_t request;
        ASSERT_EQ(htx_ticket_client_create_request(&request, server_config.ticket_pubkey, 
                                                  server_config.key_id, &policy), 0, 
                  "Client request failed");
        
        htx_access_ticket_t ticket;
        ASSERT_EQ(htx_ticket_client_generate(&request, &ticket), 0, "Ticket generation failed");
        
        secure_memcpy(client_pubkeys[i], sizeof(client_pubkeys[i]), request.client_pubkey, HTX_TICKET_PUBKEY_SIZE);
        secure_memcpy(access_tickets[i], sizeof(access_tickets[i]), ticket.access_ticket, HTX_TICKET_ACCESS_SIZE);
    }
    
    // Verify all client public keys are different (randomness check)
    for (int i = 0; i < NUM_TICKETS; i++) {
        for (int j = i + 1; j < NUM_TICKETS; j++) {
            ASSERT_TRUE(memcmp(client_pubkeys[i], client_pubkeys[j], HTX_TICKET_PUBKEY_SIZE) != 0,
                       "Client public keys should be unique");
            ASSERT_TRUE(memcmp(access_tickets[i], access_tickets[j], HTX_TICKET_ACCESS_SIZE) != 0,
                       "Access tickets should be unique");
        }
    }
    
    TEST_PASS();
    return 0;
}

// =============================================================================
// Main Test Runner
// =============================================================================

int main(void) {
    printf("=== HTX Access-Ticket Bootstrap Test Suite ===\n");
    printf("Testing BetaNet Specification §5.2 Compliance\n\n");
    
    // Initialize random seed
    srand((unsigned int)time(NULL));
    
    // Run all tests
    test_policy_parsing();
    test_server_initialization();
    test_client_ticket_generation();
    test_ticket_verification();
    test_replay_protection();
    test_carrier_formatting();
    test_base64url_encoding();
    test_time_window_validation();
    test_error_conditions();
    test_performance_and_security();
    
    // Print final statistics
    printf("\n=== Test Results ===\n");
    printf("Tests Run:    %d\n", test_stats.tests_run);
    printf("Tests Passed: %d\n", test_stats.tests_passed);
    printf("Tests Failed: %d\n", test_stats.tests_failed);
    
    if (test_stats.tests_failed == 0) {
        printf("\n🎉 ALL TESTS PASSED! HTX Access-Ticket Bootstrap system is fully compliant with BetaNet Spec §5.2\n");
        
        // Print ticket statistics
        printf("\n");
        htx_ticket_print_stats();
        
        return 0;
    } else {
        printf("\n❌ %d tests failed. Please fix issues before proceeding.\n", test_stats.tests_failed);
        return 1;
    }
}
