/**
 * @file test_scion_basic.c
 * @brief Basic SCION packet handling tests for BetaNet 1.1 compliance
 * 
 * This test verifies that our SCION implementation meets the basic
 * requirements of BetaNet 1.1 specification §4.1.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "betanet/scion.h"

// Test data for IPv4 addresses
static const uint8_t test_src_addr[] = {192, 168, 1, 1};
static const uint8_t test_dst_addr[] = {10, 0, 0, 1};
static const uint8_t test_payload[] = "Hello BetaNet SCION";

/**
 * @brief Test basic SCION packet creation and validation
 */
static void test_scion_packet_creation(void) {
    printf("Testing SCION packet creation...\n");
    
    scion_packet_t packet;
    bool result;
    
    // Test packet initialization
    result = scion_packet_init(&packet);
    assert(result && "Failed to initialize SCION packet");
    
    // Create a test packet
    result = scion_create_packet(
        0x1110000000000001ULL,  // Source IA (ISD 1, AS 1)
        0x1110000000000002ULL,  // Destination IA (ISD 1, AS 2)
        test_src_addr, sizeof(test_src_addr),
        test_dst_addr, sizeof(test_dst_addr),
        test_payload, sizeof(test_payload) - 1,  // Exclude null terminator
        &packet
    );
    assert(result && "Failed to create SCION packet");
    
    // Validate the created packet
    scion_packet_validation_result_t validation = scion_validate_packet(&packet);
    if (validation != SCION_PACKET_VALID) {
        printf("Validation failed: %s\n", scion_packet_validation_error_string(validation));
        printf("Header version_flags: 0x%02X\n", packet.header.version_flags);
        printf("Header length: %d (should be >= %d)\n", packet.header.hdr_len * 4, SCION_MIN_HEADER_SIZE);
        printf("Payload length: %d\n", ntohs(packet.header.payload_len));
        printf("Total packet size: %zu\n", packet.total_size);
    }
    assert(validation == SCION_PACKET_VALID && "Created packet failed validation");
    
    // Check BetaNet 1.1 version compliance
    bool version_valid = scion_is_valid_version(&packet);
    assert(version_valid && "Packet version is not BetaNet 1.1 compliant");
    
    // Verify packet contents
    assert(packet.addr_info.src_ia == 0x1110000000000001ULL && "Source IA mismatch");
    assert(packet.addr_info.dst_ia == 0x1110000000000002ULL && "Destination IA mismatch");
    assert(packet.addr_info.src_addr_len == sizeof(test_src_addr) && "Source address length mismatch");
    assert(packet.addr_info.dst_addr_len == sizeof(test_dst_addr) && "Destination address length mismatch");
    assert(packet.payload_size == sizeof(test_payload) - 1 && "Payload size mismatch");
    
    // Verify address data
    assert(memcmp(packet.addr_info.src_addr, test_src_addr, sizeof(test_src_addr)) == 0 && "Source address data mismatch");
    assert(memcmp(packet.addr_info.dst_addr, test_dst_addr, sizeof(test_dst_addr)) == 0 && "Destination address data mismatch");
    assert(memcmp(packet.payload, test_payload, sizeof(test_payload) - 1) == 0 && "Payload data mismatch");
    
    // Cleanup
    scion_packet_cleanup(&packet);
    
    printf("✓ SCION packet creation test passed\n");
}

/**
 * @brief Test SCION packet serialization and parsing
 */
static void test_scion_packet_serialization(void) {
    printf("Testing SCION packet serialization and parsing...\n");
    
    scion_packet_t original_packet, parsed_packet;
    uint8_t buffer[2048];
    size_t written_size;
    bool result;
    
    // Initialize packets
    scion_packet_init(&original_packet);
    scion_packet_init(&parsed_packet);
    
    // Create original packet
    result = scion_create_packet(
        0x1110000000000003ULL,  // Source IA
        0x1110000000000004ULL,  // Destination IA  
        test_src_addr, sizeof(test_src_addr),
        test_dst_addr, sizeof(test_dst_addr),
        test_payload, sizeof(test_payload) - 1,
        &original_packet
    );
    assert(result && "Failed to create original packet");
    
    // Serialize the packet
    result = scion_serialize_packet(&original_packet, buffer, sizeof(buffer), &written_size);
    assert(result && "Failed to serialize packet");
    assert(written_size > 0 && "No data written during serialization");
    
    // Parse the serialized data
    result = scion_parse_packet(buffer, written_size, &parsed_packet);
    assert(result && "Failed to parse serialized packet");
    
    // Validate parsed packet
    scion_packet_validation_result_t validation = scion_validate_packet(&parsed_packet);
    assert(validation == SCION_PACKET_VALID && "Parsed packet failed validation");
    
    // Compare original and parsed packets
    assert(original_packet.addr_info.src_ia == parsed_packet.addr_info.src_ia && "Source IA mismatch after parsing");
    assert(original_packet.addr_info.dst_ia == parsed_packet.addr_info.dst_ia && "Destination IA mismatch after parsing");
    assert(original_packet.addr_info.src_addr_len == parsed_packet.addr_info.src_addr_len && "Source address length mismatch after parsing");
    assert(original_packet.addr_info.dst_addr_len == parsed_packet.addr_info.dst_addr_len && "Destination address length mismatch after parsing");
    assert(original_packet.payload_size == parsed_packet.payload_size && "Payload size mismatch after parsing");
    
    // Compare address and payload data
    assert(memcmp(original_packet.addr_info.src_addr, parsed_packet.addr_info.src_addr, original_packet.addr_info.src_addr_len) == 0 && "Source address data mismatch after parsing");
    assert(memcmp(original_packet.addr_info.dst_addr, parsed_packet.addr_info.dst_addr, original_packet.addr_info.dst_addr_len) == 0 && "Destination address data mismatch after parsing");
    assert(memcmp(original_packet.payload, parsed_packet.payload, original_packet.payload_size) == 0 && "Payload data mismatch after parsing");
    
    // Cleanup
    scion_packet_cleanup(&original_packet);
    scion_packet_cleanup(&parsed_packet);
    
    printf("✓ SCION packet serialization and parsing test passed\n");
}

/**
 * @brief Test SCION packet validation edge cases
 */
static void test_scion_packet_validation(void) {
    printf("Testing SCION packet validation edge cases...\n");
    
    scion_packet_t packet;
    scion_packet_validation_result_t result;
    
    // Test null packet validation
    result = scion_validate_packet(NULL);
    assert(result == SCION_PACKET_ERR_INVALID_ADDRESS && "Null packet should fail validation");
    
    // Test packet with invalid version
    scion_packet_init(&packet);
    scion_create_packet(
        0x1110000000000001ULL, 0x1110000000000002ULL,
        test_src_addr, sizeof(test_src_addr),
        test_dst_addr, sizeof(test_dst_addr),
        test_payload, sizeof(test_payload) - 1,
        &packet
    );
    
    // Corrupt the version field
    packet.header.version_flags = 0x10;  // Wrong version (0x01 instead of 0x02)
    result = scion_validate_packet(&packet);
    assert(result == SCION_PACKET_ERR_INVALID_VERSION && "Invalid version should fail validation");
    
    // Test validation error strings
    const char* error_str = scion_packet_validation_error_string(SCION_PACKET_ERR_INVALID_VERSION);
    assert(error_str != NULL && "Error string should not be NULL");
    assert(strstr(error_str, "version") != NULL && "Error string should mention version");
    
    scion_packet_cleanup(&packet);
    
    printf("✓ SCION packet validation test passed\n");
}

/**
 * @brief Test BetaNet 1.1 specification compliance
 */
static void test_betanet_compliance(void) {
    printf("Testing BetaNet 1.1 specification compliance...\n");
    
    scion_packet_t packet;
    scion_packet_init(&packet);
    
    // Create a packet
    scion_create_packet(
        0x1110000000000001ULL, 0x1110000000000002ULL,
        test_src_addr, sizeof(test_src_addr),
        test_dst_addr, sizeof(test_dst_addr),
        test_payload, sizeof(test_payload) - 1,
        &packet
    );
    
    // Verify SCION version is 0x02 as per BetaNet 1.1 §4.1
    uint8_t version = (packet.header.version_flags >> 4) & 0x0F;
    assert(version == SCION_VERSION && "SCION version must be 0x02 for BetaNet 1.1");
    assert(SCION_VERSION == 0x02 && "SCION_VERSION constant must be 0x02");
    
    // Verify header structure alignment
    assert(sizeof(scion_common_hdr_t) >= SCION_MIN_HEADER_SIZE && "Header too small");
    assert(sizeof(scion_common_hdr_t) <= SCION_MAX_HEADER_SIZE && "Header too large");
    
    // Verify payload size limits
    assert(packet.payload_size <= SCION_MAX_PAYLOAD_SIZE && "Payload exceeds maximum size");
    
    scion_packet_cleanup(&packet);
    
    printf("✓ BetaNet 1.1 compliance test passed\n");
}

int main(void) {
    printf("Starting BetaNet SCION Basic Tests\n");
    printf("==================================\n");
    
    test_scion_packet_creation();
    test_scion_packet_serialization();
    test_scion_packet_validation();
    test_betanet_compliance();
    
    printf("\n🎉 All SCION basic tests passed!\n");
    printf("BetaNet 1.1 SCION implementation is working correctly.\n");
    
    return 0;
}
