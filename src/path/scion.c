/**
 * @file scion.c
 * @brief SCION Path Layer Implementation (L1) - BetaNet 1.1 Specification §4.1
 * 
 * This module implements the SCION packet header format and validation
 * as specified in BetaNet 1.1 §4.1. It provides basic SCION packet 
 * structure support for path-aware networking.
 * 
 * @author BetaNet Development Team
 * @date 2024
 * @version 1.1.0
 */

#include "betanet/scion.h"
#include "betanet/secure_utils.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

// ==============================================================================
// BetaNet 1.1 SCION Packet Implementation - §4.1 Compliance
// ==============================================================================

bool scion_packet_init(scion_packet_t *packet) {
    if (!packet) {
        return false;
    }
    
    secure_memset(packet, 0, sizeof(scion_packet_t));
    packet->path_data = NULL;
    packet->payload = NULL;
    packet->path_size = 0;
    packet->payload_size = 0;
    packet->total_size = 0;
    
    return true;
}

void scion_packet_cleanup(scion_packet_t *packet) {
    if (!packet) {
        return;
    }
    
    if (packet->path_data) {
        secure_memset(packet->path_data, 0, packet->path_size);
        free(packet->path_data);
        packet->path_data = NULL;
    }
    
    if (packet->payload) {
        secure_memset(packet->payload, 0, packet->payload_size);
        free(packet->payload);
        packet->payload = NULL;
    }
    
    secure_memset(packet, 0, sizeof(scion_packet_t));
}

bool scion_is_valid_version(const scion_packet_t *packet) {
    if (!packet) {
        return false;
    }
    
    uint8_t version = (packet->header.version_flags >> 4) & 0x0F;
    return version == SCION_VERSION;
}

scion_packet_validation_result_t scion_validate_packet(const scion_packet_t *packet) {
    if (!packet) {
        return SCION_PACKET_ERR_INVALID_ADDRESS;
    }
    
    // Check SCION version compliance with BetaNet 1.1 §4.1
    if (!scion_is_valid_version(packet)) {
        return SCION_PACKET_ERR_INVALID_VERSION;
    }
    
    // Validate header length
    uint8_t hdr_len_units = packet->header.hdr_len;
    size_t hdr_len_bytes = hdr_len_units * 4;
    
    if (hdr_len_bytes < SCION_MIN_HEADER_SIZE || hdr_len_bytes > SCION_MAX_HEADER_SIZE) {
        return SCION_PACKET_ERR_INVALID_HEADER_LEN;
    }
    
    // Validate payload length
    uint16_t payload_len = ntohs(packet->header.payload_len);
    if (payload_len > SCION_MAX_PAYLOAD_SIZE) {
        return SCION_PACKET_ERR_INVALID_PAYLOAD_LEN;
    }
    
    if (packet->payload_size != payload_len) {
        return SCION_PACKET_ERR_INVALID_PAYLOAD_LEN;
    }
    
    // Validate address lengths (note: this is simplified for our basic implementation)
    // In a real implementation, we'd need to parse the full address header properly
    uint8_t dst_type = (packet->header.dt_dl_st_sl >> 6) & 0x03;
    uint8_t dst_len_units = (packet->header.dt_dl_st_sl >> 4) & 0x03;  // Simplified for 2 bits
    uint8_t src_type = (packet->header.dt_dl_st_sl >> 2) & 0x03;
    uint8_t src_len_units = packet->header.dt_dl_st_sl & 0x03;  // Simplified for 2 bits
    
    // For our basic implementation, we'll be more lenient with address validation
    if (packet->addr_info.src_addr_len == 0 && packet->addr_info.dst_addr_len == 0) {
        return SCION_PACKET_ERR_INVALID_ADDRESS;
    }
    
    // Validate address types
    if (dst_type > SCION_ADDR_TYPE_SVC || src_type > SCION_ADDR_TYPE_SVC) {
        return SCION_PACKET_ERR_INVALID_ADDRESS;
    }
    
    // Calculate expected total size
    // Include: common header + ISD-AS identifiers + addresses + path + payload
    size_t expected_size = sizeof(scion_common_hdr_t) + 
                          sizeof(uint64_t) + sizeof(uint64_t) +  // src_ia + dst_ia
                          packet->addr_info.src_addr_len + 
                          packet->addr_info.dst_addr_len +
                          packet->path_size + 
                          packet->payload_size;
    
    if (packet->total_size != expected_size) {
        return SCION_PACKET_ERR_INVALID_HEADER_LEN;
    }
    
    return SCION_PACKET_VALID;
}

bool scion_parse_packet(const uint8_t *buffer, size_t buffer_size, scion_packet_t *packet) {
    if (!buffer || !packet || buffer_size < SCION_MIN_HEADER_SIZE) {
        return false;
    }
    
    if (!scion_packet_init(packet)) {
        return false;
    }
    
    const uint8_t *ptr = buffer;
    size_t remaining = buffer_size;
    
    // Parse common header
    if (remaining < sizeof(scion_common_hdr_t)) {
        return false;
    }
    
    secure_memcpy(&packet->header, sizeof(scion_common_hdr_t), ptr, sizeof(scion_common_hdr_t));
    ptr += sizeof(scion_common_hdr_t);
    remaining -= sizeof(scion_common_hdr_t);
    
    // Extract address lengths from header (simplified implementation)
    uint8_t dst_len_units = (packet->header.dt_dl_st_sl >> 4) & 0x03;
    uint8_t src_len_units = packet->header.dt_dl_st_sl & 0x03;
    uint8_t dst_len = (dst_len_units == 1) ? 4 : 16;  // 4 for IPv4, 16 for IPv6
    uint8_t src_len = (src_len_units == 1) ? 4 : 16;
    
    // Parse ISD-AS identifiers
    if (remaining < 16) { // 2 * 8 bytes for ISD-AS
        return false;
    }
    
    secure_memcpy(&packet->addr_info.dst_ia, sizeof(uint64_t), ptr, sizeof(uint64_t));
    ptr += 8;
    secure_memcpy(&packet->addr_info.src_ia, sizeof(uint64_t), ptr, sizeof(uint64_t));
    ptr += 8;
    remaining -= 16;
    
    // Parse addresses
    if (remaining < dst_len + src_len) {
        return false;
    }
    
    if (dst_len > 0) {
        secure_memcpy(packet->addr_info.dst_addr, sizeof(packet->addr_info.dst_addr), ptr, dst_len);
        packet->addr_info.dst_addr_len = dst_len;
        ptr += dst_len;
        remaining -= dst_len;
    }
    
    if (src_len > 0) {
        secure_memcpy(packet->addr_info.src_addr, sizeof(packet->addr_info.src_addr), ptr, src_len);
        packet->addr_info.src_addr_len = src_len;
        ptr += src_len;
        remaining -= src_len;
    }
    
    // Calculate path data size
    uint8_t hdr_len_units = packet->header.hdr_len;
    size_t total_hdr_size = hdr_len_units * 4;
    size_t parsed_hdr_size = sizeof(scion_common_hdr_t) + 16 + dst_len + src_len;
    
    if (total_hdr_size > parsed_hdr_size) {
        packet->path_size = total_hdr_size - parsed_hdr_size;
        
        if (remaining < packet->path_size) {
            return false;
        }
        
        packet->path_data = malloc(packet->path_size);
        if (!packet->path_data) {
            return false;
        }
        
        secure_memcpy(packet->path_data, packet->path_size, ptr, packet->path_size);
        ptr += packet->path_size;
        remaining -= packet->path_size;
    }
    
    // Parse payload
    uint16_t payload_len = ntohs(packet->header.payload_len);
    if (payload_len > 0) {
        if (remaining < payload_len) {
            scion_packet_cleanup(packet);
            return false;
        }
        
        packet->payload = malloc(payload_len);
        if (!packet->payload) {
            scion_packet_cleanup(packet);
            return false;
        }
        
        secure_memcpy(packet->payload, payload_len, ptr, payload_len);
        packet->payload_size = payload_len;
    }
    
    packet->total_size = buffer_size;
    
    // Validate the parsed packet
    scion_packet_validation_result_t result = scion_validate_packet(packet);
    if (result != SCION_PACKET_VALID) {
        scion_packet_cleanup(packet);
        return false;
    }
    
    return true;
}

bool scion_serialize_packet(const scion_packet_t *packet, uint8_t *buffer, 
                           size_t buffer_size, size_t *written_size) {
    if (!packet || !buffer || !written_size) {
        return false;
    }
    
    // Validate packet first
    scion_packet_validation_result_t result = scion_validate_packet(packet);
    if (result != SCION_PACKET_VALID) {
        return false;
    }
    
    if (buffer_size < packet->total_size) {
        return false;
    }
    
    uint8_t *ptr = buffer;
    size_t remaining = buffer_size;
    
    // Serialize common header
    secure_memcpy(ptr, remaining, &packet->header, sizeof(scion_common_hdr_t));
    ptr += sizeof(scion_common_hdr_t);
    remaining -= sizeof(scion_common_hdr_t);
    
    // Serialize ISD-AS identifiers
    secure_memcpy(ptr, remaining, &packet->addr_info.dst_ia, sizeof(uint64_t));
    ptr += 8;
    secure_memcpy(ptr, remaining, &packet->addr_info.src_ia, sizeof(uint64_t));
    ptr += 8;
    remaining -= 16;
    
    // Serialize addresses
    if (packet->addr_info.dst_addr_len > 0) {
        secure_memcpy(ptr, remaining, packet->addr_info.dst_addr, packet->addr_info.dst_addr_len);
        ptr += packet->addr_info.dst_addr_len;
        remaining -= packet->addr_info.dst_addr_len;
    }
    
    if (packet->addr_info.src_addr_len > 0) {
        secure_memcpy(ptr, remaining, packet->addr_info.src_addr, packet->addr_info.src_addr_len);
        ptr += packet->addr_info.src_addr_len;
        remaining -= packet->addr_info.src_addr_len;
    }
    
    // Serialize path data
    if (packet->path_size > 0 && packet->path_data) {
        secure_memcpy(ptr, remaining, packet->path_data, packet->path_size);
        ptr += packet->path_size;
        remaining -= packet->path_size;
    }
    
    // Serialize payload
    if (packet->payload_size > 0 && packet->payload) {
        secure_memcpy(ptr, remaining, packet->payload, packet->payload_size);
        ptr += packet->payload_size;
        remaining -= packet->payload_size;
    }
    
    *written_size = packet->total_size;
    return true;
}

bool scion_create_packet(uint64_t src_ia, uint64_t dst_ia,
                        const uint8_t *src_addr, uint8_t src_addr_len,
                        const uint8_t *dst_addr, uint8_t dst_addr_len,
                        const uint8_t *payload, size_t payload_size,
                        scion_packet_t *packet) {
    if (!packet || payload_size > SCION_MAX_PAYLOAD_SIZE) {
        return false;
    }
    
    if (!scion_packet_init(packet)) {
        return false;
    }
    
    // Set up common header
    packet->header.version_flags = (SCION_VERSION << 4); // Version in upper 4 bits
    packet->header.qos_flow_id = 0;
    packet->header.flow_id = 0;
    packet->header.next_hdr = SCION_NEXTHDR_UDP; // Default to UDP
    packet->header.payload_len = htons(payload_size);
    packet->header.path_type = 0;
    packet->header.rsv = 0;
    
    // Set up address information
    packet->addr_info.src_ia = src_ia;
    packet->addr_info.dst_ia = dst_ia;
    packet->addr_info.src_addr_len = src_addr_len;
    packet->addr_info.dst_addr_len = dst_addr_len;
    
    // Copy addresses
    if (src_addr_len > 0 && src_addr) {
        if (src_addr_len > sizeof(packet->addr_info.src_addr)) {
            scion_packet_cleanup(packet);
            return false;
        }
        secure_memcpy(packet->addr_info.src_addr, sizeof(packet->addr_info.src_addr), src_addr, src_addr_len);
    }
    
    if (dst_addr_len > 0 && dst_addr) {
        if (dst_addr_len > sizeof(packet->addr_info.dst_addr)) {
            scion_packet_cleanup(packet);
            return false;
        }
        secure_memcpy(packet->addr_info.dst_addr, sizeof(packet->addr_info.dst_addr), dst_addr, dst_addr_len);
    }
    
    // Set address type and length fields (simplified encoding for basic implementation)
    uint8_t dst_type = SCION_ADDR_TYPE_IPV4; // Default to IPv4
    uint8_t src_type = SCION_ADDR_TYPE_IPV4;
    uint8_t dst_len_units = (dst_addr_len > 4) ? 3 : 1; // Simplified: 1 for IPv4, 3 for larger
    uint8_t src_len_units = (src_addr_len > 4) ? 3 : 1;
    
    packet->header.dt_dl_st_sl = (dst_type << 6) | (dst_len_units << 4) | 
                                (src_type << 2) | src_len_units;
    
    // Copy payload
    if (payload_size > 0 && payload) {
        packet->payload = malloc(payload_size);
        if (!packet->payload) {
            scion_packet_cleanup(packet);
            return false;
        }
        secure_memcpy(packet->payload, payload_size, payload, payload_size);
        packet->payload_size = payload_size;
    }
    
    // Calculate header length and total size
    size_t base_hdr_size = sizeof(scion_common_hdr_t) + 16 + dst_addr_len + src_addr_len;
    packet->header.hdr_len = (base_hdr_size + 3) / 4; // Round up to 4-byte units
    packet->total_size = base_hdr_size + payload_size;
    
    return true;
}

const char* scion_packet_validation_error_string(scion_packet_validation_result_t result) {
    switch (result) {
        case SCION_PACKET_VALID:
            return "Packet is valid";
        case SCION_PACKET_ERR_INVALID_VERSION:
            return "Invalid SCION version (expected 0x02 for BetaNet 1.1)";
        case SCION_PACKET_ERR_INVALID_HEADER_LEN:
            return "Invalid header length";
        case SCION_PACKET_ERR_INVALID_PAYLOAD_LEN:
            return "Invalid payload length";
        case SCION_PACKET_ERR_INVALID_ADDRESS:
            return "Invalid address format";
        case SCION_PACKET_ERR_INVALID_PATH:
            return "Invalid path information";
        case SCION_PACKET_ERR_BUFFER_TOO_SMALL:
            return "Buffer too small for packet";
        case SCION_PACKET_ERR_INVALID_CHECKSUM:
            return "Invalid packet checksum";
        default:
            return "Unknown validation error";
    }
}
