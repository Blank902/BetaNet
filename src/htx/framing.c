// framing.c - HTTP/2–3 style framing, padding, and idle logic implementation
// See: README.md, technical-overview.md

#include "framing.h"
#include <string.h>

// Encode a frame (framing + optional padding)
// Returns 0 on success, -1 on error
int htx_frame_encode(
    htx_frame_type_t type,
    const uint8_t *payload, size_t payload_len,
    uint8_t *out, size_t out_size, size_t *written)
{
    // Stub: HTTP/2–3 style frame header (9 bytes), then payload
    if (out_size < 9 + payload_len) return -1;
    htx_frame_header_t hdr = {0};
    hdr.length = (uint32_t)payload_len;
    hdr.type = (uint8_t)type;
    hdr.flags = 0;
    hdr.stream_id = 0;
    memcpy(out, &hdr, 9); // Not wire format, just a stub
    if (payload_len) memcpy(out + 9, payload, payload_len);
    if (written) *written = 9 + payload_len;
    return 0;
}

// Decode a frame (extract header and payload)
// Returns 0 on success, -1 on error
int htx_frame_decode(
    const uint8_t *in, size_t in_len,
    htx_frame_header_t *header,
    const uint8_t **payload, size_t *payload_len)
{
    // Stub: expects at least 9 bytes for header
    if (in_len < 9) return -1;
    if (header) memcpy(header, in, 9);
    if (payload) *payload = in + 9;
    if (payload_len && header) *payload_len = header->length;
    return 0;
}

// Add padding to a frame (returns new length)
size_t htx_frame_add_padding(
    uint8_t *frame, size_t frame_len, size_t pad_len, size_t max_size)
{
    // Stub: append zero bytes as padding, up to max_size
    if (frame_len + pad_len > max_size) pad_len = max_size - frame_len;
    memset(frame + frame_len, 0, pad_len);
    return frame_len + pad_len;
}

// Generate idle frame (for keepalive)
// Returns number of bytes written
size_t htx_frame_idle(uint8_t *out, size_t out_size)
{
    // Stub: idle frame is a frame with type=HTX_FRAME_IDLE, zero payload
    if (out_size < 9) return 0;
    htx_frame_header_t hdr = {0};
    hdr.length = 0;
    hdr.type = HTX_FRAME_IDLE;
    hdr.flags = 0;
    hdr.stream_id = 0;
    memcpy(out, &hdr, 9);
    return 9;
}