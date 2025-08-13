// framing.h - HTTP/2–3 style framing, padding, and idle logic interface
// See: README.md, technical-overview.md

#ifndef HTX_FRAMING_H
#define HTX_FRAMING_H

#include <stddef.h>
#include <stdint.h>

// Frame types (mimic HTTP/2–3)
typedef enum {
    HTX_FRAME_DATA = 0,
    HTX_FRAME_PADDING = 1,
    HTX_FRAME_IDLE = 2,
    // Extend as needed
} htx_frame_type_t;

// Frame header (fixed 9 bytes like HTTP/2, can be adjusted)
typedef struct {
    uint32_t length;      // 24 bits in HTTP/2, here 32 for simplicity
    uint8_t  type;        // htx_frame_type_t
    uint8_t  flags;
    uint32_t stream_id;   // 31 bits in HTTP/2, here 32 for simplicity
} htx_frame_header_t;

// Frame encode (framing + optional padding)
int htx_frame_encode(
    htx_frame_type_t type,
    const uint8_t *payload, size_t payload_len,
    uint8_t *out, size_t out_size, size_t *written);

// Frame decode (extract header and payload)
int htx_frame_decode(
    const uint8_t *in, size_t in_len,
    htx_frame_header_t *header,
    const uint8_t **payload, size_t *payload_len);

// Add padding to a frame (returns new length)
size_t htx_frame_add_padding(
    uint8_t *frame, size_t frame_len, size_t pad_len, size_t max_size);

// Generate idle frame (for keepalive)
size_t htx_frame_idle(uint8_t *out, size_t out_size);

#endif // HTX_FRAMING_H