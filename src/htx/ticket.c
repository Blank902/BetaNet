#include "ticket.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// Carrier negotiation logic (simple demo: check for carrier byte in ticket)
int htx_ticket_negotiate_carrier(const htx_ticket_t* ticket, uint8_t* carrier_out) {
    if (!ticket || ticket->len < 1 || !carrier_out) return -1;
    // Assume first byte is carrier type for demo
    *carrier_out = ticket->data[0];
    // Accept carriers 0x01 (UDP), 0x02 (TCP), 0x03 (QUIC) for demo
    if (*carrier_out == 0x01 || *carrier_out == 0x02 || *carrier_out == 0x03) return 0;
    return -2; // unsupported carrier
}

// Parse a ticket from a string or buffer, enforce variable-length padding
int htx_ticket_parse(const char* input, htx_ticket_t* ticket) {
    if (!input || !ticket) return -1;
    size_t len = strlen(input);
    if (len > sizeof(ticket->data)) len = sizeof(ticket->data);
    // Enforce minimum ticket length (e.g., 16 bytes) and variable padding (last byte = padding length)
    if (len < 16) return -2;
    uint8_t padlen = (uint8_t)input[len-1];
    if (padlen > len-1) return -3; // invalid padding
    // Optionally: check all padding bytes are zero (or a pattern)
    for (size_t i = len - padlen; i < len - 1; ++i) {
        if (input[i] != 0x00) return -4; // nonzero padding
    }
    memcpy(ticket->data, input, len);
    ticket->len = len;
    return 0;
}

// Validate a ticket: check carrier, length, and padding
int htx_ticket_validate(const htx_ticket_t* ticket) {
    if (!ticket || ticket->len < 16) return 0;
    uint8_t carrier;
    if (htx_ticket_negotiate_carrier(ticket, &carrier) != 0) return 0;
    uint8_t padlen = ticket->data[ticket->len-1];
    if (padlen > ticket->len-1) return 0;
    for (size_t i = ticket->len - padlen; i < ticket->len - 1; ++i) {
        if (ticket->data[i] != 0x00) return 0;
    }
    return 1; // valid
}

#include <stdint.h>
#include <stdlib.h>

// Simple in-memory replay cache and rate-limiter (not thread-safe, not persistent)
#define MAX_TICKET_CACHE 128
#define MAX_TICKET_RATE 16
#define TICKET_RATE_WINDOW_SEC 5

static uint8_t ticket_cache[MAX_TICKET_CACHE][256];
static size_t ticket_cache_len[MAX_TICKET_CACHE] = {0};
static time_t ticket_cache_time[MAX_TICKET_CACHE] = {0};
static size_t ticket_cache_count = 0;

// Simple rate-limiter: allow MAX_TICKET_RATE tickets per window
static time_t ticket_rate_times[MAX_TICKET_RATE] = {0};
static size_t ticket_rate_idx = 0;

static int htx_ticket_rate_limit() {
    time_t now = time(NULL);
    size_t count = 0;
    for (size_t i = 0; i < MAX_TICKET_RATE; ++i) {
        if (now - ticket_rate_times[i] < TICKET_RATE_WINDOW_SEC) count++;
    }
    if (count >= MAX_TICKET_RATE) return -1; // rate limit exceeded
    ticket_rate_times[ticket_rate_idx] = now;
    ticket_rate_idx = (ticket_rate_idx + 1) % MAX_TICKET_RATE;
    return 0;
}

// Replay prevention check with rate-limiting
int htx_ticket_check_replay(const htx_ticket_t* ticket) {
    if (!ticket) return -1;
    if (htx_ticket_rate_limit() != 0) return 2; // rate limit exceeded
    // Check for replay
    for (size_t i = 0; i < ticket_cache_count && i < MAX_TICKET_CACHE; ++i) {
        if (ticket_cache_len[i] == ticket->len &&
            memcmp(ticket_cache[i], ticket->data, ticket->len) == 0) {
            return 1; // replay detected
        }
    }
    // Store ticket
    size_t idx = ticket_cache_count % MAX_TICKET_CACHE;
    memcpy(ticket_cache[idx], ticket->data, ticket->len);
    ticket_cache_len[idx] = ticket->len;
    ticket_cache_time[idx] = time(NULL);
    ticket_cache_count++;
    return 0; // not a replay
}