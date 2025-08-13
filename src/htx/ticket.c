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
    // Enforce minimum ticket length (1+32+8+32+32+24 = 129), max 1+32+8+32+32+64 = 169
    if (len < 129 || len > 169) return -2;
    // Parse fields in order
    size_t offset = 0;
    uint8_t version = (uint8_t)input[offset++];
    if (version != 0x01) return -3;
    offset += 32; // cliPub32
    offset += 8;  // ticketKeyID8
    offset += 32; // nonce32
    offset += 32; // accessTicket32
    size_t padlen = len - offset;
    if (padlen < 24 || padlen > 64) return -4;
    for (size_t i = offset; i < len; ++i) {
        if (input[i] != 0x00) return -5;
    }
    memcpy(ticket->data, input, len);
    ticket->len = len;
    return 0;
}

// Validate a ticket: check carrier, field order, and padding as per spec.
int htx_ticket_validate(const htx_ticket_t* ticket) {
    if (!ticket || ticket->len < 129 || ticket->len > 169) return 0;
    uint8_t carrier;
    if (htx_ticket_negotiate_carrier(ticket, &carrier) != 0) return 0;
    size_t offset = 0;
    uint8_t version = ticket->data[offset++];
    if (version != 0x01) return 0;
    offset += 32; // cliPub32
    offset += 8;  // ticketKeyID8
    offset += 32; // nonce32
    offset += 32; // accessTicket32
    size_t padlen = ticket->len - offset;
    if (padlen < 24 || padlen > 64) return 0;
    for (size_t i = offset; i < ticket->len; ++i) {
        if (ticket->data[i] != 0x00) return 0;
    }
    // Cryptographic validation is a stub (feature flag)
    return 1; // valid
}

#include <stdint.h>
#include <stdlib.h>


// Replay prevention using (cliPub, hour) tuples and a 2-hour window.
// Per-prefix rate-limiting is not yet implemented (stub).
// These declarations moved to file scope to avoid shadowing and type errors.
#define MAX_TICKET_CACHE 256
#define REPLAY_WINDOW_SEC (2 * 60 * 60)

typedef struct {
    uint8_t cliPub[32];
    uint64_t hour;
    time_t timestamp;
} ticket_replay_entry_t;

static ticket_replay_entry_t ticket_cache[MAX_TICKET_CACHE];
static size_t ticket_cache_count = 0;

static int extract_cliPub_hour(const htx_ticket_t* ticket, uint8_t* cliPub, uint64_t* hour_out) {
    if (!ticket || ticket->len < 129) return -1;
    memcpy(cliPub, ticket->data + 1, 32);
    time_t now = time(NULL);
    *hour_out = (uint64_t)(now / 3600);
    return 0;
}

static int htx_ticket_perprefix_rate_limit(/*const char* ip*/) {
    // TODO: Implement per-/24 IPv4 and /56 IPv6 token buckets
    // Spec: README.md 150, technical-overview.md 105
    return 0;
}

int htx_ticket_check_replay(const htx_ticket_t* ticket) {
    if (!ticket) return -1;
    if (htx_ticket_perprefix_rate_limit() != 0) return 2; // rate limit exceeded (stub)
    uint8_t cliPub[32];
    uint64_t hour;
    if (extract_cliPub_hour(ticket, cliPub, &hour) != 0) return -2;
    time_t now = time(NULL);
    for (size_t i = 0; i < ticket_cache_count && i < MAX_TICKET_CACHE; ++i) {
        if (memcmp(ticket_cache[i].cliPub, cliPub, 32) == 0 &&
            ticket_cache[i].hour == hour &&
            (now - ticket_cache[i].timestamp) < REPLAY_WINDOW_SEC) {
            return 1; // replay detected
        }
    }
    size_t idx = ticket_cache_count % MAX_TICKET_CACHE;
    memcpy(ticket_cache[idx].cliPub, cliPub, 32);
    ticket_cache[idx].hour = hour;
    ticket_cache[idx].timestamp = now;
    ticket_cache_count++;
    return 0; // not a replay
}