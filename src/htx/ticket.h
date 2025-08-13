#ifndef HTX_TICKET_H
#define HTX_TICKET_H

/*
 * Ticket structure and replay prevention API.
 *
 * Implements ticket parsing, validation, and replay prevention as per:
 *   - README.md 127-154, 395-396
 *   - technical-overview.md 25, 65, 105, 120, 160
 *
 * Features deferred or stubbed (feature flags):
 *   - Cryptographic validation of accessTicket
 *   - Per-prefix (IPv4 /24, IPv6 /56) rate-limiting (stub)
 *   - Distributed replay tracking
 *   - Ticket rotation logic
 *   - Persistent storage of replay cache
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * htx_ticket_t: Ticket structure.
 * Fields as per README.md 151:
 *   - version (1B)
 *   - cliPub32 (32B)
 *   - ticketKeyID8 (8B)
 *   - nonce32 (32B)
 *   - accessTicket32 (32B)
 *   - padding (24..64B)
 */
typedef struct htx_ticket_s {
    uint8_t data[256];
    size_t len;
} htx_ticket_t;
/*
 * htx_ticket_parse:
 * Parse a ticket from a string or buffer.
 * Enforces field order and padding as per README.md 151.
 * Returns 0 on success, negative on error.
 */
int htx_ticket_parse(const char* input, htx_ticket_t* ticket);

/*
 * htx_ticket_validate:
 * Validate a ticket's structure and cryptographic signature.
 * Checks carrier, field order, and padding as per README.md 151-152.
 * Cryptographic validation is stubbed (feature flag).
 * Returns 1 if valid, 0 if invalid, negative on error.
 */
int htx_ticket_validate(const htx_ticket_t* ticket);

/*
 * htx_ticket_check_replay:
 * Check if a ticket is a replay (duplicate) and enforce per-prefix rate-limiting.
 * Implements (cliPub, hour) tuple replay window as per README.md 148-150.
 * Per-prefix rate-limiting is stubbed (always allows).
 * Returns 0 if not a replay, 1 if duplicate/replayed, 2 if rate-limited, negative on error.
 */
int htx_ticket_check_replay(const htx_ticket_t* ticket);


#ifdef __cplusplus
}
#endif

#endif // HTX_TICKET_H