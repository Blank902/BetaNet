#ifndef HTX_TICKET_H
#define HTX_TICKET_H

/*
 * Ticket structure and replay prevention API.
 *
 * This header defines the ticket structure and stub APIs for ticket parsing,
 * validation, replay prevention, and related logic as described in the Betanet
 * specification ([`README.md`](../README.md:115), section "Ticket Handling and Replay Prevention").
 *
 * Features required by the spec but NOT YET IMPLEMENTED:
 *   - Ticket structure and cryptographic validation
 *   - Replay cache for duplicate rejection
 *   - Per-prefix rate-limiting
 *   - Ticket rotation logic
 *   - Persistent storage of replay cache
 *
 * All functions below are stubs. See the Betanet spec for details.
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * htx_ticket_t: Opaque ticket structure.
 * Actual ticket format, cryptographic fields, and validation logic are
 * not implemented. See Betanet spec for required fields.
 */
typedef struct htx_ticket_s {
    uint8_t data[256]; // Placeholder for ticket data (size TBD by spec)
    size_t len;        // Actual length of ticket data
} htx_ticket_t;

/*
 * htx_ticket_parse:
 * Parse a ticket from a string or buffer.
 * Not implemented. Should parse fields as per Betanet spec.
 * Returns 0 on success, negative on error.
 */
int htx_ticket_parse(const char* input, htx_ticket_t* ticket);

/*
 * htx_ticket_validate:
 * Validate a ticket's structure and cryptographic signature.
 * Not implemented. Should perform all checks required by the spec.
 * Returns 1 if valid, 0 if invalid, negative on error.
 */
int htx_ticket_validate(const htx_ticket_t* ticket);

/*
 * htx_ticket_check_replay:
 * Check if a ticket is a replay (duplicate) and enforce per-prefix rate-limiting.
 * Not implemented. Should use a replay cache and rate-limiting logic as per spec.
 * Returns 1 if not a replay, 0 if duplicate/replayed, negative on error.
 */
int htx_ticket_check_replay(const htx_ticket_t* ticket);

#ifdef __cplusplus
}
#endif

#endif // HTX_TICKET_H