#ifndef BOOT_H
#define BOOT_H

/*
 * Bootstrapping ticket and replay prevention API (stub).
 *
 * All ticket handling, replay cache, rate-limiting, and rotation logic
 * are not yet implemented. See Betanet spec section in [`README.md`](README.md:115).
 */

/*
 * boot_admit_ticket:
 * Parse, validate, and check replay for a ticket string.
 * Returns 0 if valid and not replayed, 1 if replayed, 2 if rate-limited, negative on error.
 */
int boot_admit_ticket(const char* input);

/*
 * boot_distributed_replay_check:
 * Stub for distributed replay tracking (feature flag).
 * Returns 0 (not implemented).
 */
int boot_distributed_replay_check(const char* input);

#endif // BOOT_H