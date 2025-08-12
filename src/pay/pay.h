#ifndef BETANET_PAY_H
#define BETANET_PAY_H

#include <stdint.h>
#include <stddef.h>

#define CASHU_VOUCHER_SIZE 128

typedef struct {
    uint8_t keyset_id[32];
    uint8_t secret[32];
    uint8_t aggregated_sig[64];
} cashu_voucher_t;

typedef struct pay_rate_limit_s pay_rate_limit_t;

// Validate a Cashu voucher for a known keyset.
// Returns 0 on success, nonzero on failure.
int pay_validate_voucher(const cashu_voucher_t *voucher, size_t voucher_len);

// Enforce per-keyset and per-peer rate-limits.
// Returns 0 if allowed, nonzero if rate-limited.
int pay_check_rate_limit(const uint8_t *keyset_id, const uint8_t *peer_id);

// Mark voucher as redeemed and trigger Lightning settlement if needed.
// Returns 0 on success, nonzero on failure.
int pay_settle_voucher(const cashu_voucher_t *voucher);

// Initialize and cleanup payment subsystem.
int pay_init(void);
void pay_cleanup(void);

#endif // BETANET_PAY_H