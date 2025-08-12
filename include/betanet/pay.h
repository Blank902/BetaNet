#ifndef BETANET_PAY_API_H
#define BETANET_PAY_API_H

#include <stdint.h>
#include <stddef.h>

#define CASHU_VOUCHER_SIZE 128

#include "../../src/pay/pay.h"

// Validate a Cashu voucher for a known keyset.
// Returns 0 on success, nonzero on failure.
int betanet_pay_validate_voucher(const cashu_voucher_t *voucher, size_t voucher_len);

// Enforce per-keyset and per-peer rate-limits.
// Returns 0 if allowed, nonzero if rate-limited.
int betanet_pay_check_rate_limit(const uint8_t *keyset_id, const uint8_t *peer_id);

// Mark voucher as redeemed and trigger Lightning settlement if needed.
// Returns 0 on success, nonzero on failure.
int betanet_pay_settle_voucher(const cashu_voucher_t *voucher);

// Initialize and cleanup payment subsystem.
int betanet_pay_init(void);
void betanet_pay_cleanup(void);

#endif // BETANET_PAY_API_H