#include "naming.h"
#include <sodium.h>
#include <string.h>

// Hex encoding for self-certifying ID
void betanet_id_from_pubkey(const uint8_t pubkey[BETANET_PUBKEY_LEN], char out_hex[BETANET_ID_HEX_LEN + 1]) {
    uint8_t hash[32];
    crypto_hash_sha256(hash, pubkey, BETANET_PUBKEY_LEN);
    for (int i = 0; i < 32; ++i)
        sprintf(out_hex + 2 * i, "%02x", hash[i]);
    out_hex[BETANET_ID_HEX_LEN] = 0;
}

bool betanet_id_validate(const char *id_hex, const uint8_t pubkey[BETANET_PUBKEY_LEN]) {
    char computed[BETANET_ID_HEX_LEN + 1];
    betanet_id_from_pubkey(pubkey, computed);
    return (strncmp(id_hex, computed, BETANET_ID_HEX_LEN) == 0);
}

// Alias ledger: valid if at least 2 of 3 sources finalized
bool betanet_alias_is_valid(const betanet_alias_validation_t *val) {
    return val && val->finalized_count >= 2;
}

// Quorum certificate validation
bool betanet_quorum_cert_validate(const betanet_quorum_cert_t *qc, uint64_t required_weight, uint64_t *out_total_weight) {
    if (!qc || qc->count == 0) return false;
    uint64_t total_weight = 0;
    for (size_t i = 0; i < qc->count; ++i) {
        // Verify Ed25519 sig: sigs[i] over ("bn-aa1" || payload_hash || epoch)
        uint8_t msg[32 + 8 + 6] = {0};
        memcpy(msg, "bn-aa1", 6);
        memcpy(msg + 6, qc->payload_hash, 32);
        for (int j = 0; j < 8; ++j)
            msg[38 + j] = (qc->epoch >> (56 - 8 * j)) & 0xFF;
        if (crypto_sign_verify_detached(qc->sigs[i], msg, 46, qc->signers[i]) != 0)
            return false;
        total_weight += qc->weights[i];
    }
    if (out_total_weight) *out_total_weight = total_weight;
    return total_weight >= required_weight;
}

// Emergency advance: allowed if <2 finalized for ≥14d and quorum cert is valid
bool betanet_emergency_advance_allowed(const betanet_alias_validation_t *val, const betanet_quorum_cert_t *qc, uint64_t required_weight) {
    if (!val || !qc) return false;
    if (val->finalized_count >= 2) return false;
    // Liveness window check (≥14d) is external; assume called only when eligible
    uint64_t total_weight = 0;
    if (!betanet_quorum_cert_validate(qc, required_weight, &total_weight))
        return false;
    return true;
}