#ifndef BETANET_GOV_H
#define BETANET_GOV_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#define BETANET_MAX_AS_GROUPS 256
#define BETANET_MAX_ORGS 128
#define BETANET_MAX_ISDS 16
#define BETANET_MAX_SIGNERS 256

typedef struct {
    uint64_t node_id;
    uint32_t asn;
    uint32_t org_id;
    uint32_t isd;
    float uptime_score;
    float staked_ecash;
    float vote_weight_raw;
    float vote_weight;
    time_t last_seen;
} betanet_gov_node_t;

typedef struct {
    betanet_gov_node_t nodes[BETANET_MAX_SIGNERS];
    size_t node_count;
    float total_weight;
    float as_weights[BETANET_MAX_AS_GROUPS];
    float org_weights[BETANET_MAX_ORGS];
    uint32_t as_groups[BETANET_MAX_AS_GROUPS];
    size_t as_count;
    uint32_t orgs[BETANET_MAX_ORGS];
    size_t org_count;
    uint32_t isds[BETANET_MAX_ISDS];
    size_t isd_count;
} betanet_gov_context_t;

typedef struct {
    uint8_t payload_hash[32];
    uint64_t epoch;
    uint64_t signer_ids[BETANET_MAX_SIGNERS];
    float weights[BETANET_MAX_SIGNERS];
    uint8_t sigs[BETANET_MAX_SIGNERS][64];
    size_t signer_count;
} betanet_gov_quorum_cert_t;

typedef enum {
    BETANET_GOV_OK = 0,
    BETANET_GOV_ERR_QUORUM = -1,
    BETANET_GOV_ERR_DIVERSITY = -2,
    BETANET_GOV_ERR_PARTITION = -3,
    BETANET_GOV_ERR_CONCENTRATION = -4,
    BETANET_GOV_ERR_DELAY = -5,
    BETANET_GOV_ERR_ALIAS_INVALID = -6,
    BETANET_GOV_ERR_ALIAS_LIVENESS = -7,
    BETANET_GOV_ERR_ALIAS_FINALITY = -8,
    BETANET_GOV_ERR_EMERGENCY_ADVANCE = -9
} betanet_gov_result_t;

// Voting power calculation and anti-concentration enforcement
void betanet_gov_compute_weights(betanet_gov_context_t* ctx);

// Quorum, diversity, and partition checks
betanet_gov_result_t betanet_gov_check_quorum(const betanet_gov_context_t* ctx, const betanet_gov_quorum_cert_t* cert, time_t now);

// Upgrade delay logic
betanet_gov_result_t betanet_gov_check_upgrade_delay(time_t activation_time, time_t now, int partition_ok);

/**
 * Extended compliance check:
 * - Enforces alias ledger validity and liveness/finality windows.
 * - Integrates emergency advance and partition/diversity checks.
 */
betanet_gov_result_t betanet_gov_check_compliance(
    const betanet_gov_context_t* ctx,
    const betanet_gov_quorum_cert_t* cert,
    const betanet_alias_validation_t* alias_val,
    const betanet_quorum_cert_t* emergency_qc,
    time_t activation_time,
    time_t now,
    int partition_ok,
    int emergency_advance_requested,
    uint64_t required_weight,
    time_t alias_last_finalized_time
);

#endif // BETANET_GOV_H