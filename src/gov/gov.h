#ifndef BETANET_GOV_H
#define BETANET_GOV_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "../path/naming.h"  // For betanet_alias_validation_t and betanet_quorum_cert_t

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

// Additional types for governance functions
typedef struct {
    uint64_t proposal_id;
    uint8_t proposal_hash[32];
    time_t created_time;
    time_t voting_deadline;
    int status; // 0=pending, 1=passed, -1=failed
} betanet_proposal_t;

typedef enum {
    BETANET_VOTE_YES = 1,
    BETANET_VOTE_NO = 0,
    BETANET_VOTE_ABSTAIN = -1
} betanet_vote_choice_t;

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

/**
 * Governance configuration stub (deferred).
 * This struct is reserved for future governance logic and parameterization.
 * All fields and logic are subject to future specification and integration.
 */
typedef struct {
    // Placeholder for future governance parameters (e.g., caps, thresholds, feature flags)
    // Example fields (commented out, to be defined in future milestones):
    // float as_cap;
    // float org_cap;
    // uint32_t min_quorum_as;
    // uint32_t min_quorum_isd;
    // time_t upgrade_delay_days;
    // Add additional fields as needed for governance parameterization.
    int _deferred; // Marker field; not used.
} betanet_gov_config_t;

/**
 * Stub: Load governance config from file or buffer (deferred).
 * Returns 0 on success, -1 on error. Not implemented.
 */
int betanet_gov_config_load(betanet_gov_config_t* cfg, const char* path);

/**
 * Stub: Validate governance config (deferred).
 * Returns 0 if valid, -1 if invalid. Not implemented.
 */
int betanet_gov_config_validate(const betanet_gov_config_t* cfg);

/**
 * Stub: Apply governance config to context (deferred).
 * Returns 0 on success, -1 on error. Not implemented.
 */
int betanet_gov_config_apply(betanet_gov_context_t* ctx, const betanet_gov_config_t* cfg);

/**
 * Submit a vote for a proposal.
 * Returns 0 on success, -1 on error.
 */
int betanet_gov_submit_vote(betanet_proposal_t* proposal, uint64_t voter_id, betanet_vote_choice_t choice, float weight, time_t now);

/**
 * Tally votes for a proposal.
 */
void betanet_gov_tally_votes(const betanet_proposal_t* proposal, size_t* yes_count, float* yes_weight,
                             size_t* no_count, float* no_weight,
                             size_t* abstain_count, float* abstain_weight);

/**
 * Update proposal status based on tally and thresholds.
 * Returns 1 if status changed, 0 otherwise.
 */
int betanet_gov_update_proposal_status(betanet_proposal_t* proposal, float total_weight, float threshold, time_t now);

#endif // BETANET_GOV_H