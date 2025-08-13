#include "gov.h"
#include <string.h>
#include <math.h>
#include <time.h>
#include "../path/naming.h"

static int contains(uint32_t* arr, size_t count, uint32_t val) {
    for (size_t i = 0; i < count; ++i) if (arr[i] == val) return 1;
    return 0;
}

void betanet_gov_compute_weights(betanet_gov_context_t* ctx) {
    // Reset
    memset(ctx->as_weights, 0, sizeof(ctx->as_weights));
    memset(ctx->org_weights, 0, sizeof(ctx->org_weights));
    ctx->as_count = ctx->org_count = ctx->isd_count = 0;
    ctx->total_weight = 0.0f;

    // Compute raw weights and collect AS/Org/ISD sets
    for (size_t i = 0; i < ctx->node_count; ++i) {
        betanet_gov_node_t* n = &ctx->nodes[i];
        n->vote_weight_raw = log2f(1.0f + n->uptime_score) + log10f(n->staked_ecash / 1000.0f + 1.0f);
        // Per-AS/Org/ISD sets
        if (!contains(ctx->as_groups, ctx->as_count, n->asn) && ctx->as_count < BETANET_MAX_AS_GROUPS)
            ctx->as_groups[ctx->as_count++] = n->asn;
        if (!contains(ctx->orgs, ctx->org_count, n->org_id) && ctx->org_count < BETANET_MAX_ORGS)
            ctx->orgs[ctx->org_count++] = n->org_id;
        if (!contains(ctx->isds, ctx->isd_count, n->isd) && ctx->isd_count < BETANET_MAX_ISDS)
            ctx->isds[ctx->isd_count++] = n->isd;
    }

    // Sum raw weights per AS/Org
    for (size_t i = 0; i < ctx->node_count; ++i) {
        betanet_gov_node_t* n = &ctx->nodes[i];
        ctx->as_weights[n->asn % BETANET_MAX_AS_GROUPS] += n->vote_weight_raw;
        ctx->org_weights[n->org_id % BETANET_MAX_ORGS] += n->vote_weight_raw;
    }

    // Apply caps and compute effective weights
    float global_total = 0.0f;
    for (size_t i = 0; i < ctx->node_count; ++i) {
        betanet_gov_node_t* n = &ctx->nodes[i];
        float as_cap = 0.2f * ctx->node_count; // Will normalize below
        float org_cap = 0.25f * ctx->node_count;
        float as_sum = ctx->as_weights[n->asn % BETANET_MAX_AS_GROUPS];
        float org_sum = ctx->org_weights[n->org_id % BETANET_MAX_ORGS];
        // Cap per-AS and per-Org
        float cap = n->vote_weight_raw;
        float as_limit = 0.2f * as_sum;
        float org_limit = 0.25f * org_sum;
        if (cap > as_limit) cap = as_limit;
        if (cap > org_limit) cap = org_limit;
        n->vote_weight = cap;
        global_total += cap;
    }
    ctx->total_weight = global_total;
}

static int count_distinct(uint32_t* arr, size_t count) {
    int c = 0;
    for (size_t i = 0; i < count; ++i) if (arr[i]) ++c;
    return c;
}

betanet_gov_result_t betanet_gov_check_quorum(const betanet_gov_context_t* ctx, const betanet_gov_quorum_cert_t* cert, time_t now) {
    // 1. Σ weight(ACK) ≥ 0.67 × Σ weight(active_nodes_14d)
    float ack_weight = 0.0f;
    uint32_t as_seen[BETANET_MAX_AS_GROUPS] = {0};
    uint32_t org_seen[BETANET_MAX_ORGS] = {0};
    uint32_t isd_seen[BETANET_MAX_ISDS] = {0};
    size_t as_ack = 0, org_ack = 0, isd_ack = 0;
    for (size_t i = 0; i < cert->signer_count; ++i) {
        uint64_t sid = cert->signer_ids[i];
        for (size_t j = 0; j < ctx->node_count; ++j) {
            if (ctx->nodes[j].node_id == sid) {
                ack_weight += ctx->nodes[j].vote_weight;
                uint32_t asn = ctx->nodes[j].asn;
                uint32_t org = ctx->nodes[j].org_id;
                uint32_t isd = ctx->nodes[j].isd;
                if (!contains(as_seen, as_ack, asn) && as_ack < BETANET_MAX_AS_GROUPS)
                    as_seen[as_ack++] = asn;
                if (!contains(org_seen, org_ack, org) && org_ack < BETANET_MAX_ORGS)
                    org_seen[org_ack++] = org;
                if (!contains(isd_seen, isd_ack, isd) && isd_ack < BETANET_MAX_ISDS)
                    isd_seen[isd_ack++] = isd;
                break;
            }
        }
    }
    if (ack_weight < 0.67f * ctx->total_weight)
        return BETANET_GOV_ERR_QUORUM;
    // 2. Diversity: ≥24 AS, ≥3 ISDs, no AS >20%, no Org >25%
    if (as_ack < 24 || isd_ack < 3)
        return BETANET_GOV_ERR_DIVERSITY;
    // Check AS/Org concentration
    for (size_t i = 0; i < as_ack; ++i) {
        float as_sum = 0.0f;
        for (size_t j = 0; j < cert->signer_count; ++j) {
            uint64_t sid = cert->signer_ids[j];
            for (size_t k = 0; k < ctx->node_count; ++k) {
                if (ctx->nodes[k].node_id == sid && ctx->nodes[k].asn == as_seen[i])
                    as_sum += ctx->nodes[k].vote_weight;
            }
        }
        if (as_sum > 0.2f * ack_weight)
            return BETANET_GOV_ERR_CONCENTRATION;
    }
    for (size_t i = 0; i < org_ack; ++i) {
        float org_sum = 0.0f;
        for (size_t j = 0; j < cert->signer_count; ++j) {
            uint64_t sid = cert->signer_ids[j];
            for (size_t k = 0; k < ctx->node_count; ++k) {
                if (ctx->nodes[k].node_id == sid && ctx->nodes[k].org_id == org_seen[i])
                    org_sum += ctx->nodes[k].vote_weight;
            }
        }
        if (org_sum > 0.25f * ack_weight)
            return BETANET_GOV_ERR_CONCENTRATION;
    }
    // 3. Partition/path checks and 4. Partition safety are stubbed (require network state)
    // Assume partition_ok is passed externally for now
    return BETANET_GOV_OK;
}

betanet_gov_result_t betanet_gov_check_upgrade_delay(time_t activation_time, time_t now, int partition_ok) {
    // Activation waits ≥30 days after threshold
    if (now < activation_time + 30 * 24 * 3600)
        return BETANET_GOV_ERR_DELAY;
    // If partition/diversity fails ≥7 days before activation, defer
    if (!partition_ok)
        return BETANET_GOV_ERR_PARTITION;
    return BETANET_GOV_OK;
}

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
) {
    // 1. Normal path: alias must be valid and within finality/liveness windows
    if (!emergency_advance_requested) {
        if (!betanet_alias_is_valid(alias_val))
            return BETANET_GOV_ERR_ALIAS_INVALID;
        // Enforce liveness window: must be finalized within 14 days
        if (now - alias_last_finalized_time > 14 * 24 * 3600)
            return BETANET_GOV_ERR_ALIAS_LIVENESS;
        // Enforce finality window: must be finalized at least 30 days before activation
        if (activation_time - alias_last_finalized_time < 30 * 24 * 3600)
            return BETANET_GOV_ERR_ALIAS_FINALITY;
    } else {
        // 2. Emergency advance path: allowed if <2 finalized for ≥14d and quorum cert is valid
        if (!betanet_emergency_advance_allowed(alias_val, emergency_qc, required_weight))
            return BETANET_GOV_ERR_EMERGENCY_ADVANCE;
    }

    // 3. Quorum, partition, and diversity checks
    betanet_gov_result_t q = betanet_gov_check_quorum(ctx, cert, now);
    if (q != BETANET_GOV_OK) return q;
    betanet_gov_result_t d = betanet_gov_check_upgrade_delay(activation_time, now, partition_ok);
    if (d != BETANET_GOV_OK) return d;
    return BETANET_GOV_OK;
}
/* Governance logic stub - not implemented.
 * This section is a placeholder for future governance logic.
 * Governance logic not implemented.
 */
/**
 * Governance proposal and vote structures.
 * These are the core data types for on-chain governance logic.
 */

#include <stdint.h>
#include <stddef.h>

// Enum for proposal status/state
typedef enum {
    BETANET_PROPOSAL_PENDING = 0,
    BETANET_PROPOSAL_ACTIVE,
    BETANET_PROPOSAL_ACCEPTED,
    BETANET_PROPOSAL_REJECTED,
    BETANET_PROPOSAL_EXECUTED,
    BETANET_PROPOSAL_EXPIRED
} betanet_proposal_status_t;

// Enum for vote choice
typedef enum {
    BETANET_VOTE_NONE = 0,
    BETANET_VOTE_YES,
    BETANET_VOTE_NO,
    BETANET_VOTE_ABSTAIN
} betanet_vote_choice_t;

// Structure for a single vote record
typedef struct {
    uint64_t voter_id;                // Node or participant ID
    betanet_vote_choice_t choice;     // Vote choice
    float weight;                     // Voting weight at time of vote
    time_t timestamp;                 // When the vote was cast
} betanet_vote_record_t;

// Structure for a governance proposal
typedef struct {
    uint64_t proposal_id;             // Unique proposal identifier
    uint64_t proposer_id;             // Who submitted the proposal
    time_t created_at;                // Proposal creation time
    time_t expires_at;                // Expiry time for voting
    betanet_proposal_status_t status; // Current status/state
    void* payload;                    // Pointer to proposal payload (type depends on proposal)
    size_t payload_size;              // Size of payload
    betanet_vote_record_t* votes;     // Array of votes (dynamic or fixed-size)
    size_t vote_count;                // Number of votes
    // TODO: Add execution result, audit trail, etc.
} betanet_proposal_t;

/**
 * Submit a vote for a proposal.
 * Returns 0 on success, -1 on error (e.g., expired, already voted).
 */
int betanet_gov_submit_vote(betanet_proposal_t* proposal, uint64_t voter_id, betanet_vote_choice_t choice, float weight, time_t now) {
    if (!proposal || proposal->status != BETANET_PROPOSAL_ACTIVE || now > proposal->expires_at)
        return -1;
    // Check for duplicate vote
    for (size_t i = 0; i < proposal->vote_count; ++i) {
        if (proposal->votes[i].voter_id == voter_id)
            return -1;
    }
    // Record vote
    betanet_vote_record_t* new_votes = (betanet_vote_record_t*)realloc(proposal->votes, sizeof(betanet_vote_record_t) * (proposal->vote_count + 1));
    if (!new_votes) return -1;
    proposal->votes = new_votes;
    proposal->votes[proposal->vote_count].voter_id = voter_id;
    proposal->votes[proposal->vote_count].choice = choice;
    proposal->votes[proposal->vote_count].weight = weight;
    proposal->votes[proposal->vote_count].timestamp = now;
    proposal->vote_count += 1;
    return 0;
}

/**
 * Tally votes for a proposal.
 * Returns YES/NO/ABSTAIN counts and weights.
 */
void betanet_gov_tally_votes(const betanet_proposal_t* proposal, size_t* yes_count, float* yes_weight,
                             size_t* no_count, float* no_weight,
                             size_t* abstain_count, float* abstain_weight) {
    if (!proposal) return;
    *yes_count = *no_count = *abstain_count = 0;
    *yes_weight = *no_weight = *abstain_weight = 0.0f;
    for (size_t i = 0; i < proposal->vote_count; ++i) {
        switch (proposal->votes[i].choice) {
            case BETANET_VOTE_YES:
                (*yes_count)++;
                *yes_weight += proposal->votes[i].weight;
                break;
            case BETANET_VOTE_NO:
                (*no_count)++;
                *no_weight += proposal->votes[i].weight;
                break;
            case BETANET_VOTE_ABSTAIN:
                (*abstain_count)++;
                *abstain_weight += proposal->votes[i].weight;
                break;
            default:
                break;
        }
    }
}

/**
 * Update proposal status based on tally and thresholds.
 * Returns 1 if status changed, 0 otherwise.
 * TODO: Integrate with governance thresholds and context.
 */
int betanet_gov_update_proposal_status(betanet_proposal_t* proposal, float total_weight, float threshold, time_t now) {
    if (!proposal || proposal->status != BETANET_PROPOSAL_ACTIVE)
        return 0;
    if (now < proposal->expires_at)
        return 0; // Voting still open
    size_t yes_count, no_count, abstain_count;
    float yes_weight, no_weight, abstain_weight;
    betanet_gov_tally_votes(proposal, &yes_count, &yes_weight, &no_count, &no_weight, &abstain_count, &abstain_weight);
    if (yes_weight >= threshold * total_weight)
        proposal->status = BETANET_PROPOSAL_ACCEPTED;
    else
        proposal->status = BETANET_PROPOSAL_REJECTED;
    // TODO: Hook for proposal execution after acceptance
    // TODO: Record audit/history entry for status transition
    return 1;
}

// TODO: Add hooks for proposal execution after acceptance.
// TODO: Add querying for proposal history and audit trails.

#include <stdio.h>

/**
 * Stub: Load governance config from file or buffer (deferred).
 * Not implemented. Returns -1.
 */
int betanet_gov_config_load(betanet_gov_config_t* cfg, const char* path) {
    (void)cfg; (void)path;
    // Deferred: config loading not implemented.
    return -1;
}

/**
 * Stub: Validate governance config (deferred).
 * Not implemented. Returns -1.
 */
int betanet_gov_config_validate(const betanet_gov_config_t* cfg) {
    (void)cfg;
    // Deferred: config validation not implemented.
    return -1;
}

/**
 * Stub: Apply governance config to context (deferred).
 * Not implemented. Returns -1.
 */
int betanet_gov_config_apply(betanet_gov_context_t* ctx, const betanet_gov_config_t* cfg) {
    (void)ctx; (void)cfg;
    // Deferred: config application not implemented.
    return -1;
}