// BetaNet Government Layer Protocol API
// Specification: BetaNet §6.1–§6.3
#ifndef BETANET_GOV_PROTOCOL_H
#define BETANET_GOV_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Government session structure
typedef struct {
    uint64_t session_id;
    uint32_t epoch;
    uint32_t proposal_id;
    uint8_t  state; // 0: idle, 1: voting, 2: consensus, 3: finalized
    uint8_t  result; // 0: undecided, 1: accepted, 2: rejected
    void*    user_data;
} gov_protocol_session_t;

// Proposal structure
typedef struct {
    uint32_t proposal_id;
    char     description[256];
    uint8_t  status; // 0: pending, 1: active, 2: accepted, 3: rejected
} gov_protocol_proposal_t;

// API
// Initialize government protocol session
gov_protocol_session_t* gov_protocol_session_create(uint32_t epoch);
// Destroy session
void gov_protocol_session_destroy(gov_protocol_session_t* session);
// Submit proposal
int gov_protocol_submit_proposal(gov_protocol_session_t* session, const char* description);
// Cast vote
int gov_protocol_cast_vote(gov_protocol_session_t* session, uint32_t proposal_id, bool accept);
// Tally votes
int gov_protocol_tally_votes(gov_protocol_session_t* session, uint32_t proposal_id);
// Get proposal result
int gov_protocol_get_result(gov_protocol_session_t* session, uint32_t proposal_id);
// List proposals
int gov_protocol_list_proposals(gov_protocol_session_t* session, gov_protocol_proposal_t* proposals, uint32_t max_count);

#ifdef __cplusplus
}
#endif

#endif // BETANET_GOV_PROTOCOL_H
