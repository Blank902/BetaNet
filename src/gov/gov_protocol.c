// BetaNet Government Layer Protocol Implementation
// Specification: BetaNet §6.1–§6.3
#include "betanet/gov_protocol.h"
#include <stdlib.h>
#include <string.h>

#define MAX_PROPOSALS 32
#define MAX_VOTES 128

typedef struct {
    uint32_t proposal_id;
    uint32_t votes_accept;
    uint32_t votes_reject;
    uint8_t  status;
} gov_protocol_vote_tally_t;

struct gov_protocol_session_internal {
    gov_protocol_session_t session;
    gov_protocol_proposal_t proposals[MAX_PROPOSALS];
    gov_protocol_vote_tally_t tallies[MAX_PROPOSALS];
    uint32_t proposal_count;
};

gov_protocol_session_t* gov_protocol_session_create(uint32_t epoch) {
    struct gov_protocol_session_internal* s = (struct gov_protocol_session_internal*)calloc(1, sizeof(struct gov_protocol_session_internal));
    if (!s) return NULL;
    s->session.session_id = ((uint64_t)rand() << 32) | rand();
    s->session.epoch = epoch;
    s->session.state = 0;
    s->session.result = 0;
    s->proposal_count = 0;
    return (gov_protocol_session_t*)s;
}

void gov_protocol_session_destroy(gov_protocol_session_t* session) {
    free(session);
}

int gov_protocol_submit_proposal(gov_protocol_session_t* session, const char* description) {
    struct gov_protocol_session_internal* s = (struct gov_protocol_session_internal*)session;
    if (s->proposal_count >= MAX_PROPOSALS) return -1;
    uint32_t pid = s->proposal_count + 1;
    gov_protocol_proposal_t* p = &s->proposals[s->proposal_count];
    p->proposal_id = pid;
    strncpy(p->description, description, sizeof(p->description)-1);
    p->status = 1;
    s->tallies[s->proposal_count].proposal_id = pid;
    s->tallies[s->proposal_count].status = 1;
    s->proposal_count++;
    return pid;
}

int gov_protocol_cast_vote(gov_protocol_session_t* session, uint32_t proposal_id, bool accept) {
    struct gov_protocol_session_internal* s = (struct gov_protocol_session_internal*)session;
    for (uint32_t i = 0; i < s->proposal_count; ++i) {
        if (s->proposals[i].proposal_id == proposal_id) {
            if (accept) s->tallies[i].votes_accept++;
            else s->tallies[i].votes_reject++;
            return 0;
        }
    }
    return -1;
}

int gov_protocol_tally_votes(gov_protocol_session_t* session, uint32_t proposal_id) {
    struct gov_protocol_session_internal* s = (struct gov_protocol_session_internal*)session;
    for (uint32_t i = 0; i < s->proposal_count; ++i) {
        if (s->proposals[i].proposal_id == proposal_id) {
            if (s->tallies[i].votes_accept > s->tallies[i].votes_reject) {
                s->proposals[i].status = 2;
                s->session.result = 1;
            } else {
                s->proposals[i].status = 3;
                s->session.result = 2;
            }
            s->session.state = 3;
            return s->proposals[i].status;
        }
    }
    return -1;
}

int gov_protocol_get_result(gov_protocol_session_t* session, uint32_t proposal_id) {
    struct gov_protocol_session_internal* s = (struct gov_protocol_session_internal*)session;
    for (uint32_t i = 0; i < s->proposal_count; ++i) {
        if (s->proposals[i].proposal_id == proposal_id) {
            return s->proposals[i].status;
        }
    }
    return -1;
}

int gov_protocol_list_proposals(gov_protocol_session_t* session, gov_protocol_proposal_t* proposals, uint32_t max_count) {
    struct gov_protocol_session_internal* s = (struct gov_protocol_session_internal*)session;
    uint32_t count = (s->proposal_count < max_count) ? s->proposal_count : max_count;
    for (uint32_t i = 0; i < count; ++i) {
        proposals[i] = s->proposals[i];
    }
    return count;
}
