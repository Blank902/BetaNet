// BetaNet Government Layer Protocol Unit Test
// Specification: BetaNet §6.1–§6.3
#include "betanet/gov_protocol.h"
#include <stdio.h>
#include <string.h>

int main() {
    gov_protocol_session_t* session = gov_protocol_session_create(1);
    if (!session) {
        printf("Failed to create government session\n");
        return 1;
    }
    int pid1 = gov_protocol_submit_proposal(session, "Increase block size");
    int pid2 = gov_protocol_submit_proposal(session, "Reduce fees");
    printf("Submitted proposals: %d, %d\n", pid1, pid2);
    gov_protocol_cast_vote(session, pid1, true);
    gov_protocol_cast_vote(session, pid1, true);
    gov_protocol_cast_vote(session, pid1, false);
    gov_protocol_cast_vote(session, pid2, false);
    gov_protocol_cast_vote(session, pid2, false);
    gov_protocol_cast_vote(session, pid2, true);
    gov_protocol_tally_votes(session, pid1);
    gov_protocol_tally_votes(session, pid2);
    int res1 = gov_protocol_get_result(session, pid1);
    int res2 = gov_protocol_get_result(session, pid2);
    printf("Proposal 1 result: %s\n", res1 == 2 ? "Accepted" : "Rejected");
    printf("Proposal 2 result: %s\n", res2 == 2 ? "Accepted" : "Rejected");
    gov_protocol_proposal_t proposals[4];
    int count = gov_protocol_list_proposals(session, proposals, 4);
    printf("Proposals listed: %d\n", count);
    for (int i = 0; i < count; ++i) {
        printf("Proposal %d: %s, Status: %d\n", proposals[i].proposal_id, proposals[i].description, proposals[i].status);
    }
    gov_protocol_session_destroy(session);
    printf("Government protocol test completed successfully\n");
    return 0;
}
