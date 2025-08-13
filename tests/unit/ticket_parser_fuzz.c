// Betanet Ticket Parser Fuzz Harness (libFuzzer compatible)
// References: Section 6 (Control Hooks), Section 10 (Testing Plan), Section 12 (Milestones) of technical-overview.md
// Protocol: Ticket parsing and replay logic must be robust against malformed input.

#include <stdint.h>
#include <stddef.h>
#include "betanet/betanet.h"

#include "src/htx/ticket.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

// Helper to generate a valid ticket buffer
void make_valid_ticket(uint8_t *buf, size_t *len) {
    size_t offset = 0;
    buf[offset++] = 0x01; // version
    memset(buf + offset, 0xAA, 32); offset += 32; // cliPub32
    memset(buf + offset, 0xBB, 8);  offset += 8;  // ticketKeyID8
    memset(buf + offset, 0xCC, 32); offset += 32; // nonce32
    memset(buf + offset, 0xDD, 32); offset += 32; // accessTicket32
    size_t padlen = 32; // valid padding (between 24 and 64)
    memset(buf + offset, 0x00, padlen); offset += padlen;
    *len = offset;
}

int main(void) {
    uint8_t ticket_buf[256];
    size_t ticket_len = 0;
    make_valid_ticket(ticket_buf, &ticket_len);

    htx_ticket_t ticket = {0};
    int parse_result = htx_ticket_parse((const char*)ticket_buf, &ticket);
    if (parse_result != 0) {
        printf("[FAIL] Ticket parse\n");
        return 1;
    }

    int valid = htx_ticket_validate(&ticket);
    if (valid != 1) {
        printf("[FAIL] Ticket validate\n");
        return 1;
    }

    int replay1 = htx_ticket_check_replay(&ticket);
    if (replay1 != 0) {
        printf("[FAIL] Ticket replay check (first use)\n");
        return 1;
    }

    int replay2 = htx_ticket_check_replay(&ticket);
    if (replay2 != 1) {
        printf("[FAIL] Ticket replay check (second use)\n");
        return 1;
    }

    printf("[PASS] Ticket parse/validate/replay\n");
    return 0;
}