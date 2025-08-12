#ifndef NAMING_H
#define NAMING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define BETANET_ID_HEX_LEN 64
#define BETANET_PUBKEY_LEN 32
#define BETANET_SIG_LEN 64
#define BETANET_ALIAS_MAXLEN 128

// Self-certifying ID: betanet://<hex SHA-256(pubkey)>
void betanet_id_from_pubkey(const uint8_t pubkey[BETANET_PUBKEY_LEN], char out_hex[BETANET_ID_HEX_LEN + 1]);
bool betanet_id_validate(const char *id_hex, const uint8_t pubkey[BETANET_PUBKEY_LEN]);

// Alias ledger record
typedef struct {
    uint8_t pk[BETANET_PUBKEY_LEN];
    uint64_t seq;
    uint8_t sig[BETANET_SIG_LEN];
    uint64_t exp;
    char alias[BETANET_ALIAS_MAXLEN];
} betanet_alias_record_t;

// Finality sources
typedef enum {
    BETANET_FINALITY_HANDSHAKE_L1 = 1,
    BETANET_FINALITY_FILECOIN_FVM = 2,
    BETANET_FINALITY_ETH_L2_RAVEN = 3
} betanet_finality_source_t;

// Alias ledger validation
typedef struct {
    betanet_alias_record_t record;
    bool finalized[3]; // [L1, FVM, L2]
    uint8_t finalized_count;
} betanet_alias_validation_t;

bool betanet_alias_is_valid(const betanet_alias_validation_t *val);

// Emergency advance: quorum certificate
#define BETANET_MAX_QUORUM_SIGNERS 32

typedef struct {
    uint8_t payload_hash[32];
    uint64_t epoch;
    uint8_t signers[BETANET_MAX_QUORUM_SIGNERS][BETANET_PUBKEY_LEN];
    uint32_t weights[BETANET_MAX_QUORUM_SIGNERS];
    uint8_t sigs[BETANET_MAX_QUORUM_SIGNERS][BETANET_SIG_LEN];
    size_t count;
} betanet_quorum_cert_t;

bool betanet_quorum_cert_validate(const betanet_quorum_cert_t *qc, uint64_t required_weight, uint64_t *out_total_weight);

// Emergency advance logic
bool betanet_emergency_advance_allowed(const betanet_alias_validation_t *val, const betanet_quorum_cert_t *qc, uint64_t required_weight);

#endif // NAMING_H