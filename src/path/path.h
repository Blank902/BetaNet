// Naming, trust, and alias ledger API
#include "naming.h"
#ifndef PATH_H
#define PATH_H

#include <stdint.h>
#include <stddef.h>

#define BETANET_MAX_PATHS 3

typedef enum {
    BETANET_PATH_SCION = 1,
    BETANET_PATH_SKYON = 2,
    BETANET_PATH_LEGACY = 3
} betanet_path_type_t;

#define BETANET_MAX_MIXNET_HOPS 4

typedef struct {
    char nym_id[64];      // Nym node identifier (base58 or hex)
    uint32_t as_group;    // Autonomous System group
    float trust_score;    // Trust score for this hop
} betanet_mixnet_hop_t;

typedef struct {
    float uptime_score;      // 0.0–1.0
    float relay_score;       // 0.0–1.0
    float staked_ecash;      // in satoshis
    float trust_score;       // computed, 0.0–1.0
} betanet_peer_trust_t;

typedef enum {
    BETANET_PRIVACY_STRICT = 0,
    BETANET_PRIVACY_BALANCED = 1,
    BETANET_PRIVACY_PERFORMANCE = 2
} betanet_privacy_mode_t;

typedef struct {
    betanet_path_type_t type;
    uint8_t scion_header[64]; // Enough for SCION header, adjust as needed
    size_t scion_header_len;
    int validated;
    uint64_t last_probe_ts;
    int is_active;

    // Mixnet privacy layer
    betanet_mixnet_hop_t mixnet_hops[BETANET_MAX_MIXNET_HOPS];
    size_t mixnet_hop_count;
    betanet_privacy_mode_t privacy_mode;
    float peer_trust_score;
} betanet_path_t;

typedef struct {
    betanet_path_t paths[BETANET_MAX_PATHS];
    size_t count;
    size_t active_index; // currently selected path
} betanet_path_list_t;

/**
 * Initialize a path list for multipath routing.
 */
void betanet_path_init(betanet_path_list_t* plist);

/**
 * Add a path to the list. Returns 0 on success, -1 if full.
 */
int betanet_path_add(betanet_path_list_t* plist, const betanet_path_t* path);

/**
 * Select the active path by index. Returns 0 on success, -1 on error.
 */
int betanet_path_select(betanet_path_list_t* plist, size_t index);

/**
 * Get the currently active path (or NULL if none).
 */
const betanet_path_t* betanet_path_get_active(const betanet_path_list_t* plist);

/**
 * Probe a path (stub for future path validation/probing).
 */
int betanet_path_probe(betanet_path_list_t* plist, size_t index);

/**
 * Mark a path as validated or not.
 */
void betanet_path_validate(betanet_path_list_t* plist, size_t index, int valid);

/**
 * Mixnet-aware path provider: fills out a path list with privacy hops according to mode and trust.
 */
void betanet_mixnet_path_provider(betanet_path_list_t* plist, betanet_privacy_mode_t mode, const betanet_peer_trust_t* trust, const char* src_peer_id, const char* dst_peer_id, uint16_t stream_nonce);

#endif // PATH_H