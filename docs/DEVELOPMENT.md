# Betanet Developer Guide

## Overview

This guide covers implementation details for traffic-fingerprinting, shaping, and related architectural decisions in Betanet C library.

---

## Traffic Fingerprinting

Betanet aims to minimize protocol fingerprintability by:

- Mirroring origin TLS/HTTP2/3 fingerprints (JA3/JA4, ALPN, extension order, H2 SETTINGS).
- Performing per-connection calibration to match origin parameters.
- Randomizing PING cadence and PRIORITY frame emission.
- Using variable-length padding and dummy data to obscure traffic patterns.

**Known Limitations:**  
- QUIC fingerprinting is stubbed and not yet implemented.  
- Some HTTP/2/3 behaviors are emulated but not fully origin-mirrored in all edge cases.

---

## Traffic Shaping

Traffic shaping is implemented via:

- Configurable fixed/random padding on frames.
- Jittered keepalive intervals.
- Idle padding: dummy encrypted DATA sent if no user data for 200–1200 ms.
- Cover connections on UDP→TCP fallback.

**Known Limitations:**  
- Multipath and mixnet shaping are stubbed.
- Adaptive shaping profiles are planned but not yet implemented.

---

## Architectural Notes

- Modular structure: shaping logic in [`src/shape/`](src/shape/).
- Hooks for future multipath, mixnet, and PQ hybrid features.
- All deferred features are clearly marked as stubs or behind feature flags.

---

## Incomplete or Stubbed Features

- QUIC transport support (stubbed).
- PQ hybrid handshake (stubbed, feature flag).
- Multipath routing (API hooks only).
- Mixnet integration (stubbed).

See [`technical-overview.md`](technical-overview.md:167-191) for rationale and mitigation plans.

---

_Last updated: 2025-08-12_