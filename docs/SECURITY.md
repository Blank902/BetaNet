# Betanet Security Notes

## Overview

This document summarizes security-relevant implementation details, mitigations, and known limitations for the Betanet C library.

---

## Random Number Generation (RNG)

- Uses system-provided CSPRNG via OpenSSL/mbedTLS or platform APIs.
- All cryptographic operations (keygen, nonce, padding) use CSPRNG.
- RNG is tested for basic entropy and failure modes.

**Known Limitations:**  
- PQ hybrid RNG requirements are stubbed (pending PQ integration).
- No hardware RNG fallback implemented.

---

## Replay Windows

- Bootstrap ticket replay prevention:  
  - Tickets are valid for a 2-hour window, checked per peer and per network prefix.
  - Duplicate tickets are rejected within the window.
- Nonce/counter management for AEAD and handshake follows spec.
- Flow-control and window updates are enforced per stream.

**Known Limitations:**  
- Distributed replay tracking (across multiple servers) is not implemented.
- Some replay logic is stubbed for future governance integration.

---

## Side-Channel Mitigations

- Constant-time cryptographic operations where supported by libraries.
- Proof-of-work and ticket verification are implemented to avoid timing leaks.
- Padding and dummy traffic reduce observable side-channel signals.

**Known Limitations:**  
- No formal side-channel analysis performed.
- Some mitigations depend on upstream library correctness.

---

## Incomplete or Stubbed Features

- PQ hybrid handshake (stubbed, feature flag).
- Multipath and mixnet security logic (stubbed).
- Distributed replay tracking (planned).

See [`technical-overview.md`](technical-overview.md:167-191) for deferred features and mitigation plans.

---

_Last updated: 2025-08-12_