# Betanet C Library – Technical Overview & Specifications

## 1. Introduction

This document describes the technical design, architecture, and implementation plan for a minimal but spec‑conformant **C library** for Betanet.  
The goal is to produce a fully testable implementation for the newly announced **C library bounty**, with a $0 budget and only local development tools.

## 2. Objectives

- Deliver a **minimal working C library** implementing:
  - Core handshake
  - Wire format
  - Client–server session lifecycle
  - Outer HTTPS‑like transport (HTX)
- Include CLI demo for running **two peers locally**.
- Structure code for progressive enhancement (Noise‑XK, PQ hybrid, multipath routing, cover traffic shaping).

## PQ Hybrid Handshake (X25519+Kyber768, Feature-Flagged, Stub)

Betanet implements a **PQ hybrid handshake** (X25519+Kyber768) as a stub, gated by the `BETANET_ENABLE_PQ_HYBRID` feature flag. This code path is present for compliance and future PQC readiness, but is **not implemented** and does not provide real Kyber768 security.

- **How to enable:**  
  Define `BETANET_ENABLE_PQ_HYBRID` as `1` at compile time or uncomment the macro in [`include/betanet/betanet.h`](include/betanet/betanet.h:4-7).
- **Status:** Stub only; enabling the flag does not provide PQ security.
- **Rationale:** Deferred due to dependency on external PQ libraries and evolving standards. See §14 Deferred Features for details.
## 3. Scope

### 3.1 In-Scope (Initial Milestone)
- HTX transport over TCP (later QUIC).
- Noise XK inner encrypted channel.
- Framing, padding, and idle behavior mimicking HTTPS/2–3.
- Multi-path API hooks; single-path for demo.
- Bootstrap ticket handling and replay prevention.
- Config stubs for future governance logic.

### 3.2 Out-of-Scope (Initial Milestone)
- Full SCION/Skyon routing.
- Full mixnet integration.
- Mandatory PQ hybrid (will be optional feature flag later).

## 4. Architecture Overview

+----------------------------+
| CLI Demo App |
+----------------------------+
| Public C API |
+----------------------------+
| Control Plane Hooks |
| (Bootstrap / Routing) |
+----------------------------+
| Inner Secure Channel |
| (Noise XK, AEAD Framing) |
+----------------------------+
| Cover Transport Layer |
| (TLS1.3 / HTTP2, QUIC opt) |
+----------------------------+
| Path Selection / Routing |
+----------------------------+
| Access Media (Sockets) |
+----------------------------+

**Key Layers**:
- **L0 Access Media**: Sockets (TCP loopback or LAN).
- **L1 Path Selection**: Abstraction for path providers.
- **L2 Cover Transport (HTX)**:
  - Outer TLS1.3 + HTTP/2 headers mimic.
  - ALPN, cipher suite, and fingerprint tuning.
- **Inner Secure Channel**:
  - Noise XK handshake.
  - Rekey / counter reset.
  - AEAD framing with padding.
- **Control Hooks**:
  - Ticket replay/rate-limit logic.
  - Future routing integrations.

## 5. Public C API Specification

| Function | Description |
|----------|-------------|
| `betanet_ctx_new/free` | Create/destroy context. |
| `betanet_set_option` | Set fingerprints, profiles, QUIC/h2, etc. |
| `betanet_client_connect()` | Connect to peer with ticket. |
| `betanet_server_accept()` | Accept incoming connection. |
| `betanet_send()` | Send data on stream. |
| `betanet_recv()` | Receive data from stream. |
| `betanet_rekey_now()` | Force key rotation. |
| `betanet_stats_get()` | Query counters/state. |
| `betanet_path_set_provider()` | Install path selector plugin. |
| `betanet_bootstrap_set_provider()` | Install ticket validation API. |

## 6. Project Structure

libbetanetc/
include/betanet/*.h # Public API headers
src/htx/ # TLS/HTTP mimic layer
src/noise/ # Noise XK handshake + AEAD
src/shape/ # Padding / timing logic
src/path/ # Path selection abstraction
src/boot/ # Ticket/replay management
src/util/ # Logging, RNG, timers
cli/bnetc-cli/ # CLI demo peer
tests/unit/ # Unit tests
tests/interop/ # Interop tests
cmake/ # Build configuration

text

## 7. Technical Decisions

- **TLS/HTTP Profile:** Use OpenSSL/mbedTLS with strict CDN-like profiles.
- **Noise XK:** X25519 + ChaCha20-Poly1305/AES-GCM, PQ hybrid behind feature flag.
- **Framing/Padding:** Configurable fixed/random padding, HTTP2 priorities, jittered keepalive.
- **Rate Limits:** One ticket/hour, per-network-prefix tracking.

## 8. Testing Plan (Zero Budget)

- Local loopback integration tests.
- Fingerprint conformity snapshots.
- Parser fuzzing via libFuzzer/AFL.
- Replay attack simulation in scripts.
- CI via GitHub Actions with AddressSanitizer/UndefinedBehaviorSanitizer.

## 9. Milestones

| Milestone | Deliverable | ETA |
|-----------|-------------|-----|
| M0 | Repo, build system, CI, RNG | Week 1 |
| M1 | Outer TLS/HTTP2 transport & ticket handling | Weeks 2–3 |
| M2 | Noise XK inner channel, AEAD framing | Weeks 4–5 |
| M3 | Rekey / rotation logic & replay defense | Week 6 |
| M4 | Shaping profiles / fingerprint tuning (adaptive HTTP/2/3 emulation, SETTINGS mirroring, PING cadence, padding, priorities) | Week 7 (complete) |
| M5 | QUIC transport support (optional) | Week 8+ |
| M6 | PQ hybrid integration | Future |

## 10. Documentation Deliverables

- **README** with quickstart, architecture diagram, and spec mapping.
- **Developer Guide** for traffic-fingerprinting and shaping.
- **Security Notes** with RNG, replay windows, and side-channel mitigations.
- **CLI Scripts** for local handshake/echo demo.

## 11. Risks & Mitigation

- **Spec Ambiguity:** Keep thin abstractions; log assumptions; open issues upstream.
- **QUIC Complexity:** Postpone until h2 transport is stable.
- **Fingerprint Drift:** Version fingerprint profiles; regression test against them.

## 12. Tooling Stack

- Build: CMake, clang/gcc
- Crypto: OpenSSL/mbedTLS, libsodium
- QUIC (optional): picoquic/msquic
- Fuzzing: libFuzzer/AFL
- CI: GitHub Actions (ASan/UBSan builds)

---
**Status:** draft 
**Author:** ellentane
## 13. Architectural Decisions Summary

### Extensibility
- **Feature Flags and Stubs:** Deferred features (QUIC, PQ hybrid, multipath, mixnet) are implemented as stubs or behind feature flags for progressive enhancement ([technical-overview.md:16-17, 21, 31, 124-126], [`src/htx/htx.c`](src/htx/htx.c:21, 478), [`src/noise/noise.c`](src/noise/noise.c:5, 35)).
- **Modular Structure:** Codebase is organized into modules for transport, handshake, shaping, path selection, and ticketing ([technical-overview.md:83-92]).
- **API Hooks:** Public API exposes hooks for path selection and bootstrap providers ([technical-overview.md:80-81]).

### Security
- **Noise XK with PQ Hybrid (Stubbed):** Implements Noise XK handshake with hybrid X25519 and Kyber768 support (stubbed, to be enabled by feature flag) ([technical-overview.md:103, 125], [`src/noise/noise.c`](src/noise/noise.c:5, 35, 229)).
- **Replay and Rate Limiting:** Ticket replay prevention and per-peer rate limits are planned ([technical-overview.md:25, 105], [`src/pay/pay.c`](src/pay/pay.c:11, 87)).
- **Framing and Padding:** Configurable padding, adaptive shaping, SETTINGS mirroring, PING cadence, and jittered keepalive for traffic analysis resistance and protocol indistinguishability ([technical-overview.md:104], README.md:454-455).

### Compliance
- **Governance and Compliance Checks:** Compliance logic is modular, with stubs for future governance ([technical-overview.md:26], [`src/gov/gov.c`](src/gov/gov.c:135)).
- **Replay and Admission Controls:** Planned integration of DHT, mDNS, Bluetooth, and PoW for peer admission ([`src/path/path.c`](src/path/path.c:154, 160, 166, 172)).
**Last Updated:** 2025/12/8
## 14. Deferred Features: Risks, Trade-offs, and Rationale

### QUIC Transport
- **Rationale for Deferral:** QUIC introduces significant complexity in protocol handling, dependency management, and fingerprinting ([technical-overview.md:21, 124, 137], [`src/htx/htx.c`](src/htx/htx.c:21, 478)). Deferred until HTTP/2/TLS transport is stable.
- **Risks:** Falling behind on modern transport standards; future integration may require refactoring; potential security and performance gaps.
- **Trade-offs:** Simpler initial implementation and testing; avoids premature optimization.
- **Mitigation:** Maintain modular transport abstraction; track QUIC API changes; regression test with QUIC stubs. QUIC stubs are clearly marked in code and referenced in documentation.

### PQ Hybrid (Post-Quantum)
- **Rationale for Deferral:** PQ hybrid handshake (Kyber768) is stubbed and gated by feature flag ([technical-overview.md:31, 103, 125], [`src/noise/noise.c`](src/noise/noise.c:5, 35, 229)). Deferred due to dependency on external PQ libraries and evolving standards.
- **Risks:** Delayed PQ readiness; risk of cryptographic agility issues; compliance lag if PQ becomes mandatory.
- **Trade-offs:** Reduced implementation risk; easier debugging of classical crypto.
- **Mitigation:** Hybrid handshake code paths are tested as stubs; PQC standardization is monitored; documentation and code comments reference deferred status and rationale.

### Multipath Routing
- **Rationale for Deferral:** Multipath is API-hooked but only single-path is implemented ([technical-overview.md:24, 16], [`src/path/path.c`](src/path/path.c:93)). Deferred due to complexity in path management and lack of real-world multipath scenarios in demo.
- **Risks:** Architectural drift if multipath is not considered in core logic; missed performance and resilience benefits.
- **Trade-offs:** Simpler demo and test harness; avoids premature optimization.
- **Mitigation:** Multipath hooks are retained in API; assumptions are documented in code and documentation; design tests for multipath when feasible.

### Mixnet Integration
- **Rationale for Deferral:** Mixnet logic is stubbed in path selection ([technical-overview.md:30], [`src/path/path.c`](src/path/path.c:87, 93, 111, 121, 131)). Deferred due to external dependencies and complexity of mixnet routing.
- **Risks:** Reduced privacy/anonymity; future integration may require changes to path abstraction.
- **Trade-offs:** Faster initial delivery; avoids dependency on external mixnet infrastructure.
- **Mitigation:** Mixnet stubs and interfaces are kept in code; documentation references deferred status and phased integration plan.

### Distributed Replay Tracking
- **Rationale for Deferral:** Distributed replay tracking is deferred and not yet implemented ([technical-overview.md:191], [`src/boot/boot.c`](src/boot/boot.c:4, 29)). Deferred due to complexity and prioritization of core features.
- **Risks:** Potential replay vulnerabilities in distributed settings; delayed deployment of distributed anti-abuse.
- **Trade-offs:** Faster delivery of core functionality; avoids premature optimization.
- **Mitigation:** Modular design allows for future addition; rationale and risks are documented in code and documentation.

## 15. Recommendations for Tracking and Mitigating Deferred Feature Risks

- **Maintain Modular Interfaces:** Ensure all deferred features remain behind clear API boundaries and feature flags to minimize integration friction.
- **Continuous Stub Testing:** Include stubs for deferred features in CI and regression tests to prevent bitrot and architectural drift.
- **Upstream Monitoring:** Track upstream developments in QUIC, PQC, multipath, and mixnet standards; periodically review integration feasibility.
- **Documentation and Issue Tracking:** Log all assumptions, deferred decisions, and open questions in project documentation and issue tracker.
- **Stakeholder Review:** Schedule periodic architectural reviews to reassess priorities and unblock deferred features as resources allow.
- **Compliance Watch:** Monitor regulatory and compliance changes that may affect cryptography or privacy requirements, especially for PQ and mixnet features.