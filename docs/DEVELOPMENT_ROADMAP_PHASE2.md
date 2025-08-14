# BetaNet C Library - Development Roadmap Phase 2

## Current Status Assessment

Based on analysis of the BetaNet 1.1 specification and our current implementation:

### ✅ Completed (Phase 1)

- Core HTX transport framework
- Noise XK handshake implementation
- Security utility framework (253 vulnerabilities fixed)
- Access ticket bootstrap system (basic)
- AEAD framing with ChaCha20-Poly1305
- CI/CD pipeline with Codacy integration
- Cross-platform build system

### 🚧 Partially Implemented

- HTX inner frame format (needs 5.4 compliance)
- Access ticket negotiated carrier system
- HTTP/2 behavior emulation
- Path maintenance and multipath hooks
- Bootstrap discovery system

### ❌ Missing Critical Features

- Origin mirroring and auto-calibration (5.1)
- Replay-bound access tickets (5.2)
- Anti-correlation fallback (5.6)
- Adaptive anti-abuse (6.5)
- BeaconSet-based discovery (6.3)
- SCION packet handling (4.1)
- HTX-tunneled transitions (4.2)

## Phase 2 Development Priorities

### Priority 1: HTX Transport Compliance (L2)

#### 1.1 Origin Mirroring & Auto-Calibration (§5.1)

- **Requirements**: Mirror front origin fingerprint (JA3/JA4)
- **Implementation**: Pre-flight calibration before inner handshake
- **Files**: `src/htx/origin_calibration.c`, `include/betanet/htx_calibration.h`

#### 1.2 Enhanced Access Tickets (§5.2)

- **Requirements**: Negotiated carrier (cookie/query/body), replay bounds
- **Implementation**: Carrier policy parsing, variable padding
- **Files**: `src/htx/access_tickets.c` (enhance existing)

#### 1.3 Inner Frame Format Compliance (§5.4)

- **Requirements**: Proper frame structure, flow control
- **Implementation**: Stream ID management, window updates
- **Files**: `src/htx/inner_frames.c` (enhance existing)

#### 1.4 HTTP/2 Behavior Emulation (§5.5)

- **Requirements**: SETTINGS mirroring, PING cadence, PRIORITY frames
- **Implementation**: Adaptive behavior based on origin
- **Files**: `src/htx/http2_emulation.c`

### Priority 2: Path Layer Implementation (L1)

#### 2.1 SCION Packet Header (§4.1)

- **Requirements**: Version 0x02, packet validation
- **Implementation**: Basic SCION packet structure
- **Files**: `src/path/scion.c`, `include/betanet/scion.h`

#### 2.2 HTX-Tunneled Transitions (§4.2)

- **Requirements**: Gateway bridge logic, control streams
- **Implementation**: Non-SCION link bridging
- **Files**: `src/path/htx_transitions.c`

#### 2.3 Path Maintenance (§4.3)

- **Requirements**: Multi-path management, probe logic
- **Implementation**: Path validation and switching
- **Files**: `src/path/path_maintenance.c`

### Priority 3: Overlay Mesh (L3)

#### 3.1 BeaconSet Discovery (§6.3)

- **Requirements**: Rotating rendezvous DHT, PoW-bound
- **Implementation**: Ephemeral ID generation, discovery methods
- **Files**: `src/overlay/discovery.c`, `include/betanet/discovery.h`

#### 3.2 Adaptive Anti-Abuse (§6.5)

- **Requirements**: PoW difficulty adjustment, rate limiting
- **Implementation**: Sliding window metrics, bucket limits
- **Files**: `src/overlay/anti_abuse.c`

## Implementation Schedule

### Week 1: HTX Origin Mirroring
- Implement TLS fingerprint calibration
- Add pre-flight connection logic
- Origin parameter mirroring (ALPN, extensions)

### Week 2: Enhanced Access Tickets  
- Carrier policy parsing and selection
- Variable padding implementation
- Replay prevention enhancement

### Week 3: Inner Frame Compliance
- Stream ID management
- Flow control windows
- Frame type handling

### Week 4: HTTP/2 Emulation
- SETTINGS mirroring logic
- PING cadence implementation
- Adaptive behavior patterns

### Week 5: SCION Implementation
- Basic SCION packet structure
- HTX-tunneled transitions
- Path maintenance logic

### Week 6: Discovery & Anti-Abuse
- BeaconSet-based discovery
- PoW implementation
- Rate limiting framework

### Week 7: Integration & Testing
- End-to-end compliance testing
- Interoperability validation
- Performance optimization

### Week 8: Documentation & Release
- API documentation updates
- Compliance verification
- Release preparation

## Success Criteria

### Technical Compliance
- [ ] §5.1 Origin mirroring with calibration
- [ ] §5.2 Negotiated carrier access tickets
- [ ] §5.4 Proper inner frame format
- [ ] §5.5 HTTP/2 behavior emulation
- [ ] §4.1 SCION packet handling
- [ ] §6.3 BeaconSet discovery
- [ ] §6.5 Adaptive anti-abuse

### Quality Metrics
- [ ] A-grade Codacy rating maintained
- [ ] 95%+ test coverage on new code
- [ ] Zero critical security vulnerabilities
- [ ] Cross-platform compatibility
- [ ] Performance benchmarks met

### Documentation
- [ ] Updated API documentation
- [ ] Compliance mapping document
- [ ] Integration examples
- [ ] Migration guide from 1.0

## Risk Mitigation

### Technical Risks
- **SCION Complexity**: Start with minimal implementation, expand incrementally
- **Origin Fingerprinting**: Use conservative defaults, validate against known sites
- **Performance Impact**: Profile critical paths, optimize hot code

### Resource Constraints
- **Time Management**: Focus on core compliance first, defer non-critical features
- **Testing Coverage**: Automated regression testing for each component
- **Documentation**: Generate docs as code develops, not as afterthought

This roadmap ensures we achieve BetaNet 1.1 compliance while maintaining the security and quality standards established in Phase 1.
