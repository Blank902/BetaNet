---
name: Security Issue
about: Report a security vulnerability (please email maintainers for critical issues)
title: '[SECURITY] '
labels: security
assignees: ''
---

## ⚠️ Security Advisory

**For critical security vulnerabilities, please contact the maintainers privately before opening a public issue.**

## Security Issue Type

- [ ] Cryptographic vulnerability
- [ ] Protocol design flaw
- [ ] Implementation bug with security impact
- [ ] Side-channel attack vector
- [ ] Denial of Service (DoS)
- [ ] Information disclosure
- [ ] Other (specify below)

## Affected Components

- [ ] Noise XK handshake
- [ ] HTX transport layer
- [ ] Access ticket system
- [ ] Traffic shaping/fingerprinting
- [ ] Replay protection
- [ ] Key management
- [ ] Certificate validation
- [ ] Other (specify below)

## Impact Assessment

### Severity

- [ ] Critical - Remote code execution, key recovery
- [ ] High - Authentication bypass, significant privacy leak
- [ ] Medium - Local privilege escalation, limited information disclosure
- [ ] Low - Minor information leak, DoS with local access

### Exploitability

- [ ] Network-based remote exploit
- [ ] Local access required
- [ ] Physical access required
- [ ] Theoretical/academic concern

## Description

A clear description of the security issue, including:

1. **Attack scenario**: How could an attacker exploit this?
2. **Preconditions**: What access/conditions are needed?
3. **Impact**: What could an attacker achieve?

## Proof of Concept

```text
If applicable, include a minimal proof of concept.
DO NOT include working exploits for critical vulnerabilities.
```

## Affected Versions

- Version range: [e.g. all versions, 1.0-1.1, specific commit hash]
- Configuration requirements: [e.g. only with QUIC enabled]

## Suggested Mitigation

If you have ideas for fixing the issue, please describe them.

## Timeline

For responsible disclosure:

- [ ] I understand this may be a security issue
- [ ] I am willing to work with maintainers on responsible disclosure
- [ ] I have contacted maintainers privately (if critical)

## References

Any relevant security advisories, papers, or documentation.
