# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in MCPS, please report it responsibly.

**Email**: security@agentsign.dev
**PGP**: Available on request
**Response time**: We aim to acknowledge reports within 24 hours and provide a fix within 72 hours for critical issues.

**Do NOT**:
- Open a public GitHub issue for security vulnerabilities
- Disclose the vulnerability publicly before a fix is available
- Exploit the vulnerability beyond what is necessary to demonstrate it

## Scope

The following are in scope for security reports:

- `mcp-secure` npm package (index.js)
- AgentSign Trust Authority API (agentsign.dev)
- MCPS protocol specification (SPEC.md)
- Key generation, signing, and verification functions
- Passport issuance and validation
- Nonce store and replay protection
- Tool integrity verification
- Transcript binding

## Out of Scope

- Denial of service via excessive API calls (rate limiting is the deployer's responsibility)
- Social engineering attacks
- Vulnerabilities in dependencies of applications that use MCPS (MCPS has zero dependencies)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Security Measures

### Cryptographic Standards
- **Signing**: ECDSA P-256 (NIST FIPS 186-5, RFC 6979 deterministic nonces)
- **Hash**: SHA-256
- **Format**: IEEE P1363 r||s with low-S normalization (BIP-0062)
- **Canonicalization**: RFC 8785 (JSON Canonicalization Scheme)
- **Key encoding**: PKCS#8 (private), SPKI (public), JWK (passport-embedded)

### Supply Chain Security
- Zero runtime dependencies
- All cryptography via Node.js native `crypto` module (OpenSSL)
- No use of `elliptic`, `noble-curves`, or other third-party crypto libraries
- Package published from a 2FA-protected npm account

### Testing
- 75 standard tests (SEP-2395 aligned)
- 105 advanced red team tests (19 attack categories)
- Cross-referenced against all known ECDSA/MCP CVEs (2024-2026)
- Full audit report: [SECURITY-AUDIT.md](SECURITY-AUDIT.md)

### Incident Response

1. **Triage** (0-24h): Acknowledge report, assess severity (CVSS 3.1)
2. **Containment** (24-48h): Develop fix, prepare advisory
3. **Fix** (48-72h): Publish patched version to npm, notify affected users
4. **Disclosure** (72h+): Publish advisory with CVE if applicable

### Vulnerability Disclosure Timeline

- **0 days**: Report received, acknowledged
- **≤7 days**: Fix developed and tested
- **≤14 days**: Patched version published
- **≤30 days**: Public disclosure (coordinated with reporter)
- **90 days**: Maximum embargo period

## Contact

- **Security reports**: security@agentsign.dev
- **General**: contact@agentsign.dev
- **Maintainer**: Raza Sharif, CyberSecAI Ltd
