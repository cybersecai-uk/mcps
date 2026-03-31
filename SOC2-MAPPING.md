# MCPS — SOC 2 Trust Service Criteria Mapping

How MCPS controls map to AICPA SOC 2 Type II Trust Service Criteria.
This document demonstrates how integrating MCPS into an MCP gateway or agent platform directly satisfies SOC 2 audit requirements.

---

## Overview

SOC 2 defines five Trust Service Categories: **Security**, **Availability**, **Processing Integrity**, **Confidentiality**, and **Privacy**. MCPS provides cryptographic controls that map to 23 specific criteria across Security, Processing Integrity, and Confidentiality.

For MCP gateway operators (e.g. Composio, Arcade, TrueFoundry), integrating MCPS means your SOC 2 auditor can point to concrete cryptographic evidence for each control — not just policies and procedures, but mathematically verifiable proof.

---

## Security (Common Criteria)

### CC1: Control Environment

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| CC1.1 — Integrity and ethical values | Patent (GB2604808.2), MIT license, CLA for contributors | CONTRIBUTING.md, LICENSE |
| CC1.2 — Board oversight | Single maintainer with patent holder authority, all PRs require approval | GitHub branch protection, CONTRIBUTING.md |

### CC2: Communication and Information

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| CC2.1 — Internal communication of security | SPEC.md (2,603 lines), GUIDE.md (developer manual), SECURITY.md (vulnerability policy) | Published documentation |
| CC2.2 — External communication | IETF Internet-Draft (draft-sharif-mcps-secure-mcp), OWASP alignment | Public specification |

### CC3: Risk Assessment

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| CC3.1 — Risk identification | OWASP MCP Top 10 alignment (8/10 risks mitigated), red team audit (19 attack categories) | SECURITY-AUDIT.md |
| CC3.2 — Fraud risk | Passport forgery prevention (trust levels L0-L4, self-signed capped at L0), signature verification | test-redteam.js Section 7 |
| CC3.3 — Change management risk | Tool integrity signing detects rug pulls (post-deployment tool mutations) | signTool() + verifyTool() with hash pinning |

### CC5: Control Activities

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| CC5.1 — Logical access controls | Agent passports with ECDSA P-256 identity, trust level gating (L0-L4) | createPassport(), getEffectiveTrustLevel() |
| CC5.2 — Authentication | Per-message ECDSA signatures with nonce + timestamp binding | signMessage(), verifyMessage() |
| CC5.3 — Authorization | Trust level enforcement (minTrustLevel), origin binding (server URI pinning) | secureMCP() middleware, validateOrigin() |

### CC6: Logical and Physical Access Controls

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| CC6.1 — Logical access security | Cryptographic identity (not bearer tokens, not API keys) — agent identity is unforgeable | ECDSA P-256 key pairs per agent |
| CC6.2 — User registration/deregistration | Passport issuance with TTL (default 365 days), revocation via Trust Authority | createPassport(), checkRevocation() |
| CC6.3 — Access modification | Key rotation with previous_key_hash linkage, trust level changes require TA re-issuance | key_rotation field in passport |
| CC6.6 — Restriction of access to system components | Origin binding restricts passport to specific server URI, capabilities capped at 64 | validateOrigin(), MAX_CAPABILITIES |
| CC6.7 — Restriction of information access | Per-message signing ensures only the passport holder can produce valid envelopes | signMessage() + nonce + timestamp |
| CC6.8 — Prevention of unauthorized access | Fail-closed design — unsigned messages rejected, unreachable TA = rejected | secureMCP() middleware |

### CC7: System Operations

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| CC7.1 — Detection of anomalies | onAudit callback emits structured events (accepted/rejected/replay/forgery) for SIEM integration | GUIDE.md Section 7 (Splunk, Datadog, ELK, CloudWatch examples) |
| CC7.2 — Monitoring of system components | Audit log captures: passport_id, method, timestamp, outcome for every message | secureMCP() audit() function |
| CC7.3 — Evaluation of security events | SOC Alert Priority Matrix: replay attacks (P1/Critical), signature failures (P2/High), trust level changes (P3/Medium) | GUIDE.md Section 7 |
| CC7.4 — Incident response | Passport revocation within seconds via Trust Authority, real-time revocation checking | checkRevocation(), onRevoked callback |

### CC8: Change Management

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| CC8.1 — Change authorization | Tool definitions are signed — any change is detected via hash comparison | signTool(), verifyTool(), hash_changed field |

### CC9: Risk Mitigation

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| CC9.1 — Risk mitigation activities | 180 security tests, red team audit against all known CVEs, IETF peer review | test.js, test-redteam.js, SECURITY-AUDIT.md |

---

## Processing Integrity

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| PI1.1 — Completeness and accuracy of processing | Per-message SHA-256 hash of full JSON-RPC body included in signing payload — any modification detected | message_hash in signMessage() |
| PI1.2 — Timely processing | 5-minute timestamp window prevents stale message acceptance | TIMESTAMP_WINDOW_MS, verifyMessage() |
| PI1.3 — Accuracy of processing | RFC 8785 (JCS) canonicalization ensures identical bytes across Node.js and Python implementations | canonicalJSON(), cross-platform test suite |
| PI1.4 — System inputs are complete | Nonce + timestamp + passport_id + message_hash all bound in signature — missing fields = invalid | Signing payload construction |
| PI1.5 — System outputs are complete | Server responses are also signed (mutual authentication) — clients verify server integrity | secureMCP().sign(), secureMCPClient().verify() |

---

## Confidentiality

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| C1.1 — Identification of confidential information | Passport contains only public key (JWK) — private keys never leave the signer (HSM support) | createExternalSigner(), GUIDE.md Section 5 |
| C1.2 — Disposal of confidential information | NonceStore garbage collection, passport TTL expiration, key rotation with previous_key_hash | NonceStore._gc(), isPassportExpired() |

---

## Availability

| Criteria | MCPS Control | Evidence |
|----------|-------------|----------|
| A1.1 — System availability | Zero dependencies = minimal failure surface, fail-closed on TA unreachable (no silent degradation) | package.json (0 deps), secureMCP() |
| A1.2 — Recovery from incidents | Passport revocation + key rotation enables rapid compromise recovery | checkRevocation(), key_rotation |

---

## Summary: SOC 2 Coverage

| Trust Service Category | Criteria Covered | Coverage |
|----------------------|-----------------|----------|
| **Security (CC)** | CC1–CC9 (18 criteria) | Strong |
| **Processing Integrity (PI)** | PI1.1–PI1.5 | Full |
| **Confidentiality (C)** | C1.1–C1.2 | Strong |
| **Availability (A)** | A1.1–A1.2 | Partial |
| **Privacy (P)** | — | N/A (MCPS does not process PII) |

### What This Means for Auditors

When a SOC 2 auditor asks "how do you verify the identity of agents accessing your system?", the answer is not "we check an API key" — it's:

> Every agent holds an ECDSA P-256 cryptographic passport issued by a Trust Authority. Every message is signed with a unique nonce and timestamp. Every tool definition is hash-pinned and signature-verified. Replay attacks are blocked. Compromised agents are revoked in real-time. All events are emitted to our SIEM with structured audit entries.

That's a fundamentally different conversation.

---

## Certification Roadmap

| Milestone | Target | Status |
|-----------|--------|--------|
| Security policy (SECURITY.md) | Q1 2026 | Complete |
| Vulnerability disclosure process | Q1 2026 | Complete |
| Red team security audit (internal) | Q1 2026 | Complete (180 tests, 0 critical) |
| SOC 2 Type I readiness assessment | Q2 2026 | Planned |
| Third-party penetration test | Q2 2026 | Planned |
| SOC 2 Type II certification | Q3 2026 | Planned |

---

*CyberSecAI Ltd — Patent GB2604808.2 — contact@agentsign.dev*
