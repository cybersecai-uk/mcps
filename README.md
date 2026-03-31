# MCPS -- MCP Secure

**The HTTPS of the agent era.** Cryptographic identity, message signing, and trust verification for the [Model Context Protocol](https://modelcontextprotocol.io).

[![npm](https://img.shields.io/npm/v/mcp-secure?color=059669&label=npm)](https://www.npmjs.com/package/mcp-secure)
[![PyPI](https://img.shields.io/pypi/v/mcp-secure?color=059669&label=pypi)](https://pypi.org/project/mcp-secure/)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--sharif--mcps--00-blue)](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/)
[![Tests](https://img.shields.io/badge/tests-78%20passed-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()
[![Zero Dependencies](https://img.shields.io/badge/node--deps-0-brightgreen)]()

### [Try it live in your browser -- no install needed](https://agentsign.dev/playground)

Generate keys, create passports, sign messages, verify signatures, and test tamper detection -- all client-side using Web Crypto API.

---

## The Problem

MCP has **no identity layer**. Any agent can call any tool. No signatures. No revocation. No tamper detection.

Real CVEs exist (CVSS 9.6). OWASP created an [entire Top 10](https://owasp.org/www-project-mcp-top-10/) for MCP risks. 82% of MCP servers have path traversal vulnerabilities.

**MCP is HTTP. MCPS is HTTPS.**

---

## How It Works

```
Agent                          MCP Server
  |                                |
  |-- 1. Generate ECDSA keys ----> |
  |-- 2. Create passport --------> |
  |                                |
  |== Signed JSON-RPC envelope ===>|
  |   {                            |
  |     mcps: {                    |
  |       version: "1.0",          |  3. Verify signature
  |       passport_id: "asp_...",  |  4. Check passport not revoked
  |       nonce: "abc123",         |  5. Reject if replayed
  |       timestamp: "2026-...",   |  6. Check trust level >= min
  |       signature: "base64..."   |
  |     },                         |
  |     jsonrpc: "2.0",            |
  |     method: "tools/call",      |
  |     params: { ... }            |
  |   }                            |
  |                                |
  |<====== Signed response ========|
```

Every message is wrapped in a signed envelope. Tamper any field -- the signature breaks. Replay a message -- the nonce is rejected. Revoke an agent -- instant cutoff.

---

## Try It in 30 Seconds

```bash
npm install mcp-secure
```

```javascript
const mcps = require('mcp-secure');

// 1. Generate keys (ECDSA P-256)
const keys = mcps.generateKeyPair();

// 2. Create a passport for your agent
const passport = mcps.createPassport({
  name: 'my-agent',
  version: '1.0.0',
  publicKey: keys.publicKey,
});

// 3. Sign an MCP message
const envelope = mcps.signMessage(
  { jsonrpc: '2.0', method: 'tools/call', params: { name: 'read_file' } },
  passport.passport_id,
  keys.privateKey
);

// 4. Verify on the receiving end
const result = mcps.verifyMessage(envelope, keys.publicKey);
console.log(result.valid); // true

// 5. Tamper detection -- change anything, signature breaks
envelope.params.name = 'delete_everything';
const tampered = mcps.verifyMessage(envelope, keys.publicKey);
console.log(tampered.valid); // false
```

**Python:**

```bash
pip install mcp-secure
```

```python
from mcp_secure import generate_key_pair, create_passport, sign_message, verify_message

keys = generate_key_pair()
passport = create_passport(name="my-agent", version="1.0.0", public_key=keys["public_key"])
envelope = sign_message({"jsonrpc": "2.0", "method": "tools/call"}, passport["passport_id"], keys["private_key"])
result = verify_message(envelope, keys["public_key"])
assert result["valid"] is True
```

**Interactive playground:** [agentsign.dev/playground](https://agentsign.dev/playground) -- try it in the browser, no install needed.

---

## Wrap Any MCP Server (2 Lines)

```javascript
const { secureMCP } = require('mcp-secure');

const server = secureMCP(myMCPServer, {
  passport: 'asp_abc123',
  privateKey: process.env.MCPS_PRIVATE_KEY,
  trustAuthority: 'https://agentsign.dev',
  minTrustLevel: 2,
});
```

Every incoming MCP call is now verified: passport checked, signature validated, replay blocked, audit logged.

---

## What MCPS Adds

| Feature | What It Does |
|---------|-------------|
| **Agent Passports** | ECDSA P-256 signed identity credentials -- agents carry proof of who they are |
| **Message Signing** | Every JSON-RPC message wrapped in a signed envelope with nonce + timestamp |
| **Tool Integrity** | Signed tool definitions prevent poisoning and rug pulls |
| **Model Integrity** | Signed model metadata prevents tampering, backdoors, and version swaps |
| **Transcript Binding** | Anti-downgrade binding -- cryptographically binds handshake parameters to prevent capability stripping |
| **Replay Protection** | Nonce + 5-minute timestamp window blocks replay attacks |
| **Revocation** | Real-time passport revocation via Trust Authority |
| **Trust Levels** | L0 (unsigned) through L4 (audited) -- progressive security |
| **Version Negotiation** | Client and server agree on protocol version at handshake |
| **Issuer Chains** | Delegated trust -- Trust Authority signs a passport, that passport signs sub-agents |

---

## Trust Levels

```
L0  Unsigned     Plain MCP, no MCPS
L1  Identified   Passport presented
L2  Verified     Passport verified + not revoked
L3  Scanned      Verified + passed OWASP security scan
L4  Audited      Scanned + manual audit by Trust Authority
```

Use `minTrustLevel` to set the floor. An L2 server rejects L0/L1 agents. An L4 server only accepts fully audited agents.

---

## Tool Integrity (Prevents Tool Poisoning)

```javascript
// Author signs their tool definition
const sig = mcps.signTool(myTool, authorPrivateKey);

// Client verifies before calling -- detects tampering
const safe = mcps.verifyTool(myTool, sig, authorPublicKey);
// If someone changed the tool description (tool poisoning), this returns false
```

Tool poisoning is MCP03 in the OWASP Top 10. This is the fix.

---

## Model Integrity (Prevents Backdoored Models)

```javascript
const fs = require('fs');

// Hash the model file (streams -- won't load 8GB into memory)
const fileHash = await mcps.hashModelFile('./llama-3-8b.safetensors');

// Sign the model metadata
const sig = mcps.signModel({
  name: 'llama-3-8b',
  version: '1.0.0',
  format: 'safetensors',
  fileHash,
  source: 'https://huggingface.co/meta-llama/Llama-3-8B',
  license: 'llama3',
  parameterCount: 8000000000,
}, privateKey, 'meta-llama');

// Consumer verifies before loading -- detects tampering
const result = mcps.verifyModel(
  { name: 'llama-3-8b', version: '1.0.0', format: 'safetensors', fileHash },
  sig.signature, publisherPublicKey, sig.model_hash, 'meta-llama'
);
// result.valid === true (model is authentic)
// result.hash_changed === false (matches pinned hash)
```

Model supply chain attacks are real -- poisoned weights on Hugging Face, backdoored fine-tunes, version swaps. `signModel` makes model files signed artifacts with cryptographic provenance.

---

## Transcript Binding (Anti-Downgrade)

```javascript
// Both sides sign the agreed security parameters after handshake
const binding = mcps.createTranscriptBinding(clientInitParams, serverInitResult, keys.privateKey);

// Verify the other party's binding -- detects capability stripping attacks
const result = mcps.verifyTranscriptBinding(
  binding.transcript_hash, binding.transcript_signature,
  keys.publicKey, clientInitParams, serverInitResult
);
console.log(result.valid); // true
```

---

## OWASP MCP Top 10 Coverage

MCPS mitigates 8 of 10 OWASP MCP risks:

| OWASP Risk | MCPS Mitigation |
|-----------|-----------------|
| MCP01: Token Mismanagement | Passport-based identity replaces long-lived tokens |
| MCP03: Tool Poisoning | Tool integrity signatures |
| MCP04: Supply Chain | Signed tool definitions + scan results in passport |
| MCP06: Intent Flow Subversion | Signed messages prevent manipulation |
| MCP07: Insufficient Auth | Passport verification on every connection |
| MCP08: Lack of Audit | Signed audit trail with every call |
| MCP09: Shadow Servers | Only passported agents accepted |
| MCP10: Context Injection | Envelope isolation prevents cross-session leakage |

---

## Error Codes

| Code | Meaning |
|------|---------|
| MCPS-001 | Invalid passport format |
| MCPS-002 | Passport expired |
| MCPS-003 | Passport revoked |
| MCPS-004 | Invalid message signature |
| MCPS-005 | Replay attack detected |
| MCPS-006 | Timestamp out of window |
| MCPS-007 | Trust authority unreachable |
| MCPS-008 | Tool signature mismatch |
| MCPS-009 | Insufficient trust level |
| MCPS-010 | Rate limit exceeded |
| MCPS-011 | Origin mismatch |
| MCPS-012 | Transcript binding verification failed |
| MCPS-013 | Passport exceeds maximum size |
| MCPS-014 | Issuer chain exceeds maximum depth |
| MCPS-015 | No mutually supported MCPS version |

---

## Technical Details

- **Signing**: ECDSA P-256 (NIST FIPS 186-5)
- **Signature format**: IEEE P1363 fixed-length r||s (RFC 7518 Section 3.4)
- **Low-S normalization**: BIP-0062 signature malleability prevention
- **Canonicalization**: RFC 8785 JSON Canonicalization Scheme
- **Nonce**: 16 bytes cryptographic random (128-bit)
- **Timestamp window**: 5 minutes (configurable)
- **Passport format**: `asp_` prefix + 32 hex chars
- **Node.js**: Zero dependencies (pure `crypto` built-in)
- **Python**: Single dependency (`cryptography`)
- **75 tests**: Covering all cryptographic operations, edge cases, and attack vectors

---

## Specification

- **IETF Internet-Draft**: [draft-sharif-mcps-secure-mcp-00](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/) (2,405 lines)
- **SEP-2395**: [Full specification](./SPEC.md) -- submitted to MCP specification repo
- **Playground**: [agentsign.dev/playground](https://agentsign.dev/playground)

---

## On-Premise

Run your own Trust Authority. Nothing phones home.

```bash
docker run -p 8080:8080 agentsign/server
```

---

## License

MIT. Patent pending (GB2604808.2).

Built by [CyberSecAI Ltd](https://agentsign.dev).
