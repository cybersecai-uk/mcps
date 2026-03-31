# MCPS Developer Guide

Practical guide for developers integrating MCPS into MCP servers and clients. Code-first, no fluff.

---

## Table of Contents

1. [Install & First Sign](#1-install--first-sign)
2. [Wrap an Existing MCP Server](#2-wrap-an-existing-mcp-server)
3. [Protect Tools from Poisoning](#3-protect-tools-from-poisoning)
4. [Trust Levels — Gate Access](#4-trust-levels--gate-access)
5. [HSM / KMS Integration](#5-hsm--kms-integration)
6. [Backup & Restore Passports](#6-backup--restore-passports)
7. [Logging, Monitoring & SOC Alerts](#7-logging-monitoring--soc-alerts)
8. [Key Rotation](#8-key-rotation)
9. [Multi-Tenant Isolation](#9-multi-tenant-isolation)
10. [Gotchas & Common Mistakes](#10-gotchas--common-mistakes)
11. [FAQ](#11-faq)

---

## 1. Install & First Sign

```bash
npm install mcp-secure
```

```javascript
const mcps = require('mcp-secure');

// Generate ECDSA P-256 key pair
const keys = mcps.generateKeyPair();

// Create a passport (agent identity)
const passport = mcps.createPassport({
  name: 'my-agent',
  version: '1.0.0',
  publicKey: keys.publicKey,
});

// Sign any MCP message
const envelope = mcps.signMessage(
  { jsonrpc: '2.0', method: 'tools/list', id: 1 },
  passport.passport_id,
  keys.privateKey
);

// Verify on the other end
const result = mcps.verifyMessage(envelope, keys.publicKey);
console.log(result.valid); // true
```

**What just happened:**
- `generateKeyPair()` → ECDSA P-256 key pair (PEM format)
- `createPassport()` → agent identity document with public key, name, expiry
- `signMessage()` → wraps your MCP JSON-RPC message in a signed envelope with nonce + timestamp
- `verifyMessage()` → checks signature, timestamp window (5 min), returns `{ valid: true/false }`

---

## 2. Wrap an Existing MCP Server

You already have an MCP server? Three lines:

```javascript
const { secureMCP } = require('mcp-secure');

const secure = secureMCP(myMCPServer, {
  passport: passport.passport_id,
  privateKey: keys.privateKey,
  minTrustLevel: 2,          // reject L0/L1 agents
  auditLog: true,            // emit audit events
  onAudit: (entry) => {      // your hook — pipe to SIEM, log, whatever
    console.log(JSON.stringify(entry));
  },
});

// Every incoming message is now:
// 1. Checked for MCPS envelope (dropped if missing)
// 2. Nonce checked (replay rejected)
// 3. Passport resolved + revocation checked
// 4. Trust level verified (below min = rejected)
// 5. Signature verified (tampered = rejected)
// 6. Audit event emitted
// 7. Forwarded to your MCP server
```

**Phase rollout (for existing deployments):**

```javascript
// Phase 1: Observe (log but don't block)
const secure = secureMCP(myMCPServer, {
  passport: passportId,
  privateKey,
  minTrustLevel: 0,     // accept everything
  onAudit: (e) => logger.info(e),
});

// Phase 2: Sign (require signatures, accept L0+)
const secure = secureMCP(myMCPServer, {
  passport: passportId,
  privateKey,
  minTrustLevel: 0,
  onAudit: (e) => logger.info(e),
});

// Phase 3: Enforce (require verified passports)
const secure = secureMCP(myMCPServer, {
  passport: passportId,
  privateKey,
  minTrustLevel: 2,     // only verified agents
  onAudit: (e) => siem.send(e),
});
```

---

## 3. Protect Tools from Poisoning

Tool poisoning = attacker modifies a tool description to inject malicious instructions. OWASP MCP03.

```javascript
// Server: sign your tools at startup
const tool = {
  name: 'get_weather',
  description: 'Get weather for a city',
  inputSchema: { type: 'object', properties: { city: { type: 'string' } } },
};

const { signature, tool_hash } = mcps.signTool(tool, keys.privateKey);
// Store signature + tool_hash alongside the tool definition

// Client: verify before calling
const check = mcps.verifyTool(tool, signature, serverPublicKey, tool_hash);
if (!check.valid || check.hash_changed) {
  throw new Error('Tool tampered — do not call');
}
```

**Pin the hash.** Store `tool_hash` from the first verification. On subsequent checks, pass it as `pinnedHash` — if the hash changes, someone modified the tool.

---

## 4. Trust Levels — Gate Access

```
L0  UNSIGNED     No passport, plain MCP
L1  IDENTIFIED   Passport presented (self-signed)
L2  VERIFIED     Passport signed by a Trust Authority
L3  SCANNED      Verified + passed SDLC security scan
L4  AUDITED      Scanned + manual security audit
```

```javascript
// Check an agent's effective trust level
const level = mcps.getEffectiveTrustLevel(passport, ['agentsign.dev']);
// Returns 0 for self-signed, regardless of what trust_level claims

// Gate access in secureMCP
const secure = secureMCP(myMCPServer, {
  minTrustLevel: 2,  // only L2+ agents can connect
  trustedIssuers: ['agentsign.dev', 'your-internal-ta.com'],
});
```

**Key rule:** Self-signed passports are ALWAYS L0. An agent can claim L4 in its passport — `getEffectiveTrustLevel()` will cap it at L0 if it's self-signed. You can't fake trust.

---

## 5. HSM / KMS Integration

*Added in v1.0.3.* Private keys stay in hardware — never touch Node.js memory.

### AWS KMS

```bash
npm install @aws-sdk/client-kms
```

```javascript
const { KMSClient, SignCommand } = require('@aws-sdk/client-kms');
const mcps = require('mcp-secure');

const kms = new KMSClient({ region: 'eu-west-2' });

// Create a signer that calls AWS KMS
const signer = mcps.createExternalSigner(async (data) => {
  const cmd = new SignCommand({
    KeyId: 'arn:aws:kms:eu-west-2:123456789:key/your-key-id',
    Message: data,
    MessageType: 'RAW',                // MCPS passes raw data, KMS hashes it
    SigningAlgorithm: 'ECDSA_SHA_256',  // must be P-256
  });
  const res = await kms.send(cmd);
  return mcps.derToP1363(Buffer.from(res.Signature));  // AWS returns DER
});

// Use it everywhere you'd pass a private key
const envelope = await mcps.signMessage(msg, passportId, signer);
const signedPassport = await mcps.signPassport(passport, signer);
const toolSig = await mcps.signTool(tool, signer);
```

**AWS KMS setup:**
1. Create a key: `aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY`
2. Note the KeyId ARN
3. Export the public key: `aws kms get-public-key --key-id <arn>` → use for passport creation
4. IAM: grant `kms:Sign` permission to your server's role

### Azure Key Vault

```bash
npm install @azure/keyvault-keys @azure/identity
```

```javascript
const { CryptographyClient } = require('@azure/keyvault-keys');
const { DefaultAzureCredential } = require('@azure/identity');
const crypto = require('crypto');
const mcps = require('mcp-secure');

const credential = new DefaultAzureCredential();
const client = new CryptographyClient(
  'https://your-vault.vault.azure.net/keys/mcps-signing-key/version',
  credential
);

// Azure expects pre-hashed input
const signer = mcps.createExternalSigner(async (data) => {
  const digest = crypto.createHash('sha256').update(data).digest();
  const result = await client.sign('ES256', digest);
  return result.result;  // Azure returns P1363 natively — no conversion needed
}, { prehash: false });

const envelope = await mcps.signMessage(msg, passportId, signer);
```

**Azure setup:**
1. Create Key Vault: `az keyvault create --name your-vault`
2. Create key: `az keyvault key create --vault-name your-vault --name mcps-signing-key --kty EC --curve P-256`
3. Export public key: `az keyvault key show --vault-name your-vault --name mcps-signing-key`
4. RBAC: assign `Key Vault Crypto User` role to your app identity

### GCP Cloud KMS

```bash
npm install @google-cloud/kms
```

```javascript
const { KeyManagementServiceClient } = require('@google-cloud/kms');
const crypto = require('crypto');
const mcps = require('mcp-secure');

const kms = new KeyManagementServiceClient();
const keyName = 'projects/my-project/locations/global/keyRings/mcps/cryptoKeys/agent-key/cryptoKeyVersions/1';

const signer = mcps.createExternalSigner(async (data) => {
  const digest = crypto.createHash('sha256').update(data).digest();
  const [result] = await kms.asymmetricSign({
    name: keyName,
    digest: { sha256: digest },
  });
  return mcps.derToP1363(Buffer.from(result.signature, 'base64'));  // GCP returns DER
}, { prehash: false });

const envelope = await mcps.signMessage(msg, passportId, signer);
```

**GCP setup:**
1. Create key ring: `gcloud kms keyrings create mcps --location global`
2. Create key: `gcloud kms keys create agent-key --keyring mcps --location global --purpose asymmetric-signing --default-algorithm ec-sign-p256-sha256`
3. Export public key: `gcloud kms keys versions get-public-key 1 --key agent-key --keyring mcps --location global`
4. IAM: grant `roles/cloudkms.signerVerifier` to your service account

### PKCS#11 (Thales Luna, nShield, YubiKey)

```bash
npm install pkcs11js
```

```javascript
const pkcs11 = require('pkcs11js');
const mcps = require('mcp-secure');

const lib = new pkcs11.PKCS11();
lib.load('/usr/lib/softhsm/libsofthsm2.so');  // or vendor .so/.dylib path
lib.C_Initialize();

const slots = lib.C_GetSlotList(true);
const session = lib.C_OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION);
lib.C_Login(session, pkcs11.CKU_USER, 'your-pin');

// Find your EC private key by label
lib.C_FindObjectsInit(session, [
  { type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY },
  { type: pkcs11.CKA_LABEL, value: 'mcps-agent-key' },
]);
const keyHandle = lib.C_FindObjects(session, 1)[0];
lib.C_FindObjectsFinal(session);

const signer = mcps.createExternalSigner(async (data) => {
  lib.C_SignInit(session, { mechanism: pkcs11.CKM_ECDSA_SHA256 }, keyHandle);
  const sig = lib.C_Sign(session, data, Buffer.alloc(64));
  return sig;  // PKCS#11 CKM_ECDSA returns P1363 natively
});

const envelope = await mcps.signMessage(msg, passportId, signer);
```

### Quick Reference: Which Format Does My HSM Return?

| Provider | Signature Format | Conversion Needed? |
|----------|-----------------|-------------------|
| AWS KMS | DER (ASN.1) | Yes → `mcps.derToP1363()` |
| Azure Key Vault | P1363 (r‖s) | No |
| GCP Cloud KMS | DER (ASN.1) | Yes → `mcps.derToP1363()` |
| PKCS#11 (CKM_ECDSA) | P1363 (r‖s) | No |
| PKCS#11 (CKM_ECDSA_SHA256) | P1363 (r‖s) | No |
| Node.js crypto | Both (configurable) | No (MCPS uses P1363) |

---

## 6. Backup & Restore Passports

A passport is just a JSON object. Back it up like any config.

### What to Back Up

```javascript
// These are the critical items:
const backup = {
  passport: passport,           // the full passport object (JSON)
  privateKey: keys.privateKey,  // PEM string — ENCRYPT THIS
  publicKey: keys.publicKey,    // PEM string — safe to store plaintext
};
```

### Encrypted Backup to File

```javascript
const crypto = require('crypto');
const fs = require('fs');

function backupPassport(passport, privateKey, encryptionPassword) {
  const data = JSON.stringify({ passport, privateKey });
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(encryptionPassword, salt, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  fs.writeFileSync('mcps-backup.enc', JSON.stringify({
    salt: salt.toString('hex'),
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex'),
  }));
}

function restorePassport(encryptionPassword) {
  const file = JSON.parse(fs.readFileSync('mcps-backup.enc', 'utf8'));
  const key = crypto.scryptSync(encryptionPassword, Buffer.from(file.salt, 'hex'), 32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(file.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(file.tag, 'hex'));
  const decrypted = decipher.update(file.data, 'hex', 'utf8') + decipher.final('utf8');
  return JSON.parse(decrypted);
}

// Backup
backupPassport(passport, keys.privateKey, process.env.BACKUP_PASSWORD);

// Restore
const { passport, privateKey } = restorePassport(process.env.BACKUP_PASSWORD);
```

### HSM Users: No Private Key to Back Up

If your private key is in an HSM, you only back up the passport JSON. The HSM manages key durability. Your backup is:

```javascript
fs.writeFileSync('passport.json', JSON.stringify(passport, null, 2));
```

The HSM provider handles key backup/replication:
- **AWS KMS**: Multi-region keys (`aws kms replicate-key`)
- **Azure Key Vault**: Backup/restore (`az keyvault key backup`)
- **GCP Cloud KMS**: Keys are automatically replicated within the region

### Environment Variables (Simplest for CI/CD)

```bash
# In your .env or secrets manager
MCPS_PASSPORT_ID=asp_abc123def456
MCPS_PRIVATE_KEY="-----BEGIN EC PRIVATE KEY-----\nMHQC..."
MCPS_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMFkw..."
```

```javascript
const secure = secureMCP(myMCPServer, {
  passport: process.env.MCPS_PASSPORT_ID,
  privateKey: process.env.MCPS_PRIVATE_KEY,
  minTrustLevel: 2,
});
```

---

## 7. Logging, Monitoring & SOC Alerts

MCPS doesn't build in a SIEM. It emits structured events via `onAudit`. You pipe them wherever you want. This is intentional — less code, smaller attack surface, every enterprise has different tools.

### The onAudit Event

Every accepted or rejected message fires `onAudit`:

```javascript
// Accepted event:
{
  "timestamp": "2026-03-16T10:30:00.000Z",
  "event": "accepted",
  "passport_id": "asp_abc123...",
  "method": "tools/call",
  "id": 1
}

// Rejected event:
{
  "timestamp": "2026-03-16T10:30:01.000Z",
  "event": "rejected",
  "reason": "replay_attack",        // or: invalid_signature, insufficient_trust,
  "passport_id": "asp_abc123..."    //     revoked, authority_unreachable, origin_mismatch
}
```

### Complete SIEM Integration Examples

Each example below is a **full, working integration** — copy-paste into your project.

---

#### Splunk (HTTP Event Collector)

```bash
npm install mcp-secure
# No extra deps — uses built-in https
```

```javascript
// splunk-mcps-server.js — Full working example
const express = require('express');
const https = require('https');
const mcps = require('mcp-secure');

// ── Splunk HEC Config ──
const SPLUNK_HOST = process.env.SPLUNK_HOST || 'splunk.yourcompany.com';
const SPLUNK_HEC_TOKEN = process.env.SPLUNK_HEC_TOKEN;
const SPLUNK_INDEX = process.env.SPLUNK_INDEX || 'mcps_audit';

function sendToSplunk(entry) {
  const payload = JSON.stringify({
    time: Date.now() / 1000,
    host: 'mcps-server',
    source: 'mcps:audit',
    sourcetype: '_json',
    index: SPLUNK_INDEX,
    event: entry,
  });

  const req = https.request({
    hostname: SPLUNK_HOST,
    port: 8088,
    path: '/services/collector/event',
    method: 'POST',
    headers: {
      'Authorization': `Splunk ${SPLUNK_HEC_TOKEN}`,
      'Content-Type': 'application/json',
    },
    rejectUnauthorized: true,
  }, (res) => {
    if (res.statusCode !== 200) {
      console.error(`Splunk HEC error: ${res.statusCode}`);
    }
  });

  req.on('error', (err) => console.error('Splunk HEC send failed:', err.message));
  req.write(payload);
  req.end();
}

// ── MCPS Server with Splunk ──
const keys = mcps.generateKeyPair();
const passport = mcps.createPassport({
  publicKey: keys.publicKey,
  name: 'my-mcp-server',
  version: '1.0.0',
});

const app = express();
app.use(express.json());

const secure = mcps.secureMCP(null, {
  passport: passport.passport_id,
  privateKey: keys.privateKey,
  minTrustLevel: 2,
  auditLog: true,
  onAudit: (entry) => {
    // 1. Always log to stdout (backup)
    console.log(JSON.stringify({ level: 'info', type: 'mcps_audit', ...entry }));

    // 2. Send to Splunk HEC
    sendToSplunk(entry);
  },
});

// Your MCP endpoint
app.post('/mcp', async (req, res) => {
  const result = await secure.handleMessage(req.body);
  res.json(result);
});

app.listen(3000, () => console.log('MCPS server with Splunk audit on :3000'));
```

**Splunk setup:**
1. Settings → Data Inputs → HTTP Event Collector → New Token
2. Set `sourcetype` to `_json`, index to `mcps_audit`
3. Save the token → set as `SPLUNK_HEC_TOKEN` env var
4. Create a Splunk alert: `index=mcps_audit event="rejected" reason="replay_attack"` → trigger PagerDuty

**Splunk search queries for your SOC dashboard:**
```
# All rejected events (last 24h)
index=mcps_audit event="rejected" earliest=-24h | stats count by reason

# Replay attacks
index=mcps_audit reason="replay_attack" | table _time passport_id

# Unique agents connecting
index=mcps_audit event="accepted" | stats dc(passport_id) as unique_agents

# Rejection rate (alert if > 10%)
index=mcps_audit | stats count(eval(event="rejected")) as rejected, count as total
  | eval rate=round(rejected/total*100,2) | where rate > 10
```

---

#### Datadog

```bash
npm install mcp-secure dd-trace datadog-metrics
```

```javascript
// datadog-mcps-server.js — Full working example
const tracer = require('dd-trace').init({
  service: 'mcps-server',
  env: process.env.DD_ENV || 'production',
});
const { StatsD } = require('datadog-metrics');
const mcps = require('mcp-secure');
const express = require('express');

// ── Datadog Metrics ──
const metrics = new StatsD({
  host: process.env.DD_AGENT_HOST || 'localhost',
  prefix: 'mcps.',
});

// ── MCPS Server with Datadog ──
const keys = mcps.generateKeyPair();
const passport = mcps.createPassport({
  publicKey: keys.publicKey,
  name: 'my-mcp-server',
  version: '1.0.0',
});

const app = express();
app.use(express.json());

const secure = mcps.secureMCP(null, {
  passport: passport.passport_id,
  privateKey: keys.privateKey,
  minTrustLevel: 2,
  auditLog: true,
  onAudit: (entry) => {
    // 1. Structured log (dd-trace auto-sends to Datadog Logs)
    console.log(JSON.stringify({
      level: entry.event === 'rejected' ? 'warn' : 'info',
      message: `mcps:${entry.event}`,
      dd: {
        service: 'mcps-server',
        passport_id: entry.passport_id,
        event: entry.event,
        reason: entry.reason || null,
        method: entry.method || null,
      },
    }));

    // 2. Custom metrics
    if (entry.event === 'accepted') {
      metrics.increment('messages.accepted');
    }
    if (entry.event === 'rejected') {
      metrics.increment('messages.rejected', { reason: entry.reason });
    }

    // 3. APM custom span for rejected events
    if (entry.event === 'rejected') {
      const span = tracer.startSpan('mcps.security_event', {
        tags: {
          'mcps.event': entry.event,
          'mcps.reason': entry.reason,
          'mcps.passport_id': entry.passport_id,
          'mcps.severity': ['replay_attack', 'invalid_signature', 'revoked'].includes(entry.reason)
            ? 'critical' : 'warning',
        },
      });
      span.finish();
    }
  },
});

app.post('/mcp', async (req, res) => {
  const result = await secure.handleMessage(req.body);
  res.json(result);
});

app.listen(3000, () => console.log('MCPS server with Datadog on :3000'));
```

**Datadog setup:**
1. Install Datadog Agent on your host
2. Enable Log Collection in `datadog.yaml`: `logs_enabled: true`
3. Create a Monitor: `mcps.messages.rejected` → alert if > 5 in 5 min
4. Create a Dashboard with `mcps.messages.accepted` vs `mcps.messages.rejected`

---

#### AWS CloudWatch + SNS Alerts

```bash
npm install mcp-secure @aws-sdk/client-cloudwatch-logs @aws-sdk/client-sns
```

```javascript
// cloudwatch-mcps-server.js — Full working example
const { CloudWatchLogsClient, PutLogEventsCommand,
        CreateLogGroupCommand, CreateLogStreamCommand } = require('@aws-sdk/client-cloudwatch-logs');
const { SNSClient, PublishCommand } = require('@aws-sdk/client-sns');
const mcps = require('mcp-secure');
const express = require('express');

const REGION = process.env.AWS_REGION || 'eu-west-2';
const LOG_GROUP = '/mcps/audit';
const LOG_STREAM = `agent-traffic-${Date.now()}`;
const SNS_TOPIC_ARN = process.env.MCPS_SNS_TOPIC;  // for critical alerts

const cwLogs = new CloudWatchLogsClient({ region: REGION });
const sns = new SNSClient({ region: REGION });

// Buffer logs to avoid per-event API calls
let logBuffer = [];
let sequenceToken = null;

async function initCloudWatch() {
  try {
    await cwLogs.send(new CreateLogGroupCommand({ logGroupName: LOG_GROUP }));
  } catch (e) { /* already exists */ }
  try {
    await cwLogs.send(new CreateLogStreamCommand({ logGroupName: LOG_GROUP, logStreamName: LOG_STREAM }));
  } catch (e) { /* already exists */ }
}

async function flushLogs() {
  if (logBuffer.length === 0) return;
  const events = logBuffer.splice(0, logBuffer.length);
  try {
    const cmd = new PutLogEventsCommand({
      logGroupName: LOG_GROUP,
      logStreamName: LOG_STREAM,
      logEvents: events,
      sequenceToken,
    });
    const res = await cwLogs.send(cmd);
    sequenceToken = res.nextSequenceToken;
  } catch (err) {
    console.error('CloudWatch flush failed:', err.message);
  }
}

// Flush every 5 seconds (batch writes)
setInterval(flushLogs, 5000);

async function alertSOC(entry) {
  if (!SNS_TOPIC_ARN) return;
  const severity = ['replay_attack', 'invalid_signature', 'revoked'].includes(entry.reason)
    ? 'CRITICAL' : 'WARNING';

  await sns.send(new PublishCommand({
    TopicArn: SNS_TOPIC_ARN,
    Subject: `[${severity}] MCPS Security Alert: ${entry.reason}`,
    Message: JSON.stringify({
      severity,
      event: entry.event,
      reason: entry.reason,
      passport_id: entry.passport_id,
      timestamp: entry.timestamp,
      action_required: severity === 'CRITICAL'
        ? 'Investigate immediately — possible active attack'
        : 'Review in next SOC shift',
    }, null, 2),
  }));
}

// ── MCPS Server with CloudWatch ──
const keys = mcps.generateKeyPair();
const passport = mcps.createPassport({
  publicKey: keys.publicKey,
  name: 'my-mcp-server',
  version: '1.0.0',
});

const app = express();
app.use(express.json());

initCloudWatch().then(() => {
  const secure = mcps.secureMCP(null, {
    passport: passport.passport_id,
    privateKey: keys.privateKey,
    minTrustLevel: 2,
    auditLog: true,
    onAudit: (entry) => {
      // 1. Buffer for CloudWatch Logs
      logBuffer.push({
        timestamp: Date.now(),
        message: JSON.stringify(entry),
      });

      // 2. Alert SOC on critical events via SNS → email/Slack/PagerDuty
      if (entry.event === 'rejected') {
        alertSOC(entry).catch(err => console.error('SNS alert failed:', err.message));
      }
    },
  });

  app.post('/mcp', async (req, res) => {
    const result = await secure.handleMessage(req.body);
    res.json(result);
  });

  app.listen(3000, () => console.log('MCPS server with CloudWatch + SNS on :3000'));
});
```

**AWS setup:**
1. Create SNS topic: `aws sns create-topic --name mcps-security-alerts`
2. Subscribe your SOC email: `aws sns subscribe --topic-arn <arn> --protocol email --notification-endpoint soc@company.com`
3. IAM role needs: `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`, `sns:Publish`
4. Create CloudWatch Alarm: Metric filter on `reason="replay_attack"` → alarm → SNS topic

**CloudWatch Insights queries:**
```
# Rejection breakdown (last 24h)
fields @timestamp, event, reason, passport_id
| filter event = "rejected"
| stats count(*) by reason

# Suspicious passport IDs (multiple rejections)
fields passport_id, reason
| filter event = "rejected"
| stats count(*) as attempts by passport_id
| sort attempts desc
| limit 10
```

---

#### Elasticsearch / ELK Stack

```bash
npm install mcp-secure @elastic/elasticsearch
```

```javascript
// elk-mcps-server.js — Full working example
const { Client } = require('@elastic/elasticsearch');
const mcps = require('mcp-secure');
const express = require('express');

const elastic = new Client({
  node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
  auth: {
    username: process.env.ELASTIC_USER || 'elastic',
    password: process.env.ELASTIC_PASSWORD,
  },
});

const INDEX = 'mcps-audit';

// Create index with proper mappings on startup
async function initIndex() {
  const exists = await elastic.indices.exists({ index: INDEX });
  if (!exists) {
    await elastic.indices.create({
      index: INDEX,
      body: {
        mappings: {
          properties: {
            timestamp: { type: 'date' },
            event: { type: 'keyword' },
            reason: { type: 'keyword' },
            passport_id: { type: 'keyword' },
            method: { type: 'keyword' },
            severity: { type: 'keyword' },
          },
        },
      },
    });
  }
}

// ── MCPS Server with Elasticsearch ──
const keys = mcps.generateKeyPair();
const passport = mcps.createPassport({
  publicKey: keys.publicKey,
  name: 'my-mcp-server',
  version: '1.0.0',
});

const app = express();
app.use(express.json());

initIndex().then(() => {
  const secure = mcps.secureMCP(null, {
    passport: passport.passport_id,
    privateKey: keys.privateKey,
    minTrustLevel: 2,
    auditLog: true,
    onAudit: async (entry) => {
      // Enrich with severity
      let severity = 'info';
      if (entry.event === 'rejected') {
        severity = ['replay_attack', 'invalid_signature', 'revoked'].includes(entry.reason)
          ? 'critical' : 'warning';
      }

      // Index to Elasticsearch
      await elastic.index({
        index: INDEX,
        body: {
          ...entry,
          severity,
          '@timestamp': entry.timestamp,
        },
      }).catch(err => console.error('ES index failed:', err.message));
    },
  });

  app.post('/mcp', async (req, res) => {
    const result = await secure.handleMessage(req.body);
    res.json(result);
  });

  app.listen(3000, () => console.log('MCPS server with Elasticsearch on :3000'));
});
```

**Kibana setup:**
1. Create index pattern: `mcps-audit*`
2. Build dashboard: pie chart of `event` (accepted vs rejected), bar chart of `reason`
3. Create Watcher alert: `reason:"replay_attack" OR reason:"invalid_signature"` → email SOC

---

#### Webhook (Slack, Teams, PagerDuty, any URL)

```bash
npm install mcp-secure
# No extra deps — uses built-in https
```

```javascript
// webhook-mcps-server.js — Send alerts to Slack, Teams, or any webhook
const https = require('https');
const mcps = require('mcp-secure');
const express = require('express');

const SLACK_WEBHOOK = process.env.SLACK_WEBHOOK_URL;
const PAGERDUTY_KEY = process.env.PAGERDUTY_ROUTING_KEY;

function postWebhook(url, payload) {
  const parsed = new URL(url);
  const req = https.request({
    hostname: parsed.hostname,
    port: 443,
    path: parsed.pathname,
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  req.on('error', (err) => console.error('Webhook failed:', err.message));
  req.write(JSON.stringify(payload));
  req.end();
}

function slackAlert(entry) {
  if (!SLACK_WEBHOOK) return;
  const emoji = entry.reason === 'replay_attack' ? ':rotating_light:' : ':warning:';
  postWebhook(SLACK_WEBHOOK, {
    text: `${emoji} *MCPS Security Alert*`,
    blocks: [{
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: [
          `*Event:* \`${entry.event}\``,
          `*Reason:* \`${entry.reason}\``,
          `*Passport:* \`${entry.passport_id}\``,
          `*Time:* ${entry.timestamp}`,
        ].join('\n'),
      },
    }],
  });
}

function pagerdutyAlert(entry) {
  if (!PAGERDUTY_KEY) return;
  postWebhook('https://events.pagerduty.com/v2/enqueue', {
    routing_key: PAGERDUTY_KEY,
    event_action: 'trigger',
    payload: {
      summary: `MCPS: ${entry.reason} from ${entry.passport_id}`,
      severity: ['replay_attack', 'invalid_signature', 'revoked'].includes(entry.reason)
        ? 'critical' : 'warning',
      source: 'mcps-server',
      custom_details: entry,
    },
  });
}

// ── MCPS Server with Webhook Alerts ──
const keys = mcps.generateKeyPair();
const passport = mcps.createPassport({
  publicKey: keys.publicKey,
  name: 'my-mcp-server',
  version: '1.0.0',
});

const app = express();
app.use(express.json());

const secure = mcps.secureMCP(null, {
  passport: passport.passport_id,
  privateKey: keys.privateKey,
  minTrustLevel: 2,
  auditLog: true,
  onAudit: (entry) => {
    // Always log to stdout
    console.log(JSON.stringify(entry));

    // Alert on rejections
    if (entry.event === 'rejected') {
      slackAlert(entry);

      // Only page on critical events
      if (['replay_attack', 'invalid_signature', 'revoked'].includes(entry.reason)) {
        pagerdutyAlert(entry);
      }
    }
  },
});

app.post('/mcp', async (req, res) => {
  const result = await secure.handleMessage(req.body);
  res.json(result);
});

app.listen(3000, () => console.log('MCPS server with Slack + PagerDuty on :3000'));
```

---

#### File-Based (Air-Gapped / Offline Environments)

```javascript
// file-mcps-server.js — JSONL audit log with automatic rotation
const fs = require('fs');
const path = require('path');
const mcps = require('mcp-secure');
const express = require('express');

const AUDIT_DIR = process.env.MCPS_AUDIT_DIR || './audit-logs';
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB per file

// Ensure audit directory exists
if (!fs.existsSync(AUDIT_DIR)) fs.mkdirSync(AUDIT_DIR, { recursive: true });

let currentFile = path.join(AUDIT_DIR, `mcps-audit-${Date.now()}.jsonl`);
let currentStream = fs.createWriteStream(currentFile, { flags: 'a' });
let bytesWritten = 0;

function rotateIfNeeded() {
  if (bytesWritten > MAX_FILE_SIZE) {
    currentStream.end();
    currentFile = path.join(AUDIT_DIR, `mcps-audit-${Date.now()}.jsonl`);
    currentStream = fs.createWriteStream(currentFile, { flags: 'a' });
    bytesWritten = 0;
  }
}

function writeAudit(entry) {
  const line = JSON.stringify(entry) + '\n';
  currentStream.write(line);
  bytesWritten += Buffer.byteLength(line);
  rotateIfNeeded();
}

// ── MCPS Server with File Audit ──
const keys = mcps.generateKeyPair();
const passport = mcps.createPassport({
  publicKey: keys.publicKey,
  name: 'my-mcp-server',
  version: '1.0.0',
});

const app = express();
app.use(express.json());

const secure = mcps.secureMCP(null, {
  passport: passport.passport_id,
  privateKey: keys.privateKey,
  minTrustLevel: 2,
  auditLog: true,
  onAudit: (entry) => {
    writeAudit(entry);

    // Print critical events to stderr for syslog capture
    if (entry.event === 'rejected' &&
        ['replay_attack', 'invalid_signature', 'revoked'].includes(entry.reason)) {
      process.stderr.write(`[MCPS CRITICAL] ${JSON.stringify(entry)}\n`);
    }
  },
});

app.post('/mcp', async (req, res) => {
  const result = await secure.handleMessage(req.body);
  res.json(result);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  currentStream.end();
  secure.destroy();
  process.exit(0);
});

app.listen(3000, () => console.log(`MCPS audit logs → ${AUDIT_DIR}`));
```

**Query JSONL logs with `jq`:**
```bash
# All rejections
cat audit-logs/*.jsonl | jq 'select(.event == "rejected")'

# Replay attacks in last hour
cat audit-logs/*.jsonl | jq 'select(.reason == "replay_attack")'

# Count by reason
cat audit-logs/*.jsonl | jq -r 'select(.event == "rejected") | .reason' | sort | uniq -c | sort -rn

# Unique agents
cat audit-logs/*.jsonl | jq -r 'select(.event == "accepted") | .passport_id' | sort -u | wc -l
```

---

### SOC Alert Priority Matrix

Configure these alerts in whichever SIEM you chose above:

| Event | Severity | Alert? | Response |
|-------|----------|--------|----------|
| `replay_attack` | CRITICAL | Page on-call | Active MITM — rotate keys, check network |
| `invalid_signature` | CRITICAL | Page on-call | Forgery attempt — identify source IP, block |
| `revoked` | HIGH | Alert SOC | Compromised agent reconnecting — verify revocation propagated |
| `origin_mismatch` | HIGH | Alert SOC | DNS hijack or misconfigured redirect |
| `insufficient_trust` | MEDIUM | Log + dashboard | Untrusted agent probing — may be legit misconfiguration |
| `authority_unreachable` | MEDIUM | Alert SOC | Trust Authority down — all agents blocked (fail-closed) |
| `invalid_format` | LOW | Dashboard only | Missing MCPS envelope — likely legacy MCP client |
| `no_public_key` | LOW | Dashboard only | Passport not in cache — check TA connectivity |

### Dashboard Metrics

Track these in your metrics system (Prometheus, Datadog, CloudWatch):

```javascript
let accepted = 0, rejected = 0;

secureMCP(server, {
  onAudit: (entry) => {
    if (entry.event === 'accepted') accepted++;
    if (entry.event === 'rejected') rejected++;

    // Expose via /metrics endpoint or push to your metrics system
  },
});
```

Key metrics:
- `mcps_messages_accepted_total` — healthy traffic
- `mcps_messages_rejected_total` — by reason (label: reason)
- `mcps_unique_passports` — distinct agents connecting
- `mcps_rejection_rate` — rejected / (accepted + rejected) — alert if > 10%

---

## 8. Key Rotation

When you rotate keys, link the old key to the new one:

```javascript
const crypto = require('crypto');

// Hash the old public key
const oldKeyHash = crypto.createHash('sha256')
  .update(oldKeys.publicKey)
  .digest('hex');

// Create new passport with rotation link
const newKeys = mcps.generateKeyPair();
const newPassport = mcps.createPassport({
  name: 'my-agent',
  version: '1.0.0',
  publicKey: newKeys.publicKey,
  previousKeyHash: oldKeyHash,  // links to old identity
});

// The old passport should be revoked via Trust Authority after transition
```

**Rotation checklist:**
1. Generate new key pair
2. Create new passport with `previousKeyHash`
3. Register new passport with Trust Authority
4. Deploy new keys to your server
5. Revoke old passport (via Trust Authority)
6. Back up new keys

---

## 9. Multi-Tenant Isolation

Prevent Asana-style cross-tenant data leaks. Each tenant gets its own passport scoped to its own key pair.

```javascript
// Org A has its own keys and passport
const orgA = mcps.generateKeyPair();
const passportA = mcps.createPassport({
  publicKey: orgA.publicKey,
  name: 'org-a-agent',
  origin: 'https://org-a.example.com',
});

// Org B has completely separate keys
const orgB = mcps.generateKeyPair();
const passportB = mcps.createPassport({
  publicKey: orgB.publicKey,
  name: 'org-b-agent',
  origin: 'https://org-b.example.com',
});

// On the server: map passport_id → tenant
const tenantMap = {
  [passportA.passport_id]: 'org-a',
  [passportB.passport_id]: 'org-b',
};

// In your request handler:
function handleRequest(envelope) {
  const tenant = tenantMap[envelope.mcps.passport_id];
  if (tenant !== requestedTenant) {
    // BLOCKED — Org B cannot access Org A's data
    throw new Error('Cross-tenant access denied');
  }
}
```

**Why this works:** Org B cannot forge Org A's signature — different private key. Even if Org B presents a valid signature with its own passport, the server maps it to Org B's tenant. Cross-tenant access is mathematically impossible.

---

## 10. Gotchas & Common Mistakes

### 1. Forgetting `await` with HSM signers

```javascript
// WRONG — envelope is a Promise, not an object
const envelope = mcps.signMessage(msg, passportId, hsmSigner);

// RIGHT
const envelope = await mcps.signMessage(msg, passportId, hsmSigner);
```

PEM keys return sync. HSM signers return Promises. If you switch from PEM to HSM, add `await`.

### 2. Self-signed passports are always L0

```javascript
// This passport claims L4 but it's self-signed
const passport = mcps.createPassport({ ... });
passport.trust_level = 4;  // manually set

// getEffectiveTrustLevel ignores the claim
mcps.getEffectiveTrustLevel(passport); // → 0, not 4
```

Trust level is determined by who signed the passport, not what it says. Self-signed = L0. Always.

### 3. Storing private keys in code

```javascript
// NEVER do this
const privateKey = '-----BEGIN EC PRIVATE KEY-----\nMHQC...';

// Use environment variables or secret managers
const privateKey = process.env.MCPS_PRIVATE_KEY;

// Or HSM — key never leaves hardware
const signer = mcps.createExternalSigner(async (data) => { ... });
```

### 4. Not checking `hash_changed` on tool verification

```javascript
// This only checks signature — a re-signed poisoned tool would pass
const { valid } = mcps.verifyTool(tool, sig, pubKey);

// Always pin the hash from first verification
const { valid, hash_changed } = mcps.verifyTool(tool, sig, pubKey, pinnedHash);
if (!valid || hash_changed) throw new Error('Tool tampered');
```

### 5. Sharing key pairs across services

Each service should have its own key pair and passport. If one is compromised, only that service's passport needs revoking.

### 6. Not handling `AUTHORITY_UNREACHABLE`

`secureMCP` fails closed — if the Trust Authority is unreachable, all agents are rejected. Plan for this:

```javascript
secureMCP(server, {
  trustAuthorities: [
    'https://primary-ta.agentsign.dev',
    'https://fallback-ta.agentsign.dev',  // multi-TA for resilience
  ],
  onAudit: (e) => {
    if (e.reason === 'authority_unreachable_fail_closed') {
      alert('Trust Authority down — all agents blocked');
    }
  },
});
```

### 7. Timestamp clock skew

MCPS allows a 5-minute window. If your server's clock is off by more than 5 minutes, all signatures will be rejected. Use NTP.

### 8. DER vs P1363 signatures with HSMs

AWS KMS and GCP return DER format. Azure and PKCS#11 return P1363. If verification fails, check the format:

```javascript
// AWS/GCP: must convert
return mcps.derToP1363(Buffer.from(res.Signature));

// Azure/PKCS#11: use directly
return result.result;
```

---

## 11. FAQ

**Q: Does MCPS replace TLS?**
No. TLS protects the transport. MCPS protects the messages. Use both. MCPS adds identity, integrity, and non-repudiation that TLS alone doesn't provide.

**Q: What if I lose my private key?**
Revoke the old passport via Trust Authority. Generate new keys. Create new passport. Deploy. This is why HSMs are recommended for production — they handle key durability.

**Q: Can I use MCPS without a Trust Authority?**
Yes. Self-signed passports work (L0 trust). You just can't enforce L2+ trust levels without a TA to verify identities.

**Q: How big is the overhead per message?**
~200 bytes for the MCPS envelope (version, passport_id, nonce, timestamp, signature). Signing takes <1ms on modern hardware. Negligible.

**Q: Does MCPS work with MCP over stdio?**
Yes. MCPS wraps the JSON-RPC message regardless of transport (stdio, SSE, HTTP). The envelope is transport-agnostic.

**Q: What happens if I don't call `destroy()` on secureMCP?**
The NonceStore interval keeps running. Not a leak in short-lived processes, but call `destroy()` in long-running servers on shutdown.

**Q: Can two agents share a passport?**
They can, but shouldn't. If one is compromised, both are affected. One passport per agent instance.

---

## Quick Reference

```
npm install mcp-secure          # install
mcps.generateKeyPair()          # ECDSA P-256 key pair
mcps.createPassport(opts)       # agent identity
mcps.signMessage(msg, id, key)  # sign any MCP message
mcps.verifyMessage(env, pubKey) # verify signature
mcps.signTool(tool, key)        # sign tool definition
mcps.verifyTool(tool, sig, key) # verify tool integrity
mcps.signPassport(p, key)       # authority signs passport
mcps.secureMCP(server, opts)    # wrap existing MCP server
mcps.createExternalSigner(fn)   # HSM/KMS signer factory
mcps.derToP1363(derBuf)         # convert DER → P1363
mcps.NonceStore                 # replay protection
```

---

*Built by [CyberSecAI Ltd](https://agentsign.dev). Patent pending (GB2604808.2).*
