/**
 * Cross-platform interop test: Node.js side
 * 1. Read Python output and verify its signature
 * 2. Generate keys, sign a message, export for Python verification
 */
'use strict';

const fs = require('fs');
const path = require('path');
const mcps = require('./index.js');

const INTEROP_FILE = '/tmp/mcps_interop.json';

function phase1_verify() {
  const data = JSON.parse(fs.readFileSync(INTEROP_FILE, 'utf8'));

  if (!data.python_envelope) {
    console.log('NODE PHASE 1: No Python data found, skipping');
    return false;
  }

  const pyPub = data.python_public_key;
  const pyEnvelope = data.python_envelope;
  const pyTool = data.python_tool;
  const pyToolSig = data.python_tool_signature;

  // Verify Python signed message
  const result = mcps.verifyMessage(pyEnvelope, pyPub);
  if (result.valid) {
    console.log('NODE PHASE 1: Python message verification: PASS');
  } else {
    console.log('NODE PHASE 1: Python message verification: FAIL -', JSON.stringify(result));
    return false;
  }

  // Verify Python signed tool
  const toolResult = mcps.verifyTool(pyTool, pyToolSig, pyPub);
  if (toolResult.valid) {
    console.log('NODE PHASE 1: Python tool verification: PASS');
  } else {
    console.log('NODE PHASE 1: Python tool verification: FAIL -', JSON.stringify(toolResult));
    return false;
  }

  // Tamper test
  const tampered = JSON.parse(JSON.stringify(pyEnvelope));
  tampered.params.name = 'delete_everything';
  const tamperResult = mcps.verifyMessage(tampered, pyPub);
  if (!tamperResult.valid) {
    console.log('NODE PHASE 1: Tamper detection on Python message: PASS');
  } else {
    console.log('NODE PHASE 1: Tamper detection on Python message: FAIL - should have detected tamper');
    return false;
  }

  return true;
}

function phase2_sign() {
  // Generate Node.js keys
  const keys = mcps.generateKeyPair();
  const passport = mcps.createPassport({
    name: 'node-agent',
    version: '1.0.0',
    publicKey: keys.publicKey,
  });

  // Sign a message
  const message = {
    jsonrpc: '2.0',
    method: 'tools/call',
    params: { name: 'read_file', arguments: { path: '/etc/hosts' } },
    id: 42,
  };
  const envelope = mcps.signMessage(message, passport.passport_id, keys.privateKey);

  // Sign a tool
  const tool = {
    name: 'read_file',
    description: 'Read a file from disk',
    inputSchema: {
      type: 'object',
      properties: { path: { type: 'string' } },
      required: ['path'],
    },
  };
  const { signature: toolSig } = mcps.signTool(tool, keys.privateKey);

  // Self-verify
  const selfResult = mcps.verifyMessage(envelope, keys.publicKey);
  if (!selfResult.valid) {
    console.log('NODE PHASE 2: Self-verify FAIL -', JSON.stringify(selfResult));
    process.exit(1);
  }

  const toolSelfResult = mcps.verifyTool(tool, toolSig, keys.publicKey);
  if (!toolSelfResult.valid) {
    console.log('NODE PHASE 2: Tool self-verify FAIL -', JSON.stringify(toolSelfResult));
    process.exit(1);
  }

  // Read existing and merge
  const data = JSON.parse(fs.readFileSync(INTEROP_FILE, 'utf8'));
  data.node_public_key = keys.publicKey;
  data.node_envelope = envelope;
  data.node_tool = tool;
  data.node_tool_signature = toolSig;
  data.node_passport_id = passport.passport_id;

  fs.writeFileSync(INTEROP_FILE, JSON.stringify(data, null, 2));

  console.log('NODE PHASE 2: Keys generated, message signed, tool signed');
  console.log(`  Passport ID: ${passport.passport_id}`);
  console.log(`  Envelope nonce: ${envelope.mcps.nonce}`);
  console.log('  Self-verify: PASS');
  console.log('  Tool self-verify: PASS');
}

// Run
const pyVerified = phase1_verify();
phase2_sign();

if (!pyVerified) {
  console.log('\n--- RESULT: Python verification FAILED ---');
  process.exit(1);
}
console.log('\n--- NODE COMPLETE: All checks passed ---');
