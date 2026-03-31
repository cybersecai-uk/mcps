"""
Cross-platform interop test: Python side
1. Generate keys, sign a message, export for Node.js verification
2. Read Node.js output and verify its signature
"""
import json
import sys
import os
sys.path.insert(0, '/opt/homebrew/lib/python3.14/site-packages')

from mcp_secure import (
    generate_key_pair, create_passport, sign_message, verify_message,
    sign_tool, verify_tool, canonical_json
)

INTEROP_FILE = '/tmp/mcps_interop.json'

def phase1_sign():
    """Generate Python keys, sign message, export for Node.js"""
    keys = generate_key_pair()
    passport = create_passport(
        name="python-agent",
        version="1.0.0",
        public_key=keys["public_key"]
    )

    # Sign a message
    message = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "/etc/hosts"}},
        "id": 42
    }
    envelope = sign_message(message, passport["passport_id"], keys["private_key"])

    # Sign a tool
    tool = {
        "name": "read_file",
        "description": "Read a file from disk",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]
        }
    }
    tool_sig_result = sign_tool(tool, keys["private_key"])
    tool_sig = tool_sig_result["signature"]

    # Self-verify first
    result = verify_message(envelope, keys["public_key"])
    assert result["valid"], f"Python self-verify failed: {result}"

    tool_result = verify_tool(tool, tool_sig, keys["public_key"])
    assert tool_result["valid"], f"Python tool self-verify failed: {tool_result}"

    # Export
    data = {
        "python_public_key": keys["public_key"],
        "python_envelope": envelope,
        "python_tool": tool,
        "python_tool_signature": tool_sig,
        "python_passport_id": passport["passport_id"],
    }

    # Read existing data if Node.js already wrote
    if os.path.exists(INTEROP_FILE):
        with open(INTEROP_FILE, 'r') as f:
            existing = json.load(f)
        data.update(existing)

    with open(INTEROP_FILE, 'w') as f:
        json.dump(data, f, indent=2)

    print("PYTHON PHASE 1: Keys generated, message signed, tool signed")
    print(f"  Passport ID: {passport['passport_id']}")
    print(f"  Envelope nonce: {envelope['mcps']['nonce']}")
    print(f"  Self-verify: PASS")
    print(f"  Tool self-verify: PASS")

def phase2_verify():
    """Read Node.js output and verify"""
    with open(INTEROP_FILE, 'r') as f:
        data = json.load(f)

    if 'node_envelope' not in data:
        print("PYTHON PHASE 2: No Node.js data found, skipping")
        return False

    node_pub = data['node_public_key']
    node_envelope = data['node_envelope']
    node_tool = data['node_tool']
    node_tool_sig = data['node_tool_signature']

    # Verify Node.js signed message
    result = verify_message(node_envelope, node_pub)
    if result["valid"]:
        print("PYTHON PHASE 2: Node.js message verification: PASS")
    else:
        print(f"PYTHON PHASE 2: Node.js message verification: FAIL - {result}")
        return False

    # Verify Node.js signed tool
    tool_result = verify_tool(node_tool, node_tool_sig, node_pub)
    if tool_result["valid"]:
        print("PYTHON PHASE 2: Node.js tool verification: PASS")
    else:
        print(f"PYTHON PHASE 2: Node.js tool verification: FAIL - {tool_result}")
        return False

    # Tamper test - modify the envelope and verify it fails
    tampered = json.loads(json.dumps(node_envelope))
    tampered["params"]["name"] = "delete_everything"
    tamper_result = verify_message(tampered, node_pub)
    if not tamper_result["valid"]:
        print("PYTHON PHASE 2: Tamper detection on Node.js message: PASS")
    else:
        print("PYTHON PHASE 2: Tamper detection on Node.js message: FAIL - should have detected tamper")
        return False

    return True

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'verify':
        success = phase2_verify()
        sys.exit(0 if success else 1)
    else:
        phase1_sign()
