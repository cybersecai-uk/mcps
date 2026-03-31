#!/usr/bin/env python3
"""Generate MCPS Architecture Overview - Professional Product Brief"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
import os

OUTPUT = os.path.expanduser("~/Desktop/mcps/MCPS-Architecture-Overview.pdf")

# Professional color palette
NAVY = HexColor("#0f172a")
DARK_BLUE = HexColor("#1e3a5f")
BLUE = HexColor("#2563eb")
LIGHT_BLUE = HexColor("#3b82f6")
SKY = HexColor("#dbeafe")
GREEN = HexColor("#059669")
LIGHT_GREEN = HexColor("#d1fae5")
AMBER = HexColor("#d97706")
LIGHT_AMBER = HexColor("#fef3c7")
RED = HexColor("#dc2626")
LIGHT_RED = HexColor("#fee2e2")
PURPLE = HexColor("#7c3aed")
LIGHT_PURPLE = HexColor("#ede9fe")
GRAY_50 = HexColor("#f8fafc")
GRAY_100 = HexColor("#f1f5f9")
GRAY_200 = HexColor("#e2e8f0")
GRAY_300 = HexColor("#cbd5e1")
GRAY_500 = HexColor("#64748b")
GRAY_600 = HexColor("#475569")
GRAY_700 = HexColor("#334155")
GRAY_800 = HexColor("#1e293b")
GRAY_900 = HexColor("#0f172a")
WHITE = HexColor("#ffffff")

W, H = A4  # 595 x 842 points
MARGIN = 40
CONTENT_W = W - 2 * MARGIN

def draw_rounded_rect(c, x, y, w, h, r=6, fill=None, stroke=None, stroke_width=0.75):
    c.saveState()
    if fill:
        c.setFillColor(fill)
    if stroke:
        c.setStrokeColor(stroke)
        c.setLineWidth(stroke_width)
    p = c.beginPath()
    p.roundRect(x, y, w, h, r)
    if fill and stroke:
        c.drawPath(p, fill=1, stroke=1)
    elif fill:
        c.drawPath(p, fill=1, stroke=0)
    elif stroke:
        c.drawPath(p, fill=0, stroke=1)
    c.restoreState()

def draw_arrow(c, x1, y1, x2, y2, color=GRAY_500, width=1.2):
    import math
    c.saveState()
    c.setStrokeColor(color)
    c.setLineWidth(width)
    c.line(x1, y1, x2, y2)
    angle = math.atan2(y2-y1, x2-x1)
    size = 6
    c.setFillColor(color)
    p = c.beginPath()
    p.moveTo(x2, y2)
    p.lineTo(x2 - size*math.cos(angle-0.35), y2 - size*math.sin(angle-0.35))
    p.lineTo(x2 - size*math.cos(angle+0.35), y2 - size*math.sin(angle+0.35))
    p.close()
    c.drawPath(p, fill=1, stroke=0)
    c.restoreState()

def draw_section_header(c, y, title, color=NAVY):
    """Draw a section header with left accent bar"""
    c.saveState()
    c.setFillColor(BLUE)
    c.rect(MARGIN, y-1, 3, 14, fill=1, stroke=0)
    c.setFillColor(color)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(MARGIN + 10, y, title)
    c.restoreState()
    return y - 6

def draw_pillar_card(c, x, y, w, h, title, detail, color, bg_color):
    draw_rounded_rect(c, x, y, w, h, r=5, fill=bg_color, stroke=color, stroke_width=0.5)
    c.setFillColor(color)
    c.setFont("Helvetica-Bold", 7)
    c.drawCentredString(x+w/2, y+h-14, title)
    c.setFillColor(GRAY_700)
    c.setFont("Helvetica", 5.5)
    lines = detail.split('\n')
    for i, line in enumerate(lines):
        c.drawCentredString(x+w/2, y+h-26-i*8, line)

def wrap_text(c, text, x, y, font, size, max_width, color=GRAY_700, leading=8):
    """Word wrap text and return final y position"""
    c.setFont(font, size)
    c.setFillColor(color)
    words = text.split()
    line = ""
    for word in words:
        test = line + " " + word if line else word
        if c.stringWidth(test, font, size) > max_width:
            c.drawString(x, y, line)
            y -= leading
            line = word
        else:
            line = test
    if line:
        c.drawString(x, y, line)
        y -= leading
    return y

# ============================================================
# CREATE PDF
# ============================================================
c = canvas.Canvas(OUTPUT, pagesize=A4)

# ============================================================
# PAGE 1
# ============================================================

# White background
c.setFillColor(WHITE)
c.rect(0, 0, W, H, fill=1, stroke=0)

# === TOP HEADER BAR ===
c.setFillColor(NAVY)
c.rect(0, H-60, W, 60, fill=1, stroke=0)

c.setFillColor(WHITE)
c.setFont("Helvetica-Bold", 22)
c.drawString(MARGIN, H-38, "MCPS")
c.setFont("Helvetica", 12)
c.drawString(MARGIN + 62, H-38, "MCP Secure")

c.setFillColor(HexColor("#94a3b8"))
c.setFont("Helvetica", 8)
c.drawRightString(W-MARGIN, H-28, "CyberSecAI Ltd  |  Patent Pending (GB2604808.2)")
c.drawRightString(W-MARGIN, H-40, "IETF: draft-sharif-mcps-secure-mcp")
c.drawRightString(W-MARGIN, H-52, "agentsign.dev")

# === TAGLINE ===
y = H - 80
c.setFillColor(BLUE)
c.setFont("Helvetica-Bold", 13)
c.drawString(MARGIN, y, "The HTTPS of the Agent Era")
y -= 16
c.setFillColor(GRAY_600)
c.setFont("Helvetica", 9)
c.drawString(MARGIN, y, "Cryptographic identity, message signing, and trust verification for the Model Context Protocol.")
y -= 12
c.drawString(MARGIN, y, "Zero dependencies. Sub-millisecond. IETF standards track. Patent protected.")

# === ARCHITECTURE SECTION ===
y -= 24
y = draw_section_header(c, y, "Architecture")

y -= 10
arch_top = y
arch_h = 105
draw_rounded_rect(c, MARGIN, y - arch_h, CONTENT_W, arch_h, r=8, fill=GRAY_50, stroke=GRAY_200)

# Agent box
ax, ay, aw, ah = MARGIN+15, y-arch_h+12, 105, 78
draw_rounded_rect(c, ax, ay, aw, ah, r=6, fill=WHITE, stroke=BLUE, stroke_width=1)
c.setFillColor(BLUE)
c.setFont("Helvetica-Bold", 8)
c.drawCentredString(ax+aw/2, ay+ah-13, "AI Agent")
c.setStrokeColor(GRAY_200)
c.line(ax+5, ay+ah-17, ax+aw-5, ay+ah-17)
c.setFillColor(GRAY_700)
c.setFont("Helvetica", 6)
items = ["ECDSA P-256 Key Pair", "Agent Passport (L0-L4)", "Private Key (never leaves)", "Signs every request"]
for i, item in enumerate(items):
    c.drawString(ax+8, ay+ah-28-i*11, item)

# MCPS Layer box
mx, my, mw, mh = MARGIN+155, y-arch_h+22, 115, 60
draw_rounded_rect(c, mx, my, mw, mh, r=6, fill=WHITE, stroke=GREEN, stroke_width=1.5)
c.setFillColor(GREEN)
c.setFont("Helvetica-Bold", 8)
c.drawCentredString(mx+mw/2, my+mh-13, "MCPS Security Layer")
c.setStrokeColor(GRAY_200)
c.line(mx+5, my+mh-17, mx+mw-5, my+mh-17)
c.setFillColor(GRAY_700)
c.setFont("Helvetica", 6)
mcps_items = ["secureMCP() Middleware", "Sign / Verify Messages", "Nonce + Timestamp + Hash"]
for i, item in enumerate(mcps_items):
    c.drawString(mx+8, my+mh-28-i*11, item)

# Trust Authority (above MCPS)
tx, ty, tw, th = mx+10, y-12, 95, 22
draw_rounded_rect(c, tx, ty, tw, th, r=5, fill=LIGHT_PURPLE, stroke=PURPLE, stroke_width=0.75)
c.setFillColor(PURPLE)
c.setFont("Helvetica-Bold", 6.5)
c.drawCentredString(tx+tw/2, ty+th-9, "Trust Authority")
c.setFillColor(GRAY_600)
c.setFont("Helvetica", 5.5)
c.drawCentredString(tx+tw/2, ty+4, "agentsign.dev  |  On-Prem  |  Air-Gapped")

# MCP Server box
sx, sy, sw, sh = MARGIN+305, y-arch_h+12, 105, 78
draw_rounded_rect(c, sx, sy, sw, sh, r=6, fill=WHITE, stroke=AMBER, stroke_width=1)
c.setFillColor(AMBER)
c.setFont("Helvetica-Bold", 8)
c.drawCentredString(sx+sw/2, sy+sh-13, "MCP Server")
c.setStrokeColor(GRAY_200)
c.line(sx+5, sy+sh-17, sx+sw-5, sy+sh-17)
c.setFillColor(GRAY_700)
c.setFont("Helvetica", 6)
srv_items = ["Verifies Signatures", "Enforces Trust Level", "Validates Nonce/Timestamp", "Emits Audit Events"]
for i, item in enumerate(srv_items):
    c.drawString(sx+8, sy+sh-28-i*11, item)

# SIEM box
asx, asy, asw, ash = MARGIN+445, y-arch_h+25, 60, 55
draw_rounded_rect(c, asx, asy, asw, ash, r=5, fill=LIGHT_GREEN, stroke=GREEN, stroke_width=0.5)
c.setFillColor(GREEN)
c.setFont("Helvetica-Bold", 6)
c.drawCentredString(asx+asw/2, asy+ash-11, "SIEM")
c.setFillColor(GRAY_600)
c.setFont("Helvetica", 5)
c.drawCentredString(asx+asw/2, asy+ash-22, "Splunk")
c.drawCentredString(asx+asw/2, asy+ash-30, "Datadog")
c.drawCentredString(asx+asw/2, asy+ash-38, "ELK / CW")

# Arrows
mid_y = ay + ah/2
draw_arrow(c, ax+aw+2, mid_y+3, mx-2, mid_y+3, BLUE, 1.5)
draw_arrow(c, mx+mw+2, mid_y+3, sx-2, mid_y+3, GREEN, 1.5)
draw_arrow(c, sx+sw+2, asy+ash/2, asx-2, asy+ash/2, HexColor("#059669"), 1)
draw_arrow(c, mx+mw/2, my+mh+2, tx+tw/2, ty-2, PURPLE, 1)

# Arrow labels
c.setFillColor(GRAY_500)
c.setFont("Helvetica-Oblique", 5.5)
c.drawCentredString((ax+aw+mx)/2, mid_y+10, "Signed Envelope")
c.drawCentredString((mx+mw+sx)/2, mid_y+10, "Verified Request")
c.drawCentredString((sx+sw+asx)/2, asy+ash/2+8, "onAudit()")

# === SEVEN SECURITY PILLARS ===
y = arch_top - arch_h - 22
y = draw_section_header(c, y, "Seven Security Pillars")
y -= 6

pillars = [
    ("Identity", "ECDSA P-256 passports\nTrust levels L0--L4", BLUE, SKY),
    ("Signing", "Per-message signatures\nNonce + timestamp + hash", GREEN, LIGHT_GREEN),
    ("Tool Integrity", "signTool() / verifyTool()\nSHA-256 hash pinning", AMBER, LIGHT_AMBER),
    ("Replay Block", "NonceStore with GC\n5-min timestamp window", RED, LIGHT_RED),
    ("Revocation", "Real-time via TA API\nWebhook + CRL offline", PURPLE, LIGHT_PURPLE),
    ("Trust Levels", "L0 self-signed to\nL4 externally audited", DARK_BLUE, SKY),
    ("Audit Trail", "Structured SIEM events\nAccept / reject / replay", GREEN, LIGHT_GREEN),
]
pw = (CONTENT_W - 6*6) / 7
for i, (title, desc, color, bg) in enumerate(pillars):
    px = MARGIN + i * (pw + 6)
    draw_pillar_card(c, px, y-48, pw, 48, title, desc, color, bg)

# === COMPLIANCE COVERAGE ===
y -= 68
y = draw_section_header(c, y, "Compliance & Standards Coverage")
y -= 6

# Two columns
col_w = (CONTENT_W - 12) / 2

# Left: OWASP
draw_rounded_rect(c, MARGIN, y-108, col_w, 108, r=6, fill=GRAY_50, stroke=GRAY_200)
c.setFillColor(AMBER)
c.setFont("Helvetica-Bold", 8)
c.drawString(MARGIN+10, y-14, "OWASP MCP Top 10")
c.setFillColor(GRAY_700)
c.setFont("Helvetica-Bold", 6.5)
c.drawRightString(MARGIN+col_w-10, y-14, "8 of 10 Risks Mitigated")

owasp_items = [
    ("MCP01", "Excessive Agency", "Tool trust levels + minTrustLevel gate"),
    ("MCP03", "Tool Poisoning", "signTool() with SHA-256 hash pinning"),
    ("MCP04", "Supply Chain", "Zero deps + cryptographic tool attestation"),
    ("MCP06", "Intent Subversion", "Per-message integrity hash covers full body"),
    ("MCP07", "Authentication", "ECDSA P-256 agent passports, not API keys"),
    ("MCP08", "Audit Logging", "onAudit() structured events for SIEM"),
    ("MCP09", "Shadow Servers", "Origin binding + validateOrigin() checks"),
    ("MCP10", "Context Injection", "Message hash prevents payload tampering"),
]
for i, (code, name, fix) in enumerate(owasp_items):
    row_y = y - 27 - i*10
    c.setFillColor(AMBER)
    c.setFont("Helvetica-Bold", 5.5)
    c.drawString(MARGIN+10, row_y, code)
    c.setFillColor(GRAY_800)
    c.setFont("Helvetica", 5.5)
    c.drawString(MARGIN+42, row_y, name)
    c.setFillColor(GRAY_500)
    c.setFont("Helvetica", 5.5)
    c.drawString(MARGIN+105, row_y, fix)

# Right: SOC 2
rx = MARGIN + col_w + 12
draw_rounded_rect(c, rx, y-108, col_w, 108, r=6, fill=GRAY_50, stroke=GRAY_200)
c.setFillColor(GREEN)
c.setFont("Helvetica-Bold", 8)
c.drawString(rx+10, y-14, "SOC 2 Trust Service Criteria")
c.setFillColor(GRAY_700)
c.setFont("Helvetica-Bold", 6.5)
c.drawRightString(rx+col_w-10, y-14, "23 Criteria Mapped")

soc2_items = [
    ("Security", "CC1--CC9", "Agent identity, authentication, access\ncontrols, monitoring, change management"),
    ("Processing\nIntegrity", "PI1.1--PI1.5", "Per-message SHA-256 hash, RFC 8785\nJCS, nonce + timestamp, mutual auth"),
    ("Confidentiality", "C1.1--C1.2", "Private keys never leave signer (HSM\nsupport), NonceStore GC, passport TTL"),
    ("Availability", "A1.1--A1.2", "Zero deps = minimal failure surface,\nkey rotation + revocation recovery"),
]
for i, (cat, codes, detail) in enumerate(soc2_items):
    row_y = y - 30 - i*20
    c.setFillColor(GREEN)
    c.setFont("Helvetica-Bold", 6)
    c.drawString(rx+10, row_y, cat.split('\n')[0])
    if '\n' in cat:
        c.drawString(rx+10, row_y-7, cat.split('\n')[1])
    c.setFillColor(GRAY_500)
    c.setFont("Helvetica", 5.5)
    c.drawString(rx+70, row_y, codes)
    c.setFillColor(GRAY_700)
    c.setFont("Helvetica", 5.5)
    lines = detail.split('\n')
    for j, line in enumerate(lines):
        c.drawString(rx+115, row_y-j*7, line)

# === TECH SPECS BAR ===
y -= 122
draw_rounded_rect(c, MARGIN, y-28, CONTENT_W, 28, r=5, fill=NAVY, stroke=None)
specs = [
    ("Crypto", "ECDSA P-256 (FIPS 186-5)"),
    ("Hash", "SHA-256"),
    ("Canonicalization", "RFC 8785 (JCS)"),
    ("Dependencies", "Zero"),
    ("Test Suite", "180 tests (105 red team)"),
    ("npm", "mcp-secure@1.0.4"),
]
spec_w = CONTENT_W / len(specs)
for i, (label, val) in enumerate(specs):
    sx = MARGIN + i * spec_w + 10
    c.setFillColor(HexColor("#94a3b8"))
    c.setFont("Helvetica", 5)
    c.drawString(sx, y-10, label)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 6)
    c.drawString(sx, y-20, val)

# === HOW IT WORKS (step by step) ===
y -= 42
y = draw_section_header(c, y, "How It Works -- End-to-End Flow")
y -= 8

steps = [
    ("1", "Generate Identity", "Agent generates ECDSA P-256 key pair. Private key stays local (or in HSM/KMS). Public key is embedded in the agent's passport.", BLUE),
    ("2", "Issue Passport", "Trust Authority (agentsign.dev or on-prem) issues a signed passport with trust level (L0 self-signed, L1 verified, L2 org-vouched, L3 audited, L4 certified).", PURPLE),
    ("3", "Sign Every Message", "Before sending any MCP request, the agent signs it: SHA-256(message) + nonce + timestamp + passport_id, signed with ECDSA private key.", GREEN),
    ("4", "Verify at Server", "MCP server middleware (secureMCP) verifies signature, checks nonce uniqueness, validates timestamp window, enforces minimum trust level.", AMBER),
    ("5", "Mutual Authentication", "Server signs its response back. Client verifies. Both sides now have cryptographic proof of the other's identity and message integrity.", BLUE),
    ("6", "Audit & Revoke", "Every accept/reject/replay event is emitted to SIEM via onAudit(). Compromised passports are revoked in real-time via Trust Authority API.", RED),
]

step_w = (CONTENT_W - 5*8) / 6
for i, (num, title, desc, color) in enumerate(steps):
    sx = MARGIN + i * (step_w + 8)
    draw_rounded_rect(c, sx, y-90, step_w, 90, r=5, fill=GRAY_50, stroke=color, stroke_width=0.5)
    # Step number circle
    c.setFillColor(color)
    c.circle(sx + 12, y - 10, 7, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 7)
    c.drawCentredString(sx + 12, y - 13, num)
    # Title
    c.setFillColor(GRAY_900)
    c.setFont("Helvetica-Bold", 6)
    c.drawString(sx + 22, y - 13, title)
    # Description
    c.setFillColor(GRAY_600)
    c.setFont("Helvetica", 5)
    words = desc.split()
    line = ""
    line_y = y - 26
    for word in words:
        test = line + " " + word if line else word
        if c.stringWidth(test, "Helvetica", 5) > step_w - 12:
            c.drawString(sx + 6, line_y, line)
            line_y -= 7
            line = word
        else:
            line = test
    if line:
        c.drawString(sx + 6, line_y, line)

# === KEY DIFFERENTIATORS ===
y -= 106
y = draw_section_header(c, y, "Why MCPS")
y -= 6

diffs = [
    ("Not API Keys", "Cryptographic identity that cannot be stolen from config files or intercepted in transit."),
    ("Not OAuth", "No token endpoints, no redirect flows, no refresh logic. Works per-message, offline-capable."),
    ("Not Behavioral", "Prevents attacks cryptographically at the protocol level. Does not rely on detecting anomalies after the fact."),
    ("Zero Dependencies", "Entire security layer runs on Node.js native crypto (OpenSSL). No supply chain risk in the security layer itself."),
]

diff_w = (CONTENT_W - 3*10) / 4
for i, (title, desc) in enumerate(diffs):
    dx = MARGIN + i * (diff_w + 10)
    draw_rounded_rect(c, dx, y-52, diff_w, 52, r=5, fill=SKY, stroke=BLUE, stroke_width=0.5)
    c.setFillColor(NAVY)
    c.setFont("Helvetica-Bold", 6.5)
    c.drawString(dx+8, y-12, title)
    c.setFillColor(GRAY_600)
    c.setFont("Helvetica", 5.2)
    words = desc.split()
    line = ""
    line_y = y - 24
    for word in words:
        test = line + " " + word if line else word
        if c.stringWidth(test, "Helvetica", 5.2) > diff_w - 16:
            c.drawString(dx + 8, line_y, line)
            line_y -= 7
            line = word
        else:
            line = test
    if line:
        c.drawString(dx + 8, line_y, line)

# === PAGE 1 FOOTER ===
c.setStrokeColor(GRAY_200)
c.line(MARGIN, 32, W-MARGIN, 32)
c.setFillColor(GRAY_500)
c.setFont("Helvetica", 6)
c.drawString(MARGIN, 20, "CyberSecAI Ltd  |  agentsign.dev  |  mcp-secure on npm  |  Patent Pending (GB2604808.2)")
c.drawRightString(W-MARGIN, 20, "Page 1 of 2")

# ============================================================
# PAGE 2
# ============================================================
c.showPage()

c.setFillColor(WHITE)
c.rect(0, 0, W, H, fill=1, stroke=0)

# Page 2 header
c.setFillColor(NAVY)
c.rect(0, H-40, W, 40, fill=1, stroke=0)
c.setFillColor(WHITE)
c.setFont("Helvetica-Bold", 14)
c.drawString(MARGIN, H-27, "MCPS  |  Frequently Asked Questions")
c.setFillColor(HexColor("#94a3b8"))
c.setFont("Helvetica", 7)
c.drawRightString(W-MARGIN, H-27, "agentsign.dev  |  IETF: draft-sharif-mcps-secure-mcp")

# === DEVELOPER FAQs ===
y = H - 62
y = draw_section_header(c, y, "For Developers & Engineering Teams")

dev_faqs = [
    ("How do I integrate MCPS into my existing MCP server?",
     "One line of code: secureMCP(yourServer, { privateKey, passport, trustAuthority }). The middleware wraps your server transparently with zero changes to your application logic. It intercepts every JSON-RPC message, verifies the sender's cryptographic identity, and rejects unsigned or tampered messages. Works with stdio, HTTP, and WebSocket transports. The npm package (mcp-secure) has zero dependencies -- it uses only Node.js native crypto (OpenSSL under the hood)."),

    ("What happens if the Trust Authority is unreachable?",
     "Fail-closed by design. Messages are rejected, never silently passed through. There is no configuration toggle to degrade to fail-open. For air-gapped or offline environments, CRL (Certificate Revocation List) distribution provides offline revocation checking. The Trust Authority is only consulted during passport issuance and optional revocation checks -- message signing and verification happen locally with zero network calls."),

    ("Does MCPS add latency to MCP calls?",
     "Sub-millisecond. ECDSA P-256 sign/verify operations take <0.5ms on modern hardware. The NonceStore is an in-memory Map with O(1) lookup and automatic garbage collection. No network calls occur during message verification -- the Trust Authority check is optional and cached. In benchmarks, MCPS adds less overhead than a single DNS lookup."),

    ("Can I use MCPS without agentsign.dev?",
     "Yes. Self-signed passports work immediately at L0 trust -- no external services required. For enterprise deployment, the Trust Authority can run on-prem as a Docker container, giving you full control over passport issuance, revocation, and trust level management. MCPS has zero external dependencies and makes zero outbound network calls unless you explicitly configure a Trust Authority URL."),

    ("How does tool integrity verification work?",
     "signTool() computes SHA-256 over the canonical form (RFC 8785 JCS) of the tool's name, description, and inputSchema, then signs the hash with ECDSA P-256. verifyTool() checks both the cryptographic signature and the content hash. Any modification to the tool definition -- description injection, schema mutation, or post-deployment rug-pull -- produces hash_changed: true, valid: false. The hash is pinned at first use, so even the tool author cannot silently modify it."),

    ("What's the difference between MCPS and OAuth/DPoP?",
     "OAuth authenticates users to services via token exchange. MCPS authenticates agents to agents via cryptographic identity. OAuth requires a token endpoint, redirect flows, and refresh logic. MCPS works per-message with no token exchange, no redirect URIs, and no refresh flows. MCPS can complement OAuth -- a passport can be issued after successful OAuth verification -- or replace it entirely for agent-to-server authentication. MCPS also covers message integrity (every message is hash-signed), which OAuth does not."),
]

for q, a in dev_faqs:
    y -= 14
    c.setFillColor(BLUE)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawString(MARGIN + 5, y, "Q:  " + q)
    y -= 10
    y = wrap_text(c, a, MARGIN + 10, y, "Helvetica", 6, CONTENT_W - 15, GRAY_600, 8)
    y -= 2

# === ACQUIRER FAQs ===
y -= 10
y = draw_section_header(c, y, "For Acquirers, Investors & Enterprise Buyers")

acq_faqs = [
    ("What is the defensible moat?",
     "Three layers: (1) Patent Pending GB2604808.2 covering 5 subsystems and 10 claims for cryptographic agent identity, execution chain verification, runtime attestation, tamper detection, and trust scoring. (2) IETF Internet-Draft (draft-sharif-mcps-secure-mcp) on standards track -- the only MCP security protocol submitted to the IETF. (3) First-mover advantage with a working implementation, npm package, SOC 2 mapping, and OWASP alignment. Zero dependencies means zero supply chain risk in the security layer itself."),

    ("What is the market opportunity?",
     "Every MCP deployment needs security. Anthropic, OpenAI, Google, and Microsoft all ship MCP support. The agent security market is projected at $8.2B by 2028. Today, MCP has no built-in authentication, no message signing, and no agent identity. MCPS is the only IETF-track cryptographic protocol addressing this gap. The comparable: Invariant Labs was founded in 2024 and acquired by Snyk in June 2025 for MCP security work -- in under one year, with no outside funding."),

    ("How does monetization work?",
     "Three revenue streams: (1) Self-serve SaaS API via agentsign.dev with tiered pricing ($29-$999/month) for passport issuance, revocation, and trust management. (2) OEM licensing to MCP gateway providers like Composio, Arcade, and TrueFoundry ($50-200K/year) who embed MCPS into their platforms. (3) Enterprise on-prem Trust Authority deployment for organizations requiring air-gapped or sovereign infrastructure."),

    ("What is the competitive landscape?",
     "Snyk/Invariant Labs: behavioral analysis and runtime detection, no cryptographic layer -- they detect attacks, MCPS prevents them. Complementary. Zenity (M12 invested, $59.5M raised): AI agent governance and posture management -- different layer entirely, focused on policy not protocol. No other project has an IETF submission, a patent application, and a working zero-dependency implementation for cryptographic MCP security."),

    ("What traction exists today?",
     "npm package live (mcp-secure@1.0.4). IETF Internet-Draft published on Datatracker. OWASP engagement across AOS, AISVS, MCP Top 10, and LLM Top 10 projects. 34+ GitHub comments across OpenAI, Microsoft, Google, AWS, Docker, IBM, Block, and Cline repos. Michael Bargury (Zenity CTO, OWASP Agentic Security lead) responded positively. OpenSSF sandbox application submitted. SOC 2 mapping covering 23 Trust Service Criteria. 180 automated tests including 105 red team attack scenarios."),

    ("What is the acquisition comparable?",
     "Invariant Labs (ETH Zurich spin-out): founded 2024, acquired by Snyk June 2025 for their MCP security capabilities. Under one year from founding to exit, approximately 10 employees, no outside funding. They provide behavioral detection; MCPS provides cryptographic prevention. The approaches are complementary, but MCPS has stronger IP protection (patent + IETF) and covers a wider security surface (identity, signing, tool integrity, revocation, audit)."),
]

for q, a in acq_faqs:
    y -= 14
    c.setFillColor(AMBER)
    c.setFont("Helvetica-Bold", 7.5)
    c.drawString(MARGIN + 5, y, "Q:  " + q)
    y -= 10
    y = wrap_text(c, a, MARGIN + 10, y, "Helvetica", 6, CONTENT_W - 15, GRAY_600, 8)
    y -= 2

# === LINKS / RESOURCES BAR ===
y -= 12
draw_rounded_rect(c, MARGIN, y-36, CONTENT_W, 36, r=5, fill=NAVY, stroke=None)

c.setFillColor(WHITE)
c.setFont("Helvetica-Bold", 7)
c.drawString(MARGIN+12, y-12, "Links & Resources")

links = [
    ("Platform", "agentsign.dev"),
    ("npm", "npmjs.com/package/mcp-secure"),
    ("IETF Draft", "datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp"),
    ("GitHub", "github.com/razashariff/mcps"),
]
link_x = MARGIN + 12
for label, url in links:
    c.setFillColor(HexColor("#94a3b8"))
    c.setFont("Helvetica", 5.5)
    c.drawString(link_x, y-26, label + ":")
    lw = c.stringWidth(label + ":", "Helvetica", 5.5)
    c.setFillColor(HexColor("#60a5fa"))
    c.setFont("Helvetica", 5.5)
    c.drawString(link_x + lw + 4, y-26, url)
    link_x += lw + c.stringWidth(url, "Helvetica", 5.5) + 24

# === PAGE 2 FOOTER ===
c.setStrokeColor(GRAY_200)
c.line(MARGIN, 32, W-MARGIN, 32)
c.setFillColor(GRAY_500)
c.setFont("Helvetica", 6)
c.drawString(MARGIN, 20, "CyberSecAI Ltd  |  contact@agentsign.dev  |  Patent Pending (GB2604808.2)")
c.drawRightString(W-MARGIN, 20, "Page 2 of 2")

# Add clickable links
c.linkURL("https://agentsign.dev", (MARGIN+12, y-32, MARGIN+150, y-20))
c.linkURL("https://www.npmjs.com/package/mcp-secure", (MARGIN+160, y-32, MARGIN+300, y-20))
c.linkURL("https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp/", (MARGIN+310, y-32, W-MARGIN, y-20))

c.save()
print(f"PDF saved to: {OUTPUT}")
