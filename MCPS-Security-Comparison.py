#!/usr/bin/env python3
"""Generate MCPS Security Landscape Comparison PDF - Multi-page Professional Brief"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Paragraph
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
import os

OUTPUT = os.path.expanduser("~/Desktop/mcps/MCPS-Security-Landscape.pdf")

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
TEAL = HexColor("#0d9488")
LIGHT_TEAL = HexColor("#ccfbf1")

W, H = A4
MARGIN = 36
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

def draw_header(c, page_num, total_pages):
    # Top bar
    draw_rounded_rect(c, 0, H - 52, W, 52, r=0, fill=NAVY)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(MARGIN, H - 35, "MCPS Security Landscape")
    c.setFont("Helvetica", 8)
    c.setFillColor(GRAY_300)
    c.drawString(MARGIN, H - 48, "MCP Security Approaches Compared  |  CyberSecAI Ltd  |  Patent Pending GB2604808.2")
    c.drawRightString(W - MARGIN, H - 35, f"Page {page_num}/{total_pages}")
    c.drawRightString(W - MARGIN, H - 48, "CONFIDENTIAL")

def draw_footer(c):
    c.setFont("Helvetica", 6.5)
    c.setFillColor(GRAY_500)
    c.drawString(MARGIN, 18, "CyberSecAI Ltd  |  agentsign.dev  |  IETF: draft-sharif-mcps-secure-mcp  |  Patent Pending GB2604808.2")
    c.drawRightString(W - MARGIN, 18, "March 2026")

def new_page(c, page_num, total_pages):
    c.showPage()
    draw_header(c, page_num, total_pages)
    draw_footer(c)
    return H - 75

# ─── PAGE 1: Title + Executive Summary + Comparison Matrix ─────────────────

def draw_page1(c):
    draw_header(c, 1, 5)
    draw_footer(c)
    y = H - 75

    # Title section
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(NAVY)
    c.drawString(MARGIN, y, "MCP Security Landscape")
    y -= 18
    c.setFont("Helvetica", 10)
    c.setFillColor(GRAY_600)
    c.drawString(MARGIN, y, "A comprehensive comparison of every approach to securing the Model Context Protocol")
    y -= 28

    # Executive summary box
    draw_rounded_rect(c, MARGIN, y - 72, CONTENT_W, 72, r=8, fill=SKY, stroke=BLUE, stroke_width=0.5)
    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(BLUE)
    c.drawString(MARGIN + 12, y - 14, "EXECUTIVE SUMMARY")
    c.setFont("Helvetica", 7.5)
    c.setFillColor(GRAY_800)
    lines = [
        "MCP (Model Context Protocol) has 80,000+ GitHub stars and adoption by Anthropic, OpenAI, Google, and Microsoft -- but zero built-in security layer.",
        "Current approaches (OAuth 2.0, JWT, API keys) were designed for human-to-server auth, not agent-to-agent. They lack per-message signing,",
        "agent identity, tool integrity verification, and real-time revocation. CVE-2025-6514 (CVSS 9.6) affected 437K developers. 38% of MCP servers",
        "have zero authentication. MCPS is the only approach providing cryptographic identity + per-message signing at the protocol level.",
    ]
    ty = y - 28
    for line in lines:
        c.drawString(MARGIN + 12, ty, line)
        ty -= 11
    y -= 88

    # ── Comparison Matrix ──
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(NAVY)
    c.drawString(MARGIN, y, "Security Properties Comparison")
    y -= 6

    headers = ["Approach", "Identity", "Msg Integrity", "Replay Prot.", "Revocation", "Tool Verify", "Agent-Native", "Infra Needed"]
    col_widths = [115, 55, 63, 60, 58, 58, 60, 55]
    row_h = 17
    hdr_h = 20

    # Header row
    y -= hdr_h
    x = MARGIN
    draw_rounded_rect(c, MARGIN, y, CONTENT_W, hdr_h, r=0, fill=NAVY)
    c.setFont("Helvetica-Bold", 6.5)
    c.setFillColor(WHITE)
    for i, h in enumerate(headers):
        c.drawString(x + 4, y + 6, h)
        x += col_widths[i]

    # Data rows
    rows = [
        ["OAuth 2.0 + DCR", "User only", "Token sig", "Short-lived", "Token revoke", "None", "No (browser)", "AuthZ server, PKI"],
        ["OAuth + DPoP (RFC 9449)", "User + key", "DPoP JWT", "JWT-bound", "Token revoke", "None", "Partial", "AuthZ + DPoP"],
        ["JWT Bearer Tokens", "Claims", "HMAC/RSA", "None", "Until expiry", "None", "Yes", "JWT issuer"],
        ["mTLS", "Cert-based", "TLS layer", "TLS seq", "CRL/OCSP", "None", "Yes", "PKI + CA + CRL"],
        ["API Keys", "Shared secret", "None", "None", "DB delete", "None", "Yes", "Key DB only"],
        ["AWS SigV4", "IAM creds", "Request sig", "Timestamp", "IAM rotate", "None", "Yes", "AWS account"],
        ["Runtime Scanning", "None", "None", "None", "N/A", "Behavioral", "Yes", "Proxy + ML"],
        ["MCP Gateways", "Delegated", "Proxy layer", "Proxy layer", "Gateway", "None", "Yes", "K8s + proxy"],
        ["Stytch isAgent", "Heuristic", "None", "None", "N/A", "None", "Yes", "Stytch API"],
        ["DNS + DANE", "Server only", "DNSSEC", "None", "None", "None", "Yes", "DNSSEC infra"],
    ]

    mcps_row = ["MCPS (MCP Secure)", "ECDSA P-256", "Per-message", "Nonce+TS", "Real-time TA", "Hash-pinned", "Yes", "Zero deps"]

    colors_alt = [GRAY_50, WHITE]
    c.setFont("Helvetica", 6.5)

    for idx, row in enumerate(rows):
        y -= row_h
        bg = colors_alt[idx % 2]
        draw_rounded_rect(c, MARGIN, y, CONTENT_W, row_h, r=0, fill=bg)
        c.setFillColor(GRAY_800)
        x = MARGIN
        for i, val in enumerate(row):
            # Color code weaknesses
            if val in ["None", "N/A", "No (browser)", "Heuristic", "Shared secret", "Until expiry", "User only", "Server only", "Behavioral", "Delegated", "Partial"]:
                c.setFillColor(RED)
            elif val in ["Short-lived", "Token sig", "Claims", "Token revoke", "DB delete", "Proxy layer", "DPoP JWT", "JWT-bound", "Gateway"]:
                c.setFillColor(AMBER)
            else:
                c.setFillColor(GRAY_800)
            c.setFont("Helvetica", 6.2)
            c.drawString(x + 4, y + 5, val)
            x += col_widths[i]

    # MCPS row (highlighted)
    y -= row_h + 2
    draw_rounded_rect(c, MARGIN, y, CONTENT_W, row_h + 2, r=4, fill=HexColor("#ecfdf5"), stroke=GREEN, stroke_width=1)
    x = MARGIN
    for i, val in enumerate(mcps_row):
        c.setFont("Helvetica-Bold", 6.5)
        c.setFillColor(GREEN)
        c.drawString(x + 4, y + 6, val)
        x += col_widths[i]

    y -= 16
    c.setFont("Helvetica", 6)
    c.setFillColor(GRAY_500)
    c.drawString(MARGIN, y, "Red = missing/weak  |  Amber = partial  |  Green = strong  |  TA = Trust Authority  |  TS = Timestamp")
    y -= 22

    # Key insight box
    draw_rounded_rect(c, MARGIN, y - 48, CONTENT_W, 48, r=6, fill=LIGHT_GREEN, stroke=GREEN, stroke_width=0.5)
    c.setFont("Helvetica-Bold", 8)
    c.setFillColor(GREEN)
    c.drawString(MARGIN + 10, y - 14, "KEY INSIGHT")
    c.setFont("Helvetica", 7)
    c.setFillColor(GRAY_800)
    c.drawString(MARGIN + 10, y - 27, "MCPS is the only approach that provides all six security properties at the protocol level with zero infrastructure dependencies.")
    c.drawString(MARGIN + 10, y - 39, "Every other approach requires external infrastructure (AuthZ servers, PKI, proxies, cloud accounts) and leaves gaps in agent identity or message integrity.")


# ─── PAGE 2: Deep Dive - OAuth, DPoP, JWT, mTLS ───────────────────────────

def draw_page2(c):
    y = new_page(c, 2, 5)

    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(NAVY)
    c.drawString(MARGIN, y, "Current Approaches: Deep Dive")
    y -= 22

    approaches = [
        {
            "name": "OAuth 2.0 + Dynamic Client Registration",
            "color": BLUE, "bg": SKY,
            "what": "MCP spec's recommended auth. Authorization servers issue access tokens after user authentication. DCR (RFC 7591) allows clients to register without manual setup.",
            "provides": ["User authentication via authorization server", "Token-based access control with scopes", "Refresh token rotation for revocation", "RFC 8707 resource binding (audience validation)"],
            "missing": ["No agent-to-agent identity (designed for humans)", "Requires browser redirect (breaks headless/voice agents)", "No per-message signing (token theft = full compromise)", "No tool integrity verification"],
            "infra": "Authorization server (Auth0/Keycloak/Okta) + PKCE + browser flow + .well-known endpoints",
            "evidence": "CVE-2025-6514 (CVSS 9.6): mcp-remote OAuth proxy RCE, 437K downloads. 38% of servers have zero auth. VS Code violates RFC 8707 (issue #261364)."
        },
        {
            "name": "DPoP (Demonstration of Proof-of-Possession) - RFC 9449",
            "color": PURPLE, "bg": LIGHT_PURPLE,
            "what": "Client signs a JWT with their private key on every request, proving token possession. Authorization server issues DPoP-bound tokens that require the matching key.",
            "provides": ["Token binding to client key pair", "Stolen tokens useless without private key", "Replay protection via method+URI+timestamp in JWT", "Non-repudiation of requests"],
            "missing": ["No server-to-client authentication (one-way)", "No tool integrity or tamper detection", "No agent passport/identity system", "Requires OAuth infrastructure underneath"],
            "infra": "OAuth AuthZ server with DPoP support + client key pair generation + DPoP header injection in HTTP client",
            "evidence": "RFC 9449 finalized but adoption is slow. Most MCP servers don't support DPoP yet. Adds to OAuth complexity without solving agent identity."
        },
        {
            "name": "JWT Bearer Tokens",
            "color": AMBER, "bg": LIGHT_AMBER,
            "what": "Server issues signed JWT with identity claims, scopes, and expiration. Client sends in Authorization header. Server validates signature and claims.",
            "provides": ["Self-contained identity claims", "HMAC/RSA signature prevents tampering", "Stateless (no server session needed)", "Expiration via exp claim"],
            "missing": ["No replay protection (token reusable until expiry)", "No proof of possession (stolen token = full access)", "No real-time revocation (valid until exp)", "No tool integrity verification"],
            "infra": "JWT issuer service + public key distribution + HTTPS (tokens in headers must be encrypted in transit)",
            "evidence": "Algorithm confusion attacks documented. Many servers accept expired tokens. Long-lived tokens (30+ days) maximise damage window."
        },
        {
            "name": "mTLS (Mutual TLS)",
            "color": TEAL, "bg": LIGHT_TEAL,
            "what": "Both client and server present X.509 certificates during TLS handshake. Bidirectional authentication at the transport layer.",
            "provides": ["Mutual authentication (both parties proven)", "All traffic encrypted and integrity-protected", "Certificate-bound tokens possible", "Transport-level security"],
            "missing": ["No user-level authorization (only transport identity)", "No tool integrity or per-message signing", "No agent passport or trust levels", "Requires PKI infrastructure with CA, CRL/OCSP"],
            "infra": "Certificate Authority + cert issuance pipeline + CRL/OCSP infrastructure + cert rotation process + secure storage on all clients",
            "evidence": "Most MCP servers don't support mTLS. Certificate management is operationally complex. No MCP client ships with mTLS support out of the box."
        },
    ]

    for a in approaches:
        if y < 110:
            y = new_page(c, 2, 5)

        box_h = 128
        draw_rounded_rect(c, MARGIN, y - box_h, CONTENT_W, box_h, r=8, fill=a["bg"], stroke=a["color"], stroke_width=0.75)

        # Title
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(a["color"])
        c.drawString(MARGIN + 10, y - 14, a["name"])

        # What
        c.setFont("Helvetica", 6.5)
        c.setFillColor(GRAY_800)
        c.drawString(MARGIN + 10, y - 26, a["what"][:120])
        if len(a["what"]) > 120:
            c.drawString(MARGIN + 10, y - 35, a["what"][120:])

        # Two columns: Provides | Missing
        col_x1 = MARGIN + 10
        col_x2 = MARGIN + CONTENT_W / 2 + 5

        c.setFont("Helvetica-Bold", 6.5)
        c.setFillColor(GREEN)
        c.drawString(col_x1, y - 48, "PROVIDES")
        c.setFillColor(RED)
        c.drawString(col_x2, y - 48, "MISSING")

        c.setFont("Helvetica", 6)
        for i, item in enumerate(a["provides"][:4]):
            c.setFillColor(GRAY_700)
            c.drawString(col_x1, y - 58 - i * 9, f"+ {item}")
        for i, item in enumerate(a["missing"][:4]):
            c.setFillColor(GRAY_700)
            c.drawString(col_x2, y - 58 - i * 9, f"- {item}")

        # Infrastructure
        c.setFont("Helvetica-Bold", 6)
        c.setFillColor(AMBER)
        c.drawString(MARGIN + 10, y - 98, "INFRASTRUCTURE:")
        c.setFont("Helvetica", 6)
        c.setFillColor(GRAY_700)
        c.drawString(MARGIN + 80, y - 98, a["infra"][:95])

        # Evidence
        c.setFont("Helvetica-Bold", 6)
        c.setFillColor(RED)
        c.drawString(MARGIN + 10, y - 109, "EVIDENCE:")
        c.setFont("Helvetica", 5.8)
        c.setFillColor(GRAY_600)
        c.drawString(MARGIN + 60, y - 109, a["evidence"][:110])
        if len(a["evidence"]) > 110:
            c.drawString(MARGIN + 60, y - 118, a["evidence"][110:220])

        y -= box_h + 10


# ─── PAGE 3: API Keys, SigV4, Runtime, Gateways, Stytch ──────────────────

def draw_page3(c):
    y = new_page(c, 3, 5)

    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(NAVY)
    c.drawString(MARGIN, y, "Other Approaches")
    y -= 20

    approaches = [
        {
            "name": "API Keys / Static Bearer Tokens",
            "provides": "Basic identity (key = client). Instant revocation (delete from DB). Simple to implement.",
            "missing": "No proof of possession. No expiration. No scoping. No replay protection. No audit trail of who used what.",
            "infra": "Key database + HTTPS",
            "verdict": "WEAKEST", "verdict_color": RED,
            "evidence": "OWASP MCP01: Token Mismanagement. 13,000+ MCP servers on GitHub, many with hard-coded keys in source."
        },
        {
            "name": "AWS SigV4 (Signature Version 4)",
            "provides": "Per-request signing (method+URI+body hash). Replay protection via timestamp. IAM auto-rotation. Strong integrity.",
            "missing": "AWS-only (not general purpose). Requires special proxy for standard MCP clients. No agent passport. No tool verification.",
            "infra": "AWS account + IAM + MCP proxy (github.com/aws/mcp-proxy-for-aws) + secure credential storage",
            "verdict": "STRONG BUT VENDOR-LOCKED", "verdict_color": AMBER,
            "evidence": "Only works with AWS services. Standard MCP clients need proxy adapter. Clock skew causes auth failures."
        },
        {
            "name": "Runtime Scanning (Snyk/Invariant, Behavioral Analysis)",
            "provides": "Threat detection (prompt injection, tool poisoning, exfiltration). Real-time blocking. ML anomaly detection. Audit logging.",
            "missing": "No authentication. No identity. No token integrity. Heuristic-based (false positives/negatives). Cannot prevent, only detect.",
            "infra": "Proxy/gateway service + ML models + policy engine + log aggregation + dashboard",
            "verdict": "COMPLEMENTARY (detect, not prevent)", "verdict_color": AMBER,
            "evidence": "Snyk acquired Invariant Labs (Jun 2025). Detects attacks but cannot prove agent identity. Needs identity layer underneath."
        },
        {
            "name": "MCP Gateway Proxies (Docker, AgentGateway, Microsoft)",
            "provides": "Centralised auth enforcement. Credential isolation. Least privilege per tool. Secret scanning. Container verification.",
            "missing": "Single point of failure. No cryptographic binding. Gateway compromise = total compromise. No agent identity.",
            "infra": "Docker/K8s cluster + gateway service + RBAC database + secret management (Vault) + container registry",
            "verdict": "INFRASTRUCTURE-HEAVY", "verdict_color": AMBER,
            "evidence": "Multiple components to secure. Adds proxy latency. Gateway itself needs securing. Operational overhead significant."
        },
        {
            "name": "Stytch isAgent (Agent Detection)",
            "provides": "Heuristic agent identification (User-Agent, TLS fingerprint). Routing agents vs humans. Rate limiting by agent type.",
            "missing": "Not cryptographic (easily spoofed). Best-effort heuristics. No auth, no integrity, no signing. Detection only.",
            "infra": "Stytch API account + @stytch/is-agent npm package + backend routing logic",
            "verdict": "ROUTING ONLY, NOT SECURITY", "verdict_color": RED,
            "evidence": "Stytch explicitly states results are 'best-effort heuristics that may be incorrect'. User-Agent trivially spoofed."
        },
    ]

    for a in approaches:
        if y < 95:
            y = new_page(c, 3, 5)

        box_h = 82
        draw_rounded_rect(c, MARGIN, y - box_h, CONTENT_W, box_h, r=6, fill=GRAY_50, stroke=GRAY_200, stroke_width=0.5)

        c.setFont("Helvetica-Bold", 8.5)
        c.setFillColor(NAVY)
        c.drawString(MARGIN + 10, y - 13, a["name"])

        # Verdict badge
        c.setFont("Helvetica-Bold", 5.5)
        c.setFillColor(a["verdict_color"])
        vw = c.stringWidth(a["verdict"], "Helvetica-Bold", 5.5) + 10
        draw_rounded_rect(c, W - MARGIN - vw - 10, y - 17, vw, 12, r=3, fill=a["verdict_color"])
        c.setFillColor(WHITE)
        c.drawString(W - MARGIN - vw - 5, y - 14, a["verdict"])

        c.setFont("Helvetica", 6)
        c.setFillColor(GREEN)
        c.drawString(MARGIN + 10, y - 26, "PROVIDES: ")
        c.setFillColor(GRAY_700)
        c.drawString(MARGIN + 55, y - 26, a["provides"][:105])
        if len(a["provides"]) > 105:
            c.drawString(MARGIN + 55, y - 34, a["provides"][105:210])

        c.setFillColor(RED)
        c.drawString(MARGIN + 10, y - 44, "MISSING: ")
        c.setFillColor(GRAY_700)
        c.drawString(MARGIN + 50, y - 44, a["missing"][:108])
        if len(a["missing"]) > 108:
            c.drawString(MARGIN + 50, y - 52, a["missing"][108:216])

        c.setFillColor(AMBER)
        c.drawString(MARGIN + 10, y - 62, "INFRA: ")
        c.setFillColor(GRAY_600)
        c.drawString(MARGIN + 40, y - 62, a["infra"][:115])

        c.setFont("Helvetica-Oblique", 5.5)
        c.setFillColor(GRAY_500)
        c.drawString(MARGIN + 10, y - 74, a["evidence"][:130])

        y -= box_h + 8


# ─── PAGE 4: MCPS Deep Dive ──────────────────────────────────────────────

def draw_page4(c):
    y = new_page(c, 4, 5)

    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(GREEN)
    c.drawString(MARGIN, y, "MCPS (MCP Secure) -- The Protocol-Level Solution")
    y -= 16
    c.setFont("Helvetica", 8)
    c.setFillColor(GRAY_600)
    c.drawString(MARGIN, y, "IETF Internet-Draft: draft-sharif-mcps-secure-mcp  |  npm: mcp-secure  |  pip: langchain-mcps  |  Patent Pending GB2604808.2")
    y -= 22

    # What MCPS does differently
    draw_rounded_rect(c, MARGIN, y - 65, CONTENT_W, 65, r=8, fill=LIGHT_GREEN, stroke=GREEN, stroke_width=1)
    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(GREEN)
    c.drawString(MARGIN + 12, y - 14, "WHAT MAKES MCPS DIFFERENT")
    c.setFont("Helvetica", 7)
    c.setFillColor(GRAY_800)
    items = [
        "Every agent gets a cryptographic passport (ECDSA P-256 key pair + signed identity document)",
        "Every JSON-RPC message wrapped in a signed envelope (nonce + timestamp + SHA-256 hash + ECDSA signature)",
        "Every tool definition hash-pinned and signature-verified (rug pull detection)",
        "Trust levels L0 (self-signed) through L4 (audited) with real-time revocation via Trust Authority",
    ]
    ty = y - 28
    for item in items:
        c.drawString(MARGIN + 12, ty, f">> {item}")
        ty -= 11
    y -= 80

    # 6 security pillars
    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(NAVY)
    c.drawString(MARGIN, y, "Six Security Pillars")
    y -= 14

    pillars = [
        ("Agent Identity", "ECDSA P-256 passport per agent. Unforgeable. Self-contained. Works offline.", "OAuth: user identity only. API keys: shared secrets. Stytch: heuristic guessing."),
        ("Message Integrity", "Every message signed. Tamper any field = signature breaks instantly.", "JWT: token signed, message not. OAuth: no message signing. API keys: zero integrity."),
        ("Replay Protection", "Unique nonce + 5-min timestamp window per message. NonceStore blocks reuse.", "JWT: no replay protection. API keys: none. OAuth: only short-lived tokens."),
        ("Tool Verification", "signTool() / verifyTool() with SHA-256 hash pinning. Detects rug pulls.", "No other approach verifies tool definitions. All vulnerable to tool poisoning."),
        ("Real-time Revocation", "Trust Authority revokes compromised agents in seconds. Fail-closed.", "JWT: valid until exp (hours/days). API keys: DB delete. OAuth: token revoke only."),
        ("Audit Trail", "Structured events (accepted/rejected/replay/forgery) for SIEM. Per-message.", "Gateways log requests. Runtime scanners log threats. Neither log crypto verification."),
    ]

    for name, mcps_desc, others_desc in pillars:
        if y < 60:
            y = new_page(c, 4, 5)
        box_h = 42
        draw_rounded_rect(c, MARGIN, y - box_h, CONTENT_W, box_h, r=6, fill=GRAY_50, stroke=GREEN, stroke_width=0.5)
        c.setFont("Helvetica-Bold", 7.5)
        c.setFillColor(GREEN)
        c.drawString(MARGIN + 8, y - 12, name)
        c.setFont("Helvetica", 6)
        c.setFillColor(GRAY_800)
        c.drawString(MARGIN + 8, y - 23, f"MCPS: {mcps_desc}")
        c.setFillColor(GRAY_500)
        c.drawString(MARGIN + 8, y - 33, f"Others: {others_desc}")
        y -= box_h + 6

    y -= 8

    # Infrastructure comparison
    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(NAVY)
    c.drawString(MARGIN, y, "Infrastructure Requirements Compared")
    y -= 14

    infra = [
        ("MCPS", "npm install mcp-secure (zero deps, 44KB). That's it.", GREEN),
        ("OAuth 2.0", "Authorization server + PKCE + DCR + browser flow + .well-known endpoints + token store", RED),
        ("mTLS", "Certificate Authority + cert issuance + CRL/OCSP + rotation pipeline + secure storage", RED),
        ("DPoP + OAuth", "Everything OAuth needs PLUS DPoP-capable AuthZ server + client key management", RED),
        ("AWS SigV4", "AWS account + IAM roles + MCP proxy adapter + credential management", AMBER),
        ("MCP Gateways", "Docker/K8s cluster + gateway service + RBAC DB + Vault + container registry", RED),
        ("Runtime Scanning", "Proxy service + ML models + policy engine + log aggregation + dashboard", AMBER),
    ]

    for name, desc, color in infra:
        if y < 30:
            y = new_page(c, 4, 5)
        c.setFont("Helvetica-Bold", 6.5)
        c.setFillColor(color)
        c.drawString(MARGIN + 8, y, name)
        c.setFont("Helvetica", 6)
        c.setFillColor(GRAY_700)
        c.drawString(MARGIN + 95, y, desc[:100])
        y -= 12


# ─── PAGE 5: Evidence, OWASP, CVEs, Positioning ──────────────────────────

def draw_page5(c):
    y = new_page(c, 5, 5)

    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(NAVY)
    c.drawString(MARGIN, y, "Evidence Base & Positioning")
    y -= 22

    # Real-world incidents
    draw_rounded_rect(c, MARGIN, y - 88, CONTENT_W, 88, r=8, fill=LIGHT_RED, stroke=RED, stroke_width=0.75)
    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(RED)
    c.drawString(MARGIN + 10, y - 14, "REAL-WORLD MCP SECURITY INCIDENTS")
    c.setFont("Helvetica", 6.5)
    c.setFillColor(GRAY_800)
    incidents = [
        ("CVE-2025-6514 (CVSS 9.6)", "mcp-remote OAuth proxy RCE -- 437,000 downloads affected"),
        ("Smithery.ai Breach", "3,243 MCP servers exposed, API keys compromised via registry vulnerability"),
        ("Asana Cross-Tenant Leak", "1,000 customers exposed for 34 days via MCP integration"),
        ("postmark-mcp Backdoor", "First malicious MCP server -- BCC'd all emails to attacker silently"),
        ("CVE-2025-49596", "Anthropic MCP Inspector unauthenticated RCE"),
    ]
    ty = y - 28
    for name, desc in incidents:
        c.setFont("Helvetica-Bold", 6.5)
        c.setFillColor(RED)
        c.drawString(MARGIN + 10, ty, name)
        c.setFont("Helvetica", 6.5)
        c.setFillColor(GRAY_700)
        c.drawString(MARGIN + 150, ty, desc)
        ty -= 12
    y -= 102

    # OWASP alignment
    draw_rounded_rect(c, MARGIN, y - 75, CONTENT_W, 75, r=8, fill=LIGHT_AMBER, stroke=AMBER, stroke_width=0.75)
    c.setFont("Helvetica-Bold", 9)
    c.setFillColor(AMBER)
    c.drawString(MARGIN + 10, y - 14, "OWASP ALIGNMENT")
    c.setFont("Helvetica", 6.5)
    c.setFillColor(GRAY_800)

    owasp = [
        "OWASP MCP Top 10: MCPS mitigates 8/10 risks (MCP01 Token Mgmt, MCP04 Supply Chain, MCP07 Auth, + 5 more)",
        "OWASP Agentic AI Top 10: Addresses ASI03 (Agent Identity), ASI05 (Insufficient Access Controls), ASI07 (Multi-Agent Trust)",
        "SOC 2: Maps to 23 Trust Service Criteria across Security, Processing Integrity, Confidentiality, Availability",
        "No other MCP security approach has published OWASP, SOC 2, or IETF alignment documentation",
    ]
    ty = y - 28
    for item in owasp:
        c.drawString(MARGIN + 10, ty, item)
        ty -= 11
    y -= 90

    # Why MCPS is positioned above
    c.setFont("Helvetica-Bold", 11)
    c.setFillColor(NAVY)
    c.drawString(MARGIN, y, "Why MCPS Is Positioned Above Current Implementations")
    y -= 16

    reasons = [
        ("Protocol-level, not infrastructure-level", "MCPS operates inside the MCP message, not around it. No proxy, no gateway, no external service required."),
        ("Agent-native by design", "Built for agent-to-agent and agent-to-server. Not retrofitted human auth (OAuth) forced onto agents."),
        ("Zero dependencies", "npm install mcp-secure. 44KB. Pure Node.js crypto. No AuthZ server, no PKI, no cloud account, no K8s cluster."),
        ("Cryptographic guarantees", "ECDSA P-256 signatures are mathematically unforgeable. Not heuristics (Stytch), not shared secrets (API keys)."),
        ("Tool integrity (unique to MCPS)", "No other approach verifies tool definitions. signTool()/verifyTool() with SHA-256 hash pinning detects rug pulls."),
        ("Complementary, not competing", "MCPS works WITH OAuth, gateways, and runtime scanning. It adds the identity layer they all need underneath."),
        ("Standards-track", "IETF Internet-Draft published. Patent pending. 180 security tests. Cross-platform (Node.js + Python)."),
    ]

    for title, desc in reasons:
        if y < 40:
            y = new_page(c, 5, 5)
        c.setFont("Helvetica-Bold", 7)
        c.setFillColor(GREEN)
        c.drawString(MARGIN + 8, y, f">> {title}")
        c.setFont("Helvetica", 6.5)
        c.setFillColor(GRAY_700)
        c.drawString(MARGIN + 20, y - 10, desc[:120])
        if len(desc) > 120:
            c.drawString(MARGIN + 20, y - 19, desc[120:])
            y -= 10
        y -= 22

    # Bottom CTA
    y -= 10
    draw_rounded_rect(c, MARGIN, y - 42, CONTENT_W, 42, r=8, fill=NAVY)
    c.setFont("Helvetica-Bold", 10)
    c.setFillColor(WHITE)
    c.drawCentredString(W / 2, y - 16, "MCP is HTTP.  MCPS is HTTPS.  The protocol needs this.")
    c.setFont("Helvetica", 7)
    c.setFillColor(GRAY_300)
    c.drawCentredString(W / 2, y - 30, "agentsign.dev  |  npm: mcp-secure  |  pip: langchain-mcps  |  IETF: draft-sharif-mcps-secure-mcp  |  Live demo: mcps-demo.fly.dev")


# ─── GENERATE ─────────────────────────────────────────────────────────────

def main():
    c = canvas.Canvas(OUTPUT, pagesize=A4)
    c.setTitle("MCPS Security Landscape - CyberSecAI Ltd")
    c.setAuthor("CyberSecAI Ltd")
    c.setSubject("MCP Security Approaches Compared")

    draw_page1(c)
    draw_page2(c)
    draw_page3(c)
    draw_page4(c)
    draw_page5(c)

    c.save()
    print(f"Generated: {OUTPUT}")
    print(f"Size: {os.path.getsize(OUTPUT):,} bytes")

if __name__ == "__main__":
    main()
