"""
Web3User Permission Lab — Presentation Generator
Generates Web3User-TECH-Funding-Pitch-Deck.pptx in 16:9 widescreen format
with dark executive styling, custom typography, cards, badges, and live screenshot.
Fully audited, evidence-grounded, and reconciled with all technical and statistical baselines.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# Initialize Presentation
prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)
blank_layout = prs.slide_layouts[6]

# Brand Color Palette
COLOR_BG = RGBColor(11, 18, 32)         # #0B1220 Deep Navy
COLOR_PANEL = RGBColor(17, 29, 48)      # #111D30 Card Background
COLOR_PANEL_ALT = RGBColor(14, 25, 42)  # Alternate Card Background
COLOR_LINE = RGBColor(38, 55, 82)       # #263752 Border Line
COLOR_TEXT = RGBColor(238, 244, 255)    # #EEF4FF High Contrast Text
COLOR_MUTED = RGBColor(167, 182, 204)   # #A7B6CC Subdued Text
COLOR_CYAN = RGBColor(113, 226, 208)    # #71E2D0 Primary Accent
COLOR_BLUE = RGBColor(137, 180, 255)    # #89B4FF Secondary Blue
COLOR_GOLD = RGBColor(255, 212, 138)    # #FFD48A Warning / Milestone
COLOR_GREEN = RGBColor(124, 227, 139)   # #7CE38B Success / Verification
COLOR_RED = RGBColor(255, 107, 107)     # #FF6B6B Alert / Problem
COLOR_PURPLE = RGBColor(186, 147, 255)  # #BA93FF Enterprise Accent

FONT_TITLE = "Arial"
FONT_BODY = "Arial"

def set_slide_background(slide):
    """Fills slide background with deep navy color."""
    bg_shape = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height
    )
    bg_shape.fill.solid()
    bg_shape.fill.fore_color.rgb = COLOR_BG
    bg_shape.line.fill.background()
    return bg_shape

def add_header(slide, eyebrow_text, title_text, category_badge="WEB3USER PERMISSION LAB"):
    """Adds a standard executive header to a slide."""
    header_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.733), Inches(1.1))
    tf = header_box.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    # Eyebrow / Category
    p_eye = tf.paragraphs[0]
    p_eye.text = eyebrow_text.upper()
    p_eye.font.name = FONT_TITLE
    p_eye.font.size = Pt(9.5)
    p_eye.font.bold = True
    p_eye.font.color.rgb = COLOR_CYAN
    p_eye.space_after = Pt(2)

    # Main Title
    p_title = tf.add_paragraph()
    p_title.text = title_text
    p_title.font.name = FONT_TITLE
    p_title.font.size = Pt(20)
    p_title.font.bold = True
    p_title.font.color.rgb = COLOR_TEXT

    # Badge in top right
    badge_box = slide.shapes.add_textbox(Inches(9.5), Inches(0.4), Inches(3.0), Inches(0.35))
    btf = badge_box.text_frame
    btf.margin_right = btf.margin_top = 0
    bp = btf.paragraphs[0]
    bp.alignment = PP_ALIGN.RIGHT
    bp.text = category_badge
    bp.font.name = FONT_TITLE
    bp.font.size = Pt(8.5)
    bp.font.bold = True
    bp.font.color.rgb = COLOR_GOLD

def add_footer(slide, current_slide, total_slides=12):
    """Adds standard footer to slide."""
    footer_box = slide.shapes.add_textbox(Inches(0.8), Inches(7.0), Inches(11.733), Inches(0.35))
    tf = footer_box.text_frame
    tf.margin_left = tf.margin_top = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.text = f"Web3User Permission Lab · Syed's Enterprises (Solo Venture) · Founder: Syed Shahed · web3user.tech · Slide {current_slide} of {total_slides}"
    p.font.name = FONT_BODY
    p.font.size = Pt(8)
    p.font.color.rgb = COLOR_MUTED

def add_card(slide, left, top, width, height, title, body_lines, accent_color=COLOR_LINE, title_color=COLOR_TEXT):
    """Draws a themed card with title and bullet/body text."""
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_PANEL
    card.line.color.rgb = accent_color
    card.line.width = Pt(1)
    try:
        card.adjustments[0] = 0.04  # Subtle modern rounded corners (approx 8px radius)
    except Exception:
        pass

    tb = slide.shapes.add_textbox(left + Inches(0.25), top + Inches(0.22), width - Inches(0.5), height - Inches(0.44))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    if title:
        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.name = FONT_TITLE
        p_t.font.size = Pt(11.5)
        p_t.font.bold = True
        p_t.font.color.rgb = title_color
        p_t.space_after = Pt(5)
        first_line = True
    else:
        first_line = False

    for idx, line in enumerate(body_lines):
        if not title and idx == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()

        p.text = line
        p.font.name = FONT_BODY
        p.font.size = Pt(9.5)
        if line.startswith("•") or line.startswith("✓") or line.startswith("⏳"):
            p.font.color.rgb = COLOR_TEXT
            p.space_after = Pt(3)
        elif line.startswith("TAM:") or line.startswith("SAM:") or line.startswith("SOM:"):
            p.font.name = FONT_TITLE
            p.font.bold = True
            p.font.size = Pt(11)
            p.font.color.rgb = title_color
            p.space_after = Pt(2)
        elif line.startswith("ADDRESSABLE") or line.startswith("COMMERCIAL") or line.startswith("ADOPTION"):
            p.font.name = FONT_TITLE
            p.font.bold = True
            p.font.size = Pt(10.5)
            p.font.color.rgb = title_color
            p.space_after = Pt(2)
        else:
            p.font.color.rgb = COLOR_MUTED
            p.space_after = Pt(2)

# ==============================================================================
# SLIDE 1: COVER
# ==============================================================================
slide1 = prs.slides.add_slide(blank_layout)
set_slide_background(slide1)

# Cover Pill Badge
pill = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.1), Inches(4.5), Inches(0.4))
pill.fill.solid()
pill.fill.fore_color.rgb = RGBColor(18, 38, 58)
pill.line.color.rgb = COLOR_CYAN
pill.line.width = Pt(1)
try:
    pill.adjustments[0] = 0.5
except Exception:
    pass

p_tf = pill.text_frame
p_tf.margin_left = Inches(0.18)
p_tf.margin_top = Inches(0.06)
p_p = p_tf.paragraphs[0]
p_p.text = "◈ .TECH FUNDING APPLICATION · 24 NOV 2026"
p_p.font.name = FONT_TITLE
p_p.font.size = Pt(9)
p_p.font.bold = True
p_p.font.color.rgb = COLOR_CYAN

# Main Cover Title
tbox = slide1.shapes.add_textbox(Inches(0.8), Inches(1.8), Inches(11.5), Inches(2.2))
ttf = tbox.text_frame
ttf.word_wrap = True
ttf.margin_left = ttf.margin_top = 0
tp0 = ttf.paragraphs[0]
tp0.text = "Web3User Permission Lab"
tp0.font.name = FONT_TITLE
tp0.font.size = Pt(36)
tp0.font.bold = True
tp0.font.color.rgb = COLOR_TEXT
tp0.space_after = Pt(8)

tp1 = ttf.add_paragraph()
tp1.text = "Enterprise Off-Chain Permission & Authorization Governance for Web3"
tp1.font.name = FONT_TITLE
tp1.font.size = Pt(18)
tp1.font.bold = True
tp1.font.color.rgb = COLOR_BLUE
tp1.space_after = Pt(10)

tp2 = ttf.add_paragraph()
tp2.text = "A deterministic, policy-driven authorization SDK establishing cryptographic guardrails, cumulative spending budgets, and Cloud KMS signing before transactions reach the blockchain."
tp2.font.name = FONT_BODY
tp2.font.size = Pt(12)
tp2.font.color.rgb = COLOR_MUTED

# 3 Cover Highlight Cards
c_y = Inches(4.3)
c_w = Inches(3.64)
c_h = Inches(1.8)

add_card(slide1, Inches(0.8), c_y, c_w, c_h, "FOUNDER & ENTITY", [
    "• Founder: Syed Shahed",
    "• Entity: Syed's Enterprises (Solo Venture)",
    "• Organization: syedsenterprises.org",
    "• Contact: info@syedsenterprises.org"
], COLOR_LINE, COLOR_CYAN)

add_card(slide1, Inches(4.84), c_y, c_w, c_h, "VERIFIED METRICS", [
    "• 806 / 806 Passing Tests (39 Files)",
    "• FN-SEC-01 Cloud KMS Adapters Verified",
    "• Pure Consensus Reducer Audited",
    "• Multi-Process Concurrency Tested"
], COLOR_LINE, COLOR_GREEN)

add_card(slide1, Inches(8.88), c_y, c_w, c_h, "PUBLIC URLS", [
    "• Production: web3user.tech",
    "• Documentation: docs.web3user.tech",
    "• Interactive Demo: web3user.tech/#demo",
    "• Cloudflare Worker: super-tree-7537"
], COLOR_LINE, COLOR_GOLD)

add_footer(slide1, 1)

# ==============================================================================
# SLIDE 2: THE PROBLEM
# ==============================================================================
slide2 = prs.slides.add_slide(blank_layout)
set_slide_background(slide2)
add_header(slide2, "Industry Threat Landscape & Market Failure", "The All-or-Nothing Private Key Dilemma")

# Big Stat Callout Banner
stat_banner = slide2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.55), Inches(11.733), Inches(1.3))
stat_banner.fill.solid()
stat_banner.fill.fore_color.rgb = RGBColor(30, 20, 25)
stat_banner.line.color.rgb = COLOR_RED
stat_banner.line.width = Pt(1)

sb_tf = stat_banner.text_frame
sb_tf.margin_left = Inches(0.25)
sb_tf.margin_top = Inches(0.16)
sb_p0 = sb_tf.paragraphs[0]
sb_p0.text = "76% of Crypto Hacks ($2.2B) Stolen via Key & Infrastructure Attacks (TRM Labs)"
sb_p0.font.name = FONT_TITLE
sb_p0.font.size = Pt(15)
sb_p0.font.bold = True
sb_p0.font.color.rgb = COLOR_RED

sb_p1 = sb_tf.add_paragraph()
sb_p1.text = "TRM Labs recorded $2.87B stolen across 2025 hacks/exploits, with 76% from private key and infrastructure theft. Across all theft vectors, Chainalysis recorded >$3.4B stolen in 2025, with 158,000 individual wallet compromise incidents affecting >=80,000 unique victims. Security failures stem predominantly from credential and key exposure."
sb_p1.font.name = FONT_BODY
sb_p1.font.size = Pt(9.5)
sb_p1.font.color.rgb = COLOR_MUTED

# 3 Problem Dimension Cards
c_y = Inches(3.1)
c_w = Inches(3.64)
c_h = Inches(3.55)

add_card(slide2, Inches(0.8), c_y, c_w, c_h, "1. Unconstrained Authority", [
    "• Absolute Power: Possessing a private key conveys 100% unilateral authority over all assets in an account.",
    "• Catastrophic Blast Radius: If an automated agent, worker script, or API key leaks, the entire treasury is drained instantly.",
    "• No Role Boundaries: Web3 keys lack standard enterprise IAM principles (least-privilege, spending caps, or time bounds)."
], COLOR_LINE, COLOR_RED)

add_card(slide2, Inches(4.84), c_y, c_w, c_h, "2. Blind Signing & Calldata Exploits", [
    "• Opaque Calldata: Automated bots and backend signers execute binary calldata without semantic inspection.",
    "• 158,000 Wallet Compromises: Chainalysis recorded 158K individual compromise incidents in 2025 affecting >=80,000 unique victims across all theft vectors.",
    "• Cumulative Spend Leakage: Systems lack native state tracking of prior transactions across hourly or daily windows."
], COLOR_LINE, COLOR_RED)

add_card(slide2, Inches(8.88), c_y, c_w, c_h, "3. On-Chain Multisig Operational Limits", [
    "• Gas & Latency: Every multisig action (e.g. Safe) requires on-chain execution fees and block confirmation delay.",
    "• Incompatible with Automation: Manual signing quorums cannot serve real-time AI agents or high-frequency payouts.",
    "• Missing Off-Chain Layer: Web3 has lacked a programmable, pre-execution authorization firewall."
], COLOR_LINE, COLOR_RED)

add_footer(slide2, 2)

# ==============================================================================
# SLIDE 3: THE SOLUTION
# ==============================================================================
slide3 = prs.slides.add_slide(blank_layout)
set_slide_background(slide3)
add_header(slide3, "The Web3User Solution", "Deterministic Off-Chain Policy Governance")

# Hero statement
sol_box = slide3.shapes.add_textbox(Inches(0.8), Inches(1.55), Inches(11.733), Inches(0.75))
s_tf = sol_box.text_frame
s_tf.margin_left = s_tf.margin_top = 0
s_p = s_tf.paragraphs[0]
s_p.text = "A programmable cryptographic authorization firewall placed between candidate transactions and signing keys."
s_p.font.name = FONT_TITLE
s_p.font.size = Pt(14)
s_p.font.bold = True
s_p.font.color.rgb = COLOR_CYAN

# 4 Core Solution Pillars
p_w = Inches(2.78)
p_h = Inches(4.3)
p_y = Inches(2.4)

add_card(slide3, Inches(0.8), p_y, p_w, p_h, "Deterministic Rules", [
    "• Semantic Calldata Parsing: Decodes ERC-20 selector (0xa9059cbb), recipient address, and amount.",
    "• Address Whitelisting: Strict target contract and recipient validation.",
    "• Zero Ambient Authority: Any unknown parameter fails closed to DENY immediately."
], COLOR_LINE, COLOR_CYAN)

add_card(slide3, Inches(3.78), p_y, p_w, p_h, "Cumulative Budgets", [
    "• Fixed Time Windows: UTC hourly and daily cumulative spending caps.",
    "• Prior Spend Tracking: Evaluates proposed amount + historical window spend against limits.",
    "• Leakage Prevention: Zero cross-window budget spillover or overflow."
], COLOR_LINE, COLOR_BLUE)

add_card(slide3, Inches(6.76), p_y, p_w, p_h, "Single-Use Replay Guard", [
    "• Single-Use State Tracking: Verifies that an authorization ID has not been previously consumed.",
    "• SQLite WAL Transactions: BEGIN IMMEDIATE write transactions isolate concurrent worker processes.",
    "• Multi-Process Concurrency: Tested under competing OS processes with non-spinning backoff.",
    "• Monotonic Clock: ClockGuard high-water mark tracking detects backward system clock adjustments."
], COLOR_LINE, COLOR_GREEN)

add_card(slide3, Inches(9.74), p_y, p_w, p_h, "Cloud KMS Signing", [
    "• Remote Key Isolation: Master keys reside in remote AWS KMS or GCP Cloud KMS.",
    "• Keys Never in RAM: Remote signing API returns only signatures; keys never touch app memory.",
    "• RFC 8410 Normalization: Translates ASN.1 DER to raw 64-byte Ed25519 signatures.",
    "• Verifiable Receipts: Generates signed cryptographic authorization envelopes."
], COLOR_LINE, COLOR_PURPLE)

add_footer(slide3, 3)

# ==============================================================================
# SLIDE 4: THE PRODUCT
# ==============================================================================
slide4 = prs.slides.add_slide(blank_layout)
set_slide_background(slide4)
add_header(slide4, "Product Capabilities & Live Demonstration", "Developer SDK & In-Browser Policy Playground")

# Left Column: Product Capabilities (Width 5.5 inches)
p_left = Inches(0.8)
p_top = Inches(1.6)
p_width = Inches(5.6)
p_height = Inches(5.1)

add_card(slide4, p_left, p_top, p_width, p_height, "Web3User Permission Lab Architecture", [
    "• TypeScript Developer SDK: Lightweight, embeddable Node.js library (>=22.13.0) with zero external evaluation dependencies.",
    "• Live In-Browser Evaluator: Pure client-side JavaScript engine running at web3user.tech/#demo demonstrating core policy evaluation logic.",
    "• 9 Scenario Presets: Evaluates compliant transfers (ALLOW), limit breaches (DENY), expired policies, admin revocations, budget exhaustion, and tampered calldata.",
    "• Real-Time Calldata Inspector: Decodes ERC-20 transfer ABI into selector, 32-byte padded address, and uint256 hexadecimal parameters.",
    "• Invariant Verification Checklist: Displays live validation checkmarks across 10 distinct policy safety rules.",
    "• Copyable Integration Snippets: Dynamically generates ready-to-use TypeScript code for Web3UserEngine.open, policy registration, and atomic consumption."
], COLOR_CYAN, COLOR_CYAN)

# Right Column: Screenshot from Live Production Site (Width 5.8 inches)
screenshot_path = "funding/application/assets/screenshot-playground.png"
if os.path.exists(screenshot_path):
    slide4.shapes.add_picture(screenshot_path, Inches(6.7), Inches(1.6), Inches(5.8), Inches(5.1))
else:
    add_card(slide4, Inches(6.7), Inches(1.6), Inches(5.8), Inches(5.1), "Live Policy Playground (web3user.tech)", [
        "[Product Screenshot: web3user.tech/#demo]",
        "• Live Decision Banner: Displays ALLOW / DENY in real-time.",
        "• 9 Representative Scenarios loaded via one-click presets.",
        "• Fully responsive dark UI matching production deployment."
    ], COLOR_LINE, COLOR_GOLD)

add_footer(slide4, 4)

# ==============================================================================
# SLIDE 5: HOW IT WORKS
# ==============================================================================
slide5 = prs.slides.add_slide(blank_layout)
set_slide_background(slide5)
add_header(slide5, "Operational Workflow", "The 5-Stage Cryptographic Authorization Pipeline")

# 5 Workflow Stage Boxes
stages = [
    ("Stage 1: Proposal", "Candidate Action Input", [
        "Client proposes transaction:",
        "• Target contract & recipient address",
        "• Claimed amount (uint256 base units)",
        "• Raw 68-byte calldata ABI",
        "• Governance Policy ID"
    ], COLOR_BLUE),
    ("Stage 2: Evaluation", "Deterministic Rule Engine", [
        "Pure policy evaluator executes checks:",
        "• Decodes selector (0xa9059cbb)",
        "• Validates recipient against whitelist",
        "• Checks temporal validity window",
        "• Sums cumulative window spend"
    ], COLOR_CYAN),
    ("Stage 3: Persistence", "SQLite WAL Transaction", [
        "Persistence layer enforces state invariants:",
        "• BEGIN IMMEDIATE write transaction",
        "• Single-use consumption check",
        "• Monotonic ClockGuard verification",
        "• Multi-process race protection"
    ], COLOR_GREEN),
    ("Stage 4: Signing", "Cloud KMS & Software Signers", [
        "Generates Ed25519 authorization artifact:",
        "• Dispatched to AWS KMS, GCP KMS, or local",
        "• Master keys remain in remote KMS",
        "• RFC 8410 DER-to-raw translation",
        "• Produces 64-byte Ed25519 signature"
    ], COLOR_PURPLE),
    ("Stage 5: Verification", "Signed Authorization Artifact", [
        "Signed envelope returned to caller:",
        "• Signed V3 authorization artifact",
        "• Verifiable off-chain against public key",
        "• Fails closed if tampered or replayed",
        "• Planned: On-chain paymaster & witness"
    ], COLOR_GOLD)
]

w_s = Inches(2.2)
h_s = Inches(4.9)
y_s = Inches(1.8)

for idx, (st_title, st_sub, st_lines, st_color) in enumerate(stages):
    x_s = Inches(0.8 + idx * 2.38)
    add_card(slide5, x_s, y_s, w_s, h_s, f"{st_title}\n{st_sub}", st_lines, st_color, st_color)

add_footer(slide5, 5)

# ==============================================================================
# SLIDE 6: TECHNOLOGY ARCHITECTURE
# ==============================================================================
slide6 = prs.slides.add_slide(blank_layout)
set_slide_background(slide6)
add_header(slide6, "Deep Defense Engineering", "Multi-Tiered Security & Persistence Architecture")

# 4 Architectural Grid Cards
w_g = Inches(5.66)
h_g = Inches(2.35)

add_card(slide6, Inches(0.8), Inches(1.7), w_g, h_g, "1. Storage & Persistence Engine", [
    "• SQLite WAL Journaling: node:sqlite with Write-Ahead Logging ensures zero corruption across restarts.",
    "• Immediate Write Transactions: BEGIN IMMEDIATE locks eliminate dirty reads and partial updates.",
    "• Process-Crash Recovery: Automatic rollback of uncommitted state confirmed under sudden process termination.",
    "• IPC Rendezvous Barriers: Simultaneous OS-level racing enforces exactly one ALLOW and deterministic DENYs."
], COLOR_LINE, COLOR_CYAN)

add_card(slide6, Inches(6.86), Inches(1.7), w_g, h_g, "2. Monotonic Clock & Temporal Defense", [
    "• ClockGuard Anchoring: High-water mark monotonic timestamp tracking prevents system clock manipulation.",
    "• Safe Subtraction Math: Subtraction-first validity window calculation prevents integer overflow up to MAX_SAFE_INTEGER.",
    "• Strict Expiration Boundaries: Strict rejection at exact second (nowSeconds >= expiresAtSeconds).",
    "• Cumulative Windows: Fixed UTC hourly (3,600s) and daily (86,400s) budget aggregation."
], COLOR_LINE, COLOR_BLUE)

add_card(slide6, Inches(0.8), Inches(4.35), w_g, h_g, "3. Cloud KMS Signers (FN-SEC-01)", [
    "• Native Cloud KMS Adapters: Production-ready AWS KMS and Google Cloud KMS adapters (verified in CI via mock service contracts).",
    "• RFC 8410 DER Normalization: Decodes ASN.1 SEQUENCE, r-value, and s-value into exact 64-byte raw signatures.",
    "• Remote Signing Security: Keys remain inside remote KMS during signing; never enter Node.js application memory.",
    "• Key Boundary Enforcement: Validates key activation windows, retirement deadlines, and revoked state."
], COLOR_LINE, COLOR_PURPLE)

add_card(slide6, Inches(6.86), Inches(4.35), w_g, h_g, "4. Consensus Reducer & Durable Witness", [
    "• Pure State Machine Reducer: Milestone 13-D Stage 2-B.1 deterministic in-memory reducer for consensus log events.",
    "• Single-Slot Idempotency: Duplicate action proposals are safely deduplicated without state corruption.",
    "• Atomic Epoch Transitions: Fences expired leaders and enforces monotonic consensus log indexes.",
    "• Planned Durability: etcd watch backpressure, durable PostgreSQL compaction & Raft cluster (Stages 2-B.2 & 3-A)."
], COLOR_LINE, COLOR_GOLD)

add_footer(slide6, 6)

# ==============================================================================
# SLIDE 7: SECURITY & VALIDATION EVIDENCE
# ==============================================================================
slide7 = prs.slides.add_slide(blank_layout)
set_slide_background(slide7)
add_header(slide7, "Empirical Validation & Testing", "806 Tests Passed Across 39 Test Files · 0 Failures")

# Top Metrics Banner
stat_banner7 = slide7.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.55), Inches(11.733), Inches(1.2))
stat_banner7.fill.solid()
stat_banner7.fill.fore_color.rgb = RGBColor(16, 35, 25)
stat_banner7.line.color.rgb = COLOR_GREEN
stat_banner7.line.width = Pt(1)

sb7_tf = stat_banner7.text_frame
sb7_tf.margin_left = Inches(0.25)
sb7_tf.margin_top = Inches(0.16)
sb7_p0 = sb7_tf.paragraphs[0]
sb7_p0.text = "100% Test Suite Pass Rate in Repository Regression Testing"
sb7_p0.font.name = FONT_TITLE
sb7_p0.font.size = Pt(15)
sb7_p0.font.bold = True
sb7_p0.font.color.rgb = COLOR_GREEN

sb7_p1 = sb7_tf.add_paragraph()
sb7_p1.text = "806 automated tests across 39 test files executing in Vitest (accepted in Milestone 13-D Stage 2-B.1.1). Rigorous regression testing demonstrating deterministic error handling across Linux, macOS, and Windows test environments."
sb7_p1.font.name = FONT_BODY
sb7_p1.font.size = Pt(9.5)
sb7_p1.font.color.rgb = COLOR_TEXT

# 3 Evidence Cards
c7_y = Inches(3.05)
c7_w = Inches(3.64)
c7_h = Inches(3.6)

add_card(slide7, Inches(0.8), c7_y, c7_w, c7_h, "Multi-Process Concurrency Testing", [
    "• Multi-Process IPC Barriers: Spawns competing child OS processes attempting simultaneous consumption.",
    "• Observed Outcome: Exactly 1 process receives ALLOW; competing processes receive domain-level DENY.",
    "• Replay Verification: Survives process restart and database reopen with single-use replay protection intact."
], COLOR_LINE, COLOR_CYAN)

add_card(slide7, Inches(4.84), c7_y, c7_w, c7_h, "Cloud KMS Adapter Audits (FN-SEC-01)", [
    "• Steps 1–4 Completed: Fully audited AWS KMS and GCP Cloud KMS signer adapters.",
    "• Mock Service Verification: Verified in CI against mock service contracts conforming to AWS and GCP API specifications.",
    "• Rigorous Adapter Tests: Tested RFC 8410 DER parsing, CRC32C checks, and fail-closed error handling (live cloud HSM audit is a planned roadmap step)."
], COLOR_LINE, COLOR_PURPLE)

add_card(slide7, Inches(8.88), c7_y, c7_w, c7_h, "Consensus Reducer Audit (Stage 2-B.1)", [
    "• Pure Reducer Function: Verified deterministic in-memory reducer handling 11 distinct consensus action types.",
    "• Atomic Epoch Boundaries: Verified leadership fencing and log index monotonicity.",
    "• Independent Audit Accepted: Zero open architectural defects in state-machine-types.ts & state-machine.ts (Stage 2-B.1.1)."
], COLOR_LINE, COLOR_GOLD)

add_footer(slide7, 7)

# ==============================================================================
# SLIDE 8: MARKET OPPORTUNITY & CUSTOMERS
# ==============================================================================
slide8 = prs.slides.add_slide(blank_layout)
set_slide_background(slide8)
add_header(slide8, "Market Sizing & Customer Segmentation", "Transparent Bottom-Up Developer Market Opportunity Model")

# 3 Market Size Stat Cards
m_y = Inches(1.55)
m_w = Inches(3.64)
m_h = Inches(1.4)

add_card(slide8, Inches(0.8), m_y, m_w, m_h, "ADDRESSABLE DEVELOPERS", [
    "• ~50k total active Web3 devs (Electric Capital).",
    "• ~25k eligible devs (transaction/agent/wallet subset).",
    "• ~3,500–5,000 teams (derivation: 5–7 devs/team)."
], COLOR_LINE, COLOR_BLUE)

add_card(slide8, Inches(4.84), m_y, m_w, m_h, "COMMERCIAL PRICING TIERS", [
    "• Tier 1 (Developer): $1,200/yr ($100/mo) Cloud KMS & SQLite.",
    "• Tier 2 (Growth): $6,000/yr ($500/mo) consensus state.",
    "• Tier 3 (Enterprise): $25,000/yr custom DSLs & compliance."
], COLOR_LINE, COLOR_CYAN)

add_card(slide8, Inches(8.88), m_y, m_w, m_h, "ADOPTION HYPOTHESES (ARR)", [
    "• Blended ACV Hypothesis: $6,000/yr across tiers.",
    "• Addressable Niche: ~$21M/yr (3,500 teams × $6k).",
    "• Phase 1 (50–122 teams): $151k–$600k ARR hypothesis.",
    "• Phase 2 (300–500 teams): $1.32M–$2.42M ARR hypothesis."
], COLOR_LINE, COLOR_GOLD)

# 4 Customer Segment Cards
cs_y = Inches(3.2)
cs_w = Inches(2.78)
cs_h = Inches(3.55)

add_card(slide8, Inches(0.8), cs_y, cs_w, cs_h, "Web3 Fintechs", [
    "• Profile: Payment gateways, neobanks, cross-border remittances.",
    "• Pain Point: Need strict spending ceilings and recipient whitelists before broadcasting.",
    "• Web3User Value: Deterministic limits and single-use replay protection."
], COLOR_LINE, COLOR_CYAN)

add_card(slide8, Inches(3.78), cs_y, cs_w, cs_h, "Autonomous AI Agents", [
    "• Profile: Autonomous bots executing on-chain trading and DeFi actions.",
    "• Pain Point: Granting agents master keys risks complete wallet liquidation.",
    "• Web3User Value: Bounded operational allowances without root key access."
], COLOR_LINE, COLOR_BLUE)

add_card(slide8, Inches(6.76), cs_y, cs_w, cs_h, "DAOs & Treasuries", [
    "• Profile: Corporate treasuries managing payroll and vendor payouts.",
    "• Pain Point: On-chain multisigs incur gas fees and latency for daily ops.",
    "• Web3User Value: Off-chain cumulative window budgets with zero gas."
], COLOR_LINE, COLOR_GREEN)

add_card(slide8, Inches(9.74), cs_y, cs_w, cs_h, "Account Abstraction", [
    "• Profile: Smart contract wallets (ERC-4337, ERC-7579).",
    "• Pain Point: Need robust off-chain policy engines for session keys.",
    "• Web3User Value: Verifiable Ed25519 authorization receipts."
], COLOR_LINE, COLOR_PURPLE)

add_footer(slide8, 8)

# ==============================================================================
# SLIDE 9: BUSINESS MODEL
# ==============================================================================
slide9 = prs.slides.add_slide(blank_layout)
set_slide_background(slide9)
add_header(slide9, "Commercialization & Distribution", "Open-Core Distribution & Tiered Enterprise Licensing")

# 4 Business Model Pillars
bm_y = Inches(1.7)
bm_w = Inches(2.78)
bm_h = Inches(5.0)

add_card(slide9, Inches(0.8), bm_y, bm_w, bm_h, "Community Edition (Implemented)\n(Free / Open Source)", [
    "• Target: Indie developers, hackathons, single-bot operators.",
    "• Core Features: Standalone Node.js SDK, local SQLite WAL persistence, software/KMS signing.",
    "• Objective: Drive rapid grassroots developer adoption and ecosystem familiarity.",
    "• Licensing: Open-source developer license."
], COLOR_LINE, COLOR_CYAN)

add_card(slide9, Inches(3.78), bm_y, bm_w, bm_h, "Enterprise License (Proposed)\n(Annual: $1.2k–$6k/yr)", [
    "• Target: Growth fintechs, payment processors, crypto hedge funds.",
    "• Core Features: Production adapters for AWS KMS and GCP Cloud KMS.",
    "• Clustering: Multi-node etcd and Raft consensus persistence adapters.",
    "• Support: Enterprise SLAs and prioritized security patches."
], COLOR_LINE, COLOR_BLUE)

add_card(slide9, Inches(6.76), bm_y, bm_w, bm_h, "Witness & Audit Cloud (Proposed)\n(Hosted SaaS / API)", [
    "• Target: Regulated institutions, auditors, and compliance officers.",
    "• Core Features: High-availability mTLS witness cluster recording authorization receipts.",
    "• Compliance: Tamper-evident audit logs and verifiable cryptographic proof of policy adherence.",
    "• Pricing: Usage-based per-receipt pricing."
], COLOR_LINE, COLOR_GREEN)

add_card(slide9, Inches(9.74), bm_y, bm_w, bm_h, "Enterprise Solutions (Proposed)\n(Custom Engagement: $25k+)", [
    "• Target: Tier-1 digital asset custodians and regulated financial institutions.",
    "• Offerings: Bespoke policy domain-specific language (DSL) development.",
    "• Architecture: Dedicated hardware HSM provisioning and custody integration support.",
    "• Model: High-value consulting and customized deployment retainers."
], COLOR_LINE, COLOR_GOLD)

add_footer(slide9, 9)

# ==============================================================================
# SLIDE 10: COMPETITIVE LANDSCAPE
# ==============================================================================
slide10 = prs.slides.add_slide(blank_layout)
set_slide_background(slide10)
add_header(slide10, "Competitive Landscape & Objective Positioning", "Objective Positioning Against Market Alternatives")

# 4 Competitor Analysis Cards
w_comp = Inches(5.66)
h_comp = Inches(2.35)

add_card(slide10, Inches(0.8), Inches(1.7), w_comp, h_comp, "Web3User vs. Enterprise Custody (Fireblocks)", [
    "• Fireblocks Model: Hosted institutional custody (Essentials plan at $999/mo for up to $1M quarterly volume, $249/mo embedded wallets, custom enterprise tiers).",
    "• Architectural Scope: Full-stack, cloud-hosted MPC custody solution designed for institutional treasury custody and asset movement.",
    "• Web3User Positioning: Embeddable Node.js SDK enabling developers to enforce pre-signing policies inside their own runtimes using their own Cloud KMS keys, without custodial lock-in."
], COLOR_LINE, COLOR_CYAN)

add_card(slide10, Inches(6.86), Inches(1.7), w_comp, h_comp, "Web3User vs. On-Chain Multisigs (Safe)", [
    "• Safe Model: On-chain EVM smart contracts requiring multi-signature threshold approvals directly on the blockchain.",
    "• Operational Fit: Safe provides on-chain consensus for treasury cold storage, but requiring an on-chain multisig transaction for every automated action incurs gas fees and block latency.",
    "• Web3User Positioning: Provides in-process off-chain policy evaluation and single-use replay protection that can serve as a complementary guard before submitting transactions to Safe."
], COLOR_LINE, COLOR_BLUE)

add_card(slide10, Inches(0.8), Inches(4.35), w_comp, h_comp, "Web3User vs. Embedded Enclave Wallets (Turnkey)", [
    "• Turnkey Model: Hosted wallet infrastructure leveraging AWS Nitro Enclaves and proprietary cloud quorum policies accessed via API.",
    "• Architectural Scope: Cloud-hosted, enclave-backed wallet infrastructure accessed via hosted SaaS API.",
    "• Web3User Positioning: Embeddable, self-hosted Node.js library where developers maintain control over local SQLite / PostgreSQL persistence and connect directly to their own Cloud KMS configurations."
], COLOR_LINE, COLOR_PURPLE)

add_card(slide10, Inches(6.86), Inches(4.35), w_comp, h_comp, "Web3User vs. Validator Signers (Cubist / CubeSigner)", [
    "• Cubist Model: Non-custodial hardware signing service utilizing remote HSMs, with built-in anti-slashing protections for proof-of-stake networks.",
    "• Architectural Scope: Focused heavily on validator key management, staking operations, and remote HSM-backed signing.",
    "• Web3User Positioning: Open-core developer library purpose-built for application-level ERC-20 transaction calldata parsing, address whitelisting, and cumulative hourly/daily budget windows."
], COLOR_LINE, COLOR_GOLD)

add_footer(slide10, 10)

# ==============================================================================
# SLIDE 11: FOUNDER & ROADMAP
# ==============================================================================
slide11 = prs.slides.add_slide(blank_layout)
set_slide_background(slide11)
add_header(slide11, "Leadership & Execution Roadmap", "Syed Shahed, Syed's Enterprises · Proven Track Record")

# Left Column: Founder Profile
f_left = Inches(0.8)
f_top = Inches(1.7)
f_width = Inches(4.5)
f_height = Inches(5.0)

add_card(slide11, f_left, f_top, f_width, f_height, "Founder: Syed Shahed", [
    "• Entity: Syed's Enterprises (Solo Venture · syedsenterprises.org)",
    "• Role: Founder & Lead Architect",
    "• Core Architecture: Designed and implemented Web3User's deterministic policy evaluator, transactional SQLite WAL persistence, and cumulative window budgeting.",
    "• Cryptographic Integration: Implemented RFC 8410 DER-to-raw Ed25519 signature normalization and AWS/GCP Cloud KMS adapters (Milestone FN-SEC-01).",
    "• Consensus Reducer: Implemented and audited the Milestone 13-D Stage 2-B.1 pure in-memory state machine reducer governing 11 action types.",
    "• Empirical Test Rigor: Authored comprehensive test suites achieving 806 passing tests across 39 test files in repository regression testing.",
    "• Direct Contact: info@syedsenterprises.org"
], COLOR_LINE, COLOR_CYAN)

# Right Column: Milestone Roadmap (Width 6.8 inches)
r_left = Inches(5.6)
r_top = Inches(1.7)
r_width = Inches(6.933)
r_height = Inches(5.0)

add_card(slide11, r_left, r_top, r_width, r_height, "Milestone-Based Engineering Roadmap", [
    "✓ COMPLETED — Milestones M0–M13-C.1 (Core Engine & Lifecycle)",
    "  • ERC-20 policy evaluator, SQLite WAL persistence, single-use replay guard, cumulative budgets.",
    "✓ COMPLETED — Milestone FN-SEC-01 (Cloud KMS Signers)",
    "  • AWS KMS and GCP Cloud KMS adapters verified in CI against mock contracts with RFC 8410 DER normalization.",
    "✓ COMPLETED — Milestone 13-D Stage 2-B.1 (Consensus Reducer)",
    "  • Pure in-memory consensus reducer governing 11 action types, atomic epochs, and monotonic log indexing.",
    "⏳ Q1 2027 — Stage 2-B.2 (Consensus Persistence & Compaction)",
    "  • Implement etcd watch backpressure, durable PostgreSQL historical compaction, and snapshot storage.",
    "⏳ Q2 2027 — Stage 3-A (Distributed Multi-Node Raft Cluster)",
    "  • Multi-node consensus deployment, partition tolerance, and cluster failover benchmarking.",
    "⏳ Q3 2027 — Commercial Security Audit & v1.0.0 Release",
    "  • Independent commercial security audit and production general availability release.",
    "⏳ Q4 2027 — Multi-Chain & Account Abstraction Native Plugins",
    "  • Native ERC-4337 paymasters and ERC-7579 session key validation modules for EVM & Solana."
], COLOR_LINE, COLOR_GOLD)

add_footer(slide11, 11)

# ==============================================================================
# SLIDE 12: FUNDING OPPORTUNITY & CLOSING
# ==============================================================================
slide12 = prs.slides.add_slide(blank_layout)
set_slide_background(slide12)
add_header(slide12, "Funding Allocation & Next Steps", "Accelerating Enterprise Web3 Transaction Security")

# 4 Use of Funds Cards
u_y = Inches(1.7)
u_w = Inches(2.78)
u_h = Inches(3.2)

add_card(slide12, Inches(0.8), u_y, u_w, u_h, "40% · Security Audit", [
    "• Independent Commercial Audit: Engaging a tier-1 blockchain security firm to audit policy reducer, signature normalization, and replay guards.",
    "• Formal Verification: Rigorous analysis of state-machine invariants and single-use guarantees."
], COLOR_LINE, COLOR_CYAN)

add_card(slide12, Inches(3.78), u_y, u_w, u_h, "25% · Cloud Hardware", [
    "• Dedicated Cloud HSMs: Multi-region AWS KMS and GCP Cloud KMS testbeds.",
    "• Cluster Infrastructure: Distributed etcd benchmark clusters for Stage 3-A testing."
], COLOR_LINE, COLOR_BLUE)

add_card(slide12, Inches(6.76), u_y, u_w, u_h, "20% · Dev Tooling", [
    "• Framework Adapters: Plug-and-play middleware for viem, ethers.js, and wagmi.",
    "• Interactive Quickstarts: Developer documentation, CLI generators, and reference implementations."
], COLOR_LINE, COLOR_GREEN)

add_card(slide12, Inches(9.74), u_y, u_w, u_h, "15% · Grants & Bounties", [
    "• Hackathon Integrations: Developer bounties for open-source AI agent and bot integrations.",
    "• Community Auditing: Bug bounty program for edge-case identification."
], COLOR_LINE, COLOR_GOLD)

# Bottom Call to Action Banner
cta_banner = slide12.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(5.15), Inches(11.733), Inches(1.6))
cta_banner.fill.solid()
cta_banner.fill.fore_color.rgb = RGBColor(20, 32, 54)
cta_banner.line.color.rgb = COLOR_CYAN
cta_banner.line.width = Pt(1.5)

cta_tf = cta_banner.text_frame
cta_tf.margin_left = Inches(0.3)
cta_tf.margin_top = Inches(0.18)

c_p0 = cta_tf.paragraphs[0]
c_p0.text = "Partner With Syed's Enterprises on Web3User Permission Lab"
c_p0.font.name = FONT_TITLE
c_p0.font.size = Pt(15)
c_p0.font.bold = True
c_p0.font.color.rgb = COLOR_TEXT

c_p1 = cta_tf.add_paragraph()
c_p1.text = "Proven engineering rigor (806 passed tests across 39 files), Cloud KMS integration, and a live interactive playground deployed today. With .TECH funding support, our proposed allocation will fund a commercial security audit, provision dedicated hardware HSM testbeds, and expand developer tooling."
c_p1.font.name = FONT_BODY
c_p1.font.size = Pt(10)
c_p1.font.color.rgb = COLOR_MUTED
c_p1.space_after = Pt(4)

c_p2 = cta_tf.add_paragraph()
c_p2.text = "Founder: Syed Shahed · info@syedsenterprises.org · Production: web3user.tech · Docs: docs.web3user.tech"
c_p2.font.name = FONT_TITLE
c_p2.font.size = Pt(10.5)
c_p2.font.bold = True
c_p2.font.color.rgb = COLOR_CYAN

add_footer(slide12, 12)

# Save Presentation
out_pptx = "funding/application/Web3User-TECH-Funding-Pitch-Deck.pptx"
prs.save(out_pptx)
print(f"SUCCESS: Generated {out_pptx} with 12 slides.")
