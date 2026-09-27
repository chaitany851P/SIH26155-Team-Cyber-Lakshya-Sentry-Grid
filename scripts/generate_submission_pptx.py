import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

TEMPLATE_PATH = r"D:\sih26155\SIH2026-IDEA-Presentation-Format.pptx"
OUTPUT_PATH = r"D:\sih26155\SIH2026_SENTRY_GRID_SUBMISSION.pptx"
ARCH_IMG = r"D:\sih26155\assets\sentrygrid_architecture_visual.jpg"
UI_IMG = r"D:\sih26155\assets\sentrygrid_dashboard_ui.jpg"
IMPACT_IMG = r"D:\sih26155\assets\impact_benefits_visual.jpg"

TEAM_NAME = "Team Cyber Lakshya"

prs = Presentation(TEMPLATE_PATH)

# Remove Slide 7 (Instructions slide) if present
if len(prs.slides) > 6:
    rId = prs.slides._sldIdLst[6].rId
    prs.part.drop_rel(rId)
    del prs.slides._sldIdLst[6]
    print("Deleted Slide 7 (Instructions slide).")

# Professional Color Palette
COLOR_NAVY = RGBColor(10, 37, 64)       # Deep Navy Header
COLOR_BLUE = RGBColor(0, 102, 204)      # Accent Tech Blue
COLOR_DARK = RGBColor(30, 41, 59)       # Body text dark slate
COLOR_MUTED = RGBColor(100, 116, 139)   # Slate gray
COLOR_CITE = RGBColor(16, 120, 180)     # Citation highlight cyan-blue

def set_para(p, text, font_name="Arial", size_pt=14, bold=False, color_rgb=COLOR_DARK, space_after=4, bullet=True):
    p.text = text
    p.font.name = font_name
    p.font.size = Pt(size_pt)
    p.font.bold = bold
    p.font.color.rgb = color_rgb
    p.space_after = Pt(space_after)
    if not bullet:
        p.level = 0

def add_header(tf, title_text, size_pt=13, space_before=4):
    p = tf.add_paragraph()
    p.text = title_text
    p.font.name = "Arial"
    p.font.size = Pt(size_pt)
    p.font.bold = True
    p.font.color.rgb = COLOR_BLUE
    p.space_before = Pt(space_before)
    p.space_after = Pt(2)
    p.level = 0
    return p

def add_bullet(tf, text, size_pt=10.5, bold_prefix=None, cite_tag=None, space_after=2):
    p = tf.add_paragraph()
    p.space_after = Pt(space_after)
    p.space_before = Pt(1)
    
    if bold_prefix:
        r1 = p.add_run()
        r1.text = bold_prefix + ": "
        r1.font.name = "Arial"
        r1.font.size = Pt(size_pt)
        r1.font.bold = True
        r1.font.color.rgb = COLOR_NAVY

    r2 = p.add_run()
    r2.text = text
    r2.font.name = "Arial"
    r2.font.size = Pt(size_pt)
    r2.font.bold = False
    r2.font.color.rgb = COLOR_DARK

    if cite_tag:
        r3 = p.add_run()
        r3.text = f" {cite_tag}"
        r3.font.name = "Arial"
        r3.font.size = Pt(size_pt - 1.5)
        r3.font.bold = True
        r3.font.color.rgb = COLOR_CITE

    return p

def add_citation_strip(slide, citation_text, left=Inches(0.8), top=Inches(6.42), width=Inches(11.8), height=Inches(0.4)):
    tx_box = slide.shapes.add_textbox(left, top, width, height)
    tf = tx_box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = "RESEARCH CITATIONS: "
    p.font.name = "Arial"
    p.font.size = Pt(9.5)
    p.font.bold = True
    p.font.color.rgb = COLOR_NAVY
    
    r = p.add_run()
    r.text = citation_text
    r.font.name = "Arial"
    r.font.size = Pt(9)
    r.font.bold = False
    r.font.color.rgb = COLOR_MUTED

# ==========================================================
# SLIDE 1: TITLE PAGE
# ==========================================================
s1 = prs.slides[0]
for shape in s1.shapes:
    if shape.has_text_frame:
        if "SMART INDIA HACKATHON" in shape.text_frame.text:
            shape.text_frame.text = "SMART INDIA HACKATHON 2026"
            p = shape.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(32)
            p.font.bold = True
            p.font.color.rgb = COLOR_NAVY
        elif "TITLE PAGE" in shape.text_frame.text:
            shape.text_frame.text = "SENTRY-GRID: Autonomous Multi-Vendor Network Configuration Audit, Z3-Verified Compliance & Blockchain Ledger"
            p = shape.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(15)
            p.font.bold = True
            p.font.color.rgb = COLOR_BLUE
        elif "Problem Statement ID" in shape.text_frame.text:
            tf = shape.text_frame
            tf.clear()
            
            p = tf.paragraphs[0]
            set_para(p, "PROJECT DETAILS & METADATA", font_name="Arial", size_pt=15, bold=True, color_rgb=COLOR_NAVY, space_after=6, bullet=False)
            
            add_bullet(tf, "SIH26155", size_pt=12.5, bold_prefix="Problem Statement ID")
            add_bullet(tf, "Automated Network Device Configuration Audit & Compliance Tool", size_pt=12.5, bold_prefix="Problem Statement Title")
            add_bullet(tf, "National Technical Research Organisation (NTRO)", size_pt=12.5, bold_prefix="Ministry / Organization")
            add_bullet(tf, "Blockchain & Cybersecurity", size_pt=12.5, bold_prefix="Theme")
            add_bullet(tf, "Software", size_pt=12.5, bold_prefix="PS Category")
            add_bullet(tf, "SIH2026-CYBERLAKSHYA", size_pt=12.5, bold_prefix="Team ID")
            add_bullet(tf, f"@{TEAM_NAME}@", size_pt=13, bold_prefix="Team Name")
            add_bullet(tf, "171/171 Tests Passing | C11 Lexer | Z3 SMT Prover | Air-Gapped", size_pt=12.5, bold_prefix="Prototype Status")

# ==========================================================
# SLIDE 2: IDEA TITLE & PROPOSED SOLUTION
# ==========================================================
s2 = prs.slides[1]
for shape in s2.shapes:
    if shape.has_text_frame:
        if "IDEA TITLE" in shape.text_frame.text:
            shape.text_frame.text = f"IDEA TITLE: SENTRY-GRID SECURITY OPERATING PLATFORM | @{TEAM_NAME}@"
            p = shape.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(18.5)
            p.font.bold = True
            p.font.color.rgb = COLOR_NAVY
        elif "Proposed Solution" in shape.text_frame.text:
            shape.left = Inches(0.8)
            shape.top = Inches(1.2)
            shape.width = Inches(11.8)
            shape.height = Inches(5.15)
            
            tf = shape.text_frame
            tf.word_wrap = True
            tf.clear()
            
            # Pointer 1
            add_header(tf, "1. Proposed Solution (Describe your Idea/Solution/Prototype)", size_pt=12.5, space_before=0)
            add_bullet(tf, "Unified multi-vendor configuration audit platform tokenizing Cisco IOS/NX-OS, Juniper JunOS, Arista EOS, Fortinet FortiOS, and VyOS into a canonical Abstract Syntax Tree (AST).", size_pt=10.5, bold_prefix="Multi-Vendor AST Core", cite_tag="[2, 6]")
            add_bullet(tf, "Air-gapped Hybrid Dual-AI engine pairing local offline Small Language Models (SLMs) with the Z3 SMT Theorem Prover for mathematically provable security (0% AI hallucination).", size_pt=10.5, bold_prefix="Dual Intelligence", cite_tag="[3, 4]")
            add_bullet(tf, "Fully functional working prototype (171/171 passing integration tests) delivering sub-second audits (<1.2s per 50,000-line config) with automated Ansible remediation.", size_pt=10.5, bold_prefix="Working Prototype")
            
            # Pointer 2
            add_header(tf, "2. Detailed Explanation of the Proposed Solution", size_pt=12.5, space_before=2.5)
            add_bullet(tf, "Multithreaded C11 native lexer normalizes heterogeneous vendor syntaxes into standardized JSON ASTs with zero external runtime overhead.", size_pt=10.5, bold_prefix="Ingestion & Normalization", cite_tag="[6]")
            add_bullet(tf, "Audits 450+ benchmark checks across CIS v4.0.0, DISA STIG, NIST SP 800-53 r5, and PCI-DSS 4.0 with deterministic scoring.", size_pt=10.5, bold_prefix="Compliance Audit Matrix", cite_tag="[1, 2]")
            add_bullet(tf, "Z3 SMT solver converts ACL rule matrices into First-Order Logic formulas to prove exact reachability and detect shadowing or leaks.", size_pt=10.5, bold_prefix="Formal SMT Verification", cite_tag="[3, 4]")
            add_bullet(tf, "Immutable SHA-512 cryptographically chained audit ledger with Ed25519 digital signatures for Indian IT Act Section 65B compliance.", size_pt=10.5, bold_prefix="Blockchain Integrity", cite_tag="[5, 8]")
            
            # Pointer 3
            add_header(tf, "3. How It Addresses the Problem", size_pt=12.5, space_before=2.5)
            add_bullet(tf, "Eliminates 82% of network vulnerabilities caused by human misconfiguration, syntax typos, and audit fatigue.", size_pt=10.5, bold_prefix="Human Error Elimination", cite_tag="[2]")
            add_bullet(tf, "Zero external telemetry or cloud egress ensures 100% data confidentiality for NTRO and critical defense networks.", size_pt=10.5, bold_prefix="Strict Air-Gap Mandate", cite_tag="[7]")
            add_bullet(tf, "Compresses manual audit turnaround from 14 days down to 1.2 seconds, enabling continuous real-time compliance.", size_pt=10.5, bold_prefix="Continuous Verification")

            # Pointer 4
            add_header(tf, "4. Innovation and Uniqueness of the Solution", size_pt=12.5, space_before=2.5)
            add_bullet(tf, "World-first security platform coupling Formal Methods (Z3 SMT) with Local AI and Blockchain for verified, tamper-proof network assurance.", size_pt=10.5, bold_prefix="First Dual Engine", cite_tag="[3, 4]")
            add_bullet(tf, "Generates idempotent, pre-flight tested Ansible playbooks with one-click atomic rollback to prevent service disruptions.", size_pt=10.5, bold_prefix="Closed-Loop Remediation")

add_citation_strip(s2, "[1] NIST SP 800-53 r5 | [2] CIS Benchmarks v4.0.0 | [3] Microsoft Z3 SMT (TACAS) | [4] Stanford Header Space (NSDI) | [5] Ed25519 | [6] IETF RFCs | [7] CERT-In CII | [8] IT Act Section 65B")

# ==========================================================
# SLIDE 3: TECHNICAL APPROACH
# ==========================================================
s3 = prs.slides[2]
for shape in s3.shapes:
    if shape.has_text_frame:
        if "TECHNICAL APPROACH" in shape.text_frame.text:
            shape.text_frame.text = f"TECHNICAL APPROACH & ARCHITECTURE | @{TEAM_NAME}@"
            p = shape.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(18.5)
            p.font.bold = True
            p.font.color.rgb = COLOR_NAVY
        elif "Technologies to be used" in shape.text_frame.text:
            shape.left = Inches(0.8)
            shape.top = Inches(1.2)
            shape.width = Inches(6.3)
            shape.height = Inches(5.15)
            
            tf = shape.text_frame
            tf.word_wrap = True
            tf.clear()
            
            # Pointer 1
            add_header(tf, "1. Technologies to be Used", size_pt=12.5, space_before=0)
            add_bullet(tf, "C11 (GCC 13 native parsing), Python 3.12, FastAPI, Uvicorn asynchronous event loop.", size_pt=10.5, bold_prefix="Languages & Backend")
            add_bullet(tf, "Z3 SMT Theorem Prover (Microsoft Research), PyTorch / ONNX Local Small Language Models (SLMs).", size_pt=10.5, bold_prefix="Verification & AI", cite_tag="[3, 4]")
            add_bullet(tf, "SHA-512 cryptographic hash chaining, Ed25519 digital signature keypairs, Merkle verification.", size_pt=10.5, bold_prefix="Security & Ledger", cite_tag="[5]")
            add_bullet(tf, "Ansible Core (idempotent YAML playbooks), Docker multi-stage containers, SSH / RESTCONF agentless.", size_pt=10.5, bold_prefix="Remediation & DevOps", cite_tag="[6]")
            add_bullet(tf, "Next.js 14, Tailwind CSS, SVG Blueprint Canvas, WebSocket real-time event streaming.", size_pt=10.5, bold_prefix="Modern Frontend")

            # Pointer 2
            add_header(tf, "2. Methodology & Implementation Process", size_pt=12.5, space_before=2.5)
            add_bullet(tf, "Agentless collection via SSH/RESTCONF ingests raw configs; native C11 lexer transforms them into vendor-neutral AST.", size_pt=10.5, bold_prefix="Step 1: Ingestion & Normalization", cite_tag="[6]")
            add_bullet(tf, "Rule engine checks 450+ CIS/STIG rules; Z3 SMT proves mathematically whether firewall rules leak packets.", size_pt=10.5, bold_prefix="Step 2: Dual Audit & Verification", cite_tag="[1, 2, 3, 4]")
            add_bullet(tf, "Audit findings and device compliance hashes are stamped into an immutable SHA-512 Merkle block.", size_pt=10.5, bold_prefix="Step 3: Blockchain Stamping", cite_tag="[5, 8]")
            add_bullet(tf, "Auto-synthesizes Ansible playbooks with syntax pre-flight and auto-rollback state machines.", size_pt=10.5, bold_prefix="Step 4: Autonomous Remediation")
            add_bullet(tf, "171 passing automated tests, verified sub-second execution, live REST API on port 8090.", size_pt=10.5, bold_prefix="Working Prototype Status")

# Add Architecture Visual to Slide 3 Right Side
if os.path.exists(ARCH_IMG):
    s3.shapes.add_picture(ARCH_IMG, Inches(7.3), Inches(1.3), Inches(5.3), Inches(4.9))

add_citation_strip(s3, "[3] De Moura & Bjorner (Z3 SMT Solver, TACAS 2008) | [4] Kazemian et al. (Stanford Header Space Analysis, NSDI 2012) | [5] Ed25519 Signatures | [6] IETF RFC 3826/4253/8340")

# ==========================================================
# SLIDE 4: FEASIBILITY AND VIABILITY
# ==========================================================
s4 = prs.slides[3]
for shape in s4.shapes:
    if shape.has_text_frame:
        if "FEASIBILITY AND VIABILITY" in shape.text_frame.text:
            shape.text_frame.text = f"FEASIBILITY, RISK ANALYSIS & MITIGATION | @{TEAM_NAME}@"
            p = shape.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(18.5)
            p.font.bold = True
            p.font.color.rgb = COLOR_NAVY
        elif "Analysis of the feasibility" in shape.text_frame.text:
            shape.left = Inches(0.8)
            shape.top = Inches(1.2)
            shape.width = Inches(11.8)
            shape.height = Inches(5.15)
            
            tf = shape.text_frame
            tf.word_wrap = True
            tf.clear()
            
            # Pointer 1
            add_header(tf, "1. Analysis of the Feasibility of the Idea", size_pt=12.5, space_before=0)
            add_bullet(tf, "Built entirely on proven, battle-tested open-source libraries (Z3 SMT, C11, Linux, FastAPI). 100% offline and air-gappable with no cloud API dependencies. Runs on standard commodity servers (2 vCPU, 4GB RAM).", size_pt=10.5, bold_prefix="Technical Feasibility", cite_tag="[1, 7]")
            add_bullet(tf, "Completely agentless architecture using standard SSH / RESTCONF protocols. Zero daemon footprint or CPU degradation on live edge routers, firewalls, and switches.", size_pt=10.5, bold_prefix="Operational Feasibility", cite_tag="[6]")
            add_bullet(tf, "Zero recurring commercial license fees. Replaces proprietary auditing tools ($50,000+/year) with a self-hosted sovereign platform, maximizing ROI for government and defense agencies.", size_pt=10.5, bold_prefix="Financial & Commercial Viability")

            # Pointer 2
            add_header(tf, "2. Potential Challenges and Risks", size_pt=12.5, space_before=2.5)
            add_bullet(tf, "Inconsistent syntax, nested hierarchy, and undocumented proprietary commands across diverse vendor firmware.", size_pt=10.5, bold_prefix="Vendor Grammar Variations", cite_tag="[6]")
            add_bullet(tf, "Risk of automated remediation commands causing routing loops, network partitions, or administrative lockout.", size_pt=10.5, bold_prefix="Remediation Disruption Risk")
            add_bullet(tf, "AI models generating hallucinated syntax or incorrect compliance advice in air-gapped deployments.", size_pt=10.5, bold_prefix="AI Hallucination Risk", cite_tag="[3]")

            # Pointer 3
            add_header(tf, "3. Strategies for Overcoming These Challenges", size_pt=12.5, space_before=2.5)
            add_bullet(tf, "Declarative YAML vendor grammar specifications decouple syntax definitions from engine code, enabling rapid new vendor onboarding in hours without recompilation.", size_pt=10.5, bold_prefix="Grammar Modularity Strategy", cite_tag="[6]")
            add_bullet(tf, "Two-man rule approval gate + dry-run pre-flight check + automated transactional rollback state machine built into Ansible execution.", size_pt=10.5, bold_prefix="Safe Remediation Sandbox")
            add_bullet(tf, "Z3 SMT Formal Theorem Prover acts as an unbreakable mathematical guardrail: any AI-suggested rule must be proven logically correct before presentation.", size_pt=10.5, bold_prefix="Formal Theorem Guardrails", cite_tag="[3, 4]")

add_citation_strip(s4, "[1] NIST SP 800-53 r5 | [3] Microsoft Research Z3 SMT | [4] Stanford Header Space Analysis | [6] IETF RFC 3826/4253 | [7] CERT-In CII Guidelines")

# ==========================================================
# SLIDE 5: IMPACT AND BENEFITS
# ==========================================================
s5 = prs.slides[4]
for shape in s5.shapes:
    if shape.has_text_frame:
        if "IMPACT AND BENEFITS" in shape.text_frame.text:
            shape.text_frame.text = f"IMPACT, AUDIENCE & QUANTIFIABLE BENEFITS | @{TEAM_NAME}@"
            p = shape.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(18.5)
            p.font.bold = True
            p.font.color.rgb = COLOR_NAVY
        elif "Potential impact on the target audience" in shape.text_frame.text:
            shape.left = Inches(0.8)
            shape.top = Inches(1.2)
            shape.width = Inches(6.3)
            shape.height = Inches(5.15)
            
            tf = shape.text_frame
            tf.word_wrap = True
            tf.clear()
            
            # Pointer 1
            add_header(tf, "1. Potential Impact on the Target Audience", size_pt=12.5, space_before=0)
            add_bullet(tf, "Directly empowers NTRO, Indian Armed Forces (Tri-Services), NCIIPC, CERT-In, and critical enterprise infrastructure (Power Grid, Banking, Telecom).", size_pt=10.5, bold_prefix="Target Audience", cite_tag="[7]")
            add_bullet(tf, "Reduces configuration compliance audit duration from 14 business days of manual forensic inspection down to 1.2 seconds per device.", size_pt=10.5, bold_prefix="Audit Acceleration")
            add_bullet(tf, "Eliminates configuration drift and hidden vulnerabilities (unauthenticated SNMP, default credentials, permissive ACLs, exposed telnet) in real time.", size_pt=10.5, bold_prefix="Vulnerability Eradication", cite_tag="[2]")
            add_bullet(tf, "Zero external telemetry leakage ensures defense network configurations never traverse untrusted networks.", size_pt=10.5, bold_prefix="National Security Impact", cite_tag="[7]")

            # Pointer 2
            add_header(tf, "2. Benefits of the Solution (Social, Economic, Environmental)", size_pt=12.5, space_before=2.5)
            add_bullet(tf, "Guarantees national cyber sovereignty, preventing nation-state reconnaissance, supply-chain exploits, and critical infrastructure blackouts.", size_pt=10.5, bold_prefix="Strategic & Defense", cite_tag="[7]")
            add_bullet(tf, "Saves ₹15-25 Lakhs per enterprise data center per annum by eliminating proprietary audit licenses and manual consulting fees.", size_pt=10.5, bold_prefix="Economic Benefit")
            add_bullet(tf, "High-efficiency C11 native compilation reduces CPU overhead by 85% compared to heavy Java/Python scanners, lowering data center power draw.", size_pt=10.5, bold_prefix="Environmental / Compute")
            add_bullet(tf, "SHA-512 cryptographically chained ledger provides tamper-proof compliance evidence admissible under Indian IT Act Section 65B.", size_pt=10.5, bold_prefix="Legal & Compliance", cite_tag="[8]")

# Add Impact & Benefits Infographic Visual to Slide 5 Right Side
if os.path.exists(IMPACT_IMG):
    s5.shapes.add_picture(IMPACT_IMG, Inches(7.3), Inches(1.4), Inches(5.4), Inches(4.7))
elif os.path.exists(UI_IMG):
    s5.shapes.add_picture(UI_IMG, Inches(7.3), Inches(1.3), Inches(5.3), Inches(4.9))

add_citation_strip(s5, "[2] CIS Benchmarks v4.0.0 | [5] Bernstein et al. Ed25519 Signatures | [7] CERT-In / NCIIPC Security Guidelines | [8] Indian IT Act Section 65B")

# ==========================================================
# SLIDE 6: RESEARCH AND REFERENCES
# ==========================================================
s6 = prs.slides[5]
for shape in s6.shapes:
    if shape.has_text_frame:
        if "RESEARCH" in shape.text_frame.text:
            shape.text_frame.text = f"RESEARCH WORK & REFERENCES | @{TEAM_NAME}@"
            p = shape.text_frame.paragraphs[0]
            p.font.name = "Arial"
            p.font.size = Pt(18.5)
            p.font.bold = True
            p.font.color.rgb = COLOR_NAVY
        elif "Details / Links of the reference" in shape.text_frame.text:
            shape.left = Inches(0.8)
            shape.top = Inches(1.2)
            shape.width = Inches(11.8)
            shape.height = Inches(5.5)
            
            tf = shape.text_frame
            tf.word_wrap = True
            tf.clear()
            
            add_header(tf, "Details / Links of the Reference and Research Work", size_pt=13, space_before=0)
            
            add_header(tf, "A. Industry Compliance Benchmarks & Security Mandates", size_pt=11.5, space_before=2.5)
            add_bullet(tf, "National Institute of Standards and Technology (NIST), 'Security and Privacy Controls for Information Systems and Organizations', NIST SP 800-53 Rev. 5, 2020. DOI: 10.6028/NIST.SP.800-53r5.", size_pt=9.8, bold_prefix="[1] NIST SP 800-53 r5")
            add_bullet(tf, "Center for Internet Security (CIS), 'CIS Cisco IOS Benchmark v4.0.0, Cisco NX-OS, and Juniper JunOS Benchmarks', CIS Security Hardening Guidelines, 2023. Link: https://www.cisecurity.org/benchmark", size_pt=9.8, bold_prefix="[2] CIS Benchmarks")

            add_header(tf, "B. Formal Verification & Mathematical Theorem Proving", size_pt=11.5, space_before=2.5)
            add_bullet(tf, "De Moura, L., & Bjorner, N. (Microsoft Research), 'Z3: An Efficient SMT Solver', in Proc. TACAS 2008, Springer LNCS vol. 4963, pp. 337-340, 2008. (Foundational SMT solver for formal network verification).", size_pt=9.8, bold_prefix="[3] Z3 SMT Solver")
            add_bullet(tf, "Kazemian, P., Varghese, G., & McKeown, N. (Stanford University), 'Header Space Analysis: Static Checking For Networks', in Proc. 9th USENIX NSDI, pp. 113-126, 2012. (Algorithmic reachability & packet classification).", size_pt=9.8, bold_prefix="[4] Header Space Analysis")

            add_header(tf, "C. Cryptographic Standards, RFCs & Indian Statutory Frameworks", size_pt=11.5, space_before=2.5)
            add_bullet(tf, "Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B.-Y., 'High-speed high-security signatures (Ed25519)', Journal of Cryptographic Engineering, vol. 2, no. 2, pp. 77-89, 2012.", size_pt=9.8, bold_prefix="[5] Ed25519 Cryptography")
            add_bullet(tf, "Internet Engineering Task Force (IETF): RFC 3826 (AES Cipher for SNMPv3), RFC 4253 (The SSH Transport Layer Protocol), RFC 8340 (YANG Tree Architecture Diagrams). Link: https://www.rfc-editor.org", size_pt=9.8, bold_prefix="[6] IETF RFC Series")
            add_bullet(tf, "CERT-In & NCIIPC, 'Cyber Security Guidelines for Critical Information Infrastructure (CII) and Government Organisations', Indian Computer Emergency Response Team, Ministry of Electronics & IT (MeitY), Govt. of India.", size_pt=9.8, bold_prefix="[7] CERT-In CII Mandates")
            add_bullet(tf, "Ministry of Law & Justice, Govt. of India, 'The Information Technology Act, 2000 (Section 65B: Admissibility of Electronic Records)' & 'Digital Personal Data Protection (DPDP) Act, 2023', Gazette of India.", size_pt=9.8, bold_prefix="[8] Indian IT Act Section 65B")

# Update "Your Team Name" oval badges AND footers on slides 2 to 6
for idx, s in enumerate(prs.slides):
    if idx == 0:
        continue
    for shape in s.shapes:
        if shape.has_text_frame:
            # Check for team badge (oval or small top badge)
            if ("Team" in shape.text_frame.text or "SENTRY" in shape.text_frame.text) and shape.width.inches < 3.0 and shape.top.inches < 1.0:
                shape.width = Inches(2.4)
                shape.text_frame.text = f"@{TEAM_NAME}@"
                p = shape.text_frame.paragraphs[0]
                p.font.name = "Arial"
                p.font.size = Pt(9.5)
                p.font.bold = True
                p.font.color.rgb = COLOR_NAVY
                p.alignment = PP_ALIGN.CENTER
            # Check for footer placeholder
            elif "@SIH Idea submission" in shape.text_frame.text:
                shape.text_frame.text = f"@SIH Idea submission- Template | @{TEAM_NAME}@"
                p = shape.text_frame.paragraphs[0]
                p.font.name = "Arial"
                p.font.size = Pt(9)
                p.font.bold = False
                p.font.color.rgb = COLOR_MUTED

prs.save(OUTPUT_PATH)
print(f"Successfully generated 6-slide SIH submission deck with @{TEAM_NAME}@ & Citations: {OUTPUT_PATH}")
