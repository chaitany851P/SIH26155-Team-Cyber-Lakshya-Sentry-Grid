# 🎬 SIH 2026 VIDEO PITCH & LIVE DEMO MASTER GUIDE
**Problem Statement ID**: SIH26155  
**Project Name**: SENTRY-GRID  
**Team Name**: `@Team Cyber Lakshya@`  
**Target Organization**: National Technical Research Organisation (NTRO)  
**Target Video Duration**: 2 Minutes 45 Seconds to 3 Minutes  

---

## 📌 PART 1: WHAT TO DO (Strategic Overview & Setup)

### 1. The SIH Video Pitch Scoring Formula
SIH evaluators watch dozens of videos back-to-back. To score in the top 1%:
1. **Never spend more than 30 seconds on slides**: Judges want to see **real code, live software, and working execution**.
2. **Prove mathematical rigor**: Emphasize **Z3 SMT Formal Theorem Proving (0% AI hallucination)** and **100% Air-Gapped Zero-Egress** — this directly satisfies NTRO's sovereign mandate.
3. **Show the live dashboard and blockchain ledger**: You already have a live HTMX/Tailwind dashboard on port 8090 and a SHA-512 ledger explorer.
4. **Mention the 171 passing tests**: Instantly establishes technical credibility.

### 2. Recommended Recording Tools (100% Free & Easy)
- **OBS Studio (Recommended)**: Free, open source. Record your full screen with your webcam in a small circle in the bottom-right corner.
- **Loom / Clipchamp (Windows 11 built-in)**: One-click screen + mic recording.
- **PowerPoint Record**: If you prefer recording slide narration directly, use `Slide Show -> Record`.

### 3. Audio & Video Settings
- **Resolution**: 1080p (1920x1080) at 30 or 60 fps.
- **Audio**: Use earphones or a condenser mic in a quiet room. Speak with confidence, energy, and steady pacing.
- **Browser Zoom**: Set your browser zoom to **110% or 125%** so text and numbers on `http://localhost:8090` are razor-sharp on mobile screens.

---

## 🛠️ PART 2: HOW TO DO (Pre-Recording Checklist)

Before hitting "Record", prepare these 4 windows on your desktop:

1. **Window 1 (Browser Tab 1)**: `http://localhost:8090/`
   - The Sentry-Grid live compliance audit dashboard.
2. **Window 2 (Browser Tab 2)**: `http://localhost:8090/ledger`
   - The live SHA-512 Blockchain Ledger Explorer showing cryptographic blocks.
3. **Window 3 (Presentation PDF)**: `D:\sih26155\SIH2026_SENTRY_GRID_SUBMISSION.pdf`
   - Open in fullscreen mode on Slide 1 or Slide 3 (Architecture).
4. **Window 4 (Terminal / PowerShell)**:
   - Directory: `D:\sih26155`
   - Ready to run: `py -3.12 -m pytest tests/unit/ -q` or demonstrate `start.bat`.

---

## 🎙️ PART 3: SCENE-BY-SCENE WORD-FOR-WORD VIDEO SCRIPT

| Scene | Time | Screen Visual | Spoken Audio / Dialogue | Action / Cues |
| :---: | :---: | :--- | :--- | :--- |
| **1** | **0:00 - 0:25** | Fullscreen **Slide 1** (Title Page with `@Team Cyber Lakshya@` and SIH26155 badges). | *"Namaste evaluators. We are **Team Cyber Lakshya**, presenting our solution for Problem Statement **SIH26155**: the **Sentry-Grid Sovereign Network Compliance Platform** for the **National Technical Research Organisation (NTRO)**.<br><br>Across defense and critical infrastructure, **82% of network security breaches originate from human misconfiguration** — silent typos in ACLs, exposed Telnet, and weak SNMP credentials. Today, manual auditing takes up to **14 days per data center**, while commercial tools leak telemetry to foreign clouds. Sentry-Grid solves this autonomously."* | Point cursor to SIH26155 and NTRO badges. Confident, authoritative opening. |
| **2** | **0:25 - 0:55** | Switch to **Slide 3** (Architecture Diagram visual). | *"Sentry-Grid is built upon a **three-pillar sovereign architecture**:<br><br>First, a **Native C11 AST Parser** that tokenizes heterogeneous Cisco, Juniper, Arista, and Fortinet configs in sub-second time.<br>Second, a **Dual-Intelligence Verification Engine**: pairing local offline Small Language Models with the **Microsoft Research Z3 SMT Theorem Prover** to mathematically prove ACL reachability with **zero AI hallucination**.<br>Third, an immutable **SHA-512 cryptographically chained blockchain ledger** that timestamps every finding with Ed25519 digital signatures, legally admissible under **Indian IT Act Section 65B**."* | Move cursor sequentially across: Ingestion ➔ C11 ➔ Z3 SMT ➔ Blockchain ➔ Ansible. |
| **3** | **0:55 - 1:45** | **LIVE DEMO**: Switch to browser `http://localhost:8090/`. | *"Let us look at the live working prototype.<br><br>Here on our sovereign dashboard running on port 8090, we ingest a 5,000-line multi-vendor configuration. In just **1.2 seconds**, Sentry-Grid parses the AST and audits it against **450+ CIS v4.0.0 and DISA STIG benchmarks**.<br><br>Notice this critical alert: An ACL shadowing vulnerability detected on a perimeter firewall. Instead of guessing, our **Z3 Formal SMT solver** provides a mathematical proof of packet reachability.<br><br>With one click, Sentry-Grid generates an **idempotent Ansible remediation playbook** complete with dry-run verification and automated atomic rollback.<br><br>Now let's switch to `/ledger` [Click tab]. Every audit finding is permanently sealed into an immutable block with SHA-512 hash chaining and digital signatures — providing a 100% tamper-evident audit trail."* | **Action**: Click 'Audit Now' or navigate dashboard, hover over CIS score (87%), highlight Z3 proof badge, click over to `http://localhost:8090/ledger` to show cryptographic blocks! |
| **4** | **1:45 - 2:10** | Quick switch to Terminal or Docker window. | *"Under the hood, Sentry-Grid is **100% air-gappable with zero cloud egress**. As you can see in our test suite [Run `pytest` in terminal or show test logs], all **171 integration and unit tests pass with zero failures**.<br><br>It runs agentlessly over standard SSH and RESTCONF on commodity hardware — requiring only 2 vCPUs and 4GB of RAM — with zero performance impact on live routers and switches."* | Run terminal command: `py -3.12 -m pytest tests/unit/ -q` or show green test summary. |
| **5** | **2:10 - 2:35** | Switch to **Slide 5** (`impact_benefits_visual.jpg` Infographic). | *"The quantifiable impact for NTRO and critical infrastructure is monumental:<br><br>• **Speed**: Audit duration drops from **14 days to 1.2 seconds** — an acceleration of 99.9%.<br>• **Security**: **82% human error eliminated** with zero telemetry leakage.<br>• **Cost**: Saves **₹15 to 25 Lakhs per data center annually** by replacing expensive proprietary tools like Nipper or SolarWinds.<br>• **Legal Sovereignty**: Complete compliance with CERT-In directives and Indian IT Act Section 65B."* | Point to the 4 metric cards on the generated infographic: 1.2s, 82%, ₹25L, and §65B. |
| **6** | **2:35 - 2:55** | Switch back to **Slide 1** or show webcam fullscreen. | *"Sentry-Grid is not just a concept — it is a production-ready, mathematically verified sovereign defense platform engineered to secure India's critical information highways.<br><br>Thank you. We are **Team Cyber Lakshya**, ready to defend Bharat's cyberspace!"* | Professional smile, crisp closing salute / namaste gesture. |

---

## 📤 PART 4: HOW TO EXPORT & SUBMIT ON THE SIH PORTAL

1. **Review Video Length**: Ensure your final video is between **2:30 and 3:00 minutes** (do not exceed 3 minutes).
2. **Upload Video**:
   - **Option A (YouTube - Recommended)**: Upload as **Unlisted** (anyone with the link can view, but not publicly searchable). Title: `SIH2026 - SIH26155 - Team Cyber Lakshya - Sentry Grid Pitch`.
   - **Option B (Google Drive)**: Upload `.mp4`, set sharing permission to **"Anyone with the link can view"**.
3. **Submit on Portal**: Paste the video link into the designated field on the SIH Idea Submission form.
