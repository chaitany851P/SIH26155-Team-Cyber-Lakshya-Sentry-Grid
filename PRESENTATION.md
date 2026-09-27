# SENTRY-GRID: Technical Presentation Pitch Deck
**Smart India Hackathon 2026** | **Problem Statement ID**: SIH26155  
**Theme**: Blockchain & Cybersecurity  
**Organization**: National Technical Research Organisation (NTRO)  
**System**: Sentry-Grid Sovereign Multi-Vendor Network Compliance Platform  

---

## SLIDE 1: Title & The National Security Imperative

### Title: Sentry-Grid — Sovereign AI-Driven Multi-Vendor Network Compliance Auditor
* **Theme**: Blockchain & Cybersecurity
* **Problem Statement**: SIH26155 | National Technical Research Organisation (NTRO)
* **The Core Hook**:  
  *"Modern critical infrastructure spans dozens of proprietary and white-box vendors. Security cannot rely on static spreadsheets or cloud AI APIs that leak classified network configurations. Sentry-Grid provides a self-learning, air-gapped, mathematically verifiable compliance shield for national defense networks."*
* **Core Principles**:
  * **100% Air-Gapped**: Zero cloud LLM API dependencies.
  * **Zero-Downtime Adaptation**: Learns novel vendor syntax via Laya System-1 decision models without backend recompilation.
  * **Forensic Non-Repudiation**: Blockchain-anchored SHA-512 cryptographic audit seals.

---

## SLIDE 2: The Operational Gap & Competitor Flaws

### Why Existing Approaches & Competitor Submissions Fail:
1. **The Cloud AI Trap (Competitor Vulnerability)**:
   * Naive submissions send network configs to external cloud LLM APIs (OpenAI/Claude). In defense and intelligence (NTRO), this is an **immediate security disqualification** that leaks internal topology and credentials.
2. **The Fragility of Static Parsers (SolarWinds / Titania)**:
   * Traditional tools use hardcoded regex. When a vendor updates firmware or an agency deploys white-box switches (**SONiC Linux**), the parser crashes. Teams wait weeks for vendor updates.
3. **Passive "Complaints" Without Safe Fixes**:
   * Scanners generate 50-page PDFs of failures without giving engineers safe, executable CLI commands or reverse rollback scripts.
4. **The Missing "Blockchain" Factor**:
   * Competitors completely ignore the hackathon's "Blockchain & Cybersecurity" mandate, leaving audit reports vulnerable to insider tampering.

---

## SLIDE 3: The Technical Innovation: Dual-Track Parsing & Laya AI

### How Sentry-Grid Solves the Problem:
* **Track A: Deterministic AST Core (CiscoConfParse2 & Batfish)**:
  * Established vendors (Cisco, Juniper, Palo Alto, Fortinet) are normalized into the **Canonical Security Baseline** with 100% mathematical precision.
* **Track B: The Laya System One Decision Model**:
  * Unseen commands from novel or white-box hardware are routed to **Laya**, an open-source, self-hosted System One Decision Model.
  * **Direct Logit Classification**: Computes categorical decisions in **under 8.5 milliseconds** on standard CPUs without generative text hallucinations.
* **The Active Learning Confidence Gate**:
  * **$\ge 0.95$ Confidence**: Automatically normalized into the baseline.
  * **$< 0.95$ Confidence**: Triggers the **Zero Silent Failure Policy** $\rightarrow$ routed to the **Low-Code Training GUI**.
* **Zero-Downtime Rule Crystallization**:
  * A single administrator click converts confirmed mappings into an **In-Memory Dynamic Heuristic Cache**, immediately updating the engine without server restarts.

---

## SLIDE 4: Actionable Remediation, Safety & Blockchain Trust

### Closing the Security Loop with Mathematical Proof:
* **Pre-Flight Remediation & Rollback Runbooks**:
  * Generates exact, syntax-correct CLI hardening commands for that specific OS version.
  * Auto-generates **Reverse Rollback Scripts** so network engineers never risk locking themselves out.
  * Exports multi-vendor **Ansible Playbooks** for fleet-wide push.
* **MITRE ATT&CK Adversarial Threat Chaining**:
  * Correlates failed checks (e.g. open Telnet + missing VTY ACL + disabled logging) into an **Adversarial Exploit Graph**, revealing how adversaries pivot from edge to core.
* **Sovereign Immutable Audit Ledger (Blockchain Integration)**:
  * Stamped with a **CNSA 2.0 SHA-512 cryptographic seal**.
  * Replicated across a multi-agency ledger node (NTRO $\leftrightarrow$ CERT-In $\leftrightarrow$ Asset Owner), guaranteeing forensic non-repudiation against insider threats.

---

## SLIDE 5: DevSecOps Architecture, Feasibility & National Impact

### Production Readiness for Sovereign Networks:
* **Supply-Chain Hardened Frontend**:
  * Built using **HTMX and server-rendered templates**, completely eliminating `npm` dependencies, node modules, and client-side DOM XSS vectors.
* **Distroless Container Runtime**:
  * Packaged on `gcr.io/distroless/static-debian12:nonroot` (< 25 MB image size).
  * Contains **zero OS shell (`/bin/sh`)** and **zero package managers**, rendering reverse shells impossible.
* **Automated Kubernetes Drift Scanning**:
  * Scaled horizontally via **HPA**; executes nightly **CronJobs** across 1,000+ switches in parallel.
  * **Air-gapped NetworkPolicies** block all external internet egress.
* **National Impact**:
  * Accelerates India's transition to sovereign, open-source white-box networking (SONiC).
  * Reduces manual compliance audit times from **3 weeks to 10 seconds** per network enclave.
