# Master Open-Source Tools Catalog
**Project**: AI-Driven Multi-Vendor Network Security Compliance Auditor  
**Problem Statement ID**: SIH26155  
**Organization**: National Technical Research Organisation (NTRO)  
**Theme**: Blockchain & Cybersecurity  

---

### Layer 1: Multi-Vendor Ingestion & Device Communication
*Used for single/bulk static configuration upload and live device polling.*

| Tool | License | Primary Role & Capability in the Auditor | Assigned To |
| :--- | :--- | :--- | :--- |
| **Netmiko** | MIT | Multi-vendor SSH connection engine. Supports 100+ network platforms (Cisco IOS/NX-OS/ASA, Juniper Junos/SRX, Palo Alto PAN-OS, Fortinet FortiOS, Arista EOS, Check Point Gaia, MikroTik, VyOS, HP/Aruba, etc.) for live configuration retrieval. | **Person A** |
| **NAPALM** | Apache 2.0 | Vendor-agnostic abstraction library with unified Python methods (`get_config()`, `get_facts()`) across Cisco, Juniper, Arista, and Fortinet devices. | **Person A** |
| **Scrapli** | Apache 2.0 | Ultra-fast, asynchronous Python library for CLI screen-scraping and configuration extraction from network devices. | **Person A** |
| **Nornir** | Apache 2.0 | High-performance, concurrent Python automation framework to dispatch bulk compliance audits across hundreds of enterprise devices in parallel. | **Person A** |

---

### Layer 2: Configuration Parsing, AST & Normalization
*Converts unstructured, proprietary CLI syntax into a vendor-neutral Security Baseline Model (JSON/Schema).*

| Tool | License | Primary Role & Capability in the Auditor | Assigned To |
| :--- | :--- | :--- | :--- |
| **Batfish** | Apache 2.0 | Industry standard for multi-vendor network configuration analysis. Ingests raw configurations from Cisco, Juniper, Arista, Palo Alto, AWS, and converts them into standardized AST models; analyzes ACLs, firewall rules, and management settings. | **Person A** |
| **CiscoConfParse / CiscoConfParse2** | GPL / Commercial | Hierarchical configuration parser. Enables parent-child regex queries on Cisco IOS/NX-OS, Arista EOS, F5 BIG-IP, and Palo Alto configs (e.g., finding lines without `transport input ssh` under `line vty 0 4`). | **Person A** |
| **TextFSM & ntc-templates** | Apache 2.0 | Template-based state machine parser maintained by Google & Network to Code with thousands of community templates converting raw CLI output to structured JSON dictionaries. | **Person A** |
| **Cisco pyATS / Genie Parsers** | Apache 2.0 | Open-source multi-vendor parsing library from Cisco with 3,000+ parsers that normalize CLI output into canonical Python data structures. | **Person A** |
| **TTP (Template Text Parser)** | MIT | High-speed template parsing engine designed specifically for semi-structured network CLI text using Jinja2-like syntax and regex groups. | **Person A** |
| **hier_config** | Apache 2.0 | Hierarchical configuration analysis engine that computes semantic differences between current configurations and desired security baselines. | **Person A** |
| **Pyang & OpenConfig Models** | BSD / Apache 2.0 | Standardized, vendor-neutral YANG data models (RFC 6020) for standardizing network configuration parameters (AAA, ACL, BGP, Interfaces). | **Person A** |

---

### Layer 3: AI / NLP & Dynamic Adaptation Loop (The Core Innovation)
*Enables the low-code training GUI to classify novel/unknown vendor commands into security parameters without backend code redeployment.*

| Tool | License | Primary Role & Capability in the Auditor | Assigned To |
| :--- | :--- | :--- | :--- |
| **Sentence-Transformers** | Apache 2.0 | Semantic similarity engine. Computes vector embeddings of CLI commands to match unseen vendor syntax to canonical security attributes (e.g., matching unknown command `idle-timeout 10` to `aaa.session_timeout` via cosine similarity). | **Person B** |
| **spaCy / HuggingFace Tokenizers** | MIT / Apache 2.0 | Fast Named Entity Recognition (NER) for extracting parameters, IPs, cipher suites, protocol versions, and credentials from arbitrary CLI text lines. | **Person B** |
| **Ollama / vLLM / llama.cpp** | MIT / Apache 2.0 | Local SLM/LLM inference runtime (e.g., running Qwen2.5-Coder-7B, Llama-3.2-3B, or Mistral) on-premise for offline, air-gapped zero-shot CLI parsing (vital for defense/NTRO environments with no cloud access). | **Person B** |
| **Instructor / Guidance / LangChain** | MIT / Apache 2.0 | Enforces strict Pydantic JSON schema outputs from language models when mapping unparsed configurations into canonical fields. | **Person B** |
| **modAL / Small-Text** | MIT / BSD | Open-source Active Learning frameworks in Python. Automatically identifies low-confidence unparsed CLI commands and surfaces them to the administrator's Low-Code Training GUI. | **Person B** |
| **Doccano / Label Studio** | MIT / Apache 2.0 | Open-source annotation UIs that can serve as architectural reference designs for building the low-code interactive command mapping interface. | **Person B** |

---

### Layer 4: Multi-Framework Compliance Engines & Policy-As-Code
*Evaluates the normalized device model against CIS Benchmarks, NIST SP 800-53, DISA STIGs, and ISO/IEC 27001.*

| Tool | License | Primary Role & Capability in the Auditor | Assigned To |
| :--- | :--- | :--- | :--- |
| **Open Policy Agent (OPA) & Rego** | Apache 2.0 | Declarative policy engine. Encodes security benchmarks (CIS, NIST, DISA STIG, ISO 27001) as modular, version-controlled Rego policies evaluated against normalized JSON configs. | **Person A** |
| **OpenSCAP & SCAP Workbench** | LGPL 2.1 | NIST-certified compliance framework. Parses and evaluates XCCDF (Extensible Configuration Checklist Description Format) and OVAL security benchmarks. | **Person A** |
| **Chef InSpec** | Apache 2.0 | Human-readable infrastructure compliance testing framework with pre-built profiles for CIS Benchmarks and DISA STIGs. | **Person A** |
| **Checkov** | Apache 2.0 | Static analysis and policy engine for cloud firewalls and security groups (AWS Security Groups, Azure NSGs, GCP Cloud Armor, Terraform). | **Person A** |
| **DefectDojo** | BSD 3-Clause | Open-source security orchestration and vulnerability management platform for tracking historical compliance scores and findings across enterprise assets. | **Person A** |

---

### Layer 5: Automated Remediation & Hardening Engine
*Generates device-specific CLI scripts and automated playbooks to remediate failed audit checks.*

| Tool | License | Primary Role & Capability in the Auditor | Assigned To |
| :--- | :--- | :--- | :--- |
| **Ansible Core & Collection Galaxy** | GPL v3 / Apache | Multi-vendor network collections (`cisco.ios`, `junipernetworks.junos`, `paloaltonetworks.panos`, `fortinet.fortios`) to generate ready-to-run remediation playbooks. | **Person A** |
| **Jinja2** | BSD 3-Clause | Template engine to dynamically render exact vendor-specific CLI hardening scripts tailored to the device OS version and detected violations. | **Person A** |
| **OpenTofu / Terraform** | MPL 2.0 | Infrastructure-as-Code engine for generating remediation scripts for cloud-native network security groups and virtual firewalls. | **Person A** |

---

### Layer 6: Actionable PDF Reporting & Web Interface
*Generates publication-grade compliance audit reports and the interactive administrator dashboard.*

| Tool | License | Primary Role & Capability in the Auditor | Assigned To |
| :--- | :--- | :--- | :--- |
| **ReportLab** | BSD 3-Clause | Programmatic high-fidelity PDF report generator in Python (generates executive summaries, compliance gauges, vulnerability tables, and CLI remediation annexes). | **Person A** |
| **WeasyPrint** | BSD 3-Clause | HTML/CSS to PDF rendering engine for generating pixel-perfect audit reports using modern CSS print stylesheets. | **Person A** |
| **FastAPI** | MIT | High-performance, async Python web API framework for configuration ingestion, scanning endpoints, and streaming audit logs. | **Person B** |
| **React + Vite + Tailwind CSS** *(or **HTMX + Templ**)* | MIT | Responsive frontend for the Single/Bulk Ingestion Hub, Compliance Scorecards, Remediation Playbook viewer, and the Low-Code Training GUI. | **Person B** |
| **Monaco Editor / Diff2Html** | MIT | Code editor and side-by-side visual diff viewer to inspect raw configurations vs. hardened post-remediation configurations. | **Person B** |

---

### Layer 7: Open Security Datasets & Benchmark Standards
*Public domain benchmarks, STIG checklists, and configuration datasets.*

| Dataset / Standard | Source / Authority | Description & Role | Assigned To |
| :--- | :--- | :--- | :--- |
| **DISA STIG XCCDF Repositories** | DoD Cyber Exchange (Public Domain) | Official machine-readable XML benchmarks for Cisco Routers/Switches (NDM STIG), Juniper SRX/Junos, Palo Alto Firewalls, and Network Perimeter STIG. | **Person A** |
| **CIS Benchmark Community Guidelines** | Center for Internet Security (CIS) | Hardening guidelines for Cisco IOS, NX-OS, Palo Alto PAN-OS, Fortinet FortiOS, Check Point, and Arista. | **Person A** |
| **NIST SP 800-53 Rev 5 Control Catalog** | NIST OSCAL (Open Security Controls Assessment Language) | Machine-readable JSON/XML OSCAL definitions mapping controls (`AC`, `AU`, `CM`, `IA`, `SC`) to network configuration checks. | **Person A** |
| **NCIIPC / CERT-In Best Practices** | NCIIPC India (National Critical Information Infrastructure Protection Centre) | Indian government security directives for Critical Information Infrastructure (CII) and perimeter hardening. | **Person A** |
| **Batfish Multi-Vendor Test Dataset** | Batfish GitHub (Apache 2.0) | Open collection of real-world sample configurations across Cisco, Juniper, Arista, Cumulus, and Palo Alto devices for testing and validation. | **Both** |
