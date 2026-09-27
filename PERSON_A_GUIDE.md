# PERSON A: Systems, Multi-Vendor Parsing, Compliance & Remediation Guide
**Project**: AI-Driven Multi-Vendor Network Security Compliance Auditor  
**Role**: Security & Backend Architect (Person A)  
**Partner**: AI & Platform/Product Engineer (Person B)  
**Organization / Problem**: NTRO / SIH26155 (Theme: Blockchain & Cybersecurity)  

---

## 1. Executive Mission & Scope
As **Person A**, you own the **deterministic security and compliance core** of the platform:
1. **The Shared Contract**: Define the Canonical Security Baseline JSON Schema (locked with Person B on Day 1).
2. **Device Communication & Ingestion**: Integrate live SSH polling and batch configuration ingestion across heterogeneous vendors.
3. **Multi-Vendor Configuration Parsers**: Ingest and normalize proprietary CLI and configs (Cisco, Juniper, Palo Alto, Fortinet, Arista, SONiC, Check Point, etc.) into the canonical schema.
4. **Multi-Framework Policy Engine**: Implement audit rules for **CIS Benchmarks**, **DISA STIGs**, **NIST SP 800-53**, and **ISO/IEC 27001**.
5. **Actionable Remediation Engine**: Generate vendor-specific CLI hardening commands, rollback scripts, and Ansible playbooks for every failed check.
6. **Cryptographic PDF Report Generator**: Generate publication-grade, audit-ready PDF reports with executive scorecards, findings tables, and SHA-256 integrity seals.

---

## 2. Complete Open-Source Tool Matrix Assigned to Person A

Every tool listed below is an open-source standard with proven enterprise and defense benchmarks. Use them in your pipeline as specified:

### A. Layer 1: Multi-Vendor Ingestion & Device Communication
| Tool | License | Exact Role in Your Backend Pipeline |
| :--- | :--- | :--- |
| **Netmiko** | MIT | **Primary live SSH collector**. Connects to 100+ network platforms (Cisco IOS/NX-OS/ASA, Juniper Junos/SRX, Palo Alto PAN-OS, Fortinet FortiOS, Arista EOS, Check Point Gaia, MikroTik, VyOS, HP/Aruba) to execute `show running-config` / `show configuration` and pull live configurations. |
| **NAPALM** | Apache 2.0 | **Unified multi-vendor abstraction**. Provides standardized methods (`get_config()`, `get_facts()`) across Cisco, Juniper, Arista, and Fortinet devices. |
| **Scrapli** | Apache 2.0 | **Ultra-fast asynchronous CLI screen-scraper**. Ideal for high-speed concurrent SSH connections when scanning large subnets. |
| **Nornir** | Apache 2.0 | **Concurrent Python automation framework**. Dispatches bulk compliance audits across hundreds of enterprise network devices in parallel without external dependencies. |

---

### B. Layer 2: Configuration Parsing, AST & Normalization
| Tool | License | Exact Role in Your Backend Pipeline |
| :--- | :--- | :--- |
| **Batfish** | Apache 2.0 | **Gold standard multi-vendor AST parser**. Converts raw Cisco, Juniper, Arista, Palo Alto, and AWS configs into vendor-independent data models; analyzes ACLs, firewall rules, and management settings. |
| **CiscoConfParse / CiscoConfParse2** | GPL / Commercial | **Hierarchical parent-child parser**. Use for querying nested blocks in Cisco IOS/NX-OS, Arista EOS, and Palo Alto configs (e.g., finding lines without `transport input ssh` under `line vty 0 4`). |
| **TextFSM & `ntc-templates`** | Apache 2.0 | **Template-based parser with 1,000+ community templates**. Converts raw CLI output from diverse vendors directly into structured Python dictionaries. |
| **Cisco pyATS / Genie Parsers** | Apache 2.0 | **Cisco's official multi-vendor parser**. Contains 3,000+ parsers that normalize raw device output into canonical Python data models. |
| **TTP (Template Text Parser)** | MIT | **High-speed semi-structured CLI parser**. Uses Jinja2-like syntax and regex groups to quickly extract parameters from custom or uncommon CLI layouts. |
| **hier_config** | Apache 2.0 | **Hierarchical configuration analysis engine**. Computes semantic differences between current configurations and desired security baselines, generating minimal, order-correct remediation diffs. |
| **Pyang & OpenConfig Models** | BSD / Apache 2.0 | **Standardized YANG data models (RFC 6020)**. Validates network configuration parameters (AAA, ACL, Interfaces) against vendor-neutral OpenConfig schemas. |

---

### C. Layer 4: Multi-Framework Compliance Engines & Policy-As-Code
| Tool | License | Exact Role in Your Backend Pipeline |
| :--- | :--- | :--- |
| **Open Policy Agent (OPA) & Rego** | Apache 2.0 | **Declarative policy engine**. Encodes security benchmarks (CIS, NIST, DISA STIG, ISO 27001) as modular, version-controlled Rego policies evaluated against normalized JSON configs. |
| **OpenSCAP & SCAP Workbench** | LGPL 2.1 | **NIST-certified compliance framework**. Parses and evaluates XCCDF (Extensible Configuration Checklist Description Format) and OVAL security benchmarks. |
| **Chef InSpec** | Apache 2.0 | **Human-readable infrastructure testing framework**. Provides pre-built profiles for CIS Benchmarks and DISA STIGs. |
| **Checkov** | Apache 2.0 | **Static analysis & policy engine for cloud firewalls**. Evaluates AWS Security Groups, Azure NSGs, and Terraform network definitions against CIS baselines. |
| **DefectDojo** | BSD 3-Clause | **Vulnerability & compliance tracker**. Stores historical audit results and tracks compliance posture over time. |

---

### D. Layer 5: Automated Remediation & Hardening Engine
| Tool | License | Exact Role in Your Backend Pipeline |
| :--- | :--- | :--- |
| **Ansible Core & Collection Galaxy** | GPL v3 / Apache | **Automated configuration push**. Generates multi-vendor remediation playbooks using `cisco.ios`, `junipernetworks.junos`, `paloaltonetworks.panos`, and `fortinet.fortios` collections. |
| **Jinja2** | BSD 3-Clause | **Dynamic CLI template renderer**. Dynamically renders exact vendor-specific CLI hardening scripts tailored to the device OS version and detected violations. |
| **OpenTofu / Terraform** | MPL 2.0 | **Infrastructure-as-Code remediation**. Generates remediation templates for cloud-native network security groups and virtual firewalls. |

---

### E. Layer 6 & Layer 7: Reporting, Datasets & Benchmark Standards
| Tool / Dataset | Source / License | Exact Role in Your Backend Pipeline |
| :--- | :--- | :--- |
| **ReportLab** | BSD 3-Clause | **Programmatic PDF generator**. Generates executive scorecards, compliance gauges, finding tables, CLI remediation annexes, and embeds the SHA-256 cryptographic seal. |
| **WeasyPrint** | BSD 3-Clause | **HTML-to-PDF alternative**. Optional alternative for rendering PDF reports directly from styled HTML/CSS templates. |
| **DISA STIG XCCDF Repositories** | DoD Cyber Exchange (Public Domain) | Machine-readable XML benchmarks for Cisco Routers/Switches (NDM STIG), Juniper SRX/Junos, Palo Alto, and Network Perimeter STIGs. |
| **CIS Benchmark Community Guidelines** | Center for Internet Security (CIS) | Hardening guidelines for Cisco IOS, NX-OS, Palo Alto PAN-OS, Fortinet FortiOS, Check Point, and Arista. |
| **NIST SP 800-53 Rev 5 Control Catalog** | NIST OSCAL (Public Domain) | Machine-readable JSON/XML OSCAL definitions mapping controls (`AC`, `AU`, `CM`, `IA`, `SC`) to network configuration checks. |
| **NCIIPC / CERT-In Best Practices** | NCIIPC India | Indian government security directives for Critical Information Infrastructure (CII) and perimeter hardening. |
| **Batfish Multi-Vendor Test Dataset** | Batfish GitHub (Apache 2.0) | Real-world sample configurations across Cisco, Juniper, Arista, Cumulus, and Palo Alto for testing your parsers. |

---

## 3. Step-by-Step Execution Plan for Person A

### Step 1: Define the Canonical Security Baseline Schema (Contract with Person B)
Coordinate with Person B to lock the JSON format. This model will be the single source of truth:
* `device_info`: `{ hostname, vendor, os_family, model, version, serial_number }`
* `aaa`: `{ password_encryption, min_password_length, login_banner_configured, login_banner_text, session_timeout_minutes, failed_logins_lockout }`
* `management_access`: `{ ssh_enabled, ssh_version, telnet_disabled, http_server_disabled, https_server_enabled, snmp_v1_v2_disabled, snmp_v3_enabled, vty_access_class_applied }`
* `logging_audit`: `{ syslog_servers_configured, logging_buffered_level, logging_timestamps_detail, console_logging_enabled }`
* `time_sync`: `{ ntp_servers_configured, ntp_authentication_enabled, timezone_set }`
* `network_security`: `{ ip_source_route_disabled, icmp_redirects_disabled, proxy_arp_disabled, syn_flood_defense_enabled, unicast_rpf_enabled }`
* `unmapped_lines`: `[ { line_number, raw_text, context } ]` *(Crucial: Pass all unrecognized lines here so Person B's AI engine can process them)*.

### Step 2: Implement Vendor Parsers
Build parsers in your backend engine (`parsers/` module):
1. **Cisco IOS / IOS-XE Parser** (using `ciscoconfparse2` and `ntc-templates`):
   * Query parent-child blocks:
     * Check for `service password-encryption`.
     * Check under `line vty 0 4`: verify `transport input ssh` and `exec-timeout <min> <sec>`.
     * Check `no ip http server` and `ip http secure-server`.
     * Check `ip ssh version 2`.
     * Check `logging host <IP>` and `service timestamps log datetime msec`.
     * Check `ntp server <IP>`.
2. **Juniper Junos Parser** (using hierarchical/set parsing & `Batfish`):
   * `set system services ssh protocol-version v2`
   * `delete system services web-management http`
   * `set system login idle-timeout <min>`
   * `set system syslog host <IP>`
   * `set system ntp server <IP>`
3. **Palo Alto PAN-OS Parser**:
   * Inspect XML/set commands for management access and permitted IPs.
4. **Fortinet FortiOS Parser**:
   * Inspect `config system global` and `config system admin` for disabled telnet, HTTPS redirects, and idle timeouts.
5. **White-Box / SONiC Linux & Unknown Vendors**:
   * Extract basic headers; pass non-standard lines to `unmapped_lines` for Person B's AI loop.

### Step 3: Implement the Multi-Framework Policy Engine
For every normalized configuration, execute the audit rule suite:
* **Output Structure for Every Rule Check**:
  * `rule_id`: e.g., `CIS-CISCO-1.2.1` or `DISA-STIG-V-215000`
  * `title`: "Enforce SSHv2 and Disable Insecure Telnet Management"
  * `frameworks`: `[ "CIS", "DISA_STIG", "NIST_SP_800_53", "ISO_27001" ]`
  * `control_reference`: `NIST: SC-8 | DISA STIG: V-215000 (CAT I) | ISO: A.8.20`
  * `severity`: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`
  * `status`: `PASS` / `FAIL` / `MANUAL_REVIEW`
  * `found_value`: "Telnet enabled on VTY 0-4; SSHv1 detected"
  * `expected_value`: "Telnet disabled; `transport input ssh`; `ip ssh version 2`"
  * `remediation_cli`: Ready-to-paste CLI commands (see Step 4).

### Step 4: Build the Device-Specific Remediation Generator
When a rule fails, render the exact CLI script using `Jinja2` templates and generate an `Ansible` playbook:
* **Example for Cisco IOS-XE Failure**:
  ```text
  configure terminal
  no ip http server
  ip http secure-server
  ip ssh version 2
  crypto key generate rsa modulus 2048
  line vty 0 4
   transport input ssh
   exec-timeout 10 0
  exit
  service timestamps log datetime msec
  logging host 10.10.10.50
  ntp server 10.10.10.1
  end
  write memory
  ```
* Include **Rollback instructions** for every remediation block.

### Step 5: Implement the Branded PDF Report Generator
Using `ReportLab`, generate a downloadable PDF report with:
1. **Header**: "NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) - Network Security Compliance Audit".
2. **Executive Summary**: Overall compliance score (e.g. 74%), Risk rating (High/Medium/Low), device metadata.
3. **Framework Scorecard**: Horizontal progress bars for CIS (82%), DISA STIG (68%), NIST (75%), ISO 27001 (80%).
4. **Detailed Findings Matrix**: Clean table listing Vuln ID, Control, Severity, Status, and Evidence.
5. **Remediation Annex**: Step-by-step CLI commands with copyable terminal formatting.
6. **Integrity Seal**: Compute the SHA-256 hash of the audit findings and print it at the bottom as a tamper-evident audit seal.

---

## 4. Deliverables Checklist for Person A
- [x] Live SSH ingestion module with `Netmiko` & `NAPALM` (`backend/ast_parser.py`, `/api/collector/netmiko-live`, `/api/collector/napalm-facts`).
- [x] Concurrent batch runner with `Nornir` / `Scrapli` (`backend/ast_parser.py`, `/api/collector/nornir-fleet`, `/api/collector/scrapli-async`).
- [x] Cisco IOS/NX-OS parser module with `CiscoConfParse2` & `ntc-templates` (`backend/ast_parser.py`, `/api/ast/parse`, `/api/ast/textfsm`).
- [x] Juniper Junos parser module with `Batfish` (`backend/ast_parser.py`, `/api/ast/batfish`).
- [x] Palo Alto PAN-OS & Fortinet FortiOS parsers (`backend/ast_parser.py`, `detect_device`).
- [x] CIS Benchmark audit rule suite (24 standard checks, CIS Level 1/2).
- [x] DISA STIG Cat I/II/III audit rule suite with official Vuln IDs from DoD XCCDF (`V-215000` to `V-215070`).
- [x] NIST SP 800-53 Rev 5 control mappings via OSCAL references (`AC`, `AU`, `CM`, `IA`, `SC`).
- [x] Remediation script generator with `Jinja2`, reverse rollback scripts, and Ansible playbook output (`remediation.yml`).
- [x] Programmatic PDF report generator with `ReportLab` & CNSA 2.0 SHA-512 cryptographic seal (`backend/pdf_generator.py`).
- [x] Policy-as-Code & Declarative Governance: OPA Rego (`/api/policy/opa-eval`), OpenSCAP XCCDF 1.2 XML (`/api/policy/xccdf`), Chef InSpec (`/api/policy/inspec`), Checkov (`/api/policy/checkov`), DefectDojo (`/api/policy/defectdojo`), OpenTofu/Terraform (`/api/remediation/terraform`).
- [x] Native C11 Performance Engine: Bit-exact SHA-512, Merkle tree, and 24-rule compliance engine running in <165 µs (`src_native/`, `bin/sentry_native.dll`).
- [x] Parser accuracy unit tests using the Batfish test dataset (`tests/test_person_a_systems.py`: 25/25 tests passed 100%).

