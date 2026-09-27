import urllib.request
import urllib.parse
import json
import sys

BASE_URL = "http://127.0.0.1:8090"

def get(path, headers=None):
    req = urllib.request.Request(f"{BASE_URL}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.getcode(), resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers

def post(path, data=None, headers=None):
    req_headers = headers or {}
    encoded_data = None
    if isinstance(data, dict):
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")
        if "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif isinstance(data, (bytes, str)):
        encoded_data = data.encode("utf-8") if isinstance(data, str) else data
    req = urllib.request.Request(f"{BASE_URL}{path}", data=encoded_data, headers=req_headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.getcode(), resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers

passed_tests = 0
failed_tests = 0
results = []

def record_test(name, passed, detail=""):
    global passed_tests, failed_tests
    if passed:
        passed_tests += 1
        print(f"  [PASS] {name} - {detail}")
        results.append((name, "PASS", detail))
    else:
        failed_tests += 1
        print(f"  [FAIL] {name} - {detail}")
        results.append((name, "FAIL", detail))

print("=====================================================================")
print("STARTING EXHAUSTIVE FEATURE & ENDPOINT QA SUITE (PORT 8090)")
print("=====================================================================\n")

# 1. ROOT & MAIN DASHBOARD
print("[1] Testing Main Dashboard (GET /)")
code, body, _ = get("/")
text = body.decode("utf-8", errors="ignore")
record_test("Dashboard Status Code", code == 200, f"HTTP {code}")
record_test("Dashboard Title & Brand", "SENTRY-GRID" in text and "NTRO Defense Edition" in text)
record_test("Dashboard Tabs Present", all(t in text for t in ["tab-btn-audit-hub", "tab-btn-laya-studio", "tab-btn-remediation-hub", "tab-btn-ledger-hub"]))
record_test("Multi-Vendor Presets Loaded", "Multi-Vendor Quick Audit" in text and "preset-btn-cisco-ios" in text)
record_test("Telemetry Counters Exist", all(el in text for el in ["stat-lines", "stat-words", "stat-chars", "stat-vendor"]))
record_test("Action Modals & Toasts", "fix-modal" in text and "cyber-toast" in text)

# 2. AUDIT ENGINE & MULTI-VENDOR
print("\n[2] Testing Audit Engine (POST /api/audit)")
cisco_cfg = """
hostname core-switch-cisco
line vty 0 4
 transport input telnet
 exec-timeout 30 0
service password-encryption
no ip http server
"""
code, body, _ = post("/api/audit", {"config_text": cisco_cfg})
text = body.decode("utf-8", errors="ignore")
record_test("Cisco Audit Execution", code == 200 and "core-switch-cisco" in text)
record_test("Cisco Out-of-Band Swaps Present", 'id="remediation-container" hx-swap-oob="true"' in text and 'id="nav-ledger-height" hx-swap-oob="true"' in text)
record_test("Cisco Z3 Formal Proof", "Microsoft Z3" in text)
record_test("Cisco Findings Table", "Findings & Vulnerability Matrix" in text)

# Multi-vendor: Juniper
juniper_cfg = """
set system host-name core-edge-juniper
set system services telnet
"""
code, body, _ = post("/api/audit", {"config_text": juniper_cfg})
text = body.decode("utf-8", errors="ignore")
record_test("Juniper Audit Execution", code == 200 and "delete system services telnet" in text and "core-edge-juniper" in text)

# Multi-vendor: Fortinet
fortinet_cfg = """
config system global
    set hostname fw-fortinet-01
    set admin-sport 80
end
"""
code, body, _ = post("/api/audit", {"config_text": fortinet_cfg})
text = body.decode("utf-8", errors="ignore")
record_test("Fortinet Audit Execution", code == 200 and "Fortinet" in text and "fw-fortinet-01" in text)

# Multi-vendor: Palo Alto PAN-OS
palo_cfg = """
<config version="10.2.0">
  <mgt-config>
    <users><entry name="admin"/></users>
  </mgt-config>
</config>
"""
code, body, _ = post("/api/audit", {"config_text": palo_cfg})
text = body.decode("utf-8", errors="ignore")
record_test("Palo Alto Audit Execution", code == 200 and "Palo Alto" in text)

# Multi-vendor: Arista EOS
arista_cfg = """
hostname arista-spine-01
management api http-commands
 no shutdown
"""
code, body, _ = post("/api/audit", {"config_text": arista_cfg})
text = body.decode("utf-8", errors="ignore")
record_test("Arista EOS Audit Execution", code == 200 and "Arista" in text)

# Multi-vendor: SONiC Linux
sonic_cfg = """
{
  "DEVICE_METADATA": {
    "localhost": {
      "hostname": "sonic-switch-01",
      "type": "LeafRouter"
    }
  }
}
"""
code, body, _ = post("/api/audit", {"config_text": sonic_cfg})
text = body.decode("utf-8", errors="ignore")
record_test("SONiC Linux Audit Execution", code == 200 and ("SONiC" in text or "sonic-switch-01" in text))

# Negative Audit Tests
code, body, _ = post("/api/audit", {"config_text": "   "})
text = body.decode("utf-8", errors="ignore")
record_test("Audit Empty Config Rejection", code == 200 and "Empty Configuration Input" in text)

code, body, _ = post("/api/audit", {"config_text": "A" * (2 * 1024 * 1024)})
text = body.decode("utf-8", errors="ignore")
record_test("Audit Payload Limit Guard (>1MB)", code in (400, 413) or "exceeded maximum size" in text.lower() or "limit" in text.lower())

# 3. LAYA AI COMMAND EVALUATE & LOGIT INSPECTOR
print("\n[3] Testing Laya AI Command Evaluation (POST /api/ai/evaluate)")
code, body, _ = post("/api/ai/evaluate", {"command_line": "idle-timeout 15", "vendor_scope": "all"})
text = body.decode("utf-8", errors="ignore")
record_test("Laya Inference Evaluation", code == 200 and "idle-timeout 15" in text and "PyTorch" in text)
record_test("Laya Softmax Distribution & Embedding", "PyTorch Neural Head Softmax Distribution" in text and "Latent Vector Embedding" in text)

code, body, _ = post("/api/ai/evaluate", {"command_line": "   "})
text = body.decode("utf-8", errors="ignore")
record_test("Laya Empty Command Rejection", "Please enter a command to evaluate" in text)

# 4. CRYSTALLIZE RULE CACHE
print("\n[4] Testing Rule Crystallization & Backprop (POST /api/ai/crystallize)")
code, body, _ = post("/api/ai/crystallize", {
    "raw_line": "custom-timeout 450",
    "target_category": "aaa.session_timeout_minutes",
    "assigned_value": "450",
    "vendor_scope": "all"
})
text = body.decode("utf-8", errors="ignore")
record_test("Rule Crystallization Execution", code == 200 and "Rule Crystallized" in text and "AdamW Loss" in text)
record_test("Crystallize OOB Cache Update", 'id="active-heuristics-grid" hx-swap-oob="true"' in text and 'id="heuristics-count-badge" hx-swap-oob="true"' in text)

code, body, _ = post("/api/ai/crystallize", {"raw_line": "", "target_category": ""})
text = body.decode("utf-8", errors="ignore")
record_test("Crystallize Empty Input Rejection", code in (400, 422) or "must not be empty" in text)

# 5. BATCH DATASET LOAD
print("\n[5] Testing Benchmark Batch Dataset (POST /api/ai/load-batch)")
code, body, _ = post("/api/ai/load-batch", {})
text = body.decode("utf-8", errors="ignore")
record_test("Batch Dataset Loaded", code == 200 and "Confirm & Crystallize Rule" in text and "L-101" in text)

# 6. TRAINING DATASET INSPECTOR
print("\n[6] Testing Training Dataset (GET /api/ai/dataset)")
code, body, _ = get("/api/ai/dataset", headers={"Accept": "text/html"})
text = body.decode("utf-8", errors="ignore")
record_test("Training Dataset HTML Table", code == 200 and "Laya AI Supervised Training Corpus" in text and "Corpus ID" in text)

code, body, _ = get("/api/ai/dataset?format=json")
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Training Dataset JSON Export", code == 200 and isinstance(data, list) and len(data) > 0, f"{len(data)} items")
except Exception as e:
    record_test("Training Dataset JSON Export", False, str(e))

# 7. SEMANTIC SIMILARITY
print("\n[7] Testing Semantic Vector Matcher (POST /api/ai/similarity)")
code, body, _ = post("/api/ai/similarity", {"command_line": "no ip http server"}, headers={"HX-Request": "true"})
text = body.decode("utf-8", errors="ignore")
record_test("Semantic Similarity HTMX Match", code == 200 and "Sentence-Transformers Semantic Cosine Match" in text and "Cosine Similarity Score" in text)

code, body, _ = post("/api/ai/similarity", {"command_line": "no ip http server"})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Semantic Similarity JSON Output", code == 200 and "cosine_similarity" in data and "top_category" in data)
except Exception as e:
    record_test("Semantic Similarity JSON Output", False, str(e))

code, body, _ = post("/api/ai/similarity", {"command_line": ""})
record_test("Semantic Similarity Empty Input", code in (400, 422) or "Empty command" in body.decode("utf-8"))

# 8. FAST DETERMINISTIC NER
print("\n[8] Testing Fast CLI NER (POST /api/ai/ner)")
code, body, _ = post("/api/ai/ner", {"command_line": "logging host 10.99.100.15 transport udp port 514"}, headers={"HX-Request": "true"})
text = body.decode("utf-8", errors="ignore")
record_test("Fast NER HTMX Badges", code == 200 and "Fast Deterministic Named Entities" in text and "10.99.100.15" in text and "514" in text)

code, body, _ = post("/api/ai/ner", {"command_line": "crypto ipsec transform-set ESP-AES256 esp-aes 256 esp-sha512-hmac"})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Fast NER JSON Output", code == 200 and isinstance(data.get("ciphers"), list))
except Exception as e:
    record_test("Fast NER JSON Output", False, str(e))

code, body, _ = post("/api/ai/ner", {"command_line": ""})
record_test("Fast NER Empty Input", code in (400, 422) or "Empty command" in body.decode("utf-8"))

# 9. MICROSOFT Z3 SMT THEOREM PROVER
print("\n[9] Testing Microsoft Z3 SMT Theorem Prover (POST /api/ai/smt-prove)")
code, body, _ = post("/api/ai/smt-prove", {"telnet_enabled": "no", "ssh_version": "2", "timeout_seconds": "600"})
text = body.decode("utf-8", errors="ignore")
record_test("Z3 SMT Invariant Proven Secure (UNSAT)", code == 200 and "UNSAT: Invariant Mathematically Proven Secure" in text)

code, body, _ = post("/api/ai/smt-prove", {"telnet_enabled": "yes", "ssh_version": "1", "timeout_seconds": "1800"})
text = body.decode("utf-8", errors="ignore")
record_test("Z3 SMT Counterexample Synthesized (SAT)", code == 200 and "SAT: Vulnerability Counterexample Synthesized" in text)

# 10. ACTIVE LEARNING QUERY UNCERTAINTY
print("\n[10] Testing Active Learning Uncertainty (POST /api/ai/active-learning/query)")
code, body, _ = post("/api/ai/active-learning/query", {"command_line": "snmp-server community private RW"})
try:
    data = json.loads(body.decode("utf-8"))
    metrics = data.get("active_learning_metrics", {})
    record_test("Active Learning Query Metrics", code == 200 and "shannon_entropy" in metrics and "margin_score" in metrics)
except Exception as e:
    record_test("Active Learning Query Metrics", False, str(e))

# 11. SAMPLES API
print("\n[11] Testing Batfish Multi-Vendor Samples API")
code, body, _ = get("/api/samples/list")
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Samples List API", code == 200 and data.get("total", 0) > 0, f"{data.get('total')} samples")
except Exception as e:
    record_test("Samples List API", False, str(e))

code, body, _ = get("/api/samples/cisco_ios_xe_sample.cfg")
record_test("Sample Retrieval (cisco_ios_xe)", code == 200 and "hostname" in body.decode("utf-8", errors="ignore"))

code, body, _ = get("/api/samples/non_existent_file.cfg")
record_test("Sample Missing File Rejection (404)", code == 404)

# 12. AST PARSING (CiscoConfParse2)
print("\n[12] Testing Hierarchical AST Parsing (POST /api/ast/parse)")
cisco_ast_cfg = "hostname edge-router\nline vty 0 4\n transport input ssh\n exec-timeout 10 0\n"
code, body, _ = post("/api/ast/parse", {"config_text": cisco_ast_cfg}, headers={"HX-Request": "true"})
text = body.decode("utf-8", errors="ignore")
record_test("AST Parser HTMX Card", code == 200 and "Hierarchical AST Parse (CiscoConfParse2 Engine)" in text and "VTY Blocks" in text)

code, body, _ = post("/api/ast/parse", {"config_text": cisco_ast_cfg})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("AST Parser JSON Output", code == 200 and data.get("vty_blocks_found") >= 1)
except Exception as e:
    record_test("AST Parser JSON Output", False, str(e))

code, body, _ = post("/api/ast/parse", {"config_text": ""})
record_test("AST Parser Empty Input", code in (400, 422) or "Empty configuration" in body.decode("utf-8"))

# 13. HIER CONFIG DIFF
print("\n[13] Testing Hierarchical Config Diff (POST /api/ast/hier-diff)")
code, body, _ = post("/api/ast/hier-diff", {
    "running_config": "line vty 0 4\n transport input telnet\n",
    "target_baseline": "line vty 0 4\n transport input ssh\n"
})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Hier Config Diff Execution", code == 200 and ("remediation_steps" in data or "remediation_commands" in data))
except Exception as e:
    record_test("Hier Config Diff Execution", False, str(e))

# 14. TTP TEMPLATE PARSER
print("\n[14] Testing TTP Parser (POST /api/ast/ttp)")
code, body, _ = post("/api/ast/ttp", {
    "raw_cli": "interface GigabitEthernet0/1\n ip address 192.168.1.1 255.255.255.0\n",
    "template_syntax": ""
})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("TTP Parser Execution", code == 200 and "ttp_parsed" in data)
except Exception as e:
    record_test("TTP Parser Execution", False, str(e))

# 15. COLLECTOR POLL INTERFACE
print("\n[15] Testing Device Collector Poll (POST /api/collector/poll)")
code, body, _ = post("/api/collector/poll", {
    "host": "10.0.0.1",
    "platform": "cisco_ios",
    "port": "22"
})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Collector Poll Dispatch", code == 200 and data.get("status") in ("DRY_RUN_READY", "DISPATCH_READY"))
except Exception as e:
    record_test("Collector Poll Dispatch", False, str(e))

# 16. NAPALM GET_FACTS & GET_CONFIG
print("\n[16] Testing NAPALM Integration")
code, body, _ = post("/api/collector/napalm-facts", {"hostname": "core-router-01", "platform": "ios"})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("NAPALM get_facts Abstraction", code == 200 and "hostname" in data and "vendor" in data)
except Exception as e:
    record_test("NAPALM get_facts Abstraction", False, str(e))

code, body, _ = post("/api/collector/napalm-config", {"hostname": "core-router-01", "platform": "ios"})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("NAPALM get_config Abstraction", code == 200 and "running" in data)
except Exception as e:
    record_test("NAPALM get_config Abstraction", False, str(e))

# 17. NORNIR FLEET AUDITOR
print("\n[17] Testing Nornir Fleet Auditor (POST /api/collector/nornir-fleet)")
code, body, _ = post("/api/collector/nornir-fleet", {"device_count": "5"}, headers={"HX-Request": "true"})
text = body.decode("utf-8", errors="ignore")
record_test("Nornir Fleet HTMX Scorecard", code == 200 and "Nornir Fleet Execution Result" in text and "Compliant Nodes" in text)

code, body, _ = post("/api/collector/nornir-fleet", {"device_count": "5"})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Nornir Fleet JSON Output", code == 200 and (data.get("total_devices") == 5 or data.get("total_devices_audited") == 5))
except Exception as e:
    record_test("Nornir Fleet JSON Output", False, str(e))

# 18. TEXTFSM PARSER
print("\n[18] Testing TextFSM CLI Parser (POST /api/ast/textfsm)")
code, body, _ = post("/api/ast/textfsm", {
    "command": "show version",
    "raw_output": "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE4",
    "platform": "cisco_ios"
})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("TextFSM Parsing Execution", code == 200 and "parsed_records" in data)
except Exception as e:
    record_test("TextFSM Parsing Execution", False, str(e))

# 19. CISCO GENIE PARSER
print("\n[19] Testing Cisco Genie Parser (POST /api/ast/genie)")
code, body, _ = post("/api/ast/genie", {
    "command": "show version",
    "raw_output": "Cisco IOS XE Software, Version 17.03.04a",
    "platform": "cisco_ios"
})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Genie Parsing Execution", code == 200 and ("parsed_result" in data or "parsed_structure" in data))
except Exception as e:
    record_test("Genie Parsing Execution", False, str(e))

# 20. PYANG & OPENCONFIG YANG VALIDATOR
print("\n[20] Testing OpenConfig YANG Validator (POST /api/ast/openconfig-validate)")
code, body, _ = post("/api/ast/openconfig-validate", {"config_json": "{}"}, headers={"HX-Request": "true"})
text = body.decode("utf-8", errors="ignore")
record_test("OpenConfig YANG HTMX Card", code == 200 and "OpenConfig YANG Validator" in text and ("YANG CONFORMANT" in text or "YANG VIOLATION" in text))

code, body, _ = post("/api/ast/openconfig-validate", {"config_json": "{}"})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("OpenConfig YANG JSON Output", code == 200 and "modules_validated" in data)
except Exception as e:
    record_test("OpenConfig YANG JSON Output", False, str(e))

# 21. OPEN POLICY AGENT (OPA) & REGO
print("\n[21] Testing OPA & Rego Engine")
code, body, _ = post("/api/policy/opa-eval", {"config_json": "{}"}, headers={"HX-Request": "true"})
text = body.decode("utf-8", errors="ignore")
record_test("OPA Rego HTMX Evaluation", code == 200 and "Open Policy Agent (OPA) / Rego Decision Engine" in text and "OPA COMPLIANT" in text)

code, body, _ = post("/api/policy/opa-eval", {"config_json": "{}"})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("OPA Rego JSON Output", code == 200 and data.get("compliant") is True and "compliance" in data.get("package", ""))
except Exception as e:
    record_test("OPA Rego JSON Output", False, str(e))

code, body, _ = get("/api/policy/rego")
text = body.decode("utf-8", errors="ignore")
record_test("OPA Rego Source Code Export", code == 200 and "package " in text and "deny[" in text)

# 22. CHECKOV CLOUD SECURITY GROUPS
print("\n[22] Testing Checkov Cloud Static Analysis (POST /api/policy/checkov)")
code, body, _ = post("/api/policy/checkov", {}, headers={"HX-Request": "true"})
text = body.decode("utf-8", errors="ignore")
record_test("Checkov Cloud HTMX Card", code == 200 and "Checkov Static Analysis Engine" in text and "Passed" in text and "Failed" in text)

code, body, _ = post("/api/policy/checkov", {})
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Checkov Cloud JSON Output", code == 200 and ("passed_checks" in data or "passed_checks_count" in data))
except Exception as e:
    record_test("Checkov Cloud JSON Output", False, str(e))

# 23. OPENSCAP XCCDF XML
print("\n[23] Testing OpenSCAP XCCDF Export (GET /api/policy/xccdf)")
code, body, headers = get("/api/policy/xccdf")
text = body.decode("utf-8", errors="ignore")
record_test("OpenSCAP XCCDF XML Generation", code == 200 and "xccdf" in text and "Benchmark" in text)

# 24. CHEF INSPEC PROFILE
print("\n[24] Testing Chef InSpec Profile (GET /api/policy/inspec)")
code, body, _ = get("/api/policy/inspec")
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Chef InSpec Profile JSON", code == 200 and ("controls" in data or "inspec.yml" in data))
except Exception as e:
    record_test("Chef InSpec Profile JSON", False, str(e))

# 25. DEFECTDOJO SIEM EXPORT
print("\n[25] Testing DefectDojo SIEM Export (GET /api/policy/defectdojo)")
code, body, _ = get("/api/policy/defectdojo")
try:
    data = json.loads(body.decode("utf-8"))
    record_test("DefectDojo SIEM JSON", code == 200 and "findings" in data and ("format" in data or "defectdojo_import_version" in data))
except Exception as e:
    record_test("DefectDojo SIEM JSON", False, str(e))

# 26. OPENTOFU / TERRAFORM IAC
print("\n[26] Testing OpenTofu / Terraform IaC Plan (GET /api/remediation/terraform)")
code, body, _ = get("/api/remediation/terraform")
text = body.decode("utf-8", errors="ignore")
record_test("Terraform IaC Plan Generation", code == 200 and "resource \"aws_security_group\"" in text)

# 27. CERTIFIED REPORTLAB PDF EXPORT
print("\n[27] Testing Official ReportLab PDF (GET /api/report/pdf)")
code, body, headers = get("/api/report/pdf")
record_test("ReportLab PDF Binary Valid", code == 200 and body.startswith(b"%PDF") and len(body) > 2000, f"{len(body)} bytes")
record_test("ReportLab PDF Header Attachment", "filename=" in headers.get("Content-Disposition", ""))

# 28. PRINTABLE CERTIFICATE
print("\n[28] Testing Printable Audit Certificate (GET /api/report/audit)")
code, body, _ = get("/api/report/audit")
text = body.decode("utf-8", errors="ignore")
record_test("Printable Certificate HTML", code == 200 and "National Technical Research Organisation" in text and "OFFICIAL CYBERSECURITY & COMPLIANCE VERIFICATION CERTIFICATE" in text)

# 29. BLOCKCHAIN EXPLORER GUI & BLOCKS API
print("\n[29] Testing Sovereign Ledger Explorer GUI & Blocks API")
code, body, _ = get("/ledger")
text = body.decode("utf-8", errors="ignore")
record_test("Ledger Explorer Web GUI (/ledger)", code == 200 and "Sovereign Ledger Explorer" in text and "ledger-search-input" in text and "visible-blocks-count" in text)

code, body, _ = get("/api/ledger/blocks?format=json")
try:
    blocks = json.loads(body.decode("utf-8"))
    record_test("Ledger Blocks JSON API", code == 200 and isinstance(blocks, list) and len(blocks) >= 1)
    latest_seal = blocks[-1]["audit_seal"]
    latest_audit_id = blocks[-1]["audit_id"]
    latest_hash = blocks[-1]["block_hash"]
except Exception as e:
    record_test("Ledger Blocks JSON API", False, str(e))
    latest_seal = ""
    latest_audit_id = ""
    latest_hash = ""

# 30. ON-CHAIN CRYPTOGRAPHIC SEAL VERIFICATION
print("\n[30] Testing On-Chain Cryptographic Seal Verification (POST /api/ledger/verify)")
if latest_seal:
    code, body, _ = post("/api/ledger/verify", {"query_hash": latest_seal})
    text = body.decode("utf-8", errors="ignore")
    record_test("Verify Authentic Seal On-Chain", code == 200 and "CRYPTOGRAPHIC INTEGRITY VERIFIED" in text and "Bit-for-Bit Verified" in text)

    code, body, _ = post("/api/ledger/verify", {"query_hash": latest_audit_id})
    text = body.decode("utf-8", errors="ignore")
    record_test("Verify Audit ID On-Chain", code == 200 and "CRYPTOGRAPHIC INTEGRITY VERIFIED" in text)

    code, body, _ = post("/api/ledger/verify", {"query_hash": latest_hash})
    text = body.decode("utf-8", errors="ignore")
    record_test("Verify Block Hash On-Chain", code == 200 and "CRYPTOGRAPHIC INTEGRITY VERIFIED" in text)

    # Negative: Truncated Seal
    code, body, _ = post("/api/ledger/verify", {"query_hash": latest_seal[:40]})
    text = body.decode("utf-8", errors="ignore")
    record_test("Verify Truncated Seal Rejection", code == 200 and "CRYPTOGRAPHIC VERIFICATION FAILED: TRUNCATED / TAMPERED HASH" in text)

# Negative: Completely Unknown Seal
code, body, _ = post("/api/ledger/verify", {"query_hash": "deadbeef" * 16})
text = body.decode("utf-8", errors="ignore")
record_test("Verify Unknown Seal Rejection", code == 200 and "INVALID CRYPTOGRAPHIC SEAL: NOT FOUND ON-CHAIN" in text)

# Negative: Blank Input
code, body, _ = post("/api/ledger/verify", {"query_hash": "   "})
text = body.decode("utf-8", errors="ignore")
record_test("Verify Blank Input Warning", code == 200 and "Please enter a SHA-512 seal" in text)

# 31. HEALTH CHECK & OPENAPI DOCS
print("\n[31] Testing Health Check & API Specifications")
code, body, _ = get("/health")
try:
    data = json.loads(body.decode("utf-8"))
    record_test("Health Endpoint (/health)", code == 200 and data.get("status") == "HEALTHY")
except Exception as e:
    record_test("Health Endpoint (/health)", False, str(e))

code, body, _ = get("/openapi.json")
try:
    data = json.loads(body.decode("utf-8"))
    record_test("OpenAPI Specification (/openapi.json)", code == 200 and "paths" in data and len(data["paths"]) >= 25)
except Exception as e:
    record_test("OpenAPI Specification (/openapi.json)", False, str(e))

code, body, _ = get("/docs")
record_test("Interactive Swagger UI (/docs)", code == 200 and "swagger-ui" in body.decode("utf-8", errors="ignore").lower())

print("\n=====================================================================")
print(f"EXHAUSTIVE QA TEST RESULTS SUMMARY:")
print(f"  TOTAL TESTS RUN : {passed_tests + failed_tests}")
print(f"  TESTS PASSED    : {passed_tests}")
print(f"  TESTS FAILED    : {failed_tests}")
print(f"  PASS RATE       : {(passed_tests / (passed_tests + failed_tests)) * 100:.1f}%")
print("=====================================================================")

if failed_tests > 0:
    sys.exit(1)
else:
    sys.exit(0)
