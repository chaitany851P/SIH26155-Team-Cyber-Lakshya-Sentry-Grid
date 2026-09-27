import urllib.request
import urllib.parse
import json

BASE_URL = "http://127.0.0.1:8090"

def test_dynamic_audit_juniper():
    juniper_cfg = """
set system host-name core-edge-juniper-01
set system services telnet
set system login retry-options backoff-threshold 3
"""
    data = urllib.parse.urlencode({'config_text': juniper_cfg}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/audit", data=data)
    res = urllib.request.urlopen(req).read().decode()
    
    assert 'id="remediation-container" hx-swap-oob="true"' in res, "Missing remediation-container OOB"
    assert 'delete system services telnet' in res, "Missing Juniper Junos specific remediation CLI"
    assert 'id="nav-ledger-height" hx-swap-oob="true"' in res, "Missing nav-ledger-height OOB"
    assert 'id="ledger-blocks-container" hx-swap-oob="true"' in res, "Missing ledger-blocks-container OOB"
    assert 'core-edge-juniper-01' in res, "Missing Juniper hostname in remediation bundle"
    print("[PASS] Juniper dynamic audit test passed: OOB swaps and vendor CLI present!")

def test_dynamic_audit_fortinet():
    fortinet_cfg = """
config system global
    set hostname sec-gw-fortinet-01
    set admin-sport 80
end
"""
    data = urllib.parse.urlencode({'config_text': fortinet_cfg}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/audit", data=data)
    res = urllib.request.urlopen(req).read().decode()
    
    assert 'id="remediation-container" hx-swap-oob="true"' in res
    assert 'Fortinet' in res
    assert 'sec-gw-fortinet-01' in res
    print("[PASS] Fortinet dynamic audit test passed: OOB swaps and Fortinet bundle present!")

def test_dynamic_pdf_report():
    req = urllib.request.Request(f"{BASE_URL}/api/report/pdf")
    res = urllib.request.urlopen(req).read()
    assert res.startswith(b"%PDF"), "Response is not a valid PDF file"
    assert len(res) > 2000, f"PDF file size too small: {len(res)} bytes"
    print(f"[PASS] Dynamic ReportLab PDF generated: {len(res)} bytes with valid PDF header!")

def test_dynamic_printable_certificate():
    req = urllib.request.Request(f"{BASE_URL}/api/report/audit")
    res = urllib.request.urlopen(req).read().decode()
    assert "Evaluated Hardening Controls & Violations" in res, "Missing findings table in certificate"
    assert "sec-gw-fortinet-01" in res or "core-edge-juniper-01" in res or "core-switch" in res
    print("[PASS] Dynamic printable certificate verified: contains live findings table and audited asset!")

def test_dynamic_crystallize():
    data = urllib.parse.urlencode({
        'raw_line': 'exec-timeout 15 0',
        'target_category': 'session_timeout',
        'assigned_value': '900',
        'vendor_scope': 'all'
    }).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/ai/crystallize", data=data)
    res = urllib.request.urlopen(req).read().decode()
    assert 'id="active-heuristics-grid" hx-swap-oob="true"' in res, "Missing active-heuristics-grid OOB"
    assert 'id="heuristics-count-badge" hx-swap-oob="true"' in res, "Missing heuristics-count-badge OOB"
    print("[PASS] Crystallize dynamic test passed: active heuristics grid & badge updated OOB!")

def test_nornir_fleet_htmx():
    data = urllib.parse.urlencode({'device_count': 5}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/collector/nornir-fleet", data=data, headers={"HX-Request": "true"})
    res = urllib.request.urlopen(req).read().decode()
    assert "Nornir Fleet Execution Result" in res
    assert "Compliant Nodes" in res
    print("[PASS] Nornir fleet HTMX dynamic test passed: live fleet execution scorecard rendered!")

def test_semantic_similarity_htmx():
    data = urllib.parse.urlencode({'command_line': 'no ip http server'}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/ai/similarity", data=data, headers={"HX-Request": "true"})
    res = urllib.request.urlopen(req).read().decode()
    assert "Sentence-Transformers Semantic Cosine Match" in res
    assert "Cosine Similarity Score" in res
    print("[PASS] Semantic similarity HTMX dynamic test passed: cosine match cards rendered!")

def test_ner_htmx():
    data = urllib.parse.urlencode({'command_line': 'logging host 10.99.100.15 transport udp port 514'}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/ai/ner", data=data, headers={"HX-Request": "true"})
    res = urllib.request.urlopen(req).read().decode()
    assert "Fast Deterministic Named Entities" in res
    assert "10.99.100.15" in res
    print("[PASS] Fast NER HTMX dynamic test passed: extracted entity badges rendered!")

def test_smt_prover_interactive():
    data_secure = urllib.parse.urlencode({'telnet_enabled': 'no', 'ssh_version': '2', 'timeout_seconds': 600}).encode()
    req_sec = urllib.request.Request(f"{BASE_URL}/api/ai/smt-prove", data=data_secure)
    res_sec = urllib.request.urlopen(req_sec).read().decode()
    assert "UNSAT: Invariant Mathematically Proven Secure" in res_sec

    data_vuln = urllib.parse.urlencode({'telnet_enabled': 'yes', 'ssh_version': '1', 'timeout_seconds': 1800}).encode()
    req_vuln = urllib.request.Request(f"{BASE_URL}/api/ai/smt-prove", data=data_vuln)
    res_vuln = urllib.request.urlopen(req_vuln).read().decode()
    assert "SAT: Vulnerability Counterexample Synthesized" in res_vuln
    print("[PASS] Interactive Microsoft Z3 SMT Theorem Prover test passed: formal SAT/UNSAT proofs rendered!")

def test_ast_parse_htmx():
    cisco_cfg = """
hostname edge-core-01
line vty 0 4
 transport input telnet
 exec-timeout 30 0
service password-encryption
"""
    data = urllib.parse.urlencode({'config_text': cisco_cfg}).encode()
    req = urllib.request.Request(f"{BASE_URL}/api/ast/parse", data=data, headers={"HX-Request": "true"})
    res = urllib.request.urlopen(req).read().decode()
    assert "Hierarchical AST Parse (CiscoConfParse2 Engine)" in res
    assert "VTY Blocks" in res
    assert "Telnet State" in res
    print("[PASS] Deterministic AST parser HTMX test passed: hierarchical tree card rendered!")

def test_opa_rego_htmx():
    req = urllib.request.Request(f"{BASE_URL}/api/policy/opa-eval", data=b"", headers={"HX-Request": "true"})
    res = urllib.request.urlopen(req).read().decode()
    assert "Open Policy Agent (OPA) / Rego Decision Engine" in res
    assert "Decision Path" in res
    print("[PASS] Open Policy Agent (OPA) / Rego HTMX test passed: policy decision card rendered!")

def test_checkov_cloud_htmx():
    req = urllib.request.Request(f"{BASE_URL}/api/policy/checkov", data=b"", headers={"HX-Request": "true"})
    res = urllib.request.urlopen(req).read().decode()
    assert "Checkov Static Analysis Engine" in res
    assert "Passed" in res and "Failed" in res
    print("[PASS] Checkov Cloud Static Analysis HTMX test passed: security group card rendered!")

def test_openconfig_yang_htmx():
    req = urllib.request.Request(f"{BASE_URL}/api/ast/openconfig-validate", data=b"", headers={"HX-Request": "true"})
    res = urllib.request.urlopen(req).read().decode()
    assert "Pyang & OpenConfig YANG Validator" in res
    assert "openconfig-system.yang" in res
    print("[PASS] Pyang & OpenConfig YANG HTMX test passed: RFC 6020 conformance card rendered!")

def test_ledger_explorer_ui():
    req = urllib.request.Request(f"{BASE_URL}/ledger")
    res = urllib.request.urlopen(req).read().decode()
    assert "ledger-search-input" in res, "Missing ledger search input"
    assert "visible-blocks-count" in res, "Missing visible-blocks-count element"
    assert "cyber-toast" in res, "Missing cyber-toast in ledger explorer"
    print("[PASS] Ledger explorer UI verified: real-time search filter and toast alerts present!")

def test_index_ui_elements():
    req = urllib.request.Request(f"{BASE_URL}/")
    res = urllib.request.urlopen(req).read().decode()
    assert "Multi-Vendor Quick Audit" in res, "Missing quick audit grid"
    assert "Nornir Fleet Auditor" in res, "Missing nornir fleet card"
    assert "fix-modal" in res, "Missing fix modal dialog"
    assert "openFixModal" in res, "Missing openFixModal function"
    assert "query-hash-input" in res, "Missing query-hash-input"
    assert "stat-lines" in res, "Missing stat-lines counter"
    assert "stat-vendor" in res, "Missing stat-vendor badge"
    assert "ast-inspector-results" in res, "Missing ast-inspector-results container"
    assert "cyber-toast" in res, "Missing cyber-toast container"
    assert "Interactive Policy-as-Code & Cloud Perimeter Lab" in res, "Missing Policy-as-Code Lab in Tab 3"
    print("[PASS] Index UI elements verified: telemetry counters, syntax detector, AST inspector, toast, and Policy Lab present!")

if __name__ == "__main__":
    print("Running end-to-end verification of dynamic features...")
    test_dynamic_audit_juniper()
    test_dynamic_audit_fortinet()
    test_dynamic_pdf_report()
    test_dynamic_printable_certificate()
    test_dynamic_crystallize()
    test_nornir_fleet_htmx()
    test_semantic_similarity_htmx()
    test_ner_htmx()
    test_smt_prover_interactive()
    test_ast_parse_htmx()
    test_opa_rego_htmx()
    test_checkov_cloud_htmx()
    test_openconfig_yang_htmx()
    test_ledger_explorer_ui()
    test_index_ui_elements()
    print("\nALL DYNAMIC INTERACTION TESTS (15/15) PASSED 100%!")
