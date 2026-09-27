from fastapi.testclient import TestClient
from backend.server import app

client = TestClient(app)

def test_dynamic_audit_juniper():
    juniper_cfg = """
set system host-name core-edge-juniper-01
set system services telnet
set system login retry-options backoff-threshold 3
"""
    res = client.post("/api/audit", data={'config_text': juniper_cfg}).text
    assert 'id="remediation-container" hx-swap-oob="true"' in res, "Missing remediation-container OOB"
    assert 'delete system services telnet' in res, "Missing Juniper Junos specific remediation CLI"
    assert 'id="nav-ledger-height" hx-swap-oob="true"' in res, "Missing nav-ledger-height OOB"
    assert 'id="ledger-blocks-container" hx-swap-oob="true"' in res, "Missing ledger-blocks-container OOB"
    assert 'core-edge-juniper-01' in res, "Missing Juniper hostname in remediation bundle"

def test_dynamic_audit_fortinet():
    fortinet_cfg = """
config system global
    set hostname sec-gw-fortinet-01
    set admin-sport 80
end
"""
    res = client.post("/api/audit", data={'config_text': fortinet_cfg}).text
    assert 'id="remediation-container" hx-swap-oob="true"' in res
    assert 'Fortinet' in res
    assert 'sec-gw-fortinet-01' in res

def test_dynamic_pdf_report():
    res = client.get("/api/report/pdf").content
    assert res.startswith(b"%PDF"), "Response is not a valid PDF file"
    assert len(res) > 2000, f"PDF file size too small: {len(res)} bytes"

def test_dynamic_printable_certificate():
    res = client.get("/api/report/audit").text
    assert "Evaluated Hardening Controls & Violations" in res, "Missing findings table in certificate"
    assert "sec-gw-fortinet-01" in res or "core-edge-juniper-01" in res or "core-switch" in res

def test_dynamic_crystallize():
    data = {
        'raw_line': 'exec-timeout 15 0',
        'target_category': 'session_timeout',
        'assigned_value': '900',
        'vendor_scope': 'all'
    }
    res = client.post("/api/ai/crystallize", data=data).text
    assert 'id="active-heuristics-grid" hx-swap-oob="true"' in res, "Missing active-heuristics-grid OOB"
    assert 'id="heuristics-count-badge" hx-swap-oob="true"' in res, "Missing heuristics-count-badge OOB"

def test_nornir_fleet_htmx():
    res = client.post("/api/collector/nornir-fleet", data={'device_count': 5}, headers={"HX-Request": "true"}).text
    assert "Nornir Fleet Execution Result" in res
    assert "Compliant Nodes" in res

def test_semantic_similarity_htmx():
    res = client.post("/api/ai/similarity", data={'command_line': 'no ip http server'}, headers={"HX-Request": "true"}).text
    assert "Sentence-Transformers Semantic Cosine Match" in res
    assert "Cosine Similarity Score" in res

def test_ner_htmx():
    res = client.post("/api/ai/ner", data={'command_line': 'logging host 10.99.100.15 transport udp port 514'}, headers={"HX-Request": "true"}).text
    assert "Fast Deterministic Named Entities" in res
    assert "10.99.100.15" in res

def test_smt_prover_interactive():
    data_secure = {'telnet_enabled': 'no', 'ssh_version': '2', 'timeout_seconds': 600}
    res_sec = client.post("/api/ai/smt-prove", data=data_secure).text
    assert "UNSAT: Invariant Mathematically Proven Secure" in res_sec

    data_vuln = {'telnet_enabled': 'yes', 'ssh_version': '1', 'timeout_seconds': 1800}
    res_vuln = client.post("/api/ai/smt-prove", data=data_vuln).text
    assert "SAT: Vulnerability Counterexample Synthesized" in res_vuln

def test_ast_parse_htmx():
    cisco_cfg = """
hostname edge-core-01
line vty 0 4
 transport input telnet
 exec-timeout 30 0
service password-encryption
"""
    res = client.post("/api/ast/parse", data={'config_text': cisco_cfg}, headers={"HX-Request": "true"}).text
    assert "Hierarchical AST Parse (CiscoConfParse2 Engine)" in res
    assert "VTY Blocks" in res
    assert "Telnet State" in res

def test_opa_rego_htmx():
    res = client.post("/api/policy/opa-eval", data={}, headers={"HX-Request": "true"}).text
    assert "Open Policy Agent (OPA) / Rego Decision Engine" in res
    assert "Decision Path" in res

def test_checkov_cloud_htmx():
    res = client.post("/api/policy/checkov", data={}, headers={"HX-Request": "true"}).text
    assert "Checkov Static Analysis Engine" in res
    assert "Passed" in res and "Failed" in res

def test_openconfig_yang_htmx():
    res = client.post("/api/ast/openconfig-validate", data={}, headers={"HX-Request": "true"}).text
    assert "Pyang & OpenConfig YANG Validator" in res
    assert "openconfig-system.yang" in res

def test_ledger_explorer_ui():
    res = client.get("/ledger").text
    assert "ledger-search-input" in res, "Missing ledger search input"
    assert "visible-blocks-count" in res, "Missing visible-blocks-count element"
    assert "cyber-toast" in res, "Missing cyber-toast in ledger explorer"

def test_index_ui_elements():
    res = client.get("/").text
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
