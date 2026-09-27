"""
SENTRY-GRID Exhaustive Feature & Endpoint QA Suite
Verifies all 31 critical components, endpoints, and multi-vendor compliance modules
using FastAPI TestClient for in-memory, deterministic testing.
"""

import unittest
import json
from fastapi.testclient import TestClient
from backend.server import app


class TestAllFeaturesExhaustive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def get(self, path, headers=None):
        resp = self.client.get(path, headers=headers or {})
        return resp.status_code, resp.content, resp.headers

    def post(self, path, data=None, headers=None):
        resp = self.client.post(path, data=data, headers=headers or {})
        return resp.status_code, resp.content, resp.headers

    # 1. ROOT & MAIN DASHBOARD
    def test_01_dashboard(self):
        code, body, _ = self.get("/")
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertTrue("SENTRY-GRID" in text and "NTRO Defense Edition" in text)
        for t in ["tab-btn-audit-hub", "tab-btn-laya-studio", "tab-btn-remediation-hub", "tab-btn-ledger-hub"]:
            self.assertIn(t, text)
        self.assertTrue("Multi-Vendor Quick Audit" in text and "preset-btn-cisco-ios" in text)
        for el in ["stat-lines", "stat-words", "stat-chars", "stat-vendor"]:
            self.assertIn(el, text)
        self.assertTrue("fix-modal" in text and "cyber-toast" in text)

    # 2. AUDIT ENGINE & MULTI-VENDOR
    def test_02_audit_engine(self):
        # Cisco IOS
        cisco_cfg = """
hostname core-switch-cisco
line vty 0 4
 transport input telnet
 exec-timeout 30 0
service password-encryption
no ip http server
"""
        code, body, _ = self.post("/api/audit", {"config_text": cisco_cfg})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("core-switch-cisco", text)
        self.assertIn('id="remediation-container" hx-swap-oob="true"', text)
        self.assertIn('id="nav-ledger-height" hx-swap-oob="true"', text)
        self.assertIn("Microsoft Z3", text)
        self.assertIn("Findings & Vulnerability Matrix", text)

        # Multi-vendor: Juniper
        juniper_cfg = """
set system host-name core-edge-juniper
set system services telnet
"""
        code, body, _ = self.post("/api/audit", {"config_text": juniper_cfg})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("delete system services telnet", text)
        self.assertIn("core-edge-juniper", text)

        # Multi-vendor: Fortinet
        fortinet_cfg = """
config system global
    set hostname fw-fortinet-01
    set admin-sport 80
end
"""
        code, body, _ = self.post("/api/audit", {"config_text": fortinet_cfg})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Fortinet", text)
        self.assertIn("fw-fortinet-01", text)

        # Multi-vendor: Palo Alto PAN-OS
        palo_cfg = """
<config version="10.2.0">
  <mgt-config>
    <users><entry name="admin"/></users>
  </mgt-config>
</config>
"""
        code, body, _ = self.post("/api/audit", {"config_text": palo_cfg})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Palo Alto", text)

        # Multi-vendor: Arista EOS
        arista_cfg = """
hostname arista-spine-01
management api http-commands
 no shutdown
"""
        code, body, _ = self.post("/api/audit", {"config_text": arista_cfg})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Arista", text)

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
        code, body, _ = self.post("/api/audit", {"config_text": sonic_cfg})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertTrue("SONiC" in text or "sonic-switch-01" in text)

        # Negative: Empty Config
        code, body, _ = self.post("/api/audit", {"config_text": "   "})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Empty Configuration Input", text)

        # Negative: Payload Limit Guard (>1MB)
        code, body, _ = self.post("/api/audit", {"config_text": "A" * (2 * 1024 * 1024)})
        text = body.decode("utf-8", errors="ignore")
        self.assertTrue(code in (400, 413) or "exceeded maximum size" in text.lower() or "limit" in text.lower())

    # 3. LAYA AI COMMAND EVALUATE & LOGIT INSPECTOR
    def test_03_laya_ai_evaluation(self):
        code, body, _ = self.post("/api/ai/evaluate", {"command_line": "idle-timeout 15", "vendor_scope": "all"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("idle-timeout 15", text)
        self.assertIn("PyTorch", text)
        self.assertIn("PyTorch Neural Head Softmax Distribution", text)
        self.assertIn("Latent Vector Embedding", text)

        code, body, _ = self.post("/api/ai/evaluate", {"command_line": "   "})
        text = body.decode("utf-8", errors="ignore")
        self.assertIn("Please enter a command to evaluate", text)

    # 4. CRYSTALLIZE RULE CACHE
    def test_04_crystallize_rule_cache(self):
        code, body, _ = self.post("/api/ai/crystallize", {
            "raw_line": "custom-timeout 450",
            "target_category": "aaa.session_timeout_minutes",
            "assigned_value": "450",
            "vendor_scope": "all"
        })
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Rule Crystallized", text)
        self.assertIn("AdamW Loss", text)
        self.assertIn('id="active-heuristics-grid" hx-swap-oob="true"', text)
        self.assertIn('id="heuristics-count-badge" hx-swap-oob="true"', text)

        code, body, _ = self.post("/api/ai/crystallize", {"raw_line": "", "target_category": ""})
        text = body.decode("utf-8", errors="ignore")
        self.assertTrue(code in (400, 422) or "must not be empty" in text)

    # 5. BATCH DATASET LOAD
    def test_05_batch_dataset_load(self):
        code, body, _ = self.post("/api/ai/load-batch", {})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Confirm & Crystallize Rule", text)
        self.assertIn("L-101", text)

    # 6. TRAINING DATASET INSPECTOR
    def test_06_training_dataset_inspector(self):
        code, body, _ = self.get("/api/ai/dataset", headers={"Accept": "text/html"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Laya AI Supervised Training Corpus", text)
        self.assertIn("Corpus ID", text)

        code, body, _ = self.get("/api/ai/dataset?format=json")
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    # 7. SEMANTIC SIMILARITY
    def test_07_semantic_similarity(self):
        code, body, _ = self.post("/api/ai/similarity", {"command_line": "no ip http server"}, headers={"HX-Request": "true"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Sentence-Transformers Semantic Cosine Match", text)
        self.assertIn("Cosine Similarity Score", text)

        code, body, _ = self.post("/api/ai/similarity", {"command_line": "no ip http server"})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("cosine_similarity", data)
        self.assertIn("top_category", data)

        code, body, _ = self.post("/api/ai/similarity", {"command_line": ""})
        self.assertTrue(code in (400, 422) or "Empty command" in body.decode("utf-8"))

    # 8. FAST DETERMINISTIC NER
    def test_08_fast_ner(self):
        code, body, _ = self.post("/api/ai/ner", {"command_line": "logging host 10.99.100.15 transport udp port 514"}, headers={"HX-Request": "true"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Fast Deterministic Named Entities", text)
        self.assertIn("10.99.100.15", text)
        self.assertIn("514", text)

        code, body, _ = self.post("/api/ai/ner", {"command_line": "crypto ipsec transform-set ESP-AES256 esp-aes 256 esp-sha512-hmac"})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIsInstance(data.get("ciphers"), list)

        code, body, _ = self.post("/api/ai/ner", {"command_line": ""})
        self.assertTrue(code in (400, 422) or "Empty command" in body.decode("utf-8"))

    # 9. MICROSOFT Z3 SMT THEOREM PROVER
    def test_09_smt_theorem_prover(self):
        code, body, _ = self.post("/api/ai/smt-prove", {"telnet_enabled": "no", "ssh_version": "2", "timeout_seconds": "600"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("UNSAT: Invariant Mathematically Proven Secure", text)

        code, body, _ = self.post("/api/ai/smt-prove", {"telnet_enabled": "yes", "ssh_version": "1", "timeout_seconds": "1800"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("SAT: Vulnerability Counterexample Synthesized", text)

    # 10. ACTIVE LEARNING QUERY UNCERTAINTY
    def test_10_active_learning_uncertainty(self):
        code, body, _ = self.post("/api/ai/active-learning/query", {"command_line": "snmp-server community private RW"})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        metrics = data.get("active_learning_metrics", {})
        self.assertIn("shannon_entropy", metrics)
        self.assertIn("margin_score", metrics)

    # 11. SAMPLES API
    def test_11_samples_api(self):
        code, body, _ = self.get("/api/samples/list")
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertGreater(data.get("total", 0), 0)

        code, body, _ = self.get("/api/samples/cisco_ios_xe_sample.cfg")
        self.assertEqual(code, 200)
        self.assertIn("hostname", body.decode("utf-8", errors="ignore"))

        code, body, _ = self.get("/api/samples/non_existent_file.cfg")
        self.assertEqual(code, 404)

    # 12. AST PARSING (CiscoConfParse2)
    def test_12_ast_parsing(self):
        cisco_ast_cfg = "hostname edge-router\nline vty 0 4\n transport input ssh\n exec-timeout 10 0\n"
        code, body, _ = self.post("/api/ast/parse", {"config_text": cisco_ast_cfg}, headers={"HX-Request": "true"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Hierarchical AST Parse (CiscoConfParse2 Engine)", text)
        self.assertIn("VTY Blocks", text)

        code, body, _ = self.post("/api/ast/parse", {"config_text": cisco_ast_cfg})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertGreaterEqual(data.get("vty_blocks_found", 0), 1)

        code, body, _ = self.post("/api/ast/parse", {"config_text": ""})
        self.assertTrue(code in (400, 422) or "Empty configuration" in body.decode("utf-8"))

    # 13. HIER CONFIG DIFF
    def test_13_hier_config_diff(self):
        code, body, _ = self.post("/api/ast/hier-diff", {
            "running_config": "line vty 0 4\n transport input telnet\n",
            "target_baseline": "line vty 0 4\n transport input ssh\n"
        })
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue("remediation_steps" in data or "remediation_commands" in data)

    # 14. TTP TEMPLATE PARSER
    def test_14_ttp_template_parser(self):
        code, body, _ = self.post("/api/ast/ttp", {
            "raw_cli": "interface GigabitEthernet0/1\n ip address 192.168.1.1 255.255.255.0\n",
            "template_syntax": ""
        })
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("ttp_parsed", data)

    # 15. COLLECTOR POLL INTERFACE
    def test_15_collector_poll_interface(self):
        code, body, _ = self.post("/api/collector/poll", {
            "host": "10.0.0.1",
            "platform": "cisco_ios",
            "port": "22"
        })
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn(data.get("status"), ("DRY_RUN_READY", "DISPATCH_READY"))

    # 16. NAPALM GET_FACTS & GET_CONFIG
    def test_16_napalm_integration(self):
        code, body, _ = self.post("/api/collector/napalm-facts", {"hostname": "core-router-01", "platform": "ios"})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("hostname", data)
        self.assertIn("vendor", data)

        code, body, _ = self.post("/api/collector/napalm-config", {"hostname": "core-router-01", "platform": "ios"})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("running", data)

    # 17. NORNIR FLEET AUDITOR
    def test_17_nornir_fleet_auditor(self):
        code, body, _ = self.post("/api/collector/nornir-fleet", {"device_count": "5"}, headers={"HX-Request": "true"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Nornir Fleet Execution Result", text)
        self.assertIn("Compliant Nodes", text)

        code, body, _ = self.post("/api/collector/nornir-fleet", {"device_count": "5"})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data.get("total_devices") == 5 or data.get("total_devices_audited") == 5)

    # 18. TEXTFSM PARSER
    def test_18_textfsm_cli_parser(self):
        code, body, _ = self.post("/api/ast/textfsm", {
            "command": "show version",
            "raw_output": "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE4",
            "platform": "cisco_ios"
        })
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("parsed_records", data)

    # 19. CISCO GENIE PARSER
    def test_19_cisco_genie_parser(self):
        code, body, _ = self.post("/api/ast/genie", {
            "command": "show version",
            "raw_output": "Cisco IOS XE Software, Version 17.03.04a",
            "platform": "cisco_ios"
        })
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue("parsed_result" in data or "parsed_structure" in data)

    # 20. PYANG & OPENCONFIG YANG VALIDATOR
    def test_20_openconfig_yang_validator(self):
        code, body, _ = self.post("/api/ast/openconfig-validate", {"config_json": "{}"}, headers={"HX-Request": "true"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("OpenConfig YANG Validator", text)
        self.assertTrue("YANG CONFORMANT" in text or "YANG VIOLATION" in text)

        code, body, _ = self.post("/api/ast/openconfig-validate", {"config_json": "{}"})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("modules_validated", data)

    # 21. OPEN POLICY AGENT (OPA) & REGO
    def test_21_opa_rego_engine(self):
        code, body, _ = self.post("/api/policy/opa-eval", {"config_json": "{}"}, headers={"HX-Request": "true"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Open Policy Agent (OPA) / Rego Decision Engine", text)
        self.assertIn("OPA COMPLIANT", text)

        code, body, _ = self.post("/api/policy/opa-eval", {"config_json": "{}"})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIs(data.get("compliant"), True)
        self.assertIn("compliance", data.get("package", ""))

        code, body, _ = self.get("/api/policy/rego")
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("package ", text)
        self.assertIn("deny[", text)

    # 22. CHECKOV CLOUD SECURITY GROUPS
    def test_22_checkov_cloud_static_analysis(self):
        code, body, _ = self.post("/api/policy/checkov", {}, headers={"HX-Request": "true"})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Checkov Static Analysis Engine", text)
        self.assertIn("Passed", text)
        self.assertIn("Failed", text)

        code, body, _ = self.post("/api/policy/checkov", {})
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue("passed_checks" in data or "passed_checks_count" in data)

    # 23. OPENSCAP XCCDF XML
    def test_23_openscap_xccdf_export(self):
        code, body, headers = self.get("/api/policy/xccdf")
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("xccdf", text)
        self.assertIn("Benchmark", text)

    # 24. CHEF INSPEC PROFILE
    def test_24_chef_inspec_profile(self):
        code, body, _ = self.get("/api/policy/inspec")
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue("controls" in data or "inspec.yml" in data)

    # 25. DEFECTDOJO SIEM EXPORT
    def test_25_defectdojo_siem_export(self):
        code, body, _ = self.get("/api/policy/defectdojo")
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("findings", data)
        self.assertTrue("format" in data or "defectdojo_import_version" in data)

    # 26. OPENTOFU / TERRAFORM IAC
    def test_26_opentofu_terraform_iac(self):
        code, body, _ = self.get("/api/remediation/terraform")
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn('resource "aws_security_group"', text)

    # 27. CERTIFIED REPORTLAB PDF EXPORT
    def test_27_certified_reportlab_pdf_export(self):
        code, body, headers = self.get("/api/report/pdf")
        self.assertEqual(code, 200)
        self.assertTrue(body.startswith(b"%PDF"))
        self.assertGreater(len(body), 2000)
        self.assertIn("filename=", headers.get("Content-Disposition", ""))

    # 28. PRINTABLE CERTIFICATE
    def test_28_printable_certificate(self):
        code, body, _ = self.get("/api/report/audit")
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("National Technical Research Organisation", text)
        self.assertIn("OFFICIAL CYBERSECURITY & COMPLIANCE VERIFICATION CERTIFICATE", text)

    # 29. BLOCKCHAIN EXPLORER GUI & BLOCKS API
    def test_29_ledger_explorer_gui_and_blocks(self):
        code, body, _ = self.get("/ledger")
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Sovereign Ledger Explorer", text)
        self.assertIn("ledger-search-input", text)
        self.assertIn("visible-blocks-count", text)

        code, body, _ = self.get("/api/ledger/blocks?format=json")
        self.assertEqual(code, 200)
        blocks = json.loads(body.decode("utf-8"))
        self.assertIsInstance(blocks, list)
        self.assertGreaterEqual(len(blocks), 1)

    # 30. ON-CHAIN CRYPTOGRAPHIC SEAL VERIFICATION
    def test_30_onchain_cryptographic_seal_verification(self):
        code, body, _ = self.get("/api/ledger/blocks?format=json")
        self.assertEqual(code, 200)
        blocks = json.loads(body.decode("utf-8"))
        self.assertIsInstance(blocks, list)
        self.assertGreaterEqual(len(blocks), 1)

        latest_seal = blocks[-1]["audit_seal"]
        latest_audit_id = blocks[-1]["audit_id"]
        latest_hash = blocks[-1]["block_hash"]

        code, body, _ = self.post("/api/ledger/verify", {"query_hash": latest_seal})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("CRYPTOGRAPHIC INTEGRITY VERIFIED", text)
        self.assertIn("Bit-for-Bit Verified", text)

        code, body, _ = self.post("/api/ledger/verify", {"query_hash": latest_audit_id})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("CRYPTOGRAPHIC INTEGRITY VERIFIED", text)

        code, body, _ = self.post("/api/ledger/verify", {"query_hash": latest_hash})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("CRYPTOGRAPHIC INTEGRITY VERIFIED", text)

        # Negative: Truncated Seal
        code, body, _ = self.post("/api/ledger/verify", {"query_hash": latest_seal[:40]})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("CRYPTOGRAPHIC VERIFICATION FAILED: TRUNCATED / TAMPERED HASH", text)

        # Negative: Unknown Seal
        code, body, _ = self.post("/api/ledger/verify", {"query_hash": "deadbeef" * 16})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("INVALID CRYPTOGRAPHIC SEAL: NOT FOUND ON-CHAIN", text)

        # Negative: Blank Input
        code, body, _ = self.post("/api/ledger/verify", {"query_hash": "   "})
        text = body.decode("utf-8", errors="ignore")
        self.assertEqual(code, 200)
        self.assertIn("Please enter a SHA-512 seal", text)

    # 31. HEALTH CHECK & OPENAPI DOCS
    def test_31_health_check_and_openapi_docs(self):
        code, body, _ = self.get("/health")
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertEqual(data.get("status"), "HEALTHY")

        code, body, _ = self.get("/openapi.json")
        self.assertEqual(code, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertIn("paths", data)
        self.assertGreaterEqual(len(data["paths"]), 25)

        code, body, _ = self.get("/docs")
        self.assertEqual(code, 200)
        self.assertIn("swagger-ui", body.decode("utf-8", errors="ignore").lower())


if __name__ == "__main__":
    unittest.main()
