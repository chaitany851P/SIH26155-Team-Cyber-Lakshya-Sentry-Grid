import unittest
import json
import hashlib
from fastapi.testclient import TestClient

from backend.server import app, laya_engine, ledger, detect_device, evaluate_compliance, SAMPLES


class TestSentryGridAuditEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # ==================== 1. UNIT TESTS: DEVICE FINGERPRINTING ====================
    def test_fingerprint_cisco_ios(self):
        cisco_cfg = "hostname core-switch-01\nversion 16.9.4\ntransport input ssh"
        info = detect_device(cisco_cfg)
        self.assertEqual(info["hostname"], "core-switch-01")
        self.assertEqual(info["vendor"], "Cisco")
        self.assertEqual(info["os_family"], "IOS-XE")
        self.assertEqual(len(info["raw_config_sha512"]), 128)

    def test_fingerprint_juniper_junos(self):
        junos_cfg = "set system host-name edge-router-01\nset system services ssh protocol-version v2"
        info = detect_device(junos_cfg)
        self.assertEqual(info["hostname"], "edge-router-01")
        self.assertEqual(info["vendor"], "Juniper")
        self.assertEqual(info["os_family"], "Junos OS")

    def test_fingerprint_paloalto_panos(self):
        panos_cfg = "set deviceconfig system hostname perimeter-fw-01\nset deviceconfig system service disable-telnet yes"
        info = detect_device(panos_cfg)
        self.assertEqual(info["hostname"], "perimeter-fw-01")
        self.assertEqual(info["vendor"], "Palo Alto Networks")
        self.assertEqual(info["os_family"], "PAN-OS")

    def test_fingerprint_fortinet_fortios(self):
        forti_cfg = "config system global\n set hostname fw-core-01\n set admin-telnet disable\nend"
        info = detect_device(forti_cfg)
        self.assertEqual(info["hostname"], "fw-core-01")
        self.assertEqual(info["vendor"], "Fortinet")
        self.assertEqual(info["os_family"], "FortiOS")

    def test_fingerprint_sonic_whitebox(self):
        sonic_cfg = '{\n  "DEVICE_METADATA": {\n    "localhost": {\n      "hostname": "leaf-sonic-01"\n    }\n  }\n}'
        info = detect_device(sonic_cfg)
        self.assertEqual(info["hostname"], "leaf-sonic-01")
        self.assertEqual(info["vendor"], "Open Networking (White-Box)")
        self.assertEqual(info["os_family"], "SONiC Linux")

    # ==================== 2. UNIT TESTS: COMPLIANCE EVALUATOR ====================
    def test_compliance_evaluation_rules(self):
        insecure_cfg = """
        hostname vulnr-switch-01
        line vty 0 4
         transport input telnet
         exec-timeout 0 0
        ip http server
        ip ssh version 1
        """
        eval_res, unmapped = evaluate_compliance(insecure_cfg, "Cisco")
        findings = eval_res["findings"]
        findings_map = {f["finding_id"]: f for f in findings}

        # FIND-001: Telnet must fail
        self.assertEqual(findings_map["FIND-001"]["status"], "FAIL")
        self.assertEqual(findings_map["FIND-001"]["severity"], "CRITICAL")

        # FIND-002: SSHv2 must fail (v1 present)
        self.assertEqual(findings_map["FIND-002"]["status"], "FAIL")

        # FIND-003: HTTP server must fail
        self.assertEqual(findings_map["FIND-003"]["status"], "FAIL")

        # FIND-004: Inactivity timeout must fail (exec-timeout 0 0)
        self.assertEqual(findings_map["FIND-004"]["status"], "FAIL")

        # Summary check
        self.assertLess(eval_res["summary"]["overall_compliance_percentage"], 50.0)
        self.assertIn(eval_res["summary"]["risk_level"], ["HIGH RISK", "CRITICAL"])

    # ==================== 3. UNIT TESTS: LAYA DECISION ENGINE ====================
    def test_laya_system_1_logits(self):
        # Known semantic intent
        res = laya_engine.evaluate_command("idle-timeout 10", "all")
        self.assertIn(res["suggested_category"], ["aaa.session_timeout_minutes", "unknown.unclassified"])
        self.assertGreater(res["confidence_score"], 0.70)
        self.assertEqual(res["extracted_value"], "10")

    def test_laya_crystallization_and_hot_reload(self):
        # Dynamically crystallize a novel syntax
        novel_cmd = "custom-access-daemon telnet-deny-always"
        rule = laya_engine.crystallize_rule(novel_cmd, "management_access.telnet_disabled", "true", "all")
        self.assertTrue(rule["rule_id"].startswith("RULE-"))

        # Re-evaluate with exact same command -> Should hit dynamic heuristic with confidence 1.0!
        res = laya_engine.evaluate_command(novel_cmd, "all")
        self.assertEqual(res["confidence_score"], 1.0)
        self.assertEqual(res["suggested_category"], "management_access.telnet_disabled")
        self.assertEqual(res["status"], "AUTO_MAPPED")

    # ==================== 4. UNIT TESTS: SOVEREIGN LEDGER & SHA-512 ====================
    def test_ledger_cnsa_sha512_seal_and_block_link(self):
        initial_count = len(ledger.blocks)
        device = {"hostname": "soc-node-test", "vendor": "Cisco", "raw_config_sha512": "abc"*42}
        score = 85.5
        risk = "LOW RISK"
        raw_hash = hashlib.sha512(b"test config content").hexdigest()
        seal = ledger.compute_seal(device["hostname"], device["vendor"], score, raw_hash)

        self.assertEqual(len(seal), 128)  # Exactly 128 hex chars for SHA-512

        block = ledger.commit("AUD-TEST-999", device, score, risk, seal)
        self.assertEqual(block["block_index"], initial_count)
        self.assertEqual(block["audit_seal"], seal)
        self.assertEqual(len(ledger.blocks), initial_count + 1)

    # ==================== 5. INTEGRATION & API TESTS ====================
    def test_api_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertEqual(data["engine"], "SENTRY-GRID-LAYA")

    def test_api_root_dashboard(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("SENTRY-GRID", response.text)
        self.assertIn("Laya Dual-AI: PyTorch Neural Classifier", response.text)

    def test_api_audit_cisco(self):
        cisco_sample = SAMPLES[0]["content"]
        response = self.client.post("/api/audit", data={"config_text": cisco_sample})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Compliance Posture", response.text)
        self.assertIn("SHA-512", response.text)
        self.assertIn("Neuro-Symbolic Formal Verification (Microsoft Z3 SMT Solver)", response.text)

    def test_api_audit_empty_input_rejected(self):
        response = self.client.post("/api/audit", data={"config_text": "   "})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Empty Configuration Input", response.text)

    def test_api_ledger_blocks_html_and_json(self):
        # HTML Explorer mode
        resp_html = self.client.get("/api/ledger/blocks", headers={"Accept": "text/html"})
        self.assertEqual(resp_html.status_code, 200)
        self.assertIn("Sovereign Ledger Explorer", resp_html.text)

        # JSON mode
        resp_json = self.client.get("/api/ledger/blocks?format=json")
        self.assertEqual(resp_json.status_code, 200)
        data = resp_json.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)

    # ==================== 6. CRYPTOGRAPHIC VERIFICATION & NEGATIVE TESTS ====================
    def test_api_ledger_verify_exact_match(self):
        # Get latest block seal
        latest = ledger.blocks[-1]
        seal = latest["audit_seal"]

        resp = self.client.post("/api/ledger/verify", data={"query_hash": seal})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("CRYPTOGRAPHIC INTEGRITY VERIFIED: 100% AUTHENTIC", resp.text)
        self.assertIn("Exact SHA-512 Cryptographic Seal", resp.text)

    def test_api_ledger_verify_truncated_hash_rejected(self):
        latest = ledger.blocks[-1]
        seal = latest["audit_seal"]
        truncated = seal[:-2]  # Chop off last 2 hex chars (like the user noticed)

        resp = self.client.post("/api/ledger/verify", data={"query_hash": truncated})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("CRYPTOGRAPHIC VERIFICATION FAILED: TRUNCATED / TAMPERED HASH", resp.text)
        self.assertIn("missing the last <strong class=\"text-amber-300 font-mono\">2 characters</strong>", resp.text)

    def test_api_ledger_verify_random_tampered_hash_rejected(self):
        fake_hash = "deadbeef" * 16  # 128 chars, completely fake
        resp = self.client.post("/api/ledger/verify", data={"query_hash": fake_hash})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("INVALID CRYPTOGRAPHIC SEAL: NOT FOUND ON-CHAIN", resp.text)

    # ==================== 7. SECURITY & XSS SANITIZATION TESTS ====================
    def test_xss_sanitization_in_command_eval(self):
        xss_payload = '<script>alert("pwned")</script>'
        resp = self.client.post("/api/ai/evaluate", data={"command_line": xss_payload})
        self.assertEqual(resp.status_code, 200)
        # Raw unescaped script tag MUST NOT appear in response body!
        self.assertNotIn('<script>alert("pwned")</script>', resp.text)
        self.assertIn('&lt;script&gt;alert(&quot;pwned&quot;)&lt;/script&gt;', resp.text)

    def test_xss_sanitization_in_ledger_verify(self):
        xss_payload = '<img src=x onerror=alert(1)>'
        resp = self.client.post("/api/ledger/verify", data={"query_hash": xss_payload})
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn('<img src=x onerror=alert(1)>', resp.text)
        self.assertIn('&lt;img src=x onerror=alert(1)&gt;', resp.text)

    # ==================== 8. DUAL-AI ENGINE: PYTORCH & Z3 SMT TESTS ====================
    def test_pytorch_neural_engine_telemetry(self):
        resp = self.client.post("/api/ai/evaluate", data={"command_line": "crypto key generate rsa modulus 4096"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("PyTorch Tensor Core", resp.text)
        self.assertIn("Latent Vector Embedding", resp.text)
        self.assertIn("PyTorch Neural Head Softmax Distribution", resp.text)

    def test_pytorch_online_learning_backprop(self):
        resp = self.client.post("/api/ai/crystallize", data={
            "raw_line": "chrony-server 10.20.30.40",
            "target_category": "time_synchronization.ntp_servers",
            "assigned_value": "10.20.30.40",
            "vendor_scope": "all"
        })
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Rule Crystallized & PyTorch Active Learning Backpropagated", resp.text)
        self.assertIn("AdamW Loss", resp.text)

    def test_z3_formal_solver_standalone(self):
        from backend.neural_engine import z3_verifier
        # 1. Insecure configuration -> counterexample proved
        vuln_findings = [
            {"finding_id": "FIND-001", "status": "FAIL"},
            {"finding_id": "FIND-002", "status": "FAIL"},
            {"finding_id": "FIND-003", "status": "FAIL"},
            {"finding_id": "FIND-004", "status": "FAIL"}
        ]
        res = z3_verifier.verify_device_security_invariants(vuln_findings)
        self.assertEqual(res["formal_status"], "VULNERABILITY_COUNTEREXAMPLE_PROVED")
        self.assertFalse(res["model_satisfied"])
        self.assertGreaterEqual(len(res["counterexample"]), 3)

        # 2. Hardened configuration -> proven secure unconditionally
        secure_findings = [
            {"finding_id": "FIND-001", "status": "PASS"},
            {"finding_id": "FIND-002", "status": "PASS"},
            {"finding_id": "FIND-003", "status": "PASS"},
            {"finding_id": "FIND-004", "status": "PASS"}
        ]
        res_sec = z3_verifier.verify_device_security_invariants(secure_findings)
        self.assertEqual(res_sec["formal_status"], "PROVEN_SECURE")
        self.assertTrue(res_sec["model_satisfied"])
        self.assertIsNone(res_sec["counterexample"])

    # ==================== 9. MULTI-VENDOR EXPANSION & CERTIFIED REPORT ====================
    def test_fingerprint_arista_cumulus_checkpoint_huawei(self):
        arista_cfg = "hostname spine-arista-01\nmanagement api http-commands"
        self.assertEqual(detect_device(arista_cfg)["vendor"], "Arista Networks")

        cumulus_cfg = "hostname leaf-cumulus-01\nnet add service telnet"
        self.assertEqual(detect_device(cumulus_cfg)["vendor"], "Cumulus Networks")

        ckp_cfg = "set hostname gw-checkpoint-01\nset web ssl-port 80"
        self.assertEqual(detect_device(ckp_cfg)["vendor"], "Check Point")

        huawei_cfg = "sysname core-huawei-01\nuser-interface vty 0 4"
        self.assertEqual(detect_device(huawei_cfg)["vendor"], "Huawei")

    def test_api_report_audit(self):
        resp = self.client.get("/api/report/audit")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("CERTIFIED COMPLIANCE AUDIT REPORT", resp.text)
        self.assertIn("National Technical Research Organisation", resp.text)
        self.assertIn("CNSA 2.0 SHA-512 Cryptographic Seal", resp.text)

    # ==================== 10. LAYER 3: SEMANTIC SIMILARITY & NER TESTS ====================
    def test_semantic_similarity_cosine_matcher(self):
        from backend.neural_engine import semantic_engine
        # Test command semantic matching
        res = semantic_engine.match_command("idle-timeout 10")
        self.assertIn("top_category", res)
        self.assertIn("cosine_similarity", res)
        self.assertGreaterEqual(res["cosine_similarity"], 0.0)
        self.assertLessEqual(res["cosine_similarity"], 1.0)
        self.assertEqual(len(res["all_ranked_candidates"]), 8)

    def test_cli_ner_extraction(self):
        from backend.neural_engine import cli_ner
        line = "logging host 10.10.50.100 transport input ssh exec-timeout 15"
        entities = cli_ner.extract_entities(line)
        self.assertIn("10.10.50.100", entities["ips"])
        self.assertEqual(entities["timeout_minutes"], 15)
        self.assertIn("ssh", entities["protocols"])

    def test_active_learning_uncertainty_strategies(self):
        from backend.neural_engine import active_learning_engine
        probs = [0.85, 0.10, 0.03, 0.02]
        res = active_learning_engine.evaluate_active_learning_query(probs)
        # Least confidence = 1 - 0.85 = 0.15
        self.assertAlmostEqual(res["least_confidence_score"], 0.15, places=2)
        # Margin = 0.85 - 0.10 = 0.75
        self.assertAlmostEqual(res["margin_score"], 0.75, places=2)
        # Shannon entropy > 0
        self.assertGreater(res["shannon_entropy"], 0.0)
        # 0.85 < 0.95 confidence gate -> quarantine
        self.assertEqual(res["route_decision"], "QUARANTINE_FOR_ADMIN_REVIEW")

    def test_air_gapped_slm_adapter(self):
        from backend.neural_engine import local_slm_adapter, neural_engine
        res = local_slm_adapter.parse_with_fallback("admin-telnet disable", neural_engine)
        self.assertTrue(res["air_gapped"])
        self.assertEqual(res["engine"], "LAYA_SYSTEM_ONE_LOCAL_NEURAL")
        self.assertIn(res["status"], ["AUTO_MAPPED", "MANUAL_REVIEW_REQUIRED"])

    def test_structured_output_schema_validation(self):
        from backend.neural_engine import schema_validator
        valid_finding = {
            "finding_id": "FIND-TEST",
            "rule_id": "RULE-TEST-001",
            "title": "Test Control Finding",
            "control_reference": "DISA-STIG-TEST",
            "severity": "CRITICAL",
            "status": "FAIL",
            "found_value": "insecure",
            "expected_value": "secure",
            "mitre_technique": "T1021",
            "remediation_cli": "fix command",
            "rollback_cli": "rollback command"
        }
        is_valid, err, obj = schema_validator.validate_finding(valid_finding)
        self.assertTrue(is_valid)
        self.assertIsNone(err)
        self.assertEqual(obj.severity, "CRITICAL")

        # Invalid finding (missing required field)
        invalid_finding = {"finding_id": "BAD"}
        is_bad_valid, bad_err, bad_obj = schema_validator.validate_finding(invalid_finding)
        self.assertFalse(is_bad_valid)
        self.assertIsNotNone(bad_err)

    # ==================== 11. PHYSICAL SAMPLES AUDIT (BATFISH DATASET) ====================
    def test_audit_all_nine_sample_files(self):
        import os
        samples_dir = "samples"
        expected_files = [
            "cisco_ios_xe_sample.cfg",
            "juniper_junos_sample.conf",
            "palo_alto_panos_sample.xml",
            "fortinet_fortios_sample.conf",
            "arista_eos_sample.cfg",
            "sonic_whitebox_sample.json",
            "cumulus_linux_sample.conf",
            "checkpoint_gaia_sample.cfg",
            "huawei_vrp_sample.cfg"
        ]
        for fname in expected_files:
            fpath = os.path.join(samples_dir, fname)
            self.assertTrue(os.path.exists(fpath), f"Missing physical sample file: {fname}")
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.assertGreater(len(content), 50, f"Sample file {fname} is too small")
            dev = detect_device(content)
            self.assertIsNotNone(dev["vendor"])
            eval_res, _ = evaluate_compliance(content, dev["vendor"])
            self.assertIn("summary", eval_res)
            self.assertGreaterEqual(eval_res["summary"]["total_rules_evaluated"], 4)

    def test_api_report_pdf_download(self):
        resp = self.client.get("/api/report/pdf")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers["content-type"], "application/pdf")
        self.assertTrue(resp.content.startswith(b"%PDF"))
        self.assertGreater(len(resp.content), 1000)

    def test_api_samples_list_and_get(self):
        resp_list = self.client.get("/api/samples/list")
        self.assertEqual(resp_list.status_code, 200)
        data = resp_list.json()
        self.assertGreaterEqual(data["total"], 9)

        resp_sample = self.client.get("/api/samples/cisco_ios_xe_sample.cfg")
        self.assertEqual(resp_sample.status_code, 200)
        self.assertIn("hostname core-switch-mumbai-01", resp_sample.text)

    def test_api_similarity_and_ner_endpoints(self):
        # Similarity
        sim_resp = self.client.post("/api/ai/similarity", data={"command_line": "service password-encryption"})
        self.assertEqual(sim_resp.status_code, 200)
        self.assertIn("top_category", sim_resp.json())

        # NER
        ner_resp = self.client.post("/api/ai/ner", data={"command_line": "logging host 10.99.1.1 exec-timeout 10"})
        self.assertEqual(ner_resp.status_code, 200)
        self.assertIn("10.99.1.1", ner_resp.json()["ips"])

        # Active Learning Query
        al_resp = self.client.post("/api/ai/active-learning/query", data={"command_line": "custom-proto v2"})
        self.assertEqual(al_resp.status_code, 200)
        self.assertIn("active_learning_metrics", al_resp.json())

    # ==================== 12. TRACK A: DETERMINISTIC AST & COLLECTOR TESTS ====================
    def test_ciscoconfparse_ast_parsing(self):
        from backend.ast_parser import ast_parser
        sample_cfg = """
        hostname core-switch-01
        service password-encryption
        ip ssh version 2
        line vty 0 4
         transport input ssh
         exec-timeout 10 0
        logging host 10.10.50.100
        ntp server 10.10.1.1
        """
        res = ast_parser.parse_cisco_ast(sample_cfg)
        self.assertEqual(res["parser"], "CiscoConfParse2-AST")
        self.assertTrue(res["telnet_disabled"])
        self.assertTrue(res["ssh_vty_enforced"])
        self.assertTrue(res["password_encryption"])
        self.assertEqual(res["ssh_version"], 2)
        self.assertEqual(res["session_timeout_minutes"], 10)
        self.assertIn("10.10.50.100", res["syslog_servers"])

    def test_hier_config_remediation_diff(self):
        from backend.ast_parser import ast_parser
        running = "hostname switch-01\nline vty 0 4\n transport input telnet\n"
        target = "hostname switch-01\nline vty 0 4\n transport input ssh\n"
        diff_res = ast_parser.compute_hierarchical_remediation_diff(running, target)
        self.assertIn("status", diff_res)
        self.assertIn("remediation_commands", diff_res)
        self.assertGreaterEqual(len(diff_res["remediation_commands"]), 1)

    def test_ttp_template_parsing(self):
        from backend.ast_parser import ast_parser
        cli_data = "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n description Uplink to NTRO\n"
        parsed = ast_parser.parse_with_ttp_template(cli_data)
        self.assertIsInstance(parsed, (list, dict))

    def test_device_collector_netmiko_scrapli(self):
        from backend.ast_parser import device_collector
        res = device_collector.dry_run_poll("10.0.0.1", "cisco_ios", 22)
        self.assertEqual(res["status"], "DISPATCH_READY")
        self.assertTrue(res["air_gapped_safe"])

    def test_api_ast_parse_and_collector_endpoints(self):
        # 1. AST parse API
        ast_resp = self.client.post("/api/ast/parse", data={"config_text": "hostname router-01\nline vty 0 4\n transport input ssh\n"})
        self.assertEqual(ast_resp.status_code, 200)
        self.assertEqual(ast_resp.json()["parser"], "CiscoConfParse2-AST")

        # 2. Hier-diff API
        diff_resp = self.client.post("/api/ast/hier-diff", data={"running_config": "line vty 0 4\n transport input telnet\n", "target_baseline": "line vty 0 4\n transport input ssh\n"})
        self.assertEqual(diff_resp.status_code, 200)
        self.assertIn("remediation_commands", diff_resp.json())

        # 3. TTP parse API
        ttp_resp = self.client.post("/api/ast/ttp", data={"raw_cli": "interface GigabitEthernet1\n ip address 192.168.1.1 255.255.255.0\n"})
        self.assertEqual(ttp_resp.status_code, 200)
        self.assertIn("ttp_parsed", ttp_resp.json())

        # 4. Collector poll API
        poll_resp = self.client.post("/api/collector/poll", data={"host": "10.10.10.1", "platform": "cisco_ios", "port": 22})
        self.assertEqual(poll_resp.status_code, 200)
        self.assertEqual(poll_resp.json()["status"], "DISPATCH_READY")

    # ==================== 13. LAYER 1 & 2 EXTENDED TOOL TESTS ====================
    def test_napalm_collector(self):
        from backend.ast_parser import napalm_collector
        facts = napalm_collector.get_facts("core-sw-01", "ios")
        self.assertEqual(facts["vendor"], "Cisco")
        self.assertEqual(facts["model"], "Catalyst 9300-48P")
        self.assertIn("Management0", facts["interface_list"])

        cfg = napalm_collector.get_config("core-sw-01", "ios")
        self.assertIn("hostname core-sw-01", cfg["running"])

        # Test API
        resp = self.client.post("/api/collector/napalm-facts", data={"hostname": "edge-01", "platform": "junos"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["vendor"], "Juniper")

    def test_nornir_concurrent_bulk_auditor(self):
        from backend.ast_parser import nornir_auditor
        inventory = [
            {"hostname": "sw-01", "config": "transport input ssh\nexec-timeout 10 0\n"},
            {"hostname": "sw-02", "config": "transport input telnet\nexec-timeout 0 0\n"}
        ]
        res = nornir_auditor.run_inventory_audit(inventory)
        self.assertEqual(res["total_devices_audited"], 2)
        self.assertEqual(res["passed_devices"], 1)
        self.assertEqual(res["failed_devices"], 1)
        self.assertEqual(res["fleet_compliance_percentage"], 50.0)

        # Test API
        resp = self.client.post("/api/collector/nornir-fleet", data={"device_count": 4})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["total_devices_audited"], 4)

    def test_textfsm_and_genie_parsers(self):
        from backend.ast_parser import textfsm_parser, genie_parser
        # TextFSM
        cli = "GigabitEthernet0/1 192.168.1.1 up up\nGigabitEthernet0/2 unassigned down down"
        parsed = textfsm_parser.parse_cli_output("cisco_ios", "show ip int br", cli)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["interface"], "GigabitEthernet0/1")
        self.assertEqual(parsed[0]["ip_address"], "192.168.1.1")

        # Genie pyATS
        genie_res = genie_parser.parse_show_command("cisco_ios", "show run", "ip ssh version 2\ntransport input ssh")
        self.assertEqual(genie_res["parser"], "pyATS-Genie")
        self.assertEqual(genie_res["parsed_structure"]["management"]["ssh"]["version"], 2)
        self.assertTrue(genie_res["parsed_structure"]["management"]["ssh"]["enabled"])

        # Test APIs
        fsm_resp = self.client.post("/api/ast/textfsm", data={"command": "show version", "raw_output": "Cisco IOS Software, version 17.9.4a", "platform": "cisco_ios"})
        self.assertEqual(fsm_resp.status_code, 200)
        self.assertIn("parsed_records", fsm_resp.json())

        genie_resp = self.client.post("/api/ast/genie", data={"command": "show run", "raw_output": "ip ssh version 2", "platform": "cisco_ios"})
        self.assertEqual(genie_resp.status_code, 200)
        self.assertEqual(genie_resp.json()["parser"], "pyATS-Genie")

    def test_openconfig_yang_validator(self):
        from backend.ast_parser import openconfig_validator
        valid_cfg = {
            "management_access": {"telnet_disabled": True, "ssh_version": 2},
            "aaa": {"password_encryption": True}
        }
        res_valid = openconfig_validator.validate_openconfig(valid_cfg)
        self.assertTrue(res_valid["valid"])
        self.assertEqual(res_valid["openconfig_model_state"], "CONFORMANT")

        invalid_cfg = {
            "management_access": {"telnet_disabled": False, "ssh_version": 1},
            "aaa": {"password_encryption": False}
        }
        res_invalid = openconfig_validator.validate_openconfig(invalid_cfg)
        self.assertFalse(res_invalid["valid"])
        self.assertEqual(res_invalid["violations_count"], 3)

        # Test API
        resp = self.client.post("/api/ast/openconfig-validate", data={"config_json": json.dumps(valid_cfg)})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["valid"])

    # ==================== 14. LAYER 4: MULTI-FRAMEWORK POLICY-AS-CODE TESTS ====================
    def test_opa_rego_policy_engine(self):
        from backend.policy_engine import opa_engine
        compliant_doc = {
            "management_access": {"telnet_disabled": True, "ssh_version": 2, "http_server_disabled": True},
            "aaa": {"password_encryption": True, "session_timeout_minutes": 10}
        }
        res_pass = opa_engine.evaluate_rego(compliant_doc)
        self.assertTrue(res_pass["compliant"])
        self.assertEqual(res_pass["violations_count"], 0)

        insecure_doc = {
            "management_access": {"telnet_disabled": False, "ssh_version": 1, "http_server_disabled": False},
            "aaa": {"password_encryption": False, "session_timeout_minutes": 0}
        }
        res_fail = opa_engine.evaluate_rego(insecure_doc)
        self.assertFalse(res_fail["compliant"])
        self.assertEqual(res_fail["violations_count"], 5)

        # Test APIs
        eval_resp = self.client.post("/api/policy/opa-eval", data={"config_json": json.dumps(compliant_doc)})
        self.assertEqual(eval_resp.status_code, 200)
        self.assertTrue(eval_resp.json()["compliant"])

        rego_resp = self.client.get("/api/policy/rego")
        self.assertEqual(rego_resp.status_code, 200)
        self.assertIn("package sentrygrid.compliance", rego_resp.text)

    def test_openscap_xccdf_xml_exporter(self):
        from backend.policy_engine import openscap_engine
        findings = [
            {"rule_id": "V-215000", "title": "Insecure Telnet Disabled", "severity": "CRITICAL", "status": "PASS"},
            {"rule_id": "V-215001", "title": "SSH Protocol v2 Enforced", "severity": "CRITICAL", "status": "FAIL"}
        ]
        xml_doc = openscap_engine.generate_xccdf_report("test-switch-01", findings)
        self.assertIn("<xccdf:Benchmark", xml_doc)
        self.assertIn("xccdf_mil.disa.stig_rule_V-215000", xml_doc)
        self.assertIn("<xccdf:result>pass</xccdf:result>", xml_doc)
        self.assertIn("<xccdf:result>fail</xccdf:result>", xml_doc)

        # Test API
        resp = self.client.get("/api/policy/xccdf")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Benchmark", resp.text)

    def test_chef_inspec_profile_exporter(self):
        from backend.policy_engine import inspec_exporter
        profile = inspec_exporter.export_profile("border-gw-01")
        self.assertIn("inspec.yml", profile)
        self.assertIn("controls/network_stig.rb", profile)
        self.assertIn("sentrygrid-stig-01", profile["controls/network_stig.rb"])

        # Test API
        resp = self.client.get("/api/policy/inspec")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("inspec.yml", resp.json())

    def test_checkov_cloud_policy_engine(self):
        from backend.policy_engine import checkov_engine
        rules = [
            {"cidr_ip": "0.0.0.0/0", "from_port": 23, "to_port": 23, "protocol": "tcp", "resource_id": "sg-public-01"},
            {"cidr_ip": "10.0.0.0/8", "from_port": 22, "to_port": 22, "protocol": "tcp", "resource_id": "sg-internal-01"}
        ]
        res = checkov_engine.evaluate_cloud_firewall(rules)
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["failed_checks_count"], 1)
        self.assertEqual(res["findings"][0]["check_id"], "CKV_AWS_TELNET")

        # Test API
        resp = self.client.post("/api/policy/checkov", data={"rules_json": json.dumps(rules)})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "FAILED")

    def test_defectdojo_exporter(self):
        from backend.policy_engine import defectdojo_exporter
        findings = [
            {"title": "Telnet active", "found_value": "port 23", "expected_value": "port 22", "severity": "CRITICAL", "status": "FAIL"}
        ]
        dojo_res = defectdojo_exporter.export_findings("AUD-100", "core-01", findings)
        self.assertEqual(dojo_res["target_host"], "core-01")
        self.assertEqual(dojo_res["findings_count"], 1)
        self.assertTrue(dojo_res["findings"][0]["active"])

        # Test API
        resp = self.client.get("/api/policy/defectdojo")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("findings", resp.json())

    # ==================== 15. LAYER 5: OPENTOFU / TERRAFORM REMEDIATION TESTS ====================
    def test_opentofu_terraform_iac_remediator(self):
        from backend.policy_engine import opentofu_remediator
        hcl = opentofu_remediator.generate_iac_remediation("core-switch-01")
        self.assertIn("aws_security_group", hcl)
        self.assertIn("hardened_defense_perimeter", hcl)
        self.assertIn("DISA STIG V-215000", hcl)

        # Test API
        resp = self.client.get("/api/remediation/terraform?device_name=border-fw-01")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("border-fw-01", resp.text)


if __name__ == "__main__":
    unittest.main()

