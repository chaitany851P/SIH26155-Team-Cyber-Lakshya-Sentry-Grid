"""
Unit & Integration Test Suite for PERSON A: Systems, Multi-Vendor Parsing, Compliance & Remediation
Organization: National Technical Research Organisation (NTRO) - SIH26155
Role: Security & Backend Architect (Person A)

Coverage:
1. Shared Canonical Security Baseline Schema (Contract with Person B)
2. Multi-Vendor Configuration Parsers (Cisco, Juniper, Palo Alto, Fortinet, Arista, SONiC, Check Point, Huawei)
3. Batfish Vendor-Independent Data Model (VIDM) AST Extraction
4. 24-Rule Multi-Framework Compliance Engine (CIS Benchmarks, DISA STIG, NIST SP 800-53, ISO 27001)
5. Actionable Remediation Engine (Jinja2 dynamic templating, Ansible Galaxy Playbooks, Rollback scripts)
6. Live Ingestion Drivers (Netmiko, Scrapli, NAPALM, Nornir)
7. Policy-as-Code & SIEM Exports (OPA Rego, OpenSCAP XCCDF XML, Chef InSpec, Checkov, DefectDojo, OpenTofu)
8. Cryptographic PDF Audit Report (ReportLab binary & SHA-512 cryptographic seal)
"""

import os
import unittest
import asyncio
import json

from backend.ast_parser import (
    ast_parser,
    device_collector,
    netmiko_collector,
    scrapli_collector,
    napalm_collector,
    nornir_auditor,
    textfsm_parser,
    genie_parser,
    openconfig_validator
)
from backend.policy_engine import (
    opa_engine,
    openscap_engine,
    inspec_exporter,
    checkov_engine,
    defectdojo_exporter,
    opentofu_remediator
)
from backend.remediation_engine import remediation_engine
from backend.pdf_generator import generate_certified_ntro_pdf
from backend.server import evaluate_compliance, detect_device


class TestPersonACanonicalSchema(unittest.TestCase):
    """
    Step 1 Deliverable: Verify the Canonical Security Baseline Schema Contract.
    """
    def test_canonical_baseline_contract_structure(self):
        cisco_cfg = """
        hostname core-fw-01
        line vty 0 4
         transport input ssh
         exec-timeout 10 0
        service password-encryption
        no ip http server
        ip ssh version 2
        logging host 10.10.50.100
        ntp server 10.10.1.1
        """
        canonical = ast_parser.normalize_to_canonical_baseline(cisco_cfg, "Cisco")
        self.assertIn("device_info", canonical)
        self.assertIn("normalized_security_baseline", canonical)

        dev = canonical["device_info"]
        self.assertEqual(dev["hostname"], "core-fw-01")
        self.assertEqual(dev["vendor"], "Cisco")
        self.assertEqual(dev["os_family"], "IOS-XE")

        norm = canonical["normalized_security_baseline"]
        self.assertTrue(norm["aaa"]["password_encryption_enabled"])
        self.assertEqual(norm["aaa"]["session_timeout_minutes"], 10)
        self.assertTrue(norm["management_access"]["telnet_disabled"])
        self.assertEqual(norm["management_access"]["ssh_version"], 2)
        self.assertTrue(norm["management_access"]["http_server_disabled"])
        self.assertIn("10.10.50.100", norm["logging_audit"]["syslog_servers"])
        self.assertIn("10.10.1.1", norm["time_synchronization"]["ntp_servers"])


class TestPersonAMultiVendorParsers(unittest.TestCase):
    """
    Step 2 Deliverable: Multi-Vendor Configuration Parsers against Batfish Test Dataset.
    """
    def test_cisco_ios_xe_sample_ast(self):
        with open("samples/cisco_ios_xe_sample.cfg", "r", encoding="utf-8") as f:
            cfg = f.read()
        res = ast_parser.parse_cisco_ast(cfg)
        self.assertEqual(res["parser"], "CiscoConfParse2-AST")
        self.assertFalse(res["password_encryption"])  # 'no service password-encryption'
        self.assertEqual(res["session_timeout_minutes"], 0)

    def test_juniper_junos_sample_ast(self):
        with open("samples/juniper_junos_sample.conf", "r", encoding="utf-8") as f:
            cfg = f.read()
        res = ast_parser.parse_juniper_ast(cfg)
        self.assertEqual(res["parser"], "Batfish-Junos-AST")
        self.assertEqual(res["vendor"], "Juniper")
        self.assertEqual(res["ssh_version"], 1)  # Weak 'protocol-version v1;' in sample
        self.assertFalse(res["telnet_disabled"])  # 'telnet;' enabled in sample
        self.assertEqual(res["session_timeout_minutes"], 0)  # Missing idle-timeout in sample (fails STIG)

    def test_palo_alto_panos_sample_ast(self):
        with open("samples/palo_alto_panos_sample.xml", "r", encoding="utf-8") as f:
            cfg = f.read()
        res = ast_parser.parse_paloalto_ast(cfg)
        self.assertEqual(res["parser"], "Batfish-PaloAlto-AST")
        self.assertEqual(res["vendor"], "Palo Alto Networks")
        self.assertEqual(res["ssh_version"], 2)
        self.assertIn("10.10.1.1", res["ntp_servers"])  # 'primary-ntp-server 10.10.1.1'
        self.assertEqual(len(res["syslog_servers"]), 0)  # No syslog defined in sample

    def test_fortinet_fortios_sample_ast(self):
        with open("samples/fortinet_fortios_sample.conf", "r", encoding="utf-8") as f:
            cfg = f.read()
        res = ast_parser.parse_fortinet_ast(cfg)
        self.assertEqual(res["parser"], "Batfish-Fortinet-AST")
        self.assertEqual(res["vendor"], "Fortinet")
        self.assertFalse(res["telnet_disabled"])  # 'set admin-telnet enable'
        self.assertEqual(res["session_timeout_minutes"], 480)

    def test_arista_eos_sample_ast(self):
        with open("samples/arista_eos_sample.cfg", "r", encoding="utf-8") as f:
            cfg = f.read()
        res = ast_parser.parse_arista_ast(cfg)
        self.assertEqual(res["parser"], "CiscoConfParse2-EOS-AST")
        self.assertEqual(res["vendor"], "Arista")

    def test_sonic_open_nos_sample_ast(self):
        with open("samples/sonic_whitebox_sample.json", "r", encoding="utf-8") as f:
            cfg = f.read()
        res = ast_parser.parse_sonic_ast(cfg)
        self.assertEqual(res["parser"], "SONiC-OpenNOS-AST")
        self.assertEqual(res["vendor"], "Open Networking (White-Box)")

    def test_checkpoint_gaia_sample_ast(self):
        with open("samples/checkpoint_gaia_sample.cfg", "r", encoding="utf-8") as f:
            cfg = f.read()
        res = ast_parser.parse_checkpoint_ast(cfg)
        self.assertEqual(res["parser"], "CheckPoint-GAiA-AST")
        self.assertEqual(res["vendor"], "Check Point")

    def test_huawei_vrp_sample_ast(self):
        with open("samples/huawei_vrp_sample.cfg", "r", encoding="utf-8") as f:
            cfg = f.read()
        res = ast_parser.parse_huawei_ast(cfg)
        self.assertEqual(res["parser"], "Huawei-VRP-AST")
        self.assertEqual(res["vendor"], "Huawei")


class TestPersonABatfishVIDM(unittest.TestCase):
    """
    Batfish Vendor-Independent Data Model (VIDM) AST Normalization.
    """
    def test_batfish_vidm_structure(self):
        with open("samples/cisco_ios_xe_sample.cfg", "r", encoding="utf-8") as f:
            cfg = f.read()
        vidm = ast_parser.extract_batfish_ast_model(cfg, "Cisco")
        self.assertEqual(vidm["batfish_model_version"], "2026.1-VIDM")
        self.assertEqual(vidm["node_name"], "core-switch-mumbai-01")
        self.assertTrue(vidm["batfish_ast_valid"])
        self.assertGreater(len(vidm["interfaces"]), 0)


class TestPersonAComplianceEngine(unittest.TestCase):
    """
    Step 3 Deliverable: 24-Rule Multi-Framework Compliance Engine (CIS, STIG, NIST, ISO).
    """
    def test_evaluate_compliance_24_rules_evaluated(self):
        insecure_cfg = """
        hostname vulnr-border-01
        line vty 0 4
         transport input telnet
         exec-timeout 0 0
        ip http server
        ip ssh version 1
        """
        eval_res, unmapped = evaluate_compliance(insecure_cfg, "Cisco")
        findings = eval_res["findings"]

        # Ensure all 24 standard checks were evaluated
        self.assertEqual(len(findings), 24)
        self.assertEqual(eval_res["summary"]["total_rules_evaluated"], 24)

        # FIND-001: Telnet must fail
        self.assertEqual(findings[0]["rule_id"], "DISA-STIG-V-215000")
        self.assertEqual(findings[0]["status"], "FAIL")
        self.assertEqual(findings[0]["severity"], "CRITICAL")

        # FIND-002: SSHv2 must fail
        self.assertEqual(findings[1]["rule_id"], "DISA-STIG-V-215001")
        self.assertEqual(findings[1]["status"], "FAIL")

        # FIND-003: HTTP server must fail
        self.assertEqual(findings[2]["rule_id"], "CIS-CISCO-1.2.3")
        self.assertEqual(findings[2]["status"], "FAIL")

        # FIND-004: Inactivity timeout must fail
        self.assertEqual(findings[3]["rule_id"], "DISA-STIG-V-215010")
        self.assertEqual(findings[3]["status"], "FAIL")

        # Framework scores presence
        f_scores = eval_res["framework_scores"]
        self.assertIn("cis_benchmark_score", f_scores)
        self.assertIn("disa_stig_score", f_scores)
        self.assertIn("nist_sp_800_53_score", f_scores)
        self.assertIn("iso_27001_score", f_scores)

    def test_compliance_hardened_configuration_high_score(self):
        hardened_cfg = """
        hostname hardened-cisco-core
        service password-encryption
        service timestamps log datetime msec
        service timestamps debug datetime msec
        no ip http server
        ip http secure-server
        ip ssh version 2
        crypto key generate rsa modulus 2048
        enable secret 9 $9$mERr$DefenseEnclaveStrongKey
        banner login ^C
        *** UNAUTHORIZED ACCESS PROHIBITED - SOVEREIGN DEFENSE ENCLAVE ***
        ^C
        no ip source-route
        no cdp run
        no lldp run
        ip tcp synwait-time 10
        aaa new-model
        ntp authenticate
        ntp server 10.10.1.1
        logging host 10.10.50.100
        line con 0
         exec-timeout 10 0
        line vty 0 4
         transport input ssh
         exec-timeout 10 0
         access-class VTY_MGMT_RESTRICT in
        """
        eval_res, _ = evaluate_compliance(hardened_cfg, "Cisco")
        self.assertGreater(eval_res["summary"]["overall_compliance_percentage"], 65.0)


class TestPersonARemediationEngine(unittest.TestCase):
    """
    Step 4 Deliverable: Vendor-Specific CLI Hardening, Jinja2, & Ansible Galaxy Playbooks.
    """
    def test_remediation_bundle_generation(self):
        dev_info = {
            "hostname": "core-switch-01",
            "vendor": "Cisco",
            "os_family": "IOS-XE"
        }
        findings = [
            {"rule_id": "DISA-STIG-V-215000", "status": "FAIL"},
            {"rule_id": "CIS-CISCO-1.2.3", "status": "FAIL"},
            {"rule_id": "DISA-STIG-V-215010", "status": "FAIL"},
            {"rule_id": "DISA-STIG-V-215015", "status": "FAIL"},
            {"rule_id": "DISA-STIG-V-215030", "status": "FAIL"}
        ]
        raw_cfg = "hostname core-switch-01\nline vty 0 4\n transport input telnet\n"
        bundle = remediation_engine.generate_remediation_bundle(raw_cfg, dev_info, findings)

        self.assertIn("remediation_cli", bundle)
        self.assertIn("rollback_cli", bundle)
        self.assertIn("ansible_playbook", bundle)
        self.assertIn("config_diff", bundle)
        self.assertIn("terraform_hcl", bundle)

        # Check Cisco CLI
        self.assertIn("no transport input all", bundle["remediation_cli"])
        self.assertIn("transport input ssh", bundle["remediation_cli"])
        self.assertIn("no ip http server", bundle["remediation_cli"])

        # Check Rollback CLI
        self.assertIn("transport input all", bundle["rollback_cli"])

        # Check Ansible Playbook
        self.assertIn("cisco.ios.ios_config", bundle["ansible_playbook"])

    def test_jinja2_cli_rendering(self):
        template = "line vty 0 {{ max_vty }}\n transport input {{ proto }}\n exec-timeout {{ timeout }} 0"
        context = {"max_vty": 4, "proto": "ssh", "timeout": 10}
        rendered = remediation_engine.render_jinja2_cli(template, context)
        self.assertIn("transport input ssh", rendered)
        self.assertIn("exec-timeout 10 0", rendered)


class TestPersonAIngestionDrivers(unittest.TestCase):
    """
    Step 2 Deliverable: Live SSH & Device Ingestion Drivers (Netmiko, Scrapli, NAPALM, Nornir).
    """
    def test_netmiko_collector(self):
        res = netmiko_collector.collect_config(
            host="10.10.10.1",
            platform="cisco_ios",
            mock_fallback=True
        )
        self.assertEqual(res["status"], "SIMULATED_SUCCESS")
        self.assertIn("Netmiko", res["collector"])
        self.assertTrue(res["driver_verified"])

    def test_scrapli_async_collector(self):
        res = asyncio.run(scrapli_collector.async_scrape_device(
            host="10.10.10.2",
            platform="cisco_iosxe"
        ))
        self.assertEqual(res["status"], "ASYNC_SCRAPE_COMPLETED")
        self.assertIn("Scrapli", res["collector"])

    def test_napalm_collector(self):
        facts = napalm_collector.get_facts("switch-01", "ios")
        self.assertEqual(facts["vendor"], "Cisco")
        cfg = napalm_collector.get_config("switch-01", "ios")
        self.assertIn("running", cfg)

    def test_nornir_bulk_auditor(self):
        inventory = [
            {"hostname": "node-01", "vendor": "Cisco", "platform": "cisco_ios", "config": "line vty 0 4\n transport input ssh\n exec-timeout 10 0\n"},
            {"hostname": "node-02", "vendor": "Juniper", "platform": "juniper_junos", "config": "line vty 0 4\n transport input telnet\n"}
        ]
        res = nornir_auditor.run_inventory_audit(inventory)
        self.assertEqual(res["total_devices_audited"], 2)
        self.assertEqual(res["passed_devices"], 1)
        self.assertEqual(res["failed_devices"], 1)


class TestPersonAPolicyAsCode(unittest.TestCase):
    """
    Step 4 Deliverable: Policy-as-Code & SIEM Frameworks (OPA Rego, XCCDF, InSpec, Checkov, DefectDojo).
    """
    def test_opa_rego_engine(self):
        input_doc = {
            "management_access": {"telnet_disabled": True, "ssh_version": 2, "http_server_disabled": True},
            "aaa": {"password_encryption": True, "session_timeout_minutes": 10}
        }
        res = opa_engine.evaluate_rego(input_doc)
        self.assertTrue(res["compliant"])
        self.assertEqual(res["violations_count"], 0)

    def test_openscap_xccdf_generator(self):
        findings = [
            {"rule_id": "V-215000", "title": "Telnet Disabled", "severity": "CRITICAL", "status": "FAIL"}
        ]
        xml_doc = openscap_engine.generate_xccdf_report("border-sw-01", findings)
        self.assertIn("<?xml", xml_doc)
        self.assertIn("xccdf:Benchmark", xml_doc)
        self.assertIn("border-sw-01", xml_doc)

    def test_chef_inspec_profile_export(self):
        profile = inspec_exporter.export_profile("core-node-01")
        self.assertIn("inspec.yml", profile)
        self.assertIn("controls/network_stig.rb", profile)

    def test_checkov_cloud_static_analysis(self):
        sg_rules = [
            {"cidr_ip": "0.0.0.0/0", "from_port": 23, "to_port": 23, "protocol": "tcp"}
        ]
        res = checkov_engine.evaluate_cloud_firewall(sg_rules)
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["failed_checks_count"], 1)

    def test_defectdojo_export(self):
        findings = [
            {"title": "Telnet Active", "found_value": "Telnet", "expected_value": "SSH", "status": "FAIL", "severity": "HIGH"}
        ]
        res = defectdojo_exporter.export_findings("AUD-001", "router-01", findings)
        self.assertEqual(res["findings_count"], 1)

    def test_opentofu_remediation(self):
        hcl = opentofu_remediator.generate_iac_remediation("perimeter-sg")
        self.assertIn("resource \"aws_security_group\"", hcl)
        self.assertIn("perimeter-sg", hcl)


class TestPersonAReportLabPDF(unittest.TestCase):
    """
    Step 5 Deliverable: Programmatic High-Assurance PDF Report with SHA-512 Seal.
    """
    def test_reportlab_pdf_binary_generation(self):
        audit_data = {
            "Metadata": {"AuditID": "AUD-TEST-999"},
            "DeviceInfo": {"Hostname": "core-audit-01", "Vendor": "Cisco", "OSFamily": "IOS-XE", "OSVersion": "17.9", "Model": "Cat9300"},
            "ComplianceEvaluation": {
                "Summary": {"OverallScore": 88.0, "RiskLevel": "LOW RISK"},
                "FrameworkScores": {"DISASTIGScore": 88.0, "CISScore": 92.0, "NISTScore": 90.0, "ISOScore": 89.0},
                "Findings": [
                    {"Status": "PASS", "RuleID": "DISA-STIG-V-215000", "Title": "Telnet Disabled", "Severity": "CRITICAL", "FoundValue": "SSH only", "MITRETechnique": "T1021"}
                ]
            },
            "FormalProof": {"formal_status": "PROVEN_SECURE", "smt_engine": "Microsoft Z3", "explanation": "Invariants satisfied"}
        }
        block_data = {
            "block_index": 42,
            "audit_seal": "a"*128,
            "signer_node": "NTRO-DEFENSE-NODE-01",
            "block_hash": "b"*64
        }
        pdf_bytes = generate_certified_ntro_pdf(audit_data, block_data)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 3000)


if __name__ == "__main__":
    unittest.main()
