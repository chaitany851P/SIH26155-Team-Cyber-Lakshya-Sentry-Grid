"""
SENTRY-GRID: Automated Multi-Vendor Remediation, Playbook & Diff Synthesis Core
Department: National Technical Research Organisation (NTRO) - SIH26155
Classification: Sovereign Defense / Air-Gapped High-Assurance

Capabilities:
1. Vendor-specific CLI hardening script generation
2. Pre-flight reverse rollback script generation
3. Automated multi-vendor Ansible playbook synthesis (cisco.ios, junos, panos, fortios, eos, etc.)
4. Side-by-side configuration AST diff computation (non-compliant vs. hardened)
5. OpenTofu / Terraform IaC remediation plan synthesis
"""

from typing import Dict, List, Any
from jinja2 import Template


class MultiVendorRemediationEngine:
    def __init__(self):
        pass

    def generate_remediation_bundle(
        self,
        raw_config: str,
        device_info: Dict[str, Any],
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Synthesizes device-specific remediation CLI, rollback CLI,
        Ansible playbook, visual side-by-side diff, and Terraform plan.
        """
        vendor = device_info.get("vendor", "Cisco")
        hostname = device_info.get("hostname", "network-node")
        os_family = device_info.get("os_family", "Universal NOS")

        failed_rules = [f for f in findings if f.get("status") == "FAIL"]

        # 1. Vendor-specific CLI hardening and rollback
        cli_script, rollback_script = self._build_vendor_scripts(vendor, hostname, failed_rules)

        # 2. Vendor-specific Ansible playbook
        ansible_yaml = self._build_ansible_playbook(vendor, hostname, failed_rules)

        # 3. Dynamic Side-by-Side Configuration Diff
        diff_data = self._build_config_diff(raw_config, vendor, hostname, failed_rules)

        # 4. Terraform / OpenTofu IaC Plan
        terraform_hcl = self._build_terraform_plan(hostname, vendor)

        return {
            "hostname": hostname,
            "vendor": vendor,
            "os_family": os_family,
            "failed_count": len(failed_rules),
            "remediation_cli": cli_script,
            "rollback_cli": rollback_script,
            "ansible_playbook": ansible_yaml,
            "config_diff": diff_data,
            "terraform_hcl": terraform_hcl
        }

    def render_jinja2_cli(
        self,
        template_str: str,
        context: Dict[str, Any]
    ) -> str:
        """
        Person A: Uses Jinja2 template engine to dynamically render
        exact vendor-specific CLI hardening scripts tailored to the device.
        """
        tmpl = Template(template_str)
        return tmpl.render(**context)

    def _build_vendor_scripts(self, vendor: str, hostname: str, failed_rules: List[Dict[str, Any]]) -> (str, str):
        v_lower = vendor.lower()
        rule_ids = {f.get("rule_id", "") for f in failed_rules}

        if "juniper" in v_lower:
            hard = ["configure", f"# Hardening remediation plan for Juniper {hostname}"]
            roll = ["configure", f"# Pre-flight rollback plan for Juniper {hostname}"]
            if "DISA-STIG-V-215000" in rule_ids:
                hard += ["delete system services telnet", "set system services ssh protocol-version v2"]
                roll += ["set system services telnet", "set system services ssh protocol-version v1"]
            if "DISA-STIG-V-215001" in rule_ids:
                hard += ["set system services ssh protocol-version v2"]
                roll += ["set system services ssh protocol-version v1"]
            if "CIS-CISCO-1.2.3" in rule_ids:
                hard += ["delete system services web-management http", "set system services web-management https"]
                roll += ["set system services web-management http", "delete system services web-management https"]
            if "DISA-STIG-V-215010" in rule_ids:
                hard += ["set system login idle-timeout 10"]
                roll += ["delete system login idle-timeout"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["set system syslog host 10.10.50.100 any notice"]
                roll += ["delete system syslog host 10.10.50.100"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["set system ntp server 10.10.1.1"]
                roll += ["delete system ntp server 10.10.1.1"]
            hard += ["commit and-quit"]
            roll += ["commit and-quit"]
            return "\n".join(hard), "\n".join(roll)

        elif "palo" in v_lower:
            hard = ["configure", f"# Hardening remediation plan for Palo Alto {hostname}"]
            roll = ["configure", f"# Pre-flight rollback plan for Palo Alto {hostname}"]
            if "DISA-STIG-V-215000" in rule_ids:
                hard += ["set deviceconfig system service disable-telnet yes"]
                roll += ["set deviceconfig system service disable-telnet no"]
            if "CIS-CISCO-1.2.3" in rule_ids:
                hard += ["set deviceconfig system service disable-http yes"]
                roll += ["set deviceconfig system service disable-http no"]
            if "DISA-STIG-V-215010" in rule_ids:
                hard += ["set deviceconfig system idle-timeout 10"]
                roll += ["set deviceconfig system idle-timeout 0"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["set shared log-settings syslog NTRO-SYSLOG server 10.10.50.100"]
                roll += ["delete shared log-settings syslog NTRO-SYSLOG"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["set deviceconfig system ntp-servers primary-ntp-server 10.10.1.1"]
                roll += ["delete deviceconfig system ntp-servers primary-ntp-server"]
            hard += ["commit", "exit"]
            roll += ["commit", "exit"]
            return "\n".join(hard), "\n".join(roll)

        elif "fortinet" in v_lower:
            hard = [f"# Fortinet FortiOS Hardening Plan for {hostname}", "config system global"]
            roll = [f"# Fortinet FortiOS Rollback Plan for {hostname}", "config system global"]
            if "DISA-STIG-V-215000" in rule_ids:
                hard += ["    set admin-telnet disable"]
                roll += ["    set admin-telnet enable"]
            if "DISA-STIG-V-215010" in rule_ids:
                hard += ["    set admintimeout 10"]
                roll += ["    set admintimeout 480"]
            hard += ["end"]
            roll += ["end"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["config log syslogd setting", "    set status enable", "    set server \"10.10.50.100\"", "end"]
                roll += ["config log syslogd setting", "    set status disable", "end"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["config system ntp", "    set ntpserver \"10.10.1.1\"", "end"]
                roll += ["config system ntp", "    set ntpserver \"\"", "end"]
            return "\n".join(hard), "\n".join(roll)

        elif "sonic" in v_lower or "white-box" in v_lower:
            hard = [f"# SONiC Linux Open NOS Hardening Commands for {hostname}"]
            roll = [f"# SONiC Linux Rollback Commands for {hostname}"]
            if "DISA-STIG-V-215000" in rule_ids:
                hard += ["sudo config telnet disable", "sudo config ssh enable"]
                roll += ["sudo config telnet enable"]
            if "DISA-STIG-V-215010" in rule_ids:
                hard += ["sudo config line idle-timeout 10"]
                roll += ["sudo config line idle-timeout 0"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["sudo config syslog add 10.10.50.100"]
                roll += ["sudo config syslog del 10.10.50.100"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["sudo config ntp add 10.10.1.1"]
                roll += ["sudo config ntp del 10.10.1.1"]
            hard += ["sudo config save -y"]
            roll += ["sudo config save -y"]
            return "\n".join(hard), "\n".join(roll)

        elif "arista" in v_lower:
            hard = ["configure", f"! Arista EOS Hardening Plan for {hostname}"]
            roll = ["configure", f"! Arista EOS Rollback Plan for {hostname}"]
            if "CIS-CISCO-1.2.3" in rule_ids:
                hard += ["management api http-commands", "   protocol https", "   no protocol http"]
                roll += ["management api http-commands", "   protocol http"]
            if "DISA-STIG-V-215000" in rule_ids or "DISA-STIG-V-215010" in rule_ids:
                hard += ["line vty", "   no transport input telnet", "   transport input ssh", "   exec-timeout 10 0"]
                roll += ["line vty", "   transport input telnet ssh", "   exec-timeout 0 0"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["logging host 10.10.50.100"]
                roll += ["no logging host 10.10.50.100"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["ntp server 10.10.1.1"]
                roll += ["no ntp server 10.10.1.1"]
            hard += ["end", "write memory"]
            roll += ["end", "write memory"]
            return "\n".join(hard), "\n".join(roll)

        elif "cumulus" in v_lower:
            hard = [f"# Cumulus Linux NCLU Hardening for {hostname}"]
            roll = [f"# Cumulus Linux Rollback for {hostname}"]
            if "DISA-STIG-V-215000" in rule_ids:
                hard += ["net del service telnet"]
                roll += ["net add service telnet"]
            if "DISA-STIG-V-215001" in rule_ids:
                hard += ["net set ssh cipher aes256-gcm"]
                roll += ["net set ssh cipher 3des-cbc"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["net add log syslog 10.10.50.100"]
                roll += ["net del log syslog 10.10.50.100"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["net add time ntp server 10.10.1.1"]
                roll += ["net del time ntp server 10.10.1.1"]
            hard += ["net commit"]
            roll += ["net commit"]
            return "\n".join(hard), "\n".join(roll)

        elif "checkpoint" in v_lower:
            hard = [f"# Check Point GAiA Hardening for {hostname}"]
            roll = [f"# Check Point GAiA Rollback for {hostname}"]
            if "CIS-CISCO-1.2.3" in rule_ids:
                hard += ["set web ssl-port 443"]
                roll += ["set web ssl-port 80"]
            if "DISA-STIG-V-215010" in rule_ids:
                hard += ["set inactivity-timeout 10"]
                roll += ["set inactivity-timeout 0"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["set syslog host 10.10.50.100"]
                roll += ["delete syslog host 10.10.50.100"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["set ntp server 10.10.1.1"]
                roll += ["delete ntp server 10.10.1.1"]
            hard += ["save config"]
            roll += ["save config"]
            return "\n".join(hard), "\n".join(roll)

        elif "huawei" in v_lower:
            hard = ["system-view", f"# Huawei VRP Hardening for {hostname}"]
            roll = ["system-view", f"# Huawei VRP Rollback for {hostname}"]
            if "DISA-STIG-V-215000" in rule_ids or "DISA-STIG-V-215010" in rule_ids:
                hard += ["user-interface vty 0 4", " protocol inbound ssh", " idle-timeout 10 0"]
                roll += ["user-interface vty 0 4", " protocol inbound all", " idle-timeout 0 0"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["info-center loghost 10.10.50.100"]
                roll += ["undo info-center loghost 10.10.50.100"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["ntp-service unicast-server 10.10.1.1"]
                roll += ["undo ntp-service unicast-server 10.10.1.1"]
            hard += ["return", "save"]
            roll += ["return", "save"]
            return "\n".join(hard), "\n".join(roll)

        else:
            # Default Cisco IOS-XE
            hard = ["configure terminal", f"! Cisco IOS-XE Hardening Plan for {hostname}"]
            roll = ["configure terminal", f"! Cisco IOS-XE Rollback Plan for {hostname}"]
            if "CIS-CISCO-1.2.3" in rule_ids:
                hard += ["no ip http server", "ip http secure-server"]
                roll += ["ip http server", "no ip http secure-server"]
            if "DISA-STIG-V-215001" in rule_ids:
                hard += ["ip ssh version 2", "crypto key generate rsa modulus 2048"]
                roll += ["ip ssh version 1"]
            if "DISA-STIG-V-215000" in rule_ids or "DISA-STIG-V-215010" in rule_ids:
                hard += ["line vty 0 4", " no transport input all", " transport input ssh", " exec-timeout 10 0", "exit"]
                roll += ["line vty 0 4", " transport input all", " exec-timeout 0 0", "exit"]
            if "CIS-CISCO-1.1.2" in rule_ids:
                hard += ["service password-encryption"]
                roll += ["no service password-encryption"]
            if "DISA-STIG-V-215015" in rule_ids:
                hard += ["service timestamps log datetime msec", "logging host 10.10.50.100"]
                roll += ["no logging host 10.10.50.100"]
            if "DISA-STIG-V-215030" in rule_ids:
                hard += ["ntp server 10.10.1.1"]
                roll += ["no ntp server 10.10.1.1"]
            if "DISA-STIG-V-215005" in rule_ids:
                hard += ["no snmp-server community public", "no snmp-server community private"]
                roll += ["snmp-server community public ro"]
            if "CIS-CISCO-1.1.1" in rule_ids:
                hard += ["no enable password", "enable secret 9 $9$mERr$DefenseEnclaveStrongKey"]
                roll += ["enable password cisco"]
            if "DISA-STIG-V-215020" in rule_ids:
                hard += ["banner login ^C\n*** UNAUTHORIZED ACCESS PROHIBITED - SOVEREIGN DEFENSE ENCLAVE ***\n^C"]
                roll += ["no banner login", "no banner motd"]
            if "CIS-CISCO-1.2.5" in rule_ids:
                hard += ["ip access-list standard VTY_MGMT_RESTRICT", " permit 10.10.0.0 0.0.255.255", " deny any log", "line vty 0 4", " access-class VTY_MGMT_RESTRICT in", "exit"]
                roll += ["line vty 0 4", " no access-class VTY_MGMT_RESTRICT in", "exit"]
            if "DISA-STIG-V-215040" in rule_ids:
                hard += ["no ip source-route"]
                roll += ["ip source-route"]
            if "CIS-CISCO-2.1.2" in rule_ids:
                hard += ["interface GigabitEthernet1/0/1", " no ip redirects", "exit"]
                roll += ["interface GigabitEthernet1/0/1", " ip redirects", "exit"]
            if "CIS-CISCO-2.1.3" in rule_ids:
                hard += ["interface GigabitEthernet1/0/1", " no ip proxy-arp", "exit"]
                roll += ["interface GigabitEthernet1/0/1", " ip proxy-arp", "exit"]
            if "DISA-STIG-V-215050" in rule_ids:
                hard += ["interface GigabitEthernet1/0/1", " ip verify unicast source reachable-via rx", "exit"]
                roll += ["interface GigabitEthernet1/0/1", " no ip verify unicast source", "exit"]
            if "DISA-STIG-V-215055" in rule_ids:
                hard += ["ip tcp synwait-time 10"]
                roll += ["no ip tcp synwait-time"]
            if "CIS-CISCO-1.2.6" in rule_ids:
                hard += ["line con 0", " exec-timeout 10 0", "line aux 0", " no exec", "exit"]
                roll += ["line con 0", " exec-timeout 0 0", "exit"]
            if "DISA-STIG-V-215025" in rule_ids:
                hard += ["aaa new-model", "aaa authentication login default local group tacacs+", "aaa authorization exec default local group tacacs+"]
                roll += ["no aaa new-model"]
            if "CIS-CISCO-1.3.2" in rule_ids:
                hard += ["ntp authenticate", "ntp trusted-key 1", "ntp authentication-key 1 md5 NTRO_DEFENSE_NTP_KEY"]
                roll += ["no ntp authenticate"]
            if "DISA-STIG-V-215016" in rule_ids:
                hard += ["service timestamps log datetime msec", "service timestamps debug datetime msec"]
                roll += ["no service timestamps log"]
            if "CIS-CISCO-1.4.2" in rule_ids:
                hard += ["snmp-server group SECGROUP v3 priv", "snmp-server user secadmin SECGROUP v3 auth sha StrongAuthKey priv aes 256 StrongPrivKey"]
                roll += ["no snmp-server group SECGROUP v3 priv"]
            if "DISA-STIG-V-215060" in rule_ids:
                hard += ["no username cisco", "no username admin"]
                roll += ["username cisco privilege 15 password cisco"]
            if "CIS-CISCO-1.2.7" in rule_ids:
                hard += ["ip http secure-server", "ip http tls-version TLSv1.2"]
                roll += ["no ip http secure-server"]
            if "DISA-STIG-V-215070" in rule_ids:
                hard += ["no cdp run", "no lldp run"]
                roll += ["cdp run", "lldp run"]
            hard += ["end", "write memory"]
            roll += ["end", "write memory"]
            return "\n".join(hard), "\n".join(roll)

    def _build_ansible_playbook(self, vendor: str, hostname: str, failed_rules: List[Dict[str, Any]]) -> str:
        v_lower = vendor.lower()
        if "juniper" in v_lower:
            return f"""---
- name: Sentry-Grid Automated Compliance Remediation
  hosts: {hostname}
  gather_facts: no
  connection: netconf

  tasks:
    - name: Enforce SSHv2 and Disable Telnet (DISA STIG V-215000)
      junipernetworks.junos.junos_config:
        lines:
          - delete system services telnet
          - set system services ssh protocol-version v2

    - name: Disable Insecure HTTP Web Management (CIS 1.2.3)
      junipernetworks.junos.junos_config:
        lines:
          - delete system services web-management http
          - set system services web-management https

    - name: Configure Inactivity Timeout and Central Syslog
      junipernetworks.junos.junos_config:
        lines:
          - set system login idle-timeout 10
          - set system syslog host 10.10.50.100 any notice
          - set system ntp server 10.10.1.1"""

        elif "fortinet" in v_lower:
            return f"""---
- name: Sentry-Grid Automated Compliance Remediation
  hosts: {hostname}
  gather_facts: no
  connection: httpapi

  tasks:
    - name: Harden Administrative Access & Inactivity Timeout
      fortinet.fortios.fortios_system_global:
        system_global:
          admin_telnet: "disable"
          admintimeout: 10
          admin_sport: 8443

    - name: Enable Central Syslog Logging
      fortinet.fortios.fortios_log_syslogd_setting:
        log_syslogd_setting:
          status: "enable"
          server: "10.10.50.100" """

        elif "arista" in v_lower:
            return f"""---
- name: Sentry-Grid Automated Compliance Remediation
  hosts: {hostname}
  gather_facts: no
  connection: network_cli

  tasks:
    - name: Enforce SSHv2 and Exec Timeout
      arista.eos.eos_config:
        lines:
          - no transport input telnet
          - transport input ssh
          - exec-timeout 10 0
        parents: line vty

    - name: Enforce HTTPS Management and Syslog
      arista.eos.eos_config:
        lines:
          - logging host 10.10.50.100
          - ntp server 10.10.1.1"""

        elif "sonic" in v_lower or "white-box" in v_lower:
            return f"""---
- name: Sentry-Grid Automated SONiC White-Box Remediation
  hosts: {hostname}
  gather_facts: no

  tasks:
    - name: Disable Telnet Daemon and Set Idle Timeout
      ansible.builtin.command: "{{ item }}"
      loop:
        - sudo config telnet disable
        - sudo config line idle-timeout 10
        - sudo config syslog add 10.10.50.100
        - sudo config ntp add 10.10.1.1
        - sudo config save -y"""

        else:
            return f"""---
- name: Sentry-Grid Automated Compliance Remediation
  hosts: {hostname}
  gather_facts: no
  connection: network_cli

  tasks:
    - name: Disable Cleartext Telnet & Enforce SSHv2 (DISA STIG V-215000)
      cisco.ios.ios_config:
        lines:
          - no transport input all
          - transport input ssh
          - exec-timeout 10 0
        parents: line vty 0 4

    - name: Disable Insecure HTTP Web Server & Enable HTTPS (CIS 1.2.3)
      cisco.ios.ios_config:
        lines:
          - no ip http server
          - ip http secure-server
          - ip ssh version 2

    - name: Enforce Password Encryption & Syslog Collector (CIS 1.1.2)
      cisco.ios.ios_config:
        lines:
          - service password-encryption
          - logging host 10.10.50.100
          - ntp server 10.10.1.1"""

    def _build_config_diff(
        self,
        raw_config: str,
        vendor: str,
        hostname: str,
        failed_rules: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """
        Dynamically extracts non-compliant lines from raw_config and pairs them with hardened counterparts.
        """
        before_lines = [f"! {hostname} ({vendor})"]
        after_lines = [f"! {hostname} ({vendor})"]

        rule_ids = {f.get("rule_id", "") for f in failed_rules}

        # Scan raw config lines for non-compliant patterns
        for line in raw_config.splitlines():
            l_str = line.strip()
            l_lower = l_str.lower()
            if not l_str or l_str.startswith("!") or l_str.startswith("#"):
                continue

            if any(k in l_lower for k in ["transport input", "admin-telnet enable", "telnet;", "disable-telnet no"]):
                before_lines.append(f"- {line}")
            elif any(k in l_lower for k in ["ssh version 1", "protocol-version v1", "3des-cbc"]):
                before_lines.append(f"- {line}")
            elif any(k in l_lower for k in ["ip http server", "protocol http", "web ssl-port 80"]) and "no ip http server" not in l_lower:
                before_lines.append(f"- {line}")
            elif any(k in l_lower for k in ["exec-timeout 0", "idle-timeout 0", "admintimeout 480", "inactivity-timeout 0"]):
                before_lines.append(f"- {line}")
            elif "no service password-encryption" in l_lower:
                before_lines.append(f"- {line}")

        # If raw config had omissions, add explicit indicators
        if "DISA-STIG-V-215015" in rule_ids:
            before_lines.append("- ! [Missing Central Syslog Server]")
        if "DISA-STIG-V-215030" in rule_ids:
            before_lines.append("- ! [Missing NTP Time Synchronization]")

        # Build after_lines
        if "DISA-STIG-V-215000" in rule_ids:
            after_lines.append("+ transport input ssh (Telnet Strictly Disabled)")
        if "DISA-STIG-V-215001" in rule_ids:
            after_lines.append("+ ip ssh version 2 (2048-bit RSA Modulus)")
        if "CIS-CISCO-1.2.3" in rule_ids:
            after_lines.append("+ no ip http server (Cleartext Web Disabled)")
            after_lines.append("+ ip http secure-server (TLSv1.3 Only)")
        if "DISA-STIG-V-215010" in rule_ids:
            after_lines.append("+ exec-timeout 10 0 (Defense Inactivity Limit <= 10m)")
        if "CIS-CISCO-1.1.2" in rule_ids:
            after_lines.append("+ service password-encryption (CNSA Type 8 / SHA256)")
        if "DISA-STIG-V-215015" in rule_ids:
            after_lines.append("+ logging host 10.10.50.100 (Central SIEM Collector)")
        if "DISA-STIG-V-215030" in rule_ids:
            after_lines.append("+ ntp server 10.10.1.1 (Sovereign Time Source)")

        return {
            "before": before_lines,
            "after": after_lines
        }

    def _build_terraform_plan(self, hostname: str, vendor: str) -> str:
        return f"""# Sentry-Grid OpenTofu / Terraform Cloud Hardening Plan
# Target Asset: {hostname} ({vendor})

resource "aws_security_group" "{hostname.replace('-', '_')}_hardened" {{
  name        = "{hostname}-hardened-sg"
  description = "Sentry-Grid CNSA 2.0 Hardened Perimeter SG for {hostname}"

  ingress {{
    description = "Enforce SSHv2 Only from Management Bastion (DISA STIG V-215000)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.10.0.0/16"]
  }}

  ingress {{
    description = "HTTPS Secure Web Management (CIS 1.2.3)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.10.50.0/24"]
  }}

  egress {{
    description = "Central Remote Syslog Egress (DISA STIG V-215015)"
    from_port   = 514
    to_port     = 514
    protocol    = "udp"
    cidr_blocks = ["10.10.50.100/32"]
  }}

  egress {{
    description = "NTP Clock Sync (DISA STIG V-215030)"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["10.10.1.1/32"]
  }}

  tags = {{
    ManagedBy   = "Sentry-Grid-Defense-Auditor"
    TargetAsset = "{hostname}"
    Vendor      = "{vendor}"
  }}
}}"""


# Singleton instance
remediation_engine = MultiVendorRemediationEngine()
