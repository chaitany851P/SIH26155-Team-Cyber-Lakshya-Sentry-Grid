package compliance

import (
	"fmt"
	"math"
	"regexp"
	"strings"

	"sentrygrid/pkg/laya"
	"sentrygrid/pkg/models"
)

// PolicyRule defines an individual compliance check across frameworks
type PolicyRule struct {
	RuleID           string
	Title            string
	Frameworks       []string
	ControlReference string
	Severity         string // CRITICAL, HIGH, MEDIUM, LOW
	MITRETechnique   string
	CheckFunc        func(cfg string, baseline *models.NormalizedSecurityBaseline) (passed bool, found string, expected string)
	RemediationGen   func(vendor string) (remediation string, rollback string)
	Impact           string
}

// ComplianceEvaluator manages policy rules and evaluates device configurations
type ComplianceEvaluator struct {
	rules []PolicyRule
}

// NewComplianceEvaluator initializes the benchmark rules suite
func NewComplianceEvaluator() *ComplianceEvaluator {
	ce := &ComplianceEvaluator{}
	ce.initRules()
	return ce
}

func (ce *ComplianceEvaluator) initRules() {
	ce.rules = []PolicyRule{
		{
			RuleID:           "DISA-STIG-V-215000",
			Title:            "Insecure Telnet Management Protocol Must Be Disabled",
			Frameworks:       []string{"DISA_STIG", "CIS", "NIST_SP_800_53", "ISO_27001"},
			ControlReference: "DISA STIG: V-215000 (CAT I) | NIST: SC-8 | CIS: 1.2.1 | ISO: A.8.20",
			Severity:         "CRITICAL",
			MITRETechnique:   "T1021.002 (Remote Services)",
			Impact:           "Cleartext administrative management traffic can be intercepted, exposing credentials.",
			CheckFunc: func(cfg string, b *models.NormalizedSecurityBaseline) (bool, string, string) {
				lower := strings.ToLower(cfg)
				if strings.Contains(lower, "transport input telnet") ||
					strings.Contains(lower, "transport input all") ||
					strings.Contains(lower, "set admin-telnet enable") ||
					strings.Contains(lower, "set system services telnet") {
					return false, "Insecure Telnet management protocol is enabled.", "Telnet disabled; only SSHv2 allowed."
				}
				if strings.Contains(lower, "transport input ssh") ||
					strings.Contains(lower, "delete system services telnet") ||
					strings.Contains(lower, "set admin-telnet disable") ||
					strings.Contains(lower, "disable-telnet yes") {
					return true, "Telnet is disabled; SSH only.", "Telnet disabled."
				}
				// Default fail if not explicitly disabled
				return false, "No explicit Telnet disable configuration found.", "Telnet explicitly disabled."
			},
			RemediationGen: func(vendor string) (string, string) {
				switch strings.ToLower(vendor) {
				case "juniper":
					return "delete system services telnet\ncommit and-quit", "set system services telnet\ncommit and-quit"
				case "fortinet":
					return "config system global\n set admin-telnet disable\nend", "config system global\n set admin-telnet enable\nend"
				case "palo alto networks":
					return "set deviceconfig system service disable-telnet yes", "set deviceconfig system service disable-telnet no"
				default:
					return "configure terminal\nline vty 0 4\n no transport input all\n transport input ssh\nend\nwrite memory",
						"configure terminal\nline vty 0 4\n transport input all\nend\nwrite memory"
				}
			},
		},
		{
			RuleID:           "DISA-STIG-V-215001",
			Title:            "SSH Protocol Version 2 Must Be Enforced",
			Frameworks:       []string{"DISA_STIG", "CIS", "NIST_SP_800_53", "ISO_27001"},
			ControlReference: "DISA STIG: V-215001 (CAT I) | NIST: SC-13 | CIS: 1.2.4 | ISO: A.8.24",
			Severity:         "CRITICAL",
			MITRETechnique:   "T1562.001 (Impair Defenses)",
			Impact:           "SSH version 1 suffers from known design vulnerabilities allowing man-in-the-middle decryption.",
			CheckFunc: func(cfg string, b *models.NormalizedSecurityBaseline) (bool, string, string) {
				lower := strings.ToLower(cfg)
				if strings.Contains(lower, "ip ssh version 2") ||
					strings.Contains(lower, "protocol-version v2") ||
					strings.Contains(lower, "protocol-version 2") ||
					strings.Contains(lower, "set admin-ssh-v1 disable") {
					return true, "SSH Version 2 is strictly enforced.", "SSHv2 enforced."
				}
				return false, "Legacy or unconstrained SSH version detected.", "ip ssh version 2 enforced."
			},
			RemediationGen: func(vendor string) (string, string) {
				switch strings.ToLower(vendor) {
				case "juniper":
					return "set system services ssh protocol-version v2\ncommit and-quit", "delete system services ssh protocol-version\ncommit and-quit"
				default:
					return "configure terminal\ncrypto key generate rsa modulus 2048\nip ssh version 2\nend\nwrite memory",
						"configure terminal\nip ssh version 1\nend\nwrite memory"
				}
			},
		},
		{
			RuleID:           "CIS-CISCO-1.2.3",
			Title:            "Unencrypted HTTP Server Must Be Disabled",
			Frameworks:       []string{"CIS", "DISA_STIG", "NIST_SP_800_53"},
			ControlReference: "CIS: 1.2.3 | DISA STIG: V-215004 (CAT II) | NIST: AC-3",
			Severity:         "HIGH",
			MITRETechnique:   "T1021.001 (Remote Desktop Protocol / Web)",
			Impact:           "Cleartext web management interface exposes web tokens and passwords.",
			CheckFunc: func(cfg string, b *models.NormalizedSecurityBaseline) (bool, string, string) {
				lower := strings.ToLower(cfg)
				if strings.Contains(lower, "no ip http server") ||
					strings.Contains(lower, "delete system services web-management http") ||
					strings.Contains(lower, "disable-http yes") {
					return true, "HTTP web server is disabled.", "HTTP server disabled."
				}
				if strings.Contains(lower, "ip http server") && !strings.Contains(lower, "no ip http server") {
					return false, "Unencrypted HTTP web server is active.", "no ip http server"
				}
				return true, "HTTP server not active.", "HTTP server disabled."
			},
			RemediationGen: func(vendor string) (string, string) {
				switch strings.ToLower(vendor) {
				case "juniper":
					return "delete system services web-management http\nset system services web-management https\ncommit and-quit",
						"set system services web-management http\ncommit and-quit"
				default:
					return "configure terminal\nno ip http server\nip http secure-server\nend\nwrite memory",
						"configure terminal\nip http server\nend\nwrite memory"
				}
			},
		},
		{
			RuleID:           "DISA-STIG-V-215010",
			Title:            "Terminal Inactivity / Idle Session Timeout Must Be Configured (<= 10 min)",
			Frameworks:       []string{"DISA_STIG", "CIS", "NIST_SP_800_53", "ISO_27001"},
			ControlReference: "DISA STIG: V-215010 (CAT II) | NIST: AC-7 | CIS: 1.2.8 | ISO: A.5.15",
			Severity:         "MEDIUM",
			MITRETechnique:   "T1078 (Valid Accounts)",
			Impact:           "Unattended administrative sessions remain open, allowing unauthorized physical or pivot access.",
			CheckFunc: func(cfg string, b *models.NormalizedSecurityBaseline) (bool, string, string) {
				reTimeout := regexp.MustCompile(`(?i)(?:exec-timeout|idle-timeout|admintimeout)\s+([0-9]+)`)
				if matches := reTimeout.FindStringSubmatch(cfg); len(matches) > 1 {
					var val int
					fmt.Sscanf(matches[1], "%d", &val)
					if val > 0 && val <= 10 {
						return true, fmt.Sprintf("Idle timeout configured: %d minutes.", val), "Timeout <= 10 min."
					}
					return false, fmt.Sprintf("Idle timeout exceeds policy threshold: %d min (limit 10).", val), "Timeout <= 10 min."
				}
				return false, "No terminal session timeout configured (infinite session vulnerability).", "Timeout <= 10 min."
			},
			RemediationGen: func(vendor string) (string, string) {
				switch strings.ToLower(vendor) {
				case "juniper":
					return "set system login idle-timeout 10\ncommit and-quit", "delete system login idle-timeout\ncommit and-quit"
				case "fortinet":
					return "config system global\n set admintimeout 10\nend", "config system global\n set admintimeout 480\nend"
				default:
					return "configure terminal\nline vty 0 4\n exec-timeout 10 0\nline console 0\n exec-timeout 10 0\nend\nwrite memory",
						"configure terminal\nline vty 0 4\n exec-timeout 0 0\nend\nwrite memory"
				}
			},
		},
		{
			RuleID:           "DISA-STIG-V-215015",
			Title:            "Central Remote Syslog Logging Server Must Be Configured",
			Frameworks:       []string{"DISA_STIG", "NIST_SP_800_53", "ISO_27001"},
			ControlReference: "DISA STIG: V-215015 (CAT II) | NIST: AU-2 | ISO: A.8.15",
			Severity:         "HIGH",
			MITRETechnique:   "T1562.001 (Disable or Modify Tools)",
			Impact:           "If local logs are wiped by an attacker, no central forensic record remains.",
			CheckFunc: func(cfg string, b *models.NormalizedSecurityBaseline) (bool, string, string) {
				lower := strings.ToLower(cfg)
				if strings.Contains(lower, "logging host") ||
					strings.Contains(lower, "set system syslog host") ||
					strings.Contains(lower, "config log syslogd setting") {
					return true, "Central remote syslog server is configured.", "Remote syslog configured."
				}
				return false, "No remote central syslog server defined.", "logging host <SIEM_IP>"
			},
			RemediationGen: func(vendor string) (string, string) {
				switch strings.ToLower(vendor) {
				case "juniper":
					return "set system syslog host 10.10.50.100 any notice\ncommit and-quit", "delete system syslog host 10.10.50.100\ncommit and-quit"
				default:
					return "configure terminal\nlogging host 10.10.50.100\nservice timestamps log datetime msec\nend\nwrite memory",
						"configure terminal\nno logging host 10.10.50.100\nend\nwrite memory"
				}
			},
		},
		{
			RuleID:           "CIS-CISCO-1.1.2",
			Title:            "Password Encryption Service Must Be Enabled",
			Frameworks:       []string{"CIS", "DISA_STIG", "NIST_SP_800_53"},
			ControlReference: "CIS: 1.1.2 | DISA STIG: V-215022 (CAT II) | NIST: IA-2",
			Severity:         "HIGH",
			MITRETechnique:   "T1552.001 (Credentials In Files)",
			Impact:           "Plaintext passwords in configurations can be read during backups or shoulder-surfing.",
			CheckFunc: func(cfg string, b *models.NormalizedSecurityBaseline) (bool, string, string) {
				lower := strings.ToLower(cfg)
				if strings.Contains(lower, "service password-encryption") ||
					strings.Contains(lower, "password-encryption enable") {
					return true, "Password encryption service is active.", "service password-encryption active."
				}
				return false, "Password encryption service is disabled.", "service password-encryption"
			},
			RemediationGen: func(vendor string) (string, string) {
				return "configure terminal\nservice password-encryption\nend\nwrite memory",
					"configure terminal\nno service password-encryption\nend\nwrite memory"
			},
		},
		{
			RuleID:           "DISA-STIG-V-215030",
			Title:            "NTP Clock Synchronization Must Be Configured",
			Frameworks:       []string{"DISA_STIG", "CIS", "NIST_SP_800_53", "ISO_27001"},
			ControlReference: "DISA STIG: V-215030 (CAT III) | NIST: AU-8 | CIS: 1.3.1 | ISO: A.8.15",
			Severity:         "LOW",
			MITRETechnique:   "T1070 (Indicator Removal)",
			Impact:           "Desynchronized device clocks corrupt forensic timelines during cyber incidents.",
			CheckFunc: func(cfg string, b *models.NormalizedSecurityBaseline) (bool, string, string) {
				lower := strings.ToLower(cfg)
				if strings.Contains(lower, "ntp server") || strings.Contains(lower, "set system ntp server") {
					return true, "NTP synchronization server defined.", "ntp server configured."
				}
				return false, "No NTP server configured.", "ntp server <Time_IP>"
			},
			RemediationGen: func(vendor string) (string, string) {
				switch strings.ToLower(vendor) {
				case "juniper":
					return "set system ntp server 10.10.1.1\ncommit and-quit", "delete system ntp server 10.10.1.1\ncommit and-quit"
				default:
					return "configure terminal\nntp server 10.10.1.1\nend\nwrite memory",
						"configure terminal\nno ntp server 10.10.1.1\nend\nwrite memory"
				}
			},
		},
	}
}

// EvaluateFull performs full multi-framework audit with Laya decision routing for unmapped lines
func (ce *ComplianceEvaluator) EvaluateFull(rawConfig string, vendor string, engine *laya.DecisionEngine) (models.ComplianceEvaluation, []models.UnmappedLine) {
	var findings []models.ComplianceFinding
	passCount, failCount, warnCount, manualReviewCount := 0, 0, 0, 0

	// 1. Evaluate Deterministic Rules
	for idx, rule := range ce.rules {
		passed, found, expected := rule.CheckFunc(rawConfig, nil)
		status := "FAIL"
		if passed {
			status = "PASS"
			passCount++
		} else {
			failCount++
		}

		remed, rollback := rule.RemediationGen(vendor)

		finding := models.ComplianceFinding{
			FindingID:        fmt.Sprintf("FIND-%03d", idx+1),
			RuleID:           rule.RuleID,
			Title:            rule.Title,
			Frameworks:       rule.Frameworks,
			ControlReference: rule.ControlReference,
			Severity:         rule.Severity,
			Status:           status,
			FoundValue:       found,
			ExpectedValue:    expected,
			Impact:           rule.Impact,
			RemediationCLI:   remed,
			RollbackCLI:      rollback,
			MITRETechnique:   rule.MITRETechnique,
		}
		findings = append(findings, finding)
	}

	// 2. Discover Unmapped / Novel Lines (Route to Laya Decision Model)
	var unmapped []models.UnmappedLine
	lines := strings.Split(rawConfig, "\n")
	lineCount := 0

	for lineIdx, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "!") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Look for unrecognized / custom lines (e.g. from whitebox SONiC or custom syntax)
		if strings.Contains(trimmed, "idle-timeout") ||
			strings.Contains(trimmed, "admin-telnet") ||
			strings.Contains(trimmed, "custom-access") ||
			strings.Contains(trimmed, "mgmt_ip") ||
			strings.Contains(trimmed, "web-management") {

			lineCount++
			if lineCount <= 5 { // Process up to 5 interesting unmapped lines for the AI loop
				aiRes := engine.EvaluateCommand(trimmed, vendor)
				if aiRes.Status == "MANUAL_REVIEW_REQUIRED" {
					manualReviewCount++
				}

				unmapped = append(unmapped, models.UnmappedLine{
					LineID:       fmt.Sprintf("unmapped-%03d", lineCount),
					LineNumber:   lineIdx + 1,
					RawText:      trimmed,
					ContextBlock: "device.management.stanza",
					AIAnalysis:   aiRes,
				})
			}
		}
	}

	// Compute overall scores
	totalRules := len(findings)
	overallPct := 0.0
	if totalRules > 0 {
		overallPct = math.Round((float64(passCount)/float64(totalRules))*1000) / 10
	}

	riskLevel := "LOW"
	if overallPct < 50 {
		riskLevel = "CRITICAL"
	} else if overallPct < 75 {
		riskLevel = "HIGH"
	} else if overallPct < 90 {
		riskLevel = "MEDIUM"
	}

	summary := models.ComplianceSummary{
		TotalRulesEvaluated: totalRules,
		PassedCount:         passCount,
		FailedCount:         failCount,
		WarningCount:        warnCount,
		ManualReviewCount:   manualReviewCount,
		OverallScore:        overallPct,
		RiskLevel:           riskLevel,
	}

	scores := models.FrameworkScores{
		CISScore:      math.Round((overallPct+5)*10) / 10,
		DISASTIGScore: overallPct,
		NISTScore:     math.Round((overallPct+3)*10) / 10,
		ISOScore:      math.Round((overallPct+2)*10) / 10,
	}
	if scores.CISScore > 100 {
		scores.CISScore = 100
	}

	return models.ComplianceEvaluation{
		Summary:         summary,
		FrameworkScores: scores,
		Findings:        findings,
	}, unmapped
}
