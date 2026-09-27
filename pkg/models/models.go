package models

import "time"

// AuditMetadata contains envelope information and cryptographic seal
type AuditMetadata struct {
	AuditID           string    `json:"audit_id"`
	Timestamp         time.Time `json:"timestamp"`
	SchemaVersion     string    `json:"schema_version"`
	HashAlgorithm     string    `json:"hash_algorithm"`
	CryptographicSeal string    `json:"cryptographic_seal"`
	LedgerBlockIndex  int64     `json:"ledger_block_index"`
}

// DeviceInfo represents physical and operating system characteristics
type DeviceInfo struct {
	Hostname         string `json:"hostname"`
	Vendor           string `json:"vendor"`
	OSFamily         string `json:"os_family"`
	OSVersion        string `json:"os_version"`
	Model            string `json:"model"`
	SerialNumber     string `json:"serial_number"`
	ManagementIP     string `json:"management_ip"`
	RawConfigSHA512  string `json:"raw_config_sha512"`
	DetectedFeatures int    `json:"detected_features"`
}

// AAA contains authentication, authorization, and accounting settings
type AAA struct {
	PasswordEncryptionEnabled bool   `json:"password_encryption_enabled"`
	MinPasswordLength         int    `json:"min_password_length"`
	EnableSecretType          string `json:"enable_secret_type"`
	LoginBannerConfigured     bool   `json:"login_banner_configured"`
	LoginBannerText           string `json:"login_banner_text,omitempty"`
	SessionTimeoutMinutes     int    `json:"session_timeout_minutes"`
	FailedLoginsMaxAttempts   int    `json:"failed_logins_max_attempts"`
	LockoutDurationMinutes    int    `json:"lockout_duration_minutes"`
	ExternalAuthConfigured    bool   `json:"external_auth_configured"`
}

// ManagementAccess controls remote administrative protocols and ACLs
type ManagementAccess struct {
	SSHEnabled            bool   `json:"ssh_enabled"`
	SSHVersion            int    `json:"ssh_version"`
	TelnetDisabled        bool   `json:"telnet_disabled"`
	HTTPServerDisabled    bool   `json:"http_server_disabled"`
	HTTPSServerEnabled    bool   `json:"https_server_enabled"`
	SNMPv1v2Disabled      bool   `json:"snmp_v1_v2_disabled"`
	SNMPv3Enabled         bool   `json:"snmp_v3_enabled"`
	SNMPv3Encryption      string `json:"snmp_v3_encryption,omitempty"`
	VTYACLApplied         bool   `json:"vty_acl_applied"`
	ConsoleTimeoutMinutes int    `json:"console_timeout_minutes"`
}

// LoggingAudit governs audit trail and syslog configuration
type LoggingAudit struct {
	SyslogServers           []string `json:"syslog_servers"`
	LoggingBufferedLevel    string   `json:"logging_buffered_level"`
	LoggingTimestampsDetail string   `json:"logging_timestamps_detail"`
	AuditTrailEnabled       bool     `json:"audit_trail_enabled"`
	ConsoleLoggingEnabled   bool     `json:"console_logging_enabled"`
}

// TimeSynchronization represents NTP and clock security
type TimeSynchronization struct {
	NTPServers                 []string `json:"ntp_servers"`
	NTPAuthenticationEnabled   bool     `json:"ntp_authentication_enabled"`
	Timezone                   string   `json:"timezone"`
}

// NetworkDefense covers perimeter and packet-level hardening
type NetworkDefense struct {
	IPSourceRouteDisabled     bool `json:"ip_source_route_disabled"`
	ICMPRedirectsDisabled     bool `json:"icmp_redirects_disabled"`
	ProxyARPDisabled          bool `json:"proxy_arp_disabled"`
	SYNFloodProtectionEnabled bool `json:"syn_flood_protection_enabled"`
	UnicastRPFEnabled         bool `json:"unicast_rpf_enabled"`
}

// Cryptography covers cipher suites and TLS baselines
type Cryptography struct {
	TLSMinVersion       string `json:"tls_min_version"`
	WeakCiphersDisabled bool   `json:"weak_ciphers_disabled"`
	RSAKeyLengthBits    int    `json:"rsa_key_length_bits"`
}

// NormalizedSecurityBaseline represents the canonical vendor-neutral schema
type NormalizedSecurityBaseline struct {
	AAA                 AAA                 `json:"aaa"`
	ManagementAccess    ManagementAccess    `json:"management_access"`
	LoggingAudit        LoggingAudit        `json:"logging_audit"`
	TimeSynchronization TimeSynchronization `json:"time_synchronization"`
	NetworkDefense      NetworkDefense      `json:"network_defense"`
	Cryptography        Cryptography        `json:"cryptography"`
}

// AIAnalysis contains Laya System One decision metrics
type AIAnalysis struct {
	SuggestedCategory string  `json:"suggested_category"`
	ConfidenceScore   float64 `json:"confidence_score"`
	ExtractedValue    string  `json:"extracted_value,omitempty"`
	Status            string  `json:"status"` // AUTO_MAPPED or MANUAL_REVIEW_REQUIRED
	DecisionLogits    map[string]float64 `json:"decision_logits,omitempty"`
}

// UnmappedLine represents novel CLI lines passed to the AI loop
type UnmappedLine struct {
	LineID       string     `json:"line_id"`
	LineNumber   int        `json:"line_number"`
	RawText      string     `json:"raw_text"`
	ContextBlock string     `json:"context_block"`
	AIAnalysis   AIAnalysis `json:"ai_analysis"`
}

// ComplianceFinding represents a discrete evaluation against a security standard
type ComplianceFinding struct {
	FindingID        string   `json:"finding_id"`
	RuleID           string   `json:"rule_id"`
	Title            string   `json:"title"`
	Frameworks       []string `json:"frameworks"`
	ControlReference string   `json:"control_reference"`
	Severity         string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Status           string   `json:"status"`   // PASS, FAIL, MANUAL_REVIEW
	FoundValue       string   `json:"found_value"`
	ExpectedValue    string   `json:"expected_value"`
	Impact           string   `json:"impact"`
	RemediationCLI   string   `json:"remediation_cli"`
	RollbackCLI      string   `json:"rollback_cli"`
	MITRETechnique   string   `json:"mitre_technique,omitempty"`
}

// ComplianceSummary summarizes audit statistics
type ComplianceSummary struct {
	TotalRulesEvaluated int     `json:"total_rules_evaluated"`
	PassedCount         int     `json:"passed_count"`
	FailedCount         int     `json:"failed_count"`
	WarningCount        int     `json:"warning_count"`
	ManualReviewCount   int     `json:"manual_review_count"`
	OverallScore        float64 `json:"overall_compliance_percentage"`
	RiskLevel           string  `json:"risk_level"` // CRITICAL, HIGH, MEDIUM, LOW
}

// FrameworkScores breaks down scores by security standard
type FrameworkScores struct {
	CISScore      float64 `json:"cis_benchmark_score"`
	DISASTIGScore float64 `json:"disa_stig_score"`
	NISTScore     float64 `json:"nist_sp_800_53_score"`
	ISOScore      float64 `json:"iso_27001_score"`
}

// ComplianceEvaluation represents the full evaluation results
type ComplianceEvaluation struct {
	Summary         ComplianceSummary   `json:"summary"`
	FrameworkScores FrameworkScores     `json:"framework_scores"`
	Findings        []ComplianceFinding `json:"findings"`
}

// AuditResult is the complete top-level audit envelope
type AuditResult struct {
	Metadata                   AuditMetadata              `json:"metadata"`
	DeviceInfo                 DeviceInfo                 `json:"device_info"`
	NormalizedSecurityBaseline NormalizedSecurityBaseline `json:"normalized_security_baseline"`
	UnmappedLines              []UnmappedLine             `json:"unmapped_lines"`
	ComplianceEvaluation       ComplianceEvaluation       `json:"compliance_evaluation"`
}

// DynamicHeuristicRule represents an admin-confirmed mapping
type DynamicHeuristicRule struct {
	RuleID          string    `json:"rule_id"`
	PatternRegex    string    `json:"pattern_regex"`
	TargetAttribute string    `json:"target_attribute"`
	AssignedValue   string    `json:"assigned_value"`
	VendorScope     string    `json:"vendor_scope"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	HitCount        int       `json:"hit_count"`
}
