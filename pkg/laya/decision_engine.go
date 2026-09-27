package laya

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"sentrygrid/pkg/models"
)

// IntentReference maps known security intents to semantic feature keywords
type IntentReference struct {
	Category       string
	Description    string
	Keywords       []string
	Weights        map[string]float64
	ExtractorRegex *regexp.Regexp
}

// DecisionEngine implements Laya System One decision routing
type DecisionEngine struct {
	mu             sync.RWMutex
	intents        []IntentReference
	heuristics     map[string]*models.DynamicHeuristicRule
	cacheFilePath  string
	confidenceGate float64 // default 0.95
}

// NewDecisionEngine initializes Laya with pre-compiled security intents
func NewDecisionEngine(cachePath string) *DecisionEngine {
	engine := &DecisionEngine{
		heuristics:     make(map[string]*models.DynamicHeuristicRule),
		cacheFilePath:  cachePath,
		confidenceGate: 0.95,
	}

	// Register canonical security intents
	engine.intents = []IntentReference{
		{
			Category:    "aaa.session_timeout_minutes",
			Description: "Terminal and console idle session timeout",
			Keywords:    []string{"idle", "timeout", "session", "exec-timeout", "autologout", "logout", "inactivity"},
			Weights: map[string]float64{
				"timeout":      0.45,
				"idle":         0.40,
				"exec-timeout": 0.50,
				"inactivity":   0.35,
			},
			ExtractorRegex: regexp.MustCompile(`(?i)(?:timeout|idle-timeout|exec-timeout|inactivity)\s+([0-9]+)`),
		},
		{
			Category:    "management_access.telnet_disabled",
			Description: "Insecure Telnet management daemon control",
			Keywords:    []string{"telnet", "disable", "no", "block", "deny", "transport"},
			Weights: map[string]float64{
				"telnet":  0.55,
				"disable": 0.40,
				"no":      0.30,
			},
			ExtractorRegex: regexp.MustCompile(`(?i)(?:set\s+admin-telnet\s+(disable|enable)|no\s+telnet|disable-telnet\s+(yes|no))`),
		},
		{
			Category:    "management_access.ssh_version",
			Description: "Secure Shell SSH version 2 protocol enforcement",
			Keywords:    []string{"ssh", "version", "protocol", "crypto", "rsa", "v2"},
			Weights: map[string]float64{
				"ssh":     0.50,
				"version": 0.35,
				"v2":      0.45,
				"crypto":  0.30,
			},
			ExtractorRegex: regexp.MustCompile(`(?i)(?:version\s+([0-9])|protocol-version\s+v?([0-9]))`),
		},
		{
			Category:    "management_access.http_server_disabled",
			Description: "Disabling unencrypted HTTP web management",
			Keywords:    []string{"http", "server", "web", "web-management", "disable", "no"},
			Weights: map[string]float64{
				"http":           0.50,
				"web-management": 0.45,
				"server":         0.25,
			},
			ExtractorRegex: regexp.MustCompile(`(?i)(?:no\s+ip\s+http\s+server|delete\s+system\s+services\s+web-management\s+http)`),
		},
		{
			Category:    "logging_audit.syslog_servers",
			Description: "Remote central syslog collector destination",
			Keywords:    []string{"logging", "syslog", "host", "server", "remote", "facility"},
			Weights: map[string]float64{
				"syslog":  0.50,
				"logging": 0.45,
				"host":    0.35,
				"server":  0.35,
			},
			ExtractorRegex: regexp.MustCompile(`([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`),
		},
		{
			Category:    "aaa.password_encryption_enabled",
			Description: "Reversible password encryption and strong secret hashing",
			Keywords:    []string{"password", "encryption", "secret", "algorithm", "sha256", "service"},
			Weights: map[string]float64{
				"password":   0.40,
				"encryption": 0.45,
				"secret":     0.40,
				"sha256":     0.35,
			},
			ExtractorRegex: regexp.MustCompile(`(?i)(?:service\s+password-encryption|algorithm\s+(type_8|sha256))`),
		},
		{
			Category:    "time_synchronization.ntp_servers",
			Description: "Network Time Protocol clock synchronization",
			Keywords:    []string{"ntp", "server", "clock", "synchronize", "timezone"},
			Weights: map[string]float64{
				"ntp":    0.60,
				"server": 0.30,
				"clock":  0.30,
			},
			ExtractorRegex: regexp.MustCompile(`(?i)ntp\s+server\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-zA-Z0-9.-]+)`),
		},
		{
			Category:    "cryptography.rsa_key_length_bits",
			Description: "Cryptographic RSA key modulus length",
			Keywords:    []string{"crypto", "key", "generate", "rsa", "modulus", "bits", "2048", "4096"},
			Weights: map[string]float64{
				"modulus": 0.50,
				"rsa":     0.40,
				"crypto":  0.30,
			},
			ExtractorRegex: regexp.MustCompile(`(?i)(?:modulus|bits)\s+([0-9]{4})`),
		},
	}

	// Load existing heuristics from disk if present
	engine.loadPersistedHeuristics()

	return engine
}

// EvaluateCommand applies Laya System One direct logit calculation on a raw CLI line
func (de *DecisionEngine) EvaluateCommand(line string, vendorScope string) models.AIAnalysis {
	de.mu.RLock()
	defer de.mu.RUnlock()

	cleaned := strings.ToLower(strings.TrimSpace(line))

	// 1. Check Dynamic Heuristic Store first (Instant O(1) hit for previously learned rules)
	for _, rule := range de.heuristics {
		if rule.VendorScope == "" || strings.EqualFold(rule.VendorScope, vendorScope) || rule.VendorScope == "all" {
			matched, err := regexp.MatchString(rule.PatternRegex, line)
			if err == nil && matched {
				rule.HitCount++
				return models.AIAnalysis{
					SuggestedCategory: rule.TargetAttribute,
					ConfidenceScore:   1.0,
					ExtractedValue:    rule.AssignedValue,
					Status:            "AUTO_MAPPED",
					DecisionLogits: map[string]float64{
						rule.TargetAttribute: 1.0,
					},
				}
			}
		}
	}

	// 2. Laya Logit Calculation across Intents
	tokens := strings.Fields(cleaned)
	tokenSet := make(map[string]bool)
	for _, t := range tokens {
		tokenSet[t] = true
	}

	bestCategory := "unknown.unclassified"
	maxLogit := 0.0
	logits := make(map[string]float64)

	for _, intent := range de.intents {
		score := 0.0
		for _, kw := range intent.Keywords {
			if tokenSet[kw] || strings.Contains(cleaned, kw) {
				w, exists := intent.Weights[kw]
				if !exists {
					w = 0.25
				}
				score += w
			}
		}

		// Normalize using soft logit sigmoid approximation
		logit := 1.0 / (1.0 + math.Exp(-2.5*(score-0.5)))
		if logit > 0.999 {
			logit = 0.999
		}
		logits[intent.Category] = math.Round(logit*100) / 100

		if logit > maxLogit {
			maxLogit = logit
			bestCategory = intent.Category
		}
	}

	// 3. Extract parameter entity if possible
	extracted := ""
	for _, intent := range de.intents {
		if intent.Category == bestCategory && intent.ExtractorRegex != nil {
			matches := intent.ExtractorRegex.FindStringSubmatch(line)
			if len(matches) > 1 {
				extracted = matches[1]
			}
		}
	}

	// 4. Apply Active Learning Confidence Gate
	status := "MANUAL_REVIEW_REQUIRED"
	if maxLogit >= de.confidenceGate {
		status = "AUTO_MAPPED"
	}

	return models.AIAnalysis{
		SuggestedCategory: bestCategory,
		ConfidenceScore:   math.Round(maxLogit*100) / 100,
		ExtractedValue:    extracted,
		Status:            status,
		DecisionLogits:    logits,
	}
}

// CrystallizeRule registers a human-confirmed mapping into the active heuristic store
func (de *DecisionEngine) CrystallizeRule(rawLine string, targetAttribute string, assignedValue string, vendorScope string) (*models.DynamicHeuristicRule, error) {
	de.mu.Lock()
	defer de.mu.Unlock()

	// Generate safe regex pattern from the command
	escaped := regexp.QuoteMeta(strings.TrimSpace(rawLine))
	// Generalize numeric arguments
	numRegex := regexp.MustCompile(`\b[0-9]+\b`)
	generalized := numRegex.ReplaceAllString(escaped, `([0-9]+)`)

	h := sha256.New()
	h.Write([]byte(generalized + targetAttribute + vendorScope))
	ruleID := "RULE-" + hex.EncodeToString(h.Sum(nil))[:12]

	rule := &models.DynamicHeuristicRule{
		RuleID:          ruleID,
		PatternRegex:    generalized,
		TargetAttribute: targetAttribute,
		AssignedValue:   assignedValue,
		VendorScope:     vendorScope,
		CreatedBy:       "SecOps-Administrator",
		CreatedAt:       time.Now().UTC(),
		HitCount:        1,
	}

	de.heuristics[ruleID] = rule
	de.persistHeuristics()

	return rule, nil
}

// GetActiveHeuristics returns all learned rules
func (de *DecisionEngine) GetActiveHeuristics() []*models.DynamicHeuristicRule {
	de.mu.RLock()
	defer de.mu.RUnlock()

	rules := make([]*models.DynamicHeuristicRule, 0, len(de.heuristics))
	for _, r := range de.heuristics {
		rules = append(rules, r)
	}
	return rules
}

func (de *DecisionEngine) persistHeuristics() {
	if de.cacheFilePath == "" {
		return
	}
	data, err := json.MarshalIndent(de.heuristics, "", "  ")
	if err == nil {
		_ = os.WriteFile(de.cacheFilePath, data, 0644)
	}
}

func (de *DecisionEngine) loadPersistedHeuristics() {
	if de.cacheFilePath == "" {
		return
	}
	data, err := os.ReadFile(de.cacheFilePath)
	if err == nil {
		var loaded map[string]*models.DynamicHeuristicRule
		if json.Unmarshal(data, &loaded) == nil {
			de.heuristics = loaded
			fmt.Printf("[Laya Engine] Loaded %d dynamic heuristics from %s\n", len(loaded), de.cacheFilePath)
		}
	}
}
